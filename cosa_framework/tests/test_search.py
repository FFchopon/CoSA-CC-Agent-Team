"""Tests for the stronger/more-diverse payload search."""
import json

from cosa import (Analyzer, Budgets, Dispatcher, FakeLLMClient, Grafter,
                  Reflector, is_append_only)
from cosa.graph_search import SearchConstraints
from cosa.generator import TemplatePayloadGenerator
from cosa.llm_agents import LLMGenerator
from cosa.reflection import Action
from cosa.spec import (EvidenceBundle, JudgeReport, Stage, StageVerdict, Verdict)
from targets import self_collab as sc


def _spec_ctx():
    spec_obj = sc.self_collab_mas_spec()
    context = sc.self_collab_context()
    path = Grafter(Analyzer().build(spec_obj).mdg).rank_candidates(SearchConstraints())[0]
    spec = Dispatcher().bind(path=path, context=context, terminal_objective="x",
                             permissions=["p"], target_value="pass", allowed_edits="a")
    return spec, context


def test_template_strategies_are_diverse_and_append_only():
    spec, context = _spec_ctx()
    gen = TemplatePayloadGenerator()
    seen, payload = set(), gen.generate(spec, context)
    seen.add(payload.metadata["strategy"])
    for i in range(len(gen.STRATEGIES) - 1):
        payload = gen.refine(spec, context, payload, "d", i + 2)
        seen.add(payload.metadata["strategy"])
        assert is_append_only(context.benign_source_value, payload.content)
    # All distinct strategies were explored (breadth, not one escalating framing).
    assert seen == set(gen.STRATEGIES)


def test_llm_generator_best_of_n_one_call_many_candidates():
    calls = {"n": 0}

    def responder(role, system, user):
        if role == "generator":
            calls["n"] += 1
            return json.dumps({"candidates": ["alpha inject", "beta inject",
                                              "gamma inject"]})
        return "{}"
    client = FakeLLMClient(responder)
    spec, context = _spec_ctx()
    gen = LLMGenerator(client, candidates_per_call=3)
    p1 = gen.generate(spec, context)
    p2 = gen.refine(spec, context, p1, "d", 2)
    p3 = gen.refine(spec, context, p2, "d", 3)
    # One model call seeded three distinct, append-only payloads.
    assert calls["n"] == 1
    contents = {p1.content, p2.content, p3.content}
    assert len(contents) == 3
    for p in (p1, p2, p3):
        assert is_append_only(context.benign_source_value, p.content)


def test_llm_generator_hill_climb_mutates_same_vector_then_switches():
    """With hill_climb on, refine first minimally rewrites the current injection
    (framing llm_mut_*) for mutations_per_vector steps, then switches vector."""
    mutate_prompts = []
    mut = {"n": 0}

    def responder(role, system, user):
        if role == "generator":
            if "keep it" in user.lower() or "smallest change" in user.lower():
                # mutate request: it must carry the previous injection as a seed
                mutate_prompts.append(user)
                mut["n"] += 1
                return json.dumps({"append_text": f"mutated inject v{mut['n']}"})
            return json.dumps({"append_text": "fresh inject v0"})
        return "{}"
    client = FakeLLMClient(responder)
    spec, context = _spec_ctx()
    gen = LLMGenerator(client, candidates_per_call=1, hill_climb=True,
                       mutations_per_vector=2)
    p1 = gen.generate(spec, context)                      # vector seed
    p2 = gen.refine(spec, context, p1, "diag-1", 2)       # mutate 1
    p3 = gen.refine(spec, context, p2, "diag-2", 3)       # mutate 2
    p4 = gen.refine(spec, context, p3, "diag-3", 4)       # switch vector
    assert p1.metadata["framing"] == "llm_1"
    assert p2.metadata["framing"] == "llm_mut_2"
    assert p3.metadata["framing"] == "llm_mut_3"
    assert p4.metadata["framing"] == "llm_4"              # back to a fresh vector
    # First mutate seeds on the original injection + its diagnosis; the second
    # chains on the first mutation (true hill-climb, not a reset).
    assert "fresh inject v0" in mutate_prompts[0] and "diag-1" in mutate_prompts[0]
    assert "mutated inject v1" in mutate_prompts[1] and "diag-2" in mutate_prompts[1]
    for p in (p1, p2, p3, p4):
        assert is_append_only(context.benign_source_value, p.content)


def test_reflector_exhaust_payload_keeps_refining():
    report = JudgeReport(
        spec_id="s", spec_version=1,
        stages=[StageVerdict(Stage.C1_INCORRECT_COMMITMENT, Verdict.SUPPORTED, [1], ""),
                StageVerdict(Stage.C2_EFFECTIVE_ADOPTION, Verdict.REFUTED, [], ""),
                StageVerdict(Stage.C3_TERMINAL_OUTCOME, Verdict.REFUTED, [], "")],
        chain_linked=False, attribution=False, complete_success=False)
    attack = EvidenceBundle("attack")
    attack.record("exposure")
    # Default reflector pivots; exhaust_payload reflector keeps searching.
    assert Reflector().decide(report, attack, 0, Budgets(), False).action == Action.SELECT_NEW_PATH
    assert Reflector(exhaust_payload=True).decide(
        report, attack, 0, Budgets(), False).action == Action.REFINE_PAYLOAD


def _report_at_depth(depth: int) -> JudgeReport:
    """A JudgeReport whose first ``depth`` stages are SUPPORTED (0..3)."""
    order = [Stage.C1_INCORRECT_COMMITMENT, Stage.C2_EFFECTIVE_ADOPTION,
             Stage.C3_TERMINAL_OUTCOME]
    stages = [StageVerdict(st, Verdict.SUPPORTED if i < depth else Verdict.REFUTED,
                           [1] if i < depth else [], "")
              for i, st in enumerate(order)]
    return JudgeReport(spec_id="s", spec_version=1, stages=stages,
                       chain_linked=False, attribution=False, complete_success=False)


def test_adaptive_reflector_keeps_climbing_on_progress_and_switches_on_stall():
    """Adaptive allocation holds a vector that advances a stage and switches a
    stalled one — all via hold_vector, never exposing verdicts to the Generator."""
    attack = EvidenceBundle("attack")
    attack.record("exposure")
    r = Reflector(exhaust_payload=True, adaptive=True, patience=2, max_vector_tries=5)
    budgets = Budgets()  # per_path_retries=4, but we pass retries_used below

    # Fresh vector seeded at depth 0 -> climb it.
    d0 = r.decide(_report_at_depth(0), attack, 0, budgets, False)
    assert d0.action == Action.REFINE_PAYLOAD and d0.hold_vector is True
    # Mutation advances to depth 1 -> keep climbing (progress resets stall).
    d1 = r.decide(_report_at_depth(1), attack, 1, budgets, False)
    assert d1.hold_vector is True
    # No further progress: first stall -> one more climb (patience=2).
    d2 = r.decide(_report_at_depth(1), attack, 2, budgets, False)
    assert d2.hold_vector is True
    # Second stall reaches patience -> switch to a fresh vector.
    d3 = r.decide(_report_at_depth(1), attack, 3, budgets, False)
    assert d3.hold_vector is False
    # After a switch the per-vector trackers reset: next result seeds a new vector.
    d4 = r.decide(_report_at_depth(0), attack, 0, budgets, False)
    assert d4.hold_vector is True


def test_adaptive_reflector_caps_tries_per_vector():
    """A vector that keeps advancing is still capped so it can't eat the budget."""
    attack = EvidenceBundle("attack")
    attack.record("exposure")
    r = Reflector(exhaust_payload=True, adaptive=True, patience=9, max_vector_tries=3)
    # Even with progress every step, max_vector_tries=3 forces a switch on try 3.
    assert r.decide(_report_at_depth(0), attack, 0, Budgets(), False).hold_vector is True
    assert r.decide(_report_at_depth(1), attack, 1, Budgets(), False).hold_vector is True
    assert r.decide(_report_at_depth(1), attack, 2, Budgets(), False).hold_vector is False
