"""Campaigns against the two external coding-MAS target models."""
from cosa import CampaignConfig, ContextLibrary, CoSACampaign
from cosa.reflection import Budgets
from targets import self_collab as sc
from targets import tracedev as td


def _run(target, context, spec, objective, value):
    lib = ContextLibrary()
    lib.add(context)
    campaign = CoSACampaign(target=target, context_library=lib)
    cfg = CampaignConfig(terminal_objective=objective, target_value=value,
                         budgets=Budgets(per_path_retries=5, global_attempts=20))
    return campaign.run(spec, cfg)


# -- TraceDev --------------------------------------------------------------- #
def test_tracedev_mdg_is_sound_single_path():
    from cosa import Analyzer, Grafter
    from cosa.graph_search import SearchConstraints
    result = Analyzer().build(td.tracedev_mas_spec())
    assert result.structurally_sound, result.problems
    ranked = Grafter(result.mdg).rank_candidates(SearchConstraints())
    assert len(ranked) == 1
    assert ranked[0].source == td.SRC and ranked[0].sink == td.STATE_TRACE
    assert ranked[0].terminal_operation == td.OP_IMPLEMENT


def test_tracedev_vulnerable_completes_chain():
    report = _run(td.TraceDevTarget(policy=td.VulnerableValidatorPolicy()),
                  td.tracedev_context(), td.tracedev_mas_spec(),
                  "code implemented from an unvalidated design", "complete")
    assert report.success and report.stop_reason == "target_success"
    final = report.attempts[-1]
    assert final.complete_success and final.chain_linked and final.attribution


def test_tracedev_defended_fails_closed():
    report = _run(td.TraceDevTarget(policy=td.DefendedValidatorPolicy()),
                  td.tracedev_context(), td.tracedev_mas_spec(),
                  "code implemented from an unvalidated design", "complete")
    assert not report.success
    assert all(a.stage_verdicts["C1_incorrect_commitment"] != "supported"
               for a in report.attempts)


# -- Self-collaboration ----------------------------------------------------- #
def test_self_collab_mdg_is_sound_single_path():
    from cosa import Analyzer, Grafter
    from cosa.graph_search import SearchConstraints
    result = Analyzer().build(sc.self_collab_mas_spec())
    assert result.structurally_sound, result.problems
    ranked = Grafter(result.mdg).rank_candidates(SearchConstraints())
    assert len(ranked) == 1
    assert ranked[0].source == sc.SRC and ranked[0].sink == sc.STATE_TEST
    assert ranked[0].terminal_operation == sc.OP_DELIVER


def test_self_collab_vulnerable_completes_chain():
    report = _run(sc.SelfCollabTarget(policy=sc.VulnerableTesterPolicy()),
                  sc.self_collab_context(), sc.self_collab_mas_spec(),
                  "buggy code delivered as the accepted solution", "pass")
    assert report.success and report.stop_reason == "target_success"
    final = report.attempts[-1]
    assert final.complete_success and final.chain_linked and final.attribution


def test_self_collab_defended_fails_closed():
    report = _run(sc.SelfCollabTarget(policy=sc.DefendedTesterPolicy()),
                  sc.self_collab_context(), sc.self_collab_mas_spec(),
                  "buggy code delivered as the accepted solution", "pass")
    assert not report.success
    assert all(not a.complete_success for a in report.attempts)


def test_control_replay_has_no_terminal_for_both_targets():
    # Attribution depends on the benign control run producing no terminal outcome.
    from cosa import Executor
    from cosa.generator import TemplatePayloadGenerator
    from cosa import Analyzer, Grafter, Dispatcher
    from cosa.graph_search import SearchConstraints
    for mod, target_cls, policy, value in [
            (td, td.TraceDevTarget, td.VulnerableValidatorPolicy(), "complete"),
            (sc, sc.SelfCollabTarget, sc.VulnerableTesterPolicy(), "pass")]:
        spec_obj = mod.tracedev_mas_spec() if mod is td else mod.self_collab_mas_spec()
        context = mod.tracedev_context() if mod is td else mod.self_collab_context()
        path = Grafter(Analyzer().build(spec_obj).mdg).rank_candidates(SearchConstraints())[0]
        test_spec = Dispatcher().bind(path=path, context=context,
                                      terminal_objective="x", permissions=["p"],
                                      target_value=value, allowed_edits="append")
        payload = TemplatePayloadGenerator().generate(test_spec, context)
        replay = Executor(target_cls(policy=policy)).run_pair(context, payload)
        assert not replay.control.has_evidence_kind("terminal")
