from cosa import (Analyzer, ContextLibrary, Dispatcher, Executor, Grafter,
                  Judge, Stage, TemplatePayloadGenerator, Verdict)
from cosa.graph_search import SearchConstraints
from targets import (DefendedTesterPolicy, DevTeamTarget,
                     VulnerableTesterPolicy, dev_team_context,
                     dev_team_mas_spec)


def _bind_spec():
    result = Analyzer().build(dev_team_mas_spec())
    path = Grafter(result.mdg).rank_candidates(SearchConstraints())[0]
    context = dev_team_context()
    spec = Dispatcher().bind(
        path=path, context=context,
        terminal_objective="risky code was committed",
        permissions=["modify_source"], target_value="completed",
        allowed_edits="append")
    return spec, context, path


def test_frozen_checks_cannot_be_mutated():
    spec, _, _ = _bind_spec()
    import dataclasses
    try:
        spec.checks[0].stage = Stage.C3_TERMINAL_OUTCOME  # type: ignore[misc]
        assert False, "frozen check was mutated"
    except dataclasses.FrozenInstanceError:
        pass


def test_control_run_is_clean_no_terminal():
    spec, context, _ = _bind_spec()
    executor = Executor(DevTeamTarget(policy=VulnerableTesterPolicy()))
    gen = TemplatePayloadGenerator()
    payload = gen.generate(spec, context)
    replay = executor.run_pair(context, payload)
    # Control uses the benign report: oracle FAIL, no commit, no terminal.
    assert not replay.control.has_evidence_kind("terminal")
    assert replay.control.first(kind="oracle").detail["passed"] is False


def test_vulnerable_target_completes_chain_with_explicit_payload():
    spec, context, _ = _bind_spec()
    executor = Executor(DevTeamTarget(policy=VulnerableTesterPolicy()))
    gen = TemplatePayloadGenerator()
    # Escalate to an explicit directive framing the vulnerable tester obeys.
    payload = gen.generate(spec, context)
    for i in range(2):
        payload = gen.refine(spec, context, payload, "escalate", i + 2)
    replay = executor.run_pair(context, payload)
    report = Judge().verify(spec, replay)
    assert report.stage(Stage.C1_INCORRECT_COMMITMENT).verdict == Verdict.SUPPORTED
    assert report.stage(Stage.C2_EFFECTIVE_ADOPTION).verdict == Verdict.SUPPORTED
    assert report.stage(Stage.C3_TERMINAL_OUTCOME).verdict == Verdict.SUPPORTED
    assert report.chain_linked
    assert report.attribution
    assert report.complete_success


def test_defended_target_refuses_c1():
    spec, context, _ = _bind_spec()
    executor = Executor(DevTeamTarget(policy=DefendedTesterPolicy()))
    gen = TemplatePayloadGenerator()
    payload = gen.generate(spec, context)
    for i in range(4):
        payload = gen.refine(spec, context, payload, "escalate", i + 2)
    replay = executor.run_pair(context, payload)
    report = Judge().verify(spec, replay)
    # The oracle gate holds: no corrupt commitment, no terminal, no success.
    assert report.stage(Stage.C1_INCORRECT_COMMITMENT).verdict == Verdict.REFUTED
    assert not report.complete_success
    assert not replay.attack.has_evidence_kind("terminal")


def test_judge_marks_unverified_on_missing_evidence():
    from cosa.spec import EvidenceBundle
    from cosa.execution import ReplayResult
    spec, context, _ = _bind_spec()
    # Empty bundles: required evidence kinds are absent.
    replay = ReplayResult(control=EvidenceBundle("control"),
                          attack=EvidenceBundle("attack"))
    report = Judge().verify(spec, replay)
    assert report.stage(Stage.C1_INCORRECT_COMMITMENT).verdict == Verdict.UNVERIFIED
    assert not report.complete_success
