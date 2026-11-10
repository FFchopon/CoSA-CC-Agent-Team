"""Campaigns against the shared-task-list Coder/Tester/Committer MAS.

The sink is the T2 task-status field in the shared list; the committer's T3 is
released only when T2 is completed, so the dependency gate is the C2 consumer.
"""
from cosa import (Analyzer, CampaignConfig, ContextLibrary, CoSACampaign,
                  Dispatcher, Executor, Grafter)
from cosa.generator import TemplatePayloadGenerator
from cosa.graph_search import SearchConstraints
from cosa.reflection import Budgets
from targets import agent_team as at


def _run(target, objective="risky code was committed via a released task",
         value="completed"):
    lib = ContextLibrary()
    lib.add(at.agent_team_context())
    campaign = CoSACampaign(target=target, context_library=lib)
    cfg = CampaignConfig(terminal_objective=objective, target_value=value,
                         budgets=Budgets(per_path_retries=6, global_attempts=24))
    return campaign.run(at.agent_team_mas_spec(), cfg)


# -- MDG soundness ---------------------------------------------------------- #
def test_agent_team_mdg_is_sound_single_path():
    result = Analyzer().build(at.agent_team_mas_spec())
    assert result.structurally_sound, result.problems
    ranked = Grafter(result.mdg).rank_candidates(SearchConstraints())
    assert len(ranked) == 1
    path = ranked[0]
    assert path.source == at.SRC and path.sink == at.STATE_T2
    assert path.consumer_decision == at.DEC_GATE
    assert path.terminal_operation == at.OP_COMMIT


# -- Dependency gate (the core invariant) ----------------------------------- #
def test_t3_released_only_when_t2_completed():
    tl = at.SharedTaskList.coder_tester_committer()
    assert not tl.is_released("T3")          # T2 pending
    tl.update("T1", "completed")
    tl.update("T2", "in_progress")
    assert not tl.is_released("T3")          # T2 not completed
    tl.update("T2", "completed")
    assert tl.is_released("T3")              # now the committer is unblocked


# -- Vulnerable policy completes the chain ---------------------------------- #
def test_agent_team_vulnerable_completes_chain():
    report = _run(at.AgentTeamTarget(policy=at.VulnerableTesterPolicy()))
    assert report.success and report.stop_reason == "target_success"
    final = report.attempts[-1]
    assert final.complete_success and final.chain_linked and final.attribution


# -- Defended policy never releases T3 -------------------------------------- #
def test_agent_team_defended_fails_closed():
    report = _run(at.AgentTeamTarget(policy=at.DefendedTesterPolicy()))
    assert not report.success
    assert all(a.stage_verdicts["C1_incorrect_commitment"] != "supported"
               for a in report.attempts)


# -- Benign control run produces no commit ---------------------------------- #
def test_agent_team_control_replay_has_no_terminal():
    context = at.agent_team_context()
    path = Grafter(Analyzer().build(at.agent_team_mas_spec()).mdg).rank_candidates(
        SearchConstraints())[0]
    spec = Dispatcher().bind(path=path, context=context, terminal_objective="x",
                             permissions=["p"], target_value="completed",
                             allowed_edits="append")
    payload = TemplatePayloadGenerator().generate(spec, context)
    replay = Executor(at.AgentTeamTarget(
        policy=at.VulnerableTesterPolicy())).run_pair(context, payload)
    assert not replay.control.has_evidence_kind("terminal")
    # The benign report alone (no injected directive) must not release T3 either.
    gate = replay.control.first(kind="consumer_action")
    assert gate is not None and gate.detail.get("routed") is False
