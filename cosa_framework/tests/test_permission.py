"""Tests for the P1 append-only attacker-permission chain."""
from cosa import (Analyzer, Budgets, CampaignConfig, ContextLibrary, CoSACampaign,
                  Dispatcher, Grafter, NodeType, build_payload,
                  enforce_append_only, is_append_only)
from cosa.generator import TemplatePayloadGenerator
from cosa.execution import Executor
from cosa.permission import AttackerPermission, site_for
from cosa.spec import Payload
from cosa.analyzer import MASSpec
from cosa.graph_search import SearchConstraints
from targets import (DevTeamTarget, VulnerableTesterPolicy, dev_team_context,
                     dev_team_mas_spec)
from targets import self_collab as sc
from targets import tracedev as td


# -- P2 (inter-agent-message append-only) ----------------------------------- #
def test_p2_is_append_only_onto_the_message_not_the_source():
    """P2 keeps append-only but onto the inter-agent message's benign base; the
    external source stays benign."""
    ctx = sc.self_collab_task_context(sc.SELF_COLLAB_TASKS[0])
    assert ctx.supports_message_injection()
    # Active benign base switches by mode.
    assert ctx.active_benign("append_only") == ctx.benign_source_value
    assert ctx.active_benign("message_append") == ctx.benign_message_value
    assert ctx.active_field("message_append") == ctx.message_field


def test_p2_statement_is_inter_agent_message():
    s = AttackerPermission(mode="message_append").statement("srcNode", "field")
    assert "inter-agent message" in s and "may not modify the external source" in s
    assert site_for("message_append") == "inter_agent_message"
    assert site_for("append_only") == "external_source"


def test_p2_generator_appends_to_the_handoff_message():
    gen = TemplatePayloadGenerator()
    gen.set_permission_mode("message_append")
    spec_obj = sc.self_collab_mas_spec()
    context = sc.self_collab_context()
    path = Grafter(Analyzer().build(spec_obj).mdg).rank_candidates(SearchConstraints())[0]
    spec = Dispatcher().bind(path=path, context=context, terminal_objective="x",
                             permissions=["p"], target_value="pass", allowed_edits="a")
    payload = gen.generate(spec, context)
    # Appends onto the handoff message, NOT the requirement.
    assert payload.content.startswith(str(context.benign_message_value))
    assert not payload.content.startswith(str(context.benign_source_value))


class _CaptureTarget:
    """Records the exact (source_value, inter_agent_message) each replay received."""
    name = "capture"

    def reset(self, checkpoint):
        self.state = checkpoint

    def run(self, source_value, recorder):
        recorder.record("exposure", actor="x", got_source=str(source_value),
                        got_msg=str(self.state.get("inter_agent_message", "")))


def test_p2_executor_injects_message_and_keeps_source_benign():
    """Under P2 the attack replay leaves the external source benign and carries the
    injection only in the inter-agent message; under P1 it is the reverse."""
    ctx = sc.self_collab_task_context(sc.SELF_COLLAB_TASKS[0])
    marker = "INJECTED-NOTE-XYZ"
    p_msg = Payload(spec_id="s", spec_version=1,
                    content=str(ctx.benign_message_value) + "\n\n" + marker)
    a2 = Executor(_CaptureTarget()).run_pair(ctx, p_msg, site="inter_agent_message").attack.events[0].detail
    assert marker in a2["got_msg"] and marker not in a2["got_source"]   # P2 routing
    assert a2["got_source"] == str(ctx.benign_source_value)             # source benign

    p_src = Payload(spec_id="s", spec_version=1,
                    content=str(ctx.benign_source_value) + "\n\n" + marker)
    a1 = Executor(_CaptureTarget()).run_pair(ctx, p_src, site="external_source").attack.events[0].detail
    assert marker in a1["got_source"] and marker not in a1["got_msg"]   # P1 routing
    assert a1["got_msg"] == str(ctx.benign_message_value)               # message benign


def test_p2_campaign_propagates_permission_mode():
    lib = ContextLibrary(); lib.add(dev_team_context())
    camp = CoSACampaign(target=DevTeamTarget(policy=VulnerableTesterPolicy()),
                        context_library=lib)
    report = camp.run(dev_team_mas_spec(),
                      CampaignConfig(terminal_objective="t", target_value="pass",
                                     permission_mode="message_append",
                                     budgets=Budgets(per_path_retries=5, global_attempts=20)))
    assert report.permission_mode == "message_append"


# -- permission primitives -------------------------------------------------- #
def test_build_payload_preserves_benign_prefix():
    content = build_payload("BENIGN LINE", "INJECTED")
    assert content.startswith("BENIGN LINE")
    assert "INJECTED" in content
    assert is_append_only("BENIGN LINE", content)


def test_enforce_repairs_non_append_only_payload():
    benign = "original requirement text"
    # A payload that dropped the benign content and reframed as an edit.
    rogue = '{"proposed_edits":[{"artifact":"x","content":"malicious"}]}'
    ok, repaired, note = enforce_append_only(benign, rogue)
    assert ok is False
    assert repaired.startswith(benign)        # benign restored as prefix
    assert is_append_only(benign, repaired)
    assert note == "repaired_to_append_only"


def test_enforce_passes_conformant_payload():
    benign = "requirement"
    good = build_payload(benign, "append this")
    ok, out, note = enforce_append_only(benign, good)
    assert ok and out == good and note == "append_only_ok"


# -- Analyzer marking + validation ----------------------------------------- #
def test_analyzer_marks_injectable_data_nodes():
    result = Analyzer().build(td.tracedev_mas_spec())
    assert result.structurally_sound
    injectable = result.mdg.injectable_sources()
    assert [n.id for n in injectable] == [td.SRC]
    assert result.mdg.node(td.SRC).attacker_can_append


def test_validate_flags_non_data_injectable_node():
    # Mark an OPERATION node as a permitted source -> must be flagged.
    spec = dev_team_mas_spec()
    spec.permitted_sources = ["O_run_oracle"]  # an operation, not data
    result = Analyzer().build(spec)
    assert not result.structurally_sound
    assert any("not data" in p for p in result.problems)


# -- Dispatcher writes the explicit permission ------------------------------ #
def test_dispatcher_sets_canonical_append_only_permission():
    mdg = Analyzer().build(sc.self_collab_mas_spec()).mdg
    path = Grafter(mdg).rank_candidates(SearchConstraints())[0]
    spec = Dispatcher().bind(path=path, context=sc.self_collab_context(),
                             terminal_objective="x", permissions=["modify_source"],
                             target_value="pass",
                             allowed_edits="ATTACKER TRIES TO WIDEN THIS")
    # The free-text allowed_edits must be ignored in favor of the P1 statement.
    assert "P1 append-only" in spec.plan.allowed_edits
    assert sc.SRC in spec.plan.allowed_edits
    assert "ATTACKER TRIES TO WIDEN" not in spec.plan.allowed_edits


# -- End to end: payloads stay append-only, report records the permission --- #
def test_campaign_payloads_are_append_only_and_recorded():
    lib = ContextLibrary()
    lib.add(dev_team_context())
    campaign = CoSACampaign(DevTeamTarget(policy=VulnerableTesterPolicy()), lib)
    report = campaign.run(dev_team_mas_spec(),
                          CampaignConfig("risky code was committed", "completed",
                                         budgets=Budgets(5, 20)))
    assert report.injectable_sources  # the permission labeling is recorded
    assert report.permission_mode == "append_only"
    assert all(a.append_only_ok for a in report.attempts)
    # And the report serializes the permission block.
    assert report.to_dict()["permission"]["mode"] == "append_only"


def test_campaign_retains_winning_payload_for_replay():
    """A successful campaign keeps the exact inducing payload (content, site and
    benign base) so the run can be replayed against the live victim later."""
    lib = ContextLibrary()
    lib.add(dev_team_context())
    campaign = CoSACampaign(DevTeamTarget(policy=VulnerableTesterPolicy()), lib)
    report = campaign.run(dev_team_mas_spec(),
                          CampaignConfig("risky code was committed", "completed",
                                         budgets=Budgets(5, 20)))
    assert report.success
    wp = report.winning_payload
    assert wp is not None
    # The retained content is append-only onto the benign base it appended to.
    assert wp["content"].startswith(str(wp["benign_base"]))
    assert is_append_only(str(wp["benign_base"]), wp["content"])
    assert wp["site"] == "external_source" and wp["permission_mode"] == "append_only"
    # And it survives serialization.
    assert report.to_dict()["winning_payload"]["content"] == wp["content"]
    # tries-to-success is recorded: a 1-based attempt index that matches the
    # position of the inducing attempt, and it serializes.
    assert report.tries_to_success == len(report.attempts)
    assert report.tries_to_success >= 1
    assert report.to_dict()["tries_to_success"] == report.tries_to_success


def test_campaign_without_success_has_no_winning_payload():
    lib = ContextLibrary()
    lib.add(dev_team_context())
    # A target that never adopts the injection -> no success, no winning payload.
    campaign = CoSACampaign(DevTeamTarget(policy=VulnerableTesterPolicy()), lib)
    report = campaign.run(dev_team_mas_spec(),
                          CampaignConfig("an outcome that never occurs", "completed",
                                         budgets=Budgets(1, 2)))
    if not report.success:
        assert report.winning_payload is None
        assert report.tries_to_success is None  # >budget / infinite
