"""Tests for the P1 append-only attacker-permission chain."""
from cosa import (Analyzer, Budgets, CampaignConfig, ContextLibrary, CoSACampaign,
                  Dispatcher, Grafter, NodeType, build_payload,
                  enforce_append_only, is_append_only)
from cosa.analyzer import MASSpec
from cosa.graph_search import SearchConstraints
from targets import (DevTeamTarget, VulnerableTesterPolicy, dev_team_context,
                     dev_team_mas_spec)
from targets import self_collab as sc
from targets import tracedev as td


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
