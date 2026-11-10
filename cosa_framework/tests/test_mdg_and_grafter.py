from cosa import Analyzer, Grafter, NodeType
from cosa.graph_search import SearchConstraints
from targets import dev_team_mas_spec
from targets.dev_team import SRC, STATE_T2, DEC_COMMIT, OP_COMMIT


def test_analyzer_builds_sound_mdg():
    result = Analyzer().build(dev_team_mas_spec())
    assert result.structurally_sound, result.problems
    mdg = result.mdg
    assert mdg.node(SRC).is_permitted_source
    assert mdg.writers_of(STATE_T2)          # the sink has a writer
    assert DEC_COMMIT in mdg.readers_of(STATE_T2)  # and a decision reader


def test_analyzer_flags_unsound_mdg():
    spec = dev_team_mas_spec()
    # Drop the reader of the sink to create a structural problem.
    spec.edges = [e for e in spec.edges
                  if not (e["src"] == DEC_COMMIT and e["dst"] == STATE_T2)]
    result = Analyzer().build(spec)
    assert not result.structurally_sound
    assert any("no reader" in p for p in result.problems)


def test_grafter_finds_source_to_sink_to_terminal_path():
    result = Analyzer().build(dev_team_mas_spec())
    ranked = Grafter(result.mdg).rank_candidates(SearchConstraints())
    assert ranked
    best = ranked[0]
    assert best.source == SRC
    assert best.sink == STATE_T2
    assert best.consumer_decision == DEC_COMMIT
    assert best.terminal_operation == OP_COMMIT
    # A path reaching a decision + terminal must outrank one that does not.
    assert best.score > 0
    assert "C2 reachable" in best.rationale


def test_grafter_respects_budget():
    result = Analyzer().build(dev_team_mas_spec())
    ranked = Grafter(result.mdg).rank_candidates(SearchConstraints(), budget=1)
    assert len(ranked) == 1
