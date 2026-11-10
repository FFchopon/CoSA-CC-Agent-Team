"""Grafter: interpret and rank candidate source->sink paths (slide 7).

The graph-search tool returns structurally valid candidates. The Grafter adds the
semantic layer: it relates each candidate's consumer decision to the terminal
objective, scores how directly the sink propagates to that objective, and ranks
candidates under the search budget so the Dispatcher works the most promising path
first. Scoring is deterministic and explainable (every candidate carries a
rationale) so ranking decisions are auditable.
"""
from __future__ import annotations

from typing import List, Optional

from .graph_search import GraphSearchTool, SearchConstraints
from .mdg import MDG
from .spec import CandidatePath, NodeType


class Grafter:
    def __init__(self, mdg: MDG) -> None:
        self.mdg = mdg
        self.tool = GraphSearchTool(mdg)

    def rank_candidates(self, constraints: Optional[SearchConstraints] = None,
                        budget: Optional[int] = None) -> List[CandidatePath]:
        constraints = constraints or SearchConstraints()
        candidates = self.tool.find_candidate_paths(constraints)
        for candidate in candidates:
            candidate.score, candidate.rationale = self._score(candidate)
        candidates.sort(key=lambda c: (-c.score, len(c.nodes), c.id))
        if budget is not None:
            candidates = candidates[:budget]
        return candidates

    def _score(self, candidate: CandidatePath):
        """Higher is more promising. Deterministic and explainable."""
        score = 0.0
        reasons = []

        # A path that reaches a decision consumer can satisfy C2.
        if candidate.consumer_decision is not None:
            score += 3.0
            reasons.append("sink is read by a decision (C2 reachable)")
        else:
            reasons.append("no decision consumer (C2 unreachable)")

        # A path that reaches a terminal operation can satisfy C3.
        if candidate.terminal_operation is not None:
            score += 3.0
            reasons.append("decision controls a terminal operation (C3 reachable)")
        else:
            reasons.append("no terminal operation (C3 unreachable)")

        # Shorter propagation from sink to terminal is preferred.
        propagation = max(0, len(candidate.nodes) - candidate.nodes.index(candidate.sink) - 1)
        score += max(0.0, 2.0 - 0.5 * propagation)
        reasons.append(f"propagation length from sink = {propagation}")

        # Prefer sinks owned by / read across a trust boundary (more than one reader).
        readers = self.mdg.readers_of(candidate.sink)
        if len(readers) >= 1:
            score += 0.5 * min(len(readers), 2)
            reasons.append(f"{len(readers)} reader(s) of sink")

        # Penalize a sink whose writer consumes a TRUSTED input that already
        # encodes the ground truth the attack must contradict: the deciding agent
        # holds an authoritative counter-signal the attacker cannot reach, so the
        # path is weak by construction. Annotate the STATE node (or its writer op)
        # with ``writer_trusted_contradiction: True`` to mark this.
        if self._writer_has_trusted_contradiction(candidate.sink):
            score -= 2.5
            reasons.append("sink writer holds a trusted contradiction (weak path)")

        # Shorter total structural path breaks ties toward simpler attacks.
        score += max(0.0, 1.0 - 0.1 * len(candidate.nodes))
        return score, "; ".join(reasons)

    def _writer_has_trusted_contradiction(self, sink_id: str) -> bool:
        """True if the sink's STATE node, or any operation that writes it, is
        annotated ``writer_trusted_contradiction``. Absent annotation -> False
        (no penalty), so existing specs are unaffected."""
        try:
            if self.mdg.node(sink_id).annotations.get("writer_trusted_contradiction"):
                return True
        except KeyError:
            return False
        return any(self.mdg.node(w).annotations.get("writer_trusted_contradiction")
                   for w in self.mdg.writers_of(sink_id))
