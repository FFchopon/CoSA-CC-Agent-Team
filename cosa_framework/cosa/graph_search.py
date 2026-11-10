"""GraphSearchTool: constrained structural traversal over the MDG (slide 7).

This is the *tool* half of the Grafter step. It does pure structural work:
enumerate paths that start at a permitted source, reach a coordination-state write
(the sink), and continue to the decision that consumes that state and the terminal
operation it controls. It applies source, permission and path-length constraints
during traversal and returns inspectable candidate paths. Semantic interpretation
and ranking are the Grafter's job, not this tool's.
"""
from __future__ import annotations

import dataclasses
from typing import List, Optional

from .mdg import MDG
from .spec import CandidatePath, EdgeType, NodeType


@dataclasses.dataclass
class SearchConstraints:
    max_path_length: int = 8          # bounds the search (budget, slide 7)
    allowed_sources: Optional[List[str]] = None  # restrict to these source ids
    require_terminal: bool = True     # the path must reach a terminal operation


class GraphSearchTool:
    def __init__(self, mdg: MDG) -> None:
        self.mdg = mdg

    def find_candidate_paths(self, constraints: SearchConstraints) -> List[CandidatePath]:
        # P1: only attacker-injectable external-resource DATA nodes are sources.
        sources = self.mdg.injectable_sources()
        if constraints.allowed_sources is not None:
            allowed = set(constraints.allowed_sources)
            sources = [n for n in sources if n.id in allowed]

        candidates: List[CandidatePath] = []
        for source in sources:
            for state in self.mdg.nodes_of_type(NodeType.STATE):
                # structural path from source to a write of this state
                to_sink = self._path_to_state_write(
                    source.id, state.id, constraints.max_path_length)
                if to_sink is None:
                    continue
                prefix_nodes, prefix_edges, writer_op = to_sink
                consumer, terminal = self._consumer_and_terminal(state.id)
                if constraints.require_terminal and terminal is None:
                    continue
                nodes = prefix_nodes + [state.id]
                edges = list(prefix_edges)
                if consumer is not None:
                    nodes.append(consumer)
                    edges.append(EdgeType.STATE_READ)
                if terminal is not None:
                    nodes.append(terminal)
                    edges.append(EdgeType.EXEC_CONTROL)
                candidates.append(CandidatePath(
                    nodes=nodes, source=source.id, sink=state.id,
                    consumer_decision=consumer, terminal_operation=terminal,
                    edges=edges))
        return candidates

    # -- internals ---------------------------------------------------------- #
    def _path_to_state_write(self, source: str, state: str, max_len: int):
        """BFS from source to any OPERATION that STATE_WRITEs into ``state``.

        Returns (node_ids_up_to_and_including_writer, edge_types, writer_id) or
        None. Traversal follows DATA_DEP and EXEC_CONTROL edges to reach the
        writing operation, then requires a STATE_WRITE edge into the sink.
        """
        writers = set(self.mdg.writers_of(state))
        if not writers:
            return None
        # BFS over non-state-write edges to reach a writer operation.
        queue = [(source, [source], [])]
        visited = {source}
        while queue:
            current, path_nodes, path_edges = queue.pop(0)
            if len(path_nodes) > max_len:
                continue
            if current in writers:
                return (path_nodes, path_edges, current)
            for edge in self.mdg.out_edges(current):
                if edge.type == EdgeType.STATE_WRITE:
                    continue  # the write into the sink is handled by the check above
                if edge.dst in visited:
                    continue
                visited.add(edge.dst)
                queue.append((edge.dst, path_nodes + [edge.dst],
                              path_edges + [edge.type]))
        return None

    def _consumer_and_terminal(self, state: str):
        """Find a DECISION that reads the sink state, and the operation it controls."""
        readers = self.mdg.readers_of(state)
        for reader in readers:
            node = self.mdg.node(reader)
            if node.type != NodeType.DECISION:
                continue
            controlled = self.mdg.out_edges(reader, EdgeType.EXEC_CONTROL)
            terminal = controlled[0].dst if controlled else None
            return reader, terminal
        # No decision consumer; report the first reader (weaker path).
        if readers:
            return readers[0], None
        return None, None
