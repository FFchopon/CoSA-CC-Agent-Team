"""The MAS Dependency Graph (MDG) and its structural operations.

The MDG is the shared structural model the whole pipeline reasons over. It holds
the four node types and four edge types from the method, supports the queries the
Grafter's graph-search tool needs, and validates the structural invariants that
keep an inaccurate graph from silently producing bogus candidate paths.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Set

from .spec import Edge, EdgeType, Node, NodeType


class MDG:
    def __init__(self) -> None:
        self._nodes: Dict[str, Node] = {}
        self._edges: List[Edge] = []
        # adjacency keyed by src for fast traversal
        self._out: Dict[str, List[Edge]] = {}

    # -- construction ------------------------------------------------------- #
    def add_node(self, node: Node) -> Node:
        if node.id in self._nodes:
            raise ValueError(f"duplicate node id: {node.id}")
        self._nodes[node.id] = node
        self._out.setdefault(node.id, [])
        return node

    def add_edge(self, edge: Edge) -> Edge:
        if edge.src not in self._nodes or edge.dst not in self._nodes:
            raise ValueError(f"edge references unknown node: {edge.as_tuple()}")
        self._edges.append(edge)
        self._out.setdefault(edge.src, []).append(edge)
        return edge

    # -- access ------------------------------------------------------------- #
    def node(self, node_id: str) -> Node:
        return self._nodes[node_id]

    @property
    def nodes(self) -> List[Node]:
        return list(self._nodes.values())

    @property
    def edges(self) -> List[Edge]:
        return list(self._edges)

    def nodes_of_type(self, node_type: NodeType) -> List[Node]:
        return [n for n in self._nodes.values() if n.type == node_type]

    def permitted_sources(self) -> List[Node]:
        return [n for n in self._nodes.values() if n.is_permitted_source]

    def out_edges(self, node_id: str, edge_type: Optional[EdgeType] = None) -> List[Edge]:
        edges = self._out.get(node_id, [])
        if edge_type is None:
            return list(edges)
        return [e for e in edges if e.type == edge_type]

    def writers_of(self, state_id: str) -> List[str]:
        """Operations that STATE_WRITE into ``state_id``."""
        return [e.src for e in self._edges
                if e.type == EdgeType.STATE_WRITE and e.dst == state_id]

    def readers_of(self, state_id: str) -> List[str]:
        """Nodes that STATE_READ from ``state_id``."""
        return [e.src for e in self._edges
                if e.type == EdgeType.STATE_READ and e.dst == state_id]

    # -- traversal ---------------------------------------------------------- #
    def successors(self, node_id: str, edge_type: Optional[EdgeType] = None) -> List[str]:
        return [e.dst for e in self.out_edges(node_id, edge_type)]

    def reachable(self, start: str, edge_types: Optional[Iterable[EdgeType]] = None) -> Set[str]:
        allowed = set(edge_types) if edge_types is not None else None
        seen: Set[str] = set()
        stack = [start]
        while stack:
            current = stack.pop()
            for edge in self.out_edges(current):
                if allowed is not None and edge.type not in allowed:
                    continue
                if edge.dst not in seen:
                    seen.add(edge.dst)
                    stack.append(edge.dst)
        return seen

    # -- validation (addresses the slide-4 "MDG accuracy" open issue) ------- #
    def validate(self) -> List[str]:
        """Return a list of structural problems; empty means structurally sound.

        The annotations are advisory, but these invariants must hold for a path
        search to be meaningful:
          * every STATE has at least one writer and at least one reader;
          * every DECISION reads at least one STATE or DATA input;
          * at least one node is marked as a permitted source.
        Nodes failing a check are annotated with validation_status for transparency.
        """
        problems: List[str] = []
        for node in self._nodes.values():
            node.annotations.setdefault("validation_status", "ok")

        for state in self.nodes_of_type(NodeType.STATE):
            if not self.writers_of(state.id):
                problems.append(f"STATE {state.id} has no writer")
                state.annotations["validation_status"] = "no_writer"
            if not self.readers_of(state.id):
                problems.append(f"STATE {state.id} has no reader")
                status = state.annotations.get("validation_status", "ok")
                state.annotations["validation_status"] = (
                    "no_writer_no_reader" if status == "no_writer" else "no_reader")

        for decision in self.nodes_of_type(NodeType.DECISION):
            # A decision reads either via an outgoing STATE_READ edge
            # (decision -> state) or an incoming DATA_DEP edge (data -> decision).
            state_reads = self.out_edges(decision.id, EdgeType.STATE_READ)
            data_deps = [e for e in self._edges if e.dst == decision.id
                         and e.type == EdgeType.DATA_DEP]
            if not state_reads and not data_deps:
                problems.append(f"DECISION {decision.id} reads no STATE or DATA")
                decision.annotations["validation_status"] = "no_input"

        if not self.permitted_sources():
            problems.append("no permitted source node is marked")

        # P1 permission labeling: an attacker-injectable node must be a DATA node
        # (external-resource content), never an operation/state/decision. This
        # keeps the injection point a true external input, not an internal write.
        for node in self.permitted_sources():
            if node.type != NodeType.DATA:
                problems.append(
                    f"attacker-injectable node {node.id} is {node.type.value}, "
                    f"not data (P1 injects into external-resource data only)")
                node.annotations["validation_status"] = "injectable_non_data"
        return problems

    def injectable_sources(self) -> List[Node]:
        """P1 sources: attacker-injectable DATA nodes."""
        return [n for n in self.permitted_sources() if n.type == NodeType.DATA]

    # -- serialization ------------------------------------------------------ #
    def to_dict(self) -> Dict[str, object]:
        return {
            "nodes": [
                {"id": n.id, "type": n.type.value, "label": n.label,
                 "owner": n.owner, "annotations": n.annotations}
                for n in self._nodes.values()
            ],
            "edges": [
                {"src": e.src, "dst": e.dst, "type": e.type.value,
                 "annotations": e.annotations}
                for e in self._edges
            ],
        }
