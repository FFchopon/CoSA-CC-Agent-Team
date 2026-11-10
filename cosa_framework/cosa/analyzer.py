"""Analyzer: build a MAS Dependency Graph from a declarative MAS specification.

The input ``MASSpec`` is the "MAS specification and available implementation
information" from slide 4: a declarative description of coordination states,
operations, decisions and the edges among them. The Analyzer materializes it into
an :class:`MDG`, marks permitted sources, and runs structural validation so that
MDG accuracy is an explicit, inspectable property rather than an assumption.
"""
from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Optional

from .mdg import MDG
from .spec import Edge, EdgeType, Node, NodeType


@dataclasses.dataclass
class MASSpec:
    """Declarative description of a target MAS.

    ``nodes``: list of dicts {id, type, label, owner?, annotations?}.
    ``edges``: list of dicts {src, dst, type}.
    ``permitted_sources``: node ids the attacker may modify.
    """
    name: str
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    permitted_sources: List[str] = dataclasses.field(default_factory=list)
    terminal_objective: str = ""
    # Optional raw MAS description/source. When ``nodes`` is empty and ``source``
    # is set, an LLM Analyzer can derive the MDG from this text.
    source: str = ""


@dataclasses.dataclass
class AnalyzerResult:
    mdg: MDG
    problems: List[str]

    @property
    def structurally_sound(self) -> bool:
        return not self.problems


class Analyzer:
    def build(self, spec: MASSpec) -> AnalyzerResult:
        mdg = MDG()
        for raw in spec.nodes:
            annotations = dict(raw.get("annotations", {}))
            node = Node(
                id=raw["id"],
                type=NodeType(raw["type"]) if not isinstance(raw["type"], NodeType) else raw["type"],
                label=raw.get("label", raw["id"]),
                owner=raw.get("owner"),
                annotations=annotations,
            )
            if node.id in spec.permitted_sources:
                # P1: mark the external-resource data node as attacker-injectable.
                node.annotations["permitted_source"] = True
                node.annotations.setdefault("attacker_can_append", True)
            mdg.add_node(node)

        for raw in spec.edges:
            edge_type = raw["type"]
            if not isinstance(edge_type, EdgeType):
                edge_type = EdgeType(edge_type)
            mdg.add_edge(Edge(src=raw["src"], dst=raw["dst"], type=edge_type,
                              annotations=dict(raw.get("annotations", {}))))

        problems = mdg.validate()
        return AnalyzerResult(mdg=mdg, problems=problems)
