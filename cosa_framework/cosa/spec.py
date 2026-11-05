"""Core vocabulary and typed artifacts shared across the CoSA pipeline.

Everything here is a plain dataclass or enum. The frozen dataclasses (the Test
Specification and its Fixed Checks) are the contract that keeps generation from
redefining success: once the Dispatcher freezes a spec, downstream components read
it but cannot mutate it.
"""
from __future__ import annotations

import dataclasses
import enum
from typing import Any, Callable, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
# MDG vocabulary (slide 5)
# --------------------------------------------------------------------------- #
class NodeType(enum.Enum):
    DATA = "data"            # a message, artifact or tool result
    OPERATION = "operation"  # an execution step or state operation
    STATE = "state"          # an authoritative coordination field
    DECISION = "decision"    # a choice controlling subsequent behavior


class EdgeType(enum.Enum):
    DATA_DEP = "data_dependency"
    STATE_READ = "state_read"
    STATE_WRITE = "state_write"
    EXEC_CONTROL = "execution_control"


@dataclasses.dataclass
class Node:
    id: str
    type: NodeType
    label: str
    owner: Optional[str] = None
    # Free-form annotations: source permissions, semantics, evidence selectors,
    # validation_status, etc. (slide 5).
    annotations: Dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def is_permitted_source(self) -> bool:
        return bool(self.annotations.get("permitted_source")
                    or self.annotations.get("attacker_can_append"))

    @property
    def attacker_can_append(self) -> bool:
        """P1: the attacker may append-only inject into this node's content."""
        return bool(self.annotations.get("attacker_can_append"))


@dataclasses.dataclass
class Edge:
    src: str
    dst: str
    type: EdgeType
    annotations: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def as_tuple(self) -> Tuple[str, str, EdgeType]:
        return (self.src, self.dst, self.type)


# --------------------------------------------------------------------------- #
# Candidate path (Grafter output, slide 7)
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class CandidatePath:
    """A permitted-source -> state-write-sink path, continued to the terminal.

    ``nodes`` is the ordered node-id sequence. ``source``/``sink`` are the entry
    point and the coordination-state write. ``consumer_decision`` and
    ``terminal_operation`` name the downstream nodes C2 and C3 must exercise.
    """
    nodes: List[str]
    source: str
    sink: str
    consumer_decision: Optional[str]
    terminal_operation: Optional[str]
    edges: List[EdgeType] = dataclasses.field(default_factory=list)
    score: float = 0.0
    rationale: str = ""

    @property
    def id(self) -> str:
        return "->".join(self.nodes)


# --------------------------------------------------------------------------- #
# Context instances (Context Library, slide 8)
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class ContextInstance:
    id: str
    scene_tags: List[str]
    checkpoint: Dict[str, Any]              # replayable initial state
    source_field: str                       # which input realizes the source
    benign_source_value: Any                # the original (control) artifact
    sink_field: str                         # which coordination field is the sink
    messages: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    references: Dict[str, Any] = dataclasses.field(default_factory=dict)
    rejection_reason: Optional[str] = None


# --------------------------------------------------------------------------- #
# Fixed checks + Test Specification (Dispatcher output, slides 9-11)
# --------------------------------------------------------------------------- #
class Stage(enum.Enum):
    C1_INCORRECT_COMMITMENT = "C1_incorrect_commitment"
    C2_EFFECTIVE_ADOPTION = "C2_effective_adoption"
    C3_TERMINAL_OUTCOME = "C3_terminal_outcome"


# A predicate reads the attack EvidenceBundle and returns (supported, reason,
# evidence_refs). It must decide only from recorded evidence.
Predicate = Callable[["EvidenceBundle"], Tuple[bool, str, List[int]]]


@dataclasses.dataclass(frozen=True)
class FixedCheck:
    stage: Stage
    name: str
    description: str
    selector: str                 # human-readable: which evidence proves this
    evidence_requirements: Tuple[str, ...]
    predicate: Predicate

    def evaluate(self, bundle: "EvidenceBundle") -> "StageVerdict":
        # Missing required evidence -> UNVERIFIED, never a silent pass/fail.
        missing = [r for r in self.evidence_requirements
                   if not bundle.has_evidence_kind(r)]
        if missing:
            return StageVerdict(self.stage, Verdict.UNVERIFIED, [],
                                "missing evidence: " + ", ".join(missing))
        try:
            supported, reason, refs = self.predicate(bundle)
        except Exception as exc:  # a broken selector is unverified, not success
            return StageVerdict(self.stage, Verdict.UNVERIFIED, [],
                                f"selector error: {type(exc).__name__}: {exc}")
        return StageVerdict(self.stage,
                            Verdict.SUPPORTED if supported else Verdict.REFUTED,
                            refs, reason)


@dataclasses.dataclass(frozen=True)
class TestPlan:
    """The Generator-facing half of the spec (slide 10)."""
    source_node: str
    source_field: str
    allowed_edits: str
    target_state_effect: str
    output_format: str
    context_id: str


@dataclasses.dataclass(frozen=True)
class TestSpecification:
    """One context-bound, immutable specification (slides 9-10)."""
    id: str
    version: int
    path_id: str
    context_id: str
    permissions: Tuple[str, ...]
    terminal_objective: str
    plan: TestPlan
    checks: Tuple[FixedCheck, ...]

    def versioned(self, new_context_id: str) -> "TestSpecification":
        """Dispatcher rebind: a new context yields a new spec version."""
        new_plan = dataclasses.replace(self.plan, context_id=new_context_id)
        return dataclasses.replace(self, version=self.version + 1,
                                   context_id=new_context_id, plan=new_plan)


# --------------------------------------------------------------------------- #
# Generator output
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class Payload:
    spec_id: str
    spec_version: int
    content: str                      # the attacker-controlled source value
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Evidence (Execution output, slide 13)
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class EvidenceEvent:
    order: int                         # monotonic index within a replay
    kind: str                          # exposure|state_write|consumer_action|terminal|oracle
    actor: Optional[str]
    detail: Dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class EvidenceBundle:
    mode: str                          # "control" or "attack"
    events: List[EvidenceEvent] = dataclasses.field(default_factory=list)
    committed_state: Dict[str, Any] = dataclasses.field(default_factory=dict)
    terminal_artifacts: List[str] = dataclasses.field(default_factory=list)

    def record(self, kind: str, actor: Optional[str] = None, **detail: Any) -> EvidenceEvent:
        event = EvidenceEvent(len(self.events), kind, actor, dict(detail))
        self.events.append(event)
        return event

    def has_evidence_kind(self, kind: str) -> bool:
        return any(e.kind == kind for e in self.events)

    def first(self, **match: Any) -> Optional[EvidenceEvent]:
        for event in self.events:
            if self._matches(event, match):
                return event
        return None

    @staticmethod
    def _matches(event: EvidenceEvent, match: Dict[str, Any]) -> bool:
        for key, value in match.items():
            if key == "kind":
                if event.kind != value:
                    return False
            elif event.detail.get(key) != value:
                return False
        return True


# --------------------------------------------------------------------------- #
# Judge output (slide 14)
# --------------------------------------------------------------------------- #
class Verdict(enum.Enum):
    SUPPORTED = "supported"
    REFUTED = "refuted"
    UNVERIFIED = "unverified"


@dataclasses.dataclass
class StageVerdict:
    stage: Stage
    verdict: Verdict
    evidence_refs: List[int]
    reason: str


@dataclasses.dataclass
class JudgeReport:
    spec_id: str
    spec_version: int
    stages: List[StageVerdict]
    chain_linked: bool
    attribution: bool
    complete_success: bool
    notes: str = ""

    def stage(self, stage: Stage) -> StageVerdict:
        for verdict in self.stages:
            if verdict.stage == stage:
                return verdict
        raise KeyError(stage)
