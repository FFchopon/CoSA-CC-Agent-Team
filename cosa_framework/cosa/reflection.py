"""Evidence-driven reflection: diagnose a run and route the next action (slide 15).

The controller does not retry blindly. It reads the Judge report and the attack
evidence, diagnoses *why* the chain did not complete, and chooses the next action
that the diagnosis warrants:

  * payload read but no corrupt write          -> refine the payload
  * corrupt write but no consumer adoption      -> select another source->sink path
  * path/context mismatch (source never read)   -> rebind context, version the spec
  * ambiguous evidence                          -> collect diagnostics, stay UNVERIFIED
  * complete linked chain                        -> stop, success

Routing is bounded by a per-path retry budget and a global attempt budget; when
either is exhausted the controller stops with the best retained verdict.
"""
from __future__ import annotations

import dataclasses
import enum

from .spec import EvidenceBundle, JudgeReport, Stage, Verdict


class Action(enum.Enum):
    STOP_SUCCESS = "stop_success"
    REFINE_PAYLOAD = "refine_payload"
    SELECT_NEW_PATH = "select_new_path"
    REBIND_CONTEXT = "rebind_context"
    COLLECT_DIAGNOSTICS = "collect_diagnostics"
    STOP_BUDGET = "stop_budget"


@dataclasses.dataclass
class Budgets:
    per_path_retries: int = 4      # payload refinements / context rebinds per path
    global_attempts: int = 20      # total replays across all paths


@dataclasses.dataclass
class Decision:
    action: Action
    diagnosis: str


class Reflector:
    def __init__(self, exhaust_payload: bool = False) -> None:
        # When True, keep refining the payload within the per-path budget instead
        # of pivoting to another path early — so a diverse payload search runs to
        # completion before a path is abandoned (useful with one injectable path).
        self.exhaust_payload = exhaust_payload

    def decide(self, report: JudgeReport, attack: EvidenceBundle,
               retries_used: int, budgets: Budgets,
               context_rebound: bool) -> Decision:
        if report.complete_success:
            return Decision(Action.STOP_SUCCESS, "complete linked chain observed")

        if retries_used >= budgets.per_path_retries:
            return Decision(Action.SELECT_NEW_PATH,
                            "per-path retry budget exhausted; try another path")

        c1 = report.stage(Stage.C1_INCORRECT_COMMITMENT)
        c2 = report.stage(Stage.C2_EFFECTIVE_ADOPTION)

        source_read = attack.has_evidence_kind("exposure")

        # Path/context mismatch: the consumer never even read the source.
        if not source_read and not context_rebound:
            return Decision(Action.REBIND_CONTEXT,
                            "source was never read; path and context do not align")

        # Incorrect write with no later consequence -> the sink is a dead end here.
        if c1.verdict == Verdict.SUPPORTED and c2.verdict != Verdict.SUPPORTED:
            if self.exhaust_payload:
                return Decision(Action.REFINE_PAYLOAD,
                                "sink corrupted but not adopted; keep searching "
                                "payloads on this path")
            return Decision(Action.SELECT_NEW_PATH,
                            "sink corrupted but no consumer adopted it; "
                            "select another source->sink path")

        # Source read but no corrupt commitment -> the payload is inadequate.
        if source_read and c1.verdict != Verdict.SUPPORTED:
            return Decision(Action.REFINE_PAYLOAD,
                            "source read but no corrupt commitment; refine the payload")

        # Evidence cannot distinguish causes.
        if any(s.verdict == Verdict.UNVERIFIED for s in report.stages):
            return Decision(Action.COLLECT_DIAGNOSTICS,
                            "evidence cannot distinguish causes; retain UNVERIFIED")

        return Decision(Action.REFINE_PAYLOAD, "default: refine the payload")
