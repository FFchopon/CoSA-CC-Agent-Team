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
from typing import Optional

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
    # For REFINE_PAYLOAD under adaptive allocation: True = keep climbing the SAME
    # attack vector (it is making stage progress), False = switch to a fresh
    # vector (it has stalled), None = let the Generator decide with its own
    # fixed counter (non-adaptive, backward-compatible). This is the ONLY signal
    # the controller sends the Generator about the oracle-derived stage progress;
    # the Generator never sees the Judge verdicts themselves.
    hold_vector: Optional[bool] = None


class Reflector:
    def __init__(self, exhaust_payload: bool = False, adaptive: bool = False,
                 patience: int = 2, max_vector_tries: int = 5) -> None:
        # When True, keep refining the payload within the per-path budget instead
        # of pivoting to another path early — so a diverse payload search runs to
        # completion before a path is abandoned (useful with one injectable path).
        self.exhaust_payload = exhaust_payload
        # Adaptive (bandit-style) budget allocation. The total attempt budget is
        # unchanged; it is only REDISTRIBUTED within a path: a vector that makes
        # stage progress earns more hill-climbs, a stalled one is cut early so its
        # budget flows to the next vector. The decision uses the Judge report
        # (which the controller may see); the Generator only receives hold_vector.
        self.adaptive = adaptive
        self.patience = max(1, patience)              # stalled climbs before switch
        self.max_vector_tries = max(2, max_vector_tries)  # hard ceiling per vector
        self._reset_vector()

    def _reset_vector(self) -> None:
        self._v_tries = 0        # executions seen on the current vector
        self._v_best_depth = -1  # best leading-SUPPORTED stage depth it reached
        self._v_stall = 0        # consecutive climbs with no new progress

    @staticmethod
    def _stage_depth(report: JudgeReport) -> int:
        """Number of leading stages SUPPORTED (0..3): how far the chain got."""
        depth = 0
        for st in (Stage.C1_INCORRECT_COMMITMENT, Stage.C2_EFFECTIVE_ADOPTION,
                   Stage.C3_TERMINAL_OUTCOME):
            if report.stage(st).verdict == Verdict.SUPPORTED:
                depth += 1
            else:
                break
        return depth

    def _adaptive_refine(self, report: JudgeReport) -> Decision:
        """Keep climbing a vector that advances a stage; cut a stalled one early.

        Reallocates the SAME total budget: no new attempts are created."""
        depth = self._stage_depth(report)
        if self._v_tries == 0:
            # First result on a fresh vector: set the baseline, then climb it.
            self._v_tries, self._v_best_depth, self._v_stall = 1, depth, 0
            return Decision(Action.REFINE_PAYLOAD,
                            f"vector seeded at stage depth {depth}; hill-climb it",
                            hold_vector=True)
        self._v_tries += 1
        if depth > self._v_best_depth:
            self._v_best_depth, self._v_stall = depth, 0
            return Decision(Action.REFINE_PAYLOAD,
                            f"vector advanced to stage depth {depth}; keep climbing",
                            hold_vector=True)
        self._v_stall += 1
        if self._v_stall >= self.patience or self._v_tries >= self.max_vector_tries:
            self._reset_vector()
            return Decision(Action.REFINE_PAYLOAD,
                            "vector stalled; switch to a fresh attack vector",
                            hold_vector=False)
        return Decision(Action.REFINE_PAYLOAD,
                        f"vector at depth {self._v_best_depth}, no gain; one more climb",
                        hold_vector=True)

    def decide(self, report: JudgeReport, attack: EvidenceBundle,
               retries_used: int, budgets: Budgets,
               context_rebound: bool) -> Decision:
        if report.complete_success:
            return Decision(Action.STOP_SUCCESS, "complete linked chain observed")

        if retries_used >= budgets.per_path_retries:
            self._reset_vector()
            return Decision(Action.SELECT_NEW_PATH,
                            "per-path retry budget exhausted; try another path")

        c1 = report.stage(Stage.C1_INCORRECT_COMMITMENT)
        c2 = report.stage(Stage.C2_EFFECTIVE_ADOPTION)

        source_read = attack.has_evidence_kind("exposure")

        # Path/context mismatch: the consumer never even read the source.
        if not source_read and not context_rebound:
            self._reset_vector()
            return Decision(Action.REBIND_CONTEXT,
                            "source was never read; path and context do not align")

        # Adaptive allocation drives refine-vs-switch from stage progress.
        if self.adaptive:
            return self._adaptive_refine(report)

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
