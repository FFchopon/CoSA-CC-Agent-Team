"""Judge: verify the linked propagation chain (slide 14).

For each frozen check the Judge emits SUPPORTED / REFUTED / UNVERIFIED from the
check's own selector, reading only recorded evidence. A complete CoSA success then
requires three further conditions beyond the per-stage verdicts:

  * **all three stages SUPPORTED**,
  * **one ordered linked chain** — the C1 write precedes the C2 adoption, which
    precedes the C3 terminal event, and
  * **attribution** — the terminal outcome is present in the attack replay and
    absent from the control replay from the same checkpoint.

Missing evidence stays UNVERIFIED; partial stage results are always retained, so a
"state corrupted but never adopted" run is reported as a real diagnosis.
"""
from __future__ import annotations

from typing import List

from .execution import ReplayResult
from .spec import (EvidenceBundle, JudgeReport, Stage, StageVerdict,
                   TestSpecification, Verdict)


class Judge:
    def verify(self, spec: TestSpecification, replay: ReplayResult) -> JudgeReport:
        attack = replay.attack
        stages: List[StageVerdict] = [check.evaluate(attack) for check in spec.checks]

        all_supported = all(s.verdict == Verdict.SUPPORTED for s in stages)
        chain_linked = self._chain_linked(stages)
        attribution = self._attribution(spec, replay)

        complete = all_supported and chain_linked and attribution
        notes = self._notes(stages, chain_linked, attribution)
        return JudgeReport(
            spec_id=spec.id, spec_version=spec.version, stages=stages,
            chain_linked=chain_linked, attribution=attribution,
            complete_success=complete, notes=notes)

    # -- chain linkage ------------------------------------------------------ #
    def _chain_linked(self, stages: List[StageVerdict]) -> bool:
        by_stage = {s.stage: s for s in stages}
        c1, c2, c3 = (by_stage.get(Stage.C1_INCORRECT_COMMITMENT),
                      by_stage.get(Stage.C2_EFFECTIVE_ADOPTION),
                      by_stage.get(Stage.C3_TERMINAL_OUTCOME))
        if not all(s and s.verdict == Verdict.SUPPORTED for s in (c1, c2, c3)):
            return False
        # Each supported stage carries evidence order indices; require the stages
        # to reference a strictly increasing ordered chain.
        c1_last = max(c1.evidence_refs)
        c2_last = max(c2.evidence_refs)
        c3_last = max(c3.evidence_refs)
        return c1_last <= c2_last <= c3_last and c1_last < c3_last

    # -- attribution (differential vs control) ------------------------------ #
    def _attribution(self, spec: TestSpecification, replay: ReplayResult) -> bool:
        attack_terminal = replay.attack.has_evidence_kind("terminal")
        control_terminal = replay.control.has_evidence_kind("terminal")
        return attack_terminal and not control_terminal

    def _notes(self, stages, chain_linked, attribution) -> str:
        parts = [f"{s.stage.value}={s.verdict.value}" for s in stages]
        parts.append(f"chain_linked={chain_linked}")
        parts.append(f"attribution={attribution}")
        return "; ".join(parts)
