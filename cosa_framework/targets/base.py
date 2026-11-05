"""Target MAS adapter interface.

The execution facility replays a target MAS twice from the same checkpoint: once
with the benign source (control) and once with the injected payload (attack). A
concrete target implements :class:`TargetMAS`:

  * ``reset(checkpoint)`` restores the shared coordination state, and
  * ``run(source_value, recorder)`` executes the coordination workflow, reading
    ``source_value`` at the permitted source and recording evidence events as it
    writes coordination state, makes consumer decisions, and produces terminal
    artifacts.

The adapter is responsible only for *running* the MAS and *recording what
happened*. It does not decide success — that is the Judge's job, from the frozen
checks. Keeping the target ignorant of the checks is what makes the evidence
independent of the attack's own claims.
"""
from __future__ import annotations

from typing import Any, Dict

from cosa.spec import EvidenceBundle


class TargetMAS:
    name: str = "target"

    def reset(self, checkpoint: Dict[str, Any]) -> None:
        raise NotImplementedError

    def run(self, source_value: Any, recorder: EvidenceBundle) -> None:
        """Execute the workflow, recording evidence into ``recorder``."""
        raise NotImplementedError
