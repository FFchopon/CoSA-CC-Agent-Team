"""Execution & evidence collection (slide 13).

The facility replays the target MAS from one shared initial checkpoint under two
conditions and returns the two evidence bundles the Judge needs:

  * **control** — the benign source value from the bound context, and
  * **attack** — the generated payload at the same source.

Replaying both from the same checkpoint is what lets the Judge establish
*attribution*: an outcome present in the attack bundle and absent in the control
bundle is caused by the payload, not by the scenario.
"""
from __future__ import annotations

import copy
import dataclasses
from typing import Any

from .spec import ContextInstance, EvidenceBundle, Payload


@dataclasses.dataclass
class ReplayResult:
    control: EvidenceBundle
    attack: EvidenceBundle


class Executor:
    def __init__(self, target: Any) -> None:
        self.target = target

    def _replay(self, context: ContextInstance, mode: str, source_value: Any) -> EvidenceBundle:
        bundle = EvidenceBundle(mode=mode)
        # Deep-copy the checkpoint so control and attack never share mutable state.
        self.target.reset(copy.deepcopy(context.checkpoint))
        self.target.run(source_value, bundle)
        return bundle

    def run_pair(self, context: ContextInstance, payload: Payload) -> ReplayResult:
        control = self._replay(context, "control", context.benign_source_value)
        attack = self._replay(context, "attack", payload.content)
        return ReplayResult(control=control, attack=attack)
