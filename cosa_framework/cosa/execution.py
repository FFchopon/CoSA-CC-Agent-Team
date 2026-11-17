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

    def _replay(self, context: ContextInstance, mode: str, source_value: Any,
                message_value: Any) -> EvidenceBundle:
        bundle = EvidenceBundle(mode=mode)
        # Deep-copy the checkpoint so control and attack never share mutable state.
        ckpt = copy.deepcopy(context.checkpoint)
        # The inter-agent handoff message is a second channel the victim reads;
        # targets that model one pick it up from here (benign unless P2 injects it).
        ckpt["inter_agent_message"] = message_value
        self.target.reset(ckpt)
        self.target.run(source_value, bundle)
        return bundle

    def run_pair(self, context: ContextInstance, payload: Payload,
                 site: str = "external_source") -> ReplayResult:
        """Replay benign vs attack. ``site`` selects WHERE the payload is injected:
        the external source (P1) or the upstream inter-agent message (P2). The
        non-injected channel stays benign so only the attacker's one field differs."""
        benign_src = context.benign_source_value
        benign_msg = context.benign_message_value
        control = self._replay(context, "control", benign_src, benign_msg)
        if site == "inter_agent_message" and context.supports_message_injection():
            attack = self._replay(context, "attack", benign_src, payload.content)
        else:
            attack = self._replay(context, "attack", payload.content, benign_msg)
        return ReplayResult(control=control, attack=attack)
