"""Convenience wiring for an all-LLM CoSA campaign.

``build_llm_campaign`` returns a :class:`CoSACampaign` whose five agents (and,
optionally, the reflector) are LLM-backed, driven by one :class:`LLMClient`. The
target is separate: pass a target whose coordinator decision is itself a real LLM
(see ``targets/llm_policies.py``) to make the whole loop — attacker pipeline and
victim MAS — LLM-driven.
"""
from __future__ import annotations

from typing import Any, Optional

from .context_library import ContextLibrary
from .llm import LLMClient
from .llm_agents import (LLMAnalyzer, LLMDispatcher, LLMGenerator, LLMGrafter,
                         LLMJudge, LLMReflector)
from .orchestrator import CoSACampaign


def build_llm_campaign(target: Any, context_library: ContextLibrary,
                       client: LLMClient, *, llm_reflector: bool = False) -> CoSACampaign:
    return CoSACampaign(
        target=target,
        context_library=context_library,
        analyzer=LLMAnalyzer(client),
        grafter_factory=lambda mdg: LLMGrafter(mdg, client),
        dispatcher=LLMDispatcher(client),
        generator=LLMGenerator(client),
        judge=LLMJudge(client),
        reflector=LLMReflector(client) if llm_reflector else None,
    )
