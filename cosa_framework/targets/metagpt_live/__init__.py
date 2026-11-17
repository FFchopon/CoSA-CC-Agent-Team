"""Live MetaGPT target: run the REAL WriteCodeReview reviewer from the checkout.

Unlike :mod:`targets.metagpt` (a faithful structural model with a pluggable
Reviewer policy), this package drives MetaGPT's actual ``WriteCodeReview`` action
— its real prompts (``PROMPT_TEMPLATE`` / ``EXAMPLE_AND_INSTRUCTION`` /
``FORMAT_EXAMPLE``), its real ``_aask`` LLM call, and its real ``CodeParser``
verdict extraction — overriding only ONE artifact: the Engineer's generated code
(``code_doc.content``) is replaced by the defective task's code. The Reviewer's
LGTM/LBTM decision over the (possibly injected) PRD is the sink.

Requires a checkout of FoundationAgents/MetaGPT with its deps installed (see
``preflight``). Imported only when the live target is constructed, so the
structural path and all existing results are unaffected.
"""
from .target import (MetaGPTLiveConfig, MetaGPTLiveTarget, MetaGPTLiveUnavailable,
                     build_p2_context, metagpt_live_context, metagpt_live_contexts,
                     metagpt_live_p1_context, metagpt_live_p1_contexts, preflight)

__all__ = [
    "MetaGPTLiveConfig", "MetaGPTLiveTarget", "MetaGPTLiveUnavailable", "preflight",
    "metagpt_live_context", "metagpt_live_contexts",
    "metagpt_live_p1_context", "metagpt_live_p1_contexts", "build_p2_context",
]
