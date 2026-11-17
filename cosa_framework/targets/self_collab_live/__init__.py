"""Live Self-Collaboration target: run the REAL Tester from the upstream checkout.

Unlike :mod:`targets.self_collab` (a faithful structural model with a pluggable
Tester policy), this package drives the *actual* self-collaboration code — its
``_generate_tests`` (the real LLM Tester) and ``_run_generated_test`` (the real
test execution) from ``run_humaneval.py`` — overriding only ONE artifact: the
Coder's ``solution.py`` is replaced by the defective task's code. Everything the
victim does (generate tests from the requirement, run them, decide pass/fail) is
the upstream framework's own code.

Requires a checkout of YihongDong/self-collaboration-code-generation (see
``preflight``). Nothing here is imported unless the live target is constructed, so
the structural path and all existing results are unaffected.
"""
from .target import (SelfCollabLiveConfig, SelfCollabLiveTarget,
                     SelfCollabLiveUnavailable, preflight,
                     self_collab_live_context, self_collab_live_contexts)

__all__ = [
    "SelfCollabLiveConfig", "SelfCollabLiveTarget", "SelfCollabLiveUnavailable",
    "preflight", "self_collab_live_context", "self_collab_live_contexts",
]
