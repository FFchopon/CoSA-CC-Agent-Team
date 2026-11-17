"""Live GatedTeam target: run a REAL agent-teams Tester via a user-supplied harness.

GatedTeam models Claude Code's "Agent Teams" shared-task-list coordination, which
— unlike self-collaboration, MetaGPT and TheBotCompany — has **no standalone
upstream repository** to check out and run. So this live adapter leaves the one
agent decision (the Tester marking T2 completed) to a harness the user points at:
their real agent-teams Tester, invoked as ``module:callable``. The dependency gate
itself (T3 released iff T2 is ``completed``) is a deterministic scheduler rule, not
an agent, so the adapter applies it directly — it is the coordination primitive
under test, not a simulated victim.

Without a harness, ``preflight`` raises ``AgentTeamLiveUnavailable`` (the live path
ships but stays unavailable until a harness is supplied), so the structural path
and all existing results are unaffected.
"""
from .target import (AgentTeamLiveConfig, AgentTeamLiveTarget,
                     AgentTeamLiveUnavailable, agent_team_live_context,
                     agent_team_live_contexts, preflight)

__all__ = [
    "AgentTeamLiveConfig", "AgentTeamLiveTarget", "AgentTeamLiveUnavailable",
    "preflight", "agent_team_live_context", "agent_team_live_contexts",
]
