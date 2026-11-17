"""Target MAS adapters for the CoSA framework.

Three integrated target multi-agent systems:
  * MetaGPT        (classic software company; structural + live adapters)
  * TheBotCompany  (autonomous dev team; structural + live adapter)
  * GatedTeam      (shared-task-list coding team; ``agent_team``)
"""
from .base import TargetMAS
from .agent_team import (AGENT_TEAM_TASKS, AgentTeamTarget, AgentTeamTask,
                         SharedTaskList, Task, agent_team_context,
                         agent_team_mas_spec, agent_team_task_context,
                         agent_team_task_contexts)
from .llm_policies import (LLMCoordinatorPolicy, LLMTBCApolloPolicy,
                           LLMTBCVerifierPolicy, make_llm_reviewer_policy,
                           make_llm_tbc_policies)
from .thebotcompany import (THEBOTCOMPANY_TASKS, TBCTask, TheBotCompanyTarget,
                            tbc_task_context, tbc_task_contexts)

__all__ = [
    "TargetMAS",
    "LLMCoordinatorPolicy", "make_llm_reviewer_policy",
    "LLMTBCVerifierPolicy", "LLMTBCApolloPolicy", "make_llm_tbc_policies",
    "TheBotCompanyTarget", "TBCTask", "THEBOTCOMPANY_TASKS",
    "tbc_task_context", "tbc_task_contexts",
    "AgentTeamTarget", "AgentTeamTask", "AGENT_TEAM_TASKS", "SharedTaskList",
    "Task", "agent_team_mas_spec", "agent_team_context",
    "agent_team_task_context", "agent_team_task_contexts",
]
