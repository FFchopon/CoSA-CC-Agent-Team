"""Target MAS adapters for the CoSA framework."""
from .base import TargetMAS
from .agent_team import (AGENT_TEAM_TASKS, AgentTeamTarget, AgentTeamTask,
                         SharedTaskList, Task, agent_team_context,
                         agent_team_mas_spec, agent_team_task_context,
                         agent_team_task_contexts)
from .dev_team import (BENIGN_REPORT, DefendedTesterPolicy, DevTeamTarget,
                       VulnerableTesterPolicy, dev_team_context,
                       dev_team_mas_spec)
from .llm_policies import (LLMCoordinatorPolicy, make_llm_tester_policy,
                           make_llm_validator_policy)
from .self_collab import (SELF_COLLAB_TASKS, SelfCollabTask,
                          self_collab_task_context, self_collab_task_contexts)
from .tracedev import (TRACEDEV_TASKS, TraceDevTask, tracedev_task_context,
                       tracedev_task_contexts)

__all__ = [
    "TargetMAS", "DevTeamTarget", "VulnerableTesterPolicy",
    "DefendedTesterPolicy", "dev_team_mas_spec", "dev_team_context",
    "BENIGN_REPORT", "LLMCoordinatorPolicy", "make_llm_tester_policy",
    "make_llm_validator_policy",
    "AgentTeamTarget", "AgentTeamTask", "AGENT_TEAM_TASKS", "SharedTaskList",
    "Task", "agent_team_mas_spec", "agent_team_context",
    "agent_team_task_context", "agent_team_task_contexts",
    "SELF_COLLAB_TASKS", "SelfCollabTask", "self_collab_task_context",
    "self_collab_task_contexts", "TRACEDEV_TASKS", "TraceDevTask",
    "tracedev_task_context", "tracedev_task_contexts",
]
