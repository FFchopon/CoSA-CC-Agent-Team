"""Target MAS adapters for the CoSA framework."""
from .base import TargetMAS
from .agent_team import (AGENT_TEAM_TASKS, AgentTeamTarget, AgentTeamTask,
                         SharedTaskList, Task, agent_team_context,
                         agent_team_mas_spec, agent_team_task_context,
                         agent_team_task_contexts)
from .dev_team import (BENIGN_REPORT, DefendedTesterPolicy, DevTeamTarget,
                       VulnerableTesterPolicy, dev_team_context,
                       dev_team_mas_spec)
from .llm_policies import (LLMCoordinatorPolicy, LLMResearchManagerPolicy,
                           LLMTBCApolloPolicy, LLMTBCVerifierPolicy,
                           make_llm_research_manager_policy,
                           make_llm_reviewer_policy, make_llm_tbc_policies,
                           make_llm_tester_policy, make_llm_validator_policy)
from .thebotcompany import (THEBOTCOMPANY_TASKS, TBCTask, TheBotCompanyTarget,
                            tbc_task_context, tbc_task_contexts)
from .openhands import (OPENHANDS_TASKS, OpenHandsTask, OpenHandsTarget,
                        VulnerableReviewerPolicy as OHVulnerableReviewerPolicy,
                        DefendedReviewerPolicy as OHDefendedReviewerPolicy,
                        SpecAnchoredReviewerPolicy as OHSpecAnchoredReviewerPolicy,
                        VulnerableMergeGatePolicy, DefendedMergeGatePolicy,
                        openhands_mas_spec, openhands_task_context,
                        openhands_task_contexts)
from .self_collab import (SELF_COLLAB_TASKS, SelfCollabTask,
                          self_collab_task_context, self_collab_task_contexts)
from .tracedev import (TRACEDEV_TASKS, TraceDevTask, tracedev_task_context,
                       tracedev_task_contexts)
from .trading_agents import (TRADING_TASKS, TradingAgentsTarget,
                             DefendedResearchManagerPolicy, TradingTask,
                             VulnerableResearchManagerPolicy,
                             trading_agents_mas_spec, trading_task_context,
                             trading_task_contexts)

__all__ = [
    "TargetMAS", "DevTeamTarget", "VulnerableTesterPolicy",
    "DefendedTesterPolicy", "dev_team_mas_spec", "dev_team_context",
    "BENIGN_REPORT", "LLMCoordinatorPolicy", "make_llm_tester_policy",
    "make_llm_validator_policy", "make_llm_reviewer_policy",
    "LLMResearchManagerPolicy", "make_llm_research_manager_policy",
    "LLMTBCVerifierPolicy", "LLMTBCApolloPolicy", "make_llm_tbc_policies",
    "TheBotCompanyTarget", "TBCTask", "THEBOTCOMPANY_TASKS",
    "tbc_task_context", "tbc_task_contexts",
    "AgentTeamTarget", "AgentTeamTask", "AGENT_TEAM_TASKS", "SharedTaskList",
    "Task", "agent_team_mas_spec", "agent_team_context",
    "agent_team_task_context", "agent_team_task_contexts",
    "OpenHandsTarget", "OpenHandsTask", "OPENHANDS_TASKS",
    "OHVulnerableReviewerPolicy", "OHDefendedReviewerPolicy",
    "OHSpecAnchoredReviewerPolicy", "VulnerableMergeGatePolicy",
    "DefendedMergeGatePolicy", "openhands_mas_spec",
    "openhands_task_context", "openhands_task_contexts",
    "SELF_COLLAB_TASKS", "SelfCollabTask", "self_collab_task_context",
    "self_collab_task_contexts", "TRACEDEV_TASKS", "TraceDevTask",
    "tracedev_task_context", "tracedev_task_contexts",
    "TradingAgentsTarget", "TradingTask", "TRADING_TASKS",
    "VulnerableResearchManagerPolicy", "DefendedResearchManagerPolicy",
    "trading_agents_mas_spec", "trading_task_context", "trading_task_contexts",
]
