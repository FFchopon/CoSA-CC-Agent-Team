"""CoSA: a local-only red-team testing framework for Multi-Agent Systems.

Public API mirrors the five-agent pipeline from the method:
    Analyzer -> Grafter -> Dispatcher -> Generator -> (Execution) -> Judge,
driven by an evidence-driven Reflector inside the CoSACampaign controller.
"""
from .analyzer import Analyzer, AnalyzerResult, MASSpec
from .context_library import ContextLibrary
from .dispatcher import CheckParams, Dispatcher, default_check_builder
from .execution import Executor, ReplayResult
from .generator import PayloadGenerator, TemplatePayloadGenerator
from .grafter import Grafter
from .graph_search import GraphSearchTool, SearchConstraints
from .judge import Judge
from .mdg import MDG
from .orchestrator import (AttemptRecord, CampaignConfig, CampaignReport,
                           CoSACampaign)
from .reflection import Action, Budgets, Decision, Reflector
from .permission import (AttackerPermission, build_payload, enforce_append_only,
                         is_append_only)
from .llm import FakeLLMClient, LLMClient, LLMConfig, OpenAICompatClient
from .llm_agents import (LLMAnalyzer, LLMDispatcher, LLMGenerator, LLMGrafter,
                         LLMJudge, LLMReflector)
from .llm_campaign import build_llm_campaign
from .spec import (CandidatePath, ContextInstance, Edge, EdgeType,
                   EvidenceBundle, EvidenceEvent, FixedCheck, JudgeReport, Node,
                   NodeType, Payload, Stage, StageVerdict, TestPlan,
                   TestSpecification, Verdict)

__all__ = [
    "Analyzer", "AnalyzerResult", "MASSpec", "ContextLibrary", "Dispatcher",
    "CheckParams", "default_check_builder", "Executor", "ReplayResult",
    "PayloadGenerator", "TemplatePayloadGenerator", "Grafter", "GraphSearchTool",
    "SearchConstraints", "Judge", "MDG", "CoSACampaign", "CampaignConfig",
    "CampaignReport", "AttemptRecord", "Action", "Budgets", "Decision",
    "Reflector", "CandidatePath", "ContextInstance", "Edge", "EdgeType",
    "EvidenceBundle", "EvidenceEvent", "FixedCheck", "JudgeReport", "Node",
    "NodeType", "Payload", "Stage", "StageVerdict", "TestPlan",
    "TestSpecification", "Verdict",
    "LLMClient", "LLMConfig", "OpenAICompatClient", "FakeLLMClient",
    "LLMAnalyzer", "LLMGrafter", "LLMDispatcher", "LLMGenerator", "LLMJudge",
    "LLMReflector", "build_llm_campaign",
    "AttackerPermission", "build_payload", "enforce_append_only", "is_append_only",
]
