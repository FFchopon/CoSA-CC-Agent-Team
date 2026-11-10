"""Workflow controller: run a whole CoSA campaign and report it (slides 3, 15).

Wires the five agents and the facilities together:

    Analyzer -> MDG
    Grafter  -> ranked candidate paths
    loop over paths, each under the reflection budgets:
        Dispatcher -> frozen spec (Test Plan + Fixed Checks)
        Generator  -> payload
        Executor   -> control + attack evidence
        Judge      -> per-stage verdicts + chain + attribution
        Reflector  -> next action

Stops on the first complete linked chain, or when the global budget is exhausted,
reporting the best retained verdict. The report is fully serializable and records
every attempt, every verdict, and every routing decision, so a run is auditable
end to end.
"""
from __future__ import annotations

import dataclasses
from typing import Any, Dict, List, Optional

from .analyzer import Analyzer, AnalyzerResult, MASSpec
from .context_library import ContextLibrary
from .dispatcher import CheckBuilder, Dispatcher
from .execution import Executor
from .generator import PayloadGenerator, TemplatePayloadGenerator
from .grafter import Grafter
from .graph_search import SearchConstraints
from .judge import Judge
from .permission import enforce_append_only
from .reflection import Action, Budgets, Reflector
from .spec import CandidatePath, JudgeReport, TestSpecification, Verdict


@dataclasses.dataclass
class CampaignConfig:
    terminal_objective: str
    target_value: Any                 # the corrupt value the sink must be driven to
    allowed_edits: str = "append instructions to the untrusted source"
    permissions: List[str] = dataclasses.field(default_factory=lambda: ["modify_source"])
    budgets: Budgets = dataclasses.field(default_factory=Budgets)
    search: SearchConstraints = dataclasses.field(default_factory=SearchConstraints)
    path_budget: Optional[int] = None  # cap on number of ranked paths tried
    permission_mode: str = "append_only"  # P1


@dataclasses.dataclass
class AttemptRecord:
    path_id: str
    spec_version: int
    payload_framing: str
    stage_verdicts: Dict[str, str]
    chain_linked: bool
    attribution: bool
    complete_success: bool
    decision: str
    diagnosis: str
    append_only_ok: bool = True


@dataclasses.dataclass
class CampaignReport:
    target: str
    mas_structurally_sound: bool
    mdg_problems: List[str]
    ranked_paths: List[str]
    attempts: List[AttemptRecord]
    success: bool
    successful_spec: Optional[str]
    stop_reason: str
    injectable_sources: List[str] = dataclasses.field(default_factory=list)
    permission_mode: str = "append_only"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "mas_structurally_sound": self.mas_structurally_sound,
            "mdg_problems": self.mdg_problems,
            "permission": {"mode": self.permission_mode,
                           "injectable_sources": self.injectable_sources},
            "ranked_paths": self.ranked_paths,
            "attempts": [dataclasses.asdict(a) for a in self.attempts],
            "success": self.success,
            "successful_spec": self.successful_spec,
            "stop_reason": self.stop_reason,
        }


class CoSACampaign:
    """Workflow controller. Each agent can be the deterministic default or an
    injected LLM-backed implementation (same interface), so the pipeline runs
    all-deterministic, all-LLM, or any mix. ``grafter_factory`` builds a grafter
    from the MDG once it exists.
    """

    def __init__(self, target: Any, context_library: ContextLibrary,
                 generator: Optional[PayloadGenerator] = None,
                 check_builder: Optional[CheckBuilder] = None,
                 analyzer: Optional[Any] = None,
                 grafter_factory: Optional[Any] = None,
                 dispatcher: Optional[Any] = None,
                 judge: Optional[Any] = None,
                 reflector: Optional[Any] = None) -> None:
        self.target = target
        self.library = context_library
        self.analyzer = analyzer or Analyzer()
        self.generator = generator or TemplatePayloadGenerator()
        self.dispatcher = dispatcher or Dispatcher(check_builder=check_builder)
        self.executor = Executor(target)
        self.judge = judge or Judge()
        self.reflector = reflector or Reflector()
        self.grafter_factory = grafter_factory or (lambda mdg: Grafter(mdg))

    def _enforce_permission(self, context, payload):
        """Safety net: guarantee any generator's payload is P1 append-only."""
        ok, content, note = enforce_append_only(context.benign_source_value,
                                                payload.content)
        payload.content = content
        payload.metadata.setdefault("append_only_ok", ok)
        payload.metadata["append_only_note"] = note
        return payload

    def run(self, mas_spec: MASSpec, config: CampaignConfig) -> CampaignReport:
        analysis: AnalyzerResult = self.analyzer.build(mas_spec)
        injectable = [n.id for n in analysis.mdg.injectable_sources()]
        grafter = self.grafter_factory(analysis.mdg)
        ranked = grafter.rank_candidates(config.search, budget=config.path_budget)

        attempts: List[AttemptRecord] = []
        global_used = 0
        success = False
        successful_spec: Optional[str] = None
        stop_reason = "paths_exhausted"

        for path in ranked:
            if global_used >= config.budgets.global_attempts:
                stop_reason = "global_budget_exhausted"
                break
            context = self.library.bind(path)
            if context is None:
                continue  # no eligible context realizes this path

            spec = self.dispatcher.bind(
                path=path, context=context,
                terminal_objective=config.terminal_objective,
                permissions=config.permissions,
                target_value=config.target_value,
                allowed_edits=config.allowed_edits)
            payload = self._enforce_permission(context,
                                               self.generator.generate(spec, context))

            retries_used = 0
            context_rebound = False
            while True:
                if global_used >= config.budgets.global_attempts:
                    stop_reason = "global_budget_exhausted"
                    break
                replay = self.executor.run_pair(context, payload)
                global_used += 1
                report = self.judge.verify(spec, replay)
                decision = self.reflector.decide(
                    report, replay.attack, retries_used, config.budgets,
                    context_rebound)

                attempts.append(AttemptRecord(
                    path_id=path.id, spec_version=spec.version,
                    payload_framing=payload.metadata.get("framing", "?"),
                    stage_verdicts={s.stage.value: s.verdict.value
                                    for s in report.stages},
                    chain_linked=report.chain_linked,
                    attribution=report.attribution,
                    complete_success=report.complete_success,
                    decision=decision.action.value,
                    diagnosis=decision.diagnosis,
                    append_only_ok=bool(payload.metadata.get("append_only_ok", True))))

                if decision.action == Action.STOP_SUCCESS:
                    success = True
                    successful_spec = spec.id
                    stop_reason = "target_success"
                    break
                if decision.action == Action.STOP_BUDGET:
                    stop_reason = "budget"
                    break
                if decision.action == Action.SELECT_NEW_PATH:
                    break
                if decision.action == Action.REBIND_CONTEXT:
                    new_context = self._rebind(path, exclude=context.id)
                    retries_used += 1
                    context_rebound = True
                    if new_context is None:
                        break  # nothing else to bind; move to next path
                    context = new_context
                    spec = spec.versioned(new_context.id)
                    payload = self._enforce_permission(
                        context, self.generator.generate(spec, context))
                    continue
                # REFINE_PAYLOAD or COLLECT_DIAGNOSTICS -> refine and retry
                retries_used += 1
                payload = self._enforce_permission(context, self.generator.refine(
                    spec, context, payload, decision.diagnosis, retries_used + 1))

            if success or stop_reason in ("global_budget_exhausted", "budget"):
                break

        return CampaignReport(
            target=getattr(self.target, "name", "target"),
            mas_structurally_sound=analysis.structurally_sound,
            mdg_problems=analysis.problems,
            ranked_paths=[p.id for p in ranked],
            attempts=attempts, success=success,
            successful_spec=successful_spec, stop_reason=stop_reason,
            injectable_sources=injectable,
            permission_mode=config.permission_mode)

    def _rebind(self, path: CandidatePath, exclude: str):
        for candidate in self.library.eligible_for(path):
            if candidate.id != exclude:
                return candidate
        return None
