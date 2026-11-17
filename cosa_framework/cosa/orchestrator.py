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
from .permission import AttackerPermission, enforce_append_only, site_for
from .reflection import Action, Budgets, Reflector
from .spec import CandidatePath, JudgeReport, TestSpecification, Verdict


# Evidence kinds the attacker may legitimately observe when refining a payload.
# The hidden independent check ("oracle") and any oracle-derived field are
# EXCLUDED: the Generator must condition only on what a real attacker sees flow
# back through the shared channel (the coordinator's message/verdict, the
# resulting coordination-state value, whether a consumer adopted it), never on
# the ground-truth oracle or the Judge's verdicts.
_OBSERVABLE_KINDS = ("coordinator_message", "state_write", "consumer_action",
                     "terminal", "message", "exposure")


def observable_feedback(attack: "Any", limit: int = 6) -> str:
    """Attacker-observable summary of the last attack replay, oracle-free.

    Boundary enforcement lives here: ``oracle`` events are dropped outright and
    every ``oracle*`` detail key is stripped, so no ground-truth leaks into the
    Generator. Returns a short human-readable string (empty if nothing visible).
    """
    lines: List[str] = []
    for ev in getattr(attack, "events", []):
        if ev.kind == "oracle" or ev.kind not in _OBSERVABLE_KINDS:
            continue
        safe = {k: v for k, v in (ev.detail or {}).items()
                if "oracle" not in k.lower()}
        if ev.kind == "coordinator_message":
            verdict = safe.get("verdict", "?")
            reason = str(safe.get("reason", "")).strip().replace("\n", " ")
            lines.append(f"coordinator verdict={verdict!r}" +
                         (f"; reason: {reason[:300]}" if reason else ""))
        elif ev.kind == "state_write":
            lines.append(f"coordination field {safe.get('field')}="
                         f"{safe.get('value')!r}")
        elif ev.kind == "consumer_action":
            lines.append("consumer "
                         + ("adopted" if safe.get("routed") else "did not adopt")
                         + f" ({safe.get('decision','?')})")
        elif ev.kind == "terminal":
            lines.append(f"terminal: {safe.get('outcome', safe.get('artifact','?'))}")
    return "; ".join(lines[-limit:])


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
    payload_vector: str
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
    # The exact payload that induced the terminal outcome, retained so a run can
    # be replayed later (the LLM generator's winning text is otherwise lost, as it
    # is non-deterministic and not reconstructable from the vector label alone).
    winning_payload: Optional[Dict[str, Any]] = None
    # 1-based index of the first attempt that reached the terminal outcome
    # (tries-to-success). None means the budget was exhausted without success
    # (i.e. tries-to-success > budget / infinite).
    tries_to_success: Optional[int] = None

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
            "winning_payload": self.winning_payload,
            "tries_to_success": self.tries_to_success,
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

    def _enforce_permission(self, context, payload, mode="append_only"):
        """Safety net: guarantee the payload is append-only onto the ACTIVE site's
        benign base (P1 external source / P2 inter-agent message). The cross-field
        guardrail holds by construction (only the one active field is ever set)."""
        base = context.active_benign(mode)
        ok, content, note = enforce_append_only(base, payload.content)
        payload.content = content
        payload.metadata.setdefault("append_only_ok", ok)
        payload.metadata["append_only_note"] = note
        return payload

    def run(self, mas_spec: MASSpec, config: CampaignConfig) -> CampaignReport:
        # Sync the active permission (P1 append_only / P2 replace) into the
        # generator and dispatcher so the whole pipeline agrees on the capability.
        mode = config.permission_mode
        if hasattr(self.generator, "set_permission_mode"):
            self.generator.set_permission_mode(mode)
        if hasattr(self.dispatcher, "permission"):
            self.dispatcher.permission = AttackerPermission(mode=mode)
        site = site_for(mode)

        analysis: AnalyzerResult = self.analyzer.build(mas_spec)
        injectable = [n.id for n in analysis.mdg.injectable_sources()]
        grafter = self.grafter_factory(analysis.mdg)
        ranked = grafter.rank_candidates(config.search, budget=config.path_budget)

        attempts: List[AttemptRecord] = []
        global_used = 0
        success = False
        successful_spec: Optional[str] = None
        winning_payload: Optional[Dict[str, Any]] = None
        tries_to_success: Optional[int] = None
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
            payload = self._enforce_permission(
                context, self.generator.generate(spec, context), mode)

            retries_used = 0
            context_rebound = False
            while True:
                if global_used >= config.budgets.global_attempts:
                    stop_reason = "global_budget_exhausted"
                    break
                replay = self.executor.run_pair(context, payload, site)
                global_used += 1
                report = self.judge.verify(spec, replay)
                # Attacker-observable feedback (oracle-free) that the Generator may
                # condition on. The Judge report / routing diagnosis stay with the
                # Reflector and the audit record; they never reach the Generator.
                observed = observable_feedback(replay.attack)
                decision = self.reflector.decide(
                    report, replay.attack, retries_used, config.budgets,
                    context_rebound)

                attempts.append(AttemptRecord(
                    path_id=path.id, spec_version=spec.version,
                    payload_framing=payload.metadata.get("framing", "?"),
                    payload_vector=str(payload.metadata.get("vector")
                                       or payload.metadata.get("strategy") or "?"),
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
                    # The winning attempt is the one just appended; its 1-based
                    # position over all replays is the tries-to-success count.
                    tries_to_success = len(attempts)
                    # Retain the exact inducing payload for later replay. We keep
                    # the content, where it was injected (site/sink), and the
                    # benign base it appended onto, so run_pair() can be re-driven
                    # against the live victim without re-searching.
                    winning_payload = {
                        "content": payload.content,
                        "framing": payload.metadata.get("framing", "?"),
                        "vector": str(payload.metadata.get("vector")
                                      or payload.metadata.get("strategy") or "?"),
                        "site": site,
                        "permission_mode": mode,
                        "context_id": context.id,
                        "sink_field": context.sink_field,
                        "benign_base": context.active_benign(mode),
                        "append_only_ok": bool(
                            payload.metadata.get("append_only_ok", True)),
                    }
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
                        context, self.generator.generate(spec, context), mode)
                    continue
                # REFINE_PAYLOAD or COLLECT_DIAGNOSTICS -> refine and retry.
                # The Generator conditions on attacker-OBSERVABLE feedback only,
                # not the Reflector's oracle-derived diagnosis.
                retries_used += 1
                payload = self._enforce_permission(context, self.generator.refine(
                    spec, context, payload, observed, retries_used + 1,
                    hold_vector=decision.hold_vector), mode)

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
            permission_mode=config.permission_mode,
            winning_payload=winning_payload,
            tries_to_success=tries_to_success)

    def _rebind(self, path: CandidatePath, exclude: str):
        for candidate in self.library.eligible_for(path):
            if candidate.id != exclude:
                return candidate
        return None
