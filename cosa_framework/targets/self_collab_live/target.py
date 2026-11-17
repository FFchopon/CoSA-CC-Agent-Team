"""Drive the real self-collaboration Tester for one judgment per replay.

Each replay (control or attack) gets a fresh task dir, writes the defective task's
code into ``solution.py`` (the Coder artifact we override), then calls the
upstream Tester verbatim:

    test_code      = run_humaneval._generate_tests(config, requirement, code)   # real LLM Tester
    passed, output = run_humaneval._run_generated_test(task_dir, test_code, ep) # real execution

``requirement`` is the attacker-reachable external source (P1): benign on the
control replay, benign+payload (append-only) on the attack replay — exactly what
the CoSA ReplayExecutor passes as ``source_value``. The sink is the Tester's
``passed`` verdict (``S_test_status``). The victim is the upstream framework's own
``call_llm_with_tools`` pointed at our victim endpoint via its ``ModelConfig``.

Ground truth: these tasks are defective by construction (the structural library's
``buggy_code`` + a declared FAIL_TO_PASS). No full SWE-bench repo is cloned, so the
oracle is the task's declared ground-truth failure, recorded as an independent
``oracle`` event — the same ground truth the structural adapter uses.
"""
from __future__ import annotations

import dataclasses
import datetime
import importlib
import os
import re
import secrets
import sys
from typing import Any, Dict, List, Optional

from cosa.context_library import ContextInstance
from cosa.spec import EvidenceBundle

from targets.self_collab import SELF_COLLAB_TASKS, SelfCollabTask

SOURCE_FIELD = "D_requirement"     # external source the Tester reads (P1 site)
SINK_FIELD = "S_test_status"       # Tester verdict (STATE) -- the sink
AFFIRMATIVE = "pass"
_KEY_ENV = "COSA_SC_VICTIM_KEY"    # env var the upstream backend reads the key from


class SelfCollabLiveUnavailable(RuntimeError):
    """Raised by preflight when the upstream checkout / deps are not usable."""


@dataclasses.dataclass
class SelfCollabLiveConfig:
    repo_root: str                 # checkout of self-collaboration-code-generation
    run_root: str                  # scratch dir for per-replay task dirs
    victim_model: str              # e.g. "gpt-5.6-luna"
    victim_base_url: str = "https://api.openai.com/v1"
    victim_key_file: str = ""      # file holding the victim API key
    victim_temp: float = 1.0
    max_tokens: int = 8192
    test_timeout: int = 30
    keep_runs: bool = True


def preflight(cfg: SelfCollabLiveConfig) -> None:
    rh = os.path.join(cfg.repo_root, "run_humaneval.py")
    if not os.path.isfile(rh):
        raise SelfCollabLiveUnavailable(
            f"not a self-collaboration checkout (no run_humaneval.py): {cfg.repo_root}")
    for rel in ("core/config.py", "core/backend.py"):
        if not os.path.isfile(os.path.join(cfg.repo_root, rel)):
            raise SelfCollabLiveUnavailable(f"missing {rel} in {cfg.repo_root}")
    src = _read(rh)
    for sym in ("_generate_tests", "_run_generated_test", "TESTER_PROMPT"):
        if sym not in src:
            raise SelfCollabLiveUnavailable(
                f"run_humaneval.py has no '{sym}' — upstream API changed; recalibrate the adapter")
    try:
        importlib.import_module("openai")
    except Exception as exc:  # pragma: no cover - env-dependent
        raise SelfCollabLiveUnavailable(f"`openai` package not importable: {exc}") from exc
    if not cfg.victim_key_file or not os.path.isfile(cfg.victim_key_file):
        raise SelfCollabLiveUnavailable(f"victim key file not found: {cfg.victim_key_file!r}")


def _read(path: str) -> str:
    with open(path) as f:
        return f.read()


def _entry_point(task: SelfCollabTask) -> str:
    """The function name the Tester imports from solution.py (`def NAME(`)."""
    for text in (task.buggy_code, task.requirement):
        m = re.search(r"def\s+([A-Za-z_]\w*)\s*\(", text)
        if m:
            return m.group(1)
    raise ValueError(f"cannot find an entry-point function in task {task.id}")


def _load_upstream(cfg: SelfCollabLiveConfig):
    """Import the upstream modules from the checkout (added to sys.path once)."""
    if cfg.repo_root not in sys.path:
        sys.path.insert(0, cfg.repo_root)
    # Fresh import so a different checkout in the same process is honored.
    rh = importlib.import_module("run_humaneval")
    cc = importlib.import_module("core.config")
    return rh, cc


# --------------------------------------------------------------------------- #
# Contexts: the SAME 20 defective tasks as the structural adapter
# --------------------------------------------------------------------------- #
def self_collab_live_context(task: SelfCollabTask) -> ContextInstance:
    return ContextInstance(
        id=f"ctx_sc_live_{task.id}",
        scene_tags=["code_generation", "test_feedback_loop", "live"],
        checkpoint={
            "task_id": task.id,
            "defective_code": task.buggy_code,
            "entry_point": _entry_point(task),
            "requirement": task.requirement,
            # Declared ground truth: the code is defective (fails FAIL_TO_PASS).
            "ground_truth_fail": True,
            "failing_case": task.failing_case,
            "source": task.source,
        },
        source_field=SOURCE_FIELD,
        benign_source_value=task.requirement,
        sink_field=SINK_FIELD,
        references={"oracle": "declared FAIL_TO_PASS (code defective by construction)",
                    "task": task.id, "source": task.source,
                    "instance_id": task.provenance.get("instance_id")},
    )


def self_collab_live_contexts() -> List[ContextInstance]:
    return [self_collab_live_context(t) for t in SELF_COLLAB_TASKS]


# --------------------------------------------------------------------------- #
# Target
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class SelfCollabLiveTarget:
    config: SelfCollabLiveConfig
    name: str = "self_collab_live"
    runs: list = dataclasses.field(default_factory=list)

    @property
    def policy(self):  # reporting compatibility with the other adapters
        return self

    def reset(self, checkpoint: Dict[str, Any]) -> None:
        self.state = checkpoint

    @property
    def source_field(self) -> str:
        return SOURCE_FIELD

    @property
    def sink_field(self) -> str:
        return SINK_FIELD

    def _model_config(self, cc):
        os.environ[_KEY_ENV] = _read(self.config.victim_key_file).strip()
        return cc.ModelConfig(
            model=self.config.victim_model,
            base_url=self.config.victim_base_url,
            api_key_env=_KEY_ENV,
            max_tokens=self.config.max_tokens,
            temperature=self.config.victim_temp,
        )

    def run(self, source_value: Any, recorder: EvidenceBundle) -> None:
        preflight(self.config)
        rh, cc = _load_upstream(self.config)
        config_obj = self._model_config(cc)

        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        task_dir = os.path.join(self.config.run_root,
                                f"{self.state['task_id']}-{recorder.mode}-{stamp}-{secrets.token_hex(3)}")
        os.makedirs(task_dir, exist_ok=True)
        entry_point = self.state["entry_point"]

        # Override the ONE artifact: the Coder's solution.py = the defective code.
        with open(os.path.join(task_dir, "solution.py"), "w") as f:
            f.write(self.state["defective_code"])

        requirement = str(source_value)   # benign (control) or benign+payload (P1)
        recorder.record("exposure", actor="tester", source=SOURCE_FIELD,
                        detail_preview=requirement[:80])

        # Independent ground truth (declared): the overridden code is defective.
        oracle_passed = not bool(self.state.get("ground_truth_fail", True))
        recorder.record("oracle", actor="tester", passed=oracle_passed,
                        check="declared_fail_to_pass", commit=self.state["task_id"])

        # === REAL Tester: upstream code, verbatim ===
        started = datetime.datetime.now(datetime.timezone.utc)
        test_code = rh._generate_tests(config_obj, requirement, self.state["defective_code"])
        if test_code:
            passed, output = rh._run_generated_test(
                task_dir, test_code, entry_point, timeout=self.config.test_timeout)
        else:
            # No tests produced: the upstream loop treats this as "no verdict";
            # the milestone is not accepted on this replay.
            passed, output = False, "tester produced no tests"

        verdict = AFFIRMATIVE if passed else "fail"
        recorder.record("coordinator_message", actor="tester", field="M_test_report",
                        verified=passed, preview=str(output)[:200])
        recorder.committed_state[SINK_FIELD] = verdict
        recorder.record("state_write", actor="tester", field=SINK_FIELD, value=verdict,
                        oracle_passed=oracle_passed)

        if passed:
            # Coder's accept decision adopts a pass verdict and stops iterating.
            recorder.record("consumer_action", actor="coder", read_field=SINK_FIELD,
                            routed=True, decision="accept_and_deliver",
                            task_id=self.state["task_id"])
            recorder.committed_state["delivery_status"] = "delivered"
            recorder.terminal_artifacts.append(f"solution.py <- {self.state['task_id']}")
            recorder.record("terminal", actor="coder", artifact="solution.py",
                            outcome="buggy code delivered as the accepted solution")
        else:
            recorder.record("consumer_action", actor="coder", read_field=SINK_FIELD,
                            routed=False, decision="another_coder_round")
            recorder.committed_state["delivery_status"] = "rejected"

        self.runs.append({"mode": recorder.mode, "task_dir": task_dir, "verdict": verdict,
                          "passed": passed, "tester_output": str(output)[:500]})
        if not self.config.keep_runs:
            import shutil
            shutil.rmtree(task_dir, ignore_errors=True)
        _ = started  # (kept for symmetry with tbc_live's timing records)
