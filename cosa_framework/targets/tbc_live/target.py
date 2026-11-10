"""Live TheBotCompany target: run the real orchestrator for one verification phase.

Each replay (control or attack) gets a fresh copy of the template checkpoint, writes
the source value into the CI job log (P1), starts ``node src/server.js`` with
``TBC_HOME`` pointed at the copy, waits until the orchestrator leaves the
verification phase for milestone M1 (or a cycle / wall-clock cap), stops it, and
extracts evidence from the run directory (:mod:`.evidence`).

Requirements (checked by :func:`preflight`): Node >= 22.19, a checkout of
thebotcompany with ``npm install`` done, ``git``. No GitHub access is used: the
epoch PR merges into a local bare ``origin``. TBC's merge path insists on a
GitHub token being *configured*, so a placeholder token is set; it is never sent
anywhere because the remote is a filesystem path.

Safety: TBC agents execute shell commands. Run this only inside a disposable VM or
container with no real credentials besides the victim-model key.
"""
from __future__ import annotations

import dataclasses
import datetime
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import time
from typing import Any, Dict, Optional

from cosa.spec import ContextInstance, EvidenceBundle

from .evidence import SINK, observe, record_evidence
from .workspace import (MILESTONE_ID, VictimCredential, Workspace,
                        build_workspace, clone_workspace)

SOURCE_FIELD = "D_ci_job_log"


class TBCLiveUnavailable(RuntimeError):
    pass


@dataclasses.dataclass
class TBCLiveConfig:
    tbc_root: str                         # thebotcompany checkout (npm install done)
    run_root: str                         # where per-replay copies are created
    node: str = "node"
    max_wall_seconds: int = 3600
    max_cycles: int = 4                   # TBC cycles allowed inside verification
    poll_seconds: float = 5.0
    keep_runs: bool = True                # keep run dirs for audit


def preflight(cfg: TBCLiveConfig) -> None:
    try:
        out = subprocess.run([cfg.node, "--version"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise TBCLiveUnavailable(f"node not runnable ({cfg.node}): {exc}") from exc
    m = re.match(r"v(\d+)\.(\d+)", out.strip())
    if not m or (int(m.group(1)), int(m.group(2))) < (22, 19):
        raise TBCLiveUnavailable(f"TBC needs Node >= 22.19, found {out.strip()}")
    if not os.path.isfile(os.path.join(cfg.tbc_root, "src", "server.js")):
        raise TBCLiveUnavailable(f"not a thebotcompany checkout: {cfg.tbc_root}")
    if not os.path.isdir(os.path.join(cfg.tbc_root, "node_modules", "better-sqlite3")):
        raise TBCLiveUnavailable(f"run `npm install` in {cfg.tbc_root} first")
    if shutil.which("git") is None:
        raise TBCLiveUnavailable("git not found")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def tbc_live_context(template_home: str, context_id: str = "ctx_tbc_live_m1") -> ContextInstance:
    """Context for a template built by :func:`build_workspace`."""
    manifest = Workspace(home=template_home).manifest()
    return ContextInstance(
        id=context_id,
        scene_tags=["autonomous_dev_team", "milestone_verification", "ci_evidence", "live"],
        checkpoint={"template_home": template_home},
        source_field=SOURCE_FIELD,
        benign_source_value=manifest["benign_ci_log"],
        sink_field=SINK,
        references={"oracle": "hidden acceptance suite outside the project root",
                    "head_sha": manifest["head_sha"], "tbc_commit": "df189fe"},
    )


def build_template(home: str, credential: VictimCredential, budget_per_24h: float = 5.0) -> Workspace:
    return build_workspace(home, credential=credential, budget_per_24h=budget_per_24h)


@dataclasses.dataclass
class TheBotCompanyLiveTarget:
    config: TBCLiveConfig
    name: str = "thebotcompany_live"
    runs: list = dataclasses.field(default_factory=list)   # audit trail per replay

    def reset(self, checkpoint: Dict[str, Any]) -> None:
        self.template_home = checkpoint["template_home"]

    # -- process control --------------------------------------------------- #
    def _env(self, ws: Workspace, port: int) -> Dict[str, str]:
        keep = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "TMPDIR", "USER", "SHELL") if k in os.environ}
        return {**keep,
                "TBC_HOME": ws.home, "TBC_PORT": str(port), "TBC_SERVE_STATIC": "false",
                "TBC_PASSWORD": secrets.token_hex(16), "TBC_ALLOW_CUSTOM_PROVIDER": "true",
                # Placeholder only: origin is a local path, so no GitHub request is made.
                "TBC_GITHUB_TOKEN": "cosa-local-placeholder",
                "GIT_TERMINAL_PROMPT": "0"}

    def _read_state(self, ws: Workspace) -> Dict[str, Any]:
        try:
            with open(ws.state_path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def _left_verification(self, state: Dict[str, Any]) -> bool:
        return bool(state) and (state.get("phase") != "verification"
                                or state.get("currentMilestoneId") != MILESTONE_ID)

    def _stop(self, proc: subprocess.Popen) -> None:
        if proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=20)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def run(self, source_value: Any, recorder: EvidenceBundle) -> None:
        preflight(self.config)
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        dest = os.path.join(self.config.run_root, f"{stamp}-{recorder.mode}-{secrets.token_hex(3)}")
        ws = clone_workspace(self.template_home, dest)
        ws.write_source(str(source_value))
        start_cycle = self._read_state(ws).get("cycleCount", 0)

        port = _free_port()
        started = datetime.datetime.now(datetime.timezone.utc)
        server_log = open(os.path.join(dest, "server.stdout.log"), "w")
        proc = subprocess.Popen([self.config.node, "src/server.js"], cwd=self.config.tbc_root,
                                env=self._env(ws, port), stdout=server_log,
                                stderr=subprocess.STDOUT, start_new_session=True)
        stop_reason = "wall_clock"
        try:
            deadline = time.monotonic() + self.config.max_wall_seconds
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    stop_reason = f"server_exited({proc.returncode})"
                    break
                state = self._read_state(ws)
                if self._left_verification(state):
                    stop_reason = "left_verification"
                    break
                if state.get("cycleCount", 0) - start_cycle >= self.config.max_cycles:
                    stop_reason = "cycle_cap"
                    break
                time.sleep(self.config.poll_seconds)
        finally:
            self._stop(proc)
            server_log.close()

        obs = observe(ws)
        record_evidence(obs, recorder, started_at=started)
        recorder.record("run_meta", actor="cosa", stop_reason=stop_reason, run_dir=dest)
        self.runs.append({"mode": recorder.mode, "run_dir": dest, "stop_reason": stop_reason,
                          "observation": obs.to_dict()})
        with open(os.path.join(dest, "cosa_observation.json"), "w") as f:
            json.dump({"stop_reason": stop_reason, **obs.to_dict()}, f, indent=2)
        if not self.config.keep_runs:
            shutil.rmtree(dest, ignore_errors=True)
