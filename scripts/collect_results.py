#!/usr/bin/env python3
"""Assemble a public, machine-readable result bundle from local runs.

The raw ``runs/`` directory is intentionally local and ignored by Git. This
script copies selected evidence files and writes a relative-path index so the
demo can be reviewed without exposing terminal transcripts or credentials.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "runs"
RESULT = ROOT / "result"

CANONICAL_RUNS = {
    "baseline-sonnet-5": "baseline-22da9033",
    "attack-sonnet-5": "attack-fea69bb1",
    "defended-sonnet-5": "defended-2c4f41ca",
    "healthy-opus-5-5": "healthy-519ddd93",
    "forced-control-blocked": "forced-40669b60",
    "forced-control-chain": "forced-9593d7c9",
    "refined-attack-haiku-4-5-success-a": "attack-73bfbf45",
    "refined-attack-haiku-4-5-success-b": "attack-84010821",
    "haiku-4-5-repeat": "attack-23df7ba9",
    "refinement-test": "attack-2da267db",
    "haiku-5-5-interrupted-first": "attack-4d5cead2",
    "haiku-5-5-interrupted-last": "attack-df667973",
}

COPY_FILES = (
    "PROMPT.txt",
    "candidate.py",
    "manifest.json",
    "run.json",
    "incoming/ci_report.txt",
    "evidence/events.jsonl",
    "evidence/inspection.json",
    "evidence/campaign-launcher.json",
    "evidence/launcher.json",
    "evidence/refinement-test.json",
    "evidence/refinement-round-2.json",
)


def read_json(path: Path, default=None):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def events_for(run: Path):
    path = run / "evidence/events.jsonl"
    if not path.exists():
        return []
    events = []
    for line in path.read_text().splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    return events


def summarize(run_id: str, run: Path):
    events = events_for(run)
    payloads = [e.get("payload", {}) for e in events]
    starts = [p for p in payloads if p.get("hook_event_name") == "SessionStart"]
    post = [
        e for e in events
        if e.get("payload", {}).get("hook_event_name") == "PostToolUse"
    ]
    t2_completed = [
        e for e in post
        if e.get("payload", {}).get("tool_name") == "TaskUpdate"
        and str(e.get("payload", {}).get("tool_input", {}).get("taskId")) == "2"
        and e.get("payload", {}).get("tool_input", {}).get("status") == "completed"
    ]
    t3_completed = [
        e for e in post
        if e.get("payload", {}).get("tool_name") == "TaskUpdate"
        and str(e.get("payload", {}).get("tool_input", {}).get("taskId")) == "3"
        and e.get("payload", {}).get("tool_input", {}).get("status") == "completed"
    ]
    packages = [e for e in events if e.get("source") == "package_script"]
    launch = read_json(run / "evidence/campaign-launcher.json")
    if launch is None:
        launch = read_json(run / "evidence/launcher.json")
    inspection = read_json(run / "evidence/inspection.json", {}) or {}
    oracle = inspection.get("oracle_now")
    if oracle is None and packages:
        oracle = packages[-1].get("oracle_at_packaging")
    return {
        "run_id": run_id,
        "arm": (read_json(run / "run.json", {}) or {}).get("arm"),
        "model": starts[0].get("model") if starts else (launch or {}).get("requested_model"),
        "native_hook_events": len([e for e in events if e.get("source") == "claude_hook"]),
        "oracle_passed_at_inspection": None if oracle is None else oracle.get("passed"),
        "t2_completed_event_count": len(t2_completed),
        "t3_completed_event_count": len(t3_completed),
        "package_event_count": len(packages),
        "package_exists": (run / "candidate.zip").exists(),
        "launch": launch,
        "inspection_verdict": inspection.get("verdict"),
    }


def copy_run(label: str, run_id: str):
    source = RUNS / run_id
    destination = RESULT / "runs" / label
    if not source.exists():
        return {"label": label, "run_id": run_id, "missing": True}
    for relative in COPY_FILES:
        source_file = source / relative
        if source_file.exists():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, target)
    artifact = source / "candidate.zip"
    if artifact.exists():
        shutil.copy2(artifact, destination / "candidate.zip")
    summary = summarize(run_id, source)
    summary["label"] = label
    summary["evidence_root"] = f"runs/{label}"
    return summary


def collect_campaigns():
    destination = RESULT / "campaigns"
    destination.mkdir(parents=True, exist_ok=True)
    names = (
        "refined-attack-campaign-20261007.json",
        "refined-attack-campaign-20261008-summary.json",
        "haiku-45-repeat-summary.json",
    )
    copied = []
    for name in names:
        source = RUNS / name
        if source.exists():
            shutil.copy2(source, destination / name)
            copied.append(f"campaigns/{name}")
    return copied


def main():
    global RUNS, RESULT
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-runs", type=Path, default=RUNS)
    parser.add_argument("--output", type=Path, default=RESULT)
    args = parser.parse_args()
    RUNS = args.source_runs.resolve()
    RESULT = args.output.resolve()
    (RESULT / "runs").mkdir(parents=True, exist_ok=True)
    summaries = [copy_run(label, run_id) for label, run_id in CANONICAL_RUNS.items()]
    all_runs = []
    for run in sorted(RUNS.glob("*-*")):
        if run.is_dir() and (run / "run.json").exists():
            all_runs.append(summarize(run.name, run))
    (RESULT / "index.json").write_text(json.dumps({
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "source": "local runs directory; terminal.log deliberately excluded",
        "canonical_runs": summaries,
        "all_run_summaries": all_runs,
    }, indent=2, ensure_ascii=False) + "\n")
    copied = collect_campaigns()
    (RESULT / "campaigns.json").write_text(
        json.dumps({"files": copied}, indent=2) + "\n"
    )
    print(json.dumps({
        "result": str(RESULT),
        "canonical_runs": len(summaries),
        "all_runs": len(all_runs),
        "campaign_files": len(copied),
    }, indent=2))


if __name__ == "__main__":
    main()
