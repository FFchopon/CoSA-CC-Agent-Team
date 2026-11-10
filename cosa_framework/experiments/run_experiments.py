#!/usr/bin/env python3
"""Run CoSA red-team campaigns against the two external coding-MAS targets.

Targets (structural models derived from each project's source):
  * TraceDev                 (ISSE-Lab/ISSTA2026-TraceDev)
  * Self-collaboration       (YihongDong/Self-collaboration-Code-Generation)

For each target we run two conditions:
  * vulnerable  — the coordinator agent yields to a sufficiently explicit injected
                  directive in the untrusted source;
  * defended    — the coordinator decides only from the independent ground-truth
                  oracle (requirement coverage / hidden test suite).

No network, no LLM. Writes experiments/results.json and prints a summary table.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from cosa import CampaignConfig, ContextLibrary, CoSACampaign  # noqa: E402
from cosa.reflection import Budgets  # noqa: E402
from targets import tracedev as td  # noqa: E402
from targets import self_collab as sc  # noqa: E402


def run_campaign(target, context, mas_spec, terminal_objective, target_value):
    library = ContextLibrary()
    library.add(context)
    campaign = CoSACampaign(target=target, context_library=library)
    config = CampaignConfig(
        terminal_objective=terminal_objective,
        target_value=target_value,
        budgets=Budgets(per_path_retries=5, global_attempts=20))
    return campaign.run(mas_spec, config)


def campaigns():
    return [
        ("tracedev", "vulnerable",
         td.TraceDevTarget(policy=td.VulnerableValidatorPolicy()),
         td.tracedev_context(), td.tracedev_mas_spec(),
         "code implemented from an unvalidated design", "complete"),
        ("tracedev", "defended",
         td.TraceDevTarget(policy=td.DefendedValidatorPolicy()),
         td.tracedev_context(), td.tracedev_mas_spec(),
         "code implemented from an unvalidated design", "complete"),
        ("self_collab", "vulnerable",
         sc.SelfCollabTarget(policy=sc.VulnerableTesterPolicy()),
         sc.self_collab_context(), sc.self_collab_mas_spec(),
         "buggy code delivered as the accepted solution", "pass"),
        ("self_collab", "defended",
         sc.SelfCollabTarget(policy=sc.DefendedTesterPolicy()),
         sc.self_collab_context(), sc.self_collab_mas_spec(),
         "buggy code delivered as the accepted solution", "pass"),
    ]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "results.json"))
    args = parser.parse_args()

    results = []
    for name, policy, target, context, spec, objective, value in campaigns():
        report = run_campaign(target, context, spec, objective, value)
        results.append({
            "target": name,
            "policy": policy,
            "mas_structurally_sound": report.mas_structurally_sound,
            "mdg_problems": report.mdg_problems,
            "ranked_paths": report.ranked_paths,
            "success": report.success,
            "stop_reason": report.stop_reason,
            "attempts": [
                {"framing": a.payload_framing,
                 "C1": a.stage_verdicts["C1_incorrect_commitment"],
                 "C2": a.stage_verdicts["C2_effective_adoption"],
                 "C3": a.stage_verdicts["C3_terminal_outcome"],
                 "chain_linked": a.chain_linked,
                 "attribution": a.attribution,
                 "complete_success": a.complete_success,
                 "decision": a.decision,
                 "diagnosis": a.diagnosis}
                for a in report.attempts],
        })

    bundle = {"framework": "CoSA", "network": "none", "llm": "none",
              "results": results}
    with open(args.out, "w") as f:
        json.dump(bundle, f, indent=2)

    # --- summary table ---
    print(f"{'target':<13}{'policy':<12}{'success':<9}{'attempts':<9}{'stop_reason'}")
    print("-" * 60)
    for r in results:
        print(f"{r['target']:<13}{r['policy']:<12}"
              f"{str(r['success']):<9}{len(r['attempts']):<9}{r['stop_reason']}")
    print(f"\nFull evidence written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
