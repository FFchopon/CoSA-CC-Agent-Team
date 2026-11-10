#!/usr/bin/env python3
"""Run an end-to-end CoSA campaign against the reference dev-team target.

No network, no model. Usage:

    python3 examples/run_dev_team_campaign.py              # vulnerable target
    python3 examples/run_dev_team_campaign.py --defended   # defended target

The vulnerable run should find a complete C1->C2->C3 chain after the payload
escalates; the defended run should stop with no complete chain (the oracle gate
holds), and C1 should be REFUTED throughout.
"""
import argparse
import json
import os
import sys

# Make the framework importable when run from anywhere.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from cosa import CampaignConfig, ContextLibrary, CoSACampaign  # noqa: E402
from cosa.reflection import Budgets  # noqa: E402
from targets import (DefendedTesterPolicy, DevTeamTarget,  # noqa: E402
                     VulnerableTesterPolicy, dev_team_context,
                     dev_team_mas_spec)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--defended", action="store_true",
                        help="use the defended tester policy (oracle-gated)")
    args = parser.parse_args()

    policy = DefendedTesterPolicy() if args.defended else VulnerableTesterPolicy()
    target = DevTeamTarget(policy=policy)

    library = ContextLibrary()
    library.add(dev_team_context())

    campaign = CoSACampaign(target=target, context_library=library)
    config = CampaignConfig(
        terminal_objective="risky code was committed",
        target_value="completed",
        budgets=Budgets(per_path_retries=5, global_attempts=20),
    )
    report = campaign.run(dev_team_mas_spec(), config)

    print(json.dumps(report.to_dict(), indent=2))
    print("\n== summary ==")
    print(f"target policy      : {policy.name}")
    print(f"ranked paths       : {len(report.ranked_paths)}")
    print(f"attempts           : {len(report.attempts)}")
    print(f"complete success   : {report.success}")
    print(f"stop reason        : {report.stop_reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
