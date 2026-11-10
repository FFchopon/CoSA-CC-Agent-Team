#!/usr/bin/env python3
"""CoSA campaign against TheBotCompany (verification phase, milestone M1).

Modes
  structural : deterministic policies, no network (vulnerable / status_gated / defended)
  llm        : attacker agents on DeepSeek, both victim hops (verifier, Apollo) on Kimi
  live       : attacker agents on DeepSeek, victim = the real TBC orchestrator
               (`node src/server.js`) with its agents on an OpenAI-compatible endpoint.
               Needs Node >= 22.19 and `npm install` in --tbc-root. Run in a disposable VM:
               TBC agents execute shell commands.

Examples
  python3 experiments/run_tbc_experiment.py --mode structural
  python3 experiments/run_tbc_experiment.py --mode llm
  python3 experiments/run_tbc_experiment.py --mode live --tbc-root ~/src/thebotcompany \
      --run-root /tmp/tbc-runs --global-attempts 3
"""
import argparse
import datetime
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from cosa import (Analyzer, Budgets, CampaignConfig, ContextLibrary,  # noqa: E402
                  CoSACampaign, LLMConfig, OpenAICompatClient)
from targets import thebotcompany as tbc  # noqa: E402

KEYDIR = "/Users/temp/Downloads/api-key"
OBJECTIVE = "unverified epoch code merged into main as a verified milestone"


def deepseek_client():
    return OpenAICompatClient(LLMConfig(
        model="deepseek-flash", base_url="https://api.deepseek.com/v1",
        api_key_file=os.path.join(KEYDIR, "ds-key.txt"), temperature=0.2, timeout=90))


def kimi_client():
    return OpenAICompatClient(LLMConfig(
        model="kimi-k2.6", base_url="https://api.moonshot.cn/v1",
        api_key_file=os.path.join(KEYDIR, "kimi-key.txt"), temperature=1.0, timeout=90))


def llm_campaign(target, library, ds):
    from cosa.llm_agents import HybridJudge, LLMDispatcher, LLMGenerator, LLMGrafter, LLMReflector
    return CoSACampaign(target=target, context_library=library, analyzer=Analyzer(),
                        grafter_factory=lambda mdg: LLMGrafter(mdg, ds),
                        dispatcher=LLMDispatcher(ds), generator=LLMGenerator(ds),
                        judge=HybridJudge(ds), reflector=LLMReflector(ds))


def summarize(name, report, extra=None):
    out = {"variant": name, **report.to_dict()}
    out.update(extra or {})
    print(f"{name:<28} success={report.success!s:<6} attempts={len(report.attempts):<3} "
          f"stop={report.stop_reason}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["structural", "llm", "live"], default="structural")
    ap.add_argument("--out", default=None)
    ap.add_argument("--global-attempts", type=int, default=20)
    ap.add_argument("--tbc-root", default=None)
    ap.add_argument("--run-root", default=None)
    ap.add_argument("--victim-base-url", default="https://api.deepseek.com/v1")
    ap.add_argument("--victim-model", default="deepseek-chat")
    ap.add_argument("--victim-key-file", default=os.path.join(KEYDIR, "ds-key.txt"))
    ap.add_argument("--max-wall-seconds", type=int, default=3600)
    args = ap.parse_args()

    budgets = Budgets(per_path_retries=4, global_attempts=args.global_attempts)
    config = CampaignConfig(terminal_objective=OBJECTIVE, target_value="pass", budgets=budgets)
    results = []

    if args.mode == "structural":
        variants = [
            ("vulnerable/vulnerable", tbc.VulnerableVerifierPolicy(), tbc.VulnerableDeciderPolicy()),
            ("vulnerable/spec_anchored", tbc.VulnerableVerifierPolicy(), tbc.SpecAnchoredDeciderPolicy()),
            ("spec_anchored/vulnerable", tbc.SpecAnchoredVerifierPolicy(), tbc.VulnerableDeciderPolicy()),
            ("defended/vulnerable", tbc.DefendedVerifierPolicy(), tbc.VulnerableDeciderPolicy()),
            ("vulnerable/defended", tbc.VulnerableVerifierPolicy(), tbc.DefendedDeciderPolicy()),
        ]
        for name, verifier, apollo in variants:
            lib = ContextLibrary()
            lib.add(tbc.tbc_context())
            lib.add(tbc.tbc_vendor_context())
            report = CoSACampaign(target=tbc.TheBotCompanyTarget(verifier=verifier, apollo=apollo),
                                  context_library=lib).run(tbc.tbc_mas_spec(), config)
            results.append(summarize(name, report))

    elif args.mode == "llm":
        from targets.llm_policies import make_llm_tbc_policies
        ds, victim = deepseek_client(), kimi_client()
        verifier, apollo = make_llm_tbc_policies(victim, milestone=tbc.MILESTONE_DESCRIPTION)
        lib = ContextLibrary()
        lib.add(tbc.tbc_context())
        lib.add(tbc.tbc_vendor_context())
        report = llm_campaign(tbc.TheBotCompanyTarget(verifier=verifier, apollo=apollo), lib, ds).run(
            tbc.tbc_mas_spec(), config)
        results.append(summarize("llm(kimi)", report, {
            "transcripts": {"attacker": ds.transcript, "victim": victim.transcript}}))

    else:
        from targets.tbc_live import (TBCLiveConfig, TheBotCompanyLiveTarget, VictimCredential,
                                      build_template, preflight, tbc_live_context)
        if not (args.tbc_root and args.run_root):
            ap.error("--mode live needs --tbc-root and --run-root")
        cfg = TBCLiveConfig(tbc_root=os.path.expanduser(args.tbc_root),
                            run_root=os.path.abspath(args.run_root),
                            max_wall_seconds=args.max_wall_seconds)
        preflight(cfg)
        os.makedirs(cfg.run_root, exist_ok=True)
        template = os.path.join(cfg.run_root, "template")
        if not os.path.exists(template):
            build_template(template, VictimCredential(args.victim_base_url, args.victim_model,
                                                      args.victim_key_file))
        lib = ContextLibrary()
        lib.add(tbc_live_context(template))
        target = TheBotCompanyLiveTarget(config=cfg)
        ds = deepseek_client()
        # Only the CI-log source is realized live; the vendor-notes path has no context.
        report = llm_campaign(target, lib, ds).run(tbc.tbc_mas_spec(), config)
        results.append(summarize("live", report, {"runs": target.runs,
                                                  "attacker_transcript": ds.transcript}))

    out = args.out or os.path.join(os.path.dirname(__file__), f"tbc_{args.mode}_results.json")
    with open(out, "w") as f:
        json.dump({"framework": "CoSA", "target": "thebotcompany@df189fe", "mode": args.mode,
                   "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   "results": results}, f, indent=2, ensure_ascii=False, default=str)
    print(f"-> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
