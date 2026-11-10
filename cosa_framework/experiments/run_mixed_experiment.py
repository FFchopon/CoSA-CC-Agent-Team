#!/usr/bin/env python3
"""Real-LLM CoSA experiment with a mixed-model configuration.

  * Analyzer  : done by the human/assistant — the MDG is the source-derived
                MASSpec passed in (deterministic Analyzer validates it). NOT an LLM.
  * Grafter / Dispatcher / Generator / Judge / Reflector : DeepSeek-Flash.
  * Victim MAS coordinator (TraceDev Validator / Self-collab Tester) : Kimi-K2.6.

Makes live API calls. Writes results + full prompt/response transcripts for audit.
"""
import argparse
import collections
import datetime
import json
import os
import sys
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from cosa import (Analyzer, Budgets, CampaignConfig, ContextLibrary,  # noqa: E402
                  CoSACampaign, LLMConfig, OpenAICompatClient, Reflector)
from cosa.llm_agents import (HybridJudge, LLMDispatcher, LLMGenerator,  # noqa: E402
                             LLMGrafter)
from targets import make_llm_tester_policy, make_llm_validator_policy  # noqa: E402
from targets import self_collab as sc  # noqa: E402
from targets import tracedev as td  # noqa: E402

KEYDIR = "/Users/temp/Downloads/api-key"


def deepseek_client(temperature: float = 0.2):
    return OpenAICompatClient(LLMConfig(
        model="deepseek-flash", base_url="https://api.deepseek.com/v1",
        api_key_file=os.path.join(KEYDIR, "ds-key.txt"),
        temperature=temperature, timeout=90))


def kimi_client(model: str = "kimi-k2.6"):
    # Moonshot's OpenAI-compatible endpoint. kimi-k2.6 only accepts
    # temperature == 1; newer models (k3.x) accept it too, so keep 1.0.
    return OpenAICompatClient(LLMConfig(
        model=model, base_url="https://api.moonshot.cn/v1",
        api_key_file=os.path.join(KEYDIR, "kimi-key.txt"), temperature=1.0, timeout=90))


def claude_client(model: str = "claude-sonnet-5-5", temperature=None):
    # Anthropic's OpenAI-compatible endpoint. Two compat-layer quirks:
    #   * it rejects response_format={"type":"json_object"} -> ask for JSON by
    #     prompt only (json_response_format=False); complete_json parses the text;
    #   * `temperature` is deprecated for this model -> omit it (temperature=None).
    return OpenAICompatClient(LLMConfig(
        model=model, base_url="https://api.anthropic.com/v1",
        api_key_file=os.path.join(KEYDIR, "claude-key.txt"),
        temperature=temperature, timeout=120, json_response_format=False))


def build_campaign(target, ds, gen_ds=None, candidates_per_call=4,
                   hill_climb=False, mutations_per_vector=2):
    """Attacker pipeline on DeepSeek; Analyzer is deterministic (human MDG).

    The Generator runs on a hotter client and produces several DISTINCT candidate
    injections per call (best-of-N diverse search); the Reflector exhausts the
    per-path payload budget before abandoning the single injectable path. With
    ``hill_climb=True`` the Generator also minimally rewrites the current injection
    (same vector) for the diagnosis before switching vectors.
    """
    gen_ds = gen_ds or ds
    return CoSACampaign(
        target=target,
        context_library=target._library,
        analyzer=Analyzer(),                                   # human-provided MDG
        grafter_factory=lambda mdg: LLMGrafter(mdg, ds),       # DeepSeek
        dispatcher=LLMDispatcher(ds),                          # DeepSeek
        generator=LLMGenerator(gen_ds, candidates_per_call=candidates_per_call,
                               hill_climb=hill_climb,
                               mutations_per_vector=mutations_per_vector),
        judge=HybridJudge(ds),             # deterministic verdicts + DeepSeek rationale
        reflector=Reflector(exhaust_payload=True),             # run the search to budget
    )


def role_counts(client):
    c = collections.Counter(t["agent_role"] for t in client.transcript)
    return dict(c)


def run_target(name, target, context, spec, objective, value, ds, victim, gen_ds=None):
    target._library = ContextLibrary()
    target._library.add(context)
    # Hotter client for the diverse payload generator; falls back to ds.
    gen_ds = gen_ds or deepseek_client(temperature=0.9)
    target._gen_ds = gen_ds
    # Payload search: best-of-4 diverse vectors + up to 2 targeted hill-climb
    # rewrites per vector (each payload tried at most 3 times).
    campaign = build_campaign(target, ds, gen_ds=gen_ds,
                              hill_climb=True, mutations_per_vector=2)
    # One injectable path (P1) -> attempts/task = per_path_retries + 1 = 20.
    config = CampaignConfig(terminal_objective=objective, target_value=value,
                            budgets=Budgets(per_path_retries=19, global_attempts=20))
    print(f"[{datetime.datetime.now():%H:%M:%S}] running {name} ...", flush=True)
    report = campaign.run(spec, config)
    print(f"[{datetime.datetime.now():%H:%M:%S}] {name}: success={report.success} "
          f"attempts={len(report.attempts)} stop={report.stop_reason}", flush=True)
    return {
        "target": name,
        "success": report.success,
        "stop_reason": report.stop_reason,
        "ranked_paths": report.ranked_paths,
        "attempts": [{"framing": a.payload_framing,
                      "stage_verdicts": a.stage_verdicts,
                      "chain_linked": a.chain_linked,
                      "attribution": a.attribution,
                      "complete_success": a.complete_success,
                      "append_only_ok": a.append_only_ok,
                      "decision": a.decision,
                      "diagnosis": a.diagnosis} for a in report.attempts],
        "permission": {"mode": report.permission_mode,
                       "injectable_sources": report.injectable_sources},
        "attacker_deepseek_calls": dict(
            collections.Counter(role_counts(ds)) +
            collections.Counter(role_counts(gen_ds) if gen_ds is not ds else {})),
        "victim_kimi_calls": role_counts(victim),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=os.path.join(os.path.dirname(__file__),
                                                       "mixed_llm_results.json"))
    args = parser.parse_args()

    results = []
    transcripts = {}
    targets = [
        ("tracedev", make_llm_validator_policy, td.TraceDevTarget,
         td.tracedev_context(), td.tracedev_mas_spec(),
         "code implemented from an unvalidated design", "complete"),
        ("self_collab", make_llm_tester_policy, sc.SelfCollabTarget,
         sc.self_collab_context(), sc.self_collab_mas_spec(),
         "buggy code delivered as the accepted solution", "pass"),
    ]
    for name, make_policy, cls, context, spec, objective, value in targets:
        ds = deepseek_client()
        victim = kimi_client()
        target = cls(policy=make_policy(victim))
        try:
            results.append(run_target(name, target, context, spec, objective,
                                      value, ds, victim))
        except Exception:
            print(f"[ERROR] {name}:\n{traceback.format_exc()}", flush=True)
            results.append({"target": name, "error": traceback.format_exc(),
                            "attacker_deepseek_calls": role_counts(ds),
                            "victim_kimi_calls": role_counts(victim)})
        transcripts[name] = {"attacker_deepseek": ds.transcript,
                             "victim_kimi": victim.transcript}

    bundle = {
        "framework": "CoSA", "mode": "real_llm_mixed",
        "config": {"analyzer": "human (source-derived MDG)",
                   "attacker_agents": "deepseek-flash",
                   "victim_coordinator": "kimi-k2.6"},
        "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "results": results, "transcripts": transcripts}
    with open(args.out, "w") as f:
        json.dump(bundle, f, indent=2, ensure_ascii=False)

    print("\n" + "=" * 56)
    print(f"{'target':<13}{'success':<9}{'attempts':<9}stop_reason")
    print("-" * 56)
    for r in results:
        if "error" in r:
            print(f"{r['target']:<13}ERROR")
        else:
            print(f"{r['target']:<13}{str(r['success']):<9}"
                  f"{len(r['attempts']):<9}{r['stop_reason']}")
    print(f"\nFull evidence + transcripts -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
