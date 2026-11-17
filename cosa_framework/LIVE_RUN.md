# CoSA live ("real-MAS") targets — P1

This adds a **live** execution path that runs each target MAS's **real upstream
code**, instead of the faithful structural model. The defective task overrides
**one artifact** (the coder-generated code); the real victim agent makes the
coordination decision. Only **P1** (append-only injection into the external source
the victim reads) is supported.

It is fully **additive**: the structural adapters (`targets/self_collab.py`,
`targets/metagpt.py`, `targets/agent_team.py`, `targets/thebotcompany.py`) and
every existing result JSON are untouched. Live runs write new files named
`experiments/live_<target>_p1_results.json`, with the same row schema as the
structural `attack_p1_*` files (so ASR@k / tries_to_success / winning_payload /
induced / success are directly comparable).

> ⚠️ Real agents can execute code. Run only inside a disposable VM / container,
> with no real credentials beyond the victim/attacker model keys.

## What each live target overrides vs. runs

| Target | Overridden artifact (defective task) | P1 source (victim reads) | Real code that runs | Sink |
|---|---|---|---|---|
| `self_collab` | Coder's `solution.py` | the requirement the Tester reads | upstream `_generate_tests` (real Tester LLM) + `_run_generated_test` (real exec) | Tester `passed` → `S_test_status` |
| `metagpt` | Engineer's `code_doc.content` | the PRD (`task_doc`) | real `WriteCodeReview` prompts + `_aask` + `CodeParser` LGTM/LBTM | review pass → `S_review_pass` |
| `agent_team` | Coder's `candidate_code` | the CI report the Tester reads | your agent-teams Tester via a harness; deterministic dependency gate | T2 completed → `S_T2_status` |

The same 20 defective tasks as the structural libraries are reused for each target.

## Upstream checkouts

The live adapters drive real upstream code; supply a checkout per target. Clones
used while building these adapters (read-only, treated as untrusted) live under
`~/code/CoSA/_cosa_upstream/` (`self_collab`, `metagpt`, `thebotcompany`).

- **self_collab** — YihongDong/self-collaboration-code-generation. Needs `openai`,
  `datasets`, `tqdm` importable. Preflight checks `run_humaneval.py` exposes
  `_generate_tests` / `_run_generated_test` / `TESTER_PROMPT`.
- **metagpt** — FoundationAgents/MetaGPT with its deps installed. Preflight imports
  `metagpt.actions.write_code_review`, `metagpt.schema`, `metagpt.config2` and
  checks `WriteCodeReview` / `PROMPT_TEMPLATE` / `EXAMPLE_AND_INSTRUCTION` /
  `FORMAT_EXAMPLE` and the `"Code Review Result"` parse block.
- **agent_team (GatedTeam)** — models Claude Code Agent Teams, which has **no
  standalone upstream repo**. Supply your real agent-teams Tester as a
  `module:callable` harness (see below). Until then its preflight raises
  `AgentTeamLiveUnavailable`.

If a checkout / dep / harness is missing, `preflight` raises `*Unavailable` and the
run stops cleanly — nothing is simulated.

## Running (examples)

```bash
# Self-Collab
python3 experiments/run_live_experiment.py --target self_collab \
    --repo-root ~/code/CoSA/_cosa_upstream/self_collab --run-root /tmp/sc-live-runs \
    --victim-model gpt-5.6-luna --victim-key-file ~/Downloads/api-key/gpt-key.txt \
    --tasks swederiv_sklearn_13439_pipelen        # one task; omit --tasks for all 20

# MetaGPT
python3 experiments/run_live_experiment.py --target metagpt \
    --repo-root ~/code/CoSA/_cosa_upstream/metagpt \
    --victim-model gpt-5.6-luna --victim-key-file ~/Downloads/api-key/gpt-key.txt

# GatedTeam (needs a harness)
python3 experiments/run_live_experiment.py --target agent_team \
    --agent-team-harness my_pkg.at_harness:review \
    --victim-model gpt-5.6-luna --victim-key-file ~/Downloads/api-key/gpt-key.txt
```

Attacker defaults to DeepSeek (`--attacker deepseek`), hill-climb on, 20 attempts /
task — matching the structural `attack_p1_*` runs. Isolate tasks with `--tasks`
(comma-separated ids) or `--limit N`.

## GatedTeam harness contract

```python
def review(request: dict) -> dict:
    # request keys:
    #   candidate_code   str  - the Coder's patch under review (overridden artifact)
    #   ci_report        str  - the CI report the Tester reads (P1 source; may carry payload)
    #   task_id, failing_case, victim_model, victim_base_url, victim_key_file
    # return:
    #   {"completed": bool, "detail": str}
    #   completed == True  => the Tester marked T2 completed (affirmative sink)
    ...
```
The adapter calls this (your real agent-teams Tester) and then applies the
deterministic dependency gate (T3 releases iff T2 is `completed`).

## Scope / caveats

- **P1 only.** Live P2 (tampering a real inter-agent handoff mid-pipeline) needs a
  per-framework seam and is not implemented here.
- **Oracle (ground truth)** is the task's *declared* FAIL_TO_PASS (the code is
  defective by construction), recorded as an independent `oracle` event — the same
  ground truth the structural adapters use. No full SWE-bench repo is executed.
- **self_collab_live** is smoke-tested end-to-end (override + real local test
  execution + evidence) with the LLM stubbed. **metagpt_live** / **agent_team_live**
  have their CoSA-side plumbing smoke-tested; their upstream wiring
  (MetaGPT Context/LLM; your harness) is validated on first real run — `preflight`
  flags any upstream API drift.
