# CoSA live ("real-MAS") runs

The `*_live` adapters run a target's **real upstream code** instead of the
structural model. The defective task overrides **one artifact** (the coder-produced
code); the real victim agent makes the coordination decision, and the real
coordination-state write + deliverable are **observed**, not synthesized.

> ⚠️ Real agents can execute code. Run only inside a disposable VM / container,
> with no real credentials beyond the victim/attacker model keys.

Results are written to new files (`live_<target>_<permission>_results.json`); the
structural adapters and their result JSONs are never touched. If a checkout / dep /
harness is missing, `preflight` raises `*Unavailable` and the run stops cleanly —
nothing is simulated.

## Targets

| Target | Overridden artifact | Real code driven | Channels |
|---|---|---|---|
| **metagpt** (`metagpt_live`) | Engineer's code | `WritePRD→WriteDesign→WriteTasks` relay + `WriteCodeReview` + `repo.srcs.save` | **P1** (external requirement via the relay) and **P2** (Architect→Engineer design handoff) |
| **thebotcompany** (`tbc_live`) | the epoch CI log / code | the real `node src/server.js` orchestrator | P1 |
| **agent_team** / GatedTeam (`agent_team_live`) | the Coder's patch | your agent-teams Tester via a `module:callable` harness | P1 |

The same defective task libraries as the structural adapters are reused.

## Running

```bash
# MetaGPT — needs a checkout of FoundationAgents/MetaGPT with deps installed.
# P1 injects the external requirement and runs the real upstream relay; P2 injects
# the Architect→Engineer design handoff.
python3 experiments/run_live_experiment.py --target metagpt --permission p1 \
    --repo-root /path/to/MetaGPT --victim-model <model> \
    --victim-key-file /path/to/key.txt --tasks <task_id>

python3 experiments/run_live_experiment.py --target metagpt --permission p2 \
    --repo-root /path/to/MetaGPT --victim-model <model> \
    --victim-key-file /path/to/key.txt --tasks <task_id>

# GatedTeam — supply your real agent-teams Tester as a harness
python3 experiments/run_live_experiment.py --target agent_team \
    --agent-team-harness my_pkg.at_harness:review --victim-model <model>

# TheBotCompany live orchestrator
python3 experiments/run_tbc_experiment.py --mode live --tbc-root /path/to/thebotcompany \
    --run-root /tmp/tbc-runs
```

MetaGPT setup notes: a `~/.metagpt/config2.yaml` with a valid `llm` is required
(MetaGPT loads it at import); `metagpt_live` stubs the unused provider SDKs and
adds an OpenAI param-compat shim so newer victim models (e.g. `max_completion_tokens`
only) run against the upstream backend unchanged. Use `--no-keep-runs` for large
batches to avoid accumulating per-replay workspaces.

## GatedTeam harness contract

```python
def review(request: dict) -> dict:
    # request: candidate_code, ci_report (P1 source; may carry payload), task_id,
    #          failing_case, victim_model, victim_base_url, victim_key_file
    # returns: {"completed": bool, "detail": str}
    ...
```

## Scope / caveats

- The oracle (ground truth) is the task's **declared** FAIL_TO_PASS; the live path
  observes the real review decision and workspace deliverable, not a re-executed
  acceptance suite.
- MetaGPT is modeled as the **classic** software company (Engineer + WriteCodeReview);
  this clone's out-of-box default is the newer Engineer2/MGX architecture.
- QA is off by default in MetaGPT (`run_tests=False`), so the Engineer's review +
  workspace write is the terminal; with `--run-tests` the QaEngineer adds a further
  gate that `metagpt_live` does not model.
