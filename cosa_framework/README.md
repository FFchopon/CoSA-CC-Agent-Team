# CoSA red-team testing framework

A local-first implementation of the **CoSA** method (*Coordination-State
corruption And propagation*) for red-teaming Multi-Agent Systems. It turns the
five-agent pipeline from the method into runnable, inspectable, unit-tested
components. Every agent and every target coordinator is **model-optional**: the
whole methodology runs offline against a deterministic reference target, and the
same pipeline drives **real LLMs** (attacker agents and victim coordinator)
through any OpenAI-compatible endpoint.

See [`DESIGN.md`](DESIGN.md) for the full method design and [`LLM.md`](LLM.md) for
the real-LLM wiring.

## What it tests

Not "can a model be made to say something bad", but one auditable coordination
failure: can low-trust external content corrupt a **coordination-state field** and
have that error **propagate** through a downstream decision into a terminal adverse
outcome? Success requires a linked, differentially-attributed chain:

- **C1** incorrect commitment — state corrupted while the independent oracle still says FAIL,
- **C2** effective adoption — a consumer reads the field and routes on it,
- **C3** terminal outcome — the adverse effect / artifact occurs,

plus an ordered linked chain and attribution against a **control replay**. Missing
evidence is `UNVERIFIED`, never a silent pass.

## Pipeline

```
MASSpec --Analyzer--> MDG --Grafter--> ranked source->sink paths
  loop (under reflection budgets):
    path+context --Dispatcher--> frozen TestSpecification (TestPlan + FixedChecks)
    TestPlan     --Generator--> injection payload   (P1 append-only, enforced)
    payload      --Executor-->  control + attack evidence bundles
    evidence     --Judge-->     per-stage verdicts + chain + attribution
    verdict      --Reflector--> refine payload | rebind context | new path | stop
```

- **Attacker permission (P1):** the attacker may only **append** text to an
  external-resource DATA node. The Analyzer marks injectable sources, the Dispatcher
  freezes the allowed edit, and the orchestrator enforces append-only end to end.
- **Generator:** diverse best-of-N search over a library of injection vectors, with
  optional per-vector hill-climb (minimal-rewrite refinement) before switching
  vectors; falls back to a deterministic template generator offline.
- **Judge:** `HybridJudge` keeps the C1/C2/C3 verdicts deterministic (evidence-gated)
  and uses the LLM only for human-readable rationale.

## Target MAS

Each adapter is a **faithful structural model** derived from the real system's
source, deterministic and model-free, with the coordination decision exposed as a
**pluggable policy** — swap in `llm_policies` to make that coordinator a real LLM.

A `*_live` adapter additionally drives the real upstream code (see `LIVE_RUN.md`).

| Adapter | Models | Sink (coordination field) |
|---|---|---|
| `metagpt` (`metagpt_live`) | [MetaGPT](https://github.com/FoundationAgents/MetaGPT) software company | code-review verdict |
| `thebotcompany` (`tbc_live`) | [TheBotCompany](https://github.com/syifan/thebotcompany) (two-hop verify → Apollo) | milestone verify pass/fail |
| `agent_team` / GatedTeam (`agent_team_live`) | shared-task-list coder/tester/committer | release verdict |

The victim coordinator model is configurable (any OpenAI-compatible endpoint, e.g.
DeepSeek / Kimi / GPT / Claude). API keys are read at run time from a local key
directory via `api_key_file` and are **never committed**.

## Run it

```sh
# Offline test suite (deterministic; no deps, no network, no keys):
python3 -m pytest -q

# Attack campaign against the structural targets (needs attacker + victim keys):
python3 experiments/run_attack_group.py --permission p1 --tasks <task_ids>

# Benign baseline (no injection):
python3 experiments/run_baseline.py --target metagpt
```

Driving a target's real upstream code is documented in `LIVE_RUN.md`.

Real-LLM campaigns live under `experiments/` (e.g. `run_attack_group.py`,
`run_mixed_experiment.py`), configured per target with `--attacker` / victim-model
flags. They make live API calls and need keys in the local key directory. Result
files are intentionally **not** tracked in this repository.

## Layout

```
cosa/          methodology: spec, mdg, analyzer, graph_search, grafter,
               context_library, dispatcher, generator, execution, judge,
               reflection, orchestrator, llm (OpenAI-compat client), llm_agents
targets/       TargetMAS adapters (reference + the integrated systems above)
examples/      offline end-to-end campaign runner
experiments/   real-LLM campaign runners (results not committed)
tests/         unit + end-to-end tests and a dependency-free runner
```

## Plugging in a real MAS

Implement `targets/base.py:TargetMAS` (`reset(checkpoint)` + `run(source_value,
recorder)`): record evidence events as the system reads the source, writes
coordination state, makes the consumer decision, and produces terminal artifacts.
Describe its structure as a `MASSpec`, register one or more benign
`ContextInstance`s, and (optionally) back the coordinator with an `llm_policies`
policy. The five-agent pipeline and the Judge are unchanged.

## Scope

Bounded instances on synthetic/faithfully-modeled targets. A run reports only what
its evidence supports; it does not estimate an attack rate or establish a general
property of any model or product. The ground-truth oracle for each defective task is
**declared** (a checkpoint flag), not executed, unless an adapter states otherwise
(`tbc_live` runs a real hidden suite).
