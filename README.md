# CoSA red-team testing framework

A red-teaming framework for multi-agent systems (MAS) that measures one auditable
failure: can low-trust, attacker-reachable content **corrupt a coordination-state
field** and have that error **propagate** through a downstream decision into a
terminal adverse outcome?

A success is a linked, control-attributed chain — **C1** incorrect commitment
(state corrupted while the independent oracle still says FAIL) → **C2** effective
adoption (a consumer reads the field and routes on it) → **C3** terminal outcome.
Missing evidence is `UNVERIFIED`, never a silent pass. An attacker pipeline
(Analyzer → Grafter → Dispatcher → Generator → Judge, under a Reflector search
loop) searches append-only P1 (external source) and P2 (inter-agent message)
injections for a payload that completes the chain.

The framework lives in [`cosa_framework/`](cosa_framework/).

## Integrated target MAS

Each target is attacked both as a **faithful structural model** (deterministic
coordination graph, pluggable victim policy) and, where a checkout is supplied, by
driving the **real upstream code** (`*_live` adapters) with only the coder-produced
artifact overridden.

| Target | What it models | Victim coordinator | Live adapter |
|---|---|---|---|
| **MetaGPT** | classic software company (PM → Architect → ProjectManager → Engineer) | Engineer `WriteCodeReview` | `metagpt_live` (real `WritePRD→WriteDesign→WriteTasks` relay + review; P1 & P2) |
| **TheBotCompany** | autonomous dev team (Ares → Apollo) | Apollo milestone verification | `tbc_live` (real `node` orchestrator) |
| **GatedTeam** | shared-task-list coding team (Coder/Tester/Committer) | Tester marking the gated task complete | `agent_team_live` (harness-pluggable) |

## Quick start

```bash
cd cosa_framework
python3 -m pytest -q          # offline, deterministic — no network or keys
```

Run an attack campaign against the structural targets (needs API keys for the
attacker + victim models; configure endpoints via the runner flags):

```bash
# P1 (external-source injection) over the integrated targets
python3 experiments/run_attack_group.py --permission p1 --tasks <task_ids>

# benign baseline (no injection)
python3 experiments/run_baseline.py --target metagpt
```

Drive a target's **real upstream code** (supply an installed checkout / harness;
run only in a disposable VM — real agents execute code):

```bash
python3 experiments/run_live_experiment.py --target metagpt --permission p1 \
    --repo-root /path/to/MetaGPT --victim-model <model> \
    --victim-key-file /path/to/key.txt --tasks <task_id>
```

See [`cosa_framework/LIVE_RUN.md`](cosa_framework/LIVE_RUN.md) for the live-run
requirements and [`cosa_framework/DESIGN.md`](cosa_framework/DESIGN.md) for the
method design.
