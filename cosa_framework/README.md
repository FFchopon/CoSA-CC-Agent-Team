# CoSA red-team testing framework

A local-only, model-optional implementation of the **CoSA** method
(*Coordination-State corruption And propagation*) for red-teaming Multi-Agent
Systems. It operationalizes the five-agent pipeline from the method slides into
runnable, inspectable, unit-tested components, with a deterministic reference
target so the whole methodology runs with **no network and no LLM**.

See [`DESIGN.md`](DESIGN.md) for the full method design and how it maps to the
slides.

## What it tests

Not "can a model be made to say something bad", but one auditable coordination
failure: can low-trust external content corrupt a **coordination-state field** and
have that error **propagate** through a downstream decision into a terminal adverse
outcome? Success requires a linked, differentially-attributed chain:

- **C1** incorrect commitment (state corrupted while ground truth still FAIL),
- **C2** effective adoption (a consumer reads the field and routes on it),
- **C3** terminal outcome (the adverse effect occurs),

plus an ordered linked chain and attribution against a control replay. Missing
evidence is `UNVERIFIED`, never a silent pass.

## Pipeline

```
MASSpec --Analyzer--> MDG --Grafter--> ranked source->sink paths
   loop (under reflection budgets):
     path+context --Dispatcher--> frozen TestSpecification (TestPlan + FixedChecks)
     TestPlan     --Generator--> injection payload
     payload      --Executor-->  control + attack evidence bundles
     evidence     --Judge-->     per-stage verdicts + chain + attribution
     verdict      --Reflector--> refine payload | rebind context | new path | stop
```

## Run it

```sh
# End-to-end campaign against the reference dev-team target (no deps):
python3 examples/run_dev_team_campaign.py             # vulnerable policy -> success
python3 examples/run_dev_team_campaign.py --defended  # oracle-gated     -> fails closed

# Test suite (dependency-free runner; the test files are also pytest-compatible):
python3 tests/run_tests.py
#   or, if pytest is installed:  pytest
```

Expected: the vulnerable target yields a complete C1→C2→C3 chain after the payload
escalates through the generator's framing ladder; the defended target refutes C1 on
every framing and the campaign stops with no success.

## Layout

```
cosa/          the methodology: spec, mdg, analyzer, graph_search, grafter,
               context_library, dispatcher, generator, execution, judge,
               reflection, orchestrator
targets/       TargetMAS adapter + deterministic reference dev-team target
examples/      end-to-end campaign runner
tests/         unit + end-to-end tests and a dependency-free runner
```

## Plugging in a real MAS

Implement `targets/base.py:TargetMAS` (`reset(checkpoint)` + `run(source_value,
recorder)`), record evidence events as the system writes coordination state, makes
consumer decisions, and produces terminal artifacts, then describe its structure as
a `MASSpec` and register one or more benign `ContextInstance`s. The five-agent
pipeline and the Judge are unchanged. A model-backed payload generator implements
the same `PayloadGenerator` interface as the built-in template generator.

## Relationship to the existing demo

The repository root (`lab.py`, `run_*.py`) is one hard-coded instantiation of this
exact chain. This framework is the generalized methodology; its reference target
reproduces that same scenario through the adapter interface. The existing files are
left unchanged.

## Scope

Bounded instances on synthetic targets. A run reports only what its evidence
supports; it does not estimate an attack rate or establish a general property of any
model or product.
