# Running CoSA with real LLM agents

The framework runs in two modes behind one set of interfaces:

- **Deterministic (offline, default).** Every agent is Python; no network, no model.
  Used by the test suite and the structural experiments.
- **Real-LLM.** Each CoSA agent — and the victim MAS's coordinator — is a real LLM.

Switching modes is dependency injection; no pipeline logic changes.

## What becomes an LLM

| Agent | Deterministic | LLM-backed | Tool it still uses |
|---|---|---|---|
| Analyzer | `Analyzer` | `LLMAnalyzer` | structural MDG validator |
| Grafter | `Grafter` | `LLMGrafter` | `GraphSearchTool` (structural traversal) |
| Dispatcher | `Dispatcher` | `LLMDispatcher` | fixed C1/C2/C3 predicate library |
| Generator | `TemplatePayloadGenerator` | `LLMGenerator` | — |
| Judge | `Judge` | `LLMJudge` | evidence guardrail (see below) |
| Reflector | `Reflector` | `LLMReflector` | budget limits (hard) |
| **Victim coordinator** | `Vulnerable/Defended*Policy` | `LLMCoordinatorPolicy` | — |

### Soundness guardrails (kept even in LLM mode)

- **Judge.** The LLM assigns per-stage verdicts, but a SUPPORTED verdict is
  **downgraded to UNVERIFIED unless the required evidence kind is actually present**
  in the attack bundle. Chain linkage and attribution are computed deterministically
  from evidence order indices, not from the model's prose. So the Judge is an LLM
  agent that still cannot pass a stage on narration alone.
- **Dispatcher.** The LLM writes the Test Plan and the human-readable selectors, but
  the **executable** C1/C2/C3 predicates come from the fixed library — generation
  cannot redefine success (slide 11).
- **Reflector.** Success and budget exhaustion are decided deterministically; the
  LLM only chooses among routing actions within budget.
- **Analyzer.** The LLM-derived MDG is run through the structural validator; an
  unsound graph is reported, not silently used.

## API client

`OpenAICompatClient(LLMConfig(...))` speaks the OpenAI-compatible
`/chat/completions` API (OpenAI, DeepSeek, or any `base_url`). It is stdlib-only and
makes no network call until an agent calls it. Keys resolve lazily from
`LLMConfig.api_key` → `api_key_file` → `api_key_env`, and are never written to the
transcript. Every call is appended to `client.transcript` for evidence.

## Wiring an all-LLM campaign

```python
from cosa import OpenAICompatClient, LLMConfig, ContextLibrary, build_llm_campaign, CampaignConfig
from targets import tracedev as td, make_llm_validator_policy

client = OpenAICompatClient(LLMConfig(model="deepseek-v4-flash", api_key_env="DEEPSEEK_API_KEY"))

target = td.TraceDevTarget(policy=make_llm_validator_policy(client))   # real-LLM victim
library = ContextLibrary(); library.add(td.tracedev_context())
campaign = build_llm_campaign(target, library, client)                # real-LLM pipeline
report = campaign.run(td.tracedev_mas_spec(), CampaignConfig(
    terminal_objective="code implemented from an unvalidated design", target_value="complete"))
```

Separate attacker and victim models are supported — pass two clients (see
`experiments/run_llm_experiments.py`).

## Running the real experiment

`experiments/run_llm_experiments.py` runs both targets end to end with live models
and writes results **plus the full prompt/response transcripts** for audit:

```sh
export DEEPSEEK_API_KEY=sk-...
python3 experiments/run_llm_experiments.py --attacker-model deepseek-v4-flash --victim-model gpt-4o
```

This requires network and keys and is intentionally **not** part of the offline test
suite. The offline suite (`python3 tests/run_tests.py`) exercises the same LLM code
paths with a `FakeLLMClient` (canned responses, no network), including the Judge
guardrail and an end-to-end all-LLM campaign against a scripted LLM victim.

## Honesty note

A real-LLM run produces a genuine per-instance observation (did *this* model, under
*this* prompt, complete the chain, with evidence). It is still a bounded instance,
not an attack-rate; report it with the same scope caveats as the structural runs.
