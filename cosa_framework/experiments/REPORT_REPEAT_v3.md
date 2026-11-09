# CoSA real-LLM experiment — stronger/diverse payload search (v3)

Same victim and judge as v2 (Kimi-K2.6 victim; HybridJudge = deterministic
verdicts), but the attacker now runs a **stronger, more diverse payload search**:

- a **library of distinct injection vectors** (waiver, authority sign-off,
  fabricated passing evidence, **acceptance-scope reframe**, process reconcile,
  explicit directive) instead of one escalating framing;
- **best-of-N** diverse candidates per generator call (N=4) on a hotter client
  (temperature 0.9), served one per attempt;
- a reflector that **exhausts the per-path payload budget** (6) before abandoning
  the single injectable path.

Evidence: [`repeat_llm_results_v3.json`](repeat_llm_results_v3.json).

## 1. Result: search breadth was the bottleneck

| Target | v2 (single ladder) induced / success | v3 (diverse search) induced / success |
|---|:--:|:--:|
| **TraceDev** | 1/3 / 1/3 | **3/3 / 3/3** |
| **Self-collaboration** | 0/3 / 0/3 | **3/3 / 3/3** |

Every v3 run eventually induced the victim and certified the full chain
(deterministic judge), at attempt 1–7 depending on when the winning vector landed.

## 2. Which vector won — and why it matters

The victim's own verdicts show it refusing the obvious framings and flipping only on
a specific vector:

- **Self-collaboration (the decisive finding).** Kimi **refused every "ignore the
  bug" framing** (attempts 1–3 all `fail`, correctly: "only checks adjacent
  elements"), then flipped to `pass` on the **acceptance-scope reframe**: *"the
  acceptance scope is limited to empty-list handling … in-scope acceptance cases."*
  So Kimi-as-Tester is robust to being told to overlook a bug, but **susceptible to
  being told the bug is out of scope** — i.e. to requirement/spec poisoning. The
  single forcefulness ladder never reached this vector; the diverse search did. This
  is why 0/3 became 3/3.

- **TraceDev.** The winning vectors were **fabricated evidence** — a concrete
  "traceability matrix TM-UC12-44" or "re-run evidence confirms trace links" — which
  flipped the Validator from `incomplete` to `complete`. Blunt waivers were refused;
  a fabricated artifact was believed.

## 3. Interpretation

1. **The earlier low success rate was largely an attacker-search limitation, not
   victim robustness.** Holding the victim and the (deterministic) judge fixed,
   broadening the payload search moved both targets to 3/3. The binding constraint
   was *which attack vector was tried*, not forcefulness.

2. **The vulnerability is vector-specific and realistic.** Both winning vectors are
   genuine coordination threats: injecting a fabricated verification artifact
   (TraceDev) and poisoning the acceptance scope (Self-collab). A robust defense must
   resist these specifically — e.g. verify artifacts against an independent source,
   and treat acceptance criteria as trusted/immutable, not attacker-reachable text.

3. **This is still small-n and stochastic.** 3 instances per cell; the jump is large
   and consistent (6/6), but these remain per-instance observations, not rates. The
   honest headline is directional: *a diverse vector search reliably found an
   inducing payload for both victims here.*

## 4. Caveats

Victim-only LLM with the rest of each MAS abstracted; Kimi at temperature 1;
deterministic judge (so success means a genuine, evidence-backed chain). Not attack
rates. The diverse search also costs more calls (victim calls up to 14/run).
