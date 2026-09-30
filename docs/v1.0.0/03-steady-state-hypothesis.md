# Plan 2 — the steady-state hypothesis

**This is the feature that defines 1.0.0.** It is the position neither CNCF
project occupies, and mayhem is the only tool that already holds the raw
material to build it.

## The market gap, precisely

| | Hypothesis model | Tolerance bands |
| --- | --- | --- |
| Chaos Mesh | `StatusCheck` CR, `type` enum is **`["HTTP"]` only**, `failureThreshold` (default 3) consecutive failures | **no** |
| Litmus | per-experiment `probe[]`, 4 types, 5 modes (`SOT`/`EOT`/`Edge`/`Continuous`/`OnChaos`) — the best available phase model | **no** — comparators are scalar equality/range; ROADMAP defers it |
| AWS FIS | `aws:cloudwatch:assert-alarm-state` as a **sequence action** | no bands, but assertion is first-class |
| **mayhem today** | `hypothesis: str` (prose), `success.criteria` (boolean), `slo` | **no** |

Nobody expresses *"latency rose 18%, inside the 20% band"*. Chaos Mesh and
Litmus both stop at a boolean probe result. mayhem has a `verify_probes` on
**every single fault** and does not compare against anything.

## What mayhem already has that this builds on

- `VerifyProbe` on every non-`catalog_only` fault, enforced by
  `FaultLease`'s model validator (`ACTIVE`/`RELEASING` require non-empty
  `verify_probes`).
- A `steady_state_evaluations` table already in `infra/migrations.py:138` —
  schema exists, nothing writes tolerance into it.
- `slo` in `DrillSpec`.
- `success.criteria` with `type` / `source_id` / `expected`.
- `observability.sources` (logs, probes, cadence, timeout) per drill.
- Replay capsules and a hash-chained evidence bundle.

So the gap is not plumbing. It is a comparison model.

## Proposal

### Syntax

Extend `DrillSpec` with a first-class `steady_state` block. Everything is
optional; a drill with no `steady_state` behaves exactly as it does today.

```yaml
steady_state:
  capture:
    samples: 5              # baseline samples before injection
    window: 10s

  signals:
    - name: api.latency.p99
      source_id: api.http
      metric: latency_ms
      expect: { lte: 250 }              # absolute steady-state band

    - name: api.error_rate
      source_id: api.logs
      metric: status_5xx_ratio
      baseline_window: 5m
      tolerance:                         # relative to captured baseline
        at_most: 0.02                    # +2pp absolute
        at_most_relative: 1.5            # <=1.5x baseline
      severity: critical

  phases:
    - during: { assert_unchanged: [api.error_rate] }   # must NOT regress
    - during: { assert_degraded:   [api.latency.p99], within: 2.0 }
    - after:  { assert_recovered:  [api.latency.p99, api.error_rate] }
```

The three verbs carry the semantics the market lacks:

| verb | meaning |
| --- | --- |
| `assert_unchanged` | a *safety* signal: the fault must not move it at all. Errors going up during a latency fault is a **bug in the system under test**, and the drill should say so. |
| `assert_degraded` | the *hypothesis*: the signal must move, by a bounded amount. This is what proves the fault did anything. |
| `assert_recovered` | after undo, every signal must return **within tolerance of the captured baseline**, not merely "be present." |

`assert_recovered` is the one that makes this a chaos tool rather than a load
generator, and it is the same thing Litmus means by "leaves no chaos residue
regardless of success."

### Verdict

Replace the boolean with a graded one, while keeping the boolean available:

```json
{
  "verdict": "degraded-within-tolerance",
  "signals": [
    {"name": "api.latency.p99", "baseline_ms": 88, "during_ms": 412,
     "delta_pct": 368, "asserted": "degraded", "within": 2.0, "pass": true},
    {"name": "api.error_rate", "baseline": 0.001, "during": 0.004,
     "asserted": "unchanged", "pass": false,
     "note": "safety signal moved; the target degraded beyond the fault under test"}
  ],
  "recovered": true,
  "max_recovery_delta_pct": 3.1
}
```

Verdict enum: `as-hypothesised` · `degraded-within-tolerance` ·
`degraded-beyond-tolerance` · `no-effect` (the fault did nothing — a real and
under-reported failure mode) · `not-recovered` (residue).

`no-effect` is deliberately a first-class verdict. Both CNCF projects cannot
distinguish "the fault had no impact" from "the probe never fired"; mayhem can,
because it has the baseline and the perturbation window.

### Interaction with the impact gate

This closes a real gap. `agents/impact.py` currently **bypasses** a fault the
gate proves inert, with a printed reason. With a baseline, that becomes
measurable rather than inferred: if the gate says inert and the observed
baseline-vs-during delta is zero, the bypass is *confirmed*. If the gate says
inert but the signal moved, something is wrong with the gate.

That is a self-checking property, and it is free once baseline capture exists.

### Interaction with maturity

`verified-live` from [02](02-earn-maturity.md) and this are the same machinery.
Baseline capture + tolerance evaluation is what makes live verification possible
at all. Build this first, and 02 gets materially cheaper.

## Sequencing

| Step | Deliverable | Depends on |
| --- | --- | --- |
| 1 | `steady_state.signals` + baseline capture, printed report | — |
| 2 | `assert_recovered` with tolerance vs baseline | 1 |
| 3 | `assert_degraded` / `assert_unchanged`, graded verdict | 1 |
| 4 | Verdict + signal detail into the evidence bundle | 2, 3 |
| 5 | Impact-gate cross-check (confirmed vs contradicted bypass) | 2 |
| 6 | `--baseline-from <run-id>`: reuse a previous healthy run as the reference | 2 |

Step 6 is the one that makes this composable across a campaign: the first run
establishes what "healthy" means for this stack, and every later fault is judged
against that. Litmus and Chaos Mesh have no equivalent — their probes are
absolute, so "latency ≤ 250ms" is a number someone typed by hand and is wrong
for every service but one.

## Risks

- **Signal extraction is the real cost.** `metric: latency_ms` needs a defined
  source per observability kind. This is the bulk of the work and it is
  unavoidably per-source. Start with `kind: probe` (http) only.
- **Baseline noise.** 5 samples is not a baseline. Needs a `baseline_window` and
  a percentile, not a mean. Getting this wrong makes the tool confidently wrong,
  which is worse than no tool.
- **Scope creep into a monitoring product.** Resist. The goal is to judge
  whether *the fault* did what it claimed and left no residue. Not to build
  Grafana.

---

## STATUS — SHIPPED. All six steps. 201 tests.

| Step | State |
| --- | --- |
| 1 — signals + baseline capture | **DONE.** `observability/metrics.py`; capture reuses the executor's own collector, so the declared cadence and timeout are the cadence that runs. `sample_baseline` reduces at the **percentile, not the mean**. |
| 2 — `assert_recovered` vs baseline | **DONE.** |
| 3 — the three verbs + graded verdict | **DONE.** All five `Verdict` members reachable from real evaluation, including `no-effect`. |
| 4 — verdict into the bundle | **DONE.** `EvidenceEnvelope.steady_state`, redacted on the way in. `assert_bundle_safe` runs `json.dumps(..., allow_nan=False)` before every write; `None`-as-number is refused unless it carries a note. A zero baseline serialises as `null` and the bundle still verifies. |
| 5 — impact-gate cross-check | **DONE.** Three answers, not two: **confirmed** (gate inert, nothing moved), **contradicted** (gate inert, a signal moved — the gate's verdict is wrong and the bypass was unsound), **unverified** (nothing measurable — never reported as confirmed). A *safety* signal moving is not a contradiction: that is a different question. |
| 6 — `--baseline-from <run-id>` | **DONE.** On `mayhem run`. An unknown run id is **refused by name** before anything is injected — never a silent fresh capture. The report says which run it was measured against, or that it was freshly captured. |

### The bug worth recording

The first implementation was **sign-blind**: `abs(measured) <= abs(baseline) * mult`
made a signal that went **+100 → -100** grade as `recovered / as-hypothesised`,
while `delta_pct` correctly reported −200%. The module contradicted itself —
`delta_pct` deliberately divided by `abs(baseline)` to preserve sign, and
`within_relative` threw the sign away two functions later. A relative tolerance
measures **deviation from the baseline**, not magnitude. Fixed, with 20 tests
that fail against the pre-fix tree.

### Wiring that was invisible

The evaluator was fully built and **never ran**: the spec was looked up on the
`Preflight`, which carries no spec, so `_steady_spec_from` returned `None` on
every real run. `CompiledPlan` now carries the spec it was compiled from, and
the `during` readings are lifted from the executor's own observations rather
than inferred. An ungraded assertion is never a pass — the block says
`not-graded` and every signal reads `n/a`.
