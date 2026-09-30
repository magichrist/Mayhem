# Plan 15 — Resilience Analytics and Adaptive Experiments

**Priority:** P1/P2. Gap items 25, 52, 53, 90, 91, 92, 93, 94, 95, 96.

## Objective
Move from binary chaos testing toward quantitative resilience characterization: statistics, causal chains, progressive delivery, and bounded search for resilience limits — with the AI strictly unable to reach execution authority.

## Builds on
- The graded verdict plus `no-effect`/`not-recovered` semantics and percentile-based baseline reduction stay the statistical core; new analytics extend them.
- `infra/kpi.py`, `infra/ranking.py` (RNG-free), and the M5 report builder stay the analysis substrate.
- Existing steady-state phases (pre/during/post) gain warm-up/cooldown handling; they are not replaced.

## Analytics
Baseline distributions, percentile comparison, effect size, confidence
intervals, noise estimation, sample sufficiency, warm-up/cooldown,
change-point/anomaly detection. A verdict reads like "p99 moved 5.2%
with overlapping 95% CI — NO MATERIAL EFFECT", never "520ms → FAIL".

## Resilience boundary search
Start with a small impairment and increase until the declared tolerance
is crossed (`1% loss -> 5% -> 10% -> 20%`), then minimize the boundary
(`20 -> 10 -> 5 -> 2.5 -> 3.75 -> 3.1 ...`).

## Counterexample minimization
When a complex experiment fails, automatically search for the smallest
fault/target combination that reproduces the failure.

## Progressive delivery (gaps 90, 91)
Single target → 5% → 10% → 25% → 50% stage gates (canary faulting),
each stage requiring SLO health before promotion, with automatic stop
on breach. Stages are plan-level constructs compiled from one
experiment, not ad-hoc reruns.

## Outputs
Tolerance boundary, minimal failure case, recovery curve, resilience
trend over releases, confidence/uncertainty.

## Phase 1 — Domain model: statistics and search policies
Add `domain/analytics.py`: distribution summaries, comparison results with confidence intervals, sufficiency predicates; add `domain/search.py`: `SearchPolicy` (start, step, stop-on-breach, minimization strategy, combination budget for gap 95), all pure over recorded observations. AI-generated candidates (gap 25) modeled as untrusted drafts: same type as authored plans, zero authority. Acceptance: statistics tests on fixture streams; search-policy determinism tests.

## Phase 2 — Engine: analysis service and adaptive runner
Analysis service computes boundaries, curves, and causal chains (gap 53: fault → target → dependency → metric change → customer impact as a traced path over observations plus topology). Adaptive runner executes search policies as sequences of approved micro-plans, each through full admission with remaining-budget checks — search respects safety budgets at every step, and budget exhaustion halts with findings so far. Progressive stages compile to gated step groups. Acceptance: a search that breaches tolerance stops and reports the boundary; an AI draft that fails compilation never reaches policy evaluation.

## Phase 3 — Surface: boundary reports and candidate review
Boundary reports (service tolerates latency ≤ X, loss ≤ Y with confidence), minimal-failure-case reports, candidate review flows where generated plans face identical validation, policy, impact, approval, and evidence gates as authored ones. Acceptance: generated and authored plans are indistinguishable downstream of compilation (same types, same gates).

## Phase 4 — Safety and evidence integration
Every search step individually admitted, budgeted, and evidenced; AI assistance cannot bypass safety or approval gates (architectural rule, tested not asserted); causal claims cite the observations plus topology edges that support them. Acceptance: an end-to-end adaptive run whose every step traces to evidence and budget entries.

## Phase 5 — Tests, regression guards, negative controls
Statistics unit tests (CI overlap logic, sufficiency thresholds), search tests on simulated response surfaces (finds planted boundaries; minimizes planted counterexamples), AI-boundary tests (draft with embedded approval token rejected; direct-execution attempt from advisor context refused). Negative controls: a search without a remaining budget refuses its next step; a causal claim over missing edges is withheld, not guessed. Acceptance: full matrix green.

## Phase 6 — Docs, honesty gates, rollout
Statistics interpretation guide (what "no material effect" does and does not mean), boundary-report reading guide, advisor methodology doc (priority from declared customer criteria, never opaque ranking). Rollout: analytics first, progressive stages second, boundary search third, minimization and AI candidates last. Acceptance: no doc presents a boundary as a guarantee across releases (that claim belongs to 22 regression tracking).

## Dependencies
07 (budgets per step), 11 (observations, tolerances), 14 (topology edges for causal paths), 21 (advisor inputs), 22 (trend storage).

## STATUS — planning only, 0%
