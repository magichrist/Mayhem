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

## STATUS
- Phase 1 (domain model): DONE — `domain/analytics.py` (distribution summaries, effect size, 95% CIs, sufficiency, warm-up/cooldown) and `domain/search.py` (`SearchPolicy`, pure step planning with stop conditions, untrusted AI drafts) landed with unit and negative-control tests
- Phase 2 (engine): DONE — `controller/analytics_service.py` (boundary brackets with a confidence statement, recovery curves, minimal failure cases, gap-53 causal chains where an uncited hop is withheld, the adaptive runner with per-step approval + admission + budget, and `compile_stages` for the single-target → 5% → 10% → 25% → 50% gated ladder)
- Phase 3 (surface): DONE — `cli/boundary_report_cmd.py` landed as the `mayhem boundary` group with two read-only commands: `boundary report --search FILE [--signal NAME]` renders a recorded search (each declared metric gets its **own** boundary, from one `boundary_report` call over that metric's own ladder) with the engine's own confidence sentence attached and the minimal-failure-case reduction, and `boundary review --candidate --policy --spec --graph [--deny-fault]` compiles an untrusted draft through `compile_candidate` and then takes the authored drill *and* the derived micro-drill through a single `_gate(spec, ...) -> plan_drill → compile_safety_evidence → simulate_plan_policy` core that has **no origin parameter**. The acceptance criterion is structural rather than a string comparison: both arms leave `_gate` holding the same `ExecutionPlan` type, the suite spies the three gate functions and asserts the recorded sequence is exactly `GATE_PATH` twice, and `plan_shape_digest` — the plan's digest with the planner's per-call `execution_group_id` held out, because no two `plan_drill` calls are ever byte-identical — is equal for a candidate proposing the rung the authored drill already encodes. A boundary whose confidence is insufficient never renders as a tolerance: `_tolerates` is the only thing that can emit that word, it gates on the domain's own `Comparison.sufficient`/`graded`, and it refuses when the ladder crossed without a separable measurement behind it. A refusal at the view-model layer raises `BoundaryViewRefused` with a stable rule id (unknown document field, blank/non-finite/unknown ladder value, undeclared signal, a spec that will not compile) and the Click callback only reports it. 88 tests in `tests/unit/test_boundary_report_surface.py` cover the documented invocations, the two negative controls on confidence and on support-withholding, the identical-code-path spy, the identical-shape-digest proof, the AST checks that this surface never constructs a `SearchPlan` with an approval and never re-declares an authority scan, six refusals on a draft that tries to carry authority, and mutation evidence measured against the caller's own `SafetyContext` (both probes run on clones, so `ctx.decisions` stays empty and the view reports the length) plus a filesystem assertion that neither command opens a store
- Phase 4 (safety and evidence): DONE — the runner's own per-step budget check is live via a documented `planner_budget` (the budget the planner plans against, separate from the budget the runner spends) with the divergence recorded on the run and in the step's own stamped reading; every boundary report, recovery curve, minimal failure case, and causal chain now carries its support (trial digests, sample digest, tried-case digests, observation citations plus topology edges) and seals through `infra/attestation_store` with `require_sealed_claim` refusing an unsealed report; a claim with no support cannot be constructed (`analytics.evidence_unsupported`) and a report with no support is sealed as a withholding beside the claims that survived; an adaptive run carries a `SearchRecord` and `record_boundary_search` writes it to `infra/audit_stream` as `audit.resilience_boundary.searched` with the policy digest and the escalating ladder, and `require_recorded_search` refuses a search the stream cannot show; the AI boundary is unchanged — `AUTHORITY_FIELDS`/`_authority_keys` are still the single authority scan and neither `AnalyticsClaim` nor `SearchRecord` has a field an approval could travel in
- Phase 5: not started
- Phase 6: not started

Overall: 4 of 6 phases complete.

### Open items Phase 4 could not close in its own files
- `KIND_RESILIENCE_BOUNDARY_SEARCHED` is declared in `controller/analytics_service.py`, not in `infra/audit_stream.py`'s closed `KIND_*` vocabulary. It belongs there; the audit module is not owned by this phase.
- Four new gate rule ids need entries in `controller/safety_proof.py`'s `OBLIGATION_FOR_RULE`, or a refusal carrying them voids the proof by that module's own fail-closed rule: `analytics.planner_budget_diverged` → `damage_budget`, `analytics.step_unaffordable` → `damage_budget`, `analytics.evidence_not_sealed` → `required_approvals`, `analytics.search_not_recorded` → `required_approvals`. `analytics.evidence_unsupported` is a construction refusal on a report rather than a gate refusal and needs no line.

### Open items Phase 3 could not close in its own files
- **The group is not registered.** `cli/boundary_report_cmd.py` exports `boundary` and nothing imports it; integration has to add `from mayhem.cli.boundary_report_cmd import boundary` to `command_registry.register_commands`, a `CommandSpec("boundary", "run", help_group="experiments")` row, a `COMMAND_HELP["boundary"]` entry, and the `command_map` line. Until then `mayhem boundary` does not dispatch and `test_command_inventory.py` / `test_cli_active_surface.py` / `test_cli_exhaustive_matrix.py` (which pin the top-level command set to exactly 19 names) will fail on the new name and need the matching allowlist line each. This phase's own suite invokes the group directly for exactly that reason.
- **No persistence.** Neither command reads or writes a database, so a boundary report is rendered from a document the caller supplies, not from a stored run. `infra/migrations.py` is not owned here, and the four documents (`--search`, `--policy`, `--spec`, `--graph`) are the surface's whole input surface until a store table exists. The search document is deliberately the raw ladder-plus-samples shape rather than a finished report; giving it a store home is Phase 5's call.
- **Recovery curves are not rendered.** `boundary report` renders the boundary, the per-metric tolerances, and the minimal-failure-case reduction. `recovery_curve` is Phase 2's and this phase's acceptance names neither recovery nor the causal chain, so the recovery section of `ResilienceAnalysis` is left empty here and `analyze_run` says so in its own notes ("no recovery curve was supplied: recovery is unreported, not clean"). A report that never claimed recovery is not one that reported it clean.
- **The plan-09 approval gate is not reachable.** `boundary_review_safety_context` configures no `approval_gate` and no `policy_gate`, so the proof's `required_approvals` line reports *requirements* and nothing more, and the policy state renders as `no_bundle_configured` rather than "allowed". That is the same standing `cli/advisor_cmd.py` takes and for the same reason; a context carrying either would have to come from a caller that has witnesses, which a CLI does not.
- **No `--force`, no ceiling flags, no store.** A candidate that would fail a gate is refused by that gate and the refusal names its rule id; `--deny-fault` exists because it can only *tighten*; the four blast-radius ceilings are module constants because a caller handed the ceiling is handed the gate that checks it.

