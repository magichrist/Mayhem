# Plan 23 — Performance, Scale, and Cost Engineering

**Priority:** P1. Gap items 68, 82, 83.

## Objective
Prove the Mayhem control plane and agents remain efficient at enterprise scale — and fold in resource budgets (68) so cost and consumption are governed, not merely measured.

## Builds on
- Existing performance-relevant seams: planner compilation, topology discovery, policy evaluation, agent command latency over the 03 protocol, evidence throughput into the bundle store, SQLite growth characteristics under the 08 replication scheme.
- 07 budgets (damage, cost ceilings) and 06 cost estimates: measurement here becomes enforcement there.

## Benchmarks
Plan compilation latency, target discovery latency, policy evaluation
latency, controller throughput, agent command latency, evidence
throughput, database growth, probe overhead, network overhead.

## Scale targets
10 / 100 / 1,000 / 10,000 / 100,000 targets; 10 / 100 / 1,000
concurrent runs where architecture permits. Targets are ranges to
characterize, not promises to hit on day one — each range ships with
its measured numbers or stays unclaimed.

## Cost controls and resource budgets (gap 68)
CPU, memory, network, storage, cloud spend, API-call counts, target
counts, concurrent-experiment caps as budget dimensions with
pre-execution estimates and continuous enforcement alongside damage
budgets.

## Phase 1 — Domain model: budgets and benchmark descriptors
Add `domain/budgets.py`: `ResourceBudget` (dimension, limit, window, scope) and `BenchmarkSpec` (workload shape, target scale, measured outputs) as pure types. Pre-execution estimate vs. continuous actual as comparable records. Acceptance: budget-arithmetic tests; benchmark-spec determinism tests.

## Phase 2 — Engine: metering and enforcement hooks
Metering at the existing seams (compilation timing, discovery timing, per-command agent latency, evidence bytes per run, store growth per run); resource-budget checks in admission (07 dimensions) plus continuous re-check during execution (a run exceeding its API-call budget pauses for review, never silently continues). Acceptance: a benchmark run reproduces its workload shape exactly from its spec.

## Phase 3 — Surface: benchmark reports and budget views
Published benchmark reports with methodology attached; budget configuration and consumption views in CLI/UI. Acceptance: every published number links to the spec plus the raw outputs that produced it.

## Phase 4 — Safety and evidence integration
Benchmark and metering records sealed as evidence-class data (comparable across releases via 22); cloud-action cost estimates (06) checked against cost budgets before mutation. Acceptance: an experiment that would breach its resource budget is refused with the breaching dimension named.

## Phase 5 — Tests, regression guards, negative controls
Benchmark-harness tests (deterministic workload generation), budget-enforcement tests per dimension, scale-soak tests at each claimed range, performance-regression tests (a release that regresses compilation latency beyond threshold fails CI). Negative controls: an unmeasured scale claim cannot render on any dashboard; a benchmark without its methodology attached is rejected at publish time. Acceptance: full matrix green.

## Phase 6 — Docs, honesty gates, rollout
Benchmark methodology doc, scale-characterization pages per range (measured numbers or silence — never projections presented as results), budget-configuration guide. Rollout: metering first, budgets second, published scale claims last and only for measured ranges. Acceptance: the "what overhead does Mayhem add?" question answered with numbers plus methodology, not adjectives.

## Dependencies
06 (cloud cost estimates), 07 (budget enforcement), 08 (store growth under replication), 22 (cross-release comparison).

## STATUS
- Phase 1 (domain model): DONE — `domain/budgets.py` adds ResourceDimension (8 cost dimensions), ResourceBudget/BudgetConsumption with half-open windows, pure estimate-vs-actual comparison, and a digest-pinned BenchmarkSpec whose workload regenerates exactly from the spec
- Phase 2 (engine): DONE — `infra/metering.py` meters the six real seams (plan-compilation, discovery, policy-evaluation and per-command agent latency as non-blocking context managers over an injected monotonic clock, plus evidence bytes and store growth per run; a failing sink loses one reading and is recorded, never raised), and enforces gap 68 at both moments: `admit()` refuses a pre-execution estimate that would breach *before* mutation and `observe()` re-checks continuously and raises `PauseForReview` on a mid-run breach — both naming the breaching dimension and its numbers, from the domain's own refusal text. Publishing is gated by `publish_benchmark()` (methodology attached) and `render_scale_claim()` (authorable unmeasured, not renderable). `safety.py` is untouched by design; Phase 3/4 owes the two call sites named in `ResourceBudgetEnforcer`'s docstring.
- Phase 3 (wiring + metering gap): DONE — both call sites Phase 2 named are now in the real run path, and the metering ledger that Phase 2's own gap implied is closed and written down.

  **Call sites wired (additively; no guard means byte-identical behaviour, golden-proved).**
  - *Admission* — `RunEngine.execute`, immediately after `validate_plan` and **before** `_open_run`: the last moment at which a refusal still prevents every mutation. Raises `BudgetAdmissionRefused` (via `RunBudgetGuard.admit`), so a refused run leaves no run row, no step row, no lease, and no event. `cli/execution.py` exposes the same seam for callers that want to fail fast (`resource_budget_guard`, `budget_admission`, `attach_resource_budget`).
  - *Continuity* — `RunEngine._run_step`, after the step's reading exists and its row is closed: `RunBudgetGuard.observe_step` raises `PauseForReview`, and the executor ends the run there rather than carrying on. A paused run cannot resume without a recorded `BudgetReview` naming the breaching dimension and a rationale; without one, `BudgetPauseUnreviewed` refuses further observation.
  - *Attach* — `RunEngine.with_budget_guard(guard)` / `RunBudgetGuard`, both optional with a `None` default. No global, no environment read, no default guard.

  **Metering ledger — which dimensions are metered, refused, or unmeasurable** (`infra/budget_enforcement.DIMENSION_LEDGER`, exhaustive over all eight; `RunBudgetGuard.read` returns `value=None` for anything unmeasured, never `0.0`):

  | dimension | coverage | seam / method |
  |---|---|---|
  | cpu | **unmeasured** | none from userspace — see below |
  | memory | derived | `memory_resident`: resident-set reading integrated over the injected monotonic clock into `mebibyte_seconds` (upper bound: a resident page never read still counts) |
  | network | declared | `network_egress`: bytes a call site already knows it moved; unmeasured anywhere else |
  | storage | exact | `store_growth`: cumulative byte counter (evidence bytes are a subset and are deliberately **not** added again) |
  | cloud_spend | external | `mayhem.domain.cloud.check_cost_ceiling` — deliberately not charged a second time |
  | api_calls | exact | `api_calls`: whole-number call counter |
  | target_count | exact | `targets`: whole-number counter of targets actually touched |
  | concurrent_experiments | exact | `run_reservations`: length of the live reservation set for the budget's own scope key |

  - **Metered and enforceable**: memory, network, storage, api_calls, target_count, concurrent_experiments — six of eight, each refused by `observe()` with the breaching dimension and the numbers named.
  - **Externally governed**: cloud_spend — refused by the cloud cost gate before the action runs; charging it again here would double-charge one spend against two limits.
  - **Unmeasurable, declared as such**: cpu. The dimension is declared in `core_seconds`, which is per-core accounting (a cgroup's `cpu.stat`, a container runtime's stats). Userspace can read elapsed wall-clock, which is a different quantity in a different unit; charging it to a `core_seconds` budget would be the exact unit conflation `domain/budgets.py` exists to forbid. A CPU budget may be **authored** and is **reported unmeasured** — it is never enforced off an approximation, and a CPU budget never refuses a run. Closing it requires reading container/cgroup accounting, which is a provider question this plan does not own.
  - **Unmeasured is a state, not a zero.** A dimension reports a number only once its own seam has produced at least one reading; before that, and whenever a seam is absent, it reads `unmeasured` with the ledger's own reason. A reading of exactly `0.0` is only reported after the seam has actually run, which is when it is a real zero.

  **Refusals name the dimension and the numbers** — both texts are the domain's own `BudgetConsumption.reason`/`remediation`, so admission (`budget.estimate_exceeded` → `budget.limit_exceeded`) and continuity (`budget.limit_exceeded`) read identically everywhere. Two rule namespaces stay disjoint: this ledger is refused only by `RunBudgetGuard`, which holds no damage ledger and no `BudgetNode`; a damage refusal (`damage_quota.*`, `blast_radius.*`) pauses nothing here and is unaffected by anything here. `tests/unit/test_budget_enforcement.py` asserts that structurally, by parsing the module's own imports.

  **Deviations / known limits, recorded rather than hidden.**
  1. **The run status is `aborted`, not `paused`.** `runs.status` has a CHECK constraint in `infra/migrations.py` (not this lane's file) admitting only `created|planning|validated|running|recovering|completed|failed|aborted`, so a `paused` status cannot be persisted. The breach is reported as an abort **with the breach attached** (`RunResult.budget_breach`, `engine.budget_pause`, and a `paused for review:` line naming the dimension and the numbers in `summary_md`). The pause *state* — no further observation without a recorded review — is enforced regardless.
  2. **The admission owner is `RunEngine.execute`, not `cli/execution.py`.** Phase 2 recorded the CLI as constructing the run; it does not — `cli/execution.py` is helpers only, and the last mutation-free moment is inside `execute`. Both are provided: the executor consults the guard, and `cli/execution.py` exposes the same guard for the CLI edge. The exact CLI call site is `mayhem.cli.lifecycle`'s `result = run_engine.execute(compiled.plan)`; `cli/services.build_run_engine` is shared by every surface, so the guard is attached after construction rather than threaded through that signature.
  3. **Continuity is not "beside `check_blast_radius`".** There is no per-step blast-radius consultation in the executor today — `check_blast_radius` is a *plan-time* gate inside `validate_plan`, which runs once per plan, not per step. The hook is therefore the post-step position in `_run_step`, outside the step's `try/except` (inside it, a breach would be swallowed into a "step failed" report and the run would carry on — precisely the silent continuation the pause exists to prevent).
  4. **A broader-scope budget sees this run's contribution, not the scope's aggregate.** Aggregating across runs needs a ledger shared by those runs, which is a store question; each `StepObservation` says so in its `reason` rather than presenting one run's number as a team's total.
  5. **`ExecutionPlan` carries no resource estimates.** Admission is therefore vacuous unless the guard is configured with estimates (`admission_is_vacuous` says so explicitly); deriving them in the executor would mean inventing the basis `ResourceEstimate` demands.
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 3 of 6 phases complete.
