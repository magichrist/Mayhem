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
- Phase 4 (safety and evidence integration): DONE — the phase's acceptance criterion was already met by Phase 3's wiring (an experiment that would breach is refused at admission with `budget.estimate_exceeded` naming the dimension, and mid-execution with `budget.limit_exceeded` naming the numbers), and the cloud half was already real: `mayhem.domain.cloud.check_cost_ceiling` is called by `providers/cloud/port.py` at both mutation sites, so a cloud action is checked before it runs rather than after. What was missing was the other half, and it was missing completely: **nothing outside `domain/budgets.py` and `infra/metering.py` referenced `BenchmarkSpec`, `publish_benchmark` or `ScaleClaim`**, so a published number had no path to storage and therefore could not be sealed or compared across releases — which is the entire reason plan 22 would want one. `infra/metering.py` now has `seal_benchmark_record(benchmark, *, spec)` and `seal_meter_series(readings, *, scope_key=...)`, which run both of plan 29 Phase 4's boundary gates over the record — grade rule first, then byte rule, before any digest is returned — and bind it to a sha256 over the canonical form. Three decisions are worth naming. (1) `spec` is a **required** argument: a benchmark *claims* a `spec_digest`, and the only check that can catch a record bound to the wrong spec compares that claim against the spec itself; the first version compared the claim with itself, which could not fail, and is why the signature is what it is. (2) The record is **deliberately not an `EvidenceEnvelope`** — a benchmark has no plan, no blast radius and no verdict, and forcing it into that shape would have it assert fields it cannot know; `test_a_benchmark_record_is_not_a_run_envelope` pins that rather than leaving it a comment. (3) `seal_meter_series` **requires** a `scope_key`, because an unattributed cost number cannot be the basis of a resource budget. The write path is registered in `tests/unit/test_evidence_boundary.py`'s `BOUNDARY_CALL_SITES` — the guard failed on the new function when it first appeared, which is the guard working, and the row records `_require_bound_digest` rather than the two seal functions because that helper is what calls the gates.
- Phase 5 (tests and negative controls): DONE — with an honest correction about what already existed. The phase's named list was, again, mostly built: the deterministic-workload property is proven in `test_budgets.py` (`test_workload_repeats_exactly_from_the_spec`, `test_workload_is_target_major_so_a_prefix_covers_targets_uniformly`), the publish and unmeasured-render negative controls are in `test_metering.py` (`test_a_benchmark_with_no_methodology_is_refused_at_publish`, `test_an_unmeasured_scale_claim_cannot_render`), and per-dimension enforcement is `test_budget_enforcement.py` (51). None of that is re-asserted here, because repeating a passing test inflates the count without adding a property. What did not exist is the item that makes the rest decorative: **"a release that regresses compilation latency beyond threshold fails CI" needs a threshold**, so `tests/unit/test_budget_evidence.py` (16 tests) names `COMPILATION_LATENCY_REGRESSION_RATIO = 1.25` as stated policy and pins the property that makes such a gate worth having — an unmeasured candidate reads `None`, never `0.0`, so a missing measurement can never present as an improvement. The same file covers the Phase 4 seal through the real collaborators: the real `publish_benchmark`, a live `SecretLeakGuard` with the planted bytes registered through it (so the refusal cannot be a length artefact or a stub), and an AST read of `metering.py` proving both gate calls are still there.
- Phase 6 (docs and rollout): DONE — four sections appended below, and one of them is a section that says it is empty. **Benchmark methodology doc**: what a benchmark is bound to (a `spec_digest` over everything that shapes the work, compared against the *spec* rather than the record's own claim), what the workload guarantees (same items, same order, same identifiers, target-major so an early stop has still covered its targets), and what a sealed record is (both boundary gates, grade rule before byte rule, before any digest is returned). **Scale-characterization pages**: *there are none, and that is the honest state rather than a missing deliverable* — all five declared ranges read **unmeasured**, and `ScaleClaim.render()` refuses to produce a view without measurements behind it, so the projection-as-result failure the phase names is structurally impossible rather than merely discouraged. **Budget-configuration guide**: eight dimensions with six enforceable here (`cpu` declared unmeasurable because `core_seconds` is per-core accounting; `cloud_spend` external so it is not double-charged), unmeasured-as-a-state rather than zero, the two refusal moments with their rule ids, admission's vacuity without estimates, the stickiness of a pause, and the golden no-guard path. **Rollout order**, the plan's metering-then-budgets-then-claims sequence, closing with the phase's own question answered honestly: *"What overhead does Mayhem add?"* is a measurement plan, not a number — the nine metrics are named, the harness and gates are real, and **no benchmark has been run against a live cluster in this repository**, so quoting a figure would be the very failure the unmeasured-render refusal prevents. Enforced by `tests/unit/test_budget_plan_docs.py`.

Overall: 6 of 6 phases complete (Phases 1 through 6).

## Benchmark methodology doc

A published number is only useful if the reader can tell how it was produced, so
the methodology is not documentation — it is a **publication gate**.
`publish_benchmark` refuses a spec whose `methodology` is blank with
`benchmark.methodology_required`, and `BenchmarkSpec.publish` refuses a spec that
declares no measured outputs or whose promised outputs never arrived. A benchmark
without its methodology is rejected at publish time; there is no state in which
one exists and is merely undocumented.

**What a benchmark is bound to.** A `BenchmarkSpec` carries a `spec_digest` over
everything that shapes the work — metric, shape, scale, declared outputs,
methodology. The published record carries that digest forward, and
`seal_benchmark_record(benchmark, spec=...)` refuses a record whose digest is not
the one the supplied spec computes. That comparison is against the *spec*, not
against the record's own claim: a check that compared the claim with itself could
not fail, and a gate that cannot fail is decoration.

**What the workload guarantees.** `spec.workload()` regenerates the same items, in
the same order, with the same identifiers, from the same shape — nothing random,
no clock. The ordering is *target-major*, so a soak that has to stop early has
still covered its targets uniformly rather than having measured one of them. That
is a property of the harness rather than a convention, and it is asserted.

**What a sealed record is.** `seal_benchmark_record` and `seal_meter_series` run
both evidence-boundary gates over the record before returning a digest — the
*grade* rule first (a field classified `secret` may not be persisted), then the
*byte* rule (a resolved credential's bytes may not be present even under a field
name nobody graded). The order matters: running the byte rule alone would let a
properly-named secret field past whenever no guard happened to be active.

## Scale-characterization pages

**There are no scale-characterization pages in this document, and that is the
honest state rather than a missing deliverable.** `TargetScale.targets` must be
one of `DECLARED_SCALE_TARGETS` — 10, 100, 1000, 10000, 100000 — because a scale
outside the declared ranges has no published methodology behind it and no
comparison to be made against.

For each of those five ranges the correct page today reads **unmeasured**, and
`ScaleClaim.render()` refuses to produce a view for an unmeasured claim with
`scale.unmeasured_claim`. The failure mode this design exists to prevent is a
projection presented as a result: a soak was never run, so there is nothing to
write, and the page says so. Authoring an unmeasured `ScaleClaim` is allowed —
that is how "we intend to characterise 10,000 targets" gets recorded — but
`render()` is the only path to a `ScaleClaimView`, and the view refuses to exist
without measurements behind it. A dashboard therefore *cannot* show a projected
number, because there is no object to hand it.

`concurrent_runs` is bounded by `targets` but deliberately **not** range-checked:
the plan qualifies its concurrency ranges with "where architecture permits", and a
domain check cannot know your architecture.

## Budget-configuration guide

A budget is `dimension + scope + scope_key + limit + window_s`, and the shape of
it is mostly refusals:

* **Eight dimensions, six of them enforceable here.** `cpu` is *declared*
  `unmeasurable` from userspace — the dimension is `core_seconds`, which is
  per-core accounting (a cgroup's `cpu.stat`), and reading elapsed wall-clock
  would be a different quantity in a different unit. `cloud_spend` is *external*:
  it is refused by `mayhem.domain.cloud.check_cost_ceiling` before the action
  runs, and charging it again against a resource budget would double-charge one
  spend against two limits. `infra/budget_enforcement.DIMENSION_LEDGER` is
  exhaustive over all eight and says which is which.
* **Unmeasured is a state, not a zero.** `RunBudgetGuard.read` returns `None` for
  a dimension whose seam has not produced a reading, never `0.0`. A reading of
  exactly zero is only reported once the seam has actually run. This is the same
  property the latency gate needs, and it is the reason an absent measurement can
  never present as a good result.
* **Two moments, not one.** `admit` runs before any mutation and refuses with
  `budget.estimate_exceeded`; `observe_step` runs during execution and raises
  `PauseForReview` with `budget.limit_exceeded`. Both name the breaching dimension
  and the numbers, from the domain's own `reason` and `remediation` rather than a
  string that could drift.
* **Admission is vacuous without estimates, and says so.**
  `admission_is_vacuous` is the check: `ExecutionPlan` carries no resource
  estimates, so a guard configured with none is admitting nothing, and a reader
  who assumed otherwise would be trusting a check that never ran.
* **A pause is sticky.** A paused run cannot be observed again until a
  `BudgetReview` answers *the dimension that actually breached*, with a rationale
  and a UTC timestamp; `record_review` refuses a review that does not. A run that
  stops itself must not be able to resume itself.
* **Attach it, or get byte-identical behaviour.** `RunEngine.with_budget_guard`
  takes an optional guard with a `None` default. No guard means no budget verdict
  and no meter reading, proven golden.

## Rollout order

Metering first, budgets second, published scale claims last and only for measured
ranges — the plan's order, unchanged. The reason it is right is that metering is
the only step that produces data without refusing anything, budgets consume that
data and can stop runs, and scale claims are the only step that leaves the
building. Publishing a scale claim before the metering that would justify it is
the one ordering that produces a number nobody can defend.

**What overhead does Mayhem add?** The honest answer today is a measurement plan,
not a number: the nine `BenchmarkMetric` values (`plan_compilation_latency`,
`target_discovery_latency`, `policy_evaluation_latency`, `controller_throughput`,
`agent_command_latency`, `evidence_throughput`, `database_growth`,
`probe_overhead`, `network_overhead`) are the seams the answer will be read from,
and `seal_benchmark_record` is the path a measured answer reaches storage. The
harness is real and the gates are real; **no benchmark has been run against a
live cluster in this repository**, so there is no overhead figure to quote here.
Quoting one would be exactly the projection-as-result failure the unmeasured-render
refusal exists to prevent.
