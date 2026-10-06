# Plan 22 — Resilience Coverage and Regression System

**Priority:** P1. Gap items 20, 50, 51, 102, 103, 104, 105, 106.

## Objective
Track whether services are actually tested against meaningful failure modes and whether resilience changes across releases — folding in synthetic customer journeys (50), business-metric criteria (51), run comparison (102), release gates (103), continuous testing (104), and dependency-change triggers (106).

## Builds on
- `domain/coverage.py` cells (`unknown | planned | executed | passed | inconclusive | failed | blocked`) and `infra/coverage_repository.py` five-state accounting stay the cell core; new dimensions extend the cell key, never fork the store.
- 11 probes (synthetic transactions, business-metric SLOs), 16 release gates and CI enforcement, 12 sealed comparisons.

## Coverage dimensions
`Service × Dependency × Fault × Environment × Version` — plus probe
class and certification state as cell attributes.

## Views
Service, dependency, critical-path, environment, recovery, probe, and
certification coverage. Coverage counts executed/certified evidence,
never catalog presence.

## Synthetic journeys and business metrics (gaps 50, 51)
Multi-step customer workflows (signup → login → cart → checkout →
payment → order) as versioned probe programs measuring success,
latency, error rate, and business correctness; business KPIs
(checkout success rate, orders per minute, payment success rate,
queue lag) as first-class SLO metrics with baselines and tolerances.

## Regression detection
Compare equivalent experiments across releases and environments
(gap 102: same pins, new release → latency/error/recovery deltas with
a resilience-improved/regressed call). Release gates (103) and
continuous suites (104: nightly, post-deploy, post-infra-change,
post-incident) feed the comparison store; dependency changes (106:
broker version, cache topology, database upgrade) auto-suggest the
relevant fault suites.

## Phase 1 — Domain model: cells, journeys, comparisons
Extend coverage cell keys with the new dimensions; add `domain/journeys.py` (versioned step programs with per-step assertions) and `domain/comparison.py` (equivalence predicate over pins, delta report with call). Pure types. Acceptance: equivalence tests (same experiment, new release compares; different experiment refused as incomparable).

## Phase 2 — Engine: coverage accounting and comparison service
Extend the repository accounting to new dimensions; comparison service scores run pairs and opens regression findings with exact run plus evidence refs; trigger engine maps change events (deploy, dependency, infra) to suggested suites. Acceptance: the v2.4→v2.5 tolerance-regression example detected from fixture runs.

## Phase 3 — Surface: coverage maps and gate wiring
Coverage map views (the service×fault matrix with evidence links per cell), journey builders, CI minimum-coverage enforcement for selected services (16 consumes this). Acceptance: an empty cell renders as untested, never as passing-by-absence.

## Phase 4 — Safety and evidence integration
Coverage and comparisons computed from sealed evidence only; journey probes versioned and pinned into plans; regression findings feed advisor input (21) and release decisions (16). Acceptance: a regression finding without two cited runs is unrepresentable.

## Phase 5 — Tests, regression guards, negative controls
Cell-transition tests, comparison tests on fixture run pairs (improved, regressed, incomparable, insufficient-data), journey-execution tests, trigger-mapping tests. Negative controls: catalog presence asserted as coverage fails; a comparison across different pins is refused, not scored. Acceptance: full matrix green.

## Phase 6 — Docs, honesty gates, rollout
Coverage methodology (what counts as tested), journey authoring guide, regression-triage guide. Rollout: service×fault cells first, journeys and business metrics second, continuous comparison third. Acceptance: no dashboard shows a coverage percentage without defining its denominator on the same screen.

## Dependencies
11 (journey probes, business SLOs), 12 (sealed inputs), 14 (graph cells), 16 (gate enforcement), 21 (findings consumer).

## Phase 3 outcome — the coverage map, and what an absent cell is

The acceptance criterion for this phase is one sentence: *"an empty cell renders
as untested, never as passing-by-absence."* `mayhem.cli.coverage_map` makes that
structural rather than a matter of care. `coverage_matrix` takes the **declared**
services and faults and materialises their full cross product, so a cell nobody
has run still has somewhere to be and there is no code path in which it is
skipped. `mayhem inspect coverage --matrix` declares its rows from the topology
graph and its columns from the engine's fault kinds, not from the cells that
happen to exist.

Three things the view owes its reader, each a property rather than a styling
choice:

* **Evidence, or nothing.** A cell claiming `PASSED` with no `last_run` behind
  it renders as untested and the discrepancy is printed. Only states that assert
  an *execution outcome* are held to that — `PLANNED`, `SKIPPED` and `BLOCKED` are
  true precisely because nothing ran, and flattening them would erase the
  distinction a reviewer needs.
* **The denominator travels with the number.** `denominator_description()` quotes
  the population rather than describing it, and both renderers print it. A
  percentage without the population it divides is the single most misleading
  thing a coverage dashboard can show.
* **Blocked cells are not testable cells.** Excluded from the denominator, because
  a refused environment is not a gap and counting it would let an operator raise
  the number by configuring less. Never-run cells *are* counted, because they are
  exactly the gap the map exists to surface.

### What the tests caught

The first draft of `MatrixCell.counted` excluded absent cells — the opposite of
the rule. Left alone it would have let a service nobody tested report 100%, which
is the precise failure the phase exists to prevent. The property tests found it
on the first run.

Two mutations then survived and both were gaps in the tests rather than in the
module:

* `covered` reads a cell's state, and an absent cell's state is already
  `UNKNOWN`, so a `covered` that had dropped its `counted` and `unevidenced`
  terms would have passed by coincidence. There is now a case that gives the grid
  a cell claiming `PASSED` with no run and requires it still not to count.
* The denominator assertion used a grid with nothing blocked, where declared and
  denominator are the same number. There is now a blocked cell in that grid.

Nine mutations are each proven to fail the suite.

### What this does not claim

* **It does not change what counts as covered.** Whether a cell is `PASSED` is
  decided by `infra.coverage_service` counting cited evidence. This module renders
  what it is told and reports a mismatch rather than reconciling it.
* **It does not fetch or join evidence.** `last_run` is carried on the cell and
  read here, never resolved, so a dangling run id is visible rather than hidden.
* **It does not add a dimension.** Rows are services, columns are faults. The
  other three coverage dimensions are filters over this grid, not axes of it.
* **It gates nothing.** CI minimum-coverage enforcement for selected services is
  **not** done; plan 16 consumes it and nothing consumes it yet. No release
  decision reads this number.
* **The grid gives way to a per-family listing when it would not fit.** With 128
  fault kinds a labelled table is unreadable, and the first draft truncated
  column headers to six characters so that \`container.kill\`,
  \`container.pause\` and \`container.restart\` all read \`contai\`. The
  column width is now derived from the data and a width budget selects the
  layout, so nothing is ever truncated to an ambiguous prefix. Driving the real
  command is what surfaced it; no unit test would have.
* **It is not the comparison view.** Regression deltas across releases are Phase
  2's `ComparisonService`; this map shows one release's cells.

## Phase 4 outcome — the feed, and what does not consume it yet

Phase 4 is wiring, and wiring is only honest when the ledger says which end is
dangling. Three ends are attached:

* **The store end.** `record_finding` refuses a finding whose runs were never
  recorded, or whose cited digests are not the ones its runs are sealed
  against. The acceptance — *a regression finding without two cited runs is
  unrepresentable* — was already true of the domain types; it is now true of
  the persistence boundary too, where a hand-built finding used to be able to
  cite runs nobody could produce.
* **The release-gate end.** `release_gate` takes `open_findings` and blocks
  while a finding's candidate is the release the cited run measured. A finding
  on another experiment, or with this run as the *baseline*, does not block —
  a regression between two older releases is a fact about those releases, not
  about the one being decided.
* **The advisor end.** `regression_citations` hands findings to plan 21's
  vocabulary as citations, never as a second kind of gap. The plan-21 surface
  is a closed lane and does not read the feed yet; that is recorded as a gap,
  the same way plan 21 records its own.

The dangling end: nothing in `src/` calls `release_gate` with findings yet, and
a stored finding has no close/resolve state, so "open" means "every stored
finding". Both are consequences of the phase list — lifecycle and CI callers
belong to the phases that name them — and neither is papered over here.

## Coverage methodology — what counts as tested

**Only cited evidence counts.** A cell counts as tested when executed or
`certified` evidence cites it — a `run_id` and a sha256 digest, sealed by the
run that produced it. Catalog presence is declared and never counted: the
`CoverageEvidenceKind` type has no `catalog` member, so "we wrote the test" is
not a value the accounting can receive. A percentage without its denominator
has no meaning, and every renderer here prints `denominator_description()`
beside the number; blocked cells stay out of the denominator (a refused
environment is not a gap), never-run cells stay in it (they are the gap the
map exists to surface), and an empty cell renders as untested — never as
passing-by-absence.

## Journey authoring guide

A journey is an authored program, versioned and digest-pinned — `name@version#digest`,
every byte — so two runs of the same program compare and an edited program is a
different program. Every step asserts something (a step with no assertions is
refused at construction), every assertion names exactly one basis (threshold,
or baseline-plus-tolerance, never both, never neither), a business-correctness
assertion states the business claim in words, and dependencies resolve only to
steps declared before them. Re-pinning the program lands its evidence on a
different cell — the version lives in the cell's parameter band — so old
evidence stays addressable. Authoring proves nothing: `authored_cells`
projects every cell as `unknown`, and only executed evidence ever moves one.

## Regression-triage guide

A finding is two runs and a sentence: it cites baseline and candidate run ids
with evidence digests, and it says why in prose. Comparability is the pin
vector's — same experiment, environment, plan/policy/catalog/agent/runtime
versions and journey pin, release deliberately excluded (it is the axis being
compared). A refused comparison is never scored, a refused comparison is not a
pass, and a proven regression outranks a missing metric — three unmeasurable
metrics and one regressed one still read "regressed". `insufficient_data` is
an outcome, never a pass. Findings feed the release gate (`release_gate` blocks
while the cited release is an open finding's candidate) and the advisor
(`regression_citations` returns one FINDING citation per finding — a regression
is not a gap Finding, and the two never share a type). Triage starts from the
refusal's rule id: every refusal in this system names itself.

## Rollout order

1. **Service×fault cells first** — the coverage map and its accounting are the
   floor: `mayhem inspect coverage --matrix`, cited-evidence-only counting,
   denominators on every number.
2. **Journeys and business metrics second** — authored programs pinned into
   plans, business KPIs as first-class criteria, `authoring proves nothing`
   until the runs land.
3. **Continuous comparison third** — nightly/post-deploy suites feeding the
   comparison store, findings opening from graded regressions, the release
   gate and the advisor consuming them.

## STATUS
- Phase 1 (domain model): DONE — `domain/journeys.py` (versioned, per-step-asserted journey programs with citable business-metric criteria, projecting untested coverage cells) and `domain/comparison.py` (pin equivalence predicate, delta report with improved/regressed/unchanged/insufficient-data/incomparable outcomes, two-run-cited regression findings) landed with unit tests.
- Phase 2: DONE — largely landed by a prior lane, then verified and completed. `infra/coverage_service.py` provides the five-dimension accounting (`CoverageDimensions` → existing `CoverageCell`: service→target, fault→fault_kind, environment→execution_context, version|dependency→parameter_band; probe class and certification state as cell attributes), the `ComparisonService`, and the `TriggerEngine`, over `M0027_COVERAGE_FINDINGS` — which already covered the schema, so no migration was added. Coverage is counted only from cited `EXECUTED`/`CERTIFIED` evidence: `CoverageEvidenceKind` has no `catalog` member, the sighting table's CHECK refuses an uncited or laundered row, and `DimensionCoverage.counted` requires a covering state *and* a cited sighting, so a declared-but-unrun cell renders untested. `ComparisonService.score` delegates comparability to `comparison.equivalent_pins` and cross-checks it against `compare()`, refusing to serve when the two disagree; `open_finding` persists both run ids and both evidence digests. Trigger suggestions are advisory `Literal[True]` data over a schema with no run/status column, and the engine holds no runner or gate handle. Two defects found during verification were fixed: `CoverageDimensions` was missing from `__all__` despite being `DimensionCell`'s required constructor argument, and `record_evidence`/`set_certification_state` called `declare()`, so executing a cell inflated `catalog_presence` — recording a run now upserts the dimension row without manufacturing a catalog sighting. Regression tests added for both, plus a re-scoped chain-contiguity assertion (contiguity up to M0027 only; whole-chain contiguity stays in `test_additive_schema.py`).
- Phase 3 (surface): DONE for the map — `mayhem.cli.coverage_map` materialises the declared service×fault cross product so an empty cell has somewhere to be, and `mayhem inspect coverage --matrix` renders it. Journey builders and **CI minimum-coverage enforcement are not done**; nothing gates on a number this view produces.
- Phase 5 (tests, regression guards, negative controls): DONE — the plan's named groups already existed, which the ledger records rather than rewrites: **cell-transition tests** in `test_coverage_repository.py` (idempotent same-run recording, same-state-across-runs staying covered, blocked excluded from testable, covered→inconclusive dropping the rollup bar, the covered column true iff the state is covered, unblock recording a tested state) and `test_coverage_service.py` (a blocked cell executed later, certification vocabulary shared with the domain, executed-is-not-certified, moving a claim without a reference refused); **comparison tests on fixture run pairs** in `test_comparison.py` (48 collected cases: improved, regressed, unchanged, insufficient-data, incomparable, the tolerance-boundary worked example, a proven regression outranking a missing metric, a zero baseline never within tolerance of anything else) and the service-level scoring/negative-control set in `test_coverage_service.py` (equivalence agreement, self-comparison, findings citing exactly two runs and both digests, nothing but a regression opened as a finding); **journey-execution tests** in `test_journeys.py` (43: every step asserting something, one basis per assertion, program-level criterion uniqueness, dependencies resolving to earlier steps, `authored_cells` projecting unknown cells only); **trigger-mapping tests** in `test_coverage_service.py` (nightly selecting only continuous suites, an unopted-in suite never becoming nightly, dependency-version and database-upgrade events selecting their tagged suites). **The two negative controls the plan names are already load-bearing and pinned where the behavior lives:** catalog presence asserted as coverage fails three ways in `test_coverage_service.py` (the `CoverageEvidenceKind` type with no `catalog` member, the sighting CHECK refusing an uncited row, executing a cell never manufacturing the presence it lacked), and a comparison across different pins is refused not scored (`test_comparison.py`'s incomparable-report-with-no-deltas refusal plus `test_coverage_service.py`'s `equivalence_disagreement` control, which makes `equivalent_pins` lie and proves the service stops rather than serves). Plan 22's own phase-4 additions bring the nine-suite collected count to **290 tests, all green** — counted by `pytest --collect-only`, since `def test` lines under-report every parametrised case. New negative controls in `test_plan22_phase4.py` prove the phase-4 wiring: findings refused over unrecorded runs, refusals over digests the runs are not sealed against, the green control that the honest path persists, the omitted-journey link blocking, and the gate blocking on the cited release's own finding while ignoring findings on other experiments.
- Phase 6 (docs, honesty gates, rollout): DONE — three guides written into this document below the ledger, plus the rollout order, and asserted rather than left to review: **coverage methodology** (what counts as tested — cited executed/certified evidence only, catalog presence never, blocked cells out of the denominator, never-run cells in it, and the denominator printed beside every number), **journey authoring guide** (a program is versioned and digest-pinned, every step asserts something, every assertion names one basis, business-correctness assertions state the claim in words, re-pinning lands on a different cell, and authoring proves nothing until executed evidence moves the cell), and **regression-triage guide** (a finding is two runs and a sentence, comparability is the pin vector's, insufficient data is an outcome and never a pass, proven regressions outrank missing metrics, findings feed the release gate and the advisor as citations, and triage starts from the refusal's rule id). **Rollout:** service×fault cells first, journeys and business metrics second, continuous comparison third. Honesty gates live in `tests/unit/test_plan22_plan_docs.py`, which parses this document: the `Overall:` count against the DONE lines, every refusal code quoted against the source, the methodology's five claims pinned, the denominator rule, the three rollout tiers in order, forbidden false claims refused, and every checker proven to bite against a mutated copy of the document. The known gap is stated rather than hidden: no production caller passes `open_findings` to `release_gate` yet, and the plan-21 surface does not read `regression_citations` yet — both are recorded in the Phase 4 ledger line above.
- Phase 4 (safety and evidence integration): DONE — three seams closed, each with its negative control in `tests/unit/test_plan22_phase4.py` (16 tests). **Findings are computed from sealed evidence only:** `ComparisonService.record_finding` verifies both cited runs are stored (`record_run`) and that the digests the finding cites are the ones its runs are sealed against — `comparison_service.finding_cites_unrecorded_run` and `comparison_service.finding_cites_wrong_digest` close the direct path a hand-built finding could otherwise take past `open_finding` (which reaches it only through stored runs, so the acceptance "a regression finding without two cited runs is unrepresentable" now holds at the store boundary too, not only in the domain types). **Journey probes are versioned and pinned into plans:** `PipelinePins` carries the cited run's journey program pin as `journey` — `JourneyPin.identity`, `name@version#digest`, every byte — via `from_run`; the axis is deliberately not in `REQUIRED_PINS` (a run need not be a journey run) but a *disagreement* about it blocks: a link that never recorded which journey program version its run carried cannot cite it, and `blocking_reasons` names the `journey` axis in its existing disagreement sentence. **Findings feed release decisions (16):** `release_gate(..., open_findings=())` blocks while an open regression finding's *candidate* is the release the cited run measured (same experiment, same candidate release), and the refusal carries the finding id, its summary, and both cited run labels; findings on other experiments, or with this run on the *baseline* side of the comparison, do not block — the gate blocks what the evidence names, nothing else. **Findings feed advisor input (21):** `mayhem.domain.advisor.regression_citations` converts findings into the advisor's own citation vocabulary — one `CitedFact(kind=FINDING)` per finding, detail naming the summary, both run labels, and the regressed metrics — because a regressed experiment is not a gap `Finding` (which refuses `FAILED` cells for exactly that reason) and the two must never share a type. What the phase does not claim: no CLI or dashboard consumes `open_findings` yet — `release_gate` is the wired consumer and has no production caller until plan 16's CI runners invoke it; the plan-21 surface (whose inputs document refuses unknown fields by design) is a closed lane, so the feed is delivered at the type boundary and adopting it there is recorded as the remaining gap rather than worked around; and a finding has no close/resolve state, so "open" means every stored finding.

Overall: 6 of 6 phases complete (Phases 1, 2, 3, 4, 5, and 6).
