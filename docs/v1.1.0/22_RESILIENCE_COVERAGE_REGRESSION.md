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

## STATUS
- Phase 1 (domain model): DONE — `domain/journeys.py` (versioned, per-step-asserted journey programs with citable business-metric criteria, projecting untested coverage cells) and `domain/comparison.py` (pin equivalence predicate, delta report with improved/regressed/unchanged/insufficient-data/incomparable outcomes, two-run-cited regression findings) landed with unit tests.
- Phase 2: DONE — largely landed by a prior lane, then verified and completed. `infra/coverage_service.py` provides the five-dimension accounting (`CoverageDimensions` → existing `CoverageCell`: service→target, fault→fault_kind, environment→execution_context, version|dependency→parameter_band; probe class and certification state as cell attributes), the `ComparisonService`, and the `TriggerEngine`, over `M0027_COVERAGE_FINDINGS` — which already covered the schema, so no migration was added. Coverage is counted only from cited `EXECUTED`/`CERTIFIED` evidence: `CoverageEvidenceKind` has no `catalog` member, the sighting table's CHECK refuses an uncited or laundered row, and `DimensionCoverage.counted` requires a covering state *and* a cited sighting, so a declared-but-unrun cell renders untested. `ComparisonService.score` delegates comparability to `comparison.equivalent_pins` and cross-checks it against `compare()`, refusing to serve when the two disagree; `open_finding` persists both run ids and both evidence digests. Trigger suggestions are advisory `Literal[True]` data over a schema with no run/status column, and the engine holds no runner or gate handle. Two defects found during verification were fixed: `CoverageDimensions` was missing from `__all__` despite being `DimensionCell`'s required constructor argument, and `record_evidence`/`set_certification_state` called `declare()`, so executing a cell inflated `catalog_presence` — recording a run now upserts the dimension row without manufacturing a catalog sighting. Regression tests added for both, plus a re-scoped chain-contiguity assertion (contiguity up to M0027 only; whole-chain contiguity stays in `test_additive_schema.py`).
- Phase 3 (surface): DONE for the map — `mayhem.cli.coverage_map` materialises the declared service×fault cross product so an empty cell has somewhere to be, and `mayhem inspect coverage --matrix` renders it. Journey builders and **CI minimum-coverage enforcement are not done**; nothing gates on a number this view produces.
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 3 of 6 phases complete.
