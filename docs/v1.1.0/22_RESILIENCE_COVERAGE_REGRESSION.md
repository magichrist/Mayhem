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

## STATUS
- Phase 1 (domain model): DONE — `domain/journeys.py` (versioned, per-step-asserted journey programs with citable business-metric criteria, projecting untested coverage cells) and `domain/comparison.py` (pin equivalence predicate, delta report with improved/regressed/unchanged/insufficient-data/incomparable outcomes, two-run-cited regression findings) landed with unit tests.
- Phase 2: DONE — largely landed by a prior lane, then verified and completed. `infra/coverage_service.py` provides the five-dimension accounting (`CoverageDimensions` → existing `CoverageCell`: service→target, fault→fault_kind, environment→execution_context, version|dependency→parameter_band; probe class and certification state as cell attributes), the `ComparisonService`, and the `TriggerEngine`, over `M0027_COVERAGE_FINDINGS` — which already covered the schema, so no migration was added. Coverage is counted only from cited `EXECUTED`/`CERTIFIED` evidence: `CoverageEvidenceKind` has no `catalog` member, the sighting table's CHECK refuses an uncited or laundered row, and `DimensionCoverage.counted` requires a covering state *and* a cited sighting, so a declared-but-unrun cell renders untested. `ComparisonService.score` delegates comparability to `comparison.equivalent_pins` and cross-checks it against `compare()`, refusing to serve when the two disagree; `open_finding` persists both run ids and both evidence digests. Trigger suggestions are advisory `Literal[True]` data over a schema with no run/status column, and the engine holds no runner or gate handle. Two defects found during verification were fixed: `CoverageDimensions` was missing from `__all__` despite being `DimensionCell`'s required constructor argument, and `record_evidence`/`set_certification_state` called `declare()`, so executing a cell inflated `catalog_presence` — recording a run now upserts the dimension row without manufacturing a catalog sighting. Regression tests added for both, plus a re-scoped chain-contiguity assertion (contiguity up to M0027 only; whole-chain contiguity stays in `test_additive_schema.py`).
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 2 of 6 phases complete.
