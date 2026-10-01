"""Plan 22 phase 2: dimension coverage accounting, run comparison, change triggers.

Why this file exists
--------------------
Phase 2 put a coverage accounting service over five new cell dimensions, a
comparison service that opens regression findings, and a trigger engine that
turns change events into *suggested* fault suites. Each of those can fail
quietly, and each quiet failure has a shape:

* **Catalog presence read as coverage.** The repository is told about a service
  and its dependency; a report then says 100% covered. Nothing ran. This is the
  failure the plan names twice ("coverage counts executed/certified evidence,
  never catalog presence") and the tests below attack it three ways: at the type
  level (``CoverageEvidenceKind`` has no ``catalog`` member), at the storage
  level (the migration's CHECK refuses a laundering row), and at the reporting
  level (a cell whose ``m5_coverage`` row claims ``passed`` with no cited
  sighting is still rendered untested).
* **A comparison that scores across differing pins.** The v2.4-vs-v2.5 example
  is only a *resilience* verdict because everything except the release matched.
  A second implementation of the equivalence rule in this layer would drift, so
  the tests assert the service *calls* ``equivalent_pins`` and cross-checks
  ``compare`` against it rather than re-deriving the axis list.
* **A regression finding with one run.** The domain already makes this
  unrepresentable; the migration has to make it unrepresentable too, or a
  hand-written row reinstates the finding nobody can re-derive.
* **A trigger that runs something.** "Auto-suggest the relevant fault suites"
  (gap 106) is one word away from "auto-run them". The tests assert the schema
  has nowhere to record that a suggestion ran, that the suggestion object is
  frozen data, and — the behavioural one — that suggesting suites for a
  post-deploy event moves no coverage cell.

So the tests are grouped as:

* **cell transitions over the new dimensions** — including the proof that the
  new dimensions ride on the *existing* ``m5_coverage`` accounting rather than a
  parallel one.
* **comparison scoring on fixture run pairs** — the plan's own v2.4 → v2.5
  tolerance regression, plus improved / incomparable / insufficient.
* **regression findings** — two cited runs, exact evidence references, and the
  storage-level refusal.
* **trigger mapping** — all seven change events, and the tags each selects on.
* **the negative controls**, and **the schema guarantees** they rest on.
"""

from __future__ import annotations

import dataclasses
import json
import sqlite3
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.domain import comparison as comparison_domain
from mayhem.domain.comparison import (
    ComparisonMetric,
    ComparisonOutcome,
    MetricKind,
    RegressionFinding,
    RunPin,
    RunReport,
    RunSample,
)
from mayhem.domain.coverage import CellState, CoverageCell
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.journeys import (
    AssertionKind,
    JourneyProgram,
    JourneyStage,
    JourneyStep,
    StepAssertion,
)
from mayhem.infra.coverage_repository import SQLiteCoverageRepository
from mayhem.infra.coverage_service import (
    CACHE_COMPONENT,
    CERTIFICATION_CELL_STATES,
    COUNTING_EVIDENCE,
    COVERAGE_VIEWS,
    DATABASE_COMPONENT,
    PLAN_22_SUITES,
    SIGHTING_KINDS,
    ChangeEvent,
    ChangeEventKind,
    ComparisonService,
    CoverageDimensionRepository,
    CoverageEvidenceKind,
    CoverageReport,
    DimensionCell,
    DimensionCoverage,
    FaultSuite,
    SuggestionRepository,
    SuiteRegistry,
    SuiteSuggestion,
    TriggerEngine,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

BASE_DIGEST = "a" * 64
CANDIDATE_DIGEST = "b" * 64
THIRD_DIGEST = "c" * 64

LATENCY = ComparisonMetric(
    name="p95_latency_ms",
    kind=MetricKind.LATENCY,
    unit="ms",
    tolerance_pct=20.0,
)
ERROR_RATE = ComparisonMetric(
    name="checkout_error_rate",
    kind=MetricKind.ERROR_RATE,
    unit="ratio",
    tolerance_pct=5.0,
)
METRICS: tuple[ComparisonMetric, ...] = (LATENCY, ERROR_RATE)


# ── fixtures ────────────────────────────────────────────────────────────────────


def _dimensions(**overrides: str) -> DimensionCell:
    fields: dict[str, Any] = {
        "service": "checkout",
        "dependency": "postgres",
        "fault": "db.slow_query",
        "environment": "staging",
        "version": "v2.4",
    }
    fields.update(overrides)
    return DimensionCell(
        dimensions=dataclasses.replace(
            _dimensions_base(),
            **{key: fields[key] for key in fields},
        )
    )


def _dimensions_base() -> Any:
    from mayhem.infra.coverage_service import CoverageDimensions

    return CoverageDimensions("checkout", "postgres", "db.slow_query", "staging", "v2.4")


def _open(tmp_path: Path, name: str = "coverage.db") -> tuple[Store, CoverageDimensionRepository]:
    store = Store.open_migrated(tmp_path / name)
    return store, CoverageDimensionRepository(store)


def _pin(**overrides: Any) -> RunPin:
    fields: dict[str, Any] = {
        "run_id": "run-v24-0001",
        "experiment": "checkout-resilience",
        "release": "v2.4",
        "environment": "staging",
        "plan_version": "plan-7",
        "policy_version": "policy-7",
        "catalog_version": "catalog-2024.11",
        "agent_version": "agent-1.4.0",
        "runtime_version": "runtime-1.9.0",
        "evidence_digest": BASE_DIGEST,
    }
    fields.update(overrides)
    return RunPin(**fields)


def _report(**overrides: Any) -> RunReport:
    """A v2.4 baseline run: 200ms at the p95, 2% checkout errors."""
    samples: Sequence[RunSample] = (
        RunSample(metric="p95_latency_ms", value=200.0, samples=10),
        RunSample(metric="checkout_error_rate", value=0.02, samples=10),
    )
    fields: dict[str, Any] = {"pin": _pin(**overrides), "metrics": tuple(samples)}
    return RunReport(**fields)


def _candidate(latency: float = 260.0, errors: float = 0.02, **overrides: Any) -> RunReport:
    """A v2.5 candidate run. ``latency=260`` is a +30% move past the 20% bound."""
    fields: dict[str, Any] = {
        "run_id": "run-v25-0001",
        "release": "v2.5",
        "evidence_digest": CANDIDATE_DIGEST,
    }
    fields.update(overrides)
    return (
        _report(
            **fields,
        )
        if not fields.keys() - {"pin"}
        else RunReport(
            pin=_pin(**fields),
            metrics=(
                RunSample(metric="p95_latency_ms", value=latency, samples=10),
                RunSample(metric="checkout_error_rate", value=errors, samples=10),
            ),
        )
    )


# ═══════════════════════════════════════════════════════════════════════════
# The cell key: five dimensions, projected onto the existing cell
# ═══════════════════════════════════════════════════════════════════════════


def test_the_five_dimensions_project_onto_the_existing_four_part_cell() -> None:
    cell = _dimensions()

    legacy = cell.coverage_cell
    assert legacy.target == "checkout"
    assert legacy.fault_kind == "db.slow_query"
    assert legacy.execution_context == "staging"
    assert legacy.parameter_band == "v2.4|postgres"
    assert legacy == CoverageCell(
        target="checkout",
        fault_kind="db.slow_query",
        execution_context="staging",
        parameter_band="v2.4|postgres",
    )


def test_two_dimension_cells_differing_on_any_axis_are_two_legacy_cells() -> None:
    """The version and the environment are in the key, so evidence cannot bleed."""
    base = _dimensions()
    for axis, value in (
        ("service", "cart"),
        ("dependency", "redis"),
        ("fault", "db.query_error"),
        ("environment", "prod"),
        ("version", "v2.5"),
    ):
        other = _dimensions(**{axis: value})
        assert other.cell_key != base.cell_key, axis
        assert other.dimensions.band != base.dimensions.band or axis not in {
            "version",
            "dependency",
        }


def test_probe_class_and_certification_are_attributes_not_key_parts() -> None:
    """Plan 22 words these two as attributes, so they cannot fork the key."""
    plain = _dimensions()
    attributed = DimensionCell(
        dimensions=plain.dimensions,
        probe_class="synthetic.journey",
        certification_state="certified",
    )

    assert attributed.cell_key == plain.cell_key
    assert attributed.probe_class == "synthetic.journey"
    assert attributed.certification_state == "certified"


@pytest.mark.parametrize(
    ("axis", "value"),
    [
        ("service", ""),
        ("dependency", "  postgres"),
        ("fault", "postgres "),
        ("environment", "stag\x1fprod"),
        ("version", "v2.4" * 40),
    ],
)
def test_a_dimension_value_that_would_merge_or_lose_cells_is_refused(axis: str, value: str) -> None:
    with pytest.raises(InvariantViolationError):
        _dimensions(**{axis: value})


def test_an_unknown_certification_state_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        DimensionCell(
            dimensions=_dimensions().dimensions,
            certification_state="very-certified",
        )
    assert excinfo.value.rule == "coverage_service.unknown_certification_state"


# ═══════════════════════════════════════════════════════════════════════════
# Cell transitions over the new dimensions
# ═══════════════════════════════════════════════════════════════════════════


def test_a_declared_cell_starts_unknown_and_uncovered(tmp_path: Path) -> None:
    store, repo = _open(tmp_path)
    cell = _dimensions()

    repo.declare(cell)

    coverage = repo.coverage(cell)
    assert coverage.state is CellState.UNKNOWN
    assert coverage.counted is False
    assert coverage.catalog_presence == 1
    store.close()


def test_executed_evidence_advances_the_cell_and_the_legacy_repository_agrees(
    tmp_path: Path,
) -> None:
    """The new dimensions ride on the existing accounting, not a parallel one."""
    store, repo = _open(tmp_path)
    cell = _dimensions()

    repo.record_evidence(
        cell,
        CoverageEvidenceKind.EXECUTED,
        run_id="run-1",
        evidence_digest=BASE_DIGEST,
        state=CellState.PASSED,
    )

    legacy = SQLiteCoverageRepository(store)
    assert legacy.cell_state(cell.coverage_cell) is CellState.PASSED
    assert cell.cell_key in legacy.covered_keys()
    assert repo.coverage(cell).counted is True
    assert repo.coverage(cell).citations == (f"executed:run-1#{BASE_DIGEST[:12]}",)
    store.close()


def test_a_fresh_run_downgrades_a_passed_cell_to_executed_under_the_domain_rules(
    tmp_path: Path,
) -> None:
    """The five-state transitions are the *existing* ones, not a restated copy."""
    store, repo = _open(tmp_path)
    cell = _dimensions()
    repo.record_evidence(
        cell,
        CoverageEvidenceKind.EXECUTED,
        run_id="run-1",
        evidence_digest=BASE_DIGEST,
        state=CellState.PASSED,
    )

    repo.record_evidence(
        cell,
        CoverageEvidenceKind.EXECUTED,
        run_id="run-2",
        evidence_digest=CANDIDATE_DIGEST,
        state=CellState.EXECUTED,
    )

    assert repo.coverage(cell).state is CellState.EXECUTED
    assert repo.coverage(cell).counted is True
    store.close()


def test_a_failed_verdict_is_coverage_because_it_was_tested(tmp_path: Path) -> None:
    """Coverage means exercised, not passing; hiding a failure would hide it twice."""
    store, repo = _open(tmp_path)
    cell = _dimensions()

    repo.record_evidence(
        cell,
        CoverageEvidenceKind.EXECUTED,
        run_id="run-1",
        evidence_digest=BASE_DIGEST,
        state=CellState.FAILED,
    )

    report = repo.report()
    assert report.cells[0].state is CellState.FAILED
    assert report.tested_count == 1
    assert report.passed_count == 0
    assert report.failed_count == 1
    store.close()


def test_a_failed_cell_does_not_silently_become_inconclusive(tmp_path: Path) -> None:
    """``domain.coverage`` refuses FAILED -> INCONCLUSIVE; the path must honour it."""
    store, repo = _open(tmp_path)
    cell = _dimensions()
    repo.record_evidence(
        cell,
        CoverageEvidenceKind.EXECUTED,
        run_id="run-1",
        evidence_digest=BASE_DIGEST,
        state=CellState.FAILED,
    )

    repo.record_evidence(
        cell,
        CoverageEvidenceKind.EXECUTED,
        run_id="run-2",
        evidence_digest=CANDIDATE_DIGEST,
        state=CellState.INCONCLUSIVE,
    )

    assert repo.coverage(cell).state is CellState.FAILED
    store.close()


def test_a_blocked_cell_can_be_executed_later(tmp_path: Path) -> None:
    store, repo = _open(tmp_path)
    cell = _dimensions()
    SQLiteCoverageRepository(store).record_blocked(cell.coverage_cell, "safety policy")

    repo.record_evidence(
        cell,
        CoverageEvidenceKind.EXECUTED,
        run_id="run-1",
        evidence_digest=BASE_DIGEST,
        state=CellState.EXECUTED,
    )

    assert repo.coverage(cell).state is CellState.EXECUTED
    store.close()


def test_re_recording_the_same_evidence_does_not_duplicate_the_sighting(
    tmp_path: Path,
) -> None:
    store, repo = _open(tmp_path)
    cell = _dimensions()

    for _ in range(3):
        repo.record_evidence(
            cell,
            CoverageEvidenceKind.EXECUTED,
            run_id="run-1",
            evidence_digest=BASE_DIGEST,
            state=CellState.PASSED,
        )

    evidence = [s for s in repo.sightings(cell) if s.counts]
    assert len(evidence) == 1
    store.close()


def test_catalog_presence_accumulates_so_it_can_be_reported(tmp_path: Path) -> None:
    store, repo = _open(tmp_path)
    cell = _dimensions()

    repo.declare(cell)
    repo.declare(DimensionCell(dimensions=cell.dimensions, probe_class="synthetic.journey"))

    assert repo.coverage(cell).catalog_presence == 2
    assert repo.coverage(cell).catalog_only is True
    store.close()


# ═══════════════════════════════════════════════════════════════════════════
# NEGATIVE CONTROL — catalog presence is not coverage
# ═══════════════════════════════════════════════════════════════════════════


def test_the_counting_evidence_enum_has_no_catalog_member() -> None:
    assert {kind.value for kind in CoverageEvidenceKind} == {"executed", "certified"}
    assert {"executed", "certified"} == COUNTING_EVIDENCE
    assert "catalog" not in COUNTING_EVIDENCE
    assert "catalog" in SIGHTING_KINDS  # recordable, never counting
    assert not hasattr(CoverageEvidenceKind, "CATALOG")


def test_a_sighting_that_cites_no_run_or_a_malformed_digest_is_refused(
    tmp_path: Path,
) -> None:
    store, repo = _open(tmp_path)
    cell = _dimensions()

    with pytest.raises(InvariantViolationError) as excinfo:
        repo.record_evidence(
            cell,
            CoverageEvidenceKind.EXECUTED,
            run_id="",
            evidence_digest=BASE_DIGEST,
            state=CellState.PASSED,
        )
    assert excinfo.value.rule == "coverage_service.uncited_evidence"

    for bad in ("", "not-a-digest", BASE_DIGEST.upper(), BASE_DIGEST[:63]):
        with pytest.raises(InvariantViolationError) as excinfo:
            repo.record_evidence(
                cell,
                CoverageEvidenceKind.EXECUTED,
                run_id="run-1",
                evidence_digest=bad,
                state=CellState.PASSED,
            )
        assert excinfo.value.rule == "coverage_service.malformed_evidence_digest"
    store.close()


def test_a_sighting_that_records_an_attempt_must_record_its_outcome(tmp_path: Path) -> None:
    store, repo = _open(tmp_path)
    cell = _dimensions()

    for state in (CellState.UNKNOWN, CellState.PLANNED, CellState.BLOCKED, CellState.SKIPPED):
        with pytest.raises(InvariantViolationError) as excinfo:
            repo.record_evidence(
                cell,
                CoverageEvidenceKind.EXECUTED,
                run_id="run-1",
                evidence_digest=BASE_DIGEST,
                state=state,
            )
        assert excinfo.value.rule == "coverage_service.sighting_without_outcome"
    store.close()


def test_a_covered_flag_with_no_cited_evidence_is_still_untested(tmp_path: Path) -> None:
    """The strongest form of the guard: even a lying row does not become coverage.

    Something else writes ``state='passed'`` on a cell nobody executed. The
    accounting agrees it says "passed"; the report still says untested, because
    counting coverage from the flag is exactly how catalog presence gets
    laundered into a percentage.
    """
    store, repo = _open(tmp_path)
    cell = _dimensions()
    repo.declare(cell)
    # Plant the lying row. ``declare`` deliberately writes no ``m5_coverage``
    # row at all — an absent row *is* ``unknown`` by the §4.2 convention — so the
    # UPDATE below needs one to exist first. It goes in through the accounting
    # repository because that is the only writer the five-state transition
    # rules run through; what makes it a lie is that it cites no sighting.
    SQLiteCoverageRepository(store).record(cell.coverage_cell, CellState.PASSED)
    with store.write() as conn:
        conn.execute(
            "UPDATE m5_coverage SET state = 'passed', covered = 1 WHERE cell_key = ?",
            (cell.cell_key,),
        )

    # The accounting really does say passed, from a fresh reader and not a
    # cached object — so the report below is declining to trust it, not failing
    # to see it.
    assert SQLiteCoverageRepository(store).cell_state(cell.coverage_cell) is CellState.PASSED
    coverage = repo.coverage(cell)
    assert coverage.state is CellState.PASSED
    assert coverage.counted is False
    assert coverage.catalog_only is True
    assert repo.report().tested_count == 0
    assert repo.report().fraction == 0.0
    store.close()


def test_the_schema_refuses_a_row_that_launders_catalog_presence_into_evidence(
    tmp_path: Path,
) -> None:
    store, repo = _open(tmp_path)
    cell = _dimensions()
    repo.declare(cell)
    dims = cell.dimensions.as_tuple()

    with pytest.raises(sqlite3.IntegrityError):
        with store.write() as conn:
            conn.execute(
                """
                INSERT INTO coverage_dimension_sightings (
                    service, dependency, fault, environment, version,
                    kind, run_id, evidence_digest, certification_ref, recorded_at
                ) VALUES (?, ?, ?, ?, ?, 'catalog', 'run-1', ?, '', 'now')
                """,
                (*dims, BASE_DIGEST),
            )

    with pytest.raises(sqlite3.IntegrityError):
        with store.write() as conn:
            conn.execute(
                """
                INSERT INTO coverage_dimension_sightings (
                    service, dependency, fault, environment, version,
                    kind, run_id, evidence_digest, certification_ref, recorded_at
                ) VALUES (?, ?, ?, ?, ?, 'executed', '', '', '', 'now')
                """,
                dims,
            )
    store.close()


def test_a_declared_journey_leaves_every_cell_untested(tmp_path: Path) -> None:
    """Authoring a program proves the program was authored, nothing more."""
    store, repo = _open(tmp_path)
    program = JourneyProgram(
        name="checkout-journey",
        version="1.0.0",
        steps=(
            JourneyStep(
                name="checkout",
                stage=JourneyStage.CHECKOUT,
                service="checkout",
                assertions=(
                    StepAssertion(
                        criterion_id="checkout-success",
                        kind=AssertionKind.SUCCESS,
                        metric="checkout_success_rate",
                        threshold=0.99,
                    ),
                ),
            ),
        ),
    )

    declared = repo.declare_journey(program, "staging")

    assert len(declared) == 1
    report = repo.report()
    assert report.total_count == 1
    assert report.tested_count == 0
    assert report.catalog_only_count == 1
    assert report.cells[0].cell.probe_class == "synthetic.journey"
    store.close()


# ═══════════════════════════════════════════════════════════════════════════
# NEGATIVE CONTROL — an empty cell is untested, never passing-by-absence
# ═══════════════════════════════════════════════════════════════════════════


def test_an_empty_report_is_zero_percent_not_one_hundred(tmp_path: Path) -> None:
    store, _repo = _open(tmp_path)
    report = CoverageReport()

    assert report.total_count == 0
    assert report.denominator == 0
    assert report.tested_count == 0
    assert report.fraction == 0.0
    store.close()


def test_a_declared_but_never_run_cell_counts_in_the_denominator_and_not_the_numerator(
    tmp_path: Path,
) -> None:
    store, repo = _open(tmp_path)
    cell = _dimensions()
    repo.declare(cell)

    report = repo.report()
    assert report.total_count == 1
    assert report.denominator == 1
    assert report.untested_count == 1
    assert report.fraction == 0.0
    assert report.untested_cells() == (cell,)
    store.close()


def test_blocked_cells_leave_the_denominator_but_are_still_reported(tmp_path: Path) -> None:
    store, repo = _open(tmp_path)
    blocked, executed = _dimensions(), _dimensions(environment="prod")
    repo.declare(blocked)
    repo.declare(executed)
    SQLiteCoverageRepository(store).record_blocked(blocked.coverage_cell, "safety policy")
    repo.record_evidence(
        executed,
        CoverageEvidenceKind.EXECUTED,
        run_id="run-1",
        evidence_digest=BASE_DIGEST,
        state=CellState.PASSED,
    )

    report = repo.report()
    assert report.blocked_count == 1
    assert report.denominator == 1
    assert report.tested_count == 1
    assert report.fraction == 1.0
    store.close()


def test_the_denominator_is_a_named_property_rather_than_buried_arithmetic() -> None:
    report = CoverageReport(
        cells=(
            DimensionCoverage(cell=_dimensions(), state=CellState.PASSED),
            DimensionCoverage(cell=_dimensions(service="cart"), state=CellState.BLOCKED),
        )
    )

    assert report.denominator == report.total_count - report.blocked_count
    assert "denominator" in report.to_dict()
    assert "fraction" in report.to_dict()


# ── coverage views ──────────────────────────────────────────────────────────────


def test_the_report_splits_by_every_plan_22_view(tmp_path: Path) -> None:
    store, repo = _open(tmp_path)
    repo.declare(_dimensions())
    repo.declare(_dimensions(service="cart"))
    repo.record_evidence(
        _dimensions(),
        CoverageEvidenceKind.EXECUTED,
        run_id="run-1",
        evidence_digest=BASE_DIGEST,
        state=CellState.PASSED,
    )
    repo.record_evidence(
        _dimensions(service="cart"),
        CoverageEvidenceKind.EXECUTED,
        run_id="run-2",
        evidence_digest=CANDIDATE_DIGEST,
        state=CellState.PASSED,
    )

    report = repo.report()
    for view in COVERAGE_VIEWS:
        grouped = report.group_by(view)
        assert sum(item.total_count for item in grouped.values()) == report.total_count

    by_service = report.group_by("service")
    assert by_service["checkout"].fraction == 1.0
    assert by_service["cart"].fraction == 1.0
    assert set(report.group_by("certification_state")) == {"pending"}
    store.close()


def test_an_unknown_view_is_refused_rather_than_silently_empty(tmp_path: Path) -> None:
    store, repo = _open(tmp_path)
    with pytest.raises(InvariantViolationError) as excinfo:
        repo.report().group_by("criticality")
    assert excinfo.value.rule == "coverage_service.unknown_coverage_view"
    store.close()


# ── certification state as a cell attribute ─────────────────────────────────────


def test_certified_evidence_sets_the_attribute_and_needs_a_reference(
    tmp_path: Path,
) -> None:
    store, repo = _open(tmp_path)
    cell = _dimensions()

    with pytest.raises(InvariantViolationError) as excinfo:
        repo.record_evidence(
            cell,
            CoverageEvidenceKind.CERTIFIED,
            run_id="run-1",
            evidence_digest=BASE_DIGEST,
            state=CellState.PASSED,
        )
    assert excinfo.value.rule == "coverage_service.certification_without_reference"

    repo.record_evidence(
        cell,
        CoverageEvidenceKind.CERTIFIED,
        run_id="run-1",
        evidence_digest=BASE_DIGEST,
        state=CellState.PASSED,
        certification_ref="cert-42",
    )
    assert repo.stored_certification_state(cell) == "certified"
    assert [item.cell.certification_state for item in repo.certified_cells()] == ["certified"]
    store.close()


def test_a_certification_claim_requires_a_passing_run(tmp_path: Path) -> None:
    store, repo = _open(tmp_path)
    cell = _dimensions()

    with pytest.raises(InvariantViolationError) as excinfo:
        repo.record_evidence(
            cell,
            CoverageEvidenceKind.CERTIFIED,
            run_id="run-1",
            evidence_digest=BASE_DIGEST,
            state=CellState.FAILED,
            certification_ref="cert-42",
        )
    assert excinfo.value.rule == "coverage_service.certification_without_pass"
    store.close()


def test_moving_a_claim_to_certified_without_a_reference_is_refused(tmp_path: Path) -> None:
    store, repo = _open(tmp_path)
    cell = _dimensions()
    repo.declare(cell)

    for state in ("certified", "expiring"):
        with pytest.raises(InvariantViolationError) as excinfo:
            repo.set_certification_state(cell, state)
        assert excinfo.value.rule == "coverage_service.certification_without_reference"

    repo.set_certification_state(cell, "stale")
    assert repo.stored_certification_state(cell) == "stale"
    assert repo.certified_cells() == ()
    store.close()


def test_an_executed_run_is_not_a_certification(tmp_path: Path) -> None:
    store, repo = _open(tmp_path)
    cell = _dimensions()

    repo.record_evidence(
        cell,
        CoverageEvidenceKind.EXECUTED,
        run_id="run-1",
        evidence_digest=BASE_DIGEST,
        state=CellState.PASSED,
    )
    repo.set_certification_state(cell, "certified", certification_ref="cert-7")
    # A second executed run must not age the live claim back to pending.
    repo.record_evidence(
        cell,
        CoverageEvidenceKind.EXECUTED,
        run_id="run-2",
        evidence_digest=CANDIDATE_DIGEST,
        state=CellState.EXECUTED,
    )
    assert repo.stored_certification_state(cell) == "certified"
    store.close()


def test_the_certification_vocabulary_is_the_domains_plus_uncertified() -> None:
    assert CERTIFICATION_CELL_STATES[0] == "uncertified"
    for state in ("pending", "certified", "expiring", "stale", "failed", "incompatible"):
        assert state in CERTIFICATION_CELL_STATES


# ═══════════════════════════════════════════════════════════════════════════
# Comparison service
# ═══════════════════════════════════════════════════════════════════════════


def _comparison(tmp_path: Path) -> tuple[Store, ComparisonService]:
    store = Store.open_migrated(tmp_path / "compare.db")
    return store, ComparisonService(store)


def test_the_plans_worked_example_is_detected_from_fixture_runs(tmp_path: Path) -> None:
    """Phase 2's acceptance: v2.4 -> v2.5 crossing a 20% latency tolerance."""
    store, service = _comparison(tmp_path)
    service.record_run(_report())
    service.record_run(_candidate(latency=260.0))

    delta = service.compare_runs("run-v24-0001", "run-v25-0001", METRICS)

    assert delta.outcome is ComparisonOutcome.REGRESSED
    assert delta.regressed
    assert delta.improved is False
    assert [item.metric for item in delta.regressions] == ["p95_latency_ms"]
    assert "past its 20.0% tolerance" in delta.reasons[0]
    assert delta.cited_runs == ("run-v24-0001", "run-v25-0001")
    store.close()


def test_a_faster_release_is_improved(tmp_path: Path) -> None:
    store, service = _comparison(tmp_path)
    service.record_run(_report())
    service.record_run(_candidate(latency=120.0))

    delta = service.compare_runs("run-v24-0001", "run-v25-0001", METRICS)

    assert delta.outcome is ComparisonOutcome.IMPROVED
    assert delta.improved is True
    store.close()


def test_a_move_inside_the_tolerance_is_unchanged(tmp_path: Path) -> None:
    store, service = _comparison(tmp_path)
    service.record_run(_report())
    service.record_run(_candidate(latency=220.0))

    delta = service.compare_runs("run-v24-0001", "run-v25-0001", METRICS)

    assert delta.outcome is ComparisonOutcome.UNCHANGED
    assert delta.regressions == ()
    store.close()


def test_a_metric_nobody_measured_is_insufficient_not_a_pass(tmp_path: Path) -> None:
    store, service = _comparison(tmp_path)
    service.record_run(_report())
    service.record_run(
        RunReport(
            pin=_pin(run_id="run-v25-0001", release="v2.5", evidence_digest=CANDIDATE_DIGEST),
            metrics=(RunSample(metric="p95_latency_ms", value=260.0, samples=10),),
        )
    )

    delta = service.compare_runs("run-v24-0001", "run-v25-0001", METRICS)

    assert delta.outcome is ComparisonOutcome.REGRESSED  # proven regression outranks
    assert delta.ungraded[0].metric == "checkout_error_rate"  # the missing metric
    store.close()


def test_an_equivalent_pair_with_an_unmeasured_metric_is_insufficient(
    tmp_path: Path,
) -> None:
    store, service = _comparison(tmp_path)
    service.record_run(_report())
    service.record_run(
        RunReport(
            pin=_pin(run_id="run-v25-0001", release="v2.5", evidence_digest=CANDIDATE_DIGEST),
            metrics=(RunSample(metric="p95_latency_ms", value=200.0, samples=10),),
        )
    )

    delta = service.compare_runs("run-v24-0001", "run-v25-0001", (ERROR_RATE,))

    assert delta.outcome is ComparisonOutcome.INSUFFICIENT_DATA
    assert delta.scored is False
    assert delta.improved is False
    assert delta.regressed is False
    assert "checkout_error_rate" in delta.reasons[0]
    store.close()


def test_comparing_an_unknown_run_id_is_refused(tmp_path: Path) -> None:
    store, service = _comparison(tmp_path)
    service.record_run(_report())

    with pytest.raises(InvariantViolationError) as excinfo:
        service.compare_runs("run-v24-0001", "run-nope", METRICS)
    assert excinfo.value.rule == "comparison_service.unknown_run"
    store.close()


def test_a_sealed_run_cannot_be_rerecorded_against_different_evidence(
    tmp_path: Path,
) -> None:
    store, service = _comparison(tmp_path)
    service.record_run(_report())
    service.record_run(_report())  # identical: a no-op
    assert service.runs() == ("run-v24-0001",)

    with pytest.raises(InvariantViolationError) as excinfo:
        service.record_run(_report(evidence_digest=THIRD_DIGEST))
    assert excinfo.value.rule == "comparison_service.run_resealed"
    store.close()


def test_a_stored_run_round_trips_with_its_pin_and_samples(tmp_path: Path) -> None:
    store, service = _comparison(tmp_path)
    original = _report()
    service.record_run(original)

    loaded = service.run("run-v24-0001")

    assert loaded == original
    assert loaded is not None
    assert loaded.pin.evidence_digest == BASE_DIGEST
    assert service.run("run-missing") is None
    store.close()


# ═══════════════════════════════════════════════════════════════════════════
# NEGATIVE CONTROL — a comparison across different pins is refused, not scored
# ═══════════════════════════════════════════════════════════════════════════


def test_a_comparison_across_differing_pins_is_refused_and_carries_no_deltas(
    tmp_path: Path,
) -> None:
    store, service = _comparison(tmp_path)
    service.record_run(_report())
    service.record_run(_candidate(latency=900.0, policy_version="policy-9", environment="prod"))

    assert service.equivalent("run-v24-0001", "run-v25-0001") is False
    delta = service.compare_runs("run-v24-0001", "run-v25-0001", METRICS)

    assert delta.outcome is ComparisonOutcome.INCOMPARABLE
    assert delta.deltas == ()
    assert delta.scored is False
    assert delta.regressions == ()
    assert "policy_version" in delta.reasons[0]
    assert "environment" in delta.reasons[0]
    store.close()


def test_the_service_reuses_the_domain_equivalence_rule_rather_than_rederiving_it(
    tmp_path: Path,
) -> None:
    """The spy is the proof: swap the predicate and the service's answer moves.

    If this module had its own axis list, monkeypatching
    ``equivalent_pins`` would change nothing here and the test would fail — which
    is the point. Two answers to "may these two runs be compared" is how a policy
    change gets reported as a resilience regression.
    """
    store, service = _comparison(tmp_path)
    service.record_run(_report())
    service.record_run(_candidate(latency=260.0))
    calls: list[tuple[str, str]] = []
    real = comparison_domain.equivalent_pins

    def spy(baseline: RunPin, candidate: RunPin) -> bool:
        calls.append((baseline.run_id, candidate.run_id))
        return real(baseline, candidate)

    comparison_domain.equivalent_pins = spy  # type: ignore[assignment]
    try:
        assert service.compare_runs("run-v24-0001", "run-v25-0001", METRICS).regressed is True
    finally:
        comparison_domain.equivalent_pins = real

    assert calls == [("run-v24-0001", "run-v25-0001")]
    store.close()


def test_the_service_refuses_to_serve_when_the_two_answers_disagree(
    tmp_path: Path,
) -> None:
    """A drift between ``equivalent_pins`` and ``compare`` stops the comparison."""
    store, service = _comparison(tmp_path)
    service.record_run(_report())
    service.record_run(_candidate(latency=260.0))
    real = comparison_domain.equivalent_pins

    comparison_domain.equivalent_pins = lambda *_: False  # type: ignore[assignment]
    try:
        with pytest.raises(InvariantViolationError) as excinfo:
            service.compare_runs("run-v24-0001", "run-v25-0001", METRICS)
    finally:
        comparison_domain.equivalent_pins = real

    assert excinfo.value.rule == "comparison_service.equivalence_disagreement"
    store.close()


def test_a_run_cannot_be_compared_with_itself_through_the_service(
    tmp_path: Path,
) -> None:
    store, service = _comparison(tmp_path)
    service.record_run(_report())

    with pytest.raises(InvariantViolationError):
        service.compare_runs("run-v24-0001", "run-v24-0001", METRICS)
    store.close()


# ═══════════════════════════════════════════════════════════════════════════
# Regression findings
# ═══════════════════════════════════════════════════════════════════════════


def test_a_finding_cites_exactly_two_runs_and_both_evidence_digests(
    tmp_path: Path,
) -> None:
    store, service = _comparison(tmp_path)
    service.record_run(_report())
    service.record_run(_candidate(latency=260.0))

    finding = service.open_finding(
        "F-2024-11-checkout",
        "run-v24-0001",
        "run-v25-0001",
        METRICS,
        "v2.5 p95 checkout latency crossed the 20% tolerance v2.4 held.",
    )
    row = service.finding("F-2024-11-checkout")

    assert finding.cited_runs == ("run-v24-0001", "run-v25-0001")
    assert finding.regressed_metrics == ("p95_latency_ms",)
    assert row is not None
    assert row["baseline_run"] == "run-v24-0001"
    assert row["candidate_run"] == "run-v25-0001"
    assert row["baseline_evidence_digest"] == BASE_DIGEST
    assert row["candidate_evidence_digest"] == CANDIDATE_DIGEST
    assert row["baseline_release"] == "v2.4"
    assert row["candidate_release"] == "v2.5"
    assert row["outcome"] == "regressed"
    assert json.loads(str(row["regressed_metrics"])) == ["p95_latency_ms"]
    assert len(service.findings()) == 1
    store.close()


def test_nothing_but_a_regression_can_be_opened_as_a_finding(tmp_path: Path) -> None:
    store, service = _comparison(tmp_path)
    service.record_run(_report())
    service.record_run(_candidate(latency=120.0))  # an improvement
    service.record_run(_candidate(latency=260.0, policy_version="policy-9", run_id="run-v25-0002"))

    for candidate_run in ("run-v25-0001", "run-v25-0002"):
        with pytest.raises(InvariantViolationError) as excinfo:
            service.open_finding(
                f"F-{candidate_run}", "run-v24-0001", candidate_run, METRICS, "because"
            )
        # Both candidates are refused for the same reason, and it is the one the
        # domain refuses at: neither pair graded as a regression — the first
        # improved, the second is incomparable on a differing policy pin. It is
        # *not* ``equivalence_disagreement``, which is a different failure
        # (equivalent_pins and compare() disagreeing about the same pair) with
        # its own test above. Accepting either here would let the assertion
        # pass on a rule that never fires for these inputs.
        assert excinfo.value.rule == "comparison.finding_without_regression"
    assert service.findings() == ()
    store.close()


# ═══════════════════════════════════════════════════════════════════════════
# NEGATIVE CONTROL — a finding without two cited runs is unrepresentable
# ═══════════════════════════════════════════════════════════════════════════


def test_a_finding_built_from_an_incomparable_report_cannot_be_constructed() -> None:
    baseline = _report()
    candidate = _candidate(latency=900.0, policy_version="policy-9")
    refused = comparison_domain.compare(baseline, candidate, METRICS)
    assert refused.outcome is ComparisonOutcome.INCOMPARABLE

    with pytest.raises(InvariantViolationError) as excinfo:
        RegressionFinding(
            finding_id="F-1",
            report=refused,
            summary="p95 latency moved and nobody re-derived it",
        )
    assert excinfo.value.rule == "comparison.finding_without_regression"
    assert refused.cited_runs == ("run-v24-0001", "run-v25-0001")


def test_the_schema_refuses_a_finding_row_that_cites_one_run_twice(tmp_path: Path) -> None:
    """The storage-level half: a hand-written row cannot reinstate what the type forbids."""
    store, _service = _comparison(tmp_path)
    row = (
        "F-handwritten",
        "checkout-resilience",
        "v2.4",
        "v2.5",
        "run-v24-0001",
        "run-v24-0001",  # the same run on both sides
        BASE_DIGEST,
        BASE_DIGEST,
        "regressed",
        '["p95_latency_ms"]',
        "{}",
        "2024-11-01T00:00:00+00:00",
    )
    columns = (
        "finding_id, experiment, baseline_release, candidate_release, baseline_run, "
        "candidate_run, baseline_evidence_digest, candidate_evidence_digest, outcome, "
        "regressed_metrics, finding_json, opened_at"
    )
    placeholders = ",".join("?" for _ in row)
    with pytest.raises(sqlite3.IntegrityError):
        with store.write() as conn:
            conn.execute(
                f"INSERT INTO regression_findings ({columns}) VALUES ({placeholders})", row
            )

    with pytest.raises(sqlite3.IntegrityError):
        with store.write() as conn:
            conn.execute(
                f"INSERT INTO regression_findings ({columns}) VALUES ({placeholders})",
                (*row[:8], "improved", *row[9:]),
            )
    store.close()


# ═══════════════════════════════════════════════════════════════════════════
# Trigger engine (gaps 104, 106)
# ═══════════════════════════════════════════════════════════════════════════


def test_every_named_change_event_has_a_mapping() -> None:
    assert {kind.value for kind in ChangeEventKind} == {
        "nightly",
        "post_deploy",
        "post_infra_change",
        "post_incident",
        "dependency_version_change",
        "cache_topology_change",
        "database_upgrade",
    }


def test_a_nightly_event_selects_only_the_continuous_suites() -> None:
    engine = TriggerEngine()

    suggestion = engine.suggest(ChangeEvent(ChangeEventKind.NIGHTLY, subject="checkout"))

    assert suggestion.suite_names == tuple(
        suite.name for suite in PLAN_22_SUITES.suites if suite.continuous
    )
    assert "none.registered" not in suggestion.suite_names


def test_a_suite_that_did_not_opt_into_continuous_testing_never_becomes_nightly() -> None:
    registry = SuiteRegistry(
        (
            FaultSuite(
                name="bespoke.thing",
                description="only run when a human asks",
                fault_kinds=("net.latency",),
                continuous=False,
            ),
        )
    )

    suggestion = TriggerEngine(registry).suggest(
        ChangeEvent(ChangeEventKind.NIGHTLY, subject="checkout")
    )

    assert suggestion.suite_names == ("none.registered",)


def test_a_post_deploy_event_selects_the_continuous_baseline_and_the_deployed_component() -> None:
    registry = SuiteRegistry(
        (
            FaultSuite(
                name="continuous.one",
                description="continuous",
                fault_kinds=("net.latency",),
                components=("other",),
                continuous=True,
            ),
            FaultSuite(
                name="tagged.checkout",
                description="checkout only",
                fault_kinds=("http.error_injection",),
                components=("checkout",),
                continuous=False,
            ),
            FaultSuite(
                name="unrelated",
                description="nothing to do with checkout",
                fault_kinds=("net.packet_loss",),
                components=("other",),
                continuous=False,
            ),
        )
    )

    suggestion = TriggerEngine(registry).suggest(
        ChangeEvent(ChangeEventKind.POST_DEPLOY, subject="checkout")
    )

    assert suggestion.suite_names == ("continuous.one", "tagged.checkout")


def test_a_post_infra_change_event_selects_the_platform_domain() -> None:
    engine = TriggerEngine()

    suggestion = engine.suggest(
        ChangeEvent(
            ChangeEventKind.POST_INFRA_CHANGE,
            subject="node-pool-a",
            failure_domain="platform",
        )
    )

    assert "platform.node" in suggestion.suite_names
    assert "network.edge" not in suggestion.suite_names


def test_a_post_incident_event_is_scoped_to_the_incidents_failure_domain() -> None:
    engine = TriggerEngine()

    network = engine.suggest(
        ChangeEvent(
            ChangeEventKind.POST_INCIDENT,
            subject="checkout",
            failure_domain="network",
        )
    )
    memory = engine.suggest(
        ChangeEvent(
            ChangeEventKind.POST_INCIDENT,
            subject="checkout",
            failure_domain="memory",
        )
    )

    assert "network.edge" in network.suite_names
    assert "platform.node" not in network.suite_names
    # No suite in the reference registry covers the memory domain, so an incident
    # there is a coverage gap stated explicitly rather than a broad sweep.
    assert memory.suite_names == ("none.registered",)
    assert "coverage gap" in memory.rationale


def test_a_dependency_version_change_selects_the_dependency_tagged_suites() -> None:
    """Gap 106's broker case."""
    engine = TriggerEngine()

    suggestion = engine.suggest(
        ChangeEvent(
            ChangeEventKind.DEPENDENCY_VERSION_CHANGE,
            subject="kafka",
            version="3.7.1",
        )
    )

    assert suggestion.suite_names == ("dependency.broker",)
    assert "net.tcp_half_open" in suggestion.fault_kinds
    assert "3.7.1" in suggestion.rationale


def test_a_cache_topology_change_selects_on_what_kind_of_thing_changed() -> None:
    """Not on the name: any cache dependency lands on the same suites."""
    engine = TriggerEngine()

    for subject in ("redis", "valkey", "memcached", CACHE_COMPONENT):
        suggestion = engine.suggest(
            ChangeEvent(ChangeEventKind.CACHE_TOPOLOGY_CHANGE, subject=subject)
        )
        assert suggestion.suite_names == ("dependency.cache",), subject


def test_a_database_upgrade_selects_the_database_suites() -> None:
    engine = TriggerEngine()

    suggestion = engine.suggest(
        ChangeEvent(ChangeEventKind.DATABASE_UPGRADE, subject="postgres", version="17.2")
    )

    assert suggestion.suite_names == ("dependency.database",)
    assert DATABASE_COMPONENT == "database"
    assert {"db.slow_query", "db.connection_exhaust", "db.query_error"} <= set(
        suggestion.fault_kinds
    )


def test_an_unscoped_or_unversioned_event_is_refused_rather_than_widened() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        ChangeEvent(ChangeEventKind.NIGHTLY, subject="  ")
    assert excinfo.value.rule == "trigger.unscoped_change_event"

    for kind in (ChangeEventKind.DEPENDENCY_VERSION_CHANGE, ChangeEventKind.DATABASE_UPGRADE):
        with pytest.raises(InvariantViolationError) as excinfo:
            ChangeEvent(kind, subject="postgres")
        assert excinfo.value.rule == "trigger.version_change_without_version"

    with pytest.raises(InvariantViolationError) as excinfo:
        ChangeEvent(ChangeEventKind.POST_INCIDENT, subject="checkout")
    assert excinfo.value.rule == "trigger.unscoped_incident"


def test_a_registry_cannot_name_a_fault_that_is_not_in_the_catalog() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        SuiteRegistry(
            (
                FaultSuite(
                    name="imaginary",
                    description="names a fault that does not exist",
                    fault_kinds=("net.teleport",),
                ),
            )
        )
    assert excinfo.value.rule == "trigger.unknown_fault_kind"
    assert "net.teleport" in str(excinfo.value)


def test_the_reference_registry_only_names_real_catalog_faults() -> None:
    from mayhem.domain.catalog import all_definitions

    known = {definition.id for definition in all_definitions()}
    for suite in PLAN_22_SUITES.suites:
        assert set(suite.fault_kinds) <= known, suite.name
        assert suite.fault_kinds
        assert suite.continuous


def test_a_suite_without_faults_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        SuiteRegistry((FaultSuite(name="empty", description="", fault_kinds=()),))
    assert excinfo.value.rule == "trigger.suite_without_faults"


def test_a_suggestion_with_no_suites_and_no_rationale_cannot_be_built() -> None:
    event = ChangeEvent(ChangeEventKind.NIGHTLY, subject="checkout")
    suite = PLAN_22_SUITES.suites[0]

    with pytest.raises(InvariantViolationError) as excinfo:
        SuiteSuggestion(suggestion_id="sug-1", event=event, suites=(), rationale="because")
    assert excinfo.value.rule == "trigger.empty_suggestion"

    with pytest.raises(InvariantViolationError) as excinfo:
        SuiteSuggestion(suggestion_id="sug-1", event=event, suites=(suite,), rationale="  ")
    assert excinfo.value.rule == "trigger.unexplained_suggestion"

    with pytest.raises(InvariantViolationError) as excinfo:
        SuiteSuggestion(suggestion_id=" ", event=event, suites=(suite,), rationale="because")
    assert excinfo.value.rule == "trigger.unnamed_suggestion"


def test_the_same_event_yields_the_same_citable_suggestion_id() -> None:
    engine = TriggerEngine()
    event = ChangeEvent(
        ChangeEventKind.NIGHTLY, subject="checkout", occurred_at="2024-11-01T00:00:00Z"
    )

    first = engine.suggest(event)
    second = engine.suggest(
        ChangeEvent(ChangeEventKind.NIGHTLY, subject="checkout", occurred_at="2024-11-01T00:00:00Z")
    )
    different = engine.suggest(
        ChangeEvent(ChangeEventKind.NIGHTLY, subject="cart", occurred_at="2024-11-01T00:00:00Z")
    )

    assert first.suggestion_id == second.suggestion_id
    assert first.suggestion_id != different.suggestion_id


# ═══════════════════════════════════════════════════════════════════════════
# NEGATIVE CONTROL — a trigger suggestion cannot itself execute
# ═══════════════════════════════════════════════════════════════════════════


def test_a_suggestion_is_advisory_frozen_data_with_nothing_to_run() -> None:
    engine = TriggerEngine()
    suggestion = engine.suggest(ChangeEvent(ChangeEventKind.POST_DEPLOY, subject="checkout"))

    assert suggestion.advisory is True
    assert suggestion.requires_approval is True
    assert suggestion.gates_apply is True

    callable_members = {
        name
        for name in dir(type(suggestion))
        if not name.startswith("_") and callable(getattr(type(suggestion), name, None))
    }
    assert not any(
        word in name for name in callable_members for word in ("run", "exec", "apply", "start")
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        suggestion.suites = ()  # type: ignore[misc]


def test_the_engine_exposes_no_execution_entry_point(tmp_path: Path) -> None:
    """Readable in one screen, which is the point: a reviewer need not trace a call graph."""
    engine = TriggerEngine()

    public = {
        name
        for name in dir(engine)
        if not name.startswith("_") and callable(getattr(engine, name, None)) and name != "registry"
    }
    assert public == {"suggest", "suggestions", "suites_for"}
    assert not hasattr(engine, "run")
    assert not hasattr(engine, "execute")
    assert not hasattr(engine, "runner")


def test_suggesting_suites_moves_no_coverage_cell(tmp_path: Path) -> None:
    """The behavioural negative control: a suggestion is not an observation."""
    store, repo = _open(tmp_path)
    cells = tuple(
        _dimensions(**axis)
        for axis in ({"fault": fault} for fault in ("db.slow_query", "db.query_error"))
    )
    for cell in cells:
        repo.declare(cell)
    before = repo.report().to_dict()
    engine = TriggerEngine()

    suggestion = engine.suggest(
        ChangeEvent(ChangeEventKind.POST_DEPLOY, subject="checkout", detail="deploy v2.5")
    )
    assert suggestion.suite_names
    after = repo.report().to_dict()

    assert after == before
    assert after["tested_count"] == 0
    assert all(item["state"] == "unknown" for item in after["cells"])
    store.close()


def test_the_suggestion_table_has_nowhere_to_record_that_it_ran(tmp_path: Path) -> None:
    store = Store.open_migrated(tmp_path / "suggest.db")
    rows = store.query("PRAGMA table_info(suite_suggestions)")
    columns = {str(dict(row)["name"]) for row in rows}

    assert {"advisory", "requires_approval"} <= columns
    for forbidden in ("run_id", "status", "started_at", "executed_at", "outcome"):
        assert forbidden not in columns, forbidden
    store.close()


def test_a_persisted_suggestion_is_advisory_and_re_recording_is_idempotent(
    tmp_path: Path,
) -> None:
    store = Store.open_migrated(tmp_path / "suggest.db")
    repository = SuggestionRepository(store)
    engine = TriggerEngine()
    suggestion = engine.suggest(
        ChangeEvent(
            ChangeEventKind.CACHE_TOPOLOGY_CHANGE,
            subject="redis",
            detail="cluster resharded 6 -> 9 shards",
        )
    )

    repository.record(suggestion)
    repository.record(suggestion)
    stored = repository.suggestion(suggestion.suggestion_id)

    assert stored is not None
    assert stored["advisory"] == 1
    assert stored["requires_approval"] == 1
    assert json.loads(str(stored["suites_json"])) == ["dependency.cache"]
    assert len(repository.suggestions()) == 1
    assert (
        repository.recent(ChangeEventKind.CACHE_TOPOLOGY_CHANGE, since="1970-01-01T00:00:00+00:00")
        == repository.suggestions()
    )
    store.close()


def test_the_schema_refuses_a_row_claiming_a_suggestion_was_authoritative(
    tmp_path: Path,
) -> None:
    store = Store.open_migrated(tmp_path / "suggest.db")
    columns = (
        "suggestion_id, event_kind, event_subject, event_fingerprint, suites_json, "
        "fault_kinds_json, rationale, advisory, requires_approval, suggested_at"
    )
    row = (
        "sug-1",
        "nightly",
        "checkout",
        "d" * 64,
        '["dependency.cache"]',
        '["net.latency"]',
        "because",
        0,
        0,
        "2024-11-01T00:00:00+00:00",
    )
    placeholders = ",".join("?" for _ in row)
    with pytest.raises(sqlite3.IntegrityError):
        with store.write() as conn:
            conn.execute(f"INSERT INTO suite_suggestions ({columns}) VALUES ({placeholders})", row)
    store.close()


def test_an_event_matching_no_suite_is_stated_as_a_gap_not_a_clean_result() -> None:
    engine = TriggerEngine()

    suggestion = engine.suggest(
        ChangeEvent(ChangeEventKind.DEPENDENCY_VERSION_CHANGE, subject="etcd", version="3.5")
    )

    assert suggestion.suite_names == ("none.registered",)
    assert "coverage gap" in suggestion.rationale
    assert suggestion.advisory is True


# ═══════════════════════════════════════════════════════════════════════════
# Schema: additive, reversible, and the guarantees the above rest on
# ═══════════════════════════════════════════════════════════════════════════


def test_this_migration_sits_in_the_contiguous_reversible_chain() -> None:
    """Our migration is identified by its own version, never by the chain head.

    Other v1.1.0 lanes append migrations above this one, so "is the head" is
    not a property of *this* file's migration and asserting it breaks on every
    future append. What must hold forever is that the chain is contiguous and
    that ours is present exactly once, reversible, and directly preceded by
    its own predecessor.
    """
    versions = [item.version for item in ALL_MIGRATIONS]
    assert versions == list(range(1, len(versions) + 1))
    mine = [item for item in ALL_MIGRATIONS if item.name == "coverage_findings"]
    assert len(mine) == 1
    assert mine[0].version in versions
    # Its predecessor is present and immediately adjacent, so migrating down to
    # `version - 1` reverses this migration and nothing below it.
    assert mine[0].version - 1 in versions
    assert mine[0].down_statements


def test_the_migration_adds_tables_without_touching_the_existing_accounting(
    tmp_path: Path,
) -> None:
    store = Store.open_migrated(tmp_path / "schema.db")
    columns = {str(dict(row)["name"]) for row in store.query("PRAGMA table_info(m5_coverage)")}

    assert {"cell_key", "state", "covered", "run_id", "verdict_json"} <= columns
    for table in (
        "coverage_dimension_cells",
        "coverage_dimension_sightings",
        "comparison_runs",
        "regression_findings",
        "suite_suggestions",
    ):
        assert store.query(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", (table,)
        ), table
    store.close()


def test_the_migration_is_reversible_and_reapplies(tmp_path: Path) -> None:
    """Our migration and everything stacked above it reverses and reapplies.

    The version, the migration id, and the head are all read from the chain
    itself rather than written as literals, so a later lane appending a
    migration does not make this test lie.
    """
    mine = next(item for item in ALL_MIGRATIONS if item.name == "coverage_findings")
    version = mine.version
    migration_id = mine.migration_id
    predecessor = version - 1
    head = ALL_MIGRATIONS[-1].version
    stacked_above = [item.migration_id for item in ALL_MIGRATIONS if item.version >= version]

    path = tmp_path / "down.db"
    store = Store.open_migrated(path)
    assert store.schema_version == head

    reversed_ids = store.migrate_down(predecessor)

    assert reversed_ids == list(reversed(stacked_above))
    # Ours is the lowest of the reversed set: migrating down to our predecessor
    # reverses this migration and everything stacked above it, and nothing below.
    assert migration_id == stacked_above[0]
    assert migration_id in reversed_ids
    assert store.schema_version == predecessor
    assert not store.query(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='suite_suggestions'"
    )
    assert store.migrate() == stacked_above
    assert store.schema_version == head
    assert store.query(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='suite_suggestions'"
    )
    store.close()
