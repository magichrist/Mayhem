"""Plan 23 Phase 3 — resource budgets in the run path, and the metering ledger.

Phase 1 (``test_budgets.py``) proved the arithmetic and Phase 2
(``test_metering.py``) proved the seams and the two checks. Neither could prove
the two things Phase 3 exists for, because both are properties of *wiring*:

1. **The checks are actually reached.** Admission is consulted before the run row
   is opened, so a refusal prevents every mutation rather than some; continuity
   is consulted after each step's reading exists, so a mid-run breach pauses
   instead of continuing. The proof that no-enforcer behaviour is untouched is
   the *golden* below — the same standard ``test_policy_gate.py`` set when it
   added an optional gate to ``validate_plan``.
2. **A budget is only as real as the meter behind it.** Phase 2 left four
   dimensions carrying budgets with nothing measuring them. This suite names which
   dimensions are metered and how, which are honestly unmeasurable, and asserts
   the property that makes the difference between a meter and a lie: **a
   dimension nobody measured reads unmeasured, never zero.**

The negative controls are the ones worth reading twice: a paused run cannot
resume itself, and the resource ledger cannot enforce a damage refusal (nor a
damage ledger a resource one) — asserted both behaviourally and structurally,
by parsing the module's own imports.

Nothing here decides anything from a wall clock: every decision takes ``now``,
and the only injected clock is the monotonic fake the memory seam integrates over.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.cli.execution import (
    attach_resource_budget,
    budget_admission,
    resource_budget_guard,
)
from mayhem.config import PolicyCfg
from mayhem.controller.executor import RunEngine
from mayhem.controller.planner import plan_drill
from mayhem.controller.safety import (
    SafetyContext,
    SafetyRefusedError,
    check_blast_radius,
)
from mayhem.domain.budgets import (
    RULE_ESTIMATE_EXCEEDED,
    RULE_LIMIT_EXCEEDED,
    ResourceBudget,
    ResourceDimension,
    ResourceEstimate,
    ResourceScope,
    unit_for,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    DrillContainer,
    DrillFault,
    DrillSpec,
    ExecutionStep,
)
from mayhem.domain.identity import RuntimeIdentity
from mayhem.domain.quota import DamageLedger, DamageQuota
from mayhem.domain.topology import (
    ContainerNode,
    Edge,
    EdgeKind,
    ProcessNode,
    TopologyGraph,
)
from mayhem.infra import budget_enforcement, metering
from mayhem.infra.budget_enforcement import (
    DIMENSION_LEDGER,
    RULE_PAUSE_UNREVIEWED,
    RULE_REVIEW_REQUIRED,
    RULE_UNIT_CONFLATION,
    BudgetPauseUnreviewed,
    BudgetReview,
    ConcurrentRunReservations,
    MeterCoverage,
    ReviewDecision,
    RunBudgetGuard,
    coverage_for,
    ledger_for,
    ledger_rows,
    metered_dimensions,
    unmeasured_dimensions,
)
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.metering import (
    RULE_METER_CONTRACT,
    BudgetAdmissionRefused,
    MeterReading,
    PauseForReview,
    ResourceBudgetEnforcer,
    RunMeter,
)
from mayhem.infra.store import Store
from mayhem.topology.resolve import ContainerInfo

if TYPE_CHECKING:
    from collections.abc import Iterator

_NAIVE = datetime(2026, 1, 1)  # noqa: DTZ001 — a naive stamp is what we test against
ANCHOR = datetime(2026, 1, 1, tzinfo=UTC)
"""Window grid origin. Fixed, so every window in this suite is exact."""

NOW = ANCHOR + timedelta(hours=1)
HOUR = 3600.0
RUN = "run-budget-1"


class _FakeClock:
    """A monotonic clock a test moves by hand.

    Shaped like :func:`time.perf_counter` — seconds, monotonically increasing —
    because that is the only thing the timing and memory seams are allowed to
    assume. Nothing here reads a wall clock to decide anything.
    """

    def __init__(self, start: float = 1000.0) -> None:
        self.tick = start

    def __call__(self) -> float:
        return self.tick

    def advance(self, seconds: float) -> None:
        self.tick += seconds


def _budget(
    dimension: ResourceDimension,
    limit: float,
    *,
    scope: ResourceScope = ResourceScope.RUN,
    key: str = RUN,
    window_s: float = HOUR,
) -> ResourceBudget:
    return ResourceBudget(
        dimension=dimension,
        scope=scope,
        scope_key=key,
        limit=limit,
        window_s=window_s,
        description="phase-3 fixture",
    )


def _estimate(
    dimension: ResourceDimension,
    expected: float,
    *,
    scope: ResourceScope = ResourceScope.RUN,
    key: str = RUN,
) -> ResourceEstimate:
    return ResourceEstimate(
        dimension=dimension,
        scope=scope,
        scope_key=key,
        expected=expected,
        basis="phase-3 fixture basis",
    )


def _guard(
    budgets: tuple[ResourceBudget, ...],
    *,
    meter: RunMeter | None = None,
    reservations: ConcurrentRunReservations | None = None,
    estimates: tuple[ResourceEstimate, ...] = (),
    scope: ResourceScope = ResourceScope.RUN,
    run_id: str = RUN,
) -> RunBudgetGuard:
    return RunBudgetGuard(
        enforcer=ResourceBudgetEnforcer(
            budgets=budgets,
            scope=scope,
            anchor=ANCHOR,
            run_id=run_id,
        ),
        meter=meter,
        reservations=reservations,
        estimates=estimates,
    )


# ==============================================================================
# The metering ledger — which dimensions are honestly metered, and which are not
# ==============================================================================


def test_every_dimension_has_a_ledger_entry() -> None:
    """Exhaustive on purpose: a dimension with no row is a budget with no meter."""
    assert set(DIMENSION_LEDGER) == set(ResourceDimension)


def test_ledger_rows_render_every_dimension_once() -> None:
    rows = ledger_rows()
    assert len(rows) == len(ResourceDimension)
    assert [row[0] for row in rows] == sorted(row[0] for row in rows)


def test_cpu_is_declared_unmeasurable_rather_than_approximated() -> None:
    """core_seconds is per-core accounting; userspace cannot read it."""
    entry = ledger_for(ResourceDimension.CPU)
    assert entry.coverage is MeterCoverage.UNMEASURED
    assert entry.measured is False
    assert not entry.seam
    assert "core_seconds" in entry.rationale


def test_cpu_budget_reads_unmeasured_even_when_the_meter_is_busy() -> None:
    """A CPU budget may be authored; it may not be enforced off a fake number.

    The meter is deliberately busy on three other dimensions — an elapsed-seconds
    number exists, and is in the wrong unit. Reporting it as core-seconds is
    exactly the conflation the ledger refuses.
    """
    meter = RunMeter(run_id=RUN, clock=_FakeClock())
    with meter.time_policy_evaluation(now=NOW):
        pass
    meter.add_store_growth_bytes(100, now=NOW)
    meter.add_targets(3, now=NOW)
    guard = _guard((_budget(ResourceDimension.CPU, 1.0),), meter=meter)
    reading = guard.read(ResourceDimension.CPU)
    assert reading.value is None
    assert not reading.measured
    assert "core_seconds" in reading.reason


def test_a_cpu_budget_never_pauses_a_run_it_cannot_measure() -> None:
    """Refusing on consumption nobody measured would invent the number."""
    guard = _guard((_budget(ResourceDimension.CPU, 1.0),), meter=RunMeter(run_id=RUN))
    observations = guard.observe_step(now=NOW, seam="step:c-a-0000")
    assert len(observations) == 1
    assert observations[0].dimension is ResourceDimension.CPU
    assert observations[0].is_measured is False
    assert guard.paused is False


def test_cloud_spend_is_external_and_not_charged_a_second_time() -> None:
    """Currency is metered by the cloud cost gate; a second meter double-charges."""
    entry = ledger_for(ResourceDimension.CLOUD_SPEND)
    assert entry.coverage is MeterCoverage.EXTERNAL
    guard = _guard((_budget(ResourceDimension.CLOUD_SPEND, 1.0),), meter=RunMeter(run_id=RUN))
    reading = guard.read(ResourceDimension.CLOUD_SPEND)
    assert reading.value is None
    assert "cloud.cost_estimate" in (reading.reason or "")
    assert guard.observe_step(now=NOW, seam="step:1")[0].is_measured is False


def test_network_is_declared_not_intercepted() -> None:
    """Egress has no portable userspace read, so only known sizes are counted."""
    entry = ledger_for(ResourceDimension.NETWORK)
    assert entry.coverage is MeterCoverage.DECLARED
    assert "userspace" in entry.rationale


def test_storage_is_exact_and_evidence_bytes_are_not_added_again() -> None:
    entry = ledger_for(ResourceDimension.STORAGE)
    assert entry.coverage is MeterCoverage.EXACT
    assert "Evidence bytes are a subset" in entry.rationale


def test_metered_and_unmeasured_dimensions_partition_the_eight() -> None:
    assert metered_dimensions() | unmeasured_dimensions() == set(ResourceDimension)
    assert not metered_dimensions() & unmeasured_dimensions()
    assert unmeasured_dimensions() == {ResourceDimension.CPU}
    for dimension in ResourceDimension:
        assert coverage_for(dimension) is ledger_for(dimension).coverage


# ==============================================================================
# The four newly-metered dimensions
# ==============================================================================


def test_memory_meter_integrates_the_resident_set_into_mebibyte_seconds() -> None:
    """MEMORY is the one derived dimension: a size times an interval."""
    clock = _FakeClock()
    meter = RunMeter(run_id=RUN, clock=clock)
    first = meter.sample_memory(100.0, now=NOW)
    assert first.value == 0.0  # the baseline sample opens no interval
    assert first.unit == unit_for(ResourceDimension.MEMORY)
    clock.advance(2.0)
    second = meter.sample_memory(100.0, now=NOW)
    assert second.value == pytest.approx(200.0)  # 100 MiB held for 2s
    clock.advance(1.0)
    third = meter.sample_memory(40.0, now=NOW)
    assert third.value == pytest.approx(300.0)  # + 100 MiB for 1s, then opens a new interval
    assert meter.memory_sample_count == 3


def test_memory_meter_refuses_a_negative_or_non_finite_resident_set() -> None:
    meter = RunMeter(run_id=RUN, clock=_FakeClock())
    for bad in (-1.0, float("nan"), float("inf")):
        with pytest.raises(InvariantViolationError) as caught:
            meter.sample_memory(bad, now=NOW)
        assert caught.value.rule == RULE_METER_CONTRACT


def test_a_backwards_memory_clock_yields_zero_elapsed_not_a_negative_total() -> None:
    """A clock that went backwards integrates zero, never a negative total."""
    clock = _FakeClock()
    meter = RunMeter(run_id=RUN, clock=clock)
    meter.sample_memory(500.0, now=NOW)
    clock.tick -= 10.0
    reading = meter.sample_memory(500.0, now=NOW)
    assert reading.value == pytest.approx(0.0)
    assert meter.memory_resident_mib_seconds >= 0.0


def test_network_meter_counts_only_what_a_call_site_declares() -> None:
    meter = RunMeter(run_id=RUN, clock=_FakeClock())
    reading = meter.add_network_bytes(2048, now=NOW)
    assert reading.value == pytest.approx(2048.0)
    assert reading.unit == unit_for(ResourceDimension.NETWORK)
    assert meter.add_network_bytes(512, now=NOW).value == pytest.approx(2560.0)
    with pytest.raises(InvariantViolationError):
        meter.add_network_bytes(-1, now=NOW)


def test_target_count_meter_counts_whole_targets() -> None:
    meter = RunMeter(run_id=RUN, clock=_FakeClock())
    meter.add_targets(3, now=NOW)
    reading = meter.add_targets(now=NOW)
    assert reading.value == pytest.approx(4.0)
    assert reading.unit == unit_for(ResourceDimension.TARGET_COUNT)
    for bad in (-1, 1.5, True):  # type: ignore[list-item]
        with pytest.raises(InvariantViolationError) as caught:
            meter.add_targets(bad)  # type: ignore[arg-type]
        assert caught.value.rule == RULE_METER_CONTRACT


def test_concurrent_experiments_reads_the_live_reservation_set() -> None:
    """Concurrency is a property of the live set, not of one run's bookkeeping."""
    reservations = ConcurrentRunReservations("team-a")
    assert reservations.reserve("run-a") == 1.0
    assert reservations.reserve("run-b") == 2.0
    assert reservations.live_run_ids == ("run-a", "run-b")
    assert reservations.release("run-a") == 1.0

    guard = _guard(
        (
            _budget(
                ResourceDimension.CONCURRENT_EXPERIMENTS,
                5.0,
                scope=ResourceScope.EXPERIMENT,
                key="team-a",
            ),
        ),
        reservations=reservations,
        scope=ResourceScope.EXPERIMENT,
    )
    reading = guard.read(ResourceDimension.CONCURRENT_EXPERIMENTS, scope_key="team-a")
    assert reading.measured
    assert reading.value == pytest.approx(1.0)
    assert reading.unit == unit_for(ResourceDimension.CONCURRENT_EXPERIMENTS)


def test_a_reservation_set_for_another_scope_is_no_reading_not_zero() -> None:
    """Reading zero here would be a claim about another team's concurrency."""
    reservations = ConcurrentRunReservations("team-a")
    reservations.reserve("run-a")
    guard = _guard(
        (
            _budget(
                ResourceDimension.CONCURRENT_EXPERIMENTS,
                5.0,
                scope=ResourceScope.EXPERIMENT,
                key="team-b",
            ),
        ),
        reservations=reservations,
        scope=ResourceScope.EXPERIMENT,
    )
    reading = guard.read(ResourceDimension.CONCURRENT_EXPERIMENTS, scope_key="team-b")
    assert reading.value is None
    assert "team-b" in reading.reason


def test_a_concurrency_budget_actually_pauses_a_run() -> None:
    reservations = ConcurrentRunReservations("team-a")
    reservations.reserve(RUN)
    reservations.reserve("run-other")
    reservations.reserve("run-other-2")
    guard = _guard(
        (
            _budget(
                ResourceDimension.CONCURRENT_EXPERIMENTS,
                2.0,
                scope=ResourceScope.EXPERIMENT,
                key="team-a",
            ),
        ),
        reservations=reservations,
        scope=ResourceScope.EXPERIMENT,
    )
    with pytest.raises(PauseForReview) as caught:
        guard.observe_step(now=NOW, seam="step:1")
    assert caught.value.dimension is ResourceDimension.CONCURRENT_EXPERIMENTS
    assert guard.paused


def test_a_reservation_set_needs_a_scope_key() -> None:
    with pytest.raises(InvariantViolationError):
        ConcurrentRunReservations("  ")


# ==============================================================================
# Unmeasured, never zero
# ==============================================================================


def test_a_dimension_whose_seam_has_not_run_reads_unmeasured() -> None:
    """The structural half of the rule: no reading is not the number zero."""
    guard = _guard((_budget(ResourceDimension.STORAGE, 1000.0),), meter=RunMeter(run_id=RUN))
    reading = guard.read(ResourceDimension.STORAGE)
    assert reading.value is None
    assert not reading.measured
    assert "no reading at seam" in reading.reason


def test_a_guard_with_no_meter_reports_unmeasured_for_every_metered_dimension() -> None:
    guard = _guard(
        (
            _budget(ResourceDimension.STORAGE, 1000.0),
            _budget(ResourceDimension.API_CALLS, 10),
            _budget(ResourceDimension.NETWORK, 1000.0),
        ),
    )
    dimensions = (
        ResourceDimension.STORAGE,
        ResourceDimension.API_CALLS,
        ResourceDimension.NETWORK,
    )
    for dimension in dimensions:
        reading = guard.read(dimension)
        assert reading.value is None, dimension
        assert "no meter is attached" in reading.reason


def test_a_real_zero_is_reported_once_the_seam_has_actually_run() -> None:
    """After the seam is exercised, 0.0 is a fact rather than a silence."""
    meter = RunMeter(run_id=RUN, clock=_FakeClock())
    meter.add_store_growth_bytes(0, now=NOW)
    guard = _guard((_budget(ResourceDimension.STORAGE, 1000.0),), meter=meter)
    reading = guard.read(ResourceDimension.STORAGE)
    assert reading.measured
    assert reading.value == 0.0
    assert "no consumption observed" in reading.reason


def test_a_reading_in_the_wrong_unit_is_refused_rather_than_conflated() -> None:
    """Targets counted in bytes is a confident nonsense budget."""
    meter = RunMeter(run_id=RUN, clock=_FakeClock())
    meter.readings.append(
        MeterReading(seam="targets", kind="cumulative", value=3.0, unit="bytes")
    )
    guard = _guard((_budget(ResourceDimension.TARGET_COUNT, 5.0),), meter=meter)
    with pytest.raises(InvariantViolationError) as caught:
        guard.read(ResourceDimension.TARGET_COUNT)
    assert caught.value.rule == RULE_UNIT_CONFLATION
    assert "targets" in str(caught.value)


def test_the_unmeasured_report_names_every_dimension_the_run_cannot_read() -> None:
    guard = _guard((_budget(ResourceDimension.CPU, 1.0),), meter=RunMeter(run_id=RUN))
    guard.observe_step(now=NOW, seam="step:1")
    assert guard.unmeasured() == (ResourceDimension.CPU,)
    assert guard.inputs()["unmeasured"] == ["cpu"]


# ==============================================================================
# Admission
# ==============================================================================


def test_admission_within_budget_admits_and_says_what_it_compared() -> None:
    guard = _guard(
        (_budget(ResourceDimension.STORAGE, 10_000.0),),
        meter=RunMeter(run_id=RUN, clock=_FakeClock()),
        estimates=(_estimate(ResourceDimension.STORAGE, 4000.0),),
    )
    decision = guard.admit(now=NOW)
    assert decision.allowed
    assert decision.estimates_compared == 1
    assert guard.admission_is_vacuous is False
    assert guard.admission is decision


def test_admission_with_no_estimates_is_vacuous_and_says_so() -> None:
    """"Admitted because nothing breached" is not "admitted because nothing was checked"."""
    guard = _guard((_budget(ResourceDimension.STORAGE, 10_000.0),))
    decision = guard.admit(now=NOW)
    assert decision.allowed
    assert guard.admission_is_vacuous is True


def test_admission_refuses_an_over_budget_estimate_naming_the_dimension() -> None:
    guard = _guard(
        (_budget(ResourceDimension.API_CALLS, 100),),
        estimates=(_estimate(ResourceDimension.API_CALLS, 250),),
    )
    with pytest.raises(BudgetAdmissionRefused) as caught:
        guard.admit(now=NOW)
    refusal = caught.value
    assert refusal.rule == RULE_ESTIMATE_EXCEEDED
    assert "api_calls" in refusal.decision.reason
    assert "250" in refusal.decision.reason
    assert "100" in refusal.decision.reason
    assert refusal.decision.consumption is not None
    assert refusal.decision.consumption.overage == pytest.approx(150.0)


# ==============================================================================
# Continuity, and the pause that needs a decision
# ==============================================================================


def _feed(meter: RunMeter, n_bytes: float) -> None:
    """Record storage growth and return None, so it can be a ``sleeper`` hook."""
    meter.add_store_growth_bytes(n_bytes, now=NOW)


def _storage_guard(
    limit: float = 1000.0, *, estimates: tuple[ResourceEstimate, ...] = ()
) -> tuple[RunBudgetGuard, RunMeter]:
    meter = RunMeter(run_id=RUN, clock=_FakeClock())
    guard = _guard(
        (_budget(ResourceDimension.STORAGE, limit),),
        meter=meter,
        estimates=estimates,
    )
    return guard, meter


def test_continuity_within_budget_keeps_running() -> None:
    guard, meter = _storage_guard(limit=1000.0)
    meter.add_store_growth_bytes(400, now=NOW)
    observations = guard.observe_step(now=NOW, seam="step:1")
    assert [o.decision is not None for o in observations] == [True]
    assert guard.paused is False
    assert observations[0].within_budget is True


def test_a_mid_execution_breach_pauses_and_names_the_numbers() -> None:
    guard, meter = _storage_guard(limit=1000.0)
    meter.add_store_growth_bytes(1500, now=NOW)
    with pytest.raises(PauseForReview) as caught:
        guard.observe_step(now=NOW, seam="step:c-a-0001")
    pause = caught.value
    assert pause.dimension is ResourceDimension.STORAGE
    assert pause.seam == "step:c-a-0001"
    assert "1500" in str(pause)
    assert "1000" in str(pause)
    assert guard.paused is True
    assert guard.breach is pause


def test_a_paused_run_cannot_resume_without_a_decision() -> None:
    guard, meter = _storage_guard(limit=1000.0)
    meter.add_store_growth_bytes(1500, now=NOW)
    with pytest.raises(PauseForReview):
        guard.observe_step(now=NOW, seam="step:1")
    meter.add_store_growth_bytes(100, now=NOW)  # the run keeps going, unobserved
    with pytest.raises(BudgetPauseUnreviewed) as caught:
        guard.observe_step(now=NOW, seam="step:2")
    assert RULE_PAUSE_UNREVIEWED in str(caught.value)
    assert caught.value.breach is guard.breach


def test_a_recorded_resume_lets_the_run_be_observed_again() -> None:
    guard, meter = _storage_guard(limit=1000.0)
    meter.add_store_growth_bytes(1500, now=NOW)
    with pytest.raises(PauseForReview):
        guard.observe_step(now=NOW, seam="step:1")
    guard.record_review(
        BudgetReview(
            dimension=ResourceDimension.STORAGE,
            decision=ReviewDecision.RESUME,
            rationale="load soak authorised past the storage cap for this window",
            at=NOW,
            run_id=RUN,
            decided_by="sre-oncall",
        )
    )
    # The same over-budget number is still over budget; resuming is a decision,
    # not a re-measurement, so the reading is judged again and pauses again.
    with pytest.raises(PauseForReview):
        guard.observe_step(now=NOW, seam="step:2")


def test_a_review_must_answer_the_dimension_that_actually_breached() -> None:
    guard, meter = _storage_guard(limit=1000.0)
    meter.add_store_growth_bytes(1500, now=NOW)
    with pytest.raises(PauseForReview):
        guard.observe_step(now=NOW, seam="step:1")
    with pytest.raises(InvariantViolationError) as caught:
        guard.record_review(
            BudgetReview(
                dimension=ResourceDimension.API_CALLS,
                decision=ReviewDecision.RESUME,
                rationale="reviewed the wrong dimension",
                at=NOW,
            )
        )
    assert caught.value.rule == RULE_REVIEW_REQUIRED


def test_a_review_without_a_rationale_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        BudgetReview(
            dimension=ResourceDimension.STORAGE,
            decision=ReviewDecision.RESUME,
            rationale="   ",
            at=NOW,
        )
    assert caught.value.rule == RULE_REVIEW_REQUIRED


def test_a_review_must_be_timestamped_in_utc_or_aware() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        BudgetReview(
            dimension=ResourceDimension.STORAGE,
            decision=ReviewDecision.RESUME,
            rationale="looked at it",
            at=_NAIVE,  # tzinfo deliberately absent: the guard must refuse it
        )
    assert caught.value.rule == RULE_METER_CONTRACT


def test_a_stop_review_ends_the_run_for_good() -> None:
    guard, meter = _storage_guard(limit=1000.0)
    meter.add_store_growth_bytes(1500, now=NOW)
    with pytest.raises(PauseForReview):
        guard.observe_step(now=NOW, seam="step:1")
    guard.record_review(
        BudgetReview(
            dimension=ResourceDimension.STORAGE,
            decision=ReviewDecision.STOP,
            rationale="the storage cap is a hard limit for this run",
            at=NOW,
        )
    )
    assert guard.stopped is True
    with pytest.raises(BudgetPauseUnreviewed) as caught:
        guard.observe_step(now=NOW, seam="step:2")
    assert "stops here" in str(caught.value)


def test_an_observation_against_a_broader_scope_says_it_is_this_runs_share() -> None:
    """A single run's reading is not an organisation's total, and says so."""
    meter = RunMeter(run_id=RUN, clock=_FakeClock())
    meter.add_store_growth_bytes(100, now=NOW)
    guard = _guard(
        (
            _budget(
                ResourceDimension.STORAGE,
                10_000.0,
                scope=ResourceScope.ORGANISATION,
                key="acme",
            ),
        ),
        meter=meter,
        scope=ResourceScope.RUN,
    )
    observation = guard.observe_step(now=NOW, seam="step:1")[0]
    assert "this run's contribution" in observation.reason
    assert "not the scope's aggregate" in observation.reason


def test_two_equal_budgets_meter_into_one_ledger() -> None:
    """Observing both would post one reading twice into one series."""
    budget = _budget(ResourceDimension.STORAGE, 1000.0)
    meter = RunMeter(run_id=RUN, clock=_FakeClock())
    meter.add_store_growth_bytes(400, now=NOW)
    guard = _guard((budget, budget.model_copy()), meter=meter)
    observations = guard.observe_step(now=NOW, seam="step:1")
    assert len(observations) == 1
    assert guard.enforcer.series_for(budget).length == 1


# ==============================================================================
# The two negative controls about the two ledgers
# ==============================================================================


def test_budget_enforcement_imports_no_damage_ledger_and_no_safety_gate() -> None:
    """Structural, not behavioural: the import graph is the guarantee.

    Parsed rather than asserted by hand so the check cannot be satisfied by a
    comment. ``mayhem.infra.budget_enforcement`` may not reach the damage ledger,
    the damage budget tree, or the safety gate — that is what makes "one
    dimension's slack never pays for another's overspend" structural instead of
    a review comment.
    """
    source = Path(budget_enforcement.__file__).read_text()
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)
    forbidden = {
        "mayhem.domain.quota",
        "mayhem.domain.policy",
        "mayhem.controller.safety",
        "mayhem.controller.policy_gate",
    }
    assert not imported & forbidden, imported & forbidden


def test_a_damage_refusal_is_not_a_resource_pause() -> None:
    """Damage over its limit must not pause anything the resource guard watches.

    Exercised through the real damage gate — ``check_blast_radius`` with a
    deliberately tiny ``DamageQuota`` — rather than through the ledger directly,
    so what is proven is that a *damage* refusal, the shape the controller
    actually raises, leaves the resource guard completely uninvolved.
    """
    ctx = SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(
            max_services_pct=100.0,
            max_hosts=1000,
            max_concurrent_faults=10,
        ),
        fingerprint="fp-test",
        damage_quota=DamageQuota(
            budget_s=0.001,
            per_fault_ceiling_s=0.001,
            window_s=3600.0,
        ),
    )
    graph = _graph(os.getpid())
    with pytest.raises(SafetyRefusedError) as caught:
        check_blast_radius(
            graph,
            ["proc-a"],
            300.0,
            (),
            "proc.pause",
            ctx=ctx,
        )
    assert "damage_quota." in str(caught.value)

    guard, _meter = _storage_guard(limit=1_000_000.0)
    observations = guard.observe_step(now=NOW, seam="step:1")
    assert guard.paused is False
    assert guard.breach is None
    assert observations[0].within_budget is True
    assert guard.observations[0].is_measured is False  # unmeasured, never a breach


def test_a_resource_pause_does_not_charge_a_damage_ledger() -> None:
    """The other direction: storage over budget must leave damage seconds alone."""
    ledger = DamageLedger()
    charge = ledger.charge(
        fault_id="proc.pause",
        duration_s=30.0,
        node_ids=["proc-a"],
        quota=DamageQuota(
            budget_s=1_000_000.0,
            per_fault_ceiling_s=1_000_000.0,
            window_s=3600.0,
        ),
    )
    assert charge.exceeded is False
    assert ledger.total_s == pytest.approx(30.0)

    guard, meter = _storage_guard(limit=1000.0)
    meter.add_store_growth_bytes(5000, now=NOW)
    with pytest.raises(PauseForReview) as caught:
        guard.observe_step(now=NOW, seam="step:1")
    assert caught.value.consumption.dimension is ResourceDimension.STORAGE
    # Nothing about the damage ledger moved, and its namespace is untouched:
    # storage bytes are not damage seconds.
    assert ledger.damage_for("proc-a") == pytest.approx(30.0)
    assert charge.rule_id == ""


def test_the_two_rule_namespaces_never_collide() -> None:
    """A record naming one system is unambiguously about that system."""
    guard, meter = _storage_guard(limit=1000.0)
    meter.add_store_growth_bytes(5000, now=NOW)
    with pytest.raises(PauseForReview) as caught:
        guard.observe_step(now=NOW, seam="step:1")
    payload = caught.value.inputs()
    assert payload["dimension"] == "storage"
    assert "damage" not in str(payload["dimension"])
    assert caught.value.consumption.rule_id == RULE_LIMIT_EXCEEDED


# ==============================================================================
# The wiring: the real run path, and the golden that no guard changed it
# ==============================================================================


def _spawn_sleeper() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"],
        stdout=subprocess.DEVNULL,
    )


def _graph(pid: int) -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ContainerNode(
                id="ctr-a",
                name="a",
                engine="podman",
                runtime_identity=RuntimeIdentity(
                    runtime="podman", host_id="h", runtime_id="a"
                ),
                container_name="c-a",
                state="running",
            ),
            ProcessNode(id="proc-a", name="pa", pid=pid, host_id="h", container_name="c-a"),
        ),
        edges=(Edge(src="ctr-a", dst="proc-a", kind=EdgeKind.RUNS_ON),),
    )


def _plan(run_id: str, graph: TopologyGraph) -> Any:
    spec = DrillSpec(
        kind="drill",
        name="budget-phase-3",
        containers={
            "c-a": DrillContainer(
                faults=(DrillFault(fault="proc.pause", duration="1s"),),
            )
        },
        execution=(ExecutionStep(parallel=("c-a",)), ExecutionStep(wait="2s")),
    )
    return plan_drill(
        run_id,
        spec,
        graph,
        config_snapshot_id="cfg-1",
        topology_snapshot_id="topo-1",
        environment_fingerprint="fp-test",
    )


@pytest.fixture
def sleeper() -> Iterator[subprocess.Popen[bytes]]:
    proc = _spawn_sleeper()
    try:
        yield proc
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.fixture
def resolved(
    sleeper: subprocess.Popen[bytes], monkeypatch: pytest.MonkeyPatch
) -> TopologyGraph:
    """A graph whose container resolves to a live process, with injection bypassed.

    Bypassed rather than executed so the golden is a fast, deterministic run: the
    step reports its bypass and the executor's own per-step bookkeeping is still
    exercised end to end.
    """
    from mayhem.controller import executor as executor_mod

    def fake_resolve(container_name: str, engine: str | None = None) -> ContainerInfo:
        return ContainerInfo(pid=sleeper.pid, ip_address="127.0.0.1", state="running")

    def fake_identity(container_name: str, engine: str | None = None) -> RuntimeIdentity:
        return RuntimeIdentity(runtime=engine or "podman", host_id="h", runtime_id="a")

    monkeypatch.setattr(executor_mod, "resolve_container", fake_resolve)
    monkeypatch.setattr(executor_mod, "resolve_identity", fake_identity)
    return _graph(sleeper.pid)


def _engine(tmp_path: Path, graph: TopologyGraph, **kwargs: Any) -> tuple[RunEngine, Store]:
    store = Store.open_migrated(tmp_path / "budget.db")
    engine = RunEngine(
        store,
        SQLiteLeaseSink(store),
        sleeper=lambda _seconds: None,
        live_graph=lambda: graph,
        bypass={("proc.pause", "c-a"): "phase-3 fixture"},
        **kwargs,
    )
    return engine, store


def _dump(result: Any, store: Store, run_id: str) -> str:
    """Everything a run leaves behind that is not a timestamp or a pid."""
    lines = [f"status={result.status}"]
    for step in result.steps:
        lines.append(f"step {step.step_id}|{step.ok}|{step.status}|{step.detail}")
    for row in store.query(
        "SELECT kind, payload_json FROM events WHERE run_id = ? ORDER BY id", (run_id,)
    ):
        lines.append(f"event {row['kind']}|{row['payload_json']}")
    for row in store.query("SELECT id, status FROM runs WHERE id = ?", (run_id,)):
        lines.append(f"run {row['id']}={row['status']}")
    for row in store.query(
        "SELECT id, status FROM step_runs WHERE run_id = ? ORDER BY seq", (run_id,)
    ):
        lines.append(f"step_run {row['id']}={row['status']}")
    for row in store.query(
        "SELECT id, state FROM fault_leases WHERE run_id = ? ORDER BY id", (run_id,)
    ):
        lines.append(f"lease {row['id']}={row['state']}")
    # The rendered report carries a wall-clock window line; drop it so the golden
    # asserts the *content* of the summary rather than when the run happened.
    lines += [
        f"summary|{line}"
        for line in result.summary_md().splitlines()
        if line.strip() and not line.startswith("- **window**")
    ]
    return "\n".join(lines)


#: The whole observable surface of a run with **no budget guard attached**. Any
#: drift in the executor — a reworded step, a reordered event, a status that
#: moved, a recovery that stopped running — breaks this string. It is the same
#: standard `test_policy_gate.py` set when it added an optional gate to
#: `validate_plan`: an additive hook that cannot be seen is an additive hook
#: nobody has evidence for.
GOLDEN_NO_GUARD = "\n".join(
    (
        "status=completed",
        "step c-a-0000|True|bypassed|bypass due to c-a: phase-3 fixture",
        "step wait-0001|True|ok|waited 2.0s",
        "event run.started|{}",
        'event step.started|{"step": "c-a-0000"}',
        "event step.skipped|"
        '{"step": "c-a-0000", "detail": "bypass due to c-a: phase-3 fixture"}',
        'event step.started|{"step": "wait-0001"}',
        'event step.finished|{"step": "wait-0001", "detail": "waited 2.0s"}',
        "event run.completed|{}",
        "run r-golden=completed",
        "step_run 0000-c-a-0000=bypassed",
        "step_run 0001-wait-0001=completed",
        "summary|# Run r-golden",
        "summary|## outcome",
        "summary|- **status**: completed",
        "summary|- **decisions**: ADR-M4-1 2026-09-02 (Additive, non-breaking DSL"
        " sections + typed Duration); ADR-M4-5 2026-09-02 (Schema freeze +"
        " versioned migrations with up/down)",
        "summary|- **affected services**: bypass due to c-a, waited 2.0s",
        "summary|- **observed symptoms**: c-a-0000 bypassed",
        "summary|- **recovery status**: recovered",
        "summary|## steps",
        "summary|- [bypass] c-a-0000: bypass due to c-a: phase-3 fixture",
        "summary|- [ok] wait-0001: waited 2.0s",
        "summary|## resilience",
        "summary|**resilience**: 88/100 — grade B (solid)",
        "summary|metrics:",
        "summary|| metric | result | model |",
        "summary||---|---|---|",
        "summary|| fault-injection fidelity | 100% | fault-validity of executed"
        " steps — Hsueh, Tsai & Iyer, *Fault Injection Techniques and Tools*,"
        " IEEE Computer 30(4), 1997 |",
        "summary|| recovery | 75% | self-healing without manual intervention —"
        " *Resilience Engineering: Concepts and Precepts*, Hollnagel, Woods &"
        " Leveson, Ashgate 2006 |",
        "summary|| redundancy efficacy | not measured | no replica groups resolved"
        " — M-of-N fault tolerance, Avizienis, Laprie & Randell 2001 |",
        "summary|**weighting**: fidelity 35%, recovery 35%, redundancy 30% (ADR-M6-1)",
        "summary|observations:",
        "summary|  - steps: 1/1 ok (1 bypassed)",
        "summary|  - dirty leases: 0",
        "summary|  - targets alive after run: 1/2",
        "summary|## next",
        "summary|- inspect with `mayhem inspect run <id>`; next recommended:"
        " `mayhem inspect next`",
    )
)


def test_a_run_with_no_budget_guard_is_byte_identical_to_the_golden(
    tmp_path: Path, resolved: TopologyGraph
) -> None:
    engine, store = _engine(tmp_path, resolved)
    plan = _plan("r-golden", resolved)
    result = engine.execute(plan)
    assert result.status == "completed", result.summary_md()
    assert _dump(result, store, "r-golden") == GOLDEN_NO_GUARD


def test_an_engine_with_no_guard_reports_no_budget_verdict(
    tmp_path: Path, resolved: TopologyGraph
) -> None:
    """No guard means no admission decision and no pause — not a default one."""
    engine, _store = _engine(tmp_path, resolved)
    plan = _plan("r-unbudgeted", resolved)
    result = engine.execute(plan)
    assert result.status == "completed"
    assert engine.budget_guard is None
    assert engine.budget_admission is None
    assert engine.budget_pause is None


def test_a_guard_that_nothing_breaches_leaves_the_run_alone(
    tmp_path: Path, resolved: TopologyGraph
) -> None:
    """The gate must not change a run that stays inside its budgets."""
    meter = RunMeter(run_id="r-within", clock=_FakeClock())
    meter.add_store_growth_bytes(10, now=NOW)
    guard = _guard(
        (_budget(ResourceDimension.STORAGE, 1_000_000.0),),
        meter=meter,
        estimates=(_estimate(ResourceDimension.STORAGE, 100.0),),
        run_id="r-within",
    )
    engine, _store = _engine(tmp_path, resolved, budget_guard=guard)
    result = engine.execute(_plan("r-within", resolved))
    assert result.status == "completed", result.summary_md()
    assert engine.budget_pause is None
    assert guard.admission is not None and guard.admission.allowed
    # One observation per step, and every one of them inside the budget.
    assert len(guard.observations) == 2
    assert all(obs.within_budget for obs in guard.observations)


def test_admission_refuses_before_the_run_touches_the_store(
    tmp_path: Path, resolved: TopologyGraph
) -> None:
    """The refusal has to come before _open_run, or it is a bill, not a refusal."""
    guard = _guard(
        (_budget(ResourceDimension.API_CALLS, 100),),
        estimates=(_estimate(ResourceDimension.API_CALLS, 400),),
        run_id="r-refused",
    )
    engine, store = _engine(tmp_path, resolved, budget_guard=guard)
    with pytest.raises(BudgetAdmissionRefused) as caught:
        engine.execute(_plan("r-refused", resolved))
    assert "api_calls" in caught.value.decision.reason
    assert caught.value.decision.consumption is not None
    assert caught.value.decision.consumption.dimension is ResourceDimension.API_CALLS
    # No run row, no step row, no lease, no event: nothing was mutated.
    for table in ("runs", "step_runs", "fault_leases", "events", "recovery_records"):
        assert store.query(f"SELECT COUNT(*) AS n FROM {table}")[0]["n"] == 0, table
    assert engine.budget_admission is not None
    assert engine.budget_admission.refused is True


def test_a_mid_execution_breach_pauses_the_run_and_stops_the_remaining_steps(
    tmp_path: Path, resolved: TopologyGraph
) -> None:
    """The pause is a status, and the run ends there rather than continuing."""
    meter = RunMeter(run_id="r-paused", clock=_FakeClock())
    guard = _guard(
        (_budget(ResourceDimension.STORAGE, 1000.0),),
        meter=meter,
        run_id="r-paused",
    )

    def feed(_seconds: float) -> None:
        # The sleeper is where this run's storage actually grows.
        _feed(meter, 4000)

    store = Store.open_migrated(tmp_path / "paused.db")
    engine = RunEngine(
        store,
        SQLiteLeaseSink(store),
        sleeper=feed,
        live_graph=lambda: resolved,
        bypass={("proc.pause", "c-a"): "phase-3 fixture"},
        budget_guard=guard,
    )
    result = engine.execute(_plan("r-paused", resolved))
    # The runs table admits no "paused" status, so the breach is reported as an
    # abort *with the breach attached* rather than as a status that cannot persist.
    assert result.status == "aborted", result.summary_md()
    assert result.budget_breach is not None
    pause = engine.budget_pause
    assert pause is not None
    assert pause.dimension is ResourceDimension.STORAGE
    assert guard.paused is True
    # The breached step is recorded; the step after it never ran.
    assert [step.step_id for step in result.steps] == ["c-a-0000"]
    # The pause is visible in the run's own records, not only in the exception:
    # the summary names the breaching dimension and its numbers.
    assert store.query("SELECT status FROM runs WHERE id = 'r-paused'")[0]["status"] == "aborted"
    assert "paused for review" in result.summary_md()
    assert "storage" in result.summary_md()
    # Recovery still ran: a paused run must not leave leases behind unrecovered.
    assert not result.dirty_leases


def test_a_paused_run_needs_a_review_before_it_is_observed_again(
    tmp_path: Path, resolved: TopologyGraph
) -> None:
    meter = RunMeter(run_id="r-review", clock=_FakeClock())
    guard = _guard(
        (_budget(ResourceDimension.STORAGE, 1000.0),),
        meter=meter,
        run_id="r-review",
    )
    store = Store.open_migrated(tmp_path / "review.db")
    engine = RunEngine(
        store,
        SQLiteLeaseSink(store),
        sleeper=lambda _seconds: _feed(meter, 4000),
        live_graph=lambda: resolved,
        bypass={("proc.pause", "c-a"): "phase-3 fixture"},
        budget_guard=guard,
    )
    engine.execute(_plan("r-review", resolved))
    assert engine.budget_pause is not None
    with pytest.raises(BudgetPauseUnreviewed):
        guard.observe_step(now=NOW, seam="step:later")
    guard.record_review(
        BudgetReview(
            dimension=ResourceDimension.STORAGE,
            decision=ReviewDecision.RESUME,
            rationale="the soak was authorised for this window",
            at=NOW,
            run_id="r-review",
        )
    )
    assert [review.decision for review in guard.reviews] == [ReviewDecision.RESUME]
    assert "authorised for this window" in guard.reviews[0].describe()


# ==============================================================================
# The CLI seam
# ==============================================================================


def test_the_cli_seam_builds_attaches_and_admits(tmp_path: Path, resolved: TopologyGraph) -> None:
    """`cli.execution` is the edge a CLI surface configures a run's budgets at."""
    meter = RunMeter(run_id="r-cli", clock=_FakeClock())
    guard = resource_budget_guard(
        budgets=(_budget(ResourceDimension.TARGET_COUNT, 5.0, key="team-a"),),
        scope=ResourceScope.RUN,
        anchor=ANCHOR,
        run_id="r-cli",
        meter=meter,
        reservations=ConcurrentRunReservations("team-a"),
        estimates=(_estimate(ResourceDimension.TARGET_COUNT, 2.0, key="team-a"),),
    )
    decision = budget_admission(guard, now=NOW)
    assert decision.allowed
    assert decision.estimates_compared == 1

    engine, store = _engine(tmp_path, resolved)
    assert attach_resource_budget(engine, guard) is engine
    assert engine.budget_guard is guard
    engine.execute(_plan("r-cli", resolved))
    assert engine.budget_admission is not None
    assert engine.budget_admission.allowed
    assert store.query("SELECT status FROM runs WHERE id = 'r-cli'")[0]["status"] == "completed"
    # The concurrency seam never ran a reservation for this scope key, so the
    # target-count budget is judged and the concurrency one is simply absent.
    assert guard.unmeasured() == (ResourceDimension.TARGET_COUNT,)


def test_the_cli_admission_seam_refuses_with_the_same_numbers() -> None:
    guard = resource_budget_guard(
        budgets=(_budget(ResourceDimension.NETWORK, 1000.0),),
        scope=ResourceScope.RUN,
        anchor=ANCHOR,
        run_id="r-cli-refused",
        estimates=(_estimate(ResourceDimension.NETWORK, 4000.0),),
    )
    with pytest.raises(BudgetAdmissionRefused) as caught:
        budget_admission(guard, now=NOW, estimates=guard.estimates)
    assert "network" in caught.value.decision.reason
    assert "4000" in caught.value.decision.reason


# ==============================================================================
# Metering stays a meter
# ==============================================================================


def test_a_broken_sink_still_loses_exactly_one_reading() -> None:
    """The Phase 2 discipline Phase 3 must not break: a meter never breaks a run."""

    class _Broken:
        def record(self, reading: MeterReading) -> None:
            raise RuntimeError("exporter down")

    meter = RunMeter(run_id=RUN, clock=_FakeClock(), sink=_Broken())
    meter.add_targets(2, now=NOW)
    meter.add_network_bytes(10, now=NOW)
    assert meter.failures == [
        ("targets", "RuntimeError: exporter down"),
        ("network_egress", "RuntimeError: exporter down"),
    ]
    assert meter.total_targets == pytest.approx(2.0)
    assert meter.total_network_bytes == pytest.approx(10.0)


def test_the_new_seams_are_reachable_on_the_meter_and_in_its_exports() -> None:
    for name in (
        "sample_memory",
        "add_network_bytes",
        "add_targets",
        "total_network_bytes",
        "total_targets",
        "memory_resident_mib_seconds",
        "memory_sample_count",
    ):
        assert hasattr(metering.RunMeter, name), name


def test_no_ambient_clock_in_the_wiring() -> None:
    """Every decision the guard makes takes `now`; nothing reads a wall clock."""
    source = Path(budget_enforcement.__file__).read_text()
    assert "utc_now" not in source
    assert "datetime.now" not in source
