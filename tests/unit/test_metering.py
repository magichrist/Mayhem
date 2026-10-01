"""Plan 23 Phase 2 — metering at the seams, and resource-budget enforcement.

Phase 1's suite (``test_budgets.py``) proved the *arithmetic*: a limit, a
window, a cumulative series, an estimate beside an actual, a benchmark spec that
reproduces its workload. This one proves the two things Phase 1 could not,
because they are not properties of a number:

1. **The meter is a seam, not a wrapper.** Every instrumented point records a
   reading and hands control straight back; a broken sink loses one reading and
   nothing else; a block that raises is still timed, because a failed plan
   compilation reported as zero latency would read as "instant" on a dashboard.
2. **The budget is enforced, not just measured.** A pre-execution estimate that
   would breach is refused *before* mutation, naming the dimension and the
   numbers; a run that breaches mid-execution *pauses*, with the reading that
   caused it attached, rather than being silently truncated or silently allowed
   to finish.

The suite is organized as the requirements are:

1. seam tests with fakes (an injected clock and a fake sink, so no assertion
   depends on wall-clock timing or on a real exporter);
2. admission — refusal, admission, and the governance report;
3. continuity — pause on breach, exact-limit semantics, and the stickiness that
   keeps a paused run from resuming itself;
4. publish gating — methodology attached, outputs reported;
5. negative controls — the five the plan names, each asserting a *rule id*, not
   a string that could drift.

Nothing here reads a wall clock to decide anything: every decision takes ``now``
as an argument, and the only injected clock is the monotonic
:func:`time.perf_counter`-shaped fake the timing seams consume.
"""

from __future__ import annotations

import inspect
import math
from datetime import UTC, datetime, timedelta

import pytest

from mayhem.domain.budgets import (
    RULE_ESTIMATE_EXCEEDED,
    RULE_LIMIT_EXCEEDED,
    RULE_MEASURED_OUTPUTS_REQUIRED,
    RULE_NEGATIVE_LIMIT,
    RULE_NON_MONOTONIC_CONSUMPTION,
    RULE_SCALE_UNMEASURED,
    BenchmarkMetric,
    BenchmarkSpec,
    ConsumptionSample,
    Measurement,
    ResourceBudget,
    ResourceDimension,
    ResourceEstimate,
    ResourceScope,
    ResourceSeries,
    ScaleClaim,
    TargetScale,
    WorkloadShape,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.infra import metering
from mayhem.infra.metering import (
    NEGATIVE_CONTROL_RULES,
    RULE_BUDGET_NOT_GOVERNED,
    RULE_ESTIMATE_UNMEASURED,
    RULE_METER_CONTRACT,
    RULE_METER_SINK_FAILED,
    RULE_METHODOLOGY_REQUIRED,
    BudgetAdmissionRefused,
    MeterContractError,
    MeterReading,
    PauseForReview,
    ResourceBudgetEnforcer,
    RunMeter,
    admission_check,
    build_run_meter,
    continuity_check,
    publish_benchmark,
    render_scale_claim,
    strict_reading,
)

ANCHOR = datetime(2026, 1, 1, tzinfo=UTC)
"""Window grid origin. Fixed, so every window in this suite is exact."""

NOW = ANCHOR + timedelta(hours=1)
HOUR = 3600.0


# =============================================================================
# Fakes
# =============================================================================


class FakeClock:
    """A monotonic clock that advances by a fixed step on every read.

    Two readings are consumed per timing seam (start, stop), so a test that times
    three seams supplies six steps. It is deliberately *not* random and *not*
    wall-clock: a timing assertion that could fail on a slow machine is a flaky
    test, and a flaky test in this suite would be indistinguishable from the
    property it is meant to protect.
    """

    def __init__(self, step: float = 1.5) -> None:
        self.step = step
        self.reads = 0

    def __call__(self) -> float:
        current = self.reads * self.step
        self.reads += 1
        return current


class FakeSink:
    """Records what it is handed; can be told to fail."""

    def __init__(self, *, fail: bool = False) -> None:
        self.accepted: list[MeterReading] = []
        self.fail = fail

    def record(self, reading: MeterReading) -> None:
        if self.fail:
            msg = "exporter connection refused"
            raise ConnectionError(msg)
        self.accepted.append(reading)


def _budget(
    dimension: ResourceDimension = ResourceDimension.CPU,
    *,
    limit: float = 100.0,
    window_s: float = HOUR,
    scope: ResourceScope = ResourceScope.RUN,
    scope_key: str = "drill-1",
) -> ResourceBudget:
    return ResourceBudget(
        dimension=dimension,
        scope=scope,
        scope_key=scope_key,
        limit=limit,
        window_s=window_s,
    )


def _estimate(
    dimension: ResourceDimension = ResourceDimension.CPU,
    *,
    expected: float = 10.0,
    scope: ResourceScope = ResourceScope.RUN,
    scope_key: str = "drill-1",
    basis: str = "100 targets x 0.1 core-s, from the last three runs",
) -> ResourceEstimate:
    return ResourceEstimate(
        dimension=dimension,
        scope=scope,
        scope_key=scope_key,
        expected=expected,
        basis=basis,
    )


def _enforcer(
    *budgets: ResourceBudget,
    scope: ResourceScope = ResourceScope.RUN,
) -> ResourceBudgetEnforcer:
    return ResourceBudgetEnforcer(
        budgets=budgets or (_budget(),),
        scope=scope,
        anchor=ANCHOR,
        run_id="drill-1",
    )


def _spec(**overrides: object) -> BenchmarkSpec:
    """A valid spec; ``overrides`` bend one field at a time."""
    fields: dict[str, object] = {
        "spec_id": "bench.cpu.100",
        "metric": BenchmarkMetric.PLAN_COMPILATION_LATENCY,
        "shape": WorkloadShape(iterations=2, targets=10, concurrency=5),
        "scale": TargetScale(targets=100),
        "measured_outputs": ("p50_ms", "p99_ms"),
        "methodology": "10 warmup iterations, timing injected at the compiler seam",
    }
    fields.update(overrides)
    return BenchmarkSpec(**fields)  # type: ignore[arg-type]


def _measurements(*names: str) -> tuple[Measurement, ...]:
    return tuple(Measurement(name=name, value=1.0, unit="ms", samples=10) for name in names)


# =============================================================================
# 1. Metering the seams
# =============================================================================


def test_plan_compilation_seam_records_one_duration() -> None:
    meter = RunMeter(run_id="drill-1", clock=FakeClock(step=2.0))

    with meter.time_plan_compilation(now=NOW):
        pass

    assert meter.plan_compilation_latencies == (2.0,)
    readings = meter.readings_for("plan_compilation")
    assert len(readings) == 1
    assert readings[0].value == 2.0
    assert readings[0].unit == "seconds"
    assert readings[0].at == NOW
    assert readings[0].run_id == "drill-1"


def test_discovery_and_policy_evaluation_are_separate_seams() -> None:
    """They are not folded together, and neither is folded into compilation.

    Discovery happens once per run and policy evaluation once per fault step, so
    a single blended "control-plane latency" number would be multiplied by plan
    length and describe nothing.
    """
    meter = RunMeter(run_id="drill-1", clock=FakeClock(step=1.0))

    with meter.time_discovery(now=NOW):
        pass
    with meter.time_policy_evaluation(now=NOW):
        pass
    with meter.time_plan_compilation(now=NOW):
        pass

    assert meter.discovery_latencies == (1.0,)
    assert meter.policy_evaluation_latencies == (1.0,)
    assert meter.plan_compilation_latencies == (1.0,)
    assert meter.readings_for("discovery")[0].seam == "discovery"
    assert meter.readings_for("policy_evaluation")[0].seam == "policy_evaluation"


def test_nested_timing_seams_each_report_their_own_duration() -> None:
    """A discovery inside a compilation must not clobber the outer start time.

    This is exactly what the controller does — discover, then compile — and it is
    the case an "stash the start on ``self``" implementation silently gets wrong.
    """
    meter = RunMeter(run_id="drill-1", clock=FakeClock(step=1.0))

    with meter.time_plan_compilation(now=NOW):
        with meter.time_discovery(now=NOW):
            pass

    # Inner reads the clock twice (1.0, 2.0 -> 1.0s). The outer read happened
    # before it (0.0) and reads again after it (3.0 -> 3.0s), so the outer
    # duration includes the inner one. A "stash the start on self" meter would
    # report the outer as 1.0s and lose the nesting entirely.
    assert meter.discovery_latencies == (1.0,)
    assert meter.plan_compilation_latencies == (3.0,)


def test_agent_command_latency_is_keyed_per_command() -> None:
    """One blended average over every method would describe no method at all."""
    meter = RunMeter(run_id="drill-1", clock=FakeClock(step=1.0))

    with meter.time_agent_command("sleep", now=NOW):
        pass
    with meter.time_agent_command("sleep", now=NOW):
        pass
    with meter.time_agent_command("ping", now=NOW):
        pass

    assert meter.agent_command_latency("sleep") == (1.0, 1.0)
    assert meter.agent_command_latency("ping") == (1.0,)
    assert meter.agent_command_latency("never-issued") == ()
    assert [reading.seam for reading in meter.readings_for("agent_command:sleep")] == [
        "agent_command:sleep",
        "agent_command:sleep",
    ]


def test_evidence_bytes_accumulate_cumulatively_per_run() -> None:
    meter = RunMeter(run_id="drill-1")

    first = meter.add_evidence_bytes(4096, now=NOW)
    second = meter.add_evidence_bytes(1024, now=NOW)

    assert first.value == 4096.0
    assert second.value == 5120.0
    assert meter.total_evidence_bytes == 5120.0
    # Cumulative, not delta: a consumer that summed these would report 9216
    # bytes for a run that produced 5120, which is the quadratic this shape
    # exists to prevent.
    assert second.is_cumulative is True
    assert second.unit == "bytes"


def test_store_growth_is_metered_apart_from_evidence() -> None:
    """Evidence is what a run produced; store growth is what it left behind.

    The second is routinely the larger number (indexes, WAL, replication lag), so
    a single "bytes" counter would answer neither question.
    """
    meter = RunMeter(run_id="drill-1")

    meter.add_evidence_bytes(1000, now=NOW)
    meter.add_store_growth_bytes(9000, now=NOW)

    assert meter.total_evidence_bytes == 1000.0
    assert meter.total_store_growth_bytes == 9000.0
    assert meter.readings_for("store_growth")[0].value == 9000.0


def test_api_calls_count_in_whole_calls() -> None:
    meter = RunMeter(run_id="drill-1")

    meter.count_api_calls(now=NOW)
    reading = meter.count_api_calls(3, now=NOW)

    assert reading.value == 4.0
    assert reading.unit == "calls"
    assert meter.total_api_calls == 4.0


def test_a_failed_block_is_still_timed_rather_than_reported_as_instant() -> None:
    """Zero latency reads as "instant" on a dashboard, which is a false claim.

    A plan compilation that always raises would otherwise report a mean of
    0.0 seconds and look infinitely fast — the most flattering possible lie a
    benchmark can tell.
    """
    meter = RunMeter(run_id="drill-1", clock=FakeClock(step=4.0))

    with pytest.raises(RuntimeError, match="compilation failed"), meter.time_plan_compilation(
        now=NOW
    ):
        msg = "compilation failed"
        raise RuntimeError(msg)

    assert meter.plan_compilation_latencies == (4.0,)


def test_a_backwards_clock_yields_zero_rather_than_a_negative_duration() -> None:
    """An injected or quirky clock must not poison every mean downstream."""
    backwards = iter([10.0, 4.0])
    meter = RunMeter(run_id="drill-1", clock=lambda: next(backwards))

    with meter.time_plan_compilation(now=NOW):
        pass

    assert meter.plan_compilation_latencies == (0.0,)


def test_latency_means_are_per_seam_and_sorted() -> None:
    meter = RunMeter(run_id="drill-1", clock=FakeClock(step=1.0))

    with meter.time_plan_compilation(now=NOW):
        pass
    with meter.time_agent_command("ping", now=NOW):
        pass
    with meter.time_agent_command("ping", now=NOW):
        pass

    means = meter.latency_means()
    assert means == {
        "agent_command:ping_s": 1.0,
        "plan_compilation_s": 1.0,
    }
    assert list(means) == sorted(means)


def test_the_sink_receives_every_reading() -> None:
    sink = FakeSink()
    meter = build_run_meter(run_id="drill-1", clock=FakeClock(), sink=sink)

    with meter.time_policy_evaluation(now=NOW):
        pass
    meter.add_evidence_bytes(10, now=NOW)

    assert [reading.seam for reading in sink.accepted] == ["policy_evaluation", "evidence"]


def test_a_meter_with_no_sink_records_readings_locally() -> None:
    """The default configuration must not require an exporter to exist."""
    meter = RunMeter(run_id="drill-1")

    meter.count_api_calls(now=NOW)

    assert meter.failures == []
    assert len(meter.readings) == 1


# =============================================================================
# 2. Budget enforcement — admission, before any mutation
# =============================================================================


def test_admission_refuses_an_estimate_that_would_breach() -> None:
    decision = admission_check(
        budgets=[_budget(limit=100.0)],
        estimates=[_estimate(expected=250.0)],
        scope=ResourceScope.RUN,
        now=NOW,
        anchor=ANCHOR,
    )

    assert decision.refused is True
    assert decision.allowed is False
    assert decision.rule_id == RULE_ESTIMATE_EXCEEDED


def test_the_admission_refusal_names_the_dimension_and_the_numbers() -> None:
    """Plan 23 Phase 4: a refusal must say *which* budget broke, and by how much."""
    decision = admission_check(
        budgets=[_budget(ResourceDimension.API_CALLS, limit=1000.0)],
        estimates=[_estimate(ResourceDimension.API_CALLS, expected=1500.0)],
        scope=ResourceScope.RUN,
        now=NOW,
        anchor=ANCHOR,
    )

    assert decision.refused is True
    consumption = decision.consumption
    assert consumption is not None
    assert consumption.dimension is ResourceDimension.API_CALLS
    # The dimension, the number, the limit, the overage, and the unit.
    assert "api_calls" in decision.reason
    assert "1500" in decision.reason
    assert "1000" in decision.reason
    assert "500" in decision.reason
    assert "calls" in decision.reason
    assert decision.remediation != ""


def test_admission_inputs_are_evidence_shaped() -> None:
    decision = admission_check(
        budgets=[_budget(limit=10.0)],
        estimates=[_estimate(expected=20.0)],
        scope=ResourceScope.RUN,
        now=NOW,
        anchor=ANCHOR,
    )

    inputs = decision.inputs()
    assert inputs["refused"] is True
    assert inputs["estimates_compared"] == 1
    assert inputs["dimension"] == "cpu"
    assert inputs["measured"] == 20.0
    assert inputs["limit"] == 10.0
    assert inputs["utilisation"] == 2.0


def test_an_estimate_within_budget_is_admitted() -> None:
    decision = admission_check(
        budgets=[_budget(limit=100.0)],
        estimates=[_estimate(expected=99.0)],
        scope=ResourceScope.RUN,
        now=NOW,
        anchor=ANCHOR,
    )

    assert decision.refused is False
    assert decision.estimates_compared == 1
    assert decision.consumption is None


def test_an_estimate_exactly_at_the_limit_is_admitted() -> None:
    """Exactly at the limit is spent, not over — the domain's own distinction."""
    decision = admission_check(
        budgets=[_budget(limit=100.0)],
        estimates=[_estimate(expected=100.0)],
        scope=ResourceScope.RUN,
        now=NOW,
        anchor=ANCHOR,
    )

    assert decision.refused is False


def test_a_breaching_estimate_for_a_dimension_with_no_budget_is_reported_not_refused() -> None:
    """Ungoverned is not the same as permitted, and must not read as permitted.

    Inventing a limit for an unbudgeted dimension is a policy decision this
    module must not make; silently admitting the run would make an unmetered
    run look like a governed one, which is the confusion plan 23 removes.
    """
    decision = admission_check(
        budgets=[_budget(ResourceDimension.CPU, limit=100.0)],
        estimates=[_estimate(ResourceDimension.NETWORK, expected=1e9)],
        scope=ResourceScope.RUN,
        now=NOW,
        anchor=ANCHOR,
    )

    assert decision.refused is False
    assert decision.rule_id == RULE_BUDGET_NOT_GOVERNED
    assert "network" in decision.reason
    assert decision.estimates_compared == 0
    assert decision.remediation != ""


def test_a_budget_at_an_outer_scope_governs_the_run() -> None:
    """An environment limit bounds a run's consumption; a run limit bounds nothing."""
    decision = admission_check(
        budgets=[_budget(limit=10.0, scope=ResourceScope.ENVIRONMENT, scope_key="prod")],
        estimates=[
            _estimate(
                expected=99.0,
                scope=ResourceScope.ENVIRONMENT,
                scope_key="prod",
            )
        ],
        scope=ResourceScope.RUN,
        now=NOW,
        anchor=ANCHOR,
    )

    assert decision.refused is True


def test_a_budget_below_the_runs_scope_does_not_govern_it() -> None:
    """Containment is asymmetric and a narrower budget cannot bound a wider run."""
    decision = admission_check(
        budgets=[_budget(limit=10.0, scope=ResourceScope.RUN, scope_key="drill-1")],
        estimates=[
            _estimate(expected=99.0, scope=ResourceScope.ENVIRONMENT, scope_key="prod"),
        ],
        scope=ResourceScope.ENVIRONMENT,
        now=NOW,
        anchor=ANCHOR,
    )

    assert decision.refused is False


def test_admit_raises_with_the_whole_decision_attached() -> None:
    enforcer = _enforcer(_budget(ResourceDimension.API_CALLS, limit=10.0))

    with pytest.raises(BudgetAdmissionRefused) as caught:
        enforcer.admit([_estimate(ResourceDimension.API_CALLS, expected=40.0)], now=NOW)

    assert caught.value.decision.refused is True
    assert caught.value.decision.rule_id == RULE_ESTIMATE_EXCEEDED
    assert "api_calls" in str(caught.value)
    assert isinstance(caught.value, InvariantViolationError)


def test_admit_returns_the_decision_when_nothing_breaches() -> None:
    enforcer = _enforcer(_budget(limit=100.0))

    decision = enforcer.admit([_estimate(expected=5.0)], now=NOW)

    assert decision.allowed is True
    assert decision.estimates_compared == 1


# =============================================================================
# 3. Budget enforcement — continuity, during execution
# =============================================================================


def test_observe_pauses_when_a_reading_breaches_the_budget() -> None:
    """The plan's own requirement: pause for review, never silently continue."""
    enforcer = _enforcer(_budget(ResourceDimension.API_CALLS, limit=100.0))

    enforcer.observe(
        _budget(ResourceDimension.API_CALLS, limit=100.0),
        40.0,
        now=NOW,
        seam="api_calls",
    )

    with pytest.raises(PauseForReview) as caught:
        enforcer.observe(
            _budget(ResourceDimension.API_CALLS, limit=100.0),
            140.0,
            now=NOW,
            seam="api_calls",
        )

    pause = caught.value
    assert pause.dimension is ResourceDimension.API_CALLS
    assert pause.seam == "api_calls"
    assert pause.consumption.measured == 140.0
    assert pause.consumption.limit == 100.0
    assert pause.consumption.overage == 40.0


def test_the_pause_names_the_breaching_dimension_and_the_numbers() -> None:
    enforcer = _enforcer(_budget(ResourceDimension.CPU, limit=60.0))

    with pytest.raises(PauseForReview) as caught:
        enforcer.observe(_budget(ResourceDimension.CPU, limit=60.0), 90.0, now=NOW, seam="cpu")

    text = str(caught.value)
    assert "cpu" in text
    assert "90" in text
    assert "60" in text
    assert "30" in text
    assert "core_seconds" in text
    assert caught.value.consumption.rule_id == RULE_LIMIT_EXCEEDED
    assert caught.value.consumption.remediation != ""


def test_a_pause_carries_evidence_shaped_inputs() -> None:
    enforcer = _enforcer(_budget(ResourceDimension.STORAGE, limit=1000.0))

    with pytest.raises(PauseForReview) as caught:
        enforcer.observe(
            _budget(ResourceDimension.STORAGE, limit=1000.0),
            2500.0,
            now=NOW,
            seam="evidence",
        )

    inputs = caught.value.inputs()
    assert inputs["seam"] == "evidence"
    assert inputs["dimension"] == "storage"
    assert inputs["unit"] == "bytes"
    assert inputs["measured"] == 2500.0
    assert inputs["limit"] == 1000.0
    assert inputs["headroom"] == -1500.0


def test_observe_accumulates_so_the_breach_is_caught_on_the_reading_that_caused_it() -> None:
    """Each reading below the limit, then one above it, pauses.

    Readings are *cumulative* — the domain's deliberate choice, since the
    property that makes a series auditable is a plain non-decreasing check. So
    the run crosses the limit when the running total crosses it, not when three
    increments happen to sum past it.
    """
    enforcer = _enforcer(_budget(ResourceDimension.API_CALLS, limit=100.0))
    budget = _budget(ResourceDimension.API_CALLS, limit=100.0)

    for running_total in (40.0, 90.0):
        decision = enforcer.observe(budget, running_total, now=NOW, seam="api_calls")
        assert decision.paused is False
        assert decision.consumption is not None
        assert decision.consumption.measured == running_total

    with pytest.raises(PauseForReview) as caught:
        enforcer.observe(budget, 101.0, now=NOW, seam="api_calls")

    assert caught.value.consumption.measured == 101.0


def test_a_reading_exactly_at_the_limit_is_spent_not_over() -> None:
    enforcer = _enforcer(_budget(limit=100.0))

    decision = enforcer.observe(_budget(limit=100.0), 100.0, now=NOW, seam="cpu")

    assert decision.paused is False
    assert decision.exhausted is True
    assert decision.continue_running is True
    assert "exactly spent" in decision.reason


def test_a_pause_is_sticky_because_a_resume_is_a_decision() -> None:
    """Once paused, the enforcer stays paused until someone says otherwise."""
    enforcer = _enforcer(_budget(limit=10.0))

    with pytest.raises(PauseForReview):
        enforcer.observe(_budget(limit=10.0), 11.0, now=NOW, seam="cpu")

    assert enforcer.paused is True
    assert enforcer.paused_for == "cpu"


def test_a_run_that_never_breaches_is_never_paused() -> None:
    enforcer = _enforcer(_budget(limit=100.0))
    budget = _budget(limit=100.0)

    for reading in (0.0, 50.0, 100.0):
        enforcer.observe(budget, reading, now=NOW, seam="cpu")

    assert enforcer.paused is False
    assert enforcer.paused_for == ""


def test_continuity_judges_the_window_containing_now_and_carries_forward() -> None:
    """The window rule is the domain's; this does not reimplement it.

    ``series.measured_at`` carries the last reading forward, so a re-check inside
    the same window and a re-check in the *next* window both see 11.0. That is
    the domain's stated behavior — the meter last said this much and nothing
    observed since contradicts it — and this suite pins it rather than quietly
    relying on it.
    """
    budget = _budget(limit=10.0, window_s=HOUR)
    series = ResourceSeries.for_budget(budget).post(
        ConsumptionSample(dimension=budget.dimension, measured=11.0, at=NOW)
    )

    inside = continuity_check(budget=budget, series=series, now=NOW, anchor=ANCHOR)
    same_window = continuity_check(
        budget=budget, series=series, now=NOW + timedelta(minutes=30), anchor=ANCHOR
    )
    next_window = continuity_check(
        budget=budget, series=series, now=NOW + timedelta(hours=1), anchor=ANCHOR
    )

    assert inside.paused is True
    assert inside.consumption is not None
    assert inside.consumption.window is not None
    assert inside.consumption.window.start == NOW
    assert same_window.paused is True
    assert next_window.paused is True
    assert next_window.consumption is not None
    assert next_window.consumption.measured == 11.0


def test_a_continuity_decision_serializes_its_numbers_for_evidence() -> None:
    enforcer = _enforcer(_budget(limit=10.0))

    decision = enforcer.observe(_budget(limit=10.0), 4.0, now=NOW, seam="cpu")
    inputs = decision.inputs()

    assert inputs["paused"] is False
    assert inputs["measured"] == 4.0
    assert inputs["limit"] == 10.0
    assert inputs["headroom"] == 6.0


def test_estimate_versus_actual_is_comparable_after_a_run() -> None:
    """The continuous re-check also produces the report Phase 3 renders."""
    enforcer = _enforcer(_budget(limit=100.0))
    budget = _budget(limit=100.0)
    enforcer.observe(budget, 30.0, now=NOW, seam="cpu")

    comparison = enforcer.comparison(budget, _estimate(expected=20.0), now=NOW)

    assert comparison.actual == 30.0
    assert comparison.estimate == 20.0
    assert comparison.delta == 10.0
    assert comparison.over_estimate is True
    assert comparison.within_limit is True


def test_two_equal_budgets_share_one_ledger() -> None:
    """Duplicate limits must not meter into two series and each miss the other."""
    enforcer = _enforcer(_budget(limit=100.0), _budget(limit=100.0))
    first, second = enforcer.budgets

    enforcer.observe(first, 60.0, now=NOW, seam="cpu")
    decision = enforcer.observe(second, 70.0, now=NOW, seam="cpu")

    assert decision.consumption is not None
    assert decision.consumption.measured == 70.0


# =============================================================================
# 4. Publishing discipline
# =============================================================================


def test_a_benchmark_publishes_with_its_methodology_and_outputs() -> None:
    published = publish_benchmark(_spec(), _measurements("p50_ms", "p99_ms"), now=NOW)

    assert published.methodology != ""
    assert published.measurement_names == ("p50_ms", "p99_ms")
    assert published.spec_digest == _spec().compute_digest()
    assert published.published_at == NOW


def test_a_spec_whose_outputs_never_arrived_cannot_be_published() -> None:
    """Phase 1's gate, still holding through this module's wrapper."""
    with pytest.raises(InvariantViolationError) as caught:
        publish_benchmark(_spec(), _measurements("p50_ms"), now=NOW)

    assert caught.value.rule == "benchmark.output_missing"


def test_a_spec_declaring_no_outputs_cannot_be_published() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        publish_benchmark(
            _spec(measured_outputs=(), methodology="measured at the seam"),
            _measurements(),
            now=NOW,
        )

    assert caught.value.rule == RULE_MEASURED_OUTPUTS_REQUIRED


def test_publication_requires_the_time_as_an_argument() -> None:
    """A clock the caller did not pass is the ambient behaviour this avoids."""
    assert "now" in inspect.signature(publish_benchmark).parameters
    assert inspect.signature(publish_benchmark).parameters["now"].kind.name == "KEYWORD_ONLY"


def test_a_measured_scale_claim_renders_through_the_one_door() -> None:
    spec = _spec()
    published = publish_benchmark(spec, _measurements("p50_ms", "p99_ms"), now=NOW)
    claim = ScaleClaim(scale=TargetScale(targets=100), benchmark=published)

    view = render_scale_claim(claim)

    assert view.spec_id == spec.spec_id
    assert len(view.lines) == 2


# =============================================================================
# 5. Negative controls
# =============================================================================


def test_a_negative_budget_limit_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        _budget(limit=-5.0)

    assert caught.value.rule == NEGATIVE_CONTROL_RULES["negative_limit"] == RULE_NEGATIVE_LIMIT


def test_a_non_monotonic_consumption_series_is_refused() -> None:
    """A meter that went backwards is a bug whose only safe response is to stop.

    This is deliberately *not* covered by the "a metering failure never breaks a
    run" discipline: swallowing it would let a buggy meter report a run as within
    budget forever.
    """
    enforcer = _enforcer(_budget(limit=100.0))
    budget = _budget(limit=100.0)
    enforcer.post(budget, 50.0, now=NOW)

    with pytest.raises(InvariantViolationError) as caught:
        enforcer.post(budget, 10.0, now=NOW)

    assert caught.value.rule == NEGATIVE_CONTROL_RULES["non_monotonic_series"]
    assert caught.value.rule == RULE_NON_MONOTONIC_CONSUMPTION


def test_a_benchmark_with_no_methodology_is_refused_at_publish() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        publish_benchmark(
            _spec(methodology="   "),
            _measurements("p50_ms", "p99_ms"),
            now=NOW,
        )

    assert caught.value.rule == NEGATIVE_CONTROL_RULES["no_methodology"]
    assert caught.value.rule == RULE_METHODOLOGY_REQUIRED


def test_an_unmeasured_scale_claim_cannot_render() -> None:
    """Authorable unmeasured; not renderable. The property plan 23 Phase 5 names."""
    claim = ScaleClaim(scale=TargetScale(targets=10_000))

    assert claim.measured is False
    assert claim.describe().endswith("unmeasured")

    with pytest.raises(InvariantViolationError) as caught:
        render_scale_claim(claim)

    assert caught.value.rule == NEGATIVE_CONTROL_RULES["unmeasured_render"]
    assert caught.value.rule == RULE_SCALE_UNMEASURED


def test_a_metering_failure_does_not_break_the_run() -> None:
    """A broken sink loses one reading. The instrumented code never notices."""
    sink = FakeSink(fail=True)
    meter = build_run_meter(run_id="drill-1", clock=FakeClock(), sink=sink)

    with meter.time_agent_command("sleep", now=NOW):
        pass  # the run's real work: unaffected
    meter.add_evidence_bytes(256, now=NOW)
    with meter.time_plan_compilation(now=NOW):
        pass

    assert len(meter.failures) == 3
    assert [seam for seam, _ in meter.failures] == [
        "agent_command:sleep",
        "evidence",
        "plan_compilation",
    ]
    assert all("ConnectionError" in detail for _, detail in meter.failures)
    # The work still ran, and the meter still knows what happened.
    assert meter.agent_command_latency("sleep") == (1.5,)
    assert meter.total_evidence_bytes == 256.0
    assert len(meter.readings) == 3


def test_a_sink_failure_inside_a_timing_seam_does_not_mask_the_blocks_own_error() -> None:
    """The meter is transparent in both directions: it neither raises nor hides."""
    sink = FakeSink(fail=True)
    meter = build_run_meter(run_id="drill-1", clock=FakeClock(), sink=sink)

    with pytest.raises(ValueError, match="boom"), meter.time_policy_evaluation(now=NOW):
        msg = "boom"
        raise ValueError(msg)

    assert meter.failures == [("policy_evaluation", "ConnectionError: exporter connection refused")]


def test_every_negative_control_names_a_stable_rule_id() -> None:
    """The table is the claim; assert it so a rename cannot pass unnoticed."""
    assert NEGATIVE_CONTROL_RULES == {
        "negative_limit": "budget.negative_limit",
        "non_monotonic_series": "budget.consumption_not_monotonic",
        "no_methodology": RULE_METHODOLOGY_REQUIRED,
        "unmeasured_render": "scale.unmeasured_claim",
        "sink_failure": RULE_METER_SINK_FAILED,
    }
    assert len(set(NEGATIVE_CONTROL_RULES.values())) == len(NEGATIVE_CONTROL_RULES)


# =============================================================================
# 6. Meter contract, and the absence of an ambient clock
# =============================================================================


def test_a_meter_reading_refuses_an_empty_seam_or_unit() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        MeterReading(seam="  ", kind="delta", value=1.0, unit="seconds")
    assert caught.value.rule == RULE_METER_CONTRACT

    with pytest.raises(InvariantViolationError) as caught:
        MeterReading(seam="cpu", kind="delta", value=1.0, unit=" ")
    assert caught.value.rule == RULE_METER_CONTRACT


def test_a_meter_reading_refuses_a_naive_timestamp() -> None:
    naive = datetime(2026, 1, 1)  # noqa: DTZ001 — the naive value is the subject

    with pytest.raises(InvariantViolationError) as caught:
        MeterReading(seam="cpu", kind="delta", value=1.0, unit="seconds", at=naive)

    assert caught.value.rule == RULE_METER_CONTRACT


def test_a_negative_or_non_finite_byte_count_is_refused_at_the_seam() -> None:
    meter = RunMeter(run_id="drill-1")

    for bad in (-1.0, math.inf, math.nan):
        with pytest.raises(InvariantViolationError) as caught:
            meter.add_evidence_bytes(bad, now=NOW)
        assert caught.value.rule == RULE_METER_CONTRACT

        with pytest.raises(InvariantViolationError):
            meter.add_store_growth_bytes(bad, now=NOW)


def test_a_fractional_or_negative_api_call_count_is_refused() -> None:
    """The counted dimension is indivisible, so the meter will not round one."""
    meter = RunMeter(run_id="drill-1")

    for bad in (-1, 1.5, True):  # type: ignore[list-item]
        with pytest.raises(InvariantViolationError) as caught:
            meter.count_api_calls(bad)  # type: ignore[arg-type]
        assert caught.value.rule == RULE_METER_CONTRACT


def test_strict_reading_raises_where_the_seam_only_records() -> None:
    """The opt-in strict accessor, for a call site about to publish a number."""
    good = MeterReading(seam="evidence", kind="cumulative", value=10.0, unit="bytes")
    assert strict_reading(good, expect_kind="cumulative") is good

    with pytest.raises(MeterContractError) as caught:
        strict_reading(good, expect_kind="delta")
    assert caught.value.rule == RULE_METER_CONTRACT

    with pytest.raises(MeterContractError):
        strict_reading(MeterReading(seam="cpu", kind="delta", value=-1.0, unit="seconds"))
    with pytest.raises(MeterContractError):
        strict_reading(MeterReading(seam="cpu", kind="delta", value=math.nan, unit="seconds"))


def test_an_enforcer_refuses_a_naive_anchor() -> None:
    naive = datetime(2026, 1, 1)  # noqa: DTZ001 — the naive value is the subject

    with pytest.raises(InvariantViolationError) as caught:
        ResourceBudgetEnforcer(
            budgets=[_budget()],
            scope=ResourceScope.RUN,
            anchor=naive,
        )

    assert caught.value.rule == RULE_METER_CONTRACT


def test_no_decision_path_reads_an_ambient_clock() -> None:
    """A replayed budget decision must not depend on when it was replayed.

    ``now_utc`` exists and *is* a clock read — that is the point: naming it means
    grep finds it, and this test asserts no decision function calls it.
    """
    for decision_fn in (admission_check, continuity_check):
        assert "now_utc" not in inspect.getsource(decision_fn)
        assert "now" in inspect.signature(decision_fn).parameters
        assert "now" in inspect.signature(ResourceBudgetEnforcer.observe).parameters

    assert "now_utc" in inspect.getsource(metering)


def test_every_documented_integration_point_exists() -> None:
    """The Phase 3/4 wiring is named in prose; assert the methods are really there.

    A docstring describing a method that does not exist is worse than no
    docstring, because the next lane wires to the prose.
    """
    for method in ("admit", "observe", "post", "series_for", "comparison"):
        assert callable(getattr(ResourceBudgetEnforcer, method)), method


def test_this_module_does_not_reach_into_the_safety_gate() -> None:
    """The two ledgers stay parallel; neither imports the other's enforcer.

    ``safety.py`` is read-only for this lane and untouched. If a future edit
    started importing it here, a resource budget could begin enforcing damage
    refusals and vice versa — so the absence is asserted, not assumed.
    """
    source = inspect.getsource(metering)

    assert "mayhem.controller.safety" not in source
    assert "from mayhem.controller" not in source
    assert "import mayhem.controller" not in source


def test_resource_rule_ids_are_disjoint_from_the_damage_quota_ledger() -> None:
    """Two ledgers, two vocabularies — never one rule id meaning both.

    ``quota.py`` charges damage seconds; ``budgets.py`` charges CPU, bytes, and
    counts. A shared rule id would make an evidence record ambiguous about which
    ledger it came from.
    """
    from mayhem.domain import quota as quota_module

    mine = {
        RULE_ESTIMATE_EXCEEDED,
        RULE_LIMIT_EXCEEDED,
        RULE_METER_CONTRACT,
        RULE_METER_SINK_FAILED,
        RULE_ESTIMATE_UNMEASURED,
        RULE_BUDGET_NOT_GOVERNED,
        RULE_METHODOLOGY_REQUIRED,
    }
    theirs = {quota_module.RULE_BUDGET, quota_module.RULE_PER_FAULT_CEILING}

    assert mine.isdisjoint(theirs)
