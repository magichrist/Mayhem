"""Resource budgets, estimate-vs-actual comparison, and benchmark descriptors.

Plan 23 Phase 1. The tests fall into five groups:

1. **Budget arithmetic per dimension** — headroom, utilisation, overage, and the
   counted-vs-measured split (a limit of 10.5 API calls is a unit error, not a
   tighter budget).
2. **Window boundaries** — windows are half-open, so a reading taken exactly on
   a boundary is charged to exactly one window. A closed interval would
   double-charge or drop it, and a budget that is silently wrong by a whole
   window is worse than no budget.
3. **Estimate versus actual** — the two stay comparable records with a delta,
   and neither can be silently compared to the other.
4. **Benchmark-spec determinism** — the same spec always produces the same
   workload and the same digest, so a published number can name the spec that
   produced it and a replay can reproduce the run.
5. **Negative controls** — a negative limit, a non-monotonic consumption series,
   a spec that declares no measured outputs, and an unmeasured scale claim are
   all *unrepresentable* rather than merely warned about.

Also pinned here: **no clock in any evaluation path.** Every time-dependent
function takes ``now``/``anchor`` as an argument, and the module source is
scanned to keep it that way — a stray ``datetime.now()`` inside a budget
comparison would make a replayed decision disagree with the original for
reasons no test could otherwise see.
"""

from __future__ import annotations

import ast
import inspect
from datetime import UTC, datetime, timedelta

import pytest

from mayhem.domain import budgets as budgets_module
from mayhem.domain.budgets import (
    DECLARED_SCALE_TARGETS,
    RULE_ESTIMATE_EXCEEDED,
    RULE_FRACTIONAL_COUNT,
    RULE_LIMIT_EXCEEDED,
    RULE_MEASURED_OUTPUTS_REQUIRED,
    RULE_NEGATIVE_LIMIT,
    RULE_NON_MONOTONIC_CONSUMPTION,
    RULE_OUTPUT_MISSING,
    RULE_OUTPUT_UNDECLARED,
    RULE_SCALE_UNMEASURED,
    RULE_SUBJECT_MISMATCH,
    RULE_UNSUPPORTED_SCALE,
    BenchmarkMetric,
    BenchmarkSpec,
    BudgetConsumption,
    BudgetWindow,
    ConsumptionSample,
    Measurement,
    PublishedBenchmark,
    ResourceBudget,
    ResourceDimension,
    ResourceEstimate,
    ResourceScope,
    ResourceSeries,
    ScaleClaim,
    ScaleClaimView,
    TargetScale,
    WorkloadShape,
    budget_window_for,
    compare_estimate,
    is_counted_dimension,
    scope_contains,
    unit_for,
)
from mayhem.domain.errors import InvariantViolationError

ANCHOR = datetime(2026, 1, 1, tzinfo=UTC)
"""Window grid origin. Fixed, so every window in these tests is exact."""

HOUR = 3600.0


def _budget(
    dimension: ResourceDimension = ResourceDimension.CPU,
    *,
    limit: float = 100.0,
    window_s: float = HOUR,
    scope: ResourceScope = ResourceScope.ENVIRONMENT,
    scope_key: str = "prod",
) -> ResourceBudget:
    return ResourceBudget(
        dimension=dimension,
        scope=scope,
        scope_key=scope_key,
        limit=limit,
        window_s=window_s,
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


# =============================================================================
# 1. Budget arithmetic, per dimension
# =============================================================================


@pytest.mark.parametrize("dimension", list(ResourceDimension))
def test_every_dimension_names_a_unit(dimension: ResourceDimension) -> None:
    assert unit_for(dimension)


@pytest.mark.parametrize("dimension", list(ResourceDimension))
def test_units_are_distinct_per_dimension(dimension: ResourceDimension) -> None:
    units = {unit_for(other) for other in ResourceDimension}
    assert len(units) == len(ResourceDimension)


@pytest.mark.parametrize(
    ("dimension", "unit"),
    [
        (ResourceDimension.CPU, "core_seconds"),
        (ResourceDimension.MEMORY, "mebibyte_seconds"),
        (ResourceDimension.NETWORK, "egress_bytes"),
        (ResourceDimension.STORAGE, "bytes"),
        (ResourceDimension.CLOUD_SPEND, "currency_micros"),
        (ResourceDimension.API_CALLS, "calls"),
        (ResourceDimension.TARGET_COUNT, "targets"),
        (ResourceDimension.CONCURRENT_EXPERIMENTS, "runs"),
    ],
)
def test_measurement_arithmetic_is_per_dimension(dimension: ResourceDimension, unit: str) -> None:
    """The same arithmetic runs for every dimension, in that dimension's unit."""
    counted = is_counted_dimension(dimension)
    budget = _budget(dimension, limit=200.0)
    measured = 50.0 if counted else 50.25

    consumption = budget.measure(measured)

    assert consumption.unit == unit
    assert consumption.measured == measured
    assert consumption.headroom == pytest.approx(150.0 if counted else 149.75)
    assert consumption.utilisation == pytest.approx(measured / 200.0)
    assert consumption.within_budget
    assert not consumption.exceeded
    assert consumption.rule_id == ""


def test_headroom_and_utilisation_agree_with_the_numbers() -> None:
    budget = _budget(limit=400.0)
    consumption = budget.measure(150.0)

    assert consumption.headroom == 250.0
    assert consumption.utilisation == 0.375
    assert consumption.overage == 0.0


def test_exact_limit_is_spent_not_exceeded() -> None:
    """A budget may be used up; ``>`` would refuse a run that stayed in budget."""
    consumption = _budget(limit=100.0).measure(100.0)

    assert consumption.exhausted
    assert not consumption.exceeded
    assert consumption.headroom == 0.0


def test_overage_and_refusal_name_the_breaching_dimension() -> None:
    consumption = _budget(ResourceDimension.CLOUD_SPEND, limit=100.0).measure(
        125.0, BudgetWindow(start=ANCHOR, end=ANCHOR + timedelta(hours=1))
    )

    assert consumption.exceeded
    assert consumption.overage == 25.0
    assert consumption.headroom == -25.0
    assert consumption.rule_id == RULE_LIMIT_EXCEEDED
    assert "cloud_spend" in consumption.reason
    assert "currency_micros" in consumption.reason
    assert "environment/prod" in consumption.reason
    assert "cloud_spend" in consumption.remediation


def test_consumption_inputs_are_evidence_shaped() -> None:
    window = BudgetWindow(start=ANCHOR, end=ANCHOR + timedelta(hours=1))
    inputs = _budget().measure(10.0, window).inputs()

    assert inputs["dimension"] == "cpu"
    assert inputs["unit"] == "core_seconds"
    assert inputs["window_start"] == ANCHOR.isoformat()
    assert inputs["window_end"] == window.end.isoformat()
    assert inputs["headroom"] == 90.0


def test_utilisation_is_zero_against_an_unbounded_limit() -> None:
    """Defensive: a limit built directly (not via ``ResourceBudget``) may be inf."""
    consumption = BudgetConsumption(
        dimension=ResourceDimension.CPU,
        scope=ResourceScope.RUN,
        scope_key="r-1",
        measured=42.0,
        limit=float("inf"),
    )

    assert consumption.utilisation == 0.0
    assert consumption.within_budget


@pytest.mark.parametrize("limit", [10.0, 1.0, 1000.0])
def test_counted_dimensions_accept_whole_limits(limit: float) -> None:
    assert _budget(ResourceDimension.API_CALLS, limit=limit).limit == limit


@pytest.mark.parametrize(
    ("outer", "inner"),
    [
        (ResourceScope.ORGANISATION, ResourceScope.ENVIRONMENT),
        (ResourceScope.ENVIRONMENT, ResourceScope.EXPERIMENT),
        (ResourceScope.ENVIRONMENT, ResourceScope.RUN),
        (ResourceScope.EXPERIMENT, ResourceScope.RUN),
        (ResourceScope.RUN, ResourceScope.RUN),
        (ResourceScope.RUN, ResourceScope.ENVIRONMENT),
        (ResourceScope.EXPERIMENT, ResourceScope.ORGANISATION),
    ],
)
def test_scope_containment_is_asymmetric(outer: ResourceScope, inner: ResourceScope) -> None:
    """A narrower scope never governs a wider one; only the reverse holds."""
    if outer is inner:
        assert scope_contains(outer, inner)
    else:
        assert not (scope_contains(outer, inner) and scope_contains(inner, outer))


# =============================================================================
# 2. Window boundaries
# =============================================================================


def test_window_is_half_open_at_both_ends() -> None:
    window = BudgetWindow(start=ANCHOR, end=ANCHOR + timedelta(hours=1))

    assert window.contains(ANCHOR)
    assert window.contains(ANCHOR + timedelta(minutes=59, seconds=59))
    assert not window.contains(ANCHOR + timedelta(hours=1))
    assert window.contains(ANCHOR) and not window.contains(window.end)


def test_window_for_floors_onto_the_grid() -> None:
    just_after = budget_window_for(at=ANCHOR + timedelta(seconds=1), window_s=HOUR, anchor=ANCHOR)

    assert just_after.start == ANCHOR
    assert just_after.end == ANCHOR + timedelta(hours=1)
    assert just_after.seconds == HOUR


def test_window_for_before_the_anchor_lands_in_the_previous_window() -> None:
    """Floor, not truncation: one second before the anchor is the window before."""
    window = budget_window_for(at=ANCHOR - timedelta(seconds=1), window_s=HOUR, anchor=ANCHOR)

    assert window.end == ANCHOR
    assert not window.contains(ANCHOR)


def test_budget_window_grid_matches_the_budget_length() -> None:
    budget = _budget(window_s=900.0)
    at = ANCHOR + timedelta(seconds=1200)

    window = budget.window_for(at, anchor=ANCHOR)

    assert window.seconds == 900.0
    assert window.start == ANCHOR + timedelta(minutes=15)
    assert window.contains(at)


def test_window_ending_at_is_the_run_relative_window() -> None:
    budget = _budget(window_s=1800.0)
    now = ANCHOR + timedelta(hours=5)

    window = budget.window_ending_at(now)

    assert window.start == now - timedelta(minutes=30)
    assert window.end == now
    assert window.contains(now - timedelta(seconds=1))
    assert not window.contains(now)


def test_sample_exactly_on_a_boundary_is_charged_to_one_window_only() -> None:
    """The negative space between the windows is what makes this hold."""
    budget = _budget(limit=100.0, window_s=HOUR)
    series = ResourceSeries.for_budget(budget).post(
        ConsumptionSample(
            dimension=ResourceDimension.CPU,
            measured=40.0,
            at=ANCHOR + timedelta(hours=1),
        )
    )
    boundary = ANCHOR + timedelta(hours=1)

    earlier = budget.window_for(boundary - timedelta(seconds=1), anchor=ANCHOR)
    later = budget.window_for(boundary, anchor=ANCHOR)

    assert series.samples_in(earlier) == ()
    assert len(series.samples_in(later)) == 1
    assert earlier.seconds == later.seconds == HOUR


def test_consumption_carries_forward_and_excludes_the_boundary_sample() -> None:
    budget = _budget(limit=100.0, window_s=HOUR)
    boundary = ANCHOR + timedelta(hours=1)
    series = ResourceSeries.for_budget(budget).posted(
        [
            ConsumptionSample(dimension=ResourceDimension.CPU, measured=30.0, at=ANCHOR),
            ConsumptionSample(dimension=ResourceDimension.CPU, measured=70.0, at=boundary),
        ]
    )

    closed = budget.window_ending_at(boundary)

    # The reading at the close belongs to the next window; the window below it
    # is charged the last reading observed before the close, not zero.
    assert series.measured_at(closed) == 30.0
    assert series.consumption(closed).measured == 30.0
    assert series.consumption(budget.window_for(boundary, anchor=ANCHOR)).measured == 70.0


def test_empty_series_reports_zero_consumption() -> None:
    budget = _budget()
    series = ResourceSeries.for_budget(budget)

    assert series.length == 0
    assert series.latest is None
    assert series.cumulative == 0.0
    assert series.consumption(budget.window_ending_at(ANCHOR)).measured == 0.0


def test_posting_is_pure() -> None:
    """A candidate reading can be probed without spending it."""
    budget = _budget()
    series = ResourceSeries.for_budget(budget)
    sample = ConsumptionSample(dimension=ResourceDimension.CPU, measured=5.0, at=ANCHOR)

    extended = series.post(sample)

    assert series.length == 0
    assert extended.length == 1
    assert series is not extended


# =============================================================================
# 3. Pre-execution estimate versus continuous actual
# =============================================================================


def test_actual_under_the_estimate_is_not_a_refusal() -> None:
    budget = _budget(limit=100.0)
    estimate = ResourceEstimate(
        dimension=ResourceDimension.CPU,
        scope=ResourceScope.ENVIRONMENT,
        scope_key="prod",
        expected=80.0,
        basis="10 targets x 2 iterations x measured core-seconds per plan",
    )

    comparison = compare_estimate(budget, estimate, budget.measure(20.0))

    assert comparison.delta == -60.0
    assert comparison.ratio == 0.25
    assert not comparison.over_estimate
    assert comparison.rule_id == ""
    assert comparison.reason == ""
    assert comparison.within_limit
    assert comparison.basis == estimate.basis


def test_actual_over_the_estimate_is_reported_with_its_ratio() -> None:
    budget = _budget(limit=100.0)
    estimate = ResourceEstimate(
        dimension=ResourceDimension.CPU,
        scope=ResourceScope.ENVIRONMENT,
        scope_key="prod",
        expected=50.0,
        basis="prior release measurement at 10 targets",
    )

    comparison = compare_estimate(budget, estimate, budget.measure(75.0))

    assert comparison.delta == 25.0
    assert comparison.ratio == 1.5
    assert comparison.over_estimate
    assert comparison.rule_id == RULE_ESTIMATE_EXCEEDED
    assert "cpu" in comparison.reason
    assert "core_seconds" in comparison.reason
    # Over the estimate but still inside the limit: the comparison reports the
    # overrun without inventing a refusal the budget did not earn.
    assert comparison.within_limit
    assert "exceeds the budget limit" not in comparison.reason


def test_comparison_says_so_when_the_actual_also_broke_the_limit() -> None:
    budget = _budget(limit=100.0)
    estimate = ResourceEstimate(
        dimension=ResourceDimension.CPU,
        scope=ResourceScope.ENVIRONMENT,
        scope_key="prod",
        expected=50.0,
        basis="shape-derived",
    )

    comparison = compare_estimate(budget, estimate, budget.measure(160.0))

    assert not comparison.within_limit
    assert comparison.headroom == -60.0
    assert "exceeds the budget limit 100" in comparison.reason


def test_zero_estimate_yields_no_ratio_rather_than_a_division_error() -> None:
    budget = _budget()
    estimate = ResourceEstimate(
        dimension=ResourceDimension.CPU,
        scope=ResourceScope.ENVIRONMENT,
        scope_key="prod",
        expected=0.0,
        basis="a no-op plan that should cost nothing",
    )

    comparison = compare_estimate(budget, estimate, budget.measure(5.0))

    assert comparison.ratio is None
    assert comparison.over_estimate
    assert "x the estimate" not in comparison.reason


def test_comparison_is_pure_and_repeatable() -> None:
    budget = _budget()
    estimate = ResourceEstimate(
        dimension=ResourceDimension.CPU,
        scope=ResourceScope.ENVIRONMENT,
        scope_key="prod",
        expected=10.0,
        basis="shape-derived",
    )
    window = budget.window_ending_at(ANCHOR)

    first = compare_estimate(budget, estimate, budget.measure(12.0, window))
    second = compare_estimate(budget, estimate, budget.measure(12.0, window))

    assert first == second
    assert first.inputs()["window_start"] == window.start.isoformat()


# =============================================================================
# 4. Benchmark-spec determinism
# =============================================================================


def test_workload_repeats_exactly_from_the_spec() -> None:
    spec = _spec()

    first = spec.workload()
    second = spec.workload()

    assert first == second
    assert len(first) == spec.shape.targets * spec.shape.iterations
    assert len({item.item_id for item in first}) == len(first)
    assert [item.index for item in first] == list(range(len(first)))


def test_workload_is_target_major_so_a_prefix_covers_targets_uniformly() -> None:
    """A soak that has to stop early must not have measured one target only."""
    spec = _spec(shape=WorkloadShape(iterations=2, targets=4, concurrency=2))

    assert [item.target_index for item in spec.workload()] == [0, 0, 1, 1, 2, 2, 3, 3]
    assert [item.worker for item in spec.workload()][:2] == [0, 0]
    assert [item.worker for item in spec.workload()][2:4] == [1, 1]


def test_identical_specs_hash_identically() -> None:
    assert _spec().compute_digest() == _spec().compute_digest()


@pytest.mark.parametrize(
    "overrides",
    [
        {"shape": WorkloadShape(iterations=3, targets=10, concurrency=5)},
        {"scale": TargetScale(targets=1000)},
        {"metric": BenchmarkMetric.EVIDENCE_THROUGHPUT},
        {"measured_outputs": ("p50_ms", "p99_ms", "p999_ms")},
        {"methodology": "a different methodology"},
        {"scale": TargetScale(targets=100, concurrent_runs=10)},
    ],
)
def test_any_change_to_the_spec_changes_its_digest(overrides: dict[str, object]) -> None:
    baseline = _spec().compute_digest()

    changed = _spec(**overrides)

    assert changed.compute_digest() != baseline


def test_pin_pins_content_and_a_drifted_pin_is_refused() -> None:
    pinned = _spec().pin()

    assert pinned.is_pinned()
    assert pinned.spec_digest == pinned.compute_digest()
    assert pinned.verify_pin()

    with pytest.raises(InvariantViolationError):
        _spec(spec_digest="0" * 64)


def test_publish_binds_the_spec_digest_and_orders_the_measurements() -> None:
    spec = _spec()
    readings = [
        Measurement(name="p99_ms", value=40.0, unit="ms", samples=20),
        Measurement(name="p50_ms", value=12.0, unit="ms", samples=20),
    ]

    published = spec.publish(readings, now=ANCHOR)

    assert isinstance(published, PublishedBenchmark)
    assert published.spec_digest == spec.compute_digest()
    assert published.measurement_names == ("p50_ms", "p99_ms")
    assert published.published_at == ANCHOR
    assert published.measurement("p50_ms") == readings[1]
    assert published.measurement("p999_ms") is None
    assert published.report_digest() == spec.publish(readings, now=ANCHOR).report_digest()


def test_publish_requires_the_publication_time_as_an_argument() -> None:
    """A default ``utc_now()`` here would be the ambient clock this module forbids."""
    spec = _spec()

    with pytest.raises(TypeError):
        spec.publish(  # type: ignore[call-arg]
            [Measurement(name="p50_ms", value=1.0, unit="ms")]
        )


# =============================================================================
# 5. Negative controls
# =============================================================================


@pytest.mark.parametrize("limit", [-1.0, -0.5, 0.0])
def test_a_negative_or_empty_budget_is_refused(limit: float) -> None:
    with pytest.raises(InvariantViolationError) as caught:
        _budget(limit=limit)

    assert caught.value.rule == RULE_NEGATIVE_LIMIT


def test_a_fractional_limit_on_a_counted_dimension_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        _budget(ResourceDimension.API_CALLS, limit=10.5)

    assert caught.value.rule == RULE_FRACTIONAL_COUNT


def test_a_non_positive_window_is_refused() -> None:
    with pytest.raises(InvariantViolationError):
        _budget(window_s=0.0)


def test_a_non_finite_measurement_is_refused() -> None:
    with pytest.raises(InvariantViolationError):
        _budget().measure(float("inf"))

    with pytest.raises(InvariantViolationError):
        _budget().measure(float("nan"))


def test_a_non_monotonic_consumption_series_is_refused() -> None:
    """A cumulative meter that goes down was reset, spliced, or double-posted."""
    budget = _budget()
    series = ResourceSeries.for_budget(budget).post(
        ConsumptionSample(dimension=ResourceDimension.CPU, measured=60.0, at=ANCHOR)
    )

    with pytest.raises(InvariantViolationError) as caught:
        series.post(
            ConsumptionSample(
                dimension=ResourceDimension.CPU,
                measured=59.0,
                at=ANCHOR + timedelta(minutes=1),
            )
        )

    assert caught.value.rule == RULE_NON_MONOTONIC_CONSUMPTION
    assert series.cumulative == 60.0


def test_a_flat_series_is_allowed_because_a_meter_may_not_move() -> None:
    budget = _budget()
    series = ResourceSeries.for_budget(budget).posted(
        [
            ConsumptionSample(dimension=ResourceDimension.CPU, measured=60.0, at=ANCHOR),
            ConsumptionSample(dimension=ResourceDimension.CPU, measured=60.0, at=ANCHOR),
        ]
    )

    assert series.cumulative == 60.0
    assert series.length == 2


def test_a_reading_for_another_dimension_cannot_be_posted() -> None:
    series = ResourceSeries.for_budget(_budget(ResourceDimension.CPU))

    with pytest.raises(InvariantViolationError) as caught:
        series.post(ConsumptionSample(dimension=ResourceDimension.MEMORY, measured=1.0, at=ANCHOR))

    assert caught.value.rule == RULE_SUBJECT_MISMATCH


def test_an_estimate_without_a_basis_is_refused() -> None:
    with pytest.raises(InvariantViolationError):
        ResourceEstimate(
            dimension=ResourceDimension.CPU,
            scope=ResourceScope.ENVIRONMENT,
            scope_key="prod",
            expected=10.0,
            basis="   ",
        )


def test_an_estimate_cannot_be_compared_across_subjects() -> None:
    budget = _budget(scope_key="prod")
    foreign = ResourceEstimate(
        dimension=ResourceDimension.CPU,
        scope=ResourceScope.ENVIRONMENT,
        scope_key="staging",
        expected=10.0,
        basis="a different environment's prior run",
    )

    with pytest.raises(InvariantViolationError) as caught:
        compare_estimate(budget, foreign, budget.measure(10.0))

    assert caught.value.rule == RULE_SUBJECT_MISMATCH


def test_an_actual_measured_against_another_limit_is_refused() -> None:
    budget = _budget(limit=100.0)
    other = _budget(limit=250.0)
    estimate = ResourceEstimate(
        dimension=ResourceDimension.CPU,
        scope=ResourceScope.ENVIRONMENT,
        scope_key="prod",
        expected=10.0,
        basis="shape-derived",
    )

    with pytest.raises(InvariantViolationError) as caught:
        compare_estimate(budget, estimate, other.measure(10.0))

    assert caught.value.rule == RULE_SUBJECT_MISMATCH


def test_a_spec_declaring_no_measured_outputs_cannot_be_published() -> None:
    spec = _spec(measured_outputs=())

    with pytest.raises(InvariantViolationError) as caught:
        spec.publish([Measurement(name="p50_ms", value=1.0, unit="ms")], now=ANCHOR)

    assert caught.value.rule == RULE_MEASURED_OUTPUTS_REQUIRED


def test_a_run_that_reported_nothing_cannot_be_published() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        _spec().publish([], now=ANCHOR)

    assert caught.value.rule == RULE_MEASURED_OUTPUTS_REQUIRED


def test_a_promised_output_the_run_never_reported_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        _spec().publish([Measurement(name="p50_ms", value=1.0, unit="ms")], now=ANCHOR)

    assert caught.value.rule == RULE_OUTPUT_MISSING
    assert "p99_ms" in str(caught.value)


def test_an_output_the_spec_never_declared_is_refused() -> None:
    readings = [
        Measurement(name="p50_ms", value=1.0, unit="ms"),
        Measurement(name="p99_ms", value=2.0, unit="ms"),
        Measurement(name="p999_ms", value=3.0, unit="ms"),
    ]

    with pytest.raises(InvariantViolationError) as caught:
        _spec().publish(readings, now=ANCHOR)

    assert caught.value.rule == RULE_OUTPUT_UNDECLARED
    assert "p999_ms" in str(caught.value)


def test_a_scale_outside_the_declared_ranges_is_unrepresentable() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        TargetScale(targets=37)

    assert caught.value.rule == RULE_UNSUPPORTED_SCALE
    assert 37 not in DECLARED_SCALE_TARGETS


def test_a_spec_cannot_generate_more_targets_than_it_claims_to_scale_to() -> None:
    with pytest.raises(InvariantViolationError):
        _spec(shape=WorkloadShape(iterations=1, targets=1000), scale=TargetScale(targets=100))


def test_a_workload_cannot_have_more_workers_than_targets() -> None:
    with pytest.raises(InvariantViolationError):
        WorkloadShape(iterations=1, targets=2, concurrency=4)


def test_an_unmeasured_scale_claim_cannot_be_rendered() -> None:
    """Plan 23: each range ships with its measured numbers or stays unclaimed."""
    claim = ScaleClaim(scale=TargetScale(targets=10_000))

    assert not claim.measured
    with pytest.raises(InvariantViolationError) as caught:
        claim.render()

    assert caught.value.rule == RULE_SCALE_UNMEASURED


def test_a_render_view_cannot_be_hand_built_without_measurements() -> None:
    """The structural half: not even the render type accepts an empty claim."""
    with pytest.raises(InvariantViolationError) as caught:
        ScaleClaimView(
            scale=TargetScale(targets=100),
            spec_id="bench.cpu.100",
            spec_digest="0" * 64,
            metric=BenchmarkMetric.PLAN_COMPILATION_LATENCY,
            published_at=ANCHOR,
            lines=(),
        )

    assert caught.value.rule == RULE_SCALE_UNMEASURED


def test_a_measured_scale_claim_renders_with_its_numbers_attached() -> None:
    published = _spec().publish(
        [
            Measurement(name="p50_ms", value=12.0, unit="ms", samples=20),
            Measurement(name="p99_ms", value=40.0, unit="ms", samples=20),
        ],
        now=ANCHOR,
    )

    view = ScaleClaim(scale=published.scale, benchmark=published).render()

    assert [line.name for line in view.lines] == ["p50_ms", "p99_ms"]
    assert view.spec_digest == published.spec_digest
    assert view.published_at == ANCHOR


def test_a_claim_cannot_cite_a_benchmark_measured_at_another_scale() -> None:
    published = _spec().publish(
        [
            Measurement(name="p50_ms", value=12.0, unit="ms"),
            Measurement(name="p99_ms", value=40.0, unit="ms"),
        ],
        now=ANCHOR,
    )

    with pytest.raises(InvariantViolationError):
        ScaleClaim(scale=TargetScale(targets=1000), benchmark=published)


def test_a_published_benchmark_cannot_exist_without_measurements() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        PublishedBenchmark(
            spec_id="bench.cpu.100",
            spec_digest="0" * 64,
            metric=BenchmarkMetric.PLAN_COMPILATION_LATENCY,
            scale=TargetScale(targets=100),
            measurements=(),
            published_at=ANCHOR,
        )

    assert caught.value.rule == RULE_MEASURED_OUTPUTS_REQUIRED


# =============================================================================
# 6. The clock is injected, never read
# =============================================================================


_CLOCK_CALLS = frozenset({"utc_now", "now", "utcnow", "today", "time", "time_ns", "monotonic"})


def _clock_reader(node: ast.expr) -> str | None:
    """The name of the clock function ``node`` calls, or ``None`` if it is not one."""
    if isinstance(node, ast.Name):
        return node.id if node.id in _CLOCK_CALLS else None
    if isinstance(node, ast.Attribute):
        return node.attr if node.attr in _CLOCK_CALLS else None
    return None


def test_no_evaluation_path_reads_the_clock() -> None:
    """A replayed budget decision must not depend on when it was replayed.

    Scans the module's *code*, not its prose: the docstrings say ``utc_now`` on
    purpose, to document the absence. What must not exist is a call to one.
    """
    tree = ast.parse(inspect.getsource(budgets_module))
    readers = [
        _clock_reader(node.func)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _clock_reader(node.func) is not None
    ]

    assert readers == []
    assert not hasattr(budgets_module, "utc_now")


@pytest.mark.parametrize(
    "moment",
    [
        ANCHOR,
        ANCHOR + timedelta(hours=1),
        ANCHOR - timedelta(days=3),
    ],
)
def test_every_time_dependent_result_is_a_function_of_now_alone(
    moment: datetime,
) -> None:
    budget = _budget(limit=100.0)

    assert budget.window_ending_at(moment).end == moment
    assert budget.window_for(moment, anchor=ANCHOR).contains(moment) is (
        budget.window_for(moment, anchor=ANCHOR).seconds == budget.window_s
    )


def test_a_naive_datetime_is_refused_rather_than_assumed_utc() -> None:
    naive = datetime(2026, 1, 1)  # noqa: DTZ001 - the naive value is the test subject

    with pytest.raises(InvariantViolationError):
        BudgetWindow(start=naive, end=ANCHOR)
    with pytest.raises(InvariantViolationError):
        ConsumptionSample(dimension=ResourceDimension.CPU, measured=1.0, at=naive)


# ═══════════════════════════════════════════════════════════════════════════
# The two ledgers keep separate rule ids
# ═══════════════════════════════════════════════════════════════════════════
#
# ``mayhem.domain.policy.BudgetNode`` is the hierarchical *damage* budget
# (team → environment → service → experiment → fault, in accumulated damage
# seconds). ``ResourceBudget`` here is an authored limit on a *resource*
# dimension over a window. ``ResourceScope``'s docstring is explicit that these
# are not the same ledger, so a single rule id covering "this limit is
# negative" in both would make an evidence record ambiguous about which one was
# authored badly. These tests pin the separation, and pin that the two
# thresholds really do differ — a shared id would be defensible only if the
# refusals were the same refusal.


def _resource_budget(limit: float) -> ResourceBudget:
    return ResourceBudget(
        dimension=ResourceDimension.CPU,
        scope=ResourceScope.ORGANISATION,
        scope_key="platform",
        limit=limit,
        window_s=3600.0,
    )


def test_the_two_budget_ledgers_refuse_under_different_rule_ids() -> None:
    from mayhem.domain.policy import BudgetNode, BudgetScope

    with pytest.raises(InvariantViolationError) as resource_excinfo:
        _resource_budget(-1.0)
    with pytest.raises(InvariantViolationError) as damage_excinfo:
        BudgetNode(scope=BudgetScope.TEAM, key="platform", limit_s=-1.0)

    assert resource_excinfo.value.rule == RULE_NEGATIVE_LIMIT
    assert damage_excinfo.value.rule == "budget.damage_negative_limit"
    # The decisive property: one id would name two different subjects.
    assert resource_excinfo.value.rule != damage_excinfo.value.rule


def test_a_zero_limit_is_a_typo_for_a_resource_budget_and_a_ceiling_for_a_damage_node() -> None:
    """Why one id could not have served both, stated as an executable claim.

    ``ResourceBudget`` refuses ``limit <= 0`` — a zero budget is unspendable, so
    it is a typo. ``BudgetNode`` accepts ``limit_s == 0``, because ``None`` is
    "no ceiling" but an explicit ``0`` at one scope is a real authored ceiling
    that a positive damage charge will breach later. Same word, opposite intent.
    """
    from mayhem.domain.policy import BudgetNode, BudgetScope

    with pytest.raises(InvariantViolationError) as excinfo:
        _resource_budget(0.0)
    assert excinfo.value.rule == RULE_NEGATIVE_LIMIT

    assert BudgetNode(scope=BudgetScope.TEAM, key="platform", limit_s=0.0).limit_s == 0.0
