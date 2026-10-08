"""Statistics over recorded observations: intervals, effect size, sufficiency,
and warm-up exclusion (docs/v1.1.0/15_RESILIENCE_ANALYTICS_ADAPTIVE.md, Phase 1).

Three things are being defended here, and each has a test that would fail if it
stopped being true:

* **"No material effect" is reachable and specific.** The first test replays
  plan 15's own example sentence and asserts the exact string: p99 moved 5.2%
  with overlapping 95% CI — NO MATERIAL EFFECT. A module that could only say
  "material" or nothing would pass a naive smoke test and fail this one.
* **The two interval tests are not confused.** ``overlaps`` is a description
  and ``contains`` is the decision. Two fixtures pin the cases where they
  disagree — disjoint per-series intervals with an indistinguishable
  difference, and overlapping per-series intervals with a real difference —
  because a comparison that quietly picked the wrong one would report a real
  effect as "no material effect" roughly half the time.
* **Ungradeable data is refused rather than scored.** Too few samples, and
  (the subtle one) two perfectly constant series: both report
  ``INSUFFICIENT_DATA`` with no effect size and no interval, because a probe
  that returned the same number twelve times recorded nothing to compare.

Fixtures are fixed lists, never generated, so every number below is
reproducible on any machine. ``random`` in a fixture would make a statistic
test a test of the seed.
"""

from __future__ import annotations

from typing import cast

import pytest

from mayhem.domain.analytics import (
    DEFAULT_LEVEL,
    MIN_COMPARABLE_SAMPLES,
    Comparison,
    ConfidenceInterval,
    EffectOutcome,
    ObservationPhase,
    SamplePolicy,
    WindowPlan,
    cohens_d,
    compare,
    difference_confidence_interval,
    mean_confidence_interval,
    summarize,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.steady_state import sample_baseline

# Plan 15's example, planted. The window is the baseline with jitter and one
# high sample: the p99 moves 5.2%, and the shift cannot be separated from the
# run-to-run spread of the system under test.
BASE_LATENCY = [480.0, 512.0, 495.0, 530.0, 470.0, 505.0, 488.0, 521.0, 499.0, 543.0, 476.0, 510.0]
WINDOW_LATENCY = [
    481.0,
    511.0,
    496.0,
    529.0,
    471.0,
    504.0,
    489.0,
    520.0,
    498.0,
    571.2,
    475.0,
    511.0,
]

# A shift big enough to clear the noise on the same fixture.
SHIFTED_LATENCY = [value + 120.0 for value in BASE_LATENCY]

# Five samples with a wide spread against fifty with a narrow one: the
# difference is not distinguishable, yet the per-series intervals are far
# apart. The phrase must name the difference CI rather than claim overlap.
TIGHT_BASELINE = [99.0, 100.0, 101.0, 100.0, 100.0]
NOISY_WINDOW = [116.0] * 25 + [96.0] * 25

# The mirror image: wide baseline, narrow window, and a shift that clears the
# difference interval while the per-series intervals still overlap.
WIDE_BASELINE = [70.0, 100.0, 130.0, 100.0, 100.0]
RISEN_WINDOW = [140.0] * 6 + [108.0] * 44


# -- distribution summaries -----------------------------------------------------------


def test_summarize_reports_the_numbers_a_report_can_quote() -> None:
    summary = summarize(BASE_LATENCY)

    assert summary is not None
    assert summary.count == len(BASE_LATENCY)
    assert summary.minimum == 470.0
    assert summary.maximum == 543.0
    # Two different "medians": `median` interpolates, the percentile is
    # nearest-rank because it is sample_baseline's, and the two must not be
    # confused when a report quotes one of them.
    assert summary.median == pytest.approx(502.0)
    assert summary.stdev > 0.0
    assert summary.percentile(50.0) == 499.0
    assert summary.percentile(99.0) == 543.0
    # Only the requested percentiles are computed and carried.
    narrow = summarize(BASE_LATENCY, percentiles=(50.0, 99.0))
    assert narrow is not None
    assert narrow.percentile(95.0) is None
    assert sorted(narrow.percentiles) == [50.0, 99.0]


def test_percentiles_agree_with_the_steady_state_reduction() -> None:
    """One definition of "the percentile of this series", not two.

    ``steady_state.sample_baseline`` is what the graded verdict reads, so a
    percentile computed differently here would let an analytics report and a
    steady-state verdict disagree about the same measurement.
    """
    summary = summarize(BASE_LATENCY, percentiles=(50.0, 95.0, 99.0))
    assert summary is not None

    for point in (50.0, 95.0, 99.0):
        expected = sample_baseline(BASE_LATENCY, percentile=point)
        assert expected is not None
        assert summary.percentile(point) == expected.value


def test_summarize_drops_non_finite_samples_and_counts_them() -> None:
    summary = summarize([10.0, float("nan"), 12.0, float("inf"), 11.0])

    assert summary is not None
    assert summary.count == 3
    assert summary.dropped == 2
    assert summary.mean == pytest.approx(11.0)


@pytest.mark.parametrize("values", [[], [float("nan"), float("inf")]])
def test_summarize_returns_none_when_nothing_finite_was_recorded(values: list[float]) -> None:
    assert summarize(values) is None


def test_out_of_range_percentile_and_level_are_refused() -> None:
    with pytest.raises(InvariantViolationError):
        summarize([1.0, 2.0], percentiles=(0.0,))
    with pytest.raises(InvariantViolationError):
        summarize([1.0, 2.0], percentiles=(101.0,))
    with pytest.raises(InvariantViolationError):
        summarize([1.0, 2.0], level=1.0)


def test_summary_serialises_deterministically() -> None:
    first = summarize(BASE_LATENCY)
    second = summarize(BASE_LATENCY)

    assert first is not None and second is not None
    assert first.to_dict() == second.to_dict()
    percentiles = cast("dict[str, float]", first.to_dict()["percentiles"])
    assert list(percentiles) == ["50.0", "90.0", "95.0", "99.0"]


# -- confidence intervals -------------------------------------------------------------


def test_mean_interval_needs_two_samples() -> None:
    """One sample has no spread, and reporting a zero-width interval for it
    would be a claim of perfect knowledge rather than an admission of none."""
    assert mean_confidence_interval([100.0]) is None
    assert mean_confidence_interval([]) is None


def test_mean_interval_narrows_as_samples_accumulate() -> None:
    five = mean_confidence_interval([10.0, 12.0, 11.0, 9.0, 10.5])
    twenty = mean_confidence_interval([10.0, 12.0, 11.0, 9.0, 10.5] * 4)

    assert five is not None and twenty is not None
    assert five.level == DEFAULT_LEVEL
    assert five.samples == 5 and twenty.samples == 20
    assert twenty.width < five.width


def test_interval_overlap_is_symmetric_and_touching_counts_as_overlap() -> None:
    wide = ConfidenceInterval(level=0.95, low=0.0, high=10.0, center=5.0)
    left = ConfidenceInterval(level=0.95, low=1.0, high=4.0, center=2.5)
    right = ConfidenceInterval(level=0.95, low=6.0, high=12.0, center=9.0)
    touching = ConfidenceInterval(level=0.95, low=10.0, high=20.0, center=15.0)

    assert wide.overlaps(left) is True
    assert left.overlaps(wide) is True
    assert left.overlaps(right) is False
    assert wide.overlaps(touching) is True
    assert wide.half_width == pytest.approx(5.0)


def test_interval_contains_is_inclusive_and_ignores_non_finite() -> None:
    interval = ConfidenceInterval(level=0.95, low=1.0, high=2.0, center=1.5)

    assert interval.contains(1.0) and interval.contains(2.0) and interval.contains(1.5)
    assert interval.contains(2.0001) is False
    assert interval.contains(float("nan")) is False


def test_difference_interval_centres_on_the_shift_between_means() -> None:
    interval = difference_confidence_interval([1.0, 2.0, 3.0], [3.0, 4.0, 5.0])

    assert interval is not None
    assert interval.center == pytest.approx(2.0)
    assert interval.contains(2.0)


def test_difference_interval_is_refused_without_a_measurable_spread() -> None:
    assert difference_confidence_interval([5.0, 5.0], [7.0, 7.0]) is None


# -- effect size ----------------------------------------------------------------------


def test_cohens_d_on_a_planted_shift() -> None:
    """A one-unit shift on a series whose pooled spread is sqrt(5/3)."""
    baseline = [1.0, 2.0, 3.0, 4.0]
    risen = [2.0, 3.0, 4.0, 5.0]

    effect = cohens_d(baseline, risen)

    assert effect is not None
    assert effect.kind == "cohens-d"
    assert effect.value == pytest.approx(1.0 / (5.0 / 3.0) ** 0.5)
    assert effect.baseline_samples == 4 and effect.window_samples == 4
    assert effect.magnitude == "medium"

    fallen = cohens_d(risen, baseline)
    assert fallen is not None
    assert fallen.value == pytest.approx(-effect.value)


@pytest.mark.parametrize(
    ("baseline", "window"),
    [([1.0], [2.0]), ([1.0, 1.0, 1.0], [2.0, 2.0, 2.0])],
)
def test_cohens_d_is_none_rather_than_infinite_without_spread(
    baseline: list[float], window: list[float]
) -> None:
    assert cohens_d(baseline, window) is None


def test_effect_size_magnitude_bands() -> None:
    pooled = (5.0 / 3.0) ** 0.5  # the spread of [0, 1, 2, 3]

    def sized(d: float) -> str:
        """The same series shifted by exactly ``d`` pooled standard deviations."""
        baseline = [0.0, 1.0, 2.0, 3.0]
        effect = cohens_d(baseline, [value + d * pooled for value in baseline])
        assert effect is not None
        return effect.magnitude

    assert sized(0.1) == "negligible"
    assert sized(0.3) == "small"
    assert sized(0.6) == "medium"
    assert sized(1.2) == "large"


# -- the comparison -------------------------------------------------------------------


def test_plan_15_example_phrase_is_produced_exactly() -> None:
    """*"p99 moved 5.2% with overlapping 95% CI — NO MATERIAL EFFECT"*."""
    result = compare(BASE_LATENCY, WINDOW_LATENCY, name="checkout-latency")

    assert result.verdict_phrase == ("p99 moved 5.2% with overlapping 95% CI — NO MATERIAL EFFECT")
    assert result.outcome is EffectOutcome.NO_MATERIAL_EFFECT
    assert result.intervals_overlap is True
    assert result.difference_ci is not None
    assert result.difference_ci.contains(0.0)
    assert result.effect_size is not None
    assert result.effect_size.magnitude in ("negligible", "small")
    assert result.sufficient and result.graded and not result.material


def test_a_real_shift_is_reported_as_material_with_the_statistics_beside_it() -> None:
    result = compare(BASE_LATENCY, SHIFTED_LATENCY, name="checkout-latency")

    assert result.outcome is EffectOutcome.MATERIAL_RISE
    assert result.material and result.graded
    assert result.intervals_overlap is False
    assert result.effect_size is not None
    assert result.effect_size.value > 0
    assert result.difference_ci is not None
    assert not result.difference_ci.contains(0.0)
    assert "MATERIAL RISE" in result.verdict_phrase


def test_a_fall_is_a_fall_not_a_rise() -> None:
    result = compare(BASE_LATENCY, [value / 2.0 for value in BASE_LATENCY], name="latency")

    assert result.outcome is EffectOutcome.MATERIAL_FALL
    assert result.point_delta_pct == pytest.approx(-50.0)
    assert result.effect_size is not None
    assert result.effect_size.value < 0


def test_disjoint_intervals_with_an_indistinguishable_difference_are_not_called_evidence() -> None:
    """The two interval tests disagree; the verdict must follow the right one.

    Baseline is five tight samples, the window is fifty noisy ones. The
    per-series intervals are far apart, and the difference is still inside its
    own interval — so the answer is no material effect, and the sentence says
    so by naming the difference interval rather than claiming an overlap it
    does not have.
    """
    result = compare(TIGHT_BASELINE, NOISY_WINDOW, name="queue-depth")

    assert result.intervals_overlap is False
    assert result.outcome is EffectOutcome.NO_MATERIAL_EFFECT
    assert result.difference_ci is not None
    assert result.difference_ci.contains(0.0)
    assert "CI on the difference containing zero" in result.verdict_phrase


def test_overlapping_intervals_with_a_real_difference_are_still_material() -> None:
    """The mirror image, and the case a naive overlap test gets wrong."""
    result = compare(WIDE_BASELINE, RISEN_WINDOW, name="error-rate")

    assert result.intervals_overlap is True
    assert result.outcome is EffectOutcome.MATERIAL_RISE
    assert result.difference_ci is not None
    assert not result.difference_ci.contains(0.0)
    assert "difference CI excluding zero" in result.verdict_phrase


def test_a_move_below_the_materiality_floor_is_not_material() -> None:
    result = compare(BASE_LATENCY, SHIFTED_LATENCY, name="checkout-latency", materiality_pct=95.0)

    assert result.outcome is EffectOutcome.NO_MATERIAL_EFFECT
    assert "95.0%" in result.note
    assert "materiality" in result.note


def test_comparison_is_deterministic() -> None:
    first = compare(BASE_LATENCY, WINDOW_LATENCY, name="checkout-latency")
    second = compare(BASE_LATENCY, WINDOW_LATENCY, name="checkout-latency")

    assert first.to_dict() == second.to_dict()
    assert first == second


def test_zero_baseline_is_reported_without_a_relative_scale() -> None:
    result = compare(
        [0.0, 0.0, 0.0, 1.0, 0.0], [0.0, 0.0, 0.0, 1.0, 0.0], name="deltas", percentile=50.0
    )

    assert result.point_delta_pct is None
    assert "no relative scale" in result.verdict_phrase


# -- sufficiency (negative control) ---------------------------------------------------


def test_sufficiency_threshold_is_the_five_sample_floor() -> None:
    policy = SamplePolicy()

    assert policy.check(5, 5).sufficient is True
    assert policy.check(5, 5).reason == ""
    assert policy.check(4, 5).sufficient is False
    assert policy.check(5, 4).sufficient is False
    assert "too few samples" in policy.check(4, 5).reason


def test_a_comparison_on_too_few_samples_is_marked_insufficient_not_scored() -> None:
    result = compare([100.0, 101.0], [105.0, 106.0], name="checkout-latency")

    assert result.outcome is EffectOutcome.INSUFFICIENT_DATA
    assert result.sufficient is False and result.graded is False
    assert result.material is False
    # Nothing that could be quoted as a finding: no effect size, no intervals,
    # not even the movement figure.
    assert result.effect_size is None
    assert result.difference_ci is None
    assert result.baseline_ci is None
    assert result.point_delta_pct is None
    assert result.verdict_phrase.endswith("— NOT GRADED")


def test_a_custom_floor_can_be_raised_per_series() -> None:
    policy = SamplePolicy(min_baseline=8, min_window=20)

    assert policy.check(7, 40).sufficient is False
    assert policy.check(8, 20).sufficient is True
    result = compare(BASE_LATENCY, WINDOW_LATENCY, name="x", policy=policy)
    assert result.outcome is EffectOutcome.INSUFFICIENT_DATA


def test_a_sample_floor_below_one_is_refused() -> None:
    with pytest.raises(InvariantViolationError):
        SamplePolicy(min_baseline=0)
    with pytest.raises(InvariantViolationError):
        SamplePolicy(min_window=0)


def test_two_constant_series_are_refused_rather_than_called_no_effect() -> None:
    """The subtle one: no spread means no interval, and no interval means no
    verdict. A window that reads 200 twelve times while the baseline read 100
    is a stuck probe, and "no material effect" would be a coincidence."""
    result = compare([100.0] * 12, [200.0] * 12, name="checkout-latency")

    assert result.sufficient is True  # the sample floor was cleared
    assert result.outcome is EffectOutcome.INSUFFICIENT_DATA
    assert result.graded is False
    assert result.effect_size is None
    assert result.difference_ci is None
    assert "no spread" in result.note
    assert "NOT GRADED" in result.verdict_phrase


def test_default_floor_matches_the_steady_state_capture_default() -> None:
    assert MIN_COMPARABLE_SAMPLES == 5


# -- warm-up and cooldown -------------------------------------------------------------


def test_window_plan_splits_a_run_into_its_three_phases() -> None:
    plan = WindowPlan(warmup=3, measured=4, cooldown=2)
    values = [900.0, 901.0, 902.0, 1.0, 2.0, 3.0, 4.0, 10.0, 11.0]

    segments = plan.split(values)

    assert segments.warmup == (900.0, 901.0, 902.0)
    assert segments.measured == (1.0, 2.0, 3.0, 4.0)
    assert segments.cooldown == (10.0, 11.0)
    assert segments.dropped == 0 and segments.missing == 0
    assert segments.complete is True
    assert plan.total == 9


def test_warm_up_and_cooldown_are_excluded_from_the_measured_window() -> None:
    """A settling transient must not reach the statistic.

    Both runs get the same measured window; only their warm-up differs. Scored
    on the measured window alone they are indistinguishable, which is the
    whole reason the phases exist.
    """
    plan = WindowPlan(warmup=3, measured=len(BASE_LATENCY), cooldown=2)
    quiet = plan.split([100.0, 101.0, 102.0, *BASE_LATENCY, 500.0, 501.0])
    disturbed = plan.split([5000.0, 5200.0, 5400.0, *BASE_LATENCY, 500.0, 501.0])

    assert quiet.complete and disturbed.complete
    assert disturbed.warmup == (5000.0, 5200.0, 5400.0)
    assert quiet.measured == disturbed.measured

    scored = compare(quiet.measured, disturbed.measured, name="checkout-latency")
    assert scored.outcome is EffectOutcome.NO_MATERIAL_EFFECT

    # Including the warm-up would have produced a dramatic — and entirely
    # artefactual — "effect". The phases are what stop it being quotable.
    unscored = compare(
        [*quiet.warmup, *quiet.measured],
        [*disturbed.warmup, *disturbed.measured],
        name="checkout-latency",
    )
    assert unscored.outcome is EffectOutcome.MATERIAL_RISE


def test_segmented_samples_report_what_the_run_did_not_supply() -> None:
    plan = WindowPlan(warmup=2, measured=3, cooldown=1)

    short = plan.split([1.0, 2.0])
    assert short.missing == 4
    assert short.dropped == 0
    assert short.complete is False

    long = plan.split([1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0])
    assert long.missing == 0
    assert long.dropped == 2
    assert long.complete is False


def test_segments_expose_each_phase_by_name() -> None:
    segments = WindowPlan(warmup=1, measured=2, cooldown=1).split([1.0, 2.0, 3.0, 4.0])

    assert segments.values(ObservationPhase.WARMUP) == (1.0,)
    assert segments.values(ObservationPhase.MEASURED) == (2.0, 3.0)
    assert segments.values(ObservationPhase.COOLDOWN) == (4.0,)
    plan_payload = cast("dict[str, int]", segments.to_dict()["plan"])
    assert plan_payload["measured"] == 2


def test_a_window_that_measures_nothing_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as measured:
        WindowPlan(measured=0)
    assert "measures nothing" in str(measured.value)

    with pytest.raises(InvariantViolationError):
        WindowPlan(warmup=-1)


def test_a_refused_window_cannot_produce_a_quiet_comparison() -> None:
    """A comparison over a window with no measured samples is unscored."""
    result = compare(BASE_LATENCY, [], name="checkout-latency")

    assert result.outcome is EffectOutcome.INSUFFICIENT_DATA
    assert result.effect_size is None


# -- the result type ------------------------------------------------------------------


def test_comparison_serialises_everything_a_report_needs() -> None:
    payload = compare(BASE_LATENCY, WINDOW_LATENCY, name="checkout-latency").to_dict()
    sufficiency = cast("dict[str, object]", payload["sufficiency"])
    difference = cast("dict[str, object]", payload["difference_ci"])
    effect = cast("dict[str, object]", payload["effect_size"])

    assert payload["name"] == "checkout-latency"
    assert payload["statistic"] == "p99"
    assert payload["outcome"] == "no-material-effect"
    assert payload["sufficient"] is True and payload["graded"] is True
    assert sufficiency["required_baseline"] == 5
    assert difference["method"] == "normal-approximation"
    assert effect["kind"] == "cohens-d"
    phrase = cast("str", payload["verdict_phrase"])
    assert phrase.endswith("— NO MATERIAL EFFECT")


def test_comparison_is_a_frozen_value() -> None:
    result: Comparison = compare(BASE_LATENCY, WINDOW_LATENCY, name="x")

    with pytest.raises(AttributeError):
        result.outcome = EffectOutcome.MATERIAL_RISE  # type: ignore[misc]
