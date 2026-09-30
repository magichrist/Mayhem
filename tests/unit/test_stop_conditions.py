"""Stop conditions: the expression tree, the gates, and the citations.

Plan 11's stop-condition section is one sentence long and it is the important
one: *"A firing condition names the samples that fired it — a stop without cited
samples is a defect."* These tests are therefore organised around three
questions:

1. **Does the tree say what the author meant?** ``and``/``or`` precedence,
   nesting, and — critically — that an ``or`` which fires cites the branch that
   fired and not the one that happened to be clean.
2. **Do the gates keep a stop honest?** Hysteresis edge cases on the bound
   itself, consecutive-sample counting, debounce, cooldown, and the
   maximum-observation window.
3. **Are the failures loud?** The negative controls: a firing with no cited
   samples, an unknown metric reference, a condition with no threshold. A
   stop that cannot be justified, a typo that resolves to silence, and a leaf
   that compares nothing are three ways this feature could ship a report that
   reads as calm and is not.

The other recurring theme is that time is *injected*. Every ``evaluate`` call
takes ``now_epoch_s`` explicitly, so a test can place the evaluation instant
exactly on a gate boundary instead of sleeping — and so the domain never has to
ask the wall clock, which is what makes "pure evaluation over recorded
observations" true rather than aspirational.
"""

from __future__ import annotations

import pytest

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.observations import (
    CriterionKind,
    CriterionOperator,
    ObservationResult,
    ObservationStatus,
    SloCriterion,
)
from mayhem.domain.steady_state import (
    AbsoluteExpect,
    AssertionVerb,
    Tolerance,
    Verdict,
    classify,
    within_absolute,
)
from mayhem.domain.stop_conditions import (
    Condition,
    ConditionResult,
    ConditionStatus,
    FiresWhen,
    Firing,
    MetricReference,
    NodeKind,
    Sample,
    Threshold,
    ToleranceKind,
)

# -- helpers -----------------------------------------------------------------------


def _sample(
    metric: str = "latency_ms",
    value: float | None = 100.0,
    at: float = 0.0,
    *,
    unit: str = "ms",
    source: str = "",
    status: ObservationStatus = ObservationStatus.OK,
) -> Sample:
    return Sample(
        ObservationResult(
            metric=metric,
            value=value,
            unit=unit,
            window_s=10.0,
            status=status,
            source=source,
        ),
        at,
    )


def _series(
    values: list[float], metric: str = "latency_ms", *, step: float = 1.0, source: str = ""
) -> list[Sample]:
    return [
        _sample(metric, value, index * step, source=source) for index, value in enumerate(values)
    ]


def _above(limit: float = 250.0) -> Threshold:
    """Fire when the recorded value rises above ``limit``."""
    return Threshold(expect=AbsoluteExpect(lte=limit))


def _latency(**controls: object) -> Condition:
    return Condition.metric("latency_ms", _above(250.0), **controls)  # type: ignore[arg-type]


# -- tolerance types extend the verdict core, never fork it -------------------------


class TestThresholdExtendsTheVerdictCore:
    def test_absolute_band_is_steady_states_own_comparison(self) -> None:
        threshold = _above(250.0)
        assert threshold.holds(_sample(value=200.0)) is True
        assert threshold.holds(_sample(value=300.0)) is False
        # The comparison is literally steady_state's, not a copy of it.
        assert threshold.holds(_sample(value=200.0)) == within_absolute(
            200.0, AbsoluteExpect(lte=250.0)
        )

    def test_ratio_kind_defers_to_steady_state_relative_deviation(self) -> None:
        threshold = Threshold(
            kind=ToleranceKind.RATIO,
            tolerance=Tolerance(at_most_relative=1.5),
            baseline=100.0,
        )
        # 1.5x is a bound on *deviation*: |measured - 100| <= 150.
        assert threshold.holds(_sample(value=140.0)) is True
        assert threshold.holds(_sample(value=250.0)) is True
        assert threshold.holds(_sample(value=260.0)) is False
        # A full sign inversion has the healthy magnitude and must not pass.
        assert threshold.holds(_sample(value=-100.0)) is False

    def test_percentage_kind_defers_to_steady_state_delta(self) -> None:
        threshold = Threshold(kind=ToleranceKind.PERCENTAGE, percent=20.0, baseline=100.0)
        assert threshold.holds(_sample(value=120.0)) is True
        assert threshold.holds(_sample(value=120.5)) is False

    def test_percentage_without_a_baseline_is_unmeasurable_not_healthy(self) -> None:
        threshold = Threshold(kind=ToleranceKind.PERCENTAGE, percent=20.0)
        assert threshold.holds(_sample(value=1.0)) is False

    def test_operator_kind_reuses_the_slo_criterion(self) -> None:
        threshold = Threshold(
            kind=ToleranceKind.OPERATOR,
            criterion=SloCriterion(
                kind=CriterionKind.LATENCY,
                metric="latency_ms",
                operator=CriterionOperator.LT,
                threshold=250.0,
            ),
        )
        assert threshold.holds(_sample(value=100.0)) is True
        assert threshold.holds(_sample(value=250.0)) is False  # strict lt, from the criterion
        assert threshold.holds(_sample(value=300.0)) is False

    def test_unavailable_sample_never_holds(self) -> None:
        missing = _sample("latency_ms", None, status=ObservationStatus.MISSING)
        assert _above().holds(missing) is False
        assert _above().breaches(missing) is True

    def test_fires_when_met_inverts_the_reading(self) -> None:
        completion = Threshold(
            expect=AbsoluteExpect(lte=250.0), fires_when=FiresWhen.MET
        )
        assert completion.breaches(_sample(value=100.0)) is True
        assert completion.breaches(_sample(value=300.0)) is False

    def test_assertion_projects_onto_the_steady_state_verdict(self) -> None:
        assertion = _above(250.0).assertion("api.latency", AssertionVerb.DEGRADED)
        result = classify(300.0, None, assertion)
        # Same Verdict enum, same classify() — this module adds no verdict of its own.
        assert result.verdict is None
        assert result.sufficient is False
        graded = _above(250.0).assertion("api.latency")
        assert graded.verb is AssertionVerb.DEGRADED

    def test_projected_assertion_grades_through_classify(self) -> None:
        from mayhem.domain.steady_state import Baseline

        assertion = _above(250.0).assertion("api.latency")
        result = classify(300.0, Baseline(value=100.0, samples=5), assertion)
        assert result.verdict is Verdict.DEGRADED_BEYOND_TOLERANCE
        assert result.passed is False

    def test_threshold_refuses_a_mechanism_it_cannot_compare(self) -> None:
        with pytest.raises(InvariantViolationError) as missing:
            Threshold(kind=ToleranceKind.RATIO)
        assert "declares no tolerance" in str(missing.value)

        with pytest.raises(InvariantViolationError) as mixed:
            Threshold(expect=AbsoluteExpect(lte=1.0), tolerance=Tolerance(at_most=1.0))
        assert "exactly one mechanism" in str(mixed.value)

    def test_threshold_refuses_a_baseline_it_would_ignore(self) -> None:
        with pytest.raises(InvariantViolationError) as refused:
            Threshold(expect=AbsoluteExpect(lte=1.0), baseline=10.0)
        assert "only a ratio or percentage bound" in str(refused.value)


# -- expression tree ----------------------------------------------------------------


class TestExpressionTree:
    def test_leaf_fires_and_cites_the_breaching_samples(self) -> None:
        result = _latency().evaluate(_series([100.0, 300.0, 400.0]), now_epoch_s=2.0)
        assert result.status is ConditionStatus.FIRED
        assert [sample.value for sample in result.samples] == [300.0, 400.0]
        assert result.fired_at_epoch_s == 2.0
        assert result.fired is True

    def test_leaf_stays_clear_while_the_bound_holds(self) -> None:
        result = _latency().evaluate(_series([100.0, 200.0]), now_epoch_s=1.0)
        assert result.status is ConditionStatus.CLEAR
        assert result.samples == ()

    def test_and_fires_only_when_every_branch_fires(self) -> None:
        both = Condition.all(_latency(), _errors())
        samples = [
            _sample("latency_ms", 400.0, 0.0),
            _sample("error_rate", 0.5, 0.0, unit="fraction"),
        ]
        result = both.evaluate(samples, now_epoch_s=0.0)
        assert result.status is ConditionStatus.FIRED
        assert {sample.metric for sample in result.samples} == {"latency_ms", "error_rate"}

    def test_and_does_not_fire_on_a_single_firing_branch(self) -> None:
        both = Condition.all(_latency(), _errors())
        samples = [
            _sample("latency_ms", 400.0, 0.0),
            _sample("error_rate", 0.01, 0.0, unit="fraction"),
        ]
        result = both.evaluate(samples, now_epoch_s=0.0)
        assert result.status is ConditionStatus.CLEAR
        assert result.samples == ()
        # The note names the branch that did fire, so "clear" cannot be misread.
        assert "latency_ms=fired" in result.note

    def test_or_fires_on_either_branch_and_cites_only_the_one_that_fired(self) -> None:
        either = Condition.any(_latency(), _errors())
        samples = [
            _sample("latency_ms", 400.0, 0.0),
            _sample("error_rate", 0.01, 0.0, unit="fraction"),
        ]
        result = either.evaluate(samples, now_epoch_s=0.0)
        assert result.status is ConditionStatus.FIRED
        assert [sample.metric for sample in result.samples] == ["latency_ms"]
        assert result.path == ""

    def test_or_precedence_is_structural_not_syntactic(self) -> None:
        """``all(a, any(b, c))`` and ``any(all(a, b), c)`` are different trees.

        There is no precedence rule to get wrong: each node declares its own
        operator, so the author controls the grouping by construction.
        """
        tight = Condition.all(_latency(), Condition.any(_errors(), _queue()))
        loose = Condition.any(Condition.all(_latency(), _errors()), _queue())
        only_the_right_pair_fires = [
            _sample("latency_ms", 100.0, 0.0),
            _sample("error_rate", 0.5, 0.0, unit="fraction"),
            _sample("queue_depth", 500.0, 0.0, unit="items"),
        ]
        # Tight: latency AND (errors OR queue) — latency holds, so it does not fire.
        tight_result = tight.evaluate(only_the_right_pair_fires, now_epoch_s=0.0)
        assert tight_result.status is ConditionStatus.CLEAR
        # Loose: (latency AND errors) OR queue — the right branch fires, so it does.
        assert loose.evaluate(only_the_right_pair_fires, now_epoch_s=0.0).status is (
            ConditionStatus.FIRED
        )

    def test_nested_tree_reports_the_branch_that_fired(self) -> None:
        tree = Condition.all(
            _latency(),
            Condition.any(_errors(), _queue()),
        )
        samples = [
            _sample("latency_ms", 400.0, 0.0),
            _sample("error_rate", 0.5, 0.0, unit="fraction"),
            _sample("queue_depth", 0.0, 0.0, unit="items"),
        ]
        result = tree.evaluate(samples, now_epoch_s=0.0)
        assert result.status is ConditionStatus.FIRED
        # Citations survive the nesting: both contributing branches are cited.
        assert {sample.metric for sample in result.samples} == {"latency_ms", "error_rate"}

    def test_nested_path_locates_the_firing_branch(self) -> None:
        tree = Condition.any(Condition.all(_latency(), _errors()), _queue())
        samples = [
            _sample("latency_ms", 400.0, 0.0),
            _sample("error_rate", 0.5, 0.0, unit="fraction"),
            _sample("queue_depth", 0.0, 0.0, unit="items"),
        ]
        child = tree.operands[0].evaluate(samples, now_epoch_s=0.0, path="any[0]")
        assert child.path == "any[0]"
        assert child.status is ConditionStatus.FIRED

    def test_composite_with_no_operands_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            Condition.all()
        assert "no operands" in str(refusal.value)

    def test_composite_may_not_declare_its_own_bound(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            Condition(
                kind=NodeKind.ALL,
                operands=(_latency(),),
                reference=MetricReference(metric="latency_ms"),
            )
        assert "combination has no bound of its own" in str(refusal.value)

    def test_leaf_only_controls_are_refused_on_a_composite(self) -> None:
        for control in ({"hysteresis": 0.1}, {"for_samples": 3}, {"debounce": 10.0}):
            with pytest.raises(InvariantViolationError) as refusal:
                Condition(kind=NodeKind.ALL, operands=(_latency(), _errors()), **control)
            assert "read as a control and do nothing" in str(refusal.value)

    def test_metrics_and_references_are_collected_in_order(self) -> None:
        tree = Condition.all(_latency(), Condition.any(_errors(), _latency()))
        assert tree.metrics == ("latency_ms", "error_rate")
        assert [ref.metric for ref in tree.references()] == [
            "latency_ms",
            "error_rate",
            "latency_ms",
        ]

    def test_source_scoped_reference_separates_two_producers(self) -> None:
        condition = Condition.metric(
            "latency_ms",
            _above(250.0),
            source_id="api-http",
        )
        samples = [
            _sample("latency_ms", 900.0, 0.0, source="cache"),
            _sample("latency_ms", 900.0, 1.0, source="api-http"),
        ]
        result = condition.evaluate(samples, now_epoch_s=1.0)
        assert result.status is ConditionStatus.FIRED
        assert [sample.source for sample in result.samples] == ["api-http"]


# -- hysteresis ---------------------------------------------------------------------


class TestHysteresis:
    def test_band_width_scales_with_the_bound(self) -> None:
        assert Condition.metric("m", _above(200.0), hysteresis=0.1).band() == pytest.approx(20.0)
        assert Condition.metric("m", _above(0.05), hysteresis=0.1).band() == pytest.approx(0.005)

    def test_absolute_component_adjoins_the_relative_one(self) -> None:
        condition = Condition.metric("m", _above(200.0), hysteresis=0.1, hysteresis_absolute=5.0)
        assert condition.band() == pytest.approx(25.0)

    def test_no_band_means_exact_comparison_on_the_edge(self) -> None:
        """Without a band, equality is not a verdict: ``lte`` fires on equality."""
        result = _latency().evaluate(_series([250.0]), now_epoch_s=0.0)
        assert result.status is ConditionStatus.CLEAR
        above = Condition.metric("m", _above(250.0))
        assert above.band() == 0.0
        result = _latency().evaluate(_series([250.0001]), now_epoch_s=0.0)
        assert result.status is ConditionStatus.FIRED

    def test_strict_operator_still_refuses_equality_without_a_band(self) -> None:
        condition = Condition.metric(
            "latency_ms",
            Threshold(
                kind=ToleranceKind.OPERATOR,
                criterion=SloCriterion(
                    kind=CriterionKind.LATENCY,
                    metric="latency_ms",
                    operator=CriterionOperator.LT,
                    threshold=250.0,
                ),
            ),
        )
        # A strict "stay below 250 ms" stop: 249.9 holds, 250.0 breaches.
        assert condition.evaluate(_series([249.9]), now_epoch_s=0.0).status is (
            ConditionStatus.CLEAR
        )
        assert condition.evaluate(_series([250.0]), now_epoch_s=0.0).status is (
            ConditionStatus.FIRED
        )

    def test_value_inside_the_band_holds_the_previous_state(self) -> None:
        """A hovering signal neither confirms a breach nor confirms a clear."""
        condition = Condition.metric("m", _above(250.0), hysteresis=0.1)  # band 25
        # 300 confirms a breach, 260 sits inside the band, 280 confirms it again.
        result = condition.evaluate(_series([300.0, 260.0, 280.0], "m"), now_epoch_s=2.0)
        assert result.status is ConditionStatus.FIRED
        # Only the confirmed breaches are cited: a held sample is the absence of
        # a confirmation, not evidence of the breach.
        assert [sample.value for sample in result.samples] == [300.0, 280.0]

    def test_value_inside_the_band_cannot_confirm_a_clear(self) -> None:
        condition = Condition.metric("m", _above(250.0), hysteresis=0.1)  # band 25
        # 400 confirms a breach; 240 sits inside the band, so the run survives.
        result = condition.evaluate(_series([400.0, 240.0], "m"), now_epoch_s=1.0)
        assert result.status is ConditionStatus.FIRED
        assert [sample.value for sample in result.samples] == [400.0]

    def test_breach_edge_is_inclusive_and_clear_edge_is_exclusive(self) -> None:
        condition = Condition.metric("m", _above(250.0), hysteresis=0.1)  # band 25
        edge = condition.evaluate(_series([275.0], "m"), now_epoch_s=0.0)
        assert edge.status is ConditionStatus.FIRED  # exactly limit + band confirms
        inside = condition.evaluate(_series([225.0], "m"), now_epoch_s=0.0)
        assert inside.status is ConditionStatus.CLEAR  # exactly limit - band is clear

    def test_band_flattens_a_flapping_signal(self) -> None:
        """The reason hysteresis exists: alternation around the bound stays put."""
        with_band = Condition.metric("m", _above(250.0), hysteresis=0.2)  # band 50
        without_band = Condition.metric("m", _above(250.0))
        flapping = [251.0, 249.0, 251.0, 249.0, 251.0]
        # Without a band every 251 is a fresh breach and the last one is live.
        assert without_band.evaluate(_series(flapping, "m"), now_epoch_s=4.0).status is (
            ConditionStatus.FIRED
        )
        # With a band, 251 never leaves the dead zone: nothing ever confirms.
        assert with_band.evaluate(_series(flapping, "m"), now_epoch_s=4.0).status is (
            ConditionStatus.CLEAR
        )

    def test_band_stops_consecutive_counting_from_being_gamed(self) -> None:
        """A dead value holds the run; it does not count as a fresh breach."""
        condition = Condition.metric("m", _above(250.0), for_samples=3, hysteresis=0.1)
        result = condition.evaluate(
            _series([300.0, 260.0, 260.0, 300.0, 300.0], "m"), now_epoch_s=4.0
        )
        # Only the confirmed breaches (300, 300, 300) count toward three in a row.
        assert result.status is ConditionStatus.FIRED
        assert [sample.value for sample in result.samples] == [300.0, 300.0, 300.0]

    def test_band_inverts_with_fires_when_met(self) -> None:
        completion = Condition.metric(
            "m",
            Threshold(expect=AbsoluteExpect(lte=250.0), fires_when=FiresWhen.MET),
            hysteresis=0.1,
        )
        # Inside the band and not yet clearly met → not a firing.
        assert completion.evaluate(_series([260.0], "m"), now_epoch_s=0.0).status is (
            ConditionStatus.CLEAR
        )
        assert completion.evaluate(_series([200.0], "m"), now_epoch_s=0.0).status is (
            ConditionStatus.FIRED
        )

    def test_lower_bound_band_uses_the_below_direction(self) -> None:
        condition = Condition.metric(
            "m", Threshold(expect=AbsoluteExpect(gte=10.0)), hysteresis=0.1
        )
        # 0.5 confirms a breach of a lower bound; 9.5 sits inside the band
        # (limit - band == 9.0), so it neither breaches nor clears.
        result = condition.evaluate(_series([0.5, 9.5], "m"), now_epoch_s=1.0)
        assert result.status is ConditionStatus.FIRED
        assert [sample.value for sample in result.samples] == [0.5]
        # A lower bound's clear edge is limit + band (12.0), not limit - band.
        recovers = condition.evaluate(_series([0.5, 12.0], "m"), now_epoch_s=1.0)
        assert recovers.status is ConditionStatus.CLEAR

    def test_equality_band_is_a_tolerance_around_the_value(self) -> None:
        condition = Condition.metric(
            "m",
            Threshold(expect=AbsoluteExpect(eq=1.0)),
            hysteresis_absolute=0.25,
        )
        assert condition.evaluate(_series([1.1], "m"), now_epoch_s=0.0).status is (
            ConditionStatus.CLEAR
        )
        assert condition.evaluate(_series([1.5], "m"), now_epoch_s=0.0).status is (
            ConditionStatus.FIRED
        )

    def test_hysteresis_is_refused_where_it_cannot_be_expressed(self) -> None:
        two_sided = Threshold(expect=AbsoluteExpect(gte=1.0, lte=2.0))
        assert two_sided.supports_hysteresis is False
        with pytest.raises(InvariantViolationError) as refusal:
            Condition.metric("m", two_sided, hysteresis=0.1)
        assert "no single governing bound" in str(refusal.value)

        ratio = Threshold(kind=ToleranceKind.RATIO, tolerance=Tolerance(at_most=1.0))
        with pytest.raises(InvariantViolationError) as ratio_refusal:
            Condition.metric("m", ratio, hysteresis=0.1)
        assert "until a baseline is captured" in str(ratio_refusal.value)

    def test_relative_hysteresis_must_be_a_fraction(self) -> None:
        with pytest.raises(ValueError):
            Condition.metric("m", _above(1.0), hysteresis=1.0)


# -- consecutive samples, debounce, cooldown, expiry --------------------------------


class TestGates:
    def test_consecutive_count_requires_uninterrupted_breaches(self) -> None:
        condition = _latency(for_samples=3)
        interrupted = _series([400.0, 400.0, 100.0, 400.0])
        assert condition.evaluate(interrupted, now_epoch_s=3.0).status is (
            ConditionStatus.PENDING
        )
        fired = condition.evaluate(
            _series([400.0, 400.0, 100.0, 400.0, 400.0, 400.0]), now_epoch_s=5.0
        )
        assert fired.status is ConditionStatus.FIRED
        assert len(fired.samples) == 3

    def test_pending_names_the_shortfall(self) -> None:
        result = _latency(for_samples=3).evaluate(_series([400.0, 400.0]), now_epoch_s=1.0)
        assert result.status is ConditionStatus.PENDING
        assert result.note == "breaching on 2 of 3 required consecutive sample(s)"

    def test_a_clear_sample_resets_the_count(self) -> None:
        condition = _latency(for_samples=2)
        result = condition.evaluate(
            _series([400.0, 100.0, 400.0, 400.0]), now_epoch_s=3.0
        )
        assert result.status is ConditionStatus.FIRED
        assert [sample.at_epoch_s for sample in result.samples] == [2.0, 3.0]

    def test_debounce_requires_the_breach_to_persist(self) -> None:
        condition = _latency(debounce=10.0)
        too_soon = condition.evaluate(_series([400.0, 400.0]), now_epoch_s=1.0)
        assert too_soon.status is ConditionStatus.PENDING
        assert "of the 10.000s this condition requires" in too_soon.note
        assert condition.evaluate(_series([400.0, 400.0]), now_epoch_s=10.0).status is (
            ConditionStatus.FIRED
        )

    def test_debounce_is_measured_from_the_first_breach_not_from_now(self) -> None:
        condition = _latency(debounce=10.0)
        # Breach began at t=100; evaluating at t=105 is only 5s of persistence.
        samples = [_sample("latency_ms", 400.0, 100.0), _sample("latency_ms", 400.0, 101.0)]
        assert condition.evaluate(samples, now_epoch_s=105.0).status is ConditionStatus.PENDING
        assert condition.evaluate(samples, now_epoch_s=110.0).status is ConditionStatus.FIRED

    def test_debounce_and_consecutive_samples_compose(self) -> None:
        condition = _latency(for_samples=3, debounce=5.0)
        result = condition.evaluate(_series([400.0, 400.0, 400.0]), now_epoch_s=3.0)
        assert result.status is ConditionStatus.PENDING
        assert condition.evaluate(_series([400.0, 400.0, 400.0]), now_epoch_s=5.0).status is (
            ConditionStatus.FIRED
        )

    def test_cooldown_suppresses_a_second_firing(self) -> None:
        condition = _latency(cooldown=30.0)
        samples = _series([400.0, 400.0])
        assert condition.evaluate(samples, now_epoch_s=1.0).status is ConditionStatus.FIRED
        suppressed = condition.evaluate(samples, now_epoch_s=10.0, last_fired_epoch_s=1.0)
        assert suppressed.status is ConditionStatus.SUPPRESSED
        assert suppressed.fired is False
        assert "suppressed by cooldown" in suppressed.note
        assert condition.evaluate(samples, now_epoch_s=40.0, last_fired_epoch_s=1.0).status is (
            ConditionStatus.FIRED
        )

    def test_cooldown_does_not_mask_a_breach_that_never_qualified(self) -> None:
        condition = _latency(for_samples=3, cooldown=30.0)
        result = condition.evaluate(
            _series([400.0, 400.0]), now_epoch_s=1.0, last_fired_epoch_s=0.0
        )
        assert result.status is ConditionStatus.PENDING

    def test_composite_cooldown_is_honoured(self) -> None:
        tree = Condition.all(_latency(), _errors(), cooldown=60.0)
        samples = [
            _sample("latency_ms", 400.0, 0.0),
            _sample("error_rate", 0.5, 0.0, unit="fraction"),
        ]
        assert tree.evaluate(samples, now_epoch_s=0.0).status is ConditionStatus.FIRED
        assert tree.evaluate(samples, now_epoch_s=10.0, last_fired_epoch_s=0.0).status is (
            ConditionStatus.SUPPRESSED
        )

    def test_max_duration_closes_a_window_that_never_fired(self) -> None:
        condition = _latency(max_duration=20.0)
        result = condition.evaluate(_series([100.0, 100.0, 100.0]), now_epoch_s=30.0)
        assert result.status is ConditionStatus.EXPIRED
        assert "cannot fire is a no-op" in result.note
        assert condition.evaluate(_series([100.0]), now_epoch_s=10.0).status is (
            ConditionStatus.CLEAR
        )

    def test_breach_inside_the_window_still_fires_after_it(self) -> None:
        condition = _latency(max_duration=20.0)
        result = condition.evaluate(_series([100.0, 400.0, 400.0]), now_epoch_s=60.0)
        assert result.status is ConditionStatus.FIRED
        assert [sample.value for sample in result.samples] == [400.0, 400.0]

    def test_breach_only_after_the_window_is_not_a_firing(self) -> None:
        condition = _latency(max_duration=20.0)
        samples = [_sample("latency_ms", 100.0, 0.0), _sample("latency_ms", 400.0, 50.0)]
        result = condition.evaluate(samples, now_epoch_s=50.0)
        assert result.status is ConditionStatus.EXPIRED

    def test_composite_expiry_propagates_from_its_branches(self) -> None:
        tree = Condition.all(_latency(max_duration=20.0), _errors())
        result = tree.evaluate(
            [
                _sample("latency_ms", 100.0, 0.0),
                _sample("error_rate", 0.0, 0.0, unit="fraction"),
            ],
            now_epoch_s=40.0,
        )
        assert result.status is ConditionStatus.EXPIRED

    def test_evaluation_is_pure_in_the_injected_clock(self) -> None:
        samples = _series([100.0, 400.0])
        condition = _latency(debounce=5.0)
        first = condition.evaluate(samples, now_epoch_s=2.0)
        second = condition.evaluate(samples, now_epoch_s=2.0)
        assert first.to_dict() == second.to_dict()
        assert condition.evaluate(samples, now_epoch_s=7.0).status is ConditionStatus.FIRED

    def test_evaluation_baseline_overrides_the_authored_one(self) -> None:
        """The seam Phase 2 uses to hand in what its capture window recorded."""
        condition = Condition.metric(
            "error_rate",
            Threshold(
                kind=ToleranceKind.PERCENTAGE,
                percent=10.0,
                baseline=0.10,
            ),
        )
        samples = [_sample("error_rate", 0.20, 0.0, unit="fraction")]
        # Against the authored baseline of 0.10, +100% breaches a 10% band.
        assert condition.evaluate(samples, now_epoch_s=0.0).status is ConditionStatus.FIRED
        # A captured baseline of 0.20 is the value itself: 0% change holds.
        captured = condition.evaluate(samples, now_epoch_s=0.0, baselines={"error_rate": 0.20})
        assert captured.status is ConditionStatus.CLEAR

    def test_samples_recorded_after_now_are_outside_the_window(self) -> None:
        # Two breaches would qualify; only one of them has been recorded by now.
        condition = _latency(for_samples=2)
        assert condition.evaluate(_series([400.0, 400.0]), now_epoch_s=0.0).status is (
            ConditionStatus.PENDING
        )
        assert condition.evaluate(_series([400.0, 400.0]), now_epoch_s=1.0).status is (
            ConditionStatus.FIRED
        )


# -- observations with no evidence --------------------------------------------------


class TestUnmeasured:
    def test_metric_recorded_but_never_measured_is_unmeasured(self) -> None:
        samples = [_sample("latency_ms", None, 0.0, status=ObservationStatus.MISSING)]
        result = _latency().evaluate(samples, now_epoch_s=0.0)
        assert result.status is ConditionStatus.UNMEASURED
        assert "none of them is available" in result.note

    def test_error_status_is_also_unmeasured_not_clear(self) -> None:
        samples = [_sample("latency_ms", None, 0.0, status=ObservationStatus.ERROR)]
        assert _latency().evaluate(samples, now_epoch_s=0.0).status is (
            ConditionStatus.UNMEASURED
        )

    def test_unmeasured_branch_poisons_a_conjunction(self) -> None:
        tree = Condition.all(_latency(), _errors())
        result = tree.evaluate(
            [_sample("latency_ms", 400.0, 0.0), _sample("error_rate", None, 0.0, unit="fraction")],
            now_epoch_s=0.0,
        )
        assert result.status is ConditionStatus.UNMEASURED

    def test_an_or_branch_with_no_recorded_metric_is_still_refused(self) -> None:
        """Partial evidence never turns into a quiet ``any``.

        The disjunction would not fire anyway, so accepting it would be
        harmless *this* time. Accepting it teaches the engine that an absent
        metric is a non-event, and the one time it matters is a branch that
        should have fired.
        """
        tree = Condition.any(_latency(), _errors())
        with pytest.raises(InvariantViolationError) as refusal:
            tree.evaluate(_series([400.0]), now_epoch_s=0.0)
        assert "error_rate" in str(refusal.value)


# -- negative controls ---------------------------------------------------------------


class TestNegativeControls:
    def test_a_firing_with_no_cited_samples_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            Firing(condition_name="latency", samples=(), fired_at_epoch_s=1.0)
        assert "a stop with no evidence behind it is a defect" in str(refusal.value)

    def test_a_fired_result_with_no_samples_cannot_even_be_built(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            ConditionResult(
                condition_name="latency",
                status=ConditionStatus.FIRED,
                samples=(),
                fired_at_epoch_s=1.0,
            )
        assert "fired with no cited samples" in str(refusal.value)

    def test_a_fired_result_without_a_timestamp_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            ConditionResult(
                condition_name="latency",
                status=ConditionStatus.FIRED,
                samples=(_sample(),),
            )
        assert "without a timestamp" in str(refusal.value)

    def test_a_firing_may_not_cite_an_unmeasured_sample(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            Firing(
                condition_name="latency",
                samples=(_sample("latency_ms", None, status=ObservationStatus.MISSING),),
                fired_at_epoch_s=1.0,
            )
        assert "cannot justify a stop" in str(refusal.value)

    def test_a_firing_may_not_carry_a_non_finite_timestamp(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            Firing(condition_name="latency", samples=(_sample(),), fired_at_epoch_s=float("inf"))
        assert "non-finite" in str(refusal.value)

    def test_an_unknown_metric_reference_is_refused_at_evaluation(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            _latency().evaluate(_series([100.0], metric="error_rate"), now_epoch_s=0.0)
        assert "refused, not reported as clear" in str(refusal.value)

    def test_an_unknown_metric_reference_is_refused_at_authoring_time(self) -> None:
        tree = Condition.all(_latency(), _errors())
        with pytest.raises(InvariantViolationError) as refusal:
            tree.validate_references(["latency_ms"])
        assert "a stop that can never fire" in str(refusal.value)
        tree.validate_references(["latency_ms", "error_rate"])

    def test_a_source_scoped_reference_with_no_matching_source_is_refused(self) -> None:
        condition = Condition.metric("latency_ms", _above(), source_id="api-http")
        with pytest.raises(InvariantViolationError):
            condition.evaluate(_series([400.0], source="cache"), now_epoch_s=0.0)

    def test_a_condition_with_no_threshold_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            Condition(kind=NodeKind.METRIC, reference=MetricReference(metric="latency_ms"))
        assert "declares a threshold" in str(refusal.value)

    def test_a_condition_with_no_reference_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            Condition(kind=NodeKind.METRIC, threshold=_above())
        assert "neither a reference nor a threshold" in str(refusal.value)

    def test_an_empty_absolute_band_is_refused_by_the_verdict_core(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            Threshold(expect=AbsoluteExpect())
        assert "accept every measurement" in str(refusal.value)

    def test_a_leaf_may_not_also_be_a_composition(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            Condition(
                kind=NodeKind.METRIC,
                reference=MetricReference(metric="latency_ms"),
                threshold=_above(),
                operands=(_latency(),),
            )
        assert "either a comparison or a combination" in str(refusal.value)

    def test_a_result_that_did_not_fire_cannot_be_promoted_to_a_firing(self) -> None:
        result = _latency().evaluate(_series([100.0]), now_epoch_s=0.0)
        with pytest.raises(InvariantViolationError) as refusal:
            result.to_firing()
        assert "there is no firing to record" in str(refusal.value)

    def test_a_sample_must_be_a_recorded_observation(self) -> None:
        with pytest.raises(InvariantViolationError) as refusal:
            Sample("400.0", 1.0)  # type: ignore[arg-type]
        assert "a sample is a recorded observation" in str(refusal.value)

    def test_a_sample_time_must_be_finite(self) -> None:
        observation = ObservationResult(
            metric="latency_ms", value=1.0, unit="ms", window_s=1.0
        )
        with pytest.raises(InvariantViolationError) as refusal:
            Sample(observation, float("nan"))
        assert "cannot be placed on a timeline" in str(refusal.value)


# -- firings and evidence -----------------------------------------------------------


class TestFiring:
    def test_firing_carries_the_condition_the_samples_and_the_time(self) -> None:
        result = _latency(name="api.latency").evaluate(
            _series([100.0, 400.0, 450.0]), now_epoch_s=2.0
        )
        firing = result.to_firing()
        assert firing.condition_name == "api.latency"
        assert firing.sample_count == 2
        assert firing.fired_at_epoch_s == 2.0
        assert firing.cites(_sample("latency_ms", 400.0, 1.0))
        assert not firing.cites(_sample("latency_ms", 100.0, 0.0))

    def test_firing_serialises_the_samples_it_cites(self) -> None:
        firing = _latency().evaluate(_series([400.0]), now_epoch_s=0.0).to_firing()
        payload: dict[str, object] = firing.to_dict()
        cited = payload["samples"]
        assert isinstance(cited, list) and isinstance(cited[0], dict)
        assert payload["condition"] == "latency_ms"
        assert payload["sample_count"] == 1
        assert cited[0]["metric"] == "latency_ms"
        assert cited[0]["value"] == 400.0
        assert cited[0]["at_epoch_s"] == 0.0
        assert payload["fired_at_epoch_s"] == 0.0

    def test_result_serialises_its_own_status(self) -> None:
        payload = _latency().evaluate(_series([100.0]), now_epoch_s=0.0).to_dict()
        assert payload["status"] == "clear"
        assert payload["fired"] is False
        assert payload["samples"] == []


def _errors() -> Condition:
    return Condition.metric(
        "error_rate",
        Threshold(expect=AbsoluteExpect(lte=0.05)),
        name="error_rate",
    )


def _queue() -> Condition:
    return Condition.metric(
        "queue_depth",
        Threshold(expect=AbsoluteExpect(lte=100.0)),
        name="queue_depth",
    )
