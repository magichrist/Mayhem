"""Spec-level tests for the steady-state hypothesis (plan 03, v1.0.0).

828 lines of pure domain maths had no net. The cases below are chosen to fail
on the specific failures this file exists to pin, not merely to exercise the
happy path:

* **The sign-blind relative bound.** A signed metric that inverted completely
  (``+100 → -100``) has the same magnitude as the healthy value, so comparing
  magnitudes graded a total inversion as ``as-hypothesised`` — the worst
  outcome reported as the best one — while the same run's ``delta_pct``
  correctly read ``-200.0 %``. The governing invariant is pinned directly:
  a relative bound depends only on ``|measured - baseline|``, never on which
  side of the baseline the value landed.
* **The ``within`` ceiling's blind twin.** ``within`` scales a *magnitude*, so
  it also has to say which side of zero it bounds.
* **The documented asymmetries.** ``within_absolute`` is a conjunction and
  ``within_relative`` a disjunction. That inversion is deliberate and
  documented; a test that fails if either flips is the only thing keeping it
  deliberate.
* **The ``classify`` boundary.** A bare ``float`` used to die on
  ``baseline.samples`` three frames deep.
* **Silent non-grading.** ``capture.samples=5`` with 3 captured must report
  nothing, invent nothing, and pass nothing.
* **Backward compatibility.** A spec with no ``steady_state`` block must dump
  byte-identically, which means the key must be *absent*, not ``None``.
"""

from __future__ import annotations

import json
import math
from typing import Any

import pytest
import yaml

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    DrillContainer,
    DrillFault,
    DrillSpec,
    ExecutionStep,
)
from mayhem.domain.steady_state import (
    INSUFFICIENT_BASELINE,
    NON_FINITE_BASELINE,
    AbsoluteExpect,
    Assertion,
    AssertionResult,
    AssertionVerb,
    Baseline,
    CaptureSpec,
    Phase,
    PhaseAssertion,
    PhaseChecks,
    Severity,
    SignalResult,
    SteadyStateSignal,
    SteadyStateSpec,
    Tolerance,
    Verdict,
    classify,
    degradation_limit,
    delta_pct,
    sample_baseline,
    within_absolute,
    within_relative,
)

# -- fixtures / builders -------------------------------------------------------------


def _baseline(value: float, samples: int = 5) -> Baseline:
    return Baseline(value=value, samples=samples)


def _relative(**tolerance: float) -> SteadyStateSignal:
    """A signal judged against its own captured baseline."""
    return SteadyStateSignal(
        name="api.error_rate",
        source_id="api.logs",
        metric="status_5xx_ratio",
        tolerance=Tolerance(**tolerance),
    )


def _absolute(lte: float | None = None, gte: float | None = None) -> SteadyStateSignal:
    """A signal judged against an authored band."""
    return SteadyStateSignal(
        name="api.latency.p99",
        source_id="api.http",
        metric="latency_ms",
        expect=AbsoluteExpect(lte=lte, gte=gte),
    )


def _assertion(
    signal: SteadyStateSignal,
    verb: AssertionVerb,
    *,
    required_samples: int = 1,
    within: float | None = None,
) -> Assertion:
    return Assertion.for_signal(signal, verb, required_samples=required_samples, within=within)


def _signal_of(result: AssertionResult) -> SignalResult:
    assert len(result.signals) == 1
    return result.signals[0]


def _first_signal(payload: dict[str, object]) -> dict[str, Any]:
    signals = payload["signals"]
    assert isinstance(signals, list)
    first = signals[0]
    assert isinstance(first, dict)
    return first


# -- the bug: a sign-blind relative bound --------------------------------------------


class TestWithinRelativeIsSignSafe:
    """The invariant, stated as a test.

    *A relative tolerance measures deviation from the baseline, not magnitude.
    A value on the opposite side of the baseline must never satisfy a relative
    bound it would not satisfy in the same direction.*
    """

    def test_full_sign_reversal_fails_relative(self) -> None:
        # baseline=+100 -> measured=-100. Same magnitude, opposite direction.
        assert within_relative(100.0, -100.0, Tolerance(at_most_relative=1.5)) is False

    def test_full_sign_reversal_is_not_recovered(self) -> None:
        result = classify(
            -100.0,
            _baseline(100.0),
            _assertion(_relative(at_most_relative=1.5), AssertionVerb.RECOVERED),
        )
        assert _signal_of(result).passed is False
        assert result.verdict is Verdict.NOT_RECOVERED
        assert result.passed is False
        assert result.note == ""

    def test_full_sign_reversal_on_degraded_fails_the_within_ceiling(self) -> None:
        # within 2.0 on a +100 reference -> ceiling 200; -190 has magnitude 190,
        # so the magnitude-only comparison passed it as within tolerance.
        result = classify(
            -190.0,
            _baseline(100.0),
            _assertion(_absolute(lte=100.0), AssertionVerb.DEGRADED, within=2.0),
        )
        assert _signal_of(result).passed is False
        assert result.verdict is Verdict.DEGRADED_BEYOND_TOLERANCE

    def test_the_bound_agrees_with_delta_pct(self) -> None:
        """The module was self-contradictory before: this pins the agreement.

        ``delta_pct`` divided by ``abs(baseline)`` so a signed metric reads its
        direction honestly. ``within_relative`` then threw the direction away.
        The two now tell the same story about the same pair of numbers.
        """
        tolerance = Tolerance(at_most_relative=1.5)
        assert delta_pct(100.0, -100.0) == -200.0
        assert within_relative(100.0, -100.0, tolerance) is False
        # …and a same-direction move of the same relative size still passes,
        # so the refusal above is about direction, not about being large.
        assert delta_pct(100.0, 140.0) == 40.0
        assert within_relative(100.0, 140.0, tolerance) is True

    @pytest.mark.parametrize(
        "measured",
        [-100.0, -99.0, -60.0, -49.0, -1.0, 0.0, 1.0, 49.0, 60.0, 99.0, 100.0, 250.0, 251.0, 400.0],
    )
    def test_mirroring_the_baseline_cannot_change_the_verdict(self, measured: float) -> None:
        """Deviation is symmetric about the baseline, by construction.

        ``200 - measured`` is the value on the opposite side of a ``+100``
        baseline at an identical distance. The invariant says the two must be
        graded identically; the old magnitude comparison could not even see the
        difference.
        """
        tolerance = Tolerance(at_most_relative=1.5)
        mirrored = 200.0 - measured
        assert within_relative(100.0, measured, tolerance) is within_relative(
            100.0, mirrored, tolerance
        )

    def test_movement_toward_zero_still_passes(self) -> None:
        """A halving is a 50% move, well inside a 1.5x band."""
        assert within_relative(100.0, 50.0, Tolerance(at_most_relative=1.5)) is True
        assert delta_pct(100.0, 50.0) == -50.0

    def test_zero_baseline_leaves_only_zero_measurable(self) -> None:
        tolerance = Tolerance(at_most_relative=1.5)
        assert within_relative(0.0, 0.0, tolerance) is True
        assert within_relative(0.0, 0.0001, tolerance) is False
        assert within_relative(0.0, -0.0001, tolerance) is False

    def test_absent_or_non_finite_baseline_leaves_the_bound_unsatisfiable(self) -> None:
        tolerance = Tolerance(at_most_relative=1.5)
        assert within_relative(None, 0.0, tolerance) is False
        assert within_relative(math.nan, 0.0, tolerance) is False
        assert within_relative(math.inf, 0.0, tolerance) is False

    def test_absent_tolerance_and_non_finite_measurement_are_false(self) -> None:
        assert within_relative(100.0, 100.0, None) is False
        assert within_relative(100.0, math.nan, Tolerance(at_most_relative=1.5)) is False
        assert within_relative(100.0, math.inf, Tolerance(at_most_relative=1.5)) is False
        assert within_relative(100.0, -math.inf, Tolerance(at_most_relative=1.5)) is False

    def test_unsigned_control_is_unchanged(self) -> None:
        """Regression guard: 100 → 400 on a 1.5x band was already not-recovered.

        This is the *unsigned* metric, the overwhelmingly common case, and it
        must keep behaving exactly as it did before the fix.
        """
        result = classify(
            400.0,
            _baseline(100.0),
            _assertion(_relative(at_most_relative=1.5), AssertionVerb.RECOVERED),
        )
        assert result.verdict is Verdict.NOT_RECOVERED
        assert result.passed is False
        assert within_relative(100.0, 400.0, Tolerance(at_most_relative=1.5)) is False

    def test_unsigned_control_still_accepts_the_documented_band(self) -> None:
        tolerance = Tolerance(at_most_relative=1.5)
        assert within_relative(100.0, 250.0, tolerance) is True
        assert within_relative(100.0, 251.0, tolerance) is False


class TestToleranceIsADisjunction:
    """Alternative allowances for one judgement, not a conjunction.

    Reading these as a conjunction would silently tighten every assertion
    authored with both bounds, which is how a tolerance band quietly becomes a
    no-op that fails healthy systems. All three cases below use non-negative
    values so the disjunction is what is under test, not the sign handling.
    """

    def test_at_most_alone_is_enough(self) -> None:
        # 300 is 200% of a 100 baseline, so the relative bound refuses it; the
        # absolute ceiling of 400 accepts it. One allowance is enough.
        tolerance = Tolerance(at_most=400.0, at_most_relative=1.5)
        assert within_relative(100.0, 300.0, tolerance) is True
        # 450 breaks both
        assert within_relative(100.0, 450.0, tolerance) is False

    def test_at_most_relative_alone_is_enough(self) -> None:
        tolerance = Tolerance(at_most=150.0, at_most_relative=1.5)
        assert within_relative(100.0, 240.0, tolerance) is True

    def test_failing_both_bounds_fails(self) -> None:
        tolerance = Tolerance(at_most=150.0, at_most_relative=1.5)
        assert within_relative(100.0, 400.0, tolerance) is False

    def test_the_relative_bound_is_what_refuses_a_sign_inversion(self) -> None:
        """``at_most`` is a one-sided absolute ceiling; the relative bound is
        the sign-safe one, and it refuses the inversion even though the
        ceiling would not. This is the documented disjunction doing its job,
        not a hole: an absolute ceiling like the plan's ``at_most: 0.02``
        ("+2 percentage points") is authored against a scale with a floor.
        """
        tolerance = Tolerance(at_most=200.0, at_most_relative=1.5)
        assert within_relative(100.0, -180.0, tolerance) is True  # via the ceiling
        assert within_relative(100.0, -180.0, Tolerance(at_most_relative=1.5)) is False

    def test_recovery_still_passes_via_the_absolute_ceiling(self) -> None:
        signal = _relative(at_most=200.0, at_most_relative=1.5)
        result = classify(180.0, _baseline(100.0), _assertion(signal, AssertionVerb.RECOVERED))
        assert result.verdict is Verdict.AS_HYPOTHESISED
        assert _signal_of(result).passed is True


class TestWithinCeiling:
    """The ``within`` limit path: a magnitude ceiling that names its own side."""

    def test_documented_ceiling_is_preserved(self) -> None:
        # within 2.0 on expect {lte: 250} permits 500 ms of degradation.
        assertion = _assertion(_absolute(lte=250.0), AssertionVerb.DEGRADED, within=2.0)
        assert degradation_limit(250.0, assertion) == 500.0
        result = classify(500.0, _baseline(250.0), assertion)
        assert result.verdict is Verdict.DEGRADED_WITHIN_TOLERANCE
        result = classify(500.001, _baseline(250.0), assertion)
        assert result.verdict is Verdict.DEGRADED_BEYOND_TOLERANCE

    def test_the_plans_own_worked_example(self) -> None:
        # docs/v1.0.0/03: baseline 88, during 412, within 2.0, expect {lte: 250}
        assertion = _assertion(_absolute(lte=250.0), AssertionVerb.DEGRADED, within=2.0)
        result = classify(412.0, _baseline(88.0), assertion)
        assert result.verdict is Verdict.DEGRADED_WITHIN_TOLERANCE
        assert _signal_of(result).delta_pct is not None
        assert round(_signal_of(result).delta_pct) == 368  # type: ignore[arg-type]
        assert _signal_of(result).limit == 500.0

    def test_relative_ceiling_matches_the_documented_baseline_arithmetic(self) -> None:
        # "within 2.0 on a 10-unit baseline permits 20" — unchanged for the
        # normal non-negative case.
        assertion = _assertion(_relative(at_most_relative=1.5), AssertionVerb.DEGRADED, within=2.0)
        assert degradation_limit(10.0, assertion) == 20.0
        assert classify(20.0, _baseline(10.0), assertion).passed is True
        assert classify(20.5, _baseline(10.0), assertion).passed is False

    def test_a_negative_excursion_never_passes(self) -> None:
        assertion = _assertion(_absolute(lte=100.0), AssertionVerb.DEGRADED, within=2.0)
        for measured in (-0.001, -1.0, -100.0, -190.0, -1e9):
            assert classify(measured, _baseline(100.0), assertion).passed is False, measured

    def test_a_negative_baseline_keeps_its_own_side(self) -> None:
        assertion = _assertion(_relative(at_most_relative=1.5), AssertionVerb.DEGRADED, within=2.0)
        # A signed metric from -10 may fall to -20 within 2.0…
        assert classify(-20.0, _baseline(-10.0), assertion).passed is True
        # …but may not cross zero and call it a degradation.
        assert classify(20.0, _baseline(-10.0), assertion).passed is False

    def test_no_within_falls_through_to_the_signals_own_basis(self) -> None:
        within_none = _assertion(_absolute(lte=250.0), AssertionVerb.DEGRADED)
        assert degradation_limit(88.0, within_none) is None
        assert classify(412.0, _baseline(88.0), within_none).passed is False
        assert classify(120.0, _baseline(88.0), within_none).passed is True

    def test_no_basis_at_all_passes_once_it_moved(self) -> None:
        bare = Assertion(verb=AssertionVerb.DEGRADED, name="api.latency.p99")
        assert classify(500.0, _baseline(88.0), bare).passed is True


# -- delta_pct ------------------------------------------------------------------------


class TestDeltaPct:
    def test_zero_baseline_is_undefined_not_infinite(self) -> None:
        assert delta_pct(0.0, 5.0) is None
        assert delta_pct(0.0, 0.0) is None
        assert delta_pct(-0.0, 5.0) is None

    def test_signed_baseline_reads_its_own_direction(self) -> None:
        # Divided by abs(baseline), so "closer to zero" reads as an improvement
        # and "further from zero" as a worsening, on the raw scale.
        assert delta_pct(-10.0, -5.0) == 50.0
        assert delta_pct(-10.0, -20.0) == -100.0
        assert delta_pct(-10.0, -10.0) == 0.0

    def test_positive_baseline(self) -> None:
        assert delta_pct(100.0, 150.0) == 50.0
        assert delta_pct(100.0, 50.0) == -50.0
        assert delta_pct(100.0, 100.0) == 0.0

    def test_the_plans_worked_example_rounds_to_368(self) -> None:
        value = delta_pct(88.0, 412.0)
        assert value is not None
        assert round(value) == 368

    @pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
    def test_non_finite_input_is_none(self, bad: float) -> None:
        assert delta_pct(bad, 1.0) is None
        assert delta_pct(1.0, bad) is None
        assert delta_pct(bad, bad) is None

    def test_a_never_inf_never_raise_contract(self) -> None:
        for baseline in (0.0, 1e-300, 1.0, -1.0, 1e18):
            for during in (0.0, -1e18, 1e18, math.inf, -math.inf, math.nan):
                value = delta_pct(baseline, during)
                assert value is None or math.isfinite(value)


# -- verdicts -------------------------------------------------------------------------


class TestEveryVerdictIsReachable:
    def test_all_five_verdicts_come_out_of_classify(self) -> None:
        unchanged_held = _relative(at_most_relative=1.5)
        absolute = _absolute(lte=250.0)
        reached = {
            # as-hypothesised: a safety signal that did not move
            classify(
                0.001, _baseline(0.001), _assertion(unchanged_held, AssertionVerb.UNCHANGED)
            ).verdict,
            # as-hypothesised: a signal that came back
            classify(88.0, _baseline(88.0), _assertion(absolute, AssertionVerb.RECOVERED)).verdict,
            # degraded-within-tolerance
            classify(
                412.0,
                _baseline(88.0),
                _assertion(absolute, AssertionVerb.DEGRADED, within=2.0),
            ).verdict,
            # degraded-beyond-tolerance (a safety signal that moved)
            classify(
                0.9, _baseline(0.001), _assertion(unchanged_held, AssertionVerb.UNCHANGED)
            ).verdict,
            # degraded-beyond-tolerance (degraded past the bound)
            classify(
                501.0,
                _baseline(88.0),
                _assertion(absolute, AssertionVerb.DEGRADED, within=2.0),
            ).verdict,
            # no-effect: the fault moved nothing
            classify(88.0, _baseline(88.0), _assertion(absolute, AssertionVerb.DEGRADED)).verdict,
            # not-recovered
            classify(999.0, _baseline(88.0), _assertion(absolute, AssertionVerb.RECOVERED)).verdict,
        }
        assert reached == set(Verdict)

    def test_each_verdict_is_reported_not_just_returned(self) -> None:
        no_effect = classify(
            88.0, _baseline(88.0), _assertion(_absolute(lte=250.0), AssertionVerb.DEGRADED)
        )
        assert no_effect.verdict is Verdict.NO_EFFECT
        assert no_effect.passed is False
        assert _signal_of(no_effect).note

        not_recovered = classify(
            999.0, _baseline(88.0), _assertion(_absolute(lte=250.0), AssertionVerb.RECOVERED)
        )
        assert not_recovered.verdict is Verdict.NOT_RECOVERED
        assert _signal_of(not_recovered).note

    def test_unchanged_is_graded_on_movement_not_on_tolerance(self) -> None:
        """A 4x rise in an error rate is a finding even under ``at_most``."""
        signal = _relative(at_most=0.02, at_most_relative=1.5)
        result = classify(0.004, _baseline(0.001), _assertion(signal, AssertionVerb.UNCHANGED))
        assert result.verdict is Verdict.DEGRADED_BEYOND_TOLERANCE
        assert result.passed is False
        assert _signal_of(result).note


# -- validation rejections ------------------------------------------------------------


class TestValidationRejections:
    """Every refusal names the field that caused it."""

    def _reject(self, **kwargs: Any) -> str:
        with pytest.raises(InvariantViolationError) as excinfo:
            SteadyStateSpec(**kwargs)
        return str(excinfo.value)

    def test_relative_tolerance_below_one(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            Tolerance(at_most_relative=0.95)
        assert excinfo.value.rule == "steady_state.tolerance_relative_below_one"
        assert "at_most_relative" in str(excinfo.value)

    def test_empty_tolerance(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            Tolerance()
        assert excinfo.value.rule == "steady_state.tolerance_empty"
        assert "at_most" in str(excinfo.value)

    def test_empty_expect(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            AbsoluteExpect()
        assert excinfo.value.rule == "steady_state.expect_empty"
        assert "lte" in str(excinfo.value)

    def test_signal_mixing_bases(self) -> None:
        message = self._reject(
            signals=[
                {
                    "name": "api.latency.p99",
                    "source_id": "api.http",
                    "metric": "latency_ms",
                    "expect": {"lte": 250},
                    "tolerance": {"at_most_relative": 1.5},
                }
            ],
            phases=[{"during": {"assert_degraded": ["api.latency.p99"]}}],
        )
        assert "steady_state.signal_mixes_bases" in message
        assert "api.latency.p99" in message
        assert "expect" in message and "tolerance" in message

    def test_baseline_window_without_tolerance(self) -> None:
        message = self._reject(
            signals=[
                {
                    "name": "api.latency.p99",
                    "source_id": "api.http",
                    "metric": "latency_ms",
                    "expect": {"lte": 250},
                    "baseline_window": "5m",
                }
            ],
            phases=[{"during": {"assert_unchanged": ["api.latency.p99"]}}],
        )
        assert "steady_state.baseline_window_without_tolerance" in message
        assert "api.latency.p99" in message
        assert "baseline_window" in message

    def test_phase_referencing_an_undeclared_signal(self) -> None:
        message = self._reject(
            signals=[{"name": "api.latency.p99", "source_id": "s", "metric": "latency_ms"}],
            phases=[{"during": {"assert_unchanged": ["api.error_rate"]}}],
        )
        assert "steady_state.undeclared_signal" in message
        assert "api.error_rate" in message
        assert "unchanged" in message

    def test_duplicate_signal_name(self) -> None:
        message = self._reject(
            signals=[
                {"name": "api.latency.p99", "source_id": "s", "metric": "latency_ms"},
                {"name": "api.latency.p99", "source_id": "s2", "metric": "latency_ms"},
            ],
            phases=[{"during": {"assert_unchanged": ["api.latency.p99"]}}],
        )
        assert "steady_state.duplicate_signal" in message
        assert "api.latency.p99" in message

    def test_empty_block_that_asserts_nothing(self) -> None:
        message = self._reject()
        assert "steady_state.empty_block" in message
        assert "signals" in message and "phases" in message

    def test_phase_that_asserts_nothing(self) -> None:
        message = self._reject(
            signals=[{"name": "api.latency.p99", "source_id": "s", "metric": "latency_ms"}],
            phases=[{"during": {}}],
        )
        assert "steady_state.phase_asserts_nothing" in message
        assert "assert_unchanged" in message

    def test_within_without_degraded(self) -> None:
        message = self._reject(
            signals=[{"name": "api.latency.p99", "source_id": "s", "metric": "latency_ms"}],
            phases=[{"during": {"assert_unchanged": ["api.latency.p99"], "within": 2.0}}],
        )
        assert "steady_state.within_without_degraded" in message
        assert "assert_degraded" in message

    def test_phase_entry_with_multiple_phase_keys(self) -> None:
        message = self._reject(
            signals=[{"name": "api.latency.p99", "source_id": "s", "metric": "latency_ms"}],
            phases=[
                {
                    "pre": {"assert_unchanged": ["api.latency.p99"]},
                    "post": {"assert_recovered": ["api.latency.p99"]},
                }
            ],
        )
        assert "steady_state.phase_has_multiple_keys" in message
        assert "pre" in message and "post" in message

    def test_phase_entry_with_no_phase(self) -> None:
        message = self._reject(
            signals=[{"name": "api.latency.p99", "source_id": "s", "metric": "latency_ms"}],
            phases=[{}],
        )
        assert "steady_state.phase_missing" in message

    def test_phase_aliases_before_and_after(self) -> None:
        spec = SteadyStateSpec.model_validate(
            {
                "signals": [{"name": "api.latency.p99", "source_id": "s", "metric": "m"}],
                "phases": [
                    {"before": {"assert_unchanged": ["api.latency.p99"]}},
                    {"after": {"assert_recovered": ["api.latency.p99"]}},
                ],
            }
        )
        assert spec.phases[0].pre is not None
        assert spec.phases[0].post is None
        assert spec.phases[1].post is not None
        assert Phase.POST.value == "post"  # the alias is input-only
        assert "after" not in spec.model_dump()["phases"][1]
        assert "post" in spec.model_dump()["phases"][1]

    def test_capture_samples_floor_is_enforced(self) -> None:
        with pytest.raises(ValueError):
            CaptureSpec(samples=0)


# -- baseline sufficiency -------------------------------------------------------------


class TestBaselineSufficiency:
    """Insufficient data is a verdict, not a number."""

    def test_three_of_five_samples_grades_nothing(self) -> None:
        result = classify(
            -100.0,
            _baseline(100.0, samples=3),
            _assertion(
                _relative(at_most_relative=1.5), AssertionVerb.RECOVERED, required_samples=5
            ),
        )
        assert result.verdict is None
        assert result.sufficient is False
        assert result.graded is False
        assert result.passed is False
        assert result.note == INSUFFICIENT_BASELINE.format(name="api.error_rate", got=3, need=5)
        assert _signal_of(result).passed is False

    def test_no_derived_number_is_invented(self) -> None:
        result = classify(
            412.0,
            _baseline(88.0, samples=3),
            _assertion(
                _absolute(lte=250.0), AssertionVerb.DEGRADED, required_samples=5, within=2.0
            ),
        )
        signal = _signal_of(result)
        # the captured value and the measurement are recorded because they
        # happened — they are not judgements
        assert signal.baseline == 88.0
        assert signal.during == 412.0
        # nothing is *derived* from them
        assert signal.delta_pct is None
        assert signal.limit is None

    def test_a_missing_baseline_is_the_same_refusal(self) -> None:
        result = classify(
            412.0,
            None,
            _assertion(_absolute(lte=250.0), AssertionVerb.DEGRADED, required_samples=5),
        )
        assert result.verdict is None
        assert result.sufficient is False
        assert result.passed is False
        assert _signal_of(result).baseline is None

    def test_an_absolutely_bounded_signal_is_refused_too(self) -> None:
        """Without a baseline a report cannot tell "the probe never fired"
        from "the fault did nothing" — that confusion is why the block exists,
        so an authored band is not a way around it.
        """
        result = classify(
            120.0,
            _baseline(88.0, samples=3),
            _assertion(_absolute(lte=250.0), AssertionVerb.RECOVERED, required_samples=5),
        )
        assert result.verdict is None
        assert result.sufficient is False
        assert result.passed is False
        # …while the pure band check stays available for a caller that only
        # wants the authored window and knows what it is giving up.
        assert within_absolute(120.0, AbsoluteExpect(lte=250.0)) is True

    def test_exactly_enough_samples_grades(self) -> None:
        result = classify(
            88.0,
            _baseline(88.0, samples=5),
            _assertion(_absolute(lte=250.0), AssertionVerb.RECOVERED, required_samples=5),
        )
        assert result.sufficient is True
        assert result.graded is True
        assert result.verdict is Verdict.AS_HYPOTHESISED

    def test_a_non_finite_baseline_is_refused_rather_than_graded(self) -> None:
        result = classify(
            120.0,
            _baseline(math.nan, samples=5),
            _assertion(_absolute(lte=250.0), AssertionVerb.RECOVERED, required_samples=5),
        )
        assert result.verdict is None
        assert result.sufficient is False
        assert _signal_of(result).baseline is None
        assert result.note == NON_FINITE_BASELINE.format(name="api.latency.p99", value=math.nan)

    def test_sample_baseline_never_feeds_a_non_finite_value(self) -> None:
        baseline = sample_baseline([math.nan, math.inf, -math.inf])
        assert baseline is None


# -- sample_baseline ------------------------------------------------------------------


class TestSampleBaseline:
    def test_default_percentile_is_the_maximum_not_the_mean(self) -> None:
        """Plan 03: "5 samples is not a baseline … needs a percentile, not a
        mean" — and a mean is exactly the statistic that hides the one bad
        sample a fault exists to expose.
        """
        baseline = sample_baseline([1.0, 2.0, 3.0, 4.0, 100.0])
        assert baseline is not None
        assert baseline.value == 100.0
        assert baseline.samples == 5
        assert baseline.value != sum([1.0, 2.0, 3.0, 4.0, 100.0]) / 5

    def test_median_percentile(self) -> None:
        baseline = sample_baseline([5.0, 1.0, 3.0, 2.0, 4.0], percentile=50.0)
        assert baseline is not None
        assert baseline.value == 3.0
        assert baseline.samples == 5

    def test_nearest_rank_percentiles(self) -> None:
        values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0]
        low = sample_baseline(values, percentile=1.0)
        high = sample_baseline(values, percentile=100.0)
        assert low is not None and low.value == 1.0
        assert high is not None and high.value == 10.0

    def test_non_finite_samples_are_dropped(self) -> None:
        baseline = sample_baseline([1.0, math.nan, math.inf, -math.inf, 3.0])
        assert baseline is not None
        assert baseline.value == 3.0
        assert baseline.samples == 2

    def test_an_all_non_finite_series_is_none_not_a_fabricated_zero(self) -> None:
        assert sample_baseline([]) is None
        assert sample_baseline([math.nan]) is None
        assert sample_baseline([math.inf, -math.inf]) is None

    def test_to_dict_is_plain_data(self) -> None:
        baseline = sample_baseline([1.0, 2.0])
        assert baseline is not None
        assert baseline.to_dict() == {"value": 2.0, "samples": 2}


# -- the classify boundary ------------------------------------------------------------


class TestClassifyBoundary:
    """A malformed baseline is named at the boundary, not three frames deep."""

    def test_a_bare_float_is_rejected_with_a_typed_error(self) -> None:
        assertion = _assertion(_relative(at_most_relative=1.5), AssertionVerb.RECOVERED)
        with pytest.raises(InvariantViolationError) as excinfo:
            classify(1.0, 5.0, assertion)  # type: ignore[arg-type]
        assert excinfo.value.rule == "steady_state.baseline_not_captured"
        message = str(excinfo.value)
        assert "float" in message
        assert "Baseline" in message
        assert "sample_baseline" in message

    def test_the_old_attributeerror_is_gone(self) -> None:
        assertion = _assertion(_relative(at_most_relative=1.5), AssertionVerb.RECOVERED)
        with pytest.raises(InvariantViolationError):
            classify(1.0, 5.0, assertion)  # type: ignore[arg-type]

    def test_none_is_the_documented_way_to_decline(self) -> None:
        assertion = _assertion(_relative(at_most_relative=1.5), AssertionVerb.RECOVERED)
        result = classify(1.0, None, assertion)
        assert result.verdict is None
        assert result.sufficient is False

    def test_a_real_baseline_is_accepted(self) -> None:
        assertion = _assertion(_relative(at_most_relative=1.5), AssertionVerb.RECOVERED)
        assert classify(1.0, _baseline(1.0, samples=1), assertion).graded is True


# -- the documented asymmetry ---------------------------------------------------------


class TestNonFiniteNeverGrades:
    """``nan`` and ``inf`` are measurements the tool did not take.

    A probe that returns ``nan`` and a probe that was never wired up produce
    the same bytes. Letting either reach a ``pass`` is how a report claims a
    check ran when nothing was measured.
    """

    @pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
    @pytest.mark.parametrize("verb", list(AssertionVerb))
    def test_no_verb_ever_passes_a_non_finite_measurement(
        self, bad: float, verb: AssertionVerb
    ) -> None:
        for signal in (_relative(at_most_relative=1.5), _absolute(lte=250.0)):
            result = classify(bad, _baseline(100.0), _assertion(signal, verb, within=2.0))
            assert result.passed is False, (verb, signal.name, bad)
            assert _signal_of(result).passed is False
            assert result.verdict is not Verdict.AS_HYPOTHESISED
            assert _signal_of(result).delta_pct is None

    @pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
    def test_no_derived_number_reaches_the_result(self, bad: float) -> None:
        result = classify(
            bad,
            _baseline(100.0),
            _assertion(_relative(at_most_relative=1.5), AssertionVerb.RECOVERED),
        )
        signal = _signal_of(result)
        assert signal.delta_pct is None
        assert signal.limit is None


class TestAbsoluteIsAConjunctionRelativeIsADisjunction:
    """A deliberate inversion. A test is the only thing that keeps it
    deliberate: flipping either one is a behaviour change nobody would notice
    in review, because both still "work" on a single-bound signal.
    """

    def test_absolute_narrows_the_window(self) -> None:
        band = AbsoluteExpect(gte=10.0, lte=250.0)
        assert within_absolute(100.0, band) is True
        # both bounds must hold: 300 breaks lte, 5 breaks gte
        assert within_absolute(300.0, band) is False
        assert within_absolute(5.0, band) is False

    def test_relative_alternates_the_allowances(self) -> None:
        tolerance = Tolerance(at_most=400.0, at_most_relative=1.5)
        # 300 breaks the relative bound but clears the absolute ceiling
        assert within_relative(100.0, 300.0, tolerance) is True
        # 100 satisfies every bound; it is the pass/fail *shape* that differs
        assert within_absolute(300.0, AbsoluteExpect(lte=250.0)) is False

    def test_an_unmeasurable_measurement_fails_both(self) -> None:
        band = AbsoluteExpect(gte=0.0, lte=1.0)
        tolerance = Tolerance(at_most=1.0, at_most_relative=1.0)
        for bad in (math.nan, math.inf, -math.inf):
            assert within_absolute(bad, band) is False
            assert within_relative(0.5, bad, tolerance) is False

    def test_a_band_with_no_bounds_accepts_nothing(self) -> None:
        # AbsoluteExpect() cannot be constructed — the model validator refuses
        # an empty band — so reach past that guard the way a caller mutating a
        # validated model could. The predicate is conjunctive, so with no
        # bound declared it must refuse rather than vacuously pass.
        empty = AbsoluteExpect.model_construct()
        assert empty.lte is None and empty.gte is None and empty.eq is None
        assert within_absolute(0.0, empty) is False
        assert within_absolute(-99.0, empty) is False
        assert within_absolute(math.nan, empty) is False


# -- plan 03's own example ------------------------------------------------------------

PLAN_EXAMPLE_YAML = """
capture:
  samples: 5
  window: 10s

signals:
  - name: api.latency.p99
    source_id: api.http
    metric: latency_ms
    expect: { lte: 250 }

  - name: api.error_rate
    source_id: api.logs
    metric: status_5xx_ratio
    baseline_window: 5m
    tolerance:
      at_most: 0.02
      at_most_relative: 1.5
    severity: critical

phases:
  - during: { assert_unchanged: [api.error_rate] }
  - during: { assert_degraded:   [api.latency.p99], within: 2.0 }
  - after:  { assert_recovered:  [api.latency.p99, api.error_rate] }
"""


class TestPlanExampleParses:
    """docs/v1.0.0/03-steady-state-hypothesis.md, verbatim."""

    @pytest.fixture
    def spec(self) -> SteadyStateSpec:
        return SteadyStateSpec.model_validate(yaml.safe_load(PLAN_EXAMPLE_YAML))

    def test_capture(self, spec: SteadyStateSpec) -> None:
        assert spec.capture.samples == 5
        assert spec.capture.window == 10.0

    def test_signals(self, spec: SteadyStateSpec) -> None:
        assert [s.name for s in spec.signals] == ["api.latency.p99", "api.error_rate"]
        latency = spec.signal("api.latency.p99")
        assert latency is not None and latency.expect == AbsoluteExpect(lte=250.0)
        assert latency.tolerance is None
        error_rate = spec.signal("api.error_rate")
        assert error_rate is not None
        assert error_rate.tolerance == Tolerance(at_most=0.02, at_most_relative=1.5)
        assert error_rate.severity is Severity.CRITICAL
        assert str(error_rate.baseline_window) == "300.0"

    def test_phases(self, spec: SteadyStateSpec) -> None:
        assert len(spec.phases) == 3
        first, second, third = spec.phases
        assert first.during is not None
        assert first.during.assert_unchanged == ("api.error_rate",)
        assert second.during is not None
        assert second.during.assert_degraded == ("api.latency.p99",)
        assert second.during.within == 2.0
        # `after:` is an input alias; what serialises is `post`
        assert third.post is not None
        assert third.post.assert_recovered == ("api.latency.p99", "api.error_rate")

    def test_the_plans_json_example(self, spec: SteadyStateSpec) -> None:
        """The worked example in the plan's verdict block, end to end."""
        latency = spec.signal("api.latency.p99")
        assert latency is not None
        degraded = classify(
            412.0,
            _baseline(88.0),
            _assertion(latency, AssertionVerb.DEGRADED, required_samples=5, within=2.0),
        )
        payload = degraded.to_dict()
        assert payload["verdict"] == "degraded-within-tolerance"
        assert payload["sufficient"] is True
        assert payload["passed"] is True
        signal = _first_signal(payload)
        assert signal["name"] == "api.latency.p99"
        assert signal["asserted"] == "degraded"
        assert signal["pass"] is True
        assert signal["within"] == 2.0
        assert signal["limit"] == 500.0
        delta = signal["delta_pct"]
        assert isinstance(delta, float)
        assert round(delta) == 368

        error_rate = spec.signal("api.error_rate")
        assert error_rate is not None
        safety = classify(
            0.004,
            _baseline(0.001),
            _assertion(error_rate, AssertionVerb.UNCHANGED, required_samples=5),
        )
        assert _first_signal(safety.to_dict())["pass"] is False


# -- backward compatibility -----------------------------------------------------------


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _drill() -> DrillSpec:
    return DrillSpec(
        kind="drill",
        name="steady-state-compat",
        hypothesis="stack recovers",
        containers={"api": DrillContainer(faults=(DrillFault(fault="proc.pause"),))},
        execution=(ExecutionStep(parallel=("api",)),),
    )


class TestAdditiveSchemaCompat:
    def test_a_drill_without_steady_state_omits_the_key_entirely(self) -> None:
        """Not present-and-``None`` — *absent*.

        Every digest path in the toolkit hashes the dump, so a spec authored
        before this block existed must produce the same bytes as it did before
        the block existed. A ``"steady_state": null`` key would change every
        digest of every existing spec in the field.
        """
        spec = _drill()
        assert spec.steady_state is None
        assert "steady_state" not in spec.model_dump(exclude_none=True)
        assert _canonical(spec.model_dump(exclude_none=True)) == _canonical(
            spec.model_dump(exclude_none=True)
        )

    def test_a_drill_without_steady_state_round_trips_byte_identically(self) -> None:
        spec = _drill()
        once = _canonical(spec.model_dump(exclude_none=True))
        twice = _canonical(
            DrillSpec.model_validate_json(spec.model_dump_json()).model_dump(exclude_none=True)
        )
        assert once == twice

    def test_a_drill_with_steady_state_round_trips_too(self) -> None:
        payload = yaml.safe_load(PLAN_EXAMPLE_YAML)
        spec = _drill().model_copy(update={"steady_state": SteadyStateSpec.model_validate(payload)})
        once = _canonical(spec.model_dump(exclude_none=True))
        reparsed = DrillSpec.model_validate_json(spec.model_dump_json())
        assert once == _canonical(reparsed.model_dump(exclude_none=True))
        assert reparsed.steady_state is not None
        assert reparsed.steady_state is not None
        assert [s.name for s in reparsed.steady_state.signals] == [
            "api.latency.p99",
            "api.error_rate",
        ]
        # the `after:` alias is input-only: it is gone on the way out
        assert "after" not in once

    def test_the_two_schemas_disagree_only_by_the_optional_key(self) -> None:
        without = _drill().model_dump(exclude_none=True)
        with_block = (
            _drill()
            .model_copy(
                update={
                    "steady_state": SteadyStateSpec.model_validate(
                        yaml.safe_load(PLAN_EXAMPLE_YAML)
                    )
                }
            )
            .model_dump(exclude_none=True)
        )
        assert set(with_block) - set(without) == {"steady_state"}
        assert set(without) - set(with_block) == set()


# -- result plumbing -------------------------------------------------------------------


class TestResultTypes:
    def test_verdict_to_dict_renames_pass_on_the_signal(self) -> None:
        result = classify(
            88.0, _baseline(88.0), _assertion(_absolute(lte=250.0), AssertionVerb.RECOVERED)
        )
        payload = result.to_dict()
        # the top level keeps the Python-friendly name…
        assert payload["passed"] is True
        # …while the per-signal block uses the plan's JSON spelling, which is
        # a Python keyword
        signal = _first_signal(payload)
        assert signal["pass"] is True
        assert "passed" not in signal

    def test_assertion_for_signal_carries_the_spec(self) -> None:
        signal = _relative(at_most_relative=1.5)
        signal = signal.model_copy(update={"severity": Severity.CRITICAL})
        assertion = _assertion(signal, AssertionVerb.DEGRADED, required_samples=5, within=2.0)
        assert assertion.name == "api.error_rate"
        assert assertion.severity is Severity.CRITICAL
        assert assertion.required_samples == 5
        assert assertion.within == 2.0
        assert assertion.to_dict()["verb"] == "degraded"

    def test_reference_value_is_the_authored_ceiling(self) -> None:
        assert (
            _assertion(_absolute(lte=250.0), AssertionVerb.DEGRADED, within=2.0).reference_value
            == 250.0
        )
        # a signal with only a tolerance has no authored reference: the
        # baseline is it
        assert (
            _assertion(_relative(at_most_relative=1.5), AssertionVerb.DEGRADED).reference_value
            is None
        )

    def test_no_within_yields_no_limit(self) -> None:
        assertion = _assertion(_absolute(lte=250.0), AssertionVerb.DEGRADED)
        assert degradation_limit(88.0, assertion) is None
        # …and a non-finite baseline cannot produce one either
        assert (
            degradation_limit(
                math.nan,
                _assertion(_relative(at_most_relative=1.5), AssertionVerb.DEGRADED, within=2.0),
            )
            is None
        )

    def test_phase_checks_reject_an_empty_verb_tuple(self) -> None:
        with pytest.raises(InvariantViolationError):
            PhaseChecks()
        assert PhaseChecks(assert_unchanged=("api.error_rate",)).assert_unchanged == (
            "api.error_rate",
        )

    def test_phase_assertion_exposes_its_checks(self) -> None:
        assertion = PhaseAssertion(pre=PhaseChecks(assert_unchanged=("api.error_rate",)))
        assert [phase for phase, _ in assertion.checks()] == [Phase.PRE, Phase.DURING, Phase.POST]
        assert assertion.checks()[0][1] is not None
