"""Run comparison: what may be compared, what may not, and what a refusal says.

Why this file exists
--------------------
Plan 22's gap 102 is "compare equivalent experiments across releases". Two
things can go wrong with that, and both are silent:

* **Comparing things that are not equivalent.** A latency delta between a run
  under policy 7 and a run under policy 8 measures the policy change too.
  Report it as a resilience regression and the signal becomes noise that people
  learn to ignore. So the pins must match, and a mismatch is a *refusal* with
  no numbers in it — not a comparison that happens to come out flat.
* **Comparing things that could not be measured.** A metric missing from one
  run is not a metric with value 0. Report it as unchanged and the release looks
  healthy on the strength of a probe that never fired.

So the tests are grouped as:

* **the equivalence predicate.** Which axes must match, which is the axis the
  comparison is about, and the refusal that names the axes that moved.
* **the four fixture verdicts.** Improved, regressed, incomparable,
  insufficient-data — the plan's own matrix.
* **the decision order.** A proven regression outranks a missing metric;
  insufficient data outranks a pass. A comparison with nothing declared is
  insufficient, never improved.
* **the negative controls.** A run compared with itself, a report that is
  incomparable *and* carries deltas, a graded verdict with no metric graded, a
  finding opened from anything but a regression, a run pin whose evidence
  digest is not a sha256 — each refused at construction.
* **the plan's own worked example.** v2.4 → v2.5 crossing a 20% latency
  tolerance, which is the regression phase 2 has to detect from fixture runs.

The last test re-states the domain law locally: this module may not import the
toolkit, agents, controller, infra, or the IO modules. ``pyproject.toml``'s
import-linter contract enforces the same thing in CI, but that check needs an
extra dependency, so the guard also lives here.
"""

from __future__ import annotations

import ast
import math
from typing import TYPE_CHECKING, Any

import pytest

import mayhem.domain.comparison as comparison_module
from mayhem.domain.comparison import (
    EQUIVALENCE_FIELDS,
    RELEASE_FIELD,
    ComparisonMetric,
    ComparisonOutcome,
    DeltaReport,
    MetricDelta,
    MetricKind,
    RegressionFinding,
    RunPin,
    RunReport,
    RunSample,
    compare,
    equivalent_pins,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.journeys import JourneyPin

if TYPE_CHECKING:
    from collections.abc import Sequence

# ── fixtures ────────────────────────────────────────────────────────────────────

JOURNEY_PIN = JourneyPin(name="checkout-journey", version="1.0.0", digest="a" * 64)

#: sha256-shaped digests standing in for the two runs' sealed evidence bundles.
BASE_DIGEST = "0" * 64
CANDIDATE_DIGEST = "1" * 64


def _pin(**overrides: Any) -> RunPin:
    """A pinned v2.4 run; override any axis, including the release."""
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
        "journey": JOURNEY_PIN,
    }
    fields.update(overrides)
    return RunPin(**fields)


def _report(pin: RunPin, samples: Sequence[RunSample]) -> RunReport:
    return RunReport(pin=pin, metrics=tuple(samples))


def _sample(metric: str, value: float | None, samples: int = 10) -> RunSample:
    return RunSample(metric=metric, value=value, samples=samples)


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
RECOVERY = ComparisonMetric(
    name="recovery_seconds",
    kind=MetricKind.RECOVERY,
    unit="s",
    tolerance_pct=10.0,
)
THROUGHPUT = ComparisonMetric(
    name="orders_per_minute",
    kind=MetricKind.BUSINESS,
    unit="per_minute",
    tolerance_pct=5.0,
    higher_is_worse=False,
)


def _baseline_report() -> RunReport:
    return _report(
        _pin(),
        (
            _sample("p95_latency_ms", 200.0),
            _sample("checkout_error_rate", 0.02),
            _sample("recovery_seconds", 30.0),
            _sample("orders_per_minute", 100.0),
        ),
    )


def _candidate_report(**pin_overrides: Any) -> RunReport:
    pin = _pin(
        run_id="run-v25-0001",
        release="v2.5",
        evidence_digest=CANDIDATE_DIGEST,
        **pin_overrides,
    )
    return _report(
        pin,
        (
            _sample("p95_latency_ms", 200.0),
            _sample("checkout_error_rate", 0.02),
            _sample("recovery_seconds", 30.0),
            _sample("orders_per_minute", 100.0),
        ),
    )


METRICS = (LATENCY, ERROR_RATE, RECOVERY, THROUGHPUT)

# ── the equivalence predicate ───────────────────────────────────────────────────


def test_two_runs_of_the_same_experiment_on_a_new_release_are_equivalent() -> None:
    """The plan's acceptance case: same pins, new release, comparison happens."""
    baseline, candidate = _baseline_report(), _candidate_report()

    assert equivalent_pins(baseline.pin, candidate.pin)
    assert baseline.pin.differences_from(candidate.pin) == ()
    assert baseline.pin.release_differences(candidate.pin) == (RELEASE_FIELD,)


def test_the_release_is_not_one_of_the_axes_that_must_match() -> None:
    assert RELEASE_FIELD not in EQUIVALENCE_FIELDS
    assert "release" not in _pin().equivalence_key


def test_a_seed_difference_does_not_make_runs_incomparable() -> None:
    """Draw-to-draw noise is what ``tolerance_pct`` absorbs, not a refusal.

    Nightly runs pick a fresh seed; if the seed were an equivalence axis, the
    continuous comparison plan 22 gap 104 asks for could never fire.
    """
    seeded = _pin(run_id="run-v24-seeded", seed=7)

    assert equivalent_pins(_pin(), seeded)
    assert "seed" not in EQUIVALENCE_FIELDS


@pytest.mark.parametrize(
    "axis",
    [
        "experiment",
        "environment",
        "plan_version",
        "policy_version",
        "catalog_version",
        "agent_version",
        "runtime_version",
    ],
)
def test_every_pinned_axis_must_match(axis: str) -> None:
    other = _candidate_report(**{axis: "different"}).pin

    assert not equivalent_pins(_pin(), other)
    assert other.differences_from(_pin()) == (axis,)


def test_a_repin_journey_makes_two_runs_incomparable() -> None:
    repinned = _candidate_report(
        journey=JourneyPin(name="checkout-journey", version="2.0.0", digest="b" * 64)
    ).pin

    assert repinned.differences_from(_pin()) == ("journey",)


def test_a_release_difference_is_reported_separately_from_refusal() -> None:
    same_release = _pin(run_id="run-repeat-0002")

    assert equivalent_pins(_pin(), same_release)
    assert same_release.release_differences(_pin()) == ()


def test_a_pin_labels_itself_with_the_three_things_a_report_quotes() -> None:
    pin = _pin()

    assert pin.label == "checkout-resilience@v2.4#run-v24-0001"


# ── the four fixture verdicts ───────────────────────────────────────────────────


def test_an_identical_release_is_unchanged() -> None:
    report = compare(_baseline_report(), _candidate_report(), METRICS)

    assert report.outcome is ComparisonOutcome.UNCHANGED
    assert report.scored
    assert not report.improved
    assert not report.regressed
    assert report.cited_runs == ("run-v24-0001", "run-v25-0001")
    assert all(delta.within_tolerance for delta in report.deltas)


def test_a_faster_cheaper_candidate_is_improved() -> None:
    candidate = _report(
        _candidate_report().pin,
        (
            _sample("p95_latency_ms", 120.0),
            _sample("checkout_error_rate", 0.01),
            _sample("recovery_seconds", 20.0),
            _sample("orders_per_minute", 130.0),
        ),
    )

    report = compare(_baseline_report(), candidate, METRICS)

    assert report.outcome is ComparisonOutcome.IMPROVED
    assert report.improved
    assert report.regressions == ()
    assert all(delta.improved for delta in report.deltas)


def test_a_slower_candidate_is_regressed_and_says_which_metric_moved() -> None:
    candidate = _report(
        _candidate_report().pin,
        (
            _sample("p95_latency_ms", 280.0),
            _sample("checkout_error_rate", 0.02),
            _sample("recovery_seconds", 30.0),
            _sample("orders_per_minute", 100.0),
        ),
    )

    report = compare(_baseline_report(), candidate, METRICS)

    assert report.outcome is ComparisonOutcome.REGRESSED
    assert report.regressed
    assert [delta.metric for delta in report.regressions] == ["p95_latency_ms"]
    assert "p95_latency_ms" in report.reasons[0]
    assert "20.0%" in report.reasons[0]
    assert report.delta_for("p95_latency_ms") is not None
    assert report.delta_for("p95_latency_ms").delta == 80.0  # type: ignore[union-attr]


def test_a_move_inside_the_tolerance_is_not_a_regression() -> None:
    """19% latency rise on a 20% tolerance: a move, reported, and not a finding.

    A tool that calls every wobble a regression gets muted, and a muted
    regression tool catches nothing.
    """
    candidate = _report(
        _candidate_report().pin,
        (
            _sample("p95_latency_ms", 238.0),
            _sample("checkout_error_rate", 0.02),
            _sample("recovery_seconds", 30.0),
            _sample("orders_per_minute", 100.0),
        ),
    )

    report = compare(_baseline_report(), candidate, METRICS)

    assert report.outcome is ComparisonOutcome.UNCHANGED
    latency = report.delta_for("p95_latency_ms")
    assert latency is not None
    assert latency.delta_pct == pytest.approx(19.0)
    assert latency.within_tolerance
    assert latency.worse is False


def test_the_plans_worked_example_v24_to_v25_crosses_the_tolerance() -> None:
    """Plan 22 phase 2's acceptance case, decided here by the pure model."""
    candidate = _report(
        _candidate_report().pin,
        (
            _sample("p95_latency_ms", 260.0),  # +30% against a 20% tolerance
            _sample("checkout_error_rate", 0.02),
        ),
    )

    report = compare(_baseline_report(), candidate, (LATENCY, ERROR_RATE))

    assert report.outcome is ComparisonOutcome.REGRESSED
    assert report.regressions[0].delta_pct == pytest.approx(30.0)


def test_a_business_kpi_moving_the_right_way_is_an_improvement() -> None:
    """More orders per minute is better — the direction is declared, not guessed."""
    candidate = _report(
        _candidate_report().pin,
        (
            _sample("p95_latency_ms", 200.0),
            _sample("checkout_error_rate", 0.02),
            _sample("recovery_seconds", 30.0),
            _sample("orders_per_minute", 60.0),  # throughput halved
        ),
    )

    report = compare(_baseline_report(), candidate, METRICS)

    assert report.outcome is ComparisonOutcome.REGRESSED
    assert [delta.metric for delta in report.regressions] == ["orders_per_minute"]


def test_different_pins_are_incomparable_and_carry_no_deltas() -> None:
    """The negative control: refused, not scored."""
    candidate = _report(
        _candidate_report(policy_version="policy-8").pin,
        (_sample("p95_latency_ms", 5000.0),),
    )

    report = compare(_baseline_report(), candidate, METRICS)

    assert report.outcome is ComparisonOutcome.INCOMPARABLE
    assert report.deltas == ()
    assert not report.scored
    assert not report.improved
    assert not report.regressed
    assert report.reasons[0] == "runs are not comparable: policy_version differs"


def test_an_incomparable_report_still_cites_both_runs_it_refused() -> None:
    report = compare(_baseline_report(), _candidate_report(agent_version="agent-2"), METRICS)

    assert report.outcome is ComparisonOutcome.INCOMPARABLE
    assert report.cited_runs == ("run-v24-0001", "run-v25-0001")
    assert "agent_version" in report.reasons[0]


def test_several_differing_axes_are_all_named_in_the_refusal() -> None:
    candidate = _candidate_report(policy_version="policy-8", environment="prod").pin

    differences = candidate.differences_from(_pin())

    assert differences == ("environment", "policy_version")
    assert (
        "environment, policy_version differ"
        in compare(_baseline_report(), _report(candidate, ()), METRICS).reasons[0]
    )


def test_a_metric_missing_from_one_run_is_insufficient_not_a_pass() -> None:
    candidate = _report(
        _candidate_report().pin,
        (
            _sample("p95_latency_ms", 200.0),
            _sample("checkout_error_rate", 0.02),
        ),
    )

    report = compare(_baseline_report(), candidate, METRICS)

    assert report.outcome is ComparisonOutcome.INSUFFICIENT_DATA
    assert not report.improved
    assert not report.regressed
    assert not report.scored
    assert any("recovery_seconds on run run-v25-0001" in reason for reason in report.reasons)
    assert [delta.metric for delta in report.ungraded] == [
        "recovery_seconds",
        "orders_per_minute",
    ]


def test_an_unmeasured_value_is_insufficient_rather_than_zero() -> None:
    """A probe that returned nothing must not be graded as a perfect 0.0."""
    candidate = _report(
        _candidate_report().pin,
        (
            _sample("p95_latency_ms", None),
            _sample("checkout_error_rate", 0.02),
        ),
    )

    report = compare(_baseline_report(), candidate, (LATENCY, ERROR_RATE))

    assert report.outcome is ComparisonOutcome.INSUFFICIENT_DATA
    assert report.delta_for("p95_latency_ms") is not None
    assert report.delta_for("p95_latency_ms").worse is None  # type: ignore[union-attr]
    # "Not measured" and "measured as nothing" are different claims, and the
    # report has to say which one this is.
    assert report.reasons == ("p95_latency_ms on run run-v25-0001 was not measured",)


@pytest.mark.parametrize("bad", [math.nan, math.inf])
def test_a_non_finite_measurement_is_never_graded(bad: float) -> None:
    candidate = _report(
        _candidate_report().pin,
        (_sample("p95_latency_ms", bad), _sample("checkout_error_rate", 0.02)),
    )

    report = compare(_baseline_report(), candidate, (LATENCY, ERROR_RATE))

    assert report.outcome is ComparisonOutcome.INSUFFICIENT_DATA
    assert report.delta_for("p95_latency_ms") is not None
    assert report.delta_for("p95_latency_ms").graded is False  # type: ignore[union-attr]


def test_an_under_sampled_metric_is_insufficient() -> None:
    """Two samples is not a baseline — the same rule steady-state applies."""
    strict = ComparisonMetric(
        name="p95_latency_ms",
        kind=MetricKind.LATENCY,
        unit="ms",
        tolerance_pct=20.0,
        required_samples=5,
    )
    candidate = _report(
        _candidate_report().pin,
        (_sample("p95_latency_ms", 200.0, samples=2), _sample("checkout_error_rate", 0.02)),
    )

    report = compare(_baseline_report(), candidate, (strict, ERROR_RATE))

    assert report.outcome is ComparisonOutcome.INSUFFICIENT_DATA
    assert "2 samples, 5 required" in report.reasons[0]


def test_a_comparison_with_no_declared_metrics_is_insufficient_not_a_pass() -> None:
    report = compare(_baseline_report(), _candidate_report())

    assert report.outcome is ComparisonOutcome.INSUFFICIENT_DATA
    assert not report.improved
    assert report.deltas == ()
    assert "not a pass" in report.reasons[0]


# ── the decision order ─────────────────────────────────────────────────────────


def test_a_proven_regression_outranks_a_metric_that_could_not_be_measured() -> None:
    """The bell that rang does not stop ringing because another probe was silent."""
    candidate = _report(
        _candidate_report().pin,
        (_sample("p95_latency_ms", 400.0),),
    )

    report = compare(_baseline_report(), candidate, METRICS)

    assert report.outcome is ComparisonOutcome.REGRESSED
    assert [delta.metric for delta in report.regressions] == ["p95_latency_ms"]
    assert len(report.ungraded) == 3


def test_insufficient_data_outranks_an_improvement_on_the_metrics_that_did_move() -> None:
    candidate = _report(
        _candidate_report().pin,
        (
            _sample("p95_latency_ms", 100.0),
            _sample("checkout_error_rate", 0.01),
        ),
    )

    report = compare(_baseline_report(), candidate, METRICS)

    assert report.outcome is ComparisonOutcome.INSUFFICIENT_DATA
    assert not report.improved
    assert [delta.metric for delta in report.ungraded] == ["recovery_seconds", "orders_per_minute"]


def test_a_zero_baseline_is_never_within_tolerance_of_anything_else() -> None:
    """``0`` has no scale, so the relative bound is undefined rather than infinite."""
    baseline = _report(_pin(run_id="run-zero"), (_sample("checkout_error_rate", 0.0),))
    candidate = _report(
        _pin(run_id="run-nonzero", release="v2.5"), (_sample("checkout_error_rate", 0.05),)
    )

    report = compare(baseline, candidate, (ERROR_RATE,))
    delta = report.delta_for("checkout_error_rate")

    assert delta is not None
    assert delta.delta_pct is None
    assert not delta.within_tolerance
    assert delta.worse is True
    assert report.outcome is ComparisonOutcome.REGRESSED
    assert "relative change is undefined" in report.reasons[0]


# ── negative controls ───────────────────────────────────────────────────────────


def test_a_run_cannot_be_compared_with_itself() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        compare(_baseline_report(), _baseline_report(), METRICS)

    assert excinfo.value.rule == "comparison.same_run"
    assert "cannot be compared with itself" in str(excinfo.value)


def test_an_incomparable_report_cannot_be_built_carrying_deltas() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        DeltaReport(
            outcome=ComparisonOutcome.INCOMPARABLE,
            baseline=_pin(),
            candidate=_candidate_report().pin,
            deltas=(
                MetricDelta(
                    metric="p95_latency_ms",
                    kind=MetricKind.LATENCY,
                    unit="ms",
                    baseline=200.0,
                    candidate=280.0,
                    delta=80.0,
                    delta_pct=40.0,
                    worse=True,
                    improved=False,
                    within_tolerance=False,
                    tolerance_pct=20.0,
                    required_samples=1,
                ),
            ),
        )

    assert excinfo.value.rule == "comparison.scored_while_incomparable"
    assert "refused, not scored" in str(excinfo.value)


def test_a_graded_verdict_with_nothing_graded_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        DeltaReport(
            outcome=ComparisonOutcome.IMPROVED,
            baseline=_pin(),
            candidate=_candidate_report().pin,
        )

    assert excinfo.value.rule == "comparison.graded_without_metrics"
    assert "pass by absence" in str(excinfo.value)


def test_a_run_pin_without_a_citable_evidence_digest_cannot_be_written() -> None:
    with pytest.raises(ValueError, match=r"string_pattern_mismatch|^$"):
        _pin(evidence_digest="not-a-digest")

    with pytest.raises(ValueError, match="string_too_short"):
        _pin(run_id="")


def test_a_finding_needs_two_cited_runs_and_can_only_be_a_regression() -> None:
    improved = compare(_baseline_report(), _candidate_report(), METRICS)

    with pytest.raises(InvariantViolationError) as excinfo:
        RegressionFinding(finding_id="F-1", report=improved, summary="everything got better")

    assert excinfo.value.rule == "comparison.finding_without_regression"
    assert "false alarm" in str(excinfo.value)


def test_a_finding_must_say_why_and_must_be_named() -> None:
    regressed = compare(
        _baseline_report(),
        _report(
            _candidate_report().pin,
            (_sample("p95_latency_ms", 400.0), _sample("checkout_error_rate", 0.02)),
        ),
        (LATENCY, ERROR_RATE),
    )

    with pytest.raises(InvariantViolationError) as excinfo:
        RegressionFinding(finding_id="F-1", report=regressed, summary="   ")

    assert excinfo.value.rule == "comparison.finding_unexplained"

    with pytest.raises(InvariantViolationError) as named:
        RegressionFinding(finding_id="  ", report=regressed, summary="p95 latency rose")

    assert named.value.rule == "comparison.finding_unnamed"


def test_a_finding_opened_from_a_regression_cites_exactly_two_runs() -> None:
    baseline = _baseline_report()
    candidate = _report(
        _candidate_report().pin,
        (
            _sample("p95_latency_ms", 400.0),
            _sample("checkout_error_rate", 0.02),
            _sample("recovery_seconds", 30.0),
            _sample("orders_per_minute", 100.0),
        ),
    )

    finding = RegressionFinding.open(
        "F-22",
        baseline,
        candidate,
        METRICS,
        summary="v2.5 doubled p95 checkout latency against a 20% tolerance",
    )

    assert finding.cited_runs == ("run-v24-0001", "run-v25-0001")
    assert finding.baseline_run == "run-v24-0001"
    assert finding.candidate_run == "run-v25-0001"
    assert finding.regressed_metrics == ("p95_latency_ms",)
    payload: dict[str, Any] = finding.to_dict()
    assert payload["cited_runs"] == ["run-v24-0001", "run-v25-0001"]
    assert payload["report"]["outcome"] == "regressed"


def test_a_finding_refuses_to_open_from_an_insufficient_comparison() -> None:
    candidate = _report(_candidate_report().pin, (_sample("p95_latency_ms", 200.0),))

    with pytest.raises(InvariantViolationError) as excinfo:
        RegressionFinding.open("F-2", _baseline_report(), candidate, METRICS, summary="??")

    assert excinfo.value.rule == "comparison.finding_without_regression"


# ── metric declarations ─────────────────────────────────────────────────────────


def test_a_business_metric_must_declare_which_direction_is_worse() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        ComparisonMetric(name="orders_per_minute", kind=MetricKind.BUSINESS)

    assert excinfo.value.rule == "comparison.business_metric_undecidable"
    assert "reported as an improvement" in str(excinfo.value)


def test_non_business_kinds_know_their_own_direction() -> None:
    assert LATENCY.worse_direction
    assert ERROR_RATE.worse_direction
    assert RECOVERY.worse_direction
    assert not THROUGHPUT.worse_direction
    assert ComparisonMetric(
        name="queue_lag", kind=MetricKind.BUSINESS, higher_is_worse=True
    ).worse_direction


@pytest.mark.parametrize("bad", [math.nan, math.inf, -1.0])
def test_a_tolerance_that_is_not_a_real_percentage_is_refused(bad: float) -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        ComparisonMetric(
            name="p95_latency_ms",
            kind=MetricKind.LATENCY,
            unit="ms",
            tolerance_pct=bad,
        )

    assert excinfo.value.rule == "comparison.tolerance_not_finite"


def test_a_run_may_not_report_the_same_metric_twice() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _report(_pin(), (_sample("p95_latency_ms", 200.0), _sample("p95_latency_ms", 210.0)))

    assert excinfo.value.rule == "comparison.duplicate_metric_sample"
    assert "the delta arbitrary" in str(excinfo.value)


def test_an_unsupported_run_pin_schema_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _pin(schema_version="9.9")

    assert excinfo.value.rule == "comparison.unsupported_schema"


def test_a_report_serialises_with_its_cited_runs_and_reasons() -> None:
    report = compare(_baseline_report(), _candidate_report(policy_version="policy-8"), METRICS)
    payload: dict[str, Any] = report.to_dict()

    assert payload["outcome"] == "incomparable"
    assert payload["scored"] is False
    assert payload["cited_runs"] == ["run-v24-0001", "run-v25-0001"]
    assert payload["deltas"] == []
    assert payload["baseline"]["label"] == "checkout-resilience@v2.4#run-v24-0001"


# ── the domain law, restated where the module lives ────────────────────────────

_FORBIDDEN_STDLIB = frozenset({"asyncio", "socket", "subprocess", "sqlite3", "pathlib", "os"})
_FORBIDDEN_LAYERS = ("mayhem.toolkit", "mayhem.agents", "mayhem.controller", "mayhem.infra")


def test_comparison_imports_nothing_the_domain_may_not_import() -> None:
    source = open(comparison_module.__file__, encoding="utf-8").read()  # noqa: SIM115, PTH123
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module)
    assert not imported & _FORBIDDEN_STDLIB
    assert not [name for name in sorted(imported) if name.startswith(_FORBIDDEN_LAYERS)]
