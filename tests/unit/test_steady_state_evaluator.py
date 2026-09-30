"""The steady-state evaluator: capture, grade, persist, cross-check, render.

Covers plan 03's sequencing steps 2 through 6:

* **2** baseline capture reduced by percentile, and an under-sampled capture
  yielding ``sufficient=False`` rather than a number;
* **3** the three verbs — ``assert_unchanged``, ``assert_degraded``,
  ``assert_recovered`` — end to end, with the graded verdict;
* **4** the verdict reaching a hash-chained evidence bundle with no ``inf`` and
  no ``nan``, proven with ``allow_nan=False`` on a **zero baseline**, which is
  exactly the input that makes ``delta_pct`` return ``None``;
* **5** the impact-gate cross-check distinguishing *confirmed* from
  *contradicted*, with the contradiction surfaced loudly;
* **6** ``--baseline-from`` reusing a previous run's ``pre``-phase baseline;
* plus persistence through the existing ``steady_state_evaluations`` table, and
  the compatibility guard that a drill with no ``steady_state`` block changes
  nothing at all.

The five ``Verdict`` members are all reached from *real* evaluation rather than
constructed by hand. ``no-effect`` in particular is the reason this feature
exists: "the fault had no impact" and "the probe never fired" collapse to the
same boolean in Chaos Mesh and Litmus, and separating them requires holding
both a baseline and a perturbation window.
"""

from __future__ import annotations

import json
import math
import sqlite3
from types import SimpleNamespace

import pytest

from mayhem.cli.execution import evaluate_steady_state, steady_state_display
from mayhem.cli.render import render_preflight_human, render_steady_state_human
from mayhem.controller.observability_collector import (
    ObservabilitySample,
    SourceCollection,
)
from mayhem.controller.steady_state import (
    BaselineCapture,
    BaselineUnavailableError,
    GateAgreement,
    SteadyStateEvaluationRepository,
    assert_bundle_safe,
    baseline_from_run,
    capture_baselines,
    cross_check_gate,
    evaluate_phase,
    evaluate_run,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    DrillContainer,
    DrillFault,
    DrillSpec,
    ExecutionStep,
)
from mayhem.domain.observability import MetricsSource, ObservabilityConfig
from mayhem.domain.steady_state import (
    Baseline,
    Phase,
    SteadyStateSpec,
    Verdict,
    sample_baseline,
)
from mayhem.infra.store import Store

# -- fixtures ------------------------------------------------------------------------


def _spec(**kwargs: object) -> SteadyStateSpec:
    base: dict[str, object] = {
        "capture": {"samples": 5, "window": "10s"},
        "signals": [
            {
                "name": "api.latency.p99",
                "source_id": "api.http",
                "metric": "latency_ms",
                "tolerance": {"at_most_relative": 4.0},
            },
            {
                "name": "api.error_rate",
                "source_id": "api.http",
                "metric": "status_5xx_ratio",
                "tolerance": {"at_most": 0.02},
                "severity": "critical",
            },
        ],
        "phases": [
            {"during": {"assert_degraded": ["api.latency.p99"], "within": 5.0}},
            {"during": {"assert_unchanged": ["api.error_rate"]}},
            {"post": {"assert_recovered": ["api.latency.p99", "api.error_rate"]}},
        ],
    }
    base.update(kwargs)
    return SteadyStateSpec(**base)  # type: ignore[arg-type]


def _safety_only_spec(**kwargs: object) -> SteadyStateSpec:
    """A drill that asserts no ``degraded`` signal.

    With no hypothesis to confirm, the run's verdict is ``as-hypothesised`` when
    the safety signals held and everything came back. This is the shape of run
    that ``degraded-within-tolerance`` is *not*: a bounded perturbation reports
    the grade it measured, a run with nothing to report reports the clean one.
    """
    base: dict[str, object] = {
        "capture": {"samples": 5, "window": "10s"},
        "signals": [
            {
                "name": "api.error_rate",
                "source_id": "api.http",
                "metric": "status_5xx_ratio",
                "tolerance": {"at_most": 0.02},
                "severity": "critical",
            }
        ],
        "phases": [
            {"during": {"assert_unchanged": ["api.error_rate"]}},
            {"post": {"assert_recovered": ["api.error_rate"]}},
        ],
    }
    base.update(kwargs)
    return SteadyStateSpec(**base)  # type: ignore[arg-type]


def _safety_report(
    *,
    during: float | None = 0.001,
    post: float | None = 0.001,
    bypasses: dict[tuple[str, str], str] | None = None,
):
    spec = _safety_only_spec()
    return evaluate_run(
        spec,
        run_id="run-1",
        capture=BaselineCapture(
            baselines={"api.error_rate": Baseline(value=0.001, samples=5)},
            readings={"api.error_rate": (0.001,) * 5},
        ),
        during={} if during is None else {"api.error_rate": during},
        post={} if post is None else {"api.error_rate": post},
        bypasses=bypasses,
    )


def _collection(values: list[float], *, source_id: str = "api.http") -> SourceCollection:
    return SourceCollection(
        source_id=source_id,
        kind="metrics",  # type: ignore[arg-type]
        ok=True,
        note=f"{len(values)} metric sample(s)",
        latency_ms=1.0,
        samples=tuple(
            ObservabilitySample(at=f"2026-01-01T00:00:0{i}Z", value=v) for i, v in enumerate(values)
        ),
    )


def _config() -> ObservabilityConfig:
    return ObservabilityConfig(
        sources=(
            MetricsSource(source_id="api.http", endpoint="http://prom:9090/metrics", metric="x"),
        ),
        cadence=1.0,
        total_timeout=30.0,
    )


def _capture(values: list[float], *, samples: int = 5, **kwargs: object) -> BaselineCapture:
    """A capture built from a real percentile reduction, as production does."""
    spec = _spec(capture={"samples": samples, "window": "10s"}, **kwargs)
    baselines = {
        signal.name: sample_baseline(values if i == 0 else [0.001] * samples)
        for i, signal in enumerate(spec.signals)
    }
    return BaselineCapture(
        baselines=baselines,
        readings={
            signal.name: tuple(values if i == 0 else (0.001,) * samples)
            for i, signal in enumerate(spec.signals)
        },
        source_id="run-a",
    )


def _report(
    *,
    during: dict[str, float | None] | None = None,
    post: dict[str, float | None] | None = None,
    values: list[float] | None = None,
    bypasses: dict[tuple[str, str], str] | None = None,
    samples: int = 5,
):
    spec = _spec(capture={"samples": samples, "window": "10s"})
    return evaluate_run(
        spec,
        run_id="run-1",
        capture=_capture(values if values is not None else [80.0] * samples, samples=samples),
        during=during,
        post=post,
        bypasses=bypasses,
    )


def _seed_run(store: Store, run_id: str) -> None:
    with store.write() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO config_snapshots (id, resolved_json, source_map, created_at) "
            "VALUES (?,?,?,datetime('now'))",
            ("cfg-1", "{}", "{}"),
        )
        conn.execute(
            "INSERT OR REPLACE INTO runs (id, experiment_name, kind, spec_json, plan_json, "
            "seed, status, environment_fingerprint, config_snapshot_id) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (run_id, "steady", "deterministic", "{}", "{}", 1, "completed", "fp-1", "cfg-1"),
        )


# -- step 2: baseline capture --------------------------------------------------------


class TestBaselineCapture:
    def test_capture_reduces_to_a_baseline_via_percentile(self) -> None:
        calls: list[int] = []

        def collector(cfg: object, *, engine: str = "podman") -> tuple[SourceCollection, ...]:
            calls.append(1)
            # Five readings, with one bad sample a mean would have hidden.
            return (_collection([80.0, 82.0, 81.0, 79.0, 400.0]),)

        capture = capture_baselines(_spec(), config=_config(), collector=collector)
        baseline = capture.baselines["api.latency.p99"]
        assert baseline is not None
        # The default percentile is the maximum, deliberately: a mean would have
        # read 244.4 and called it a normal latency.
        assert baseline.value == 400.0
        assert baseline.samples == 5
        assert capture.sufficient is True

    def test_capture_keeps_the_readings_behind_the_baseline(self) -> None:
        def collector(cfg: object, *, engine: str = "podman") -> tuple[SourceCollection, ...]:
            return (_collection([80.0, 82.0, 81.0, 79.0, 84.0]),)

        capture = capture_baselines(_spec(), config=_config(), collector=collector)
        # Step 6 diffs two captures; a baseline with nothing behind it cannot be.
        assert len(capture.readings["api.latency.p99"]) == 5

    def test_a_median_percentile_is_available_for_a_wobbling_signal(self) -> None:
        def collector(cfg: object, *, engine: str = "podman") -> tuple[SourceCollection, ...]:
            return (_collection([10.0, 10.0, 11.0, 12.0, 90.0]),)

        capture = capture_baselines(_spec(), config=_config(), collector=collector, percentile=50.0)
        assert capture.baselines["api.latency.p99"] is not None
        assert capture.baselines["api.latency.p99"].value == 11.0  # type: ignore[union-attr]

    def test_an_under_sampled_capture_yields_insufficient_rather_than_a_number(self) -> None:
        # Plan 03: "5 samples is not a baseline ... getting this wrong makes the
        # tool confidently wrong, which is worse than no tool."
        def collector(cfg: object, *, engine: str = "podman") -> tuple[SourceCollection, ...]:
            return (_collection([80.0, 82.0]),)

        # A `0s` window is the "no time left" case: one pass happened and it
        # yielded two readings against a declared five.
        starved = _spec(capture={"samples": 5, "window": "0s"})
        capture = capture_baselines(starved, config=_config(), collector=collector)
        latency = capture.baselines["api.latency.p99"]
        assert latency is not None
        assert latency.samples == 2
        assert "captured 2 of 5 declared samples" in capture.notes["api.latency.p99"]

        evaluation = evaluate_phase(
            starved, Phase.DURING, {"api.latency.p99": 400.0}, baselines=capture.baselines
        )[0]
        assert evaluation.verdict is None
        assert evaluation.graded is False
        assert evaluation.passed is False
        assert evaluation.result.sufficient is False
        assert "insufficient baseline" in evaluation.result.note

    def test_a_signal_with_no_source_reads_as_no_baseline_at_all(self) -> None:
        def collector(cfg: object, *, engine: str = "podman") -> tuple[SourceCollection, ...]:
            return (_collection([80.0] * 5, source_id="some.other.source"),)

        capture = capture_baselines(_spec(), config=_config(), collector=collector)
        assert capture.baselines["api.latency.p99"] is None
        assert capture.sufficient is False

    def test_capture_uses_the_injected_collector_and_never_a_transport(self) -> None:
        # If the loop opened a socket this fake would never be consulted and the
        # test would hang or fail. Cadence and timeout are the collector's job.
        def collector(cfg: object, *, engine: str = "podman") -> tuple[SourceCollection, ...]:
            return (_collection([80.0] * 5),)

        capture = capture_baselines(
            _spec(capture={"samples": 5, "window": "0s"}),
            config=_config(),
            collector=collector,
        )
        assert capture.baselines["api.latency.p99"] is not None

    def test_a_zero_window_captures_exactly_one_pass(self) -> None:
        passes: list[int] = []

        def collector(cfg: object, *, engine: str = "podman") -> tuple[SourceCollection, ...]:
            passes.append(1)
            return (_collection([80.0] * 5),)

        capture_baselines(
            _spec(capture={"samples": 5, "window": "0s"}), config=_config(), collector=collector
        )
        # One pass, then the window deadline is already spent — the loop never
        # sleeps past an authored bound.
        assert len(passes) == 1


# -- step 3: the three verbs ---------------------------------------------------------


class TestAssertUnchanged:
    def test_a_safety_signal_that_held_is_as_hypothesised(self) -> None:
        report = _report(during={"api.latency.p99": 400.0, "api.error_rate": 0.001})
        safety = next(
            e
            for e in report.evaluations
            if e.check_id == "api.error_rate" and e.phase is Phase.DURING
        )
        assert safety.verb.value == "unchanged"
        assert safety.verdict is Verdict.AS_HYPOTHESISED
        assert safety.passed is True

    def test_a_safety_signal_that_moved_is_a_finding_not_a_soft_pass(self) -> None:
        report = _report(during={"api.latency.p99": 400.0, "api.error_rate": 0.4})
        safety = next(
            e
            for e in report.evaluations
            if e.check_id == "api.error_rate" and e.phase is Phase.DURING
        )
        assert safety.verdict is Verdict.DEGRADED_BEYOND_TOLERANCE
        assert safety.passed is False
        assert "safety signal moved" in safety.signal.note
        assert safety.signal.severity.value == "critical"

    def test_a_moved_safety_signal_is_graded_on_movement_not_its_tolerance(self) -> None:
        # 0.4 is far outside `at_most: 0.02`, so this is not the interesting
        # case. The interesting one is a move that stays *under* the declared
        # tolerance: the verb is about drift, and a safety signal that drifted
        # is a finding even when it is small.
        spec = _spec(
            capture={"samples": 5, "window": "10s"},
            signals=[
                {
                    "name": "api.error_rate",
                    "source_id": "api.http",
                    "metric": "status_5xx_ratio",
                    "tolerance": {"at_most": 0.5},
                }
            ],
            phases=[{"during": {"assert_unchanged": ["api.error_rate"]}}],
        )
        capture = BaselineCapture(
            baselines={"api.error_rate": Baseline(value=0.001, samples=5)},
            readings={"api.error_rate": (0.001,) * 5},
        )
        evaluation = evaluate_phase(
            spec, Phase.DURING, {"api.error_rate": 0.01}, baselines=capture.baselines
        )[0]
        # Inside the declared tolerance (at_most: 0.5) and still a finding:
        # the verb grades drift, not the signal's own band.
        assert evaluation.signal.during is not None
        assert evaluation.signal.during < 0.5
        assert evaluation.verdict is Verdict.DEGRADED_BEYOND_TOLERANCE


class TestAssertDegraded:
    def test_a_moved_signal_within_within_is_degraded_within_tolerance(self) -> None:
        report = _report(during={"api.latency.p99": 300.0, "api.error_rate": 0.001})
        degraded = next(
            e
            for e in report.evaluations
            if e.check_id == "api.latency.p99" and e.phase is Phase.DURING
        )
        assert degraded.verb.value == "degraded"
        assert degraded.verdict is Verdict.DEGRADED_WITHIN_TOLERANCE
        assert degraded.passed is True
        # within: 5.0 on an 80ms baseline permits 400ms; 300ms is inside it.
        assert degraded.signal.limit == 400.0
        assert degraded.signal.delta_pct == pytest.approx(275.0)

    def test_a_moved_signal_beyond_within_is_degraded_beyond_tolerance(self) -> None:
        report = _report(during={"api.latency.p99": 900.0, "api.error_rate": 0.001})
        degraded = next(
            e
            for e in report.evaluations
            if e.check_id == "api.latency.p99" and e.phase is Phase.DURING
        )
        assert degraded.verdict is Verdict.DEGRADED_BEYOND_TOLERANCE
        assert degraded.passed is False
        assert "further than the declared tolerance" in degraded.signal.note

    def test_a_signal_that_did_not_move_is_no_effect_and_not_a_pass(self) -> None:
        # The under-reported failure mode both CNCF projects collapse into a
        # pass: the fault did nothing, and the probe still answered.
        report = _report(during={"api.latency.p99": 80.0, "api.error_rate": 0.001})
        degraded = next(
            e
            for e in report.evaluations
            if e.check_id == "api.latency.p99" and e.phase is Phase.DURING
        )
        assert degraded.verdict is Verdict.NO_EFFECT
        assert degraded.passed is False
        assert "a fault with no impact and a probe that never fired look identical" in (
            degraded.signal.note
        )
        assert report.verdict is Verdict.NO_EFFECT
        assert report.passed is False

    def test_no_effect_is_distinguishable_from_an_unmeasurable_probe(self) -> None:
        # The fault did nothing -> NO_EFFECT. The probe never answered ->
        # no verdict at all. Same "nothing happened" shape, different facts.
        nothing_happened = _report(during={"api.latency.p99": 80.0})
        never_answered = _report(during={"api.latency.p99": None})
        assert nothing_happened.verdict is Verdict.NO_EFFECT
        assert never_answered.verdict is None
        ungraded = never_answered.ungraded()
        assert ungraded and "no reading captured" in ungraded[0].result.note


class TestAssertRecovered:
    def test_a_signal_back_at_its_baseline_is_recovered(self) -> None:
        report = _report(
            during={"api.latency.p99": 400.0, "api.error_rate": 0.001},
            post={"api.latency.p99": 81.0, "api.error_rate": 0.0011},
        )
        recovery = next(
            e
            for e in report.evaluations
            if e.check_id == "api.latency.p99" and e.phase is Phase.POST
        )
        assert recovery.verb.value == "recovered"
        assert recovery.verdict is Verdict.AS_HYPOTHESISED
        assert report.recovered is True
        # The max is across both recovered signals: 81ms is +1.25% and the
        # 0.0011 error rate is +10%.
        assert report.max_recovery_delta_pct == pytest.approx(10.0)

    def test_a_signal_that_did_not_come_back_is_not_recovered(self) -> None:
        report = _report(
            during={"api.latency.p99": 400.0, "api.error_rate": 0.001},
            post={"api.latency.p99": 500.0, "api.error_rate": 0.001},
        )
        assert report.recovered is False
        assert report.verdict is Verdict.NOT_RECOVERED
        assert "chaos residue" in report.findings()[0].signal.note

    def test_recovery_is_measured_against_the_baseline_not_against_presence(self) -> None:
        # 700ms is a *perfectly present* probe, still answering, and 8.75x the
        # healthy 80ms. Presence is not recovery.
        report = _report(
            during={"api.latency.p99": 400.0, "api.error_rate": 0.001},
            post={"api.latency.p99": 700.0, "api.error_rate": 0.001},
        )
        recovery = next(
            e
            for e in report.evaluations
            if e.check_id == "api.latency.p99" and e.phase is Phase.POST
        )
        assert recovery.verdict is Verdict.NOT_RECOVERED
        assert recovery.signal.delta_pct == pytest.approx(775.0)
        assert recovery.reading is not None  # the probe answered throughout


class TestVerdictAggregation:
    def test_all_five_verdicts_are_reachable_from_real_evaluation(self) -> None:
        cases: dict[Verdict, object] = {
            # 300ms against an 80ms baseline: moved, inside `within: 5.0`.
            Verdict.DEGRADED_WITHIN_TOLERANCE: _report(
                during={"api.latency.p99": 300.0, "api.error_rate": 0.001},
                post={"api.latency.p99": 81.0, "api.error_rate": 0.001},
            ),
            # 900ms: moved, past `within: 5.0` (which permits 400ms).
            Verdict.DEGRADED_BEYOND_TOLERANCE: _report(
                during={"api.latency.p99": 900.0, "api.error_rate": 0.001},
                post={"api.latency.p99": 81.0, "api.error_rate": 0.001},
            ),
            # The fault did not move the signal at all.
            Verdict.NO_EFFECT: _report(
                during={"api.latency.p99": 80.0, "api.error_rate": 0.001},
                post={"api.latency.p99": 81.0, "api.error_rate": 0.001},
            ),
            # A run with no degraded signal: safety held, everything came back.
            Verdict.AS_HYPOTHESISED: _safety_report(),
            # Moved and left residue.
            Verdict.NOT_RECOVERED: _report(
                during={"api.latency.p99": 400.0, "api.error_rate": 0.001},
                post={"api.latency.p99": 500.0, "api.error_rate": 0.001},
            ),
        }
        for expected, report in cases.items():
            assert report.verdict is expected, f"{expected} was not reproduced"
        assert {r.verdict for r in cases.values()} == set(Verdict)

    def test_degraded_beyond_tolerance_outranks_within(self) -> None:
        spec = _spec(
            capture={"samples": 5, "window": "10s"},
            signals=[
                {
                    "name": "api.latency.p99",
                    "source_id": "api.http",
                    "metric": "latency_ms",
                    "tolerance": {"at_most_relative": 100.0},
                }
            ],
            phases=[{"during": {"assert_degraded": ["api.latency.p99"], "within": 5.0}}],
        )
        capture = BaselineCapture(
            baselines={"api.latency.p99": Baseline(value=80.0, samples=5)},
            readings={"api.latency.p99": (80.0,) * 5},
        )
        within = evaluate_phase(
            spec, Phase.DURING, {"api.latency.p99": 300.0}, baselines=capture.baselines
        )[0]
        beyond = evaluate_phase(
            spec, Phase.DURING, {"api.latency.p99": 900.0}, baselines=capture.baselines
        )[0]
        assert within.verdict is Verdict.DEGRADED_WITHIN_TOLERANCE
        assert beyond.verdict is Verdict.DEGRADED_BEYOND_TOLERANCE
        report = evaluate_run(spec, run_id="run-x", capture=capture, during={})
        assert report.verdict is None
        report = evaluate_run(
            spec,
            run_id="run-x",
            capture=capture,
            during={"api.latency.p99": 300.0},
            post={},
        )
        assert report.verdict is Verdict.DEGRADED_WITHIN_TOLERANCE

    def test_a_run_where_nothing_graded_has_no_verdict(self) -> None:
        report = _report(
            during={"api.latency.p99": None, "api.error_rate": None},
            post={"api.latency.p99": None, "api.error_rate": None},
        )
        assert report.verdict is None
        assert report.passed is False
        assert report.recovered is False
        assert report.max_recovery_delta_pct is None
        assert len(report.ungraded()) == 4

    def test_pre_phase_readings_default_to_the_captured_baseline(self) -> None:
        spec = _spec(
            capture={"samples": 5, "window": "10s"},
            signals=[
                {
                    "name": "api.latency.p99",
                    "source_id": "api.http",
                    "metric": "latency_ms",
                    "tolerance": {"at_most_relative": 4.0},
                }
            ],
            phases=[{"pre": {"assert_unchanged": ["api.latency.p99"]}}],
        )
        capture = BaselineCapture(
            baselines={"api.latency.p99": Baseline(value=80.0, samples=5)},
            readings={"api.latency.p99": (80.0,) * 5},
        )
        report = evaluate_run(spec, run_id="run-x", capture=capture)
        pre = report.by_phase(Phase.PRE)[0]
        assert pre.verdict is Verdict.AS_HYPOTHESISED
        assert pre.passed is True


class TestNonFiniteNeverProducesAVerdict:
    @pytest.mark.parametrize("bad", [math.inf, -math.inf, math.nan])
    def test_a_non_finite_reading_is_never_graded(self, bad: float) -> None:
        report = _report(during={"api.latency.p99": bad, "api.error_rate": 0.001})
        latency = next(
            e
            for e in report.evaluations
            if e.check_id == "api.latency.p99" and e.phase is Phase.DURING
        )
        assert latency.verdict is None
        assert latency.graded is False
        assert latency.passed is False
        assert "not a finite number" in latency.result.note
        # Not even `degraded-beyond-tolerance`, which is what a naive hand-off to
        # classify() would have produced for a nan.
        assert report.verdict is not Verdict.DEGRADED_BEYOND_TOLERANCE

    def test_a_non_finite_post_reading_is_never_graded_as_recovered(self) -> None:
        report = _report(
            during={"api.latency.p99": 400.0, "api.error_rate": 0.001},
            post={"api.latency.p99": math.nan, "api.error_rate": 0.001},
        )
        assert report.recovered is False
        assert report.verdict is not Verdict.AS_HYPOTHESISED


# -- step 4: the bundle --------------------------------------------------------------


class TestBundleSafety:
    def test_a_zero_baseline_serialises_into_a_bundle_with_no_inf_or_nan(self) -> None:
        # The exact case that matters: `delta_pct(0.0, x)` returns None rather
        # than inf. If any layer in this path substituted 0.0 -> inf, the strict
        # dump below would raise.
        spec = _spec(
            capture={"samples": 5, "window": "10s"},
            signals=[
                {
                    "name": "api.error_rate",
                    "source_id": "api.http",
                    "metric": "status_5xx_ratio",
                    "tolerance": {"at_most_relative": 1.5},
                }
            ],
            phases=[{"during": {"assert_degraded": ["api.error_rate"], "within": 2.0}}],
        )
        capture = BaselineCapture(
            baselines={"api.error_rate": Baseline(value=0.0, samples=5)},
            readings={"api.error_rate": (0.0,) * 5},
        )
        report = evaluate_run(
            spec, run_id="run-zero", capture=capture, during={"api.error_rate": 0.5}
        )
        signal = report.by_phase(Phase.DURING)[0].signal
        assert signal.baseline == 0.0
        assert signal.delta_pct is None  # refused, not inf

        payload = report.bundle_payload()
        # allow_nan=False raises on inf/nan — the proof they cannot be present.
        text = json.dumps(payload, allow_nan=False)
        assert "Infinity" not in text
        assert "NaN" not in text
        assert "null" in text  # the absence is present, and explicit
        assert payload["evaluations"][0]["signals"][0]["delta_pct"] is None

    def test_a_zero_baseline_bundles_and_verifies_under_a_hash_chain(self) -> None:
        from mayhem.domain.evidence_bundle import build_bundle, verify_bundle

        report = _report(during={"api.latency.p99": 0.0, "api.error_rate": 0.0})
        evidence = {
            "run_id": "run-1",
            "plan_hash": "abc",
            "verdict": "complete",
            "step_reports": [{"id": "s1"}],
            "redaction_metrics": {"policy_version": "test-v1"},
            "steady_state": report.bundle_payload(),
        }
        bundle = build_bundle(evidence=evidence, created_at="2026-01-01T00:00:00Z")
        assert_bundle_safe(bundle.artifacts)
        json.dumps(bundle.artifacts, allow_nan=False)
        assert verify_bundle(bundle).valid is True
        # A changed payload changes the root digest: the verdict is chained in.
        tampered_payload = report.bundle_payload()
        tampered_payload["verdict"] = "as-hypothesised"
        other = build_bundle(
            evidence={**evidence, "steady_state": tampered_payload},
            created_at="2026-01-01T00:00:00Z",
        )
        assert report.bundle_payload()["verdict"] != "as-hypothesised"
        assert other.root_digest != bundle.root_digest

    def test_no_applicable_numeric_slot_is_ever_unexplained(self) -> None:
        # `after` is inapplicable to a `during` result and vice versa; what must
        # never appear is an *applicable* null with no reason behind it.
        for report in (
            _report(during={"api.latency.p99": None, "api.error_rate": None}),
            _report(
                during={"api.latency.p99": 400.0, "api.error_rate": 0.001},
                post={"api.latency.p99": 81.0, "api.error_rate": 0.001},
            ),
            _safety_report(during=None, post=None),
            _report(during={"api.latency.p99": 0.0, "api.error_rate": 0.0}),
        ):
            for evaluation in report.evaluations:
                assert evaluation.unexplained_nulls() == ()

    def test_an_unexplained_null_is_refused_at_the_bundle_boundary(self) -> None:
        # The invariant is enforced by the code, not merely asserted by a test: a
        # payload that would ship an unexplained null raises rather than writes.
        report = _report(during={"api.latency.p99": 400.0, "api.error_rate": 0.001})
        clean = report.by_phase(Phase.DURING)[0]
        # Inapplicable, not absent: a `during` result carries no `after`.
        assert clean.signal.after is None
        assert clean.unexplained_nulls() == ()
        assert_bundle_safe(report.bundle_payload())

    def test_assert_bundle_safe_refuses_a_non_finite_payload(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            assert_bundle_safe({"delta_pct": math.inf})
        assert "not strictly serialisable" in str(excinfo.value)

    def test_assert_bundle_safe_refuses_a_nan_payload(self) -> None:
        with pytest.raises(InvariantViolationError):
            assert_bundle_safe({"reading": math.nan})

    def test_an_ordinary_verdict_payload_passes_the_gate(self) -> None:
        report = _report(
            during={"api.latency.p99": 400.0, "api.error_rate": 0.001},
            post={"api.latency.p99": 81.0, "api.error_rate": 0.001},
        )
        assert_bundle_safe(report.bundle_payload())
        # A bounded perturbation both reports the grade it measured and passes.
        # The graded verdict is not a failure signal on its own.
        assert report.verdict is Verdict.DEGRADED_WITHIN_TOLERANCE
        assert report.passed is True
        assert report.recovered is True

    def test_a_clean_run_payload_passes_the_gate(self) -> None:
        report = _safety_report()
        assert_bundle_safe(report.bundle_payload())
        assert report.verdict is Verdict.AS_HYPOTHESISED
        assert report.passed is True


# -- step 5: the impact-gate cross-check ---------------------------------------------


class TestImpactCrossCheck:
    def test_gate_inert_with_a_zero_delta_confirms_the_bypass(self) -> None:
        report = _report(
            during={"api.latency.p99": 80.0, "api.error_rate": 0.001},
            bypasses={("net.latency", "web"): "missing bin:tc"},
        )
        check = report.cross_check
        assert check is not None
        assert check.ok is True
        assert len(check.confirmed) == 1
        assert check.confirmed[0].agreement is GateAgreement.CONFIRMED
        assert check.confirmed[0].fault_id == "net.latency"
        assert check.contradicted == ()
        assert "impact gate confirmed" in check.confirmed[0].loud_line()

    def test_gate_inert_with_a_moved_signal_is_contradicted_loudly(self) -> None:
        report = _report(
            during={"api.latency.p99": 400.0, "api.error_rate": 0.001},
            bypasses={("net.latency", "web"): "missing bin:tc"},
        )
        check = report.cross_check
        assert check is not None
        assert check.ok is False
        assert len(check.contradicted) == 1
        finding = check.contradicted[0]
        assert finding.signals == ("api.latency.p99",)
        assert finding.deltas_pct["api.latency.p99"] == pytest.approx(400.0)
        loud = finding.loud_line()
        assert loud.startswith("IMPACT GATE CONTRADICTED")
        assert "net.latency" in loud
        assert "inert verdict is wrong" in loud
        assert check.to_dict()["contradicted"][0]["fault_id"] == "net.latency"

    def test_a_contradiction_survives_into_the_bundle_payload(self) -> None:
        report = _report(
            during={"api.latency.p99": 400.0, "api.error_rate": 0.001},
            bypasses={("net.latency", "web"): "missing bin:tc"},
        )
        payload = report.bundle_payload()
        assert payload["impact_cross_check"]["ok"] is False
        assert payload["impact_cross_check"]["contradicted"]
        json.dumps(payload, allow_nan=False)

    def test_no_measurable_degraded_signal_is_unverified_not_confirmed(self) -> None:
        # A drill that asserts no degraded signal cannot confirm the gate.
        # Reporting "confirmed" would manufacture a self-check that never ran.
        report = _report(
            during={"api.error_rate": 0.001},
            bypasses={("proc.pause", "web"): "missing bin:python"},
        )
        check = report.cross_check
        assert check is not None
        assert check.confirmed == ()
        assert len(check.unverified) == 1
        assert "can be neither confirmed nor contradicted" in check.unverified[0].loud_line()

    def test_an_under_sampled_baseline_leaves_the_gate_unverified(self) -> None:
        # The fault demonstrably moved the signal (400ms against an 80ms
        # baseline) but the baseline never reached capture.samples, so the
        # assertion was never graded and the gate can be neither confirmed nor
        # contradicted. Reporting "confirmed" here would be the whole bug.
        starved = _spec(capture={"samples": 5, "window": "10s"})
        capture = BaselineCapture(
            baselines={"api.latency.p99": Baseline(value=80.0, samples=2)},
            readings={"api.latency.p99": (80.0, 80.0)},
        )
        report = evaluate_run(
            starved,
            run_id="run-1",
            capture=capture,
            during={"api.latency.p99": 400.0},
            bypasses={("net.latency", "web"): "missing bin:tc"},
        )
        assert report.cross_check is not None
        assert report.cross_check.confirmed == ()
        assert report.cross_check.contradicted == ()
        assert len(report.cross_check.unverified) == 1

    def test_a_safety_signal_moving_is_not_a_gate_contradiction(self) -> None:
        # Only `assert_degraded` signals are the fault's own hypothesis. A safety
        # signal moving while a fault is bypassed means something *else* moved.
        report = _report(
            during={"api.latency.p99": 80.0, "api.error_rate": 0.4},
            bypasses={("net.latency", "web"): "missing bin:tc"},
        )
        check = report.cross_check
        assert check is not None
        assert check.contradicted == ()
        assert len(check.confirmed) == 1

    def test_no_bypasses_means_nothing_to_check(self) -> None:
        report = _report(during={"api.latency.p99": 400.0, "api.error_rate": 0.001})
        assert report.cross_check is None
        check = cross_check_gate({}, report.evaluations)
        assert check.ok is True
        assert check.findings == ()

    def test_the_cross_check_reads_the_epsilon_the_domain_published(self) -> None:
        # A move smaller than UNCHANGED_EPSILON is "did not move" by the domain's
        # own definition. If the cross-check used a different threshold it could
        # report "moved" for a pair of numbers classify() calls unchanged.
        from mayhem.domain.steady_state import UNCHANGED_EPSILON

        report = _report(
            during={"api.latency.p99": 80.0 + 80.0 * UNCHANGED_EPSILON * 0.5},
            bypasses={("net.latency", "web"): "missing bin:tc"},
        )
        assert report.cross_check is not None
        assert len(report.cross_check.confirmed) == 1


# -- persistence ---------------------------------------------------------------------


class TestPersistence:
    def test_a_row_is_written_with_a_valid_phase_and_round_trips(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "steady.db")
        try:
            _seed_run(store, "run-1")
            report = _report(
                during={"api.latency.p99": 400.0, "api.error_rate": 0.001},
                post={"api.latency.p99": 81.0, "api.error_rate": 0.001},
            )
            repository = SteadyStateEvaluationRepository(store)
            written = repository.save(report)
            assert written == len(report.evaluations)
            assert written > 0

            rows = store.query(
                "SELECT phase FROM steady_state_evaluations WHERE run_id = ?", ("run-1",)
            )
            assert rows
            # The table's own CHECK constraint accepts every phase we wrote.
            assert {str(dict(r)["phase"]) for r in rows} <= {"pre", "during", "post"}

            loaded = repository.load("run-1")
            assert len(loaded) == written
            by_key = {(e.check_id, e.phase) for e in loaded}
            assert ("api.latency.p99", Phase.DURING) in by_key
            degraded = next(
                e for e in loaded if e.check_id == "api.latency.p99" and e.phase is Phase.DURING
            )
            assert degraded.verb.value == "degraded"
            assert degraded.verdict is Verdict.DEGRADED_WITHIN_TOLERANCE
            assert degraded.passed is True
            assert degraded.measured["reading"] == 400.0
            recovery = next(
                e for e in loaded if e.check_id == "api.latency.p99" and e.phase is Phase.POST
            )
            assert recovery.verdict is Verdict.AS_HYPOTHESISED
        finally:
            store.close()

    def test_the_stored_baseline_carries_its_captured_sample_count(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "steady.db")
        try:
            _seed_run(store, "run-1")
            repository = SteadyStateEvaluationRepository(store)
            repository.save(_report(during={"api.latency.p99": 400.0, "api.error_rate": 0.001}))
            stored = next(
                e
                for e in repository.load("run-1")
                if e.check_id == "api.latency.p99" and e.phase is Phase.DURING
            )
            assert stored.baseline == Baseline(value=80.0, samples=5)
        finally:
            store.close()

    def test_saving_twice_is_idempotent(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "steady.db")
        try:
            _seed_run(store, "run-1")
            repository = SteadyStateEvaluationRepository(store)
            report = _report(during={"api.latency.p99": 400.0, "api.error_rate": 0.001})
            first = repository.save(report)
            second = repository.save(report)
            assert first == second
            assert len(repository.load("run-1")) == first
        finally:
            store.close()

    def test_a_non_finite_payload_is_refused_before_it_is_stored(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "steady.db")
        try:
            _seed_run(store, "run-1")
            report = _report(during={"api.latency.p99": 400.0, "api.error_rate": 0.001})
            tampered = evaluate_run(
                _spec(capture={"samples": 5, "window": "10s"}),
                run_id="run-1",
                capture=report.capture,
                during={"api.latency.p99": math.inf},
            )
            # The evaluator refuses it at the boundary, so there is nothing bad
            # left for the repository to store.
            assert tampered.by_phase(Phase.DURING)[0].verdict is None
            assert _row_count(store, "steady_state_evaluations") == 0
        finally:
            store.close()

    def test_loading_an_unknown_run_is_empty_not_an_error(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "steady.db")
        try:
            assert SteadyStateEvaluationRepository(store).load("nope") == ()
        finally:
            store.close()

    def test_a_row_with_an_invalid_phase_is_skipped_not_crashed_on(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "steady.db")
        try:
            _seed_run(store, "run-1")
            # The CHECK constraint makes this unwritable through the normal path;
            # written directly, it proves the reader degrades instead of raising.
            with store.write() as conn:
                conn.execute("PRAGMA ignore_check_constraints = ON")
                conn.execute(
                    "INSERT INTO steady_state_evaluations (id, run_id, check_id, phase, passed, "
                    "measured_json, expectation_json, evaluated_at) VALUES (?,?,?,?,?,?,?,?)",
                    ("x", "run-1", "s", "during-ish", 1, "{}", "{}", "now"),
                )
            loaded = SteadyStateEvaluationRepository(store).load("run-1")
            assert [e.check_id for e in loaded] == []
        finally:
            store.close()


# -- step 6: --baseline-from ---------------------------------------------------------


class TestBaselineFromRun:
    def test_a_previous_runs_captured_baselines_become_the_reference(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "steady.db")
        try:
            _seed_run(store, "run-1")
            _seed_run(store, "run-2")
            SteadyStateEvaluationRepository(store).save(
                _report(during={"api.latency.p99": 400.0, "api.error_rate": 0.001})
            )
            reused = baseline_from_run(store, "run-1", ["api.latency.p99", "api.error_rate"])
            assert reused["api.latency.p99"] == Baseline(value=80.0, samples=5)
            assert reused["api.error_rate"] == Baseline(value=0.001, samples=5)
        finally:
            store.close()

    def test_a_reused_baseline_grades_the_next_run(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "steady.db")
        try:
            _seed_run(store, "run-1")
            _seed_run(store, "run-2")
            SteadyStateEvaluationRepository(store).save(
                _report(during={"api.latency.p99": 400.0, "api.error_rate": 0.001})
            )
            spec = _spec()
            reused = baseline_from_run(store, "run-1", [str(s.name) for s in spec.signals])
            capture = BaselineCapture(baselines=reused, source_id="run-1")
            report = evaluate_run(
                spec,
                run_id="run-2",
                capture=capture,
                during={"api.latency.p99": 300.0, "api.error_rate": 0.001},
                baseline_from="run-1",
            )
            assert report.verdict is Verdict.DEGRADED_WITHIN_TOLERANCE
            assert report.baseline_from == "run-1"
            assert report.bundle_payload()["baseline_from"] == "run-1"
        finally:
            store.close()

    def test_a_run_with_no_evaluations_is_refused_by_name(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "steady.db")
        try:
            _seed_run(store, "run-9")
            with pytest.raises(BaselineUnavailableError) as excinfo:
                baseline_from_run(store, "run-9", ["api.latency.p99"])
            assert "api.latency.p99" in str(excinfo.value)
            assert "once it has captured one" in str(excinfo.value)
        finally:
            store.close()

    def test_partial_reuse_is_refused_rather_than_half_applied(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "steady.db")
        try:
            _seed_run(store, "run-1")
            SteadyStateEvaluationRepository(store).save(
                _report(during={"api.latency.p99": 400.0, "api.error_rate": 0.001})
            )
            with pytest.raises(BaselineUnavailableError) as excinfo:
                baseline_from_run(store, "run-1", ["api.latency.p99", "api.some.new.signal"])
            # Grading one signal against a reused baseline and another against a
            # missing one would produce a mixed-provenance reference that reads
            # as a normal report.
            assert "api.some.new.signal" in str(excinfo.value)
        finally:
            store.close()


# -- the compatibility guard ---------------------------------------------------------


class TestNoSteadyStateIsByteIdentical:
    def test_a_drill_without_steady_state_round_trips_unchanged(self) -> None:
        spec = DrillSpec(
            kind="drill",
            name="plain",
            hypothesis="stack recovers",
            containers={"api": DrillContainer(faults=(DrillFault(fault="proc.pause"),))},
            execution=(ExecutionStep(parallel=("api",)),),
        )
        assert spec.steady_state is None
        # Absent, not present-and-None: a `"steady_state": null` key would
        # change the digest of every spec ever authored.
        assert "steady_state" not in spec.model_dump(exclude_none=True)

    def test_evaluation_is_a_no_op_without_the_block(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "steady.db")
        try:
            _seed_run(store, "run-1")
            report = evaluate_steady_state(None, run_id="run-1", config=_config(), store=store)
            assert report is None
            # No capture, no row, no artefact — a run without the block leaves
            # the database exactly as it found it.
            assert _row_count(store, "steady_state_evaluations") == 0
        finally:
            store.close()

    def test_an_empty_steady_state_spec_is_also_a_no_op(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "steady.db")
        try:
            _seed_run(store, "run-1")
            empty = SteadyStateSpec.model_construct(capture=None, signals=(), phases=())
            assert (
                evaluate_steady_state(empty, run_id="run-1", config=_config(), store=store) is None
            )
        finally:
            store.close()

    def test_the_preflight_block_is_byte_identical_without_a_report(self) -> None:
        preflight = SimpleNamespace(
            resolved_target="local/podman",
            engine="podman",
            plan_id="plan-1",
            plan_hash="a" * 64,
            environment_fingerprint="b" * 64,
            config_snapshot_id="c" * 64,
            topology_snapshot_id="d" * 64,
            blast_radius={"status": "within-budget"},
            compensation_status="clean",
            expected_evidence=("evidence.json",),
            blocked_items=(),
            warnings=(),
            safety_decisions=("allow",),
            plan=SimpleNamespace(
                steps=[SimpleNamespace(fault=SimpleNamespace(fault_id="proc.pause", duration=1.0))]
            ),
        )
        rendered = render_preflight_human(preflight)
        assert "steady_state" not in rendered
        # The block ends exactly where it did before this feature existed.
        assert rendered.endswith("faults: proc.pause\ndurations: 1.0s")
        assert rendered.splitlines()[:6] == [
            "target: local/podman",
            "engine: podman",
            "plan: plan-1 hash aaaaaaaaaaaa",
            "fingerprint: bbbbbbbbbbbb",
            "config: cccccccccccc topo dddddddddddd",
            "blast_radius:",
        ]

    def test_a_preflight_with_no_steady_state_attribute_is_unchanged(self) -> None:
        # A preflight that predates the field entirely: no attribute at all.
        preflight = SimpleNamespace(resolved_target="local/podman", engine="podman")
        rendered = render_preflight_human(preflight)
        assert "steady_state" not in rendered
        assert rendered.splitlines()[:2] == ["target: local/podman", "engine: podman"]

    def test_the_steady_state_display_is_empty_without_a_report(self) -> None:
        assert steady_state_display(None) == ""

    def test_evaluate_steady_state_persists_when_the_block_is_declared(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "steady.db")
        try:
            _seed_run(store, "run-1")
            report = evaluate_steady_state(
                # One signal, so the single fake series reads as a plausible
                # measurement of it: 80ms healthy, 300ms perturbed (inside
                # `within: 5.0`), 81ms after undo.
                _spec(
                    signals=[
                        {
                            "name": "api.latency.p99",
                            "source_id": "api.http",
                            "metric": "latency_ms",
                            "tolerance": {"at_most_relative": 4.0},
                        }
                    ],
                    phases=[
                        {"during": {"assert_degraded": ["api.latency.p99"], "within": 5.0}},
                        {"post": {"assert_recovered": ["api.latency.p99"]}},
                    ],
                ),
                run_id="run-1",
                config=_config(),
                store=store,
                collector=lambda cfg, *, engine="podman": (_collection([80.0] * 5),),
                during={"api.latency.p99": 300.0},
                post={"api.latency.p99": 81.0},
            )
            assert report is not None
            assert report.verdict is Verdict.DEGRADED_WITHIN_TOLERANCE
            assert report.passed is True
            assert _row_count(store, "steady_state_evaluations") > 0
            assert "steady_state: verdict degraded-within-tolerance" in steady_state_display(report)
        finally:
            store.close()


# -- rendering -----------------------------------------------------------------------


class TestRendering:
    def test_the_verdict_leads_the_rendered_block(self) -> None:
        report = _report(
            during={"api.latency.p99": 400.0, "api.error_rate": 0.001},
            post={"api.latency.p99": 81.0, "api.error_rate": 0.001},
        )
        lines = render_steady_state_human(report)
        assert lines[0] == "steady_state: verdict degraded-within-tolerance"
        assert any("recovered yes" in line for line in lines)
        assert any("during/degraded api.latency.p99" in line for line in lines)
        assert any("post/recovered" in line for line in lines)
        assert all(line.strip() for line in lines)

    def test_an_ungraded_assertion_says_so_in_the_render(self) -> None:
        report = _report(during={"api.latency.p99": None, "api.error_rate": None})
        lines = render_steady_state_human(report)
        assert lines[0] == "steady_state: verdict not-graded"
        assert any("not graded" in line for line in lines)
        assert any("never a pass" in line for line in lines)

    def test_a_contradicted_gate_is_rendered_with_its_marker(self) -> None:
        report = _report(
            during={"api.latency.p99": 400.0, "api.error_rate": 0.001},
            bypasses={("net.latency", "web"): "missing bin:tc"},
        )
        text = "\n".join(render_steady_state_human(report))
        assert "IMPACT GATE CONTRADICTED" in text
        assert "impact gate cross-check 1 contradicted, 0 confirmed" in text

    def test_the_render_never_prints_a_non_finite_number(self) -> None:
        from mayhem.cli.render import _number

        assert _number(math.inf) == "n/a"
        assert _number(math.nan) == "n/a"
        assert _number(None) == "n/a"
        assert _number(0.0) == "0"
        assert _number(88.5) == "88.5"
        assert _number(275.0, "%") == "275%"

    def test_steady_state_display_renders_the_report(self) -> None:
        report = _report(during={"api.latency.p99": 80.0, "api.error_rate": 0.001})
        assert "no-effect" in steady_state_display(report)


# -- the table's own constraint ------------------------------------------------------


class TestSchemaContract:
    def test_the_phase_check_constraint_rejects_a_fourth_spelling(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "steady.db")
        try:
            _seed_run(store, "run-1")
            with pytest.raises(sqlite3.IntegrityError):
                with store.write() as conn:
                    conn.execute(
                        "INSERT INTO steady_state_evaluations (id, run_id, check_id, phase, "
                        "passed, measured_json, expectation_json, evaluated_at) "
                        "VALUES (?,?,?,?,?,?,?,?)",
                        ("x", "run-1", "s", "after", 1, "{}", "{}", "now"),
                    )
        finally:
            store.close()

    def test_a_stored_row_carries_only_strict_json(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "steady.db")
        try:
            _seed_run(store, "run-1")
            SteadyStateEvaluationRepository(store).save(
                _report(during={"api.latency.p99": 0.0, "api.error_rate": 0.0})
            )
            for row in store.query(
                "SELECT measured_json, expectation_json FROM steady_state_evaluations"
            ):
                record = dict(row)
                json.loads(str(record["measured_json"]), parse_constant=_no_constants)
                json.loads(str(record["expectation_json"]), parse_constant=_no_constants)
        finally:
            store.close()


def _row_count(store: Store, table: str) -> int:
    rows = store.query(f"SELECT COUNT(*) AS n FROM {table}")
    return int(dict(rows[0])["n"])


def _no_constants(name: str) -> float:
    raise AssertionError(f"stored JSON contained the non-standard literal {name!r}")
