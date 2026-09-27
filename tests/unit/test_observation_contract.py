"""v0.9.0 expansion task 13: provider-neutral observation contracts."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from mayhem.domain.observations import (
    CriterionKind,
    CriterionOperator,
    ObservationProvider,
    ObservationQuery,
    ObservationResult,
    ObservationStatus,
    SloCriterion,
    collect,
    evaluate_all,
    provenance_summary,
)


def _obs(metric: str, value: float | None, status: ObservationStatus = ObservationStatus.OK):
    return ObservationResult(metric=metric, value=value, unit="ms", window_s=60.0, status=status)


# ── criteria ─────────────────────────────────────────────────────────────────
def test_latency_threshold_passes_and_fails() -> None:
    criterion = SloCriterion(
        kind=CriterionKind.LATENCY,
        metric="http.latency",
        operator=CriterionOperator.LTE,
        threshold=250.0,
    )
    assert criterion.evaluate(_obs("http.latency", 120.0)).passed is True
    outcome = criterion.evaluate(_obs("http.latency", 900.0))
    assert outcome.passed is False
    assert "900.0ms violates lte 250.0ms" in outcome.reason


def test_error_budget_threshold() -> None:
    criterion = SloCriterion(
        kind=CriterionKind.ERROR_BUDGET,
        metric="http.errors",
        operator=CriterionOperator.LTE,
        threshold=0.01,
        unit="ratio",
    )
    assert (
        criterion.evaluate(
            _obs(
                "http.errors",
                0.001,
            )
        ).passed
        is True
    )
    assert criterion.evaluate(_obs("http.errors", 0.2)).passed is False


def test_recovery_time_threshold() -> None:
    criterion = SloCriterion(
        kind=CriterionKind.RECOVERY_TIME,
        metric="recovery.time",
        operator=CriterionOperator.LT,
        threshold=30.0,
        unit="s",
    )
    assert criterion.evaluate(_obs("recovery.time", 12.0)).passed is True
    assert criterion.evaluate(_obs("recovery.time", 45.0)).passed is False


def test_saturation_threshold() -> None:
    criterion = SloCriterion(
        kind=CriterionKind.SATURATION,
        metric="cpu.saturation",
        operator=CriterionOperator.LTE,
        threshold=0.8,
        unit="ratio",
    )
    assert criterion.evaluate(_obs("cpu.saturation", 0.95)).passed is False


def test_absence_criterion() -> None:
    criterion = SloCriterion(
        kind=CriterionKind.ABSENCE,
        metric="errors.logged",
        operator=CriterionOperator.EQ,
        threshold=0.0,
        unit="count",
    )
    assert criterion.evaluate(_obs("errors.logged", 0.0)).passed is True
    assert criterion.evaluate(_obs("errors.logged", 3.0)).passed is False


@pytest.mark.parametrize("status", [ObservationStatus.MISSING, ObservationStatus.ERROR])
def test_missing_observation_fails_instead_of_passing(status: ObservationStatus) -> None:
    criterion = SloCriterion(
        kind=CriterionKind.LATENCY,
        metric="http.latency",
        operator=CriterionOperator.LTE,
        threshold=1000.0,
    )
    outcome = criterion.evaluate(_obs("http.latency", None, status))
    assert outcome.passed is False
    assert "unavailable" in outcome.reason


def test_zero_is_not_treated_as_missing() -> None:
    criterion = SloCriterion(
        kind=CriterionKind.SATURATION,
        metric="cpu",
        operator=CriterionOperator.LTE,
        threshold=0.5,
        unit="ratio",
    )
    outcome = criterion.evaluate(_obs("cpu", 0.0))
    assert outcome.passed is True
    assert outcome.observed == 0.0


def test_criterion_round_trips_to_dict() -> None:
    payload = SloCriterion(
        kind=CriterionKind.LATENCY, metric="m", operator=CriterionOperator.LT, threshold=1.0
    ).to_dict()
    assert payload["kind"] == "latency"
    assert payload["operator"] == "lt"
    assert json.loads(json.dumps(payload))["criterion_id"]


# ── providers ────────────────────────────────────────────────────────────────
class _FakeProvider:
    name = "fake"

    def __init__(self, values: dict[str, float]) -> None:
        self.values = values
        self.seen: list[ObservationQuery] = []

    def observe(self, query: ObservationQuery) -> ObservationResult:
        self.seen.append(query)
        if query.metric not in self.values:
            return ObservationResult(
                metric=query.metric,
                value=None,
                unit=query.unit,
                window_s=query.window_s,
                status=ObservationStatus.MISSING,
                provenance=self.name,
            )
        return ObservationResult(
            metric=query.metric,
            value=self.values[query.metric],
            unit=query.unit,
            window_s=query.window_s,
            provenance=self.name,
            source="fake",
        )


def test_fake_provider_satisfies_the_protocol() -> None:
    provider = _FakeProvider({})
    assert isinstance(provider, ObservationProvider)


def test_collect_is_deterministic_for_a_fake_provider() -> None:
    provider = _FakeProvider({"a": 1.0, "b": 2.0})
    queries = (ObservationQuery(metric="a"), ObservationQuery(metric="b"))
    first = collect(provider, queries)
    second = collect(provider, queries)
    assert [r.to_dict() for r in first] == [r.to_dict() for r in second]
    assert [r.metric for r in first] == ["a", "b"]


def test_collect_converts_a_provider_crash_into_an_error_result() -> None:
    class Exploding:
        name = "boom"

        def observe(self, query: ObservationQuery) -> ObservationResult:
            raise RuntimeError("provider down")

    results = collect(Exploding(), (ObservationQuery(metric="a"),))
    assert results[0].status is ObservationStatus.ERROR
    assert results[0].available is False
    assert "provider down" in results[0].detail


def test_evaluate_all_injects_missing_for_unreturned_metrics() -> None:
    criteria = (
        SloCriterion(
            kind=CriterionKind.LATENCY,
            metric="missing.metric",
            operator=CriterionOperator.LTE,
            threshold=10.0,
        ),
    )
    outcomes = evaluate_all(criteria, ())
    assert outcomes[0].passed is False
    assert "missing" in outcomes[0].reason


def test_provenance_summary_counts_only() -> None:
    observations = (_obs("a", 1.0), _obs("b", None, ObservationStatus.MISSING))
    summary = provenance_summary(observations)
    assert summary == {
        "schema_version": "1.0",
        "count": 2,
        "available": 1,
        "missing": 1,
        "sources": ["local"],
    }
    assert "value" not in json.dumps(summary)


def test_provenance_summary_lists_sources() -> None:
    observations = (
        ObservationResult("a", 1.0, "ms", 60.0, provenance="http"),
        ObservationResult("b", 2.0, "ms", 60.0, provenance="prometheus"),
    )
    assert provenance_summary(observations)["sources"] == ["http", "prometheus"]


# ── concrete providers ───────────────────────────────────────────────────────
def test_static_provider_is_deterministic() -> None:
    from mayhem.providers.observation import StaticObservationProvider

    provider = StaticObservationProvider({"a": 3.0})
    assert provider.observe(ObservationQuery(metric="a")).value == 3.0
    assert provider.observe(ObservationQuery(metric="a")).value == 3.0
    assert provider.observe(ObservationQuery(metric="zz")).status is ObservationStatus.MISSING


def test_process_provider_reads_numeric_stdout() -> None:
    from mayhem.providers.observation import ProcessObservationProvider

    provider = ProcessObservationProvider(
        runner=lambda argv: SimpleNamespace(stdout="42\n", returncode=0)
    )
    result = provider.observe(ObservationQuery(metric="procs", target="pgrep -c mayhem"))
    assert result.value == 42.0
    assert result.provenance == "process"


def test_process_provider_reports_nonzero_exit_as_error() -> None:
    from mayhem.providers.observation import ProcessObservationProvider

    provider = ProcessObservationProvider(
        runner=lambda argv: SimpleNamespace(stdout="", returncode=2)
    )
    result = provider.observe(ObservationQuery(metric="procs", target="false"))
    assert result.status is ObservationStatus.ERROR
    assert result.available is False


def test_process_provider_redacts_output_detail() -> None:
    from mayhem.providers.observation import ProcessObservationProvider

    provider = ProcessObservationProvider(
        runner=lambda argv: SimpleNamespace(stdout="token=ghp_supersecret\n", returncode=0)
    )
    result = provider.observe(ObservationQuery(metric="m", target="cmd"))
    assert result.status is ObservationStatus.MISSING
    assert "ghp_supersecret" not in result.detail
    assert "REDACTED" in result.detail


def test_http_provider_reports_missing_target() -> None:
    from mayhem.providers.observation import HttpObservationProvider

    result = HttpObservationProvider().observe(ObservationQuery(metric="http.latency"))
    assert result.status is ObservationStatus.MISSING
    assert result.provenance == "http"


def test_http_provider_converts_a_connection_failure_to_error() -> None:
    from mayhem.providers.observation import HttpObservationProvider

    result = HttpObservationProvider(timeout_s=0.2).observe(
        ObservationQuery(metric="http.latency", target="http://127.0.0.1:1/healthz")
    )
    assert result.status is ObservationStatus.ERROR
    assert result.value is None


def test_parse_json_metric_handles_shapes() -> None:
    from mayhem.providers.observation import parse_json_metric

    assert parse_json_metric("3.5") == 3.5
    assert parse_json_metric('{"value": 7}') == 7.0
    assert parse_json_metric('{"result": [1, 2]}') is None
    assert parse_json_metric("not json") is None
