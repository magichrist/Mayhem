"""Signal extraction: turning a declared signal into a number, or into a reason.

Plan 03's own risk section calls this the bulk of the work: *"`metric:
latency_ms` needs a defined source per observability kind. This is the bulk of
the work and it is unavoidably per-source."*

These tests pin the three resolutions that exist and, more importantly, the
cases where a reading is *refused*. The refusals are the interesting half: a
probe that cannot produce a number must say so by name, because the whole
steady-state feature exists to stop "the probe never fired" and "the fault did
nothing" from sharing one boolean.
"""

from __future__ import annotations

import math

import pytest

from mayhem.controller.observability_collector import (
    ObservabilitySample,
    SourceCollection,
)
from mayhem.controller.steady_state import readings_for
from mayhem.domain.observations import (
    ObservationQuery,
    ObservationResult,
    ObservationStatus,
)
from mayhem.domain.steady_state import SteadyStateSignal
from mayhem.observability.metrics import (
    DERIVED_LOG_METRICS,
    Measurement,
    coerce_finite,
    derive_log_metric,
    measure_signal,
    signal_query,
    unmeasurable_reason,
)

LOG_TAIL = "\n".join(
    [
        "GET /api/orders 200 12ms",
        "GET /api/orders 200 9ms",
        "GET /api/orders 500 401ms",
        "GET /api/orders 502 33ms",
        "GET /api/orders 200 11ms",
        "POST /api/checkout 201 44ms",
    ]
)


def _signal(**kwargs: object) -> SteadyStateSignal:
    base: dict[str, object] = {
        "name": "api.latency.p99",
        "source_id": "api.http",
        "metric": "latency_ms",
    }
    base.update(kwargs)
    return SteadyStateSignal(**base)  # type: ignore[arg-type]


def _metrics_collection(source_id: str, values: list[object]) -> SourceCollection:
    return SourceCollection(
        source_id=source_id,
        kind="metrics",  # type: ignore[arg-type]
        ok=True,
        note=f"{len(values)} metric sample(s)",
        latency_ms=1.0,
        samples=tuple(ObservabilitySample(at="2026-01-01T00:00:00Z", value=v) for v in values),
    )


def _logs_collection(source_id: str, text: str) -> SourceCollection:
    return SourceCollection(
        source_id=source_id,
        kind="logs",  # type: ignore[arg-type]
        ok=True,
        note="collected",
        latency_ms=1.0,
        samples=(ObservabilitySample(at="2026-01-01T00:00:00Z", value=text),),
    )


# -- coerce_finite -------------------------------------------------------------------


class TestCoerceFinite:
    def test_finite_numbers_pass_through_as_floats(self) -> None:
        assert coerce_finite(88) == 88.0
        assert isinstance(coerce_finite(88), float)
        assert coerce_finite(-0.5) == -0.5
        assert coerce_finite(0.0) == 0.0

    def test_non_finite_is_refused_rather_than_forwarded(self) -> None:
        assert coerce_finite(float("nan")) is None
        assert coerce_finite(float("inf")) is None
        assert coerce_finite(float("-inf")) is None

    def test_a_zero_baseline_is_a_number_not_a_refusal(self) -> None:
        # 0.0 is finite and is a real measurement. `delta_pct` is what returns
        # None for it — the refusal lives in the ratio, not in the reading.
        assert coerce_finite(0.0) == 0.0

    def test_non_numbers_are_refused(self) -> None:
        assert coerce_finite(None) is None
        assert coerce_finite("42") is None
        assert coerce_finite(True) is None
        assert coerce_finite({"value": 1}) is None


# -- derived log metrics -------------------------------------------------------------


class TestDerivedLogMetrics:
    def test_status_ratio_counts_5xx_over_all_response_lines(self) -> None:
        # 6 response lines, 2 of them 5xx.
        assert derive_log_metric("status_5xx_ratio", LOG_TAIL) == pytest.approx(2 / 6)

    def test_a_clean_tail_is_a_zero_rate_not_a_missing_one(self) -> None:
        clean = "GET /a 200 1ms\nGET /b 204 1ms"
        assert derive_log_metric("status_5xx_ratio", clean) == 0.0

    def test_a_tail_with_no_response_line_yields_no_number(self) -> None:
        # 0/0 would be a fabricated rate, and a zero error rate is exactly the
        # number a reader cannot tell from "never measured".
        assert derive_log_metric("status_5xx_ratio", "starting up\nno traffic yet") is None

    def test_an_undeclared_derived_metric_is_refused_by_name(self) -> None:
        assert derive_log_metric("cpu_pct", LOG_TAIL) is None
        reason = unmeasurable_reason("logs", "cpu_pct")
        assert "cpu_pct" in reason
        assert "status_5xx_ratio" in reason

    def test_the_registry_names_what_it_can_derive(self) -> None:
        assert "status_5xx_ratio" in DERIVED_LOG_METRICS


# -- readings_for: the per-source-kind resolution -------------------------------------


class TestReadingsFor:
    def test_a_metrics_source_yields_one_reading_per_sample(self) -> None:
        signal = _signal()
        collection = _metrics_collection("api.http", [88.0, 91.0, 87.0])
        series = readings_for(signal, collection)
        assert [m.value for m in series] == [88.0, 91.0, 87.0]
        assert all(m.available for m in series)
        assert all(m.source == "api.http" for m in series)

    def test_a_non_finite_sample_becomes_an_unavailable_reading_with_a_reason(self) -> None:
        signal = _signal()
        series = readings_for(signal, _metrics_collection("api.http", [88.0, math.inf]))
        assert series[0].value == 88.0
        assert series[1].value is None
        assert series[1].available is False
        assert "not a finite number" in series[1].detail

    def test_a_logs_source_derives_the_declared_ratio(self) -> None:
        signal = _signal(name="api.error_rate", source_id="api.logs", metric="status_5xx_ratio")
        series = readings_for(signal, _logs_collection("api.logs", LOG_TAIL))
        assert len(series) == 1
        assert series[0].value == pytest.approx(2 / 6)
        assert series[0].provenance == "loki"

    def test_a_probe_source_is_refused_by_kind_not_guessed(self) -> None:
        signal = _signal()
        collection = SourceCollection(
            source_id="api.http",
            kind="probe",  # type: ignore[arg-type]
            ok=True,
            note="1 probe sample",
            latency_ms=1.0,
            samples=(ObservabilitySample(at="2026-01-01T00:00:00Z", value={"satisfied": True}),),
        )
        series = readings_for(signal, collection)
        assert series[0].value is None
        assert "probes and inspect output are not quantities" in series[0].detail

    def test_a_missing_source_is_named_rather_than_defaulted(self) -> None:
        series = readings_for(_signal(), None)
        assert len(series) == 1
        assert series[0].value is None
        assert "no collection for source_id 'api.http'" in series[0].detail

    def test_a_collection_for_another_source_is_refused_by_name(self) -> None:
        series = readings_for(_signal(), _metrics_collection("other.http", [1.0]))
        assert series[0].value is None
        assert "other.http" in series[0].detail
        assert "api.http" in series[0].detail

    def test_an_empty_collection_reports_its_own_note(self) -> None:
        collection = SourceCollection(
            source_id="api.http",
            kind="metrics",  # type: ignore[arg-type]
            ok=False,
            note="collection failed: URLError",
            latency_ms=0.0,
        )
        series = readings_for(_signal(), collection)
        assert series[0].value is None
        assert series[0].detail == "collection failed: URLError"


# -- the provider path ---------------------------------------------------------------


class _ExplodingProvider:
    name = "boom"

    def observe(self, query: ObservationQuery) -> ObservationResult:
        raise RuntimeError("scrape endpoint refused the connection")


class _PrometheusLike:
    """Stands in for ``PrometheusConnector``, which returns ``ObservationResult``."""

    name = "prometheus"

    def __init__(self, value: float | None) -> None:
        self._value = value
        self.queries: list[ObservationQuery] = []

    def observe(self, query: ObservationQuery) -> ObservationResult:
        self.queries.append(query)
        return ObservationResult(
            metric=query.metric,
            value=self._value,
            unit=query.unit,
            window_s=query.window_s,
            provenance=self.name,
            source="http://prom:9090",
        )


class TestMeasureSignal:
    def test_a_provider_reading_becomes_a_measurement_with_provenance(self) -> None:
        provider = _PrometheusLike(88.0)
        result = measure_signal(_signal(), provider=provider)
        assert result.value == 88.0
        assert result.available is True
        assert result.provenance == "prometheus"
        assert result.source == "http://prom:9090"
        assert provider.queries[0].metric == "latency_ms"
        assert provider.queries[0].target == "api.http"

    def test_a_missing_provider_result_stays_missing_not_zero(self) -> None:
        result = measure_signal(_signal(), provider=_PrometheusLike(None))
        assert result.value is None
        assert result.status is ObservationStatus.MISSING
        assert result.available is False

    def test_a_provider_that_raises_becomes_an_error_measurement(self) -> None:
        # Routed through domain.observations.collect, so a broken provider
        # cannot escape into the run as an exception mid-drill.
        result = measure_signal(_signal(), provider=_ExplodingProvider())
        assert result.value is None
        assert result.status is ObservationStatus.ERROR
        assert "scrape endpoint refused" in result.detail

    def test_no_provider_and_no_collection_is_missing_by_name(self) -> None:
        result = measure_signal(_signal())
        assert result.value is None
        assert "no provider or captured collection" in result.detail

    def test_a_captured_log_tail_is_reduced_through_the_derived_metric(self) -> None:
        signal = _signal(name="api.error_rate", source_id="api.logs", metric="status_5xx_ratio")
        result = measure_signal(signal, collection_values=(LOG_TAIL,))
        assert result.value == pytest.approx(2 / 6)
        assert result.provenance == "loki"

    def test_the_signal_name_reaches_the_measurement(self) -> None:
        result = measure_signal(_signal(), provider=_PrometheusLike(1.0))
        assert result.name == "api.latency.p99"


class TestSignalQuery:
    def test_baseline_window_overrides_the_capture_window(self) -> None:
        signal = _signal(baseline_window="5m", tolerance={"at_most": 0.02})
        query = signal_query(signal, window_s=10.0)
        assert query.window_s == 300.0

    def test_without_an_override_the_capture_window_is_used(self) -> None:
        assert signal_query(_signal(), window_s=10.0).window_s == 10.0

    def test_the_query_carries_the_source_and_signal_identity(self) -> None:
        query = signal_query(_signal(), window_s=10.0)
        assert query.labels == {"source_id": "api.http", "signal": "api.latency.p99"}


class TestMeasurementRoundTrip:
    def test_a_measurement_projects_onto_the_shared_observation_contract(self) -> None:
        original = measure_signal(_signal(), provider=_PrometheusLike(88.0))
        projected = original.to_observation()
        assert projected.metric == "api.latency.p99"
        assert projected.value == 88.0
        assert projected.provenance == "prometheus"
        assert projected.status is ObservationStatus.OK

    def test_an_unavailable_measurement_stays_unavailable_through_the_round_trip(self) -> None:
        original = measure_signal(_signal(), provider=_PrometheusLike(None))
        assert original.to_observation().value is None
        assert original.to_observation().available is False

    def test_to_dict_reports_availability_alongside_the_value(self) -> None:
        payload = Measurement(name="s", value=1.0).to_dict()
        assert payload["available"] is True
        assert payload["status"] == "ok"
        assert Measurement(name="s", value=None).to_dict()["available"] is False
