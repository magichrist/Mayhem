"""v0.9.0 expansion task 19: observability connectors."""

from __future__ import annotations

import io
import json
from typing import Any

import pytest

from mayhem.observability.base import ConnectorError, fetch_json, redacted
from mayhem.observability.loki import LogQuery, LokiConnector
from mayhem.observability.otel import (
    SPAN_NAMES,
    InMemorySpanSink,
    Span,
    missing_spans,
    record_span,
)
from mayhem.observability.prometheus import MetricQuery, PrometheusConnector


class _FakeResponse(io.BytesIO):
    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def _opener(payload: dict[str, Any], recorder: list[str] | None = None) -> Any:
    body = json.dumps(payload).encode()

    def opener(request: Any, timeout: float | None = None) -> _FakeResponse:
        if recorder is not None:
            recorder.append(getattr(request, "full_url", str(request)))
        return _FakeResponse(body)

    return opener


PROM_OK = {
    "status": "success",
    "data": {"resultType": "vector", "result": [{"metric": {}, "value": [1, "0.42"]}]},
}
PROM_EMPTY = {"status": "success", "data": {"resultType": "vector", "result": []}}
PROM_ERROR = {"status": "error", "errorType": "bad_data", "error": "parse error"}
LOKI_OK = {
    "status": "success",
    "data": {
        "result": [
            {"stream": {"app": "checkout"}, "values": [["1", "line one"], ["2", "line two"]]}
        ]
    },
}
LOKI_ERROR = {"status": "error", "error": "too many outstanding requests"}


# ── Prometheus ───────────────────────────────────────────────────────────────
def test_prometheus_query_returns_the_first_sample() -> None:
    connector = PrometheusConnector("http://prom:9090", opener=_opener(PROM_OK))
    assert connector.query(MetricQuery(promql="up")) == pytest.approx(0.42)


def test_prometheus_query_sends_the_promql() -> None:
    seen: list[str] = []
    connector = PrometheusConnector("http://prom:9090", opener=_opener(PROM_OK, seen))
    connector.query(MetricQuery(promql="rate(http_requests_total[5m])"))
    assert "promql=rate" in seen[0] or "query=rate" in seen[0]


def test_prometheus_empty_result_is_missing_not_zero() -> None:
    connector = PrometheusConnector("http://prom:9090", opener=_opener(PROM_EMPTY))
    assert connector.query(MetricQuery(promql="up")) is None


def test_prometheus_error_status_raises_a_connector_error() -> None:
    connector = PrometheusConnector("http://prom:9090", opener=_opener(PROM_ERROR))
    with pytest.raises(ConnectorError, match="prometheus query failed"):
        connector.query(MetricQuery(promql="up"))


def test_prometheus_observe_reports_error_as_degraded_observation() -> None:
    from mayhem.domain.observations import ObservationQuery, ObservationStatus

    connector = PrometheusConnector("http://prom:9090", opener=_opener(PROM_ERROR))
    result = connector.observe(ObservationQuery(metric="up"))
    assert result.status is ObservationStatus.ERROR
    assert result.value is None
    assert result.provenance == "prometheus"


def test_prometheus_observe_reports_missing_when_no_samples() -> None:
    from mayhem.domain.observations import ObservationQuery, ObservationStatus

    connector = PrometheusConnector("http://prom:9090", opener=_opener(PROM_EMPTY))
    result = connector.observe(ObservationQuery(metric="up"))
    assert result.status is ObservationStatus.MISSING
    assert result.available is False


def test_prometheus_observe_success_path() -> None:
    from mayhem.domain.observations import ObservationQuery

    connector = PrometheusConnector("http://prom:9090", opener=_opener(PROM_OK))
    result = connector.observe(ObservationQuery(metric="up", unit="ratio"))
    assert result.value == pytest.approx(0.42)
    assert result.provenance == "prometheus"


# ── Loki ─────────────────────────────────────────────────────────────────────
def test_loki_returns_redacted_lines() -> None:
    connector = LokiConnector("http://loki:3100", opener=_opener(LOKI_OK))
    lines = connector.query_lines(LogQuery(selector='{app="checkout"}'))
    assert lines == ("line one", "line two")


def test_loki_redacts_tokens_in_log_lines() -> None:
    payload = {
        "status": "success",
        "data": {
            "result": [{"stream": {}, "values": [["1", "auth failed token=ghp_supersecretvalue"]]}]
        },
    }
    connector = LokiConnector("http://loki:3100", opener=_opener(payload))
    lines = connector.query_lines(LogQuery(selector='{app="checkout"}'))
    assert "ghp_supersecretvalue" not in lines[0]
    assert "REDACTED" in lines[0]


def test_loki_error_status_raises() -> None:
    connector = LokiConnector("http://loki:3100", opener=_opener(LOKI_ERROR))
    with pytest.raises(ConnectorError, match="loki query failed"):
        connector.query_lines(LogQuery(selector='{app="checkout"}'))


def test_loki_count_counts_lines() -> None:
    connector = LokiConnector("http://loki:3100", opener=_opener(LOKI_OK))
    assert connector.count(LogQuery(selector='{app="checkout"}')) == 2


def test_loki_missing_result_list_raises() -> None:
    connector = LokiConnector("http://loki:3100", opener=_opener({"status": "success", "data": {}}))
    with pytest.raises(ConnectorError, match="no result list"):
        connector.query_lines(LogQuery(selector='{app="checkout"}'))


# ── bounds, timeouts, redaction ──────────────────────────────────────────────
def test_response_size_limit_is_enforced() -> None:
    big = json.dumps(PROM_OK | {"padding": "x" * 5000}).encode()

    def opener(request: Any, timeout: float | None = None) -> _FakeResponse:
        return _FakeResponse(big)

    connector = PrometheusConnector("http://prom:9090", max_bytes=1024, opener=opener)
    with pytest.raises(ConnectorError, match="exceeded 1024 bytes"):
        connector.query(MetricQuery(promql="up"))


def test_timeout_is_passed_to_the_transport() -> None:
    seen: list[float | None] = []

    def opener(request: Any, timeout: float | None = None) -> _FakeResponse:
        seen.append(timeout)
        return _FakeResponse(json.dumps(PROM_OK).encode())

    PrometheusConnector("http://prom:9090", timeout_s=1.5, opener=opener).query(
        MetricQuery(promql="up")
    )
    assert seen == [1.5]


def test_transport_failure_becomes_a_connector_error() -> None:
    def opener(request: Any, timeout: float | None = None) -> _FakeResponse:
        raise OSError("connection refused")

    connector = PrometheusConnector("http://prom:9090", opener=opener)
    with pytest.raises(ConnectorError, match="connection refused"):
        connector.query(MetricQuery(promql="up"))


def test_transport_failure_detail_is_redacted() -> None:
    def opener(request: Any, timeout: float | None = None) -> _FakeResponse:
        raise OSError("failed with password=hunter2-plaintext")

    connector = PrometheusConnector("http://prom:9090", opener=opener)
    with pytest.raises(ConnectorError) as excinfo:
        connector.query(MetricQuery(promql="up"))
    assert "hunter2-plaintext" not in str(excinfo.value)


def test_connector_authorization_header_is_never_echoed() -> None:
    seen: list[dict[str, str]] = []

    def opener(request: Any, timeout: float | None = None) -> _FakeResponse:
        seen.append(dict(getattr(request, "headers", {}) or {}))
        return _FakeResponse(json.dumps(PROM_OK).encode())

    PrometheusConnector(
        "http://prom:9090",
        headers={"Authorization": "Bearer prom-secret-token"},
        opener=opener,
    ).query(MetricQuery(promql="up"))
    rendered = json.dumps(seen)
    assert "prom-secret-token" in rendered or not seen  # only ever sent, never returned


def test_non_json_response_is_refused() -> None:
    def opener(request: Any, timeout: float | None = None) -> _FakeResponse:
        return _FakeResponse(b"<html>login</html>")

    with pytest.raises(ConnectorError, match="non-JSON"):
        fetch_json("http://prom:9090/x", opener=opener)


def test_unexpected_json_shape_is_refused() -> None:
    def opener(request: Any, timeout: float | None = None) -> _FakeResponse:
        return _FakeResponse(b"[1, 2, 3]")

    with pytest.raises(ConnectorError, match="unexpected JSON shape"):
        fetch_json("http://prom:9090/x", opener=opener)


def test_redacted_helper_is_available_to_connectors() -> None:
    assert redacted("token=abc123") == "token=***REDACTED***"


# ── OpenTelemetry spans ──────────────────────────────────────────────────────
def test_span_sink_records_spans_in_order() -> None:
    sink = InMemorySpanSink()
    for name in SPAN_NAMES:
        record_span(sink, name, run_id="r1")
    assert sink.names() == SPAN_NAMES


def test_record_span_is_a_noop_without_a_sink() -> None:
    record_span(None, "mayhem.plan", run_id="r1")


def test_span_attributes_are_redacted() -> None:
    sink = InMemorySpanSink()
    record_span(sink, "mayhem.lease", run_id="r1", lease="token=ghp_leak")
    assert "ghp_leak" not in json.dumps(sink.spans[0].to_dict())


def test_span_export_is_deterministic_json() -> None:
    first, second = InMemorySpanSink(), InMemorySpanSink()
    for sink in (first, second):
        record_span(sink, "mayhem.plan", run_id="r1", steps=3)
    assert first.export_json() == second.export_json()
    parsed = json.loads(first.export_json())
    assert parsed[0]["name"] == "mayhem.plan"
    assert parsed[0]["attributes"]["steps"] == "3"


def test_required_lifecycle_spans_are_reported_when_missing() -> None:
    sink = InMemorySpanSink()
    record_span(sink, "mayhem.plan")
    record_span(sink, "mayhem.evidence")
    missing = missing_spans(sink.names())
    assert "mayhem.lease" in missing
    assert "mayhem.plan" not in missing


def test_span_is_serialisable() -> None:
    assert json.loads(json.dumps(Span("mayhem.plan").to_dict()))["name"] == "mayhem.plan"


def test_span_sink_clear_resets_state() -> None:
    sink = InMemorySpanSink()
    record_span(sink, "mayhem.plan")
    sink.clear()
    assert sink.names() == ()
