"""Observability connectors (v0.9.0 expansion task 19).

All connectors are read-only against remote systems; the only thing Mayhem
writes is a local OpenTelemetry span sink. Every connector is bounded by a
timeout and a response-size limit, and its payloads pass through the redaction
policy before anything can reach evidence.
"""

from mayhem.observability.loki import LokiConnector, LogQuery
from mayhem.observability.otel import SpanSink, record_span
from mayhem.observability.prometheus import MetricQuery, PrometheusConnector

__all__ = [
    "LokiConnector",
    "LogQuery",
    "MetricQuery",
    "PrometheusConnector",
    "SpanSink",
    "record_span",
]
