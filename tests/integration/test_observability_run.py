"""Observability connectors inside a real run (v0.9.0 expansion task 19)."""

from __future__ import annotations

import json

from mayhem.infra.evidence import build_evidence, write_evidence, write_evidence_file
from mayhem.infra.store import Store
from mayhem.observability.otel import SPAN_NAMES, InMemorySpanSink, record_span


def _envelope(**kwargs):
    return build_evidence(
        run_id="obs-run",
        plan=None,
        target_profile=None,
        engine="kubernetes",
        safety_decisions=(),
        step_reports=(),
        lease_timeline=(),
        observations=(),
        verdict="pass",
        recovery_state="none",
        remediation=(),
        **kwargs,
    )


def test_a_run_records_every_lifecycle_span() -> None:
    sink = InMemorySpanSink()
    for name in SPAN_NAMES:
        record_span(sink, name, run_id="obs-run")
    envelope = _envelope(emitted_spans=sink.names())
    assert set(envelope.emitted_spans) == set(SPAN_NAMES)
    assert "mayhem.lease" in envelope.emitted_spans
    assert "mayhem.compensation" in envelope.emitted_spans


def test_spans_persist_to_sqlite_and_the_evidence_file(tmp_path) -> None:
    sink = InMemorySpanSink()
    for name in SPAN_NAMES:
        record_span(sink, name, run_id="obs-run")
    envelope = _envelope(emitted_spans=sink.names())
    store = Store.open_migrated(tmp_path / "obs.db")
    try:
        write_evidence(store, envelope)
        rows = store.query("SELECT envelope_json FROM evidence_envelopes")
    finally:
        store.close()
    blob = json.dumps([dict(row) for row in rows])
    assert "emitted_spans" in blob
    assert "mayhem.evidence" in blob

    path = write_evidence_file(envelope, tmp_path / "evidence")
    assert "mayhem.verification" in path.read_text()


def test_span_attributes_never_reach_the_evidence(tmp_path) -> None:
    sink = InMemorySpanSink()
    record_span(sink, "mayhem.lease", run_id="obs-run", credential="token=ghp_leakvalue")
    envelope = _envelope(emitted_spans=sink.names())
    path = write_evidence_file(envelope, tmp_path / "evidence")
    blob = path.read_text()
    assert "ghp_leakvalue" not in blob
    assert "mayhem.lease" in blob  # the name is recorded, the payload is not


def test_connector_failure_degrades_evidence_instead_of_claiming_success() -> None:
    from mayhem.domain.observations import (
        CriterionKind,
        CriterionOperator,
        ObservationQuery,
        ObservationStatus,
        SloCriterion,
    )
    from mayhem.providers.observation import HttpObservationProvider

    provider = HttpObservationProvider(timeout_s=0.2)
    result = provider.observe(
        ObservationQuery(metric="http.latency", target="http://127.0.0.1:1/healthz")
    )
    assert result.status is ObservationStatus.ERROR

    criterion = SloCriterion(
        kind=CriterionKind.LATENCY,
        metric="http.latency",
        operator=CriterionOperator.LTE,
        threshold=1000.0,
    )
    outcome = criterion.evaluate(result)
    assert outcome.passed is False
    assert "unavailable" in outcome.reason


def test_connector_credentials_are_redacted_in_error_detail() -> None:
    from mayhem.observability.base import ConnectorError, redacted

    message = redacted("GET http://prom:9090 failed with Authorization: Bearer prom-secret")
    assert "prom-secret" not in message
    assert isinstance(ConnectorError("x"), Exception)
