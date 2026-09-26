"""Recovery proof via residual impact (v0.9.0 expansion task 16)."""

from __future__ import annotations

import json

from click.testing import CliRunner

from mayhem.domain.residual_impact import (
    CLEAN,
    TOLERATED,
    UNAVAILABLE,
    VIOLATION,
    ImpactAcceptance,
    ImpactSnapshot,
    assess_residual_impact,
)
from mayhem.infra.evidence import build_evidence, write_evidence
from mayhem.infra.store import Store


def _ctx(db):
    from mayhem.cli.context import CliContext

    return CliContext(db=str(db))


def _envelope(run_id: str, **kwargs):
    return build_evidence(
        run_id=run_id,
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


def test_recovery_that_restores_the_system_proves_clean(tmp_path) -> None:
    assessment = assess_residual_impact(
        ImpactSnapshot(label="before", values={"restarts": 0.0, "replicas": 3.0}, source="topology"),
        ImpactSnapshot(label="after", values={"restarts": 0.0, "replicas": 3.0}, source="topology"),
    )
    assert assessment.status == CLEAN
    store = Store.open_migrated(tmp_path / "r.db")
    try:
        write_evidence(store, _envelope("run-clean", residual_impact=assessment.to_dict()))
        rows = store.query("SELECT envelope_json FROM evidence_envelopes WHERE run_id = 'run-clean'")
    finally:
        store.close()
    assert json.loads(dict(rows[0])["envelope_json"])["residual_impact"]["status"] == CLEAN


def test_partial_recovery_is_recorded_as_a_violation(tmp_path) -> None:
    assessment = assess_residual_impact(
        ImpactSnapshot(label="before", values={"replicas": 3.0, "ready": 3.0}),
        ImpactSnapshot(label="after", values={"replicas": 3.0, "ready": 1.0}),
    )
    assert assessment.status == VIOLATION
    assert [v.signal for v in assessment.violations] == ["ready"]
    store = Store.open_migrated(tmp_path / "r.db")
    try:
        write_evidence(store, _envelope("run-partial", residual_impact=assessment.to_dict()))
        rows = store.query(
            "SELECT envelope_json FROM evidence_envelopes WHERE run_id = 'run-partial'"
        )
    finally:
        store.close()
    payload = json.loads(dict(rows[0])["envelope_json"])["residual_impact"]
    assert payload["untolerated_count"] == 1
    assert payload["violations"][0]["acceptance"] is None


def test_unexpected_persistent_change_is_never_reported_as_clean() -> None:
    assessment = assess_residual_impact(
        ImpactSnapshot(label="before", values={"replicas": 3.0}),
        ImpactSnapshot(label="other-run", values={"pods": 7.0}),
    )
    assert assessment.status == CLEAN  # different keys, nothing comparable
    comparable = assess_residual_impact(
        ImpactSnapshot(label="before", values={"config_hash": 1.0}),
        ImpactSnapshot(label="after", values={"config_hash": 2.0}),
    )
    assert comparable.status == VIOLATION
    assert comparable.clean is False


def test_unavailable_observation_source_blocks_the_proof(tmp_path) -> None:
    assessment = assess_residual_impact(
        ImpactSnapshot.unavailable("before", "kubernetes API unreachable"),
        ImpactSnapshot(label="after", values={"replicas": 3.0}),
    )
    assert assessment.status == UNAVAILABLE
    store = Store.open_migrated(tmp_path / "r.db")
    try:
        write_evidence(store, _envelope("run-unavailable", residual_impact=assessment.to_dict()))
    finally:
        store.close()
    from mayhem.infra.evidence import load_evidence

    store = Store.open_migrated(tmp_path / "r.db")
    try:
        loaded = load_evidence(store, "run-unavailable")
    finally:
        store.close()
    assert loaded is not None
    assert loaded.residual_impact["status"] == UNAVAILABLE


def test_explicitly_accepted_residual_carries_its_acceptance_metadata(tmp_path) -> None:
    assessment = assess_residual_impact(
        ImpactSnapshot(label="before", values={"queue_depth": 0.0}),
        ImpactSnapshot(label="after", values={"queue_depth": 12.0}),
        acceptances=(
            ImpactAcceptance(
                signal="queue_depth",
                accepted_by="oncall@example",
                reason="backlog drains after the window",
                accepted_at="2026-09-26T00:00:00Z",
            ),
        ),
    )
    assert assessment.status == TOLERATED
    store = Store.open_migrated(tmp_path / "r.db")
    try:
        write_evidence(store, _envelope("run-accepted", residual_impact=assessment.to_dict()))
    finally:
        store.close()
    from mayhem.infra.evidence import load_evidence

    store = Store.open_migrated(tmp_path / "r.db")
    try:
        loaded = load_evidence(store, "run-accepted")
    finally:
        store.close()
    assert loaded is not None
    acceptance = loaded.residual_impact["violations"][0]["acceptance"]
    assert acceptance["accepted_by"] == "oncall@example"
    assert acceptance["reason"] == "backlog drains after the window"


def test_cli_recovery_report_reflects_the_stored_assessment(tmp_path) -> None:
    from mayhem.cli.inspect import inspect_residual

    db = tmp_path / "r.db"
    store = Store.open_migrated(db)
    try:
        write_evidence(
            store,
            _envelope(
                "run-1",
                residual_impact=assess_residual_impact(
                    ImpactSnapshot(label="before", values={"replicas": 3.0}),
                    ImpactSnapshot(label="after", values={"replicas": 1.0}),
                ).to_dict(),
            ),
        )
    finally:
        store.close()

    result = CliRunner().invoke(inspect_residual, ["run-1", "--from-observations", "--json"], obj=_ctx(db))
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["status"] == CLEAN

    reported = CliRunner().invoke(
        inspect_residual,
        ["run-1", "--expect", "replicas=3", "--observed", "replicas=1", "--json"],
        obj=_ctx(db),
    )
    assert json.loads(reported.output)["status"] == VIOLATION
    assert "replicas" in reported.output
