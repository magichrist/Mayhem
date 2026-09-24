import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

from mayhem.infra.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticRecord,
    DiagnosticSeverity,
    DiagnosticStatus,
    check_capabilities,
    check_config,
    check_database,
    check_engine,
    check_permissions,
    check_target_profiles,
    check_topology,
    diagnose_run,
    lease_projection,
    run_diagnostics,
    structured_diagnostics,
    to_json_records,
)


def test_diagnostic_record_typed():
    rec = DiagnosticRecord(
        id="config.valid",
        category=DiagnosticCategory.config,
        severity=DiagnosticSeverity.info,
        message="ok",
        remediation="",
        evidence_ref="mayhem.yaml",
    )
    assert rec.id == "config.valid"
    assert rec.category == DiagnosticCategory.config
    assert rec.severity == DiagnosticSeverity.info
    assert rec.remediation == ""
    assert rec.evidence_ref == "mayhem.yaml"
    dumped = rec.model_dump(mode="json")
    assert dumped["id"] == "config.valid"


def test_check_config_valid(tmp_path):
    Path(tmp_path / "mayhem.yaml").write_text("apiVersion: mayhem/v1\n")
    records = check_config(str(tmp_path / "mayhem.yaml"), None)
    assert any(r.id == "config.valid" for r in records)
    assert all(isinstance(r, DiagnosticRecord) for r in records)


def test_check_config_invalid(tmp_path):
    Path(tmp_path / "mayhem.yaml").write_text("apiVersion: mayhem/v1\nfrobnicate: true\n")
    records = check_config(str(tmp_path / "mayhem.yaml"), None)
    assert any(r.severity == DiagnosticSeverity.error for r in records)
    err = next(r for r in records if r.severity == DiagnosticSeverity.error)
    assert err.remediation != ""


def test_check_target_profiles_none(tmp_path):
    Path(tmp_path / "mayhem.yaml").write_text("apiVersion: mayhem/v1\n")
    records = check_target_profiles(str(tmp_path / "mayhem.yaml"))
    assert any("none" in r.id for r in records)


def test_check_target_profiles_invalid(tmp_path):
    Path(tmp_path / "mayhem.yaml").write_text(
        "apiVersion: mayhem/v1\ntargets:\n  bad name:\n    engine: docker\n"
    )
    records = check_target_profiles(str(tmp_path / "mayhem.yaml"))
    assert any(r.severity == DiagnosticSeverity.error for r in records)


def test_check_database_missing_is_info(tmp_path):
    records = check_database(str(tmp_path / "missing.db"))
    assert any(r.severity == DiagnosticSeverity.info and "missing" in r.id for r in records)


def test_check_database_migration_drift(tmp_path):
    db = tmp_path / "drift.db"
    conn = sqlite3.connect(str(db))
    conn.execute(
        "CREATE TABLE _schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
    )
    conn.execute("INSERT INTO _schema_migrations (version, name) VALUES (1, 'initial')")
    conn.commit()
    conn.close()
    records = check_database(str(db))
    assert any(r.id == "database.migration_drift" for r in records)
    assert any(r.severity == DiagnosticSeverity.error for r in records)
    assert any(r.remediation != "" for r in records)


def test_check_engine_never_claims_healthy():
    records = check_engine()
    for r in records:
        assert "does not prove" in r.message or "file presence" in r.message.lower()
    with patch("mayhem.infra.diagnostics.shutil.which", return_value=None):
        records2 = check_engine()
        for r in records2:
            assert r.severity == DiagnosticSeverity.warning
            assert "does not prove" in r.message or "file presence" in r.message.lower()


def test_missing_optional_runtimes_are_warnings():
    with patch("mayhem.infra.diagnostics.shutil.which", return_value=None):
        records = check_engine()
        warnings = [r for r in records if r.severity == DiagnosticSeverity.warning]
        assert len(warnings) >= 3


def test_check_topology_valid(tmp_path):
    compose = tmp_path / "compose.yaml"
    compose.write_text("services:\n  web:\n    image: nginx\n")
    records = check_topology(str(compose), None)
    assert any(r.id == "topology.compose.valid" for r in records)


def test_check_topology_missing(tmp_path):
    records = check_topology(str(tmp_path / "nope.yaml"), None)
    assert any(r.severity == DiagnosticSeverity.warning for r in records)


def test_check_capabilities_typed():
    records = check_capabilities()
    assert all(isinstance(r, DiagnosticRecord) for r in records)
    assert all(r.category == DiagnosticCategory.capabilities for r in records)


def test_check_permissions_writable(tmp_path):
    records = check_permissions(str(tmp_path / "mayhem.db"))
    assert any(r.category == DiagnosticCategory.permissions for r in records)


def test_run_diagnostics_categories():
    records = run_diagnostics(db_path=":memory:", config_path=None)
    categories = {r.category for r in records}
    assert DiagnosticCategory.config in categories
    assert DiagnosticCategory.database in categories
    assert DiagnosticCategory.engine in categories
    assert DiagnosticCategory.topology in categories
    assert DiagnosticCategory.capabilities in categories
    assert DiagnosticCategory.permissions in categories


def test_to_json_records_stable():
    records = run_diagnostics(db_path=":memory:", config_path=None)
    payload = to_json_records(records)
    for rec in payload:
        assert set(rec.keys()) == {
            "id",
            "category",
            "severity",
            "message",
            "remediation",
            "evidence_ref",
        }
    text = json.dumps(payload, sort_keys=True)
    text2 = json.dumps(to_json_records(records), sort_keys=True)
    assert text == text2


def test_json_output_machine_readable(tmp_path):
    records = run_diagnostics(db_path=str(tmp_path / "missing.db"), config_path=None)
    data = [r.model_dump(mode="json") for r in records]
    assert json.loads(json.dumps(data)) == data


def test_structured_diagnostic_preserves_legacy_record():
    record = DiagnosticRecord(
        id="run.dirty",
        category=DiagnosticCategory.database,
        severity=DiagnosticSeverity.error,
        message="dirty lease",
        remediation="compensate manually",
        evidence_ref="l-1",
    )
    diagnostic = structured_diagnostics([record], related_run="run-1")[0]
    assert isinstance(diagnostic, Diagnostic)
    assert diagnostic.check_id == "run.dirty"
    assert diagnostic.id == "run.dirty"
    assert diagnostic.status is DiagnosticStatus.DIRTY
    assert diagnostic.related_run == "run-1"
    assert diagnostic.evidence == {"ref": "l-1"}
    assert diagnostic.remediation == "compensate manually"


def test_structured_diagnostic_status_projection():
    records = [
        DiagnosticRecord(
            id="doctor.ok",
            category=DiagnosticCategory.config,
            severity=DiagnosticSeverity.info,
            message="ok",
        ),
        DiagnosticRecord(
            id="doctor.warn",
            category=DiagnosticCategory.engine,
            severity=DiagnosticSeverity.warning,
            message="missing runtime",
        ),
        DiagnosticRecord(
            id="doctor.block",
            category=DiagnosticCategory.config,
            severity=DiagnosticSeverity.error,
            message="blocked",
        ),
    ]
    statuses = [item.status for item in structured_diagnostics(records)]
    assert statuses == [
        DiagnosticStatus.HEALTHY,
        DiagnosticStatus.WARNING,
        DiagnosticStatus.BLOCKED,
    ]


def test_lease_projection_exposes_recovery_contract():
    from mayhem.domain.common import utc_now
    from mayhem.domain.leases import FaultLease, LeaseState

    lease = FaultLease.model_validate(
        {
            "id": "l-projection",
            "run_id": "run-1",
            "fault_id": "net.latency",
            "owner_agent": "agent-1",
            "targets": ["api"],
            "undo_ops": ({"op": "tc.del", "args": {"target": "api"}},),
            "verify_probes": ({"probe": "tc.qdisc_absent", "args": {}, "expect_present": False},),
            "ttl_seconds": 30,
            "state": LeaseState.ACTIVE,
            "created_at": utc_now(),
        }
    )
    projection = lease_projection(lease)
    assert projection["owner"] == "agent-1"
    assert projection["ttl_seconds"] == 30.0
    assert projection["expires_at"]
    assert projection["target"] == ["api"]
    assert projection["fault"] == "net.latency"
    assert projection["state"] == "active"
    assert projection["recovery"] == "pending"
    assert projection["compensation"][0]["op"] == "tc.del"
    assert projection["probe"][0]["probe"] == "tc.qdisc_absent"


def test_inspect_projections_are_data_only(tmp_path, capsys):
    from mayhem.cli.app import main
    from mayhem.domain.evidence import EvidenceEnvelope
    from mayhem.infra.evidence import write_evidence
    from mayhem.infra.store import Store

    store = Store.open_migrated(tmp_path / "inspect.db")
    with store.write() as conn:
        conn.execute(
            "INSERT INTO config_snapshots (id, resolved_json, source_map, created_at) "
            "VALUES ('cfg', '{}', '{}', 'now')"
        )
        conn.execute(
            "INSERT INTO runs (id, experiment_name, kind, spec_json, plan_json, seed, "
            "status, environment_fingerprint, config_snapshot_id) "
            "VALUES ('run-inspect', 'exp', 'deterministic', '{}', '{}', 1, "
            "'completed', 'fp', 'cfg')"
        )
        conn.execute(
            "INSERT INTO fault_leases (id, state, owner_agent, undo_json, verify_json, "
            "ttl_seconds, expires_at, run_id, fault_id, targets_json, created_epoch_s) "
            "VALUES ('l-inspect', 'active', 'agent', '[{\"op\":\"noop\"}]', "
            "'[{\"probe\":\"exec\"}]', 60, "
            "'2030-01-01T00:00:00+00:00', 'run-inspect', 'proc.pause', '[\"api\"]', 0)"
        )
    write_evidence(
        store,
        EvidenceEnvelope(
            run_id="run-inspect",
            plan_hash="hash",
            step_reports=({"step_id": "s1"},),
            verdict="pass",
            recovery_state="pending",
        ),
    )
    store.close()
    assert main(["--db", str(tmp_path / "inspect.db"), "inspect", "leases", "--json"]) == 0
    lease_payload = json.loads(capsys.readouterr().out)
    assert lease_payload["leases"][0]["recovery"] == "pending"
    assert main([
        "--db",
        str(tmp_path / "inspect.db"),
        "inspect",
        "run",
        "run-inspect",
        "--report",
        "json",
    ]) == 0
    report_payload = json.loads(capsys.readouterr().out)
    assert report_payload["report_id"] == "report-run-inspect"
    assert report_payload["evidence"]["run_id"] == "run-inspect"



def test_diagnose_run_reports_dirty_and_related_run(tmp_path):
    from mayhem.infra.store import Store

    store = Store.open_migrated(tmp_path / "runs.db")
    with store.write() as conn:
        conn.execute(
            "INSERT INTO config_snapshots (id, resolved_json, source_map, created_at) "
            "VALUES ('cfg', '{}', '{}', 'now')"
        )
        conn.execute(
            "INSERT INTO runs (id, experiment_name, kind, spec_json, plan_json, seed, "
            "status, environment_fingerprint, config_snapshot_id) "
            "VALUES ('run-dirty', 'exp', 'deterministic', '{}', '{}', 1, 'failed', 'fp', 'cfg')"
        )
        conn.execute(
            "INSERT INTO fault_leases (id, state, owner_agent, undo_json, verify_json, "
            "ttl_seconds, expires_at, run_id, fault_id, targets_json, created_epoch_s, "
            "escalation_notes) VALUES ('l-dirty', 'dirty', 'agent', '[]', '[]', 60, "
            "'2030-01-01T00:00:00+00:00', 'run-dirty', 'proc.pause', '[\"api\"]', 0, 'manual')"
        )
    diagnostics = diagnose_run(store, "run-dirty")
    assert any(
        item.related_run == "run-dirty" and item.status is DiagnosticStatus.DIRTY
        for item in diagnostics
    )
    store.close()
