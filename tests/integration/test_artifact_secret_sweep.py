"""v0.9.0 checkpoint: no known credential fixture may reach a written artifact.

The redaction boundary is only real if the *bytes on disk* are clean, not just
the in-memory model. This test writes every artifact surface Mayhem produces
from one deliberately poisoned envelope and then greps the resulting files.
"""

from __future__ import annotations

import json
from pathlib import Path

from mayhem.domain.evidence import EvidenceEnvelope
from mayhem.infra.evidence import build_evidence, write_evidence, write_evidence_file
from mayhem.infra.report import ReportArtifactPolicy, write_report_artifacts
from mayhem.infra.store import Store

CREDENTIAL_FIXTURES = (
    "hunter2-plaintext-password",
    "gh-token-abc123",
    "registry-secret-xyz789",
    "alice:another-plain-password",
    "kubeconfig-secret-fixture",
)


def _poisoned_envelope() -> EvidenceEnvelope:
    return EvidenceEnvelope(
        run_id="cred-sweep",
        plan_hash="deadbeef",
        report_id="cred-sweep",
        plan_id="cred-sweep",
        engine="kubernetes",
        verdict="pass",
        recovery_state="none",
        step_reports=(
            {
                "step_id": "s1",
                "ok": True,
                "detail": (
                    "docker login -u alice --password hunter2-plaintext-password; "
                    "token=gh-token-abc123; https://bob:another-plain-password@example.test/x"
                ),
                "password": "hunter2-plaintext-password",
                "env": {"KUBECONFIG_SECRET": "kubeconfig-secret-fixture"},
            },
        ),
        observations=({"registry_token": "registry-secret-xyz789"},),
        lease_timeline=({"password": "hunter2-plaintext-password"},),
    )


def test_known_credentials_never_reach_written_artifacts(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    evidence_dir = tmp_path / "evidence"

    store = Store.open_migrated(tmp_path / "cred.db")
    try:
        write_evidence(store, _poisoned_envelope())
    finally:
        store.close()
    evidence_path = write_evidence_file(_poisoned_envelope(), evidence_dir)
    report_paths = write_report_artifacts(_poisoned_envelope(), artifact_dir=artifacts)

    paths = [evidence_path, *report_paths.values()]
    paths += sorted(p for p in artifacts.rglob("*") if p.is_file())
    paths += sorted(p for p in evidence_dir.rglob("*") if p.is_file())
    assert paths, "expected at least one artifact to inspect"

    for path in paths:
        blob = path.read_text(encoding="utf-8", errors="replace")
        for fixture in CREDENTIAL_FIXTURES:
            assert fixture not in blob, f"{fixture!r} leaked into {path.name}"


def test_evidence_row_in_sqlite_is_clean(tmp_path: Path) -> None:
    store = Store.open_migrated(tmp_path / "cred.db")
    try:
        write_evidence(store, _poisoned_envelope())
        rows = store.query("SELECT envelope_json FROM evidence_envelopes")
    finally:
        store.close()
    assert rows
    blob = json.dumps([dict(row) for row in rows])
    for fixture in CREDENTIAL_FIXTURES:
        assert fixture not in blob, f"{fixture!r} leaked into SQLite"


def test_redaction_metrics_record_the_sweep(tmp_path: Path) -> None:
    envelope = build_evidence(
        run_id="cred-sweep",
        plan=None,
        target_profile=None,
        engine="kubernetes",
        safety_decisions=(),
        step_reports=({"password": "hunter2-plaintext-password"},),
        lease_timeline=(),
        observations=({"registry_token": "registry-secret-xyz789"},),
        verdict="pass",
        recovery_state="none",
        remediation=(),
    )
    metrics = envelope.redaction_metrics
    assert metrics["redacted_path_count"] >= 2
    assert metrics["redacted_paths"]
    assert all(isinstance(path, str) for path in metrics["redacted_paths"])


def test_report_artifact_policy_directory_is_honored(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "artifacts"
    written = write_report_artifacts(
        _poisoned_envelope(),
        policy=ReportArtifactPolicy(artifact_dir=target),
    )
    assert written
    for path in written.values():
        assert target in Path(path).parents or Path(path).parent == target
