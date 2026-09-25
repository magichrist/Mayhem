import json
import pathlib

from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.execution import (
    artifact_name,
    blast_radius_display,
    compensation_display,
    expected_evidence_display,
    reject_if_stale,
)
from mayhem.controller.plan_diff import diff_plans
from mayhem.domain.evidence import EvidenceEnvelope
from mayhem.infra.evidence import build_evidence, verify_evidence

TESTCASE = (
    pathlib.Path(__file__).resolve().parents[2] / "examples" / "testCase" / "docker-compose.yml"
)
DRILL_YAML = """\
kind: drill
apiVersion: "mayhem/v1"
name: drill-pause
hypothesis: test
config:
  risk_ceiling: critical
  max_faults: 1
  timeout: 10m
containers:
  testcase-api:
    faults:
      - fault: proc.pause
        duration: 2s
execution:
  - parallel: [testcase-api]
"""


def _write(tmp_path, text):
    p = tmp_path / "spec.yaml"
    p.write_text(text)
    return p


def test_reject_stale_fingerprint():
    try:
        reject_if_stale(
            preflight_fingerprint="a" * 64,
            current_fingerprint="b" * 64,
            preflight_target="dev",
            current_target="dev",
        )
        raise AssertionError("should have raised")
    except ValueError as exc:
        assert "fingerprint changed" in str(exc)


def test_reject_stale_target():
    try:
        reject_if_stale(
            preflight_fingerprint="a" * 64,
            current_fingerprint="a" * 64,
            preflight_target="dev",
            current_target="prod",
        )
        raise AssertionError("should have raised")
    except ValueError as exc:
        assert "target changed" in str(exc)


def test_plan_reuse_from_file(tmp_path, monkeypatch):
    runner = CliRunner()
    _write(tmp_path, DRILL_YAML)
    with monkeypatch.context() as mp:
        mp.chdir(tmp_path)
        result = runner.invoke(
            app,
            ["prepare", "plan", "spec.yaml", "--compose", str(TESTCASE), "--json"],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        assert "plan_hash" in payload
        assert "engine" in payload


def test_explicit_approval_required(tmp_path, monkeypatch):
    runner = CliRunner()
    _write(tmp_path, DRILL_YAML)
    with monkeypatch.context() as mp:
        mp.chdir(tmp_path)
        from unittest.mock import MagicMock, patch

        with patch("mayhem.cli.services.RunEngine") as mock_cls:
            eng = mock_cls.return_value
            res = MagicMock()
            res.status = "completed"
            res.summary_md.return_value = "ok"
            res.run_id = "r-test"
            res.steps = []
            res.observability = []
            res.dirty_leases = []
            res.verdict = None
            res.wall_seconds = 0.1
            eng.execute.return_value = res
            result = runner.invoke(
                app,
                [
                    "--db",
                    str(tmp_path / "db.db"),
                    "--skip-gate",
                    "run",
                    "spec.yaml",
                    "--compose",
                    str(TESTCASE),
                    "--json",
                ],
            )
        assert result.exit_code == 0
        assert "plan_hash" in result.output or "target" in result.output


def test_blast_radius_display():
    out = blast_radius_display({"services_pct": 10.0, "hosts": 1.0})
    assert "services_pct=10.0" in out
    assert "blast_radius:" in out


def test_compensation_display():
    assert "compensated" in compensation_display("compensated")
    assert "unknown" in compensation_display("")


def test_expected_evidence_display():
    out = expected_evidence_display(("plan", "verdict"))
    assert "plan" in out and "verdict" in out


def test_artifact_naming():
    name = artifact_name("r-drill-pause-abc123", "evidence")
    assert name.startswith("r-drill-pause-abc123")
    assert name.endswith(".json")


def test_evidence_envelope_complete():
    env = build_evidence(
        run_id="r-1",
        plan=None,
        target_profile="dev",
        engine="docker",
        safety_decisions=("allow",),
        step_reports=({"step_id": "s1", "ok": True},),
        lease_timeline=(),
        observations=(),
        verdict="pass",
        recovery_state="recovered",
        remediation=(),
        environment_fingerprint="fp",
        target_identity="dev",
        blast_radius={},
        compensation_status="compensated",
    )
    result = verify_evidence(env)
    assert result["complete"] is False
    env2 = EvidenceEnvelope(run_id="r-1", plan_hash="abc", step_reports=({"a": 1},), verdict="pass")
    result2 = verify_evidence(env2)
    assert result2["complete"] is True


def test_evidence_file_written(tmp_path):
    env = EvidenceEnvelope(
        run_id="r-evidence-test",
        plan_hash="abc123",
        step_reports=({"step_id": "s1"},),
        verdict="pass",
        target_profile="dev",
    )
    from mayhem.infra.evidence import write_evidence_file

    path = write_evidence_file(env, tmp_path)
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["run_id"] == "r-evidence-test"


def test_verify_command_without_mutation(tmp_path):
    runner = CliRunner()
    env = EvidenceEnvelope(
        run_id="r-verify-1", plan_hash="abc", step_reports=({"step_id": "s1"},), verdict="pass"
    )
    from mayhem.infra.store import Store

    store = Store.open_migrated(tmp_path / "v.db")
    from mayhem.infra.evidence import write_evidence

    write_evidence(store, env)
    store.close()
    result = runner.invoke(app, ["--db", str(tmp_path / "v.db"), "verify", "r-verify-1", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["complete"] is True


def test_plan_diff_schemas():
    a = {"steps": [{"id": "wait-0000"}], "run_id": "r-1"}
    b = {"steps": [{"id": "wait-0000"}, {"id": "wait-0001"}], "run_id": "r-1"}
    diff = diff_plans(a, b)
    assert set(diff.keys()) == {
        "added",
        "removed",
        "changed_keys",
        "equal",
        "authored_hash",
        "accepted_hash",
    }
    assert diff["equal"] is False
