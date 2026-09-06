"""CLI surface for campaign lifecycle + sequential run (ADR-0023)."""

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from mayhem.cli.app import main
from mayhem.controller.executor import RunResult

TESTCASE = Path(__file__).resolve().parents[2] / "examples" / "testCase"
COMPOSE_FILE = TESTCASE / "docker-compose.yml"

DRILL_YAML = """\
kind: drill
name: drill-pause
hypothesis: brief process pause is survivable
config:
  risk_ceiling: critical
  max_faults: 1
  timeout: 10m
containers:
  testcase-api:
    faults:
      - fault: proc.pause
        duration: 10s
  testcase-lb:
    faults:
      - fault: fuzz.protocol_abuse
        duration: 5s
execution:
  - parallel: [testcase-api, testcase-lb]
  - wait: 2s
  - check:
      - http: http://testcase-api:8080/
        expect: { status: 200 }
"""


def _stub_engine(execute_status: str = "completed"):
    def factory(*args: object, **kwargs: object):
        eng = MagicMock()
        eng.execute.return_value = RunResult(
            run_id="r-camp",
            status=execute_status,
            started_at_epoch_s=0.0,
            ended_at_epoch_s=0.0,
        )
        return eng

    return factory


def _campaign_id(db: Path) -> str:
    with sqlite3.connect(db) as conn:
        return conn.execute("SELECT id FROM campaigns ORDER BY created_at LIMIT 1").fetchone()[0]


def _status(db: Path) -> str:
    with sqlite3.connect(db) as conn:
        row = conn.execute("SELECT status FROM campaigns ORDER BY created_at LIMIT 1").fetchone()
        return str(row[0])


def _make_draft(db: Path, tmp_path: Path, name: str = "cli-e2e") -> str:
    rc = main(["--db", str(db), "campaign", "create", name])
    assert rc == 0
    cid = _campaign_id(db)
    spec = tmp_path / "spec.yaml"
    spec.write_text(DRILL_YAML)
    rc = main(["--db", str(db), "campaign", "add-experiment", cid, str(spec)])
    assert rc == 0
    return cid


class TestCampaignRunCLI:
    def test_default_policy_aborts_on_failed_experiment(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "cli.db"
        cid = _make_draft(db, tmp_path)
        monkeypatch.setattr("mayhem.cli.services.RunEngine", _stub_engine("failed"))
        rc = main(
            [
                "--db",
                str(db),
                "campaign",
                "run",
                cid,
                "--compose",
                str(COMPOSE_FILE),
                "--no-gate",
            ]
        )
        out = capsys.readouterr().out
        assert rc == 0, out
        assert "finished with status failed" in out
        assert _status(db) == "aborted"

    def test_completed_campaign_records_observations(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "cli.db"
        cid = _make_draft(db, tmp_path)
        monkeypatch.setattr("mayhem.cli.services.RunEngine", _stub_engine("completed"))
        rc = main(
            [
                "--db",
                str(db),
                "campaign",
                "run",
                cid,
                "--compose",
                str(COMPOSE_FILE),
                "--no-gate",
            ]
        )
        out = capsys.readouterr().out
        assert rc == 0, out
        assert _status(db) == "completed"
        assert "finished with status completed" in out
        with sqlite3.connect(db) as conn:
            n_run = conn.execute(
                "SELECT COUNT(*) FROM observations WHERE source = ? AND kind = 'campaign_run'",
                (cid,),
            ).fetchone()[0]
            n_done = conn.execute(
                "SELECT COUNT(*) FROM observations WHERE source = ? AND kind = 'campaign_done'",
                (cid,),
            ).fetchone()[0]
        assert n_run == 1
        assert n_done == 1

    def test_requires_at_least_one_experiment(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        db = tmp_path / "cli.db"
        rc = main(["--db", str(db), "campaign", "create", "empty"])
        assert rc == 0
        cid = _campaign_id(db)
        rc = main(
            [
                "--db",
                str(db),
                "campaign",
                "run",
                cid,
                "--compose",
                str(COMPOSE_FILE),
                "--no-gate",
            ]
        )
        assert rc == 2

    def test_show_lists_runs_after_execution(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "cli.db"
        cid = _make_draft(db, tmp_path)
        monkeypatch.setattr("mayhem.cli.services.RunEngine", _stub_engine("completed"))
        rc = main(
            [
                "--db",
                str(db),
                "campaign",
                "run",
                cid,
                "--compose",
                str(COMPOSE_FILE),
                "--no-gate",
            ]
        )
        assert rc == 0

        rc = main(["--db", str(db), "campaign", "show", cid])
        out = capsys.readouterr().out
        assert rc == 0
        assert "Runs:" in out
        assert "spec.yaml -> r-camp" in out

    def test_show_json_includes_runs(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        db = tmp_path / "cli.db"
        cid = _make_draft(db, tmp_path)
        monkeypatch.setattr("mayhem.cli.services.RunEngine", _stub_engine("completed"))
        main(
            [
                "--db",
                str(db),
                "campaign",
                "run",
                cid,
                "--compose",
                str(COMPOSE_FILE),
                "--no-gate",
            ]
        )
        capsys.readouterr()  # drain the run output
        rc = main(["--db", str(db), "campaign", "show", cid, "--json"])
        doc = json.loads(capsys.readouterr().out)
        assert rc == 0
        assert doc["status"] == "completed"
        assert doc["runs"][0]["run_id"] == "r-camp"
        assert "spec.yaml" in doc["runs"][0]["spec_path"]

    def test_start_sets_running_status(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        db = tmp_path / "cli.db"
        cid = _make_draft(db, tmp_path)
        rc = main(["--db", str(db), "campaign", "start", cid])
        assert rc == 0
        assert _status(db) == "running"
        rc = main(["--db", str(db), "campaign", "archive", cid])
        assert rc == 0
        assert _status(db) == "completed"
