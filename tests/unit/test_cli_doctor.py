import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from mayhem.cli.app import app


def test_doctor_human_output(tmp_path, monkeypatch):
    runner = CliRunner()
    with monkeypatch.context() as mp:
        mp.chdir(tmp_path)
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code in {0, 4}
        assert "doctor" in result.output.lower() or "config" in result.output.lower()


def test_doctor_json_output_stable(tmp_path, monkeypatch):
    runner = CliRunner()
    with monkeypatch.context() as mp:
        mp.chdir(tmp_path)
        result = runner.invoke(app, ["doctor", "--json"])
        assert result.exit_code in (0, 4)
        payload = json.loads(result.output)
        assert "diagnostics" in payload
        assert "summary" in payload
        for rec in payload["diagnostics"]:
            assert "id" in rec
            assert "category" in rec
            assert "severity" in rec
            assert "message" in rec
            assert "remediation" in rec
            assert "evidence_ref" in rec
            assert rec["category"] in (
                "config",
                "database",
                "engine",
                "topology",
                "capabilities",
                "permissions",
            )
            assert rec["severity"] in ("info", "warning", "error")


def test_doctor_quiet_suppresses_human(tmp_path, monkeypatch):
    runner = CliRunner()
    with monkeypatch.context() as mp:
        mp.chdir(tmp_path)
        result = runner.invoke(app, ["doctor", "--quiet"])
        assert result.output.strip() == "" or "doctor" not in result.output.lower()
        assert result.exit_code in (0, 4)


def test_doctor_invalid_config_is_error(tmp_path, monkeypatch):
    runner = CliRunner()
    with monkeypatch.context() as mp:
        mp.chdir(tmp_path)
        Path("mayhem.yaml").write_text("apiVersion: mayhem/v1\nfrobnicate: true\n")
        result = runner.invoke(app, ["--config", "mayhem.yaml", "doctor", "--json"])
        payload = json.loads(result.output)
        errors = [r for r in payload["diagnostics"] if r["severity"] == "error"]
        assert len(errors) >= 1
        assert result.exit_code == 4


def test_doctor_missing_optional_runtimes_are_warnings(tmp_path, monkeypatch):
    runner = CliRunner()
    with monkeypatch.context() as mp:
        mp.chdir(tmp_path)
        with patch("mayhem.infra.diagnostics.shutil.which", return_value=None):
            result = runner.invoke(app, ["doctor", "--json"])
            payload = json.loads(result.output)
            engine_warnings = [
                record
                for record in payload["diagnostics"]
                if record["category"] == "engine" and record["severity"] == "warning"
            ]
            assert len(engine_warnings) >= 1
            engine_errors = [
                record
                for record in payload["diagnostics"]
                if record["category"] == "engine" and record["severity"] == "error"
            ]
            assert len(engine_errors) == 0


def test_doctor_database_migration_drift(tmp_path, monkeypatch):
    runner = CliRunner()
    with monkeypatch.context() as mp:
        mp.chdir(tmp_path)
        db = Path("mayhem.db")
        conn = sqlite3.connect(str(db))
        conn.execute(
            "CREATE TABLE _schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL)"
        )
        conn.execute("INSERT INTO _schema_migrations (version, name) VALUES (1, 'initial')")
        conn.commit()
        conn.close()
        result = runner.invoke(app, ["--db", "mayhem.db", "doctor", "--json"])
        payload = json.loads(result.output)
        db_errors = [
            record
            for record in payload["diagnostics"]
            if record["category"] == "database" and record["severity"] == "error"
        ]
        assert any(
            "migration" in record["message"].lower() or "missing" in record["message"].lower()
            for record in db_errors
        )
        assert result.exit_code == 4


def test_doctor_categories_filter(tmp_path, monkeypatch):
    runner = CliRunner()
    with monkeypatch.context() as mp:
        mp.chdir(tmp_path)
        result = runner.invoke(app, ["doctor", "--json", "--category", "config"])
        payload = json.loads(result.output)
        assert all(r["category"] == "config" for r in payload["diagnostics"])


def test_doctor_target_profile_handling(tmp_path, monkeypatch):
    runner = CliRunner()
    with monkeypatch.context() as mp:
        mp.chdir(tmp_path)
        Path("mayhem.yaml").write_text(
            "apiVersion: mayhem/v1\n"
            "targets:\n"
            "  dev:\n"
            "    engine: docker\n"
            "  prod:\n"
            "    engine: kubernetes\n"
        )
        result = runner.invoke(
            app,
            ["--config", "mayhem.yaml", "--target", "dev", "doctor", "--json"],
        )
        payload = json.loads(result.output)
        selected = [r for r in payload["diagnostics"] if r["id"] == "config.target.selected"]
        assert len(selected) == 1
        assert "dev" in selected[0]["message"]
