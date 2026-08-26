"""CLI surface: lifecycle commands, prefix resolution, output formats."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from mayhem.cli.app import main

DETERMINISTIC_YAML = """
kind: deterministic
name: pause-drill
hypothesis: brief process pause is survivable
steps:
  - id: pause
    inject_fault:
      fault: proc.pause
      targets:
        - kind: process
          expr: "name=api"
      duration: 10s
    on_failure: abort_and_recover
  - id: settle
    wait: 2s
"""


def _write(tmp_path: Path, text: str) -> Path:
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(text)
    return spec_file


def _sleeper() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"],
        stdout=subprocess.DEVNULL,
    )


class TestToolkitGroup:
    def test_faults_lists_catalog(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["toolkit", "faults"]) == 0
        assert "proc.pause" in capsys.readouterr().out

    def test_two_level_prefix_reaches_nested_command(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, DETERMINISTIC_YAML)
        assert main(["ex", "v", str(spec), "--process", "api=424242"]) == 0
        assert "validated r-pause-drill" in capsys.readouterr().out


class TestPlanValidateRun:
    def test_plan_prints_frozen_json(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, DETERMINISTIC_YAML)
        assert main(["plan", str(spec), "--process", "api=424242"]) == 0
        out = capsys.readouterr().out
        assert '"proc.pause"' in out
        plan = json.loads(out)
        assert plan["run_id"] == "r-pause-drill"

    def test_validate_passes_gates(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, DETERMINISTIC_YAML)
        assert main(["v", str(spec), "--process", "api=424242"]) == 0
        assert "validated r-pause-drill" in capsys.readouterr().out

    def test_bad_process_flag_is_usage_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, DETERMINISTIC_YAML)
        assert main(["plan", str(spec), "--process", "api"]) == 2
        err = capsys.readouterr().err
        assert "--process" in err

    def test_run_end_to_end_real_process(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        proc = _sleeper()
        try:
            needle = 'expr: "name=api"'
            spec_text = DETERMINISTIC_YAML.replace(needle, f'expr: "sleeper-{proc.pid}"')
            spec = _write(tmp_path, spec_text)
            db = tmp_path / "cli.db"
            argv = [
                "--db",
                str(db),
                "run",
                str(spec),
                "--process",
                f"sleeper-{proc.pid}={proc.pid}",
            ]
            assert main(argv) == 0
            assert "completed" in capsys.readouterr().out
            assert main(["--db", str(db), "status"]) == 0
            assert "r-pause-drill" in capsys.readouterr().out
            assert main(["--db", str(db), "status", "--run", "r-pause-drill"]) == 0
            detail = json.loads(capsys.readouterr().out)
            assert detail["id"] == "r-pause-drill"
            assert main(["--db", str(db), "h", "r-pause-drill"]) == 0
            journal = json.loads(capsys.readouterr().out)
            assert any(step["action_type"] == "InjectFault" for step in journal["steps"])
        finally:
            proc.terminate()
            proc.wait(timeout=10)


class TestRecoveryCommands:
    def test_janitor_quiet_sweep(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--db", str(tmp_path / "j.db"), "janitor"]) == 0
        assert "nothing to do" in capsys.readouterr().out

    def test_recover_unknown_run_is_noop(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["--db", str(tmp_path / "j.db"), "recover", "r-ghost"]) == 0
        assert "nothing to recover" in capsys.readouterr().out

    def test_history_unknown_run_returns_empty(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["--db", str(tmp_path / "j.db"), "history", "r-ghost"])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data == {"steps": [], "events": [], "leases": []}

    def test_status_empty_db(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--db", str(tmp_path / "j.db"), "status"]) == 0
