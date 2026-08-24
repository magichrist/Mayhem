"""Spec loading and the CLI surface."""
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from mayhem.cli import app
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.experiments import DeterministicExperiment, RandomExperiment
from mayhem.spec import load_spec, parse_spec

runner = CliRunner()

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

RANDOM_YAML = """
kind: random
name: maniac-hour
seed: 7
selection:
  count: 3
  categories: [cpu, mem, fs]
"""


class TestSpecLoader:
    def test_deterministic_roundtrip(self, tmp_path: Path) -> None:
        spec_file = tmp_path / "spec.yaml"
        spec_file.write_text(DETERMINISTIC_YAML)
        experiment = load_spec(spec_file)
        assert isinstance(experiment, DeterministicExperiment)
        assert experiment.metadata.name == "pause-drill"
        step = experiment.steps[0]
        fault = step.action
        assert fault.fault == "proc.pause"
        assert fault.duration == 10.0

    def test_random_spec(self) -> None:
        experiment = parse_spec({"kind": "random", "name": "m", "selection": {"count": 3}})
        assert isinstance(experiment, RandomExperiment)
        assert experiment.selection.count == 3

    def test_unknown_kind_refused(self) -> None:
        try:
            parse_spec({"kind": "quantum", "name": "x"})
        except SchemaValidationError as exc:
            assert "or 'random'" in str(exc)
        else:
            raise AssertionError("expected refusal")

    def test_domain_refusals_surfaced(self) -> None:
        bad = {"kind": "random", "name": "x", "selection": {"count": 0}}
        try:
            parse_spec(bad)
        except SchemaValidationError as exc:
            assert "spec" in str(exc)
        else:
            raise AssertionError("count=0 must be refused")

    def test_missing_file(self, tmp_path: Path) -> None:
        try:
            load_spec(tmp_path / "nope.yaml")
        except FileNotFoundError:
            pass
        else:
            raise AssertionError("missing file must raise")


def _write(tmp_path: Path, text: str) -> str:
    spec = tmp_path / "spec.yaml"
    spec.write_text(text)
    return str(spec)


class TestCli:
    def test_faults_lists_catalog(self) -> None:
        result = runner.invoke(app, ["faults"])
        assert result.exit_code == 0
        assert "proc.pause" in result.output

    def test_plan_prints_json(self, tmp_path: Path) -> None:
        spec = _write(tmp_path, DETERMINISTIC_YAML)
        result = runner.invoke(
            app, ["plan", spec, "--process", f"api={424242}"]
        )
        assert result.exit_code == 0, result.output
        assert '"proc.pause"' in result.output

    def test_plan_bad_process_flag(self, tmp_path: Path) -> None:
        spec = _write(tmp_path, DETERMINISTIC_YAML)
        result = runner.invoke(app, ["plan", spec, "--process", "api"])
        assert result.exit_code != 0

    def test_run_end_to_end_real_process(self, tmp_path: Path) -> None:
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(120)"],
            stdout=subprocess.DEVNULL,
        )
        try:
            needle = 'expr: "name=api"'
            spec_text = DETERMINISTIC_YAML.replace(needle, f'expr: "sleeper-{proc.pid}"')
            spec = _write(tmp_path, spec_text)
            db = tmp_path / "cli.db"
            result = runner.invoke(
                app,
                ["run", spec, "--db", str(db), "--process", f"sleeper-{proc.pid}={proc.pid}"],
            )
            assert result.exit_code == 0, result.output
            assert "completed" in result.output
            # status sees it too
            status = runner.invoke(app, ["status", "--db", str(db)])
            assert "r-pause-drill" in status.output
        finally:
            proc.terminate()
            proc.wait(timeout=10)

    def test_janitor_clean_sweep(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["janitor", "--db", str(tmp_path / "j.db")])
        assert result.exit_code == 0
        assert "expired=0" in result.output
