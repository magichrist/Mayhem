"""Spec loading: schema round-trips and refusals (moved from test_cli.py)."""

from pathlib import Path

from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.experiments import DeterministicExperiment, RandomExperiment
from mayhem.spec import load_spec, parse_spec

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
            assert "greater than or equal to 1" in str(exc)
        else:
            raise AssertionError("count=0 must be refused")

    def test_missing_file_raises_filenotfound(self, tmp_path: Path) -> None:
        try:
            load_spec(tmp_path / "nope.yaml")
        except FileNotFoundError:
            pass
        else:
            raise AssertionError("missing file must raise")
