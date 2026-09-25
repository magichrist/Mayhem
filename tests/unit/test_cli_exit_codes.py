"""The documented exit-code contract of ``mayhem.cli.app.main``."""

from pathlib import Path

import pytest

import mayhem.cli.services as services_mod
from mayhem.cli import lifecycle
from mayhem.cli.app import main
from mayhem.cli.exit_codes import ExitCode
from mayhem.controller.safety import SafetyRefusedError
from mayhem.toolkit.tool_runner import ToolError

TESTCASE = Path(__file__).resolve().parents[2] / "examples" / "testCase"
COMPOSE_FILE = TESTCASE / "docker-compose.yml"

SPEC = """\
kind: drill
name: pause-drill
config:
  risk_ceiling: critical
containers:
  testcase-api:
    faults:
      - fault: proc.pause
        duration: 10s
execution:
  - parallel: [testcase-api]
"""

BAD_CONFIG = """
version: 0.0
bogus_section:
  nonsense: true
"""


class TestDocumentedExitCodes:
    def test_success(self, tmp_path: Path) -> None:
        assert main(["--db", str(tmp_path / "x.db"), "janitor"]) == int(ExitCode.SUCCESS)

    def test_ambiguous_command_prefix(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["c"]) == int(ExitCode.AMBIGUOUS_COMMAND)
        err = capsys.readouterr().err
        assert "campaign" in err and "commands" in err

    def test_unknown_command_prefix(self) -> None:
        assert main(["zzz"]) == int(ExitCode.USAGE_ERROR)

    def test_usage_error_bad_flag_value(self, tmp_path: Path) -> None:
        spec = tmp_path / "spec.yaml"
        spec.write_text(SPEC)
        assert main(["prepare", "plan", str(spec), "--process", "api"]) == int(ExitCode.USAGE_ERROR)

    def test_missing_spec_file(self) -> None:
        assert main(
            ["prepare", "plan", "/nonexistent/spec.yaml", "--compose", str(COMPOSE_FILE)]
        ) == int(ExitCode.VALIDATION_ERROR)

    def test_invalid_spec_schema(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("kind: nope\nname: x\n")
        assert main(["prepare", "plan", str(bad), "--compose", str(COMPOSE_FILE)]) == int(
            ExitCode.VALIDATION_ERROR
        )

    def test_invalid_config_layer(self, tmp_path: Path) -> None:
        cfg = tmp_path / "mayhem.yaml"
        cfg.write_text(BAD_CONFIG)
        rc = main(["--config", str(cfg), "prepare", "config", "show"])
        assert rc == int(ExitCode.CONFIG_ERROR)

    def test_safety_refusal_maps_to_five(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        spec = tmp_path / "spec.yaml"
        spec.write_text(SPEC)

        def _refuse(**kwargs: object) -> None:
            raise SafetyRefusedError("g1_blast_radius", "blast radius exceeded")

        monkeypatch.setattr(lifecycle, "prepare", _refuse)
        assert main(["prepare", "validate", str(spec), "--compose", str(COMPOSE_FILE)]) == int(
            ExitCode.SAFETY_REFUSAL
        )
        assert "safety refused" in capsys.readouterr().err

    def test_tool_error_maps_to_nine(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(*, host: str) -> object:
            raise ToolError("docker", "timeout after 30s")

        monkeypatch.setattr(services_mod, "probe_capabilities", _boom)
        assert main(["discover", "capabilities"]) == int(ExitCode.TOOLKIT_ERROR)

    def test_debug_reraises_internal_errors(self, tmp_path: Path) -> None:
        spec = tmp_path / "spec.yaml"
        spec.write_text(SPEC)

        def _explode(**kwargs: object) -> None:
            raise RuntimeError("internal detail")

        original = lifecycle.prepare
        try:
            lifecycle.prepare = _explode  # type: ignore[assignment]
            with pytest.raises(RuntimeError):
                main(["--debug", "prepare", "validate", str(spec), "--compose", str(COMPOSE_FILE)])
        finally:
            lifecycle.prepare = original


class TestHelpSurface:
    def test_bare_invocation_shows_usage(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main([])
        out = capsys.readouterr()
        assert rc == int(ExitCode.USAGE_ERROR)
        combined = out.out + out.err
        assert "Commands:" in combined

    def test_help_flag_exits_zero(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--help"]) == int(ExitCode.SUCCESS)
        assert "safe-by-construction" in capsys.readouterr().out
