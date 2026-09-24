from __future__ import annotations

import json

from mayhem.cli.app import main
from mayhem.cli.errors import MayhemCliError, error_to_exit_code, map_exception_to_error
from mayhem.cli.exit_codes import ExitCode
from mayhem.controller.safety import SafetyRefusedError
from mayhem.domain.errors import SchemaValidationError, TargetResolutionError
from mayhem.toolkit.tool_runner import ToolError


def test_mayhem_cli_error_carries_fields():
    err = MayhemCliError(
        code="missing_target",
        message="no target",
        details={"selector": "x"},
        remediation="fix",
        evidence_ref="r1",
    )
    d = err.to_dict()
    assert d["code"] == "missing_target"
    assert d["message"] == "no target"
    assert d["details"]["selector"] == "x"
    assert d["remediation"] == "fix"
    assert d["evidence_ref"] == "r1"
    assert d["exit_code"] == int(ExitCode.VALIDATION_ERROR)


def test_error_codes_mapping():
    assert error_to_exit_code("missing_target") == int(ExitCode.VALIDATION_ERROR)
    assert error_to_exit_code("missing_capability") == int(ExitCode.VALIDATION_ERROR)
    assert error_to_exit_code("stale_plan") == int(ExitCode.VALIDATION_ERROR)
    assert error_to_exit_code("blocked_topology") == int(ExitCode.VALIDATION_ERROR)
    assert error_to_exit_code("unavailable_engine") == int(ExitCode.TOOLKIT_ERROR)
    assert error_to_exit_code("ambiguous_command") == int(ExitCode.AMBIGUOUS_COMMAND)
    assert error_to_exit_code("usage_error") == int(ExitCode.USAGE_ERROR)
    assert error_to_exit_code("config_error") == int(ExitCode.CONFIG_ERROR)
    assert error_to_exit_code("safety_refusal") == int(ExitCode.SAFETY_REFUSAL)


def test_no_secret_in_details():
    err = MayhemCliError(
        code="general_failure",
        message="bad",
        details={"password": "hunter2", "token": "abc", "info": "keep"},
    )
    assert err.details["password"] == "***redacted***"
    assert err.details["token"] == "***redacted***"
    assert err.details["info"] == "keep"
    payload = json.dumps(err.to_dict())
    assert "hunter2" not in payload
    assert "abc" not in payload


def test_map_safety_refused():
    exc = SafetyRefusedError("safety.refused", "denied")
    err = map_exception_to_error(exc)
    assert err.code == "safety_refusal"
    assert err.exit_code == ExitCode.SAFETY_REFUSAL


def test_map_schema_validation_config():
    exc = SchemaValidationError("config", "bad yaml")
    err = map_exception_to_error(exc)
    assert err.code == "config_error"
    assert err.exit_code == ExitCode.CONFIG_ERROR


def test_map_schema_validation_other():
    exc = SchemaValidationError("spec", "bad spec")
    err = map_exception_to_error(exc)
    assert err.code == "validation_error"


def test_map_tool_error():
    exc = ToolError("tool missing")
    err = map_exception_to_error(exc)
    assert err.code == "toolkit_error"
    assert err.exit_code == ExitCode.TOOLKIT_ERROR


def test_map_target_resolution_is_missing_target():
    exc = TargetResolutionError("sel", "unresolved")
    err = map_exception_to_error(exc)
    assert err.code == "missing_target"


def test_debug_does_not_change_exit_code(capsys):
    code = main(["--debug", "run", "--help"])
    assert code == 0
    code2 = main(["plan", "--help"])
    assert code2 == 0


def test_error_json_format_with_format_flag(capsys):
    code = main(
        ["--format", "json", "plan", "nonexistent.yaml", "--compose", "nonexistent-compose.yml"]
    )
    assert code == int(ExitCode.USAGE_ERROR)
    err_text = capsys.readouterr().err
    assert err_text.strip() != ""
    start = err_text.find("{")
    end = err_text.rfind("}")
    assert start != -1 and end != -1
    payload = json.loads(err_text[start : end + 1])
    assert "code" in payload


def test_mayhem_cli_error_debug_traceback_still_same_code(capsys):
    err = MayhemCliError(code="stale_plan", message="stale", remediation="re-plan")
    try:
        raise err
    except MayhemCliError as exc:
        mapped = map_exception_to_error(exc)
        assert mapped.exit_code == ExitCode.VALIDATION_ERROR
        text = mapped.format_human(debug=False)
        assert "stale" in text
        assert mapped.code == "stale_plan"


def test_usage_error_shown():
    code = main(["--podman", "--kubernetes", "plan", "--help"])
    assert code == int(ExitCode.USAGE_ERROR)
