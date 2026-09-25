from __future__ import annotations

import json
import traceback
from dataclasses import dataclass, field
from typing import Any

import click

from mayhem.cli.exit_codes import ExitCode

SECRET_KEYS = frozenset({"password", "token", "secret", "api_key", "apikey", "credential"})

CODE_EXIT_MAP: dict[str, ExitCode] = {
    "usage_error": ExitCode.USAGE_ERROR,
    "ambiguous_command": ExitCode.AMBIGUOUS_COMMAND,
    "config_error": ExitCode.CONFIG_ERROR,
    "validation_error": ExitCode.VALIDATION_ERROR,
    "safety_refusal": ExitCode.SAFETY_REFUSAL,
    "experiment_failure": ExitCode.EXPERIMENT_FAILURE,
    "recovery_failure": ExitCode.RECOVERY_FAILURE,
    "toolkit_error": ExitCode.TOOLKIT_ERROR,
    "general_failure": ExitCode.GENERAL_FAILURE,
    "missing_target": ExitCode.VALIDATION_ERROR,
    "missing_capability": ExitCode.VALIDATION_ERROR,
    "stale_plan": ExitCode.VALIDATION_ERROR,
    "blocked_topology": ExitCode.VALIDATION_ERROR,
    "unavailable_engine": ExitCode.TOOLKIT_ERROR,
}


def _sanitize_details(details: dict[str, Any] | None) -> dict[str, Any]:
    if not details:
        return {}
    sanitized: dict[str, Any] = {}
    for key, value in details.items():
        lowered = key.lower()
        if any(secret in lowered for secret in SECRET_KEYS):
            sanitized[key] = "***redacted***"
        else:
            sanitized[key] = value
    return sanitized


@dataclass(slots=True)
class MayhemCliError(Exception):
    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    evidence_ref: str = ""

    def __post_init__(self) -> None:
        Exception.__init__(self, self.message)
        self.details = _sanitize_details(self.details)

    @property
    def exit_code(self) -> ExitCode:
        return CODE_EXIT_MAP.get(self.code, ExitCode.GENERAL_FAILURE)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
            "exit_code": int(self.exit_code),
        }
        if self.details:
            payload["details"] = dict(sorted(self.details.items()))
        if self.remediation:
            payload["remediation"] = self.remediation
        if self.evidence_ref:
            payload["evidence_ref"] = self.evidence_ref
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, ensure_ascii=False)

    def format_human(self, debug: bool = False) -> str:
        lines: list[str] = [f"error [{self.code}]: {self.message}"]
        if self.details:
            for key in sorted(self.details.keys()):
                lines.append(f"  {key}: {self.details[key]}")
        if self.remediation:
            lines.append(f"  remediation: {self.remediation}")
        if self.evidence_ref:
            lines.append(f"  evidence_ref: {self.evidence_ref}")
        if debug:
            tb = traceback.format_exc()
            if tb and tb.strip() != "NoneType: None":
                lines.append(tb.strip())
        return "\n".join(lines)

    def emit(self, debug: bool = False, as_json: bool = False) -> None:
        if as_json:
            click.echo(self.to_json(), err=True)
        else:
            click.echo(self.format_human(debug=False), err=True)
        if debug:
            tb = traceback.format_exc()
            if tb and tb.strip() != "NoneType: None":
                click.echo(tb.strip(), err=True)


def map_exception_to_error(exc: BaseException) -> MayhemCliError:
    from mayhem.cli.resolver import CommandResolutionError
    from mayhem.controller.planner import PlanningError
    from mayhem.controller.safety import SafetyRefusedError
    from mayhem.domain.errors import (
        DomainError,
        InvariantViolationError,
        SchemaValidationError,
        TargetDriftError,
        TargetResolutionError,
    )
    from mayhem.domain.maniac import ManiacError
    from mayhem.toolkit.tool_runner import ToolError

    if isinstance(exc, MayhemCliError):
        return exc
    if isinstance(exc, CommandResolutionError):
        code = "ambiguous_command" if exc.candidates else "usage_error"
        return MayhemCliError(
            code=code, message=str(exc), remediation="use a longer prefix or --help"
        )
    if isinstance(exc, click.UsageError):
        return MayhemCliError(
            code="usage_error", message=str(exc), remediation="see --help for usage"
        )
    if isinstance(exc, SafetyRefusedError):
        return MayhemCliError(
            code="safety_refusal",
            message=str(exc),
            remediation="adjust policy or target profile, or review safety docs",
        )
    if isinstance(exc, SchemaValidationError):
        subject = getattr(exc, "subject", "")
        if subject == "config":
            return MayhemCliError(
                code="config_error", message=str(exc), remediation="fix mayhem.yaml and retry"
            )
        return MayhemCliError(
            code="validation_error", message=str(exc), remediation="fix spec and retry"
        )
    if isinstance(
        exc,
        (
            InvariantViolationError,
            ManiacError,
            PlanningError,
            TargetResolutionError,
            TargetDriftError,
            FileNotFoundError,
        ),
    ):
        msg = str(exc)
        lowered = msg.lower()
        if "missing target" in lowered or "no such target" in lowered or "unresolved" in lowered:
            return MayhemCliError(
                code="missing_target", message=msg, remediation="check topology and target selector"
            )
        if "capability" in lowered or "unsupported" in lowered:
            return MayhemCliError(
                code="missing_capability",
                message=msg,
                remediation="check engine capabilities and configure requirements",
            )
        if "stale plan" in lowered or "fingerprint" in lowered or "drift" in lowered:
            return MayhemCliError(
                code="stale_plan", message=msg, remediation="re-run plan to refresh fingerprint"
            )
        if "blocked" in lowered or "topology" in lowered:
            return MayhemCliError(
                code="blocked_topology",
                message=msg,
                remediation="inspect topology for blocked cells and unblock",
            )
        if "engine" in lowered and ("unavailable" in lowered or "not found" in lowered):
            return MayhemCliError(
                code="unavailable_engine",
                message=msg,
                remediation="check engine availability with doctor",
            )
        return MayhemCliError(
            code="validation_error", message=msg, remediation="fix input and retry"
        )
    if isinstance(exc, ToolError):
        return MayhemCliError(
            code="toolkit_error", message=str(exc), remediation="check tool availability and logs"
        )
    if isinstance(exc, DomainError):
        return MayhemCliError(code="general_failure", message=str(exc))
    return MayhemCliError(code="general_failure", message=f"{type(exc).__name__}: {exc}")


def error_to_exit_code(code: str) -> int:
    return int(CODE_EXIT_MAP.get(code, ExitCode.GENERAL_FAILURE))
