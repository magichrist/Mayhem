from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

OUTPUT_SCHEMA_VERSION = "1.0"
OUTPUT_SCHEMA_LOCATION = "src/mayhem/schemas/output_v1.json"


@dataclass(frozen=True, slots=True)
class CommandResult:
    status: str
    data: Any | None = None
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    meta: dict[str, Any] = field(default_factory=dict)

    def is_success(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": self.status,
            "schema_version": OUTPUT_SCHEMA_VERSION,
        }
        if self.data is not None:
            payload["data"] = self.data
        else:
            payload["data"] = None
        payload["warnings"] = list(self.warnings)
        payload["errors"] = list(self.errors)
        payload["evidence_refs"] = list(self.evidence_refs)
        if self.meta:
            payload["meta"] = dict(sorted(self.meta.items()))
        else:
            payload["meta"] = {}
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True, ensure_ascii=False)

    @classmethod
    def ok(
        cls,
        data: Any | None = None,
        warnings: tuple[str, ...] | list[str] = (),
        evidence_refs: tuple[str, ...] | list[str] = (),
        meta: dict[str, Any] | None = None,
    ) -> CommandResult:
        return cls(
            status="ok",
            data=data,
            warnings=tuple(warnings),
            errors=(),
            evidence_refs=tuple(evidence_refs),
            meta=dict(meta or {}),
        )

    @classmethod
    def fail(
        cls,
        errors: tuple[str, ...] | list[str],
        data: Any | None = None,
        warnings: tuple[str, ...] | list[str] = (),
        evidence_refs: tuple[str, ...] | list[str] = (),
        meta: dict[str, Any] | None = None,
    ) -> CommandResult:
        return cls(
            status="error",
            data=data,
            warnings=tuple(warnings),
            errors=tuple(errors),
            evidence_refs=tuple(evidence_refs),
            meta=dict(meta or {}),
        )


def resolve_format(
    explicit_format: str | None,
    as_json: bool | None,
    env_format: str | None = None,
) -> str:
    if explicit_format is not None:
        normalized = explicit_format.strip().lower()
        if normalized in ("json", "yaml", "text", "human"):
            return "json" if normalized == "json" else ("yaml" if normalized == "yaml" else "text")
        return "text"
    if as_json:
        return "json"
    if env_format is not None and env_format.strip().lower() in ("json", "yaml", "text"):
        return env_format.strip().lower()
    return "text"


def is_human_format(fmt: str) -> bool:
    return fmt not in ("json", "yaml")


def current_format(default: str = "text") -> str:
    """The format the global ``--format`` option resolved to for this command.

    The root group stores the resolved format in ``mayhem.cli.app._STATE``;
    that is the single source of truth every command reads, so a new command
    gets text/JSON/YAML for free.
    """
    import importlib

    try:
        app_module = importlib.import_module("mayhem.cli.app")
    except Exception:
        return default
    value = getattr(app_module, "_STATE", {}).get("format", "")
    return str(value).lower() if value else default


def echo_machine(payload: object, *, as_json: bool = False) -> bool:
    """Echo ``payload`` as JSON or YAML when a machine format is requested.

    Returns ``True`` when it handled the output, so the caller can skip its own
    human rendering. ``--json`` is honoured for compatibility, and the global
    ``--format yaml`` gives every command the same three modes.
    """
    import click

    fmt = "json" if as_json else current_format()
    if fmt not in ("json", "yaml"):
        return False
    if fmt == "json":
        click.echo(json.dumps(payload, indent=2, sort_keys=True, default=str))
        return True
    import yaml

    click.echo(yaml.safe_dump(json.loads(json.dumps(payload, default=str)), sort_keys=True))
    return True


def should_use_color(no_color: bool = False) -> bool:
    if no_color:
        return False
    if os.environ.get("NO_COLOR"):
        return False
    return False


def envelopes_equal(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
