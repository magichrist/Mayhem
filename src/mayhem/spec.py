"""YAML drill-spec loading — the authored entry point into the domain.

Spec files stay close to the domain models: keys map 1:1 onto pydantic
fields (durations as ``10s`` strings, enums as lowercase values), so the
loader is a thin validate-and-discriminate layer, not a second language.

``load_drill`` / ``parse_drill`` handle the ``kind: drill`` format (ADR-0019)
— the only supported spec kind since the clean break (ADR-0021).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from mayhem.domain.errors import InvariantViolationError, SchemaValidationError
from mayhem.domain.experiments import DrillSpec
from mayhem.domain.secrets import require_no_literal_credentials


def _flatten(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors()[:8]:
        loc = ".".join(str(part) for part in err["loc"]) or "<root>"
        parts.append(f"{loc}: {err['msg']}")
    return "; ".join(parts)


def load_drill(path: str | Path) -> DrillSpec:
    """Load a drill spec from YAML; refuse anything the domain refuses."""
    raw_path = Path(path)
    if not raw_path.is_file():
        raise FileNotFoundError(f"spec file not found: {raw_path}")
    try:
        data = yaml.safe_load(raw_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SchemaValidationError("drill", f"invalid YAML: {exc}") from None
    return parse_drill(data)


def parse_drill(data: Any) -> DrillSpec:
    """Parse raw YAML data into a DrillSpec."""
    if not isinstance(data, dict):
        raise SchemaValidationError("drill", "top level must be a mapping")
    if data.get("kind") != "drill":
        raise SchemaValidationError("drill", f"expected kind: drill, got: {data.get('kind')}")
    _require_no_literal_credential(data)
    try:
        return DrillSpec.model_validate(data)
    except ValidationError as exc:
        raise SchemaValidationError("drill", _flatten(exc)) from None
    except InvariantViolationError as exc:
        raise SchemaValidationError("drill", str(exc)) from None


def _require_no_literal_credential(data: dict[str, Any]) -> None:
    """Refuse a spec carrying a credential *value* (plan 29 Phase 3).

    The plan's sentence for this phase is "a literal where a reference is
    required fails spec validation with the field named", and this is the door
    every authored drill spec comes through — `load_drill`, the API planner's
    file path, and the boundary report's. The decision is the domain's own
    (:func:`mayhem.domain.secrets.require_no_literal_credentials`), so "what
    counts as a literal" has exactly one answer; only the error type is local,
    because every caller of this function already handles
    :class:`SchemaValidationError` and none of them handles a raw domain
    refusal.

    The message is carried into the schema error verbatim, so the offending
    field path is what the author sees and the value never is.
    """
    try:
        require_no_literal_credentials(data, path="drill spec")
    except InvariantViolationError as exc:
        raise SchemaValidationError("drill", str(exc)) from None
