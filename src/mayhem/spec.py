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

from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.experiments import DrillSpec


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
    try:
        return DrillSpec.model_validate(data)
    except ValidationError as exc:
        raise SchemaValidationError("drill", _flatten(exc)) from None
