"""YAML experiment-spec loading — the authored entry point into the domain.

Spec files stay close to the domain models: keys map 1:1 onto pydantic
fields (durations as ``10s`` strings, enums as lowercase values), so the
loader is a thin validate-and-discriminate layer, not a second language.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.experiments import DeterministicExperiment, RandomExperiment


def load_spec(path: str | Path) -> DeterministicExperiment | RandomExperiment:
    """Load an experiment spec from YAML; refuse anything the domain refuses."""
    raw_path = Path(path)
    if not raw_path.is_file():
        raise FileNotFoundError(f"spec file not found: {raw_path}")
    try:
        data = yaml.safe_load(raw_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SchemaValidationError("spec", f"invalid YAML: {exc}") from None
    return parse_spec(data)


_ACTION_KEYS = {
    "inject_fault": "inject_fault",
    "start_load": "start_load",
    "stop_load": "stop_load",
    "check": "check",
    "notify": "notify",
    "parallel": "parallel",
}


def parse_spec(data: Any) -> DeterministicExperiment | RandomExperiment:
    if not isinstance(data, dict):
        raise SchemaValidationError("spec", "top level must be a mapping")
    kind = data.get("kind")
    normalized = _normalize(data)
    try:
        if kind == "random":
            return RandomExperiment.model_validate(normalized)
        if kind == "deterministic":
            return DeterministicExperiment.model_validate(normalized)
    except ValidationError as exc:
        raise SchemaValidationError("spec", _flatten(exc)) from None
    raise SchemaValidationError(
        "spec", f"field 'kind' must be 'deterministic' or 'random', got {kind!r}"
    )


def _normalize(data: dict[str, Any]) -> dict[str, Any]:
    """Translate the friendly YAML dialect onto domain field names."""
    out = dict(data)
    if "metadata" not in out and "name" in out:
        metadata: dict[str, Any] = {"name": out.pop("name")}
        for key in ("hypothesis", "labels"):
            if key in out:
                metadata[key] = out.pop(key)
        out["metadata"] = metadata
    steps = out.get("steps")
    if isinstance(steps, list):
        out["steps"] = [_normalize_step(step) for step in steps]
    return out


def _normalize_step(step: Any) -> Any:
    if not isinstance(step, dict):
        return step
    candidates = [key for key in step if key in _ACTION_KEYS or key == "wait"]
    if len(candidates) != 1:
        raise SchemaValidationError(
            "step", f"exactly one action key required, found {candidates or 'none'}"
        )
    key = candidates[0]
    payload = step[key]
    out = {k: v for k, v in step.items() if k != key}
    if key == "wait":
        out["action"] = {"type": "wait", "duration": payload}
        return out
    if not isinstance(payload, dict):
        raise SchemaValidationError("step", f"{key} expects a mapping body")
    body = dict(payload)
    if key == "inject_fault" and "targets" in body and "selectors" not in body:
        body["selectors"] = body.pop("targets")  # YAML dialect alias
    out["action"] = {"type": key, **body}
    return out


def _flatten(exc: ValidationError) -> str:
    parts = []
    for err in exc.errors()[:8]:
        loc = ".".join(str(part) for part in err["loc"]) or "<root>"
        parts.append(f"{loc}: {err['msg']}")
    return "; ".join(parts)
