from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mayhem.domain.errors import SchemaValidationError

_ALLOWED_ENGINES = {"docker", "podman", "kubernetes"}
_FORBIDDEN_CREDENTIAL_KEYS = {"password", "secret", "token", "credentials", "api_key", "apikey"}
_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")


class TargetProfile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
    engine: Literal["docker", "podman", "kubernetes"] = "docker"
    compose: str | None = None
    namespace: str | None = None
    context: str | None = None
    policy: str | None = None
    workload_selector: str | None = None
    capability_policy: str | None = None
    targets: list[str] = Field(default_factory=list)
    observability: dict[str, Any] | None = None
    extends: str | None = None
    env_ref: str | None = None


def _reject_credentials(data: dict[str, Any]) -> None:
    for key, val in data.items():
        if key.lower() in _FORBIDDEN_CREDENTIAL_KEYS:
            raise SchemaValidationError("target_profile", f"credential key forbidden: {key}")
        if isinstance(val, dict):
            _reject_credentials(val)


def _validate_name(name: str) -> None:
    if not _NAME_RE.match(name):
        raise SchemaValidationError("target_profile", f"invalid target name: {name!r}")


def load_profiles_from_file(path: str | Path) -> dict[str, TargetProfile]:
    p = Path(path)
    if not p.exists():
        raise SchemaValidationError("target_profile", f"profile file not found: {p}")
    try:
        data = yaml.safe_load(p.read_text()) or {}
    except yaml.YAMLError as exc:
        raise SchemaValidationError("target_profile", f"invalid YAML in {p}: {exc}") from None
    if not isinstance(data, dict):
        raise SchemaValidationError("target_profile", f"{p} must contain a mapping")
    raw_profiles: Any = (
        data.get("targets")
        if "targets" in data
        else data.get("profiles")
        if "profiles" in data
        else data
    )
    if raw_profiles is None:
        return {}
    if not isinstance(raw_profiles, dict):
        raise SchemaValidationError(
            "target_profile", "profiles must be a mapping of name to profile"
        )
    result: dict[str, TargetProfile] = {}
    for name, profile_data in raw_profiles.items():
        _validate_name(str(name))
        pdata = profile_data
        if pdata is None:
            pdata = {}
        if not isinstance(pdata, dict):
            raise SchemaValidationError("target_profile", f"profile {name!r} must be a mapping")
        _reject_credentials(pdata)
        merged = dict(pdata)
        merged["name"] = str(name)
        if "engine" in merged and merged["engine"] not in _ALLOWED_ENGINES:
            raise SchemaValidationError(
                "target_profile", f"profile {name!r} has invalid engine {merged['engine']!r}"
            )
        try:
            result[str(name)] = TargetProfile.model_validate(merged)
        except ValidationError as exc:
            raise SchemaValidationError(
                "target_profile", f"invalid profile {name!r}: {exc}"
            ) from None
    if any(v.extends is not None for v in result.values()):
        result = _resolve_inheritance(result)
    return result


_ALLOWED_INHERITANCE_KEYS = frozenset(
    {
        "engine",
        "compose",
        "namespace",
        "context",
        "policy",
        "workload_selector",
        "capability_policy",
        "targets",
        "observability",
        "env_ref",
    }
)


def _resolve_inheritance(profiles: dict[str, TargetProfile]) -> dict[str, TargetProfile]:
    resolved: dict[str, TargetProfile] = {}
    for name, profile in profiles.items():
        if profile.extends is None:
            resolved[name] = profile
            continue
        parent_name = profile.extends
        if parent_name not in profiles:
            raise SchemaValidationError(
                "target_profile", f"profile {name!r} extends unknown profile {parent_name!r}"
            )
        parent = profiles[parent_name]
        if parent.extends is not None:
            raise SchemaValidationError(
                "target_profile", f"profile inheritance depth >1 not allowed: {name!r}"
            )
        _reject_credentials(parent.model_dump(mode="json"))
        merged = parent.model_dump(mode="json")
        child_dump = profile.model_dump(mode="json")
        for k, v in child_dump.items():
            if k == "name":
                continue
            if k == "extends":
                continue
            if k not in _ALLOWED_INHERITANCE_KEYS:
                raise SchemaValidationError(
                    "target_profile", f"profile {name!r} inherits non-allowlisted key {k!r}"
                )
            if (v is not None and v not in ([], {})) or k not in merged or merged[k] is None:
                merged[k] = v
        merged["name"] = name
        merged["extends"] = None
        try:
            resolved[name] = TargetProfile.model_validate(merged)
        except ValidationError as exc:
            raise SchemaValidationError(
                "target_profile", f"invalid inherited profile {name!r}: {exc}"
            ) from None
    return resolved


def load_profiles_from_mayhem_yaml(path: str | Path | None = None) -> dict[str, TargetProfile]:
    base = Path(path) if path else Path("mayhem.yaml")
    if not base.exists():
        return {}
    try:
        data = yaml.safe_load(base.read_text()) or {}
    except yaml.YAMLError as exc:
        raise SchemaValidationError("target_profile", f"invalid YAML in {base}: {exc}") from None
    if not isinstance(data, dict):
        return {}
    raw = data.get("targets") if "targets" in data else data.get("profiles")
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise SchemaValidationError("target_profile", "profiles must be a mapping")
    result: dict[str, TargetProfile] = {}
    for name, profile_data in raw.items():
        _validate_name(str(name))
        if profile_data is None:
            profile_data = {}  # noqa: PLW2901
        if not isinstance(profile_data, dict):
            raise SchemaValidationError("target_profile", f"profile {name!r} must be a mapping")
        _reject_credentials(profile_data)
        merged = dict(profile_data)
        merged["name"] = str(name)
        if "engine" in merged and merged["engine"] not in _ALLOWED_ENGINES:
            raise SchemaValidationError(
                "target_profile", f"profile {name!r} has invalid engine {merged['engine']!r}"
            )
        try:
            result[str(name)] = TargetProfile.model_validate(merged)
        except ValidationError as exc:
            raise SchemaValidationError(
                "target_profile", f"invalid profile {name!r}: {exc}"
            ) from None
    if any(v.extends is not None for v in result.values()):
        result = _resolve_inheritance(result)
    return result


def select_profile(profiles: dict[str, TargetProfile], name: str | None) -> TargetProfile | None:
    if not profiles:
        return None
    if name is not None:
        if name not in profiles:
            raise SchemaValidationError(
                "target_profile",
                f"unknown target {name!r}; available: {', '.join(sorted(profiles))}",
            )
        return profiles[name]
    if len(profiles) == 1:
        return next(iter(profiles.values()))
    return None


def require_profile(
    profiles: dict[str, TargetProfile], name: str | None, *, mutating: bool = False
) -> TargetProfile | None:
    if name is not None:
        return select_profile(profiles, name)
    if mutating and len(profiles) > 1:
        raise SchemaValidationError(
            "target_profile",
            f"multiple targets exist ({', '.join(sorted(profiles))}); "
            "--target is required for mutating operations",
        )
    if len(profiles) == 1:
        return next(iter(profiles.values()))
    return None
