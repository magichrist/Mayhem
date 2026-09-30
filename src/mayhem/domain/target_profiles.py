"""The target-profile vocabulary: models, inheritance, validation, selection.

Pure over already-parsed documents — no ``pathlib``, no YAML. The filesystem
readers live in :mod:`mayhem.infra.target_profile_io` so this module keeps the
domain layer's zero-IO invariant; both share the rules defined here.
"""

from __future__ import annotations

import re
from typing import Any, Literal

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


def is_spec_document(data: Any) -> bool:
    """True when a parsed document is an experiment spec, not a profile document.

    A drill spec declares ``kind: drill`` and owns a top-level ``targets:``
    block of *logical targets* (name → :class:`~mayhem.domain.experiments.DrillTarget`,
    k-plan-1 §1.2). That block shares a key with target profiles but has a
    different schema, so it is never read as one.
    """
    return isinstance(data, dict) and isinstance(data.get("kind"), str)


def parse_profiles_mapping(raw: Any, source: str = "target profiles") -> dict[str, TargetProfile]:
    """Validate a raw ``targets:``/``profiles:`` mapping into target profiles.

    The single pure validator for the target-profile vocabulary: no file access,
    no environment, and no dependency on :mod:`mayhem.config` (the domain layer
    never imports upward). Every reader — the standalone profile file, the
    layered ``mayhem.yaml``, and ``load_config`` itself — delegates here so a
    profile means exactly one thing.

    ``source`` names the origin in error messages. ``None`` (an empty
    ``targets:`` block) yields no profiles rather than an error.

    Raises:
        SchemaValidationError: for a non-mapping block, an invalid profile
            name, a non-mapping profile, a forbidden credential key, an
            unsupported engine, an unknown key, or an unresolvable
            ``extends``.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise SchemaValidationError(
            "target_profile", f"{source}: profiles must be a mapping of name to profile"
        )
    result: dict[str, TargetProfile] = {}
    for name, profile_data in raw.items():
        _validate_name(str(name))
        pdata = profile_data
        if pdata is None:
            pdata = {}
        if not isinstance(pdata, dict):
            raise SchemaValidationError(
                "target_profile", f"{source}: profile {name!r} must be a mapping"
            )
        _reject_credentials(pdata)
        merged = dict(pdata)
        merged["name"] = str(name)
        if "engine" in merged and merged["engine"] not in _ALLOWED_ENGINES:
            raise SchemaValidationError(
                "target_profile",
                f"{source}: profile {name!r} has invalid engine {merged['engine']!r}",
            )
        try:
            result[str(name)] = TargetProfile.model_validate(merged)
        except ValidationError as exc:
            raise SchemaValidationError(
                "target_profile", f"{source}: invalid profile {name!r}: {exc}"
            ) from None
    if any(v.extends is not None for v in result.values()):
        result = _resolve_inheritance(result)
    return result


def profile_block(data: dict[str, Any], *, bare_document: bool) -> Any:
    """The raw target-profile mapping of a document, or ``None``.

    ``targets:`` wins over the ``profiles:`` alias. A drill spec's own
    ``targets:`` block is *not* a profile block and yields ``None`` — see
    :func:`is_spec_document`. When neither key is present and the caller
    accepts a profile-only document (``load_profiles_from_file`` does,
    ``mayhem.yaml`` does not), the document itself is the mapping.

    Pure over an already-parsed document, so the filesystem readers in
    :mod:`mayhem.infra.target_profile_io` can share this rule without the
    domain importing ``pathlib``.
    """
    if is_spec_document(data):
        return None
    if "targets" in data:
        return data["targets"]
    if "profiles" in data:
        return data["profiles"]
    return data if bare_document else None


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
