"""Layered, versioned, strictly-validated configuration (ADR-0008).

Layering order (later wins):
  built-in defaults → ``mayhem.yaml`` → profile overlay (``mayhem.{profile}.yaml``)
  → ``MAYHEM_*`` environment variables (limited allowlist) → CLI flags.

Every document carries ``apiVersion: mayhem/v1``; unknown versions and unknown
keys are rejected loudly. The effective merged config is snapshotted into the
store so every run records exactly what configuration produced it.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mayhem.domain.common import utc_now
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.experiments import BlastRadiusBudget
from mayhem.domain.risks import RiskLevel

API_VERSION: Literal["mayhem/v1"] = "mayhem/v1"
ENV_PREFIX = "MAYHEM_"
_ENV_ALLOWED = {
    "STORAGE_PATH": "storage.path",
    "ARTIFACTS_DIR": "storage.artifacts_dir",
    "LOG_LEVEL": "log_level",
}


class EnvironmentCfg(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = "default"
    klass: Literal["development", "staging", "production"] = "development"


class PolicyCfg(BaseModel):
    """G1 config-policy gate (ADR-0012 §4)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    allow_faults: frozenset[str] | None = None  # None ⇒ whole catalog
    deny_faults: frozenset[str] = frozenset()
    risk_ceiling: RiskLevel | None = None
    allow_critical: bool = False  # config-side half of the critical opt-in


class StorageCfg(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = ".mayhem/state.db"
    artifacts_dir: str = ".mayhem/artifacts"


class ToolkitOverrides(BaseModel):
    """Pin binaries/versions per tool (architecture/toolkit.md §5)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    binaries: dict[str, str] = Field(default_factory=dict)


class TargetCfg(BaseModel):
    """Explicit container targets when running without a compose file."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    containers: list[str] = Field(default_factory=list)


class MayhemConfigBase(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    api_version: Literal["mayhem/v1"] = API_VERSION
    environment: EnvironmentCfg = Field(default_factory=EnvironmentCfg)
    policy: PolicyCfg = Field(default_factory=PolicyCfg)
    blast_radius: BlastRadiusBudget = Field(default_factory=BlastRadiusBudget)
    storage: StorageCfg = Field(default_factory=StorageCfg)
    toolkit: ToolkitOverrides = Field(default_factory=ToolkitOverrides)
    runtime: Literal["docker", "podman"] = "docker"
    target: TargetCfg = Field(default_factory=TargetCfg)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"


# Alias kept for readability at call sites.
MayhemConfig = MayhemConfigBase


def _deep_merge(dst: dict[str, Any], src: dict[str, Any]) -> None:
    for key, value in src.items():
        if isinstance(dst.get(key), dict) and isinstance(value, dict):
            _deep_merge(dst[key], value)
        else:
            dst[key] = value


def _read_document(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SchemaValidationError("config", f"config file not found: {path}")
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise SchemaValidationError("config", f"invalid YAML in {path}: {exc}") from None
    if not isinstance(data, dict):
        raise SchemaValidationError("config", f"{path} must contain a mapping")
    version = data.get("apiVersion")
    if version != API_VERSION:
        raise SchemaValidationError(
            "config", f"apiVersion must be {API_VERSION!r}, got {version!r}"
        )
    return data


def _apply_env(data: dict[str, Any], env: dict[str, str]) -> dict[str, Any]:
    merged: dict[str, Any] = json.loads(json.dumps(data))  # deep-copy defaults away
    for suffix, dotted in _ENV_ALLOWED.items():
        value = env.get(ENV_PREFIX + suffix)
        if value is None:
            continue
        target = merged
        keys = dotted.split(".")
        for key in keys[:-1]:
            target = target.setdefault(key, {})
        target[keys[-1]] = value
    return merged


def load_config(
    *,
    config_path: str | Path | None = None,
    profile: str | None = None,
    cli_overrides: dict[str, Any] | None = None,
    environ: dict[str, str] | None = None,
    skip_default_file_if_spec: str | Path | None = None,
) -> tuple[MayhemConfig, dict[str, str]]:
    """Return ``(effective config, source map)``.

    The source map records which layer last supplied each top-level section —
    provenance is part of the snapshot.

    ``skip_default_file_if_spec`` guards against the default config file
    (``mayhem.yaml``) doubling as the drill-spec being run: when a spec is
    executing from ``mayhem.yaml`` and no explicit ``--config`` was given, the
    file layer is skipped (pure defaults apply) instead of re-parsing the drill
    spec as a strictly-forbidden config document.
    """
    env = dict(os.environ if environ is None else environ)
    sources: dict[str, str] = dict.fromkeys(
        ("environment", "policy", "blast_radius", "storage", "toolkit", "log_level"),
        "defaults",
    )
    merged: dict[str, Any] = {"api_version": API_VERSION}

    def absorb(layer_data: dict[str, Any], layer_name: str) -> None:
        for key, value in layer_data.items():
            if key == "apiVersion":
                continue
            field_name = "api_version" if key == "apiVersion" else key
            existing = merged.get(field_name)
            if isinstance(existing, dict) and isinstance(value, dict):
                _deep_merge(existing, value)
            else:
                merged[field_name] = value
            sources[field_name] = layer_name

    base_path = Path(config_path) if config_path else Path("mayhem.yaml")
    skip_file = (
        config_path is None
        and skip_default_file_if_spec is not None
        and base_path.resolve() == Path(skip_default_file_if_spec).resolve()
    )
    if not skip_file and (config_path or base_path.exists()):
        absorb(_read_document(base_path), "file")
    if profile:
        overlay = base_path.parent / f"mayhem.{profile}.yaml"
        absorb(_read_document(overlay), f"profile:{profile}")
    absorb(_apply_env({}, env), "env")
    if cli_overrides:
        absorb({k: v for k, v in cli_overrides.items() if v is not None}, "cli")

    try:
        return MayhemConfig.model_validate(merged), sources
    except ValidationError as exc:
        raise SchemaValidationError("config", f"invalid configuration: {exc}") from None


def snapshot_id_for(config: MayhemConfig) -> str:
    canonical = json.dumps(config.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return "cfg-" + hashlib.sha256(canonical.encode()).hexdigest()[:12]


def save_snapshot(store: Any, config: MayhemConfig, sources: dict[str, str]) -> str:
    """Persist the effective config; idempotent per identical content."""
    snapshot_id = snapshot_id_for(config)
    with store.write() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO config_snapshots (id, resolved_json, source_map, created_at)"
            " VALUES (?, ?, ?, ?)",
            (
                snapshot_id,
                config.model_dump_json(),
                json.dumps(sources, sort_keys=True),
                utc_now().isoformat(),
            ),
        )
    return snapshot_id
