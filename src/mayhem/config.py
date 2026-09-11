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
import warnings
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from mayhem.domain.common import utc_now
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.experiments import BlastRadiusBudget, ManiacCfg
from mayhem.domain.risks import RiskLevel


class SpecFileUsedAsConfig(Warning):
    """A file given as ``--config`` declares ``kind: drill`` — it is a drill
    spec, not a plain configuration.

    ``mayhem.yaml`` is the single-file home for everything (ADR-M4: the drill
    spec's ``config:`` section *replaces* the separate config file), so when a
    spec document is found where a config was expected, the overlapping keys
    of its embedded ``config:`` section are absorbed as the config layer. This
    warning only fires when the spec carries nothing to absorb (defaults
    apply)."""


def is_spec_file(data: object) -> bool:
    """True when a parsed document is an experiment spec, not a config.

    A config document never carries a top-level ``kind``; drill specs always
    do (``kind: drill``), so the presence of any ``kind`` value marks a spec.
    """
    return isinstance(data, dict) and isinstance(data.get("kind"), str)


def _config_layer_from_spec(document: dict[str, Any]) -> dict[str, Any]:
    """Project a drill spec's embedded ``config:`` section onto the config
    vocabulary — the "one file for all things" contract.

    Overlapping keys become config fields; spec-only knobs (``max-faults``,
    ``timeout``, ``recovery``, ``on_failure``, ``maniac``) stay owned by the
    spec and are deliberately *not* copied (they are not config fields and
    would trip ``extra="forbid"``).
    """
    spec_cfg = document.get("config")
    if not isinstance(spec_cfg, dict):
        return {}
    out: dict[str, Any] = {}
    if "log_level" in spec_cfg:
        out["log_level"] = spec_cfg["log_level"]
    policy: dict[str, Any] = {}
    if "risk_ceiling" in spec_cfg:
        policy["risk_ceiling"] = spec_cfg["risk_ceiling"]
    if policy:
        out["policy"] = policy
    return out


API_VERSION: Literal["mayhem/v1"] = "mayhem/v1"
ENV_PREFIX = "MAYHEM_"
_ENV_ALLOWED = {
    "STORAGE_PATH": "storage.path",
    "ARTIFACTS_DIR": "storage.artifacts_dir",
    "LOG_LEVEL": "log_level",
}


class PolicyCfg(BaseModel):
    """G1 config-policy gate (ADR-0012 §4)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    allow_faults: frozenset[str] | None = None  # None ⇒ whole catalog
    deny_faults: frozenset[str] = frozenset()
    risk_ceiling: RiskLevel | None = None
    allow_critical: bool = False  # config-side half of the critical opt-in


class StorageCfg(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = "mayhem.db"
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

    api_version: Literal["mayhem/v1"] = Field(default=API_VERSION, serialization_alias="apiVersion")
    policy: PolicyCfg = Field(default_factory=PolicyCfg)
    blast_radius: BlastRadiusBudget = Field(default_factory=BlastRadiusBudget)
    storage: StorageCfg = Field(default_factory=StorageCfg)
    toolkit: ToolkitOverrides = Field(default_factory=ToolkitOverrides)
    runtime: Literal["docker", "podman"] = "docker"
    target: TargetCfg = Field(default_factory=TargetCfg)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    # ADR-M5-1 fallback for `mayhem maniac` when the drill spec's own
    # `config.maniac` block is absent (spec-level settings win).
    maniac: ManiacCfg = Field(default_factory=ManiacCfg)


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

    ``mayhem.yaml`` is the single-file home for everything: when the config
    document turns out to be a drill spec (``kind: drill``), the overlapping
    keys of its embedded ``config:`` section are absorbed as the config layer
    (ADR-M4: the spec's ``config:`` section replaces the separate mayhem.yml)
    instead of failing on ``extra="forbid"``. ``skip_default_file_if_spec`` is
    kept for backward compatibility and has no effect — the spec doubling case
    is handled by :func:`_config_layer_from_spec` directly.
    """
    env = dict(os.environ if environ is None else environ)
    sources: dict[str, str] = dict.fromkeys(
        ("policy", "blast_radius", "storage", "toolkit", "log_level"),
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
    if config_path or base_path.exists():
        document = _read_document(base_path)
        if is_spec_file(document):
            layer = _config_layer_from_spec(document)
            if layer:
                absorb(layer, "file(spec)")
            else:
                warnings.warn(
                    f"{base_path}: declares `kind: {document.get('kind')}` — this "
                    "file is a drill spec without an embedded `config:` section, "
                    "so configuration defaults apply. Add a `config:` block to the "
                    "spec to fold configuration into the single mayhem.yaml.",
                    SpecFileUsedAsConfig,
                    stacklevel=2,
                )
        else:
            absorb(document, "file")
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
