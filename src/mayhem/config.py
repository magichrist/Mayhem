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
from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    model_validator,
)

from mayhem.domain.common import utc_now
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.experiments import BlastRadiusBudget, ManiacCfg
from mayhem.domain.policy import BUILTIN_PROFILES
from mayhem.domain.redaction import redact
from mayhem.domain.risks import RiskLevel
from mayhem.domain.target_profiles import (
    TargetProfile,
    load_profiles_from_mayhem_yaml,
    parse_profiles_mapping,
    select_profile,
)


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

_POLICY_ENV_VAR = "MAYHEM_POLICY"
_SECRET_FIELD_NAMES = frozenset(
    {
        "password",
        "secret",
        "token",
        "credentials",
        "api_key",
        "apikey",
        "kubeconfig",
        "registry_token",
        "secret_value",
        "secrets",
    }
)


class PolicyCfg(BaseModel):
    """G1 config-policy gate (ADR-0012 §4)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    allow_faults: frozenset[str] | None = None  # None ⇒ whole catalog
    deny_faults: frozenset[str] = frozenset()
    risk_ceiling: RiskLevel | None = None
    allow_critical: bool = False  # config-side half of the critical opt-in
    # k-plan-5 §5.1: CRITICAL-risk faults additionally require a per-fault
    # explicit ack here AND the CLI-level --allow-critical flag (triple opt-in).
    critical_fault_acks: frozenset[str] = frozenset()


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


class KubernetesCfg(BaseModel):
    """Kubernetes discovery overrides (k-plan-2 §2.6)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    context: str | None = None  # kubeconfig context; None => current-context
    namespace: str | None = None  # None => all namespaces


class MayhemConfigBase(BaseModel):
    # ``populate_by_name`` keeps ``targets=`` usable programmatically while the
    # field also answers to the ``profiles:`` alias authored in YAML.
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    api_version: Literal["mayhem/v1"] = Field(default=API_VERSION, serialization_alias="apiVersion")
    policy: PolicyCfg = Field(default_factory=PolicyCfg)
    blast_radius: BlastRadiusBudget = Field(default_factory=BlastRadiusBudget)
    storage: StorageCfg = Field(default_factory=StorageCfg)
    toolkit: ToolkitOverrides = Field(default_factory=ToolkitOverrides)
    runtime: Literal["docker", "podman", "kubernetes"] = "docker"
    target: TargetCfg = Field(default_factory=TargetCfg)
    # v0.9.0 task 4: target profiles are first-class configuration. The
    # singular ``target:`` above is a different concept (explicit container
    # names for no-compose discovery) and is unchanged. ``profiles:`` is an
    # accepted alias for ``targets:`` in YAML and normalizes into this field.
    targets: dict[str, TargetProfile] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("targets", "profiles"),
    )

    @model_validator(mode="before")
    @classmethod
    def _inject_target_profile_names(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        for key in ("targets", "profiles"):
            profiles = data.get(key)
            if not isinstance(profiles, dict):
                continue
            normalized = {
                str(name): (
                    {**profile, "name": str(name)}
                    if isinstance(profile, dict) and "name" not in profile
                    else profile
                )
                for name, profile in profiles.items()
            }
            data = dict(data)
            data[key] = normalized
        return data

    kubernetes: KubernetesCfg = Field(default_factory=KubernetesCfg)
    # k-plan-4 §4.5: how long pod-lifecycle compensation waits for the
    # controller's replacement pod to reach Ready before timing out.
    recovery_grace: float = Field(default=300.0, gt=0)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    # ADR-M5-1 fallback for `mayhem maniac` when the drill spec's own
    # `config.maniac` block is absent (spec-level settings win).
    maniac: ManiacCfg = Field(default_factory=ManiacCfg)


# Alias kept for readability at call sites.
MayhemConfig = MayhemConfigBase

#: The YAML keys that carry target profiles, in precedence order. ``targets``
#: is canonical; ``profiles`` is the accepted alias.
_PROFILE_LAYER_KEYS = ("targets", "profiles")


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


def _sanitize_value(key: str, value: Any) -> Any:
    """Redact a configuration value for display.

    Two layers, both of them redaction-only:

    * the *field* name (``policy``'s nested keys, a field literally named
      ``token``), using :data:`_SECRET_FIELD_NAMES`;
    * the *value* mapping, using the same
      :func:`mayhem.domain.policy.sanitize_for_logging` policy that ``config
      show`` and the evidence envelope use — so free-form data a field carries
      (a target profile's ``observability`` block, for instance) is filtered by
      exactly the same rules, including its list recursion and its wider key
      set.
    """
    if key.lower() in _SECRET_FIELD_NAMES:
        return "***REDACTED***"
    if isinstance(value, dict):
        return redact(value).value
    return value


def explain_config(config: MayhemConfig, sources: dict[str, str]) -> list[dict[str, Any]]:
    safe_mutable = {"log_level", "blast_radius", "storage"}
    rows: list[dict[str, Any]] = []
    dump = config.model_dump(mode="json", by_alias=True)
    fields = (
        "policy",
        "blast_radius",
        "storage",
        "toolkit",
        "runtime",
        "target",
        "targets",
        "kubernetes",
        "log_level",
        "recovery_grace",
        "maniac",
        "apiVersion",
    )
    for field_name in fields:
        if field_name == "apiVersion":
            raw_value = dump.get("apiVersion", API_VERSION)
            rows.append(
                {
                    "field": "apiVersion",
                    "value": raw_value,
                    "source": sources.get("api_version", "defaults"),
                    "safe_for_mutation": False,
                }
            )
            continue
        key = field_name
        if key not in dump:
            continue
        raw_value = dump[key]
        display_value = _sanitize_value(key, raw_value)
        src = sources.get(key, "defaults")
        rows.append(
            {
                "field": key,
                "value": display_value,
                "source": src,
                "safe_for_mutation": key in safe_mutable,
            }
        )
    return rows


def _apply_policy_profile(
    merged: dict[str, Any],
    sources: dict[str, str],
    profile_name: str,
    policy_source: str,
) -> None:
    profile = BUILTIN_PROFILES.get(profile_name)
    if profile is None:
        raise SchemaValidationError("config", f"unknown policy profile {profile_name!r}")
    if sources.get("policy", "defaults") != "defaults":
        raise SchemaValidationError(
            "config",
            f"conflicting policy sources: --policy {profile_name!r} and "
            f"{sources['policy']} both set policy; use one",
        )
    policy_dict: dict[str, Any] = {}
    if profile.risk_ceiling is not None:
        policy_dict["risk_ceiling"] = profile.risk_ceiling
    if profile.allowed_faults is not None:
        policy_dict["allow_faults"] = sorted(profile.allowed_faults)
    if profile.denied_faults:
        policy_dict["deny_faults"] = sorted(profile.denied_faults)
    policy_dict["allow_critical"] = profile.allow_critical
    if profile.critical_fault_acks:
        policy_dict["critical_fault_acks"] = sorted(profile.critical_fault_acks)
    merged["policy"] = policy_dict
    merged["blast_radius"] = profile.blast_radius.model_dump(mode="json")
    sources["policy"] = policy_source
    sources["blast_radius"] = policy_source


def load_config(
    *,
    config_path: str | Path | None = None,
    profile: str | None = None,
    policy: str | None = None,
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
    (ADR-M4: the spec's ``config:` section replaces the separate mayhem.yml)
    instead of failing on ``extra="forbid"``. ``skip_default_file_if_spec`` is
    kept for backward compatibility and has no effect — the spec doubling case
    is handled by :func:`_config_layer_from_spec` directly.

    Target profiles (``targets:``, or the ``profiles:`` alias) merge per
    profile *name*: a later layer replaces a same-named profile whole rather
    than deep-merging into it, and a name declared in neither key of the same
    layer is a duplicate and is refused. Every layer's accumulated profile
    block is re-validated, so a profile that inherits (``extends:``) from one
    declared in an earlier layer resolves, and a profile a later layer
    replaced with a bad one is still refused. Provenance for the section is
    recorded under ``sources["targets"]``.
    """
    env = dict(os.environ if environ is None else environ)
    env_policy = env.get(_POLICY_ENV_VAR)
    effective_policy = policy or env_policy
    if policy is not None and env_policy is not None and policy != env_policy:
        raise SchemaValidationError(
            "config",
            f"conflicting policy sources: --policy {policy!r} and {_POLICY_ENV_VAR}={env_policy!r}",
        )
    sources: dict[str, str] = dict.fromkeys(
        ("policy", "blast_radius", "storage", "toolkit", "log_level", "targets"),
        "defaults",
    )
    merged: dict[str, Any] = {"api_version": API_VERSION}
    # name -> raw profile mapping, accumulated across layers (later wins).
    raw_profiles: dict[str, Any] = {}

    def absorb_profiles(layer_data: dict[str, Any], layer_name: str) -> None:
        declared: set[str] = set()
        for key in _PROFILE_LAYER_KEYS:
            if key not in layer_data:
                continue
            block = layer_data[key]
            if block is None:
                block = {}
            if not isinstance(block, dict):
                raise SchemaValidationError(
                    "config", f"{layer_name}: {key} must be a mapping of name to profile"
                )
            for raw_name in block:
                name = str(raw_name)
                if name in declared:
                    raise SchemaValidationError(
                        "target_profile",
                        f"{layer_name}: duplicate target name {name!r} declared in both "
                        f"'targets' and 'profiles'",
                    )
                declared.add(name)
                raw_profiles[name] = block[raw_name]
        if not declared:
            return
        merged["targets"] = parse_profiles_mapping(raw_profiles, source=f"{layer_name} targets:")
        sources["targets"] = layer_name

    def absorb(layer_data: dict[str, Any], layer_name: str) -> None:
        for key, value in layer_data.items():
            if key == "apiVersion":
                continue
            if key in _PROFILE_LAYER_KEYS:
                continue
            field_name = "api_version" if key == "apiVersion" else key
            existing = merged.get(field_name)
            if isinstance(existing, dict) and isinstance(value, dict):
                _deep_merge(existing, value)
            else:
                merged[field_name] = value
            sources[field_name] = layer_name
        absorb_profiles(layer_data, layer_name)

    base_path = Path(config_path) if config_path else Path("mayhem.yaml")
    if config_path or base_path.exists():
        document = _read_document(base_path)
        if is_spec_file(document):
            # Only the projected `config:` section reaches `absorb`: a drill
            # spec's own top-level `targets:` block is its logical targets
            # (k-plan-1 §1.2), never target profiles.
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
    if effective_policy is not None:
        _apply_policy_profile(merged, sources, effective_policy, "policy:" + effective_policy)
    if cli_overrides:
        if effective_policy is not None and any(
            key in cli_overrides for key in ("policy", "blast_radius")
        ):
            raise SchemaValidationError(
                "config",
                "conflicting policy sources: --policy and cli_overrides both set policy fields",
            )
        absorb({k: v for k, v in cli_overrides.items() if v is not None}, "cli")

    try:
        return MayhemConfig.model_validate(merged), sources
    except ValidationError as exc:
        raise SchemaValidationError("config", f"invalid configuration: {exc}") from None


def effective_target_profiles(
    config_path: str | Path | None = None,
    profile: str | None = None,
    *,
    environ: dict[str, str] | None = None,
) -> dict[str, TargetProfile]:
    """The target profiles of the **effective** configuration.

    The base document plus the ``mayhem.{profile}.yaml`` overlay, merged per
    profile name by :func:`load_config`. This is the single resolution seam for
    production consumers — CLI services, topology, preflight, and diagnostics
    all call it — so a profile declared only in an overlay is visible to all of
    them and none of them re-reads the base file on its own.

    Two deliberate tolerances, both pre-existing behaviours of the readers
    this replaces:

    * A profile-only document (no ``apiVersion``) is not a loadable
      configuration, so the profile-file reader is the fallback. Nothing is lost
      for that shape; a *requested but missing* overlay simply leaves the base
      document's profiles in place, and ``mayhem doctor`` reports the missing
      overlay.
    * A drill spec (``kind: drill``) is not a configuration layer, so its own
      ``targets:`` block — its logical targets — is never read as profiles.

    Both paths share one validator,
    :func:`mayhem.domain.target_profiles.parse_profiles_mapping`; there is no
    second implementation of the profile vocabulary anywhere in the tree.
    """
    with warnings.catch_warnings():
        # A spec declared where a config was expected is not an error for a
        # profile lookup: its `targets:` block is logical targets, so the
        # answer is "no profiles here". Surfaces that genuinely load a spec as
        # configuration (config show/explain, doctor) still surface the
        # warning; only this lookup suppresses it.
        warnings.simplefilter("ignore", SpecFileUsedAsConfig)
        try:
            cfg, _sources = load_config(
                config_path=config_path,
                profile=profile,
                environ={} if environ is None else environ,
            )
        except (OSError, ValueError, SchemaValidationError):
            return load_profiles_from_mayhem_yaml(config_path)
    return dict(cfg.targets)


def select_target_profile(
    config_path: str | Path | None = None,
    *,
    profile: str | None = None,
    target: str | None = None,
    environ: dict[str, str] | None = None,
) -> TargetProfile | None:
    """The target profile a selection resolves to, or ``None``.

    :func:`effective_target_profiles` plus the domain's selection rule, so every
    consumer starts from the same *effective* configuration — base document plus
    the ``mayhem.{profile}.yaml`` overlay. An explicit ``target`` wins; a single
    configured profile is inferred; anything ambiguous resolves to nothing
    rather than guessing, and an unknown ``target`` is refused.

    Consumers that must distinguish *ambiguous* from *unknown* (preflight's
    Kubernetes cross-check, topology discovery, the doctor's own reporting)
    select from the resolved mapping themselves, using
    :func:`effective_target_profiles` for the resolution.

    ``profile`` is the configuration overlay (``mayhem.{profile}.yaml``), not a
    target-profile name.
    """
    return select_profile(effective_target_profiles(config_path, profile, environ=environ), target)


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
