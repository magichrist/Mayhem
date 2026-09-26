from __future__ import annotations

import os
import shutil
import sqlite3
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.target_profiles import TargetProfile
from mayhem.infra.migrations import ALL_MIGRATIONS

if TYPE_CHECKING:
    from collections.abc import Iterable

    from mayhem.domain.leases import FaultLease


class DiagnosticSeverity(StrEnum):
    info = "info"
    warning = "warning"
    error = "error"


class DiagnosticCategory(StrEnum):
    config = "config"
    database = "database"
    engine = "engine"
    topology = "topology"
    capabilities = "capabilities"
    permissions = "permissions"


class DiagnosticStatus(StrEnum):
    healthy = "healthy"
    warning = "warning"
    blocked = "blocked"
    dirty = "dirty"
    unknown = "unknown"
    HEALTHY = "healthy"
    WARNING = "warning"
    BLOCKED = "blocked"
    DIRTY = "dirty"
    UNKNOWN = "unknown"


class DiagnosticRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    category: DiagnosticCategory
    severity: DiagnosticSeverity
    message: str
    remediation: str = ""
    evidence_ref: str = ""


class Diagnostic(BaseModel):
    model_config = ConfigDict(frozen=True)

    check_id: str
    severity: DiagnosticSeverity
    status: DiagnosticStatus
    message: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""
    related_run: str | None = None
    category: DiagnosticCategory = DiagnosticCategory.config

    @property
    def id(self) -> str:
        return self.check_id

    @property
    def evidence_ref(self) -> str:
        return str(self.evidence.get("ref", ""))

    def to_record(self) -> DiagnosticRecord:
        return DiagnosticRecord(
            id=self.check_id,
            category=self.category,
            severity=self.severity,
            message=self.message,
            remediation=self.remediation,
            evidence_ref=self.evidence_ref,
        )


def _record(  # noqa: PLR0917
    check_id: str,
    category: DiagnosticCategory,
    severity: DiagnosticSeverity,
    message: str,
    remediation: str = "",
    evidence_ref: str = "",
) -> DiagnosticRecord:
    return DiagnosticRecord(
        id=check_id,
        category=category,
        severity=severity,
        message=message,
        remediation=remediation,
        evidence_ref=evidence_ref,
    )


def check_config(config_path: str | Path | None, profile: str | None) -> list[DiagnosticRecord]:
    records: list[DiagnosticRecord] = []
    try:
        from mayhem.config import load_config

        load_config(config_path=config_path, profile=profile, environ={})
        records.append(
            _record(
                "config.valid",
                DiagnosticCategory.config,
                DiagnosticSeverity.info,
                "configuration layering valid",
                remediation="",
                evidence_ref=str(config_path) if config_path else "mayhem.yaml",
            )
        )
    except SchemaValidationError as exc:
        records.append(
            _record(
                "config.invalid",
                DiagnosticCategory.config,
                DiagnosticSeverity.error,
                str(exc),
                remediation="fix the configuration file and re-run mayhem doctor",
                evidence_ref=str(config_path) if config_path else "mayhem.yaml",
            )
        )
    except Exception as exc:
        records.append(
            _record(
                "config.error",
                DiagnosticCategory.config,
                DiagnosticSeverity.error,
                f"unexpected config error: {exc}",
                remediation="check file permissions and YAML syntax",
                evidence_ref=str(config_path) if config_path else "mayhem.yaml",
            )
        )
    if config_path is not None and not Path(config_path).exists():
        records.append(
            _record(
                "config.missing",
                DiagnosticCategory.config,
                DiagnosticSeverity.error,
                f"config file not found: {config_path}",
                remediation="create the file with mayhem init or pass a valid --config",
                evidence_ref=str(config_path),
            )
        )
    return records


def check_target_profiles(config_path: str | Path | None) -> list[DiagnosticRecord]:
    records: list[DiagnosticRecord] = []
    try:
        profiles = _configured_target_profiles(config_path)
        if not profiles:
            records.append(
                _record(
                    "config.target_profiles.none",
                    DiagnosticCategory.config,
                    DiagnosticSeverity.info,
                    "no target profiles defined",
                    remediation="add targets to mayhem.yaml or run mayhem init",
                    evidence_ref=str(config_path) if config_path else "mayhem.yaml",
                )
            )
        else:
            for name, profile in profiles.items():
                records.append(
                    _record(
                        f"config.target_profile.{name}",
                        DiagnosticCategory.config,
                        DiagnosticSeverity.info,
                        f"target profile {name!r} valid (engine={profile.engine})",
                        remediation="",
                        evidence_ref=str(config_path) if config_path else "mayhem.yaml",
                    )
                )
    except SchemaValidationError as exc:
        records.append(
            _record(
                "config.target_profile.invalid",
                DiagnosticCategory.config,
                DiagnosticSeverity.error,
                str(exc),
                remediation="fix the target profile definition; unknown keys are rejected",
                evidence_ref=str(config_path) if config_path else "mayhem.yaml",
            )
        )
    return records


def _configured_target_profiles(
    config_path: str | Path | None,
) -> dict[str, TargetProfile]:
    """Target profiles of *config_path*, from the effective config when possible.

    The layered configuration is the source of truth: ``load_config`` carries
    the validated profiles and merges the profile overlay, so a doctor run
    reports the profiles that would actually be used. A profile-only document
    (no ``apiVersion``) is not a loadable configuration, so the file reader is
    the fallback for it; both share one validator
    (:func:`mayhem.domain.target_profiles.parse_profiles_mapping`).
    """
    from mayhem.config import load_config as _load
    from mayhem.domain.target_profiles import load_profiles_from_mayhem_yaml

    try:
        cfg, _sources = _load(config_path=config_path, environ={})
    except Exception:
        return load_profiles_from_mayhem_yaml(config_path)
    return dict(cfg.targets)


def _select_from(
    profiles: dict[str, TargetProfile], target: str | None
) -> tuple[TargetProfile | None, bool]:
    """``(selected, ambiguous)`` for *target* within already-loaded *profiles*.

    Selection semantics are the domain's, unchanged: an explicit ``--target``
    wins, a single configured profile is inferred, and more than one without
    ``--target`` is ambiguous and resolves to nothing rather than guessing. An
    unknown ``--target`` resolves to nothing too; ``config.target.mismatch`` is
    what reports it.
    """
    if not profiles:
        return None, False
    if target is not None:
        return profiles.get(target), False
    if len(profiles) == 1:
        return next(iter(profiles.values())), False
    return None, True


def _selected_target_profile(
    config_path: str | Path | None, target: str | None
) -> tuple[dict[str, TargetProfile], TargetProfile | None, bool]:
    """``(profiles, selected, ambiguous)`` for *target*."""
    profiles = _configured_target_profiles(config_path)
    selected, ambiguous = _select_from(profiles, target)
    return profiles, selected, ambiguous


def check_target_selection(
    config_path: str | Path | None,
    target: str | None = None,
    *,
    profiles: dict[str, TargetProfile] | None = None,
) -> list[DiagnosticRecord]:
    """Report the selected target profile, or why none was selected.

    ``config.target.selected`` is the stable machine-readable record: same id,
    same message, and the same ``config`` category the doctor command has
    always emitted for an explicitly selected target.
    """
    records: list[DiagnosticRecord] = []
    try:
        if profiles is None:
            profiles, selected, ambiguous = _selected_target_profile(config_path, target)
        else:
            selected, ambiguous = _select_from(profiles, target)
    except SchemaValidationError as exc:
        return [
            _record(
                "config.target.error",
                DiagnosticCategory.config,
                DiagnosticSeverity.error,
                str(exc),
                remediation="fix target profile",
                evidence_ref=target or "",
            )
        ]
    if ambiguous:
        records.append(
            _record(
                "config.target.ambiguous",
                DiagnosticCategory.config,
                DiagnosticSeverity.warning,
                "multiple target profiles are configured; pass --target to choose one "
                f"(available: {', '.join(sorted(profiles))})",
                remediation="pass --target NAME; nothing is selected by default",
                evidence_ref=",".join(sorted(profiles)),
            )
        )
        return records
    if selected is not None:
        records.append(
            _record(
                "config.target.selected",
                DiagnosticCategory.config,
                DiagnosticSeverity.info,
                f"target {selected.name!r} selected (engine={selected.engine})",
                remediation="",
                evidence_ref=selected.name,
            )
        )
    return records


def check_target_profile_policy(profiles: dict[str, TargetProfile]) -> list[DiagnosticRecord]:
    """Warn about a target profile's declarative ``policy:``.

    A target profile's ``policy:`` names a policy the run does **not** enforce:
    the enforced policy is the one ``--policy``/``MAYHEM_POLICY``/``policy:``
    resolves. Saying so is more useful than letting the field read as if it
    were in force, and an unrecognized name is called out separately.
    """
    from mayhem.domain.policy import BUILTIN_PROFILES

    records: list[DiagnosticRecord] = []
    for name, profile in sorted(profiles.items()):
        declared = profile.policy
        if not declared:
            continue
        records.append(
            _record(
                f"config.target_profile.{name}.policy_advisory",
                DiagnosticCategory.config,
                DiagnosticSeverity.warning,
                f"target profile {name!r} declares policy {declared!r}, which the run "
                "does not enforce; the enforced policy comes from --policy or policy:",
                remediation="select the policy with --policy or the config policy: block",
                evidence_ref=declared,
            )
        )
        if declared not in BUILTIN_PROFILES:
            records.append(
                _record(
                    f"config.target_profile.{name}.policy_unknown",
                    DiagnosticCategory.config,
                    DiagnosticSeverity.warning,
                    f"target profile {name!r} declares unknown policy {declared!r}; "
                    f"available: {', '.join(sorted(BUILTIN_PROFILES))}",
                    remediation="use a built-in policy name or define a custom one",
                    evidence_ref=declared,
                )
            )
    return records


#: The binary each target-profile engine needs on PATH.
_ENGINE_BINARIES = {"docker": "docker", "podman": "podman", "kubernetes": "kubectl"}


def check_engine_for_target(engine: str | None) -> list[DiagnosticRecord]:
    """Whether the selected target's engine binary is on ``PATH``.

    ``shutil.which`` only: file presence, never a subprocess, and never a claim
    that the runtime is healthy.
    """
    if not engine:
        return []
    binary = _ENGINE_BINARIES.get(engine)
    if binary is None:
        return [
            _record(
                "engine.target.unknown",
                DiagnosticCategory.engine,
                DiagnosticSeverity.warning,
                f"target profile engine {engine!r} has no known binary on PATH",
                remediation="use engine docker, podman, or kubernetes",
                evidence_ref=engine,
            )
        ]
    found = shutil.which(binary)
    if found:
        return [
            _record(
                "engine.target.available",
                DiagnosticCategory.engine,
                DiagnosticSeverity.info,
                f"{binary} found at {found} for target engine {engine!r}; "
                "file presence does not prove the runtime is healthy",
                remediation="verify the runtime is running separately",
                evidence_ref=found,
            )
        ]
    return [
        _record(
            "engine.target.missing",
            DiagnosticCategory.engine,
            DiagnosticSeverity.warning,
            f"{binary} not found in PATH; the selected target's engine {engine!r} "
            "cannot be used until it is installed",
            remediation=f"install {binary} or select a target profile whose engine is present",
            evidence_ref="PATH",
        )
    ]


def check_spec(spec_path: str | Path | None) -> list[DiagnosticRecord]:
    if spec_path is None:
        return [
            _record(
                "topology.spec.none",
                DiagnosticCategory.topology,
                DiagnosticSeverity.info,
                "no spec path provided; will auto-detect mayhem.yaml",
                remediation="",
                evidence_ref="",
            )
        ]
    p = Path(spec_path)
    if not p.exists():
        return [
            _record(
                "topology.spec.missing",
                DiagnosticCategory.topology,
                DiagnosticSeverity.error,
                f"spec file not found: {p}",
                remediation="create the spec or pass a valid path",
                evidence_ref=str(p),
            )
        ]
    try:
        data = yaml.safe_load(p.read_text()) or {}
        if not isinstance(data, dict):
            return [
                _record(
                    "topology.spec.invalid",
                    DiagnosticCategory.topology,
                    DiagnosticSeverity.error,
                    f"{p} must contain a mapping",
                    remediation="fix YAML structure",
                    evidence_ref=str(p),
                )
            ]
        if data.get("kind") == "drill" and "name" not in data:
            return [
                _record(
                    "topology.spec.invalid",
                    DiagnosticCategory.topology,
                    DiagnosticSeverity.error,
                    f"{p} drill spec missing name",
                    remediation="add name field to drill spec",
                    evidence_ref=str(p),
                )
            ]
        return [
            _record(
                "topology.spec.valid",
                DiagnosticCategory.topology,
                DiagnosticSeverity.info,
                f"spec {p} parsed successfully",
                remediation="",
                evidence_ref=str(p),
            )
        ]
    except yaml.YAMLError as exc:
        return [
            _record(
                "topology.spec.invalid",
                DiagnosticCategory.topology,
                DiagnosticSeverity.error,
                f"invalid YAML in {p}: {exc}",
                remediation="fix YAML syntax",
                evidence_ref=str(p),
            )
        ]


def check_database(db_path: str | Path) -> list[DiagnosticRecord]:
    records: list[DiagnosticRecord] = []
    p = Path(db_path)
    if not p.exists():
        records.append(
            _record(
                "database.missing",
                DiagnosticCategory.database,
                DiagnosticSeverity.info,
                f"database not found at {p}; will be created on first run",
                remediation="run any mayhem command to create the database",
                evidence_ref=str(p),
            )
        )
        return records
    try:
        conn = sqlite3.connect(str(p))
        try:
            cur = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='_schema_migrations'"
            )
            if cur.fetchone() is None:
                records.append(
                    _record(
                        "database.unmigrated",
                        DiagnosticCategory.database,
                        DiagnosticSeverity.error,
                        f"database {p} has no migration table; run mayhem to migrate",
                        remediation="delete the file or run mayhem with a valid store",
                        evidence_ref=str(p),
                    )
                )
                return records
            rows = list(conn.execute("SELECT version FROM _schema_migrations"))
            applied = {int(r[0]) for r in rows}
            expected = {m.version for m in ALL_MIGRATIONS}
            missing = expected - applied
            extra = applied - expected
            if missing:
                records.append(
                    _record(
                        "database.migration_drift",
                        DiagnosticCategory.database,
                        DiagnosticSeverity.error,
                        f"database {p} missing migrations: {sorted(missing)}",
                        remediation="run mayhem to apply pending migrations or restore from backup",
                        evidence_ref=str(p),
                    )
                )
            elif extra:
                records.append(
                    _record(
                        "database.migration_extra",
                        DiagnosticCategory.database,
                        DiagnosticSeverity.warning,
                        f"database {p} has extra migrations: {sorted(extra)}",
                        remediation="database was created with a newer mayhem version",
                        evidence_ref=str(p),
                    )
                )
            else:
                records.append(
                    _record(
                        "database.migrated",
                        DiagnosticCategory.database,
                        DiagnosticSeverity.info,
                        f"database {p} at schema version {max(applied) if applied else 0}",
                        remediation="",
                        evidence_ref=str(p),
                    )
                )
        finally:
            conn.close()
    except sqlite3.Error as exc:
        records.append(
            _record(
                "database.error",
                DiagnosticCategory.database,
                DiagnosticSeverity.error,
                f"database error for {p}: {exc}",
                remediation="check file permissions and integrity",
                evidence_ref=str(p),
            )
        )
    return records


def check_engine() -> list[DiagnosticRecord]:
    records: list[DiagnosticRecord] = []
    for engine in ("docker", "podman", "kubectl"):
        found = shutil.which(engine)
        if found:
            records.append(
                _record(
                    f"engine.{engine}.found",
                    DiagnosticCategory.engine,
                    DiagnosticSeverity.info,
                    f"{engine} binary found at {found}; file presence does not prove the runtime is healthy",
                    remediation="verify the runtime is running separately",
                    evidence_ref=found,
                )
            )
        else:
            sev = (
                DiagnosticSeverity.warning
                if engine in ("docker", "podman", "kubectl")
                else DiagnosticSeverity.info
            )
            records.append(
                _record(
                    f"engine.{engine}.missing",
                    DiagnosticCategory.engine,
                    sev,
                    f"{engine} not found in PATH; file presence does not prove health",
                    remediation=f"install {engine} if you need it; missing optional runtimes are warnings",
                    evidence_ref="PATH",
                )
            )
    try:
        from mayhem.domain.k8s_adapter import k8s_adapter_doctor_status

        status = k8s_adapter_doctor_status()
        if not status.get("available"):
            records.append(
                _record(
                    "engine.kubernetes.unavailable",
                    DiagnosticCategory.engine,
                    DiagnosticSeverity.warning,
                    "kubernetes adapter is interface-only (ADR-M7-1); live execution unavailable; adapter presence does not prove a healthy cluster",
                    remediation=str(
                        status.get("remediation")
                        or "attach kubeconfig for live mode; manifest mode remains usable"
                    ),
                    evidence_ref="k8s_adapter",
                )
            )
        else:
            records.append(
                _record(
                    "engine.kubernetes.available",
                    DiagnosticCategory.engine,
                    DiagnosticSeverity.info,
                    "kubernetes adapter available",
                    remediation="",
                    evidence_ref="k8s_adapter",
                )
            )
    except Exception:
        pass
    return records


def check_topology(
    compose_path: str | Path | None, config_path: str | Path | None
) -> list[DiagnosticRecord]:
    records: list[DiagnosticRecord] = []
    if compose_path is not None:
        p = Path(compose_path)
        if not p.exists():
            records.append(
                _record(
                    "topology.compose.missing",
                    DiagnosticCategory.topology,
                    DiagnosticSeverity.warning,
                    f"compose file not found: {p}",
                    remediation="pass a valid --compose or place a compose file in cwd",
                    evidence_ref=str(p),
                )
            )
        else:
            try:
                data = yaml.safe_load(p.read_text()) or {}
                if not isinstance(data, dict) or "services" not in data:
                    records.append(
                        _record(
                            "topology.compose.invalid",
                            DiagnosticCategory.topology,
                            DiagnosticSeverity.error,
                            f"{p} missing services key",
                            remediation="fix compose file structure",
                            evidence_ref=str(p),
                        )
                    )
                else:
                    records.append(
                        _record(
                            "topology.compose.valid",
                            DiagnosticCategory.topology,
                            DiagnosticSeverity.info,
                            f"compose file {p} has {len(data['services'])} service(s)",
                            remediation="",
                            evidence_ref=str(p),
                        )
                    )
            except yaml.YAMLError as exc:
                records.append(
                    _record(
                        "topology.compose.invalid",
                        DiagnosticCategory.topology,
                        DiagnosticSeverity.error,
                        f"invalid YAML in {p}: {exc}",
                        remediation="fix YAML syntax",
                        evidence_ref=str(p),
                    )
                )
    else:
        from mayhem.infra.project_detection import find_compose_files

        base = Path.cwd()
        if config_path is not None:
            base = Path(config_path).parent
        found = find_compose_files(base)
        if found:
            records.append(
                _record(
                    "topology.compose.auto",
                    DiagnosticCategory.topology,
                    DiagnosticSeverity.info,
                    f"auto-detected compose file: {found[0]}",
                    remediation="",
                    evidence_ref=str(found[0]),
                )
            )
        else:
            records.append(
                _record(
                    "topology.compose.none",
                    DiagnosticCategory.topology,
                    DiagnosticSeverity.warning,
                    "no compose file auto-detected",
                    remediation="pass --compose or add target.containers to mayhem.yaml",
                    evidence_ref=str(base),
                )
            )
    return records


def check_capabilities() -> list[DiagnosticRecord]:
    records: list[DiagnosticRecord] = []
    for tool in ("curl", "iptables", "tc"):
        found = shutil.which(tool)
        if found:
            records.append(
                _record(
                    f"capabilities.{tool}.found",
                    DiagnosticCategory.capabilities,
                    DiagnosticSeverity.info,
                    f"{tool} found at {found}",
                    remediation="",
                    evidence_ref=found,
                )
            )
        else:
            records.append(
                _record(
                    f"capabilities.{tool}.missing",
                    DiagnosticCategory.capabilities,
                    DiagnosticSeverity.warning,
                    f"{tool} not found in PATH; some faults may be unavailable",
                    remediation=f"install {tool} if needed",
                    evidence_ref="PATH",
                )
            )
    return records


def check_permissions(
    db_path: str | Path, artifacts_dir: str | Path | None = None
) -> list[DiagnosticRecord]:
    records: list[DiagnosticRecord] = []
    p = Path(db_path)
    parent = p.parent
    if not parent.exists():
        records.append(
            _record(
                "permissions.db_parent.missing",
                DiagnosticCategory.permissions,
                DiagnosticSeverity.info,
                f"database parent directory {parent} does not exist; will be created",
                remediation="",
                evidence_ref=str(parent),
            )
        )
    elif not parent.is_dir():
        records.append(
            _record(
                "permissions.db_parent.not_dir",
                DiagnosticCategory.permissions,
                DiagnosticSeverity.error,
                f"database parent {parent} is not a directory",
                remediation="fix the path",
                evidence_ref=str(parent),
            )
        )
    elif not os.access(parent, os.W_OK):
        records.append(
            _record(
                "permissions.db_parent.not_writable",
                DiagnosticCategory.permissions,
                DiagnosticSeverity.error,
                f"database parent {parent} not writable",
                remediation="fix permissions",
                evidence_ref=str(parent),
            )
        )
    else:
        records.append(
            _record(
                "permissions.db_parent.writable",
                DiagnosticCategory.permissions,
                DiagnosticSeverity.info,
                f"database parent {parent} writable",
                remediation="",
                evidence_ref=str(parent),
            )
        )
    if artifacts_dir is not None:
        ad = Path(artifacts_dir)
        if not ad.exists():
            records.append(
                _record(
                    "permissions.artifacts.missing",
                    DiagnosticCategory.permissions,
                    DiagnosticSeverity.info,
                    f"artifacts dir {ad} does not exist; will be created",
                    remediation="",
                    evidence_ref=str(ad),
                )
            )
        elif not os.access(ad, os.W_OK):
            records.append(
                _record(
                    "permissions.artifacts.not_writable",
                    DiagnosticCategory.permissions,
                    DiagnosticSeverity.error,
                    f"artifacts dir {ad} not writable",
                    remediation="fix permissions",
                    evidence_ref=str(ad),
                )
            )
        else:
            records.append(
                _record(
                    "permissions.artifacts.writable",
                    DiagnosticCategory.permissions,
                    DiagnosticSeverity.info,
                    f"artifacts dir {ad} writable",
                    remediation="",
                    evidence_ref=str(ad),
                )
            )
    return records


def check_profile_identity(
    config_path: str | Path | None, profile: str | None
) -> list[DiagnosticRecord]:
    """Check the ``--profile`` *configuration overlay* selection.

    ``--profile`` names a ``mayhem.{profile}.yaml`` overlay, not a target
    profile. It is therefore never compared against target-profile names: a
    missing overlay is a configuration error (``load_config`` already refuses
    it), and nothing is reported when the overlay resolves. The old check
    compared the overlay name with the ``targets:`` names, which reported a
    false mismatch for every layered configuration that also defined targets.
    """
    if profile is None:
        return []
    overlay = Path(config_path).parent / f"mayhem.{profile}.yaml" if config_path else Path(
        f"mayhem.{profile}.yaml"
    )
    if overlay.exists():
        return [
            _record(
                "config.profile.matched",
                DiagnosticCategory.config,
                DiagnosticSeverity.info,
                f"configuration profile overlay {profile!r} resolved to {overlay}",
                remediation="",
                evidence_ref=str(overlay),
            )
        ]
    return [
        _record(
            "config.profile.overlay_missing",
            DiagnosticCategory.config,
            DiagnosticSeverity.error,
            f"configuration profile overlay {profile!r} not found at {overlay}",
            remediation=(
                f"create {overlay} or drop --profile; "
                "a target profile is selected with --target, not --profile"
            ),
            evidence_ref=profile,
        )
    ]


def check_policy_identity(
    config_path: str | Path | None, profile: str | None, policy: str | None = None
) -> list[DiagnosticRecord]:
    records: list[DiagnosticRecord] = []
    try:
        from mayhem.config import load_config as _load
        from mayhem.domain.policy import BUILTIN_PROFILES

        if policy is not None and policy not in BUILTIN_PROFILES:
            records.append(
                _record(
                    "config.policy.unknown",
                    DiagnosticCategory.config,
                    DiagnosticSeverity.error,
                    f"policy {policy!r} unknown; available: {', '.join(sorted(BUILTIN_PROFILES))}",
                    remediation="use a built-in policy or define custom",
                    evidence_ref=policy,
                )
            )
        elif policy is not None:
            records.append(
                _record(
                    "config.policy.matched",
                    DiagnosticCategory.config,
                    DiagnosticSeverity.info,
                    f"policy {policy!r} identity verified",
                    remediation="",
                    evidence_ref=policy,
                )
            )
        if profile is not None:
            try:
                cfg, sources = _load(
                    config_path=config_path, profile=profile, policy=policy, environ={}
                )
                _ = cfg
                _ = sources
            except Exception as exc:
                if "conflicting policy" in str(exc).lower():
                    records.append(
                        _record(
                            "config.policy.conflict",
                            DiagnosticCategory.config,
                            DiagnosticSeverity.error,
                            str(exc),
                            remediation="use either --policy or file policy, not both",
                            evidence_ref=policy or "",
                        )
                    )
    except Exception as exc:
        records.append(
            _record(
                "config.policy.error",
                DiagnosticCategory.config,
                DiagnosticSeverity.error,
                str(exc),
                remediation="fix policy",
                evidence_ref=policy or "",
            )
        )
    return records


def check_target_mismatch(
    config_path: str | Path | None,
    target: str | None,
    *,
    profiles: dict[str, TargetProfile] | None = None,
) -> list[DiagnosticRecord]:
    records: list[DiagnosticRecord] = []
    try:
        resolved = _configured_target_profiles(config_path) if profiles is None else profiles
        if target is not None and resolved and target not in resolved:
            records.append(
                _record(
                    "config.target.mismatch",
                    DiagnosticCategory.config,
                    DiagnosticSeverity.error,
                    f"target {target!r} not found; available: {', '.join(sorted(resolved))}",
                    remediation="use an existing target or create it",
                    evidence_ref=target,
                )
            )
        elif target is not None and target in resolved:
            records.append(
                _record(
                    "config.target.identity_ok",
                    DiagnosticCategory.config,
                    DiagnosticSeverity.info,
                    f"target {target!r} identity verified",
                    remediation="",
                    evidence_ref=target,
                )
            )
    except Exception as exc:
        records.append(
            _record(
                "config.target.mismatch_error",
                DiagnosticCategory.config,
                DiagnosticSeverity.error,
                str(exc),
                remediation="fix target profiles",
                evidence_ref=target or "",
            )
        )
    return records


def run_diagnostics(
    *,
    config_path: str | Path | None = None,
    profile: str | None = None,
    policy: str | None = None,
    target: str | None = None,
    db_path: str | Path = "mayhem.db",
    compose_path: str | Path | None = None,
    spec_path: str | Path | None = None,
) -> list[DiagnosticRecord]:
    records: list[DiagnosticRecord] = []
    records.extend(check_config(config_path, profile))
    records.extend(check_target_profiles(config_path))
    records.extend(check_spec(spec_path))
    records.extend(check_database(db_path))
    records.extend(check_engine())
    try:
        profiles, selected, _ambiguous = _selected_target_profile(config_path, target)
    except Exception:
        profiles, selected = {}, None
    records.extend(check_target_selection(config_path, target, profiles=profiles))
    records.extend(check_engine_for_target(selected.engine if selected is not None else None))
    records.extend(check_target_profile_policy(profiles))
    records.extend(check_topology(compose_path, config_path))
    records.extend(check_capabilities())
    records.extend(check_profile_identity(config_path, profile))
    records.extend(check_policy_identity(config_path, profile, policy))
    records.extend(check_target_mismatch(config_path, target, profiles=profiles))
    from mayhem.config import load_config as _load

    try:
        cfg, _ = _load(config_path=config_path, profile=profile, policy=policy, environ={})
        art = cfg.storage.artifacts_dir
    except Exception:
        art = None
    records.extend(check_permissions(db_path, art))
    return records


def to_json_records(records: list[DiagnosticRecord]) -> list[dict[str, Any]]:
    return [r.model_dump(mode="json") for r in records]


def _status_for_record(record: DiagnosticRecord) -> DiagnosticStatus:
    haystack = f"{record.id} {record.message} {record.evidence_ref}".lower()
    if "dirty" in haystack:
        return DiagnosticStatus.dirty
    if record.severity is DiagnosticSeverity.error:
        return DiagnosticStatus.blocked
    if record.severity is DiagnosticSeverity.warning:
        return DiagnosticStatus.warning
    return DiagnosticStatus.healthy


def structured_diagnostics(
    records: Iterable[DiagnosticRecord | Diagnostic],
    *,
    related_run: str | None = None,
) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    for record in records:
        if isinstance(record, Diagnostic):
            diagnostics.append(
                record
                if related_run is None or record.related_run == related_run
                else record.model_copy(update={"related_run": related_run})
            )
            continue
        evidence: dict[str, Any] = {"ref": record.evidence_ref} if record.evidence_ref else {}
        diagnostics.append(
            Diagnostic(
                check_id=record.id,
                severity=record.severity,
                status=_status_for_record(record),
                message=record.message,
                evidence=evidence,
                remediation=record.remediation,
                related_run=related_run,
                category=record.category,
            )
        )
    return diagnostics


def lease_projection(lease: FaultLease) -> dict[str, Any]:
    from mayhem.domain.leases import LeaseState

    expires_at = lease.created_at + timedelta(seconds=float(lease.ttl_seconds))
    if lease.state is LeaseState.DIRTY:
        recovery = "dirty"
    elif lease.state is LeaseState.RELEASING:
        recovery = "running"
    elif lease.state is LeaseState.RELEASED:
        recovery = "recovered"
    elif lease.state is LeaseState.EXPIRED:
        recovery = "abandoned"
    else:
        recovery = "pending"
    return {
        "id": lease.id,
        "run_id": lease.run_id,
        "owner": lease.owner_agent,
        "ttl_seconds": float(lease.ttl_seconds),
        "expires_at": expires_at.isoformat(),
        "target": sorted(lease.targets),
        "fault": lease.fault_id,
        "state": lease.state.value,
        "recovery": recovery,
        "compensation": [op.model_dump(mode="json") for op in lease.undo_ops],
        "probe": [probe.model_dump(mode="json") for probe in lease.verify_probes],
        "escalation": [lease.escalation_notes] if lease.escalation_notes else [],
    }


def diagnose_run(store: Any, run_id: str) -> list[Diagnostic]:
    rows = store.query(
        "SELECT status, verdict, summary_md FROM runs WHERE id = ?",
        (run_id,),
    )
    if not rows:
        return [
            Diagnostic(
                check_id="run.exists",
                severity=DiagnosticSeverity.error,
                status=DiagnosticStatus.blocked,
                message=f"run not found: {run_id}",
                evidence={"run_id": run_id},
                remediation="inspect an existing run id",
                related_run=run_id,
            )
        ]
    row = rows[0]
    lease_rows = store.query(
        "SELECT state, escalation_notes FROM fault_leases WHERE run_id = ? ORDER BY created_epoch_s",
        (run_id,),
    )
    states = [str(lease["state"]) for lease in lease_rows]
    recovery_status = "recovered"
    status = DiagnosticStatus.healthy
    severity = DiagnosticSeverity.info
    if "dirty" in states:
        recovery_status = "dirty"
        status = DiagnosticStatus.dirty
        severity = DiagnosticSeverity.error
    elif "active" in states or "releasing" in states or "orphaned" in states:
        recovery_status = "pending" if "releasing" not in states else "running"
        status = DiagnosticStatus.warning
        severity = DiagnosticSeverity.warning
    return [
        Diagnostic(
            check_id="run.lifecycle",
            severity=severity,
            status=status,
            message=f"run status={row['status']} verdict={row['verdict'] or 'unrecorded'}",
            evidence={
                "run_id": run_id,
                "run_status": row["status"],
                "verdict": row["verdict"] or "",
            },
            related_run=run_id,
            category=DiagnosticCategory.database,
        ),
        Diagnostic(
            check_id="run.recovery",
            severity=severity,
            status=status,
            message=f"recovery status={recovery_status}",
            evidence={
                "recovery_state": recovery_status,
                "lease_states": states,
                "escalations": [
                    str(lease["escalation_notes"])
                    for lease in lease_rows
                    if lease["escalation_notes"]
                ],
            },
            remediation=(
                "run mayhem recover plan with the explicit run id, then execute with operator approval"
                if status is not DiagnosticStatus.healthy
                else ""
            ),
            related_run=run_id,
            category=DiagnosticCategory.permissions,
        ),
    ]


def to_json_diagnostics(records: Iterable[Diagnostic]) -> list[dict[str, Any]]:
    return [record.model_dump(mode="json") for record in records]
