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


def _effective_target_profiles(
    config_path: str | Path | None, profile: str | None = None
) -> dict[str, TargetProfile]:
    """Every check's profile resolution, in one place.

    The layered configuration is the source of truth, so each check resolves the
    *effective* profiles — base document plus the ``mayhem.{profile}.yaml``
    overlay — through :func:`mayhem.config.effective_target_profiles` rather
    than reading the base file itself. The import stays local, matching the rest
    of this module's ``mayhem.config`` usage.
    """
    from mayhem.config import effective_target_profiles

    return effective_target_profiles(config_path, profile)


def check_target_profiles(
    config_path: str | Path | None, profile: str | None = None
) -> list[DiagnosticRecord]:
    records: list[DiagnosticRecord] = []
    try:
        profiles = _effective_target_profiles(config_path, profile)
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
            for name, entry in profiles.items():
                records.append(
                    _record(
                        f"config.target_profile.{name}",
                        DiagnosticCategory.config,
                        DiagnosticSeverity.info,
                        f"target profile {name!r} valid (engine={entry.engine})",
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


def check_target_selection(
    config_path: str | Path | None,
    target: str | None = None,
    *,
    profile: str | None = None,
    profiles: dict[str, TargetProfile] | None = None,
) -> list[DiagnosticRecord]:
    """Report the selected target profile, or why none was selected.

    The profiles are the *effective* configuration's — base document plus the
    ``mayhem.{profile}.yaml`` overlay — so the target doctor reports is the
    target the run would use. ``config.target.selected`` is the stable
    machine-readable record: same id, same message, and the same ``config``
    category the doctor command has always emitted for a selected target.
    """
    records: list[DiagnosticRecord] = []
    try:
        if profiles is None:
            profiles = _effective_target_profiles(config_path, profile)
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
    """Report a target profile whose declarative ``policy:`` resolves to nothing.

    A target profile's ``policy:`` is declarative — the enforced policy is the
    one ``--policy``/``MAYHEM_POLICY``/``policy:`` resolves. A *resolvable* name
    is therefore not worth a warning (it is a valid label the run simply does not
    enforce, and the profile is not the thing that fails); a name that is not a
    built-in policy cannot be honoured by anything, so that is the case worth
    reporting. Reuses the ``config`` category and the per-profile
    ``config.target_profile.<name>`` id family.
    """
    from mayhem.domain.policy import BUILTIN_PROFILES

    records: list[DiagnosticRecord] = []
    for name, profile in sorted(profiles.items()):
        declared = profile.policy
        if not declared or declared in BUILTIN_PROFILES:
            continue
        records.append(
            _record(
                f"config.target_profile.{name}.policy_unknown",
                DiagnosticCategory.config,
                DiagnosticSeverity.warning,
                f"target profile {name!r} declares unknown policy {declared!r}; "
                f"available: {', '.join(sorted(BUILTIN_PROFILES))}",
                remediation=(
                    "use a built-in policy name, or select the enforced policy with "
                    "--policy or the config policy: block"
                ),
                evidence_ref=declared,
            )
        )
    return records


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


#: The binary each target-profile engine needs on PATH. Used to say *which* of
#: the ``check_engine`` records the selected target actually depends on — the
#: records themselves stay one-per-binary, so there is no second, contradictory
#: availability family.
_ENGINE_BINARIES = {"docker": "docker", "podman": "podman", "kubernetes": "kubectl"}


def check_engine(target_engine: str | None = None) -> list[DiagnosticRecord]:
    """One record per engine binary, annotated for the selected target.

    ``target_engine`` is the engine of the selected target profile (or ``None``
    when no target is selected). It does not add a record of its own: it tells
    the existing ``engine.<binary>.found`` / ``engine.<binary>.missing`` family
    which binary the target actually needs, so a missing runtime that blocks the
    selected target is called out instead of looking like an optional runtime
    that happens to be absent.

    ``shutil.which`` only: file presence, never a subprocess, and never a claim
    that a runtime is healthy.
    """
    needed = _ENGINE_BINARIES.get(target_engine or "")
    records: list[DiagnosticRecord] = []
    for engine in ("docker", "podman", "kubectl"):
        required = engine == needed
        found = shutil.which(engine)
        if found:
            suffix = (
                f"; required by the selected target (engine={target_engine})" if required else ""
            )
            records.append(
                _record(
                    f"engine.{engine}.found",
                    DiagnosticCategory.engine,
                    DiagnosticSeverity.info,
                    f"{engine} binary found at {found}; file presence does not prove "
                    f"the runtime is healthy{suffix}",
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
            if required:
                message = (
                    f"{engine} not found in PATH; the selected target's engine "
                    f"{target_engine!r} cannot be used until it is installed"
                )
                remediation = f"install {engine} or select a target profile whose engine is present"
            else:
                message = f"{engine} not found in PATH; file presence does not prove health"
                remediation = (
                    "install {engine} if you need it; missing optional runtimes are warnings"
                )
            records.append(
                _record(
                    f"engine.{engine}.missing",
                    DiagnosticCategory.engine,
                    sev,
                    message,
                    remediation=remediation,
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


def _profile_overlay_path(config_path: str | Path | None, profile: str) -> Path:
    """The overlay ``load_config`` would read for ``profile``.

    Mirrors ``load_config``: the overlay sits beside the selected base document
    (``./mayhem.<profile>.yaml`` when no ``--config`` was given).
    """
    base = Path(config_path) if config_path else Path("mayhem.yaml")
    return base.parent / f"mayhem.{profile}.yaml"


def _available_overlays(config_path: str | Path | None) -> str:
    base = Path(config_path) if config_path else Path("mayhem.yaml")
    try:
        found = sorted(p.name for p in base.parent.glob("mayhem.*.yaml"))
    except OSError:  # pragma: no cover - unreadable directory
        found = []
    return ", ".join(found) or "none"


def check_profile_identity(
    config_path: str | Path | None, profile: str | None
) -> list[DiagnosticRecord]:
    """Check the ``--profile`` *configuration overlay* selection.

    ``--profile`` names a ``mayhem.{profile}.yaml`` overlay, not a target
    profile, so it is never compared against target-profile names: the old check
    reported a false ``config.profile.mismatch`` for every layered configuration
    that also defined ``targets``.

    The record ids and the ``profile`` ``evidence_ref`` are the pre-existing
    ones, so a consumer keying on ``config.profile.mismatch`` still finds it —
    but the *meaning* is now the truth: the requested overlay does not exist.
    The id's message keeps its ``not found; available: …`` shape and now names
    the overlays that do exist beside the selected base document.
    """
    if profile is None:
        return []
    overlay = _profile_overlay_path(config_path, profile)
    if overlay.exists():
        return [
            _record(
                "config.profile.matched",
                DiagnosticCategory.config,
                DiagnosticSeverity.info,
                f"profile {profile!r} resolved to overlay {overlay}",
                remediation="",
                evidence_ref=profile,
            )
        ]
    return [
        _record(
            "config.profile.mismatch",
            DiagnosticCategory.config,
            DiagnosticSeverity.error,
            f"profile {profile!r} not found; overlay {overlay} does not exist; "
            f"available: {_available_overlays(config_path)}",
            remediation=(
                f"create {overlay} or drop --profile; a target profile is selected "
                "with --target, not --profile"
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
    profile: str | None = None,
    profiles: dict[str, TargetProfile] | None = None,
) -> list[DiagnosticRecord]:
    records: list[DiagnosticRecord] = []
    try:
        resolved = (
            _effective_target_profiles(config_path, profile) if profiles is None else profiles
        )
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
    records.extend(check_target_profiles(config_path, profile))
    records.extend(check_spec(spec_path))
    records.extend(check_database(db_path))
    # The selected target is resolved from the *effective* configuration
    # (base + `--profile` overlay) before the engine family runs, so the engine
    # records can name the binary the selected target actually needs.
    try:
        profiles = _effective_target_profiles(config_path, profile)
    except Exception:
        profiles = {}
    selected, _ambiguous = _select_from(profiles, target)
    records.extend(check_engine(selected.engine if selected is not None else None))
    records.extend(check_target_selection(config_path, target, profiles=profiles))
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
