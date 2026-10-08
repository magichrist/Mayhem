"""Runtime identity and runtime metadata value objects (ADR-M1-1, ADR-M1-2).

The container half of the codebase used to bind targets by authored name
(``container_name``, ADR-0019/0020) plus ad-hoc scalars. Those are now split
into two sharply different concepts:

* :class:`RuntimeIdentity` **is** the identity — equality and hashing operate on
  the three identity fields only. It is the key used by every persisted
  plan/lease/execution/recovery record.
* :class:`RuntimeMetadata` is descriptive context (project, service, labels,
  lifecycle timestamps). It is explicitly excluded from equality: metadata churn
  never changes the identity.

``container_name``/``service`` are *authoring resolver keys* that resolve to a
``RuntimeIdentity`` at planning time; they are never identity equality.

The second half of this module is the *enterprise* identity vocabulary (plan 09
Phase 1): :class:`Principal`, :class:`TeamMembership`, :class:`EnvironmentScope`,
:class:`Role`, and :class:`RoleGrant`. Same discipline, one level up: a
:class:`Principal` is an identity (equality on ``principal_id`` alone, so
renaming a person or re-labelling a service account never re-identifies them),
while a :class:`RoleGrant` is *context* — a role, an environment scope, a
window, and who granted it. Nothing here reads a clock or a store: role
resolution is a pure function over grants, memberships, and an explicitly
supplied ``now``.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence


class RuntimeLabel(StrEnum):
    """Locked runtime labels (k-plan-1 §1.3) — docker/podman/kubernetes.

    ``RuntimeIdentity.runtime`` stays a free string in the model so persisted
    rows never need a migration, but the DSL and config surface now speak only
    this vocabulary. Enum values equal the historical strings, so any stored
    ``runtime`` parse is a no-op round-trip.
    """

    DOCKER = "docker"
    PODMAN = "podman"
    KUBERNETES = "kubernetes"


class RuntimeIdentity(BaseModel):
    """Equality key for a single running workload (a container, later a process).

    Attributes:
        runtime: Engine label (``"docker"``/``"podman"``) — label only, per
            ADR-0013.
        host_id: Host node the workload runs under (e.g. ``h-podman-local``).
        runtime_id: Engine-reported runtime object id (full container id).
    """

    model_config = ConfigDict(frozen=True)

    runtime: str
    host_id: str | None = None
    runtime_id: str

    @field_validator("runtime", "runtime_id")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("identity fields runtime and runtime_id must be non-empty")
        return value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RuntimeIdentity):
            return NotImplemented
        # Equality on the three identity fields ONLY (ADR-M1-1); names, labels,
        # and metadata never participate.
        return (self.runtime, self.host_id, self.runtime_id) == (
            other.runtime,
            other.host_id,
            other.runtime_id,
        )

    def __hash__(self) -> int:
        return hash((self.runtime, self.host_id, self.runtime_id))

    def resolve_key(self) -> str:
        """Canonical, opaque, store-safe identity key (round-trippable)."""
        return f"{self.runtime}|{self.host_id or ''}|{self.runtime_id}"

    def key(self) -> str:  # alias: key() == resolve_key()
        """Short canonical key, usable as a SQL/store column value."""
        return self.resolve_key()

    @classmethod
    def from_key(cls, key: str) -> RuntimeIdentity:
        """Rebuild an identity from a canonical ``resolve_key()`` string."""
        try:
            runtime, host_id, runtime_id = key.split("|", maxsplit=2)
        except ValueError as exc:
            raise ValueError(f"not a canonical identity key: {key!r}") from exc
        return cls(
            runtime=runtime,
            host_id=host_id or None,
            runtime_id=runtime_id,
        )


class ProcessRuntimeIdentity(BaseModel):
    """Equality key for a single running process (ADR-M2 Phase 2.4).

    A PID alone is not an identity: the kernel recycles PIDs after exit, so a
    short-lived process can exit and its PID be reused by an unrelated process
    while a lease is still active. The boot time (process start time, ``/proc/
    <pid>/stat`` field 22, expressed in clock ticks since boot) disambiguates.

    Attributes:
        host_id: Host node the process runs under (e.g. ``h-local``).
        pid: Host PID (or container-namespace PID for container-addressed runs).
        boot_time: Process start time in clock ticks since boot; ``None`` when
            the platform does not expose it (e.g. non-Linux), in which case the
            guard degrades to pid-only checks.
        container_name: Owning container name where applicable (ADR-0019/0020),
            part of the identity for container-addressed targets.
    """

    model_config = ConfigDict(frozen=True)

    host_id: str
    pid: int
    boot_time: int | None = None
    container_name: str | None = None

    @field_validator("pid")
    @classmethod
    def _positive_pid(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("pid must be positive")
        return value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ProcessRuntimeIdentity):
            return NotImplemented
        return (self.host_id, self.pid, self.boot_time, self.container_name) == (
            other.host_id,
            other.pid,
            other.boot_time,
            other.container_name,
        )

    def __hash__(self) -> int:
        return hash((self.host_id, self.pid, self.boot_time, self.container_name))

    def resolve_key(self) -> str:
        """Canonical, opaque, store-safe identity key (round-trippable)."""
        return f"{self.host_id}|{self.pid}|{self.boot_time or ''}|{self.container_name or ''}"

    def key(self) -> str:  # alias: key() == resolve_key()
        return self.resolve_key()

    @classmethod
    def from_key(cls, key: str) -> ProcessRuntimeIdentity:
        """Rebuild an identity from a canonical ``resolve_key()`` string."""
        try:
            host_id, pid, boot_time, container_name = key.split("|", maxsplit=3)
        except ValueError as exc:
            raise ValueError(f"not a canonical process identity key: {key!r}") from exc
        return cls(
            host_id=host_id,
            pid=int(pid),
            boot_time=int(boot_time) if boot_time else None,
            container_name=container_name or None,
        )


class RuntimeMetadata(BaseModel):
    """Descriptive, non-identity runtime context (ADR-M1-2).

    All fields are mutable/descriptive and explicitly excluded from identity
    equality. ``project``/``service`` come from the engine's compose labels;
    ``name`` is the container name; lifecycle timestamps come from inspect.
    """

    model_config = ConfigDict(frozen=True)

    project: str | None = None
    service: str | None = None
    name: str | None = None
    labels: dict[str, str] = {}
    created_at: str | None = None
    started_at: str | None = None
    image: str | None = None

    @classmethod
    def from_compose_labels(
        cls, labels: Mapping[str, Any], name: str | None = None
    ) -> RuntimeMetadata:
        """Build metadata from engine compose labels (podman/docker)."""
        raw = {str(k): str(v) for k, v in (labels or {}).items()}
        return cls(
            project=raw.get("com.docker.compose.project"),
            service=raw.get("com.docker.compose.service"),
            name=name,
            labels=raw,
        )

    @classmethod
    def from_inspect(cls, info: Mapping[str, Any], name: str | None = None) -> RuntimeMetadata:
        """Build metadata from an engine ``inspect``-like mapping.

        Recognized keys: ``"labels"``, ``"project"``, ``"service"``,
        ``"created_at"``, ``"started_at"``, ``"image"``.
        """
        meta = cls.from_compose_labels(info.get("labels") or {}, name=name)
        overrides: dict[str, Any] = {}
        if info.get("created_at"):
            overrides["created_at"] = str(info["created_at"])
        if info.get("started_at"):
            overrides["started_at"] = str(info["started_at"])
        if info.get("image"):
            overrides["image"] = str(info["image"])
        return meta.model_copy(update=overrides)


# =============================================================================
# Enterprise identity vocabulary (plan 09, Phase 1 — identity and approval types)
#
# The organization model the plan states — Organization -> Project ->
# Environment -> Team -> User / Service Account — needs a name for everything
# below the workload, because an approval has to name *who* approved, *which
# team* they answer to, and *which environment* the approval is good for. Three
# deliberate readings:
#
# * A :class:`Principal` is an identity, not a profile. Equality and hashing
#   operate on ``principal_id`` alone (the ADR-M1-1 rule applied one level up),
#   so a display-name change cannot re-identify a person and cannot silently
#   re-key a role grant.
# * :class:`EnvironmentScope` is the *bound*, not a filter. A role grant is
#   scoped, and a scope that does not cover the environment being acted on does
#   not confer the role there — RBAC layered on environment boundaries, as the
#   plan says, rather than a second authorization system.
# * A grant may name a principal or a *team*. Team grants are why
#   :class:`TeamMembership` is load-bearing rather than decorative: role
#   resolution cannot answer "is this person an approver" without it.
#
# Every function here is pure. ``now`` is an argument (as in
# ``policy.evaluate_bundle``), never a clock read, so a decision is a function
# of (grants, memberships, scope, now) and nothing else.
# =============================================================================

#: The any-environment wildcard. Written as the environment itself so a scope
#: stays one comparable value rather than an optional flag.
ANY_ENVIRONMENT = "*"

_ID_PATTERN = r"^[a-z0-9][a-z0-9._:-]{0,127}$"


class PrincipalKind(StrEnum):
    """The three kinds of thing that can hold a role grant.

    Kept as a vocabulary, not a permission hierarchy: a ``WORKLOAD`` principal
    is not a lesser human, it is a different issuer, and Phase 2 is where the
    difference becomes a real authentication path (local auth, OIDC, mTLS).
    """

    HUMAN = "human"
    SERVICE_ACCOUNT = "service_account"
    WORKLOAD = "workload"


class Principal(BaseModel):
    """A human user, a service account, or a workload identity.

    ``principal_id`` is the stable, issuer-assigned id (``u-``/``sa-``/``wl-``
    prefix recommended, not enforced) and the *only* thing identity compares.
    ``external_id`` records the provider's own id when one exists, so a
    re-issued local id never loses the link back to the IdP record.

    ``disabled`` is a state of the *record*, not a revocation event: it says
    this principal may not exercise authority now. A grant to a disabled
    principal confers nothing (:func:`effective_roles` skips it), which is the
    "revoked approver" negative control expressed as a rule rather than as a
    check somebody has to remember to add.
    """

    model_config = ConfigDict(frozen=True)

    principal_id: str
    kind: PrincipalKind = PrincipalKind.HUMAN
    display_name: str = ""
    email: str = ""
    external_id: str = ""
    disabled: bool = False

    @field_validator("principal_id")
    @classmethod
    def _principal_id_not_blank(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            msg = f"principal_id must be a non-blank trimmed string, got {value!r}"
            raise InvariantViolationError("principal_id_not_blank", msg)
        return value

    @property
    def key(self) -> str:
        """Alias for ``principal_id`` — matches the ``key()`` idiom above."""
        return self.principal_id

    @property
    def is_human(self) -> bool:
        return self.kind is PrincipalKind.HUMAN

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Principal):
            return NotImplemented
        # Identity only, exactly as RuntimeIdentity does it.
        return self.principal_id == other.principal_id

    def __hash__(self) -> int:
        return hash(self.principal_id)

    def describe(self) -> str:
        label = self.display_name or self.principal_id
        return f"{label} ({self.kind.value})"


class TeamMembership(BaseModel):
    """One principal's membership in one team, for a window.

    ``until`` is what makes a membership revocable without deletion: the record
    stays as evidence, and :meth:`is_active` stops answering true.
    """

    model_config = ConfigDict(frozen=True)

    principal: Principal
    team_id: str = Field(pattern=_ID_PATTERN)
    joined_at: datetime = Field(default_factory=utc_now)
    until: datetime | None = None

    @model_validator(mode="after")
    def _check_window(self) -> Self:
        if self.until is not None and self.until <= self.joined_at:
            msg = (
                f"membership of {self.principal.principal_id!r} in "
                f"{self.team_id!r} ends ({self.until.isoformat()}) at or before it "
                f"began ({self.joined_at.isoformat()})"
            )
            raise InvariantViolationError("membership.window", msg)
        return self

    def is_active(self, now: datetime) -> bool:
        """True while the membership is in force at ``now``."""
        if self.principal.disabled:
            return False
        return self.until is None or now < self.until

    def describe(self) -> str:
        window = "open" if self.until is None else self.until.isoformat()
        return f"{self.principal.principal_id} in {self.team_id} (until {window})"


class EnvironmentScope(BaseModel):
    """The environment boundary an authority is good for.

    ``environment`` is required — an authority with no environment is not an
    authority, it is an omission. ``ANY_ENVIRONMENT`` (``"*"``) is the explicit
    org-wide form, written as a value so that "covers everything" is a claim a
    reader can see in the record rather than an absent field being interpreted
    generously.

    ``project``/``organization`` are optional narrowing. The covering rule in
    :meth:`covers` treats a *contradiction* as a refusal and an *omission* as
    nothing to contradict, so a project-scoped grant does not leak into another
    project while a bare environment grant still applies inside any project.
    """

    model_config = ConfigDict(frozen=True)

    environment: str
    project: str = ""
    organization: str = ""

    @field_validator("environment")
    @classmethod
    def _environment_not_blank(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            msg = f"environment must be a non-blank trimmed string, got {value!r}"
            raise InvariantViolationError("environment_not_blank", msg)
        return value

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        for field in ("project", "organization"):
            value = getattr(self, field)
            if value and value != value.strip():
                msg = f"{field} must be trimmed or empty, got {value!r}"
                raise InvariantViolationError("scope_field_not_trimmed", msg)
        return self

    @classmethod
    def any(cls, *, project: str = "", organization: str = "") -> EnvironmentScope:
        """The org-wide scope: every environment, optionally narrowed."""
        return cls(environment=ANY_ENVIRONMENT, project=project, organization=organization)

    @property
    def is_wildcard(self) -> bool:
        return self.environment == ANY_ENVIRONMENT

    def key(self) -> str:
        """Canonical, comparable scope string (``org/project/environment``)."""
        return f"{self.organization}/{self.project}/{self.environment}"

    def covers(self, other: EnvironmentScope) -> bool:
        """True when authority held in ``self`` reaches ``other``.

        Asymmetric on purpose, and that asymmetry is the whole point: a
        ``production`` grant does not reach ``staging``, a ``*`` grant reaches
        everything inside its project, and neither reaches a *different*
        project. Where a side states nothing (``""``) there is nothing to
        contradict, so the other side's narrowing stands.
        """
        if not self.is_wildcard and self.environment != other.environment:
            return False
        return not _contradicts(self.organization, other.organization) and not _contradicts(
            self.project, other.project
        )

    def describe(self) -> str:
        env = "any environment" if self.is_wildcard else self.environment
        if not (self.organization or self.project):
            return env
        return f"{self.organization}/{self.project}/{env}"


def _contradicts(left: str, right: str) -> bool:
    """True only when both sides state a value and they disagree."""
    return bool(left) and bool(right) and left != right


class Role(StrEnum):
    """The eight separated roles the plan names.

    Separation is the point: ``PLAN`` and ``APPROVE`` are different roles so a
    policy can require two people; ``EXECUTE`` is separate from ``APPROVE`` so
    approving is not self-granting authority to run. A default-deny posture
    (the one ``providers.permissions`` already holds) means a role is never
    implicit.
    """

    VIEW = "view"
    DESIGN = "design"
    PLAN = "plan"
    APPROVE = "approve"
    EXECUTE = "execute"
    EMERGENCY_STOP = "emergency_stop"
    ADMINISTER = "administer"
    EVIDENCE_ADMIN = "evidence_admin"


class RoleGrant(BaseModel):
    """One role, held in one environment scope, by one principal or one team.

    Exactly one of ``principal``/``team_id`` must be stated: a grant addressed to
    nobody is a template, not a grant, and silently promoting one to "everyone"
    would be the worst possible default.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    role: Role
    scope: EnvironmentScope
    principal: Principal | None = None
    team_id: str = Field(default="", pattern=_ID_PATTERN)
    granted_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None
    granted_by: str = ""
    change_ticket: str = ""

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        stated = [self.principal is not None, bool(self.team_id)]
        if sum(stated) != 1:
            msg = (
                "role grant must name exactly one of principal or team_id, got "
                f"principal={self.principal is not None} team_id={self.team_id!r}"
            )
            raise InvariantViolationError("role_grant.addressee", msg)
        if self.expires_at is not None and self.expires_at <= self.granted_at:
            msg = (
                f"role grant of {self.role.value} expires ({self.expires_at.isoformat()}) "
                f"at or before it was granted ({self.granted_at.isoformat()})"
            )
            raise InvariantViolationError("role_grant.window", msg)
        return self

    @property
    def addressee(self) -> str:
        """The principal id or team id this grant names."""
        return self.principal.principal_id if self.principal is not None else self.team_id

    def is_active(self, now: datetime) -> bool:
        """True while the grant is in force at ``now``."""
        return self.expires_at is None or now < self.expires_at

    def applies_to(
        self,
        principal: Principal,
        scope: EnvironmentScope,
        *,
        memberships: Sequence[TeamMembership] = (),
        now: datetime,
    ) -> bool:
        """True when this grant confers its role on ``principal`` in ``scope``.

        A disabled principal holds nothing — the grant is still on record, but it
        confers no authority, which is what makes a revoked approver unable to
        approve without anybody having to delete the grant.
        """
        if principal.disabled or not self.is_active(now):
            return False
        if not self.scope.covers(scope):
            return False
        if self.principal is not None:
            return self.principal == principal
        return any(
            membership.principal == principal
            and membership.team_id == self.team_id
            and membership.is_active(now)
            for membership in memberships
        )

    def describe(self) -> str:
        window = "never" if self.expires_at is None else self.expires_at.isoformat()
        scope = self.scope.describe()
        return f"{self.role.value} to {self.addressee} in {scope} (expires {window})"


def team_ids_for(
    principal: Principal,
    memberships: Iterable[TeamMembership],
    *,
    now: datetime,
) -> frozenset[str]:
    """Teams ``principal`` actively belongs to at ``now``."""
    return frozenset(
        membership.team_id
        for membership in memberships
        if membership.principal == principal and membership.is_active(now)
    )


def effective_roles(
    grants: Iterable[RoleGrant],
    *,
    principal: Principal,
    scope: EnvironmentScope,
    memberships: Sequence[TeamMembership] = (),
    now: datetime,
) -> frozenset[Role]:
    """Every role ``principal`` holds in ``scope`` at ``now``.

    Direct and team grants are unioned rather than ranked: a role is a role, and
    the environment scope — not the grant's origin — is the boundary. An empty
    result is the answer for a principal nobody granted anything, which is the
    default-deny posture the rest of the system already holds.
    """
    return frozenset(
        grant.role
        for grant in grants
        if grant.applies_to(principal, scope, memberships=memberships, now=now)
    )


def has_role(
    grants: Iterable[RoleGrant],
    *,
    principal: Principal,
    role: Role,
    scope: EnvironmentScope,
    memberships: Sequence[TeamMembership] = (),
    now: datetime,
) -> bool:
    """True when ``principal`` holds ``role`` in ``scope`` at ``now``."""
    return role in effective_roles(
        grants, principal=principal, scope=scope, memberships=memberships, now=now
    )
