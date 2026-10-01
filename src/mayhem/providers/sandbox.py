"""Sandbox profiles for third-party providers: the *decision* seam (plan 17, gap 75).

A provider is third-party code, so the question is never "should we trust it"
but "what did it say it needs, and what happens when it needs more". This
module answers the first question and refuses on the second:

* :func:`select_profile` turns a declaration's **requested permissions** — the
  union over capabilities, locators and faults, not just the top-level set — into
  one :class:`SandboxProfile`: a named tier, the mechanisms the request implies,
  and three concrete policies (filesystem, network egress, dropped Linux
  capabilities).
* :class:`SandboxEnforcer` is the seam an enforcement mechanism plugs into. It
  makes the **decisions** the profile encodes (may this path be read? may this
  host be reached?), records every denial as a
  :class:`~mayhem.domain.provider.ProviderEvidenceRecord`, and then raises.
  A denial is never swallowed: the raised exception carries the same evidence
  object the enforcer recorded.

What is deliberately **not** implemented, and must not be reported as if it were:

* No seccomp filter is built, loaded, or installed. No AppArmor profile is
  written, no SELinux label is assigned, and no container is created. Those four
  mechanisms are *named* per profile and carry
  :data:`MechanismState.DECLARED_NOT_APPLIED`.
* Therefore no provider is confined by this module. It decides; the operating
  system still has not acted. Every profile says so in its own ``notice`` field
  and in :data:`SANDBOX_NOT_ENFORCED_NOTICE`, and
  :attr:`SandboxProfile.unapplied_mechanisms` is non-empty for every profile that
  requested anything at all.
* :meth:`SandboxEnforcer.admit` only refuses when the caller sets
  ``require_enforced=True``. The default posture is to load the provider and
  *report* that its confinement is declared rather than applied — a refusal by
  default would be a policy decision this phase was not asked to make, and a
  silent pass would be a lie. Both are stated; neither is hidden.

Also not claimed: nothing here verifies a signature.
:data:`mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` remains
``False``, and a sandbox profile is not a trust signal — it describes the
permissions a provider *asked* for, which is a claim by the author, checked
against the grant, and never evidence that the code is safe.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, Final

from mayhem.domain.common import utc_now
from mayhem.domain.provider import (
    CompensationStatus,
    ProviderError,
    ProviderPermission,
    evidence_record,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from datetime import datetime

    from mayhem.domain.provider import ProviderEvidenceRecord, ProviderMetadata

#: The sentence every profile carries. Kept next to the code that decides, so a
#: caller cannot print a profile without the caveat being available to print.
SANDBOX_NOT_ENFORCED_NOTICE: Final[str] = (
    "mayhem decides this provider's filesystem, egress and capability policy but does not "
    "apply it: no seccomp filter, AppArmor profile, SELinux label or container isolation is "
    "installed in this build, so a provider that declares network or target:mutate is loaded "
    "unconfined. Treat a sandbox profile as a stated intent, never as enforced isolation."
)

#: The permissions through which third-party code reaches past its own process.
#: A provider holding none of these is confined by construction — it cannot ask
#: the kernel for anything — which is why the empty-permission profile is the
#: only one with no unapplied mechanism.
_WORLD_REACHING_PERMISSIONS: Final[frozenset[ProviderPermission]] = frozenset(
    {
        ProviderPermission.SUBPROCESS,
        ProviderPermission.NETWORK,
        ProviderPermission.FILESYSTEM_WRITE,
        ProviderPermission.TARGET_MUTATE,
    }
)


class ProviderSandboxError(ProviderError):
    """A sandbox profile could not be honoured at load time."""


class SandboxMechanism(StrEnum):
    """The confinement primitives a profile names.

    Named as an OS vocabulary, not as an implementation plan. Adding a member
    means claiming mayhem can apply it, which is false for every member today.
    """

    SECCOMP = "seccomp"
    APPARMOR = "apparmor"
    SELINUX = "selinux"
    CONTAINER = "container"
    CAPABILITY_DROP = "capability_drop"
    FILESYSTEM = "filesystem"
    EGRESS = "egress"


class MechanismState(StrEnum):
    """How much of a mechanism mayhem actually delivers.

    The distinction is the point. ``POLICY_DECIDED`` means mayhem's own code
    evaluates the policy and can refuse; ``DECLARED_NOT_APPLIED`` means mayhem
    computed what *would* be needed and named it, and the operating system has
    not been touched. Collapsing the two would be the whole failure this module
    exists to prevent.
    """

    POLICY_DECIDED = "policy_decided"
    DECLARED_NOT_APPLIED = "declared_not_applied"


#: Mechanisms mayhem names and reasons about but cannot install in this build.
UNAPPLIED_MECHANISMS: Final[frozenset[SandboxMechanism]] = frozenset(
    {
        SandboxMechanism.SECCOMP,
        SandboxMechanism.APPARMOR,
        SandboxMechanism.SELINUX,
        SandboxMechanism.CONTAINER,
        SandboxMechanism.CAPABILITY_DROP,
    }
)

#: Linux capabilities dropped from a provider runtime unconditionally. The
#: ambient set a third-party runtime inherits is far larger than anything a
#: fault injector legitimately needs; this is the standard "start from nothing
#: and add back what was declared" posture, expressed as a drop list because a
#: drop list is a subtraction and therefore cannot accidentally grant.
BASELINE_DROPPED_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {
        "CAP_AUDIT_CONTROL",
        "CAP_AUDIT_READ",
        "CAP_AUDIT_WRITE",
        "CAP_BLOCK_SUSPEND",
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_DAC_READ_SEARCH",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_IPC_LOCK",
        "CAP_IPC_OWNER",
        "CAP_KILL",
        "CAP_LEASE",
        "CAP_LINUX_IMMUTABLE",
        "CAP_MAC_ADMIN",
        "CAP_MAC_OVERRIDE",
        "CAP_MKNOD",
        "CAP_NET_ADMIN",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_RAW",
        "CAP_PERFMON",
        "CAP_SETFCAP",
        "CAP_SETGID",
        "CAP_SETPCAP",
        "CAP_SETUID",
        "CAP_SYSLOG",
        "CAP_SYS_ADMIN",
        "CAP_SYS_BOOT",
        "CAP_SYS_CHROOT",
        "CAP_SYS_MODULE",
        "CAP_SYS_NICE",
        "CAP_SYS_PACCT",
        "CAP_SYS_PTRACE",
        "CAP_SYS_RAWIO",
        "CAP_SYS_RESOURCE",
        "CAP_SYS_TIME",
        "CAP_WAKE_ALARM",
    }
)

#: Capabilities a provider may keep **because it declared the permission that
#: needs one**. Retention is derived from the declaration, never from a
#: capability name a provider chose to send.
CAPABILITIES_RETAINED_BY_PERMISSION: Final[Mapping[ProviderPermission, frozenset[str]]] = {
    ProviderPermission.SUBPROCESS: frozenset({"CAP_SYS_CHROOT"}),
    ProviderPermission.FILESYSTEM_WRITE: frozenset({"CAP_DAC_OVERRIDE", "CAP_FOWNER"}),
    ProviderPermission.NETWORK: frozenset({"CAP_NET_BIND_SERVICE"}),
}


@dataclass(frozen=True, slots=True)
class MechanismRequirement:
    """One mechanism a profile names, and how much of it mayhem delivers."""

    mechanism: SandboxMechanism
    state: MechanismState
    detail: str

    @property
    def applied(self) -> bool:
        """True only when mayhem's own code enforces the decision.

        Every ``DECLARED_NOT_APPLIED`` mechanism is ``False``, which is the only
        honest answer this build can give.
        """
        return self.state is MechanismState.POLICY_DECIDED

    def to_dict(self) -> dict[str, str]:
        return {
            "mechanism": self.mechanism.value,
            "state": self.state.value,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class SandboxTier:
    """A named profile: a permission shape, not a set of instructions."""

    id: str
    required_permissions: frozenset[ProviderPermission]
    summary: str


#: The named profiles, in declaration order. Selection picks the *most specific*
#: tier whose requirements the declaration satisfies, so a provider that declares
#: ``filesystem:read`` on top of ``target:read`` is described as
#: ``sandbox.filesystem.read`` rather than as the read-only profile.
SANDBOX_TIERS: Final[tuple[SandboxTier, ...]] = (
    SandboxTier(
        id="declaration_only",
        required_permissions=frozenset(),
        summary="Declared no permissions: metadata only, nothing to confine.",
    ),
    SandboxTier(
        id="target.read",
        required_permissions=frozenset({ProviderPermission.TARGET_READ}),
        summary="Reads a target through mayhem's own API; no world reach.",
    ),
    SandboxTier(
        id="target.mutate",
        required_permissions=frozenset(
            {ProviderPermission.TARGET_READ, ProviderPermission.TARGET_MUTATE}
        ),
        summary="Changes the target, so it must be syscall-confined and label-separated.",
    ),
    SandboxTier(
        id="filesystem.read",
        required_permissions=frozenset(
            {ProviderPermission.TARGET_READ, ProviderPermission.FILESYSTEM_READ}
        ),
        summary="Reads paths, so path mediation applies; no egress.",
    ),
    SandboxTier(
        id="filesystem.write",
        required_permissions=frozenset(
            {
                ProviderPermission.TARGET_READ,
                ProviderPermission.FILESYSTEM_READ,
                ProviderPermission.FILESYSTEM_WRITE,
            }
        ),
        summary="Writes paths, so writes need both path mediation and label separation.",
    ),
    SandboxTier(
        id="subprocess",
        required_permissions=frozenset(
            {ProviderPermission.TARGET_READ, ProviderPermission.SUBPROCESS}
        ),
        summary="Spawns processes, so it needs syscall filtering and an isolation boundary.",
    ),
    SandboxTier(
        id="network.egress",
        required_permissions=frozenset(
            {ProviderPermission.TARGET_READ, ProviderPermission.NETWORK}
        ),
        summary="Reaches the network, so egress is deny-by-default until destinations exist.",
    ),
)


def select_tier(permissions: frozenset[ProviderPermission]) -> SandboxTier:
    """The most specific :data:`SANDBOX_TIERS` entry *permissions* satisfies.

    "Most specific" is ``len(required_permissions)``; ties break on declaration
    order so the answer is deterministic for a given set. ``declaration_only``
    requires nothing, so it is always a candidate and the function is total.
    """
    candidates = [
        (-index, tier)
        for index, tier in enumerate(SANDBOX_TIERS)
        if tier.required_permissions <= permissions
    ]
    return max(candidates, key=lambda item: (len(item[1].required_permissions), item[0]))[1]


@dataclass(frozen=True, slots=True)
class CapabilityPolicy:
    """Which Linux capabilities a provider runtime keeps, and which it loses."""

    dropped: frozenset[str]
    retained: frozenset[str]

    @classmethod
    def for_permissions(cls, permissions: frozenset[ProviderPermission]) -> CapabilityPolicy:
        """Derive the drop set from what the provider *declared*.

        Start from the unconditional baseline and subtract only the
        capabilities a declared permission justifies. A permission nobody
        declared can never retain anything, so the subtraction is a grant.
        """
        retained: set[str] = set()
        for permission in sorted(permissions, key=lambda item: item.value):
            retained |= CAPABILITIES_RETAINED_BY_PERMISSION.get(permission, frozenset())
        return cls(
            dropped=BASELINE_DROPPED_CAPABILITIES - frozenset(retained),
            retained=frozenset(retained),
        )

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "dropped": sorted(self.dropped),
            "retained": sorted(self.retained),
        }


@dataclass(frozen=True, slots=True)
class FilesystemDecision:
    """Whether a provider may touch a path, and the reason for the verdict."""

    provider_id: str
    profile_id: str
    operation: str
    path: str
    allowed: bool
    reason: str

    @property
    def denied(self) -> bool:
        return not self.allowed

    def to_dict(self) -> dict[str, str]:
        return {
            "provider_id": self.provider_id,
            "profile_id": self.profile_id,
            "operation": self.operation,
            "path": self.path,
            "allowed": str(self.allowed).lower(),
            "reason": self.reason,
        }


def _unsafe_path_reason(value: str) -> str:
    """Why *value* is not a usable path, or ``""`` when it is.

    The same three hazards the fault-pack reader refuses (``..`` traversal, a
    home expansion, an embedded NUL), restated rather than imported: ``pack.py``
    keeps that check private to the pack format, and a sandbox path and a pack
    target are different inputs that happen to share the hazards.
    """
    if not value:
        return "the path is empty"
    if "\x00" in value:
        return "the path contains a NUL byte"
    if value.startswith("~"):
        return "the path expands a home directory"
    normalized = value.replace("\\", "/")
    if any(segment == ".." for segment in normalized.split("/")):
        return "the path traverses out of its directory"
    return ""


@dataclass(frozen=True, slots=True)
class FilesystemPolicy:
    """Path mediation derived from the declared filesystem permissions.

    Roots are operator-granted and start empty: the declaration schema has no
    field for a path, so mayhem must never invent one. A provider that declared
    ``filesystem:read`` and was given no root can read nothing, and the decision
    says exactly that instead of defaulting to the host filesystem.
    """

    provider_id: str
    profile_id: str
    read_declared: bool = False
    write_declared: bool = False
    read_roots: tuple[str, ...] = ()
    writable_roots: tuple[str, ...] = ()

    def with_roots(
        self, *, read_roots: Iterable[str] = (), writable_roots: Iterable[str] = ()
    ) -> FilesystemPolicy:
        """The same policy with operator-granted roots attached."""
        return replace(
            self,
            read_roots=tuple(read_roots),
            writable_roots=tuple(writable_roots),
        )

    def _within(self, path: str, root: str) -> bool:
        base = root.rstrip("/") or "/"
        return path == base or path.startswith(base if base == "/" else f"{base}/")

    def decide(self, operation: str, path: str) -> FilesystemDecision:
        """Allow or deny one filesystem operation, with a reason either way."""
        if operation not in {"read", "write"}:
            return FilesystemDecision(
                self.provider_id,
                self.profile_id,
                operation,
                path,
                False,
                f"unknown filesystem operation {operation!r}; expected 'read' or 'write'",
            )
        declared = self.read_declared if operation == "read" else self.write_declared
        permission = (
            ProviderPermission.FILESYSTEM_READ
            if operation == "read"
            else ProviderPermission.FILESYSTEM_WRITE
        )
        if not declared:
            return FilesystemDecision(
                self.provider_id,
                self.profile_id,
                operation,
                path,
                False,
                f"provider does not declare {permission.value}; "
                f"the default posture allows no {operation} at all",
            )
        unsafe = _unsafe_path_reason(path)
        if unsafe:
            return FilesystemDecision(
                self.provider_id,
                self.profile_id,
                operation,
                path,
                False,
                f"{path!r} is not a usable provider path because {unsafe}",
            )
        roots = self.read_roots if operation == "read" else self.writable_roots
        if not roots:
            return FilesystemDecision(
                self.provider_id,
                self.profile_id,
                operation,
                path,
                False,
                f"provider declares {permission.value} but no {operation} root was granted; "
                "the declaration schema names permissions, not paths",
            )
        normalized = str(PurePosixPath(path))
        for root in roots:
            if self._within(normalized, str(PurePosixPath(root))):
                return FilesystemDecision(
                    self.provider_id,
                    self.profile_id,
                    operation,
                    path,
                    True,
                    f"{path!r} is inside the {operation} root {root!r}",
                )
        readable_elsewhere = (
            operation == "write"
            and self.read_roots
            and any(self._within(normalized, str(PurePosixPath(root))) for root in self.read_roots)
        )
        reason = (
            f"{path!r} is inside a read-only root; writing needs a writable root"
            if readable_elsewhere
            else f"{path!r} is outside every granted {operation} root"
        )
        return FilesystemDecision(self.provider_id, self.profile_id, operation, path, False, reason)


class EgressMode(StrEnum):
    """How much of the network a profile may reach."""

    #: No egress whatsoever. The mode whenever ``network`` is undeclared.
    DENY_ALL = "deny_all"
    #: ``network`` was declared, so sockets may be opened — but only to the
    #: destinations an operator enumerated. An empty allowlist denies
    #: everything, which is why declaring ``network`` is necessary and not
    #: sufficient for egress.
    ALLOW_DECLARED_HOSTS = "allow_declared_hosts"


@dataclass(frozen=True, slots=True)
class EgressDecision:
    """Whether a provider may reach a destination, and the reason for the verdict."""

    provider_id: str
    profile_id: str
    destination: str
    host: str
    allowed: bool
    reason: str

    @property
    def denied(self) -> bool:
        return not self.allowed

    def denial_message(self) -> str:
        return f"provider {self.provider_id!r} denied egress to {self.destination!r}: {self.reason}"

    def to_dict(self) -> dict[str, str]:
        return {
            "provider_id": self.provider_id,
            "profile_id": self.profile_id,
            "destination": self.destination,
            "host": self.host,
            "allowed": str(self.allowed).lower(),
            "reason": self.reason,
        }


def destination_host(destination: str) -> str:
    """The host part of *destination*, accepting a bare host or an http(s) URL.

    Deliberately small and total: it strips a scheme, a userinfo section, a path,
    a query, and a port, and returns the remainder lowercased. It does not
    resolve anything and does not treat an unparsable value as safe — an
    unparsable value produces a host that will not match any allowlist entry, so
    it is denied rather than admitted.
    """
    value = destination.strip().lower()
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0].split("?", 1)[0]
    if "@" in value:
        value = value.rsplit("@", 1)[1]
    if value.startswith("["):  # IPv6 literal: the colons inside are not a port.
        literal, _, _ = value.partition("]")
        return literal.lstrip("[")
    if value.count(":") == 1:
        value = value.split(":", 1)[0]
    return value


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    """Egress rules derived from the declared ``network`` permission."""

    provider_id: str
    profile_id: str
    network_declared: bool = False
    allowed_hosts: tuple[str, ...] = ()

    @property
    def mode(self) -> EgressMode:
        return EgressMode.ALLOW_DECLARED_HOSTS if self.network_declared else EgressMode.DENY_ALL

    def with_allowed_hosts(self, hosts: Iterable[str]) -> EgressPolicy:
        """The same policy with operator-enumerated destinations attached."""
        return replace(self, allowed_hosts=tuple(hosts))

    def _listed(self, host: str) -> bool:
        for entry in self.allowed_hosts:
            candidate = entry.strip().lower()
            if candidate.startswith("."):
                if host == candidate[1:] or host.endswith(candidate):
                    return True
            elif host == candidate:
                return True
        return False

    def decide(self, destination: str) -> EgressDecision:
        """Allow or deny one egress attempt, with a reason either way."""
        if not self.network_declared:
            return EgressDecision(
                self.provider_id,
                self.profile_id,
                destination,
                destination_host(destination),
                False,
                "provider does not declare network; the default posture reaches nothing",
            )
        host = destination_host(destination)
        if self._listed(host):
            return EgressDecision(
                self.provider_id,
                self.profile_id,
                destination,
                host,
                True,
                f"{host!r} is in the operator-granted egress allowlist",
            )
        if not self.allowed_hosts:
            return EgressDecision(
                self.provider_id,
                self.profile_id,
                destination,
                host,
                False,
                "provider declares network but no egress destination was granted, "
                "so egress is deny-by-default",
            )
        return EgressDecision(
            self.provider_id,
            self.profile_id,
            destination,
            host,
            False,
            f"{host!r} is outside the operator-granted egress allowlist "
            f"({', '.join(sorted(self.allowed_hosts))})",
        )


def sandbox_denial_evidence(
    decision: EgressDecision | FilesystemDecision,
    *,
    kind: str,
    recorded_at: datetime | None = None,
) -> ProviderEvidenceRecord:
    """A sandbox denial as a sealed-shaped evidence record.

    Same model as any other provider evidence — one schema, one ``outcome``
    vocabulary — so a denial cannot be recorded in a private shape that an
    auditor would have to special-case. ``compensation_status`` is
    ``NOT_REQUIRED`` because a denial has no effect to compensate; the thing
    that happened is that nothing happened.
    """
    target = decision.destination if isinstance(decision, EgressDecision) else decision.path
    stamped = recorded_at if recorded_at is not None else utc_now()
    return evidence_record(
        provider_id=decision.provider_id,
        operation_id=f"sandbox.{kind}:{target}",
        target_id=target,
        outcome="denied",
        recorded_at=stamped,
        source=f"sandbox.{kind}",
        compensation_status=CompensationStatus.NOT_REQUIRED,
        details={
            "sandbox_kind": kind,
            "sandbox_profile": decision.profile_id,
            "decision": decision.to_dict(),
        },
    )


class SandboxEgressDenied(ProviderError):  # noqa: N818 — public API, not a stdlib error
    """A sandboxed provider tried to egress outside policy.

    Carries the evidence record for the denial so a caller cannot log the
    exception and lose the record (or record it and swallow the exception).
    Both are wrong: the refusal must propagate *and* the evidence must exist.
    """

    def __init__(self, decision: EgressDecision, evidence: ProviderEvidenceRecord) -> None:
        self.decision = decision
        self.evidence = evidence
        super().__init__("provider_sandbox_egress_denied", decision.denial_message())


@dataclass(frozen=True, slots=True)
class SandboxProfile:
    """One provider's declared sandbox: a named tier plus three decisions.

    Every field is derived from the declaration, so two providers with the same
    requested permissions get the same policy and no provider gets a policy
    nobody asked for. Nothing here has been applied to the operating system; see
    :data:`SANDBOX_NOT_ENFORCED_NOTICE`.
    """

    provider_id: str
    profile_id: str
    tier: str
    tier_summary: str
    requested_permissions: frozenset[ProviderPermission]
    mechanisms: tuple[MechanismRequirement, ...]
    filesystem: FilesystemPolicy
    egress: EgressPolicy
    capabilities: CapabilityPolicy
    notice: str = SANDBOX_NOT_ENFORCED_NOTICE

    @property
    def unapplied_mechanisms(self) -> tuple[MechanismRequirement, ...]:
        """The mechanisms this build names but cannot install."""
        return tuple(item for item in self.mechanisms if not item.applied)

    @property
    def admits_enforcement(self) -> bool:
        """True when nothing declared needs a mechanism mayhem cannot apply.

        A provider that declared no permissions reaches nothing, so there is
        nothing to confine; every other profile has at least one unapplied
        mechanism. This is what :meth:`SandboxEnforcer.admit` checks under
        ``require_enforced=True``.
        """
        return not self.unapplied_mechanisms

    def decide_filesystem(self, operation: str, path: str) -> FilesystemDecision:
        return self.filesystem.decide(operation, path)

    def decide_egress(self, destination: str) -> EgressDecision:
        return self.egress.decide(destination)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "profile_id": self.profile_id,
            "tier": self.tier,
            "tier_summary": self.tier_summary,
            "requested_permissions": sorted(
                permission.value for permission in self.requested_permissions
            ),
            "mechanisms": [item.to_dict() for item in self.mechanisms],
            "unapplied_mechanisms": [item.mechanism.value for item in self.unapplied_mechanisms],
            "admits_enforcement": self.admits_enforcement,
            "filesystem": {
                "read_declared": self.filesystem.read_declared,
                "write_declared": self.filesystem.write_declared,
                "read_roots": list(self.filesystem.read_roots),
                "writable_roots": list(self.filesystem.writable_roots),
            },
            "egress": {
                "mode": self.egress.mode.value,
                "allowed_hosts": list(self.egress.allowed_hosts),
            },
            "capabilities": self.capabilities.to_dict(),
            "notice": self.notice,
        }


def _mechanism_requirements(
    permissions: frozenset[ProviderPermission],
) -> tuple[MechanismRequirement, ...]:
    """Every mechanism the requested permissions imply, in a fixed order.

    Which mechanisms a permission implies is a statement about the operating
    system, not a preference: spawning a process needs syscall filtering and an
    isolation boundary; touching the network needs both plus egress rules;
    writing a path needs path mediation plus label separation. The order is
    fixed so two runs over the same declaration produce the same profile.
    """
    undeclared = (
        f"{SandboxMechanism.SECCOMP.value}, {SandboxMechanism.APPARMOR.value}, "
        f"{SandboxMechanism.SELINUX.value}, {SandboxMechanism.CONTAINER.value} "
        "are named but never applied by this build"
    )
    requirements: list[MechanismRequirement] = []
    if permissions & _WORLD_REACHING_PERMISSIONS:
        requirements.append(
            MechanismRequirement(
                SandboxMechanism.SECCOMP,
                MechanismState.DECLARED_NOT_APPLIED,
                f"declared {sorted(p.value for p in permissions & _WORLD_REACHING_PERMISSIONS)} "
                f"leave the process able to call any syscall; {undeclared}",
            )
        )
    if permissions & {
        ProviderPermission.FILESYSTEM_READ,
        ProviderPermission.FILESYSTEM_WRITE,
    }:
        requirements.append(
            MechanismRequirement(
                SandboxMechanism.APPARMOR,
                MechanismState.DECLARED_NOT_APPLIED,
                "path mediation is decided by FilesystemPolicy but no profile is loaded "
                f"into the kernel; {undeclared}",
            )
        )
    if permissions & {ProviderPermission.TARGET_MUTATE, ProviderPermission.FILESYSTEM_WRITE}:
        requirements.append(
            MechanismRequirement(
                SandboxMechanism.SELINUX,
                MechanismState.DECLARED_NOT_APPLIED,
                f"writes need label separation; no label is assigned. {undeclared}",
            )
        )
    if permissions & {ProviderPermission.SUBPROCESS, ProviderPermission.NETWORK}:
        requirements.append(
            MechanismRequirement(
                SandboxMechanism.CONTAINER,
                MechanismState.DECLARED_NOT_APPLIED,
                "an isolation boundary is implied by spawning processes or reaching the "
                f"network; no container is created. {undeclared}",
            )
        )
    if permissions:
        requirements.append(
            MechanismRequirement(
                SandboxMechanism.CAPABILITY_DROP,
                MechanismState.DECLARED_NOT_APPLIED,
                f"the drop set is computed ({len(BASELINE_DROPPED_CAPABILITIES)} capabilities "
                "less the declared retentions) but nothing calls prctl/capset to apply it",
            )
        )
    requirements.append(
        MechanismRequirement(
            SandboxMechanism.FILESYSTEM,
            MechanismState.POLICY_DECIDED,
            "FilesystemPolicy.decide answers per path and is the refusal this build enforces",
        )
    )
    requirements.append(
        MechanismRequirement(
            SandboxMechanism.EGRESS,
            MechanismState.POLICY_DECIDED,
            "EgressPolicy.decide answers per destination and denies, with the denial in evidence",
        )
    )
    return tuple(requirements)


def select_profile(metadata: ProviderMetadata) -> SandboxProfile:
    """The sandbox profile a declaration earns, from what it *requested*.

    Keyed on the **declared** :attr:`ProviderMetadata.permissions` — the set
    :func:`~mayhem.domain.provider.ensure_permissions` compares against a grant,
    and therefore the set an operator is shown before approving an install —
    widened by :attr:`ProviderMetadata.required_permissions`, the union over
    capabilities, locators and faults.

    The two are equal for a validated declaration. They can disagree for one that
    was never validated (``model_copy`` does not re-validate), and then the
    **wider** claim is the one a profile must follow: a confinement decision made
    from the narrower of two claims is exactly the decision a lying declaration
    wants.

    Pure: no IO, no clock, no host inspection, and no third-party dependency.
    """
    provider_id = metadata.provider_id
    requested = metadata.permissions | metadata.required_permissions
    tier = select_tier(requested)
    profile_id = f"sandbox.{tier.id}"
    return SandboxProfile(
        provider_id=provider_id,
        profile_id=profile_id,
        tier=tier.id,
        tier_summary=tier.summary,
        requested_permissions=requested,
        mechanisms=_mechanism_requirements(requested),
        filesystem=FilesystemPolicy(
            provider_id=provider_id,
            profile_id=profile_id,
            read_declared=ProviderPermission.FILESYSTEM_READ in requested,
            write_declared=ProviderPermission.FILESYSTEM_WRITE in requested,
        ),
        egress=EgressPolicy(
            provider_id=provider_id,
            profile_id=profile_id,
            network_declared=ProviderPermission.NETWORK in requested,
        ),
        capabilities=CapabilityPolicy.for_permissions(requested),
    )


@dataclass(frozen=True, slots=True)
class SandboxAdmission:
    """What admission established — and, explicitly, what it did not."""

    provider_id: str
    profile_id: str
    enforced: bool
    mechanisms: tuple[MechanismRequirement, ...]
    notice: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "profile_id": self.profile_id,
            "enforced": self.enforced,
            "mechanisms": [item.to_dict() for item in self.mechanisms],
            "notice": self.notice,
        }


class SandboxEnforcer:
    """The seam a real confinement mechanism plugs into.

    Two jobs, and only two:

    1. **Admit** — say whether mayhem can honour what the profile asks for. With
       ``require_enforced=True`` a profile that needs an unapplied mechanism is
       refused at load, naming the mechanism; the default is to admit and report
       the gap.
    2. **Decide** — answer the per-operation questions (this path, this
       destination), record a denial as
       :class:`~mayhem.domain.provider.ProviderEvidenceRecord`, and raise.

    A real seccomp/AppArmor/SELinux/container backend belongs behind
    :meth:`admit` as an additional :class:`MechanismRequirement` whose state
    becomes ``POLICY_DECIDED`` once it can actually run. Nothing in this file
    needs to change for that; only the state does, which is the point of
    modelling the state separately from the decision.
    """

    def __init__(
        self,
        profile: SandboxProfile,
        *,
        require_enforced: bool = False,
        read_roots: Iterable[str] = (),
        writable_roots: Iterable[str] = (),
        egress_allowlist: Iterable[str] = (),
    ) -> None:
        self.profile = replace(
            profile,
            filesystem=profile.filesystem.with_roots(
                read_roots=read_roots, writable_roots=writable_roots
            ),
            egress=profile.egress.with_allowed_hosts(egress_allowlist),
        )
        self._require_enforced = require_enforced
        self._denials: list[ProviderEvidenceRecord] = []

    @property
    def denials(self) -> tuple[ProviderEvidenceRecord, ...]:
        """Every denial recorded, oldest first.

        Recorded *before* the refusal is raised, so a caller that catches the
        exception still has the evidence, and a caller that lets it propagate
        still has it here.
        """
        return tuple(self._denials)

    def admit(self) -> SandboxAdmission:
        """Admit the provider, or refuse to because mayhem cannot confine it."""
        unapplied = self.profile.unapplied_mechanisms
        if self._require_enforced and unapplied:
            names = ", ".join(item.mechanism.value for item in unapplied)
            raise ProviderSandboxError(
                "provider_sandbox_mechanism_unapplied",
                f"provider {self.profile.provider_id!r} profile "
                f"{self.profile.profile_id!r} requires {names}, which this mayhem "
                "build does not apply; load it without sandbox enforcement or "
                "provide a mechanism that does",
            )
        return SandboxAdmission(
            provider_id=self.profile.provider_id,
            profile_id=self.profile.profile_id,
            enforced=self.profile.admits_enforcement,
            mechanisms=self.profile.mechanisms,
            notice=self.profile.notice,
        )

    def authorize_filesystem(self, operation: str, path: str) -> FilesystemDecision:
        """Decide one filesystem operation; raise nothing, record a denial."""
        decision = self.profile.decide_filesystem(operation, path)
        if decision.denied:
            self._denials.append(
                sandbox_denial_evidence(decision, kind="filesystem", recorded_at=utc_now())
            )
        return decision

    def require_filesystem(self, operation: str, path: str) -> FilesystemDecision:
        """Decide one filesystem operation, or refuse it as a sandbox denial."""
        decision = self.authorize_filesystem(operation, path)
        if decision.denied:
            raise SandboxAccessDenied(decision, self._denials[-1])
        return decision

    def authorize_egress(self, destination: str) -> EgressDecision:
        """Decide one egress attempt; record a denial and refuse it.

        The evidence record is created, recorded, and attached to the exception,
        so "logged" and "propagated" are not alternatives.
        """
        decision = self.profile.decide_egress(destination)
        if decision.allowed:
            return decision
        evidence = sandbox_denial_evidence(decision, kind="egress", recorded_at=utc_now())
        self._denials.append(evidence)
        raise SandboxEgressDenied(decision, evidence)


class SandboxAccessDenied(ProviderError):  # noqa: N818 — public API, not a stdlib error
    """A sandboxed provider tried to touch a path outside policy.

    Carries its evidence record for the same reason
    :class:`SandboxEgressDenied` does: the denial must be recordable *and*
    propagable, so the record travels with the exception rather than living
    only in the enforcer that raised it.
    """

    def __init__(self, decision: FilesystemDecision, evidence: ProviderEvidenceRecord) -> None:
        self.decision = decision
        self.evidence = evidence
        super().__init__(
            "provider_sandbox_filesystem_denied",
            f"provider {decision.provider_id!r} denied {decision.operation} of "
            f"{decision.path!r}: {decision.reason}",
        )
