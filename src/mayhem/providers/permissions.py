"""Provider sandbox permissions (v0.9.0 expansion task 18).

A provider is third-party code. The default posture is *nothing*: no target
mutation, no subprocess, no network, no environment reads, no filesystem writes.
Anything a provider needs beyond that must be granted explicitly, and every
refusal names the exact permission and the fix.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mayhem.domain.provider import ProviderPermission

#: Nothing is allowed unless a grant says otherwise.
DEFAULT_PERMISSION_SET: frozenset[ProviderPermission] = frozenset()

#: The permissions that make a provider able to affect the world.
DANGEROUS_PERMISSIONS: frozenset[ProviderPermission] = frozenset(
    {
        ProviderPermission.TARGET_MUTATE,
        ProviderPermission.SUBPROCESS,
        ProviderPermission.NETWORK,
        ProviderPermission.FILESYSTEM_WRITE,
    }
)


class SandboxRefusal(Exception):
    """Deterministic refusal: the message is the contract, not a log line."""

    def __init__(self, provider_id: str, permission: str, reason: str) -> None:
        self.provider_id = provider_id
        self.permission = permission
        self.reason = reason
        super().__init__(
            f"provider {provider_id!r} denied {permission!r}: {reason}"
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "provider_id": self.provider_id,
            "permission": self.permission,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class ProviderPermissionSet:
    """The permissions one provider is allowed to exercise."""

    provider_id: str
    granted: frozenset[ProviderPermission] = DEFAULT_PERMISSION_SET
    grants: tuple[dict[str, str], ...] = field(default_factory=tuple)

    @classmethod
    def default(cls, provider_id: str) -> ProviderPermissionSet:
        """The default posture: read-only target access, nothing else."""
        return cls(
            provider_id=provider_id,
            granted=frozenset({ProviderPermission.TARGET_READ}),
            grants=(
                {
                    "permission": ProviderPermission.TARGET_READ.value,
                    "reason": "default read-only provider posture",
                },
            ),
        )

    @classmethod
    def from_names(cls, provider_id: str, names: tuple[str, ...]) -> ProviderPermissionSet:
        granted: set[ProviderPermission] = set()
        for name in names:
            granted.add(ProviderPermission(name))
        return cls(provider_id=provider_id, granted=frozenset(granted))

    def allows(self, permission: ProviderPermission) -> bool:
        return permission in self.granted

    @property
    def mutating(self) -> bool:
        """True when this provider can change the target at all."""
        return ProviderPermission.TARGET_MUTATE in self.granted

    def require(self, permission: ProviderPermission, *, reason: str = "") -> None:
        """Raise a deterministic refusal unless the permission was granted."""
        if permission in self.granted:
            return
        raise SandboxRefusal(
            self.provider_id,
            permission.value,
            reason
            or (
                "not granted; add an explicit permission grant for this provider"
            ),
        )

    def check(self, requested: frozenset[ProviderPermission]) -> tuple[str, ...]:
        """Return the sorted names of ungranted permissions, if any."""
        return tuple(sorted(p.value for p in requested - self.granted))

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "granted": sorted(permission.value for permission in self.granted),
            "mutating": self.mutating,
            "grants": [dict(grant) for grant in self.grants],
        }


def validate_pack_permissions(
    provider_id: str, permissions: ProviderPermissionSet, requested: frozenset[ProviderPermission]
) -> None:
    """Refuse a pack that asks for more than the provider was granted."""
    missing = permissions.check(requested)
    if missing:
        raise SandboxRefusal(
            provider_id,
            ",".join(missing),
            "pack requests permissions outside the provider's grant",
        )
