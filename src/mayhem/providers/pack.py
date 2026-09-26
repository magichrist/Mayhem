"""Fault packs: signed, validated bundles of fault definitions (task 18).

A pack is third-party content, so it is treated like third-party code: the
schema version must be known, the digest must match the bytes, unsafe targets
and duplicate ids are refused, and a fault with no compensation is refused
outright. An unsigned pack is explicitly *local development only* — never a
silent pass.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mayhem.domain.provider import ProviderPermission

PACK_SCHEMA_VERSION = "1.0"
SUPPORTED_PACK_SCHEMA_VERSIONS: frozenset[str] = frozenset({PACK_SCHEMA_VERSION})

#: Targets a pack may never name, whatever it declares.
FORBIDDEN_TARGET_PREFIXES: tuple[str, ...] = ("host", "/", "node://", "ssh://")


class PackValidationError(ValueError):
    """A pack was refused. The message names every problem found."""


class ProviderManifest(BaseModel):
    """Who published the pack and what it needs."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider_id: str
    version: str = "0.0.0"
    api_version: str = PACK_SCHEMA_VERSION
    homepage: str = ""
    permissions: tuple[ProviderPermission, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        payload["permissions"] = sorted(p.value for p in self.permissions)
        return payload


class PackFault(BaseModel):
    """One fault contributed by a pack."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    target: str = ""
    risk: str = "medium"
    reversible: bool = True
    compensation: str = ""
    observable_effect: str = ""
    permissions: tuple[ProviderPermission, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        payload["permissions"] = sorted(p.value for p in self.permissions)
        return payload


class FaultPack(BaseModel):
    """A versioned, digest-bearing bundle of fault definitions."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = PACK_SCHEMA_VERSION
    manifest: ProviderManifest
    faults: tuple[PackFault, ...] = ()
    signature: str = ""
    signer: str = ""
    declared_digest: str = ""
    development_only: bool = False

    def canonical_json(self) -> str:
        return json.dumps(
            self.model_dump(mode="json", exclude={"declared_digest"}),
            sort_keys=True,
            separators=(",", ":"),
        )

    def pack_digest(self) -> str:
        """Content digest, excluding the digest field itself."""
        return hashlib.sha256(self.canonical_json().encode()).hexdigest()

    @property
    def signed(self) -> bool:
        return bool(self.signature)

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.model_dump(mode="json"),
            "digest": self.pack_digest(),
            "signed": self.signed,
        }


def validate_pack(
    pack: FaultPack,
    *,
    expected_digest: str = "",
    granted_permissions: frozenset[ProviderPermission] = frozenset(),
    allow_development_only: bool = False,
) -> dict[str, Any]:
    """Validate a pack, returning a report or raising with every reason.

    The check order is fixed so the message is deterministic: schema, digest,
    signature, ids, targets, compensation, permissions.
    """
    problems: list[str] = []

    if pack.schema_version not in SUPPORTED_PACK_SCHEMA_VERSIONS:
        problems.append(
            f"unsupported pack schema {pack.schema_version!r} "
            f"(supported: {sorted(SUPPORTED_PACK_SCHEMA_VERSIONS)})"
        )
    if pack.manifest.api_version not in SUPPORTED_PACK_SCHEMA_VERSIONS:
        problems.append(
            f"pack manifest targets api {pack.manifest.api_version!r}, which this "
            f"Mayhem does not implement (supported: {sorted(SUPPORTED_PACK_SCHEMA_VERSIONS)})"
        )

    digest = pack.pack_digest()
    if pack.declared_digest and pack.declared_digest != digest:
        problems.append(
            f"pack digest mismatch: declared {pack.declared_digest[:12]}, computed {digest[:12]}"
        )
    if expected_digest and expected_digest != digest:
        problems.append(
            f"pack digest does not match the expected {expected_digest[:12]}"
        )

    if not pack.signed:
        if not allow_development_only:
            problems.append(
                "pack is unsigned: local development only, "
                "pass an explicit development-only allowance to load it"
            )
    elif not pack.signer:
        problems.append("pack is signed but names no signer")

    seen: set[str] = set()
    for fault in pack.faults:
        if fault.id in seen:
            problems.append(f"duplicate fault id {fault.id!r}")
        seen.add(fault.id)
        if not fault.id or "." not in fault.id:
            problems.append(f"fault id {fault.id!r} is not namespaced")
        lowered = fault.target.lower()
        if lowered and lowered.startswith(FORBIDDEN_TARGET_PREFIXES):
            problems.append(f"fault {fault.id!r} names an unsafe target {fault.target!r}")
        if not fault.reversible and not fault.compensation:
            problems.append(
                f"fault {fault.id!r} is irreversible with no compensation"
            )
        if not fault.compensation:
            problems.append(f"fault {fault.id!r} declares no compensation")

    requested = set(pack.manifest.permissions)
    for fault in pack.faults:
        requested |= set(fault.permissions)
    ungranted = sorted(p.value for p in requested - granted_permissions)
    if ungranted:
        problems.append(
            "pack requests permissions that were not granted: " + ", ".join(ungranted)
        )

    if problems:
        raise PackValidationError(
            f"pack {pack.manifest.provider_id!r} refused: " + "; ".join(problems)
        )

    return {
        "provider_id": pack.manifest.provider_id,
        "schema_version": pack.schema_version,
        "digest": digest,
        "signed": pack.signed,
        "fault_count": len(pack.faults),
        "permissions": sorted(p.value for p in requested),
        "development_only": not pack.signed,
        "loadable": True,
    }


def load_pack(payload: dict[str, Any]) -> FaultPack:
    """Parse a pack document, reporting parse errors as PackValidationError."""
    try:
        return FaultPack.model_validate(payload)
    except Exception as exc:  # pydantic ValidationError or TypeError
        raise PackValidationError(f"invalid pack document: {exc}") from exc
