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

from pydantic import BaseModel, ConfigDict

from mayhem.domain.provider import ProviderPermission

PACK_SCHEMA_VERSION = "1.0"
SUPPORTED_PACK_SCHEMA_VERSIONS: frozenset[str] = frozenset({PACK_SCHEMA_VERSION})

#: Targets a pack may never name, whatever it declares.
FORBIDDEN_TARGET_PREFIXES: tuple[str, ...] = ("host", "/", "node://", "ssh://")

#: Mayhem 1.0 **cannot verify a fault-pack signature**, and no code path may
#: claim that it has. The format carries a bare ``signature: str`` and a
#: ``signer: str``: no public key, no key id, no algorithm identifier, no
#: trust store, and no signature-verification dependency in this build. What
#: ``signature`` therefore holds is an *assertion of authorship by whoever
#: wrote the file* — the same trust you get from a comment.
#:
#: What a pack *can* prove is integrity: ``declared_digest`` is a SHA-256 over
#: the canonical pack document, and the loader checks it against the bytes on
#: disk. That detects tampering; it says nothing about who wrote the pack.
#: Consumers must surface this distinction rather than collapsing it into a
#: single "verified" flag.
SIGNATURE_VERIFICATION_IMPLEMENTED: bool = False

#: The sentence that must accompany every pack verdict. It is deliberately
#: part of the format module so that no consumer can report a pack as trusted
#: without the caveat being structurally next to the flag that says so.
SIGNATURE_TRUST_NOTICE: str = (
    "mayhem cannot verify fault-pack signatures: the format declares no key, no algorithm, "
    "and no trust store, so a pack signature is an unverified claim of authorship. "
    "Only the sha256 content digest is checked, and that proves integrity, not provenance."
)

#: Flag named in every development-only refusal, so the message tells the user
#: exactly what to type.
DEVELOPMENT_ONLY_FLAG: str = "--allow-development-only"


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


def _check_schema_versions(pack: FaultPack) -> list[str]:
    """Schema of the pack document and of the manifest it declares."""
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
    return problems


def _check_digests(pack: FaultPack, digest: str, expected_digest: str) -> list[str]:
    """The pack's own declared digest and any caller-supplied expectation."""
    problems: list[str] = []
    if pack.declared_digest and pack.declared_digest != digest:
        problems.append(
            f"pack digest mismatch: declared {pack.declared_digest[:12]}, computed {digest[:12]}"
        )
    if expected_digest and expected_digest != digest:
        problems.append(f"pack digest does not match the expected {expected_digest[:12]}")
    return problems


def _check_signature(pack: FaultPack, *, allow_development_only: bool) -> list[str]:
    """An unsigned pack is local-development-only; a signed one names its signer.

    A non-empty ``signature`` is *not* checked against a key: see
    :data:`SIGNATURE_VERIFICATION_IMPLEMENTED`. This check only refuses packs
    that make no provenance claim at all, or claim one without naming a signer.
    """
    problems: list[str] = []
    if not pack.signed:
        if not allow_development_only:
            problems.append(
                "pack is unsigned: local development only, re-run with "
                f"{DEVELOPMENT_ONLY_FLAG} to load it"
            )
    elif not pack.signer:
        problems.append("pack is signed but names no signer")
    return problems


def _check_development_only(pack: FaultPack, *, allow_development_only: bool) -> list[str]:
    """A pack that *declares* itself development-only is refused unless opted in.

    The ``development_only`` field is an author assertion, so it is honoured
    independently of whether the pack also carries a signature string.
    """
    if not pack.development_only or allow_development_only:
        return []
    return [
        "pack is marked development_only by its author: re-run with "
        f"{DEVELOPMENT_ONLY_FLAG} to load a development-only pack"
    ]


def _path_traversal(value: str) -> str:
    """Why ``value`` is an unsafe path, or ``""`` when it is not path-shaped.

    ``..`` traversal is checked explicitly because a relative traversal does not
    begin with any of :data:`FORBIDDEN_TARGET_PREFIXES` and would otherwise slip
    past them.
    """
    if "\x00" in value:
        return "it contains a NUL byte"
    normalized = value.replace("\\", "/")
    if normalized.startswith("~"):
        return "it expands a home directory"
    if any(segment == ".." for segment in normalized.split("/")):
        return "it traverses out of its directory"
    return ""


def _check_fault(fault: PackFault, seen: set[str]) -> list[str]:
    """Problems with one contributed fault, in a fixed order for determinism."""
    problems: list[str] = []
    if fault.id in seen:
        problems.append(f"duplicate fault id {fault.id!r}")
    seen.add(fault.id)
    if not fault.id or "." not in fault.id:
        problems.append(f"fault id {fault.id!r} is not namespaced")
    lowered = fault.target.lower()
    if lowered and lowered.startswith(FORBIDDEN_TARGET_PREFIXES):
        problems.append(f"fault {fault.id!r} names an unsafe target {fault.target!r}")
    traversal = _path_traversal(fault.target)
    if traversal:
        problems.append(f"fault {fault.id!r} names an unsafe target {fault.target!r}: {traversal}")
    if not fault.reversible and not fault.compensation:
        problems.append(f"fault {fault.id!r} is irreversible with no compensation")
    if not fault.compensation:
        problems.append(f"fault {fault.id!r} declares no compensation")
    return problems


def _check_homepage(pack: FaultPack) -> list[str]:
    """The manifest homepage is display metadata, so it must be inert."""
    homepage = pack.manifest.homepage
    if not homepage:
        return []
    if not homepage.startswith(("http://", "https://")):
        return [f"manifest homepage {homepage!r} is not an http(s) URL"]
    traversal = _path_traversal(homepage)
    if traversal:
        return [f"manifest homepage {homepage!r} is an unsafe path: {traversal}"]
    authority = homepage.split("//", 1)[-1].split("/", 1)[0]
    if "@" in authority:
        return [f"manifest homepage {homepage!r} embeds credentials"]
    return []


def _check_faults(pack: FaultPack) -> list[str]:
    """Every contributed fault, in pack order, with duplicates detected across them."""
    problems: list[str] = []
    seen: set[str] = set()
    for fault in pack.faults:
        problems.extend(_check_fault(fault, seen))
    return problems


def _requested_permissions(pack: FaultPack) -> set[ProviderPermission]:
    """Manifest permissions unioned with every fault's own permissions."""
    requested = set(pack.manifest.permissions)
    for fault in pack.faults:
        requested |= set(fault.permissions)
    return requested


def _check_permissions(
    requested: set[ProviderPermission], granted_permissions: frozenset[ProviderPermission]
) -> list[str]:
    """A pack may only ask for permissions the provider was actually granted."""
    ungranted = sorted(p.value for p in requested - granted_permissions)
    if not ungranted:
        return []
    return ["pack requests permissions that were not granted: " + ", ".join(ungranted)]


def validate_pack(
    pack: FaultPack,
    *,
    expected_digest: str = "",
    granted_permissions: frozenset[ProviderPermission] = frozenset(),
    allow_development_only: bool = False,
) -> dict[str, Any]:
    """Validate a pack, returning a report or raising with every reason.

    The check order is fixed so the message is deterministic: schema, digest,
    signature, development-only, ids, targets, compensation, permissions.

    A successful return is **not** a claim of provenance. Read
    :func:`pack_assurance` for what was and was not established.
    """
    digest = pack.pack_digest()
    requested = _requested_permissions(pack)
    problems: list[str] = [
        *_check_schema_versions(pack),
        *_check_digests(pack, digest, expected_digest),
        *_check_signature(pack, allow_development_only=allow_development_only),
        *_check_development_only(pack, allow_development_only=allow_development_only),
        *_check_faults(pack),
        *_check_homepage(pack),
        *_check_permissions(requested, granted_permissions),
    ]

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
        "development_only": pack.development_only or not pack.signed,
        "loadable": True,
        "assurance": pack_assurance(pack, digest_verified=True),
    }


def pack_assurance(pack: FaultPack, *, digest_verified: bool) -> dict[str, Any]:
    """What a pack verdict does and does not establish.

    Deliberately split into two axes. ``digest_verified`` says the bytes on
    disk hash to the declared digest — *integrity*. ``signature_verified`` says
    a cryptographic signature was checked against a trusted key — *provenance*.
    In this build the second is always ``False``, because the format has no
    mechanism to check it. A consumer that collapses the two into one boolean
    is manufacturing assurance, which is the failure mode this whole format
    exists to avoid.
    """
    return {
        "signature_verified": SIGNATURE_VERIFICATION_IMPLEMENTED,
        "signature_present": pack.signed,
        "signature_scheme": "none",
        "signer_claimed": pack.signer,
        "signer_trusted": False,
        "digest_verified": digest_verified,
        "digest": pack.pack_digest(),
        "development_only": pack.development_only or not pack.signed,
        "assurance": "integrity-only" if pack.signed else "none",
        "notice": SIGNATURE_TRUST_NOTICE,
    }


def load_pack(payload: dict[str, Any]) -> FaultPack:
    """Parse a pack document, reporting parse errors as PackValidationError."""
    try:
        return FaultPack.model_validate(payload)
    except Exception as exc:  # pydantic ValidationError or TypeError
        raise PackValidationError(f"invalid pack document: {exc}") from exc
