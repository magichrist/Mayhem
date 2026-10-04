"""Secure update manifests: what may be applied, and what is not (plan 19, Phase 3).

The plan's Security section asks for a "secure update mechanism for agents and
controllers (signed update manifests verified before apply)". This module is that
mechanism's *decision*, and it is built around one rule:

    **Nothing is applied that has not been verified, and the verification is a
    separate value from the thing it verified.**

There is no ``apply()`` that takes an unverified manifest, and no
:meth:`UpdateApplier.apply` that re-derives trust itself. The caller holds a
:class:`ManifestVerdict`, the verdict says yes or no, and a refusal names *which*
of eight reasons fired. There is no field on a manifest called ``trusted``, and no
way to construct one.

What the verification really establishes
----------------------------------------

:meth:`UpdateVerifier.verify` runs the same HMAC-SHA256 check over a canonical
payload that
:class:`~mayhem.infra.agent_identity_verifier.HmacSha256SignatureVerifier` runs
over a command envelope, and it reuses that class rather than writing a second
MAC — one canonicaliser, one comparison, one key-length rule.

So the honest statement is the same one plan 03 and Phase 2 already made:
**a holder of the shared signing key produced these bytes, and they have not
changed since.** It is symmetric. It is not a public-key signature, it is not a
certificate, and it proves nothing to a third party who does not hold the key.
:meth:`UpdateVerifier.algorithm` and :attr:`ManifestVerdict.algorithm` are stamped
on every verdict for that reason.

What is *not* here
------------------

* **No Sigstore, no Cosign, no transparency log, no Rekor entry.** Not imported,
  not configured, not stubbed. Naming any of them in a deployment document for
  this build would be a lie.
* **No SLSA provenance and no SBOM generation.** Plan 19's Phase 4 acceptance
  lists SBOM and provenance as part of the release gate; they are recorded here as
  *references on a manifest* (:attr:`UpdateManifest.sbom_ref`,
  :attr:`UpdateManifest.provenance_ref`) and this module checks only that they are
  present and well-formed. It does not produce them and it does not verify their
  contents. A reference is a pointer, not an attestation, and the field names say
  so.
* **No download, no unpack, no install.** :class:`UpdateApplier` calls an
  injected :class:`ArtifactPort` for bytes and an injected ``apply`` callable; this
  module opens no socket and runs no subprocess. What it does decide is whether the
  bytes it was handed match the digest that was signed, which is the part a secure
  mechanism actually owes.
* **No key custody.** :class:`UpdateSignerKeyPort` is the same in-process shape as
  :class:`~mayhem.infra.agent_identity_verifier.StaticKeyMaterial`; nothing here
  persists a signing key.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Final, Protocol

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from mayhem.domain.attestation import canonical_event_bytes
from mayhem.domain.common import utc_now
from mayhem.domain.errors import DomainError, InvariantViolationError
from mayhem.infra.agent_identity_verifier import (
    ALGORITHM_HMAC_SHA256,
    ALGORITHM_X509,
    HmacSha256CommandSigner,
    HmacSha256SignatureVerifier,
    KeyMaterialPort,
    SignaturePortUnavailableError,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping, Sequence

_ID = r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$"
_IDENT = Annotated[str, StringConstraints(pattern=_ID)]
_SHA256 = r"^[0-9a-f]{64}$"
_VERSION = r"^[0-9]+(\.[0-9]+){0,3}([-+][A-Za-z0-9.-]+)?$"
_SIG = r"^[A-Za-z0-9+/=_-]+$"

#: Stable refusal codes. ``UPDATE_*`` so a caller can route on the prefix without
#: colliding with the plan's other refusal vocabularies.
UPDATE_UNVERIFIED = "update_manifest_unverified"
UPDATE_PORT_UNAVAILABLE = "agent_signature_port_unavailable"

_REMEDIATION: Final[str] = (
    "apply only a manifest whose signature verifies under a key the release channel "
    "publishes, inside its validity window, on the expected channel, for the component "
    "being updated; a downgrade additionally needs a recorded approval"
)


def _require_aware(moment: datetime, rule: str, subject: str) -> None:
    if moment.tzinfo is None:
        raise InvariantViolationError(
            rule, f"{subject} must be timezone-aware, got naive {moment!r}"
        )


def _require_hex(value: str, rule: str, subject: str) -> str:
    if not value or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        msg = f"{subject} must be a lowercase 64-hex sha256 digest, got {value!r}"
        raise InvariantViolationError(rule, msg)
    return value


# --------------------------------------------------------------------------- #
# Vocabulary                                                                    #
# --------------------------------------------------------------------------- #


class UpdateComponent(StrEnum):
    """What a manifest updates. A controller manifest may not update an agent."""

    CONTROLLER = "controller"
    AGENT = "agent"


class UpdateChannel(StrEnum):
    """Which release stream a manifest belongs to.

    :attr:`PINNED` is the only channel a build that refuses to follow a moving
    stream should use, and it is the only one that makes an unsigned-then-patched
    channel swap visible: a manifest must declare the channel it is for, and a
    pinned deployment refuses anything else rather than accepting "the newest".
    """

    STABLE = "stable"
    TEST = "test"
    PINNED = "pinned"


class UpdateRefusal(StrEnum):
    """Every way an update was refused. ``APPLIED`` is not one of them."""

    SIGNATURE_INVALID = "signature_invalid"
    UNKNOWN_SIGNING_KEY = "unknown_signing_key"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    CHANNEL_MISMATCH = "channel_mismatch"
    WRONG_COMPONENT = "wrong_component"
    DOWNGRADE_NOT_APPROVED = "downgrade_not_approved"
    DOWNGRADE_NOT_SUPPORTED = "downgrade_not_supported"
    PROVENANCE_MISSING = "provenance_missing"
    ARTIFACT_DIGEST_MISMATCH = "artifact_digest_mismatch"
    ARTIFACT_UNAVAILABLE = "artifact_unavailable"
    NOT_VERIFIED = "not_verified"


#: Canonical reporting order. Authored, and asserted equal to :class:`UpdateRefusal`'s
#: declaration order by the unit tests.
UPDATE_REFUSAL_ORDER: Final[tuple[UpdateRefusal, ...]] = tuple(UpdateRefusal)


def order_update_refusals(reasons: Iterable[UpdateRefusal]) -> tuple[UpdateRefusal, ...]:
    """De-duplicate and canonically order a refusal set."""
    present = set(reasons)
    return tuple(reason for reason in UPDATE_REFUSAL_ORDER if reason in present)


class ArtifactUnavailableError(DomainError):
    """The artifact could not be fetched, so nothing was applied."""

    def __init__(self, locator: str, reason: str) -> None:
        self.code = UpdateRefusal.ARTIFACT_UNAVAILABLE.value
        self.locator = locator
        self.reason = reason
        super().__init__(
            f"{self.code}: could not fetch artifact {locator!r}: {reason}"
        )


class UpdateRefusedError(DomainError):
    """An update was refused. **Nothing was applied.**"""

    def __init__(self, refusals: Sequence[UpdateRefusal], *, manifest_id: str = "") -> None:
        self.code = UPDATE_UNVERIFIED
        self.refusals = tuple(refusals)
        self.manifest_id = manifest_id
        self.remediation = _REMEDIATION
        names = ", ".join(reason.value for reason in self.refusals) or "unspecified"
        super().__init__(f"{UPDATE_UNVERIFIED}: manifest {manifest_id or '(none)'} — {names}")


# --------------------------------------------------------------------------- #
# The manifest                                                                  #
# --------------------------------------------------------------------------- #


class UpdateManifest(BaseModel):
    """A release statement: which artifact, for which component, signed by whom.

    No field has a default that could be filled in after the fact, and there is no
    ``verified`` field, no ``signature_valid`` field, and no ``trusted`` field.
    Those are verdicts (:class:`ManifestVerdict`), and keeping them off the record
    is what stops a manifest from asserting its own trustworthiness.

    Attributes:
        manifest_id: Stable id of this release statement.
        component: What it updates.
        component_version: The version being installed.
        artifact_digest: sha256 of the artifact bytes. **This is the load-bearing
            field**: it is inside the signed body, so the digest that verification
            commits to is the digest the applier compares the fetched bytes
            against. A manifest that names a digest nobody checks would make every
            signature in this module decorative.
        channel: The stream this manifest belongs to.
        issued_at: When it was signed (tz-aware).
        expires_at: When it stops being acceptable (tz-aware).
        signer_key_id: Which release key signed it.
        signature: The signature over :meth:`signed_body`.
        sbom_ref: A *reference* to a software bill of materials. Required, because
            a release that cannot name its SBOM should not be installable — but
            this module checks the reference's shape, never its contents.
        provenance_ref: A *reference* to build provenance. Same caveat.
        rollback_supported: Whether the release may be rolled back to.
        rollback_target_version: The version to roll back to, when supported.
        minimum_acceptable_version: The floor below which an install is a downgrade.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest_id: _IDENT
    component: UpdateComponent
    component_version: str = Field(pattern=_VERSION)
    artifact_digest: str
    channel: UpdateChannel = UpdateChannel.STABLE
    issued_at: datetime
    expires_at: datetime
    signer_key_id: _IDENT
    signature: str = Field(pattern=_SIG, min_length=16)
    sbom_ref: str = Field(min_length=1)
    provenance_ref: str = Field(min_length=1)
    rollback_supported: bool = False
    rollback_target_version: str | None = None
    minimum_acceptable_version: str | None = None

    @model_validator(mode="after")
    def _check_invariants(self) -> UpdateManifest:
        _require_aware(self.issued_at, "update.time_aware", f"manifest {self.manifest_id}")
        _require_aware(self.expires_at, "update.time_aware", f"manifest {self.manifest_id}")
        if self.expires_at <= self.issued_at:
            msg = (
                f"manifest {self.manifest_id} expires ({self.expires_at.isoformat()}) at or "
                f"before it was issued ({self.issued_at.isoformat()})"
            )
            raise InvariantViolationError("update.window", msg)
        _require_hex(
            self.artifact_digest, "update.artifact_digest", f"manifest {self.manifest_id}"
        )
        if self.rollback_supported:
            if not self.rollback_target_version:
                msg = (
                    f"manifest {self.manifest_id} claims rollback is supported but names no "
                    "target version; a rollback with no target is not a rollback"
                )
                raise InvariantViolationError("update.rollback_target_required", msg)
            if self.rollback_target_version == self.component_version:
                msg = (
                    f"manifest {self.manifest_id} names its own version as the rollback "
                    "target"
                )
                raise InvariantViolationError("update.rollback_target_identical", msg)
        return self

    def signed_body(self) -> dict[str, object]:
        """Exactly the fields the signature covers — every field but ``signature``.

        Returning the mapping rather than bytes is deliberate: the same
        :func:`~mayhem.domain.attestation.canonical_event_bytes` encoder is applied
        by the signer and the verifier, so "what was signed" has one definition.
        """
        payload = self.model_dump(mode="json", exclude={"signature"})
        return dict(sorted(payload.items()))

    def signed_payload(self) -> bytes:
        """The canonical bytes the signature covers."""
        return canonical_event_bytes(self.signed_body())

    def covers(self, at: datetime) -> bool:
        """True when ``at`` is inside the manifest's validity window."""
        return self.issued_at <= at < self.expires_at

    def is_downgrade_from(self, installed_version: str) -> bool:
        """True when installing this manifest would move the component backwards.

        Compared numerically on dotted integer segments, with the first segment
        that differs deciding — the same rule an operator reads off a version
        string. A non-numeric suffix (``2.0.0-rc1``) compares equal to its base, so
        ``2.0.0-rc1`` and ``2.0.0`` are *not* a downgrade relative to each other;
        that is stated rather than pretended away, because a release-candidate
        ordering rule is a policy question and not this module's to invent.
        """
        if not installed_version:
            return False
        target = _version_key(self.component_version)
        current = _version_key(installed_version)
        return current > target

    def describe(self) -> str:
        return (
            f"manifest {self.manifest_id}: {self.component.value} {self.component_version} "
            f"on {self.channel.value}, artifact {self.artifact_digest[:12]}…, signed by "
            f"{self.signer_key_id!r}, valid [{self.issued_at.isoformat()} → "
            f"{self.expires_at.isoformat()}]"
        )


def _version_key(version: str) -> tuple[int, ...]:
    """The numeric prefix of a dotted version, for ordering."""
    parts: list[int] = []
    for segment in version.split("."):
        digits = ""
        for char in segment:
            if not char.isdigit():
                break
            digits += char
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) if parts else (0,)


def version_is_newer(candidate: str, than: str) -> bool:
    """True when ``candidate`` is strictly newer than ``than`` by numeric prefix."""
    return _version_key(candidate) > _version_key(than)


# --------------------------------------------------------------------------- #
# Signature ports                                                               #
# --------------------------------------------------------------------------- #


class UpdateSignerKeyPort(Protocol):
    """Where a ``signer_key_id`` becomes a secret. No key is persisted in this repo."""

    def lookup(self, signer_key_id: str) -> bytes | None: ...


class UpdateSignaturePort(Protocol):
    """Verify a signature over :meth:`UpdateManifest.signed_payload`."""

    algorithm: str

    def verify(self, *, payload: bytes, signature: str, signing_key_id: str) -> bool: ...


class X509UpdateSignatureVerifier:
    """The public-key update-signature seam. **Fails closed, always.**

    A release channel that signs with a real key and publishes a trust store is the
    thing that would replace this, and it needs the same X.509 parsing this plan's
    command verifier already refuses for. So this class raises
    :class:`~mayhem.infra.agent_identity_verifier.SignaturePortUnavailableError`
    rather than returning ``False``: "we could not check" and "the signature is
    wrong" are different facts, and a caller conflating them would retry a bad
    manifest forever or, worse, treat an unavailable checker as a pass.

    It does **not** fall back to HMAC.
    """

    algorithm = ALGORITHM_X509

    REASON: Final[str] = (
        "public-key update manifests need an X.509/RSA signature verifier and a trust "
        "store, neither of which is in this build's dependency set; the release channel "
        "in this build is symmetric (HMAC-SHA256), which proves a holder of the shared "
        "key produced the manifest and is not public-key authorship"
    )

    def verify(self, *, payload: bytes, signature: str, signing_key_id: str) -> bool:
        """Always refuses. Never returns ``True``.

        Raises:
            SignaturePortUnavailableError: Always.
        """
        del payload, signature, signing_key_id
        raise SignaturePortUnavailableError(ALGORITHM_X509, self.REASON)


# --------------------------------------------------------------------------- #
# The verdict                                                                   #
# --------------------------------------------------------------------------- #


class ManifestVerdict(BaseModel):
    """The answer to "may this manifest be applied?".

    ``applicable`` is ``not refusals`` — a derived property rather than an
    independent flag, so there is no ``verified=False`` value that some later
    construction could contradict. ``refusals`` names *every* reason rather than
    the first, in :data:`UPDATE_REFUSAL_ORDER`, because a manifest that is both
    expired and a downgrade is one operator action (fetch a good one), not two.

    Attributes:
        manifest_id: Which manifest this is about.
        refusals: Every reason it may not be applied, canonically ordered.
        algorithm: The signature algorithm that actually ran. Always populated,
            including when the port refused — "nothing was checked" is the more
            important half of that fact.
        detail: The account a reader gets. Required on both paths.
        manifest_digest: sha256 of the signed payload, so a reader can tie the
            verdict to the exact bytes it was about.
        downgrade: True when this manifest would move the component backwards.
        channel: The channel the manifest declared.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest_id: str
    refusals: tuple[UpdateRefusal, ...] = ()
    algorithm: str = ""
    detail: str = Field(min_length=1)
    manifest_digest: str = ""
    downgrade: bool = False
    channel: UpdateChannel | None = None

    @property
    def applicable(self) -> bool:
        """True when there is no refusal. Derived, never set."""
        return not self.refusals

    @property
    def verified(self) -> bool:
        """True when the *signature* passed, ignoring policy refusals.

        Kept separate from :attr:`applicable` because they answer different
        questions: a manifest can carry a perfectly good signature and still be
        refused because it is for the wrong channel. Reading ``verified`` as
        "installable" is the mistake this split exists to prevent.
        """
        return UpdateRefusal.SIGNATURE_INVALID not in self.refusals and (
            UpdateRefusal.UNKNOWN_SIGNING_KEY not in self.refusals
        )

    def require_applicable(self) -> ManifestVerdict:
        """Return ``self``, or refuse.

        Raises:
            UpdateRefusedError: Carrying every :attr:`refusals`.
        """
        if not self.applicable:
            raise UpdateRefusedError(self.refusals, manifest_id=self.manifest_id)
        return self

    def describe(self) -> str:
        mark = "APPLICABLE" if self.applicable else "REFUSED"
        names = ", ".join(reason.value for reason in self.refusals) or "no refusal"
        return f"{mark} manifest {self.manifest_id} ({names}, {self.algorithm}): {self.detail}"


# --------------------------------------------------------------------------- #
# The verifier                                                                  #
# --------------------------------------------------------------------------- #


class UpdateVerifier:
    """Decide whether a manifest may be applied. Pure; no store, no network.

    Args:
        signature: The signature port.
            :class:`~mayhem.infra.agent_identity_verifier.HmacSha256SignatureVerifier`
            is the one real implementation; :class:`X509UpdateSignatureVerifier`
            fails closed.
        signer_keys: Where a ``signer_key_id`` becomes a secret.
        expected_channel: The stream this deployment follows. A manifest for any
            other channel is refused — "the newest" is not a security property.
        allow_downgrade: Whether an install below the currently installed version
            is permitted at all. Defaults to ``False``, and there is deliberately no
            flag that widens it without naming an approver.

    Check order, and why it is that order
    --------------------------------------

    ``signature`` → ``window`` → ``channel`` → ``component`` → ``downgrade``.
    The signature runs first because every other check is a *policy* statement
    about bytes that may not be genuine; answering a policy question about forged
    bytes tells an attacker which policy they are up against. The provenance
    references are validated by the manifest's own constructor rather than here,
    so there is no "missing reference" branch to forget.
    """

    def __init__(
        self,
        *,
        signature: UpdateSignaturePort,
        signer_keys: UpdateSignerKeyPort,
        expected_channel: UpdateChannel = UpdateChannel.STABLE,
        allow_downgrade: bool = False,
    ) -> None:
        self._signature = signature
        self._keys = signer_keys
        self._channel = expected_channel
        self._allow_downgrade = bool(allow_downgrade)

    @property
    def algorithm(self) -> str:
        return self._signature.algorithm

    @property
    def expected_channel(self) -> UpdateChannel:
        return self._channel

    @property
    def allows_downgrade(self) -> bool:
        return self._allow_downgrade

    def verify(
        self,
        manifest: UpdateManifest,
        *,
        component: UpdateComponent | None = None,
        installed_version: str | None = None,
        downgrade_approval: str = "",
        at: datetime | None = None,
    ) -> ManifestVerdict:
        """Verify ``manifest``, refusing with **every** reason that applies.

        Args:
            manifest: The release statement.
            component: The component actually being updated. ``None`` means "the
                manifest's own component", which is only correct when the caller is
                updating what the manifest names — the update CLI always states it.
            installed_version: The version presently installed. Its absence is not
                treated as "version zero": an unknown installed version cannot make
                a manifest a downgrade, and pretending otherwise would let a fresh
                install be refused as a downgrade from nothing.
            downgrade_approval: The operator who approved a downgrade. Required when
                one is happening; a non-empty approval alone does not enable
                downgrades, :attr:`allows_downgrade` does.
            at: Injected instant so a drill reproduces.

        Returns:
            A :class:`ManifestVerdict`. It is returned, not raised, because a
            caller usually wants to *show* the refusals; :meth:`verify_or_refuse`
            is the raising form.

        Raises:
            SignaturePortUnavailableError: When the configured port cannot verify
                its own algorithm. Deliberately not converted into a refusal: the
                verifier checks nothing, and a verdict that read like a checked
                refusal would be a lie.
        """
        moment = utc_now() if at is None else at
        _require_aware(moment, "update.time_aware", "verify")
        reasons: set[UpdateRefusal] = set()

        payload = manifest.signed_payload()
        if not self._signature.verify(
            payload=payload,
            signature=manifest.signature,
            signing_key_id=manifest.signer_key_id,
        ):
            reasons.add(UpdateRefusal.SIGNATURE_INVALID)
        if self._keys.lookup(manifest.signer_key_id) is None:
            reasons.add(UpdateRefusal.UNKNOWN_SIGNING_KEY)
        if not manifest.covers(moment):
            reasons.add(
                UpdateRefusal.EXPIRED
                if moment >= manifest.expires_at
                else UpdateRefusal.NOT_YET_VALID
            )
        if manifest.channel is not self._channel:
            reasons.add(UpdateRefusal.CHANNEL_MISMATCH)
        expected_component = manifest.component if component is None else component
        if manifest.component is not expected_component:
            reasons.add(UpdateRefusal.WRONG_COMPONENT)

        downgrade = False
        if installed_version is not None and manifest.is_downgrade_from(installed_version):
            downgrade = True
            if not self._allow_downgrade or not downgrade_approval.strip():
                reasons.add(UpdateRefusal.DOWNGRADE_NOT_APPROVED)

        refusals = order_update_refusals(reasons)
        return ManifestVerdict(
            manifest_id=manifest.manifest_id,
            refusals=refusals,
            algorithm=self._signature.algorithm,
            detail=self._detail(manifest, refusals, moment=moment, downgrade=downgrade),
            manifest_digest=_sha256_hex(payload),
            downgrade=downgrade,
            channel=manifest.channel,
        )

    def verify_or_refuse(self, manifest: UpdateManifest, **kwargs: object) -> ManifestVerdict:
        """:meth:`verify`, or refuse.

        Raises:
            UpdateRefusedError: On any refusal, carrying every reason.
            SignaturePortUnavailableError: Unchanged.
        """
        return self.verify(manifest, **kwargs).require_applicable()  # type: ignore[arg-type]

    def _detail(
        self,
        manifest: UpdateManifest,
        refusals: Sequence[UpdateRefusal],
        *,
        moment: datetime,
        downgrade: bool,
    ) -> str:
        if refusals:
            return (
                f"refused at {moment.isoformat()}: "
                + "; ".join(reason.value for reason in refusals)
                + f"; expected channel {self._channel.value}, "
                f"declared {manifest.channel.value}"
                + ("; install would move the component backwards" if downgrade else "")
            )
        return (
            f"{manifest.artifact_digest[:12]}… committed to by a "
            f"{self._signature.algorithm} signature over the canonical manifest body at "
            f"{moment.isoformat()}; this proves a holder of the shared release key signed "
            "these bytes and that they are unaltered, which is NOT public-key authorship "
            "and NOT a supply-chain attestation"
        )


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


# --------------------------------------------------------------------------- #
# Signing (dev/test side)                                                       #
# --------------------------------------------------------------------------- #


class HmacUpdateManifestSigner:
    """Mint a signed :class:`UpdateManifest`. Symmetric; lives beside the verifier.

    Not a trust boundary: holding the release key is the whole of its authority,
    and it says so. It exists so a test (or a dev release channel) can produce a
    manifest the verifier accepts, and so that "the signer and the verifier disagree
    about what was signed" is a state this module cannot be in — both use
    :meth:`UpdateManifest.signed_payload`.
    """

    algorithm = ALGORITHM_HMAC_SHA256

    def __init__(
        self,
        keys: KeyMaterialPort,
        *,
        verifier: HmacSha256SignatureVerifier | None = None,
    ) -> None:
        self._keys = keys
        # Reused from the command verifier rather than re-derived: one MAC, one
        # canonicaliser, one key-length rule, in one place.
        self._signer = HmacSha256CommandSigner(keys)
        self._verifier = verifier if verifier is not None else HmacSha256SignatureVerifier(keys)

    def sign(self, fields: Mapping[str, object]) -> UpdateManifest:
        """Return a validated manifest whose signature this verifier will accept.

        Raises:
            SignaturePortUnavailableError: If the signing key is unknown.
        """
        unsigned = {key: value for key, value in fields.items() if key != "signature"}
        shaped = UpdateManifest.model_validate({**unsigned, "signature": "A" * 64})
        payload = shaped.signed_payload()
        return UpdateManifest.model_validate(
            {
                **shaped.model_dump(),
                "signature": self._signer.algorithm_mac(payload, self._secret(shaped)),
            }
        )

    def _secret(self, manifest: UpdateManifest) -> bytes:
        secret = self._keys.lookup(manifest.signer_key_id)
        if secret is None:
            msg = (
                "no release key material for signer_key_id "
                f"{manifest.signer_key_id!r}; refusing to sign"
            )
            raise SignaturePortUnavailableError(ALGORITHM_HMAC_SHA256, msg)
        return secret


# --------------------------------------------------------------------------- #
# The applier                                                                   #
# --------------------------------------------------------------------------- #


class ArtifactPort(Protocol):
    """Where an artifact's bytes come from. A port, so nothing here opens a socket."""

    def fetch(self, locator: str) -> bytes: ...


class ApplyOutcome(BaseModel):
    """What an apply did. ``applied`` is ``True`` only when the hook returned.

    Attributes:
        manifest_id: Which manifest was applied.
        component: What was updated.
        from_version: What was installed before.
        to_version: What was installed now.
        artifact_digest: The digest the bytes were checked against.
        applied: Whether the hook ran to completion.
        detail: The account a reader gets. Required even on failure.
        verified_under: The algorithm whose signature authorised this.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    manifest_id: str
    component: UpdateComponent
    from_version: str
    to_version: str
    artifact_digest: str
    applied: bool
    detail: str = Field(min_length=1)
    verified_under: str = ""

    def describe(self) -> str:
        mark = "applied" if self.applied else "NOT applied"
        return (
            f"{mark}: {self.component.value} {self.from_version} → {self.to_version} from "
            f"manifest {self.manifest_id} (artifact {self.artifact_digest[:12]}…, "
            f"verified under {self.verified_under or 'nothing'})"
        )


class UpdateApplier:
    """Apply a manifest — but only a verified one, and only bytes that match it.

    The ordering is the whole module:

    1. the caller must pass a :class:`ManifestVerdict` and it must be
       ``applicable``. :meth:`apply` **does not** re-verify and has no ``verify``
       keyword; a caller cannot apply a manifest it never checked, because the
       first argument is the verdict rather than the manifest.
    2. the artifact bytes are fetched through the port and re-digested against
       :attr:`UpdateManifest.artifact_digest`. A mismatch refuses and nothing is
       applied — this is the check that would catch a store serving different bytes
       than the manifest committed to.
    3. only then does the injected ``apply`` callable run.

    Args:
        artifacts: Where bytes come from.
        apply_hook: What "installed" means here. A callable, not a shell command:
            this module runs no subprocess, so a deployment supplies the mechanism
            it actually uses (a package manager, a container pull, a file copy).
    """

    def __init__(
        self,
        *,
        artifacts: ArtifactPort,
        apply_hook: Callable[[UpdateManifest, bytes], str],
    ) -> None:
        self._artifacts = artifacts
        self._apply_hook = apply_hook

    def apply(
        self,
        manifest: UpdateManifest,
        verdict: ManifestVerdict,
        *,
        installed_version: str,
        operator: str,
    ) -> ApplyOutcome:
        """Install ``manifest`` if ``verdict`` says so and the bytes agree with it.

        Raises:
            UpdateRefusedError: If ``verdict`` is not applicable, if it is about a
                different manifest, or if the fetched bytes do not match the signed
                digest. Nothing is applied on any of these paths.
            ArtifactUnavailableError: If the port could not produce bytes. Also
                nothing applied — an unreachable store is not an applied update.
        """
        payload = self._fetch_checked(manifest, verdict)
        detail = self._apply_hook(manifest, payload)
        return ApplyOutcome(
            manifest_id=manifest.manifest_id,
            component=manifest.component,
            from_version=installed_version,
            to_version=manifest.component_version,
            artifact_digest=manifest.artifact_digest,
            applied=True,
            detail=(
                f"{detail}; operator {operator or '(unnamed)'}; authorized by a "
                f"{verdict.algorithm} signature over manifest digest "
                f"{verdict.manifest_digest[:12]}…"
            ),
            verified_under=verdict.algorithm,
        )

    def rollback(
        self,
        previous: UpdateManifest,
        verdict: ManifestVerdict,
        *,
        installed_version: str,
        operator: str,
        approved_by: str,
    ) -> ApplyOutcome:
        """Return to ``previous`` -- the manifest of the release being returned to.

        A rollback takes **the earlier release's own manifest**, not the current
        one with a flag flipped. That is the honest shape: the artifact being
        installed still has to be the bytes some manifest committed to, and the
        only manifest that committed to *those* bytes is the old release's. An
        implementation that reused the current manifest and looked up the previous
        artifact by convention would be trusting a filename.

        Three refusals are specific to this path and each names itself:
        :data:`UpdateRefusal.DOWNGRADE_NOT_SUPPORTED` when ``previous`` is not
        actually older than what is installed (rolling "back" to something newer is
        an install, and calling it a rollback would misreport the direction), and
        :data:`UpdateRefusal.DOWNGRADE_NOT_APPROVED` when no operator is named.

        Args:
            previous: The earlier release's manifest.
            verdict: The verdict *for that manifest*.
            installed_version: What is installed now.
            operator: Who performed the rollback.
            approved_by: Who approved it. Required, and distinct from
                ``operator``: a rollback an operator quietly performs is the shape
                an incident review cannot use.

        Raises:
            UpdateRefusedError: On any of the above, or any refusal
                :meth:`apply` would raise for ``previous``.
        """
        verdict.require_applicable()
        if verdict.manifest_id != previous.manifest_id:
            raise UpdateRefusedError(
                (UpdateRefusal.NOT_VERIFIED,), manifest_id=previous.manifest_id
            )
        if not previous.is_downgrade_from(installed_version):
            raise UpdateRefusedError(
                (UpdateRefusal.DOWNGRADE_NOT_SUPPORTED,), manifest_id=previous.manifest_id
            )
        if not approved_by.strip():
            raise UpdateRefusedError(
                (UpdateRefusal.DOWNGRADE_NOT_APPROVED,), manifest_id=previous.manifest_id
            )
        payload = self._fetch_checked(previous, verdict)
        detail = self._apply_hook(previous, payload)
        return ApplyOutcome(
            manifest_id=previous.manifest_id,
            component=previous.component,
            from_version=installed_version,
            to_version=previous.component_version,
            artifact_digest=previous.artifact_digest,
            applied=True,
            detail=(
                f"{detail}; rollback performed by {operator or '(unnamed)'} and approved "
                f"by {approved_by}; authorized by a {verdict.algorithm} signature over "
                f"the earlier release's manifest digest {verdict.manifest_digest[:12]}…"
            ),
            verified_under=verdict.algorithm,
        )

    def _fetch_checked(self, manifest: UpdateManifest, verdict: ManifestVerdict) -> bytes:
        """The bytes for ``manifest``, proven to be the bytes it committed to.

        The one place the signed digest is compared to reality, shared by
        :meth:`apply` and :meth:`rollback` so neither can grow a path that skips
        it.
        """
        verdict.require_applicable()
        if verdict.manifest_id != manifest.manifest_id:
            raise UpdateRefusedError(
                (UpdateRefusal.NOT_VERIFIED,), manifest_id=manifest.manifest_id
            )
        try:
            payload = self._artifacts.fetch(manifest.artifact_digest)
        except ArtifactUnavailableError:
            raise
        except Exception as exc:
            raise ArtifactUnavailableError(manifest.artifact_digest, str(exc)) from exc
        if _sha256_hex(payload) != manifest.artifact_digest:
            raise UpdateRefusedError(
                (UpdateRefusal.ARTIFACT_DIGEST_MISMATCH,), manifest_id=manifest.manifest_id
            )
        return payload

    def unavailable(self, reason: str) -> ArtifactUnavailableError:
        """The error an :class:`ArtifactPort` should raise when it cannot fetch.

        Provided so a deployment's port raises the same typed failure the applier
        recognizes, rather than an arbitrary exception the applier has to
        pattern-match on ``str(exc)``.
        """
        return ArtifactUnavailableError("<unknown>", reason)


__all__ = [
    "ALGORITHM_HMAC_SHA256",
    "ALGORITHM_X509",
    "UPDATE_PORT_UNAVAILABLE",
    "UPDATE_REFUSAL_ORDER",
    "UPDATE_UNVERIFIED",
    "ApplyOutcome",
    "ArtifactPort",
    "ArtifactUnavailableError",
    "HmacUpdateManifestSigner",
    "ManifestVerdict",
    "UpdateApplier",
    "UpdateChannel",
    "UpdateComponent",
    "UpdateManifest",
    "UpdateRefusal",
    "UpdateRefusedError",
    "UpdateSignaturePort",
    "UpdateSignerKeyPort",
    "UpdateVerifier",
    "X509UpdateSignatureVerifier",
    "order_update_refusals",
    "version_is_newer",
]
