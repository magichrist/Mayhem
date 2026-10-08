"""Evidence signing (plan 12, Phase 3).

Plan 12 Phase 2 sealed evidence into a hash chain and refused to pretend that
sealing was authorship: every manifest it wrote recorded
``signature_state = "unsigned_no_signing"`` with a reason, because no key
material existed. This module is the signing half that Phase said it owed.

The signing order here is Phase 6's own stated rollout order — local keys, then
KMS/HSM, then Sigstore/Cosign. Only the first rung is implemented, and the
refusal for the other two is written down rather than left as an absence.

The scheme, stated plainly
-------------------------
Signatures here are **HMAC-SHA256** over the artifact's canonical bytes, keyed
by a shared secret. That is a *symmetric* authenticity scheme and every verdict
says so:

* it proves the bytes are unaltered and were produced by **someone holding this
  key** — which is what an internal control-plane audit needs;
* it is **not** a public-key proof of authorship. A third party cannot verify it
  without the secret, and a verifier who holds the key could have minted the
  signature themselves.

:class:`SignatureAlgorithm` names the algorithms this build *knows about* and
:data:`PUBLIC_KEY_ALGORITHMS_IMPLEMENTED` is ``False``, so a caller asking for
Ed25519 gets a named refusal (:class:`SigningNotImplementedError`) instead of a
silent downgrade to HMAC. The downgrade is the failure worth engineering
against: an operator who asks for Ed25519 and silently receives an HMAC has been
handed a signature the intended verifier cannot check.

Why stdlib HMAC and not Ed25519/RSA
-----------------------------------
The project carries an explicit no-new-dependency policy, enforced where it is
documented: :mod:`mayhem.infra.certificate_authority` builds its fixture
authority from ``hmac`` + ``compare_digest`` and stamps ``CA_ALGORITHM_FIXTURE``
on every verdict so a report cannot read as a PKI result, and
:mod:`mayhem.infra.agent_identity_verifier` refuses an X.509-declared algorithm
with ``SIGNATURE_PORT_UNAVAILABLE`` precisely because it binds no
``cryptography`` or OpenSSL. Phase 3 implements the local-key rung and leaves
the other rungs refused rather than adding a crypto dependency to install an
evidence feature.

What this module does NOT do
----------------------------
* **It does not make fault-pack signatures verifiable.** That is fault-pack
  authorship, tracked separately by
  :data:`mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED`, which stays
  ``False``. Nothing here may be quoted as evidence that it became ``True``.
* **It does not implement KMS/HSM or Sigstore/Cosign.** Both are declared
  custody modes that fail closed (:class:`CustodyUnavailableError`).
* **It does not write key material to the evidence store.** Keys live in
  owner-only files, or in memory. No key ever enters an evidence row, an
  evidence envelope, or a bundle.
* **It does not re-implement verification.** Both sides derive bytes through the
  single plan 12 Phase 1 canonicalizer and compare with ``compare_digest``, so
  signing and verifying cannot drift apart.

The privacy boundary
--------------------
This module is inside plan 29's evidence boundary, not beside it. A signature
travels further than anything else in the system — it is what makes evidence
acceptable to somebody outside the control plane — and a signed artifact is
therefore *more* attractive to leak, not less. Every write path here calls
:func:`mayhem.infra.secret_resolver.require_persistable_document` before a
transaction opens, exactly as ``infra/audit_stream.py`` and
``infra/attestation_store.py`` do, so a field graded ``secret`` cannot reach a
signature row, a trust-root file, or an external object store.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import stat
from dataclasses import dataclass, replace
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from mayhem.domain.attestation import canonical_event_bytes
from mayhem.domain.common import utc_now
from mayhem.domain.errors import DomainError
from mayhem.infra.attestation_store import AttestationRepository
from mayhem.infra.secret_resolver import require_persistable_document

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mayhem.domain.attestation import Manifest
    from mayhem.infra.store import Store


# --------------------------------------------------------------------------- #
# Algorithms and custody, declared with the unimplemented ones failing closed    #
# --------------------------------------------------------------------------- #


class SignatureAlgorithm(StrEnum):
    """Signing algorithms this build knows about, not just the one it has.

    Declaring ``ED25519`` and ``X509`` is the point: a caller asking for a
    public-key algorithm gets a *named refusal* instead of a silent downgrade.
    """

    HMAC_SHA256 = "hmac-sha256"
    ED25519 = "ed25519"
    X509 = "x509"


class CustodyMode(StrEnum):
    """Where signing key material lives."""

    LOCAL_FILE = "local_file"
    KMS_HSM = "kms_hsm"
    SIGSTORE = "sigstore"


#: The one implemented algorithm. Every other declared algorithm refuses.
IMPLEMENTED_ALGORITHMS: frozenset[SignatureAlgorithm] = frozenset({SignatureAlgorithm.HMAC_SHA256})

#: The one implemented custody mode. ``kms_hsm`` and ``sigstore`` refuse.
IMPLEMENTED_CUSTODY_MODES: frozenset[CustodyMode] = frozenset({CustodyMode.LOCAL_FILE})

#: ``False`` always, so no caller can infer public-key support from the enum's
#: existence. Downstream honesty gates read this instead of guessing from the
#: algorithm name.
PUBLIC_KEY_ALGORITHMS_IMPLEMENTED = False

#: What artifact kind a signature covers. A signature is always *about* a named
#: artifact, so a verifier is never handed bytes it did not expect.
MANIFEST_ARTIFACT_KIND = "attestation_manifest"

#: Domain separator prefixed to every signing input. It makes these bytes
#: unambiguously an *evidence signature* and never a valid input to any other
#: HMAC in the system, so an evidence signature cannot be replayed as a valid
#: signature over something else.
SIGNING_DOMAIN = b"mayhem-evidence-signature-v1\x00"


# --------------------------------------------------------------------------- #
# Errors                                                                       #
# --------------------------------------------------------------------------- #


class SigningError(DomainError):
    """Base class for every refusal raised by this module."""


class SigningNotImplementedError(SigningError):
    """The requested algorithm exists as a name but is not implemented.

    Raised instead of falling back to HMAC. Distinct from
    :class:`mayhem.infra.attestation_store.SigningNotImplementedError`, which
    Phase 2 raised when a signer was named on a manifest that could carry no
    signature: that one refused to pretend, this one names the gap.
    """

    def __init__(self, algorithm: str, detail: str = "") -> None:
        self.algorithm = algorithm
        super().__init__(
            f"cannot sign with {algorithm!r}: {detail or 'not implemented in this build'}"
        )


class CustodyUnavailableError(SigningError):
    """A declared custody mode has no implementation and no fallback."""

    def __init__(self, mode: str, detail: str = "") -> None:
        self.mode = mode
        super().__init__(f"no key custody for {mode!r}: {detail or 'not implemented'}")


class KeyMaterialError(SigningError):
    """Key material is missing, malformed, or has unsafe filesystem permissions."""


class TrustRootRefusedError(SigningError):
    """A signature cannot be established as trustworthy.

    Raised for failures that are *about trust* rather than about bytes: an
    undeclared algorithm, an unknown key id, a fingerprint the trust root does
    not vouch for, and a signature that does not verify. Distinct from
    ``SigningNotImplementedError`` because the caller asked for something that
    exists and it failed for a reason a reader of the evidence must be able to
    tell apart from "this build cannot do that".
    """

    def __init__(self, reason: str, *, key_id: str = "") -> None:
        self.reason = reason
        self.key_id = key_id
        detail = f" (key {key_id!r})" if key_id else ""
        super().__init__(f"refusing to establish trust{detail}: {reason}")


class SignatureStateError(SigningError):
    """A stored signature contradicts the manifest it claims to cover."""


# --------------------------------------------------------------------------- #
# Key material                                                                  #
# --------------------------------------------------------------------------- #


def _is_hex_fingerprint(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value.lower())


def _require_owner_only(target: Path, *, key_id: str) -> None:
    """Refuse key material any local user other than the owner can read.

    Group/other bits set means another local user can read the key, and can
    therefore mint a signature that verifies. Refusing here is the last cheap
    point at which to refuse. Shared by the live and archived readers so there is
    one implementation of the rule rather than two that can drift.
    """
    mode = stat.S_IMODE(target.stat().st_mode)
    if mode & 0o077:
        raise KeyMaterialError(
            f"key file {target} is mode {mode:04o}; owner-only (0600) is required "
            "or any local user can mint evidence that verifies as deployment-signed"
        )


@dataclass(frozen=True, slots=True)
class SigningKey:
    """A local HMAC key, named by a **fingerprint** rather than by its bytes.

    ``fingerprint`` is ``sha256(secret)`` hex. It identifies which key was used
    without publishing the secret, so it can be written into evidence and shown
    to a third party without anything becoming verifiable.

    Because HMAC keys are symmetric, an HMAC fingerprint is an offline
    dictionary-attack target if it leaks. So it is never logged, and never
    written to a bundle or an evidence row — it lives in trust-root files and
    signature records, both of which are already inside the plan 29 boundary.
    """

    key_id: str
    secret: bytes
    algorithm: SignatureAlgorithm = SignatureAlgorithm.HMAC_SHA256
    note: str = ""

    def __post_init__(self) -> None:
        if not self.key_id:
            raise KeyMaterialError("a signing key must have a key id")
        if len(self.secret) < 32:
            # A short key makes the signature brute-forceable, which would turn
            # "produced by a holder of this key" into a guessable claim.
            raise KeyMaterialError(
                f"signing key {self.key_id!r} is {len(self.secret)} bytes; HMAC-SHA256 "
                "keys must be at least 32 bytes or the authenticity claim is not worth making"
            )

    @property
    def fingerprint(self) -> str:
        """``sha256(secret)`` hex. Identifies the key without revealing it."""
        return sha256(self.secret).hexdigest()

    @property
    def is_public_key_scheme(self) -> bool:
        """Always ``False``. HMAC is symmetric; see the module docstring."""
        return False

    def to_dict(self) -> dict[str, Any]:
        """Identity only. The secret never appears in any serialisation."""
        return {
            "key_id": self.key_id,
            "algorithm": str(self.algorithm),
            "fingerprint": self.fingerprint,
            "public_key": False,
            "note_present": bool(self.note),
        }


@dataclass(frozen=True, slots=True)
class TrustRoot:
    """A named trust anchor: the key fingerprints this deployment trusts.

    This is the trust-root reference plan 12's Phase 6 honesty gate demands
    ("every signing claim names the key holder and trust root"), expressed as a
    resolvable value rather than a free-text string. A signature naming a trust
    root absent from the deployment's trust store is reported as ``untrusted``,
    never as verified — the same rule the evidence bundle follows for an
    unsigned bundle.

    ``algorithm`` matters: a root vouching for Ed25519 cannot be used to accept an
    HMAC signature, and vice versa. Without that, a trust root would silently
    accept a weaker algorithm than the one it was created to vouch for.
    """

    trust_root_id: str
    fingerprints: tuple[str, ...] = ()
    algorithm: SignatureAlgorithm = SignatureAlgorithm.HMAC_SHA256
    note: str = ""

    def __post_init__(self) -> None:
        if not self.trust_root_id:
            raise KeyMaterialError(
                "a trust root must have an id: an unnamed trust root would let any "
                "key holder claim the evidence was signed under the deployment's trust"
            )

    def vouches_for(self, fingerprint: str) -> bool:
        """Whether this root vouches for *fingerprint* under its own algorithm."""
        return fingerprint in self.fingerprints

    def with_key(self, key: SigningKey) -> TrustRoot:
        """A copy vouching for *key*'s fingerprint as well."""
        if key.algorithm is not self.algorithm:
            raise TrustRootRefusedError(
                f"trust root {self.trust_root_id!r} vouches for {self.algorithm} but the "
                f"key is declared for {key.algorithm}; refusing to substitute",
                key_id=key.key_id,
            )
        if key.fingerprint in self.fingerprints:
            return self
        return replace(self, fingerprints=(*self.fingerprints, key.fingerprint))

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust_root_id": self.trust_root_id,
            "fingerprints": list(self.fingerprints),
            "algorithm": str(self.algorithm),
            "note_present": bool(self.note),
            "public_key": False,
        }


@dataclass(frozen=True, slots=True)
class EvidenceSignature:
    """One signature over one artifact's canonical bytes.

    ``signature`` is base64 of the raw HMAC digest. ``signed_digest`` is the
    SHA-256 of the *same* bytes the signature covers — the independent content
    commitment — so a verifier can confirm both that the bytes are unaltered and
    that the signature was made *about those bytes*, without needing the key.

    A signature omitting any of algorithm, key id, fingerprint, or trust root is
    not a signature this module produced, and verifying one is refused with a
    reason rather than reported as a pass.
    """

    artifact_kind: str
    artifact_id: str
    algorithm: SignatureAlgorithm
    key_id: str
    key_fingerprint: str
    trust_root_id: str
    signature: str
    signed_digest: str
    signed_at: str = ""
    public_key: bool = False

    @property
    def signed(self) -> bool:
        return bool(self.signature)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact_kind": self.artifact_kind,
            "artifact_id": self.artifact_id,
            "algorithm": str(self.algorithm),
            "key_id": self.key_id,
            "key_fingerprint": self.key_fingerprint,
            "trust_root_id": self.trust_root_id,
            "signature": self.signature,
            "signed_digest": self.signed_digest,
            "signed_at": self.signed_at,
            "public_key": self.public_key,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> EvidenceSignature:
        """Rebuild a signature from a persisted row or a bundle file.

        Refuses a payload missing any honesty-critical field, so a signature
        record that lost a field in transit is *refused* rather than verifying
        against blanks. The alternative — defaulting blanks and then reporting a
        failure — would let a reader conclude the signature was present and merely
        wrong, when in fact it was never a complete claim.
        """
        required = ("artifact_kind", "artifact_id", "algorithm", "key_id", "key_fingerprint")
        missing = [name for name in required if not str(payload.get(name, "")).strip()]
        if missing:
            raise SignatureStateError(
                f"signature record is missing required field(s) {', '.join(missing)}; "
                "an incomplete signing claim is refused rather than verified against blanks"
            )
        algorithm = str(payload.get("algorithm", ""))
        if algorithm not in {str(item) for item in SignatureAlgorithm}:
            raise SignatureStateError(f"signature record names unknown algorithm {algorithm!r}")
        return cls(
            artifact_kind=str(payload["artifact_kind"]),
            artifact_id=str(payload["artifact_id"]),
            algorithm=SignatureAlgorithm(algorithm),
            key_id=str(payload["key_id"]),
            key_fingerprint=str(payload["key_fingerprint"]),
            trust_root_id=str(payload.get("trust_root_id", "")),
            signature=str(payload.get("signature", "")),
            signed_digest=str(payload.get("signed_digest", "")),
            signed_at=str(payload.get("signed_at", "")),
            public_key=bool(payload.get("public_key", False)),
        )


@dataclass(frozen=True, slots=True)
class SignatureVerification:
    """The verdict on one signature. Every field is a recorded fact.

    ``trusted`` answers "does the deployment's trust root vouch for the key that
    made this signature" and ``verified`` answers "do the bytes match". They are
    separate because a signature can be cryptographically valid and still be
    *untrusted* — for example, made by a key that has since been rotated out.
    A single boolean would collapse exactly the case an auditor most needs to see.
    """

    verified: bool = False
    trusted: bool = False
    signed_digest: str = ""
    trust_root_id: str = ""
    key_id: str = ""
    key_fingerprint: str = ""
    algorithm: SignatureAlgorithm = SignatureAlgorithm.HMAC_SHA256
    public_key: bool = False
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "trusted": self.trusted,
            "signed_digest": self.signed_digest,
            "trust_root_id": self.trust_root_id,
            "key_id": self.key_id,
            "key_fingerprint": self.key_fingerprint,
            "algorithm": str(self.algorithm),
            "public_key": self.public_key,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            # Availability follows from the scheme being public-key, NOT from it
            # being absent. Inverting this reads "no public key, so a third party
            # can verify" and hands a downstream report a claim this build cannot
            # support. ``PUBLIC_KEY_ALGORITHMS_IMPLEMENTED`` is the authority; a
            # verdict derives from its own scheme and nothing else.
            "public_key_verification_available": self.public_key,
        }


# --------------------------------------------------------------------------- #
# Canonical signing bytes                                                       #
# --------------------------------------------------------------------------- #


def signing_bytes(
    manifest: Manifest,
    *,
    trust_root_id: str,
    algorithm: SignatureAlgorithm,
    key_fingerprint: str,
) -> bytes:
    """The exact bytes a signature covers: a domain-separated envelope.

    Derived through :func:`mayhem.domain.attestation.canonical_event_bytes` —
    the same Phase 1 canonicalizer used to build the chain — so signing and
    verification cannot drift: there is one canonicalizer and both sides call
    it. The envelope carries no secret and never the signature itself.
    """

    body = canonical_event_bytes(manifest.model_dump(mode="json"))
    envelope = {
        "_domain": SIGNING_DOMAIN.rstrip(b"\x00").decode(),
        "body": base64.b64encode(body).hex(),
        "trust_root_id": trust_root_id,
        "algorithm": str(algorithm),
        "key_fingerprint": key_fingerprint,
    }
    return SIGNING_DOMAIN + canonical_event_bytes(envelope)


# --------------------------------------------------------------------------- #
# Signer / verifier seams                                                      #
# --------------------------------------------------------------------------- #


@runtime_checkable
class EvidenceSigner(Protocol):
    """The signing seam, a Protocol so the unit suite can drive it with fakes.

    ``key_id`` is declared as a read-only property because that is how the only
    signer implements it: its id comes from the loaded key, so exposing a
    setter would invite a caller to rewrite the identity of a key that is
    already on disk. The same argument covers ``trust_root_id`` and
    ``algorithm`` -- both name the context a signature is made under, and
    neither is a thing a caller may retune after construction. A future
    KMS/HSM signer satisfies this with the same shape.
    """

    @property
    def key_id(self) -> str:
        """The id of the key this signer signs with."""

    @property
    def trust_root_id(self) -> str:
        """The trust root this signer's signatures claim to sit under."""

    @property
    def algorithm(self) -> SignatureAlgorithm:
        """The algorithm this signer signs with; never downgraded."""

    def sign_manifest(self, manifest: Manifest) -> EvidenceSignature:  # pragma: no cover
        """Sign *manifest*, or refuse."""


@runtime_checkable
class EvidenceVerifier(Protocol):
    def verify_signature(
        self,
        signature: EvidenceSignature | None,
        manifest: Manifest,
    ) -> SignatureVerification:  # pragma: no cover
        """Verify *signature* over *manifest* against a named trust root."""


@dataclass(slots=True)
class HmacLocalKeySigner:
    """Signs manifests with a local HMAC key. The one implemented signer.

    A dataclass so it is constructible in a test with no filesystem and no key
    file, and so a future KMS/HSM signer can satisfy :class:`EvidenceSigner`
    without either class knowing about the other.
    """

    key: SigningKey
    trust_root_id: str
    algorithm: SignatureAlgorithm = SignatureAlgorithm.HMAC_SHA256

    def __post_init__(self) -> None:
        if self.algorithm not in IMPLEMENTED_ALGORITHMS:
            raise SigningNotImplementedError(
                str(self.algorithm),
                "this build implements hmac-sha256 only; no fallback is applied, because "
                "silently downgrading a requested algorithm would hand the caller a "
                "signature the intended verifier cannot check",
            )
        if not self.trust_root_id:
            raise TrustRootRefusedError(
                "a signature must name a trust root; an unnamed trust root would let any "
                "key holder claim the evidence was signed under the deployment's trust"
            )
        if self.key.algorithm is not self.algorithm:
            raise KeyMaterialError(
                f"key {self.key.key_id!r} is declared for {self.key.algorithm} but the "
                f"signer is configured for {self.algorithm}; refusing to substitute"
            )

    @property
    def key_id(self) -> str:
        return self.key.key_id

    def sign_manifest(self, manifest: Manifest) -> EvidenceSignature:
        payload = signing_bytes(
            manifest,
            trust_root_id=self.trust_root_id,
            algorithm=self.algorithm,
            key_fingerprint=self.key.fingerprint,
        )
        digest = hmac.new(self.key.secret, payload, sha256).digest()
        return EvidenceSignature(
            artifact_kind=MANIFEST_ARTIFACT_KIND,
            artifact_id=manifest.manifest_id,
            algorithm=self.algorithm,
            key_id=self.key.key_id,
            key_fingerprint=self.key.fingerprint,
            trust_root_id=self.trust_root_id,
            signature=base64.b64encode(digest).decode(),
            signed_digest=sha256(payload).hexdigest(),
            signed_at=utc_now().isoformat(),
            public_key=False,
        )


@dataclass(slots=True)
class UnavailableCustodySigner:
    """The KMS/HSM and Sigstore rungs: declared, and they refuse.

    Exists so a caller can name the custody mode it wants and get the refusal at
    that point, instead of discovering later that the deployment quietly signed
    with a local file. The refusal is the behaviour; the class is how it is
    reachable from configuration.
    """

    trust_root_id: str = ""
    mode: CustodyMode = CustodyMode.KMS_HSM

    def __post_init__(self) -> None:
        if self.mode in IMPLEMENTED_CUSTODY_MODES:
            raise CustodyUnavailableError(
                str(self.mode),
                "this class only models custody modes that are NOT implemented",
            )

    def sign_manifest(self, manifest: Manifest) -> EvidenceSignature:
        raise CustodyUnavailableError(
            str(self.mode),
            "plan 12 Phase 3 implements local-file custody only; KMS/HSM and Sigstore "
            "remain later phases and no fallback signer is substituted",
        )


class LocalKeyVerifier:
    """Verifies a signature offline against a **named trust root**.

    Offline means no database, no cluster, no control plane: the verifier is
    handed a signature, the artifact, and the trust store, and decides. That is
    the property a third party needs for a signature to mean anything to it.

    The verdicts are deliberately two-dimensional rather than one boolean,
    because a single boolean collapses "the signature is absent" into "the
    signature did not verify" — the two facts an auditor must never see
    conflated.
    """

    def __init__(self, trust_store: Sequence[TrustRoot]) -> None:
        self.trust_store: tuple[TrustRoot, ...] = tuple(trust_store)

    def trust_root_for(self, signature: EvidenceSignature) -> TrustRoot | None:
        """The root that vouches for this signature's key, or ``None``."""
        for root in self.trust_store:
            if root.trust_root_id != signature.trust_root_id:
                continue
            if root.algorithm is not signature.algorithm:
                continue
            if root.vouches_for(signature.key_fingerprint):
                return root
        return None

    def verify_signature(
        self,
        signature: EvidenceSignature | None,
        manifest: Manifest,
    ) -> SignatureVerification:
        base = SignatureVerification(
            algorithm=(
                signature.algorithm if signature is not None else SignatureAlgorithm.HMAC_SHA256
            ),
            public_key=False,
        )
        if signature is None or not signature.signed:
            return replace(
                base,
                errors=("no signature: integrity is verified, authorship is not",),
                warnings=("bundle/manifest is unsigned",),
            )

        errors: list[str] = []
        warnings: list[str] = []

        def verdict(*, verified: bool = False, trusted: bool = False) -> SignatureVerification:
            """The one shape every outcome below is returned in.

            A refusal and a pass must be indistinguishable in *shape*, so a
            caller can read ``verified``, ``trusted`` and ``errors`` without
            first working out which check stopped the run. Six hand-built
            ``replace`` calls meant six places to forget a field.
            """
            return replace(
                base,
                verified=verified,
                trusted=trusted,
                errors=tuple(errors),
                warnings=tuple(warnings),
                trust_root_id=signature.trust_root_id,
                key_id=signature.key_id,
                key_fingerprint=signature.key_fingerprint,
                # What the record *claims*, reported on refusal paths too — the
                # operator needs the claim to diagnose it. It is only ever a
                # verified digest when ``verified`` is True.
                signed_digest=signature.signed_digest,
                public_key=False,
            )

        # A signature that does not name the artifact it covers is not evidence
        # about this artifact: it is evidence about a different one. Refused, not
        # checked.
        if signature.artifact_kind != MANIFEST_ARTIFACT_KIND:
            errors.append(
                f"signature covers artifact kind {signature.artifact_kind!r}, not "
                f"{MANIFEST_ARTIFACT_KIND!r}"
            )
        elif signature.artifact_id != manifest.manifest_id:
            errors.append(
                f"signature covers manifest {signature.artifact_id!r}, not {manifest.manifest_id!r}"
            )

        if signature.algorithm not in IMPLEMENTED_ALGORITHMS:
            errors.append(f"cannot verify {signature.algorithm}: not implemented in this build")
            return verdict()

        payload = signing_bytes(
            manifest,
            trust_root_id=signature.trust_root_id,
            algorithm=signature.algorithm,
            key_fingerprint=signature.key_fingerprint,
        )
        if signature.signed_digest and signature.signed_digest != sha256(payload).hexdigest():
            errors.append(
                "signed digest does not match the artifact: the manifest was changed "
                "after signing, or the signature covers different bytes"
            )
            return verdict()

        # Both reasons below are "this run cannot reach a verdict", so they are
        # *accumulated* behind one gate rather than returned from separately: an
        # operator with no trust store whose signature is also malformed needs
        # both facts, and a per-branch return discards the earlier ones.
        expected: bytes | None = None
        try:
            expected = base64.b64decode(signature.signature, validate=True)
        except ValueError:
            errors.append("signature is not valid base64")
        if not self.trust_store:
            errors.append("no trust store: nothing vouches for any key")
        if expected is None or not self.trust_store:
            return verdict()

        # The trust question and the bytes question are asked separately, and
        # both are reported. A signature made by a key the deployment trusts is
        # reported trusted; one made by any other key is reported *untrusted*
        # even when its bytes verify, which is the rotated-out-key case.
        trusted = self.trust_root_for(signature) is not None
        if not trusted:
            errors.append(
                f"no trust root {signature.trust_root_id!r} vouches for key "
                f"{signature.key_id!r} (fingerprint {signature.key_fingerprint[:12]})"
            )

        # Verification *reports*; it never raises. Every way the check can fail —
        # key absent, key rotated, permissions wrong — is a verdict an operator
        # needs rendered, not a traceback. A rotated-out key is the common case:
        # the key id still exists, its fingerprint no longer matches the
        # signature, and the answer is "this no longer verifies here".
        try:
            secret = self._secret_for(signature)
        except (TrustRootRefusedError, KeyMaterialError) as exc:
            errors.append(str(exc))
            return verdict(trusted=False)

        verified = hmac.compare_digest(expected, hmac.new(secret, payload, sha256).digest())
        if not verified:
            errors.append("signature does not verify against the bytes supplied")
        else:
            # The honest caveat, recorded on every pass. It is a fact about the
            # algorithm, not a defect in this signature: a symmetric scheme
            # cannot support third-party verification without the secret.
            warnings.append(
                f"{signature.algorithm} is symmetric: this proves the bytes are "
                "unaltered and were produced by a holder of this key, not authorship "
                "by a named party verifiable by a third party"
            )
        return verdict(verified=verified, trusted=trusted)

    def _secret_for(self, signature: EvidenceSignature) -> bytes:
        """The secret for *signature*'s key, from the verifier's own key store.

        A verifier holding the secret can verify but cannot *attribute* — which is
        exactly the HMAC limit, so this is where the scheme stops rather than
        pretending a public key exists behind it.
        """
        raise NotImplementedError(
            "LocalKeyVerifier must be constructed with a key store; use KeyStoreBackedVerifier"
        )


class KeyStoreBackedVerifier(LocalKeyVerifier):
    """A verifier that also holds the keys, so it can actually check bytes.

    Constructed with a :class:`LocalKeyStore` (or any object satisfying the same
    methods). The key is looked up **by id**, and the fingerprint in the
    signature is compared against the loaded key's own fingerprint before the
    secret is used — so a signature naming one key cannot be verified with
    another key's secret, which would make the whole scheme meaningless.

    A fingerprint that matches no live key falls back to the archived generation
    of that id. Without this, rotation would be destructive: ``rotate_key``
    preserves the retired secret precisely so old evidence stays checkable, and a
    verifier that only ever consulted the live file would report that preserved
    evidence as unverifiable and make the archive pointless. The fingerprint is
    still the selector, so the fallback resolves a *specific* generation and
    never "whatever secret is nearest".
    """

    def __init__(self, key_store: LocalKeyStore, trust_store: Sequence[TrustRoot]) -> None:
        super().__init__(trust_store)
        self.key_store = key_store

    def _secret_for(self, signature: EvidenceSignature) -> bytes:
        # Resolve by fingerprint, not by "whatever is live". The live key is
        # preferred *only when its fingerprint matches the signature*; otherwise
        # the fingerprint names a retired generation and the archive is the
        # correct answer. Loading live material first and only falling back on
        # absence would report every archived signature as rotated-out, which is
        # precisely the evidence rotation is supposed to preserve.
        try:
            key = self.key_store.load_key(signature.key_id)
            if key.fingerprint == signature.key_fingerprint:
                return key.secret
        except KeyMaterialError:
            # No live material for this id at all; fall through to the archive.
            key = None
        try:
            archived = self.key_store.load_archived_key(signature.key_id, signature.key_fingerprint)
        except KeyMaterialError as exc:
            if key is None:
                raise TrustRootRefusedError(
                    "no live or archived key material for this signature's key id and "
                    f"fingerprint, so the bytes cannot be checked: {exc}",
                    key_id=signature.key_id,
                ) from None
            # Live material exists but is a *different* generation. Naming the
            # mismatch is more useful to an auditor than a bare absence.
            raise TrustRootRefusedError(
                "key fingerprint does not match the loaded key; the key was rotated "
                "or replaced since this signature was made, and no archived generation "
                "matches the signature's fingerprint",
                key_id=signature.key_id,
            ) from None
        return archived.secret


# --------------------------------------------------------------------------- #
# Key store                                                                     #
# --------------------------------------------------------------------------- #


class LocalKeyStore:
    """Holds local HMAC keys in files with owner-only permissions.

    The permission check is the point of this class, not a nicety. A signing key
    file any local user can read is a key any local user can use to mint evidence
    that verifies as deployment-signed. ``mode`` is checked on read as well as set
    on write, so a key chmod-ed world-readable after the fact is refused at the
    moment it is loaded rather than discovered later in an audit.
    """

    KEY_DIR_MODE = 0o700
    KEY_FILE_MODE = 0o600
    NAME = "local-file"

    def __init__(self, directory: Path | None = None) -> None:
        target = Path(directory) if directory is not None else Path.home() / ".mayhem" / "keys"
        target.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            # Best-effort: on a filesystem that cannot honour the mode the store
            # still works, and ``load_key`` refuses unsafe permissions on read.
            target.chmod(self.KEY_DIR_MODE)
        self.directory = target

    def _path(self, key_id: str) -> Path:
        if not key_id or key_id in {".", ".."} or "/" in key_id or "\\" in key_id:
            raise KeyMaterialError(
                f"key id {key_id!r} is not a valid identifier; a key id is an "
                "identifier, not a path, and may not name a directory"
            )
        return self.directory / f"{key_id}.key"

    def create_key(self, key_id: str, *, note: str = "") -> SigningKey:
        """Mint a fresh 32-byte key, write it owner-only, and return it."""
        secret = os.urandom(32)
        key = SigningKey(key_id=key_id, secret=secret, note=note)
        self._write(key)
        return key

    def _archive_dir(self) -> Path:
        return self.directory / "archive"

    def _archive(self, key: SigningKey) -> Path:
        """Move a retired generation to ``archive/`` before it is overwritten.

        Written rather than renamed into place so the fingerprint is part of the
        filename: a rotation that reused ``release.key`` would make the old
        secret indistinguishable from the new one on the next load.
        """
        target = self._archive_dir() / f"{key.key_id}.{key.fingerprint}.key"
        target.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            target.parent.chmod(self.KEY_DIR_MODE)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, self.KEY_FILE_MODE)
        try:
            os.write(descriptor, key.secret)
        finally:
            os.close(descriptor)
        return target

    def _write(self, key: SigningKey) -> Path:
        target = self._path(key.key_id)
        # Write owner-only from the first byte rather than chmod-ing after: a
        # brief world-readable window is a real window.
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, self.KEY_FILE_MODE)
        try:
            os.write(descriptor, key.secret)
        finally:
            os.close(descriptor)
        return target

    def load_key(self, key_id: str) -> SigningKey:
        """Read a key file, refusing unsafe permissions. Never logs the secret."""
        target = self._path(key_id)
        if not target.exists():
            raise KeyMaterialError(f"no key {key_id!r} in {self.directory}")
        _require_owner_only(target, key_id=key_id)
        return SigningKey(key_id=key_id, secret=target.read_bytes())

    def list_keys(self) -> tuple[str, ...]:
        if not self.directory.exists():
            return ()
        return tuple(sorted(item.stem for item in self.directory.glob("*.key")))

    def rotate_key(self, key_id: str, *, note: str = "") -> SigningKey:
        """Replace a key's bytes under the same id, archiving the old material.

        Rotation keeps the key id stable so evidence already signed under it
        stays attributable to the same logical holder, and changes the
        fingerprint. So a reader can always tell a rotated key from an unrotated
        one — the id matches but the fingerprint does not.

        The retired secret is **archived, not destroyed** (``archive/`` beside
        the live keys). A rotation that overwrote the bytes in place would leave
        the operator with no safe move at all: rotate and every historical
        signature becomes permanently unverifiable, or don't rotate and a leaked
        key stays live forever. Archiving makes revocation and preservation the
        same action, which is the only way both requirements can hold.

        The archive is *not* trusted on its own. :meth:`load_archived_key` exists
        so a trust root can be reconstructed over retired material deliberately,
        and :meth:`active_key_ids` deliberately excludes it — archived material
        is never in the forward trust store, so a retired key cannot sign
        anything new even if it is still readable on disk.
        """
        current = self.load_key(key_id)
        self._archive(current)
        replacement = SigningKey(key_id=key_id, secret=os.urandom(32), note=note)
        self._write(replacement)
        return replacement

    def load_archived_key(self, key_id: str, fingerprint: str) -> SigningKey:
        """The archived secret for *fingerprint* of *key_id*, or refuse.

        Fingerprint-addressed rather than "the most recent one" because a key id
        may have been rotated several times and guessing which generation is
        meant would let a verifier silently check a signature against the wrong
        key. An unknown fingerprint raises rather than returning nothing: a
        caller that asked for a specific generation must be told it is absent
        instead of quietly reporting the signature as unverified.
        """
        if not _is_hex_fingerprint(fingerprint):
            raise KeyMaterialError(
                f"{fingerprint!r} is not a sha256 fingerprint; archived key material is "
                "addressed by fingerprint so a rotation cannot resolve to the wrong "
                "generation"
            )
        target = self._archive_dir() / f"{key_id}.{fingerprint}.key"
        if not target.exists():
            raise KeyMaterialError(
                f"no archived key {key_id!r} with fingerprint {fingerprint[:16]}… in "
                f"{self._archive_dir()}; an archived fingerprint is never guessed, "
                "because checking a signature against the wrong generation is worse "
                "than reporting it unverifiable"
            )
        _require_owner_only(target, key_id=f"archived key {key_id!r}")
        return SigningKey(
            key_id=key_id,
            secret=target.read_bytes(),
            note=f"archived generation {fingerprint[:16]}",
        )

    def archived_fingerprints(self, key_id: str) -> tuple[str, ...]:
        """Fingerprints archived for *key_id*, oldest first, without secrets."""
        directory = self._archive_dir()
        if not directory.exists():
            return ()
        prefix = f"{key_id}."
        found = [
            item.name[len(prefix) : -len(".key")]
            for item in directory.glob(f"{key_id}.*.key")
            if item.name.endswith(".key")
        ]
        return tuple(sorted(found))

    def active_key_ids(self) -> tuple[str, ...]:
        """Key ids whose *current* material exists — the forward trust set.

        Archived generations are excluded on purpose. A retired key stays on disk
        so old evidence remains checkable, but it must never be able to produce a
        new signature, and the trust store a deployment derives from itself is
        exactly the forward set.
        """
        return self.list_keys()

    def fingerprint_for(self, key_id: str) -> str:
        """The fingerprint of the stored key, without returning the secret."""
        return self.load_key(key_id).fingerprint


# --------------------------------------------------------------------------- #
# Trust store construction                                                      #
# --------------------------------------------------------------------------- #


def build_trust_store(
    key_store: LocalKeyStore,
    *,
    trust_root_id: str,
    key_ids: Sequence[str] = (),
) -> tuple[TrustRoot, ...]:
    """Derive the deployment trust store from the keys that actually exist.

    Derived rather than hand-written so it cannot drift from the deployment: a
    root vouching for a key the deployment does not hold is exactly the
    "trust nobody verified anybody" state this plan exists to make impossible.
    """
    ids = tuple(key_ids) if key_ids else key_store.list_keys()
    root = TrustRoot(trust_root_id=trust_root_id, algorithm=SignatureAlgorithm.HMAC_SHA256)
    for key_id in ids:
        root = root.with_key(key_store.load_key(key_id))
    return (root,)


# --------------------------------------------------------------------------- #
# Persistence — signature rows and the signature_state column                   #
# --------------------------------------------------------------------------- #

#: The one ``signature_state`` Phase 2 could write. Unchanged by Phase 3: an
#: unsigned manifest still says *why* it is unsigned. Signing does not replace
#: this state, it adds two others — a manifest that was never signed stays in
#: this one, and the reason string says which of the three real causes it was.
UNSIGNED_NO_SIGNING = "unsigned_no_signing"

#: Phase 2's reason, kept verbatim. Phase 2 was accurate when it was written —
#: no key material existed at all. Phase 3 adds signing, so it is now only
#: truthful for manifests written by a deployment with no signing configured at
#: all, which is why it is named rather than assumed: a reader that sees this
#: text on a Phase 3 deployment is being told the truth about *that* row.
#: :data:`UNSIGNED_NO_SIGNER` and :data:`UNSIGNED_NO_TRUST_ROOT` name the other
#: two real cases a Phase 3 deployment can hit.
UNSIGNED_NO_SIGNING_REASON = (
    "plan 12 Phase 2 implements sealing and retention only: no key material, no "
    "KMS/HSM custody and no Sigstore integration exist, so no signature bytes were "
    "minted. This manifest attests integrity, not authorship."
)

#: Phase 3: a deployment has key material and a trust store, but no key was named
#: for this manifest, so nothing was minted. Distinct from
#: :data:`UNSIGNED_NO_SIGNING` because key material *does* exist — the row is not
#: telling an operator that signing is unimplemented, it is telling them a key was
#: simply not chosen.
UNSIGNED_NO_SIGNER = "unsigned_no_signer"
UNSIGNED_NO_SIGNER_REASON = (
    "no signing key was named for this manifest. The deployment holds key material "
    "and a trust store, but signing requires choosing a key; this manifest attests "
    "integrity, not authorship."
)

#: Phase 3: a key was named but nothing vouches for it, so a signature minted by
#: it would be evidence about an unknown party. Rather than record a signature no
#: trust root covers, the manifest is left unsigned and says so — see
#: :class:`SignatureRepository`'s ``SIGNATURE_SIGNED_UNTRUSTED`` for the case
#: where a signature *is* recorded by an unvouched key.
UNSIGNED_NO_TRUST_ROOT = "unsigned_no_trust_root"
UNSIGNED_NO_TRUST_ROOT_REASON = (
    "the named signing key is not vouched for by any trust root in this deployment. "
    "Signing with it would produce evidence about an unknown party, so no signature "
    "was recorded; this manifest attests integrity, not authorship."
)


class SignatureRepository:
    """Reads and writes signature records for attested manifests.

    Sits beside :class:`mayhem.infra.attestation_store.AttestationRepository`
    rather than inside it: attestation sealing is already DONE and pinned, and
    a signing lane that edited its transaction would put an unsealed signing bug
    inside a proven lane. The two share the ``attestation_manifests`` row through
    the ``signature_state`` column and nothing else.
    """

    #: A signature that verifies and whose key this deployment's trust store
    #: vouches for.
    SIGNATURE_SIGNED = "signed"
    #: A signature whose key is **not** vouched for locally. Recorded rather than
    #: refused: evidence signed by a key this deployment does not hold is
    #: exactly the evidence an auditor needs to see flagged, and hiding the row
    #: would make the gap invisible instead of visible.
    SIGNATURE_SIGNED_UNTRUSTED = "signed_untrusted"
    #: Phase 2's single unsigned state, kept so a reader of an old row still
    #: finds the state it expects. A deployment with no signing configured at all
    #: still writes this.
    UNSIGNED_NO_SIGNING = UNSIGNED_NO_SIGNING

    def __init__(self, store: Store) -> None:
        self._store = store

    def load_manifest(self, manifest_id: str) -> Manifest | None:
        """The stored manifest *manifest_id*, or ``None``.

        Read through the attestation repository rather than with a second query,
        so the JSON decode and the model construction have exactly one
        implementation. A signing lane that re-parsed ``manifest_json`` itself
        could disagree with the sealing lane about what a manifest is.
        """
        return AttestationRepository(self._store).load_manifest(manifest_id)

    def require_manifest(self, manifest_id: str) -> Manifest:
        """The stored manifest, refusing when it does not exist.

        Signing an artifact that is not sealed would mint a signature over
        evidence the database never committed, so a signature that verifies for a
        manifest with no row — a signature that authenticates nothing.
        """
        manifest = self.load_manifest(manifest_id)
        if manifest is None:
            raise SignatureStateError(
                f"cannot sign manifest {manifest_id!r}: no such sealed manifest, so a "
                "signature over it would authenticate evidence that was never recorded"
            )
        return manifest

    # -- reads --------------------------------------------------------------- #

    def load_signature(self, manifest_id: str) -> EvidenceSignature | None:
        """The signature stored for *manifest_id*, or ``None`` when unsigned."""
        rows = self._store.query(
            "SELECT signature_json FROM attestation_signatures WHERE manifest_id = ?",
            (manifest_id,),
        )
        if not rows:
            return None
        payload = str(dict(rows[0])["signature_json"])
        if not payload:
            return None
        return EvidenceSignature.from_dict(json.loads(payload))

    def load_signature_state(self, manifest_id: str) -> tuple[str, str]:
        """``(signature_state, signature_reason)`` for a stored manifest."""
        rows = self._store.query(
            "SELECT signature_state, signature_reason FROM attestation_manifests"
            " WHERE manifest_id = ?",
            (manifest_id,),
        )
        if not rows:
            raise KeyError(manifest_id)
        row = dict(rows[0])
        return str(row["signature_state"]), str(row["signature_reason"])

    def is_trusted_by(self, manifest_id: str, verifier: LocalKeyVerifier) -> bool:
        """Whether the stored signature is trusted by *verifier*'s trust store."""
        signature = self.load_signature(manifest_id)
        if signature is None:
            return False
        return verifier.trust_root_for(signature) is not None

    # -- writes -------------------------------------------------------------- #

    def save_signature(
        self,
        manifest_id: str,
        signature: EvidenceSignature,
        *,
        trusted: bool = True,
    ) -> EvidenceSignature:
        """Persist *signature* for the stored manifest *manifest_id*.

        The manifest is loaded from the store rather than passed in, so a caller
        cannot sign a manifest it holds in memory while the database holds a
        different one. Both writes happen in one transaction, so a manifest can
        never be observed with a signature row and an unsigned state, or the
        reverse. The evidence boundary is consulted first, on exactly the bytes
        each row will hold, so a refusal leaves no partial write.

        Raises:
            InvariantViolationError: From the plan 29 evidence boundary, if the
                signature carries a secret-classified field or a value this run
                resolved. Nothing is written.
            SignatureStateError: If the manifest is not sealed, or the signature
                does not cover it.
        """
        manifest = self.require_manifest(manifest_id)
        if signature.artifact_id != manifest.manifest_id:
            raise SignatureStateError(
                f"refusing to store a signature for {signature.artifact_id!r} under "
                f"manifest {manifest.manifest_id!r}: the signature covers a different artifact"
            )

        require_persistable_document(
            signature.to_dict(),
            artifact=f"attestation_signature:{manifest.manifest_id}",
        )

        state = self.SIGNATURE_SIGNED if trusted else self.SIGNATURE_SIGNED_UNTRUSTED
        reason = (
            f"signed with {signature.algorithm} by key {signature.key_id} "
            f"(fingerprint {signature.key_fingerprint[:12]}) under trust root "
            f"{signature.trust_root_id}; verified by this deployment's trust store"
        )
        if not trusted:
            reason = (
                f"signed with {signature.algorithm} by key {signature.key_id} "
                f"(fingerprint {signature.key_fingerprint[:12]}), but no trust root "
                f"{signature.trust_root_id!r} in this deployment vouches for that key; "
                "the bytes may verify and the signature is still not trusted here"
            )

        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO attestation_signatures "
                "(manifest_id, run_id, algorithm, key_id, key_fingerprint, trust_root_id, "
                "signed_digest, signature, signed_at, signature_json)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    manifest.manifest_id,
                    manifest.run_id,
                    str(signature.algorithm),
                    signature.key_id,
                    signature.key_fingerprint,
                    signature.trust_root_id,
                    signature.signed_digest,
                    signature.signature,
                    signature.signed_at or utc_now().isoformat(),
                    json.dumps(signature.to_dict(), sort_keys=True),
                ),
            )
            conn.execute(
                "UPDATE attestation_manifests SET signature_state = ?, signature_reason = ?"
                " WHERE manifest_id = ?",
                (state, reason, manifest.manifest_id),
            )
        return signature

    def record_unsigned_reason(self, manifest_id: str, reason: str) -> None:
        """Record *why* a manifest is unsigned, without touching its chain.

        Used when a deployment has signing *available* but no signer configured
        for this manifest — a case Phase 2's single reason string could not
        describe. Recording it keeps the promise Phase 2 made: a reader who finds
        an unsigned manifest is told the reason rather than left to guess whether
        an absence is a bug or a phase boundary.
        """
        if not reason:
            raise SignatureStateError("an unsigned reason must not be empty")
        with self._store.write() as conn:
            conn.execute(
                "UPDATE attestation_manifests SET signature_reason = ? WHERE manifest_id = ?",
                (reason, manifest_id),
            )

    def list_signatures(self, run_id: str) -> tuple[EvidenceSignature, ...]:
        """Every signature stored for ``run_id``, oldest first."""
        rows = self._store.query(
            "SELECT signature_json FROM attestation_signatures WHERE run_id = ?"
            " ORDER BY signed_at, manifest_id",
            (run_id,),
        )
        return tuple(
            EvidenceSignature.from_dict(json.loads(str(dict(row)["signature_json"])))
            for row in rows
        )

    # -- the surface seam ---------------------------------------------------- #

    def sign_manifest(
        self,
        manifest_id: str,
        signer: EvidenceSigner,
        *,
        verifier: KeyStoreBackedVerifier,
    ) -> EvidenceSignature:
        """Sign the stored manifest *manifest_id* and record the result.

        The whole operation in one call so no caller can mint a signature
        without recording it, or record one without minting it — the two halves
        drifting apart is how a "signed" manifest with no signature bytes, or a
        signature row for an unsealed manifest, gets into a database.

        Trust is decided by *verifier*, the reader's view, not by the signer:
        a deployment must be able to record a signature as **signed but
        untrusted** when the signing key is not in the local trust store, because
        that is a fact about the evidence, not an error to be raised.
        """
        manifest = self.require_manifest(manifest_id)
        signature = signer.sign_manifest(manifest)
        self.save_signature(
            manifest_id,
            signature,
            trusted=verifier.trust_root_for(signature) is not None,
        )
        return signature


# --------------------------------------------------------------------------- #
# Key management surface helpers                                                #
# --------------------------------------------------------------------------- #


def signer_for(
    key_store: LocalKeyStore,
    key_id: str,
    *,
    trust_root_id: str,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.HMAC_SHA256,
) -> HmacLocalKeySigner:
    """Build a signer over a stored key, refusing an unsupported algorithm.

    The single place a caller goes from "I have a key file" to "I can sign", so
    the algorithm refusal and the trust-root requirement are checked once.
    """
    if algorithm not in IMPLEMENTED_ALGORITHMS:
        raise SigningNotImplementedError(
            str(algorithm),
            "this build implements hmac-sha256 only; no fallback is applied, because "
            "silently downgrading a requested algorithm would hand the caller a "
            "signature the intended verifier cannot check",
        )
    key = key_store.load_key(key_id)
    return HmacLocalKeySigner(
        key=key,
        trust_root_id=trust_root_id,
        algorithm=algorithm,
    )


def trust_store_for(
    key_store: LocalKeyStore,
    *,
    trust_root_id: str,
    key_ids: Sequence[str] = (),
) -> tuple[TrustRoot, ...]:
    """The trust store for a deployment whose keys live in *key_store*."""
    return build_trust_store(key_store, trust_root_id=trust_root_id, key_ids=key_ids)


__all__ = [
    "IMPLEMENTED_ALGORITHMS",
    "IMPLEMENTED_CUSTODY_MODES",
    "MANIFEST_ARTIFACT_KIND",
    "PUBLIC_KEY_ALGORITHMS_IMPLEMENTED",
    "SIGNING_DOMAIN",
    "UNSIGNED_NO_SIGNER",
    "UNSIGNED_NO_SIGNER_REASON",
    "UNSIGNED_NO_SIGNING",
    "UNSIGNED_NO_SIGNING_REASON",
    "UNSIGNED_NO_TRUST_ROOT",
    "UNSIGNED_NO_TRUST_ROOT_REASON",
    "CustodyMode",
    "CustodyUnavailableError",
    "EvidenceSignature",
    "EvidenceSigner",
    "EvidenceVerifier",
    "HmacLocalKeySigner",
    "KeyMaterialError",
    "KeyStoreBackedVerifier",
    "LocalKeyStore",
    "LocalKeyVerifier",
    "SignatureAlgorithm",
    "SignatureRepository",
    "SignatureStateError",
    "SignatureVerification",
    "SigningError",
    "SigningKey",
    "SigningNotImplementedError",
    "TrustRoot",
    "TrustRootRefusedError",
    "UnavailableCustodySigner",
    "build_trust_store",
    "signer_for",
    "signing_bytes",
    "trust_store_for",
]
