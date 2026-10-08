"""Certificate authorities, roles, and the mTLS trust decision (plan 19, Phase 3).

Phase 2 shipped :class:`~mayhem.infra.agent_identity_verifier.X509CommandSignatureVerifier`,
which **fails closed** with
:data:`~mayhem.infra.agent_identity_verifier.SIGNATURE_PORT_UNAVAILABLE`, and wrote
down the reason: chain building needs an X.509 parser and a signature algorithm
this build has no dependency for. Plan 03's ledger records the same handoff and
says the fixtures arrive with this phase.

What arrives here is **half** of what that sentence could be read as promising, and
which half matters.

**What this module ships.** A :class:`CertificateAuthorityPort` with two
implementations, a certificate record type that carries a role and a validity
window, and a trust decision that refuses on every one of the six ways a
certificate can be wrong: no certificate, not yet valid, expired, revoked, issued
by an unknown anchor, a wrong role, an unpinned fingerprint, or a body the issuer
did not sign. :class:`FixtureCertificateAuthority` implements all of it *for real*
over a fixture record, and the conformance matrix (Phase 5) exercises every
refusal against it end to end. What it establishes is: **a holder of that
fixture authority's shared key issued these bytes, and those bytes say the
certificate carries the role and window it claims.** That is a real check with a
real negative control behind each branch.

**What this module does not ship, and says so in its own name.**

* :class:`X509CertificateAuthority` is the port a real deployment configures, and
  it **raises** :class:`~mayhem.infra.agent_identity_verifier.SignaturePortUnavailableError`
  on every call. It never returns a verdict and never returns ``True``. It does
  **not** silently fall back to the fixture CA, because a downgrade that a caller
  cannot see is precisely the attack that picks the weaker scheme for you.
* :class:`FixtureCertificateAuthority` is **not a CA**. It is not X.509, it has no
  ASN.1, no RSA, no ECDSA, no certificate *parser*, and no private key. Its
  "signature" is an HMAC over a canonical JSON body. Its fingerprint is a digest
  of the record's own body, **not** of a public key, and is therefore not
  substitutable for a real certificate fingerprint. The constant
  :data:`CA_ALGORITHM_FIXTURE` is recorded on every verdict, so a report cannot
  read as a PKI result.
* There is **no handshake, no session, no socket, and no wire** anywhere in this
  module. Mutual authentication of a *connection* needs a transport, and ADR-0003
  says agents never listen; the controller dials out and supplies the session. What
  is here is the decision that would be made over one.

Relationship to Phase 1's certificate types
-------------------------------------------

:mod:`mayhem.domain.agent_identity` already owns :class:`CertificateRef` and
:class:`TrustAnchorRef`, and its ``trust_state`` is validated to be exactly
``unverified_plan19_phase1`` so a Phase 1 record is *structurally incapable* of
claiming a chain was validated. That is unchanged here. This module does **not**
add a "verified" state to ``CertificateRef`` and does **not** rewrite a recorded
one: :class:`~mayhem.domain.agent_identity.AgentIdentity.certificate.chain_verified`
is still ``False`` by construction, and the tests pin that, because a real
deployment that has not implemented X.509 must not be able to write a record that
says it did.

So the two types have different jobs and the difference is deliberate:

``CertificateRef``
    a **record** somebody wrote down about a certificate. Data. Its
    ``trust_state`` is a statement that no chain was validated.
``IssuedCertificate``
    a **fixture record** a :class:`CertificateAuthorityPort` can be *asked about*,
    carrying the role and the issuer's own signature over its body. It exists to
    be verified, and the verification result is
    :class:`TrustVerdict` -- never a flag somebody sets on the certificate.

Nothing here persists, and nothing here holds a key that outlives the process
(:class:`CaKeyMaterial` is the same in-process, test/dev shape
:class:`~mayhem.infra.agent_identity_verifier.StaticKeyMaterial` already is). Plan
29 owns key resolution.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated, Final, Protocol

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from mayhem.domain.agent_identity import (
    CertificateRef,
    PinVerdict,
    TrustAnchorRef,
    check_certificate_pinning,
)
from mayhem.domain.attestation import canonical_event_bytes
from mayhem.domain.errors import DomainError, InvariantViolationError
from mayhem.infra.agent_identity_verifier import ALGORITHM_X509, SignaturePortUnavailableError

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator, Mapping, Sequence

#: Algorithm name recorded by :class:`FixtureCertificateAuthority` on every
#: verdict. Deliberately not a plausible-looking PKI name: a report that says
#: ``fixture-ca-hmac-sha256`` cannot be mistaken for one that says ``sha256WithRSA``.
CA_ALGORITHM_FIXTURE = "fixture-ca-hmac-sha256"

#: Every refusal code this module can produce, except
#: :data:`~mayhem.infra.agent_identity_verifier.SIGNATURE_PORT_UNAVAILABLE`, which
#: it reuses rather than re-spelling -- "the port cannot do this in this build" is
#: one fact with one name.
MTLS_NO_CERTIFICATE = "mtls_no_certificate"
MTLS_NOT_YET_VALID = "mtls_not_yet_valid"
MTLS_EXPIRED = "mtls_certificate_expired"
MTLS_REVOKED = "mtls_certificate_revoked"
MTLS_UNKNOWN_ISSUER = "mtls_unknown_issuer"
MTLS_SIGNATURE_INVALID = "mtls_signature_invalid"
MTLS_WRONG_ROLE = "mtls_wrong_role"
MTLS_NOT_PINNED = "mtls_not_pinned"

#: The ``artifact`` label the evidence boundary reports a refusal under.
MTLS_ARTIFACT = "agent_certificate"

_ID = r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$"
_IDENT = Annotated[str, StringConstraints(pattern=_ID)]
_FINGERPRINT = r"^[0-9a-f]{64}$"
_SIG = r"^[A-Za-z0-9+/=_-]+$"


def _require_aware(moment: datetime, rule: str, subject: str) -> None:
    """Refuse naive datetimes. A window comparison on a naive value is meaningless."""
    if moment.tzinfo is None:
        raise InvariantViolationError(
            rule, f"{subject} must be timezone-aware, got naive {moment!r}"
        )


# --------------------------------------------------------------------------- #
# Roles                                                                         #
# --------------------------------------------------------------------------- #


class MtlsRole(StrEnum):
    """What a certificate may be used for.

    Roles exist because "valid certificate" is not a sufficient answer: a
    certificate issued to an agent must not be usable to present a controller on a
    link that expects a controller. That is the wrong-role refusal, and it is the
    refusal a deployment with a single shared trust anchor would otherwise never
    make.
    """

    #: May act as the elected controller.
    CONTROLLER = "controller"
    #: May accept fabric commands as a dispatcher.
    AGENT = "agent"
    #: May *become* the elected controller, having been recorded as a standby.
    STANDBY_CONTROLLER = "standby_controller"
    #: May observe only; may not authenticate a dispatch or a promotion.
    AUDITOR = "auditor"


#: The roles that may present themselves as the elected controller. Used by the
#: promotion path, which must not accept an agent certificate as authority to take
#: the leadership scope.
CONTROLLER_ROLES: Final[frozenset[MtlsRole]] = frozenset(
    {MtlsRole.CONTROLLER, MtlsRole.STANDBY_CONTROLLER}
)


# --------------------------------------------------------------------------- #
# The certificate record                                                        #
# --------------------------------------------------------------------------- #


class IssuedCertificate(BaseModel):
    """A certificate record a :class:`CertificateAuthorityPort` can be asked about.

    Frozen, ``extra="forbid"``, and every field required. Two properties are worth
    naming:

    * ``roles`` is required and must be **non-empty**. A certificate with no role
      is a credential that is good for nothing, and encoding that as "the role
      check is vacuously satisfied" is how a record ends up usable for everything.
    * ``sha256_fingerprint`` is required even though
      :class:`FixtureCertificateAuthority` derives it. Requiring it means the
      pinning check compares a value that was *recorded*, so a record whose body
      and fingerprint disagree is detectable by a caller that recomputes — and
      :meth:`body_digest` is the recomputation.

    **This is not an X.509 certificate.** No DER, no ASN.1, no subject public key,
    no issuer distinguished name beyond a string, no extensions, no Basic
    Constraints. It is a typed record with an HMAC over its canonical body, and
    its fingerprint is a digest of that body rather than of a public key.

    Attributes:
        subject: Who the certificate names.
        issuer_ca_id: Which authority issued it; must match a trusted anchor's
            ``ca_id`` or the certificate is refused as unknown-issuer.
        serial: Issuer-assigned serial; the key a revocation names.
        sha256_fingerprint: Recorded fingerprint, compared against the anchors.
        not_before: Start of the validity window (tz-aware).
        not_after: End of the validity window (tz-aware).
        roles: What the certificate may be used for. Non-empty.
        authority_signature: The issuer's signature over the body.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    subject: str = Field(min_length=1)
    issuer_ca_id: _IDENT
    serial: _IDENT
    sha256_fingerprint: str = Field(pattern=_FINGERPRINT)
    not_before: datetime
    not_after: datetime
    roles: tuple[MtlsRole, ...]
    authority_signature: str = Field(pattern=_SIG, min_length=16)

    @model_validator(mode="after")
    def _check_invariants(self) -> IssuedCertificate:
        _require_aware(self.not_before, "certificate.time_aware", f"certificate {self.serial}")
        _require_aware(self.not_after, "certificate.time_aware", f"certificate {self.serial}")
        if self.not_after <= self.not_before:
            msg = (
                f"certificate {self.serial} expires ({self.not_after.isoformat()}) at or "
                f"before it starts ({self.not_before.isoformat()})"
            )
            raise InvariantViolationError("certificate.window", msg)
        if not self.roles:
            msg = (
                f"certificate {self.serial} carries no role; a certificate that is good "
                "for nothing must not be a certificate that is good for everything"
            )
            raise InvariantViolationError("certificate.roles_required", msg)
        return self

    def covers(self, at: datetime) -> bool:
        """True when ``at`` is inside the stated window. A comparison, not a validation."""
        return self.not_before <= at < self.not_after

    def has_role(self, role: MtlsRole) -> bool:
        """True when this certificate may be used as ``role``."""
        return role in self.roles

    def core_body(self) -> dict[str, object]:
        """The fields a **fingerprint** identifies: everything but the signature and
        the fingerprint.

        This is the one exclusion that is not merely obvious. A digest computed
        over a body that *contains* that same digest can never agree with it, so an
        issued certificate would always fail its own :meth:`fingerprint_agrees`
        and no anchor could ever be minted from one. The fingerprint identifies the
        body; it is therefore not part of the body it identifies.

        Note what this does *not* give up: the fingerprint is still covered by
        :meth:`body`, so rewriting a certificate's recorded fingerprint to name
        somebody else's pinned anchor invalidates the issuer's signature. Only the
        digest input is narrowed, never the signed bytes.
        """
        payload = self.model_dump(
            mode="json",
            exclude={"authority_signature", "sha256_fingerprint"},
        )
        return dict(sorted(payload.items()))

    def body(self) -> dict[str, object]:
        """The exact fields the issuer's signature covers.

        Every field except ``authority_signature`` — including the recorded
        ``sha256_fingerprint``, so a swapped fingerprint is a broken signature
        rather than a successful pin against an anchor the certificate has nothing
        to do with.

        Adding a field to this model therefore changes what is signed, which is the
        property that makes a tampered record detectable — and the reason
        :meth:`~mayhem.domain.agent_identity.CertificateRef` can never be
        substituted for one of these.
        """
        payload = self.model_dump(mode="json", exclude={"authority_signature"})
        return dict(sorted(payload.items()))

    def body_digest(self) -> str:
        """sha256 over :meth:`core_body`.

        The recomputation a recorded fingerprint is checked against.
        """
        return hashlib.sha256(canonical_event_bytes(self.core_body())).hexdigest()

    def fingerprint_agrees(self) -> bool:
        """True when the recorded fingerprint matches the body it claims to identify."""
        return self.sha256_fingerprint == self.body_digest()

    def as_recorded_ref(self) -> CertificateRef:
        """The Phase 1 :class:`CertificateRef` for this certificate.

        Carries ``trust_state='unverified_plan19_phase1'`` because that is the only
        state Phase 1's validator accepts, and this method does **not** launder a
        fixture verification into it. The returned record says "no X.509 chain was
        validated", which remains true whether or not :class:`TrustVerdict` said
        ``TRUSTED`` — because a fixture verdict is not a chain validation.
        """
        return CertificateRef(
            subject=self.subject,
            issuer=self.issuer_ca_id,
            serial=self.serial,
            sha256_fingerprint=self.sha256_fingerprint,
            not_before=self.not_before,
            not_after=self.not_after,
        )

    def describe(self) -> str:
        roles = ", ".join(role.value for role in self.roles)
        return (
            f"certificate {self.serial} for {self.subject} issued by {self.issuer_ca_id}, "
            f"roles [{roles}], window [{self.not_before.isoformat()} → "
            f"{self.not_after.isoformat()}], fingerprint {self.sha256_fingerprint[:12]}…"
        )


# --------------------------------------------------------------------------- #
# Key material                                                                  #
# --------------------------------------------------------------------------- #


class CaKeyPort(Protocol):
    """Where a ``ca_id`` becomes a secret. **No key material is persisted in this repo.**"""

    def lookup(self, ca_id: str) -> bytes | None: ...


class CaKeyMaterial:
    """A test/dev CA key map, in-process only.

    Same lifetime and same honesty as
    :class:`~mayhem.infra.agent_identity_verifier.StaticKeyMaterial`: the process
    is the store. ``lookup`` returning ``None`` means *unknown authority*, and the
    verifier turns that into :data:`MTLS_UNKNOWN_ISSUER` rather than into an empty
    secret that would make the signature check vacuous.
    """

    def __init__(self, keys: Mapping[str, bytes] | None = None) -> None:
        self._keys: dict[str, bytes] = dict(keys or {})

    def add(self, ca_id: str, secret: bytes) -> None:
        self._keys[ca_id] = secret

    def lookup(self, ca_id: str) -> bytes | None:
        return self._keys.get(ca_id)

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self._keys))


# --------------------------------------------------------------------------- #
# The trust decision                                                            #
# --------------------------------------------------------------------------- #


class TrustReason(StrEnum):
    """Why a certificate was or was not trusted. ``TRUSTED`` is one member of nine."""

    TRUSTED = "trusted"
    NO_CERTIFICATE = "no_certificate"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    UNKNOWN_ISSUER = "unknown_issuer"
    SIGNATURE_INVALID = "signature_invalid"
    WRONG_ROLE = "wrong_role"
    NOT_PINNED = "not_pinned"


#: Canonical reporting order. Authored, and asserted equal to :class:`TrustReason`'s
#: declaration order by the unit tests.
TRUST_ORDER: Final[tuple[TrustReason, ...]] = tuple(TrustReason)


class TrustVerdict(BaseModel):
    """The result of asking an authority whether a certificate may be used.

    ``trusted`` is ``reason is TRUSTED`` — an identity test, never an independent
    boolean — so a caller cannot report a pass by forgetting a branch, and a tenth
    member added to :class:`TrustReason` in future defaults to *not* trusted.

    ``algorithm`` is always populated, including on every refusal, because
    "refused" and "refused *by a fixture authority rather than by a CA*" are
    different facts and a report that only records the first is misleading.

    Attributes:
        reason: The verdict.
        detail: What was observed. Required on every path, including ``TRUSTED``
            — a trust decision with no narrative is not an auditable one.
        algorithm: The authority algorithm that decided it.
        certificate_serial: Which certificate, or ``""`` when none was offered.
        roles: The roles the certificate actually carries.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    reason: TrustReason
    detail: str = Field(min_length=1)
    algorithm: str = ""
    certificate_serial: str = ""
    roles: tuple[MtlsRole, ...] = ()

    @property
    def trusted(self) -> bool:
        return self.reason is TrustReason.TRUSTED

    @property
    def refusal_code(self) -> str:
        """The stable code for this verdict's refusal, or ``""`` when trusted."""
        if self.trusted:
            return ""
        return _REFUSAL_CODES[self.reason]

    def describe(self) -> str:
        mark = "trusted" if self.trusted else f"REFUSED {self.reason.value}"
        serial = f" [{self.certificate_serial}]" if self.certificate_serial else ""
        return f"{mark}{serial} ({self.algorithm}): {self.detail}"

    def require_trusted(self) -> TrustVerdict:
        """Return ``self``, or refuse.

        Raises:
            MtlsTrustRefusedError: With :attr:`~MtlsTrustRefusedError.code` set to
                :attr:`refusal_code`, so the caller can route on the same strings
                the gates elsewhere in the plan use.
        """
        if not self.trusted:
            raise MtlsTrustRefusedError(self)
        return self


_REFUSAL_CODES: Final[Mapping[TrustReason, str]] = {
    TrustReason.NO_CERTIFICATE: MTLS_NO_CERTIFICATE,
    TrustReason.NOT_YET_VALID: MTLS_NOT_YET_VALID,
    TrustReason.EXPIRED: MTLS_EXPIRED,
    TrustReason.REVOKED: MTLS_REVOKED,
    TrustReason.UNKNOWN_ISSUER: MTLS_UNKNOWN_ISSUER,
    TrustReason.SIGNATURE_INVALID: MTLS_SIGNATURE_INVALID,
    TrustReason.WRONG_ROLE: MTLS_WRONG_ROLE,
    TrustReason.NOT_PINNED: MTLS_NOT_PINNED,
}


class MtlsTrustRefusedError(DomainError):
    """A certificate was refused. Nothing was authenticated."""

    def __init__(
        self,
        verdict: TrustVerdict,
        *,
        remediation: str = (
            "present a certificate issued by a trusted authority, inside its validity "
            "window, unrevoked, carrying the role this link requires, and pinned in the "
            "configured anchors"
        ),
    ) -> None:
        self.code = verdict.refusal_code or MTLS_NO_CERTIFICATE
        self.verdict = verdict
        self.reason = verdict.reason
        self.algorithm = verdict.algorithm
        self.remediation = remediation
        super().__init__(f"{self.code}: {verdict.describe()}")


class RevocationSourcePort(Protocol):
    """Which certificate serials an authority has revoked."""

    def revoked_serials(self, ca_id: str) -> tuple[str, ...]: ...


class RecordedRevocations:
    """An in-process revocation set. A test/dev source, never a store."""

    def __init__(self, revoked: Iterable[str] | None = None) -> None:
        self._serials: set[str] = set(revoked or ())

    def revoke(self, serial: str) -> None:
        self._serials.add(serial)

    def revoked_serials(self, ca_id: str) -> tuple[str, ...]:
        del ca_id  # serials are namespaced by their own certificate
        return tuple(sorted(self._serials))


class CertificateAuthorityPort(Protocol):
    """Decide whether a certificate may be used. **Two implementations ship; one refuses.**

    The method answers exactly one question — "may this certificate serve
    ``required_role`` at ``at``?" — and answers it as a
    :class:`TrustVerdict` rather than a boolean, because the interesting refusals
    are distinguishable and an operator needs to know which one fired.
    """

    #: Algorithm name, recorded on every verdict this authority produces.
    algorithm: str

    def verify_certificate(
        self,
        certificate: IssuedCertificate | None,
        *,
        anchors: Sequence[TrustAnchorRef],
        required_role: MtlsRole,
        revoked: RevocationSourcePort,
        at: datetime,
    ) -> TrustVerdict: ...


# --------------------------------------------------------------------------- #
# The fixture authority — real checks, fixture cryptography                     #
# --------------------------------------------------------------------------- #


class FixtureCertificateAuthority:
    """Issue and verify fixture certificates. **Not a CA. Not X.509.**

    What it really does
    -------------------

    * **Issues.** :meth:`issue` builds an :class:`IssuedCertificate` whose
      ``authority_signature`` is ``HMAC-SHA256(ca_secret, canonical_body)`` over
      :meth:`IssuedCertificate.body`, base64url encoded, and whose
      ``sha256_fingerprint`` is the sha256 of that same body.
    * **Verifies.** :meth:`verify_certificate` recomputes both and compares with
      :func:`hmac.compare_digest`, then runs the role/window/revocation/pinning
      refusals.

    What that establishes, stated exactly
    -------------------------------------

    * **A holder of that fixture authority's shared key issued these bytes.** A
      symmetric proof, so it is authorship *to the verifier*, never to a third
      party — the same limitation
      :class:`~mayhem.infra.agent_identity_verifier.HmacSha256SignatureVerifier`
      states, and for the same reason.
    * **The bytes have not changed since issuance**, because the signature covers
      every field including ``roles`` and the window.

    What it does **not** establish: that the key belongs to a real CA, that a
    private key was used, that a chain of issuers exists, that a name was validated
    against a directory, or that a certificate was not forged by somebody holding
    the fixture key. :data:`CA_ALGORITHM_FIXTURE` is stamped on every verdict for
    exactly this reason.

    Check order, and why
    --------------------

    ``no certificate`` → ``window`` → ``revoked`` → ``unknown issuer`` →
    ``signature`` → ``role`` → ``pinning``. The first four answer from public
    metadata and are ordered cheapest-first. The signature check runs *before* the
    role and pinning refusals on purpose: a forged record must not be able to
    learn which role a link wants, or whether its fingerprint is pinned, by
    asking. ``no_certificate`` leads because a link that offered nothing has
    nothing else to say.
    """

    algorithm = CA_ALGORITHM_FIXTURE

    #: Minimum authority secret length. A shorter one buys no size and would make
    #: an HMAC key brute-forceable in a way a real curve key is not, so this build
    #: refuses it rather than accepting it.
    minimum_key_bytes = 32

    def __init__(self, keys: CaKeyPort, *, minimum_key_bytes: int | None = None) -> None:
        if minimum_key_bytes is not None and minimum_key_bytes < 1:
            msg = f"minimum_key_bytes must be positive, got {minimum_key_bytes}"
            raise DomainError(msg)
        self._keys = keys
        self._minimum = minimum_key_bytes or self.minimum_key_bytes

    # -- issuing --------------------------------------------------------------
    def sign_body(self, body: Mapping[str, object], *, ca_id: str) -> str:
        """The fixture authority signature over ``body``.

        Raises:
            SignaturePortUnavailableError: If no key is registered for ``ca_id``.
                Minting with an empty secret would produce a certificate whose
                signature every verifier accepts, which is worse than refusing.
        """
        secret = self._keys.lookup(ca_id)
        if secret is None:
            msg = f"no fixture authority key for {ca_id!r}; refusing to issue"
            raise SignaturePortUnavailableError(CA_ALGORITHM_FIXTURE, msg)
        if len(secret) < self._minimum:
            msg = (
                f"fixture authority {ca_id!r} secret is {len(secret)} bytes, below the "
                f"{self._minimum}-byte minimum; refusing to issue"
            )
            raise SignaturePortUnavailableError(CA_ALGORITHM_FIXTURE, msg)
        payload = canonical_event_bytes(dict(sorted(body.items())))
        return base64.urlsafe_b64encode(hmac.new(secret, payload, hashlib.sha256).digest()).decode(
            "ascii"
        )

    def issue(
        self,
        *,
        ca_id: str,
        subject: str,
        serial: str,
        not_before: datetime,
        not_after: datetime,
        roles: Sequence[MtlsRole],
    ) -> IssuedCertificate:
        """Mint a fixture certificate signed by ``ca_id``.

        Raises:
            SignaturePortUnavailableError: If ``ca_id`` has no usable key. See
                :meth:`sign_body`.
            InvariantViolationError: If the window or the role set is unusable —
                surfaced from the model, never worked around here.
        """
        _require_aware(not_before, "certificate.time_aware", f"certificate {serial}")
        _require_aware(not_after, "certificate.time_aware", f"certificate {serial}")
        draft = IssuedCertificate(
            subject=subject,
            issuer_ca_id=ca_id,
            serial=serial,
            # Placeholders so the draft validates. Neither is part of
            # ``core_body()``, and the signature is computed *after* the real
            # fingerprint is known, so neither placeholder reaches the output.
            sha256_fingerprint="0" * 64,
            not_before=not_before,
            not_after=not_after,
            roles=tuple(roles),
            authority_signature="A" * 64,
        )
        fingerprint = hashlib.sha256(canonical_event_bytes(draft.core_body())).hexdigest()
        # The signed body carries the *real* fingerprint, so a certificate whose
        # fingerprint was swapped fails signature verification rather than pinning
        # itself to another certificate's anchor.
        signed = {**draft.body(), "sha256_fingerprint": fingerprint}
        return IssuedCertificate.model_validate(
            {
                **signed,
                "authority_signature": self.sign_body(signed, ca_id=ca_id),
            }
        )

    def anchor(self, certificate: IssuedCertificate) -> TrustAnchorRef:
        """A :class:`TrustAnchorRef` that pins exactly ``certificate``.

        ``subject`` is the **issuer**, not the leaf, because that is what Phase 1's
        :func:`~mayhem.domain.agent_identity.check_certificate_pinning` compares
        against the certificate's own ``issuer`` field — an anchor whose ``subject``
        named the leaf would be reported :data:`PinReason.ISSUER_MISMATCH` and then,
        as written before this was pinned by a test, *ignored* by the caller.

        This is the only way an anchor for a fixture certificate is minted, so an
        anchor always names a body somebody actually signed rather than a
        fingerprint typed into a config file and hoped for.
        """
        if not certificate.fingerprint_agrees():
            msg = (
                f"certificate {certificate.serial} does not agree with its own fingerprint, "
                "so no anchor may be minted for it"
            )
            raise InvariantViolationError("certificate.fingerprint_disagrees", msg)
        return TrustAnchorRef(
            ca_id=certificate.issuer_ca_id,
            subject=certificate.issuer_ca_id,
            sha256_fingerprint=certificate.sha256_fingerprint,
        )

    # -- verifying ------------------------------------------------------------
    def verify_certificate(
        self,
        certificate: IssuedCertificate | None,
        *,
        anchors: Sequence[TrustAnchorRef],
        required_role: MtlsRole,
        revoked: RevocationSourcePort,
        at: datetime,
    ) -> TrustVerdict:
        """Answer whether ``certificate`` may serve ``required_role`` at ``at``.

        Never raises for a bad certificate -- every rejection is a verdict -- so a
        caller cannot accidentally treat an exception as "not a trust problem". The
        refusals are gathered by :meth:`_refusal_reason`, which is the whole rule
        in one ordered function, and this method is the single place that turns a
        reason into a :class:`TrustVerdict`.

        The one exception path is deliberately *not* here: an authority port that
        cannot do its own algorithm raises
        :class:`~mayhem.infra.agent_identity_verifier.SignaturePortUnavailableError`
        (see :class:`X509CertificateAuthority`), and that is a different kind of
        failure from "this certificate is bad".
        """
        _require_aware(at, "mtls.time_aware", "verify_certificate")
        refusal = self._refusal_reason(
            certificate,
            anchors=anchors,
            required_role=required_role,
            revoked=revoked,
            at=at,
        )
        if refusal is not None:
            reason, detail = refusal
            return self._refuse(reason, detail, certificate, at=at)
        # Narrowed by `_refusal_reason`: it returns ``None`` only when the window
        # check passed, and that check is the first thing that dereferences the
        # certificate. Written as an explicit refusal rather than an ``assert`` so
        # a future reordering cannot turn a logic slip into an ``-O``-stripped pass.
        if certificate is None:  # pragma: no cover - unreachable
            msg = "internal: a refusal-free evaluation produced no certificate to trust"
            raise DomainError(msg)
        verdict = self._pinning(certificate, anchors)
        return TrustVerdict(
            reason=TrustReason.TRUSTED,
            detail=(
                f"issued by {certificate.issuer_ca_id}, role {required_role.value!r}, "
                f"unrevoked, inside window, {verdict.describe()}; the fixture signature "
                f"verifies with the shared authority key, which proves a holder of that "
                "key issued these bytes and that they are unaltered -- this is NOT a "
                "public-key signature and NOT an X.509 chain validation"
            ),
            algorithm=self.algorithm,
            certificate_serial=certificate.serial,
            roles=certificate.roles,
        )

    def _refusal_reason(
        self,
        certificate: IssuedCertificate | None,
        *,
        anchors: Sequence[TrustAnchorRef],
        required_role: MtlsRole,
        revoked: RevocationSourcePort,
        at: datetime,
    ) -> tuple[TrustReason, str] | None:
        """The first refusal in documented order, or ``None`` when none applies.

        Order: no certificate, window, authority (revoked / unknown issuer /
        signature), role, pinning. Pinning is last and it is *not* optional: the
        verdict used to be computed for the narrative and then thrown away, so a
        certificate nobody had pinned was reported ``TRUSTED`` with the words
        "not pinned" in its own detail. The check itself is Phase 1's
        :func:`~mayhem.domain.agent_identity.check_certificate_pinning`; the rule
        is not re-derived here, only its place in the order is.
        """
        if certificate is None:
            return (
                TrustReason.NO_CERTIFICATE,
                "no certificate was offered; a link that presents nothing authenticates "
                "nothing, so it fails closed",
            )
        if not certificate.covers(at):
            closed = certificate.not_after <= at
            return (
                TrustReason.EXPIRED if closed else TrustReason.NOT_YET_VALID,
                f"the validity window [{certificate.not_before.isoformat()} → "
                f"{certificate.not_after.isoformat()}) does not cover the check instant "
                f"{at.isoformat()}"
                + ("; it had already closed" if closed else "; it is not open yet"),
            )
        authority = self._authority_problem(certificate, anchors=anchors, revoked=revoked)
        if authority is not None:
            return authority
        if not certificate.has_role(required_role):
            return (
                TrustReason.WRONG_ROLE,
                f"certificate carries role(s) "
                f"[{', '.join(r.value for r in certificate.roles)}] and this link requires "
                f"{required_role.value!r}",
            )
        pinning = self._pinning(certificate, anchors)
        if not pinning.pinned:
            return (
                TrustReason.NOT_PINNED,
                f"{pinning.describe()}: the certificate is issued by a trusted authority "
                "and carries the role this link requires, but no configured anchor pins "
                "it. A link that trusts what it did not pin is the thing this refusal "
                "exists for.",
            )
        return None

    def _pinning(
        self,
        certificate: IssuedCertificate,
        anchors: Sequence[TrustAnchorRef],
    ) -> PinVerdict:
        """Phase 1's pinning check, over this module's certificate.

        Kept in one method so the refusal path and the trusted path cannot compute
        two different answers from two different projections of the record.
        """
        return check_certificate_pinning(
            CertificateRef(
                subject=certificate.subject,
                issuer=certificate.issuer_ca_id,
                serial=certificate.serial,
                sha256_fingerprint=certificate.sha256_fingerprint,
                not_before=certificate.not_before,
                not_after=certificate.not_after,
            ),
            anchors,
        )

    def _authority_problem(
        self,
        certificate: IssuedCertificate,
        *,
        anchors: Sequence[TrustAnchorRef],
        revoked: RevocationSourcePort,
    ) -> tuple[TrustReason, str] | None:
        """Everything that needs the trusted key: revocation, issuer, signature.

        Split out so the check order in :meth:`verify_certificate` reads as one
        line per *kind* of question, and so the "was it issued by the key we trust"
        logic has a single home.
        """
        if certificate.serial in revoked.revoked_serials(certificate.issuer_ca_id):
            return (
                TrustReason.REVOKED,
                f"serial {certificate.serial!r} is revoked by {certificate.issuer_ca_id}",
            )
        known = [anchor for anchor in anchors if anchor.ca_id == certificate.issuer_ca_id]
        if not known:
            return (
                TrustReason.UNKNOWN_ISSUER,
                f"no configured anchor trusts issuer {certificate.issuer_ca_id!r}; "
                f"{len(anchors)} anchor(s) are configured",
            )
        secret = self._keys.lookup(certificate.issuer_ca_id)
        if secret is None or len(secret) < self._minimum:
            return (
                TrustReason.SIGNATURE_INVALID,
                f"no usable key for issuer {certificate.issuer_ca_id!r} (need "
                f"{self._minimum} bytes), so the signature could not be checked at all",
            )
        offered = _b64decode(certificate.authority_signature)
        expected = hmac.new(secret, canonical_event_bytes(certificate.body()), hashlib.sha256)
        expected_mac = expected.digest()
        if offered is None or not hmac.compare_digest(offered, expected_mac):
            return (
                TrustReason.SIGNATURE_INVALID,
                "the fixture authority signature did not verify over the certificate body; "
                "the body was altered, or it was not issued by the trusted key",
            )
        return None

    def _refuse(
        self,
        reason: TrustReason,
        detail: str,
        certificate: IssuedCertificate | None = None,
        *,
        at: datetime,
    ) -> TrustVerdict:
        del at  # carried by the detail text, which already states the instant
        return TrustVerdict(
            reason=reason,
            detail=detail,
            algorithm=self.algorithm,
            certificate_serial="" if certificate is None else certificate.serial,
            roles=() if certificate is None else certificate.roles,
        )


def _b64decode(signature: str) -> bytes | None:
    """Decode a base64url signature, or ``None`` when it is not decodable at all."""
    try:
        return base64.urlsafe_b64decode(signature.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        return None


# --------------------------------------------------------------------------- #
# The X.509 seam — defined, and refused                                         #
# --------------------------------------------------------------------------- #


class X509CertificateAuthority:
    """The CA-backed mTLS seam. **Defined; not implemented; fails closed.**

    This is the class plan 03's ledger and Phase 2 both pointed at. Replacing its
    body with a real implementation is a future change, and the tests here pin the
    refusal so that the replacement cannot land silently — the same discipline
    :class:`~mayhem.infra.agent_identity_verifier.X509CommandSignatureVerifier`
    uses.

    Why it refuses, precisely
    ------------------------

    Chain validation needs an X.509 parser (DER/ASN.1), a signature algorithm to
    check the issuer's signature with, a path builder, and a revocation-checking
    protocol. None of those is in this build's dependency set and plan 19 adds no
    third-party dependency, so the honest answer is a refusal rather than a stub
    that "verifies" something.

    What makes the refusal safe rather than merely inconvenient:

    * it **never returns a verdict**, so a caller cannot read ``True`` out of it by
      accident, and :attr:`MtlsRole` check ordering never runs;
    * it **does not fall back** to :class:`FixtureCertificateAuthority`, so a
      caller who configures the real algorithm cannot be silently downgraded to a
      shared-key fixture check — that downgrade is precisely how an attacker who
      can influence a configuration value chooses the weaker scheme;
    * it carries the **same code**
      (:data:`~mayhem.infra.agent_identity_verifier.SIGNATURE_PORT_UNAVAILABLE`) the
      command verifier uses, so "this build cannot do PKI" is one fact with one
      name across the whole plan.
    """

    algorithm = ALGORITHM_X509

    #: Stated as data so a caller can assert on the reason without importing this.
    REASON: Final[str] = (
        "CA-backed X.509 verification needs an X.509 parser, a signature algorithm, "
        "a path builder, and a revocation-checking protocol, none of which is in this "
        "build's dependency set; plan 19 adds no third-party dependency, so this port "
        "refuses rather than verifying with something weaker"
    )

    def verify_certificate(
        self,
        certificate: IssuedCertificate | None,
        *,
        anchors: Sequence[TrustAnchorRef],
        required_role: MtlsRole,
        revoked: RevocationSourcePort,
        at: datetime,
    ) -> TrustVerdict:
        """Always refuses. Never returns a verdict.

        Raises:
            SignaturePortUnavailableError: Always, with code
                :data:`~mayhem.infra.agent_identity_verifier.SIGNATURE_PORT_UNAVAILABLE`.
        """
        del certificate, anchors, required_role, revoked, at
        raise SignaturePortUnavailableError(ALGORITHM_X509, self.REASON)


def mtls_unavailable_error(algorithm: str = ALGORITHM_X509) -> SignaturePortUnavailableError:
    """The refusal :class:`X509CertificateAuthority` raises, as a value.

    Exposed so a caller can name the failure without importing the class, and so a
    test can assert on it without catching an exception it raised itself.
    """
    return SignaturePortUnavailableError(ALGORITHM_X509, X509CertificateAuthority.REASON)


# --------------------------------------------------------------------------- #
# The service the rest of the plan uses                                          #
# --------------------------------------------------------------------------- #


class MtlsTrustService:
    """Bind an authority, its anchors, and a revocation source into one decision.

    Exists so that "which authority, which anchors, which revocations" is decided
    once at composition time and every call site cannot pick its own. A call site
    that constructed its own anchors per request could pin whatever it liked; here
    the anchor set is a constructor argument, so widening it is a visible edit.
    """

    def __init__(
        self,
        authority: CertificateAuthorityPort,
        *,
        anchors: Sequence[TrustAnchorRef] = (),
        revoked: RevocationSourcePort | None = None,
    ) -> None:
        self._authority = authority
        self._anchors = tuple(anchors)
        self._revoked = revoked if revoked is not None else RecordedRevocations()

    @property
    def algorithm(self) -> str:
        """The algorithm that will actually be used, for the record."""
        return self._authority.algorithm

    @property
    def anchors(self) -> tuple[TrustAnchorRef, ...]:
        return self._anchors

    @property
    def is_real_pkix(self) -> bool:
        """Always ``False``.

        Present so a caller can *ask* whether this service is backed by a PKI
        without remembering which class it was given. Both shipped implementations
        answer ``False``: one is a fixture, one refuses.
        """
        return False

    def with_anchors(self, anchors: Sequence[TrustAnchorRef]) -> MtlsTrustService:
        """A copy anchored to a different set. Used by rotation drills."""
        return MtlsTrustService(self._authority, anchors=anchors, revoked=self._revoked)

    def authorize(
        self,
        certificate: IssuedCertificate | None,
        *,
        required_role: MtlsRole,
        at: datetime,
    ) -> TrustVerdict:
        """May ``certificate`` serve ``required_role`` at ``at``?

        Raises:
            SignaturePortUnavailableError: When the configured authority cannot
                verify its own algorithm (:class:`X509CertificateAuthority`). Kept
                distinct from a refusal because *nothing was checked* is a different
                fact from *checked and wrong* — the caller's remedy is to
                reconfigure, not to retry.
            InvariantViolationError: If ``at`` is naive.
        """
        return self._authority.verify_certificate(
            certificate,
            anchors=self._anchors,
            required_role=required_role,
            revoked=self._revoked,
            at=at,
        )

    def authorize_or_raise(
        self,
        certificate: IssuedCertificate | None,
        *,
        required_role: MtlsRole,
        at: datetime,
    ) -> TrustVerdict:
        """:meth:`authorize`, or raise on a refusal.

        Raises:
            MtlsTrustRefusedError: On any non-``TRUSTED`` verdict.
            SignaturePortUnavailableError: Unchanged — an unavailable port is not a
                refused certificate.
        """
        return self.authorize(certificate, required_role=required_role, at=at).require_trusted()

    def controller_capable(
        self,
        certificate: IssuedCertificate | None,
        *,
        at: datetime,
    ) -> TrustVerdict:
        """May ``certificate`` present itself as the elected controller?

        Requires the :attr:`CONTROLLER_ROLES` set, checked through the same service
        so the promotion path cannot skip the other refusals by asserting a role
        directly. The ``standby_controller`` certificate is accepted here *and* is
        refused on a live controller link by
        :attr:`MtlsRole.CONTROLLER` — that asymmetry is the point of recording the
        distinction.
        """
        for role in sorted(CONTROLLER_ROLES, key=lambda r: r.value):
            if certificate is not None and certificate.has_role(role):
                return self.authorize(certificate, required_role=role, at=at)
        # Nothing controller-shaped was offered: authorize against the primary
        # controller role anyway so the refusal is the right one rather than a
        # synthesized verdict.
        return self.authorize(certificate, required_role=MtlsRole.CONTROLLER, at=at)
