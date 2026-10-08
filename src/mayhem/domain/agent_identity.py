"""Agent identity, short-lived credentials, and fencing authorisation.

Plan ``docs/v1.1.0/19_HA_DR_SECURITY.md``, Phase 1 — "identity, fencing, backup
types". The plan's Agent-security paragraph (gap 30) asks for three things:
short-lived agent credentials with rotation and revocation, a controller that
issues signed commands the agent checks before executing, and fencing so only
one owner of a step survives a failover. This module is the *words* for the
first and third. The words for the second already exist and are not restated
here.

What this module is
-------------------

* :class:`AgentIdentity` — who an agent is, which controller issued it, the
  authority it holds (:class:`~mayhem.domain.identity.RoleGrant` in a named
  :class:`~mayhem.domain.identity.EnvironmentScope`), its credential lifetime,
  its rotation state, and the certificate/CA *references* recorded for it.
* :func:`credential_refusals` — every reason a credential may not be used at an
  instant, enumerated rather than short-circuited, exactly as
  :func:`mayhem.domain.approval.approval_reasons` enumerates approval triggers.
  An operator asking "why was this agent refused?" gets the whole list from one
  log line instead of the first failure.
* :class:`CredentialGrant` — the only thing a caller may hold when it wants to
  authenticate an agent. It has no public constructor path that skips the check:
  its own validator re-runs :func:`credential_refusals` against the identity it
  carries, so a revoked or expired identity cannot be wrapped in a grant even by
  a caller that ignores :func:`authorize_credential`. That is the type-level
  form of "a stale or revoked credential is unusable" — not a comment somebody
  has to remember.
* :class:`AgentIdentityRegistry` — the revocation-propagation vehicle. Frozen:
  :meth:`AgentIdentityRegistry.revoke_credential` and
  :meth:`AgentIdentityRegistry.rotate_credential` return a *new* registry with a
  higher :attr:`AgentIdentityRegistry.version`, and every grant names the
  registry version it was authorised against, so a grant issued before a
  revocation is detectably stale instead of silently still-good.

Fencing: why there is no second fencing type here
-------------------------------------------------

**This module deliberately has no fencing type of its own.** It imports
:class:`mayhem.domain.fabric.FencingToken` and adds only *authorisation*
predicates over it. The reasoning, stated once so nobody reopens it:

* A fence orders ownership of one ``(run_id, step_id)``. Plan 03 Phase 1 already
  fixed that order — 1-based epochs, :meth:`~mayhem.domain.fabric.FencingToken.next_fence`
  as the only way to grow an epoch, and ``is_after``/``is_at_least``/``outranks``
  as the predicates. Plan 19's Phase 1 acceptance is "fencing-token monotonicity
  … as pure predicates", and those predicates exist.
* A *second* fence type would create a **second order over the same scope**.
  Two orderings over one scope is not redundancy, it is the split-brain the fence
  exists to prevent: a token minted by one type could not be compared with a
  token minted by the other, so "which epoch am I?" would have two correct
  answers and neither would be wrong. Reuse is the safety property.
* Plan 19 does add one thing plan 03 did not state, and it is a *predicate*, not a
  type: what it means for a fence to **authorise** something. Plan 03 fixed the
  dispatch rule (``is_at_least`` — a retry of the same command keeps the same
  fence, and that is the same owner continuing). Plan 19 needs the stricter
  question as well — *may this fence take ownership away from the current one* —
  which is ``outranks`` (strictly newer). Both are named here:
  :func:`fence_permits_dispatch` and :func:`fence_transfers_ownership`. Neither
  re-decides plan 03's rule; the second is the plan-19 addition and is a
  strictly-newer test over the same epochs.

What this module is NOT (recorded here so no doc may claim otherwise)
---------------------------------------------------------------------

* **No mTLS.** There is no handshake, no session, no key material, no CA
  implementation. :class:`CertificateRef` and :class:`TrustAnchorRef` hold
  *recorded references*; :func:`check_certificate_pinning` compares recorded
  fingerprints, which is a configuration check, not authentication. Mutually
  authenticated transport is Phase 2.
* **No signature verification.** :class:`mayhem.domain.fabric.FabricCommand`
  already makes an unsigned command unrepresentable; *checking* that its
  ``signature`` is good against ``signing_key_id`` is Phase 2, and nothing in
  this module pretends to have done it. :class:`CertificateRef` therefore
  accepts exactly one ``trust_state`` (:data:`CERTIFICATE_TRUST_UNVERIFIED`) —
  a Phase 1 record cannot even *claim* to be verified.

Everything here is a value: no IO, no clock read (``now`` is always an argument,
as in :func:`mayhem.domain.approval.evaluate_approvals`), no crypto, no store.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from itertools import pairwise
from typing import TYPE_CHECKING, Annotated, Final, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.common import Duration, utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import digest
from mayhem.domain.identity import (
    EnvironmentScope,
    Principal,
    RoleGrant,
    effective_roles,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    # Imported, never redefined: plan 19 reuses plan 03's fence type verbatim.
    # See the "Fencing: why there is no second fencing type here" section of the
    # module docstring for the reasoning — two orderings over one scope would be
    # the split-brain the fence exists to prevent, not redundancy.
    from mayhem.domain.fabric import FencingToken

#: Agent ids are minted by the controller and follow the same shape as every
#: other id in the system (``ag-1``, ``ag/k8s-3``), so an agent id is
#: recognisable in a log line without a lookup.
_IDENT = r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$"

#: Default credential lifetime. Short *on purpose*: the plan says short-lived
#: credentials, and a long-lived credential is the thing a stolen private key
#: wants. 900s matches ``approval.DEFAULT_APPROVAL_TTL_S`` because both are
#: "an hour of unattended authority is already too much".
DEFAULT_CREDENTIAL_TTL_S: Final[float] = 900.0

#: Default lead time before expiry at which rotation becomes due.
DEFAULT_ROTATION_LEAD_S: Final[float] = 300.0

#: Default grace during which an overdue credential still works. Zero by
#: default: an operator who wants slack configures it explicitly rather than
#: inheriting it.
DEFAULT_ROTATION_GRACE_S: Final[float] = 0.0

#: The only ``trust_state`` a Phase 1 :class:`CertificateRef` may carry. See the
#: module docstring: Phase 1 verifies no chain, so a record that claims otherwise
#: is refused at construction rather than believed.
CERTIFICATE_TRUST_UNVERIFIED: Final[str] = "unverified_plan19_phase1"

#: Stable refusal code for a credential that may not be used.
CREDENTIAL_REFUSED: Final[str] = "agent_credential_refused"

#: Stable refusal code for a fence that does not authorise an action.
FENCE_NOT_AUTHORISED: Final[str] = "agent_fence_not_authorised"

_REMEDIATION_CREDENTIAL: Final[str] = (
    "rotate or reissue the agent credential; a revoked, superseded, expired or "
    "overdue credential is refused by design"
)

_REMEDIATION_FENCE: Final[str] = (
    "mint the successor fence with next_fence() and re-dispatch; a fence from "
    "another run or step never authorises this action"
)


def _require_aware(moment: datetime, rule: str, subject: str) -> None:
    """Refuse naive datetimes — the same discipline :mod:`mayhem.domain.fabric` uses."""
    if moment.tzinfo is None:
        raise InvariantViolationError(
            rule, f"{subject} must be timezone-aware, got naive {moment!r}"
        )


# --------------------------------------------------------------------------- #
# Revocation                                                                   #
# --------------------------------------------------------------------------- #


class RevocationReason(StrEnum):
    """Why a credential or an identity was pulled.

    The reason travels with the record because "we revoked it" and "we revoked it
    because the host was reimaged" are different answers to "can this key come
    back?", and a DR plan depends on the difference.
    """

    EXPIRED = "expired"
    ROTATION_OVERDUE = "rotation_overdue"
    COMPROMISED = "compromised"
    DECOMMISSIONED = "decommissioned"
    OPERATOR_REQUEST = "operator_request"


class Revocation(BaseModel):
    """One revocation event: what, when, why, and who said so.

    A revocation always names a revoker. "It was revoked" with no actor is the
    one provenance an audit cannot reconstruct from, so it is unrepresentable
    rather than merely discouraged.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    reason: RevocationReason
    revoked_at: datetime
    revoked_by: str = Field(min_length=1)
    note: str = ""

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        _require_aware(self.revoked_at, "revocation.time_aware", "revocation")
        if self.revoked_by != self.revoked_by.strip():
            msg = f"revoked_by must be trimmed, got {self.revoked_by!r}"
            raise InvariantViolationError("revocation.revoker_trimmed", msg)
        return self

    def describe(self) -> str:
        suffix = f": {self.note}" if self.note else ""
        return f"{self.reason.value} by {self.revoked_by} at {self.revoked_at.isoformat()}{suffix}"


# --------------------------------------------------------------------------- #
# Rotation state                                                               #
# --------------------------------------------------------------------------- #


class RotationState(StrEnum):
    """The rotation *lifecycle* of a credential — a recorded fact, not a clock read.

    Whether rotation is due is a function of ``now`` and is asked of
    :func:`rotation_window`, never stored. Storing a "due" flag would make the
    answer depend on when the row was written rather than when it is read.
    """

    CURRENT = "current"
    SUPERSEDED = "superseded"


class RotationWindow(BaseModel):
    """When a credential must be rotated, derived — never stored.

    Attributes:
        issued_at: Start of the credential's life.
        due_at: Rotation is due from here (``expires_at - rotate_before``).
        grace_until: Past ``due_at`` the credential is *overdue*; it still works
            until here only if a grace period was configured.
        expires_at: Hard end of life. Past this the credential is expired
            regardless of any grace.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    issued_at: datetime
    due_at: datetime
    grace_until: datetime
    expires_at: datetime

    def is_open(self, now: datetime) -> bool:
        """True before rotation is due."""
        return now < self.due_at

    def is_due(self, now: datetime) -> bool:
        """True from ``due_at`` until the credential expires."""
        return self.due_at <= now < self.expires_at

    def is_overdue(self, now: datetime) -> bool:
        """True past ``grace_until`` and before ``expires_at``.

        With the default zero grace, ``is_overdue`` and "past due" are the same
        instant, so an operator who configures no slack gets no slack.
        """
        return self.grace_until <= now < self.expires_at

    def is_expired(self, now: datetime) -> bool:
        """True at and after ``expires_at``.

        At-and-after, matching ``Approval.is_expired``: a credential whose
        deadline is *now* has lapsed, so the boundary belongs to the expired side.
        """
        return now >= self.expires_at

    def is_not_yet_valid(self, now: datetime) -> bool:
        """True before ``issued_at`` — clock skew or a forged future stamp."""
        return now < self.issued_at

    def remaining(self, now: datetime) -> timedelta:
        """Time left before hard expiry (negative once expired)."""
        return self.expires_at - now


# --------------------------------------------------------------------------- #
# Credentials                                                                  #
# --------------------------------------------------------------------------- #


class AgentCredential(BaseModel):
    """One short-lived credential an agent authenticates with.

    Three properties are type-level, not documented conventions:

    1. **An eternal credential is unrepresentable.** ``expires_at`` is required
       and validated to be strictly after ``issued_at``. There is no "no expiry"
       spelling, so there is no long-lived key to leak.
    2. **The rotation due time is derived, not stated.** ``rotate_before`` and
       ``rotation_grace`` are the only knobs; :meth:`rotation_window` computes
       the rest, so two records cannot disagree about when rotation was due.
    3. **A revoked credential stays revoked.** ``revocation`` is part of the
       frozen record; there is no code path that clears it, and
       :func:`credential_refusals` reads it on every evaluation.

    The credential holds no key material. It names an id, a window, and a
    rotation lifecycle; the secret itself is plan 29's problem and never enters
    this repository (see ``M0022_SECRET_GRANTS``'s stated rule: no column a
    credential value could occupy).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    credential_id: str = Field(pattern=_IDENT)
    agent_id: str = Field(pattern=_IDENT)
    issued_at: datetime
    expires_at: datetime
    serial: str = ""
    rotate_before: Duration = DEFAULT_ROTATION_LEAD_S
    rotation_grace: Duration = DEFAULT_ROTATION_GRACE_S
    rotation_state: RotationState = RotationState.CURRENT
    generation: Annotated[int, Field(ge=1)] = 1
    superseded_at: datetime | None = None
    superseded_by: str | None = None
    revocation: Revocation | None = None

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        _require_aware(self.issued_at, "credential.time_aware", f"credential {self.credential_id}")
        _require_aware(self.expires_at, "credential.time_aware", f"credential {self.credential_id}")
        if self.expires_at <= self.issued_at:
            msg = (
                f"credential {self.credential_id} expires ({self.expires_at.isoformat()}) "
                f"at or before it was issued ({self.issued_at.isoformat()}); a credential "
                "with no usable window is not a credential"
            )
            raise InvariantViolationError("credential.window", msg)
        # Note on what is deliberately NOT an invariant here: a ``rotate_before``
        # longer than the remaining lifetime (which is every *expired* credential,
        # and any emergency short-lived one) is a policy smell, not a malformed
        # record. Refusing it at construction would make an expired credential
        # unrepresentable, and an expired credential is exactly the record a store
        # must still be able to persist and a reviewer must still be able to read.
        # The consequence of such a record is a refusal, not an error: see
        # ``CredentialRefusal.ROTATION_OVERDUE``. (The grace period needs no check
        # either: the shared ``Duration`` type already refuses a negative value at
        # field validation, before this validator runs.)
        if self.rotation_state is RotationState.SUPERSEDED:
            if self.superseded_at is None or not self.superseded_by:
                msg = (
                    f"credential {self.credential_id} is superseded without naming when "
                    "and by what; a supersession nobody can date is not a rotation"
                )
                raise InvariantViolationError("credential.superseded_needs_provenance", msg)
            _require_aware(
                self.superseded_at,
                "credential.time_aware",
                f"credential {self.credential_id} supersession",
            )
            if self.superseded_at < self.issued_at:
                msg = f"credential {self.credential_id} is superseded before it was issued"
                raise InvariantViolationError("credential.supersede_time_order", msg)
        return self

    # -- windows ----------------------------------------------------------------
    @property
    def ttl_seconds(self) -> float:
        return (self.expires_at - self.issued_at).total_seconds()

    def rotation_window(self) -> RotationWindow:
        """The derived rotation window. Pure — a function of this record only."""
        due_at = self.expires_at - timedelta(seconds=float(self.rotate_before))
        return RotationWindow(
            issued_at=self.issued_at,
            due_at=due_at,
            grace_until=due_at + timedelta(seconds=float(self.rotation_grace)),
            expires_at=self.expires_at,
        )

    @property
    def revoked(self) -> bool:
        return self.revocation is not None

    @property
    def superseded(self) -> bool:
        return self.rotation_state is RotationState.SUPERSEDED

    def is_valid_at(self, now: datetime) -> bool:
        """Convenience inverse of :func:`credential_refusals` for single checks.

        Prefer :func:`credential_refusals` when the *reason* matters — this
        answers yes/no and discards why.
        """
        return not self.refusals_at(now)

    def refusals_at(self, now: datetime) -> tuple[CredentialRefusal, ...]:
        """The credential's own refusals, independent of the identity around it."""
        reasons: list[CredentialRefusal] = []
        window = self.rotation_window()
        if window.is_not_yet_valid(now):
            reasons.append(CredentialRefusal.NOT_YET_VALID)
        if window.is_expired(now):
            reasons.append(CredentialRefusal.EXPIRED)
        if self.revoked:
            reasons.append(CredentialRefusal.CREDENTIAL_REVOKED)
        if self.superseded:
            reasons.append(CredentialRefusal.SUPERSEDED)
        if window.is_overdue(now):
            reasons.append(CredentialRefusal.ROTATION_OVERDUE)
        return tuple(sorted(set(reasons), key=lambda r: r.value))

    # -- transitions ------------------------------------------------------------
    def revoke(self, revocation: Revocation) -> AgentCredential:
        """Return a copy carrying ``revocation``.

        The first revocation wins: re-revoking an already-revoked credential
        returns the existing record rather than overwriting the actor, because
        "who revoked this first?" is the question an incident review asks.
        """
        if self.revocation is not None:
            return self
        return self.__class__.model_validate(
            {**self.model_dump(), "revocation": revocation.model_dump()}
        )

    def supersede(self, *, successor_id: str, at: datetime | None = None) -> AgentCredential:
        """Return the copy a rotation replaced.

        Raises:
            InvariantViolationError: If the credential is already revoked — a
                revoked credential cannot also be presented as a live rotation,
                because that would resurrect it for one more dispatch.
        """
        if self.revocation is not None:
            msg = (
                f"credential {self.credential_id} is already revoked "
                f"({self.revocation.describe()}); a revoked credential is not rotated"
            )
            raise InvariantViolationError("credential.cannot_rotate_revoked", msg)
        moment = utc_now() if at is None else at
        return self.__class__.model_validate(
            {
                **self.model_dump(),
                "rotation_state": RotationState.SUPERSEDED.value,
                "superseded_at": moment,
                "superseded_by": successor_id,
            }
        )

    def successor(
        self,
        *,
        credential_id: str,
        ttl_s: float,
        now: datetime | None = None,
    ) -> AgentCredential:
        """Mint the next generation of this agent's credential.

        The only way to grow a credential generation, mirroring
        :meth:`mayhem.domain.fabric.FencingToken.next_fence`: rotation cannot
        produce a credential that is not strictly newer than the one it replaces.
        Marking the predecessor superseded is the caller's step, and
        :meth:`AgentIdentity.with_credential` does it in the same operation, so
        a controller that kept the old row still refuses it.
        """
        if ttl_s <= 0:
            msg = f"successor ttl must be positive, got {ttl_s}"
            raise InvariantViolationError("credential.successor_ttl", msg)
        moment = utc_now() if now is None else now
        rotate_before = float(self.rotate_before)
        return AgentCredential(
            credential_id=credential_id,
            agent_id=self.agent_id,
            issued_at=moment,
            expires_at=moment + timedelta(seconds=float(ttl_s)),
            serial=self.serial,
            rotate_before=rotate_before,
            rotation_grace=float(self.rotation_grace),
            rotation_state=RotationState.CURRENT,
            generation=self.generation + 1,
        )

    def describe(self) -> str:
        state = self.rotation_state.value
        if self.revocation is not None:
            state = f"revoked ({self.revocation.reason.value})"
        window = self.rotation_window()
        return (
            f"{self.credential_id} gen{self.generation} for {self.agent_id} "
            f"[{window.issued_at.isoformat()} → {window.expires_at.isoformat()}] {state}"
        )


class CredentialRefusal(StrEnum):
    """Every way an agent credential may not be used.

    Enumerated rather than short-circuited, for the reason
    :class:`mayhem.domain.approval.InvalidationReason` enumerates: an operator
    diagnosing a refused agent needs the whole list, and the canonical order
    makes two runs over the same inputs produce the same log line.

    Members are declared in the canonical reporting order — the lifecycle of the
    credential first, then the revocations, then the administrative check — and
    :data:`REFUSAL_ORDER` restates that order so the two can be asserted equal
    rather than assumed to agree.
    """

    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    SUPERSEDED = "superseded"
    ROTATION_OVERDUE = "rotation_overdue"
    CREDENTIAL_REVOKED = "credential_revoked"
    IDENTITY_REVOKED = "identity_revoked"
    CONTROLLER_MISMATCH = "controller_mismatch"


#: Canonical order refusals are reported in: lifecycle first, then revocation,
#: then the administrative check. Authored, not incidental.
REFUSAL_ORDER: Final[tuple[CredentialRefusal, ...]] = (
    CredentialRefusal.NOT_YET_VALID,
    CredentialRefusal.EXPIRED,
    CredentialRefusal.SUPERSEDED,
    CredentialRefusal.ROTATION_OVERDUE,
    CredentialRefusal.CREDENTIAL_REVOKED,
    CredentialRefusal.IDENTITY_REVOKED,
    CredentialRefusal.CONTROLLER_MISMATCH,
)


class CredentialRefusedError(InvariantViolationError):
    """An agent credential may not be used.

    Subclasses :class:`~mayhem.domain.errors.InvariantViolationError` so existing
    domain error handling catches it, while carrying the machine-readable
    :attr:`code` and :attr:`reasons` the agent path logs.
    """

    def __init__(
        self,
        agent_id: str,
        reasons: Sequence[CredentialRefusal],
        *,
        code: str = CREDENTIAL_REFUSED,
        remediation: str = _REMEDIATION_CREDENTIAL,
    ) -> None:
        self.code = code
        self.agent_id = agent_id
        self.reasons = tuple(reasons)
        self.remediation = remediation
        detail = ", ".join(reason.value for reason in self.reasons) or "no reason recorded"
        super().__init__("credential.refused", f"agent '{agent_id}' credential refused: {detail}")


def order_refusals(reasons: Iterable[CredentialRefusal]) -> tuple[CredentialRefusal, ...]:
    """De-duplicate and canonically order a refusal set."""
    present = set(reasons)
    return tuple(reason for reason in REFUSAL_ORDER if reason in present)


# --------------------------------------------------------------------------- #
# Certificate references — data only, no verification claim                    #
# --------------------------------------------------------------------------- #

_FINGERPRINT = r"^[0-9a-f]{64}$"


class TrustAnchorRef(BaseModel):
    """A referenced certificate authority. A reference, never a CA.

    Attributes:
        ca_id: Stable id of the anchor (``ca-mesh-1``).
        subject: Distinguished name the anchor is issued under.
        sha256_fingerprint: Fingerprint an agent certificate is pinned against.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ca_id: str = Field(pattern=_IDENT)
    subject: str = Field(min_length=1)
    sha256_fingerprint: str = Field(pattern=_FINGERPRINT)


class CertificateRef(BaseModel):
    """A recorded agent certificate. **Data, not a verification.**

    Every field is a *reference* the controller wrote down when it issued the
    certificate. Nothing here was parsed, chain-checked, or signature-checked,
    and this type cannot say otherwise: ``trust_state`` is validated to be
    exactly :data:`CERTIFICATE_TRUST_UNVERIFIED`, so a Phase 1 record is
    structurally incapable of claiming to be verified. Mutually authenticated
    transport and real chain validation are Phase 2 (plan 19), which will add
    the verified states here — it will not add a parallel certificate type.

    :attr:`chain_verified` exists so a caller can *ask* the question and get
    ``False`` rather than having to remember which phase it is reading.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    subject: str = Field(min_length=1)
    issuer: str = Field(min_length=1)
    serial: str = Field(min_length=1)
    sha256_fingerprint: str = Field(pattern=_FINGERPRINT)
    not_before: datetime
    not_after: datetime
    trust_state: str = CERTIFICATE_TRUST_UNVERIFIED

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        if self.trust_state != CERTIFICATE_TRUST_UNVERIFIED:
            msg = (
                f"certificate {self.serial} claims trust_state "
                f"{self.trust_state!r}; plan 19 Phase 1 verifies no chain and the only "
                f"state it can honestly record is {CERTIFICATE_TRUST_UNVERIFIED!r}"
            )
            raise InvariantViolationError("certificate.trust_state_unsupported", msg)
        _require_aware(self.not_before, "certificate.time_aware", f"certificate {self.serial}")
        _require_aware(self.not_after, "certificate.time_aware", f"certificate {self.serial}")
        if self.not_after <= self.not_before:
            msg = (
                f"certificate {self.serial} expires ({self.not_after.isoformat()}) at or "
                f"before it starts ({self.not_before.isoformat()})"
            )
            raise InvariantViolationError("certificate.window", msg)
        return self

    @property
    def chain_verified(self) -> bool:
        """Always ``False`` in Phase 1. Present so callers need not remember the phase."""
        return False

    def covers(self, now: datetime) -> bool:
        """True when ``now`` is inside the certificate's *stated* validity window.

        This compares two recorded timestamps. It is not a validity decision: an
        expired-looking certificate is not refused here, because a certificate
        without a real verifier cannot be honestly judged. Phase 2 owns that.
        """
        return self.not_before <= now < self.not_after


class PinReason(StrEnum):
    """Why a pinning check came out the way it did."""

    PINNED = "pinned"
    NO_ANCHORS = "no_anchors"
    FINGERPRINT_MISMATCH = "fingerprint_mismatch"
    ISSUER_MISMATCH = "issuer_mismatch"


class PinVerdict(BaseModel):
    """The result of comparing a recorded fingerprint against recorded anchors.

    ``pinned`` is ``reason is PinReason.PINNED`` — never an independent boolean,
    so "no anchors configured" cannot be reported as a pass by a caller that
    forgets a branch.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    reason: PinReason
    offered_fingerprint: str
    expected_fingerprints: tuple[str, ...]

    @property
    def pinned(self) -> bool:
        return self.reason is PinReason.PINNED

    def describe(self) -> str:
        if self.reason is PinReason.PINNED:
            return f"pinned to {self.offered_fingerprint[:12]}…"
        return f"not pinned ({self.reason.value}); expected {len(self.expected_fingerprints)}"


def check_certificate_pinning(
    certificate: CertificateRef | None,
    anchors: Sequence[TrustAnchorRef],
) -> PinVerdict:
    """Compare a recorded certificate against recorded anchors. Fails closed.

    **This is not authentication.** It answers "is this certificate the one the
    configuration expects?", which is a comparison of strings somebody wrote
    down. It cannot tell a genuine certificate from a forged one, because no
    cryptography runs here — mTLS is Phase 2. What it *can* do is refuse the
    negative controls plan 19 Phase 5 lists, which is why an agent with **no**
    configured anchor gets :data:`PinReason.NO_ANCHORS` rather than a pass: an
    agent that trusts everything because it pinned nothing has to fail closed.
    """
    offered = certificate.sha256_fingerprint if certificate is not None else ""
    if not anchors:
        return PinVerdict(
            reason=PinReason.NO_ANCHORS,
            offered_fingerprint=offered,
            expected_fingerprints=(),
        )
    expected = tuple(anchor.sha256_fingerprint for anchor in anchors)
    if offered in expected:
        if certificate is not None and not any(
            anchor.subject == certificate.issuer for anchor in anchors
        ):
            return PinVerdict(
                reason=PinReason.ISSUER_MISMATCH,
                offered_fingerprint=offered,
                expected_fingerprints=expected,
            )
        return PinVerdict(
            reason=PinReason.PINNED,
            offered_fingerprint=offered,
            expected_fingerprints=expected,
        )
    return PinVerdict(
        reason=PinReason.FINGERPRINT_MISMATCH,
        offered_fingerprint=offered,
        expected_fingerprints=expected,
    )


# --------------------------------------------------------------------------- #
# Identity                                                                     #
# --------------------------------------------------------------------------- #


class AgentIdentity(BaseModel):
    """Who an agent is, and everything that decides whether it may still act.

    Attributes:
        agent_id: Controller-minted agent id.
        controller_id: The controller that owns this agent. A credential
            presented to a *different* controller is refused with
            :data:`CredentialRefusal.CONTROLLER_MISMATCH` — a compromised
            controller must not be able to spend another controller's agents.
        principal: The identity this agent acts as, in plan 09's vocabulary.
        scope: The environment the agent's authority is bounded by.
        credential: The short-lived credential (required — an agent with no
            credential is not an agent that can authenticate).
        certificate: Recorded certificate reference, if one was issued.
        trust_anchors: Anchors the agent's certificate is pinned against.
        revocations: Identity-level revocations. A credential-level revocation
            lives on the credential; this is the "the whole agent is pulled" case.
        version: Monotonic per-identity counter bumped by every rotation and
            revocation. A :class:`CredentialGrant` names the version it was
            authorised against, so revocation *propagation* is detectable rather
            than assumed: a grant against an older version is stale by
            construction, not by luck.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: str = Field(pattern=_IDENT)
    controller_id: str = Field(pattern=_IDENT)
    principal: Principal
    scope: EnvironmentScope
    credential: AgentCredential
    certificate: CertificateRef | None = None
    trust_anchors: tuple[TrustAnchorRef, ...] = ()
    revocations: tuple[Revocation, ...] = ()
    superseded_credentials: tuple[AgentCredential, ...] = ()
    version: Annotated[int, Field(ge=1)] = 1
    recorded_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        _require_aware(self.recorded_at, "agent_identity.time_aware", f"agent {self.agent_id}")
        if self.credential.agent_id != self.agent_id:
            msg = (
                f"agent {self.agent_id} carries credential {self.credential.credential_id} "
                f"issued to {self.credential.agent_id!r}; an identity and its credential "
                "must name the same agent or a grant would authenticate the wrong one"
            )
            raise InvariantViolationError("agent_identity.credential_agent_mismatch", msg)
        stale_revocation = any(
            revocation.revoked_at < self.credential.issued_at for revocation in self.revocations
        )
        if stale_revocation:
            msg = (
                f"agent {self.agent_id} carries a revocation predating its own "
                "credential; the record's own ordering is inconsistent"
            )
            raise InvariantViolationError("agent_identity.revocation_time_order", msg)
        return self

    # -- revocation ------------------------------------------------------------
    @property
    def revoked(self) -> bool:
        """True when the *identity* is revoked (credential-level is on the credential)."""
        return bool(self.revocations)

    @property
    def credential_id(self) -> str:
        return self.credential.credential_id

    def is_revoked(self, now: datetime | None = None) -> bool:
        """True when this identity may not be used at all, at any time.

        A revocation has no window: it is absolute. ``now`` is accepted for
        signature symmetry with the other predicates and deliberately ignored,
        because a revocation that expires is not a revocation.
        """
        del now  # a revocation is absolute; the parameter exists for call-site symmetry
        return self.revoked

    # -- refusals --------------------------------------------------------------
    def refusals_at(
        self, *, now: datetime, controller_id: str | None = None
    ) -> tuple[CredentialRefusal, ...]:
        """Every reason this identity may not authenticate at ``now``.

        ``controller_id`` is the *receiving* controller. When stated and
        different from the issuing one, the result carries
        :data:`CredentialRefusal.CONTROLLER_MISMATCH` in addition to whatever the
        credential's own window says.
        """
        reasons = list(self.credential.refusals_at(now))
        if self.revoked:
            reasons.append(CredentialRefusal.IDENTITY_REVOKED)
        if controller_id is not None and controller_id != self.controller_id:
            reasons.append(CredentialRefusal.CONTROLLER_MISMATCH)
        return order_refusals(reasons)

    def is_usable_at(self, *, now: datetime, controller_id: str | None = None) -> bool:
        """Pure predicate: may this identity authenticate at ``now``?"""
        return not self.refusals_at(now=now, controller_id=controller_id)

    def rotation_window(self) -> RotationWindow:
        """The derived rotation window for the current credential."""
        return self.credential.rotation_window()

    def needs_rotation(self, *, now: datetime) -> bool:
        """True from the rotation due time until the credential expires."""
        return self.rotation_window().is_due(now)

    def pin_verdict(self) -> PinVerdict:
        """Pinning comparison for this identity's recorded certificate."""
        return check_certificate_pinning(self.certificate, self.trust_anchors)

    def holds_role(
        self,
        grants: Iterable[RoleGrant],
        *,
        scope: EnvironmentScope,
        now: datetime,
    ) -> bool:
        """True when this agent's principal holds any active grant in ``scope``.

        Delegates to :func:`mayhem.domain.identity.effective_roles` rather than
        re-deriving grant resolution, so agent authority and human authority
        cannot drift apart.
        """
        return bool(effective_roles(grants, principal=self.principal, scope=scope, now=now))

    # -- transitions -----------------------------------------------------------
    def revoke(self, revocation: Revocation) -> AgentIdentity:
        """Return a copy whose identity is revoked. Idempotent per revocation.

        The first revocation wins for the same reason
        :meth:`AgentCredential.revoke` keeps the first: overwriting the actor
        would erase who pulled the credential.
        """
        if self.revocation_in_place(revocation.reason):
            return self
        recorded = tuple(existing.model_dump() for existing in self.revocations)
        return self.__class__.model_validate(
            {
                **self.model_dump(),
                "revocations": (*recorded, revocation.model_dump()),
                "version": self.version + 1,
            }
        )

    def revocation_in_place(self, reason: RevocationReason) -> bool:
        """True when a revocation with ``reason`` is already recorded."""
        return any(existing.reason is reason for existing in self.revocations)

    def with_credential(self, credential: AgentCredential) -> AgentIdentity:
        """Return a copy carrying a rotated credential, version bumped.

        Two things happen together, and both matter:

        * the previous credential is marked :data:`RotationState.SUPERSEDED` and
          *retained* in :attr:`superseded_credentials` rather than dropped, so a
          controller that still holds the old row refuses it and an auditor can
          still read when it was retired and by what;
        * the identity's *revocations survive* the rotation. Reissuing a key must
          not launder a compromised identity back into service — that is the
          whole reason revocation is identity-level and not only a field on the
          credential.

        Raises:
            InvariantViolationError: If the previous credential cannot be
                superseded (it is revoked), or if the two credentials are for
                different agents.
        """
        if credential.agent_id != self.agent_id:
            msg = (
                f"agent {self.agent_id} cannot take credential {credential.credential_id} "
                f"issued to {credential.agent_id!r}"
            )
            raise InvariantViolationError("agent_identity.credential_agent_mismatch", msg)
        retired = self.credential.supersede(
            successor_id=credential.credential_id, at=credential.issued_at
        )
        history = (*(c.model_dump() for c in self.superseded_credentials), retired.model_dump())
        return self.__class__.model_validate(
            {
                **self.model_dump(),
                "credential": credential.model_dump(),
                "superseded_credentials": history,
                "version": self.version + 1,
            }
        )

    @property
    def credential_history(self) -> tuple[AgentCredential, ...]:
        """Every credential this identity has ever held, oldest first.

        Retired credentials stay readable because ``CredentialRefusal.SUPERSEDED``
        is a refusal, not a deletion: the record is the evidence that a rotation
        happened, and a key that was rotated out is exactly the one somebody
        should not be able to present.
        """
        return (*self.superseded_credentials, self.credential)

    def usable_credentials_at(self, *, now: datetime) -> tuple[str, ...]:
        """Ids of the credentials usable at ``now`` — at most one, or none."""
        return tuple(
            credential.credential_id
            for credential in self.credential_history
            if credential.is_valid_at(now)
        )

    def identity_digest(self) -> str:
        """Canonical digest of the whole record, window and revocations included.

        Same shape as ``Approval.approval_digest``: the window is *inside* the
        digest, so a record cannot be re-stamped with a longer lifetime while
        keeping an identity an audit trail already recorded.
        """
        return digest(self.model_dump(mode="json"))

    def describe(self) -> str:
        state = "active" if not self.revoked else f"revoked ({len(self.revocations)})"
        return (
            f"{self.agent_id} on {self.controller_id} as {self.principal.principal_id} "
            f"in {self.scope.describe()} — {self.credential.describe()}, {state}, "
            f"v{self.version}"
        )


# --------------------------------------------------------------------------- #
# The grant — the only thing a caller may hold to act                          #
# --------------------------------------------------------------------------- #


class CredentialGrant(BaseModel):
    """Proof that an identity was usable at an instant. Only ever issued by
    :func:`authorize_credential`.

    The load-bearing property is the validator: a grant re-runs
    :meth:`AgentIdentity.refusals_at` against the identity it carries, at
    :attr:`authorised_at`, and refuses to exist if anything is wrong. So
    "a stale or revoked credential is unusable" is enforced *by the type* — a
    caller that skips :func:`authorize_credential` and constructs a grant
    directly still cannot get one for a revoked identity.

    A grant is a statement about the past, not a session. It proves validity at
    :attr:`authorised_at`; using it later requires
    :func:`require_still_usable`, which re-evaluates at the moment of use. That
    is the honest shape for a pure domain layer: this module cannot revoke
    anything a caller already holds, so it does not pretend to.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    identity: AgentIdentity
    identity_digest: str
    authorised_at: datetime
    identity_version: Annotated[int, Field(ge=1)]
    controller_id: str | None = None

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        _require_aware(
            self.authorised_at, "credential_grant.time_aware", f"grant for {self.agent_id}"
        )
        if self.identity_digest != self.identity.identity_digest():
            msg = (
                f"credential grant for {self.agent_id} was issued against a different "
                "identity record than the one it carries; the grant is not about this identity"
            )
            raise InvariantViolationError("credential_grant.identity_digest_mismatch", msg)
        if self.identity_version != self.identity.version:
            msg = (
                f"credential grant for {self.agent_id} names identity version "
                f"{self.identity_version} but carries version {self.identity.version}"
            )
            raise InvariantViolationError("credential_grant.version_mismatch", msg)
        reasons = self.identity.refusals_at(
            now=self.authorised_at, controller_id=self.controller_id
        )
        if reasons:
            detail = ", ".join(reason.value for reason in reasons)
            msg = (
                f"a credential grant was constructed for {self.agent_id} at "
                f"{self.authorised_at.isoformat()} with refusals: {detail}"
            )
            raise InvariantViolationError("credential_grant.refused_identity", msg)
        return self

    @property
    def agent_id(self) -> str:
        return self.identity.agent_id

    def still_usable(self, *, now: datetime) -> bool:
        """True when the identity is still usable at ``now`` (re-evaluated)."""
        return self.identity.is_usable_at(now=now, controller_id=self.controller_id)

    def pin_verdict(self) -> PinVerdict:
        return self.identity.pin_verdict()

    def describe(self) -> str:
        return (
            f"grant for {self.agent_id} at {self.authorised_at.isoformat()} "
            f"against identity v{self.identity_version}"
        )


def authorize_credential(
    identity: AgentIdentity,
    *,
    now: datetime,
    controller_id: str | None = None,
) -> CredentialGrant:
    """Authorise ``identity`` to authenticate at ``now``, or refuse with every reason.

    The only supported way to obtain a :class:`CredentialGrant`. ``now`` is an
    argument rather than a clock read, so replaying the decision from recorded
    evidence reproduces it exactly.

    Raises:
        CredentialRefusedError: With :attr:`~CredentialRefusedError.reasons`
            listing *every* refusal, not the first.
    """
    reasons = identity.refusals_at(now=now, controller_id=controller_id)
    if reasons:
        raise CredentialRefusedError(identity.agent_id, reasons)
    return CredentialGrant(
        identity=identity,
        identity_digest=identity.identity_digest(),
        authorised_at=now,
        identity_version=identity.version,
        controller_id=controller_id,
    )


def require_still_usable(grant: CredentialGrant, *, now: datetime) -> CredentialGrant:
    """Re-check a grant at the moment of use.

    Raises:
        CredentialRefusedError: If the identity stopped being usable between
            authorisation and use — revoked, rotated to a successor, or expired.
    """
    reasons = grant.identity.refusals_at(now=now, controller_id=grant.controller_id)
    if reasons:
        raise CredentialRefusedError(grant.agent_id, reasons)
    return grant


# --------------------------------------------------------------------------- #
# Registry — revocation propagation                                            #
# --------------------------------------------------------------------------- #


class AgentIdentityRegistry(BaseModel):
    """An immutable set of agent identities, and the vehicle for propagation.

    Frozen, like :class:`mayhem.domain.fabric.NonceLedger`: a revocation returns
    a *new* registry, so two controllers holding different registry versions
    cannot both believe an agent is live. :attr:`version` increases on every
    change, and :meth:`grant_is_current` is how a holder of an older registry
    discovers that a grant it already has has been overtaken.

    What this type does **not** claim: it cannot reach into a process that
    already cached an older registry. Propagating a revocation to a live agent
    over the wire is Phase 2's mTLS work; what is guaranteed here is that any
    registry carrying a revocation refuses, and that staleness is *detectable*
    (:attr:`CredentialGrant.identity_version` versus
    :meth:`AgentIdentityRegistry.version`).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    identities: tuple[AgentIdentity, ...] = ()
    version: Annotated[int, Field(ge=1)] = 1

    # -- lookup ----------------------------------------------------------------
    def get(self, agent_id: str) -> AgentIdentity | None:
        """The identity for ``agent_id``, or ``None``."""
        for identity in self.identities:
            if identity.agent_id == agent_id:
                return identity
        return None

    def by_controller(self, controller_id: str) -> tuple[AgentIdentity, ...]:
        """Every identity issued by ``controller_id``."""
        return tuple(
            identity for identity in self.identities if identity.controller_id == controller_id
        )

    def revoked_agent_ids(self) -> frozenset[str]:
        """Every agent this registry currently refuses on revocation grounds."""
        return frozenset(identity.agent_id for identity in self.identities if identity.revoked)

    def grant_is_current(self, grant: CredentialGrant) -> bool:
        """True when ``grant`` was authorised against this registry's state.

        False once any rotation or revocation anywhere in the registry has
        advanced :attr:`version` past the grant. This is a *staleness* check, not
        a validity check: a current grant can still be expired, which
        :func:`require_still_usable` decides.
        """
        return grant.identity_version >= self.version

    def authorize(
        self, agent_id: str, *, now: datetime, controller_id: str | None = None
    ) -> CredentialGrant:
        """Look ``agent_id`` up and authorise it.

        Raises:
            CredentialRefusedError: If the agent is unknown — a refusal with
                :data:`CredentialRefusal.IDENTITY_REVOKED` would be misleading, so
                an unknown agent gets its own error carrying no reasons beyond
                that it is not enrolled. This is default-deny, matching
                :func:`mayhem.domain.approval.evaluate_approvals` refusing an empty
                approval set.
        """
        identity = self.get(agent_id)
        if identity is None:
            raise CredentialRefusedError(
                agent_id,
                (),
                remediation="enrol the agent with a controller before it can authenticate",
            )
        return authorize_credential(identity, now=now, controller_id=controller_id)

    # -- propagation -----------------------------------------------------------
    def _replace(self, agent_id: str, identity: AgentIdentity) -> AgentIdentityRegistry:
        return self.__class__(
            identities=tuple(
                identity if existing.agent_id == agent_id else existing
                for existing in self.identities
            ),
            version=self.version + 1,
        )

    def revoke_credential(self, agent_id: str, revocation: Revocation) -> AgentIdentityRegistry:
        """Revoke one credential and return the advanced registry.

        Raises:
            InvariantViolationError: If the agent is not enrolled — a revocation
                for an unknown agent is a typo or a bug, and silently accepting it
                would leave an operator believing a credential was pulled.
        """
        identity = self.get(agent_id)
        if identity is None:
            msg = f"cannot revoke a credential for unenrolled agent {agent_id!r}"
            raise InvariantViolationError("registry.agent_not_enrolled", msg)
        revoked = identity.with_credential(identity.credential.revoke(revocation))
        return self._replace(agent_id, revoked)

    def revoke_agent(self, agent_id: str, revocation: Revocation) -> AgentIdentityRegistry:
        """Revoke the whole identity and return the advanced registry.

        Raises:
            InvariantViolationError: If the agent is not enrolled.
        """
        identity = self.get(agent_id)
        if identity is None:
            msg = f"cannot revoke unenrolled agent {agent_id!r}"
            raise InvariantViolationError("registry.agent_not_enrolled", msg)
        return self._replace(agent_id, identity.revoke(revocation))

    def rotate_credential(
        self,
        agent_id: str,
        *,
        credential_id: str,
        ttl_s: float = DEFAULT_CREDENTIAL_TTL_S,
        now: datetime | None = None,
    ) -> AgentIdentityRegistry:
        """Rotate an agent's credential and return the advanced registry.

        The successor is minted by :meth:`AgentCredential.successor`, so the new
        credential is strictly newer and the old one is marked superseded and
        retained (see :meth:`AgentIdentity.with_credential`) in the same
        operation. A revoked identity refuses to rotate — reissuing a key for a
        compromised agent would undo the revocation.

        Raises:
            InvariantViolationError: If the agent is unknown or revoked.
        """
        identity = self.get(agent_id)
        if identity is None:
            msg = f"cannot rotate a credential for unenrolled agent {agent_id!r}"
            raise InvariantViolationError("registry.agent_not_enrolled", msg)
        if identity.revoked:
            msg = (
                f"agent {agent_id} is revoked ({identity.revocations[0].describe()}); "
                "rotation would resurrect a compromised identity"
            )
            raise InvariantViolationError("registry.cannot_rotate_revoked_agent", msg)
        moment = utc_now() if now is None else now
        successor = identity.credential.successor(
            credential_id=credential_id, ttl_s=ttl_s, now=moment
        )
        return self._replace(agent_id, identity.with_credential(successor))

    def enrol(self, identity: AgentIdentity) -> AgentIdentityRegistry:
        """Add or replace an identity, returning the advanced registry."""
        remaining = tuple(
            existing for existing in self.identities if existing.agent_id != identity.agent_id
        )
        return self.__class__(
            identities=(*remaining, identity),
            version=self.version + 1,
        )


def identity_digest(identity: AgentIdentity) -> str:
    """Module-level spelling of :meth:`AgentIdentity.identity_digest`."""
    return identity.identity_digest()


# --------------------------------------------------------------------------- #
# Fencing authorisation (over fabric.FencingToken — see module docstring)       #
# --------------------------------------------------------------------------- #


class FenceNotAuthorised(InvariantViolationError):  # noqa: N818 — public API, not a stdlib error
    """A fencing token does not authorise the action it was offered for."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        presented: FencingToken,
        remediation: str = _REMEDIATION_FENCE,
    ) -> None:
        self.code = code
        self.presented = presented
        self.remediation = remediation
        super().__init__("fence.not_authorised", message)


def fence_scope_matches(presented: FencingToken, current: FencingToken) -> bool:
    """True when both fences claim the same step of the same run.

    A thin, *named* wrapper over :meth:`mayhem.domain.fabric.FencingToken.same_scope`
    that exists so the refusal sites read as a decision and the negative control
    (cross-run / cross-step fences) has a predicate of its own to test. The rule
    is plan 03's; this module only names the plan-19 question.
    """
    return presented.same_scope(current)


def fence_permits_dispatch(presented: FencingToken, current: FencingToken) -> bool:
    """True when ``presented`` may be dispatched against ``current``.

    Exactly plan 03's dispatch predicate — ``is_at_least``, so a **retry** of the
    same command (same fence, same owner) is still permitted while a *deposed*
    owner's fence is not. Plan 19 does not re-decide this rule; it names it, and
    the negative control "a non-outranking token is refused" is this function
    returning ``False`` for every stale scope and every older epoch.
    """
    return presented.is_at_least(current)


def fence_transfers_ownership(presented: FencingToken, current: FencingToken) -> bool:
    """True when ``presented`` may take ownership of the step from ``current``.

    The plan-19 addition, and strictly stronger than dispatch: ownership changes
    hands only on a **strictly newer** fence — that is
    :meth:`~mayhem.domain.fabric.FencingToken.is_after`, ``presented.epoch >
    current.epoch`` in the same scope. An equal epoch is the same owner
    continuing, which is a dispatch, not a transfer, so a duplicated fence cannot
    be used to claim a second ownership.

    A note on which plan-03 method this does **not** use:
    :meth:`~mayhem.domain.fabric.FencingToken.outranks` is documented there as
    "the inverse of ``is_at_least``", which means ``a.outranks(b)`` answers
    *b is at least as new as a* — i.e. ``a`` is the **older** one. Using it here
    would invert the ownership test and let a deposed epoch take the step back.
    Plan 03's method is left exactly as it is (it is not this lane's file to
    change); the plan-19 predicate spells out the direction it needs instead, and
    the negative controls below pin it.
    """
    return presented.is_after(current)


def assert_fence_authorises(
    presented: FencingToken,
    current: FencingToken,
    *,
    require_transfer: bool = False,
) -> None:
    """Refuse unless ``presented`` authorises the action.

    Args:
        presented: The fence carried by the command being offered.
        current: The highest fence the receiver has already served.
        require_transfer: When true, the fence must *strictly* outrank ``current``
            (ownership transfer) rather than merely be at least as new (dispatch).

    Raises:
        FenceNotAuthorised: If the scopes differ (an epoch from another run or
            step never authorises anything here) or the fence does not outrank.
    """
    if not fence_scope_matches(presented, current):
        raise FenceNotAuthorised(
            FENCE_NOT_AUTHORISED,
            f"fence {presented.run_id}/{presented.step_id} epoch {presented.epoch} names a "
            f"different step than the served fence {current.run_id}/{current.step_id} "
            f"epoch {current.epoch}; a fence orders one step of one run and no other",
            presented=presented,
        )
    permitted = (
        fence_transfers_ownership(presented, current)
        if require_transfer
        else fence_permits_dispatch(presented, current)
    )
    if not permitted:
        relation = "outrank" if require_transfer else "match or outrank"
        raise FenceNotAuthorised(
            FENCE_NOT_AUTHORISED,
            f"fence epoch {presented.epoch} does not {relation} the served epoch "
            f"{current.epoch} for step {presented.step_id}; the offered owner is deposed",
            presented=presented,
        )


def fence_chain_is_monotonic(chain: Sequence[FencingToken]) -> bool:
    """True when every fence in ``chain`` is in the same scope and strictly newer
    than the one before it.

    The ordering a controller must be able to prove from its own log: if a chain
    of handovers contains a repeat or a backwards step, two owners could have
    held the step and the record is not trustworthy. Ties are a failure, not a
    pass — an equal epoch is the same owner, not a second owner.
    """
    if not chain:
        return True
    first = chain[0]
    for previous, current in pairwise(chain):
        if not current.same_scope(first):
            return False
        if not fence_transfers_ownership(current, previous):
            return False
    return True
