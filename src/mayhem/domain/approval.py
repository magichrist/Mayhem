"""Approvals as statements about an exact plan (plan 09, Phase 1).

The plan's objective is one sentence: *an approval is a cryptographic statement
about an exact plan — invalid the moment anything changes*. This module is that
sentence, as types and pure functions.

An :class:`Approval` binds four digests and one identity together:

* ``plan_digest`` — the frozen plan, hashed by :func:`plan_content_digest`, which
  is :func:`mayhem.domain.hashing.digest` and therefore byte-identical to
  ``controller.plan_diff._hash_dict``. There is no second digest scheme: the
  thing that detects "the plan changed" for a human reviewing a diff is the
  thing that invalidates an approval at execution.
* ``policy_digest`` — the :class:`mayhem.domain.policy.PolicyBundle` content
  digest the decision was made under, so an approval cannot outlive the policy
  version it reasoned about.
* ``proof_digest`` — :attr:`mayhem.domain.safety_proof.SafetyProof.proof_digest`,
  which pins the proof *including its verdict*, so a later ``VOID`` rendering
  of the same obligations is a different proof and this approval stops matching
  it.
* ``approver`` — the :class:`~mayhem.domain.identity.Principal` who signed, in a
  named :class:`~mayhem.domain.identity.EnvironmentScope`.

The load-bearing rule is :func:`evaluate_approvals`: a candidate plan plus a set
of approvals in, a :class:`ApprovalState` out. It is pure — no clock read
(``now`` is an argument, as in ``policy.evaluate_bundle``), no store, no IO, no
adapter — and it *enumerates* every invalidation trigger rather than returning
the first one, because "why was this refused" is a question an operator has to
be able to answer in full from a log line.

The seven triggers the plan names are
:data:`InvalidationReason.PLAN_DIGEST_MISMATCH`,
:data:`InvalidationReason.POLICY_DIGEST_MISMATCH`,
:data:`InvalidationReason.PROOF_DIGEST_MISMATCH`, :data:`InvalidationReason.EXPIRED`,
:data:`InvalidationReason.ENVIRONMENT_SCOPE`,
:data:`InvalidationReason.APPROVER_ROLE`, and
:data:`InvalidationReason.OVERRIDE_WITHOUT_REASON`. The rest are the negative
controls the same plan lists: self-approval under separation of duties, a
replayed approval id, a revoked approval, and quorum arithmetic.

Default-deny throughout: an approval whose approver holds no ``APPROVE`` grant
in scope is refused, and an empty set of approvals is refused. An override flag
never *helps* — it is recorded, and an override with no reason is refused
outright, because "someone bypassed this and wrote nothing down" is the one
record an audit trail cannot reconstruct from.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import canonical_json, digest, sha256_hex
from mayhem.domain.identity import (
    EnvironmentScope,
    Principal,
    Role,
    RoleGrant,
    effective_roles,
)
from mayhem.domain.safety_proof import ProofVerdict, SafetyProof

if TYPE_CHECKING:
    from collections.abc import Collection, Iterable, Sequence

    from mayhem.domain.identity import TeamMembership

#: A digest field is a lowercase sha256 hex string and nothing looser. Same rule,
#: same regex, and the same producer (:mod:`mayhem.domain.hashing`) as
#: ``safety_proof`` — an approval that cannot name a digest did not name an
#: artifact.
_SHA256_HEX = r"^[0-9a-f]{64}$"

#: How long a freshly minted approval stays valid unless the caller says
#: otherwise. Same default and the same 900s as
#: :data:`mayhem.domain.execution_intent.DEFAULT_APPROVAL_TTL_S`; the two live
#: in separate modules because neither imports the other, and
#: ``tests/unit/test_approval.py`` asserts the constants agree.
DEFAULT_APPROVAL_TTL_S: float = 900.0


def plan_content_digest(plan: Any) -> str:
    """Canonical digest of a plan payload — the value an approval binds to.

    Defined as :func:`mayhem.domain.hashing.digest` over the plan's JSON form,
    which is exactly what ``controller.plan_diff._hash_dict`` computes
    (``sha256`` over ``canonical_json``). The two are kept honest by a test that
    compares them; the domain cannot import the controller to share one
    function, and duplicating the *algorithm* would have been worse than
    delegating to the one hashing module the whole system already agrees on.
    """
    return digest(plan)


class ChangeTicket(BaseModel):
    """A reference to the change record an approval is filed under (plan 16).

    Recorded, not enforced: whether a ticket is *required* is a policy decision
    for Phase 2, whereas "this approval says it was filed under CHG-1234" is a
    fact the evidence chain needs from day one.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    system: str
    key: str
    url: str = ""

    @field_validator("system", "key")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            msg = "change ticket system and key must be non-blank trimmed strings"
            raise InvariantViolationError("change_ticket_not_blank", msg)
        return value

    def describe(self) -> str:
        return f"{self.system}:{self.key}"


class Approval(BaseModel):
    """One approver's signed statement about one exact plan.

    The record is a *statement*, not a permit: whether it still authorizes
    anything is decided by :func:`evaluate_approvals`, never by reading fields
    here. That is what lets an approval outlive its own validity (as evidence)
    without ever being honoured past it.

    ``override`` records that this approval came through the emergency path.
    It is never sufficient by itself, and an override with no
    ``override_reason`` is refused at evaluation rather than at construction —
    the record is worth keeping precisely because somebody tried, and refusing
    to *mint* it would erase the attempt.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    approval_id: str = Field(pattern=r"^a-[0-9a-z]{1,64}$")
    plan_digest: str = Field(pattern=_SHA256_HEX)
    policy_digest: str = Field(pattern=_SHA256_HEX)
    proof_digest: str = Field(pattern=_SHA256_HEX)
    approver: Principal
    environment: EnvironmentScope
    issued_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None
    change_tickets: tuple[ChangeTicket, ...] = ()
    override: bool = False
    override_reason: str = ""
    revoked_at: datetime | None = None
    revoked_by: str = ""
    note: str = ""

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        if self.expires_at is not None and self.expires_at <= self.issued_at:
            msg = (
                f"approval {self.approval_id} expires ({self.expires_at.isoformat()}) "
                f"at or before it was issued ({self.issued_at.isoformat()})"
            )
            raise InvariantViolationError("approval.window", msg)
        if self.revoked_at is not None and not self.revoked_by.strip():
            msg = f"approval {self.approval_id} is revoked but names no revoker"
            raise InvariantViolationError("approval.revocation_needs_actor", msg)
        if self.revoked_at is not None and self.revoked_at < self.issued_at:
            msg = f"approval {self.approval_id} is revoked before it was issued"
            raise InvariantViolationError("approval.revocation_time_order", msg)
        return self

    # -- lifecycle ------------------------------------------------------------
    def is_expired(self, now: datetime) -> bool:
        """True at and after ``expires_at``; an approval with no expiry never is.

        At-and-after, matching ``PolicyBundle.is_expired`` and
        ``ResourceLock.is_expired``: an approval whose deadline is *now* has
        lapsed, so the boundary belongs to the expired side.
        """
        return self.expires_at is not None and now >= self.expires_at

    @property
    def revoked(self) -> bool:
        return self.revoked_at is not None

    # -- binding --------------------------------------------------------------
    def speaks_for(
        self,
        *,
        plan_digest: str,
        policy_digest: str,
        proof_digest: str,
        environment: EnvironmentScope,
    ) -> bool:
        """The load-bearing predicate, on its own: does this approval still name
        exactly what is about to run?

        Four conjunctive comparisons and nothing else — no clock, no role
        resolution. It is the property the plan states in one line ("a user
        cannot approve a modified plan using an old approval"), factored so it
        can be read, tested, and reused without dragging the rest of the
        evaluation along. :func:`evaluate_approvals` uses it for the three
        digest triggers and the scope trigger.
        """
        return (
            self.plan_digest == plan_digest
            and self.policy_digest == policy_digest
            and self.proof_digest == proof_digest
            and self.environment.covers(environment)
        )

    @property
    def approval_digest(self) -> str:
        """Canonical digest of the whole record, window included.

        Same shape as :attr:`SafetyProof.proof_digest`: the expiry is inside the
        digest so a record cannot be re-stamped with a longer window while
        keeping the identity an audit trail already recorded.
        """
        return sha256_hex(canonical_json(self.model_dump(mode="json")))

    # -- construction ---------------------------------------------------------
    @classmethod
    def bind(
        cls,
        *,
        approval_id: str,
        proof: SafetyProof,
        policy_digest: str,
        approver: Principal,
        environment: EnvironmentScope,
        issued_at: datetime | None = None,
        ttl_s: float | None = DEFAULT_APPROVAL_TTL_S,
        change_tickets: tuple[ChangeTicket, ...] = (),
        override: bool = False,
        override_reason: str = "",
        note: str = "",
    ) -> Approval:
        """Mint an approval bound to ``proof``'s plan, policy, and proof digests.

        The plan digest is *taken from* the proof rather than passed in, so the
        two cannot disagree: an approval over a plan its proof was not compiled
        from is unrepresentable from this constructor. A proof that is not
        ``PASS`` is refused here too — approval is granted on a safety case, and
        there is no way to write down "I approved this even though the proof
        did not hold" in Phase 1.

        Raises:
            InvariantViolationError: If ``proof`` is not ``PASS``, or ``ttl_s``
                is negative.
        """
        if proof.verdict is not ProofVerdict.PASS:
            msg = (
                f"cannot bind an approval to a {proof.verdict.value} proof "
                f"({proof.void_reason or 'obligations did not all pass'}); "
                "approval is granted on a safety case, not around one"
            )
            raise InvariantViolationError("approval.requires_passing_proof", msg)
        if ttl_s is not None and ttl_s < 0:
            msg = f"approval ttl_s must be non-negative or None, got {ttl_s}"
            raise InvariantViolationError("approval.negative_ttl", msg)
        moment = utc_now() if issued_at is None else issued_at
        return cls(
            approval_id=approval_id,
            plan_digest=proof.plan_digest,
            policy_digest=policy_digest,
            proof_digest=proof.proof_digest,
            approver=approver,
            environment=environment,
            issued_at=moment,
            expires_at=None if ttl_s is None else moment + timedelta(seconds=float(ttl_s)),
            change_tickets=change_tickets,
            override=override,
            override_reason=override_reason,
            note=note,
        )


class InvalidationReason(StrEnum):
    """Every way an approval can stop authorizing something.

    The seven the plan names come first; the rest are the negative controls the
    same plan lists under Phase 5, promoted to triggers here so that they are
    enforced by the type rather than by a test that happens to check one caller.
    """

    PLAN_DIGEST_MISMATCH = "plan_digest_mismatch"
    POLICY_DIGEST_MISMATCH = "policy_digest_mismatch"
    PROOF_DIGEST_MISMATCH = "proof_digest_mismatch"
    EXPIRED = "expired"
    ENVIRONMENT_SCOPE = "environment_scope"
    APPROVER_ROLE = "approver_role"
    OVERRIDE_WITHOUT_REASON = "override_without_reason"
    SELF_APPROVED = "self_approved"
    REVOKED = "revoked"
    REPLAYED = "replayed"
    NO_APPROVALS = "no_approvals"
    QUORUM_NOT_MET = "quorum_not_met"


#: Canonical order reasons are reported in: the binding digests first (they are
#: what "the plan changed" means), then the approver, then the arithmetic. The
#: order is authored, not incidental, so two runs over the same inputs produce
#: the same log line.
REASON_ORDER: tuple[InvalidationReason, ...] = tuple(InvalidationReason)


def order_reasons(
    reasons: Iterable[InvalidationReason],
) -> tuple[InvalidationReason, ...]:
    """De-duplicate and canonically order a reason set."""
    return tuple(reason for reason in REASON_ORDER if reason in set(reasons))


class DiscardedApproval(BaseModel):
    """An approval that was offered and why it did not count.

    Kept even when the quorum is met by others: "two of two required, a third
    was expired" is the line an operator needs, and dropping it would hide a
    revoked or replayed token behind a passing quorum.
    """

    model_config = ConfigDict(frozen=True)

    approval_id: str
    approver: str
    reasons: tuple[InvalidationReason, ...]


class ApprovalState(BaseModel):
    """The verdict: valid or not, every reason, and the quorum arithmetic.

    ``valid`` is exactly ``not reasons`` — there is no third "probably" state,
    and no way to construct a valid state that carries a reason.

    ``reasons`` explains a *refusal*: why nobody who was counted could authorize
    this, plus the quorum arithmetic. ``discarded`` explains every approval that
    did not count, whether or not the quorum was met by the others — so a
    revoked or replayed token is visible in the state even when two other
    approvals carried the run.
    """

    model_config = ConfigDict(frozen=True)

    valid: bool
    reasons: tuple[InvalidationReason, ...] = ()
    approvers: tuple[str, ...] = ()
    required: int = 1
    discarded: tuple[DiscardedApproval, ...] = ()
    detail: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check_consistency(self) -> Self:
        if self.valid and self.reasons:
            msg = f"approval state is valid yet names reasons {[r.value for r in self.reasons]}"
            raise InvariantViolationError("approval_state.valid_with_reasons", msg)
        return self

    def has(self, reason: InvalidationReason) -> bool:
        return reason in self.reasons

    @property
    def quorum_met(self) -> bool:
        return not self.has(InvalidationReason.QUORUM_NOT_MET) and not self.has(
            InvalidationReason.NO_APPROVALS
        )

    def describe(self) -> str:
        if self.valid:
            return (
                f"approved by {', '.join(self.approvers) or 'nobody'} "
                f"({len(self.approvers)}/{self.required} required)"
            )
        return "refused: " + "; ".join(reason.value for reason in self.reasons)


def approval_reasons(
    approval: Approval,
    *,
    plan_digest: str,
    policy_digest: str,
    proof_digest: str,
    environment: EnvironmentScope,
    grants: Sequence[RoleGrant] = (),
    memberships: Sequence[TeamMembership] = (),
    plan_author: str | None = None,
    separation_of_duties: bool = False,
    consumed_ids: Collection[str] = (),
    now: datetime,
) -> tuple[InvalidationReason, ...]:
    """Every reason ``approval`` does not authorize, in canonical order.

    The four binding triggers are exactly the comparisons in
    :meth:`Approval.speaks_for`; the rest are about the approver and the
    record. Empty tuple means this approval may be counted toward a quorum.

    ``grants`` is not optional in spirit even though it defaults to empty: an
    approval whose approver holds no ``APPROVE`` grant in scope is refused, so a
    caller that forgets to pass grants gets the default-deny answer rather than
    an accidental allow.
    """
    reasons: list[InvalidationReason] = []
    if approval.plan_digest != plan_digest:
        reasons.append(InvalidationReason.PLAN_DIGEST_MISMATCH)
    if approval.policy_digest != policy_digest:
        reasons.append(InvalidationReason.POLICY_DIGEST_MISMATCH)
    if approval.proof_digest != proof_digest:
        reasons.append(InvalidationReason.PROOF_DIGEST_MISMATCH)
    if not approval.environment.covers(environment):
        reasons.append(InvalidationReason.ENVIRONMENT_SCOPE)
    if approval.is_expired(now):
        reasons.append(InvalidationReason.EXPIRED)
    if approval.revoked:
        reasons.append(InvalidationReason.REVOKED)
    if approval.override and not approval.override_reason.strip():
        reasons.append(InvalidationReason.OVERRIDE_WITHOUT_REASON)
    if approval.approval_id in set(consumed_ids):
        reasons.append(InvalidationReason.REPLAYED)
    if Role.APPROVE not in effective_roles(
        grants,
        principal=approval.approver,
        scope=environment,
        memberships=memberships,
        now=now,
    ):
        reasons.append(InvalidationReason.APPROVER_ROLE)
    if separation_of_duties and plan_author is not None and (
        approval.approver.principal_id == plan_author
    ):
        reasons.append(InvalidationReason.SELF_APPROVED)
    return order_reasons(reasons)


def evaluate_approvals(
    approvals: Iterable[Approval],
    *,
    plan_digest: str,
    policy_digest: str,
    proof_digest: str,
    environment: EnvironmentScope,
    now: datetime,
    required_approvals: int = 1,
    grants: Sequence[RoleGrant] = (),
    memberships: Sequence[TeamMembership] = (),
    plan_author: str | None = None,
    separation_of_duties: bool = False,
    consumed_ids: Collection[str] = (),
) -> ApprovalState:
    """Decide whether ``approvals`` authorize running *this* plan, here, now.

    The rule the plan states in one sentence: an approval authorizes an exact
    plan, under an exact policy, proved by an exact proof, granted by a principal
    who held the approve role in the exact environment being acted on, before it
    expired. Change any of those and it stops being an approval of anything.

    Each approval is classified by :func:`approval_reasons`; the ones with no
    reasons are the *counting* approvals. Quorum counts **distinct** approver
    principals, so the same person approving four times is one signature.

    An approval that fails any trigger is discarded and cannot count — but it
    does not, by itself, sink a quorum the survivors already satisfy: "two of two
    required, a third was expired" is an authorized run with a stale record
    attached, not a refusal. When the quorum *is* not met, the reasons the
    discarded approvals carry are folded into ``reasons`` alongside
    :data:`InvalidationReason.QUORUM_NOT_MET`, because "one of two required and
    the one you have expired" is the diagnosis an operator needs and
    ``quorum_not_met`` alone is not.

    Pure by construction: ``now`` is an argument, and no store, clock, or adapter
    is touched — so replaying this decision from recorded evidence reproduces it
    exactly.

    Raises:
        InvariantViolationError: If ``required_approvals`` is below 1.
    """
    if required_approvals < 1:
        msg = f"required_approvals must be at least 1, got {required_approvals}"
        raise InvariantViolationError("approval.quorum_arithmetic", msg)

    offered = list(approvals)
    counting: list[Approval] = []
    discarded: list[DiscardedApproval] = []
    discarded_reasons: list[InvalidationReason] = []
    details: list[str] = []
    for approval in offered:
        found = approval_reasons(
            approval,
            plan_digest=plan_digest,
            policy_digest=policy_digest,
            proof_digest=proof_digest,
            environment=environment,
            grants=grants,
            memberships=memberships,
            plan_author=plan_author,
            separation_of_duties=separation_of_duties,
            consumed_ids=consumed_ids,
            now=now,
        )
        if found:
            discarded_reasons.extend(found)
            discarded.append(
                DiscardedApproval(
                    approval_id=approval.approval_id,
                    approver=approval.approver.principal_id,
                    reasons=found,
                )
            )
            details.append(
                f"{approval.approval_id} by {approval.approver.principal_id}: "
                f"{', '.join(reason.value for reason in found)}"
            )
        else:
            counting.append(approval)

    approvers = tuple(sorted({approval.approver.principal_id for approval in counting}))
    quorum_met = bool(offered) and len(approvers) >= required_approvals
    reasons: list[InvalidationReason] = []
    if not offered:
        reasons.append(InvalidationReason.NO_APPROVALS)
    if not quorum_met:
        reasons.extend(discarded_reasons)
        if offered:
            reasons.append(InvalidationReason.QUORUM_NOT_MET)

    ordered = order_reasons(reasons)
    return ApprovalState(
        valid=not ordered,
        reasons=ordered,
        approvers=approvers,
        required=required_approvals,
        discarded=tuple(discarded),
        detail=tuple(details),
    )


def evaluate_approval(
    approval: Approval,
    *,
    plan_digest: str,
    policy_digest: str,
    proof_digest: str,
    environment: EnvironmentScope,
    now: datetime,
    **kwargs: Any,
) -> ApprovalState:
    """Single-approval convenience wrapper over :func:`evaluate_approvals`."""
    return evaluate_approvals(
        [approval],
        plan_digest=plan_digest,
        policy_digest=policy_digest,
        proof_digest=proof_digest,
        environment=environment,
        now=now,
        **kwargs,
    )
