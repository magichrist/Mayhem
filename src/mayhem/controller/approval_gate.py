"""Plan 09 Phase 2 — identity, authorization, and approvals *at admission*.

Phase 1 (:mod:`mayhem.domain.approval`, :mod:`mayhem.domain.identity`) decided
whether an approval authorizes something, as a pure predicate over four digests,
a role grant set, and an explicitly supplied clock. Nothing read it. This module
is the call site, and the call site is admission:
:func:`mayhem.controller.safety.validate_plan` consults it through
:class:`ApprovalGateInputs` on ``SafetyContext``, so a run whose approvals do not
cover the exact ``(plan, policy, proof, environment)`` tuple is refused before a
single fault step is admitted. A helper nobody calls is not a gate; this one is
reached from the same function that decides whether the plan may run at all.

Three answers, asked in this order, each naming what it refused:

1. **Authorization.** The principal who wants to run the plan must hold
   :data:`~mayhem.domain.identity.Role.EXECUTE` *in the environment being acted
   on*, resolved with the Phase 1 vocabulary
   (:func:`~mayhem.domain.identity.has_role` /
   :func:`~mayhem.domain.identity.effective_roles`) at the gate's injected
   clock. No grants, no environment, no executor — refusal. RBAC layered on the
   environment boundary rather than a second authorization system.
2. **The safety case.** The proof presented must *declare* ``PASS`` and must
   still evaluate to ``PASS`` *for this plan*. Both halves: an approval binds
   :attr:`~mayhem.domain.safety_proof.SafetyProof.proof_digest`, and that digest
   covers the verdict, so a later ``VOID`` rendering of the same obligations is
   a different proof and stops matching — and a caller who voided a proof for a
   reason its obligations cannot show (a superseded plan, a review in progress)
   must not have that void treated as a pass, which is the same rule
   :meth:`mayhem.domain.approval.Approval.bind` holds at mint time. Checking the
   verdict here as well is what makes the refusal legible — "you presented a
   void proof", not "some digest does not match".
3. **The approvals.** Delegated to
   :func:`~mayhem.domain.approval.evaluate_approvals`, which *enumerates* every
   trigger rather than returning the first. Nothing here re-derives what an
   approval means; the gate contributes the plan it is about, the environment it
   is being run in, the executor, and the clock, and reports the verdict.

**Separation of duties is a switch, and both settings are enforced.**
:data:`ApprovalGateInputs.separation_of_duties` off means a principal who holds
both ``APPROVE`` and ``EXECUTE`` may approve a plan they are about to run — the
roles are still separate, they just need not be *held by different people*.
On means the executor may not be among the approvers, whatever they hold. The
switch belongs to whatever configures the policy layer; the gate honours either
answer and never derives it itself.

**What this phase does not claim.** A policy decision's approval *levels*
(``sre``, ``service_owner`` — see
:func:`mayhem.domain.policy_gate.required_approvals`) are not yet bound to
roles or teams, so :func:`quorum_from_requirements` enforces their **count** and
the refusal *names* every outstanding level. Which named group satisfies which
level is plan 09 Phase 3's approval-flow work, and until it lands the levels a
refusal lists are the one part of the answer the gate cannot check for itself.
It says so in the evidence rather than implying a binding it did not verify.

The module is pure in the same sense the policy gate is: ``now`` is a field on
:class:`ApprovalGateInputs` and never a clock read, no store is opened, and
nothing is mutated. Re-running :func:`verify_approvals` over recorded inputs
reproduces the verdict exactly, which is what makes the sealed
:func:`ApprovalGateResult.evidence` payload worth sealing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from mayhem.domain.approval import (
    DEFAULT_APPROVAL_TTL_S,
    Approval,
    InvalidationReason,
    evaluate_approvals,
    order_reasons,
    plan_content_digest,
)

# The approval gate's *verdict value types* moved into the domain —
# ``mayhem.domain.approval_gate_result`` — because their consumers reach below
# the gate: ``Preflight.approval_verdict`` (``mayhem.domain.preflight``) rides
# the whole result out to the run close, and a domain carrier cannot annotate
# itself with a controller type. The four names are re-exported here — through
# an explicit self-alias, the same form ``approval_evidence`` uses for its
# audit-stream re-exports, which is what mypy's ``implicit_reexport = False``
# honors — so every existing citation —
# ``mayhem.controller.approval_gate.ApprovalGateResult`` and its siblings —
# keeps resolving under the historical module.
from mayhem.domain.approval_gate_result import (
    ApprovalGateResult as ApprovalGateResult,  # noqa: PLC0414
)
from mayhem.domain.approval_gate_result import (
    ApprovalOverride as ApprovalOverride,  # noqa: PLC0414
)
from mayhem.domain.approval_gate_result import (
    ApprovalRefusal as ApprovalRefusal,  # noqa: PLC0414
)
from mayhem.domain.approval_gate_result import (
    AuthorizationVerdict as AuthorizationVerdict,  # noqa: PLC0414
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.identity import (
    EnvironmentScope,
    Principal,
    Role,
    RoleGrant,
    TeamMembership,
    effective_roles,
    has_role,
)
from mayhem.domain.pipeline import PlanApproval, PlanMerge
from mayhem.domain.safety_proof import ProofVerdict, SafetyProof

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from datetime import datetime

    from mayhem.domain.approval import ApprovalState, ChangeTicket
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.policy_gate import RequiredApproval

# =============================================================================
# Rule ids
# =============================================================================

#: The executor holds no ``EXECUTE`` grant in the environment being acted on.
RULE_APPROVAL_EXECUTOR_UNAUTHORIZED = "approval.executor_unauthorized"
#: The proof presented is not a ``PASS`` for the plan about to run.
RULE_APPROVAL_PROOF_NOT_PASS = "approval.proof_not_pass"
#: The approvals do not cover this plan/policy/proof/environment tuple.
RULE_APPROVAL_REQUIRED = "approval.required"
#: Recorded when the gate authorized the run.
RULE_APPROVAL_ALLOW = "approval.allow"
#: Recorded when an emergency override is what authorized the run.
RULE_APPROVAL_OVERRIDE = "approval.override"

#: A digest field is a lowercase sha256 hex string and nothing looser — the same
#: rule and the same regex ``domain.approval`` and ``domain.safety_proof`` use.
#: A policy digest that cannot be named did not authorize anything.
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


# =============================================================================
# Small pure helpers
# =============================================================================


def candidate_plan_digest(plan: ExecutionPlan) -> str:
    """The plan digest an approval must name to speak for ``plan``.

    :func:`~mayhem.domain.approval.plan_content_digest` over the plan's JSON
    form, which is byte-identical to ``controller.plan_diff._hash_dict`` and to
    :func:`controller.safety_proof.canonical_plan_digest` (both hash
    ``plan.model_dump(mode="json")`` through ``canonical_json``). It is spelled
    out here rather than imported from either so the approval gate carries no
    dependency on the proof compiler; ``tests/unit/test_approval_gate.py``
    asserts the three agree, so "the plan changed" cannot mean two things.
    """
    return plan_content_digest(plan.model_dump(mode="json"))


def quorum_from_requirements(
    requirements: Iterable[RequiredApproval],
    *,
    configured: int = 1,
) -> int:
    """How many distinct approvers this run needs, given what policy asked for.

    ``configured`` is the operator's own floor. A policy decision that names
    outstanding approval *levels* raises it to one approver per level, because
    "SRE plus service owner" is two signatures and the plan says so.

    Only the **count** is enforced. Nothing in :class:`~mayhem.domain.approval.Approval`
    says which group an approver belongs to, so the gate cannot check that the
    two signatures came from the two named groups — see the module docstring.
    The levels are still carried into the refusal and the evidence, so the gap
    is visible in the record rather than papered over with a quorum.
    """
    levels = {requirement.approval_level for requirement in requirements}
    return max(1, int(configured), len(levels))


# =============================================================================
# Verdicts
#
# The four verdict value types this section used to define —
# ``AuthorizationVerdict``, ``ApprovalOverride``, ``ApprovalRefusal`` and
# ``ApprovalGateResult`` — now live in ``mayhem.domain.approval_gate_result``
# and are re-exported at the top of this module. The gate logic below still
# builds and refuses every one of them; only the *ownership* moved.
# =============================================================================


# =============================================================================
# Gate inputs
# =============================================================================


@dataclass(frozen=True)
class ApprovalGateInputs:
    """Everything the approval gate needs that the plan does not carry.

    ``now`` is a required field for the same reason
    :class:`~mayhem.domain.policy_gate.PolicyGateInputs` makes it one: the
    decision is a pure function of its inputs, and a default clock is how that
    promise gets quietly broken. ``executor`` and ``proof`` are required for the
    same default-deny reason — an authority with no principal is an omission, and
    a safety case with no proof is a plan nobody checked.

    ``plan_digest`` defaults to the candidate plan's own digest, so a caller
    cannot approve one plan and run another by passing a stale value *silently*:
    the override is explicit, and an override that disagrees with the plan is
    caught by the proof check rather than trusted.
    """

    now: datetime
    environment: EnvironmentScope
    executor: Principal
    proof: SafetyProof
    policy_digest: str
    approvals: tuple[Approval, ...] = ()
    grants: tuple[RoleGrant, ...] = ()
    memberships: tuple[TeamMembership, ...] = ()
    plan_digest: str = ""
    required_approvals: int = 1
    separation_of_duties: bool = False
    consumed_ids: frozenset[str] = frozenset()
    run_id: str = ""

    def __post_init__(self) -> None:
        if self.now.tzinfo is None or self.now.utcoffset() is None:
            msg = (
                "approval gate requires a timezone-aware `now`; a naive clock makes "
                "expiry and role windows unreproducible"
            )
            raise InvariantViolationError("approval.gate_naive_clock", msg)
        # The policy digest is required and validated strictly: an approval
        # binds an exact policy version, and "" names none. ``plan_digest`` is
        # genuinely optional (it defaults to the candidate plan's own digest),
        # so it is only checked when stated.
        if not _SHA256_HEX.fullmatch(self.policy_digest):
            msg = (
                "approval gate policy_digest must be a lowercase sha256 hex digest, got "
                f"{self.policy_digest!r}; an approval names an exact policy version"
            )
            raise InvariantViolationError("approval.gate_digest_malformed", msg)
        if self.plan_digest and not _SHA256_HEX.fullmatch(self.plan_digest):
            msg = (
                "approval gate plan_digest must be a lowercase sha256 hex digest, got "
                f"{self.plan_digest!r}"
            )
            raise InvariantViolationError("approval.gate_digest_malformed", msg)
        if self.required_approvals < 1:
            msg = (
                "approval gate required_approvals must be at least 1, got "
                f"{self.required_approvals}"
            )
            raise InvariantViolationError("approval.gate_quorum_arithmetic", msg)

    def with_now(self, now: datetime) -> ApprovalGateInputs:
        """The same gate as of a different instant — a replay, not a re-approval."""
        return replace(self, now=now)

    def resolved_plan_digest(self, plan: ExecutionPlan) -> str:
        return self.plan_digest or candidate_plan_digest(plan)


# =============================================================================
# The gate
# =============================================================================


def _executor_refusal(
    authorization: AuthorizationVerdict, inputs: ApprovalGateInputs
) -> ApprovalRefusal | None:
    if authorization.authorized:
        return None
    missing = ", ".join(role.value for role in authorization.missing)
    return ApprovalRefusal(
        rule_id=RULE_APPROVAL_EXECUTOR_UNAUTHORIZED,
        reason=(
            f"{authorization.principal} is not authorized to execute in "
            f"{authorization.environment}: holds "
            f"[{', '.join(sorted(role.value for role in authorization.roles)) or 'no roles'}], "
            f"needs {missing} [{RULE_APPROVAL_EXECUTOR_UNAUTHORIZED}]"
        ),
        remediation=(
            f"grant {missing} to {authorization.principal} in {authorization.environment}, "
            "or run as a principal that already holds it there"
        ),
        triggers=(),
        inputs={
            **authorization.evidence(),
            "run_id": inputs.run_id,
            "now": inputs.now.isoformat(),
        },
    )


def gate_proof_verdict(proof: SafetyProof, plan_digest: str) -> ProofVerdict:
    """The verdict this gate reads a proof at: freshness, then the declaration.

    :meth:`mayhem.domain.safety_proof.SafetyProof.evaluate` recomputes from the
    obligations, so a proof someone deliberately voided over passing lines still
    evaluates ``PASS``. The declaration is authoritative here — voiding is
    always the safe direction, and honouring a void as a pass would undo the
    decision that voided it.
    """
    computed = proof.evaluate(plan_digest)
    return computed if proof.verdict is ProofVerdict.PASS else proof.verdict


def _proof_refusal(
    proof: SafetyProof, plan_digest: str, proof_digest: str
) -> ApprovalRefusal | None:
    """Refuse a proof that did not pass, for any of the three ways that happens.

    ``evaluate`` is freshness plus recomputed obligations; the *declared*
    verdict is checked alongside it because ``recompute_verdict`` reads only
    the lines. A proof someone voided on purpose therefore evaluates as PASS
    for its own plan, and honouring that here would quietly undo their
    decision — voiding is always the safe direction, so the gate treats a
    non-PASS declaration as authoritative no matter what the lines say.
    """
    computed = proof.evaluate(plan_digest)
    verdict = gate_proof_verdict(proof, plan_digest)
    if verdict is ProofVerdict.PASS:
        return None
    reasons = proof.void_reasons(plan_digest) or (
        proof.void_reason or "obligations did not all pass",
    )
    superseded = proof.plan_digest != plan_digest
    return ApprovalRefusal(
        rule_id=RULE_APPROVAL_PROOF_NOT_PASS,
        reason=(
            f"the safety proof presented is {verdict.value} for this plan "
            f"({'; '.join(reasons)}) [{RULE_APPROVAL_PROOF_NOT_PASS}]"
        ),
        remediation=(
            "re-compile the proof for this plan digest and re-approve against the new "
            "proof digest; an approval cannot outlive the case it was granted on"
        ),
        # A superseded plan is also a digest mismatch, and naming it here means
        # the operator sees "the plan moved" and not only "the proof is void".
        triggers=order_reasons({InvalidationReason.PROOF_DIGEST_MISMATCH} if superseded else set()),
        inputs={
            "proof_verdict": verdict.value,
            "declared_verdict": proof.verdict.value,
            "computed_verdict": computed.value,
            "proof_plan_digest": proof.plan_digest,
            "proof_digest": proof_digest,
            "plan_digest": plan_digest,
            "void_reasons": list(reasons),
            "superseded": superseded,
        },
    )


def _approval_refusal(
    state: ApprovalState,
    plan_digest: str,
    required: int,
    requirements: Sequence[RequiredApproval],
    inputs: ApprovalGateInputs,
) -> ApprovalRefusal | None:
    if state.valid:
        return None
    triggers = order_reasons(state.reasons)
    levels = sorted({requirement.approval_level for requirement in requirements})
    shortfall = max(0, required - len(state.approvers))
    reason = f"{state.describe()} [{RULE_APPROVAL_REQUIRED}]"
    if levels:
        reason += f" Outstanding levels: {', '.join(levels)}."
    return ApprovalRefusal(
        rule_id=RULE_APPROVAL_REQUIRED,
        reason=reason,
        remediation=(
            f"obtain {required} distinct approval(s) bound to plan {plan_digest[:12]}… in "
            f"{inputs.environment.describe()}, each by a principal holding approve in that "
            "environment; an emergency override must carry a reason"
        ),
        triggers=triggers,
        inputs={
            "plan_digest": plan_digest,
            "policy_digest": inputs.policy_digest,
            "proof_digest": inputs.proof.proof_digest,
            "environment": inputs.environment.describe(),
            "required": required,
            "counted": len(state.approvers),
            "shortfall": shortfall,
            "triggers": [reason.value for reason in triggers],
            "discarded": [
                {
                    "approval_id": discarded.approval_id,
                    "approver": discarded.approver,
                    "reasons": [reason.value for reason in discarded.reasons],
                }
                for discarded in state.discarded
            ],
            "unbound_levels": levels,
            "separation_of_duties": inputs.separation_of_duties,
            "run_id": inputs.run_id,
        },
    )


def verify_approvals(
    plan: ExecutionPlan,
    inputs: ApprovalGateInputs,
    *,
    requirements: Sequence[RequiredApproval] = (),
) -> ApprovalGateResult:
    """Decide whether ``inputs`` authorize running *this* plan, here, now.

    ``requirements`` are the approval requirements a policy decision surfaced
    (:attr:`~mayhem.domain.policy_gate.PolicyGateResult.required_approvals`).
    They raise the quorum; see :func:`quorum_from_requirements` for what is and
    is not enforced about them.

    Pure: ``inputs.now`` is the clock, no store is read, and nothing is mutated,
    so the same inputs always produce the same verdict. Refusals are ordered
    executor, then proof, then approvals — the three questions in the order a
    human can answer them, each a hard refusal, so the order is a reporting
    preference and never a ranking.
    """
    plan_digest = inputs.resolved_plan_digest(plan)
    proof_digest = inputs.proof.proof_digest
    roles = effective_roles(
        inputs.grants,
        principal=inputs.executor,
        scope=inputs.environment,
        memberships=inputs.memberships,
        now=inputs.now,
    )
    authorization = AuthorizationVerdict(
        principal=inputs.executor.principal_id,
        environment=inputs.environment.describe(),
        roles=roles,
    )
    required = quorum_from_requirements(requirements, configured=inputs.required_approvals)
    state = evaluate_approvals(
        inputs.approvals,
        plan_digest=plan_digest,
        policy_digest=inputs.policy_digest,
        proof_digest=proof_digest,
        environment=inputs.environment,
        now=inputs.now,
        required_approvals=required,
        grants=inputs.grants,
        memberships=inputs.memberships,
        # Separation of duties names the *executor* as the author of the plan
        # being approved: the person who will run it is the person who must not
        # be the one who signed it. With the switch off this is ``None`` and the
        # trigger cannot fire — the roles stay separate, the holders need not be.
        plan_author=inputs.executor.principal_id if inputs.separation_of_duties else None,
        separation_of_duties=inputs.separation_of_duties,
        consumed_ids=inputs.consumed_ids,
    )
    counted = set(state.approvers)
    overrides = tuple(
        ApprovalOverride(
            approval_id=approval.approval_id,
            principal=approval.approver.principal_id,
            reason=approval.override_reason,
            environment=approval.environment.describe(),
            approval_digest=approval.approval_digest,
        )
        for approval in inputs.approvals
        if approval.override and approval.approver.principal_id in counted
    )
    refusal: ApprovalRefusal | None = (
        _executor_refusal(authorization, inputs)
        or _proof_refusal(inputs.proof, plan_digest, proof_digest)
        or _approval_refusal(state, plan_digest, required, requirements, inputs)
    )
    if refusal is not None:
        # One report, both halves: the winner names the rule, and every trigger
        # either half found is enumerated (see :class:`ApprovalRefusal`).
        refusal = replace(
            refusal, triggers=order_reasons(set(refusal.triggers) | set(state.reasons))
        )
    return ApprovalGateResult(
        state=state,
        authorization=authorization,
        proof_verdict=gate_proof_verdict(inputs.proof, plan_digest),
        plan_digest=plan_digest,
        policy_digest=inputs.policy_digest,
        proof_digest=proof_digest,
        environment=inputs.environment.describe(),
        required=required,
        now=inputs.now,
        separation_of_duties=inputs.separation_of_duties,
        requirements=tuple(requirements),
        overrides=overrides,
        refusal=refusal,
    )


def executor_may_run(
    inputs: ApprovalGateInputs,
    *,
    role: Role = Role.EXECUTE,
) -> bool:
    """:data:`~mayhem.domain.identity.Role.EXECUTE` in the acted-on environment.

    The authorization half of the gate on its own, for a surface that must
    answer "may this principal act here?" before it has a plan to check.
    Delegates to the Phase 1 vocabulary rather than re-deriving it.
    """
    return has_role(
        inputs.grants,
        principal=inputs.executor,
        role=role,
        scope=inputs.environment,
        memberships=inputs.memberships,
        now=inputs.now,
    )


# =============================================================================
# The approval service
# =============================================================================


@dataclass(frozen=True)
class ExpiryReport:
    """Which approvals have lapsed at one instant, and which have not.

    Expiry is a fact about the clock, not a state transition: an approval is
    already expired the moment its window closes, whether or not anybody called
    this. So the service *reports* rather than mutates, and
    :func:`~mayhem.domain.approval.approval_reasons` is what enforces it — the
    same function the gate uses, so a report and a refusal cannot disagree.
    """

    at: datetime
    lapsed: tuple[Approval, ...]
    live: tuple[Approval, ...]

    @property
    def next_expiry(self) -> datetime | None:
        """The soonest live expiry, or ``None`` when nothing will lapse."""
        windows = [a.expires_at for a in self.live if a.expires_at is not None]
        return min(windows) if windows else None

    def describe(self) -> str:
        soonest = "none" if self.next_expiry is None else self.next_expiry.isoformat()
        return (
            f"at {self.at.isoformat()}: {len(self.lapsed)} lapsed, "
            f"{len(self.live)} live, next expiry {soonest}"
        )


@dataclass(frozen=True)
class ApprovalInvalidation:
    """What a plan change took away.

    The decision is :class:`~mayhem.domain.pipeline.PlanMerge`'s — "when the two
    digests differ, **every** prior approval is invalidated" — reached through
    that type rather than re-derived here, so the release gate and this gate
    cannot hold different opinions about what a merge did to an approval. This
    record only maps the projection back onto the approvals it came from.
    """

    merge: PlanMerge
    invalidated: tuple[Approval, ...]
    surviving: tuple[Approval, ...]

    @property
    def reason(self) -> str:
        return self.merge.invalidation_reason

    def describe(self) -> str:
        if not self.invalidated:
            return f"plan unchanged at {self.merge.merged_plan_digest[:12]}: every approval stands"
        return (
            f"{len(self.invalidated)} approval(s) invalidated, "
            f"{len(self.surviving)} survive: {self.reason}"
        )


@dataclass(frozen=True)
class ApprovalLedger:
    """The approval service: mint, revoke, expire, invalidate on plan change.

    A frozen record of approvals and the authority around them. Every operation
    returns a *new* ledger, so a rejected request cannot leave a half-applied
    state behind, and the value a caller keeps is the value an evidence reader
    can reproduce. There is no store and no clock: ``now`` is an argument of
    every method that needs one.

    Two rules the minting path enforces, both default-deny:

    * an approver must actually hold ``APPROVE`` in the scope they are approving
      in — an approval nobody was authorized to make is not minted at all, and
      the record says why;
    * an override must carry a reason. The domain deliberately keeps a
      reason-less override *constructible* (the attempt is worth recording); the
      service refuses to issue one, because a service that mints it is the only
      place the requirement can be met before the fact.
    """

    approvals: tuple[Approval, ...] = ()
    grants: tuple[RoleGrant, ...] = ()
    memberships: tuple[TeamMembership, ...] = ()
    consumed_ids: frozenset[str] = frozenset()

    def __len__(self) -> int:
        return len(self.approvals)

    def find(self, approval_id: str) -> Approval | None:
        for approval in self.approvals:
            if approval.approval_id == approval_id:
                return approval
        return None

    def mint(
        self,
        *,
        approval_id: str,
        proof: SafetyProof,
        policy_digest: str,
        approver: Principal,
        environment: EnvironmentScope,
        now: datetime,
        ttl_s: float | None = DEFAULT_APPROVAL_TTL_S,
        change_tickets: tuple[ChangeTicket, ...] = (),
        override: bool = False,
        override_reason: str = "",
        note: str = "",
    ) -> ApprovalLedger:
        """Issue one approval and return the ledger that holds it.

        Raises:
            InvariantViolationError: If the approver holds no ``APPROVE`` grant in
                ``environment`` at ``now``; if ``approval_id`` is already held or
                was consumed by an earlier run; if an override carries no reason;
                or whatever :meth:`mayhem.domain.approval.Approval.bind` refuses
                (a proof that did not pass, a negative TTL).
        """
        if override and not override_reason.strip():
            msg = (
                f"approval {approval_id!r} is an emergency override with no reason; an "
                "override is only issuable when it says why, and that reason is what the "
                "post-hoc review is written against"
            )
            raise InvariantViolationError("approval.override_requires_reason", msg)
        if not has_role(
            self.grants,
            principal=approver,
            role=Role.APPROVE,
            scope=environment,
            memberships=self.memberships,
            now=now,
        ):
            msg = (
                f"{approver.principal_id!r} holds no approve grant in "
                f"{environment.describe()}; an approval nobody was authorized to make "
                "authorizes nothing, so it is not issued"
            )
            raise InvariantViolationError("approval.minting_unauthorized", msg)
        if self.find(approval_id) is not None:
            msg = f"approval id {approval_id!r} is already held by this ledger"
            raise InvariantViolationError("approval.duplicate_id", msg)
        if approval_id in self.consumed_ids:
            msg = (
                f"approval id {approval_id!r} was already consumed by an earlier run; "
                "an approval id is spent once and never reissued"
            )
            raise InvariantViolationError("approval.consumed_id", msg)
        approval = Approval.bind(
            approval_id=approval_id,
            proof=proof,
            policy_digest=policy_digest,
            approver=approver,
            environment=environment,
            issued_at=now,
            ttl_s=ttl_s,
            change_tickets=change_tickets,
            override=override,
            override_reason=override_reason,
            note=note,
        )
        return replace(self, approvals=(*self.approvals, approval))

    def revoke(self, approval_id: str, *, revoked_by: str, now: datetime) -> ApprovalLedger:
        """Record a revocation and return the ledger that carries it.

        No role is required, deliberately: revocation can only *remove*
        authority, so requiring a grant to use it would let a stale approver keep
        a live approval by being unable to revoke it. A blank ``revoked_by`` is
        refused by the record itself (``Approval`` requires a revoker), so an
        unattributed revocation is unrepresentable.

        Revoking an already-revoked approval is a no-op rather than an error —
        the first revocation stands and its digest is already on record.
        """
        target = self.find(approval_id)
        if target is None:
            msg = f"no approval {approval_id!r} in this ledger"
            raise InvariantViolationError("approval.unknown", msg)
        if target.revoked:
            return self
        revoked = Approval.model_validate(
            {**target.model_dump(), "revoked_at": now, "revoked_by": revoked_by}
        )
        approvals = tuple(
            revoked if approval.approval_id == approval_id else approval
            for approval in self.approvals
        )
        return replace(self, approvals=approvals)

    def expire(self, now: datetime) -> ExpiryReport:
        """Which approvals have lapsed at ``now`` — a report, not a mutation."""
        lapsed = tuple(a for a in self.approvals if a.is_expired(now))
        live = tuple(a for a in self.approvals if not a.is_expired(now))
        return ExpiryReport(at=now, lapsed=lapsed, live=live)

    def consume(self, approval_ids: Iterable[str]) -> ApprovalLedger:
        """Mark approval ids spent, so a replayed token is refused.

        The replay guard is a set of ids the gate is handed, not a store lookup:
        who consumed what is the caller's ledger, and the gate only has to know
        an id has already been spent.
        """
        requested = tuple(dict.fromkeys(approval_ids))
        unknown = [approval_id for approval_id in requested if self.find(approval_id) is None]
        if unknown:
            msg = f"cannot consume approval(s) this ledger does not hold: {unknown}"
            raise InvariantViolationError("approval.consume_unknown", msg)
        return replace(self, consumed_ids=self.consumed_ids | frozenset(requested))

    def invalidate_on_plan_change(
        self,
        *,
        checked_plan_digest: str,
        merged_plan_digest: str,
        now: datetime,
    ) -> ApprovalInvalidation:
        """What a plan change did to these approvals, per :class:`PlanMerge`.

        Every prior approval is invalidated when the digests differ — not merely
        the ones whose digest happens to disagree — because an approval granted
        against a plan nobody ran approves a different thing. Same concept, same
        sentence, same type as the release gate.
        """
        projected = tuple(
            PlanApproval(approver=approval.approver.principal_id, plan_digest=approval.plan_digest)
            for approval in self.approvals
        )
        merge = PlanMerge(
            checked_plan_digest=checked_plan_digest,
            merged_plan_digest=merged_plan_digest,
            approvals=projected,
            merged_at=now,
        )
        by_projection = {
            id(projection): approval
            for projection, approval in zip(projected, self.approvals, strict=True)
        }
        return ApprovalInvalidation(
            merge=merge,
            invalidated=tuple(by_projection[id(projection)] for projection in merge.invalidated),
            surviving=tuple(by_projection[id(projection)] for projection in merge.surviving),
        )

    def gate_inputs(
        self,
        *,
        now: datetime,
        environment: EnvironmentScope,
        executor: Principal,
        proof: SafetyProof,
        policy_digest: str,
        **overrides: Any,
    ) -> ApprovalGateInputs:
        """Build :class:`ApprovalGateInputs` from this ledger's own state.

        The seam between the service and the gate: approvals, grants,
        memberships, and consumed ids come from the ledger rather than being
        restated by a caller, which is how a caller ends up checking against a
        different set than the one it holds.
        """
        base = ApprovalGateInputs(
            now=now,
            environment=environment,
            executor=executor,
            proof=proof,
            policy_digest=policy_digest,
            approvals=self.approvals,
            grants=self.grants,
            memberships=self.memberships,
            consumed_ids=self.consumed_ids,
        )
        return replace(base, **overrides) if overrides else base
