"""Plan 09 Phase 4 — approvals into the sealed chain, and the audit records.

Phase 2 shipped :mod:`mayhem.controller.approval_gate`: a gate that decides, at
admission, whether a run is authorized, and whose verdict is reproducible from
recorded inputs. What it did **not** do is put that verdict anywhere. The gate
result was a return value, so "who approved this run, against which plan, under
which policy and proof, and did anything change afterwards?" was answerable
only by re-running the gate against inputs that might since have moved. This
module is the seam where the answer becomes a record.

Three jobs, and a refusal for each
----------------------------------

**1. Re-derive the binding at seal time, not at grant time.**
:func:`verify_approval_binding` re-evaluates the approvals *as presented at the
moment of sealing* against the digests the chain is about to commit to, and
refuses when the answer is no. This is the plan's sentence made structural —
"a user can never approve a modified plan with an old approval" — because the
check runs twice, at mint (:meth:`~mayhem.domain.approval.Approval.bind`) and
here, and the second run is the one whose inputs are in hand when the evidence
is written. A gate that only checked at grant would still seal an approval that
was revoked, expired, or forked in the minutes between grant and close.

Crucially it calls :func:`~mayhem.domain.approval.evaluate_approvals` rather
than re-deriving what an approval means. There is one evaluation in this
codebase and this module adds no second opinion about validity; it supplies the
fresh inputs and reports the verdict.

**2. Put the decision in the sealed chain.**
:func:`build_authorization` builds the
:class:`~mayhem.infra.attestation_store.RunAuthorization` that plan 12 already
knows how to seal, and :func:`seal_approval_decision` hands it to
:func:`~mayhem.infra.audit_stream.seal_run_evidence_at_run_close`, which inserts
the ``approval_evaluated`` event between the evidence and closure events and
verifies the chain before a row is written. This module mints no event type, no
digest, no manifest, and no sealer. Its contribution is refusing the inputs
that would make the sealed answer a lie.

**3. Record the privileged actions as audit entries.**
Approval granted, approval revoked, an emergency override *exercised*, a role
grant issued or withdrawn, a principal disabled: each is a cross-run fact about
*people*, so each belongs in
:class:`~mayhem.infra.audit_stream.AuditStream` rather than in any one run's
chain. :func:`record_approval_granted`, :func:`record_approval_revoked`,
:func:`record_override_exercised`, :func:`record_role_grant_issued`,
:func:`record_role_grant_revoked`, and :func:`record_principal_disabled` write
them. Each goes through :meth:`AuditStream.record`, which enforces
append-only, re-verifies the chain before extending it, and runs the same
evidence-boundary secret gate every other write path runs.

The audit trail is not optional
-------------------------------
:func:`require_approval_records` is the acceptance criterion the plan names, in
code: **a run whose approvals authorized it but whose approval records are not
in the audit stream cannot be sealed.** :func:`seal_approval_decision` calls it
before touching the store, so the gap is closed *before* anything is written
rather than noticed afterwards. The check is by approval *digest*, so it cannot
be satisfied by naming the right people in the wrong record.

What this does NOT do
---------------------

* **It does not authenticate anybody.** No signature, no key material, no KMS or
  Sigstore custody exists (see
  :data:`~mayhem.infra.attestation_store.SIGNATURE_UNSIGNED_NO_SIGNING`). Every
  artifact here is integrity-chained and *named*. A reader must treat "these
  bytes were not altered and are in order" as established, and "these bytes were
  written by this person" as **a claim by the writer, not a proven fact**. The
  ``principal`` on an audit entry is exactly as authenticated as a signature
  would have made it, which is to say: not at all. Nothing here may imply
  otherwise, and the approval ``digest`` pins the record's *content* — it is not
  an authorship claim.
* **It does not sign the approvals themselves.** An approval's binding is four
  digests; that it was issued by the person it names is not established by
  anything in this module.
* **It does not close the gap between the gate and the run close.** Between
  admission and sealing an approval can be revoked — that is why
  :func:`verify_approval_binding` re-evaluates rather than trusting the gate's
  earlier answer, and the refusal it produces is the mechanism. It does not make
  revocation *impossible* in that window; it makes the window's outcome recorded
  rather than assumed.
* **It does not wire itself into a run-close path.**
  :func:`seal_approval_decision` is the call a caller makes with a store, an
  envelope, and a gate result in hand. Nothing in ``controller/executor.py`` or
  ``cli/lifecycle.py`` calls it yet, for the same reason
  :func:`~mayhem.infra.audit_stream.seal_run_evidence_at_run_close` is not
  called from the executor: the envelope is assembled after the run, and the
  gate result is a ``SafetyContext`` local. This is the documented seam, not a
  silent omission.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mayhem.controller.approval_gate import ApprovalGateResult, ApprovalRefusal
from mayhem.domain.approval import Approval, evaluate_approvals, order_reasons
from mayhem.domain.errors import DomainError
from mayhem.domain.hashing import canonical_json, sha256_hex
from mayhem.infra.attestation_store import RunAuthorization
from mayhem.infra.audit_stream import (
    KIND_APPROVAL_GRANTED as KIND_APPROVAL_GRANTED,  # noqa: PLC0414
)
from mayhem.infra.audit_stream import (
    KIND_APPROVAL_REVOKED as KIND_APPROVAL_REVOKED,  # noqa: PLC0414
)
from mayhem.infra.audit_stream import (
    KIND_EMERGENCY_OVERRIDE_EXERCISED as KIND_EMERGENCY_OVERRIDE_EXERCISED,  # noqa: PLC0414
)
from mayhem.infra.audit_stream import (
    KIND_PRINCIPAL_DISABLED as KIND_PRINCIPAL_DISABLED,  # noqa: PLC0414
)
from mayhem.infra.audit_stream import (
    KIND_ROLE_GRANT_ISSUED as KIND_ROLE_GRANT_ISSUED,  # noqa: PLC0414
)
from mayhem.infra.audit_stream import (
    KIND_ROLE_GRANT_REVOKED as KIND_ROLE_GRANT_REVOKED,  # noqa: PLC0414
)
from mayhem.infra.audit_stream import (
    AuditEntry,
    AuditStream,
    seal_run_evidence_at_run_close,
)

if TYPE_CHECKING:
    from datetime import datetime

    from mayhem.controller.approval_gate import ApprovalGateResult
    from mayhem.domain.attestation import AttestedEvent, AttestedTimestamp, RetentionClass
    from mayhem.domain.evidence import EvidenceEnvelope
    from mayhem.domain.identity import EnvironmentScope, Principal, RoleGrant
    from mayhem.domain.policy import PolicyDecision
    from mayhem.infra.attestation_store import SealedRun

#: The gate refused, so there is no authorization to record.
RULE_APPROVAL_DENIED = "approval.gate_denied"
#: The gate allowed, but the approvals cannot be re-derived as valid at seal time.
RULE_APPROVAL_NOT_REPRODUCIBLE = "approval.not_reproducible"
#: An audit entry claims a change or an action that did not happen.
RULE_APPROVAL_AUDIT_UNCHANGED = "approval.audit_nothing_changed"
#: A privileged identity action carries no actor.
RULE_APPROVAL_AUDIT_UNATTRIBUTED = "approval.audit_unattributed"


class ApprovalEvidenceError(DomainError):
    """The evidence seam refused. Nothing was written."""


class ApprovalAuthorizationRefusedError(ApprovalEvidenceError):
    """A typed refusal from the evidence seam, carrying the gate's vocabulary.

    Shaped like :class:`~mayhem.controller.approval_gate.ApprovalRefusal` so the
    rule id, reason, and remediation read the same as everywhere else, and so a
    caller that would rather log the gap than traceback it can.
    """

    def __init__(self, refusal: ApprovalRefusal) -> None:
        super().__init__(refusal.reason)
        self.refusal = refusal

    @property
    def rule_id(self) -> str:
        return self.refusal.rule_id

    @property
    def remediation(self) -> str:
        return self.refusal.remediation

    def detail(self) -> dict[str, Any]:
        return {"rule_id": self.rule_id, **self.refusal.inputs}


# =============================================================================
# The sealed payload
# =============================================================================


def approval_evidence(
    result: ApprovalGateResult, approvals: tuple[Approval, ...] = ()
) -> dict[str, Any]:
    """The gate's whole answer as one sealed payload.

    Everything an auditor needs to challenge the verdict without re-running
    anything: the four digests, the executor's authorization, every approval that
    counted with its own content digest, every approval that did not with the
    reasons, the overrides with their principals and reasons, and the unbound
    approval levels the gate reports rather than enforces.

    ``sealed_digest`` is taken over every other key, so an edited record is
    detectable by recomputing it — the same shape
    :meth:`~mayhem.controller.approval_gate.ApprovalGateResult.evidence` uses,
    and for the same reason. This function adds the per-approval digests that
    the gate's own payload summarises by count; that is the difference between
    "two approvals counted" and "these two records, by content".

    ``approvals`` is the set of records that were offered, and only those whose
    approver the gate counted appear under ``counted_approvals`` — the pairing
    is derived from :attr:`ApprovalState.approvers`, which is the gate's own
    answer, rather than from anything recomputed here. An approval that was
    offered and discarded is in the gate payload's ``discarded`` list with its
    reasons, and does not appear here: this key names authority, not history.
    """
    counted = set(result.state.approvers)
    payload: dict[str, Any] = {
        **result.evidence(),
        "counted_approvals": [
            {
                "approval_id": approval.approval_id,
                "principal": approval.approver.principal_id,
                "approval_digest": approval.approval_digest,
                "environment": approval.environment.describe(),
                "override": approval.override,
            }
            for approval in approvals
            if approval.approver.principal_id in counted
        ],
    }
    payload.pop("sealed_digest", None)
    return {**payload, "sealed_digest": sha256_hex(canonical_json(payload))}


# =============================================================================
# 1. Re-derive the binding at seal time
# =============================================================================


def verify_approval_binding(
    result: ApprovalGateResult,
    *,
    now: datetime,
    approvals: tuple[Approval, ...] = (),
    environment: EnvironmentScope | None = None,
    grants: tuple[RoleGrant, ...] = (),
    memberships: tuple[Any, ...] = (),
    consumed_ids: frozenset[str] = frozenset(),
) -> ApprovalRefusal | None:
    """Whether ``result`` may be sealed as *this run's* authorization.

    Re-evaluates ``approvals`` against the four digests the chain is about to
    commit to, at ``now``, and requires the answer to be the one the gate gave.
    Three refusals, in the order they are fundamental:

    1. **A denied gate.** ``RunAuthorization`` says "this run was allowed"; a
       refused plan has no such claim to make. Callers that want the refusal
       recorded read :attr:`ApprovalGateResult.refusal` and record it themselves
       — :func:`seal_approval_decision` will not do it for them, because this
       type is an authorization and a denial is not one.
    2. **The gate allowed, but no approvals were supplied.** Checked before
       re-evaluation, because with nothing offered the re-evaluation would
       answer ``no_approvals`` — true, but a weaker reason than the one that is
       actually available. An ``allowed`` result with an empty approval set is a
       claim about nothing, and refusing it here is what stops a caller sealing
       a quorum it cannot show.
    3. **The gate allowed and approvals were supplied, but no environment scope
       was.** Also checked before re-evaluation, for the same reason: without the
       scope the four bindings cannot be compared at all, and a re-evaluation
       over three of them is a different check rather than a weaker one.
    4. **The gate allowed, the inputs are complete, and re-evaluation says
       otherwise.** The exact case the plan names: revoked, expired, forked, or
       replayed between admission and close. The reasons are enumerated, not
       truncated.

    ``approvals`` defaults to empty rather than to "whatever the gate used",
    because the point of this function is to be handed the records *as they are
    now*. A caller that has them passes them; a caller that does not is told so.

    ``grants`` and ``memberships`` are the authority behind the approvals, and
    they default to empty **on purpose**: :func:`~mayhem.domain.approval.approval_reasons`
    refuses an approval whose approver holds no ``APPROVE`` grant in scope, so a
    caller that forgets them gets the default-deny answer rather than an
    accidental pass. This is deliberate and it is a second property, not a
    repeat of the first: the four digest comparisons say *what* was approved,
    and the grants say *whether the person who approved it still could*. An
    approver whose grant was withdrawn between admission and close is caught
    here, exactly as a revoked approval is.

    ``consumed_ids`` is the replay guard, carried for the same reason: an
    approval id already spent by an earlier run is not authority for this one.

    ``environment`` is the :class:`~mayhem.domain.identity.EnvironmentScope` the
    run is being executed in, and it is a parameter rather than being re-derived
    from ``result.environment`` for a specific reason: that field is the scope's
    *rendered* form, and parsing a rendered string back into a scope would be a
    second, looser notion of what an environment is — one that could resolve a
    string to a scope covering a different environment than the gate judged.
    The caller built :class:`~mayhem.controller.approval_gate.ApprovalGateInputs`
    and therefore already holds the scope, so it is asked for. When it is
    ``None`` this function cannot re-evaluate at all and says so, rather than
    silently checking fewer of the four bindings than the gate did.

    Raises:
        InvariantViolationError: Never directly; every failure is a refusal.
    """
    if result.denied:
        refusal = result.refusal
        assert refusal is not None  # `denied` is exactly `refusal is not None`
        return ApprovalRefusal(
            rule_id=RULE_APPROVAL_DENIED,
            reason=(f"approval gate refused this plan ({refusal.reason}) [{RULE_APPROVAL_DENIED}]"),
            remediation=(
                "seal only gate results that authorized the run; a refusal is recorded "
                f"by the caller as {refusal.rule_id}, not as an authorization"
            ),
            triggers=order_reasons(set(refusal.triggers)),
            inputs={**refusal.inputs, "gate_rule_id": refusal.rule_id},
        )

    if not approvals:
        return ApprovalRefusal(
            rule_id=RULE_APPROVAL_NOT_REPRODUCIBLE,
            reason=(
                "the gate allowed this run but no approval records were supplied to seal; "
                f"an authorization with nothing behind it cannot be attested "
                f"[{RULE_APPROVAL_NOT_REPRODUCIBLE}]"
            ),
            remediation=(
                "pass the approvals this run was authorized by; sealing a quorum the "
                "evidence cannot name is how a run acquires authority nobody granted"
            ),
            triggers=(),
            inputs={"offered": 0, "gate_approvers": list(result.state.approvers)},
        )

    if environment is None:
        return ApprovalRefusal(
            rule_id=RULE_APPROVAL_NOT_REPRODUCIBLE,
            reason=(
                "no environment scope was supplied, so the approvals cannot be "
                "re-evaluated against the environment they were granted in; checking "
                "three of the four bindings is not a weaker version of the check, it is "
                f"a different one [{RULE_APPROVAL_NOT_REPRODUCIBLE}]"
            ),
            remediation=(
                "pass the EnvironmentScope the run executes in — the same value the "
                "ApprovalGateInputs carried, not a string parsed from the gate result"
            ),
            triggers=(),
            inputs={"environment": result.environment},
        )

    replayed = evaluate_approvals(
        approvals,
        plan_digest=result.plan_digest,
        policy_digest=result.policy_digest,
        proof_digest=result.proof_digest,
        environment=environment,
        now=now,
        required_approvals=result.required,
        grants=grants,
        memberships=memberships,
        consumed_ids=consumed_ids,
        # Separation of duties names the *executor* as the plan's author, which is
        # what the gate does at admission; re-deriving it from the same two fields
        # is what keeps this a replay rather than a re-authorization.
        plan_author=(result.authorization.principal if result.separation_of_duties else None),
        separation_of_duties=result.separation_of_duties,
    )
    if not replayed.valid:
        return ApprovalRefusal(
            rule_id=RULE_APPROVAL_NOT_REPRODUCIBLE,
            reason=(
                f"the approvals that authorized this run no longer do at "
                f"{now.isoformat()} ({replayed.describe()}) [{RULE_APPROVAL_NOT_REPRODUCIBLE}]"
            ),
            remediation=(
                "re-approve against the current plan, policy, and proof digests; an "
                "approval that expired, was revoked, or names different digests cannot "
                "be sealed as this run's authority"
            ),
            triggers=order_reasons(set(replayed.reasons)),
            inputs={
                "at": now.isoformat(),
                "plan_digest": result.plan_digest,
                "policy_digest": result.policy_digest,
                "proof_digest": result.proof_digest,
                "environment": result.environment,
                "offered": len(approvals),
                "replayed_approvers": list(replayed.approvers),
                "gate_approvers": list(result.state.approvers),
                "reasons": [reason.value for reason in replayed.reasons],
                "discarded": [
                    {
                        "approval_id": discarded.approval_id,
                        "approver": discarded.approver,
                        "reasons": [reason.value for reason in discarded.reasons],
                    }
                    for discarded in replayed.discarded
                ],
            },
        )
    return None


# =============================================================================
# 2. The sealed authorization
# =============================================================================


def build_authorization(
    result: ApprovalGateResult,
    *,
    policy_decision: PolicyDecision,
    approvals: tuple[Approval, ...],
    plan_digest: str,
    now: datetime,
    environment: EnvironmentScope,
    grants: tuple[RoleGrant, ...] = (),
    memberships: tuple[Any, ...] = (),
    consumed_ids: frozenset[str] = frozenset(),
    proof_digest: str = "",
) -> RunAuthorization:
    """Build the :class:`RunAuthorization` for one approval-gated run.

    Refuses — rather than seals — on a denied gate, on approvals that no longer
    speak for the digests, and on a missing environment scope. See
    :func:`verify_approval_binding` for all three.

    ``plan_digest`` is passed through to :class:`RunAuthorization`, which
    compares it against the evidence envelope's ``plan_hash`` at seal time, so a
    decision pinned to one plan and evidence describing another is refused by
    plan 12's own rule rather than by a second one here.
    """
    binding = verify_approval_binding(
        result,
        now=now,
        approvals=approvals,
        environment=environment,
        grants=grants,
        memberships=memberships,
        consumed_ids=consumed_ids,
    )
    if binding is not None:
        raise ApprovalAuthorizationRefusedError(binding)
    return RunAuthorization(
        policy_decision=policy_decision,
        approval_state=result.state,
        plan_digest=plan_digest,
        proof_digest=proof_digest,
    )


# =============================================================================
# 3. Sealing
# =============================================================================


def seal_approval_decision(
    store: Any,
    envelope: EvidenceEnvelope,
    *,
    result: ApprovalGateResult,
    policy_decision: PolicyDecision,
    approvals: tuple[Approval, ...],
    plan_digest: str,
    run_status: str,
    now: datetime,
    environment: EnvironmentScope,
    grants: tuple[RoleGrant, ...] = (),
    memberships: tuple[Any, ...] = (),
    consumed_ids: frozenset[str] = frozenset(),
    verdict: str = "",
    proof_digest: str = "",
    audit: AuditStream | None = None,
    principal: str = "mayhem.controller",
    retention_class: RetentionClass | None = None,
    manifest_id: str = "",
    previous_manifest_digest: str = "",
    recorded_at: AttestedTimestamp | None = None,
) -> SealedRun:
    """Seal ``result`` into ``envelope``'s attested chain, via plan 12's sealer.

    Order is the point of this function, and it is fixed:

    1. :func:`build_authorization` refuses anything unfit to seal — before the
       store is touched at all.
    2. :func:`require_approval_records` refuses a run whose approvals authorized
       it but whose approval records are absent from the audit stream. This is
       the plan's acceptance criterion, and it runs **before** the seal so the
       gap is closed rather than reported.
    3. Only then does plan 12's ``seal_run_evidence_at_run_close`` run, which
       inserts the ``approval_evaluated`` event, verifies the chain, and writes.

    A refusal at either of the first two steps leaves the store exactly as it
    was. ``retention_class`` and ``previous_manifest_digest`` default to plan
    12's own defaults when left ``None``/empty, so this module does not restate
    another module's defaults.
    """
    authorization = build_authorization(
        result,
        policy_decision=policy_decision,
        approvals=approvals,
        plan_digest=plan_digest,
        now=now,
        environment=environment,
        grants=grants,
        memberships=memberships,
        consumed_ids=consumed_ids,
        proof_digest=proof_digest,
    )
    if audit is not None:
        require_approval_records(
            audit,
            approvals=approvals,
            run_id=envelope.run_id,
            result=result,
        )
    kwargs: dict[str, Any] = {}
    if retention_class is not None:
        kwargs["retention_class"] = retention_class
    if previous_manifest_digest:
        kwargs["previous_manifest_digest"] = previous_manifest_digest
    return seal_run_evidence_at_run_close(
        store,
        envelope,
        run_status=run_status,
        verdict=verdict,
        authorization=authorization,
        audit=audit,
        principal=principal,
        manifest_id=manifest_id,
        recorded_at=recorded_at,
        **kwargs,
    )


# =============================================================================
# Audit-trail completeness
# =============================================================================


@dataclass(frozen=True, slots=True)
class ApprovalRecordGap:
    """One approval the run was authorized by and the stream cannot account for.

    ``approval_digest`` is the record's own content digest, which is what the
    check compares. Matching on the approver's *name* would let an entry for
    one approval satisfy the requirement for a different one; matching on the
    digest cannot, because re-minting a changed approval changes the digest.
    """

    approval_id: str
    approver: str
    approval_digest: str
    reason: str

    def describe(self) -> str:
        return f"{self.approval_id} by {self.approver}: {self.reason}"


def approval_record_gaps(
    entries: tuple[AttestedEvent, ...],
    *,
    approvals: tuple[Approval, ...],
) -> tuple[ApprovalRecordGap, ...]:
    """Which approvals the stream does not account for, and why.

    Three requirements per approval, each with a distinct reason:

    * an ``audit.approval.granted`` entry naming this approval's **digest** —
      the grant itself;
    * an ``audit.approval.revoked`` entry naming the same digest, *only* when
      the approval is revoked. A revoked approval that authorized nothing is
      not required to be recorded here; one that is being sealed as authority
      with a revocation on record is refused by
      :func:`verify_approval_binding` before this runs, so this check is about
      the *grant* being on record;
    * an ``audit.approval.override_exercised`` entry, only for an override.

    Returns gaps rather than raising, so a caller can report all of them at
    once. Pure: it reads the entries it is handed and opens nothing.
    """
    granted = {
        str(event.payload.get("approval_digest", ""))
        for event in entries
        if event.event_kind == KIND_APPROVAL_GRANTED
    }
    revoked = {
        str(event.payload.get("approval_digest", ""))
        for event in entries
        if event.event_kind == KIND_APPROVAL_REVOKED
    }
    overrides = {
        str(event.payload.get("approval_digest", ""))
        for event in entries
        if event.event_kind == KIND_EMERGENCY_OVERRIDE_EXERCISED
    }
    gaps: list[ApprovalRecordGap] = []
    for approval in approvals:
        digest = approval.approval_digest
        if digest not in granted:
            gaps.append(
                ApprovalRecordGap(
                    approval_id=approval.approval_id,
                    approver=approval.approver.principal_id,
                    approval_digest=digest,
                    reason=(
                        f"no {KIND_APPROVAL_GRANTED} entry in the audit stream carries "
                        f"approval digest {digest[:12]}…"
                    ),
                )
            )
        if approval.revoked and digest not in revoked:
            gaps.append(
                ApprovalRecordGap(
                    approval_id=approval.approval_id,
                    approver=approval.approver.principal_id,
                    approval_digest=digest,
                    reason=(
                        f"the approval is revoked but no {KIND_APPROVAL_REVOKED} entry "
                        f"carries its digest {digest[:12]}…"
                    ),
                )
            )
        if approval.override and digest not in overrides:
            gaps.append(
                ApprovalRecordGap(
                    approval_id=approval.approval_id,
                    approver=approval.approver.principal_id,
                    approval_digest=digest,
                    reason=(
                        f"the approval is an emergency override but no "
                        f"{KIND_EMERGENCY_OVERRIDE_EXERCISED} entry carries its digest "
                        f"{digest[:12]}…"
                    ),
                )
            )
    return tuple(gaps)


def require_approval_records(
    audit: AuditStream,
    *,
    approvals: tuple[Approval, ...],
    run_id: str,
    result: ApprovalGateResult | None = None,
) -> None:
    """Refuse a run whose approval records are not in the audit stream.

    The plan's acceptance criterion in code: *"a run without a matching approval
    record is unrepresentable."* An approval's presence in the stream is checked
    by content digest, and the stream read is
    :meth:`AuditStream.entries_for_run`, so only entries naming this run count.

    ``result`` is accepted and used to tighten the check: when supplied, the
    approvals must cover the approvers the gate counted, so a caller cannot
    satisfy this by handing over a subset whose records all happen to be
    present. Omitting it weakens the check to "these approvals are on record",
    which is still a real check — the parameter is additive.
    """
    entries = audit.entries_for_run(run_id)
    if result is not None:
        counted = set(result.state.approvers)
        approvers = {approval.approver.principal_id for approval in approvals}
        missing = sorted(counted - approvers)
        if missing:
            raise ApprovalEvidenceError(
                f"refusing to seal run {run_id!r}: the gate counted approval(s) from "
                f"{missing}, and no such approval was supplied, so the run's authority "
                f"cannot be shown [{RULE_APPROVAL_NOT_REPRODUCIBLE}]"
            )
    gaps = approval_record_gaps(entries, approvals=approvals)
    if gaps:
        raise ApprovalEvidenceError(
            f"refusing to seal run {run_id!r}: the audit stream has no record of "
            f"{len(gaps)} approval(s) that authorized it — "
            + "; ".join(gap.describe() for gap in gaps)
        )


# =============================================================================
# Audit records for privileged identity actions
# =============================================================================


def _require_actor(principal: str, action: str) -> None:
    """Refuse an entry whose actor is blank or untrimmed.

    Same rule :class:`~mayhem.infra.audit_stream.AuditEntry` applies, checked
    here first so the message names *which* action was unattributed — a role
    grant issued by nobody is a different operational problem from an approval
    granted by nobody.
    """
    if not principal.strip():
        msg = (
            f"refusing to record {action}: it names no principal; an unattributed "
            "privileged action is not an audit record"
        )
        raise ApprovalEvidenceError(msg)
    if principal != principal.strip():
        msg = (
            f"refusing to record {action}: principal {principal!r} is untrimmed, and the "
            "stored entry would not match the actor it names"
        )
        raise ApprovalEvidenceError(msg)


def _approval_detail(approval: Approval) -> dict[str, Any]:
    """The approval facts an auditor asks for, and no credential material.

    ``approval_digest`` is on the entry itself (the
    :attr:`AuditEntry.approval_digest` column), not duplicated in ``detail``. The
    digests of what the approval binds travel in the detail because they are
    the *question* — "which plan did this approve?" — and the entry's own
    ``target`` names the approval.
    """
    return {
        "approval_id": approval.approval_id,
        "approver": approval.approver.principal_id,
        "approver_kind": approval.approver.kind.value,
        "environment": approval.environment.describe(),
        "plan_digest": approval.plan_digest,
        "policy_digest": approval.policy_digest,
        "proof_digest": approval.proof_digest,
        "issued_at": approval.issued_at.isoformat(),
        "expires_at": approval.expires_at.isoformat() if approval.expires_at else "",
        "change_tickets": [ticket.key for ticket in approval.change_tickets],
        "override": approval.override,
    }


def record_approval_granted(
    audit: AuditStream,
    approval: Approval,
    *,
    subject_run_id: str = "",
    reason: str = "",
    recorded_at: AttestedTimestamp | None = None,
) -> AttestedEvent:
    """Record that ``approval`` was granted.

    ``principal`` is the approver — the person who made the statement, not the
    person who asked for it. That distinction is the reason this is a function
    over an :class:`~mayhem.domain.approval.Approval` rather than a call a
    caller makes with its own name: the actor is a field of the record, and a
    caller cannot put someone else's name on it.

    ``subject_run_id`` is empty by default and often should be: an approval is
    granted against a *plan digest*, which may be approved long before any run
    exists. Binding it to a run that had not started yet would be the more
    misleading of the two.
    """
    detail = _approval_detail(approval)
    if reason:
        detail["reason"] = reason
    if approval.override:
        # The override's reason is mandatory at mint and travels in the record,
        # so copying it here costs nothing and means the audit stream alone can
        # answer "why did this bypass the quorum?" without the approval store.
        detail["override_reason"] = approval.override_reason
    return audit.record(
        AuditEntry(
            principal=approval.approver.principal_id,
            action=KIND_APPROVAL_GRANTED,
            target=approval.approval_id,
            subject_run_id=subject_run_id,
            policy_digest=approval.policy_digest,
            approval_digest=approval.approval_digest,
            decision_digest=approval.proof_digest,
            detail=detail,
        ),
        recorded_at=recorded_at,
    )


def record_approval_revoked(
    audit: AuditStream,
    approval: Approval,
    *,
    subject_run_id: str = "",
    reason: str = "",
    recorded_at: AttestedTimestamp | None = None,
) -> AttestedEvent:
    """Record that ``approval`` was revoked, naming who revoked it.

    ``principal`` is ``approval.revoked_by`` — the actor, not the approver.
    Recording the approver here would make a revocation look like the approver
    withdrawing their own statement, which is a different event.

    An approval with no revocation on it is refused: an entry asserting a
    revocation that did not happen is the same defect
    :func:`~mayhem.controller.policy_evidence.record_policy_bundle_change`
    refuses, and it is worse in an append-only log because there is no later
    entry to contradict it.
    """
    if not approval.revoked:
        raise ApprovalEvidenceError(
            f"refusing to record a revocation of approval {approval.approval_id!r}: it is "
            f"not revoked, so the entry would assert a change that did not happen "
            f"[{RULE_APPROVAL_AUDIT_UNCHANGED}]"
        )
    detail: dict[str, object] = {
        "approval_id": approval.approval_id,
        "approver": approval.approver.principal_id,
        "revoked_at": approval.revoked_at.isoformat() if approval.revoked_at else "",
        "revoked_by": approval.revoked_by,
    }
    if reason:
        detail["reason"] = reason
    return audit.record(
        AuditEntry(
            principal=approval.revoked_by,
            action=KIND_APPROVAL_REVOKED,
            target=approval.approval_id,
            subject_run_id=subject_run_id,
            policy_digest=approval.policy_digest,
            approval_digest=approval.approval_digest,
            detail=detail,
        ),
        recorded_at=recorded_at,
    )


def record_override_exercised(
    audit: AuditStream,
    approval: Approval,
    *,
    principal: str,
    run_id: str,
    reason: str = "",
    recorded_at: AttestedTimestamp | None = None,
) -> AttestedEvent:
    """Record that an emergency override was *used*, and by whom.

    Distinct from :func:`record_approval_granted` on purpose. Granting an
    override is minting a record; exercising one is a principal deciding to run
    a plan under it. The gate records both — the mint in the approval's own
    fields, the exercise in its ``approval.evaluated`` decision — but the audit
    stream is where a reader asks "who pressed the button", and that question is
    only answerable if the *use* is its own entry.

    ``principal`` is the principal who exercised the override, which is not
    necessarily the approver who minted it. Refused when blank.
    """
    if not approval.override:
        raise ApprovalEvidenceError(
            f"refusing to record an override exercise for approval "
            f"{approval.approval_id!r}: it is not an override, so the entry would assert "
            f"a bypass that did not happen [{RULE_APPROVAL_AUDIT_UNCHANGED}]"
        )
    _require_actor(principal, "an emergency override being exercised")
    if not run_id.strip():
        raise ApprovalEvidenceError(
            "refusing to record an override exercise with no run: an override with no "
            "run is not an exercise, and an unattributed override cannot be reviewed"
        )
    detail: dict[str, object] = {
        "approval_id": approval.approval_id,
        "approver": approval.approver.principal_id,
        "environment": approval.environment.describe(),
        "override_reason": approval.override_reason,
        "plan_digest": approval.plan_digest,
    }
    if reason:
        detail["exercise_reason"] = reason
    return audit.record(
        AuditEntry(
            principal=principal,
            action=KIND_EMERGENCY_OVERRIDE_EXERCISED,
            target=approval.approval_id,
            subject_run_id=run_id,
            policy_digest=approval.policy_digest,
            approval_digest=approval.approval_digest,
            decision_digest=approval.proof_digest,
            detail=detail,
        ),
        recorded_at=recorded_at,
    )


def record_role_grant_issued(
    audit: AuditStream,
    grant: RoleGrant,
    *,
    principal: str,
    reason: str = "",
    recorded_at: AttestedTimestamp | None = None,
) -> AttestedEvent:
    """Record a role being granted to a principal or a team.

    ``principal`` is whoever *issued* the grant, which
    :attr:`~mayhem.domain.identity.RoleGrant.granted_by` also names. They are
    separate parameters because the grant's field is optional and this entry's
    is not: a grant with no ``granted_by`` is constructible (Phase 1 does not
    require it), but recording it as a privileged action without an actor is
    refused.

    The target names *what was granted and where*, because an auditor filtering
    the stream by target is asking "who can execute in prod?" — and an entry
    whose target is only the addressee answers a different question.
    """
    _require_actor(principal, f"role {grant.role.value} being granted")
    detail: dict[str, Any] = {
        "role": grant.role.value,
        "addressee": grant.addressee,
        "addressed_to": "principal" if grant.principal is not None else "team",
        "environment": grant.scope.describe(),
        "granted_at": grant.granted_at.isoformat(),
        "expires_at": grant.expires_at.isoformat() if grant.expires_at else "",
        "change_ticket": grant.change_ticket,
        "granted_by_recorded": grant.granted_by,
    }
    if reason:
        detail["reason"] = reason
    return audit.record(
        AuditEntry(
            principal=principal,
            action=KIND_ROLE_GRANT_ISSUED,
            target=f"{grant.role.value}@{grant.scope.describe()}",
            detail=detail,
        ),
        recorded_at=recorded_at,
    )


def record_role_grant_revoked(
    audit: AuditStream,
    *,
    role: str,
    scope: str,
    addressee: str,
    principal: str,
    reason: str = "",
    recorded_at: AttestedTimestamp | None = None,
) -> AttestedEvent:
    """Record a role grant being withdrawn.

    Takes the four facts a revoked grant can still be described by, because
    :class:`~mayhem.domain.identity.RoleGrant` is immutable and the withdrawn
    grant is gone from the store — an entry written afterwards has nothing to
    read it from. That is the reason this signature is four strings where
    :func:`record_role_grant_issued` takes the object, and it is a real
    asymmetry rather than an inconsistency.

    Every field is required and refused when blank except ``reason``: a
    withdrawal with no role, scope, or addressee names nothing, and "the admin
    grant in prod was withdrawn" is not a record an auditor can act on.
    """
    _require_actor(principal, f"role {role or '(unnamed)'} being revoked")
    for name, value in (("role", role), ("scope", scope), ("addressee", addressee)):
        if not value.strip():
            raise ApprovalEvidenceError(
                f"refusing to record a role revocation with no {name}: the entry must "
                f"name what was withdrawn, or a reader cannot tell which grant ended "
                f"[{RULE_APPROVAL_AUDIT_UNATTRIBUTED}]"
            )
    detail: dict[str, Any] = {
        "role": role,
        "addressee": addressee,
        "environment": scope,
    }
    if reason:
        detail["reason"] = reason
    return audit.record(
        AuditEntry(
            principal=principal,
            action=KIND_ROLE_GRANT_REVOKED,
            target=f"{role}@{scope}",
            detail=detail,
        ),
        recorded_at=recorded_at,
    )


def record_principal_disabled(
    audit: AuditStream,
    principal_record: Principal,
    *,
    revoked_by: str,
    reason: str,
    recorded_at: AttestedTimestamp | None = None,
) -> AttestedEvent:
    """Record a principal being disabled and every credential revoked with it.

    ``reason`` is required, not optional. ``AuthService.disable_principal``
    already demands an actor; this adds the *why*, because disabling a principal
    is the action most likely to be regretted later and the one whose audit
    entry is read months afterwards by whoever is asking "why can't I log in?".

    The entry names the target as the principal id, and the detail carries the
    principal's kind and display name so an auditor reading the stream months
    later can tell *which* person it was even if the principal row is gone.
    """
    _require_actor(revoked_by, f"principal {principal_record.principal_id} being disabled")
    if not reason.strip():
        raise ApprovalEvidenceError(
            f"refusing to record {principal_record.principal_id!r} being disabled with no "
            f"reason: disabling an account is the action most often regretted later, and "
            f"an unexplained one cannot be told apart from a mistake "
            f"[{RULE_APPROVAL_AUDIT_UNATTRIBUTED}]"
        )
    if not principal_record.disabled:
        raise ApprovalEvidenceError(
            f"refusing to record {principal_record.principal_id!r} being disabled: the "
            f"principal is not disabled, so the entry would assert a change that did not "
            f"happen [{RULE_APPROVAL_AUDIT_UNCHANGED}]"
        )
    return audit.record(
        AuditEntry(
            principal=revoked_by,
            action=KIND_PRINCIPAL_DISABLED,
            target=principal_record.principal_id,
            detail={
                "principal_id": principal_record.principal_id,
                "principal_kind": principal_record.kind.value,
                "display_name": principal_record.display_name,
                "reason": reason,
            },
        ),
        recorded_at=recorded_at,
    )
