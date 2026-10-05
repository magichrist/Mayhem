"""Plan 07 Phase 4 — sealing the policy decision, and recording what changed it.

Phase 2's gate produced a :class:`~mayhem.domain.policy_gate.PolicyGateResult`
and stopped there. The result was reachable, reproducible, and *undiscoverable*:
nothing wrote it down, so "why was this plan allowed?" was answerable only by
re-running the gate against inputs that might since have changed. This module is
the seam where a decision stops being a return value and becomes a record.

Three jobs, and a refusal for each
------------------------------------

**1. Bind the decision to the bundle before it can be sealed.**
:func:`verify_decision_binding` re-derives the bundle's digest and compares it
against the decision's ``policy_digest``. A record whose decision was reached
under a different bundle, a different bundle *version*, or under no rule set at
all is refused here rather than sealed with a confident-looking wrong pin. This
is the same shape as
:class:`~mayhem.infra.attestation_store.AuthorizationMismatchError` — refusing at
the one point where both values are in hand, not recording and noticing later —
and it is the negative control for "a decision's digest must agree with its
bundle".

**2. Put the decision in the sealed chain.** :func:`seal_policy_decision` builds a
:class:`~mayhem.infra.attestation_store.RunAuthorization` and hands it to
:func:`~mayhem.infra.attestation_store.seal_run_evidence`, which inserts the
``policy_decided`` event into the run's attested chain. Nothing here mints an
event type, a digest, a manifest, or a seal: plan 12 already owns all of that,
and this module's entire contribution is refusing the inputs that would make the
sealed answer a lie. The bundle *version* rides inside the event payload as part
of ``policy_bundle``, alongside the decision, rule, and facts digests.

**3. Record a policy VERSION CHANGE in the audit stream.**
:func:`record_policy_bundle_change` appends a privileged-action entry to
:class:`~mayhem.infra.audit_stream.AuditStream`. A decision is per-run and belongs
in that run's chain; a version change is cross-run, changes what *every future*
decision means, and belongs in the stream that spans runs. The distinction is the
same one the audit stream's module docstring draws for its own actions.

Why the audit action constant is re-exported here
---------------------------------------------------

:mod:`mayhem.infra.audit_stream` owns the closed ``KIND_*`` table, and
:data:`KIND_POLICY_VERSION_CHANGED` is a member of it — declared there, with its
``audit.policy.*`` namespace and its one spelling. It was originally declared in
this module because the audit module was not plan 07's to edit; that deferral is
over, so the definition has moved to its owner.

The *name* did not move. It is imported here and stays in this module's namespace,
so every existing ``mayhem.controller.policy_evidence.KIND_POLICY_VERSION_CHANGED``
import keeps resolving unchanged. There is one declaration of the action's string
in the repository and one exported name at each of its two import paths — a move,
not a copy. ``tests/unit/test_audit_kind_ownership.py`` fails if this module ever
defines the constant again, and
``tests/unit/test_policy_evidence.py`` covers the entry it produces.

What this does NOT do
---------------------

* **It does not post a budget charge.** Phase 2's probe-then-commit shape is still
  probe-only: spending a ledger is a write, and this module's other two jobs
  already take a store. The reconciliation decision (which budget system wins)
  lives in :func:`~mayhem.domain.policy_gate.reconcile_budgets`, not here.
* **It does not sign anything.** Every artifact it produces is integrity-chained
  and *named*, never authenticated — no key material exists yet. A reader must
  treat the sealed chain as proof that the recorded bytes were unaltered and in
  order, and as no proof at all about who wrote them.
* **It does not verify approvals.** :func:`build_authorization` takes an
  :class:`~mayhem.domain.approval.ApprovalState` the caller already obtained from
  :mod:`mayhem.controller.approval_gate`. Re-deriving an approval verdict here
  would be a second implementation of a gate that already has one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mayhem.domain.attestation import GENESIS_DIGEST, RetentionClass
from mayhem.domain.errors import DomainError
from mayhem.domain.hashing import canonical_json, sha256_hex
from mayhem.domain.policy_gate import PolicyRefusal
from mayhem.infra.attestation_store import RunAuthorization

#: Re-exported, not declared: the action kind lives in the audit stream's ``KIND_*``
#: table, which this module does not own. Kept in this namespace so existing
#: callers keep importing it from here.
#:
#: The redundant alias is deliberate and is the PEP 484 explicit-re-export idiom,
#: not a mistake: this module has no ``__all__``, so without it a type checker
#: running with ``--no-implicit-reexport`` (the setting this repository uses) would
#: treat the name as private and fail every caller's import. ``PLC0414`` objects to
#: exactly that idiom, hence the suppression on the one line.
from mayhem.infra.audit_stream import (
    KIND_POLICY_VERSION_CHANGED as KIND_POLICY_VERSION_CHANGED,  # noqa: PLC0414
)
from mayhem.infra.audit_stream import (
    AuditEntry,
    seal_run_evidence_at_run_close,
)

if TYPE_CHECKING:
    from datetime import datetime

    from mayhem.domain.approval import ApprovalState
    from mayhem.domain.attestation import AttestedEvent, AttestedTimestamp
    from mayhem.domain.evidence import EvidenceEnvelope
    from mayhem.domain.policy import PolicyBundle, PolicyDecision
    from mayhem.domain.policy_gate import PolicyGateResult
    from mayhem.infra.attestation_store import SealedRun
    from mayhem.infra.audit_stream import AuditStream
    from mayhem.infra.store import Store

#: A decision whose digests do not agree with the bundle it claims to come from.
RULE_DECISION_BINDING = "policy.decision_bundle_mismatch"
#: The bundle cannot authorize this run as of the instant being sealed.
RULE_BUNDLE_CANNOT_AUTHORIZE = "policy.bundle_cannot_authorize"
#: The gate refused the plan; a refusal may be sealed but never authorized.
RULE_DECISION_DENIED = "policy.decision_denied"
#: The policy configuration could not be evaluated, so there is nothing to attest.
RULE_CONFIG_DEFECT = "policy.config_unattestable"


class PolicyEvidenceError(DomainError):
    """The evidence seam refused. Nothing was written."""


class PolicyAuthorizationRefusedError(PolicyEvidenceError):
    """A typed refusal from the evidence seam, carrying the gate's own vocabulary.

    Not an admission refusal — nothing about *this plan* is wrong — but shaped
    like one (it holds a :class:`~mayhem.domain.policy_gate.PolicyRefusal`) so
    the rule id, reason, and remediation are the same three things a caller reads
    everywhere else, and so :func:`build_authorization`'s refusal can be recorded
    verbatim by a caller that would rather log the gap than traceback it.
    """

    def __init__(self, refusal: PolicyRefusal) -> None:
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
# Binding a decision to its bundle
# =============================================================================


def _binding_refusal(
    rule_id: str, reason: str, remediation: str, inputs: dict[str, Any] | None = None
) -> PolicyRefusal:
    """An evidence-seam refusal in the gate's shape, with the rule id echoed.

    The rule id appears in the reason text as well as on the field, for the same
    reason every other refusal in this codebase does it: a log line and a query
    then cannot disagree about which rule spoke.
    """
    return PolicyRefusal(
        rule_id=rule_id,
        reason=f"{reason} [{rule_id}]",
        remediation=remediation,
        inputs=inputs or {},
    )


def verify_decision_binding(
    decision: PolicyDecision, bundle: PolicyBundle, *, now: datetime | None = None
) -> PolicyRefusal | None:
    """Whether ``decision`` may be sealed as a decision *about* ``bundle``.

    Four checks, in order of how fundamental they are:

    1. **Identity.** ``bundle_id`` and ``version`` must be the bundle's. A
       decision is a statement about one version of one bundle; a record that
       named the version it was reached under is useless for replay, which is the
       whole point of sealing it.
    2. **Content.** ``policy_digest`` must equal ``bundle.compute_digest()``
       re-derived *now*, not merely be well-formed. This is the check that cannot
       be faked by a caller assembling a decision by hand: a decision reached
       under an earlier bundle version carries that version's digest, and the
       re-derivation disagrees.
    3. **Resolution.** ``rule_digest`` must be non-empty. An empty one means no
       rule set was ever resolved — which is what a
       :class:`~mayhem.domain.policy_gate.ConfigDefect` produces — and there
       is then no statement to seal, only the fact that the gate could not read
       its configuration.
    4. **Currency.** When ``now`` is supplied the bundle must still authorize it.
       ``evaluate_gate`` already refuses an expired bundle, so this is the
       second place the same rule is enforced, and it exists because a caller can
       hand this function a decision it built at any time: sealing a decision made
       by a version that has since expired would let a run's evidence answer "why
       was this allowed?" with a rule set that no longer speaks.

    Returns ``None`` when the binding holds, and a refusal naming the specific
    disagreement when it does not.
    """
    if decision.bundle_id != bundle.bundle_id or decision.bundle_version != bundle.version:
        return _binding_refusal(
            RULE_DECISION_BINDING,
            f"policy decision records {decision.describe()} but the bundle supplied is "
            f"{bundle.describe()}",
            "seal the decision with the bundle it was actually reached under; a "
            "decision for one policy version does not describe another",
            {
                "decision_bundle": decision.describe(),
                "supplied_bundle": bundle.describe(),
            },
        )
    expected = bundle.compute_digest()
    if decision.policy_digest != expected:
        return _binding_refusal(
            RULE_DECISION_BINDING,
            f"policy decision for {bundle.describe()} carries policy digest "
            f"{decision.policy_digest or '(empty)'} but the bundle hashes to {expected}",
            "seal the decision produced by the bundle whose content digest is "
            f"{expected[:12]}; a decision whose digest disagrees with its bundle "
            "cannot say which rules produced it",
            {
                "decision_policy_digest": decision.policy_digest,
                "bundle_policy_digest": expected,
            },
        )
    if not decision.rule_digest:
        return _binding_refusal(
            RULE_CONFIG_DEFECT,
            f"policy decision for {bundle.describe()} has no rule digest, so no rule "
            "set was resolved behind it",
            "fix the policy configuration first — "
            + (
                f"{decision.reasons[0]}"
                if decision.reasons
                else "the gate refused before any rule could speak"
            )
            + " — then re-run admission; there is no rule set to attest until then",
            {"bundle": bundle.describe()},
        )
    if now is not None and not bundle.authorizes(now):
        return _binding_refusal(
            RULE_BUNDLE_CANNOT_AUTHORIZE,
            f"policy bundle {bundle.describe()} expired at "
            f"{bundle.expires_at.isoformat() if bundle.expires_at else '?'}",
            "pin a newer bundle version before sealing; an expired policy version "
            "cannot authorize a run, and a run cannot cite one as its authority",
            {"bundle": bundle.describe(), "now": now.isoformat()},
        )
    return None


def build_authorization(
    result: PolicyGateResult,
    *,
    approval_state: ApprovalState,
    plan_digest: str,
    proof_digest: str = "",
) -> RunAuthorization:
    """The sealed-chain input for one policy decision, or a typed refusal.

    Refuses — rather than seals — on four things, each of which would put a
    confident lie in the chain:

    * a **denied** result. A refusal is evidence and may be *recorded*, but a
      ``RunAuthorization`` is the object that says this run was allowed, and a
      denied plan has no authorization to record. Callers that want the refusal in
      the log read :attr:`PolicyGateResult.refusal` and record it themselves.
    * a **config defect**, checked before the generic denial check so the message
      names the real problem (an unreadable policy layer) rather than the
      consequence of it (a deny).
    * a **binding disagreement**, via :func:`verify_decision_binding` at
      ``result``'s own clock.
    * **missing bundle**. A hand-built result that omits the bundle cannot be
      bound to anything, and a check that is skipped when the artifact is absent
      is not a check.

    ``plan_digest`` is passed through to :class:`RunAuthorization`, which
    compares it against the evidence envelope's ``plan_hash`` at seal time — so a
    policy decision pinned to one plan and evidence describing another is refused
    by plan 12's own rule, not by a second one here.
    """
    if result.config_defect is not None:
        raise PolicyAuthorizationRefusedError(
            _binding_refusal(
                RULE_CONFIG_DEFECT,
                f"policy configuration for "
                f"{result.config_defect.inputs.get('bundle', 'the bundle')} could not be "
                f"evaluated ({result.config_defect.defect.value})",
                result.config_defect.remediation,
                {"config_defect": result.config_defect.defect.value},
            )
        )
    if result.denied:
        refusal = result.refusal
        assert refusal is not None  # `denied` is exactly `refusal is not None`
        raise PolicyAuthorizationRefusedError(
            _binding_refusal(
                RULE_DECISION_DENIED,
                f"policy refused this plan: {refusal.reason}",
                "seal only decisions that authorized the run; the refusal itself is "
                f"recorded by the caller as {refusal.rule_id}",
                {"refusal_rule_id": refusal.rule_id, **refusal.inputs},
            )
        )
    if result.bundle is None:
        raise PolicyAuthorizationRefusedError(
            _binding_refusal(
                RULE_DECISION_BINDING,
                "policy result carries no bundle, so its decision cannot be bound to "
                "a policy version",
                "pass the bundle the decision was reached under; an unbound decision "
                "cannot be sealed, because nothing about it can be re-derived later",
            )
        )
    binding = verify_decision_binding(result.decision, result.bundle, now=result.now)
    if binding is not None:
        raise PolicyAuthorizationRefusedError(binding)
    return RunAuthorization(
        policy_decision=result.decision,
        approval_state=approval_state,
        plan_digest=plan_digest,
        proof_digest=proof_digest,
    )


# =============================================================================
# The sealed record
# =============================================================================


def policy_evidence(result: PolicyGateResult) -> dict[str, Any]:
    """The gate's whole answer as one sealed payload.

    Everything an auditor needs to re-derive or challenge the verdict: the
    decision and its three digests, the bundle id and version, the budget
    conjunction (both systems' numbers and which one reported), the approvals the
    decision asked for, the compatibility outcomes, and the pending charges a
    commit would post. ``sealed_digest`` is taken over every other key, so an
    edited record is detectable by recomputing it — the same shape
    :meth:`~mayhem.controller.approval_gate.ApprovalGateResult.evidence` uses, and
    for the same reason.

    A refusal is inside the payload too. A plan that was refused is exactly the
    plan whose evidence is most worth keeping.
    """
    payload: dict[str, Any] = {
        "allowed": result.allowed,
        "simulated": result.simulated,
        "decided_at": result.now.isoformat() if result.now is not None else "",
        "decision": result.decision.model_dump(mode="json"),
        "decision_digest": result.decision.decision_digest(),
        "bundle": result.bundle.describe() if result.bundle is not None else "",
        "bundle_version": result.bundle.version if result.bundle is not None else 0,
        "bundle_digest": result.decision.policy_digest,
        "facts_digest": result.facts.facts_digest(),
        "facts": {
            dimension.value: sorted(values)
            for dimension, values in sorted(
                result.facts.values.items(), key=lambda item: item[0].value
            )
        },
        "budget": result.budget.inputs() if result.budget is not None else {},
        "pending_charges": [
            f"{charge.scope.value}:{charge.key}={charge.after_s}"
            for charge in result.pending_charges
        ],
        "compatibility": [outcome.describe() for outcome in result.compatibility],
        "required_approvals": [
            {
                "approval_level": approval.approval_level,
                "rule_id": approval.rule_id,
                "reason": approval.reason,
                "remediation": approval.remediation,
            }
            for approval in result.required_approvals
        ],
        "locks": [
            {
                "resource": verdict.resource,
                "granted": verdict.granted,
                "requested_by": verdict.requested_by,
                "blockers": list(verdict.blockers),
            }
            for verdict in result.lock_verdicts
        ],
        "config_defect": (
            "" if result.config_defect is None else result.config_defect.describe()
        ),
        "refusal": None
        if result.refusal is None
        else {
            "rule_id": result.refusal.rule_id,
            "reason": result.refusal.reason,
            "remediation": result.refusal.remediation,
            "inputs": result.refusal.inputs,
        },
    }
    return {**payload, "sealed_digest": sha256_hex(canonical_json(payload))}


def seal_policy_decision(
    store: Store,
    result: PolicyGateResult,
    envelope: EvidenceEnvelope,
    *,
    approval_state: ApprovalState,
    plan_digest: str,
    run_status: str,
    verdict: str = "",
    proof_digest: str = "",
    retention_class: RetentionClass = RetentionClass.HOT,
    manifest_id: str = "",
    previous_manifest_digest: str = GENESIS_DIGEST,
    recorded_at: AttestedTimestamp | None = None,
    audit: AuditStream | None = None,
    principal: str = "mayhem.controller",
) -> SealedRun:
    """Seal ``result`` into ``envelope``'s attested chain, via plan 12's sealer.

    This is a thin, honest wrapper: it builds the
    :class:`~mayhem.infra.attestation_store.RunAuthorization` that plan 12 already
    knows how to seal, and hands the result to
    :func:`~mayhem.infra.attestation_store.seal_run_evidence`, which inserts the
    ``policy_decided`` and ``approval_evaluated`` events between the evidence and
    closure events and verifies the chain before a single row is written.

    The only reason it exists rather than being two lines at the call site is the
    refusal: :func:`build_authorization` raises
    :class:`PolicyAuthorizationRefusedError` for every way a decision can be unfit to
    seal, so that check cannot be forgotten at a call site that has a store in
    hand and an incentive to seal anyway.

    ``audit`` is passed through to plan 12's run-close seam, which records the seal
    itself. Recording the *decision* is what this function adds; recording the
    *version change* that would change what the decision means is
    :func:`record_policy_bundle_change`.
    """
    authorization = build_authorization(
        result,
        approval_state=approval_state,
        plan_digest=plan_digest,
        proof_digest=proof_digest,
    )
    return seal_run_evidence_at_run_close(
        store,
        envelope,
        run_status=run_status,
        verdict=verdict,
        authorization=authorization,
        audit=audit,
        principal=principal,
        retention_class=retention_class,
        manifest_id=manifest_id,
        previous_manifest_digest=previous_manifest_digest,
        recorded_at=recorded_at,
    )


# =============================================================================
# Version changes
# =============================================================================


def record_policy_bundle_change(
    audit: AuditStream,
    *,
    principal: str,
    previous: PolicyBundle,
    current: PolicyBundle,
    subject_run_id: str = "",
    reason: str = "",
    recorded_at: AttestedTimestamp | None = None,
) -> AttestedEvent:
    """Record that the policy a decision is read against changed.

    A privileged action, in the audit stream rather than in any run's chain: a
    decision is about one run, and a version change is about every decision not yet
    reached. An auditor asking "which rules did run *r* actually see?" needs the
    run's chain; an auditor asking "who changed the policy under us, and when?"
    needs the stream, and no run's chain can answer it.

    Both digests are recorded, old and new, because one alone cannot show that a
    *change* happened — a new digest with no predecessor proves something was
    published, not what it replaced. ``subject_run_id`` is left empty by default:
    a bundle change usually predates every run it affects, so binding it to one run
    would be wrong more often than right.

    Refuses when nothing changed. A "version change" with an identical id, version
    and content is a re-write of the same policy, and recording it would inflate
    the stream's entry count with an event that says no such thing happened.

    The entry goes through :meth:`AuditStream.record`, which enforces
    append-only, re-verifies the chain before extending it, and runs the same
    evidence-boundary secret gate every other write path runs. No bypass.
    """
    if (
        previous.bundle_id == current.bundle_id
        and previous.version == current.version
        and previous.compute_digest() == current.compute_digest()
    ):
        raise PolicyEvidenceError(
            f"refusing to record a policy version change for {current.describe()}: "
            f"nothing changed (id, version and content digest are all identical); an "
            "audit entry asserting a change that did not happen is worse than no entry"
        )
    detail: dict[str, object] = {
        "previous_bundle": previous.describe(),
        "previous_version": previous.version,
        "previous_digest": previous.compute_digest(),
        "current_bundle": current.describe(),
        "current_version": current.version,
        "current_digest": current.compute_digest(),
    }
    if previous.bundle_id != current.bundle_id:
        # Not a version change of the same bundle: say so rather than let a
        # reader infer an upgrade from two unrelated ids.
        detail["bundle_id_changed"] = True
    if reason:
        detail["reason"] = reason
    return audit.record(
        AuditEntry(
            principal=principal,
            action=KIND_POLICY_VERSION_CHANGED,
            target=current.describe(),
            subject_run_id=subject_run_id,
            policy_digest=current.compute_digest(),
            detail=detail,
        ),
        recorded_at=recorded_at,
    )
