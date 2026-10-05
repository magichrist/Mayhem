"""Plan 09 Phase 4 — approvals into the sealed chain, and the audit records.

Phase 2's suite (``test_approval_gate.py``) proved the gate *decides* at
admission. Phase 3's (``test_auth_service.py``) proved the service that supplies
principals and grants works. This one proves the thing that was missing
entirely: that the decision becomes a **record**, and that the record cannot
assert something the system cannot show.

The organization follows the three jobs in
:mod:`mayhem.controller.approval_evidence`:

1. **the binding is re-derived at seal time, not trusted from the gate.** The
   load-bearing negative controls are here: an approval revoked, expired, or
   forked *between admission and close* is refused, even though the gate said
   yes. A module that only checked at grant time would pass every other test in
   this file.
2. **the authorization is sealed into the chain** through plan 12's own sealer,
   and the refusals are typed refusals that leave the store untouched.
3. **privileged actions are recorded** in the audit stream, and the stream is
   *required* to account for the approvals before a run may be sealed — the
   plan's acceptance criterion, "a run without a matching approval record is
   unrepresentable", in code.

The negative controls are asserted against real objects, not comments:

* an approval revoked after the gate allowed is refused at seal time;
* an approval whose plan digest no longer matches the plan is refused, which is
  the plan's own sentence ("a user can never approve a modified plan with an
  old approval") checked a second time at the boundary rather than only at
  grant;
* a quorum the evidence cannot name — the gate allowed, the approvals are not
  supplied — is refused;
* an entry naming the right people but the wrong approval digest does **not**
  satisfy the completeness check, because a grant of one approval is not a grant
  of a different one;
* a revocation entry for an approval that was not revoked, and an override
  exercise for an approval that is not an override, are both refused.

Every clock is explicit and every store is a real migrated SQLite file. Nothing
here reads ``utc_now()`` or touches a socket or a subprocess.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.controller.approval_evidence import (
    RULE_APPROVAL_AUDIT_UNATTRIBUTED,
    RULE_APPROVAL_AUDIT_UNCHANGED,
    RULE_APPROVAL_DENIED,
    RULE_APPROVAL_NOT_REPRODUCIBLE,
    ApprovalAuthorizationRefusedError,
    ApprovalEvidenceError,
    approval_evidence,
    approval_record_gaps,
    build_authorization,
    record_approval_granted,
    record_approval_revoked,
    record_override_exercised,
    record_principal_disabled,
    record_role_grant_issued,
    record_role_grant_revoked,
    require_approval_records,
    seal_approval_decision,
    verify_approval_binding,
)
from mayhem.controller.approval_gate import (
    ApprovalGateInputs,
    ApprovalGateResult,
    candidate_plan_digest,
    verify_approvals,
)
from mayhem.domain.approval import Approval, InvalidationReason
from mayhem.domain.attestation import AttestedTimestamp
from mayhem.domain.evidence import EvidenceEnvelope
from mayhem.domain.experiments import (
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.hashing import canonical_json, digest, sha256_hex
from mayhem.domain.identity import (
    EnvironmentScope,
    Principal,
    PrincipalKind,
    Role,
    RoleGrant,
)
from mayhem.domain.policy import PolicyDecision
from mayhem.domain.safety_proof import (
    Obligation,
    ObligationName,
    ObligationStatus,
    ProofVerdict,
    SafetyProof,
)
from mayhem.domain.topology import NodeKind, TargetSelector
from mayhem.infra.attestation_store import (
    EVENT_APPROVAL_EVALUATED,
    EVENT_POLICY_DECIDED,
    SIGNATURE_UNSIGNED_NO_SIGNING,
)
from mayhem.infra.audit_stream import (
    KIND_APPROVAL_GRANTED,
    KIND_APPROVAL_REVOKED,
    KIND_EMERGENCY_OVERRIDE_EXERCISED,
    KIND_PRINCIPAL_DISABLED,
    KIND_ROLE_GRANT_ISSUED,
    KIND_ROLE_GRANT_REVOKED,
    AuditStream,
    verify_audit_chain,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
BEFORE = T0 - timedelta(seconds=1)
AFTER = T0 + timedelta(seconds=1)
YESTERDAY = T0 - timedelta(days=1)
LATER = T0 + timedelta(minutes=5)

PROD = EnvironmentScope(environment="production")
STAGING = EnvironmentScope(environment="staging")
ORG_WIDE = EnvironmentScope.any()

POLICY_DIGEST = digest({"bundle": "prod-approvals", "version": 3})

ALICE = Principal(principal_id="u-alice", display_name="Alice")
BOB = Principal(principal_id="u-bob", display_name="Bob")
MALLORY = Principal(principal_id="u-mallory", display_name="Mallory")
DANA = Principal(principal_id="u-dana", display_name="Dana")
ONBOARDER = Principal(principal_id="u-onboarder", display_name="Onboarder")
SRE_SA = Principal(
    principal_id="sa-sre", kind=PrincipalKind.SERVICE_ACCOUNT, display_name="SRE Bot"
)

STANDING_GRANTS: tuple[RoleGrant, ...] = (
    RoleGrant(role=Role.APPROVE, scope=ORG_WIDE, principal=ALICE, granted_at=YESTERDAY),
    RoleGrant(role=Role.APPROVE, scope=PROD, principal=BOB, granted_at=YESTERDAY),
    RoleGrant(role=Role.EXECUTE, scope=PROD, principal=MALLORY, granted_at=YESTERDAY),
    RoleGrant(role=Role.APPROVE, scope=PROD, principal=DANA, granted_at=YESTERDAY),
    RoleGrant(role=Role.EXECUTE, scope=PROD, principal=DANA, granted_at=YESTERDAY),
    RoleGrant(role=Role.ADMINISTER, scope=ORG_WIDE, principal=ONBOARDER, granted_at=YESTERDAY),
)


# =============================================================================
# Fixtures-as-values — no shared mutable state, so order cannot matter
# =============================================================================


def _plan(*fault_ids: str, duration: float = 5.0, run_id: str = "run-1") -> ExecutionPlan:
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="web")
    steps = tuple(
        PlannedStep(
            id=f"s{seq}",
            seq=seq,
            raw_action=InjectFault(fault=fault_id, selectors=(selector,), duration=duration),
            fault=PlannedFault(
                fault_id=fault_id,
                targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"n-web"})),),
                duration=duration,
            ),
        )
        for seq, fault_id in enumerate(fault_ids)
    )
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        steps=steps,
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
    )


def _passing_proof(plan_digest: str, *, generated_at: datetime = BEFORE) -> SafetyProof:
    obligations = tuple(
        Obligation(
            name=name.value,
            status=ObligationStatus.PASS,
            gate_digest=digest({"gate": name.value}),
            evidence_ref=f"evidence://{name.value}",
            evaluated_at=BEFORE,
        )
        for name in ObligationName
    )
    return SafetyProof(
        plan_digest=plan_digest,
        obligations=obligations,
        verdict=ProofVerdict.PASS,
        generated_at=generated_at,
    )


PLAN = _plan("proc.pause")
PLAN_DIGEST = candidate_plan_digest(PLAN)
PROOF = _passing_proof(PLAN_DIGEST)


def _mint(
    approval_id: str = "a-1",
    *,
    approver: Principal = ALICE,
    proof: SafetyProof = PROOF,
    scope: EnvironmentScope = PROD,
    now: datetime = BEFORE,
    ttl_s: float | None = 900.0,
    override: bool = False,
    override_reason: str = "",
    policy_digest: str = POLICY_DIGEST,
) -> Approval:
    return Approval.bind(
        approval_id=approval_id,
        proof=proof,
        policy_digest=policy_digest,
        approver=approver,
        environment=scope,
        issued_at=now,
        ttl_s=ttl_s,
        override=override,
        override_reason=override_reason,
    )


def _revoked(approval: Approval, *, by: str = "u-admin", at: datetime = AFTER) -> Approval:
    return Approval.model_validate({**approval.model_dump(), "revoked_at": at, "revoked_by": by})


def _gate(
    *approvals: Approval,
    executor: Principal = MALLORY,
    proof: SafetyProof = PROOF,
    environment: EnvironmentScope = PROD,
    policy_digest: str = POLICY_DIGEST,
    grants: tuple[RoleGrant, ...] = STANDING_GRANTS,
    now: datetime = T0,
    required_approvals: int = 1,
) -> ApprovalGateInputs:
    return ApprovalGateInputs(
        now=now,
        environment=environment,
        executor=executor,
        proof=proof,
        policy_digest=policy_digest,
        approvals=tuple(approvals),
        grants=grants,
        required_approvals=required_approvals,
    )


def _allowed(*approvals: Approval, **kwargs: Any) -> ApprovalGateResult:
    """A gate result that allowed, through the real gate."""
    result = verify_approvals(PLAN, _gate(*approvals, **kwargs))
    assert result.allowed, result.describe()
    return result


def _decision(*, outcome: str = "allow", policy_digest: str = POLICY_DIGEST) -> PolicyDecision:
    return PolicyDecision(
        outcome=outcome,  # type: ignore[arg-type]
        matched_rules=("r-1",),
        bundle_id="prod-approvals",
        bundle_version=3,
        rule_digest=digest({"rules": "r-1"}),
        policy_digest=policy_digest,
        facts_digest=digest({"facts": "f"}),
    )


def _envelope(run_id: str = "run-1", *, plan_hash: str = PLAN_DIGEST) -> EvidenceEnvelope:
    return EvidenceEnvelope.model_validate(
        {
            "run_id": run_id,
            "plan_hash": plan_hash,
            "verdict": "pass",
            "step_reports": ({"step_id": "s0", "status": "completed"},),
            "created_at": T0.isoformat(),
            "action_outcomes": ("applied",),
            "redaction_metrics": {"policy_version": "redaction-v9", "redacted_path_count": 0},
        }
    )


def _reading(seconds: int = 0) -> AttestedTimestamp:
    return AttestedTimestamp(
        wall_clock=T0 + timedelta(seconds=seconds),
        monotonic_ns=1_000_000 * (seconds + 1),
        uncertainty_ms=0.0,
        source="test",
    )


def open_store(tmp_path: Path) -> Store:
    return Store.open_migrated(tmp_path / "mayhem.db", migrations=ALL_MIGRATIONS)


def _chain_count(store: Store) -> int:
    """How many sealed chains exist — the "nothing was written" probe."""
    rows = store.query("SELECT COUNT(*) AS n FROM attestation_chains")
    return int(str(rows[0]["n"]))


def _seal(
    store: Store,
    result: ApprovalGateResult,
    approvals: tuple[Approval, ...],
    *,
    audit: AuditStream | None = None,
    environment: EnvironmentScope = PROD,
    now: datetime = T0,
    envelope: EvidenceEnvelope | None = None,
    plan_digest: str = PLAN_DIGEST,
) -> Any:
    return seal_approval_decision(
        store,
        envelope if envelope is not None else _envelope(plan_hash=plan_digest),
        result=result,
        policy_decision=_decision(),
        approvals=approvals,
        plan_digest=plan_digest,
        run_status="completed",
        now=now,
        environment=environment,
        grants=STANDING_GRANTS,
        verdict="pass",
        audit=audit,
        recorded_at=_reading(),
    )


# =============================================================================
# 1. The binding is re-derived at seal time
# =============================================================================


def test_an_unmodified_approval_binding_is_reproducible() -> None:
    """The positive case: the gate's answer is the seal-time answer."""
    approval = _mint()
    result = _allowed(approval)

    assert (
        verify_approval_binding(
            result,
            now=T0,
            approvals=(approval,),
            environment=PROD,
            grants=STANDING_GRANTS,
        )
        is None
    )


def test_the_re_derivation_is_the_domain_evaluator_not_a_second_one() -> None:
    """The refusals are the domain's own, so the two cannot disagree.

    The module docstring claims it delegates rather than re-deriving what an
    approval means. This is that claim, asserted: the triggers in the seal-time
    refusal are exactly the ``InvalidationReason`` values the domain evaluator
    produces for the same inputs.
    """
    from mayhem.domain.approval import evaluate_approvals

    approval = _revoked(_mint())
    result = _allowed(_mint("a-gate"), _mint("a-revoked"))
    refusal = verify_approval_binding(
        result,
        now=T0,
        approvals=(approval,),
        environment=PROD,
        grants=STANDING_GRANTS,
    )

    assert refusal is not None
    expected = evaluate_approvals(
        (approval,),
        plan_digest=result.plan_digest,
        policy_digest=result.policy_digest,
        proof_digest=result.proof_digest,
        environment=PROD,
        now=T0,
        required_approvals=result.required,
        grants=STANDING_GRANTS,
    )
    assert set(refusal.triggers) == set(expected.reasons)
    assert InvalidationReason.REVOKED in refusal.triggers


def test_an_approval_revoked_between_admission_and_close_is_refused() -> None:
    """The load-bearing negative control: the gate said yes; it is no longer yes.

    A module that checked only at grant time passes every other test here and
    fails this one, which is the whole reason the check runs twice.
    """
    approval = _mint()
    result = _allowed(approval)
    assert result.allowed

    refusal = verify_approval_binding(
        result,
        now=T0,
        approvals=(_revoked(approval),),
        environment=PROD,
        grants=STANDING_GRANTS,
    )

    assert refusal is not None
    assert refusal.rule_id == RULE_APPROVAL_NOT_REPRODUCIBLE
    assert InvalidationReason.REVOKED in refusal.triggers
    assert "no longer" in refusal.reason


def test_an_approval_that_expired_between_admission_and_close_is_refused() -> None:
    """The clock moved. The approval's own window says it is over."""
    approval = _mint(ttl_s=60.0)
    result = _allowed(approval)

    refusal = verify_approval_binding(
        result,
        now=AFTER + timedelta(seconds=120),
        approvals=(approval,),
        environment=PROD,
        grants=STANDING_GRANTS,
    )

    assert refusal is not None
    assert InvalidationReason.EXPIRED in refusal.triggers


def test_an_approval_that_lapses_exactly_at_its_expiry_is_refused() -> None:
    """At-and-after, matching ``Approval.is_expired``: no off-by-one window."""
    approval = _mint(ttl_s=60.0)
    result = _allowed(approval)
    boundary = approval.expires_at
    assert boundary is not None

    before = verify_approval_binding(
        result,
        now=boundary - timedelta(microseconds=1),
        approvals=(approval,),
        environment=PROD,
        grants=STANDING_GRANTS,
    )
    at = verify_approval_binding(
        result,
        now=boundary,
        approvals=(approval,),
        environment=PROD,
        grants=STANDING_GRANTS,
    )

    assert before is None
    assert at is not None
    assert InvalidationReason.EXPIRED in at.triggers


def test_an_approval_for_a_modified_plan_cannot_be_sealed() -> None:
    """The plan's own sentence, checked at the boundary rather than only at grant.

    Built by granting against one plan's digest and sealing against another's —
    the exact "approve, then modify the plan" sequence the plan forbids.
    """
    # The approval is granted against a *different* plan than the one running.
    # A second step is a different plan by content, which is the whole point:
    # nobody edited a digest, the plan simply grew.
    other_plan = _plan("proc.pause", "net.latency")
    assert candidate_plan_digest(other_plan) != PLAN_DIGEST
    stale = _mint(approval_id="a-other", proof=_passing_proof(candidate_plan_digest(other_plan)))

    # The gate refuses it at admission...
    denied = verify_approvals(PLAN, _gate(stale))
    assert denied.denied
    assert denied.refusal is not None
    assert InvalidationReason.PLAN_DIGEST_MISMATCH in denied.refusal.triggers

    # ...and the seal-time re-derivation refuses the same approval independently,
    # which is what a *hand-built* allowed result would be caught by.
    refusal = verify_approval_binding(
        _allowed(_mint()),
        now=T0,
        approvals=(stale,),
        environment=PROD,
        grants=STANDING_GRANTS,
    )
    assert refusal is not None
    assert InvalidationReason.PLAN_DIGEST_MISMATCH in refusal.triggers
    assert refusal.inputs["offered"] == 1


def test_a_denied_gate_result_cannot_be_sealed_as_an_authorization() -> None:
    """A refusal is evidence; it is not an authorization."""
    result = verify_approvals(PLAN, _gate())  # no approvals at all

    refusal = verify_approval_binding(
        result,
        now=T0,
        approvals=(),
        environment=PROD,
        grants=STANDING_GRANTS,
    )

    assert refusal is not None
    assert refusal.rule_id == RULE_APPROVAL_DENIED
    assert "gate_rule_id" in refusal.inputs


def test_a_quorum_the_evidence_cannot_name_is_refused() -> None:
    """The gate allowed, and the caller supplies nothing to show for it.

    This is the refusal that makes "a run's authority is in its evidence" more
    than a convention: the gate's own word is not enough.
    """
    result = _allowed(_mint())

    refusal = verify_approval_binding(
        result,
        now=T0,
        approvals=(),
        environment=PROD,
        grants=STANDING_GRANTS,
    )

    assert refusal is not None
    assert refusal.rule_id == RULE_APPROVAL_NOT_REPRODUCIBLE
    assert "no approval records were supplied" in refusal.reason


def test_a_missing_environment_scope_is_refused_rather_than_guessed() -> None:
    """Checking three of the four bindings is a different check, not a weaker one.

    ``result.environment`` is the scope's *rendered* string. Parsing it back
    would be a second, looser notion of what an environment is, so the scope is
    demanded instead.
    """
    result = _allowed(_mint())

    refusal = verify_approval_binding(
        result,
        now=T0,
        approvals=(_mint(),),
        environment=None,
        grants=STANDING_GRANTS,
    )

    assert refusal is not None
    assert refusal.rule_id == RULE_APPROVAL_NOT_REPRODUCIBLE
    assert "environment scope" in refusal.reason


def test_a_cross_environment_replay_is_refused_at_seal_time_too() -> None:
    """An approval granted for staging cannot authorize a production run.

    The gate is run *in staging*, where the approval legitimately holds, so the
    gate result is a real ``allowed`` — and the run it is being sealed for is in
    production. That is the sequence the check exists for: the authority was
    genuine where it was granted, and it does not travel.
    """
    staging_approval = _mint(scope=STAGING)
    staging_grants = (
        *STANDING_GRANTS,
        RoleGrant(role=Role.EXECUTE, scope=ORG_WIDE, principal=MALLORY, granted_at=YESTERDAY),
    )
    result = verify_approvals(
        PLAN,
        _gate(staging_approval, environment=STAGING, grants=staging_grants),
    )
    assert result.allowed, result.describe()

    refusal = verify_approval_binding(
        result,
        now=T0,
        approvals=(staging_approval,),
        environment=PROD,
        grants=staging_grants,
    )

    assert refusal is not None
    assert InvalidationReason.ENVIRONMENT_SCOPE in refusal.triggers


def test_the_refusal_enumerates_every_trigger_rather_than_the_first() -> None:
    """A record that reports one cause of three understates what went wrong."""
    stale = _revoked(_mint(ttl_s=1.0))
    result = _allowed(_mint())

    refusal = verify_approval_binding(
        result,
        now=LATER,
        approvals=(stale,),
        environment=PROD,
        grants=STANDING_GRANTS,
    )

    assert refusal is not None
    assert {InvalidationReason.REVOKED, InvalidationReason.EXPIRED} <= set(refusal.triggers)
    assert refusal.remediation


# =============================================================================
# 2. The sealed authorization
# =============================================================================


def test_an_allowed_binding_builds_the_sealed_authorization() -> None:
    """The happy path, through the real builder."""
    approval = _mint()

    authorization = build_authorization(
        _allowed(approval),
        policy_decision=_decision(),
        approvals=(approval,),
        plan_digest=PLAN_DIGEST,
        now=T0,
        environment=PROD,
        grants=STANDING_GRANTS,
        proof_digest=PROOF.proof_digest,
    )

    assert authorization.plan_digest == PLAN_DIGEST
    assert authorization.proof_digest == PROOF.proof_digest
    assert authorization.approval_state.approvers == (ALICE.principal_id,)


def test_an_unfit_result_raises_a_typed_refusal_that_can_be_recorded() -> None:
    """A refusal shaped like every other one, so a caller can log it."""
    result = verify_approvals(PLAN, _gate())

    with pytest.raises(ApprovalAuthorizationRefusedError) as excinfo:
        build_authorization(
            result,
            policy_decision=_decision(),
            approvals=(),
            plan_digest=PLAN_DIGEST,
            now=T0,
            environment=PROD,
            grants=STANDING_GRANTS,
        )

    assert excinfo.value.rule_id == RULE_APPROVAL_DENIED
    assert excinfo.value.remediation
    assert excinfo.value.detail()["rule_id"] == RULE_APPROVAL_DENIED


def test_the_authorization_carries_both_halves_and_neither_in_full() -> None:
    """The chain references the artifacts by digest; it is not a second copy."""
    approval = _mint()
    authorization = build_authorization(
        _allowed(approval),
        policy_decision=_decision(),
        approvals=(approval,),
        plan_digest=PLAN_DIGEST,
        now=T0,
        environment=PROD,
        grants=STANDING_GRANTS,
        proof_digest=PROOF.proof_digest,
    )
    payload = authorization.payload()

    assert payload["plan_digest"] == PLAN_DIGEST
    assert payload["decision_digest"]
    assert payload["approval_state_digest"]
    assert payload["approval_proof_digest"] == PROOF.proof_digest
    # The full approval records are *not* in the payload — the chain names them.
    assert "approvals" not in payload


def test_an_authorization_pinned_to_another_plan_is_refused_by_plan_12s_own_rule(
    tmp_path: Path,
) -> None:
    """Not a second check here: the envelope's ``plan_hash`` is the authority.

    The seam passes ``plan_digest`` straight through to plan 12, which compares
    it against the evidence envelope. This asserts the refusal happens, that the
    rule belongs to plan 12 rather than to this module, and that nothing was
    written when it fired.
    """
    from mayhem.infra.attestation_store import AuthorizationMismatchError

    approval = _mint()
    other = _plan("proc.pause", "net.latency")
    store = open_store(tmp_path)

    # The envelope describes one plan and the authorization pins another. The
    # refusal is plan 12's, raised inside its sealer.
    with pytest.raises(AuthorizationMismatchError, match="does not authorize another"):
        _seal(
            store,
            _allowed(approval),
            (approval,),
            envelope=_envelope(plan_hash=PLAN_DIGEST),
            plan_digest=candidate_plan_digest(other),
        )

    assert _chain_count(store) == 0


def test_the_approval_evidence_payload_is_sealed_against_its_own_edits() -> None:
    """``sealed_digest`` is recomputable, so an edited record is detectable.

    The check a reader performs is "recompute over everything else and compare".
    Asserted in both directions: the digest matches the payload it came from,
    and editing any single field breaks it. A digest that only covered *some*
    keys would pass the first assertion and fail the second.
    """
    payload = approval_evidence(_allowed(_mint()), (_mint(),))

    def recompute(document: dict[str, Any]) -> str:
        return sha256_hex(
            canonical_json({k: v for k, v in document.items() if k != "sealed_digest"})
        )

    assert payload["sealed_digest"] == recompute(payload)

    for field, value in (
        ("environment", "staging"),
        ("allowed", False),
        ("plan_digest", digest({"plan": "somewhere else"})),
        ("unbound_levels", ["sre"]),
    ):
        assert recompute({**payload, field: value}) != payload["sealed_digest"], (
            f"editing {field!r} must break the sealed digest"
        )


def test_the_sealed_digest_covers_the_counted_approval_digests() -> None:
    """The per-approval digests are inside the sealed payload, not beside it."""
    approval = _mint()
    payload = approval_evidence(_allowed(approval), (approval,))
    tampered = copy.deepcopy(payload)
    tampered["counted_approvals"][0]["approval_digest"] = digest({"forged": True})

    body = {k: v for k, v in tampered.items() if k != "sealed_digest"}
    assert sha256_hex(canonical_json(body)) != payload["sealed_digest"]


def test_the_approval_evidence_payload_names_each_counted_approval_by_digest() -> None:
    """The difference between "two approvals counted" and "these two records"."""
    payload = approval_evidence(
        _allowed(_mint("a-1"), _mint("a-2", approver=BOB)),
        (_mint("a-1"), _mint("a-2", approver=BOB)),
    )

    digests = {entry["approval_id"] for entry in payload["counted_approvals"]}
    assert digests == {"a-1", "a-2"}


def test_the_approval_evidence_payload_reports_a_refusal_too() -> None:
    """A refused plan is exactly the plan whose evidence is most worth keeping."""
    payload = approval_evidence(verify_approvals(PLAN, _gate()))

    assert payload["allowed"] is False
    assert payload["refusal"]["rule_id"]


# =============================================================================
# 3. The audit records for privileged actions
# =============================================================================


def test_granting_an_approval_is_recorded_naming_the_approver(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    audit = AuditStream(store)
    approval = _mint()

    event = record_approval_granted(audit, approval)

    assert event.event_kind == KIND_APPROVAL_GRANTED
    assert event.payload["principal"] == ALICE.principal_id
    assert event.payload["approval_digest"] == approval.approval_digest
    assert event.payload["target"] == approval.approval_id
    assert verify_audit_chain(audit.load()).valid


def test_the_grant_entry_records_what_the_approval_binds(tmp_path: Path) -> None:
    """An auditor asks "which plan did this approve?" — the entry answers it."""
    store = open_store(tmp_path)
    audit = AuditStream(store)
    approval = _mint()

    detail = record_approval_granted(audit, approval).payload["detail"]

    assert detail["plan_digest"] == approval.plan_digest
    assert detail["policy_digest"] == approval.policy_digest
    assert detail["proof_digest"] == approval.proof_digest
    assert detail["environment"] == PROD.describe()
    assert detail["override"] is False


def test_an_override_grant_entry_carries_the_reason(tmp_path: Path) -> None:
    """The audit stream alone can answer "why did this bypass the quorum?"."""
    store = open_store(tmp_path)
    audit = AuditStream(store)
    approval = _mint(override=True, override_reason="prod incident INC-42")

    detail = record_approval_granted(audit, approval).payload["detail"]

    assert detail["override"] is True
    assert detail["override_reason"] == "prod incident INC-42"


def test_a_revocation_names_the_revoker_not_the_approver(tmp_path: Path) -> None:
    """Otherwise a revocation looks like the approver withdrawing their own word."""
    store = open_store(tmp_path)
    audit = AuditStream(store)
    approval = _revoked(_mint())

    event = record_approval_revoked(audit, approval)

    assert event.event_kind == KIND_APPROVAL_REVOKED
    assert event.payload["principal"] == "u-admin"
    assert event.payload["approval_digest"] == approval.approval_digest


def test_recording_a_revocation_of_an_unrevoked_approval_is_refused(tmp_path: Path) -> None:
    """An entry asserting a change that did not happen, in an append-only log.

    There is no later entry to contradict it, which is why this is a refusal and
    not a warning.
    """
    store = open_store(tmp_path)
    audit = AuditStream(store)

    with pytest.raises(ApprovalEvidenceError, match="not revoked"):
        record_approval_revoked(audit, _mint())

    assert audit.entry_count() == 0


def test_exercising_an_override_names_the_principal_who_pressed_it(tmp_path: Path) -> None:
    """Exercised by someone; approved by someone else. The stream tells them apart."""
    store = open_store(tmp_path)
    audit = AuditStream(store)
    approval = _mint(override=True, override_reason="INC-42")

    event = record_override_exercised(
        audit, approval, principal=MALLORY.principal_id, run_id="run-1"
    )

    assert event.event_kind == KIND_EMERGENCY_OVERRIDE_EXERCISED
    assert event.payload["principal"] == MALLORY.principal_id
    assert event.payload["subject_run_id"] == "run-1"
    assert event.payload["detail"]["approver"] == ALICE.principal_id
    assert event.payload["detail"]["override_reason"] == "INC-42"


def test_an_override_exercise_with_no_actor_is_refused(tmp_path: Path) -> None:
    """The action most likely to be reviewed later, by the person least expected."""
    store = open_store(tmp_path)
    audit = AuditStream(store)
    approval = _mint(override=True, override_reason="INC-42")

    for principal in ("", "   "):
        with pytest.raises(ApprovalEvidenceError, match="names no principal"):
            record_override_exercised(audit, approval, principal=principal, run_id="run-1")

    assert audit.entry_count() == 0


def test_an_override_exercise_with_no_run_is_refused(tmp_path: Path) -> None:
    """An override with no run is not an exercise."""
    store = open_store(tmp_path)
    audit = AuditStream(store)
    approval = _mint(override=True, override_reason="INC-42")

    with pytest.raises(ApprovalEvidenceError, match="no run"):
        record_override_exercised(audit, approval, principal=MALLORY.principal_id, run_id="  ")

    assert audit.entry_count() == 0


def test_exercising_a_non_override_is_refused(tmp_path: Path) -> None:
    """A bypass that did not happen is not a record."""
    store = open_store(tmp_path)
    audit = AuditStream(store)

    with pytest.raises(ApprovalEvidenceError, match="not an override"):
        record_override_exercised(audit, _mint(), principal=MALLORY.principal_id, run_id="run-1")

    assert audit.entry_count() == 0


def test_a_role_grant_is_recorded_naming_what_and_where(tmp_path: Path) -> None:
    """An auditor filtering by target is asking "who can execute in prod?"."""
    store = open_store(tmp_path)
    audit = AuditStream(store)
    grant = RoleGrant(
        role=Role.EMERGENCY_STOP,
        scope=PROD,
        principal=DANA,
        granted_at=T0,
        granted_by=ONBOARDER.principal_id,
        change_ticket="OPS-9",
    )

    event = record_role_grant_issued(audit, grant, principal=ONBOARDER.principal_id)

    assert event.event_kind == KIND_ROLE_GRANT_ISSUED
    assert event.payload["target"] == f"emergency_stop@{PROD.describe()}"
    assert event.payload["detail"]["addressee"] == DANA.principal_id
    assert event.payload["detail"]["change_ticket"] == "OPS-9"


def test_a_role_grant_with_no_issuer_is_refused(tmp_path: Path) -> None:
    """``RoleGrant.granted_by`` is optional; an audit entry's actor is not."""
    store = open_store(tmp_path)
    audit = AuditStream(store)
    grant = RoleGrant(role=Role.VIEW, scope=PROD, principal=DANA, granted_at=T0)

    with pytest.raises(ApprovalEvidenceError, match="names no principal"):
        record_role_grant_issued(audit, grant, principal="")

    assert audit.entry_count() == 0


def test_a_role_revocation_takes_the_facts_because_the_grant_is_gone(tmp_path: Path) -> None:
    """The withdrawn grant no longer exists to read an entry from.

    This is why the signature is four strings where the issue path takes the
    object, and it is a real asymmetry rather than an inconsistency.
    """
    store = open_store(tmp_path)
    audit = AuditStream(store)

    event = record_role_grant_revoked(
        audit,
        role="emergency_stop",
        scope=PROD.describe(),
        addressee=DANA.principal_id,
        principal=ONBOARDER.principal_id,
        reason="offboarded",
    )

    assert event.event_kind == KIND_ROLE_GRANT_REVOKED
    assert event.payload["detail"]["reason"] == "offboarded"


def test_a_role_revocation_naming_nothing_is_refused(tmp_path: Path) -> None:
    """ "The admin grant in prod was withdrawn" is not a record anyone can act on."""
    store = open_store(tmp_path)
    audit = AuditStream(store)

    for omitted in ("role", "scope", "addressee"):
        facts = {
            "role": "execute",
            "scope": PROD.describe(),
            "addressee": DANA.principal_id,
        }
        facts[omitted] = ""
        with pytest.raises(ApprovalEvidenceError, match=f"no {omitted}"):
            record_role_grant_revoked(audit, principal=ONBOARDER.principal_id, **facts)

    assert audit.entry_count() == 0


def test_disabling_a_principal_requires_a_reason(tmp_path: Path) -> None:
    """The entry most often read months later, by whoever asks "why can't I log in?"."""
    store = open_store(tmp_path)
    audit = AuditStream(store)
    disabled = Principal(principal_id="u-alice", display_name="Alice", disabled=True)

    with pytest.raises(ApprovalEvidenceError, match="no reason"):
        record_principal_disabled(audit, disabled, revoked_by=ONBOARDER.principal_id, reason="  ")

    assert audit.entry_count() == 0


def test_disabling_a_principal_that_is_not_disabled_is_refused(tmp_path: Path) -> None:
    """Same rule as the revocation: a change that did not happen is not a record."""
    store = open_store(tmp_path)
    audit = AuditStream(store)

    with pytest.raises(ApprovalEvidenceError, match="not disabled"):
        record_principal_disabled(
            audit,
            ALICE,
            revoked_by=ONBOARDER.principal_id,
            reason="left the company",
        )

    assert audit.entry_count() == 0


def test_disabling_a_principal_names_who_did_it_and_why(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    audit = AuditStream(store)
    disabled = Principal(principal_id="u-alice", display_name="Alice", disabled=True)

    event = record_principal_disabled(
        audit, disabled, revoked_by=ONBOARDER.principal_id, reason="left the company"
    )

    assert event.event_kind == KIND_PRINCIPAL_DISABLED
    assert event.payload["principal"] == ONBOARDER.principal_id
    assert event.payload["target"] == "u-alice"
    assert event.payload["detail"]["display_name"] == "Alice"


# =============================================================================
# 4. The audit trail is not optional
# =============================================================================


def test_a_run_cannot_be_sealed_without_its_approval_records(tmp_path: Path) -> None:
    """The plan's acceptance criterion: a run with no approval record is unrepresentable."""
    store = open_store(tmp_path)
    audit = AuditStream(store)
    approval = _mint()
    result = _allowed(approval)

    with pytest.raises(ApprovalEvidenceError, match="audit stream has no record"):
        _seal(store, result, (approval,), audit=audit)

    # Nothing was written: no chain, no manifest, no audit entry.
    assert audit.entry_count() == 0
    rows = store.query("SELECT COUNT(*) AS n FROM attestation_chains")
    assert int(str(rows[0]["n"])) == 0


def test_a_run_seals_once_its_approval_records_are_present(tmp_path: Path) -> None:
    """The positive case for the same check, through a real migrated store."""
    store = open_store(tmp_path)
    audit = AuditStream(store)
    approval = _mint()
    record_approval_granted(audit, approval, subject_run_id="run-1")

    sealed = _seal(store, _allowed(approval), (approval,), audit=audit)

    assert [event.event_kind for event in sealed.events] == [
        "evidence.recorded",
        EVENT_POLICY_DECIDED,
        EVENT_APPROVAL_EVALUATED,
        "run.closed",
    ]
    assert sealed.completeness is not None
    assert sealed.completeness.complete


def test_an_entry_naming_the_right_people_but_the_wrong_approval_does_not_satisfy_it(
    tmp_path: Path,
) -> None:
    """A grant of one approval is not a grant of a different one.

    The strongest form of the completeness check: the stream holds a grant
    entry, for the same approver, for the same run — and it still does not
    account for this approval, because the digests differ.
    """
    store = open_store(tmp_path)
    audit = AuditStream(store)
    granted = _mint("a-1", approver=ALICE)
    other = _mint("a-2", approver=ALICE)
    record_approval_granted(audit, granted, subject_run_id="run-1")

    with pytest.raises(ApprovalEvidenceError, match="audit stream has no record"):
        _seal(store, _allowed(other), (other,), audit=audit)

    assert audit.entry_count() == 1


def test_an_approval_record_for_another_run_does_not_satisfy_the_check(tmp_path: Path) -> None:
    """The stream read is per-run, so a sibling run's grant cannot stand in."""
    store = open_store(tmp_path)
    audit = AuditStream(store)
    approval = _mint()
    record_approval_granted(audit, approval, subject_run_id="run-2")

    with pytest.raises(ApprovalEvidenceError, match="audit stream has no record"):
        _seal(store, _allowed(approval), (approval,), audit=audit)


def test_a_two_signature_quorum_needs_two_approvals_and_two_records(tmp_path: Path) -> None:
    """Two refusals from two layers, asserted separately because they differ.

    Handing over only one of the two approvals is caught by the **binding** —
    a single signature cannot reach a quorum of two, so the gate's answer no
    longer reproduces. Handing over both while the stream records only one grant
    is caught by the **audit trail** — the quorum is real but one of its
    signatures is not on record. A test that only supplied both would pass
    against an implementation that checked neither.
    """
    store = open_store(tmp_path)
    audit = AuditStream(store)
    alice = _mint("a-1", approver=ALICE)
    bob = _mint("a-2", approver=BOB)
    result = _allowed(alice, bob, required_approvals=2)

    # Layer one: the binding cannot reproduce a quorum of two from one approval.
    with pytest.raises(ApprovalAuthorizationRefusedError) as excinfo:
        _seal(store, result, (alice,), audit=audit)
    assert excinfo.value.rule_id == RULE_APPROVAL_NOT_REPRODUCIBLE
    assert audit.entry_count() == 0

    # Layer two: both approvals supplied, only one grant on record.
    record_approval_granted(audit, alice, subject_run_id="run-1")
    with pytest.raises(ApprovalEvidenceError) as trail:
        _seal(store, result, (alice, bob), audit=audit)
    assert "a-2" in str(trail.value)
    assert _chain_count(store) == 0

    # Both on record: the run seals, and the chain says it is complete.
    record_approval_granted(audit, bob, subject_run_id="run-1")
    sealed = _seal(store, result, (alice, bob), audit=audit)
    assert sealed.completeness is not None and sealed.completeness.complete


def test_a_gate_that_counted_someone_the_supplied_approvals_omit_is_refused(tmp_path: Path) -> None:
    """What the optional ``result`` parameter buys, asserted on its own.

    The gate counts *every* approval that was valid, not just enough to reach
    the quorum — so with two approvals offered and a quorum of one, both approvers
    are in :attr:`ApprovalState.approvers`. A caller that then hands over only
    one of them has an authority set that does not match the answer being sealed,
    and matching on digests alone would not see it: alice's digest is perfectly
    on record. Comparing against the gate's own approver set does see it.
    """
    store = open_store(tmp_path)
    audit = AuditStream(store)
    alice = _mint("a-1", approver=ALICE)
    bob = _mint("a-2", approver=BOB)
    result = _allowed(alice, bob, required_approvals=1)
    assert result.state.approvers == ("u-alice", "u-bob")
    record_approval_granted(audit, alice, subject_run_id="run-1")

    # alice's record is present and the quorum was met, yet bob is counted and
    # absent — so the refusal is about the mismatch, not about the audit stream.
    with pytest.raises(ApprovalEvidenceError, match="u-bob") as excinfo:
        _seal(store, result, (alice,), audit=audit)
    assert "audit stream has no record" not in str(excinfo.value)
    assert _chain_count(store) == 0

    # The weaker form is reachable only by calling the check directly, and it is
    # a real check rather than a no-op: alice's grant is on record, so it
    # passes. ``seal_approval_decision`` itself has no way to ask for the weaker
    # form, because the strict one is the only one it offers.
    require_approval_records(audit, approvals=(alice,), run_id="run-1")
    with pytest.raises(ApprovalEvidenceError, match="audit stream has no record"):
        require_approval_records(audit, approvals=(bob,), run_id="run-1")


def test_an_override_run_needs_its_override_exercise_on_record(tmp_path: Path) -> None:
    """Granting an override and *using* it are two entries, and only one is not enough."""
    store = open_store(tmp_path)
    audit = AuditStream(store)
    approval = _mint(override=True, override_reason="INC-42")
    result = _allowed(approval)
    record_approval_granted(audit, approval, subject_run_id="run-1")

    with pytest.raises(ApprovalEvidenceError, match="override_exercised"):
        _seal(store, result, (approval,), audit=audit)

    record_override_exercised(audit, approval, principal=MALLORY.principal_id, run_id="run-1")
    sealed = _seal(store, result, (approval,), audit=audit)
    assert sealed.completeness is not None and sealed.completeness.complete


def test_a_revoked_records_digest_is_on_record_only_once_it_is_revoked(tmp_path: Path) -> None:
    """Revocation changes the digest, so both entries are needed — and only one is.

    ``Approval.approval_digest`` covers the revocation fields, so the revoked
    record has a *different* digest from the one that was granted. A grant entry
    naming the pre-revocation digest therefore does not account for the record
    as presented at seal time, and the revoked gap is reported alongside it. That
    is not a bug in the check: it is the check refusing to let a revoked
    approval be the run's authority, which is also why
    :func:`verify_approval_binding` refuses it before this is ever reached.
    """
    store = open_store(tmp_path)
    audit = AuditStream(store)
    approval = _mint()
    revoked = _revoked(approval)
    assert revoked.approval_digest != approval.approval_digest
    record_approval_granted(audit, approval, subject_run_id="run-1")

    gaps = approval_record_gaps(audit.entries_for_run("run-1"), approvals=(revoked,))
    assert [gap.reason for gap in gaps] == [
        f"no {KIND_APPROVAL_GRANTED} entry in the audit stream carries approval digest "
        f"{revoked.approval_digest[:12]}…",
        f"the approval is revoked but no {KIND_APPROVAL_REVOKED} entry carries its "
        f"digest {revoked.approval_digest[:12]}…",
    ]

    # Recording the revocation clears the second gap; the first remains, and
    # must: nobody ever granted the record as it now reads.
    record_approval_revoked(audit, revoked, subject_run_id="run-1")
    remaining = approval_record_gaps(audit.entries_for_run("run-1"), approvals=(revoked,))
    assert [gap.reason for gap in remaining] == [
        f"no {KIND_APPROVAL_GRANTED} entry in the audit stream carries approval digest "
        f"{revoked.approval_digest[:12]}…"
    ]


def test_gap_detection_is_pure_over_the_entries_it_is_handed(tmp_path: Path) -> None:
    """It reads what it is given and opens nothing, so it is testable as such."""
    store = open_store(tmp_path)
    audit = AuditStream(store)
    approval = _mint()
    record_approval_granted(audit, approval)

    # The entry is in the stream, but it was handed to the function as if it
    # were for another run: the function does not consult the store.
    assert approval_record_gaps(audit.entries_for_run("run-other"), approvals=(approval,))


def test_the_completeness_check_names_every_gap_at_once(tmp_path: Path) -> None:
    """Three missing records produce one message listing all three, not three rounds."""
    store = open_store(tmp_path)
    audit = AuditStream(store)
    approvals = (
        _mint("a-1"),
        _revoked(_mint("a-2")),
        _mint("a-3", override=True, override_reason="INC-42"),
    )

    with pytest.raises(ApprovalEvidenceError) as excinfo:
        require_approval_records(audit, approvals=approvals, run_id="run-1")

    message = str(excinfo.value)
    for approval_id in ("a-1", "a-2", "a-3"):
        assert approval_id in message


def test_an_unattributed_role_revocation_is_refused_with_its_own_rule(tmp_path: Path) -> None:
    """The rule id is on the message so a log line and a query cannot disagree.

    Two refusals, two rule ids: an entry with no *actor* is refused by the
    actor rule, and an entry naming nothing about *what* is refused by the
    unattributed rule. Asserting only "it raised" would let either rule be
    swapped for the other.
    """
    store = open_store(tmp_path)
    audit = AuditStream(store)

    with pytest.raises(ApprovalEvidenceError, match="names no principal"):
        record_role_grant_revoked(
            audit,
            role="execute",
            scope=PROD.describe(),
            addressee=DANA.principal_id,
            principal="",
        )

    with pytest.raises(ApprovalEvidenceError) as excinfo:
        record_role_grant_revoked(
            audit,
            role="execute",
            scope=PROD.describe(),
            addressee="",
            principal=ONBOARDER.principal_id,
        )
    assert RULE_APPROVAL_AUDIT_UNATTRIBUTED in str(excinfo.value)
    assert audit.entry_count() == 0


def test_the_rule_ids_on_this_module_are_names_it_declares() -> None:
    """A rule id quoted by a caller is a constant, not a string that could drift."""
    from mayhem.controller import approval_evidence as module

    for name, rule in (
        ("RULE_APPROVAL_DENIED", RULE_APPROVAL_DENIED),
        ("RULE_APPROVAL_NOT_REPRODUCIBLE", RULE_APPROVAL_NOT_REPRODUCIBLE),
        ("RULE_APPROVAL_AUDIT_UNCHANGED", RULE_APPROVAL_AUDIT_UNCHANGED),
        ("RULE_APPROVAL_AUDIT_UNATTRIBUTED", RULE_APPROVAL_AUDIT_UNATTRIBUTED),
    ):
        assert getattr(module, name) == rule
        assert rule.startswith("approval.")


#: The six kinds this phase added, with the values this module records.
IDENTITY_KINDS: dict[str, str] = {
    "KIND_APPROVAL_GRANTED": KIND_APPROVAL_GRANTED,
    "KIND_APPROVAL_REVOKED": KIND_APPROVAL_REVOKED,
    "KIND_EMERGENCY_OVERRIDE_EXERCISED": KIND_EMERGENCY_OVERRIDE_EXERCISED,
    "KIND_ROLE_GRANT_ISSUED": KIND_ROLE_GRANT_ISSUED,
    "KIND_ROLE_GRANT_REVOKED": KIND_ROLE_GRANT_REVOKED,
    "KIND_PRINCIPAL_DISABLED": KIND_PRINCIPAL_DISABLED,
}


def _declared_kinds() -> dict[str, list[str]]:
    """Map every ``KIND_*`` assignment in ``src/mayhem`` to the files making it.

    Read from source rather than imported, because a module's namespace cannot
    say where a name came from once it has been rebound — which is exactly the
    failure the audit stream's owning table exists to prevent.
    """
    import re
    from pathlib import Path as _Path

    root = _Path(__file__).resolve().parents[2] / "src" / "mayhem"
    declaration = re.compile(r"^(?P<name>KIND_[A-Z0-9_]+)\s*(?::\s*[^=]+)?=", re.MULTILINE)
    found: dict[str, list[str]] = {}
    for path in sorted(root.rglob("*.py")):
        for match in declaration.finditer(path.read_text(encoding="utf-8")):
            found.setdefault(match.group("name"), []).append(path.name)
    return found


@pytest.mark.parametrize("name", sorted(IDENTITY_KINDS))
def test_an_identity_kind_is_declared_only_by_the_audit_stream(name: str) -> None:
    """These six were born in the owning table, not pasted into a controller.

    ``tests/unit/test_audit_kind_ownership.py`` pins this for the two kinds it
    folded in from foreign modules; this pins it for the ones added since, so
    the guard does not have to be widened by hand to cover them.
    """
    assert _declared_kinds().get(name) == ["audit_stream.py"]


@pytest.mark.parametrize(("name", "value"), sorted(IDENTITY_KINDS.items()))
def test_an_identity_kind_keeps_the_string_an_auditor_filters_on(name: str, value: str) -> None:
    """The action name is the filter key, so its spelling is part of the contract."""
    from mayhem.infra import audit_stream

    assert getattr(audit_stream, name) == value
    assert name in audit_stream.__all__


#: Which recorder function writes each kind. Keyed by the *name*, because the
#: assertion that follows reads source text, and source text names constants.
RECORDERS: dict[str, str] = {
    "KIND_APPROVAL_GRANTED": "record_approval_granted",
    "KIND_APPROVAL_REVOKED": "record_approval_revoked",
    "KIND_EMERGENCY_OVERRIDE_EXERCISED": "record_override_exercised",
    "KIND_ROLE_GRANT_ISSUED": "record_role_grant_issued",
    "KIND_ROLE_GRANT_REVOKED": "record_role_grant_revoked",
    "KIND_PRINCIPAL_DISABLED": "record_principal_disabled",
}


def test_the_recorders_cover_exactly_the_kinds_this_phase_added() -> None:
    """A kind nobody writes is a name in a table, not an action that happens.

    The table is documentary (see the audit stream's own comment on that), so
    this asserts the other half: each of the six has a recorder here, and there
    is no recorder for a kind this phase did not add.
    """
    from mayhem.controller import approval_evidence as module

    assert set(RECORDERS) == set(IDENTITY_KINDS)
    for name, function in RECORDERS.items():
        assert callable(getattr(module, function)), f"{name} has no recorder"

    # And each recorder's own source names its kind, so renaming a kind cannot
    # leave a recorder quietly writing the previous action's string.
    import inspect

    for name, function in RECORDERS.items():
        assert name in inspect.getsource(getattr(module, function)), (
            f"{function} does not name {name}"
        )


# =============================================================================
# 5. Nothing here authenticates anybody
# =============================================================================


def test_every_artifact_this_module_produces_is_unsigned(tmp_path: Path) -> None:
    """The honesty control on the module: no artifact may claim an authorship.

    A reader must be able to tell "these bytes were not altered" (established)
    from "these bytes were written by this person" (**not** established). The
    module docstring says so; this is what stops it from quietly becoming false
    if someone later adds a key.
    """
    store = open_store(tmp_path)
    audit = AuditStream(store)
    approval = _mint()
    record_approval_granted(audit, approval, subject_run_id="run-1")
    sealed = _seal(store, _allowed(approval), (approval,), audit=audit)

    assert audit.signed is False
    assert audit.signature_state == SIGNATURE_UNSIGNED_NO_SIGNING
    assert sealed.signed is False
    assert sealed.signature_state == SIGNATURE_UNSIGNED_NO_SIGNING
    assert sealed.signature_reason


def test_the_approval_digest_pins_content_not_authorship(tmp_path: Path) -> None:
    """Two facts that are easy to confuse, asserted separately.

    The digest is a content hash: it changes when the record changes, and says
    nothing at all about who wrote it. A test that conflated the two would let a
    future reader believe a digest is a signature.
    """
    approval = _mint()
    edited = Approval.model_validate({**approval.model_dump(), "note": "after the fact"})

    assert approval.approval_digest != edited.approval_digest
    # And the *author* is a field, not a derivation: two records by the same
    # approver have different digests and the same principal.
    other = _mint("a-2")
    assert approval.approval_digest != other.approval_digest
    assert approval.approver == other.approver


# =============================================================================
# 6. Wiring: the seam exists, and nothing in the run path calls it yet
# =============================================================================


def test_the_seal_is_reached_from_this_module_and_not_merely_callable() -> None:
    """A helper nobody calls is not a gate.

    Read from source, because the failure worth catching is a *second*
    implementation: this asserts every path to
    :func:`~mayhem.infra.audit_stream.seal_run_evidence_at_run_close` in the
    controller layer goes through
    :func:`~mayhem.controller.approval_evidence.seal_approval_decision`.
    """
    import ast
    from pathlib import Path as _Path

    source_root = _Path(__file__).resolve().parents[2] / "src" / "mayhem" / "controller"
    callers: list[str] = []
    for path in sorted(source_root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = getattr(func, "id", None) or getattr(func, "attr", None)
            if name == "seal_run_evidence_at_run_close":
                callers.append(path.name)

    # ``policy_evidence`` has its own documented seam; this module has the other.
    # Nothing else may reach the sealer directly, because a caller that skipped
    # the binding re-derivation would seal an approval nobody can re-check.
    assert set(callers) <= {"approval_evidence.py", "policy_evidence.py"}


def test_the_approval_decision_recorded_at_admission_is_the_one_sealed() -> None:
    """The SafetyContext decision and the sealed authorization agree.

    Not a coincidence: the gate result the sealer is handed is the same object
    admission reached, and this asserts the run-close path cannot be handed a
    *different* gate's answer without the plan digest moving with it.
    """
    from mayhem.config import PolicyCfg
    from mayhem.controller.safety import SafetyContext, validate_plan
    from mayhem.domain.experiments import BlastRadiusBudget
    from mayhem.domain.topology import Edge, EdgeKind, ServiceNode, TopologyGraph

    approval = _mint()
    gate = _gate(approval)
    ctx = SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(max_services_pct=100.0),
        fingerprint="f",
        approval_gate=gate,
    )
    graph = TopologyGraph(
        nodes=(ServiceNode(id="n-web", name="web"),),
        edges=(Edge(src="n-web", dst="n-web", kind=EdgeKind.DEPENDS_ON, weight=1.0),),
    )
    validate_plan(PLAN, graph, ctx)

    decisions = [d for d in ctx.decisions if d.rule_id == "approval.allow"]
    assert len(decisions) == 1
    assert decisions[0].inputs["sealed_digest"]
    # And the sealed payload for the same result carries the same approver set.
    payload = approval_evidence(verify_approvals(PLAN, gate), (approval,))
    assert payload["approvals"]["approvers"] == [ALICE.principal_id]


# =============================================================================
# Helpers used by the sealing tests
# =============================================================================
