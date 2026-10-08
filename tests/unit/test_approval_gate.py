"""Plan 09 Phase 2 — the approval gate at admission.

Phase 1's suite (``test_approval.py``) proved the *predicate* decides. This one
proves the thing that was missing: that the decision is reached inside
``safety.validate_plan``, that authorization precedes it, that the emergency
override executes while still being reconstructable afterwards, and that the
whole thing is additive — a run with no approval gate configured records
byte-for-byte what it recorded before this phase existed.

The organization follows the requirement list:

1. the refusal matrix — every ``InvalidationReason``, one per row, each row
   tripping *only* its own trigger;
2. authorization: role plus environment scope, and the refusals for a missing
   role, a wrong environment, and a lapsed grant;
3. separation of duties, both settings, including that ``EXECUTE`` alone never
   self-approves regardless of the switch;
4. the approval service: mint, revoke, expire, invalidate on plan change;
5. override semantics — it runs, it seals, and it is not an ordinary approval;
6. admission integration, including the no-approvals golden;
7. the negative controls the plan names: approve-then-modify-plan, a revoked
   approver, cross-environment replay, self-approval by an ``EXECUTE``-only
   principal, and an approval over a ``VOID`` proof.

Every input is explicit, including the clock. Nothing here reads ``utc_now()``
or touches a socket, a file, or a subprocess: the property under test is that
the verdict is a function of (plan, proof, policy, approvals, grants, now).
"""

from __future__ import annotations

from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mayhem.config import PolicyCfg
from mayhem.controller.approval_gate import (
    RULE_APPROVAL_ALLOW,
    RULE_APPROVAL_EXECUTOR_UNAUTHORIZED,
    RULE_APPROVAL_OVERRIDE,
    RULE_APPROVAL_PROOF_NOT_PASS,
    RULE_APPROVAL_REQUIRED,
    ApprovalGateInputs,
    ApprovalGateResult,
    ApprovalLedger,
    candidate_plan_digest,
    executor_may_run,
    quorum_from_requirements,
    verify_approvals,
)
from mayhem.controller.plan_diff import diff_plans
from mayhem.controller.safety import (
    SafetyContext,
    SafetyRefusedError,
    validate_plan,
)
from mayhem.controller.safety_proof import OBLIGATION_FOR_RULE, canonical_plan_digest
from mayhem.domain.approval import (
    Approval,
    InvalidationReason,
    plan_content_digest,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.hashing import canonical_json, digest, sha256_hex
from mayhem.domain.identity import (
    ANY_ENVIRONMENT,
    EnvironmentScope,
    Principal,
    PrincipalKind,
    Role,
    RoleGrant,
    TeamMembership,
)
from mayhem.domain.policy import (
    PolicyBundle,
    PolicyDimension,
    PolicyEffect,
    PolicyOperator,
    PolicyPredicate,
    PolicyRule,
)
from mayhem.domain.policy_gate import PolicyGateInputs, evaluate_gate
from mayhem.domain.safety_proof import (
    Obligation,
    ObligationName,
    ObligationStatus,
    ProofVerdict,
    SafetyProof,
)
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    NodeKind,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
BEFORE = T0 - timedelta(seconds=1)
AFTER = T0 + timedelta(seconds=1)
YESTERDAY = T0 - timedelta(days=1)

PROD = EnvironmentScope(environment="production")
STAGING = EnvironmentScope(environment="staging")
ORG_WIDE = EnvironmentScope.any()

POLICY_DIGEST = digest({"bundle": "prod-approvals", "version": 3})


# =============================================================================
# Fixtures-as-values — no shared mutable state, so order cannot matter
# =============================================================================


def _principal(pid: str, **kwargs: Any) -> Principal:
    kwargs.setdefault("display_name", pid.replace("-", " ").title())
    return Principal(principal_id=pid, **kwargs)


#: Alice and Bob may approve production; Mallory may execute but not approve;
#: Dana holds both, which is what the separation-of-duties rows need.
ALICE = _principal("u-alice")
BOB = _principal("u-bob")
MALLORY = _principal("u-mallory")
DANA = _principal("u-dana")
SRE_SA = _principal("sa-sre", kind=PrincipalKind.SERVICE_ACCOUNT)


def _graph() -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-api", name="api"),
            ServiceNode(id="n-web", name="web"),
            ServiceNode(id="n-db", name="db"),
        ),
        edges=(
            Edge(src="n-web", dst="n-api", kind=EdgeKind.DEPENDS_ON, weight=1.0),
            Edge(src="n-api", dst="n-db", kind=EdgeKind.DEPENDS_ON, weight=2.0),
        ),
    )


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


def _ctx(**kwargs: Any) -> SafetyContext:
    return SafetyContext(
        policy=PolicyCfg(),
        # Wide enough that the per-step blast caps never fire: a refusal here has
        # to have exactly one cause.
        budget=BlastRadiusBudget(max_services_pct=100.0),
        fingerprint="f",
        **kwargs,
    )


def _dump(ctx: SafetyContext) -> str:
    """A stable rendering of everything one validation pass recorded."""
    return "\n".join(
        f"{d.rule_id}|{d.outcome}|{d.reason}|{d.remediation}|{sorted(d.inputs)}"
        for d in ctx.decisions
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


def _grant(
    principal: Principal,
    role: Role,
    *,
    scope: EnvironmentScope = PROD,
    team_id: str = "",
    expires_at: datetime | None = None,
    granted_at: datetime = YESTERDAY,
) -> RoleGrant:
    addressee: dict[str, Any] = {"team_id": team_id} if team_id else {"principal": principal}
    return RoleGrant(
        role=role,
        scope=scope,
        granted_at=granted_at,
        expires_at=expires_at,
        **addressee,
    )


def _memberships(*, team_id: str = "t-sre") -> tuple[TeamMembership, ...]:
    return (TeamMembership(principal=MALLORY, team_id=team_id, joined_at=YESTERDAY),)


def _grant_for(principal: Principal, role: Role, **kwargs: Any) -> tuple[RoleGrant, ...]:
    """A one-element grant tuple — the shape a single deviation needs."""
    return (_grant(principal, role, **kwargs),)


#: The standing authorization state. Mallory holds EXECUTE only — deliberate
#: role separation, so the ``approver_role`` trigger is never masked.
STANDING_GRANTS: tuple[RoleGrant, ...] = (
    _grant(ALICE, Role.APPROVE, scope=ORG_WIDE),
    _grant(BOB, Role.APPROVE),
    _grant(MALLORY, Role.EXECUTE),
    _grant(DANA, Role.APPROVE),
    _grant(DANA, Role.EXECUTE),
)

PLAN = _plan("proc.pause")
PLAN_DIGEST = candidate_plan_digest(PLAN)
PROOF = _passing_proof(PLAN_DIGEST)


def _ledger(
    *approvals: Approval,
    grants: tuple[RoleGrant, ...] = STANDING_GRANTS,
    memberships: tuple[TeamMembership, ...] = (),
) -> ApprovalLedger:
    return ApprovalLedger(approvals=tuple(approvals), grants=grants, memberships=memberships)


def _mint(
    approval_id: str = "a-1",
    *,
    approver: Principal = ALICE,
    proof: SafetyProof = PROOF,
    scope: EnvironmentScope = PROD,
    now: datetime = BEFORE,
    ledger: ApprovalLedger | None = None,
    ttl_s: float | None = 900.0,
    override: bool = False,
    override_reason: str = "",
    **kwargs: Any,
) -> Approval:
    """A mint through the service, so the service is on the path under test."""
    base = ledger if ledger is not None else _ledger()
    return base.mint(
        approval_id=approval_id,
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approver=approver,
        environment=scope,
        now=now,
        ttl_s=ttl_s,
        override=override,
        override_reason=override_reason,
        **kwargs,
    ).approvals[-1]


def _gate(
    *,
    approvals: tuple[Approval, ...] = (),
    executor: Principal = MALLORY,
    proof: SafetyProof = PROOF,
    environment: EnvironmentScope = PROD,
    policy_digest: str = POLICY_DIGEST,
    grants: tuple[RoleGrant, ...] = STANDING_GRANTS,
    memberships: tuple[TeamMembership, ...] = (),
    now: datetime = T0,
    required_approvals: int = 1,
    separation_of_duties: bool = False,
    consumed_ids: frozenset[str] = frozenset(),
) -> ApprovalGateInputs:
    return ApprovalGateInputs(
        now=now,
        environment=environment,
        executor=executor,
        proof=proof,
        policy_digest=policy_digest,
        approvals=approvals,
        grants=grants,
        memberships=memberships,
        required_approvals=required_approvals,
        separation_of_duties=separation_of_duties,
        consumed_ids=consumed_ids,
    )


def _verify(
    plan: ExecutionPlan = PLAN, inputs: ApprovalGateInputs | None = None, **kwargs: Any
) -> ApprovalGateResult:
    return verify_approvals(plan, inputs if inputs is not None else _gate(), **kwargs)


def _triggers(result: ApprovalGateResult) -> tuple[InvalidationReason, ...]:
    return result.refusal.triggers if result.refusal is not None else ()


# =============================================================================
# 0. Digest-scheme unity and gate-input hygiene
# =============================================================================


def test_candidate_plan_digest_is_the_one_digest_the_system_agrees_on() -> None:
    """Three producers, one hash — so "the plan changed" cannot mean two things."""
    assert candidate_plan_digest(PLAN) == plan_content_digest(PLAN.model_dump(mode="json"))
    assert candidate_plan_digest(PLAN) == canonical_plan_digest(PLAN)
    assert candidate_plan_digest(PLAN) == str(diff_plans(PLAN, PLAN)["authored_hash"])
    # And it is the digest the proof and the approval bind to.
    assert PROOF.plan_digest == candidate_plan_digest(PLAN)
    assert _mint().plan_digest == candidate_plan_digest(PLAN)


def test_gate_inputs_refuse_a_naive_clock() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _gate(now=datetime(2026, 3, 1, 12, 0))  # noqa: DTZ001 — the point of the row
    assert excinfo.value.rule == "approval.gate_naive_clock"


@pytest.mark.parametrize(
    "field, value",
    [
        ("policy_digest", "not-a-digest"),
        ("policy_digest", ""),
    ],
)
def test_gate_inputs_refuse_a_policy_digest_that_is_not_a_digest(field: str, value: str) -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        replace(_gate(), **{field: value})
    assert excinfo.value.rule == "approval.gate_digest_malformed"


def test_gate_inputs_refuse_a_quorum_below_one() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        replace(_gate(), required_approvals=0)
    assert excinfo.value.rule == "approval.gate_quorum_arithmetic"


def test_with_now_is_a_replay_not_a_re_approval() -> None:
    approval = _mint()
    inputs = _gate(approvals=(approval,), now=T0)
    assert _verify(inputs=inputs).allowed
    replayed = inputs.with_now(T0 + timedelta(days=1))
    assert replayed.now == T0 + timedelta(days=1)
    assert _verify(inputs=replayed).denied


def test_the_gate_is_pure_across_repeated_evaluation() -> None:
    inputs = _gate(approvals=(_mint(),), now=T0)
    first, second = _verify(inputs=inputs), _verify(inputs=inputs)
    assert first.evidence() == second.evidence()
    assert first.describe() == second.describe()


# =============================================================================
# 1. The refusal matrix — one row per invalidation trigger
# =============================================================================


#: A gate whose happy path is a single valid approval from Alice, in production,
#: against this plan, this proof, and this policy. Every row below perturbs
#: exactly one thing, which is what makes "``reasons == (row,)``" worth
#: asserting rather than merely suggestive.
def _matrix_row(reason: InvalidationReason) -> ApprovalGateInputs:
    approval = _rebind(_mint(), **_APPROVAL_MUTATIONS.get(reason, {}))
    overrides = _GATE_OVERRIDES.get(reason)
    if overrides is None:
        return _gate(approvals=(approval,))
    if "approvals" in overrides:
        return _gate(**overrides)
    return _gate(**overrides, approvals=(approval,))


#: How each row breaks the *record* (rebound on the standing valid approval).
_APPROVAL_MUTATIONS: dict[InvalidationReason, dict[str, Any]] = {
    InvalidationReason.PLAN_DIGEST_MISMATCH: {"plan_digest": digest({"plan": "someone else's"})},
    InvalidationReason.EXPIRED: {
        "issued_at": BEFORE - timedelta(hours=2),
        "expires_at": BEFORE,
    },
    # Alice is replaced by a service account that was granted nothing: the
    # approval is otherwise perfectly formed, and only the role is missing.
    InvalidationReason.APPROVER_ROLE: {"approver": SRE_SA},
    InvalidationReason.OVERRIDE_WITHOUT_REASON: {"override": True, "override_reason": ""},
    # Scoping the *record* rather than the run keeps the executor authorized in
    # the environment the gate acts in, so no second trigger can co-fire.
    InvalidationReason.ENVIRONMENT_SCOPE: {"environment": STAGING},
}

#: How each row breaks the *run* (what the gate is asked about).
_GATE_OVERRIDES: dict[InvalidationReason, dict[str, Any]] = {
    InvalidationReason.POLICY_DIGEST_MISMATCH: {"policy_digest": digest({"bundle": "other"})},
    # A later VOID rendering of the same obligations is a different proof.
    InvalidationReason.PROOF_DIGEST_MISMATCH: {"proof": _passing_proof(digest({"plan": "moved"}))},
    # Dana holds approve *and* execute: only separation of duties refuses.
    InvalidationReason.SELF_APPROVED: {
        "approvals": (_mint("a-2", approver=DANA),),
        "executor": DANA,
        "separation_of_duties": True,
    },
    InvalidationReason.REVOKED: {
        "approvals": _ledger(_mint()).revoke("a-1", revoked_by="u-admin", now=BEFORE).approvals
    },
    InvalidationReason.REPLAYED: {"consumed_ids": frozenset({"a-1"})},
    InvalidationReason.NO_APPROVALS: {"approvals": ()},
    InvalidationReason.QUORUM_NOT_MET: {"required_approvals": 2},
}


def _rebind(approval: Approval, **changes: Any) -> Approval:
    """The same record with named fields replaced — re-validated, never patched."""
    return Approval.model_validate({**approval.model_dump(), **changes})


MATRIX = tuple(InvalidationReason)

#: Every rule id the approval gate can refuse under. A row tripped by an
#: unusable proof is refused by the proof check rather than the quorum check,
#: so the matrix asserts membership here and exactness on the triggers.
APPROVAL_RULE_IDS = frozenset(
    {RULE_APPROVAL_EXECUTOR_UNAUTHORIZED, RULE_APPROVAL_PROOF_NOT_PASS, RULE_APPROVAL_REQUIRED}
)


def _expected_triggers(reason: InvalidationReason) -> tuple[InvalidationReason, ...]:
    """The exact trigger tuple a row must produce, and no more.

    ``evaluate_approvals`` adds :data:`InvalidationReason.QUORUM_NOT_MET` beside
    a discarded approval's own reason — "one of two required, and the one you
    have is revoked" is the diagnosis — except for the empty set, which is
    ``NO_APPROVALS`` alone.
    """
    if reason in (InvalidationReason.NO_APPROVALS, InvalidationReason.QUORUM_NOT_MET):
        return (reason,)
    return (reason, InvalidationReason.QUORUM_NOT_MET)


@pytest.mark.parametrize("reason", MATRIX, ids=lambda r: r.value)
def test_every_trigger_refuses_the_run_at_admission(reason: InvalidationReason) -> None:
    result = _verify(inputs=_matrix_row(reason))
    assert result.denied, f"{reason.value} did not refuse the run"
    assert result.refusal is not None
    assert result.refusal.rule_id in APPROVAL_RULE_IDS
    assert result.refusal.triggers == _expected_triggers(reason), "the row tripped only its own"


@pytest.mark.parametrize("reason", MATRIX, ids=lambda r: r.value)
def test_every_trigger_refuses_inside_validate_plan(reason: InvalidationReason) -> None:
    """The refusal happens at admission, not merely in the helper."""
    ctx = _ctx(approval_gate=_matrix_row(reason))
    with pytest.raises(SafetyRefusedError) as excinfo:
        validate_plan(PLAN, _graph(), ctx)
    decision = excinfo.value.decision
    assert decision is not None
    assert decision.rule_id in APPROVAL_RULE_IDS
    # The trigger is named in the sealed record, not only in the rule id.
    assert decision.inputs["approvals"]["reasons"] == [
        trigger.value for trigger in _expected_triggers(reason)
    ]


def test_the_happy_path_authorizes_and_names_its_approver() -> None:
    result = _verify(inputs=_gate(approvals=(_mint(),)))
    assert result.allowed
    assert result.state.approvers == ("u-alice",)
    assert result.describe().startswith("ALLOW")
    assert not result.overridden
    assert result.evidence()["allowed"] is True


def test_a_refusal_enumerates_every_trigger_rather_than_the_first() -> None:
    """Three things moved, so the operator is told three things."""
    result = _verify(
        inputs=_gate(
            approvals=(
                _rebind(
                    _mint(),
                    plan_digest=digest({"plan": "fork"}),
                    policy_digest=digest({"bundle": "fork"}),
                ),
            ),
            policy_digest=digest({"bundle": "current"}),
            required_approvals=2,
        )
    )
    assert result.denied
    assert result.refusal is not None
    assert set(result.refusal.triggers) == {
        InvalidationReason.PLAN_DIGEST_MISMATCH,
        InvalidationReason.POLICY_DIGEST_MISMATCH,
        InvalidationReason.QUORUM_NOT_MET,
    }
    # Enumerated in the canonical order, not the order they were noticed.
    assert _triggers(result) == tuple(sorted(result.refusal.triggers, key=_reason_order))


def _reason_order(reason: InvalidationReason) -> int:
    return MATRIX.index(reason)


# =============================================================================
# 2. Authorization: role plus environment scope
# =============================================================================


def test_an_executor_with_no_execute_role_is_refused() -> None:
    grants = (*_grant_for(ALICE, Role.APPROVE),)
    result = _verify(inputs=_gate(approvals=(_mint(ledger=_ledger(grants=grants)),), grants=grants))
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.rule_id == RULE_APPROVAL_EXECUTOR_UNAUTHORIZED
    assert "u-mallory" in result.refusal.reason
    assert result.authorization.missing == (Role.EXECUTE,)


def test_authorization_is_scoped_to_the_environment_being_acted_on() -> None:
    """A staging execute grant does not reach production."""
    # Mallory may execute in staging only; Alice may approve in both, so the
    # refusal has exactly one cause.
    staging = (
        _grant(MALLORY, Role.EXECUTE, scope=STAGING),
        _grant(ALICE, Role.APPROVE, scope=STAGING),
        _grant(ALICE, Role.APPROVE),
    )
    result = _verify(
        inputs=_gate(
            approvals=(_mint(ledger=_ledger(grants=staging)),), grants=staging, environment=PROD
        )
    )
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.rule_id == RULE_APPROVAL_EXECUTOR_UNAUTHORIZED
    # The same grant reaches staging, which is the asymmetry doing the work.
    staging_approval = _mint("a-1", scope=STAGING, ledger=_ledger(grants=staging))
    assert _verify(
        inputs=_gate(approvals=(staging_approval,), grants=staging, environment=STAGING)
    ).allowed


def test_an_org_wide_execute_grant_reaches_every_environment() -> None:
    grants = (
        _grant(ALICE, Role.APPROVE, scope=ORG_WIDE),
        _grant(MALLORY, Role.EXECUTE, scope=EnvironmentScope(environment=ANY_ENVIRONMENT)),
    )
    approval = _mint("a-1", scope=ORG_WIDE, ledger=_ledger(grants=grants))
    for environment in (PROD, STAGING):
        assert _verify(
            inputs=_gate(approvals=(approval,), grants=grants, environment=environment)
        ).allowed


def test_a_team_grant_confers_the_role_through_membership() -> None:
    """The executor holds no direct grant at all; the team is what grants it."""
    grants = (_grant(ALICE, Role.APPROVE), _grant(MALLORY, Role.EXECUTE, team_id="t-sre"))
    approval = _mint(ledger=_ledger(grants=grants, memberships=_memberships()))
    assert _verify(
        inputs=_gate(
            approvals=(approval,),
            grants=grants,
            memberships=_memberships(),
        )
    ).allowed
    # ...and only while the membership is in force.
    lapsed = (
        TeamMembership(
            principal=MALLORY,
            team_id="t-sre",
            joined_at=YESTERDAY,
            until=T0 - timedelta(seconds=1),
        ),
    )
    result = _verify(inputs=_gate(approvals=(approval,), grants=grants, memberships=lapsed))
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.rule_id == RULE_APPROVAL_EXECUTOR_UNAUTHORIZED


def test_an_expired_execute_grant_stops_conferring_anything() -> None:
    grants = (
        _grant(ALICE, Role.APPROVE),
        _grant(MALLORY, Role.EXECUTE, expires_at=T0 - timedelta(seconds=1)),
    )
    result = _verify(inputs=_gate(approvals=(_mint(),), grants=grants))
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.rule_id == RULE_APPROVAL_EXECUTOR_UNAUTHORIZED


def test_authorization_is_asked_before_the_approvals_are_read() -> None:
    """An unauthorized executor is refused even with a perfect approval."""
    perfect = _mint()
    result = _verify(inputs=_gate(approvals=(perfect,), executor=SRE_SA))
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.rule_id == RULE_APPROVAL_EXECUTOR_UNAUTHORIZED
    # The approvals were still evaluated and are visible in the sealed record —
    # the gate refuses for the one reason, not because it stopped looking.
    assert result.state.approvers == ("u-alice",)


def test_executor_may_run_is_the_authorization_half_on_its_own() -> None:
    assert executor_may_run(_gate()) is True
    assert executor_may_run(_gate(executor=SRE_SA)) is False
    assert executor_may_run(_gate(), role=Role.APPROVE) is False


# =============================================================================
# 3. Separation of duties — on and off
# =============================================================================


def test_execute_alone_can_never_self_approve_even_with_the_switch_off() -> None:
    """The role separation is unconditional; only the *holder* separation is a switch."""
    forged = _rebind(_mint(), approver=MALLORY)
    for switch in (False, True):
        result = _verify(
            inputs=_gate(approvals=(forged,), executor=MALLORY, separation_of_duties=switch)
        )
        assert result.denied, f"separation_of_duties={switch} let EXECUTE-only self-approve"
        assert result.refusal is not None
        assert InvalidationReason.APPROVER_ROLE in result.refusal.triggers


def test_separation_of_duties_on_refuses_a_dual_role_approver() -> None:
    result = _verify(
        inputs=_gate(
            approvals=(_mint("a-1", approver=DANA),),
            executor=DANA,
            separation_of_duties=True,
        )
    )
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.triggers == _expected_triggers(InvalidationReason.SELF_APPROVED)
    assert result.state.discarded[0].approver == "u-dana"


def test_separation_of_duties_off_permits_a_dual_role_approver() -> None:
    """Off means the roles are still separate, they just need not be held apart."""
    result = _verify(
        inputs=_gate(
            approvals=(_mint("a-1", approver=DANA),),
            executor=DANA,
            separation_of_duties=False,
        )
    )
    assert result.allowed
    assert result.state.approvers == ("u-dana",)
    assert result.separation_of_duties is False


def test_separation_of_duties_on_still_accepts_a_second_person() -> None:
    result = _verify(
        inputs=_gate(
            approvals=(_mint("a-1", approver=ALICE),),
            executor=DANA,
            separation_of_duties=True,
        )
    )
    assert result.allowed


# =============================================================================
# 4. The approval service
# =============================================================================


def test_mint_binds_the_plan_policy_and_proof_digests() -> None:
    approval = _mint()
    assert approval.plan_digest == candidate_plan_digest(PLAN)
    assert approval.policy_digest == POLICY_DIGEST
    assert approval.proof_digest == PROOF.proof_digest
    assert approval.approver == ALICE
    assert approval.expires_at == BEFORE + timedelta(seconds=900.0)


def test_mint_refuses_an_approver_with_no_approve_grant() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _mint(approver=MALLORY)
    assert excinfo.value.rule == "approval.minting_unauthorized"
    assert "approve" in str(excinfo.value)


def test_mint_refuses_an_override_with_no_reason() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _mint(override=True, override_reason="   ")
    assert excinfo.value.rule == "approval.override_requires_reason"


def test_mint_refuses_a_reused_approval_id_even_after_it_was_consumed() -> None:
    """An id is spent once; the ledger that holds it says so first."""
    ledger = _ledger(_mint("a-1"))
    spent = ledger.consume(["a-1"])
    for held in (ledger, spent):
        with pytest.raises(InvariantViolationError) as excinfo:
            held.mint(
                approval_id="a-1",
                proof=PROOF,
                policy_digest=POLICY_DIGEST,
                approver=BOB,
                environment=PROD,
                now=BEFORE,
            )
        # Held *and* consumed is refused as a duplicate: the record exists, so
        # the more specific answer is the one an operator can act on.
        assert excinfo.value.rule == "approval.duplicate_id"


def test_mint_refuses_a_proof_that_did_not_pass() -> None:
    void = PROOF.voided(digest({"plan": "superseded"}))
    with pytest.raises(InvariantViolationError) as excinfo:
        _mint(proof=void)
    assert excinfo.value.rule == "approval.requires_passing_proof"


def test_revoke_then_execute_is_refused_and_names_the_revoker() -> None:
    approval = _mint()
    revoked = _ledger(approval).revoke("a-1", revoked_by="u-admin", now=BEFORE)
    record = revoked.find("a-1")
    assert record is not None
    assert record.revoked
    assert record.revoked_by == "u-admin"
    result = _verify(inputs=_gate(approvals=revoked.approvals))
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.triggers == _expected_triggers(InvalidationReason.REVOKED)
    # The reason names the approval, not the person who pulled it: a revocation
    # is a fact about the record, and the revoker is on the record itself.
    assert "a-1" in str(result.evidence()["approvals"]["discarded"])


def test_revocation_changes_the_record_digest_so_the_old_one_cannot_pass() -> None:
    approval = _mint()
    revoked = _ledger(approval).revoke("a-1", revoked_by="u-admin", now=BEFORE)
    assert revoked.find("a-1").approval_digest != approval.approval_digest  # type: ignore[union-attr]


def test_revoking_twice_keeps_the_first_revocation() -> None:
    once = _ledger(_mint()).revoke("a-1", revoked_by="u-admin", now=BEFORE)
    twice = once.revoke("a-1", revoked_by="u-someone-else", now=T0)
    assert twice.find("a-1").revoked_by == "u-admin"  # type: ignore[union-attr]
    assert twice == once


def test_revoking_an_unknown_approval_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _ledger().revoke("a-404", revoked_by="u-admin", now=BEFORE)
    assert excinfo.value.rule == "approval.unknown"


def test_expiry_is_reported_at_the_boundary_and_never_lets_a_lapsed_one_run() -> None:
    expiring = _mint(now=BEFORE, ttl_s=900.0)
    ledger = _ledger(expiring)
    report = ledger.expire(expiring.expires_at - timedelta(seconds=1))
    assert report.lapsed == ()
    assert report.live == (expiring,)
    assert report.next_expiry == expiring.expires_at
    assert "0 lapsed, 1 live" in report.describe()
    # At-and-after, matching Approval.is_expired and the policy bundle's rule.
    at_boundary = ledger.expire(expiring.expires_at)
    assert at_boundary.lapsed == (expiring,)
    assert at_boundary.live == ()
    assert at_boundary.next_expiry is None
    result = _verify(inputs=_gate(approvals=(expiring,), now=expiring.expires_at))
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.triggers == _expected_triggers(InvalidationReason.EXPIRED)


def test_an_approval_with_no_expiry_never_lapses() -> None:
    forever = _mint(ttl_s=None)
    report = _ledger(forever).expire(T0 + timedelta(days=3650))
    assert report.lapsed == ()
    assert report.live == (forever,)
    assert report.next_expiry is None


def test_a_changed_plan_invalidates_every_prior_approval() -> None:
    """The PlanMerge rule, reached through PlanMerge rather than re-derived."""
    ledger = _ledger(_mint("a-1"), _mint("a-2", approver=BOB))
    same = ledger.invalidate_on_plan_change(
        checked_plan_digest=PLAN_DIGEST, merged_plan_digest=PLAN_DIGEST, now=T0
    )
    assert same.invalidated == ()
    assert len(same.surviving) == 2
    assert "every approval stands" in same.describe()

    changed = ledger.invalidate_on_plan_change(
        checked_plan_digest=PLAN_DIGEST,
        merged_plan_digest=digest({"plan": "a merged change"}),
        now=T0,
    )
    assert len(changed.invalidated) == 2
    assert changed.surviving == ()
    assert changed.merge.changed is True
    assert "is not the checked digest" in changed.reason


def test_invalidation_survives_a_plan_change_only_against_a_foreign_approval() -> None:
    foreign = _rebind(_mint("a-2", approver=BOB), plan_digest=digest({"x": 1}))
    ledger = _ledger(_mint("a-1"), foreign)
    result = ledger.invalidate_on_plan_change(
        checked_plan_digest=PLAN_DIGEST, merged_plan_digest=PLAN_DIGEST, now=T0
    )
    assert [a.approval_id for a in result.invalidated] == ["a-2"]
    assert [a.approval_id for a in result.surviving] == ["a-1"]


def test_consuming_an_approval_makes_its_replay_refused() -> None:
    approval = _mint()
    ledger = _ledger(approval)
    spent = ledger.consume(["a-1"])
    assert spent.consumed_ids == frozenset({"a-1"})
    inputs = spent.gate_inputs(
        now=T0, environment=PROD, executor=MALLORY, proof=PROOF, policy_digest=POLICY_DIGEST
    )
    assert inputs.approvals == (approval,)
    assert inputs.consumed_ids == frozenset({"a-1"})
    assert inputs.grants == ledger.grants
    result = _verify(inputs=inputs)
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.triggers == _expected_triggers(InvalidationReason.REPLAYED)


def test_consuming_an_approval_the_ledger_does_not_hold_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _ledger().consume(["a-404"])
    assert excinfo.value.rule == "approval.consume_unknown"


def test_gate_inputs_takes_the_authorizations_from_the_ledger_not_the_caller() -> None:
    """A caller cannot check against a different grant set than the one held."""
    ledger = _ledger(_mint())
    inputs = ledger.gate_inputs(
        now=T0, environment=PROD, executor=MALLORY, proof=PROOF, policy_digest=POLICY_DIGEST
    )
    assert inputs.grants == ledger.grants
    assert inputs.memberships == ledger.memberships
    assert inputs.approvals == ledger.approvals
    assert _verify(inputs=inputs).allowed
    # ...and overrides are still available, for the caller's own policy choice.
    assert (
        ledger.gate_inputs(
            now=T0,
            environment=PROD,
            executor=MALLORY,
            proof=PROOF,
            policy_digest=POLICY_DIGEST,
            separation_of_duties=True,
        ).separation_of_duties
        is True
    )


# =============================================================================
# 5. Emergency override — it executes, it seals, and it is not an ordinary approval
# =============================================================================


OVERRIDE_REASON = "sev-1 page: db primary unreachable, waiting on the change window"


def test_an_emergency_override_executes() -> None:
    approval = _mint("a-1", override=True, override_reason=OVERRIDE_REASON)
    result = _verify(inputs=_gate(approvals=(approval,)))
    assert result.allowed
    assert result.overridden
    assert result.describe().startswith("OVERRIDE")
    assert OVERRIDE_REASON in result.describe()


def test_an_override_seals_the_overriding_principal_and_reason_into_evidence() -> None:
    approval = _mint("a-1", approver=DANA, override=True, override_reason=OVERRIDE_REASON)
    evidence = _verify(inputs=_gate(approvals=(approval,), executor=MALLORY)).evidence()
    assert evidence["overrides"] == [
        {
            "approval_id": "a-1",
            "principal": "u-dana",
            "reason": OVERRIDE_REASON,
            "environment": "production",
            "approval_digest": approval.approval_digest,
        }
    ]
    # The seal covers the override: recomputing it from the payload reproduces
    # the digest, and editing the reason in the payload breaks it.
    payload = {k: v for k, v in evidence.items() if k != "sealed_digest"}
    assert evidence["sealed_digest"] == sha256_hex(canonical_json(payload))
    tampered = {**payload, "overrides": [{"principal": "u-someone-else"}]}
    assert sha256_hex(canonical_json(tampered)) != evidence["sealed_digest"]


def test_an_override_is_distinguishable_from_an_ordinary_approval_downstream() -> None:
    """Different rule id, different severity, and both principal and reason in text."""
    ordinary_ctx = _ctx(approval_gate=_gate(approvals=(_mint(),)))
    validate_plan(PLAN, _graph(), ordinary_ctx)
    ordinary = [d for d in ordinary_ctx.decisions if d.rule_id == RULE_APPROVAL_ALLOW]
    assert len(ordinary) == 1
    assert ordinary_ctx.warnings == []

    override = _mint("a-1", override=True, override_reason=OVERRIDE_REASON)
    override_ctx = _ctx(approval_gate=_gate(approvals=(override,)))
    validate_plan(PLAN, _graph(), override_ctx)
    marks = [d for d in override_ctx.decisions if d.rule_id == RULE_APPROVAL_OVERRIDE]
    assert len(marks) == 1
    assert "u-alice" in marks[0].reason
    assert OVERRIDE_REASON in marks[0].reason
    assert override_ctx.warnings == [marks[0].reason]
    # The rendered decision — what reaches the evidence envelope's
    # safety_decisions — names the override in text, not only in a field.
    assert "u-alice" in str(marks[0])
    # Both decisions are present: the override never hides the authorization.
    assert len([d for d in override_ctx.decisions if d.rule_id == RULE_APPROVAL_ALLOW]) == 1
    # And the sealed digests differ, so an ordinary run's record cannot be
    # mistaken for an overridden one downstream.
    override_allow = next(d for d in override_ctx.decisions if d.rule_id == RULE_APPROVAL_ALLOW)
    assert ordinary[0].inputs["sealed_digest"] != override_allow.inputs["sealed_digest"]
    assert override_allow.inputs["overrides"][0]["principal"] == "u-alice"


def test_an_override_without_a_reason_never_executes() -> None:
    forged = _rebind(_mint(), override=True, override_reason="")
    result = _verify(inputs=_gate(approvals=(forged,)))
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.triggers == _expected_triggers(InvalidationReason.OVERRIDE_WITHOUT_REASON)


def test_an_override_still_needs_an_authorised_approver() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _mint(
            "a-1",
            approver=MALLORY,
            override=True,
            override_reason=OVERRIDE_REASON,
        )
    assert excinfo.value.rule == "approval.minting_unauthorized"


# =============================================================================
# 6. Admission integration, and the no-approvals golden
# =============================================================================


#: Golden rendering of a full validation pass with no approval gate configured.
#: Captured from the tree *before* this phase existed (identical to the one in
#: ``tests/unit/test_policy_gate.py``). Any drift in the existing gate — a
#: reworded reason, a reordered check, a decision recorded at a different point,
#: or an approval decision leaking into a run that configured no approvals —
#: breaks these four lines.
GOLDEN_NO_APPROVALS = "\n".join(
    (
        "policy.allow|allow|proc.pause: admitted||['fault_id', 'risk']",
        "blast_radius.allow|allow|proc.pause: blast radius within budget||['fault_id', 'stats']",
        "policy.allow|allow|net.latency: admitted||['fault_id', 'risk']",
        "blast_radius.allow|allow|net.latency: blast radius within budget||['fault_id', 'stats']",
    )
)


def test_no_approvals_configured_is_byte_identical_to_the_golden() -> None:
    ctx = _ctx()
    assert ctx.approval_gate is None
    validate_plan(_plan("proc.pause", "net.latency"), _graph(), ctx)
    assert _dump(ctx) == GOLDEN_NO_APPROVALS


def test_the_gate_is_reached_from_admission_and_not_merely_callable() -> None:
    """A helper nobody calls is not a gate; this one refuses the run itself."""
    ctx = _ctx(approval_gate=_gate())  # no approvals offered at all
    with pytest.raises(SafetyRefusedError, match=RULE_APPROVAL_REQUIRED):
        validate_plan(PLAN, _graph(), ctx)
    # And it refused *before* the per-step admission loop: no fault was
    # admitted, so there is no blast-radius decision on record.
    assert all(d.rule_id != "blast_radius.allow" for d in ctx.decisions)
    assert [d.rule_id for d in ctx.decisions] == [RULE_APPROVAL_REQUIRED]


def test_an_authorized_run_records_the_approval_decision_and_nothing_else_changes() -> None:
    ctx = _ctx(approval_gate=_gate(approvals=(_mint(),)))
    validate_plan(PLAN, _graph(), ctx)
    assert [d.rule_id for d in ctx.decisions] == [
        RULE_APPROVAL_ALLOW,
        "policy.allow",
        "blast_radius.allow",
    ]
    assert ctx.warnings == []


def test_the_approval_gate_is_optional_and_defaults_to_absent() -> None:
    names = [f.name for f in fields(SafetyContext)]
    assert "approval_gate" in names
    legacy = SafetyContext(policy=PolicyCfg(), budget=BlastRadiusBudget(), fingerprint="f")
    assert legacy.approval_gate is None


def test_the_approval_gate_runs_without_a_policy_bundle() -> None:
    """Approvals are not a policy-bundle feature; a bundle is not required."""
    ctx = _ctx(approval_gate=_gate())
    assert ctx.policy_gate is None
    with pytest.raises(SafetyRefusedError, match=RULE_APPROVAL_REQUIRED):
        validate_plan(PLAN, _graph(), ctx)


# -- policy requirements raise the quorum ---------------------------------------


def _approval_bundle(*levels: str) -> PolicyBundle:
    """A bundle whose approval-level rule matches while no level is held.

    ``NOT_IN`` rather than ``IN`` for the reason :meth:`PolicyPredicate.matches`
    gives: with ``IN`` the rule only speaks once somebody already holds one of
    the levels, which reports the *remainder* rather than the requirement.
    """
    rule = PolicyRule(
        rule_id="prod.approval-level",
        dimension=PolicyDimension.APPROVAL_LEVEL,
        predicate=PolicyPredicate(operator=PolicyOperator.NOT_IN, values=tuple(levels)),
        effect=PolicyEffect.ALLOW,
        reason="this plan needs sign-off",
    )
    return PolicyBundle(
        bundle_id="prod-approvals",
        version=3,
        rules=(rule,),
        default_effect=PolicyEffect.ALLOW,
        created_at=YESTERDAY,
    )


def test_policy_surfaced_approval_levels_are_now_enforced_at_admission() -> None:
    """The gap this phase closes: the policy gate names the levels, this checks them."""
    bundle = _approval_bundle("sre", "service_owner")
    policy_inputs = PolicyGateInputs(
        bundle=bundle,
        now=T0,
        observed={PolicyDimension.APPROVAL_LEVEL: ("routine",)},
    )
    gate = evaluate_gate(PLAN, policy_inputs, environment="production")
    # Sorted by level, as ``required_approvals`` reports them.
    assert [a.approval_level for a in gate.required_approvals] == [
        "service_owner",
        "sre",
    ]

    ctx = _ctx(policy_gate=policy_inputs, approval_gate=_gate())
    with pytest.raises(SafetyRefusedError, match="Outstanding levels: service_owner, sre"):
        validate_plan(PLAN, _graph(), ctx)
    # Both halves spoke: the policy gate recorded one warning per level it
    # requires, then the approval gate refused for want of them.
    assert [d.outcome for d in ctx.decisions] == ["warn", "warn", "allow", "deny"]
    assert [d.inputs["approval_level"] for d in ctx.decisions[:2]] == [
        "service_owner",
        "sre",
    ]
    refusal = ctx.decisions[3]
    # The refusal's inputs are the sealed payload, so the quorum the policy
    # raised and the levels it named are both machine-readable.
    assert refusal.inputs["approvals"]["required"] == 2
    assert refusal.inputs["unbound_levels"] == ["service_owner", "sre"]
    assert refusal.inputs["refusal"]["triggers"] == ["no_approvals"]

    # Two distinct approvers satisfy the count the policy asked for.
    two = _mint("a-1"), _mint("a-2", approver=BOB)
    allowed = _ctx(policy_gate=policy_inputs, approval_gate=_gate(approvals=two))
    validate_plan(PLAN, _graph(), allowed)
    assert any(d.rule_id == RULE_APPROVAL_ALLOW for d in allowed.decisions)
    # The levels are still named on the allow, because Phase 2 enforces the count
    # and cannot yet bind a level to a role. That gap is stated, not hidden.
    allow = next(d for d in allowed.decisions if d.rule_id == RULE_APPROVAL_ALLOW)
    assert allow.inputs["unbound_levels"] == ["service_owner", "sre"]


def test_quorum_from_requirements_is_the_maximum_of_configuration_and_levels() -> None:
    from mayhem.domain.policy_gate import required_approvals as _required

    bundle = _approval_bundle("sre", "service_owner", "oncall")
    inputs = PolicyGateInputs(
        bundle=bundle,
        now=T0,
        observed={PolicyDimension.APPROVAL_LEVEL: ("routine",)},
    )
    levels = _required(bundle.rules, evaluate_gate(PLAN, inputs, environment="production").facts)
    assert [level.approval_level for level in levels] == ["oncall", "service_owner", "sre"]
    assert quorum_from_requirements(levels) == 3
    assert quorum_from_requirements(levels, configured=5) == 5
    assert quorum_from_requirements((), configured=2) == 2
    assert quorum_from_requirements(()) == 1


def test_the_policy_gate_still_speaks_before_the_approval_gate() -> None:
    """An approval cannot legalize a plan the policy half refuses."""
    from mayhem.domain.policy import PolicyDimension as Dimension

    deny = PolicyRule(
        rule_id="prod.forbids",
        dimension=Dimension.ENVIRONMENT,
        predicate=PolicyPredicate(operator=PolicyOperator.IN, values=("production",)),
        effect=PolicyEffect.DENY,
        reason="production policy forbids this",
    )
    bundle = PolicyBundle(
        bundle_id="prod-approvals",
        version=3,
        rules=(deny,),
        default_effect=PolicyEffect.ALLOW,
        created_at=YESTERDAY,
    )
    ctx = _ctx(
        policy_gate=PolicyGateInputs(bundle=bundle, now=T0),
        approval_gate=_gate(approvals=(_mint(),)),
        environment="production",
    )
    with pytest.raises(SafetyRefusedError, match="production policy forbids this"):
        validate_plan(PLAN, _graph(), ctx)
    assert not any(d.rule_id.startswith("approval.") for d in ctx.decisions)


# =============================================================================
# 7. Negative controls — the privilege escalations the plan names
# =============================================================================


def test_negative_control_a_user_cannot_approve_a_modified_plan_with_an_old_approval() -> None:
    """Approve, then change one duration: the approval stops speaking for it."""
    approved = _mint()
    modified = _plan("proc.pause", duration=6.0)
    assert candidate_plan_digest(modified) != approved.plan_digest
    result = _verify(plan=modified, inputs=_gate(approvals=(approved,)))
    assert result.denied
    assert result.refusal is not None
    assert InvalidationReason.PLAN_DIGEST_MISMATCH in result.refusal.triggers
    # ...and the proof is named as superseded rather than merely stale.
    assert result.proof_verdict is ProofVerdict.VOID


def test_negative_control_a_revoked_approvers_approval_is_worthless() -> None:
    approval = _mint()
    disabled = _rebind(approval, approver=_principal("u-alice", disabled=True))
    result = _verify(inputs=_gate(approvals=(disabled,)))
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.triggers == _expected_triggers(InvalidationReason.APPROVER_ROLE)

    # The same answer when the grant is withdrawn rather than the person
    # disabled: a grant to somebody nobody can authorize confers nothing.
    withdrawn = _verify(inputs=_gate(approvals=(approval,), grants=()))
    assert withdrawn.denied
    assert withdrawn.refusal is not None
    assert InvalidationReason.APPROVER_ROLE in withdrawn.refusal.triggers


def test_negative_control_a_cross_environment_replay_is_refused() -> None:
    """The same approval, replayed at the run it was not given for."""
    # Mallory may execute in both environments here, so the environment of the
    # *approval* is the only thing that differs between the two legs.
    grants = (*STANDING_GRANTS, _grant(MALLORY, Role.EXECUTE, scope=STAGING))
    approved_in_staging = _mint("a-1", scope=STAGING)
    assert _verify(
        inputs=_gate(approvals=(approved_in_staging,), environment=STAGING, grants=grants)
    ).allowed
    replayed = _verify(
        inputs=_gate(approvals=(approved_in_staging,), environment=PROD, grants=grants)
    )
    assert replayed.denied
    assert replayed.refusal is not None
    assert replayed.refusal.triggers == _expected_triggers(InvalidationReason.ENVIRONMENT_SCOPE)


def test_negative_control_an_execute_only_principal_cannot_self_approve() -> None:
    """Both halves: the service refuses to mint it, and the gate refuses it."""
    with pytest.raises(InvariantViolationError) as excinfo:
        _mint("a-1", approver=MALLORY)
    assert excinfo.value.rule == "approval.minting_unauthorized"

    forged = _rebind(_mint(), approver=MALLORY)
    result = _verify(inputs=_gate(approvals=(forged,), executor=MALLORY))
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.triggers == _expected_triggers(InvalidationReason.APPROVER_ROLE)


def test_negative_control_an_approval_over_a_void_proof_is_refused() -> None:
    """The proof digest pins the verdict, so a later VOID stops matching it."""
    approval = _mint()
    voided = PROOF.voided(digest({"plan": "a later state of the world"}))
    assert voided.verdict is ProofVerdict.VOID
    result = _verify(inputs=_gate(approvals=(approval,), proof=voided))
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.rule_id == RULE_APPROVAL_PROOF_NOT_PASS
    assert InvalidationReason.PROOF_DIGEST_MISMATCH in result.refusal.triggers
    assert "VOID" in result.refusal.reason


def test_a_proof_that_never_passed_is_refused_even_with_a_matching_approval() -> None:
    """An approval cannot be bound to a non-passing proof, so this is defence in depth."""
    incomplete = SafetyProof(
        plan_digest=PLAN_DIGEST,
        obligations=PROOF.obligations[:3],
        verdict=ProofVerdict.VOID,
        void_reason="required obligations absent",
        generated_at=BEFORE,
    )
    assert incomplete.obligations[:3]  # not empty: the line count is the point
    result = _verify(inputs=_gate(proof=incomplete, approvals=(_mint(),)))
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.rule_id == RULE_APPROVAL_PROOF_NOT_PASS
    # The report names the proof *and* the fact that the approval no longer
    # matches it, rather than stopping at whichever check it asked first.
    assert InvalidationReason.PROOF_DIGEST_MISMATCH in result.refusal.triggers
    assert "required obligations absent" in result.refusal.reason


def test_the_same_person_approving_twice_is_one_signature() -> None:
    """Quorum counts distinct principals; a second signature is not a second person."""
    result = _verify(inputs=_gate(approvals=(_mint("a-1"), _mint("a-2")), required_approvals=2))
    assert result.denied
    assert result.refusal is not None
    assert result.refusal.triggers == _expected_triggers(InvalidationReason.QUORUM_NOT_MET)


def test_a_different_but_equally_ungated_plan_is_gated_the_same_way() -> None:
    """The gate is about the tuple, not about how risky the fault looked."""
    other = _plan("net.latency")
    other_proof = _passing_proof(candidate_plan_digest(other))
    approval = _mint("a-1", proof=other_proof)
    assert _verify(plan=other, inputs=_gate(approvals=(approval,), proof=other_proof)).allowed
    ungated = _verify(plan=other, inputs=_gate(proof=other_proof))
    assert ungated.denied
    assert ungated.refusal is not None
    assert ungated.refusal.rule_id == RULE_APPROVAL_REQUIRED


# =============================================================================
# Mapping completeness — this module's refusals must be reportable on a line
# =============================================================================
#
# Added by plan 30 Phase 4. This module's author recorded the gap directly:
#
#   "Approval-refusal rule ids are unmapped in
#    `controller.safety_proof.OBLIGATION_FOR_RULE`, so a run refused by the
#    approval gate compiles to a `VOID` proof with the rule named unmapped.
#    Fail-closed and by that module's own design, but the honest fix ... belongs
#    to Phase 4."
#
# The fix landed; these two tests are the guard against the next lane repeating
# it. The wider coverage — every rule both gate modules can raise — lives in
# `tests/unit/test_proof_compiler.py`, which parses the sources. What belongs
# here is the check a reader of *this* module would want: its own three refusal
# ids, asserted against its own rule constants, plus the admission behaviour the
# mapping buys.


def test_every_refusal_this_module_raises_is_owned_by_a_proof_line() -> None:
    """All three refusals land on ``required_approvals``.

    Stated here as well as in the compiler suite because this module is where a
    future refusal would be added, and the constants below are the module's own.
    If a fourth refusal is added and nobody maps it, this fails by name.
    """
    for rule in (
        RULE_APPROVAL_EXECUTOR_UNAUTHORIZED,
        RULE_APPROVAL_PROOF_NOT_PASS,
        RULE_APPROVAL_REQUIRED,
    ):
        assert OBLIGATION_FOR_RULE.get(rule) == ObligationName.REQUIRED_APPROVALS.value, rule


def test_its_allow_and_override_rules_are_not_blameable_and_so_need_no_line() -> None:
    """The non-refusal rules stay unmapped, and that is correct.

    ``approval.allow`` and ``approval.override`` are recorded on the *allow*
    path — the override one as a warning beside a decision that permitted the
    run. Mapping them would claim an owning line for a rule that can never
    refuse, which would let the blame pass name a line for something that
    happened to succeed. Asserted so a future "map everything for safety" pass
    does not quietly add them.
    """
    assert RULE_APPROVAL_ALLOW not in OBLIGATION_FOR_RULE
    assert RULE_APPROVAL_OVERRIDE not in OBLIGATION_FOR_RULE


def test_an_approval_refused_plan_compiles_to_a_reported_fail_not_an_unplaceable_void() -> None:
    """The gap's actual symptom, asserted at the boundary that produced it.

    Before the mapping this compiled to a whole-proof ``VOID`` whose
    ``void_reason`` said "a gate refused on a rule no obligation owns". The gate
    had *refused*, which is a finding about the plan and belongs on a line — so
    the rule is now blamed on ``required_approvals`` and named in that line's own
    detail.

    The overall verdict is deliberately *not* asserted here. This module's
    ``_plan`` fixture carries no undo contract and the compiler is given no
    adapter, so ``compensation``, ``recovery_path`` and ``capability_requirements``
    are unestablished independently of any approval — and ``VOID`` outranks
    ``FAIL``. Asserting ``FAIL`` would be asserting something about this
    fixture, not about the mapping. The end-to-end ``FAIL`` verdict over an
    otherwise-admitted plan is asserted in ``tests/unit/test_proof_compiler.py``;
    what this test owns is that the refusal is *placed*.
    """
    from mayhem.controller.safety_proof import compile_safety_evidence

    plan = _plan("proc.pause")
    # The gate's proof must be over this plan's digest, or the *proof* check
    # fires first and the quorum refusal under test would be masked.
    plan_proof = _passing_proof(candidate_plan_digest(plan))
    ctx = replace(_ctx(), approval_gate=_gate(proof=plan_proof))

    compilation = compile_safety_evidence(plan, _graph(), ctx)

    # The gate refused on the quorum, and that refusal is the authoritative one.
    assert compilation.gate_refusals == (RULE_APPROVAL_REQUIRED,)
    # It is blamed on a named line...
    blamed = compilation.blame[ObligationName.REQUIRED_APPROVALS.value]
    assert any(RULE_APPROVAL_REQUIRED in entry for entry in blamed)
    # ...the line reports it in its own text...
    line = compilation.proof.obligation(ObligationName.REQUIRED_APPROVALS.value)
    assert line is not None
    assert line.status is ObligationStatus.FAIL
    assert RULE_APPROVAL_REQUIRED in line.detail
    # ...and the pre-fix symptom is gone: no refusal is unplaceable any more.
    assert "no obligation owns" not in compilation.proof.void_reason
