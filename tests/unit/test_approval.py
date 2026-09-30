"""Plan 09 Phase 1 — approvals as statements about an exact plan.

The suite is organized the way the plan states the requirement, then the way a
reviewer wants to attack it:

1. the approval-validity matrix — one row per invalidation trigger, plus the
   happy path;
2. "modified plan invalidates approval" as a property of a pure function, over
   real plan payloads and real mutations of them;
3. multi-approver quorum arithmetic;
4. expiry boundaries, including the exact boundary instant;
5. override handling — including override-without-reason, which is refused;
6. negative controls — self-approval under separation of duties, a replayed
   approval id, cross-environment replay, a revoked approver;
7. digest-scheme unity, so "the plan changed" means one thing everywhere.

Everything is driven by explicit inputs, including the clock. No test reads
``utc_now()`` and no test opens a socket, a file, or a subprocess: the property
under test is that the verdict is a function of (plan, policy, proof, approvals,
grants, now) and of nothing else.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import ValidationError

from mayhem.controller.plan_diff import diff_plans
from mayhem.domain.approval import (
    DEFAULT_APPROVAL_TTL_S,
    Approval,
    ApprovalState,
    ChangeTicket,
    InvalidationReason,
    approval_reasons,
    evaluate_approval,
    evaluate_approvals,
    plan_content_digest,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.execution_intent import DEFAULT_APPROVAL_TTL_S as INTENT_TTL_S
from mayhem.domain.hashing import digest
from mayhem.domain.identity import (
    ANY_ENVIRONMENT,
    EnvironmentScope,
    Principal,
    PrincipalKind,
    Role,
    RoleGrant,
    TeamMembership,
    effective_roles,
    has_role,
    team_ids_for,
)
from mayhem.domain.safety_proof import (
    REQUIRED_OBLIGATIONS,
    Obligation,
    ObligationName,
    ObligationStatus,
    ProofVerdict,
    SafetyProof,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
BEFORE = T0 - timedelta(seconds=1)
AFTER = T0 + timedelta(seconds=1)
YESTERDAY = T0 - timedelta(days=1)

PROD = EnvironmentScope(environment="production")
STAGING = EnvironmentScope(environment="staging")
ORG_WIDE = EnvironmentScope.any()

# -- fixtures-as-values (no shared mutable state, so order cannot matter) -------

PLAN: dict[str, Any] = {
    "profile": "staging",
    "steps": [
        {"id": "s1", "fault": "net.latency", "target": "svc-a", "params": {"ms": 250}},
        {"id": "s2", "fault": "process.kill", "target": "svc-b"},
    ],
}
PLAN_DIGEST = plan_content_digest(PLAN)
POLICY_DIGEST = digest({"bundle": "default", "version": 1, "rules": []})
PROOF_DIGEST = digest({"proof": "plan-30", "verdict": "PASS"})


def _principal(pid: str, **kwargs: Any) -> Principal:
    kwargs.setdefault("display_name", pid.replace("-", " ").title())
    return Principal(principal_id=pid, **kwargs)


ALICE = _principal("u-alice")
BOB = _principal("u-bob")
MALLORY = _principal("sa-mallory", kind=PrincipalKind.SERVICE_ACCOUNT)


def _grant(
    principal: Principal,
    *,
    role: Role = Role.APPROVE,
    scope: EnvironmentScope = PROD,
    **kwargs: Any,
) -> RoleGrant:
    return RoleGrant(role=role, scope=scope, principal=principal, granted_at=BEFORE, **kwargs)


def _approver_grants(
    *principals: Principal,
    scope: EnvironmentScope = PROD,
    role: Role = Role.APPROVE,
) -> tuple[RoleGrant, ...]:
    return tuple(_grant(p, role=role, scope=scope) for p in principals)


#: The standing fixture's authorization state: Alice and Bob may approve
#: production, Mallory holds only EXECUTE. Giving Mallory an approve grant would
#: hide the ``approver_role`` trigger, so her role separation is deliberate.
DEFAULT_GRANTS: tuple[RoleGrant, ...] = (
    *_approver_grants(ALICE, BOB),
    _grant(MALLORY, role=Role.EXECUTE),
)


def _approval(
    approval_id: str = "a-1",
    *,
    plan_digest: str = PLAN_DIGEST,
    policy_digest: str = POLICY_DIGEST,
    proof_digest: str = PROOF_DIGEST,
    approver: Principal = ALICE,
    environment: EnvironmentScope = PROD,
    issued_at: datetime = BEFORE,
    expires_at: datetime | None = AFTER,
    **kwargs: Any,
) -> Approval:
    return Approval(
        approval_id=approval_id,
        plan_digest=plan_digest,
        policy_digest=policy_digest,
        proof_digest=proof_digest,
        approver=approver,
        environment=environment,
        issued_at=issued_at,
        expires_at=expires_at,
        **kwargs,
    )


def _evaluate(approvals: Iterable[Approval], **overrides: Any) -> ApprovalState:
    """The happy path, with named deviations applied on top."""
    kwargs: dict[str, Any] = {
        "plan_digest": PLAN_DIGEST,
        "policy_digest": POLICY_DIGEST,
        "proof_digest": PROOF_DIGEST,
        "environment": PROD,
        "now": T0,
        "grants": DEFAULT_GRANTS,
    }
    kwargs.update(overrides)
    return evaluate_approvals(approvals, **kwargs)


def _reasons(approval: Approval, **overrides: Any) -> tuple[InvalidationReason, ...]:
    kwargs: dict[str, Any] = {
        "plan_digest": PLAN_DIGEST,
        "policy_digest": POLICY_DIGEST,
        "proof_digest": PROOF_DIGEST,
        "environment": PROD,
        "grants": DEFAULT_GRANTS,
        "now": T0,
    }
    kwargs.update(overrides)
    return approval_reasons(approval, **kwargs)


# =============================================================================
# 1. The approval-validity matrix — every trigger, exactly once
# =============================================================================

#: The seven triggers the plan names, in the plan's order.
PLAN_TRIGGERS: tuple[InvalidationReason, ...] = (
    InvalidationReason.PLAN_DIGEST_MISMATCH,
    InvalidationReason.POLICY_DIGEST_MISMATCH,
    InvalidationReason.PROOF_DIGEST_MISMATCH,
    InvalidationReason.EXPIRED,
    InvalidationReason.ENVIRONMENT_SCOPE,
    InvalidationReason.APPROVER_ROLE,
    InvalidationReason.OVERRIDE_WITHOUT_REASON,
)


#: One deviation per matrix row, as ``_approval`` keyword overrides. A dict
#: rather than a chain of branches, so a row cannot accidentally trip two
#: triggers — that is what makes the ``reasons == (reason,)`` assertion below
#: worth anything.
_TRIGGER_OVERRIDES: dict[InvalidationReason, dict[str, Any]] = {
    InvalidationReason.PLAN_DIGEST_MISMATCH: {"plan_digest": digest({"plan": "someone elses"})},
    InvalidationReason.POLICY_DIGEST_MISMATCH: {
        "policy_digest": digest({"bundle": "strict", "version": 9})
    },
    InvalidationReason.PROOF_DIGEST_MISMATCH: {
        "proof_digest": digest({"proof": "a later VOID rendering"})
    },
    InvalidationReason.EXPIRED: {"issued_at": BEFORE - timedelta(hours=2), "expires_at": BEFORE},
    InvalidationReason.ENVIRONMENT_SCOPE: {"environment": STAGING},
    # Mallory holds only EXECUTE in the standing fixture — role separation.
    InvalidationReason.APPROVER_ROLE: {"approver": MALLORY},
    InvalidationReason.OVERRIDE_WITHOUT_REASON: {"override": True, "override_reason": ""},
}


def _trigger_approval(reason: InvalidationReason) -> Approval:
    """One approval invalid for ``reason`` and for no other reason."""
    overrides = _TRIGGER_OVERRIDES.get(reason)
    if overrides is None:  # pragma: no cover - the table above is the whole matrix
        raise AssertionError(f"no matrix row for {reason}")
    return _approval(**overrides)


@pytest.mark.parametrize("reason", PLAN_TRIGGERS, ids=lambda r: r.value)
def test_each_trigger_invalidates_the_approval(reason: InvalidationReason) -> None:
    approval = _trigger_approval(reason)
    assert _reasons(approval) == (reason,)


@pytest.mark.parametrize("reason", PLAN_TRIGGERS, ids=lambda r: r.value)
def test_each_trigger_refuses_the_evaluation(reason: InvalidationReason) -> None:
    state = _evaluate([_trigger_approval(reason)])
    assert not state.valid
    assert state.has(reason)
    assert not state.quorum_met, "a discarded approval cannot satisfy a 1-of-1 quorum"
    assert [d.reasons for d in state.discarded] == [(reason,)]


def test_happy_path_is_valid_and_names_its_approver() -> None:
    state = _evaluate([_approval()])
    assert state.valid
    assert state.reasons == ()
    assert state.approvers == ("u-alice",)
    assert state.quorum_met
    assert "u-alice" in state.describe()


def test_no_approvals_at_all_is_refused() -> None:
    state = _evaluate([])
    assert not state.valid
    assert state.reasons == (InvalidationReason.NO_APPROVALS,)


def test_every_trigger_at_once_is_enumerated_not_short_circuited() -> None:
    """The verdict enumerates; it does not stop at the first problem.

    A caller that reads one reason would otherwise conclude "just re-approve"
    for a plan/policy/proof triple that all moved.
    """
    broken = Approval(
        approval_id="a-broken",
        plan_digest=digest({"plan": "changed"}),
        policy_digest=digest({"bundle": "changed"}),
        proof_digest=digest({"proof": "changed"}),
        approver=MALLORY,
        environment=STAGING,
        issued_at=BEFORE - timedelta(hours=2),
        expires_at=BEFORE,
        override=True,
    )
    state = _evaluate([broken])
    assert not state.valid
    assert set(state.reasons) == {
        InvalidationReason.PLAN_DIGEST_MISMATCH,
        InvalidationReason.POLICY_DIGEST_MISMATCH,
        InvalidationReason.PROOF_DIGEST_MISMATCH,
        InvalidationReason.ENVIRONMENT_SCOPE,
        InvalidationReason.EXPIRED,
        InvalidationReason.APPROVER_ROLE,
        InvalidationReason.OVERRIDE_WITHOUT_REASON,
        InvalidationReason.QUORUM_NOT_MET,
    }


def test_reasons_are_reported_in_canonical_order_not_argument_order() -> None:
    broken = _trigger_approval(InvalidationReason.PLAN_DIGEST_MISMATCH)
    reversed_kwargs = _reasons(broken, policy_digest=POLICY_DIGEST, proof_digest=digest({"x": 1}))
    assert reversed_kwargs == (
        InvalidationReason.PLAN_DIGEST_MISMATCH,
        InvalidationReason.PROOF_DIGEST_MISMATCH,
    )


def test_state_cannot_be_valid_and_carry_reasons() -> None:
    """``valid`` is a fact about ``reasons``, not an independent opinion."""
    with pytest.raises(InvariantViolationError) as excinfo:
        ApprovalState(valid=True, reasons=(InvalidationReason.EXPIRED,))
    assert excinfo.value.rule == "approval_state.valid_with_reasons"


def test_discarded_approvals_are_reported_with_their_reasons() -> None:
    stale = _approval("a-2", issued_at=BEFORE - timedelta(hours=2), expires_at=BEFORE)
    state = _evaluate([_approval("a-1"), stale])
    assert state.valid, "the live approval alone satisfies 1-of-1"
    assert [(d.approval_id, d.reasons) for d in state.discarded] == [
        ("a-2", (InvalidationReason.EXPIRED,))
    ]


# =============================================================================
# 2. "Modified plan invalidates approval" — the pure property
# =============================================================================

#: Real mutations of ``PLAN``. Each is a change a human would make between the
#: approved version and the version about to run.
MUTATIONS: dict[str, dict[str, Any]] = {
    "added step": {
        **PLAN,
        "steps": [*PLAN["steps"], {"id": "s3", "fault": "net.latency", "target": "svc-c"}],
    },
    "removed step": {"profile": "staging", "steps": [PLAN["steps"][0]]},
    "reordered steps": {"profile": "staging", "steps": list(reversed(PLAN["steps"]))},
    "changed fault type": {
        **PLAN,
        "steps": [{**PLAN["steps"][0], "fault": "net.packet_loss"}, PLAN["steps"][1]],
    },
    "changed target": {
        **PLAN,
        "steps": [{**PLAN["steps"][0], "target": "svc-z"}, PLAN["steps"][1]],
    },
    "changed parameter": {
        **PLAN,
        "steps": [{**PLAN["steps"][0], "params": {"ms": 9999}}, PLAN["steps"][1]],
    },
    "changed profile": {**PLAN, "profile": "production"},
}


@pytest.mark.parametrize("mutation", sorted(MUTATIONS), ids=sorted(MUTATIONS))
def test_modified_plan_invalidates_the_approval(mutation: str) -> None:
    candidate = MUTATIONS[mutation]
    approval = _approval()
    assert plan_content_digest(candidate) != approval.plan_digest, mutation
    assert not approval.speaks_for(
        plan_digest=plan_content_digest(candidate),
        policy_digest=POLICY_DIGEST,
        proof_digest=PROOF_DIGEST,
        environment=PROD,
    )
    assert _reasons(approval, plan_digest=plan_content_digest(candidate)) == (
        InvalidationReason.PLAN_DIGEST_MISMATCH,
    )


def test_unmodified_plan_keeps_the_approval() -> None:
    approval = _approval()
    assert plan_content_digest(PLAN) == approval.plan_digest
    assert approval.speaks_for(
        plan_digest=PLAN_DIGEST,
        policy_digest=POLICY_DIGEST,
        proof_digest=PROOF_DIGEST,
        environment=PROD,
    )
    assert _evaluate([approval]).valid


def test_property_holds_for_every_single_field_mutation() -> None:
    """Walk the payload rather than a hand-written list of mutations."""
    changed = 0
    for step_index, step in enumerate(PLAN["steps"]):
        for key in sorted(step):
            mutated = {
                **PLAN,
                "steps": [
                    {**s, **({key: "different-value"} if i == step_index else {})}
                    for i, s in enumerate(PLAN["steps"])
                ],
            }
            approval = _approval()
            assert not approval.speaks_for(
                plan_digest=plan_content_digest(mutated),
                policy_digest=POLICY_DIGEST,
                proof_digest=PROOF_DIGEST,
                environment=PROD,
            ), f"changing {step['id']}.{key} did not invalidate the approval"
            changed += 1
    assert changed >= 5


def test_digest_is_order_insensitive_but_content_sensitive() -> None:
    """Key order is not a change; content is."""
    reordered = {
        "steps": [
            {"params": {"ms": 250}, "target": "svc-a", "fault": "net.latency", "id": "s1"},
            {"id": "s2", "target": "svc-b", "fault": "process.kill"},
        ],
        "profile": "staging",
    }
    assert plan_content_digest(reordered) == PLAN_DIGEST


# =============================================================================
# 3. Multi-approver quorum arithmetic
# =============================================================================


def test_two_of_two_is_valid() -> None:
    state = _evaluate(
        [_approval("a-1", approver=ALICE), _approval("a-2", approver=BOB)],
        required_approvals=2,
    )
    assert state.valid
    assert state.approvers == ("u-alice", "u-bob")
    assert "2/2" in state.describe()


def test_one_of_two_is_refused() -> None:
    state = _evaluate([_approval("a-1", approver=ALICE)], required_approvals=2)
    assert not state.valid
    assert state.reasons == (InvalidationReason.QUORUM_NOT_MET,)


def test_the_same_principal_twice_is_one_signature() -> None:
    """Four approvals from one person is not four approvers."""
    state = _evaluate(
        [_approval(f"a-{index}", approver=ALICE) for index in range(4)],
        required_approvals=2,
    )
    assert not state.valid
    assert state.has(InvalidationReason.QUORUM_NOT_MET)
    assert state.approvers == ("u-alice",)
    assert state.discarded == ()


def test_one_expired_approver_does_not_sink_a_satisfied_quorum() -> None:
    state = _evaluate(
        [
            _approval("a-1", approver=ALICE),
            _approval("a-2", approver=BOB),
            _approval(
                "a-3", approver=MALLORY, issued_at=BEFORE - timedelta(hours=2), expires_at=BEFORE
            ),
        ],
        required_approvals=2,
    )
    assert state.valid
    assert state.approvers == ("u-alice", "u-bob")
    assert [d.approval_id for d in state.discarded] == ["a-3"]


def test_quorum_below_one_is_refused_as_an_arithmetic_error() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _evaluate([_approval()], required_approvals=0)
    assert excinfo.value.rule == "approval.quorum_arithmetic"


def test_quorum_of_three_needs_three_distinct_principals() -> None:
    two = _evaluate(
        [_approval("a-1", approver=ALICE), _approval("a-2", approver=BOB)],
        required_approvals=3,
    )
    assert two.reasons == (InvalidationReason.QUORUM_NOT_MET,)
    three = _evaluate(
        [
            _approval("a-1", approver=ALICE),
            _approval("a-2", approver=BOB),
            _approval("a-3", approver=MALLORY),
        ],
        required_approvals=3,
        grants=_approver_grants(ALICE, BOB, MALLORY),
    )
    assert three.valid
    assert three.approvers == ("sa-mallory", "u-alice", "u-bob")


# =============================================================================
# 4. Expiry boundaries
# =============================================================================


def test_not_yet_expired_is_valid() -> None:
    approval = _approval(issued_at=T0, expires_at=T0 + timedelta(seconds=1))
    assert not approval.is_expired(T0)
    assert _evaluate([approval], now=T0).valid


def test_expiry_boundary_belongs_to_the_expired_side() -> None:
    """At-and-after, so the last millisecond of validity is *before* ``expires_at``."""
    approval = _approval(issued_at=T0, expires_at=T0 + timedelta(seconds=10))
    assert not approval.is_expired(T0 + timedelta(seconds=9, microseconds=999999))
    assert approval.is_expired(T0 + timedelta(seconds=10))
    assert _reasons(approval, now=T0 + timedelta(seconds=10)) == (InvalidationReason.EXPIRED,)


def test_an_approval_with_no_expiry_never_expires() -> None:
    approval = _approval(expires_at=None)
    assert not approval.is_expired(T0 + timedelta(days=3650))
    assert _evaluate([approval], now=T0 + timedelta(days=3650)).valid


def test_expiry_at_or_before_issue_is_unrepresentable() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _approval(issued_at=T0, expires_at=T0)
    assert excinfo.value.rule == "approval.window"
    with pytest.raises(InvariantViolationError):
        _approval(issued_at=T0, expires_at=T0 - timedelta(seconds=1))


# =============================================================================
# 5. Override — recorded, never sufficient, never unreasoned
# =============================================================================


def test_override_without_a_reason_is_refused() -> None:
    approval = _approval(override=True, override_reason="   ")
    state = _evaluate([approval])
    assert not state.valid
    assert state.has(InvalidationReason.OVERRIDE_WITHOUT_REASON)


def test_an_unreasoned_override_is_mintable_so_the_attempt_is_on_record() -> None:
    """Construction must not erase the evidence that somebody tried."""
    approval = _approval(override=True)
    assert approval.override
    assert approval.override_reason == ""


def test_override_with_a_reason_is_valid_and_still_marked() -> None:
    approval = _approval(override=True, override_reason="sev1, page on-call, review after")
    assert _evaluate([approval]).valid


# =============================================================================
# 6. Negative controls
# =============================================================================


def test_you_cannot_approve_your_own_plan_when_separation_of_duties_is_on() -> None:
    approval = _approval(approver=ALICE)
    state = _evaluate(
        [approval],
        separation_of_duties=True,
        plan_author="u-alice",
    )
    assert not state.valid
    assert state.reasons == (
        InvalidationReason.SELF_APPROVED,
        InvalidationReason.QUORUM_NOT_MET,
    )


def test_separation_of_duties_off_allows_self_approval() -> None:
    state = _evaluate([_approval(approver=ALICE)], plan_author="u-alice")
    assert state.valid


def test_separation_of_duties_only_bites_the_plan_author() -> None:
    state = _evaluate([_approval(approver=BOB)], separation_of_duties=True, plan_author="u-alice")
    assert state.valid


def test_a_replayed_approval_id_is_refused() -> None:
    approval = _approval("a-1")
    assert _evaluate([approval]).valid, "first use is legitimate"
    replay = _evaluate([approval], consumed_ids=["a-1"])
    assert not replay.valid
    assert replay.reasons == (InvalidationReason.REPLAYED, InvalidationReason.QUORUM_NOT_MET)
    assert replay.discarded[0].reasons == (InvalidationReason.REPLAYED,)


def test_a_replay_from_a_different_principal_is_still_a_replay() -> None:
    state = _evaluate([_approval("a-1", approver=BOB)], consumed_ids=["a-1"])
    assert state.has(InvalidationReason.REPLAYED)


def test_an_approval_bound_to_another_environment_is_refused() -> None:
    """Cross-environment replay: a staging approval cannot authorize production."""
    approval = _approval(environment=STAGING)
    state = _evaluate([approval], environment=PROD)
    assert not state.valid
    assert state.has(InvalidationReason.ENVIRONMENT_SCOPE)


def test_an_approval_in_the_right_environment_is_honoured() -> None:
    state = _evaluate(
        [_approval(environment=STAGING)],
        environment=STAGING,
        grants=_approver_grants(ALICE, scope=STAGING),
    )
    assert state.valid


def test_a_wildcard_scope_reaches_any_environment() -> None:
    approval = _approval(environment=ORG_WIDE)
    org_wide_grants = (*_approver_grants(ALICE), *_approver_grants(ALICE, scope=STAGING))
    assert _evaluate([approval], environment=PROD).valid
    assert _evaluate([approval], environment=STAGING, grants=org_wide_grants).valid


def test_a_project_narrowing_is_not_crossed() -> None:
    scoped = EnvironmentScope(environment=PROD.environment, project="payments")
    other = EnvironmentScope(environment=PROD.environment, project="search")
    assert _evaluate([_approval(environment=scoped)], environment=other).has(
        InvalidationReason.ENVIRONMENT_SCOPE
    )
    assert _evaluate([_approval(environment=scoped)], environment=scoped).valid


def test_execute_without_approve_does_not_approve() -> None:
    """Role separation: holding EXECUTE is not holding APPROVE."""
    grants = _approver_grants(MALLORY, role=Role.EXECUTE)
    state = _evaluate([_approval(approver=MALLORY)], grants=grants)
    assert state.has(InvalidationReason.APPROVER_ROLE)


def test_a_revoke_role_does_not_approve() -> None:
    grants = _approver_grants(MALLORY, role=Role.EMERGENCY_STOP)
    assert _evaluate([_approval(approver=MALLORY)], grants=grants).has(
        InvalidationReason.APPROVER_ROLE
    )


def test_no_grants_at_all_is_default_deny() -> None:
    state = _evaluate([_approval()], grants=())
    assert state.has(InvalidationReason.APPROVER_ROLE)


def test_an_approver_scoped_to_staging_cannot_approve_production() -> None:
    grants = _approver_grants(ALICE, scope=STAGING)
    assert _evaluate([_approval()], grants=grants).has(InvalidationReason.APPROVER_ROLE)


def test_a_disabled_approver_holds_nothing() -> None:
    disabled = Principal(principal_id="u-alice", disabled=True)
    grants = _approver_grants(disabled)
    state = _evaluate([_approval(approver=disabled)], grants=grants)
    assert state.has(InvalidationReason.APPROVER_ROLE)


def test_a_revoked_approval_is_refused_even_while_live() -> None:
    approval = _approval(revoked_at=BEFORE, revoked_by="u-bob")
    state = _evaluate([approval])
    assert not state.valid
    assert state.reasons == (InvalidationReason.REVOKED, InvalidationReason.QUORUM_NOT_MET)


def test_a_revocation_must_name_who_revoked_it() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        _approval(revoked_at=BEFORE)
    assert excinfo.value.rule == "approval.revocation_needs_actor"


def test_a_team_grant_approves_through_membership() -> None:
    membership = TeamMembership(principal=ALICE, team_id="t-sre", joined_at=BEFORE)
    grant = RoleGrant(role=Role.APPROVE, scope=PROD, team_id="t-sre", granted_at=BEFORE)
    state = _evaluate([_approval(approver=ALICE)], grants=[grant], memberships=[membership])
    assert state.valid


def test_a_team_grant_does_not_reach_a_non_member() -> None:
    membership = TeamMembership(principal=BOB, team_id="t-sre", joined_at=BEFORE)
    grant = RoleGrant(role=Role.APPROVE, scope=PROD, team_id="t-sre", granted_at=BEFORE)
    state = _evaluate([_approval(approver=ALICE)], grants=[grant], memberships=[membership])
    assert state.has(InvalidationReason.APPROVER_ROLE)


def test_an_expired_membership_does_not_carry_a_team_grant() -> None:
    membership = TeamMembership(
        principal=ALICE, team_id="t-sre", joined_at=YESTERDAY, until=T0 - timedelta(seconds=1)
    )
    grant = RoleGrant(role=Role.APPROVE, scope=PROD, team_id="t-sre", granted_at=BEFORE)
    state = _evaluate([_approval(approver=ALICE)], grants=[grant], memberships=[membership])
    assert state.has(InvalidationReason.APPROVER_ROLE)


def test_an_expired_role_grant_approves_nothing() -> None:
    grant = RoleGrant(
        role=Role.APPROVE,
        scope=PROD,
        principal=ALICE,
        granted_at=YESTERDAY,
        expires_at=T0 - timedelta(seconds=1),
    )
    assert _evaluate([_approval()], grants=[grant]).has(InvalidationReason.APPROVER_ROLE)


# =============================================================================
# 7. Digest-scheme unity and proof binding
# =============================================================================


def test_plan_digest_is_the_same_digest_the_diff_reports() -> None:
    """No parallel digest scheme: ``plan_diff`` and this module must agree."""
    diff = diff_plans(PLAN, PLAN)
    assert diff["authored_hash"] == plan_content_digest(PLAN)
    mutated = diff_plans(MUTATIONS["changed target"], PLAN)
    assert mutated["accepted_hash"] == plan_content_digest(PLAN)
    assert not mutated["equal"]


def test_default_ttl_matches_the_execution_intent_default() -> None:
    assert DEFAULT_APPROVAL_TTL_S == INTENT_TTL_S


def _passing_proof(plan_digest: str = PLAN_DIGEST) -> SafetyProof:
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
    assert set(REQUIRED_OBLIGATIONS) == {name.value for name in ObligationName}
    return SafetyProof(
        plan_digest=plan_digest,
        obligations=obligations,
        verdict=ProofVerdict.PASS,
        generated_at=BEFORE,
    )


def test_bind_takes_the_plan_digest_from_the_proof() -> None:
    proof = _passing_proof()
    approval = Approval.bind(
        approval_id="a-1",
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approver=ALICE,
        environment=PROD,
        issued_at=BEFORE,
    )
    assert approval.plan_digest == proof.plan_digest == plan_content_digest(PLAN)
    assert approval.proof_digest == proof.proof_digest
    assert approval.expires_at == BEFORE + timedelta(seconds=DEFAULT_APPROVAL_TTL_S)


def test_bind_refuses_a_proof_that_did_not_pass() -> None:
    proof = _passing_proof().voided(digest({"plan": "different"}))
    assert proof.verdict is ProofVerdict.VOID
    with pytest.raises(InvariantViolationError) as excinfo:
        Approval.bind(
            approval_id="a-1",
            proof=proof,
            policy_digest=POLICY_DIGEST,
            approver=ALICE,
            environment=PROD,
        )
    assert excinfo.value.rule == "approval.requires_passing_proof"


def test_an_approval_cannot_outlive_its_proof() -> None:
    """The proof digest pins the verdict, so a later VOID stops matching."""
    proof = _passing_proof()
    approval = Approval.bind(
        approval_id="a-1",
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approver=ALICE,
        environment=PROD,
        issued_at=BEFORE,
    )
    assert _evaluate([approval], proof_digest=proof.proof_digest).valid
    voided = proof.voided(digest({"plan": "superseded"}))
    assert voided.proof_digest != proof.proof_digest
    state = _evaluate([approval], proof_digest=voided.proof_digest)
    assert state.has(InvalidationReason.PROOF_DIGEST_MISMATCH)


def test_approval_digest_covers_the_window() -> None:
    short = _approval(expires_at=T0 + timedelta(seconds=60))
    long = _approval(expires_at=T0 + timedelta(seconds=600))
    assert short.approval_digest != long.approval_digest
    assert short.approval_digest == _approval(expires_at=T0 + timedelta(seconds=60)).approval_digest


# =============================================================================
# 8. The identity vocabulary, exercised through the approval entry point
# =============================================================================


def test_principal_equality_is_identity_only() -> None:
    renamed = Principal(principal_id="u-alice", display_name="Alice Renamed", email="a@example.com")
    assert renamed == ALICE
    assert hash(renamed) == hash(ALICE)
    assert renamed != BOB


def test_principal_is_hashable_as_a_key() -> None:
    assert len({ALICE, _principal("u-alice", display_name="Alice Renamed"), BOB}) == 2


def test_effective_roles_unions_direct_and_team_grants() -> None:
    membership = TeamMembership(principal=ALICE, team_id="t-sre", joined_at=BEFORE)
    grants = [
        RoleGrant(role=Role.VIEW, scope=PROD, principal=ALICE, granted_at=BEFORE),
        RoleGrant(role=Role.APPROVE, scope=PROD, team_id="t-sre", granted_at=BEFORE),
        RoleGrant(role=Role.EXECUTE, scope=STAGING, principal=ALICE, granted_at=BEFORE),
    ]
    roles = effective_roles(grants, principal=ALICE, scope=PROD, memberships=[membership], now=T0)
    assert roles == {Role.VIEW, Role.APPROVE}
    assert has_role(
        grants,
        principal=ALICE,
        role=Role.EXECUTE,
        scope=STAGING,
        memberships=[membership],
        now=T0,
    )
    assert team_ids_for(ALICE, [membership], now=T0) == frozenset({"t-sre"})


def test_environment_scope_wildcard_is_a_value_not_an_absent_field() -> None:
    assert ORG_WIDE.is_wildcard
    assert ORG_WIDE.environment == ANY_ENVIRONMENT
    assert ORG_WIDE.covers(PROD)
    assert ORG_WIDE.covers(STAGING)
    assert PROD.key() == "//production"
    assert ORG_WIDE.describe() == "any environment"


def test_role_grant_must_name_exactly_one_addressee() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        RoleGrant(role=Role.APPROVE, scope=PROD, granted_at=BEFORE)
    assert excinfo.value.rule == "role_grant.addressee"
    with pytest.raises(InvariantViolationError):
        RoleGrant(
            role=Role.APPROVE, scope=PROD, principal=ALICE, team_id="t-sre", granted_at=BEFORE
        )


def test_change_tickets_are_recorded_on_the_approval() -> None:
    approval = _approval(
        change_tickets=(
            ChangeTicket(system="jira", key="CHG-1234", url="https://jira.example/CHG-1234"),
            ChangeTicket(system="linear", key="ENG-42"),
        )
    )
    assert [t.describe() for t in approval.change_tickets] == ["jira:CHG-1234", "linear:ENG-42"]


def test_a_blank_change_ticket_key_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        ChangeTicket(system="jira", key="  ")
    assert excinfo.value.rule == "change_ticket_not_blank"


def test_a_digest_field_must_be_a_sha256_hex_string() -> None:
    with pytest.raises(ValidationError):
        _approval(plan_digest="not-a-digest")


# =============================================================================
# 9. Determinism — the property the plan's replay requirement rests on
# =============================================================================


def test_the_same_inputs_produce_the_same_verdict() -> None:
    approvals = [
        _approval("a-1", approver=ALICE),
        _approval("a-2", approver=BOB, policy_digest=digest({"bundle": "other"})),
    ]
    first = _evaluate(approvals, required_approvals=2)
    second = _evaluate(list(reversed(approvals)), required_approvals=2)
    assert first.reasons == second.reasons
    assert first.approvers == second.approvers
    assert first.describe() == second.describe()


def test_single_approval_wrapper_agrees_with_the_set_form() -> None:
    approval = _approval()
    one = evaluate_approval(
        approval,
        plan_digest=PLAN_DIGEST,
        policy_digest=POLICY_DIGEST,
        proof_digest=PROOF_DIGEST,
        environment=PROD,
        now=T0,
        grants=_approver_grants(ALICE),
    )
    assert one == _evaluate([approval])


def test_evaluation_does_not_mutate_the_approvals_it_was_given() -> None:
    approval = _approval()
    before = approval.model_dump()
    _evaluate([approval], required_approvals=3)
    assert approval.model_dump() == before
