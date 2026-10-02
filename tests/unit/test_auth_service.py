"""Plan 09 Phase 3 — the authentication and authorization service.

Phase 1's suite (``test_approval.py``) proved the *types* decide. Phase 2's
(``test_approval_gate.py``) proved the gate is *reached*. This one proves the
service that answers "who is this, and what may they act?" — and, just as
importantly, proves what it refuses.

The organization follows the requirement list:

1. the role x environment x action matrix, over the Phase 1 vocabulary rather
   than a service-private one;
2. separation of duties, both settings, at both enforcement points (minting and
   the gate);
3. token lifecycle: issue, authenticate, rotate, revoke, expire — including that
   rotation leaves no window where both tokens work or neither does;
4. revocation propagation, with the bound *measured on an injected monotonic
   clock* rather than slept through, across two independent connections;
5. API keys: short-lived, scoped, hashed at rest, revocable, and never readable
   back out of the store;
6. the negative controls: a revoked approver, a cross-environment replay, a
   disabled principal, an expired session, an unauthorized mint, and a store
   with no plaintext in any column;
7. the enterprise walkthrough the plan's Phase 3 acceptance names —
   authenticate -> policy -> approve -> execute — end to end against a *faked*
   identity provider.

Every clock is injected and every input explicit. Nothing here reads
``utc_now()`` for a decision, and no assertion depends on wall time.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.controller.approval_gate import (
    RULE_APPROVAL_EXECUTOR_UNAUTHORIZED,
    ApprovalGateInputs,
    verify_approvals,
)
from mayhem.controller.auth_service import (
    DEFAULT_API_KEY_TTL_S,
    REFUSAL_API_KEY_EXPIRED,
    REFUSAL_API_KEY_UNKNOWN,
    REFUSAL_CREDENTIAL_INVALID,
    REFUSAL_MINT_UNAUTHORIZED,
    REFUSAL_PRINCIPAL_DISABLED,
    REFUSAL_PRINCIPAL_UNKNOWN,
    REFUSAL_PROVIDER_UNAVAILABLE,
    REFUSAL_ROLE_MISSING,
    REFUSAL_SELF_APPROVAL,
    REFUSAL_SESSION_EXPIRED,
    REFUSAL_SESSION_REVOKED,
    REFUSAL_SESSION_SCOPE,
    REFUSAL_SESSION_UNKNOWN,
    REVOCATION_PROPAGATION_BOUND_S,
    AuthMethod,
    AuthRefusedError,
    AuthService,
    CallableIdentityProvider,
    FederatedCredentials,
    StaticIdentityProvider,
)
from mayhem.domain.approval import Approval, InvalidationReason
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.hashing import digest
from mayhem.domain.identity import (
    ANY_ENVIRONMENT,
    EnvironmentScope,
    Principal,
    PrincipalKind,
    Role,
    RoleGrant,
    TeamMembership,
)
from mayhem.domain.safety_proof import (
    Obligation,
    ObligationName,
    ObligationStatus,
    ProofVerdict,
    SafetyProof,
)
from mayhem.domain.topology import NodeKind, TargetSelector
from mayhem.infra.identity_store import (
    CREDENTIAL_HASH_ALGORITHM,
    PASSWORD_HASH_ITERATIONS,
    AuthSource,
    IdentityStore,
    RevocationRecord,
    RevocationSubject,
    SessionKind,
    scope_from_json,
    scopes_to_json,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Iterator

# =============================================================================
# Fixtures-as-values
# =============================================================================

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
BEFORE = T0 - timedelta(seconds=1)
YESTERDAY = T0 - timedelta(days=1)
HOUR_LATER = T0 + timedelta(hours=1)

PROD = EnvironmentScope(environment="production")
STAGING = EnvironmentScope(environment="staging")
ORG_WIDE = EnvironmentScope.any()

POLICY_DIGEST = digest({"bundle": "prod-approvals", "version": 3})
OTHER_POLICY_DIGEST = digest({"bundle": "prod-approvals", "version": 4})

#: The eight roles the plan separates. Enumerated here so the matrix below fails
#: if a role is added to the domain vocabulary without a row saying what this
#: service does with it.
ALL_ROLES: tuple[Role, ...] = tuple(Role)

PEPPER = b"mayhem-test-pepper-not-a-real-secret"


@dataclass
class FakeClock:
    """A hand-advanced clock. Every time-dependent assertion drives this."""

    now: datetime = T0

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


@dataclass
class FakeMonotonic:
    """A hand-advanced monotonic reading, for the propagation bound."""

    value: float = 1000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> float:
        self.value += seconds
        return self.value


class Harness:
    """A migrated store, an identity store, and an :class:`AuthService`.

    Both clocks are injected and both are advanceable, so a test can say "three
    hours later" and "six seconds later" and get the same answer every run.
    """

    def __init__(self, path: str = ":memory:") -> None:
        self.store = Store.open_migrated(path)
        self.identity = IdentityStore(self.store)
        self.clock = FakeClock()
        self.monotonic = FakeMonotonic()
        self.service = AuthService(
            self.identity,
            pepper=PEPPER,
            clock=self.clock,
            monotonic=self.monotonic,
            # A low PBKDF2 work factor keeps the suite from being a benchmark;
            # ``test_default_password_work_factor_is_the_real_one`` asserts the
            # shipped default separately so this cannot quietly become posture.
            password_iterations=1_000,
        )

    def close(self) -> None:
        self.store.close()

    def add_human(self, principal_id: str, password: str = "correct-horse") -> Principal:
        principal = self.service.register_principal(
            Principal(principal_id=principal_id, display_name=principal_id), now=BEFORE
        )
        self.service.set_password(principal_id, password, now=BEFORE)
        return principal

    def grant(self, principal_id: str, role: Role, scope: EnvironmentScope = PROD) -> str:
        return self.service.grant_role(
            role=role, scope=scope, principal_id=principal_id, granted_by="u-root", now=YESTERDAY
        )


@pytest.fixture
def harness() -> Iterator[Harness]:
    built = Harness()
    yield built
    built.close()


# =============================================================================
# Plan / proof helpers
# =============================================================================


def _plan(*fault_ids: str) -> ExecutionPlan:
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="web")
    steps = tuple(
        PlannedStep(
            id=f"s{seq}",
            seq=seq,
            raw_action=InjectFault(fault=fault_id, selectors=(selector,), duration=5.0),
            fault=PlannedFault(
                fault_id=fault_id,
                targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"n-web"})),),
                duration=5.0,
            ),
        )
        for seq, fault_id in enumerate(fault_ids)
    )
    return ExecutionPlan(
        run_id="run-1",
        kind=ExperimentKind.DRILL,
        steps=steps,
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
    )


def _passing_proof(plan: ExecutionPlan) -> SafetyProof:
    from mayhem.controller.approval_gate import candidate_plan_digest

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
        plan_digest=candidate_plan_digest(plan),
        obligations=obligations,
        verdict=ProofVerdict.PASS,
        generated_at=BEFORE,
    )


@pytest.fixture
def plan() -> ExecutionPlan:
    return _plan("container.kill", "net.latency")


@pytest.fixture
def proof(plan: ExecutionPlan) -> SafetyProof:
    return _passing_proof(plan)


# =============================================================================
# 1. The role x environment x action matrix
# =============================================================================


def test_role_environment_action_matrix(harness: Harness, plan: ExecutionPlan) -> None:
    """Every (role, environment, action) row resolves the way the domain says.

    The action column is ``EXECUTE`` against the approval gate, which is the
    surface this phase's authority actually reaches: a role resolves, and the
    Phase 2 gate is what turns a resolved role into a permission. Each row
    asserts the resolved set *and* the gate's verdict, so a service that
    resolved correctly but handed the gate a different grant set would fail
    here rather than at execution.
    """
    harness.add_human("u-viewer")
    harness.add_human("u-runner")
    harness.add_human("u-runner-staging")
    harness.add_human("u-approver")
    harness.add_human("u-dana")

    harness.grant("u-viewer", Role.VIEW, PROD)
    harness.grant("u-runner", Role.EXECUTE, PROD)
    harness.grant("u-runner-staging", Role.EXECUTE, STAGING)
    harness.grant("u-approver", Role.APPROVE, PROD)
    harness.grant("u-dana", Role.APPROVE, PROD)
    harness.grant("u-dana", Role.EXECUTE, PROD)

    proof = _passing_proof(plan)
    matrix = {
        ("u-viewer", PROD): (frozenset({Role.VIEW}), False),
        ("u-viewer", STAGING): (frozenset(), False),
        ("u-runner", PROD): (frozenset({Role.EXECUTE}), True),
        ("u-runner", STAGING): (frozenset(), False),
        ("u-runner-staging", STAGING): (frozenset({Role.EXECUTE}), True),
        ("u-runner-staging", PROD): (frozenset(), False),
        ("u-approver", PROD): (frozenset({Role.APPROVE}), False),
        ("u-dana", PROD): (frozenset({Role.APPROVE, Role.EXECUTE}), True),
        ("u-dana", ORG_WIDE): (frozenset(), False),
    }

    for (principal_id, scope), (expected_roles, expected_execute) in matrix.items():
        principal = harness.service.principal(principal_id)
        assert principal is not None
        roles = harness.service.roles_for(principal, scope, now=T0)
        assert roles == expected_roles, f"{principal_id} in {scope.key()}"
        decision = harness.service.authorize(
            principal=principal, role=Role.EXECUTE, scope=scope, now=T0
        )
        assert decision.authorized is expected_execute, decision.describe()
        # The gate is given the service's own state and reaches the same answer.
        inputs = harness.service.gate_inputs(
            environment=scope,
            executor=principal,
            proof=proof,
            policy_digest=POLICY_DIGEST,
            approvals=(),
            now=T0,
        )
        result = verify_approvals(plan, inputs)
        assert result.authorization.authorized is expected_execute, result.describe()


def test_every_role_in_the_vocabulary_is_resolvable(harness: Harness) -> None:
    """No role in the vocabulary is special-cased, silently, by this service.

    Each of the eight is granted org-wide to one principal and must come back.
    A role added to :class:`~mayhem.domain.identity.Role` therefore cannot be
    handed to a caller as "granted" and resolve as nothing.
    """
    for index, role in enumerate(ALL_ROLES):
        principal_id = f"u-role-{index}"
        harness.service.register_principal(Principal(principal_id=principal_id), now=BEFORE)
        harness.grant(principal_id, role, ORG_WIDE)
        principal = harness.service.principal(principal_id)
        assert principal is not None
        assert harness.service.roles_for(principal, ORG_WIDE, now=T0) == frozenset({role})


def test_team_grants_reach_a_member_and_stop_at_a_non_member(
    harness: Harness,
) -> None:
    """A team grant is a grant; membership is what turns it into authority.

    Both halves, in one test, because the failure mode is asymmetric: granting
    the team too widely is a privilege escalation nobody notices, and granting it
    too narrowly is a support ticket.
    """
    harness.add_human("u-member")
    harness.add_human("u-outsider")
    harness.service.add_membership("u-member", team_id="t-sre", now=YESTERDAY)
    harness.service.grant_role(
        role=Role.APPROVE, scope=PROD, team_id="t-sre", granted_by="u-root", now=YESTERDAY
    )

    member = harness.service.principal("u-member")
    outsider = harness.service.principal("u-outsider")
    assert member is not None and outsider is not None
    assert harness.service.roles_for(member, PROD, now=T0) == frozenset({Role.APPROVE})
    assert harness.service.roles_for(outsider, PROD, now=T0) == frozenset()
    assert harness.service.teams("u-member", now=T0) == frozenset({"t-sre"})


def test_a_closed_membership_stops_conferring_at_its_deadline(harness: Harness) -> None:
    harness.add_human("u-leaver")
    harness.service.add_membership("u-leaver", team_id="t-sre", now=YESTERDAY, until=T0)
    harness.service.grant_role(
        role=Role.EXECUTE, scope=PROD, team_id="t-sre", granted_by="u-root", now=YESTERDAY
    )
    leaver = harness.service.principal("u-leaver")
    assert leaver is not None
    assert harness.service.roles_for(leaver, PROD, now=BEFORE) == frozenset({Role.EXECUTE})
    # At-and-after, matching ``TeamMembership.is_active``.
    assert harness.service.roles_for(leaver, PROD, now=T0) == frozenset()


def test_a_lapsed_grant_confers_nothing(harness: Harness) -> None:
    harness.add_human("u-temp")
    harness.service.grant_role(
        role=Role.EXECUTE,
        scope=PROD,
        principal_id="u-temp",
        granted_by="u-root",
        now=YESTERDAY,
        expires_at=T0,
    )
    temp = harness.service.principal("u-temp")
    assert temp is not None
    assert harness.service.roles_for(temp, PROD, now=BEFORE) == frozenset({Role.EXECUTE})
    assert harness.service.roles_for(temp, PROD, now=T0) == frozenset()


def test_a_project_scoped_grant_does_not_leak_into_another_project(
    harness: Harness,
) -> None:
    """The asymmetry :meth:`EnvironmentScope.covers` states, exercised end to end.

    Several directions, because asserting only one would let a "a grant means a
    grant everywhere" regression pass: a project-scoped grant reaches *its*
    project and not another, and an unstated narrowing on the acted-on side is
    nothing to contradict — so it does reach a bare ``production``, which is the
    rule the domain states and this service inherits rather than re-decides.
    """
    harness.add_human("u-scoped")
    payments = EnvironmentScope(environment="production", project="payments")
    billing = EnvironmentScope(environment="production", project="billing")
    harness.service.grant_role(
        role=Role.EXECUTE,
        scope=payments,
        principal_id="u-scoped",
        granted_by="u-root",
        now=YESTERDAY,
    )
    scoped = harness.service.principal("u-scoped")
    assert scoped is not None
    assert harness.service.roles_for(scoped, payments, now=T0) == frozenset({Role.EXECUTE})
    assert harness.service.roles_for(scoped, billing, now=T0) == frozenset()
    assert harness.service.roles_for(scoped, STAGING, now=T0) == frozenset()
    assert harness.service.roles_for(scoped, PROD, now=T0) == frozenset({Role.EXECUTE})


def test_require_role_raises_a_typed_refusal(harness: Harness) -> None:
    harness.add_human("u-nobody")
    nobody = harness.service.principal("u-nobody")
    assert nobody is not None
    with pytest.raises(AuthRefusedError) as caught:
        harness.service.require_role(principal=nobody, role=Role.EXECUTE, scope=PROD, now=T0)
    assert caught.value.code == REFUSAL_ROLE_MISSING
    assert "u-nobody" in str(caught.value)


# =============================================================================
# 2. Separation of duties — both settings, both enforcement points
# =============================================================================


def test_separation_of_duties_off_allows_a_dual_holder_to_approve_own_plan(
    harness: Harness, plan: ExecutionPlan, proof: SafetyProof
) -> None:
    """Off means the roles stay separate and their holders need not differ."""
    harness.add_human("u-dana")
    harness.grant("u-dana", Role.APPROVE, PROD)
    harness.grant("u-dana", Role.EXECUTE, PROD)
    dana = harness.service.principal("u-dana")
    assert dana is not None

    approval = harness.service.mint_approval(
        approval_id="a-self",
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approver_id="u-dana",
        environment=PROD,
        now=T0,
        plan_author="u-dana",
        separation_of_duties=False,
    )
    result = verify_approvals(
        plan,
        harness.service.gate_inputs(
            environment=PROD,
            executor=dana,
            proof=proof,
            policy_digest=POLICY_DIGEST,
            approvals=(approval,),
            now=T0,
            separation_of_duties=False,
        ),
    )
    assert result.allowed, result.describe()
    assert result.state.approvers == ("u-dana",)


def test_separation_of_duties_on_refuses_the_mint(harness: Harness, proof: SafetyProof) -> None:
    """The service refuses *before* the fact, not only at the gate."""
    harness.add_human("u-dana")
    harness.grant("u-dana", Role.APPROVE, PROD)
    with pytest.raises(AuthRefusedError) as caught:
        harness.service.mint_approval(
            approval_id="a-self",
            proof=proof,
            policy_digest=POLICY_DIGEST,
            approver_id="u-dana",
            environment=PROD,
            now=T0,
            plan_author="u-dana",
            separation_of_duties=True,
        )
    assert caught.value.code == REFUSAL_SELF_APPROVAL


def test_separation_of_duties_on_refuses_at_the_gate_too(
    harness: Harness, plan: ExecutionPlan, proof: SafetyProof
) -> None:
    """A separately minted self-approval still fails the Phase 2 gate.

    Proof that the service's own refusal is defence in depth rather than the
    only thing standing there: the approval record exists, and the gate — which
    the service does not control — refuses it.
    """
    harness.add_human("u-dana")
    harness.grant("u-dana", Role.APPROVE, PROD)
    harness.grant("u-dana", Role.EXECUTE, PROD)
    dana = harness.service.principal("u-dana")
    assert dana is not None

    approval = harness.service.mint_approval(
        approval_id="a-self",
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approver_id="u-dana",
        environment=PROD,
        now=T0,
        plan_author="u-dana",
        separation_of_duties=False,  # minted with the switch off …
    )
    result = verify_approvals(
        plan,
        harness.service.gate_inputs(
            environment=PROD,
            executor=dana,
            proof=proof,
            policy_digest=POLICY_DIGEST,
            approvals=(approval,),
            now=T0,
            separation_of_duties=True,  # … and evaluated with it on
        ),
    )
    assert not result.allowed
    assert InvalidationReason.SELF_APPROVED in result.state.reasons


def test_separation_of_duties_defaults_to_the_service_switch(harness: Harness) -> None:
    """The service default flows into ``gate_inputs`` when the caller is silent."""
    harness.service.separation_of_duties = True
    inputs = harness.service.gate_inputs(
        environment=PROD,
        executor=Principal(principal_id="u-x"),
        proof=_passing_proof(_plan("container.kill")),
        policy_digest=POLICY_DIGEST,
        now=T0,
    )
    assert inputs.separation_of_duties is True
    override = harness.service.gate_inputs(
        environment=PROD,
        executor=Principal(principal_id="u-x"),
        proof=_passing_proof(_plan("container.kill")),
        policy_digest=POLICY_DIGEST,
        now=T0,
        separation_of_duties=False,
    )
    assert override.separation_of_duties is False


def test_an_executor_never_approves_by_holding_execute_alone(
    harness: Harness, plan: ExecutionPlan, proof: SafetyProof
) -> None:
    """``EXECUTE`` is not ``APPROVE``, with the switch in either position."""
    for switch in (True, False):
        harness.service.register_principal(Principal(principal_id="u-runner"), now=BEFORE)
        harness.grant("u-runner", Role.EXECUTE, PROD)
        runner = harness.service.principal("u-runner")
        assert runner is not None
        with pytest.raises(AuthRefusedError) as caught:
            harness.service.mint_approval(
                approval_id="a-exec",
                proof=proof,
                policy_digest=POLICY_DIGEST,
                approver_id="u-runner",
                environment=PROD,
                now=T0,
                separation_of_duties=switch,
            )
        assert caught.value.code == REFUSAL_MINT_UNAUTHORIZED


# =============================================================================
# 3. Token lifecycle
# =============================================================================


def test_issue_and_authenticate_a_session_token(harness: Harness) -> None:
    principal = harness.add_human("u-alice")
    result = harness.service.authenticate_password(
        principal_id="u-alice", password="correct-horse", now=T0
    )
    assert result.authenticated
    assert result.principal == principal
    assert result.method is AuthMethod.PASSWORD
    assert result.expires_at == T0 + timedelta(seconds=3600)

    # The credential handed back by a *password* login is the subject id, not a
    # token: the caller must not be holding a bearer value it never asked for.
    verified = harness.service.authenticate_token(result.subject_id, now=T0)
    assert not verified.authenticated
    assert verified.code == REFUSAL_SESSION_UNKNOWN


def test_session_token_authenticates_and_binds_to_its_principal(harness: Harness) -> None:
    harness.add_human("u-alice")
    issued = harness.service.issue_session("u-alice", ttl_s=900.0, now=T0)
    assert issued.token.startswith(f"{issued.session_id}.")
    verified = harness.service.authenticate_token(issued.token, now=T0)
    assert verified.authenticated
    assert verified.principal is not None
    assert verified.principal.principal_id == "u-alice"
    assert verified.auth_source is AuthSource.WORKLOAD


def test_rotation_replaces_the_token_with_no_overlap(harness: Harness) -> None:
    """No instant at which both are live, and none at which neither is."""
    harness.add_human("u-alice")
    issued = harness.service.issue_session("u-alice", ttl_s=900.0, now=T0)
    successor = harness.service.rotate_session(issued.token, now=T0)

    assert successor.token != issued.token
    assert successor.session_id != issued.session_id
    assert not harness.service.authenticate_token(issued.token, now=T0).authenticated
    assert harness.service.authenticate_token(successor.token, now=T0).authenticated

    records = {s.session_id: s for s in harness.identity.sessions_for("u-alice")}
    assert records[issued.session_id].rotated_to == successor.session_id
    assert records[issued.session_id].revoked_by == "u-alice"
    assert records[successor.session_id].rotated_from == ""


def test_rotation_is_refused_for_a_token_that_does_not_verify(harness: Harness) -> None:
    harness.add_human("u-alice")
    issued = harness.service.issue_session("u-alice", ttl_s=900.0, now=T0)
    forged = f"{issued.session_id}.not-the-secret"
    with pytest.raises(AuthRefusedError) as caught:
        harness.service.rotate_session(forged, now=T0)
    assert caught.value.code == REFUSAL_CREDENTIAL_INVALID


def test_revocation_stops_the_token_and_names_who_revoked_it(harness: Harness) -> None:
    harness.add_human("u-alice")
    issued = harness.service.issue_session("u-alice", ttl_s=900.0, now=T0)
    propagation = harness.service.revoke_session(
        issued.token, revoked_by="u-root", reason="offboarded", now=T0
    )
    assert propagation.within_bound, propagation.describe()
    assert propagation.still_authenticated is False

    after = harness.service.authenticate_token(issued.token, now=T0)
    assert not after.authenticated
    assert after.code == REFUSAL_SESSION_REVOKED
    revocation = harness.identity.revocation_for(RevocationSubject.SESSION, issued.session_id)
    assert revocation is not None
    assert (revocation.revoked_by, revocation.reason) == ("u-root", "offboarded")


def test_a_revocation_needs_an_actor_and_a_reason(harness: Harness) -> None:
    harness.add_human("u-alice")
    issued = harness.service.issue_session("u-alice", ttl_s=900.0, now=T0)
    with pytest.raises(AuthRefusedError):
        harness.service.revoke_session(issued.token, revoked_by="  ", reason="x", now=T0)
    with pytest.raises(AuthRefusedError):
        harness.service.revoke_session(issued.token, revoked_by="u-root", reason="  ", now=T0)


def test_expiry_closes_the_window_at_its_deadline(harness: Harness) -> None:
    harness.add_human("u-alice")
    issued = harness.service.issue_session("u-alice", ttl_s=900.0, now=T0)
    assert harness.service.authenticate_token(issued.token, now=T0 + timedelta(seconds=899))
    report = harness.service.expire_sessions(now=T0 + timedelta(seconds=899))
    assert report.live == (issued.session_id,)
    assert report.lapsed == ()

    at_deadline = T0 + timedelta(seconds=900)
    assert not harness.service.authenticate_token(issued.token, now=at_deadline).authenticated
    assert (
        harness.service.authenticate_token(issued.token, now=at_deadline).code
        == REFUSAL_SESSION_EXPIRED
    )
    lapsed = harness.service.expire_sessions(now=at_deadline)
    assert lapsed.lapsed == (issued.session_id,)


def test_a_disabled_principal_cannot_obtain_a_session(harness: Harness) -> None:
    harness.add_human("u-alice")
    harness.service.disable_principal("u-alice", revoked_by="u-root", reason="offboarded", now=T0)
    with pytest.raises(AuthRefusedError) as caught:
        harness.service.issue_session("u-alice", now=T0)
    assert caught.value.code == REFUSAL_PRINCIPAL_DISABLED


def test_a_naive_clock_is_refused(harness: Harness) -> None:
    with pytest.raises(InvariantViolationError) as caught:
        harness.service.issue_session("u-alice", now=datetime(2026, 3, 1, 12, 0))  # noqa: DTZ001
    assert caught.value.rule == "auth.naive_clock"


def test_a_non_positive_ttl_is_refused(harness: Harness) -> None:
    harness.add_human("u-alice")
    with pytest.raises(InvariantViolationError):
        harness.service.issue_session("u-alice", ttl_s=0.0, now=T0)


def test_an_empty_password_is_refused(harness: Harness) -> None:
    harness.add_human("u-alice")
    with pytest.raises(AuthRefusedError):
        harness.service.set_password("u-alice", "", now=T0)


def test_the_issued_token_never_prints_its_secret(harness: Harness) -> None:
    harness.add_human("u-alice")
    issued = harness.service.issue_session("u-alice", ttl_s=900.0, now=T0)
    secret = issued.token.split(".", 1)[1]
    assert secret not in repr(issued)
    assert "<redacted>" in repr(issued)
    assert secret not in issued.describe()


# =============================================================================
# 4. Revocation propagation, and the bound on it
# =============================================================================


def test_revocation_propagates_within_the_bound_on_one_clock(
    harness: Harness,
) -> None:
    """The in-process case: the revocation is visible on the next statement.

    The measurement is on the injected monotonic clock, so the number in the
    report is the elapsed *service* time, not test noise.
    """
    harness.add_human("u-alice")
    issued = harness.service.issue_session("u-alice", ttl_s=3600.0, now=T0)
    assert harness.service.authenticate_token(issued.token, now=T0).authenticated

    propagation = harness.service.revoke_session(
        issued.token, revoked_by="u-root", reason="offboarded", now=T0
    )
    assert propagation.bound_s == REVOCATION_PROPAGATION_BOUND_S
    assert propagation.latency_s is not None
    assert propagation.latency_s <= REVOCATION_PROPAGATION_BOUND_S
    assert propagation.within_bound
    assert not harness.service.authenticate_token(issued.token, now=T0).authenticated


def test_revocation_propagates_across_two_connections(tmp_path: Any) -> None:
    """The case a cache exists for: a peer process revoked the token.

    Two :class:`~mayhem.infra.store.Store` handles on one file — the shape of two
    controllers — and the *reader* never learns about the revocation from its
    own writes. The bound is what makes that acceptable: it is asserted, not
    assumed, and the reader's cached decision is not served past it.
    """
    path = tmp_path / "identity.db"
    writer = Harness(str(path))
    reader = Harness(str(path))
    try:
        writer.add_human("u-alice")
        issued = writer.service.issue_session("u-alice", ttl_s=3600.0, now=T0)

        # The reader authenticates once and caches the decision.
        assert reader.service.authenticate_token(issued.token, now=T0).authenticated
        assert reader.service.revocation_propagation_bound_s == (REVOCATION_PROPAGATION_BOUND_S)

        # A peer revokes it. The reader is told nothing.
        writer.service.revoke_session(
            issued.token, revoked_by="u-root", reason="offboarded", now=T0
        )

        # Inside the bound the cached decision may still be served: that is the
        # documented, bounded cost, and it is *bounded*.
        assert reader.service.authenticate_token(issued.token, now=T0).authenticated
        reader.monotonic.advance(REVOCATION_PROPAGATION_BOUND_S)
        after = reader.service.authenticate_token(issued.token, now=T0)
        assert not after.authenticated
        assert after.code == REFUSAL_SESSION_REVOKED
    finally:
        writer.close()
        reader.close()


def test_a_cached_decision_is_never_served_past_the_bound(harness: Harness) -> None:
    """The bound is checked *before* the cache is read, not cleaned up after.

    One millisecond short of the bound the cached decision is still served —
    otherwise the bound would be untestable — and one millisecond past it the
    revocation is re-read. Both halves asserted, because a bound that only
    works when the cache is cold is not a bound.
    """
    harness.add_human("u-alice")
    issued = harness.service.issue_session("u-alice", ttl_s=3600.0, now=T0)
    assert harness.service.authenticate_token(issued.token, now=T0).authenticated
    harness.identity.record_revocation(
        _revocation(RevocationSubject.SESSION, issued.session_id, "u-root", "offboarded", T0)
    )
    harness.monotonic.advance(REVOCATION_PROPAGATION_BOUND_S - 0.001)
    assert harness.service.authenticate_token(issued.token, now=T0).authenticated
    harness.monotonic.advance(0.002)
    assert not harness.service.authenticate_token(issued.token, now=T0).authenticated


def test_a_negative_answer_is_never_cached(harness: Harness) -> None:
    """A disabled principal's refusal must not be servable from a cache.

    Caching a *denial* would extend the window in which "no" survives a grant
    being restored, which is the mirror of the propagation property and just as
    wrong.
    """
    harness.add_human("u-alice")
    issued = harness.service.issue_session("u-alice", ttl_s=3600.0, now=T0)
    harness.service.disable_principal("u-alice", revoked_by="u-root", reason="offboarded", now=T0)
    first = harness.service.authenticate_token(issued.token, now=T0)
    assert not first.authenticated
    harness.monotonic.advance(1_000.0)
    second = harness.service.authenticate_token(issued.token, now=T0)
    assert not second.authenticated
    assert second.code == REFUSAL_PRINCIPAL_DISABLED


def test_disabling_a_principal_fences_every_session_it_holds(harness: Harness) -> None:
    """The principal-level revocation row is what makes this one write."""
    harness.add_human("u-alice")
    first = harness.service.issue_session("u-alice", ttl_s=3600.0, now=T0)
    second = harness.service.issue_session("u-alice", ttl_s=3600.0, now=T0)
    harness.service.disable_principal("u-alice", revoked_by="u-root", reason="offboarded", now=T0)
    for issued in (first, second):
        result = harness.service.authenticate_token(issued.token, now=T0)
        assert not result.authenticated, issued.session_id
    revocation = harness.identity.revocation_for(RevocationSubject.PRINCIPAL, "u-alice")
    assert revocation is not None
    assert revocation.reason == "offboarded"


def test_revoke_all_sessions_probes_each_one(harness: Harness) -> None:
    harness.add_human("u-alice")
    tokens = [harness.service.issue_session("u-alice", ttl_s=3600.0, now=T0) for _ in range(3)]
    reports = harness.service.revoke_all_sessions(
        "u-alice", revoked_by="u-root", reason="offboarded", now=T0
    )
    assert len(reports) == 3
    assert all(report.within_bound for report in reports)
    assert not any(
        harness.service.authenticate_token(token.token, now=T0).authenticated for token in tokens
    )


def test_the_revocation_log_cannot_be_rewritten(harness: Harness) -> None:
    """The triggers are the backstop, not the writer's discipline."""
    import sqlite3

    harness.add_human("u-alice")
    harness.service.disable_principal("u-alice", revoked_by="u-root", reason="offboarded", now=T0)
    with pytest.raises(sqlite3.IntegrityError):
        with harness.store.write() as conn:
            conn.execute(
                "UPDATE identity_revocations SET reason = 'never mind' WHERE subject_id = ?",
                ("u-alice",),
            )
    with pytest.raises(sqlite3.IntegrityError):
        with harness.store.write() as conn:
            conn.execute("DELETE FROM identity_revocations WHERE subject_id = ?", ("u-alice",))


def test_a_second_revocation_cannot_overwrite_the_first(harness: Harness) -> None:
    harness.add_human("u-alice")
    first = harness.identity.record_revocation(
        _revocation(RevocationSubject.PRINCIPAL, "u-alice", "u-root", "offboarded", T0)
    )
    second = harness.identity.record_revocation(
        _revocation(RevocationSubject.PRINCIPAL, "u-alice", "u-other", "actually fine", HOUR_LATER)
    )
    stored = harness.identity.revocation_for(RevocationSubject.PRINCIPAL, "u-alice")
    assert stored is not None
    assert stored.revocation_id == first.revocation_id
    assert stored.revoked_by == "u-root"
    assert second.reason == "actually fine"  # the caller's record is still returned


# =============================================================================
# 5. API keys and service accounts
# =============================================================================


def test_api_keys_are_short_lived_scoped_and_hashed(harness: Harness) -> None:
    account = harness.service.service_account(
        principal_id="sa-deploy", display_name="deploy bot", now=BEFORE
    )
    assert account.kind is PrincipalKind.SERVICE_ACCOUNT
    key = harness.service.create_api_key("sa-deploy", scopes=[STAGING], ttl_s=None, now=T0)
    assert key.expires_at == T0 + timedelta(seconds=DEFAULT_API_KEY_TTL_S)
    assert key.scopes == (STAGING,)

    verified = harness.service.authenticate_api_key(key.presented, now=T0)
    assert verified.authenticated
    assert verified.principal is not None
    assert verified.principal.principal_id == "sa-deploy"
    assert verified.scopes == (STAGING,)

    record = harness.identity.load_api_key(key.api_key_id)
    assert record is not None
    assert record.secret_hash != key.secret
    assert key.secret not in record.secret_hash
    assert record.key_prefix == key.key_prefix


def test_an_api_key_must_be_scoped(harness: Harness) -> None:
    harness.service.service_account(principal_id="sa-deploy", now=BEFORE)
    with pytest.raises(AuthRefusedError) as caught:
        harness.service.create_api_key("sa-deploy", scopes=[], now=T0)
    assert caught.value.code == "auth.api_key_unscoped"


def test_an_expired_api_key_cannot_authenticate(harness: Harness) -> None:
    harness.service.service_account(principal_id="sa-deploy", now=BEFORE)
    key = harness.service.create_api_key("sa-deploy", scopes=[STAGING], ttl_s=60.0, now=T0)
    assert harness.service.authenticate_api_key(
        key.presented, now=T0 + timedelta(seconds=59)
    ).authenticated
    result = harness.service.authenticate_api_key(key.presented, now=T0 + timedelta(seconds=60))
    assert not result.authenticated
    assert result.code == REFUSAL_API_KEY_EXPIRED


def test_a_revoked_api_key_is_refused_and_propagates_within_the_bound(
    harness: Harness,
) -> None:
    harness.service.service_account(principal_id="sa-deploy", now=BEFORE)
    key = harness.service.create_api_key("sa-deploy", scopes=[STAGING], now=T0)
    assert harness.service.authenticate_api_key(key.presented, now=T0).authenticated
    propagation = harness.service.revoke_api_key(
        key.api_key_id, revoked_by="u-root", reason="rotated out", now=T0
    )
    assert propagation.within_bound, propagation.describe()
    assert propagation.subject_kind == "api_key"
    result = harness.service.authenticate_api_key(key.presented, now=T0)
    assert not result.authenticated
    assert result.code == "auth.api_key_revoked"


def test_an_unknown_or_malformed_api_key_is_refused(harness: Harness) -> None:
    harness.service.service_account(principal_id="sa-deploy", now=BEFORE)
    key = harness.service.create_api_key("sa-deploy", scopes=[STAGING], now=T0)
    for presented in ("", "mk_short.x", f"mk_{key.key_prefix}.wrong-secret", "nonsense"):
        result = harness.service.authenticate_api_key(presented, now=T0)
        assert not result.authenticated, presented
        assert result.code in {REFUSAL_API_KEY_UNKNOWN, REFUSAL_CREDENTIAL_INVALID}


def test_an_api_key_is_reissued_with_a_new_secret(harness: Harness) -> None:
    """The realistic rotation for a script: revoke, then mint."""
    harness.service.service_account(principal_id="sa-deploy", now=BEFORE)
    first = harness.service.create_api_key("sa-deploy", scopes=[STAGING], now=T0)
    second = harness.service.create_api_key("sa-deploy", scopes=[PROD], now=T0)
    assert first.secret != second.secret
    assert first.api_key_id != second.api_key_id
    harness.service.revoke_api_key(
        first.api_key_id, revoked_by="u-root", reason="superseded", now=T0
    )
    assert not harness.service.authenticate_api_key(first.presented, now=T0).authenticated
    assert harness.service.authenticate_api_key(second.presented, now=T0).authenticated


def test_a_disabled_service_account_confers_nothing(harness: Harness) -> None:
    harness.service.service_account(principal_id="sa-deploy", now=BEFORE)
    key = harness.service.create_api_key("sa-deploy", scopes=[PROD], now=T0)
    harness.service.disable_principal(
        "sa-deploy", revoked_by="u-root", reason="decommissioned", now=T0
    )
    result = harness.service.authenticate_api_key(key.presented, now=T0)
    assert not result.authenticated
    assert result.code == REFUSAL_PRINCIPAL_DISABLED
    with pytest.raises(AuthRefusedError):
        harness.service.create_api_key("sa-deploy", scopes=[PROD], now=T0)


def test_default_password_work_factor_is_the_real_one(harness: Harness) -> None:
    """The shipped posture, asserted once, so the test override cannot drift."""
    harness.service.register_principal(Principal(principal_id="u-alice"), now=BEFORE)
    strict = AuthService(harness.identity, pepper=PEPPER, clock=harness.clock)
    strict.set_password("u-alice", "correct-horse", now=BEFORE)
    record = harness.identity.load_local_credential("u-alice")
    assert record is not None
    assert record.algorithm == CREDENTIAL_HASH_ALGORITHM
    assert record.iterations == PASSWORD_HASH_ITERATIONS


def test_a_credential_is_never_readable_back_out_of_the_store(harness: Harness) -> None:
    """The no-plaintext property, asserted against the schema and every column.

    Two passes: the service-level objects, and then a sweep of *every* value in
    the identity tables looking for the literal. The second pass is the one that
    would catch a future column added without thinking about it.
    """
    password = "correct-horse-battery-staple"
    api_secret = "unmistakable-api-secret-value"
    harness.add_human("u-alice", password)
    session = harness.service.issue_session("u-alice", ttl_s=900.0, now=T0)
    harness.service.service_account(principal_id="sa-deploy", now=BEFORE)
    key = harness.service.create_api_key("sa-deploy", scopes=[PROD], now=T0)

    # 1. Nothing the service hands back contains the credential.
    for needle in (password, api_secret, session.token.split(".", 1)[1], key.secret):
        for values in harness.identity.credential_material().values():
            for column_values in values.values():
                assert needle not in column_values, (needle, column_values)

    # 2. A sweep of every cell of every identity table.
    tables = [
        str(row[0])
        for row in harness.store.query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'identity_%'"
        )
    ]
    assert len(tables) == 7, sorted(tables)
    needles = (password, api_secret, session.token, key.secret, key.presented)
    for table in tables:
        for row in harness.store.query(f'SELECT * FROM "{table}"'):
            for cell in tuple(row):
                text = "" if cell is None else str(cell)
                for needle in needles:
                    assert needle not in text, f"{table} holds a plaintext credential"

    # 3. A wrong pepper cannot read a stored hash back.
    other = AuthService(harness.identity, pepper=b"a-different-pepper", clock=harness.clock)
    assert not other.authenticate_token(session.token, now=T0).authenticated
    assert not other.authenticate_api_key(key.presented, now=T0).authenticated


def test_a_session_row_never_stores_the_presented_token(harness: Harness) -> None:
    harness.add_human("u-alice")
    issued = harness.service.issue_session("u-alice", ttl_s=900.0, now=T0)
    record = harness.identity.load_session(issued.session_id)
    assert record is not None
    assert record.token_hash not in issued.token
    assert issued.token not in json.dumps(record.model_dump(mode="json"))


# =============================================================================
# 6. Negative controls
# =============================================================================


def test_a_revoked_approvers_approval_is_worthless(
    harness: Harness, plan: ExecutionPlan, proof: SafetyProof
) -> None:
    """The control the plan names: revoke the approver, keep the approval.

    The approval record survives untouched — it is evidence, and evidence is not
    deleted by the fact that it no longer authorizes anything. What changes is
    that the approver holds no grant, so ``effective_roles`` skips their grant
    and the gate refuses for ``approver_role``.
    """
    harness.add_human("u-alice")
    harness.grant("u-alice", Role.APPROVE, PROD)
    runner = harness.service.register_principal(Principal(principal_id="u-runner"), now=BEFORE)
    harness.grant("u-runner", Role.EXECUTE, PROD)

    approval = harness.service.mint_approval(
        approval_id="a-alice",
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approver_id="u-alice",
        environment=PROD,
        now=T0,
    )
    assert verify_approvals(
        plan,
        harness.service.gate_inputs(
            environment=PROD,
            executor=runner,
            proof=proof,
            policy_digest=POLICY_DIGEST,
            approvals=(approval,),
            now=T0,
        ),
    ).allowed

    harness.service.disable_principal(
        "u-alice", revoked_by="u-root", reason="left the company", now=T0
    )
    after = verify_approvals(
        plan,
        harness.service.gate_inputs(
            environment=PROD,
            executor=runner,
            proof=proof,
            policy_digest=POLICY_DIGEST,
            approvals=(approval,),
            now=T0,
        ),
    )
    assert not after.allowed
    assert InvalidationReason.APPROVER_ROLE in after.state.reasons
    assert approval.revoked is False  # the record stands as evidence


def test_rebinding_an_approver_changes_only_the_authority_facts(
    harness: Harness, proof: SafetyProof, plan: ExecutionPlan
) -> None:
    """What :meth:`AuthService.rebind_approver` may touch, asserted explicitly.

    The point of the re-binding is that it is *not* an edit of the approval's
    substance. Only the approver's current record changes; all four binding
    digests and the window survive, so a re-bound approval still speaks for
    exactly the plan, policy, proof, and environment it was issued against.
    """
    harness.add_human("u-alice")
    harness.grant("u-alice", Role.APPROVE, PROD)
    approval = harness.service.mint_approval(
        approval_id="a-rebind",
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approver_id="u-alice",
        environment=PROD,
        now=T0,
    )
    assert harness.service.rebind_approver(approval) is approval

    harness.service.disable_principal(
        "u-alice", revoked_by="u-root", reason="left the company", now=T0
    )
    rebound = harness.service.rebind_approver(approval)
    assert rebound is not approval
    assert rebound.approver.disabled is True
    assert rebound.approval_digest != approval.approval_digest
    for field in (
        "plan_digest",
        "policy_digest",
        "proof_digest",
        "issued_at",
        "expires_at",
        "change_tickets",
        "note",
    ):
        assert getattr(rebound, field) == getattr(approval, field), field
    assert rebound.environment == approval.environment
    # And the record the caller holds is untouched evidence.
    assert approval.approver.disabled is False

    # The unresolvable-approver branch binds a disabled stand-in rather than
    # dropping the approval, so the quorum cannot change under the operator.
    orphan = Approval.model_validate(
        {**approval.model_dump(), "approver": Principal(principal_id="u-gone")}
    )
    rehydrated = harness.service.rebind_approver(orphan)
    assert rehydrated.approver.principal_id == "u-gone"
    assert rehydrated.approver.disabled is True
    from mayhem.controller.approval_gate import candidate_plan_digest

    assert rebound.plan_digest == candidate_plan_digest(plan)


def test_a_cross_environment_replay_is_refused(
    harness: Harness, plan: ExecutionPlan, proof: SafetyProof
) -> None:
    """A production approval replayed into staging, and a staging key into prod.

    Two different mechanisms, both of which have to hold: the *approval* is
    scoped, and the *credential* is scoped. Either alone would leave the other
    replay available.
    """
    harness.add_human("u-alice")
    harness.grant("u-alice", Role.APPROVE, PROD)
    harness.grant("u-alice", Role.EXECUTE, STAGING)
    runner = harness.service.register_principal(Principal(principal_id="u-runner"), now=BEFORE)
    harness.grant("u-runner", Role.EXECUTE, STAGING)

    approval = harness.service.mint_approval(
        approval_id="a-prod",
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approver_id="u-alice",
        environment=PROD,
        now=T0,
    )
    replayed = verify_approvals(
        plan,
        harness.service.gate_inputs(
            environment=STAGING,
            executor=runner,
            proof=proof,
            policy_digest=POLICY_DIGEST,
            approvals=(approval,),
            now=T0,
        ),
    )
    assert not replayed.allowed
    assert InvalidationReason.ENVIRONMENT_SCOPE in replayed.state.reasons

    # The credential half: a staging-scoped API key cannot authorize production
    # even for a principal holding a production grant.
    harness.service.service_account(principal_id="sa-deploy", now=BEFORE)
    harness.grant("sa-deploy", Role.EXECUTE, PROD)
    key = harness.service.create_api_key("sa-deploy", scopes=[STAGING], now=T0)
    authentication = harness.service.authenticate_api_key(key.presented, now=T0)
    assert authentication.authenticated
    key_principal = authentication.principal
    assert key_principal is not None
    decision = harness.service.authorize(
        principal=key_principal,
        role=Role.EXECUTE,
        scope=PROD,
        authentication=authentication,
        now=T0,
    )
    assert not decision.authorized
    assert decision.code == REFUSAL_SESSION_SCOPE
    assert decision.roles == frozenset({Role.EXECUTE})  # the grant exists; the reach does not


def test_a_disabled_principal_confers_nothing(harness: Harness) -> None:
    harness.add_human("u-alice")
    harness.grant("u-alice", Role.EXECUTE, PROD)
    alice = harness.service.principal("u-alice")
    assert alice is not None
    assert harness.service.roles_for(alice, PROD, now=T0) == frozenset({Role.EXECUTE})

    disabled = harness.service.disable_principal(
        "u-alice", revoked_by="u-root", reason="offboarded", now=T0
    )
    assert disabled is not None and disabled.disabled
    assert harness.service.roles_for(disabled, PROD, now=T0) == frozenset()
    decision = harness.service.authorize(principal=disabled, role=Role.EXECUTE, scope=PROD, now=T0)
    assert not decision.authorized
    assert decision.code == REFUSAL_PRINCIPAL_DISABLED
    # And the grant is still on record: a disabled principal is a *state*, not a
    # deletion, which is what makes re-enabling an answer rather than a rebuild.
    assert harness.service.grants_for(principal_id="u-alice")


def test_an_expired_session_cannot_authenticate(harness: Harness) -> None:
    harness.add_human("u-alice")
    issued = harness.service.issue_session("u-alice", ttl_s=300.0, now=T0)
    deadline = T0 + timedelta(seconds=300)
    assert harness.service.authenticate_token(issued.token, now=deadline).code == (
        REFUSAL_SESSION_EXPIRED
    )
    later = harness.service.authenticate_token(issued.token, now=deadline + timedelta(days=1))
    assert not later.authenticated
    assert later.principal is None
    assert later.refusal is not None and later.refusal.remediation


def test_an_approval_cannot_be_minted_without_the_approve_grant_in_scope(
    harness: Harness, proof: SafetyProof
) -> None:
    """The negative control this phase is most likely to get wrong.

    Three ways to hold no ``APPROVE`` *in scope*: hold nothing at all, hold it in
    another environment, or hold a different role. Each must be refused at mint,
    and each must be refused by the same predicate the gate later uses.
    """
    harness.add_human("u-none")
    harness.add_human("u-wrong-env")
    harness.add_human("u-wrong-role")
    harness.grant("u-wrong-env", Role.APPROVE, STAGING)
    harness.grant("u-wrong-role", Role.EXECUTE, PROD)

    for principal_id in ("u-none", "u-wrong-env", "u-wrong-role"):
        subject = harness.service.principal(principal_id)
        assert subject is not None
        assert not harness.service.may_approve(subject, PROD, now=T0)
        with pytest.raises(AuthRefusedError) as caught:
            harness.service.mint_approval(
                approval_id=f"a-{principal_id}",
                proof=proof,
                policy_digest=POLICY_DIGEST,
                approver_id=principal_id,
                environment=PROD,
                now=T0,
            )
        assert caught.value.code == REFUSAL_MINT_UNAUTHORIZED, principal_id
        assert "approve grant" in str(caught.value)


def test_an_unknown_principal_cannot_be_minted_for(harness: Harness, proof: SafetyProof) -> None:
    with pytest.raises(AuthRefusedError) as caught:
        harness.service.mint_approval(
            approval_id="a-ghost",
            proof=proof,
            policy_digest=POLICY_DIGEST,
            approver_id="u-ghost",
            environment=PROD,
            now=T0,
        )
    assert caught.value.code == REFUSAL_PRINCIPAL_UNKNOWN


def test_a_wrong_password_and_an_unknown_principal_both_refuse(
    harness: Harness,
) -> None:
    harness.add_human("u-alice")
    wrong = harness.service.authenticate_password(principal_id="u-alice", password="not-it", now=T0)
    assert not wrong.authenticated
    assert wrong.code == REFUSAL_CREDENTIAL_INVALID
    unknown = harness.service.authenticate_password(
        principal_id="u-nobody", password="not-it", now=T0
    )
    assert not unknown.authenticated
    assert unknown.code == REFUSAL_PRINCIPAL_UNKNOWN


def test_an_override_must_carry_a_reason(harness: Harness, proof: SafetyProof) -> None:
    harness.add_human("u-alice")
    harness.grant("u-alice", Role.APPROVE, PROD)
    with pytest.raises(InvariantViolationError) as caught:
        harness.service.mint_overridden_approval(
            approval_id="a-breakglass",
            proof=proof,
            policy_digest=POLICY_DIGEST,
            approver_id="u-alice",
            environment=PROD,
            reason="   ",
            now=T0,
        )
    assert caught.value.rule == "auth.override_requires_reason"
    override = harness.service.mint_overridden_approval(
        approval_id="a-breakglass",
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approver_id="u-alice",
        environment=PROD,
        reason="prod is down and the plan is safe",
        now=T0,
    )
    assert override.override and override.override_reason


def test_a_refusal_never_echoes_the_presented_credential(harness: Harness) -> None:
    harness.add_human("u-alice")
    wrong = harness.service.authenticate_password(
        principal_id="u-alice", password="hunter2-the-actual-guess", now=T0
    )
    assert wrong.refusal is not None
    assert "hunter2" not in wrong.refusal.reason
    assert "hunter2" not in wrong.describe()
    issued = harness.service.issue_session("u-alice", ttl_s=900.0, now=T0)
    forged = f"{issued.session_id}.a-guess-that-is-wrong"
    result = harness.service.authenticate_token(forged, now=T0)
    assert "a-guess-that-is-wrong" not in result.describe()


# =============================================================================
# 7. Identity-provider ports, and the enterprise walkthrough
# =============================================================================


def test_local_auth_is_implemented_not_delegated(harness: Harness) -> None:
    """There is no local *port*: the password check lives in this module.

    Registering one would create a second answer to "is this password correct",
    so the registration refuses rather than silently shadowing it.
    """
    with pytest.raises(InvariantViolationError) as caught:
        harness.service.register_provider(StaticIdentityProvider(source=AuthSource.LOCAL))
    assert caught.value.rule == "auth.local_is_not_a_port"


def test_an_oidc_port_authenticates_and_provisions(harness: Harness) -> None:
    """The port shape, end to end: verify, provision-or-resolve, mint a session."""
    remote = Principal(
        principal_id="u-carol",
        kind=PrincipalKind.HUMAN,
        display_name="Carol",
        external_id="oidc|carol@example.test",
    )
    harness.service.register_provider(
        StaticIdentityProvider(source=AuthSource.OIDC, known=(("carol", remote, ("t-sre",)),))
    )
    result = harness.service.authenticate_federated(
        FederatedCredentials(source=AuthSource.OIDC, external_id="carol", assertion="jwt"),
        now=T0,
    )
    assert result.authenticated
    assert result.principal is not None
    assert result.principal.principal_id == "u-carol"
    assert result.auth_source is AuthSource.OIDC
    # The session a federated login mints is the same kind of session a password
    # login mints, so the token lifecycle below applies to both.
    stored = harness.identity.load_principal("u-carol")
    assert stored is not None
    assert harness.identity.load_local_credential("u-carol") is None

    # And the local principal is now resolvable by the provider's own id.
    again = harness.service.authenticate_federated(
        FederatedCredentials(source=AuthSource.OIDC, external_id="carol"), now=T0
    )
    assert again.authenticated
    assert again.principal is not None
    assert again.principal.principal_id == "u-carol"


def test_a_provider_rejection_is_a_refusal_not_an_exception(harness: Harness) -> None:
    harness.service.register_provider(
        StaticIdentityProvider(
            source=AuthSource.OIDC,
            known=(("carol", Principal(principal_id="u-carol", external_id="carol"), ()),),
            rejected=frozenset({"mallory"}),
        )
    )
    result = harness.service.authenticate_federated(
        FederatedCredentials(source=AuthSource.OIDC, external_id="mallory"), now=T0
    )
    assert not result.authenticated
    assert result.code == REFUSAL_CREDENTIAL_INVALID
    assert result.principal is None


def test_an_unregistered_source_is_refused(harness: Harness) -> None:
    result = harness.service.authenticate_federated(
        FederatedCredentials(source=AuthSource.SAML, external_id="whoever"), now=T0
    )
    assert not result.authenticated
    assert result.code == REFUSAL_PROVIDER_UNAVAILABLE


def test_provider_teams_are_only_trusted_when_the_deployment_says_so(tmp_path: Any) -> None:
    """SCIM asserting a group must not silently become a membership by default."""
    path = tmp_path / "teams.db"
    built = Harness(str(path))
    try:
        remote = Principal(principal_id="u-dan", external_id="dan")
        provider = StaticIdentityProvider(
            source=AuthSource.SCIM, known=(("dan", remote, ("t-sre",)),)
        )
        built.service.register_provider(provider)
        result = built.service.authenticate_federated(
            FederatedCredentials(source=AuthSource.SCIM, external_id="dan"), now=T0
        )
        assert result.authenticated
        assert built.service.teams("u-dan", now=T0) == frozenset()

        trusting = AuthService(
            built.identity,
            pepper=PEPPER,
            clock=built.clock,
            monotonic=built.monotonic,
            providers=(provider,),
            trust_provider_teams=True,
        )
        trusting.authenticate_federated(
            FederatedCredentials(source=AuthSource.SCIM, external_id="dan"), now=T0
        )
        assert trusting.teams("u-dan", now=T0) == frozenset({"t-sre"})
    finally:
        built.close()


def test_a_callable_provider_is_the_oidc_seam(harness: Harness) -> None:
    """The documented way a deployment plugs a real OIDC client in."""
    seen: list[FederatedCredentials] = []

    def resolve(credentials: FederatedCredentials) -> tuple[Principal, tuple[str, ...]]:
        seen.append(credentials)
        if credentials.assertion != "a-valid-assertion":
            raise AuthRefusedError(REFUSAL_CREDENTIAL_INVALID, "signature did not verify")
        return Principal(principal_id="u-erin", external_id="erin"), ("t-sre",)

    harness.service.register_provider(CallableIdentityProvider(AuthSource.OAUTH, resolve))
    bad = harness.service.authenticate_federated(
        FederatedCredentials(source=AuthSource.OAUTH, external_id="erin", assertion="forged"),
        now=T0,
    )
    assert bad.code == REFUSAL_CREDENTIAL_INVALID
    good = harness.service.authenticate_federated(
        FederatedCredentials(
            source=AuthSource.OAUTH, external_id="erin", assertion="a-valid-assertion"
        ),
        now=T0,
    )
    assert good.authenticated
    assert len(seen) == 2


def test_the_enterprise_walkthrough_end_to_end_with_a_faked_idp(
    harness: Harness, plan: ExecutionPlan, proof: SafetyProof
) -> None:
    """authenticate -> policy -> approve -> execute, with a faked IdP.

    The Phase 3 acceptance, in one test: an OIDC login (faked), a scoped API key
    for the executor's service account, an approval minted by a human over the
    proof for *this* plan, and the Phase 2 gate allowing the run — followed by
    the same approval failing the moment the principal who signed it is revoked.
    """
    # 1. Authenticate. A human arrives through a faked IdP.
    human = Principal(principal_id="u-alice", external_id="alice")
    harness.service.register_provider(
        StaticIdentityProvider(source=AuthSource.OIDC, known=(("alice", human, ("t-sre",)),))
    )
    login = harness.service.authenticate_federated(
        FederatedCredentials(source=AuthSource.OIDC, external_id="alice"), now=T0
    )
    assert login.authenticated
    harness.grant("u-alice", Role.APPROVE, PROD)

    # 2. Authorize the executor through a short-lived, scoped API key.
    harness.service.service_account(principal_id="sa-runner", now=BEFORE)
    harness.grant("sa-runner", Role.EXECUTE, PROD)
    key = harness.service.create_api_key("sa-runner", scopes=[PROD], now=T0)
    executor_auth = harness.service.authenticate_api_key(key.presented, now=T0)
    assert executor_auth.authenticated
    executor = executor_auth.principal
    assert executor is not None
    authorized = harness.service.require_role(
        principal=executor,
        role=Role.EXECUTE,
        scope=PROD,
        authentication=executor_auth,
        now=T0,
    )
    assert authorized.authorized

    # 3. Approve, over the proof for this exact plan.
    approval = harness.service.mint_approval(
        approval_id="a-walkthrough",
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approver_id="u-alice",
        environment=PROD,
        now=T0,
        plan_author="sa-runner",
    )

    # 4. Execute — the Phase 2 gate decides, from the state this service supplied.
    inputs = harness.service.gate_inputs(
        environment=PROD,
        executor=executor,
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approvals=(approval,),
        now=T0,
        separation_of_duties=True,
    )
    assert isinstance(inputs, ApprovalGateInputs)
    result = verify_approvals(plan, inputs)
    assert result.allowed, result.describe()
    assert result.state.approvers == ("u-alice",)

    # 5. The same evidence, after the approver is revoked, authorizes nothing.
    harness.service.disable_principal(
        "u-alice", revoked_by="u-root", reason="left the company", now=T0
    )
    after = verify_approvals(
        plan,
        harness.service.gate_inputs(
            environment=PROD,
            executor=executor,
            proof=proof,
            policy_digest=POLICY_DIGEST,
            approvals=(approval,),
            now=T0,
            separation_of_duties=True,
        ),
    )
    assert not after.allowed
    assert InvalidationReason.APPROVER_ROLE in after.state.reasons

    # 6. And a different policy version refuses the same approval: the approval
    #    names an exact policy, so a policy change is not survivable.
    assert (
        InvalidationReason.POLICY_DIGEST_MISMATCH
        in verify_approvals(
            plan,
            harness.service.gate_inputs(
                environment=PROD,
                executor=executor,
                proof=proof,
                policy_digest=OTHER_POLICY_DIGEST,
                approvals=(approval,),
                now=T0,
            ),
        ).state.reasons
    )


def test_the_gate_is_given_the_service_state_not_a_restated_copy(
    harness: Harness, plan: ExecutionPlan, proof: SafetyProof
) -> None:
    """The seam: a grant added after the inputs were built is not in them.

    This is the failure mode :meth:`AuthService.gate_inputs` exists to prevent —
    a caller holding its own, smaller grant list and authorizing against it.
    Asserted in both directions: inputs built *before* the grant refuse the run,
    and inputs built after it allow the same plan with the same approval.
    """
    harness.add_human("u-alice")
    harness.grant("u-alice", Role.APPROVE, PROD)
    runner = harness.service.register_principal(Principal(principal_id="u-runner"), now=BEFORE)
    approval = harness.service.mint_approval(
        approval_id="a-seam",
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approver_id="u-alice",
        environment=PROD,
        now=T0,
    )

    # Built while the runner holds nothing: the gate refuses, as it must.
    stale = harness.service.gate_inputs(
        environment=PROD,
        executor=runner,
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approvals=(approval,),
        now=T0,
    )
    stale_result = verify_approvals(plan, stale)
    assert not stale_result.allowed
    assert stale_result.refusal is not None
    assert stale_result.refusal.rule_id == RULE_APPROVAL_EXECUTOR_UNAUTHORIZED

    # The grant lands; the same approval, freshly supplied state, now authorizes.
    harness.grant("u-runner", Role.EXECUTE, PROD)
    fresh = harness.service.gate_inputs(
        environment=PROD,
        executor=runner,
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approvals=(approval,),
        now=T0,
    )
    assert len(fresh.grants) == len(stale.grants) + 1
    assert verify_approvals(plan, fresh).allowed


def test_gate_inputs_supply_the_approvers_grants_too(
    harness: Harness, plan: ExecutionPlan, proof: SafetyProof
) -> None:
    """An approver's grant must reach the gate, or no approval could ever count."""
    harness.add_human("u-alice")
    harness.grant("u-alice", Role.APPROVE, PROD)
    harness.service.register_principal(Principal(principal_id="u-runner"), now=BEFORE)
    harness.grant("u-runner", Role.EXECUTE, PROD)
    runner = harness.service.principal("u-runner")
    assert runner is not None
    approval = harness.service.mint_approval(
        approval_id="a-1",
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approver_id="u-alice",
        environment=PROD,
        now=T0,
    )
    inputs = harness.service.gate_inputs(
        environment=PROD,
        executor=runner,
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approvals=(approval,),
        now=T0,
    )
    approver_grants = [g for g in inputs.grants if g.addressee == "u-alice"]
    assert approver_grants
    assert verify_approvals(plan, inputs).allowed


def test_an_executor_without_the_role_is_refused_with_the_gate_rule(
    harness: Harness, plan: ExecutionPlan, proof: SafetyProof
) -> None:
    """The Phase 2 executor refusal, reached with this service's inputs."""
    harness.add_human("u-alice")
    harness.grant("u-alice", Role.APPROVE, PROD)
    outsider = harness.service.register_principal(Principal(principal_id="u-outsider"), now=BEFORE)
    approval = harness.service.mint_approval(
        approval_id="a-1",
        proof=proof,
        policy_digest=POLICY_DIGEST,
        approver_id="u-alice",
        environment=PROD,
        now=T0,
    )
    result = verify_approvals(
        plan,
        harness.service.gate_inputs(
            environment=PROD,
            executor=outsider,
            proof=proof,
            policy_digest=POLICY_DIGEST,
            approvals=(approval,),
            now=T0,
        ),
    )
    assert not result.allowed
    assert result.refusal is not None
    assert result.refusal.rule_id == RULE_APPROVAL_EXECUTOR_UNAUTHORIZED


# =============================================================================
# 8. Schema
# =============================================================================


def test_the_identity_migration_is_reversible_and_additive() -> None:
    """Reversibility, proven by doing it — and scoped to *this* migration.

    The migration list is truncated at this one rather than using the full head,
    because :meth:`Store.migrate_down` reverses every version newer than its
    target and another agent's migration landing at 32 must not change what this
    test asserts. A suite that broke when a neighbour added a table would be a
    suite nobody trusts.
    """
    index = next(i for i, m in enumerate(ALL_MIGRATIONS) if m.name == "identity")
    migration = ALL_MIGRATIONS[index]
    assert migration.version == 31
    assert migration.down_statements

    truncated = ALL_MIGRATIONS[: index + 1]
    built = Store.open_migrated(":memory:", truncated)
    try:
        assert built.schema_version == 31
        tables = {
            str(row[0])
            for row in built.query(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'identity_%'"
            )
        }
        assert tables == {
            "identity_principals",
            "identity_local_credentials",
            "identity_memberships",
            "identity_role_grants",
            "identity_sessions",
            "identity_api_keys",
            "identity_revocations",
        }
        assert built.migrate_down(migration.version - 1) == ["0031_identity"]
        assert (
            built.query(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'identity_%'"
            )
            == []
        )
        # And forward again, so the round trip is proven rather than assumed.
        # ``migrate()`` re-applies the *full* list (its default), so the assertion
        # is that this migration came back, not that nothing else did.
        assert "0031_identity" in built.migrate()
        assert built.schema_version is not None
        assert built.schema_version >= migration.version
        assert {
            str(row[0])
            for row in built.query(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'identity_%'"
            )
        } == tables
    finally:
        built.close()


def test_the_schema_refuses_a_plaintext_credential(harness: Harness) -> None:
    """The CHECK constraints, not the writer, are what make plaintext storable-nowhere."""
    import sqlite3

    harness.service.register_principal(Principal(principal_id="u-alice"), now=BEFORE)
    with pytest.raises(sqlite3.IntegrityError):
        with harness.store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO identity_local_credentials (principal_id, algorithm, "
                "iterations, salt_hex, credential_hash, updated_at) VALUES (?,?,?,?,?,?)",
                (
                    "u-alice",
                    CREDENTIAL_HASH_ALGORITHM,
                    1_000,
                    "0" * 64,
                    "hunter2",  # not 64 hex characters: refused
                    T0.isoformat(),
                ),
            )
    with pytest.raises(sqlite3.IntegrityError):
        with harness.store.write() as conn:
            conn.execute(
                "INSERT INTO identity_role_grants (grant_id, role, scope_key, addressee_kind, "
                "addressee_id, granted_at, grant_json) VALUES (?,?,?,?,?,?,?)",
                ("g-1", "superuser", "org/prod/*", "principal", "u-alice", T0.isoformat(), "{}"),
            )


def test_memberships_survive_a_restart_and_reconstruct_the_principal(harness: Harness) -> None:
    """Durability: a restarted controller reads back the same identity."""
    harness.add_human("u-alice")
    harness.service.add_membership("u-alice", team_id="t-sre", now=YESTERDAY)
    harness.grant("u-alice", Role.APPROVE, PROD)
    alice = harness.identity.load_principal("u-alice")
    assert alice is not None
    memberships = harness.identity.memberships_for("u-alice")
    assert len(memberships) == 1
    assert memberships[0].principal == alice
    assert memberships[0].team_id == "t-sre"
    assert harness.identity.grants_for(principal_id="u-alice")
    with pytest.raises(InvariantViolationError):
        harness.identity.grants_for()


def test_a_membership_cannot_exist_for_an_unresolvable_principal() -> None:
    """A team membership has to name somebody, in the database as well as the type.

    The foreign key is the strong form of "a dangling row confers nothing": the
    row is unrepresentable rather than merely unreadable, so
    ``TeamMembership`` never has to reconstruct a principal that does not exist.
    The reader keeps its own guard anyway — a database restored without its
    foreign keys still must not invent a subject.
    """
    import sqlite3

    store = Store.open_migrated(":memory:")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            with store.write() as conn:
                conn.execute(
                    "INSERT INTO identity_memberships (principal_id, team_id, joined_at) "
                    "VALUES ('u-ghost', 't-sre', ?)",
                    (T0.isoformat(),),
                )
        identity = IdentityStore(store)
        assert identity.all_memberships() == ()
        assert identity.memberships_for("u-ghost") == ()

        # The reader's own guard: a row that exists but whose principal does not
        # (a database restored with foreign keys off) reads as nothing.
        with store.write() as conn:
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute(
                "INSERT INTO identity_memberships (principal_id, team_id, joined_at) "
                "VALUES ('u-ghost', 't-sre', ?)",
                (T0.isoformat(),),
            )
        assert identity.all_memberships() == ()
        assert identity.memberships_for("u-ghost") == ()
    finally:
        store.close()


def test_a_session_cannot_exist_for_a_principal_nobody_can_resolve() -> None:
    import sqlite3

    store = Store.open_migrated(":memory:")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            with store.write() as conn:
                conn.execute(
                    "INSERT INTO identity_sessions (session_id, principal_id, kind, auth_source, "
                    "token_hash, issued_at, expires_at) VALUES (?,?,?,?,?,?,?)",
                    (
                        "s-1",
                        "u-ghost",
                        SessionKind.PASSWORD.value,
                        AuthSource.LOCAL.value,
                        "a" * 64,
                        T0.isoformat(),
                        HOUR_LATER.isoformat(),
                    ),
                )
    finally:
        store.close()


def test_grant_ids_are_deterministic_so_writing_one_twice_is_idempotent(
    harness: Harness,
) -> None:
    grant = RoleGrant(
        role=Role.EXECUTE,
        scope=PROD,
        principal=Principal(principal_id="u-alice"),
        granted_at=YESTERDAY,
    )
    first = harness.identity.save_grant(grant)
    second = harness.identity.save_grant(grant)
    assert first == second
    assert len(harness.identity.all_grants()) == 1


def test_any_environment_wildcard_grants_reach_a_named_environment(harness: Harness) -> None:
    harness.add_human("u-root")
    harness.grant("u-root", Role.ADMINISTER, ORG_WIDE)
    root = harness.service.principal("u-root")
    assert root is not None
    assert ORG_WIDE.is_wildcard
    assert ORG_WIDE.environment == ANY_ENVIRONMENT
    assert harness.service.roles_for(root, PROD, now=T0) == frozenset({Role.ADMINISTER})
    assert harness.service.roles_for(root, EnvironmentScope(environment="dr"), now=T0) == frozenset(
        {Role.ADMINISTER}
    )


# =============================================================================
# Helpers
# =============================================================================


def _revocation(
    kind: RevocationSubject, subject_id: str, actor: str, reason: str, at: datetime
) -> RevocationRecord:
    return RevocationRecord(
        revocation_id=f"rv-{kind.value}-{subject_id}",
        subject_kind=kind,
        subject_id=subject_id,
        revoked_at=at,
        revoked_by=actor,
        reason=reason,
    )


def test_scope_serialisation_round_trips() -> None:
    """The scope a grant is stored under is the one the domain compares."""
    raw = scopes_to_json([PROD, EnvironmentScope(environment="prod", project="payments")])
    rebuilt = [scope_from_json(json.dumps(item)) for item in json.loads(raw)]
    assert rebuilt[0] == PROD
    assert rebuilt[1].covers(EnvironmentScope(environment="prod", project="payments"))
    assert not rebuilt[1].covers(PROD)


def test_team_membership_construction_is_left_to_the_domain(harness: Harness) -> None:
    """A membership with an end before its start is refused by the type."""
    with pytest.raises(InvariantViolationError):
        TeamMembership(
            principal=Principal(principal_id="u-alice"),
            team_id="t-sre",
            joined_at=T0,
            until=YESTERDAY,
        )
    assert harness.identity.load_principal("u-nobody") is None
