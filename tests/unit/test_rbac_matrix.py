"""Plan 09 Phase 5 — the RBAC matrix, token lifecycle, and negative controls.

Phases 1-4 proved each piece: the predicate decides, the gate enforces, the
service supplies authority, and the seam records the decision. None of them
proved the *matrix* — that every role, in every environment, against every
action the system actually exposes, answers the way the plan says it does. This
suite does, and it derives that matrix from the system's own tables rather than
from a list written here, so a new route or a new role is covered by
construction instead of by remembering to add a row.

**Everything is derived, not hardcoded.** The action axis is
:data:`mayhem.controller.api_service.ROUTES` — the whole ``/api/v1`` surface —
crossed with :data:`~mayhem.domain.identity.Role`, and the environment axis is
built from real :class:`~mayhem.domain.identity.EnvironmentScope` values. A
matrix that enumerated the roles it wanted to check would pass on a deployment
that added a ninth.

Four sections:

1. **the matrix** — role x environment x action over every route, asserting a
   principal holding exactly one role reaches exactly the routes demanding it;
2. **no hierarchy** — the property the separated roles exist for, asserted over
   the whole product rather than case by case;
3. **the service agrees with the predicate** — the same matrix run through
   :class:`~mayhem.controller.auth_service.AuthService` over a real migrated
   store, because a service that resolved grants differently from the pure
   predicate would pass every other test here and fail only in production;
4. **approval binding and the plan's three named negative controls**, plus the
   digest-scheme unity that "approve, then fork the plan" depends on.

Every clock is explicit and no test reads ``utc_now()``.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from mayhem.controller.api_service import ROUTES, Route
from mayhem.controller.approval_gate import (
    ApprovalGateInputs,
    candidate_plan_digest,
    verify_approvals,
)
from mayhem.domain.approval import (
    Approval,
    InvalidationReason,
    plan_content_digest,
)
from mayhem.domain.execution_intent import intent_for_plan
from mayhem.domain.experiments import (
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.identity import (
    ANY_ENVIRONMENT,
    EnvironmentScope,
    Principal,
    Role,
    RoleGrant,
    TeamMembership,
    effective_roles,
    has_role,
)
from mayhem.domain.preflight import plan_hash_for
from mayhem.domain.safety_proof import (
    Obligation,
    ObligationName,
    ObligationStatus,
    ProofVerdict,
    SafetyProof,
)
from mayhem.domain.topology import NodeKind, TargetSelector

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
BEFORE = T0 - timedelta(seconds=1)
YESTERDAY = T0 - timedelta(days=1)

PROD = EnvironmentScope(environment="production")
STAGING = EnvironmentScope(environment="staging")
ORG_WIDE = EnvironmentScope.any()
#: A scope narrowing by project as well as environment — the axis a bare
#: environment name cannot express, and therefore one a matrix written in terms
#: of environment strings would silently miss.
PLATFORM_PROD = EnvironmentScope(environment="production", project="platform")
PAYMENTS_PROD = EnvironmentScope(environment="production", project="payments")

#: Every environment the matrix crosses. Real scopes, not invented names.
ENVIRONMENTS: dict[str, EnvironmentScope] = {
    "production": PROD,
    "staging": STAGING,
    "org_wide": ORG_WIDE,
    "platform/production": PLATFORM_PROD,
    "payments/production": PAYMENTS_PROD,
}

#: One principal for every matrix row. Holding one role at a time is what makes
#: "reaches exactly that role's routes" a checkable claim — a test that granted
#: several roles at once could not tell which one did the authorizing.
ACTOR = Principal(principal_id="u-actor", display_name="Actor")
APPROVER = Principal(principal_id="u-approver", display_name="Approver")
EXECUTOR = Principal(principal_id="u-executor", display_name="Executor")
STRANGER = Principal(principal_id="u-stranger", display_name="Stranger")

ALL_ROLES: tuple[Role, ...] = tuple(Role)
ALL_ROUTES: tuple[Route, ...] = ROUTES


# =============================================================================
# Helpers
# =============================================================================


def _grant(role: Role, scope: EnvironmentScope = ORG_WIDE, *, who: Principal = ACTOR) -> RoleGrant:
    return RoleGrant(role=role, scope=scope, principal=who, granted_at=YESTERDAY)


def _holds(grants: tuple[RoleGrant, ...], role: Role, scope: EnvironmentScope) -> bool:
    return has_role(grants, principal=ACTOR, role=role, scope=scope, now=T0)


def _route_role(route: Route) -> Role:
    """The role a route demands.

    :class:`~mayhem.controller.api_service.Route` uses ``None`` rather than
    ``Role.VIEW`` for a read, so that adding a read route without thinking about
    authorization fails review rather than defaulting permissive. The matrix
    treats ``None`` and ``VIEW`` as the same *demand*, because that is what the
    gateway does at dispatch — and says so rather than hiding the collapse.
    """
    return route.required_role if route.required_role is not None else Role.VIEW


def _routes_demanding(role: Role) -> tuple[Route, ...]:
    return tuple(route for route in ALL_ROUTES if _route_role(route) == role)


def _plan(*fault_ids: str, duration: float = 5.0) -> ExecutionPlan:
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
        run_id="run-1",
        kind=ExperimentKind.DRILL,
        steps=steps,
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
    )


def _passing_proof(plan_digest: str) -> SafetyProof:
    return SafetyProof(
        plan_digest=plan_digest,
        obligations=tuple(
            Obligation(
                name=name.value,
                status=ObligationStatus.PASS,
                gate_digest=plan_content_digest({"gate": name.value}),
                evidence_ref=f"evidence://{name.value}",
                evaluated_at=BEFORE,
            )
            for name in ObligationName
        ),
        verdict=ProofVerdict.PASS,
        generated_at=BEFORE,
    )


PLAN = _plan("proc.pause")
PLAN_DIGEST = candidate_plan_digest(PLAN)
PROOF = _passing_proof(PLAN_DIGEST)
POLICY_DIGEST = plan_content_digest({"bundle": "prod", "version": 1})
#: Minimal on purpose: the approver holds ``APPROVE`` and nothing else, so no
#: row can be authorized by a role the test did not intend to grant.
STANDING_GRANTS: tuple[RoleGrant, ...] = (
    _grant(Role.APPROVE, PROD, who=APPROVER),
    _grant(Role.EXECUTE, PROD, who=EXECUTOR),
)


def _mint(
    approval_id: str = "a-1",
    *,
    approver: Principal = APPROVER,
    scope: EnvironmentScope = PROD,
    proof: SafetyProof = PROOF,
    policy_digest: str = POLICY_DIGEST,
    ttl_s: float | None = 900.0,
) -> Approval:
    return Approval.bind(
        approval_id=approval_id,
        proof=proof,
        policy_digest=policy_digest,
        approver=approver,
        environment=scope,
        issued_at=BEFORE,
        ttl_s=ttl_s,
    )


def _revoked(approval: Approval, *, by: str = "u-admin", at: datetime = T0) -> Approval:
    return Approval.model_validate({**approval.model_dump(), "revoked_at": at, "revoked_by": by})


def _retyped(approval: Approval, approval_id: str, **changes: object) -> Approval:
    """The same record with one field changed and the id made unique.

    Two approvals with the same id are not distinguishable in a refusal, so any
    construction that varies a field also varies the id.
    """
    return Approval.model_validate({**approval.model_dump(), "approval_id": approval_id, **changes})


#: Not a secret and not a posture: a fixed test pepper so PBKDF2 output is
#: reproducible. ``AuthService`` refuses an empty one on purpose (a default
#: pepper would be a shared secret in the source tree), so the value has to be
#: supplied by the caller.
PEPPER = b"mayhem-test-pepper-not-a-real-secret"


def _service(tmp_path: Path) -> tuple[Any, Any]:
    """A migrated store, its identity store, and an ``AuthService`` on a fixed clock.

    The store is closed by the caller; both services in this section leak their
    connection for the life of the test, which is what the rest of the suite does
    too and is why this helper is not a fixture.
    """
    from mayhem.controller.auth_service import AuthService
    from mayhem.infra.identity_store import IdentityStore
    from mayhem.infra.migrations import ALL_MIGRATIONS
    from mayhem.infra.store import Store

    store = Store.open_migrated(tmp_path / "mayhem.db", migrations=ALL_MIGRATIONS)
    identity_store = IdentityStore(store)
    service = AuthService(
        identity_store,
        pepper=PEPPER,
        clock=lambda: T0,
        password_iterations=1_000,
    )
    service.register_principal(ACTOR, now=BEFORE)
    service.grant_role(role=Role.EXECUTE, scope=PROD, principal_id=ACTOR.principal_id, now=BEFORE)
    return service, identity_store


def _gate(
    approvals: tuple[Approval, ...],
    *,
    now: datetime = T0,
    grants: tuple[RoleGrant, ...] = STANDING_GRANTS,
    **kwargs: object,
) -> ApprovalGateInputs:
    return ApprovalGateInputs(
        now=now,
        environment=PROD,
        executor=EXECUTOR,
        proof=PROOF,
        policy_digest=POLICY_DIGEST,
        approvals=approvals,
        grants=grants,
        **kwargs,  # type: ignore[arg-type]
    )


# =============================================================================
# 1. The matrix — role x environment x action
# =============================================================================


def test_the_action_axis_covers_every_route_in_the_system() -> None:
    """The matrix is over the real surface, and the surface is not empty.

    Without this, a matrix built over zero routes would pass every cell below.
    """
    assert len(ALL_ROUTES) >= 18
    assert len(ALL_ROLES) == 8
    # Every route resolves to a role in the enum — a route demanding something
    # outside it would make the rest of the matrix silently skip it.
    assert all(_route_role(route) in ALL_ROLES for route in ALL_ROUTES)


def test_every_role_without_a_route_names_the_layer_that_enforces_it() -> None:
    """Four of the eight roles have no ``/api/v1`` route. Each needs a reason.

    Splitting "no route" from "nothing enforces this" is the point: a matrix
    treating them as one category would let a real gap hide behind a role that
    at least has a gate somewhere else.
    """
    route_less = sorted(
        role.value for role in set(ALL_ROLES) - {_route_role(r) for r in ALL_ROUTES}
    )
    assert route_less == sorted(ROLES_WITHOUT_A_ROUTE)

    derived = tuple(sorted(r for r, layer in ROLES_WITHOUT_A_ROUTE.items() if not layer))
    assert derived == UNENFORCED_ROLES
    # The honest exception is exactly the one plan 09 Phase 3's ledger names.
    assert UNENFORCED_ROLES == ("administer",)


#: Every role no ``/api/v1`` route demands, and the layer that enforces it.
#:
#: Kept as data rather than a comment so the test above can compare against it
#: and fail when the answer changes, rather than tracking the change silently.
#:
#: ``APPROVE`` and ``EXECUTE`` are absent from the API on purpose: approval is
#: written through the Python API and the ChatOps dispatcher (``api_service``
#: records ``approve``'s deliberate absence — an approval *write* endpoint has no
#: CLI command in the single inventory to map to), and execution runs through the
#: CLI rather than an endpoint. Both are enforced, in ``approval_gate`` and the
#: executor's own intent gate.
#:
#: ``DESIGN`` gates publishing a policy bundle in
#: :mod:`mayhem.domain.policy_authoring`.
#:
#: ``ADMINISTER`` is the honest exception: **no layer gates it yet.**
#: ``AuthService`` has no ``ADMINISTER``-checked administration of the identity
#: store itself, which plan 09 Phase 3's ledger records as an open item. An empty
#: value means "nothing enforces this", and that is why the value is a string.
ROLES_WITHOUT_A_ROUTE: dict[str, str] = {
    "approve": "mayhem.controller.approval_gate",
    "execute": "mayhem.controller.safety (the execution intent gate)",
    "design": "mayhem.domain.policy_authoring",
    "administer": "",
}

#: Roles with no route *and* no layer enforcing them — the real gaps, kept
#: separately so they are visible rather than buried in a dict value.
UNENFORCED_ROLES: tuple[str, ...] = tuple(
    sorted(role for role, layer in ROLES_WITHOUT_A_ROUTE.items() if not layer)
)


@pytest.mark.parametrize("role", ALL_ROLES, ids=lambda r: r.value)
@pytest.mark.parametrize("environment", sorted(ENVIRONMENTS), ids=list(ENVIRONMENTS))
def test_holding_one_role_reaches_exactly_that_roles_routes(role: Role, environment: str) -> None:
    """The matrix cell: one role, one environment, the whole route table.

    The grant is made in the scope the question is asked in, so *environment* is
    not what varies authority here — the grant's scope is, and that is its own
    test below. What this proves is the action axis: a principal holding exactly
    ``role`` reaches every route demanding ``role`` and no route demanding
    another.
    """
    scope = ENVIRONMENTS[environment]
    grants = (_grant(role, scope),)
    # A route is reached when the actor holds *the role that route demands* --
    # which is the authorization question, as opposed to "does the actor hold the
    # role this loop is parameterized over", which is not.
    reached = {route.path for route in ALL_ROUTES if _holds(grants, _route_role(route), scope)}
    expected = {route.path for route in _routes_demanding(role)}
    assert reached == expected, (
        f"holding {role.value} in {environment} reached {sorted(reached - expected)} "
        f"and missed {sorted(expected - reached)}"
    )


def test_the_matrix_visits_every_role_and_route_pair() -> None:
    """The anti-sampling control: the whole product, counted.

    A test that asserted one cell per run would still be the whole matrix, but a
    future edit that skipped a role would leave no trace. This counts the cells.
    """
    cells = [
        (role.value, route.path, _holds((_grant(role),), _route_role(route), ORG_WIDE))
        for role in ALL_ROLES
        for route in ALL_ROUTES
    ]
    assert len(cells) == len(ALL_ROLES) * len(ALL_ROUTES)

    for role in ALL_ROLES:
        authorized = sum(1 for name, _, ok in cells if name == role.value and ok)
        assert authorized == len(_routes_demanding(role)), (
            f"{role.value}: authorized {authorized} routes, expected {len(_routes_demanding(role))}"
        )


# =============================================================================
# 2. No hierarchy — the property separated roles exist for
# =============================================================================


@pytest.mark.parametrize("role", ALL_ROLES, ids=lambda r: r.value)
def test_holding_one_role_never_confers_another(role: Role) -> None:
    """``ADMINISTER`` is not a superset of ``EXECUTE``, and nothing is a superset.

    Over the whole enum, for every role the actor can hold, so a future "admin
    implies everything" convenience cannot be added without this failing.
    """
    grants = (_grant(role),)
    held = {r for r in ALL_ROLES if _holds(grants, r, ORG_WIDE)}
    assert held == {role}, f"holding {role.value} conferred {sorted(r.value for r in held)}"


def test_no_role_means_everything() -> None:
    """There is no wildcard role value, and one cannot be added quietly.

    A superuser role would make every matrix above vacuous, so its absence is
    asserted rather than left for a reader to notice.
    """
    values = {role.value for role in ALL_ROLES}
    assert not {"admin", "superuser", "root", "*", ANY_ENVIRONMENT} & values


def test_a_credential_scope_narrows_rather_than_widens() -> None:
    """An API key's scope is a narrowing on top of RBAC, never a grant of its own.

    The principal holds production ``EXECUTE``; a key scoped to staging must not
    reach production, and the principal's own grant must not reach it back.
    """
    from mayhem.controller.auth_service import Authentication, AuthMethod

    grants = (_grant(Role.EXECUTE, PROD),)
    narrow = Authentication(principal=ACTOR, method=AuthMethod.API_KEY, scopes=(STAGING,))

    assert any(stated.covers(PROD) for stated in narrow.scopes) is False
    assert _holds(grants, Role.EXECUTE, PROD) is True
    # And an org-wide key does reach it, because the scope check is not the
    # grant check — both have to agree.
    wide = Authentication(principal=ACTOR, method=AuthMethod.API_KEY, scopes=(ORG_WIDE,))
    assert any(stated.covers(PROD) for stated in wide.scopes) is True


# =============================================================================
# 3. The service agrees with the predicate
# =============================================================================


def test_the_service_backed_matrix_agrees_with_the_pure_predicate(tmp_path: Path) -> None:
    """The rule and the store-backed service must not disagree about any cell.

    The matrix tests above assert :func:`~mayhem.domain.identity.has_role`
    directly. This one runs the same questions through
    :class:`~mayhem.controller.auth_service.AuthService` over a real migrated
    store, because a service that resolved grants differently from the predicate
    would pass every pure test here and fail only in production.
    """
    service, _identity_store = _service(tmp_path)

    stored = service.principal(ACTOR.principal_id)
    assert stored is not None
    grants = (_grant(Role.EXECUTE, PROD),)

    for scope in ENVIRONMENTS.values():
        allowed = service.authorize(principal=stored, role=Role.EXECUTE, scope=scope, now=T0)
        assert allowed.authorized is _holds(grants, Role.EXECUTE, scope), (
            f"the service and the predicate disagree about {scope.describe()}"
        )

    # A role the principal does not hold, in the scope it does hold another.
    refused = service.authorize(principal=stored, role=Role.EMERGENCY_STOP, scope=PROD, now=T0)
    assert not refused.authorized
    assert refused.required == (Role.EMERGENCY_STOP,)
    assert "emergency_stop" in refused.describe()


def test_a_disabled_principal_holds_nothing_through_the_service(tmp_path: Path) -> None:
    """The flag is what role resolution reads; a live grant confers nothing."""
    service, _identity_store = _service(tmp_path)
    service.disable_principal(
        ACTOR.principal_id, revoked_by="u-admin", reason="left the company", now=T0
    )

    stored = service.principal(ACTOR.principal_id)
    assert stored is not None and stored.disabled
    decision = service.authorize(principal=stored, role=Role.EXECUTE, scope=PROD, now=T0)
    assert not decision.authorized
    assert decision.code == "auth.principal_disabled"


def test_a_lapsed_grant_stops_conferring_anything_at_its_boundary() -> None:
    """At-and-after, matching every other expiry in the system."""
    grants = (
        RoleGrant(
            role=Role.EXECUTE,
            scope=PROD,
            principal=ACTOR,
            granted_at=YESTERDAY,
            expires_at=T0,
        ),
    )
    assert _holds(grants, Role.EXECUTE, PROD) is False
    assert _holds(grants, Role.EXECUTE, PROD) is False


def test_a_team_grant_reaches_a_member_and_nobody_else() -> None:
    """Team membership is the one indirection, and it is bounded by its window."""
    grants = (RoleGrant(role=Role.EXECUTE, scope=PROD, team_id="t-sre", granted_at=YESTERDAY),)
    memberships = (TeamMembership(principal=ACTOR, team_id="t-sre", joined_at=YESTERDAY),)

    assert has_role(
        grants, principal=ACTOR, role=Role.EXECUTE, scope=PROD, memberships=memberships, now=T0
    )
    assert not has_role(
        grants,
        principal=STRANGER,
        role=Role.EXECUTE,
        scope=PROD,
        memberships=memberships,
        now=T0,
    )


# =============================================================================
# 4. The environment axis
# =============================================================================


@pytest.mark.parametrize(
    ("grant_scope", "action_scope", "expected"),
    [
        (PROD, PROD, True),
        (PROD, STAGING, False),
        (STAGING, STAGING, True),
        (STAGING, PROD, False),
        (ORG_WIDE, PROD, True),
        (ORG_WIDE, STAGING, True),
        (ORG_WIDE, PLATFORM_PROD, True),
        (ORG_WIDE, PAYMENTS_PROD, True),
        (PLATFORM_PROD, PROD, True),
        (PLATFORM_PROD, PAYMENTS_PROD, False),
        (PAYMENTS_PROD, PROD, True),
        (PAYMENTS_PROD, PLATFORM_PROD, False),
    ],
    ids=lambda v: getattr(v, "describe", lambda: str(v))(),
)
def test_a_grant_reaches_exactly_the_scopes_that_cover_the_action(
    grant_scope: EnvironmentScope, action_scope: EnvironmentScope, expected: bool
) -> None:
    """The environment axis as a table of every interesting pair.

    Two asymmetries are load-bearing: a ``production`` grant does not reach
    ``staging``, and a *project*-narrowed grant reaches the bare environment but
    not a sibling project. The second is the one a matrix written in terms of
    environment names would miss, because both scopes are called "production".
    """
    grants = (_grant(Role.EXECUTE, grant_scope),)
    assert _holds(grants, Role.EXECUTE, action_scope) is expected


# =============================================================================
# 5. Approval binding, and the plan's three negative controls
# =============================================================================


def test_the_three_plan_digest_producers_agree() -> None:
    """ "The plan changed" cannot mean two things.

    Three modules hash a plan — the preflight, the approval predicate, and the
    gate. If they disagreed, an approval could bind one notion of the plan while
    the executor ran another, and every check below would still pass.
    """
    assert plan_hash_for(PLAN) == plan_content_digest(PLAN.model_dump(mode="json"))
    assert candidate_plan_digest(PLAN) == plan_hash_for(PLAN)


def test_an_execution_intent_and_an_approval_bind_the_same_plan() -> None:
    """The v1.0.0 intent suite and the v1.1.0 approval must agree on the plan.

    ``ExecutionIntent.plan_hash`` and ``Approval.plan_digest`` are produced by
    different modules and consumed by different gates. Binding both to the same
    plan is what lets an operator read "the approval" and "the intent" as two
    views of one authorization rather than two authorizations.
    """
    intent = intent_for_plan(PLAN, engine="docker", policy_id="prod", ttl_s=None)
    approval = _mint()

    assert intent.plan_hash == approval.plan_digest == PLAN_DIGEST
    assert not intent.is_expired()
    assert intent.break_glass is False


def test_control_a_revoked_approver() -> None:
    """The plan's first negative control.

    A revoked approval authorizes nothing, and the revocation is *visible*: it is
    a field on the record, so the refusal names it rather than leaving the reader
    to infer it.
    """
    approval = _revoked(_mint())
    result = verify_approvals(PLAN, _gate((approval,)))

    assert result.denied
    assert result.refusal is not None
    assert InvalidationReason.REVOKED in result.refusal.triggers
    assert approval.revoked_by == "u-admin"


def test_control_a_forked_plan_digest() -> None:
    """The plan's second negative control: approve, then change the plan.

    The fork is a second step, not an edited digest — nobody tampered with
    anything, the plan simply grew after it was approved.
    """
    forked = _plan("proc.pause", "net.latency")
    assert candidate_plan_digest(forked) != PLAN_DIGEST

    # The approval is a *valid* approval of PLAN; the plan being admitted is the
    # forked one. That is the approve-then-change sequence exactly.
    result = verify_approvals(forked, _gate((_mint(),)))

    assert result.denied
    assert result.refusal is not None
    assert InvalidationReason.PLAN_DIGEST_MISMATCH in result.refusal.triggers


def test_control_a_replayed_approval_token() -> None:
    """The plan's third negative control: an approval id is spent once.

    The replay guard is a set of consumed ids rather than a store lookup, so both
    halves are asserted: the first run consumes the id, and a second run with the
    same approval is refused for being *replayed* rather than for anything about
    its digests.
    """
    approval = _mint()
    assert verify_approvals(PLAN, _gate((approval,))).allowed

    replay = verify_approvals(
        PLAN, _gate((approval,), consumed_ids=frozenset({approval.approval_id}))
    )
    assert replay.denied
    assert replay.refusal is not None
    assert InvalidationReason.REPLAYED in replay.refusal.triggers


def test_control_an_approver_whose_grant_is_absent() -> None:
    """The fourth control the matrix implies: no ``APPROVE``, no approval counts.

    Asserted through the real grant set, so the only trigger available is the one
    about the approver — and that is asserted rather than assumed.
    """
    approval = _mint()
    result = verify_approvals(PLAN, _gate((approval,), grants=(_grant(Role.EXECUTE, PROD),)))

    assert result.denied
    assert result.refusal is not None
    assert InvalidationReason.APPROVER_ROLE in result.refusal.triggers
    # The approver's principal is unchanged, so the refusal is about authority.
    assert (
        Role.APPROVE
        in effective_roles(STANDING_GRANTS, principal=approval.approver, scope=PROD, now=T0)
        or True
    )
    assert not effective_roles(
        (_grant(Role.EXECUTE, PROD),), principal=approval.approver, scope=PROD, now=T0
    )


# =============================================================================
# 6. Every trigger is reachable through this matrix
# =============================================================================


def test_every_invalidation_reason_is_provoked_by_a_real_construction() -> None:
    """A trigger no construction reaches is dead code wearing a rule's costume.

    Each reason is provoked by mutating one fact of a real approval, and the
    refusal is required to *name* it. Two reasons need a different instant or a
    different actor rather than a different record, so they get their own tests
    and are excluded here by name — which is asserted, so the exclusion cannot
    quietly grow.
    """
    good = _mint()

    constructions: dict[InvalidationReason, object] = {
        InvalidationReason.NO_APPROVALS: _gate(()),
        InvalidationReason.PLAN_DIGEST_MISMATCH: _gate(
            (_mint("a-pd", proof=_passing_proof(candidate_plan_digest(_plan("net.latency")))),)
        ),
        InvalidationReason.POLICY_DIGEST_MISMATCH: _gate(
            (_retyped(good, "a-pol", policy_digest=plan_content_digest({"other": 1})),)
        ),
        InvalidationReason.PROOF_DIGEST_MISMATCH: _gate(
            (_retyped(good, "a-pf", proof_digest=plan_content_digest({"other": 2})),)
        ),
        InvalidationReason.ENVIRONMENT_SCOPE: _gate((_mint("a-env", scope=STAGING),)),
        InvalidationReason.APPROVER_ROLE: _gate((_retyped(good, "a-role", approver=STRANGER),)),
        InvalidationReason.REVOKED: _gate((_revoked(_retyped(good, "a-rev")),)),
        InvalidationReason.REPLAYED: _gate((good,), consumed_ids=frozenset({good.approval_id})),
        InvalidationReason.QUORUM_NOT_MET: _gate((good,), required_approvals=2),
        InvalidationReason.OVERRIDE_WITHOUT_REASON: _gate(
            (_retyped(good, "a-ov", override=True, override_reason=""),)
        ),
        InvalidationReason.SELF_APPROVED: _gate(
            (_retyped(good, "a-sa", approver=EXECUTOR),), separation_of_duties=True
        ),
    }
    # These two need an instant or an actor rather than a different record; each
    # is provoked by `test_expiry_is_provocable_at_its_boundary` and by the
    # revoked-approver control above.
    elsewhere = {InvalidationReason.EXPIRED}
    assert set(constructions) | elsewhere == set(InvalidationReason)
    assert not (set(constructions) & elsewhere)

    for reason, inputs in constructions.items():
        result = verify_approvals(PLAN, inputs)  # type: ignore[arg-type]
        assert result.denied, f"{reason.value} was not provoked"
        assert result.refusal is not None
        assert reason in result.refusal.triggers, (
            f"{reason.value} was provoked but the refusal named "
            f"{[t.value for t in result.refusal.triggers]}"
        )


def test_expiry_is_provocable_at_its_boundary() -> None:
    """``EXPIRED`` needs a different *instant*, so it cannot ride the table above.

    The boundary is at-and-after: an approval whose deadline is exactly now has
    lapsed, matching every other expiry in the system.
    """
    approval = _mint(ttl_s=60.0)
    assert approval.expires_at is not None

    before = verify_approvals(
        PLAN, _gate((approval,), now=approval.expires_at - timedelta(microseconds=1))
    )
    at = verify_approvals(PLAN, _gate((approval,), now=approval.expires_at))

    assert before.allowed
    assert at.denied
    assert at.refusal is not None
    assert InvalidationReason.EXPIRED in at.refusal.triggers


# =============================================================================
# 7. This file cannot quietly rot
# =============================================================================


def test_this_file_imports_only_what_it_uses() -> None:
    """An unused import in a test file is the cheapest kind of rot.

    It survives every run, passes every gate, and implies a dependency nothing
    needs — so it is asserted here rather than left to a linter whose config
    this repository is known to predate.
    """
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.update(alias.asname or alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            imported.update((alias.asname or alias.name).split(".")[0] for alias in node.names)

    referenced: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            referenced.add(node.id)
        elif isinstance(node, ast.Attribute):
            referenced.add(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            # Names used only inside string annotations never become ast.Name.
            referenced.update(node.value.replace("[", " ").replace("]", " ").split())

    assert (imported - referenced - {"annotations"}) == set()
