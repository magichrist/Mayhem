"""The ``/api/v1`` gateway, the service facades, and the parameter UX (plan 08,
Phase 3).

Grouped by the failure each group rules out, with the negative controls first
because they are the ones that decide whether this layer is a *gate* or a
decorator somebody can route around.

* **Construction refuses a route table that cannot be honest** (construction
  invariants). A mutation naming a command the CLI does not have, a mutation that
  is not idempotent, a read that claims a CLI command, a duplicate
  ``(method, path)``, and a read that quietly requires more than ``VIEW`` are all
  refused before the gateway serves a request.
* **Authorize before validate** (the security property). An unauthorized principal
  sending a malformed body is refused with ``auth.role_missing``, not with a parse
  error — the assertion is over the *rule id*, because a validation message is a
  description of the request and returning one to somebody who may not read the
  resource is an oracle.
* **Plan 09 is the only authorization model.** The required role per mutating
  route is read from ``CHATOPS_REQUIRED_ROLE``; an environment-less request is
  refused rather than resolved against a default; a session minted for one
  environment cannot reach another.
* **Idempotency is a replay, not a re-run** (same key + same request → the
  recorded response byte for byte; same key + different request → 409, never the
  first response).
* **Normalized errors.** Every refusal is one envelope carrying the rule id both
  in ``meta`` and inside ``errors[0]``, so it is greppable without parsing
  metadata. ``tests/unit/test_api_http.py`` proves the same over a real socket.
* **The OpenAPI document is generated** from the route table: it cannot describe
  an unimplemented handler, and every route appears in it.
* **Plan equivalence** (the acceptance criterion) lives in
  ``tests/unit/test_api_planner.py``; this file covers the gateway half.

Every negative control below is *executable*: each names the refusal it breaks
and then asserts the refusal, so a check that cannot fail is not counted.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.controller.api_planner import (
    REQUIRED_SUBMISSION_KEYS,
    EvidenceService,
    PlannerService,
    PlanSubmission,
    PolicyService,
)
from mayhem.controller.api_service import (
    API_GATEWAY_MIGRATION,
    API_GATEWAY_VERSION,
    API_PREFIX,
    CONTROL_ACTIONS,
    DEFAULT_PAGE_SIZE,
    ENVIRONMENT_HEADER,
    MAX_PAGE_SIZE,
    ROUTES,
    SLIDER_SPAN_LIMIT,
    UNIMPLEMENTED_API_SURFACES,
    ApiGateway,
    ApiRefusedError,
    ApiRequest,
    ControlKind,
    MutationRequest,
    ParameterControl,
    Route,
    command_path_for,
    control_for_parameter,
    control_kind_for,
    openapi_document,
    parameter_controls,
)
from mayhem.domain.api import PlanResource, PolicyResource, RunResource, plan_digest_of
from mayhem.domain.catalog import definition_for
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    DrillSpec,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
    Wait,
)
from mayhem.domain.identity import (
    EnvironmentScope,
    Principal,
    Role,
    RoleGrant,
)
from mayhem.domain.policy import PolicyDecision
from mayhem.domain.run_outcome import RunRecord, RunStatus, RunVerdict
from mayhem.domain.topology import NodeKind, TargetSelector
from mayhem.infra.api_store import ApiStore
from mayhem.infra.identity_store import AuthSource, IdentityStore
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

    from mayhem.controller.auth_service import AuthService
    from mayhem.domain.api import ApiEnvelope

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
ENVIRONMENT = "staging"
PEPPER = b"unit-test-pepper-for-plan-08"
PASSWORD = "correct horse battery staple"

#: The chain these fixtures migrate through: the production chain below this
#: module's reserved version, plus this module's own migration.
#:
#: Written as a *filter* rather than a splice for the reason
#: ``tests/unit/test_fabric_evidence.py`` documents at length — a hand-spliced
#: chain registers a version twice and cannot fail for want of the table under
#: test, which makes it a fixture built to fit the code. Filtering keeps the
#: chain strictly increasing no matter what concurrent lanes append around 34.
MIGRATIONS = (
    *(m for m in ALL_MIGRATIONS if m.version < API_GATEWAY_VERSION),
    API_GATEWAY_MIGRATION,
)


# ── domain fixtures ─────────────────────────────────────────────────────────


def _selector(name: str = "checkout") -> TargetSelector:
    return TargetSelector(kind=NodeKind.CONTAINER, expr=name)


def _plan(run_id: str = "run-0001") -> ExecutionPlan:
    selector = _selector()
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        steps=(
            PlannedStep(
                id="step-1",
                seq=0,
                raw_action=InjectFault(fault="net.latency", selectors=(selector,), duration="10s"),
                fault=PlannedFault(
                    fault_id="net.latency",
                    targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"checkout"})),),
                    duration=10.0,
                ),
            ),
            PlannedStep(id="step-2", seq=1, raw_action=Wait(duration="5s")),
        ),
        config_snapshot_id="cfg-0001",
        topology_snapshot_id="topo-0001",
        environment_fingerprint="env-fp-1",
        policy_id="policy-9",
        seed=7,
    )


def _spec() -> DrillSpec:
    return DrillSpec.model_validate(
        {
            "kind": "drill",
            "name": "checkout-latency",
            "hypothesis": "p99 rises under packet loss",
            "containers": {"checkout": {"faults": [{"fault": "net.latency", "duration": "5s"}]}},
            "execution": [{"sequential": ["checkout"]}],
        }
    )


def _record(run_id: str = "run-0001") -> RunRecord:
    authored = _spec()
    return RunRecord(
        run_id=run_id,
        experiment_name=authored.name,
        spec_json=authored.model_dump_json(),
        plan_json=_plan(run_id).model_dump_json(),
        seed=7,
        status=RunStatus.COMPLETED,
        verdict=RunVerdict.FAIL,
        environment_fingerprint="env-fp-1",
        config_snapshot_id="cfg-0001",
        started_at="2026-01-01T00:00:00+00:00",
        ended_at="2026-01-01T00:00:30+00:00",
        tags=("nightly",),
    )


def _run_resource(run_id: str = "run-0001") -> RunResource:
    return RunResource.of(_record(run_id))


def _decision(allowed: bool = True) -> PolicyDecision:
    return PolicyDecision(
        bundle_id="bundle-1",
        bundle_version=1,
        policy_digest="a" * 64,
        rule_digest="b" * 64,
        facts_digest="c" * 64,
        allowed=allowed,
        outcome="allow" if allowed else "deny",
        reasons=("bundle-1 allows this plan",) if allowed else ("bundle-1 denies this plan",),
    )


# ── identity + gateway fixtures ─────────────────────────────────────────────


class _RecordingPort:
    """A mutation port that records what it was asked to do."""

    def __init__(self, envelope: ApiEnvelope | None = None) -> None:
        self.calls: list[MutationRequest] = []
        self._envelope = envelope

    def submit(self, request: MutationRequest) -> ApiEnvelope:
        from mayhem.domain.api import ApiEnvelope as _Envelope

        self.calls.append(request)
        return self._envelope or _Envelope.ok({"accepted": True, "route": request.route})


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    opened = Store.open_migrated(tmp_path / "mayhem.db", MIGRATIONS)
    yield opened
    opened.close()


@pytest.fixture()
def api(store: Store) -> ApiStore:
    return ApiStore(store)


@pytest.fixture()
def identities(store: Store) -> IdentityStore:
    return IdentityStore(store)


@pytest.fixture()
def auth(identities: IdentityStore, store: Store) -> AuthService:
    from mayhem.controller.auth_service import AuthService

    return AuthService(identities, pepper=PEPPER, clock=lambda: NOW)


def _principal(identities: IdentityStore, principal_id: str, *roles: Role) -> Principal:
    principal = Principal(principal_id=principal_id)
    identities.save_principal(principal, auth_source=AuthSource.LOCAL, now=NOW)
    for role in roles:
        identities.save_grant(
            RoleGrant(
                role=role,
                scope=EnvironmentScope(environment=ENVIRONMENT),
                principal=principal,
                granted_at=NOW,
                granted_by="u-root",
            )
        )
    return principal


def _token(auth: AuthService, identities: IdentityStore, principal_id: str) -> str:
    identities.set_local_credential(principal_id, PASSWORD, now=NOW, iterations=10)
    return auth.issue_session(principal_id, now=NOW).token


def _gateway(
    api: ApiStore,
    auth: AuthService,
    identities: IdentityStore,
    *,
    now: datetime = NOW,
    mutation: Any = None,
) -> ApiGateway:
    counter = {"n": 0}

    def next_id() -> str:
        counter["n"] += 1
        return f"req-{counter['n']:04d}"

    return ApiGateway(
        store=api,
        auth=auth,
        identity=identities,
        now=now,
        mutation=mutation,
        request_id=next_id,
    )


def _request(
    method: str,
    path: str,
    *,
    token: str = "",
    environment: str = ENVIRONMENT,
    query: dict[str, str] | None = None,
    body: Any = None,
    idempotency_key: str = "",
) -> ApiRequest:
    headers: dict[str, str] = {}
    if token:
        headers["authorization"] = f"Bearer {token}"
    if environment:
        headers[ENVIRONMENT_HEADER] = environment
    if idempotency_key:
        headers["idempotency-key"] = idempotency_key
    raw = b"" if body is None else json.dumps(body).encode()
    return ApiRequest(method=method, path=path, query=query or {}, headers=headers, body=raw)


def _rule_of(response: Any) -> str:
    return str(response.envelope.meta.get("rule_id", ""))


# ── construction invariants: negative controls ──────────────────────────────


class TestTheRouteTableCannotBeDishonest:
    """The gateway refuses a route table that claims something untrue."""

    def test_a_mutation_naming_a_command_the_cli_does_not_have_is_refused(self) -> None:
        route = Route(
            method="POST",
            path=f"{API_PREFIX}/plans",
            handler="create_plan",
            summary="invented",
            required_role=Role.PLAN,
            mutating=True,
            command_path="not_a_command",
            idempotent=True,
        )
        with pytest.raises(ApiRefusedError) as caught:
            _construct(routes=(route,))
        assert caught.value.rule == "api.command_unknown"
        assert "not_a_command" in str(caught.value)

    def test_a_mutation_with_no_command_path_is_refused(self) -> None:
        route = Route(
            method="POST",
            path=f"{API_PREFIX}/plans",
            handler="create_plan",
            summary="invented",
            required_role=Role.PLAN,
            mutating=True,
            idempotent=True,
        )
        with pytest.raises(ApiRefusedError) as caught:
            _construct(routes=(route,))
        assert caught.value.rule == "api.command_unknown"
        assert "identical validation" in str(caught.value)

    def test_a_mutation_that_is_not_idempotent_is_refused(self) -> None:
        route = Route(
            method="POST",
            path=f"{API_PREFIX}/plans",
            handler="create_plan",
            summary="invented",
            required_role=Role.PLAN,
            mutating=True,
            command_path="run",
            idempotent=False,
        )
        with pytest.raises(ApiRefusedError) as caught:
            _construct(routes=(route,))
        assert caught.value.rule == "api.idempotency_required"

    def test_a_read_claiming_a_cli_command_is_refused(self) -> None:
        route = Route(
            method="GET",
            path=f"{API_PREFIX}/runs",
            handler="list_runs",
            summary="invented",
            required_role=Role.VIEW,
            command_path="run",
        )
        with pytest.raises(ApiRefusedError) as caught:
            _construct(routes=(route,))
        assert caught.value.rule == "api.route_not_mutating"

    def test_a_read_behind_an_action_role_is_refused(self) -> None:
        """A read that needs ``EXECUTE`` is a mutation in disguise."""
        route = Route(
            method="GET",
            path=f"{API_PREFIX}/runs",
            handler="list_runs",
            summary="invented",
            required_role=Role.EXECUTE,
        )
        with pytest.raises(ApiRefusedError) as caught:
            _construct(routes=(route,))
        assert caught.value.rule == "api.route_not_mutating"
        assert "mutation in disguise" in str(caught.value)

    def test_a_read_behind_a_segregation_role_is_allowed(self) -> None:
        """``EVIDENCE_ADMIN`` is who may *see* sealed evidence, not who may act.

        The counter-case to the refusal above, and the reason the action-role set
        is explicit: reading evidence is a read, and making it a build failure
        would push the next segregation role into a fake mutation.
        """
        route = Route(
            method="GET",
            path=f"{API_PREFIX}/runs/{{run_id}}/evidence",
            handler="run_evidence",
            summary="sealed evidence for one run",
            required_role=Role.EVIDENCE_ADMIN,
        )
        assert _construct(routes=(route,)).route_for("run_evidence").required_role is (
            Role.EVIDENCE_ADMIN
        )

    def test_two_routes_for_one_method_and_path_are_refused(self) -> None:
        route = Route(
            method="GET",
            path=f"{API_PREFIX}/health",
            handler="health",
            summary="twice",
            required_role=None,
        )
        with pytest.raises(ApiRefusedError) as caught:
            _construct(routes=(route, route))
        assert caught.value.rule == "api.route_unknown"

    def test_the_refusal_is_not_a_tautology_a_benign_route_table_passes(self) -> None:
        """The negative controls above only mean something if a real one builds."""
        assert _construct(routes=ROUTES).routes == ROUTES


def _construct(*, routes: tuple[Route, ...]) -> ApiGateway:
    """Build a gateway with stub collaborators, for construction-only assertions."""
    from mayhem.controller.auth_service import AuthService

    store = Store(":memory:")
    store.migrate(MIGRATIONS)
    identities = IdentityStore(store)
    auth = AuthService(identities, pepper=PEPPER, clock=lambda: NOW)
    gateway = ApiGateway(
        store=ApiStore(store),
        auth=auth,
        identity=identities,
        now=NOW,
        routes=routes,
    )
    store.close()
    return gateway


# ── authorization ordering: the security property ───────────────────────────


class TestAuthorizeHappensBeforeValidate:
    @pytest.fixture()
    def wired(
        self, api: ApiStore, auth: AuthService, identities: IdentityStore
    ) -> tuple[ApiGateway, str]:
        _principal(identities, "u-ana", Role.VIEW)
        token = _token(auth, identities, "u-ana")
        return _gateway(api, auth, identities), token

    def test_an_unauthenticated_request_is_refused_with_plan_09s_code(
        self, wired: tuple[ApiGateway, str]
    ) -> None:
        gateway, _token_value = wired
        response = gateway.dispatch(_request("GET", f"{API_PREFIX}/runs"))
        assert response.status == 401
        assert _rule_of(response) == "auth.session_unknown"

    def test_a_missing_environment_is_refused_rather_than_defaulted(
        self, wired: tuple[ApiGateway, str]
    ) -> None:
        gateway, token = wired
        response = gateway.dispatch(
            _request("GET", f"{API_PREFIX}/runs", token=token, environment="")
        )
        assert response.status == 400
        assert _rule_of(response) == "auth.session_scope"
        assert "first" in str(response.envelope.errors[0])

    def test_an_authorized_principal_reads(self, wired: tuple[ApiGateway, str]) -> None:
        gateway, token = wired
        response = gateway.dispatch(_request("GET", f"{API_PREFIX}/health", token=token))
        assert response.status == 200
        assert response.envelope.data["api_prefix"] == API_PREFIX

    def test_a_principal_without_the_role_is_refused_before_the_body_is_read(
        self, api: ApiStore, auth: AuthService, identities: IdentityStore
    ) -> None:
        """The load-bearing ordering assertion.

        The request carries a body that is **not** JSON. If validation ran first
        the response would be ``api.malformed_request`` with a 400 — which is a
        description of a request the principal may not make at all. The rule id
        is the assertion, because "it was refused somehow" is not a property.
        """
        _principal(identities, "u-bob", Role.VIEW)
        token = _token(auth, identities, "u-bob")
        gateway = _gateway(api, auth, identities, mutation=_RecordingPort())
        request = ApiRequest(
            method="POST",
            path=f"{API_PREFIX}/runs/run-0001/stop",
            headers={
                "authorization": f"Bearer {token}",
                ENVIRONMENT_HEADER: ENVIRONMENT,
                "idempotency-key": "k-1",
            },
            body=b"this is not json at all",
        )
        response = gateway.dispatch(request)
        assert response.status == 403
        assert _rule_of(response) == "auth.role_missing"
        assert "emergency_stop" in str(response.envelope.errors[0])

    def test_a_session_for_one_environment_cannot_reach_another(
        self, api: ApiStore, auth: AuthService, identities: IdentityStore
    ) -> None:
        """Plan 09's *reach* check, carried through rather than re-implemented."""
        _principal(identities, "u-ana", Role.VIEW)
        token = _token(auth, identities, "u-ana")
        gateway = _gateway(api, auth, identities)
        response = gateway.dispatch(
            _request("GET", f"{API_PREFIX}/runs", token=token, environment="production")
        )
        assert response.status == 403
        assert _rule_of(response) == "auth.role_missing"


def test_the_required_role_per_mutation_is_read_from_plan_09s_table() -> None:
    """Not restated: the ChatOps table is the single answer."""
    from mayhem.controller.check_gate import CHATOPS_REQUIRED_ROLE, ChatOpsCommand

    stop = next(route for route in ROUTES if route.handler == "stop_run")
    assert stop.required_role is Role(CHATOPS_REQUIRED_ROLE[ChatOpsCommand.STOP])
    assert stop.required_role is Role.EMERGENCY_STOP
    run = next(route for route in ROUTES if route.handler == "create_plan")
    assert run.required_role is Role.PLAN, "compiling is planning, not executing"


def test_approve_is_absent_from_the_control_actions_and_that_is_documented() -> None:
    """There is no ``mayhem approve`` command, so no approval write endpoint."""
    assert [name for name, _ in CONTROL_ACTIONS] == ["run", "stop"]
    assert not any(route.handler == "create_approval" for route in ROUTES)
    assert all(not route.path.endswith("/approvals") or route.method == "GET" for route in ROUTES)


def test_command_path_for_refuses_an_action_with_no_command() -> None:
    with pytest.raises(ApiRefusedError) as caught:
        command_path_for("approve")
    assert caught.value.rule == "api.command_unknown"


# ── idempotency ─────────────────────────────────────────────────────────────


class TestIdempotency:
    @pytest.fixture()
    def wired(
        self, api: ApiStore, auth: AuthService, identities: IdentityStore
    ) -> tuple[ApiGateway, str, _RecordingPort]:
        _principal(identities, "u-ops", Role.VIEW, Role.EMERGENCY_STOP)
        token = _token(auth, identities, "u-ops")
        port = _RecordingPort()
        return _gateway(api, auth, identities, mutation=port), token, port

    def test_a_mutation_with_no_key_is_refused(self, wired: tuple[Any, ...]) -> None:
        gateway, token, _port = wired
        response = gateway.dispatch(
            _request("POST", f"{API_PREFIX}/runs/run-0001/stop", token=token, body={})
        )
        assert response.status == 400
        assert _rule_of(response) == "api.idempotency_required"

    def test_a_replay_returns_the_recorded_response_without_dispatching_again(
        self, wired: tuple[Any, ...]
    ) -> None:
        gateway, token, port = wired
        request = _request(
            "POST",
            f"{API_PREFIX}/runs/run-0001/stop",
            token=token,
            body={"reason": "fault not reversing"},
            idempotency_key="k-replay",
        )
        first = gateway.dispatch(request)
        second = gateway.dispatch(request)
        assert first.body_json() == second.body_json()
        assert len(port.calls) == 1, "the replay performed the mutation again"
        assert second.headers.get("Idempotent-Replay") == "true"

    def test_the_same_key_with_a_different_request_is_a_conflict(
        self, wired: tuple[Any, ...]
    ) -> None:
        gateway, token, port = wired
        gateway.dispatch(
            _request(
                "POST",
                f"{API_PREFIX}/runs/run-0001/stop",
                token=token,
                body={"reason": "first"},
                idempotency_key="k-conflict",
            )
        )
        second = gateway.dispatch(
            _request(
                "POST",
                f"{API_PREFIX}/runs/run-0001/stop",
                token=token,
                body={"reason": "a different reason entirely"},
                idempotency_key="k-conflict",
            )
        )
        assert second.status == 409
        assert _rule_of(second) == "api.idempotency_conflict"
        assert len(port.calls) == 1

    def test_a_mutation_with_no_bound_port_is_refused_not_acknowledged(
        self, api: ApiStore, auth: AuthService, identities: IdentityStore
    ) -> None:
        _principal(identities, "u-ops", Role.EMERGENCY_STOP)
        token = _token(auth, identities, "u-ops")
        gateway = _gateway(api, auth, identities, mutation=None)
        response = gateway.dispatch(
            _request(
                "POST",
                f"{API_PREFIX}/runs/run-0001/stop",
                token=token,
                body={},
                idempotency_key="k-no-port",
            )
        )
        assert response.status == 501
        assert _rule_of(response) == "api.mutation_port_absent"


# ── routing, pagination, normalized errors ──────────────────────────────────


class TestRoutingAndPagination:
    @pytest.fixture()
    def wired(
        self, api: ApiStore, auth: AuthService, identities: IdentityStore
    ) -> tuple[ApiGateway, str]:
        _principal(identities, "u-ana", Role.VIEW, Role.EVIDENCE_ADMIN)
        token = _token(auth, identities, "u-ana")
        gateway = _gateway(api, auth, identities)
        for index in range(3):
            api.save_run(_run_resource(f"run-{index:04d}"))
        return gateway, token

    def test_an_unknown_path_names_the_routes_that_exist(self, wired: tuple[Any, str]) -> None:
        gateway, token = wired
        response = gateway.dispatch(
            _request("GET", f"{API_PREFIX}/nope", token=token)
        )
        assert response.status == 404
        assert _rule_of(response) == "api.route_unknown"
        assert response.envelope.meta["routes"], "the refusal must name what does exist"

    def test_a_path_outside_the_prefix_says_the_version_is_unsupported(
        self, wired: tuple[Any, str]
    ) -> None:
        gateway, token = wired
        response = gateway.dispatch(_request("GET", "/api/v2/runs", token=token))
        assert response.status == 404
        assert _rule_of(response) == "api.version_unsupported"

    def test_a_wrong_method_is_405_and_names_the_right_one(self, wired: tuple[Any, str]) -> None:
        gateway, token = wired
        response = gateway.dispatch(_request("DELETE", f"{API_PREFIX}/runs", token=token))
        assert response.status == 405
        assert _rule_of(response) == "api.method_not_allowed"
        assert "GET" in str(response.envelope.meta["allow"])

    def test_pagination_is_applied_and_the_window_is_not_the_table(
        self, wired: tuple[Any, str]
    ) -> None:
        gateway, token = wired
        response = gateway.dispatch(
            _request("GET", f"{API_PREFIX}/runs", token=token, query={"limit": "2"})
        )
        assert response.status == 200
        data = response.envelope.data
        assert len(data["items"]) == 2
        assert data["limit"] == 2 and data["offset"] == 0
        assert data["has_more"] is True

    def test_a_limit_above_the_maximum_is_refused(self, wired: tuple[Any, str]) -> None:
        gateway, token = wired
        response = gateway.dispatch(
            _request(
                "GET", f"{API_PREFIX}/runs", token=token, query={"limit": str(MAX_PAGE_SIZE + 1)}
            )
        )
        assert response.status == 400
        assert _rule_of(response) == "api.malformed_request"

    def test_a_non_integer_limit_is_refused(self, wired: tuple[Any, str]) -> None:
        gateway, token = wired
        response = gateway.dispatch(
            _request("GET", f"{API_PREFIX}/runs", token=token, query={"limit": "lots"})
        )
        assert response.status == 400
        assert "not an integer" in str(response.envelope.errors[0])

    def test_an_unknown_run_is_404_not_an_empty_page(
        self, wired: tuple[Any, str]
    ) -> None:
        gateway, token = wired
        response = gateway.dispatch(
            _request("GET", f"{API_PREFIX}/runs/run-9999", token=token)
        )
        assert response.status == 404
        assert _rule_of(response) == "api.resource_not_found"

    def test_every_refusal_carries_its_rule_in_the_error_text_too(
        self, wired: tuple[Any, str]
    ) -> None:
        """Greppable without parsing metadata — the property plan 14 claims."""
        gateway, token = wired
        response = gateway.dispatch(_request("GET", f"{API_PREFIX}/nope", token=token))
        rule = _rule_of(response)
        assert rule
        assert rule in str(response.envelope.errors[0])

    def test_the_default_page_size_is_the_documented_one(
        self, wired: tuple[Any, str]
    ) -> None:
        gateway, token = wired
        response = gateway.dispatch(_request("GET", f"{API_PREFIX}/runs", token=token))
        assert response.envelope.data["limit"] == DEFAULT_PAGE_SIZE


# ── the OpenAPI document is generated ───────────────────────────────────────


class TestOpenApiIsGeneratedNotWritten:
    def test_every_route_appears_in_the_document(self) -> None:
        document = openapi_document()
        served = {(route.method.lower(), route.path) for route in ROUTES}
        documented = {
            (method, path) for path, entry in document["paths"].items() for method in entry
        }
        assert documented == served

    def test_a_route_naming_an_unimplemented_handler_fails_the_build(self) -> None:
        route = Route(
            method="GET",
            path=f"{API_PREFIX}/imaginary",
            handler="not_a_handler",
            summary="invented",
            required_role=Role.VIEW,
        )
        with pytest.raises(ApiRefusedError) as caught:
            openapi_document((route,))
        assert caught.value.rule == "api.route_unknown"
        assert "refuses every call" in str(caught.value)

    def test_the_document_declares_what_this_build_does_not_serve(self) -> None:
        description = openapi_document()["info"]["description"]
        for surface in UNIMPLEMENTED_API_SURFACES:
            assert surface in description, f"{surface} is an omission, not a silence"

    def test_the_environment_header_is_declared_required(self) -> None:
        environment = openapi_document()["components"]["parameters"]["environment"]
        assert environment["name"] == ENVIRONMENT_HEADER
        assert environment["required"] is True

    def test_the_envelope_schema_is_the_clis_own(self) -> None:
        schema = openapi_document()["components"]["schemas"]["Envelope"]
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == {
            "status",
            "schema_version",
            "data",
            "warnings",
            "errors",
            "evidence_refs",
            "meta",
        }


# ── the parameter UX (gap 61) ───────────────────────────────────────────────


class TestParameterControlsProjectTheCatalog:
    def test_a_bounded_numeric_parameter_renders_as_a_slider(self) -> None:
        definition = definition_for("mem.leak")
        control = control_for_parameter(definition, "rate_mb")
        assert control.kind is ControlKind.SLIDER
        assert control.minimum == 1.0 and control.maximum == 512.0
        assert control.step == pytest.approx((512.0 - 1.0) / 100.0)

    def test_an_unbounded_parameter_renders_as_text_and_carries_no_bounds(
        self,
    ) -> None:
        definition = definition_for("net.latency")
        control = control_for_parameter(definition, "seconds")
        assert control.kind is ControlKind.TEXT
        payload = control.to_payload()
        assert "minimum" not in payload and "maximum" not in payload

    def test_a_span_wider_than_the_slider_limit_renders_as_text(self) -> None:
        """A slider over ``0..1e9`` moves one unit per pixel."""
        from mayhem.domain.faults import ParamSpec, ParamType

        kind, _step = control_kind_for(
            ParamSpec(name="huge", type=ParamType.FLOAT, minimum=0.0, maximum=1e9)
        )
        assert kind is ControlKind.TEXT

    def test_the_boundary_is_exact(self) -> None:
        """Both sides of ``SLIDER_SPAN_LIMIT``, so the constant is not decoration."""
        from mayhem.domain.faults import ParamSpec, ParamType

        for maximum, expected in (
            (SLIDER_SPAN_LIMIT, ControlKind.SLIDER),
            (SLIDER_SPAN_LIMIT + 1.0, ControlKind.TEXT),
        ):
            spec = ParamSpec(name="span", type=ParamType.FLOAT, minimum=0.0, maximum=maximum)
            assert control_kind_for(spec)[0] is expected, maximum

    def test_a_boolean_renders_as_a_toggle_not_a_select(self) -> None:
        from mayhem.domain.faults import ParamSpec, ParamType

        assert control_kind_for(ParamSpec(name="flag", type=ParamType.BOOLEAN))[0] is (
            ControlKind.BOOLEAN
        )

    def test_a_provider_enum_renders_as_a_select(self) -> None:
        """The provider grammar's own vocabulary reaches the same five kinds."""
        from mayhem.domain.provider import ParameterDeclaration, ParameterKind

        enum = ParameterDeclaration(
            name="strategy",
            kind=ParameterKind.ENUM,
            default="first",
            choices=("first", "second"),
        )
        assert control_kind_for(enum)[0] is ControlKind.SELECT
        duration = ParameterDeclaration(
            name="hold",
            kind=ParameterKind.DURATION_S,
            default="1",
            minimum=1.0,
            maximum=60.0,
        )
        assert control_kind_for(duration)[0] is ControlKind.DIRECTION_SELECTOR

    def test_the_control_kind_is_a_total_function_of_the_schema(self) -> None:
        """One schema, one widget, forever — in every surface at once."""
        from mayhem.domain.catalog import all_definitions

        seen: dict[tuple[str, str, object, object], ControlKind] = {}
        for definition in all_definitions():
            for spec in definition.params_schema:
                key = (spec.name, str(spec.type), spec.minimum, spec.maximum)
                rendered = control_for_parameter(definition, spec.name).kind
                if key in seen:
                    assert seen[key] is rendered, f"{key} rendered two different widgets"
                seen[key] = rendered

    def test_an_undeclared_parameter_is_refused_naming_the_declared_ones(self) -> None:
        definition = definition_for("net.latency")
        with pytest.raises(ApiRefusedError) as caught:
            control_for_parameter(definition, "not_a_parameter")
        assert caught.value.rule == "api.parameter_unknown"
        assert caught.value.detail["declared"]

    def test_the_risk_annotation_is_the_catalogs_own_field(self) -> None:
        definition = definition_for("mem.leak")
        control = control_for_parameter(definition, "rate_mb")
        assert control.risk == definition.risk.value
        assert control.required_capabilities == tuple(
            sorted(cap.value for cap in definition.required_caps)
        )
        assert control.max_duration_s == definition.max_duration_s

    def test_the_control_table_is_derived_and_therefore_total(self) -> None:
        from mayhem.domain.catalog import all_definitions

        controls = parameter_controls()
        expected = sum(len(d.params_schema) for d in all_definitions())
        assert len(controls) == expected
        assert all(isinstance(row, ParameterControl) for row in controls)

    def test_a_fault_filter_narrows_the_table(self) -> None:
        narrow = parameter_controls(["mem.leak"])
        assert {row.fault_id for row in narrow} == {"mem.leak"}
        assert len(narrow) < len(parameter_controls())


# ── the facades ─────────────────────────────────────────────────────────────


def test_a_submission_missing_its_plan_identity_names_every_missing_key() -> None:
    with pytest.raises(InvariantViolationError) as caught:
        PlanSubmission.from_payload({"run_id": "r-1"})
    message = str(caught.value)
    for key in REQUIRED_SUBMISSION_KEYS:
        if key != "run_id":
            assert key in message


def test_a_submission_whose_spec_is_malformed_surfaces_the_spec_error() -> None:
    payload = {
        "run_id": "r-1",
        "spec": {"kind": "drill", "name": "x"},
        "config_snapshot_id": "cfg",
        "topology_snapshot_id": "topo",
        "environment_fingerprint": "fp",
    }
    # The DrillSpec validator owns the message. Asserting its *own* type name
    # through is what proves the refusal is the spec's rather than a wrapper's:
    # a paraphrase would lose "DrillSpec" and this would notice.
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="DrillSpec"):
        PlanSubmission.from_payload(payload)


def test_the_planner_stores_the_phase_1_projection(api: ApiStore) -> None:
    planner = PlannerService(api)
    submission = PlanSubmission(
        run_id="r-planner",
        spec=_spec(),
        config_snapshot_id="cfg-0001",
        topology_snapshot_id="topo-0001",
        environment_fingerprint="env-fp-1",
    )
    graph = _graph()
    resource = planner.compile(submission, graph)
    assert isinstance(resource, PlanResource)
    assert api.plan_for_run("r-planner") is not None
    assert resource.plan_digest == plan_digest_of(resource.plan)


def test_the_policy_facade_refuses_to_guess_at_an_absent_decision(api: ApiStore) -> None:
    service = PolicyService(api)
    with pytest.raises(InvariantViolationError) as caught:
        service.allow("a" * 64)
    assert "nothing was evaluated" in str(caught.value)
    api.save_policy_decision(PolicyResource.of(_decision(allowed=True)))
    assert service.allow("a" * 64) is True


def test_the_policy_facade_refuses_two_disagreeing_decisions(api: ApiStore) -> None:
    """A denial that becomes an allowance because it sorted second is a real bug."""
    service = PolicyService(api)
    api.save_policy_decision(PolicyResource.of(_decision(allowed=True)))
    api.save_policy_decision(PolicyResource.of(_decision(allowed=False)))
    with pytest.raises(InvariantViolationError) as caught:
        service.allow("a" * 64)
    assert caught.value.rule == "api.policy_decision_ambiguous"
    assert "picking the first" in str(caught.value)


def test_the_evidence_facade_states_what_it_cannot_prove(api: ApiStore) -> None:
    limitations = EvidenceService(api).unverified_by_design()
    assert limitations, "a surface that omits its limitations reads as having none"
    assert any("signature" in text for text in limitations)
    from mayhem.providers.pack import SIGNATURE_VERIFICATION_IMPLEMENTED

    assert SIGNATURE_VERIFICATION_IMPLEMENTED is False


# ── the migration this module owns ──────────────────────────────────────────


class TestTheGatewayMigration:
    def test_it_is_the_next_version_after_the_chain_head(self) -> None:
        head = max(migration.version for migration in ALL_MIGRATIONS)
        assert head < API_GATEWAY_VERSION, (
            "reservation needed: version 34 collides with a registered migration"
        )

    def test_it_applies_and_the_table_exists(self, store: Store) -> None:
        names = {
            str(row["name"])
            for row in store.query("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert "api_idempotency" in names

    def test_the_down_path_removes_the_table(self, tmp_path: Path) -> None:
        opened = Store.open_migrated(tmp_path / "down.db", MIGRATIONS)
        opened.migrate_down(API_GATEWAY_VERSION - 1, MIGRATIONS)
        names = {
            str(row["name"])
            for row in opened.query("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert "api_idempotency" not in names
        opened.close()


# ── helpers ─────────────────────────────────────────────────────────────────


def _graph() -> Any:
    """A one-container graph, built the way the domain requires."""
    from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
    from mayhem.domain.topology import ContainerNode, TopologyGraph

    return TopologyGraph(
        nodes=(
            ContainerNode(
                id="checkout",
                name="checkout",
                engine="podman",
                runtime_identity=RuntimeIdentity(
                    runtime="podman", host_id="h1", runtime_id="ctr-checkout"
                ),
                runtime_metadata=RuntimeMetadata(service="checkout", name="checkout"),
                container_name="checkout",
                state="running",
            ),
        ),
        edges=(),
    )
