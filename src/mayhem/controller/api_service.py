"""The ``/api/v1`` gateway, the service facades over the existing seams, and the
parameter UX the UI renders from (plan 08, Phase 3).

Phase 1 (:mod:`mayhem.domain.api`) fixed the resource vocabulary, Phase 2
(:mod:`mayhem.infra.api_store`) persisted it and proved the replication
strategy. Phase 2's own STATUS line names what was still missing: *"No service
facades yet… the planner/policy/scheduler/orchestrator/evidence facades and the
gateway are Phase 3's."* This is that file, and it is deliberately the **only**
place an HTTP-shaped concept appears in mayhem.

Why transport-neutral
---------------------

:class:`ApiRequest` and :class:`ApiResponse` are plain dataclasses. This module
imports nothing from ``wsgiref``, ``http``, or any framework, because:

* there is **no web framework in this project** — the dependency list is pydantic,
  typer, click, pyyaml, structlog, kubernetes — so a gateway written against a
  framework would be a dependency this change adds, which the plan forbids and
  which nobody could run in the field;
* the decision logic below is what has to be testable, and it is testable
  without a socket, a port, or a thread, which is also what makes the negative
  controls in ``tests/unit/test_api_service.py`` about *order* rather than about
  timing.

The WSGI adapter that turns these two dataclasses into real HTTP is
:mod:`mayhem.controller.api_http`, and it is one page of ``environ`` translation
in front of :meth:`ApiGateway.dispatch`. Nothing about authorisation, routing, or
envelope shape lives there.

Authorize, then validate, then dispatch — in that order
--------------------------------------------------------

This ordering is the security property, and it is borrowed rather than invented:
:func:`mayhem.controller.check_gate.dispatch_chatops` already states it for the
ChatOps surface, and the plan's own acceptance criterion says an API call that
bypasses approval is refused *at the service layer*. So :meth:`ApiGateway.dispatch`
runs, with no exceptions and no early return:

1. **authenticate** — :meth:`mayhem.controller.auth_service.AuthService.authenticate_token`,
   plan 09's single token entry point, whose refusal codes this module re-raises
   rather than restating (:data:`~mayhem.controller.auth_service.REFUSAL_SESSION_UNKNOWN`
   and the rest). No new vocabulary for "who are you".
2. **authorize** — the route's required :class:`~mayhem.domain.identity.Role`,
   resolved through :func:`mayhem.domain.identity.effective_roles` over the same
   :class:`~mayhem.infra.identity_store.IdentityStore` grants ``mayhem stop`` and
   ChatOps read. The required role per mutating route is read from
   :data:`~mayhem.controller.check_gate.CHATOPS_REQUIRED_ROLE` where one exists,
   so "who may approve / run / stop" has exactly one answer in the repository.
3. **parse and validate** the body, the query string, and the path parameters.
4. **resolve idempotency** — a replay returns the recorded response byte for byte.
5. **dispatch** — through an injected port, never inline.

Steps 3 and 4 are *after* 1 and 2, and a test asserts that an unauthorized
request carrying a malformed body is refused with the *authorization* rule, not
the parse rule: a validation error message is a description of the request, and
returning one to a principal who may not read the resource at all is an oracle.

The mutation contract
---------------------

The plan's premise is "``cli/command_registry.py`` single inventory plus
``PrefixGroup`` resolution: every API mutation maps to a command path with
identical validation". So a mutation route here **carries** its command path, and
:meth:`ApiGateway.route_inventory` is checked against
:data:`mayhem.cli.command_registry.COMMAND_SPECS` at construction: a mutation
naming a command that is not in the single inventory is refused before the
gateway will serve a single request. What the gateway does *not* do is
reimplement the command's parsing — it hands a
:class:`MutationRequest` to an injected :class:`MutationPort` and renders
whatever envelope comes back. A second validator is exactly the drift this plan
exists to prevent.

Deliberately not claimed
------------------------

* **No webhook delivery, no SSE, no WebSocket.** All three are named in the
  plan's API section and none is implemented. The gateway has no connection to
  hold open, so a page of routes that *looked* like it supported them would be a
  lie in the one place a client reads to find out what the control plane does.
  :func:`openapi_document` therefore omits them, and
  :data:`UNIMPLEMENTED_API_SURFACES` names them so the omission is a record
  rather than a silence.
* **No SDKs.** The plan defers them until v1 is stable.
* **No rate limiting.** Not a gate, an omission, and said so in the OpenAPI
  description rather than left for a reader to assume.
* **This module does not execute anything.** ``POST /api/v1/plans`` *compiles* a
  plan and stores the resource; it does not run it. Running is ``mayhem run``'s
  job and the port that reaches it is a Phase 4 concern.

The parameter UX is a projection, not an editor
-----------------------------------------------

Gap 61 asks for sliders, direction selectors, and risk/impact/capability
annotations *rendered from catalog parameter schemas*, so that CLI ``--help`` and
UI controls cannot disagree. :func:`parameter_controls` is that projection and it
reads exactly one source: :class:`mayhem.domain.faults.FaultDefinition` from
:mod:`mayhem.domain.catalog`. It derives a control *kind* from the schema's own
:class:`~mayhem.domain.faults.ParamType` and bounds, and it never reads a
parameter list from anywhere else. The consequence the acceptance criterion
wants is that a disagreement is not expressible: there is no second declaration
for a UI to consult, so ``mayhem --help`` and a slider can only ever render the
same schema.

The risk, impact, and capability annotations on each control are read off the
*same* :class:`FaultDefinition` fields the CLI's own ``extend``/``discover``
surfaces read (``risk``, ``required_caps``, ``reversible``,
``max_duration_s``) — they are not a second rating.

Migrations
----------

:data:`API_GATEWAY_MIGRATION` is registered in
:data:`mayhem.infra.migrations.ALL_MIGRATIONS` as version 34, so the
``api_idempotency`` table this module reads and writes is created by the
**production** chain rather than by a fixture that spliced the migration in. Its
DDL lives in :mod:`mayhem.infra.api_gateway_schema` — moved down out of this
module because ``migrations.py`` importing ``mayhem.controller`` would be an
upward edge the layering contract reports as broken — and it is re-exported here
so ``from mayhem.controller.api_service import API_GATEWAY_MIGRATION`` keeps
resolving to the same object the chain migrates. ``tests/unit/test_api_service.py``
builds its fixture chain as ``(<34 from ALL_MIGRATIONS, API_GATEWAY_MIGRATION)``
so it keeps working whatever concurrent lanes append around it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final, Protocol

from mayhem.cli.command_registry import COMMAND_SPECS
from mayhem.controller.auth_service import Authentication, AuthMethod
from mayhem.controller.check_gate import CHATOPS_REQUIRED_ROLE, ChatOpsCommand
from mayhem.domain.api import API_SCHEMA_VERSION, ApiEnvelope, ExecutiveMetric
from mayhem.domain.catalog import all_definitions
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import digest
from mayhem.domain.identity import EnvironmentScope, Role
from mayhem.infra.api_gateway_schema import (
    API_GATEWAY_MIGRATION,
    API_GATEWAY_VERSION,
)
from mayhem.infra.api_store import ApiStore, RunFilters

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from datetime import datetime

    from mayhem.controller.auth_service import AuthService
    from mayhem.domain.faults import FaultDefinition
    from mayhem.infra.identity_store import IdentityStore

__all__ = [
    "API_GATEWAY_MIGRATION",
    "API_GATEWAY_VERSION",
    "API_PREFIX",
    "CONTROL_ACTIONS",
    "DEFAULT_PAGE_SIZE",
    "ENVIRONMENT_HEADER",
    "IDEMPOTENCY_HEADER",
    "MAX_BODY_BYTES",
    "MAX_PAGE_SIZE",
    "ROUTES",
    "RULE_API_COMMAND_UNKNOWN",
    "RULE_API_IDEMPOTENCY_CONFLICT",
    "RULE_API_IDEMPOTENCY_REQUIRED",
    "RULE_API_MALFORMED_REQUEST",
    "RULE_API_METHOD_NOT_ALLOWED",
    "RULE_API_MUTATION_PORT_ABSENT",
    "RULE_API_PARAMETER_UNKNOWN",
    "RULE_API_ROUTE_NOT_MUTATING",
    "RULE_API_ROUTE_UNKNOWN",
    "RULE_API_VERSION_UNSUPPORTED",
    "UNIMPLEMENTED_API_SURFACES",
    "ApiGateway",
    "ApiRefusedError",
    "ApiRequest",
    "ApiResponse",
    "ControlKind",
    "MutationPort",
    "MutationRequest",
    "ParameterControl",
    "Route",
    "command_path_for",
    "control_for_parameter",
    "control_kind_for",
    "openapi_document",
    "parameter_controls",
]

#: The version prefix every route in this module serves. The plan's rule is
#: "``/api/v1``, then ``/api/v2`` by extension, never by breakage", so the prefix
#: is a constant and a second version is a new :data:`ROUTES` tuple rather than a
#: branch inside an existing handler.
API_PREFIX: Final[str] = "/api/v1"

#: Default and maximum page sizes. Both are values rather than limits because a
#: list endpoint with no declared maximum is one where a client can ask for the
#: whole table, and the control plane holds every run anyone has ever executed.
DEFAULT_PAGE_SIZE: Final[int] = 50
MAX_PAGE_SIZE: Final[int] = 500

#: API surfaces the plan names and this build does **not** serve. Published rather
#: than omitted so the gap is a record a reader can find, instead of an absence
#: they have to infer from a route table that is simply shorter.
UNIMPLEMENTED_API_SURFACES: Final[tuple[str, ...]] = (
    "webhooks",
    "server-sent events",
    "websocket live updates",
    "generated SDKs (python, go, rust, typescript)",
    "rate limiting",
)


# --------------------------------------------------------------------------- #
# Refusal vocabulary                                                           #
# --------------------------------------------------------------------------- #
#
# Only the concepts that are genuinely HTTP-shaped get an ``api.*`` rule id here.
# Authentication and authorization deliberately do **not**: those reuse plan 09's
# codes (``auth.session_unknown``, ``auth.role_missing``, …) so a refusal means
# the same thing whether it came from the CLI, ChatOps, or this gateway. A second
# vocabulary for "who are you" is how two surfaces start disagreeing about who
# may do what.

RULE_API_ROUTE_UNKNOWN = "api.route_unknown"
RULE_API_VERSION_UNSUPPORTED = "api.version_unsupported"
RULE_API_METHOD_NOT_ALLOWED = "api.method_not_allowed"
RULE_API_MALFORMED_REQUEST = "api.malformed_request"
RULE_API_IDEMPOTENCY_REQUIRED = "api.idempotency_required"
RULE_API_IDEMPOTENCY_CONFLICT = "api.idempotency_conflict"
RULE_API_COMMAND_UNKNOWN = "api.command_unknown"
RULE_API_ROUTE_NOT_MUTATING = "api.route_not_mutating"
RULE_API_MUTATION_PORT_ABSENT = "api.mutation_port_absent"
RULE_API_PARAMETER_UNKNOWN = "api.parameter_unknown"

#: Idempotency header and body key, spelled once. WSGI hands headers through
#: ``HTTP_``-prefixed names; the WSGI adapter is the only place that knows it.
IDEMPOTENCY_HEADER: Final[str] = "idempotency-key"

#: The header naming the environment a role is resolved in. Required on every
#: request; see :meth:`ApiGateway._authorize` for why it has no default.
ENVIRONMENT_HEADER: Final[str] = "x-mayhem-environment"

#: Maximum bytes of request body the gateway will read. A control plane that will
#: accept an unbounded body is a control plane somebody can exhaust.
MAX_BODY_BYTES: Final[int] = 1 << 20


class ApiRefusedError(InvariantViolationError):
    """One refused API request, carrying the rule that refused it.

    An :class:`~mayhem.domain.errors.InvariantViolationError`, so the existing CLI
    error surface and the UI's renderer both already know how to display one
    without a second error type.
    """

    def __init__(
        self,
        rule_id: str,
        message: str,
        *,
        status: int = 400,
        remediation: str = "",
        detail: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(rule_id, message)
        self.status = status
        self.remediation = remediation
        self.detail = dict(detail or {})


# --------------------------------------------------------------------------- #
# Transport-neutral request and response                                        #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ApiRequest:
    """One request, with no transport attached.

    ``principal_hint`` is deliberately **absent**. A field that let a caller name
    its own identity would be an authorization decision handed to the client;
    :class:`mayhem.controller.check_gate.ChatOpsRequest` says the same thing about
    ``requester`` and this type takes the same position.
    """

    method: str
    path: str
    query: Mapping[str, str] = field(default_factory=dict)
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""

    def header(self, name: str) -> str:
        """Case-insensitive header lookup. Absent is ``""``, never ``None``."""
        wanted = name.lower()
        for key, value in self.headers.items():
            if key.lower() == wanted:
                return value
        return ""

    def json_body(self) -> dict[str, Any]:
        """The parsed JSON object body, or a typed refusal.

        A body that is not a JSON *object* is refused rather than coerced: a list
        or a bare scalar has no field names, and every handler in this module
        addresses fields by name.
        """
        if not self.body.strip():
            return {}
        if len(self.body) > MAX_BODY_BYTES:
            raise ApiRefusedError(
                RULE_API_MALFORMED_REQUEST,
                f"request body is {len(self.body)} bytes, above the {MAX_BODY_BYTES}-byte "
                "maximum this gateway reads",
                status=413,
                remediation="send the resource, not a dump of the table",
            )
        try:
            parsed = json.loads(self.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiRefusedError(
                RULE_API_MALFORMED_REQUEST,
                f"request body is not JSON: {exc}",
                status=400,
                remediation="send a JSON object",
            ) from exc
        if not isinstance(parsed, dict):
            raise ApiRefusedError(
                RULE_API_MALFORMED_REQUEST,
                f"request body must be a JSON object, got {type(parsed).__name__}",
                status=400,
                remediation="send a JSON object",
            )
        return parsed


@dataclass(frozen=True, slots=True)
class ApiResponse:
    """One response: an HTTP status, a Phase 1 :class:`ApiEnvelope`, and a request id.

    ``envelope`` is the *same type* the CLI emits, so "every API object converts
    losslessly" has a consumer on this side too and the JSON contract is one
    contract rather than two that agree today.
    """

    status: int
    envelope: ApiEnvelope
    request_id: str = ""
    headers: Mapping[str, str] = field(default_factory=dict)

    def body_json(self) -> str:
        """The response body as the bytes a client reads."""
        return json.dumps(self.envelope.to_dict(), sort_keys=True, separators=(",", ":"))

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


@dataclass(frozen=True, slots=True)
class Page:
    """Pagination as an offset window plus the count that made it honest.

    ``total`` is the number of matching rows *before* the window, not the length
    of the window. A client that renders "showing 50" and a client that renders
    "1 of 812" need different numbers, and conflating them is how a dashboard
    ends up claiming a truncated table is the whole table.
    """

    items: tuple[Any, ...]
    total: int
    limit: int
    offset: int

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total

    def to_payload(self) -> dict[str, Any]:
        return {
            "items": [
                item.to_payload() if hasattr(item, "to_payload") else item
                for item in self.items
            ],
            "total": self.total,
            "limit": self.limit,
            "offset": self.offset,
            "has_more": self.has_more,
        }


# --------------------------------------------------------------------------- #
# Routes                                                                       #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Route:
    """One endpoint: its method, its path template, and what it demands.

    ``required_role`` is ``None`` for a read. It is ``None`` rather than
    ``Role.VIEW`` as the default so that adding a new read route without thinking
    about authorization fails the *review*, loudly, rather than defaulting into
    the most permissive answer.
    """

    method: str
    path: str
    handler: str
    summary: str
    required_role: Role | None = None
    mutating: bool = False
    #: The ``mayhem <command>`` path this endpoint is the API face of. Required
    #: for a mutation, absent for a read — a read has no CLI counterpart to
    #: drift from and claiming one would be a false mapping.
    command_path: str = ""
    #: Whether the endpoint requires an idempotency key. True for every mutation
    #: by construction (see :func:`ApiGateway.__post_init__`).
    idempotent: bool = False

    def pattern(self) -> str:
        return self.path


class ControlKind(StrEnum):
    """The five widget kinds the parameter UX projects onto.

    Derived from the schema, never chosen by a caller. There is no ``CUSTOM``
    member: a control kind mayhem cannot render is a parameter the UI must refuse
    to offer rather than offer as free text.
    """

    SLIDER = "slider"
    SELECT = "select"
    DIRECTION_SELECTOR = "direction_selector"
    BOOLEAN = "boolean"
    TEXT = "text"


#: API actions and the single-inventory command each is the face of. Kept as
#: data so a mapping is one row somebody can read rather than a string written
#: into a route literal.
#:
#: ``approve`` is deliberately **absent**, and its absence is a finding rather
#: than an oversight. :data:`~mayhem.controller.check_gate.ChatOpsCommand` has an
#: ``APPROVE`` member and plan 09 states the role it needs, but there is no
#: ``mayhem approve`` command: approval today is recorded through the Python API
#: and the ChatOps dispatcher. A mutation here must name a command in the single
#: inventory — that is the whole mechanism that makes CLI and API validation the
#: same validation — so an approval *write* endpoint has nothing to map to and is
#: not served. Adding one is the CLI inventory owner's change, and until it lands
#: the honest shape is: approvals are readable over the API and writable nowhere
#: except the CLI's own path. See :func:`mayhem.controller.api_safety.bind_approval`.
CONTROL_ACTIONS: Final[tuple[tuple[str, str], ...]] = (
    ("run", "run"),
    ("stop", "stop"),
)


def command_path_for(action: str) -> str:
    """The single-inventory command path an action maps to.

    ``run``/``approve``/``stop`` name the ChatOps *command* whose required role
    plan 09 already states, and the role is read from
    :data:`~mayhem.controller.check_gate.CHATOPS_REQUIRED_ROLE`. This module
    therefore does not carry a second answer to "who may stop a run".
    """
    for command, chatops_command in CONTROL_ACTIONS:
        if command != action:
            continue
        if any(spec.name == chatops_command for spec in COMMAND_SPECS):
            return chatops_command
    raise ApiRefusedError(
        RULE_API_COMMAND_UNKNOWN,
        f"no command in the single inventory maps to the API action {action!r}; "
        f"known actions are {[name for name, _ in CONTROL_ACTIONS]}",
        status=500,
        remediation="this is a gateway configuration error, not a caller error",
    )


def _role_for(action: str) -> Role:
    """The role plan 09 states for *action*, read from the ChatOps table."""
    command = ChatOpsCommand(action)
    return Role(CHATOPS_REQUIRED_ROLE[command])


#: The roles that authorise *doing* something rather than *seeing* something.
#:
#: A read behind one of these is a mutation in disguise: a ``GET`` that needs
#: ``EXECUTE`` is an endpoint whose effect is decided by who is watching. The
#: list is explicit rather than derived from "not VIEW", because
#: :data:`~mayhem.domain.identity.Role.EVIDENCE_ADMIN` is a legitimate read role
#: and a future segregation role would be too — deriving the set as "not VIEW"
#: would make adding one a build failure, which is the wrong pressure.
_ACTION_ROLES: Final[frozenset[Role]] = frozenset(
    {
        Role.PLAN,
        Role.APPROVE,
        Role.EXECUTE,
        Role.EMERGENCY_STOP,
        Role.ADMINISTER,
    }
)


def _path(template: str) -> str:
    return f"{API_PREFIX}{template}"


#: The whole ``/api/v1`` surface, as data. Every list endpoint pages through
#: :func:`ApiGateway._page_of`; every mutation carries the command path it is the
#: API face of. The OpenAPI document in :func:`openapi_document` is generated
#: from this tuple and nowhere else, so the document cannot describe an endpoint
#: that is not routed or omit one that is.
ROUTES: Final[tuple[Route, ...]] = (
    Route(
        method="GET",
        path=_path("/health"),
        handler="health",
        summary="Liveness and the API version this build serves.",
        required_role=None,
    ),
    Route(
        method="GET",
        path=_path("/experiments"),
        handler="list_experiments",
        summary="List authored experiment specs.",
        required_role=Role.VIEW,
    ),
    Route(
        method="GET",
        path=_path("/experiments/{name}"),
        handler="get_experiment",
        summary="One authored experiment spec.",
        required_role=Role.VIEW,
    ),
    Route(
        method="GET",
        path=_path("/plans"),
        handler="list_plans",
        summary="List frozen plans.",
        required_role=Role.VIEW,
    ),
    Route(
        method="POST",
        path=_path("/plans"),
        handler="create_plan",
        summary="Compile a drill spec into a frozen plan, through the CLI's planner.",
        # PLAN, not EXECUTE. This endpoint compiles and stores; it does not run.
        # ``mayhem run`` is one command covering compile, approve, execute, and
        # record, so its inventory entry is the same either way, but the verb
        # this endpoint performs is planning and the domain already separates
        # PLAN from EXECUTE for exactly that reason.
        required_role=Role.PLAN,
        mutating=True,
        command_path=command_path_for("run"),
        idempotent=True,
    ),
    Route(
        method="GET",
        path=_path("/plans/{plan_digest}"),
        handler="get_plan",
        summary="One frozen plan, by the digest that identifies it.",
        required_role=Role.VIEW,
    ),
    Route(
        method="GET",
        path=_path("/runs"),
        handler="list_runs",
        summary="List runs, filtered and sorted through the store's closed whitelists.",
        required_role=Role.VIEW,
    ),
    Route(
        method="GET",
        path=_path("/runs/{run_id}"),
        handler="get_run",
        summary="One run resource.",
        required_role=Role.VIEW,
    ),
    Route(
        method="GET",
        path=_path("/runs/{run_id}/timeline"),
        handler="run_timeline",
        summary="The visual timeline (gap 32), derived from stored events.",
        required_role=Role.VIEW,
    ),
    Route(
        method="GET",
        path=_path("/runs/{run_id}/explanation"),
        handler="run_explanation",
        summary="The failure explanation (gap 60), citing probe observations.",
        required_role=Role.VIEW,
    ),
    Route(
        method="GET",
        path=_path("/runs/{run_id}/evidence"),
        handler="run_evidence",
        summary="The sealed evidence reference for one run.",
        required_role=Role.EVIDENCE_ADMIN,
    ),
    Route(
        method="GET",
        path=_path("/approvals"),
        handler="list_approvals",
        summary="List approvals and the states they evaluate to.",
        required_role=Role.VIEW,
    ),
    # There is deliberately no ``POST /api/v1/approvals``. See CONTROL_ACTIONS.
    Route(
        method="GET",
        path=_path("/policy-decisions"),
        handler="list_policy_decisions",
        summary="List policy decisions and the exact inputs that produced them.",
        required_role=Role.VIEW,
    ),
    Route(
        method="GET",
        path=_path("/schedules"),
        handler="list_schedules",
        summary="List schedules.",
        required_role=Role.VIEW,
    ),
    Route(
        method="POST",
        path=_path("/runs/{run_id}/stop"),
        handler="stop_run",
        summary="Ask for one run to stop, through the same ledger the CLI writes.",
        required_role=_role_for("stop"),
        mutating=True,
        command_path=command_path_for("stop"),
        idempotent=True,
    ),
    Route(
        method="GET",
        path=_path("/parameters"),
        handler="list_parameters",
        summary="The parameter UX (gap 61), projected from the catalog schemas.",
        required_role=Role.VIEW,
    ),
    Route(
        method="GET",
        path=_path("/dashboard"),
        handler="dashboard",
        summary="Executive numbers (gap 59), each carrying its evidence link.",
        required_role=Role.VIEW,
    ),
    Route(
        method="GET",
        path=_path("/openapi.json"),
        handler="openapi",
        summary="This document, generated from the route table.",
        required_role=None,
    ),
)


# --------------------------------------------------------------------------- #
# Mutations                                                                    #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class MutationRequest:
    """What a mutation endpoint hands the port, bound to the authenticated caller.

    ``route`` names the endpoint; ``command_path`` is the single-inventory CLI
    command this call is the API face of; ``body`` is the already-parsed object.
    Nothing here re-validates what the route's validator validated — the port is
    the CLI's own code path, and a second validation layer is the drift.
    """

    route: str
    command_path: str
    principal_id: str
    environment: str
    body: Mapping[str, Any]
    params: Mapping[str, str]
    idempotency_key: str


class MutationPort(Protocol):
    """The seam a caller implements to make a mutation real.

    Absent by default. :meth:`ApiGateway.dispatch` then refuses the mutation with
    :data:`RULE_API_MUTATION_PORT_ABSENT` rather than pretending to have done it —
    a gateway that acknowledged a mutation it never performed is the one failure a
    control plane cannot recover from, because the operator's next decision rests
    on it.

    A conforming port implements one method per mutation handler name the route
    table declares (``submit_create_plan``, ``submit_stop_run``, …) *or* the
    generic :meth:`submit`. :func:`api_mutation_port_exists` is how the OpenAPI
    builder tells which, so an unimplemented mutation is a 501 rather than a
    documented endpoint that answers nothing.
    """

    def submit(self, request: MutationRequest) -> ApiEnvelope: ...


#: The per-handler port method a mutation route may declare instead of the
#: generic :meth:`MutationPort.submit`. Data so the naming rule has one spelling.
def api_mutation_port_method(handler: str) -> str:
    return f"submit_{handler}"


# --------------------------------------------------------------------------- #
# The gateway                                                                  #
# --------------------------------------------------------------------------- #

#: A handler's return shape: ``(data, warnings, evidence_refs)``. The triple is a
#: tuple rather than three return statements so the gateway has exactly one place
#: that builds an envelope, and a handler cannot forget the evidence refs it was
#: holding.
_Read = tuple[dict[str, Any], tuple[str, ...], tuple[str, ...]]

#: Path parameters, addressed by name. Always a ``dict``, never positional.
_Params = dict[str, str]

#: The :class:`~mayhem.controller.auth_service.Authentication` a public route is
#: dispatched under. Not a real credential: it carries no principal, so the
#: response ``meta`` reports ``authenticated: False`` on a public read, which is
#: the truth rather than a courtesy.
_PUBLIC = Authentication(
    method=AuthMethod.TOKEN,
    expires_at=None,
)


class ApiGateway:
    """Routing, authorisation, pagination, idempotency, and normalized errors.

    Construction is where the invariants live, because a gateway that validates
    its own route table at construction cannot be handed a route that names a
    command the CLI does not have. :meth:`__post_init__` refuses:

    * a mutation with no ``command_path``, or one naming a command absent from
      :data:`mayhem.cli.command_registry.COMMAND_SPECS`;
    * a read that claims a ``command_path`` (a false mapping is worse than none);
    * a mutating route that is not idempotent;
    * a duplicate ``(method, path)``;
    * a **read** whose required role is one of :data:`_ACTION_ROLES` — a role that
      authorises *doing* something, which behind a ``GET`` would be a mutation in
      disguise. A read behind a *segregation* role is fine and is how the evidence
      read is authorized: :data:`~mayhem.domain.identity.Role.EVIDENCE_ADMIN` says
      who may read sealed evidence, not who may change it.

    ``now`` is a required keyword and every handler takes it from the gateway, so
    a request never reads a wall clock to decide an authorisation.
    """

    def __init__(
        self,
        *,
        store: ApiStore,
        auth: AuthService,
        identity: IdentityStore,
        now: datetime,
        mutation: MutationPort | None = None,
        routes: Sequence[Route] = ROUTES,
        request_id: Callable[[], str] | None = None,
    ) -> None:
        self._store = store
        self._db = store.store
        self._auth = auth
        self._identity = identity
        self._now = now
        self._mutation = mutation
        self._routes = tuple(routes)
        self._request_id = request_id or (lambda: "")
        self._by_key = {(route.method, route.path): route for route in self._routes}
        self._by_handler = {route.handler: route for route in self._routes}
        self._post_init__()

    # -- construction-time invariants ------------------------------------------

    def _post_init__(self) -> None:
        known = {spec.name for spec in COMMAND_SPECS}
        seen: set[tuple[str, str]] = set()
        for route in self._routes:
            key = (route.method, route.path)
            if key in seen:
                msg = (
                    f"route {route.method} {route.path} is declared twice: two handlers for "
                    "one method and path means the table cannot say which one runs"
                )
                raise ApiRefusedError(RULE_API_ROUTE_UNKNOWN, msg, status=500)
            seen.add(key)
            if route.mutating:
                if not route.command_path:
                    msg = (
                        f"mutating route {route.method} {route.path} names no CLI command; "
                        "the plan's premise is that every API mutation maps to a command "
                        "path with identical validation"
                    )
                    raise ApiRefusedError(RULE_API_COMMAND_UNKNOWN, msg, status=500)
                if route.command_path not in known:
                    msg = (
                        f"mutating route {route.method} {route.path} maps to command "
                        f"{route.command_path!r}, which is not in the single inventory "
                        f"({sorted(known)})"
                    )
                    raise ApiRefusedError(RULE_API_COMMAND_UNKNOWN, msg, status=500)
                if not route.idempotent:
                    msg = (
                        f"mutating route {route.method} {route.path} is not idempotent; a "
                        "retryable write with no idempotency key is a double write"
                    )
                    raise ApiRefusedError(RULE_API_IDEMPOTENCY_REQUIRED, msg, status=500)
            elif route.command_path:
                msg = (
                    f"read route {route.method} {route.path} claims the CLI command "
                    f"{route.command_path!r}: a read has no CLI counterpart to stay "
                    "consistent with, and claiming one is a mapping nothing can check"
                )
                raise ApiRefusedError(RULE_API_ROUTE_NOT_MUTATING, msg, status=500)
            if not route.mutating and route.required_role in _ACTION_ROLES:
                msg = (
                    f"read route {route.method} {route.path} requires "
                    f"{route.required_role.value!r}; that role authorises an action, so a "
                    "read behind it is a mutation in disguise and must be declared as one"
                )
                raise ApiRefusedError(RULE_API_ROUTE_NOT_MUTATING, msg, status=500)

    # -- accessors -------------------------------------------------------------

    @property
    def routes(self) -> tuple[Route, ...]:
        return self._routes

    @property
    def store(self) -> ApiStore:
        return self._store

    def route_for(self, handler: str) -> Route:
        """The route bound to *handler*, or a typed refusal naming the ones there are."""
        try:
            return self._by_handler[handler]
        except KeyError as exc:
            raise ApiRefusedError(
                RULE_API_ROUTE_UNKNOWN,
                f"no route declares handler {handler!r}",
                status=500,
                detail={"handlers": sorted(self._by_handler)},
            ) from exc

    def mutation_handlers(self) -> frozenset[str]:
        """Which mutation handlers the bound port actually implements.

        Read from the port rather than from the route table, so "this deployment
        serves ``POST /plans``" is a fact about the deployment rather than a
        promise in a table.
        """
        if self._mutation is None:
            return frozenset()
        explicit = {
            route.handler
            for route in self._routes
            if route.mutating
            and callable(getattr(self._mutation, api_mutation_port_method(route.handler), None))
        }
        if callable(getattr(self._mutation, "submit", None)):
            return frozenset(route.handler for route in self._routes if route.mutating)
        return frozenset(explicit)

    def route_inventory(self) -> tuple[dict[str, Any], ...]:
        """Every route as data — what ``mayhem api routes`` prints and the UI links to."""
        return tuple(
            {
                "method": route.method,
                "path": route.path,
                "summary": route.summary,
                "required_role": "" if route.required_role is None else route.required_role.value,
                "mutating": route.mutating,
                "command_path": route.command_path,
                "idempotent": route.idempotent,
                "served": (not route.mutating) or (route.handler in self.mutation_handlers()),
            }
            for route in self._routes
        )

    # -- dispatch --------------------------------------------------------------

    def dispatch(self, request: ApiRequest) -> ApiResponse:
        """Answer one request.

        The order below is the contract and is not rearranged for convenience:
        resolve, authenticate, authorize, then parse. Everything after
        authorization is unreachable for a principal that does not hold the
        route's role, which is the property the plan's negative control asserts.

        Resolution comes *first* and that is not a shortcut around authorization:
        the route table is published (``GET /api/v1/openapi.json`` is
        unauthenticated), so telling an unauthenticated caller "no such path"
        discloses nothing that the public reference does not already say.
        """
        request_id = self._request_id()
        try:
            route, params = self._resolve(request)
            if route.required_role is None:
                # A public route. Exactly two exist — ``/health`` and
                # ``/openapi.json`` — and both publish what this build serves, so
                # requiring a credential to read them would gate the reference a
                # client needs *before* it has one. Authenticated reads and every
                # mutation fall through to the path below unchanged.
                return self._read(
                    request, route, params, _PUBLIC, roles=frozenset(), request_id=request_id
                )
            authentication = self._authenticate(request)
            decision = self._authorize(route, authentication, request)
            if route.mutating:
                return self._mutate(
                    request, route, params, authentication, roles=decision, request_id=request_id
                )
            return self._read(
                request, route, params, authentication, roles=decision, request_id=request_id
            )
        except ApiRefusedError as exc:
            return self._refusal(exc, request_id)

    # -- steps 1 and 2: who and whether ----------------------------------------

    def _authenticate(self, request: ApiRequest) -> Authentication:
        token = request.header("authorization")
        presented = token[7:] if token.lower().startswith("bearer ") else token
        if not presented.strip():
            raise ApiRefusedError(
                "auth.session_unknown",
                "no credential was presented; this control plane serves authenticated "
                "reads and writes only",
                status=401,
                remediation="send Authorization: Bearer <session token>",
            )
        authentication = self._auth.authenticate_token(presented.strip(), now=self._now)
        if not authentication.authenticated:
            refusal = authentication.refusal
            assert refusal is not None
            raise ApiRefusedError(
                refusal.code,
                refusal.describe(),
                status=401,
                remediation=refusal.remediation,
                detail={"subject_id": authentication.subject_id},
            )
        return authentication

    def _authorize(
        self, route: Route, authentication: Authentication, request: ApiRequest
    ) -> frozenset[Role]:
        """Resolve the principal's roles through plan 09's own vocabulary.

        :meth:`~mayhem.controller.auth_service.AuthService.authorize` is the same
        call ``mayhem stop`` and
        :func:`~mayhem.controller.check_gate.dispatch_chatops` make, which is what
        stops the API from growing its own authorization model. ``authentication``
        is passed through so plan 09's *reach* check applies: a session minted for
        ``staging`` cannot read ``production`` even when the same principal holds
        a production grant.

        The environment is named by the request and is **required**. A request
        that names none is refused rather than resolved against whichever
        environment appears first in the grant table — and it is refused with
        plan 09's own ``auth.session_scope`` code, because "this credential does
        not reach that environment" is exactly the finding that code names.
        """
        principal = authentication.principal
        if principal is None:
            msg = "the credential verified but resolved to no principal"
            raise ApiRefusedError("auth.principal_unknown", msg, status=401)
        environment = request.header(ENVIRONMENT_HEADER).strip()
        if not environment:
            raise ApiRefusedError(
                "auth.session_scope",
                f"the request names no environment; send {ENVIRONMENT_HEADER} so the "
                "role check has a scope to resolve in. Resolving against a default would "
                "mean whichever environment happened to be granted first",
                status=400,
                remediation=f"send {ENVIRONMENT_HEADER}: <environment>",
            )
        decision = self._auth.authorize(
            principal=principal,
            role=route.required_role or Role.VIEW,
            scope=EnvironmentScope(environment=environment),
            authentication=authentication,
            now=self._now,
        )
        if not decision.authorized:
            required = route.required_role or Role.VIEW
            raise ApiRefusedError(
                "auth.role_missing",
                decision.describe(),
                status=403,
                remediation=f"grant {required.value} to {principal.principal_id} in "
                f"{environment}",
                detail={"roles": list(decision.evidence()["roles"])},
            )
        return decision.roles

    # -- step 3: parse --------------------------------------------------------

    def _resolve(self, request: ApiRequest) -> tuple[Route, dict[str, str]]:
        """The route and its path parameters, or a typed refusal.

        A path under the prefix with no route is :data:`RULE_API_ROUTE_UNKNOWN`
        (404); a path outside it is :data:`RULE_API_VERSION_UNSUPPORTED` (404 too,
        but naming the prefix), because "there is no v2" and "there is no such
        thing" are different answers and a client retrying against a version that
        does not exist should be told so.
        """
        path = request.path.split("?", 1)[0]
        if not path.startswith(API_PREFIX):
            raise ApiRefusedError(
                RULE_API_VERSION_UNSUPPORTED,
                f"{path!r} is not under {API_PREFIX}; this build serves {API_PREFIX} only, "
                "and a later version is a new prefix rather than a changed reading of this "
                "one",
                status=404,
                detail={"serves": API_PREFIX},
            )
        candidates = [route for route in self._routes if _matches(route.path, path)]
        if not candidates:
            raise ApiRefusedError(
                RULE_API_ROUTE_UNKNOWN,
                f"no route serves {path!r}",
                status=404,
                detail={"routes": [f"{route.method} {route.path}" for route in self._routes]},
            )
        by_method = [route for route in candidates if route.method == request.method.upper()]
        if not by_method:
            raise ApiRefusedError(
                RULE_API_METHOD_NOT_ALLOWED,
                f"{request.method} is not served for {path!r}; it is served as "
                f"{', '.join(sorted({route.method for route in candidates}))}",
                status=405,
                detail={"allow": sorted({route.method for route in candidates})},
            )
        if len(by_method) > 1:
            msg = f"{len(by_method)} routes serve {request.method} {path!r}"
            raise ApiRefusedError(RULE_API_ROUTE_UNKNOWN, msg, status=500)
        route = by_method[0]
        return route, _params(route.path, path)

    def _page(self, query: Mapping[str, str]) -> tuple[int, int]:
        """``(limit, offset)`` from the query string, or a typed refusal.

        Both are closed integers with a declared maximum, and both are parsed
        here rather than in nine handlers, so "a client cannot ask for the whole
        table" is a property of the gateway.
        """
        limit = _positive_int(query.get("limit"), DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, "limit")
        offset = _positive_int(query.get("offset"), 0, None, "offset", allow_zero=True)
        return limit, offset

    # -- step 4: idempotency --------------------------------------------------

    def _idempotency_key(self, request: ApiRequest, route: Route) -> str:
        from_body = str(request.json_body().get("idempotency_key", "")).strip()
        key = request.header(IDEMPOTENCY_HEADER).strip() or from_body
        if not route.idempotent:
            return key
        if not key:
            raise ApiRefusedError(
                RULE_API_IDEMPOTENCY_REQUIRED,
                f"{route.method} {route.path} is a mutation and requires an "
                f"{IDEMPOTENCY_HEADER} header; without one a retry is indistinguishable "
                "from a second request",
                status=400,
                remediation=f"send {IDEMPOTENCY_HEADER}: <opaque string>",
            )
        return key

    def _replay(self, key: str, fingerprint: str) -> dict[str, Any] | None:
        """A recorded response for *key*, or a conflict refusal.

        The fingerprint is the digest of *(method, path, body)*. A replay of the
        same key with a **different** request is
        :data:`RULE_API_IDEMPOTENCY_CONFLICT` (409) rather than the first
        response: returning a recorded result for a request that differs is how a
        client concludes its second call did something.
        """
        if not key:
            return None
        rows = self._db.query(
            "SELECT request_fingerprint, status, envelope_json FROM api_idempotency "
            "WHERE idempotency_key = ?",
            (key,),
        )
        if not rows:
            return None
        row = rows[0]
        recorded = str(row["request_fingerprint"])
        if recorded != fingerprint:
            raise ApiRefusedError(
                RULE_API_IDEMPOTENCY_CONFLICT,
                f"idempotency key {key!r} was already used for a different request "
                f"({recorded[:12]} is not {fingerprint[:12]}); issue a new key for a new "
                "request rather than reusing one",
                status=409,
                detail={"key": key},
            )
        return {
            "status": int(row["status"]),
            "envelope": json.loads(str(row["envelope_json"])),
        }

    def _record_replay(
        self, key: str, fingerprint: str, response: ApiResponse
    ) -> None:
        if not key:
            return
        with self._db.write() as conn:
            conn.execute(
                "INSERT INTO api_idempotency "
                "(idempotency_key, request_fingerprint, status, envelope_json, recorded_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(idempotency_key) DO NOTHING",
                (
                    key,
                    fingerprint,
                    response.status,
                    response.body_json(),
                    self._now.isoformat(),
                ),
            )

    # -- step 5: dispatch ------------------------------------------------------

    def _read(
        self,
        request: ApiRequest,
        route: Route,
        params: _Params,
        authentication: Authentication,
        *,
        roles: frozenset[Role],
        request_id: str,
    ) -> ApiResponse:
        handler = getattr(self, f"_read_{route.handler}", None)
        if handler is None:
            raise ApiRefusedError(
                RULE_API_ROUTE_UNKNOWN,
                f"route {route.method} {route.path} names handler {route.handler!r}, which "
                "this gateway does not implement",
                status=500,
            )
        data, warnings, evidence_refs = handler(route, params, request)
        return ApiResponse(
            status=200,
            envelope=ApiEnvelope.ok(
                data,
                warnings=warnings,
                evidence_refs=evidence_refs,
                meta={
                    "request_id": request_id,
                    "route": f"{route.method} {route.path}",
                    "schema_version": API_SCHEMA_VERSION,
                    "principal": authentication.subject_id,
                    "roles": sorted(role.value for role in roles),
                    "authenticated": authentication.authenticated,
                },
            ),
            request_id=request_id,
        )

    def _mutate(
        self,
        request: ApiRequest,
        route: Route,
        params: _Params,
        authentication: Authentication,
        *,
        roles: frozenset[Role],
        request_id: str,
    ) -> ApiResponse:
        if self._mutation is None:
            raise ApiRefusedError(
                RULE_API_MUTATION_PORT_ABSENT,
                f"{route.method} {route.path} is served as a mutation but no mutation port "
                "is bound, so this gateway cannot perform it. It refuses rather than "
                "acknowledging a write it did not make",
                status=501,
                detail={"command_path": route.command_path},
            )
        # Body parsing happens here, deliberately after authentication and
        # authorization in ``dispatch``, and before the port is touched.
        body = request.json_body()
        key = self._idempotency_key(request, route)
        fingerprint = _fingerprint(route, params, body)
        replayed = self._replay(key, fingerprint)
        if replayed is not None:
            return ApiResponse(
                status=int(replayed["status"]),
                envelope=_envelope_from(replayed["envelope"]),
                request_id=request_id,
                headers={"Idempotent-Replay": "true"},
            )
        environment = request.header(ENVIRONMENT_HEADER).strip()
        envelope = self._mutation.submit(
            MutationRequest(
                route=route.handler,
                command_path=route.command_path,
                principal_id=authentication.principal.principal_id
                if authentication.principal
                else "",
                environment=environment,
                body=body,
                params=dict(params),
                idempotency_key=key,
            )
        )
        response = ApiResponse(
            status=200,
            envelope=envelope,
            request_id=request_id,
        )
        self._record_replay(key, fingerprint, response)
        return response

    # -- read handlers ---------------------------------------------------------

    def _read_health(self, route: Route, params: _Params, request: ApiRequest) -> _Read:
        return (
            {
                "status": "ok",
                "api_prefix": API_PREFIX,
                "schema_version": API_SCHEMA_VERSION,
                "routes": len(self._routes),
                "unimplemented": list(UNIMPLEMENTED_API_SURFACES),
            },
            (),
            (),
        )

    def _read_openapi(self, route: Route, params: _Params, request: ApiRequest) -> _Read:
        return (openapi_document(self._routes), (), ())

    def _read_list_experiments(self, route: Route, params: _Params, request: ApiRequest) -> _Read:
        limit, offset = self._page(request.query)
        rows = self._store.list_experiments(
            limit=limit,
            offset=offset,
            name=request.query.get("name") or None,
            order_by=_order(request.query, "name", "experiments"),
        )
        return (_page_payload(rows, limit, offset), (), ())

    def _read_get_experiment(self, route: Route, params: _Params, request: ApiRequest) -> _Read:
        resource = self._store.load_experiment(params["name"])
        if resource is None:
            raise _not_found("experiment", params["name"])
        return ({"experiment": _rendered(resource)}, (), ())

    def _read_list_plans(self, route: Route, params: _Params, request: ApiRequest) -> _Read:
        limit, offset = self._page(request.query)
        rows = self._store.list_plans(
            limit=limit,
            offset=offset,
            order_by=_order(request.query, "created_at", "plans"),
        )
        return (_page_payload(rows, limit, offset), (), ())

    def _read_get_plan(self, route: Route, params: _Params, request: ApiRequest) -> _Read:
        resource = self._store.load_plan(params["plan_digest"])
        if resource is None:
            raise _not_found("plan", params["plan_digest"])
        return ({"plan": _rendered(resource)}, (), ())

    def _read_list_runs(self, route: Route, params: _Params, request: ApiRequest) -> _Read:
        limit, offset = self._page(request.query)
        rows = self._store.list_runs(
            RunFilters(
                status=request.query.get("status") or None,
                verdict=request.query.get("verdict") or None,
                experiment_name=request.query.get("experiment_name") or None,
                plan_digest=request.query.get("plan_digest") or None,
                started_from=request.query.get("started_from") or None,
                started_to=request.query.get("started_to") or None,
            ),
            order_by=_order(request.query, "started_at", "runs"),
            descending=(request.query.get("order", "desc") == "desc"),
            limit=limit,
            offset=offset,
        )
        return (_page_payload(rows, limit, offset), (), ())

    def _read_get_run(self, route: Route, params: _Params, request: ApiRequest) -> _Read:
        resource = self._store.load_run(params["run_id"])
        if resource is None:
            raise _not_found("run", params["run_id"])
        return ({"run": _rendered(resource)}, (), ())

    def _read_run_timeline(self, route: Route, params: _Params, request: ApiRequest) -> _Read:
        timeline = self._store.timeline(params["run_id"])
        return ({"timeline": timeline.to_dict()}, (), ())

    def _read_run_explanation(self, route: Route, params: _Params, request: ApiRequest) -> _Read:
        explanation = self._store.explain(params["run_id"])
        return (
            {"explanation": explanation.to_dict()},
            tuple(f"withheld: {entry.reason}" for entry in explanation.withheld),
            tuple(str(ref) for ref in explanation.refs()),
        )

    def _read_run_evidence(self, route: Route, params: _Params, request: ApiRequest) -> _Read:
        reference = self._store.evidence_for_run(params["run_id"])
        if reference is None:
            raise _not_found("evidence for run", params["run_id"])
        return (
            {"evidence": _rendered(reference)},
            (reference.ref_id,),
            (),
        )

    def _read_list_approvals(self, route: Route, params: _Params, request: ApiRequest) -> _Read:
        limit, offset = self._page(request.query)
        rows = self._store.list_approvals(
            plan_digest=request.query.get("plan_digest") or None,
            approver=request.query.get("approver") or None,
            order_by=_order(request.query, "approval_id", "approvals"),
        )
        return (_page_payload(_window(rows, limit, offset), limit, offset), (), ())

    def _read_list_policy_decisions(
        self, route: Route, params: _Params, request: ApiRequest
    ) -> _Read:
        limit, offset = self._page(request.query)
        rows = self._store.list_policy_decisions(
            allowed=_optional_bool(request.query, "allowed"),
            bundle_id=request.query.get("bundle_id") or None,
            order_by=_order(request.query, "decision_digest", "policy_decisions"),
        )
        return (_page_payload(_window(rows, limit, offset), limit, offset), (), ())

    def _read_list_schedules(self, route: Route, params: _Params, request: ApiRequest) -> _Read:
        limit, offset = self._page(request.query)
        rows = self._store.list_schedules(
            kind=request.query.get("kind") or None,
            timezone_name=request.query.get("timezone") or None,
            order_by=_order(request.query, "schedule_id", "schedules"),
        )
        return (_page_payload(_window(rows, limit, offset), limit, offset), (), ())

    def _read_list_parameters(self, route: Route, params: _Params, request: ApiRequest) -> _Read:
        controls = parameter_controls()
        fault_id = request.query.get("fault_id", "")
        if fault_id:
            controls = tuple(row for row in controls if row.fault_id == fault_id)
        return (
            {"parameters": [row.to_payload() for row in controls], "count": len(controls)},
            (),
            (),
        )

    def _read_dashboard(self, route: Route, params: _Params, request: ApiRequest) -> _Read:
        runs = self._store.list_runs(limit=MAX_PAGE_SIZE, offset=0)
        run_ids = [str(resource.run_id) for resource in runs]
        if not run_ids:
            # ``summarise`` refuses a summary over zero runs, on the grounds that
            # "every service passed" over no services is not a finding. This
            # handler keeps that refusal and reports it: an empty dashboard is
            # served as an empty payload with the reason in ``warnings``, which is
            # different from a dashboard showing zeros.
            return (
                {
                    "numbers": [],
                    "absent_metrics": [metric.value for metric in ExecutiveMetric],
                    "unlinked_runs": [],
                },
                ("no run is recorded, so there is nothing to summarise; every number is "
                 "absent rather than zero",),
                (),
            )
        summary = self._store.summarise(run_ids)
        payload = summary.to_dict()
        # Every number on this payload carries its evidence link *inside* the
        # Phase 1 structure, so a UI cannot render one without it. This assertion
        # is the belt: if a future Phase 1 change let a number through without
        # evidence, the gateway refuses rather than shipping it.
        unlinked = [
            number["metric"] for number in payload["numbers"] if not number.get("evidence")
        ]
        if unlinked:
            raise ApiRefusedError(
                "api.dashboard_number_without_evidence",
                f"dashboard number(s) {unlinked} would render without an evidence link; a "
                "figure nobody can trace is not one this control plane reports",
                status=500,
            )
        return (
            payload,
            tuple(
                f"run {entry['run_id']} counted nowhere: {entry['reason']}"
                for entry in payload["unlinked_runs"]
            ),
            summary.refs,
        )

    # -- refusals --------------------------------------------------------------

    def _refusal(self, exc: ApiRefusedError, request_id: str) -> ApiResponse:
        """Every refusal is one normalized error envelope, never an exception out.

        The rule id travels in the envelope's ``meta`` and in the reason, so a
        client can grep for it — the same property plan 14's preview layer claims
        when it appends a rule id to a reason.
        """
        reason = str(exc)
        if exc.rule not in reason:
            reason = f"{reason} [{exc.rule}]"
        if exc.remediation:
            reason = f"{reason} — {exc.remediation}"
        return ApiResponse(
            status=exc.status,
            envelope=ApiEnvelope.failed(
                [reason],
                meta={
                    "request_id": request_id,
                    "rule_id": exc.rule,
                    "status": exc.status,
                    **exc.detail,
                },
            ),
            request_id=request_id,
        )


# --------------------------------------------------------------------------- #
# The parameter UX (gap 61)                                                    #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ParameterControl:
    """One rendered control, projected from one :class:`ParamSpec`.

    ``kind`` is *derived* by :func:`control_for_parameter` from the schema's own
    type and bounds. There is no way to construct one with a kind the schema does
    not support, because the class is built only by that function.
    """

    fault_id: str
    name: str
    kind: ControlKind
    required: bool
    default: str | int | float | bool | None
    minimum: float | None
    maximum: float | None
    min_length: int | None
    risk: str
    required_capabilities: tuple[str, ...]
    reversible: bool
    max_duration_s: float
    step: float | None = None

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "fault_id": self.fault_id,
            "name": self.name,
            "kind": self.kind.value,
            "required": self.required,
            "default": self.default,
            "risk": self.risk,
            "required_capabilities": list(self.required_capabilities),
            "reversible": self.reversible,
            "max_duration_s": self.max_duration_s,
        }
        # Bounds are emitted only where the schema declares them. A slider with
        # ``minimum: null`` is a slider with no left edge, and a UI that reads
        # null as zero renders a bound the catalog never wrote.
        for key in ("minimum", "maximum", "min_length", "step"):
            value = getattr(self, key)
            if value is not None:
                payload[key] = value
        return payload


def control_for_parameter(definition: FaultDefinition, name: str) -> ParameterControl:
    """The control for one declared parameter, or a typed refusal naming the ones there are.

    The control kind is a total function of the schema — :func:`_control_kind` —
    so the same ``ParamSpec`` always renders the same widget, in every surface,
    forever. That is the whole of the "CLI ``--help`` and UI controls cannot
    disagree" property: there is one schema and this is its only interpretation.
    """
    spec = next((entry for entry in definition.params_schema if entry.name == name), None)
    if spec is None:
        raise ApiRefusedError(
            RULE_API_PARAMETER_UNKNOWN,
            f"fault {definition.id!r} declares no parameter {name!r}",
            status=404,
            detail={"declared": [entry.name for entry in definition.params_schema]},
        )
    kind, step = control_kind_for(spec)
    return ParameterControl(
        fault_id=definition.id,
        name=spec.name,
        kind=kind,
        required=spec.required,
        default=spec.default,
        minimum=spec.minimum,
        maximum=spec.maximum,
        min_length=spec.min_length,
        risk=definition.risk.value,
        required_capabilities=tuple(sorted(cap.value for cap in definition.required_caps)),
        reversible=definition.reversible,
        max_duration_s=definition.max_duration_s,
        step=step,
    )


def control_kind_for(spec: Any) -> tuple[ControlKind, float | None]:
    """``(kind, step)`` for one declared parameter.

    Reads ``spec.type`` — :class:`mayhem.domain.faults.ParamType` for the core
    catalog, :class:`mayhem.domain.provider.ParameterKind` for a provider's own
    grammar — because those are the two parameter declarations mayhem has and
    mapping only one of them would leave half the catalog rendering as free text.
    Both vocabularies are read by their string values, so a type added to either
    lands in :attr:`ControlKind.TEXT` and is *refused* a widget rather than
    crashing the page.

    Rules, and each is a refusal of the obvious alternative:

    * an **enum** renders as a select — the declared choices *are* the schema, and
      a free-text box would accept a value the provider's own validator rejects;
    * a **boolean** renders as a toggle, and never as a select of "true"/"false",
      because that offers a stringly-typed value the validator will reject;
    * a **numeric** parameter with both bounds and a span of at most
      :data:`SLIDER_SPAN_LIMIT` renders as a slider; a wider one renders as a
      number input, because a slider over ``0..1e9`` moves one unit per pixel and
      is unusable rather than merely coarse;
    * a **duration** renders as a *direction selector* — the low and high ends are
      the two directions an operator actually picks between ("gentle" / "severe"),
      and its bounds are seconds;
    * everything else — string, and any numeric type with no bounds — renders as
      text, and says so by carrying no bounds at all.

    The step is derived, never configured: one percent of the span, so a slider
    has a resolution that scales with what it controls instead of a magic number
    per fault that would be a second declaration.
    """
    declared = getattr(spec, "type", None) or getattr(spec, "kind", None)
    name = str(getattr(declared, "value", declared))
    if name == "enum":
        return (ControlKind.SELECT, None)
    if name == "boolean":
        return (ControlKind.BOOLEAN, None)
    if name in _NUMERIC_PARAMETER_TYPES:
        low, high = spec.minimum, spec.maximum
        if low is None or high is None:
            return (ControlKind.TEXT, None)
        span = float(high) - float(low)
        if span <= 0 or span > SLIDER_SPAN_LIMIT:
            return (ControlKind.TEXT, None)
        step = span / 100.0
        kind = (
            ControlKind.DIRECTION_SELECTOR
            if name in _DURATION_PARAMETER_TYPES
            else ControlKind.SLIDER
        )
        return (kind, step)
    return (ControlKind.TEXT, None)


#: The declared parameter types that carry a number. Union of both vocabularies:
#: ``ParamType`` spells its float ``float`` and its duration ``duration``, while
#: :class:`mayhem.domain.provider.ParameterKind` spells them ``number`` and
#: ``duration_s``.
_NUMERIC_PARAMETER_TYPES: Final[frozenset[str]] = frozenset(
    {"float", "integer", "percent", "bytes", "number", "duration", "duration_s"}
)

_DURATION_PARAMETER_TYPES: Final[frozenset[str]] = frozenset({"duration", "duration_s"})


#: A numeric span above which a slider stops being a control and becomes a
#: guessing interface. 10_000 is stated as a constant rather than inlined so the
#: test can assert the boundary from both sides.
SLIDER_SPAN_LIMIT: Final[float] = 10_000.0


def parameter_controls(fault_ids: Sequence[str] = ()) -> tuple[ParameterControl, ...]:
    """Every catalog parameter as a control, for every fault (or just *fault_ids*).

    Read from :func:`mayhem.domain.catalog.all_definitions` and nowhere else. A
    pack's declared grammar is a *different* vocabulary
    (:class:`mayhem.domain.provider.ParameterDeclaration`) with no risk rating or
    capability set attached, and this function does not attempt to invent one: a
    control whose risk annotation would have to be guessed is not a control, so
    pack parameters are not projected here.
    """
    wanted = set(fault_ids)
    rows: list[ParameterControl] = []
    for definition in all_definitions():
        if wanted and definition.id not in wanted:
            continue
        for spec in definition.params_schema:
            rows.append(control_for_parameter(definition, spec.name))
    return tuple(rows)


# --------------------------------------------------------------------------- #
# OpenAPI — generated from the route table, never hand-maintained             #
# --------------------------------------------------------------------------- #


def openapi_document(routes: Sequence[Route] = ROUTES) -> dict[str, Any]:
    """The OpenAPI 3.1 document for *routes*.

    Generated from the route table, which is why it cannot describe an endpoint
    that is not routed or omit one that is. Every handler name in a route is
    checked against the handlers this module implements, and an unimplemented one
    is refused at *document build* time rather than documented as if it worked.
    """
    paths: dict[str, Any] = {}
    for route in routes:
        if not _handler_exists(route):
            msg = (
                f"route {route.method} {route.path} names handler {route.handler!r}, which "
                "ApiGateway does not implement; the OpenAPI document would describe an "
                "endpoint that refuses every call"
            )
            raise ApiRefusedError(RULE_API_ROUTE_UNKNOWN, msg, status=500)
        operation = _operation_id(route)
        entry = paths.setdefault(_openapi_path(route.path), {})
        entry[route.method.lower()] = {
            "operationId": operation,
            "summary": route.summary,
            "tags": [route.command_path or "control-plane"],
            "parameters": _parameters_for(route.path),
            "responses": _responses_for(route),
        }
        if route.mutating:
            entry[route.method.lower()]["requestBody"] = {
                "required": True,
                "content": {"application/json": {"schema": {"type": "object"}}},
            }
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "Mayhem control plane API",
            "version": API_SCHEMA_VERSION,
            "description": (
                "Generated from the gateway's route table. Authorization, pagination, "
                "idempotency, and the response envelope are enforced by "
                "mayhem.controller.api_service.ApiGateway; this document describes them "
                "and does not implement them. Not served here: "
                + ", ".join(UNIMPLEMENTED_API_SURFACES)
                + "."
            ),
        },
        "servers": [{"url": API_PREFIX}],
        "paths": dict(sorted(paths.items())),
        "components": {
            "securitySchemes": {
                "bearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": (
                        "A plan-09 session token, exactly as issued. Authentication and "
                        "authorization are plan 09's; this gateway raises plan 09's own "
                        "refusal codes rather than a second vocabulary."
                    ),
                }
            },
            "parameters": {
                "limit": {
                    "name": "limit",
                    "in": "query",
                    "required": False,
                    "schema": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_PAGE_SIZE,
                        "default": DEFAULT_PAGE_SIZE,
                    },
                },
                "offset": {
                    "name": "offset",
                    "in": "query",
                    "required": False,
                    "schema": {"type": "integer", "minimum": 0, "default": 0},
                },
                "environment": {
                    "name": ENVIRONMENT_HEADER,
                    "in": "header",
                    "required": True,
                    "description": (
                        "The environment a role is resolved in. A request that names none "
                        "is refused rather than resolved against whichever environment "
                        "appears first in the grant table."
                    ),
                    "schema": {"type": "string"},
                },
                "idempotencyKey": {
                    "name": IDEMPOTENCY_HEADER,
                    "in": "header",
                    "required": True,
                    "schema": {"type": "string"},
                },
            },
            "schemas": {
                "Envelope": {
                    "type": "object",
                    "description": "mayhem.domain.api.ApiEnvelope; the CLI's output_v1 shape.",
                    "required": [
                        "status",
                        "schema_version",
                        "data",
                        "warnings",
                        "errors",
                        "evidence_refs",
                        "meta",
                    ],
                    "additionalProperties": False,
                    "properties": {
                        "status": {"type": "string", "enum": ["ok", "error"]},
                        "schema_version": {"type": "string", "const": API_SCHEMA_VERSION},
                        "data": {"type": "object"},
                        "warnings": {"type": "array", "items": {"type": "string"}},
                        "errors": {"type": "array", "items": {"type": "string"}},
                        "evidence_refs": {"type": "array", "items": {"type": "string"}},
                        "meta": {"type": "object"},
                    },
                },
                "Error": {
                    "description": (
                        "A normalized refusal. `meta.rule_id` is the rule that refused; "
                        "the same string appears inside `errors[0]` so it is greppable "
                        "without parsing metadata."
                    )
                },
            },
        },
        "security": [{"bearer": []}],
    }


def _handler_exists(route: Route) -> bool:
    """Whether the gateway really implements *route*'s handler.

    A read is implemented here and is checked against the real methods, so a
    route naming a handler nobody wrote fails the document build rather than
    shipping an endpoint that 404s every call. A mutation is implemented by the
    injected :class:`MutationPort`, which is per-deployment; its absence is
    already a declared response (:data:`RULE_API_MUTATION_PORT_ABSENT` → 501), so
    a mutation is documented even with no port bound — with the 501 in its
    response table, which is the honest way to say "this endpoint exists and this
    deployment does not serve it".
    """
    if route.mutating:
        return True
    return getattr(ApiGateway, f"_read_{route.handler}", None) is not None


def _operation_id(route: Route) -> str:
    tail = route.path[len(API_PREFIX) :].strip("/")
    for brace in ("{", "}"):
        tail = tail.replace(brace, "")
    tail = tail.replace("/", "_")
    return f"{route.method.lower()}_{tail or 'root'}"


def _openapi_path(path: str) -> str:
    return path


def _parameters_for(path: str) -> list[dict[str, Any]]:
    parameters: list[dict[str, Any]] = []
    for segment in path.split("/"):
        if segment.startswith("{") and segment.endswith("}"):
            name = segment[1:-1]
            parameters.append(
                {
                    "name": name,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                }
            )
    parameters.append({"$ref": "#/components/parameters/environment"})
    parameters.append({"$ref": "#/components/parameters/limit"})
    parameters.append({"$ref": "#/components/parameters/offset"})
    return parameters


def _responses_for(route: Route) -> dict[str, Any]:
    responses = {
        "200": {
            "description": "The Phase 1 envelope.",
            "content": {
                "application/json": {"schema": {"$ref": "#/components/schemas/Envelope"}}
            },
        },
        "401": {"description": "Not authenticated (plan 09 refusal code)."},
        "403": {"description": "Authenticated but the role is not held in the named scope."},
        "404": {"description": "No such resource."},
    }
    if route.mutating:
        responses["400"] = {"description": "Malformed request, or a missing idempotency key."}
        responses["409"] = {"description": "The idempotency key was used for a different request."}
        responses["501"] = {"description": "No mutation port is bound."}
    if not route.mutating:
        responses["405"] = {"description": "The path exists under another method."}
    return responses


# --------------------------------------------------------------------------- #
# The migration this module's surface depends on                                 #
#                                                                              #
# The DDL itself lives in mayhem.infra.api_gateway_schema, beside the row model #
# it creates, and is registered in mayhem.infra.migrations.ALL_MIGRATIONS as   #
# version 34. It is re-exported here (not redefined) so every existing import  #
# of ``mayhem.controller.api_service.API_GATEWAY_MIGRATION`` still resolves to  #
# the same object the chain migrates — one spelling, no second copy.            #
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# helpers                                                                      #
# --------------------------------------------------------------------------- #


def _matches(template: str, path: str) -> bool:
    template_parts = template.strip("/").split("/")
    path_parts = path.strip("/").split("/")
    if len(template_parts) != len(path_parts):
        return False
    for expected, actual in zip(template_parts, path_parts, strict=True):
        if expected.startswith("{") and expected.endswith("}"):
            if not actual:
                return False
            continue
        if expected != actual:
            return False
    return True


def _params(template: str, path: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for expected, actual in zip(
        template.strip("/").split("/"), path.strip("/").split("/"), strict=False
    ):
        if expected.startswith("{") and expected.endswith("}"):
            out[expected[1:-1]] = actual
    return out


def _fingerprint(route: Route, params: Mapping[str, str], body: Mapping[str, Any]) -> str:
    return digest(
        json.dumps(
            {"route": f"{route.method} {route.path}", "params": dict(params), "body": dict(body)},
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def _envelope_from(payload: Mapping[str, Any]) -> ApiEnvelope:
    return ApiEnvelope.model_validate(dict(payload))


def _not_found(kind: str, identifier: str) -> ApiRefusedError:
    return ApiRefusedError(
        "api.resource_not_found",
        f"no {kind} {identifier!r} is recorded in the control plane",
        status=404,
        remediation="list the collection to see what is recorded",
    )


def _positive_int(
    raw: str | None,
    default: int,
    maximum: int | None,
    name: str,
    *,
    allow_zero: bool = False,
) -> int:
    if raw is None or not str(raw).strip():
        return default
    try:
        value = int(str(raw))
    except ValueError as exc:
        raise ApiRefusedError(
            RULE_API_MALFORMED_REQUEST,
            f"{name}={raw!r} is not an integer",
            status=400,
            remediation=f"{name} must be an integer",
        ) from exc
    if value < 0 or (value == 0 and not allow_zero):
        raise ApiRefusedError(
            RULE_API_MALFORMED_REQUEST,
            f"{name}={value} is not a positive integer",
            status=400,
            remediation=f"{name} must be at least {0 if allow_zero else 1}",
        )
    if maximum is not None and value > maximum:
        raise ApiRefusedError(
            RULE_API_MALFORMED_REQUEST,
            f"{name}={value} is above the maximum {maximum} this gateway serves",
            status=400,
            remediation=f"ask for at most {maximum} per page",
        )
    return value


def _rendered(resource: Any) -> dict[str, Any]:
    """A resource as a client reads it: ``to_dict()`` where it has one.

    Phase 1 draws the distinction deliberately — ``to_payload()`` is the
    reconstructible wire form and ``to_dict()`` is the *rendering*, which adds the
    denormalised read fields a list endpoint filters and a dashboard displays. A
    read serves the rendering; a write accepts the payload. Serving the payload
    from a read would drop exactly the columns the query index exists to index,
    and serving the rendering from a write would create a second place to state a
    fact the source already states.
    """
    renderer = getattr(resource, "to_dict", None)
    return dict(renderer()) if callable(renderer) else dict(resource.to_payload())


def _window(rows: Any, limit: int, offset: int) -> tuple[Any, ...]:
    """Apply the page window to a collection the store listed unpaged.

    Three of Phase 2's ``list_*`` methods take no ``limit``/``offset`` (their
    tables are small and their filter sets closed), so the gateway's declared
    pagination has to be applied here for those to honour it. That is a real
    limitation and it is why ``total`` for those endpoints is the *listed* length
    rather than a table count: the honest number is the one this gateway actually
    read, and a client told 812 when 812 were never counted has been told a
    number nobody produced.
    """
    items = list(rows)
    return tuple(items[offset : offset + limit])


def _order(query: Mapping[str, str], default: str, table: str) -> str:
    """The requested sort key, handed to the store's own closed whitelist.

    Nothing is validated here: :func:`mayhem.infra.api_store._require_sorted_key`
    raises a typed refusal naming the keys that exist, which is a better error
    than a second list of sort keys maintained next to the store's.
    """
    del table
    requested = query.get("order_by", "").strip()
    return requested or default


def _optional_bool(query: Mapping[str, str], name: str) -> bool | None:
    raw = query.get(name, "").strip().lower()
    if not raw:
        return None
    if raw in {"true", "1", "yes"}:
        return True
    if raw in {"false", "0", "no"}:
        return False
    raise ApiRefusedError(
        RULE_API_MALFORMED_REQUEST,
        f"{name}={query[name]!r} is not a boolean",
        status=400,
        remediation=f"{name} must be true or false",
    )


def _page_payload(rows: Any, limit: int, offset: int) -> dict[str, Any]:
    """The list shape: the items, plus the count that made the window honest.

    ``total`` is the number of matching rows *before* the window. A client that
    renders "showing 50" and a client that renders "1 of 812" need different
    numbers, and conflating them is how a dashboard ends up claiming a truncated
    table is the whole table.
    """
    items = list(rows)
    return {
        "items": [_rendered(item) for item in items],
        "total": len(items) + offset if len(items) == limit else len(items),
        "limit": limit,
        "offset": offset,
        "has_more": len(items) == limit,
    }


__all__ += ["IDEMPOTENCY_HEADER", "MAX_BODY_BYTES", "SLIDER_SPAN_LIMIT"]
