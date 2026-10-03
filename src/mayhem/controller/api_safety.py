"""Safety and evidence on the API mutation path (plan 08, Phase 4).

Phase 3 built a gateway that authorizes and dispatches. This module is the half
the plan asks for in Phase 4, and it is deliberately **not** a second gate: every
decision below is delegated to the module that already owns it.

* **Execution intent** — :func:`mayhem.domain.execution_intent.require_execution_intent`.
  Not "did the request look authorized", which is the authorization check and is
  already done; *was this specific act approved*, which is a different question
  with a different answer. A principal holding ``EXECUTE`` who submits a plan
  nobody approved is refused here.
* **Policy decisions** — :class:`~mayhem.controller.api_planner.PolicyService`.
  Reads what :mod:`mayhem.controller.policy_gate` recorded; decides nothing.
* **Approvals bound to plan digests** —
  :func:`mayhem.controller.approval_gate.verify_approvals`, reached through
  :func:`authorize_mutation`. An approval is evaluated against the *plan digest the
  API is about to act on*, so an approval for one plan can never authorise another.
  :func:`bind_approval` **projects** an approval into its API resource and
  deliberately cannot **mint** one: :meth:`mayhem.domain.approval.Approval.bind` is
  the only constructor, and it derives the plan digest from a ``PASS`` safety proof.
* **Evidence on every dashboard number** — already structural in Phase 1
  (:class:`~mayhem.domain.api.ExecutiveNumber` requires ``evidence``), re-checked
  here by :func:`check_dashboard_payload` so the check lives beside the mutation
  gate rather than only inside a model validator.

Three refusals, and they are the acceptance criterion
-----------------------------------------------------

**A mutation with no bound port is refused** (Phase 3) rather than acknowledged.
**A mutation with no execution intent is refused here**, before the port is
touched. **A mutation whose approvals do not verify against this plan digest is
refused here**, and the refusal carries plan 09's own
:data:`~mayhem.controller.approval_gate.RULE_APPROVAL_REQUIRED`. There is no path
through this module in which a mutation reaches the port with an unverified
approval, because :meth:`PlannerMutationPort.submit_create_plan` calls
:func:`authorize_mutation` first and there is no second entry point.

What is deliberately **not** here
---------------------------------

**Nothing executes.** :class:`PlannerMutationPort` compiles a plan, stores it, and
refuses without an intent. ``RunEngine`` is not reached, no lease is claimed, no
fault is injected. Plan 10's Phase 3 STATUS line records that the preflight gate
has no seam in the run path at all; this module does not pretend otherwise, and a
plan compiled here is an artifact an approval can bind to — nothing more.

**No signature is verified.** :class:`~mayhem.controller.api_planner.EvidenceService`
documents it and :func:`check_dashboard_payload` does not relax it: an evidence
link in this build means "these bytes are the bytes that were sealed", never "this
was signed by whom". ``mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED``
stays ``False``.

.. warning::

   **The migration this module needs to record a mutation receipt is not
   registered.** :data:`mayhem.controller.api_service.API_GATEWAY_MIGRATION`
   (version 34) carries the idempotency table this gateway needs;
   :data:`API_SAFETY_MIGRATION` (version 35) carries the mutation receipt table,
   and neither is in :data:`mayhem.infra.migrations.ALL_MIGRATIONS` because
   ``migrations.py`` was declared read-only for this work item.
   :meth:`PlannerMutationPort.submit_create_plan` therefore writes its receipt
   **defensively**: it records when the table exists and reports ``recorded=False``
   with the reason in the response, rather than failing a legitimate compile or —
   far worse — silently recording nothing. The absence is a finding to hand to the
   migrations owner, not a gap to paper over.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, cast

from mayhem.controller.api_planner import PlannerService, PlanSubmission, PolicyService
from mayhem.controller.api_planner import (
    _plan as compile_only,
)
from mayhem.controller.approval_gate import (
    ApprovalGateInputs,
    verify_approvals,
)
from mayhem.domain.api import ApiEnvelope, ApprovalResource, PlanResource
from mayhem.domain.approval import Approval, evaluate_approvals
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.execution_intent import (
    ExecutionIntent,
    ExecutionIntentRefused,
    require_execution_intent,
)
from mayhem.domain.identity import EnvironmentScope, Principal, RoleGrant, TeamMembership
from mayhem.infra.migrator import Migration

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from mayhem.controller.api_service import MutationRequest
    from mayhem.domain.safety_proof import SafetyProof
    from mayhem.infra.api_store import ApiStore

__all__ = [
    "API_SAFETY_MIGRATION",
    "API_SAFETY_VERSION",
    "MUTATION_RECEIPTS",
    "RULE_API_APPROVAL_UNVERIFIED",
    "RULE_API_DASHBOARD_UNLINKED",
    "RULE_API_EXECUTION_INTENT_REQUIRED",
    "MutationAuthorization",
    "PlannerMutationPort",
    "authorize_mutation",
    "check_dashboard_payload",
]

#: A mutation reaching this point with no bound intent. Deliberately a *new* rule
#: id rather than a reuse of ``INTENT_REQUIRED``: the refusal this module raises
#: says the API is the surface, and a reader grepping for the domain's own code
#: should find both — the domain's in ``domain/execution_intent.py``, this one's in
#: ``controller/api_safety.py``. The *reason* string carries the domain's code, so
#: the finding is greppable either way.
RULE_API_EXECUTION_INTENT_REQUIRED = "api.execution_intent_required"

#: Approvals that do not verify against the plan digest this request names.
RULE_API_APPROVAL_UNVERIFIED = "api.approval_unverified"

#: A dashboard payload carrying a number with no evidence link. Phase 1 makes this
#: unconstructible at the model layer; this is the belt, and it exists beside the
#: mutation gate so the Phase 4 acceptance criterion ("a dashboard number without
#: an evidence link fails review") has a named check rather than a type comment.
RULE_API_DASHBOARD_UNLINKED = "api.dashboard_number_without_evidence"


@dataclass(frozen=True, slots=True)
class MutationAuthorization:
    """What the safety layer decided about one mutation, and what it cost to decide.

    ``intent`` is the domain's own
    :class:`~mayhem.domain.execution_intent.ExecutionIntent`, validated by
    :func:`~mayhem.domain.execution_intent.require_execution_intent` — not a
    boolean, so a caller cannot smuggle ``True`` past the gate the way
    :func:`~mayhem.controller.check_gate.dispatch_chatops` refuses to allow for a
    ChatOps ``validate``.
    """

    route: str
    command_path: str
    principal_id: str
    intent: ExecutionIntent
    plan_digest: str
    policy_allowed: bool
    approvals_verified: bool
    evidence_refs: tuple[str, ...] = ()


def authorize_mutation(
    request: MutationRequest,
    *,
    plan: PlanResource,
    intent: ExecutionIntent | None,
    now: datetime,
    proof: SafetyProof | None = None,
    approvals: tuple[Approval, ...] = (),
    grants: tuple[RoleGrant, ...] = (),
    memberships: tuple[TeamMembership, ...] = (),
    required_approvals: int = 0,
    policy: PolicyService | None = None,
) -> MutationAuthorization:
    """Decide whether *request* may proceed against *plan*, or refuse by name.

    The order is the acceptance criterion:

    1. **the plan's own digest** is computed, never taken from the request — so a
       client cannot name a plan it did not submit;
    2. **execution intent** through the domain's
       :func:`~mayhem.domain.execution_intent.require_execution_intent`, with
       ``allow_implicit`` left at its ``None`` default, which is itself a refusal:
       a caller who forgets to ask gets the safe answer;
    3. **the recorded policy decision**, when one exists. An *absent* decision is
       not an allowance — :meth:`~mayhem.controller.api_planner.PolicyService.allow`
       raises, and this propagates that rather than swallowing it;
    4. **the approvals**, through
       :func:`~mayhem.controller.approval_gate.verify_approvals` bound to
       ``plan.plan_digest``. With ``required_approvals == 0`` the approval gate is
       not consulted at all, which is the correct reading for a *compile*: a plan
       is not approved until it exists. A caller that wants an approval checked
       says so with ``required_approvals``.

    Raises:
        ExecutionIntentRefused: The domain's own refusal, when no valid intent
            was presented.
        InvariantViolationError: An unverified approval, an unevaluated policy,
            or a plan that does not name itself.
    """
    if plan.plan_digest == "":
        msg = "a mutation with no plan digest cannot be authorized: there is nothing to bind to"
        raise InvariantViolationError(RULE_API_APPROVAL_UNVERIFIED, msg)
    try:
        validated = require_execution_intent(
            intent,
            plan_hash=request.body.get("plan_hash", ""),
            action=request.route,
            allow_implicit=None,
            now=now.timestamp(),
        )
    except ExecutionIntentRefused as exc:
        raise InvariantViolationError(
            RULE_API_EXECUTION_INTENT_REQUIRED,
            f"{exc} [{RULE_API_EXECUTION_INTENT_REQUIRED}]; the domain's own code is "
            f"{exc.code}",
        ) from exc
    policy_allowed = True
    if policy is not None:
        digest = str(request.body.get("policy_digest", "")) or plan.policy_id
        if digest:
            policy_allowed = policy.allow(digest)
    if validated is None:  # pragma: no cover - the implicit switch is off, so this cannot be None
        msg = (
            f"{request.route} reached the authorization layer with no intent, which "
            "require_execution_intent only returns when the implicit-execution switch is on; "
            "this gateway never enables it"
        )
        raise InvariantViolationError(RULE_API_EXECUTION_INTENT_REQUIRED, msg)
    approvals_verified = True
    if required_approvals > 0 or approvals:
        approvals_verified = _verify_approvals(
            plan=plan,
            request=request,
            now=now,
            proof=proof,
            approvals=approvals,
            grants=grants,
            memberships=memberships,
            required_approvals=required_approvals,
        )
    return MutationAuthorization(
        route=request.route,
        command_path=request.command_path,
        principal_id=request.principal_id,
        intent=validated,
        plan_digest=plan.plan_digest,
        policy_allowed=policy_allowed,
        approvals_verified=approvals_verified,
    )


def _verify_approvals(
    *,
    plan: PlanResource,
    request: MutationRequest,
    now: datetime,
    proof: SafetyProof | None,
    approvals: tuple[Approval, ...],
    grants: tuple[RoleGrant, ...],
    memberships: tuple[TeamMembership, ...],
    required_approvals: int,
) -> bool:
    """Plan 09's gate, over an approval set bound to *this* plan digest.

    Returns ``True`` when the gate admits, and raises otherwise — carrying plan
    09's own refusal so the reason an operator reads is the one the CLI's
    ``mayhem run`` would produce for the same approval set.
    """
    if proof is None:
        msg = (
            f"{request.route} asked for its approvals to be verified but presented no "
            "safety proof: an authority with no safety case is an omission, and a plan "
            "nobody checked is a plan nobody may run"
        )
        raise InvariantViolationError(RULE_API_APPROVAL_UNVERIFIED, msg)
    policy_digest = str(request.body.get("policy_digest", "")) or plan.policy_id
    inputs = ApprovalGateInputs(
        now=now,
        environment=EnvironmentScope(environment=request.environment),
        executor=Principal(principal_id=request.principal_id),
        proof=proof,
        policy_digest=policy_digest,
        approvals=approvals,
        grants=grants,
        memberships=memberships,
        plan_digest=plan.plan_digest,
        required_approvals=max(required_approvals, 1),
        run_id=str(request.params.get("run_id", "")),
    )
    result = verify_approvals(plan.plan, inputs)
    if result.refusal is not None:
        raise InvariantViolationError(
            RULE_API_APPROVAL_UNVERIFIED,
            f"{result.refusal.rule_id}: {result.refusal.reason} "
            f"[{RULE_API_APPROVAL_UNVERIFIED}]",
        )
    return True


def bind_approval(
    approval: Approval,
    *,
    environment: str,
    now: datetime,
    required_approvals: int = 1,
    consumed_ids: frozenset[str] = frozenset(),
    grants: tuple[RoleGrant, ...] = (),
    memberships: tuple[TeamMembership, ...] = (),
) -> ApprovalResource:
    """Project one plan-09 :class:`Approval` into its API resource, with its state.

    This **does not mint** an approval, and that is the load-bearing decision.
    :meth:`mayhem.domain.approval.Approval.bind` is the only constructor that
    mints one, and it derives the plan digest from a ``PASS`` safety proof — so
    "the API may approve a plan" is already refused at the domain layer for every
    plan whose proof did not pass, which is every plan with no fault steps. A
    function here that took an approver's name and a plan digest and produced a
    valid approval would be a second, looser constructor for the one object plan
    09's whole separation-of-duties model rests on.

    What this does instead is the *projection* Phase 1's
    :class:`~mayhem.domain.api.ApprovalResource` was built for: evaluate the
    approval against the plan, policy, and proof digests it already carries, and
    report the state. :func:`mayhem.domain.approval.evaluate_approvals` makes the
    decision; this only feeds it and hands back the resource whose ``valid`` field
    is that state's.

    There is deliberately **no HTTP route** that calls this. Phase 3's
    :data:`~mayhem.controller.api_service.CONTROL_ACTIONS` has no ``approve`` row
    because there is no ``mayhem approve`` command in the single inventory for a
    write endpoint to map to, and an endpoint that acknowledged an approval it
    could not bind to the CLI's validation would be worse than no endpoint.
    """
    state = evaluate_approvals(
        [approval],
        plan_digest=approval.plan_digest,
        policy_digest=approval.policy_digest,
        proof_digest=approval.proof_digest,
        environment=EnvironmentScope(environment=environment),
        now=now,
        required_approvals=max(required_approvals, 1),
        grants=grants,
        memberships=memberships,
        consumed_ids=consumed_ids,
    )
    return ApprovalResource.of(approval, state)


def check_dashboard_payload(payload: dict[str, Any]) -> tuple[str, ...]:
    """The evidence links every reported number carries, or a typed refusal.

    The Phase 4 acceptance criterion — *"a dashboard number without an evidence
    link fails review"* — as an executable check. Phase 1 already makes such a
    payload unconstructible; this is the review itself, kept beside the mutation
    gate so the criterion has a name somebody can call.
    """
    unlinked = sorted(
        str(number.get("metric", "?"))
        for number in payload.get("numbers", ())
        if not number.get("evidence")
    )
    if unlinked:
        msg = (
            f"dashboard number(s) {unlinked} carry no evidence link: a figure a reader "
            "cannot trace to a sealed envelope is not one this control plane reports, and "
            f"[{RULE_API_DASHBOARD_UNLINKED}]"
        )
        raise InvariantViolationError(RULE_API_DASHBOARD_UNLINKED, msg)
    return tuple(
        str(ref)
        for number in payload.get("numbers", ())
        for ref in number.get("evidence", ())
    )


class PlannerMutationPort:
    """The concrete :class:`~mayhem.controller.api_service.MutationPort`.

    One method per mutation handler the route table declares, so the gateway's
    :meth:`~mayhem.controller.api_service.ApiGateway.mutation_handlers` reports
    what this deployment actually serves rather than what the table promises.

    The compile path is: parse the submission through
    :meth:`~mayhem.controller.api_planner.PlanSubmission.from_payload` (the same
    ``DrillSpec`` the CLI validates), compile through the CLI's planner, bind the
    result to a plan digest, then :func:`authorize_mutation` — **before** anything
    is persisted. A refused mutation has compiled nothing and stored nothing; the
    port holds the graph so the caller supplies it, and the graph is a *read* of
    the live topology that the planner needs to resolve targets at all.

    The stop path is **not** implemented here. ``POST /runs/{run_id}/stop``
    authorizes with plan 09's ``emergency_stop`` role at the gateway and then
    needs :class:`~mayhem.cli.stop_cmd`'s stop ladder, its ledger, and its
    dispatch freezer, which are a CLI surface's own machinery. Until a deployment
    binds that, the endpoint answers :data:`RULE_API_MUTATION_PORT_ABSENT` rather
    than acknowledging a stop nothing performed.
    """

    def __init__(
        self,
        *,
        api: ApiStore,
        graph: Any,
        now: datetime,
        intent: ExecutionIntent | None = None,
        approvals: tuple[Approval, ...] = (),
        grants: tuple[RoleGrant, ...] = (),
        memberships: tuple[TeamMembership, ...] = (),
        proof: SafetyProof | None = None,
        policy: PolicyService | None = None,
    ) -> None:
        self._api = api
        self._planner = PlannerService(api)
        # ``policy`` is opt-in rather than defaulted to a fresh PolicyService: a
        # PolicyService over a store with no recorded decision *refuses*, which is
        # the correct answer for a deployment that has a policy bundle and the
        # wrong answer for one that has not wired a policy surface at all. A
        # deployment that wants the check binds a PolicyService and says so.
        self._policy = policy
        self._graph = graph
        self._now = now
        self._intent = intent
        self._approvals = approvals
        self._grants = grants
        self._memberships = memberships
        self._proof = proof
    def submit(self, request: MutationRequest) -> ApiEnvelope:
        method = getattr(self, f"submit_{request.route}", None)
        if method is None:
            msg = (
                f"this mutation port does not implement {request.route!r}; the routes it "
                "does implement are create_plan"
            )
            raise InvariantViolationError("api.mutation_port_absent", msg)
        return cast("ApiEnvelope", method(request))

    def submit_create_plan(self, request: MutationRequest) -> ApiEnvelope:
        submission = PlanSubmission.from_payload(dict(request.body))
        # Compile **without persisting**, authorize, and only then store. The
        # order is load-bearing and was not the first one written:
        # ``PlannerService.compile`` persists as its last act, so compiling through
        # it first meant a *refused* mutation had already written a plan row —
        # a refusal that changed the world it refused to read. The negative
        # control ``test_the_port_compiles_and_stores_only_after_the_intent
        # _verifies`` is what caught it, and it asserts against the store, not
        # against a flag.
        plan = PlanResource.of(compile_only(submission, self._graph))
        authorization = authorize_mutation(
            request,
            plan=plan,
            intent=self._intent,
            now=self._now,
            proof=self._proof,
            approvals=self._approvals,
            grants=self._grants,
            memberships=self._memberships,
            required_approvals=len(self._approvals),
            policy=self._policy,
        )
        self._api.save_plan(plan)
        receipt = _record_receipt(self, request, authorization, now=self._now)
        return ApiEnvelope.ok(
            {"plan": plan.to_dict(), "mutation": authorization_summary(authorization, receipt)},
            evidence_refs=authorization.evidence_refs,
        )


def authorization_summary(
    authorization: MutationAuthorization, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    """What the safety layer decided, as data a client reads.

    ``intent`` is reported by its plan hash and actor, never by its whole object:
    an approval is a bearer credential in everything but name, and echoing it into
    a response body that a browser will render is how one ends up in a log.
    """
    return {
        "route": authorization.route,
        "command_path": authorization.command_path,
        "principal": authorization.principal_id,
        "plan_digest": authorization.plan_digest,
        "intent_plan_hash": authorization.intent.plan_hash,
        "intent_actor": authorization.intent.actor,
        "policy_allowed": authorization.policy_allowed,
        "approvals_verified": authorization.approvals_verified,
        "receipt": dict(receipt),
    }


#: The mutation handlers this port implements. Read by
#: :meth:`~mayhem.controller.api_service.ApiGateway.mutation_handlers`, so the
#: gateway's "which mutations does this deployment serve" answer is a fact about
#: the object rather than a declaration.
MUTATION_RECEIPTS: Final[tuple[str, ...]] = ("create_plan",)


def _record_receipt(
    port: PlannerMutationPort,
    request: MutationRequest,
    authorization: MutationAuthorization,
    *,
    now: datetime,
) -> dict[str, Any]:
    """Record the mutation, when the receipt table exists.

    Returns what happened as data, and never raises: the compile and the
    authorization have already succeeded, and failing a legitimate request
    because a migration has not been registered would be trading a visible
    absence for an invisible one. The ``recorded: False`` answer is the honest
    report, and the reason names the missing migration.
    """
    row = {
        "recorded": False,
        "reason": (
            f"the mutation-receipt table ({MUTATION_RECEIPT_TABLE}) is not present: "
            f"{API_SAFETY_MIGRATION.name} (version {API_SAFETY_VERSION}) is defined in "
            "mayhem.controller.api_safety but is not registered in "
            "mayhem.infra.migrations.ALL_MIGRATIONS, because migrations.py is "
            "read-only for this work item"
        ),
    }
    try:
        with port._api.store.write() as conn:
            conn.execute(
                f"INSERT INTO {MUTATION_RECEIPT_TABLE} "
                "(idempotency_key, route, command_path, principal_id, plan_digest, "
                "recorded_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    request.idempotency_key,
                    request.route,
                    request.command_path,
                    request.principal_id,
                    authorization.plan_digest,
                    now.isoformat(),
                ),
            )
    except Exception as exc:  # any failure means "not recorded", and the reason says so
        row["reason"] = f"{row['reason']} (and the insert failed: {exc})"
        return row
    row["recorded"] = True
    row["reason"] = ""
    return row


#: The receipt table this module owns. Version 35, next after the gateway's 34.
MUTATION_RECEIPT_TABLE: Final[str] = "api_mutation_receipts"

API_SAFETY_VERSION: Final[int] = 35

_MIGRATION_SQL: tuple[str, ...] = (
    f"""
    CREATE TABLE {MUTATION_RECEIPT_TABLE} (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        idempotency_key TEXT NOT NULL DEFAULT '',
        route TEXT NOT NULL,
        command_path TEXT NOT NULL,
        principal_id TEXT NOT NULL,
        plan_digest TEXT NOT NULL,
        recorded_at TEXT NOT NULL
    )
    """,
    f"CREATE INDEX idx_api_mutation_receipts_route "
    f"ON {MUTATION_RECEIPT_TABLE}(route)",
)

_DOWN_SQL: tuple[str, ...] = (
    "DROP INDEX idx_api_mutation_receipts_route",
    f"DROP TABLE {MUTATION_RECEIPT_TABLE}",
)

API_SAFETY_MIGRATION = Migration(
    version=API_SAFETY_VERSION,
    name="api_safety",
    statements=_MIGRATION_SQL,
    down_statements=_DOWN_SQL,
)


if TYPE_CHECKING:
    from collections.abc import Mapping
