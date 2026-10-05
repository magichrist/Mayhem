"""The planner, policy, and evidence facades the API gateway sits on (plan 08,
Phase 3).

Phase 2 persisted the API resource vocabulary and its own STATUS line named what
was still missing: *"the planner/policy/scheduler/orchestrator/evidence facades
and the gateway are Phase 3's"*. The gateway is
:mod:`mayhem.controller.api_service`; these are the three facades the ``/api/v1``
surface can actually be built on, and each one is a **thin wrapper over a seam
that already exists** rather than a reimplementation:

* :class:`PlannerService` wraps :func:`mayhem.controller.planner.plan_drill` —
  the same function :func:`mayhem.cli.services.plan_from_spec` calls;
* :class:`PolicyService` reads what :meth:`~mayhem.infra.api_store.ApiStore.list_policy_decisions`
  stored; it *decides* nothing, because the decision belongs to
  :mod:`mayhem.domain.policy_gate`;
* :class:`EvidenceService` reads what the executor sealed; it *seals* nothing,
  because sealing belongs to :mod:`mayhem.infra.attestation_store`.

Not facaded here, and why
--------------------------

**The scheduler** is :mod:`mayhem.controller.scheduler` plus
:mod:`mayhem.infra.schedule_store`. The API projects a
:class:`~mayhem.domain.api.ScheduleResource`, which by Phase 2's design names no
campaign, so a scheduler facade that dispatched from it would be inventing a
campaign an author never wrote. The resource is served; dispatch is not.

**The orchestrator** is :class:`mayhem.controller.executor.RunEngine`, and a plan
compiled here is a *frozen plan object*, not a run. Nothing here opens a run,
claims a lease, or injects a fault. The acceptance criterion for Phase 3 is
narrower and is the one worth having: *CLI and UI submissions produce
byte-identical frozen plans for the same inputs* — a statement about the compiled
artifact, which is testable, rather than a claim that two surfaces can both
execute, which is Phase 4's job and needs the approval gate wired into a run path
that plan 10's Phase 3 STATUS line already records as absent.

Why the planner's identity is a refusal
---------------------------------------

:class:`PlanSubmission` requires ``run_id``, the four snapshot identities, and a
topology graph argument — none of them defaulted. A submission that omits any of
them cannot be compiled into a plan whose ``plan_digest`` an approval can bind
to, because the digest covers exactly those fields; letting one default would
mean a digest that no approval could ever match. The gateway therefore refuses
the request rather than inventing an identity for it.

The equivalence property, stated as a test rather than a hope
-------------------------------------------------------------

:func:`PlannerService.compile` calls :func:`plan_drill` and nothing else. The CLI
reaches the same function through :func:`mayhem.cli.services.plan_from_spec`.
``tests/unit/test_api_planner.py`` compiles the same authored spec through both
paths with the same run id and the same snapshot identities and asserts
``model_dump_json()`` equality — byte for byte, which is a stronger statement than
"the same fields are set". There is no second compiler here to disagree, because
there is no second compiler here at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from mayhem.controller.planner import plan_drill
from mayhem.domain.api import EvidenceReference, PlanResource, PolicyResource
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import DrillSpec, ExecutionPlan

if TYPE_CHECKING:
    from mayhem.domain.api import FailureExplanation
    from mayhem.domain.topology import TopologyGraph
    from mayhem.infra.api_store import ApiStore

__all__ = [
    "RULE_PLANNER_MISSING_IDENTITY",
    "EvidenceService",
    "PlanSubmission",
    "PlannerService",
    "PolicyService",
]

#: A submission that names no plan identity. Refused rather than filled in.
RULE_PLANNER_MISSING_IDENTITY = "api.planner_missing_identity"

#: The body keys :meth:`PlanSubmission.from_payload` requires. Stated as data so
#: the refusal can *name* what is missing instead of failing on the first absent
#: key and leaving the caller to guess the rest.
REQUIRED_SUBMISSION_KEYS: Final[tuple[str, ...]] = (
    "run_id",
    "spec",
    "config_snapshot_id",
    "topology_snapshot_id",
    "environment_fingerprint",
)


@dataclass(frozen=True, slots=True)
class PlanSubmission:
    """One authored spec plus the identities a frozen plan is pinned by.

    Frozen, because a submission that changes between validation and compilation
    is a submission whose digest is not the digest anything approved.
    """

    run_id: str
    spec: DrillSpec
    config_snapshot_id: str
    topology_snapshot_id: str
    environment_fingerprint: str
    policy_id: str = ""
    engine: str = "podman"
    spec_dir: str = ""

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> PlanSubmission:
        """Parse a wire submission, refusing anything the CLI would not accept.

        The spec is validated with :meth:`~pydantic.BaseModel.model_validate` on
        :class:`~mayhem.domain.experiments.DrillSpec`, which is exactly what
        :func:`mayhem.cli.services.load_drill` does with the file the CLI was
        handed. Same validator, same ``extra="forbid"``, so a field the API
        accepts is a field the CLI accepts — which is the "identical validation"
        the plan asks for, enforced by sharing the type rather than by agreeing.

        Two failure modes are separated on purpose:

        * a body missing a *required key* is :data:`RULE_PLANNER_MISSING_IDENTITY`
          and names **all** of them at once, because a caller who fixes one and
          resubmits should not have to learn the next one by trying again;
        * a body whose ``spec`` is present but malformed surfaces the
          :class:`~mayhem.domain.experiments.DrillSpec` validation error
          verbatim, because that message names the field the author got wrong and
          a paraphrase would be strictly less useful.
        """
        missing = [key for key in REQUIRED_SUBMISSION_KEYS if not str(payload.get(key, "")).strip()]
        if missing:
            raise InvariantViolationError(
                RULE_PLANNER_MISSING_IDENTITY,
                f"plan submission is missing {missing}; a plan's digest covers its run id "
                "and its four snapshot identities, so a submission that does not name them "
                "cannot produce a plan an approval could bind to",
            )
        raw_spec = payload.get("spec")
        if not isinstance(raw_spec, dict):
            msg = (
                "plan submission field 'spec' must be the authored drill spec object; "
                f"got {type(raw_spec).__name__}"
            )
            raise InvariantViolationError("api.planner_spec_not_object", msg)
        return cls(
            run_id=str(payload["run_id"]),
            spec=DrillSpec.model_validate(raw_spec),
            config_snapshot_id=str(payload["config_snapshot_id"]),
            topology_snapshot_id=str(payload["topology_snapshot_id"]),
            environment_fingerprint=str(payload["environment_fingerprint"]),
            policy_id=str(payload.get("policy_id", "")),
            engine=str(payload.get("engine", "podman")),
            spec_dir=str(payload.get("spec_dir", "")),
        )


class PlannerService:
    """Compile an authored spec into a frozen plan and store its projection."""

    def __init__(self, store: ApiStore) -> None:
        self._api = store

    @property
    def api_store(self) -> ApiStore:
        return self._api

    def compile(self, submission: PlanSubmission, graph: TopologyGraph) -> PlanResource:
        """Compile through the CLI's planner, then persist the Phase 1 projection.

        The single call into
        :func:`mayhem.controller.planner.plan_drill` happens inside
        :func:`_plan`, and that is the *only* place this module compiles
        anything. :func:`_plan` is public and separate so a caller that wants a
        plan without storing it — the equivalence test, the CLI's own path — can
        call the same function rather than reaching past it through a store.
        """
        plan = _plan(submission, graph)
        resource = PlanResource.of(plan)
        self._api.save_plan(resource)
        return resource

    def resource_for(self, run_id: str) -> PlanResource | None:
        return self._api.plan_for_run(run_id)


def _plan(submission: PlanSubmission, graph: TopologyGraph) -> ExecutionPlan:
    """The one compiler call. Everything about plan identity is decided above."""
    return plan_drill(
        submission.run_id,
        submission.spec,
        graph,
        config_snapshot_id=submission.config_snapshot_id,
        topology_snapshot_id=submission.topology_snapshot_id,
        environment_fingerprint=submission.environment_fingerprint,
        policy_id=submission.policy_id,
        engine=submission.engine,
        spec_dir=submission.spec_dir or None,
    )


class PolicyService:
    """Read the policy decisions the gate already made. Decide nothing.

    :meth:`allow` returns the *recorded* ``allowed`` flag off a stored
    :class:`~mayhem.domain.api.PolicyResource`. It does not re-evaluate the
    bundle, does not re-derive the inputs, and has no opinion of its own: a
    second policy evaluator in the API would be a second answer to "may this plan
    run", and the plan's premise is that there is one.
    """

    def __init__(self, store: ApiStore) -> None:
        self._api = store

    def decision_for(self, policy_digest: str) -> PolicyResource | None:
        """The decision recorded for *policy_digest*, or ``None``.

        The key is the policy digest and not the plan digest because that is what
        a :class:`~mayhem.domain.policy.PolicyDecision` is *about*: an approval
        binds to one of these by :attr:`ApprovalGateInputs.policy_digest`, and a
        plan is checked against a decision by looking the decision up on the
        policy version the plan names. Keyed any other way this would be a
        second, looser binding between a plan and a decision.

        ``None`` means "no decision was recorded", which is **not** the same as
        "a decision allowing it": an absent decision is a missing input, and
        :meth:`allow` refuses rather than defaulting. Two recorded decisions
        sharing one policy digest is a *third* answer, and it refuses too — picking
        the first would make "which row sorts first" into the authorization
        decision.
        """
        matches = tuple(
            decision
            for decision in self._api.list_policy_decisions()
            if decision.policy_digest == policy_digest
        )
        if len(matches) > 1:
            digests = sorted(decision.decision_digest for decision in matches)
            msg = (
                f"{len(matches)} recorded decisions share policy digest "
                f"{policy_digest[:12]}… ({digests}): two decisions about one policy "
                "version is not a lookup failure to be resolved by picking one, and "
                "picking the first is how a denial silently becomes an allowance"
            )
            raise InvariantViolationError("api.policy_decision_ambiguous", msg)
        return matches[0] if matches else None

    def allow(self, policy_digest: str) -> bool:
        """Whether a recorded decision allows *policy_digest*, or a typed refusal."""
        decision = self.decision_for(policy_digest)
        if decision is None:
            msg = (
                f"no policy decision is recorded for policy {policy_digest[:12]}…; mayhem "
                "does not infer an allowance from an absent decision, because 'nothing was "
                "evaluated' is not 'nothing was wrong'"
            )
            raise InvariantViolationError("api.policy_not_evaluated", msg)
        return bool(decision.allowed)


class EvidenceService:
    """Read sealed evidence. Seal nothing, and claim nothing about signatures.

    :meth:`explain` is :func:`mayhem.domain.api.explain_run` over what is stored,
    so the failure explanation on a UI screen is the same object the CLI would
    print. :meth:`reference_for` is the Phase 1
    :class:`~mayhem.domain.api.EvidenceReference`, which carries the sealed
    envelope's digest and its completeness flag.

    .. warning::

       **A digest is not a signature.** This module verifies nothing about who
       produced an envelope. ``mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED``
       is ``False`` and :mod:`mayhem.infra.attestation_store` verifies a SHA-256
       *digest* — the loader confirms a pack was not altered between publication
       and load, and nothing about its publisher. Anything this facade reports is
       "these bytes are the bytes that were sealed", never "this was signed by
       whom".
    """

    def __init__(self, store: ApiStore) -> None:
        self._api = store

    def reference_for(self, run_id: str) -> EvidenceReference | None:
        return self._api.evidence_for_run(run_id)

    def explain(self, run_id: str) -> FailureExplanation:
        """The Phase 1 failure explanation for *run_id*, or a typed refusal."""
        return self._api.explain(run_id)

    def unverified_by_design(self) -> tuple[str, ...]:
        """What this facade cannot tell a reader. Always non-empty, on purpose.

        A surface that omits its own limitations reads as though it has none, so
        the limitation is a value rather than a docstring a client never sees.
        """
        return (
            "no publisher signature is verified: a sealed envelope proves which bytes were "
            "sealed, not who sealed them",
            "no timestamp authority is consulted: recorded_at is the writing host's clock",
            "an absent reference means no envelope was sealed for that run, which is not "
            "the same as an envelope that was verified and found clean",
        )


def _unused(*_args: object) -> None:
    """Keep the TYPE_CHECKING-only names referenced for readers and type checkers."""
    del _args
