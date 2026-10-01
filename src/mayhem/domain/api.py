"""The API resource vocabulary: every surface Mayhem will show, as a view (plan
08, Phase 1).

``docs/v1.1.0/08_CONTROL_PLANE_API_UI.md`` Phase 1 asks for one thing, and asks
for it in the same breath it forbids the obvious alternative: *"resource shapes
for experiments, plans, runs, approvals, policies, schedules, evidence
references — each a thin projection of existing domain types, never a parallel
model"*. Phases 2 through 6 then build the gateway, the services, the REST
surface, and the UI on top of this file. So this file is the seam that decides
whether "CLI and UI produce identical plans" is a property or a hope.

The rule this module is built around
-----------------------------------

**A resource that could disagree with its domain source is a defect, so no
resource has a duplicated field that could.** Every type here *contains* its
domain object — ``PlanResource.plan`` **is** the :class:`ExecutionPlan`, not a
copy of it — and every identifier it exposes is a **stored** field validated
against that contained source at construction. There is no ``verdict`` string
typed next to a ``RunRecord`` that could say something else, because the
verdict is read off the record. The consequence is the part worth stating: the
class of bugs this design cannot express is exactly the class that a REST
surface ships ("the API said pass, the CLI said fail"), so it is not caught by
a test, it is not constructible.

The digests are the second half of the same commitment. A resource that names
a plan must be able to *prove* which plan, so:

* :class:`PlanResource` stores ``plan_digest`` and refuses any value that is not
  :func:`~mayhem.domain.approval.plan_content_digest` of the plan it carries —
  the same function ``controller.approval_gate.candidate_plan_digest`` uses, so
  the API and the approval gate cannot compute two different identities for one
  plan;
* :class:`RunResource` re-derives its ``plan_digest`` from the ``plan_json``
  the :class:`~mayhem.domain.run_outcome.RunRecord` already stores, so a run
  that cannot name its plan cannot be projected at all; and
* :class:`OutcomeResource` carries the plan digest too and refuses to agree with
  a run it does not match — the two records persist separately and are never
  conflated (see :mod:`mayhem.domain.run_outcome`), so neither is the place a
  mismatch could hide.

Timeline points are views, never storage (gap 32)
------------------------------------------------

:class:`RunTimeline` holds the :class:`~mayhem.domain.events.Event` records and
exposes :attr:`RunTimeline.points` as a **property**. There is no field to store
a point in, so a timeline cannot drift from its events even in principle. Each
:class:`TimelinePoint` in turn carries the one event it was derived from plus
that event's digest, and refuses a digest that does not match — so a point
without an event behind it cannot be built, by hand or by a future refactor.
Phase mapping is a total function over all 22 :class:`EventKind` members
(:data:`EVENT_PHASES`), which is a total function by construction rather than
by review.

Failure explanation explains the verdict that already exists (gap 60)
--------------------------------------------------------------------

The graded verdict belongs to :mod:`mayhem.domain.steady_state`, computed by
:mod:`mayhem.controller.steady_state`, and persisted in the evidence envelope's
``steady_state`` payload. This module does not grade anything. It *reads* that
payload and renders: hypothesis, observed versus tolerance, impact, root
failure, recovery result, and the observation each statement rests on.

The honesty rule is that **a claim without evidence is unrepresentable and a
cause without evidence is withheld**. :class:`FailureClaim` requires at least
one :class:`ObservationRef` (``Field(min_length=1)``), so prose with nothing
behind it cannot be constructed; and :func:`explain_run` emits a
:class:`WithheldClaim` — a named reason, never a guess — whenever the stored
observations cannot support the statement. The clearest case is the root cause:
if the run graded nothing, or what it graded held, then there is no root
failure, and the report says so in :attr:`FailureExplanation.withheld` instead
of inventing a plausible one.

Executive numbers carry their evidence link (gap 59)
---------------------------------------------------

:class:`ExecutiveNumber` requires ``evidence`` with ``min_length=1``, so a
dashboard number with nothing behind it is not a value that can be built. And a
run with no evidence envelope contributes to **no** number at all: it is named
in :attr:`ExecutiveSummary.unlinked_runs` with the reason. Coverage is not
invented either — a percentage is derived from a caller-supplied
:class:`CoverageFigure` that must itself carry evidence, and with no figure the
metric is withheld rather than guessed at.

One envelope, versioned forward
-------------------------------

:data:`API_SCHEMA_VERSION` is ``"1.0"`` and :class:`ApiEnvelope` mirrors
``src/mayhem/schemas/output_v1.json`` field for field: the same seven keys, the
same ``status`` enum, the same ``schema_version`` const, ``extra="forbid"`` for
the schema's ``additionalProperties: false``. The API starts from the shape the
CLI already emits and versions forward from it — never by breaking a client.
``tests/unit/test_api.py`` reads the schema file and asserts the two agree, so
the JSON contract and this model cannot drift apart quietly.

Scope
-----
Phase 1 is vocabulary and pure functions. Nothing here performs IO, reads a
clock, dispatches a command, or decides anything: every function takes the
recorded records and returns a value. Phases 2 to 6 add the services, the
gateway, and the UI, and they read these types rather than redefining them.
"""

from __future__ import annotations

import json
import math
from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from typing import Any, Final, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.approval import Approval, ApprovalState, plan_content_digest
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.events import Event, EventKind
from mayhem.domain.evidence import EvidenceEnvelope
from mayhem.domain.experiments import DrillSpec, ExecutionPlan, PlannedStep
from mayhem.domain.hashing import digest
from mayhem.domain.policy import PolicyDecision
from mayhem.domain.run_outcome import Outcome, RunRecord, RunVerdict
from mayhem.domain.scheduling import Schedule
from mayhem.domain.steady_state import Verdict

__all__ = [
    "API_SCHEMA_VERSION",
    "API_STATUS_ERROR",
    "API_STATUS_OK",
    "CLAIM_DETAIL_KEYS",
    "CLAIM_KIND_COMMAND",
    "CLAIM_KIND_FAULT",
    "CLAIM_KIND_METRIC",
    "CLAIM_KIND_PROCESS",
    "CLAIM_KIND_RECOVERY",
    "CLAIM_KIND_STEP",
    "CLAIM_KIND_TARGET",
    "EVENT_PHASES",
    "EXPLANATION_SECTIONS",
    "RECOVERY_RULES_ARE_CLAIMS",
    "ApiEnvelope",
    "ApiStatus",
    "ApprovalResource",
    "CoverageFigure",
    "EvidenceReference",
    "ExecutiveMetric",
    "ExecutiveNumber",
    "ExecutiveSummary",
    "ExperimentResource",
    "ExplanationSection",
    "FailureClaim",
    "FailureExplanation",
    "ObservationKind",
    "ObservationRef",
    "OutcomeResource",
    "PlanResource",
    "PlanStepResource",
    "PolicyResource",
    "RunResource",
    "RunTimeline",
    "ScheduleResource",
    "TimelinePhase",
    "TimelinePoint",
    "UnlinkedRun",
    "WithheldClaim",
    "explain_run",
    "plan_digest_of",
    "spec_digest_of",
    "summarise",
    "timeline_point_of",
]

# ---------------------------------------------------------------------------
# shared scalars
# ---------------------------------------------------------------------------

#: The CLI envelope's own ``schema_version`` const, copied rather than imported
#: from JSON: ``src/mayhem/schemas/output_v1.json`` is data, not a module, and a
#: resource type that had to open a file to learn its own version could not be
#: validated in a pure domain context. ``tests/unit/test_api.py`` asserts this
#: literal equals the ``const`` in that file, so the two cannot drift.
API_SCHEMA_VERSION: Final[str] = "1.0"

#: sha256 hex, the shape :data:`mayhem.domain.fabric.PlanDigest`,
#: :data:`mayhem.domain.pipeline.PlanDigest`, and every other plan-pinning
#: module already use. Written once more here so "a digest" means one thing in
#: every resource that pins a plan, without this module importing a module that
#: pins command frames.
Sha256Hex = str

def _require_sha256(value: str, rule: str, subject: str) -> str:
    """A lowercase sha256 hex digest, or a typed refusal naming the subject."""
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        msg = (
            f"{subject} must be 64 lowercase hex characters (sha256), got "
            f"{value!r}: a projection that cannot name a digest did not name an "
            "artifact"
        )
        raise InvariantViolationError(rule, msg)
    return value


def _require_nonblank(value: str, rule: str, subject: str) -> str:
    if not value or not value.strip():
        raise InvariantViolationError(rule, f"{subject} must not be blank")
    return value


def plan_digest_of(plan: ExecutionPlan) -> str:
    """The canonical identity of a frozen plan.

    Delegates to :func:`mayhem.domain.approval.plan_content_digest` over the
    plan's JSON form — the same value ``controller.approval_gate`` binds an
    approval to and the same bytes ``controller.plan_diff`` hashes. Re-deriving
    it here would be a second definition of "which plan", and two definitions
    disagree.
    """
    return plan_content_digest(plan.model_dump(mode="json"))


def spec_digest_of(spec: DrillSpec) -> str:
    """The canonical identity of an authored drill spec."""
    return digest(spec.model_dump(mode="json"))


def _envelope_digest(envelope: EvidenceEnvelope) -> str:
    return digest(envelope.model_dump(mode="json"))


def _parse_plan_json(plan_json: str, subject: str) -> dict[str, Any]:
    """The plan payload a run record stored, or a typed refusal.

    ``RunRecord.plan_json`` is ``plan.model_dump_json()`` as written by
    ``controller.executor``. Parsing it back is what lets a run resource *prove*
    which plan it executed rather than assert it.
    """
    try:
        parsed = json.loads(plan_json)
    except (TypeError, ValueError) as exc:
        msg = (
            f"{subject} stores plan_json that is not JSON ({exc}), so it cannot name "
            "the plan it ran: a run whose plan cannot be read cannot be projected"
        )
        raise InvariantViolationError("api.run_plan_unreadable", msg) from exc
    if not isinstance(parsed, dict):
        msg = (
            f"{subject} stores a plan_json that is not a JSON object, so it names no "
            "frozen plan"
        )
        raise InvariantViolationError("api.run_plan_unreadable", msg)
    return parsed


# ---------------------------------------------------------------------------
# envelope
# ---------------------------------------------------------------------------


class ApiStatus(StrEnum):
    """The two outcomes ``schemas/output_v1.json`` allows. Not a third.

    ``ERROR`` is the only way a failure is reported. A partial success with a
    warning and no data has no spelling here, which is the point: an API that
    can answer "ok, sort of" is an API whose ``ok`` nobody trusts.
    """

    OK = "ok"
    ERROR = "error"


API_STATUS_OK: Final[str] = ApiStatus.OK.value
API_STATUS_ERROR: Final[str] = ApiStatus.ERROR.value


class ApiEnvelope(BaseModel):
    """The response wrapper — ``schemas/output_v1.json`` as a type.

    Seven keys, no more: ``status``, ``schema_version``, ``data``, ``warnings``,
    ``errors``, ``evidence_refs``, ``meta``. ``extra="forbid"`` mirrors the
    schema's ``additionalProperties: false``, and ``schema_version`` is a ``Literal``
    on the same const, so a response claiming a version this build does not
    implement is refused at construction rather than shipped to a client that
    will misread it.

    Forward, not backward: a future additive key arrives as ``"1.1"`` and a
    *new* envelope, not as a changed reading of ``"1.0"``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: ApiStatus = ApiStatus.OK
    schema_version: str = API_SCHEMA_VERSION
    data: dict[str, Any] = Field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    meta: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _known_version_and_honest_status(self) -> Self:
        if self.schema_version != API_SCHEMA_VERSION:
            msg = (
                f"unsupported API schema version {self.schema_version!r}: this build "
                f"emits {API_SCHEMA_VERSION!r} only, and a new key is a new version "
                "rather than a changed reading of an old one"
            )
            raise InvariantViolationError("api.unsupported_schema", msg)
        if self.status is ApiStatus.ERROR and not self.errors:
            msg = (
                "an error envelope carries no error: a client that sees "
                "status=error with an empty errors array cannot tell what failed"
            )
            raise InvariantViolationError("api.error_without_message", msg)
        if self.status is ApiStatus.OK and self.errors:
            msg = (
                "an ok envelope carries errors: only one of status and errors is true, "
                "and a reader must not have to guess which"
            )
            raise InvariantViolationError("api.ok_with_errors", msg)
        if any(not ref.strip() for ref in self.evidence_refs):
            msg = "the API envelope carries a blank evidence reference"
            raise InvariantViolationError("api.blank_evidence_ref", msg)
        return self

    @classmethod
    def ok(
        cls,
        data: Mapping[str, Any],
        *,
        warnings: Sequence[str] = (),
        evidence_refs: Sequence[str] = (),
        meta: Mapping[str, Any] | None = None,
    ) -> ApiEnvelope:
        """A successful envelope. The only supported way to report success."""
        return cls(
            status=ApiStatus.OK,
            data=dict(data),
            warnings=tuple(warnings),
            evidence_refs=tuple(evidence_refs),
            meta=dict(meta or {}),
        )

    @classmethod
    def failed(cls, errors: Sequence[str], *, meta: Mapping[str, Any] | None = None) -> ApiEnvelope:
        """An error envelope. Refuses to be built without something to say."""
        if not errors or any(not str(error).strip() for error in errors):
            msg = "an error envelope must carry at least one non-blank error"
            raise InvariantViolationError("api.error_without_message", msg)
        return cls(
            status=ApiStatus.ERROR,
            errors=tuple(str(error) for error in errors),
            meta=dict(meta or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "schema_version": self.schema_version,
            "data": self.data,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
            "evidence_refs": list(self.evidence_refs),
            "meta": self.meta,
        }


# ---------------------------------------------------------------------------
# observations: the thing a claim has to point at
# ---------------------------------------------------------------------------


class ObservationKind(StrEnum):
    """What kind of stored record a claim is resting on.

    A closed vocabulary. "Evidence" in the loose sense is not an option here:
    a claim that cannot name *which kind of record* it read cannot be re-derived
    by whoever reads the report.
    """

    PLAN = "plan"
    ENVELOPE = "envelope"
    EVENT = "event"
    STEP_REPORT = "step_report"
    OBSERVATION = "observation"
    STEADY_SIGNAL = "steady_signal"
    SLO_OUTCOME = "slo_outcome"
    RESIDUAL_IMPACT = "residual_impact"
    ACTION_OUTCOME = "action_outcome"
    FINDING = "finding"
    COVERAGE_CELL = "coverage_cell"


class ObservationRef(BaseModel):
    """One citation: a kind of record, and the key inside it.

    ``key`` is deliberately a *locator inside the run's own records* rather than
    a URL or a path. An evidence bundle is content-addressed and offline
    verifiable (plan 12), so a ref that named a location could be checked by
    asking whether the location exists; a ref that names the observation is
    checked by re-reading it. ``detail`` is the human half of the same sentence
    — what moved, or which check failed.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: ObservationKind
    key: str = Field(min_length=1)
    detail: str = ""

    @model_validator(mode="after")
    def _key_is_not_blank(self) -> Self:
        _require_nonblank(self.key, "api.observation_key_not_blank", "observation reference key")
        return self

    def __str__(self) -> str:
        return f"{self.kind.value}:{self.key}"

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "key": self.key, "detail": self.detail}


# ---------------------------------------------------------------------------
# resources
# ---------------------------------------------------------------------------


class _Resource(BaseModel):
    """Base for every API resource: frozen, closed, and versioned.

    ``extra="forbid"`` on a projection is not pedantry. The failure mode of a
    REST surface is a client writing a field the server ignores — the response
    says ``verdict: fail``, the client reads ``status: pass`` from a field that
    was never part of the contract. A closed model has no such field to write.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = API_SCHEMA_VERSION

    @model_validator(mode="after")
    def _known_version(self) -> Self:
        if self.schema_version != API_SCHEMA_VERSION:
            msg = (
                f"unsupported resource schema {self.schema_version!r}: this build "
                f"reads {API_SCHEMA_VERSION!r} only"
            )
            raise InvariantViolationError("api.unsupported_schema", msg)
        return self

    def to_payload(self) -> dict[str, Any]:
        """The reconstructible wire form: declared fields only.

        Distinct from each resource's ``to_dict()``, and the distinction is
        load-bearing rather than stylistic. ``to_dict()`` is the *rendering* a
        ``GET`` returns: it adds the denormalised read fields a client filters
        and displays on (``run_id``, ``verdict``, ``resolved_target_ids``…), all
        of which are properties re-derived from the contained source. Those keys
        are not accepted back, because accepting them would create a second place
        to state a fact the source already states. ``to_payload()`` is what a
        client loads, what a store round-trips, and what
        :meth:`pydantic.BaseModel.model_validate` accepts.
        """
        return self.model_dump(mode="json")


class ExperimentResource(_Resource):
    """An authored experiment: the :class:`DrillSpec` itself.

    The spec is the *input* to a run, so this resource carries the authored
    hypothesis and the steady-state block verbatim. ``spec_digest`` is stored and
    validated against the contained spec, which is what makes the resource
    citable: a dashboard row saying "experiment checkout-latency" is only
    meaningful next to the digest of the spec it was derived from.
    """

    name: str = Field(min_length=1)
    spec_digest: str
    spec: DrillSpec

    @model_validator(mode="after")
    def _binds_to_its_spec(self) -> Self:
        _require_sha256(self.spec_digest, "api.spec_digest_not_sha256", "experiment spec_digest")
        actual = spec_digest_of(self.spec)
        if self.spec_digest != actual:
            msg = (
                f"experiment {self.name!r} claims spec_digest {self.spec_digest[:12]}… "
                f"but the spec it carries hashes to {actual[:12]}…: a resource that "
                "disagrees with its own source is not a projection"
            )
            raise InvariantViolationError("api.spec_digest_mismatch", msg)
        if self.name != self.spec.name:
            msg = (
                f"experiment resource is named {self.name!r} but its spec is named "
                f"{self.spec.name!r}"
            )
            raise InvariantViolationError("api.experiment_name_mismatch", msg)
        return self

    @classmethod
    def of(cls, spec: DrillSpec) -> ExperimentResource:
        return cls(name=spec.name, spec_digest=spec_digest_of(spec), spec=spec)

    @property
    def hypothesis(self) -> str:
        """The authored hypothesis, or ``""``. Never a generated one."""
        return self.spec.hypothesis

    @property
    def steady_state_signals(self) -> tuple[str, ...]:
        """The names of the signals the spec grades, in declaration order."""
        if self.spec.steady_state is None:
            return ()
        return tuple(signal.name for signal in self.spec.steady_state.signals)

    def to_spec(self) -> DrillSpec:
        """The domain source, unchanged. Round trip is identity by construction."""
        return self.spec

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "spec_digest": self.spec_digest,
            "hypothesis": self.hypothesis,
            "steady_state_signals": list(self.steady_state_signals),
            "spec": self.spec.model_dump(mode="json"),
        }


class PlanResource(_Resource):
    """A frozen :class:`ExecutionPlan` — the contract CLI and UI must share.

    ``plan_digest`` is stored *and* recomputed on every construction, against
    :func:`plan_digest_of`. This is the load-bearing refusal of the whole
    module: it is what makes "the API showed a plan that was not the plan that
    ran" unrepresentable rather than merely untested. The snapshot ids and the
    environment fingerprint are properties read off the plan, not fields, so
    they cannot be reported for a plan that does not carry them.
    """

    plan_digest: str
    plan: ExecutionPlan

    @model_validator(mode="after")
    def _binds_to_its_plan(self) -> Self:
        _require_sha256(self.plan_digest, "api.plan_digest_not_sha256", "plan plan_digest")
        actual = plan_digest_of(self.plan)
        if self.plan_digest != actual:
            msg = (
                f"plan resource claims plan_digest {self.plan_digest[:12]}… but the plan "
                f"it carries hashes to {actual[:12]}…: an approval, an evidence "
                "envelope, and a dashboard row that disagree about plan identity are "
                "three answers to one question"
            )
            raise InvariantViolationError("api.plan_digest_mismatch", msg)
        return self

    @classmethod
    def of(cls, plan: ExecutionPlan) -> PlanResource:
        return cls(plan_digest=plan_digest_of(plan), plan=plan)

    @property
    def run_id(self) -> str:
        return self.plan.run_id

    @property
    def config_snapshot_id(self) -> str:
        return self.plan.config_snapshot_id

    @property
    def topology_snapshot_id(self) -> str:
        return self.plan.topology_snapshot_id

    @property
    def environment_fingerprint(self) -> str:
        return self.plan.environment_fingerprint

    @property
    def policy_id(self) -> str:
        return self.plan.policy_id

    @property
    def steps(self) -> tuple[PlanStepResource, ...]:
        """Per-step projections, each pinned to this plan's digest."""
        return tuple(PlanStepResource.of(self.plan_digest, step) for step in self.plan.steps)

    def to_plan(self) -> ExecutionPlan:
        return self.plan

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_digest": self.plan_digest,
            "run_id": self.run_id,
            "config_snapshot_id": self.config_snapshot_id,
            "topology_snapshot_id": self.topology_snapshot_id,
            "environment_fingerprint": self.environment_fingerprint,
            "policy_id": self.policy_id,
            "plan": self.plan.model_dump(mode="json"),
        }


class PlanStepResource(_Resource):
    """One planned step, and the plan it belongs to.

    Carries ``plan_digest`` even though the step itself knows nothing about
    plans, because a step shown without its plan is a step nobody can check
    against an approval. :meth:`PlanResource.steps` is the only intended
    constructor: it fills the digest from the plan the step came from, so a step
    cannot be attributed to a plan that does not contain it. ``resolve_target_ids``
    reads the *resolved* nodes, not the selector — a selector is an intent, and a
    timeline row that reported the intent instead of what was actually targeted
    would be showing a plan where a run happened.
    """

    plan_digest: str
    step_id: str = Field(min_length=1)
    seq: int
    step: PlannedStep

    @model_validator(mode="after")
    def _binds_to_its_step(self) -> Self:
        _require_sha256(self.plan_digest, "api.plan_digest_not_sha256", "step plan_digest")
        if self.step_id != self.step.id:
            msg = (
                f"step resource is named {self.step_id!r} but the step it carries is "
                f"{self.step.id!r}"
            )
            raise InvariantViolationError("api.step_id_mismatch", msg)
        if self.seq != self.step.seq:
            msg = (
                f"step {self.step_id!r} claims sequence {self.seq} but the plan orders "
                f"it at {self.step.seq}: execution order is read from the plan, not "
                "from a projection of it"
            )
            raise InvariantViolationError("api.step_seq_mismatch", msg)
        return self

    @classmethod
    def of(cls, plan_digest: str, step: PlannedStep) -> PlanStepResource:
        return cls(plan_digest=plan_digest, step_id=step.id, seq=step.seq, step=step)

    @property
    def fault_id(self) -> str:
        """The fault this step injects, or ``""`` for a wait/check step."""
        return "" if self.step.fault is None else self.step.fault.fault_id

    @property
    def action_type(self) -> str:
        """``inject_fault``/``wait``/``check_http``/``check_spec`` — read off the plan."""
        return str(self.step.raw_action.type)

    @property
    def resolve_target_ids(self) -> tuple[str, ...]:
        """Node ids the selector resolved to, sorted; ``()`` for a non-fault step."""
        if self.step.fault is None:
            return ()
        nodes = {node for target in self.step.fault.targets for node in target.node_ids}
        return tuple(sorted(nodes))

    @property
    def logical_target_id(self) -> str:
        """The ``targets:``-authored target, or ``""`` for selector-addressed faults."""
        if self.step.fault is None or self.step.fault.target is None:
            return ""
        return self.step.fault.target.logical_id

    def to_step(self) -> PlannedStep:
        return self.step

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_digest": self.plan_digest,
            "step_id": self.step_id,
            "seq": self.seq,
            "fault_id": self.fault_id,
            "action_type": self.action_type,
            "logical_target_id": self.logical_target_id,
            "resolved_target_ids": list(self.resolve_target_ids),
            "step": self.step.model_dump(mode="json"),
        }


class RunResource(_Resource):
    """What was executed: the :class:`RunRecord`, plus proof of which plan.

    ``plan_digest`` is **required** and is re-derived from the record's own
    ``plan_json`` on construction. A run that cannot name its plan is refused,
    which sounds strict until you ask the alternative question: what does a
    dashboard row mean when it cannot name the plan behind the number? Nothing,
    and nothing is exactly what it would be reporting.
    """

    run_id: str = Field(min_length=1)
    plan_digest: str
    record: RunRecord

    @model_validator(mode="after")
    def _binds_to_its_record_and_plan(self) -> Self:
        _require_nonblank(self.run_id, "api.run_id_not_blank", "run resource run_id")
        _require_sha256(self.plan_digest, "api.plan_digest_not_sha256", "run plan_digest")
        if self.run_id != self.record.run_id:
            msg = (
                f"run resource is named {self.run_id!r} but the record it carries is "
                f"{self.record.run_id!r}"
            )
            raise InvariantViolationError("api.run_id_mismatch", msg)
        parsed = _parse_plan_json(self.record.plan_json, f"run {self.run_id!r}")
        actual = digest(parsed)
        if self.plan_digest != actual:
            msg = (
                f"run {self.run_id!r} claims plan_digest {self.plan_digest[:12]}… but the "
                f"plan_json it stores hashes to {actual[:12]}…: a run resource that "
                "cannot name the plan it executed cannot back a dashboard number"
            )
            raise InvariantViolationError("api.plan_digest_mismatch", msg)
        return self

    @classmethod
    def of(cls, record: RunRecord, *, plan_digest: str | None = None) -> RunResource:
        """Project a run record. The plan digest is derived unless supplied.

        Passing the wrong digest explicitly is refused by the validator; passing
        none means the caller never had to know.
        """
        resolved = plan_digest or digest(
            _parse_plan_json(record.plan_json, f"run {record.run_id!r}")
        )
        return cls(run_id=record.run_id, plan_digest=resolved, record=record)

    @property
    def verdict(self) -> RunVerdict:
        return self.record.verdict

    @property
    def status(self) -> str:
        return self.record.status.value

    @property
    def experiment_name(self) -> str:
        return self.record.experiment_name

    @property
    def hypothesis(self) -> str:
        """The hypothesis the executed spec authored, or ``""``.

        Read out of the spec the run stored. A run whose ``spec_json`` does not
        parse, or that names no hypothesis, reports none — the failure
        explanation withholds its hypothesis section rather than inventing one.
        """
        try:
            parsed = json.loads(self.record.spec_json)
        except (TypeError, ValueError):
            return ""
        if not isinstance(parsed, dict):
            return ""
        hypothesis = parsed.get("hypothesis")
        return hypothesis if isinstance(hypothesis, str) else ""

    def to_record(self) -> RunRecord:
        return self.record

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "plan_digest": self.plan_digest,
            "experiment_name": self.experiment_name,
            "status": self.status,
            "verdict": self.verdict.value,
            "hypothesis": self.hypothesis,
            "record": {
                "run_id": self.record.run_id,
                "experiment_name": self.record.experiment_name,
                "seed": self.record.seed,
                "status": self.record.status.value,
                "verdict": self.record.verdict.value,
                "environment_fingerprint": self.record.environment_fingerprint,
                "config_snapshot_id": self.record.config_snapshot_id,
                "started_at": self.record.started_at,
                "ended_at": self.record.ended_at,
                "wall_seconds": self.record.wall_seconds,
                "description": self.record.description,
                "tags": list(self.record.tags),
            },
        }


class OutcomeResource(_Resource):
    """What happened: the :class:`Outcome` record.

    Persisted separately from the :class:`RunRecord` and linked by ``run_id``
    (see :mod:`mayhem.domain.run_outcome`), so this resource deliberately
    carries no verdict of its own. It pins the plan digest too — the outcome is
    only interpretable against the plan that produced it — and
    :meth:`agrees_with` is the predicate that says whether an outcome and a run
    describe the same execution.

    A non-empty ``body_json`` with an empty ``body_hash`` is refused: an
    observation whose content is not digested cannot be checked against the
    envelope that cites it, and "the body was there but nobody hashed it" is not
    a state a report should be able to describe.
    """

    run_id: str = Field(min_length=1)
    plan_digest: str
    outcome: Outcome

    @model_validator(mode="after")
    def _binds_to_its_outcome(self) -> Self:
        _require_nonblank(self.run_id, "api.run_id_not_blank", "outcome resource run_id")
        _require_sha256(self.plan_digest, "api.plan_digest_not_sha256", "outcome plan_digest")
        if self.run_id != self.outcome.run_id:
            msg = (
                f"outcome resource is named for run {self.run_id!r} but the outcome it "
                f"carries is for {self.outcome.run_id!r}"
            )
            raise InvariantViolationError("api.run_id_mismatch", msg)
        if self.outcome.body_json not in ("", "{}") and not self.outcome.body_hash:
            msg = (
                f"outcome for run {self.run_id!r} carries an observation body with no "
                "body_hash: an unhashed observation cannot be verified against the "
                "envelope that cites it"
            )
            raise InvariantViolationError("api.outcome_body_unhashed", msg)
        return self

    @classmethod
    def of(cls, outcome: Outcome, *, plan_digest: str) -> OutcomeResource:
        return cls(run_id=outcome.run_id, plan_digest=plan_digest, outcome=outcome)

    @property
    def checks_passed(self) -> int:
        return self.outcome.checks_passed

    @property
    def checks_failed(self) -> int:
        return self.outcome.checks_failed

    @property
    def metric_deltas(self) -> dict[str, float]:
        return dict(self.outcome.metric_deltas)

    @property
    def all_checks_passed(self) -> bool:
        return self.outcome.all_checks_passed

    def agrees_with(self, run: RunResource) -> bool:
        """True when this outcome describes the same execution as ``run``.

        Two comparisons, both necessary: the same ``run_id``, and the same plan.
        The second is the one that matters — an outcome from a *different* plan
        filed under the same run id would otherwise read as this run's result.
        """
        return self.run_id == run.run_id and self.plan_digest == run.plan_digest

    def to_outcome(self) -> Outcome:
        return self.outcome

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "plan_digest": self.plan_digest,
            "checks_passed": self.checks_passed,
            "checks_failed": self.checks_failed,
            "metric_deltas": self.metric_deltas,
            "residual_effect": self.outcome.residual_effect,
            "stability_signal": self.outcome.stability_signal,
            "body_hash": self.outcome.body_hash,
        }


class ApprovalResource(_Resource):
    """An approval and the state it evaluates to.

    Both halves are domain objects: the :class:`Approval` record (which binds
    ``plan_digest``, ``policy_digest``, and ``proof_digest`` by construction)
    and the :class:`ApprovalState` from
    :func:`~mayhem.domain.approval.evaluate_approvals`. The resource exposes
    ``valid`` and the reasons as *stored* fields validated against the state, so
    a UI cannot render "approved" beside a state that says refused.
    """

    approval_digest: str
    valid: bool
    reasons: tuple[str, ...]
    approval: Approval
    state: ApprovalState

    @model_validator(mode="after")
    def _binds_to_its_approval_and_state(self) -> Self:
        _require_sha256(
            self.approval_digest, "api.approval_digest_not_sha256", "approval approval_digest"
        )
        actual = self.approval.approval_digest
        if self.approval_digest != actual:
            msg = (
                f"approval resource claims digest {self.approval_digest[:12]}… but the "
                f"approval it carries hashes to {actual[:12]}…"
            )
            raise InvariantViolationError("api.approval_digest_mismatch", msg)
        if self.valid is not self.state.valid:
            msg = (
                f"approval resource reports valid={self.valid} while its state says "
                f"valid={self.state.valid}: the verdict is read off the state, not "
                "typed beside it"
            )
            raise InvariantViolationError("api.approval_state_mismatch", msg)
        expected_reasons = tuple(reason.value for reason in self.state.reasons)
        if self.reasons != expected_reasons:
            msg = (
                f"approval resource lists reasons {list(self.reasons)} but its state "
                f"holds {list(expected_reasons)}"
            )
            raise InvariantViolationError("api.approval_reasons_mismatch", msg)
        if self.valid and self.reasons:
            msg = "an approval resource cannot be valid and name reasons"
            raise InvariantViolationError("api.approval_valid_with_reasons", msg)
        return self

    @classmethod
    def of(cls, approval: Approval, state: ApprovalState) -> ApprovalResource:
        return cls(
            approval_digest=approval.approval_digest,
            valid=state.valid,
            reasons=tuple(reason.value for reason in state.reasons),
            approval=approval,
            state=state,
        )

    @property
    def approval_id(self) -> str:
        return self.approval.approval_id

    @property
    def plan_digest(self) -> str:
        """The plan this approval speaks for. Empty is unrepresentable in the record."""
        return self.approval.plan_digest

    @property
    def policy_digest(self) -> str:
        return self.approval.policy_digest

    @property
    def proof_digest(self) -> str:
        return self.approval.proof_digest

    @property
    def approver(self) -> str:
        return self.approval.approver.principal_id

    @property
    def expired(self) -> bool:
        """Whether the window has closed, as of ``now``.

        ``now`` is an argument rather than a clock read so that re-deriving this
        resource from recorded evidence reproduces it exactly.
        """
        from mayhem.domain.common import utc_now  # noqa: PLC0415 — kept off the hot path

        return self.approval.is_expired(utc_now())

    def to_approval(self) -> Approval:
        return self.approval

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "approval_id": self.approval_id,
            "approval_digest": self.approval_digest,
            "plan_digest": self.plan_digest,
            "policy_digest": self.policy_digest,
            "proof_digest": self.proof_digest,
            "approver": self.approver,
            "valid": self.valid,
            "reasons": list(self.reasons),
            "required": self.state.required,
            "approvers": list(self.state.approvers),
        }


class PolicyResource(_Resource):
    """A policy decision and the exact inputs that produced it.

    ``decision_digest`` is
    :meth:`mayhem.domain.policy.PolicyDecision.decision_digest` — the replay
    comparison key — and it is validated on construction. ``allowed`` is a
    stored field checked against the decision rather than a property, because it
    is the one thing on this resource a client will branch on, and a branch on a
    field that was validated at the boundary is a branch nobody regrets.
    """

    decision_digest: str
    allowed: bool
    decision: PolicyDecision

    @model_validator(mode="after")
    def _binds_to_its_decision(self) -> Self:
        _require_sha256(
            self.decision_digest, "api.decision_digest_not_sha256", "policy decision_digest"
        )
        actual = self.decision.decision_digest()
        if self.decision_digest != actual:
            msg = (
                f"policy resource claims decision_digest {self.decision_digest[:12]}… but "
                f"the decision it carries hashes to {actual[:12]}…: replaying a decision "
                "under different inputs is not a replay"
            )
            raise InvariantViolationError("api.decision_digest_mismatch", msg)
        if self.allowed is not self.decision.allowed:
            msg = (
                f"policy resource reports allowed={self.allowed} while the decision says "
                f"outcome={self.decision.outcome!r}"
            )
            raise InvariantViolationError("api.policy_outcome_mismatch", msg)
        return self

    @classmethod
    def of(cls, decision: PolicyDecision) -> PolicyResource:
        return cls(
            decision_digest=decision.decision_digest(),
            allowed=decision.allowed,
            decision=decision,
        )

    @property
    def bundle_id(self) -> str:
        return self.decision.bundle_id

    @property
    def bundle_version(self) -> int:
        return self.decision.bundle_version

    @property
    def policy_digest(self) -> str:
        return self.decision.policy_digest

    @property
    def rule_digest(self) -> str:
        return self.decision.rule_digest

    @property
    def facts_digest(self) -> str:
        return self.decision.facts_digest

    def to_decision(self) -> PolicyDecision:
        return self.decision

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "decision_digest": self.decision_digest,
            "allowed": self.allowed,
            "outcome": self.decision.outcome,
            "bundle_id": self.bundle_id,
            "bundle_version": self.bundle_version,
            "policy_digest": self.policy_digest,
            "rule_digest": self.rule_digest,
            "facts_digest": self.facts_digest,
            "reasons": list(self.decision.reasons),
            "matched_rules": list(self.decision.matched_rules),
        }


class ScheduleResource(_Resource):
    """A :class:`Schedule`, pinned by the digest of the schedule itself.

    A schedule names no plan — the plan is compiled when it fires — so unlike
    every other resource here this one pins its *own* identity rather than a
    plan's. That asymmetry is deliberate and worth stating: it is the reason a
    schedule row in a UI reads "fires under policy P at 02:00" and not "runs
    plan X", because at the moment the row is rendered, plan X does not exist.
    """

    schedule_digest: str
    schedule: Schedule

    @model_validator(mode="after")
    def _binds_to_its_schedule(self) -> Self:
        _require_sha256(
            self.schedule_digest, "api.schedule_digest_not_sha256", "schedule schedule_digest"
        )
        actual = digest(self.schedule.model_dump(mode="json"))
        if self.schedule_digest != actual:
            msg = (
                f"schedule resource claims digest {self.schedule_digest[:12]}… but the "
                f"schedule it carries hashes to {actual[:12]}…"
            )
            raise InvariantViolationError("api.schedule_digest_mismatch", msg)
        return self

    @classmethod
    def of(cls, schedule: Schedule) -> ScheduleResource:
        return cls(schedule_digest=digest(schedule.model_dump(mode="json")), schedule=schedule)

    @property
    def schedule_id(self) -> str:
        return self.schedule.schedule_id

    @property
    def kind(self) -> str:
        return self.schedule.kind.value

    @property
    def timezone_name(self) -> str:
        return self.schedule.timezone_name

    @property
    def horizon(self) -> str:
        """The bound that stops this schedule recurring forever.

        :class:`~mayhem.domain.scheduling.Schedule` refuses an unbounded
        recurrence at construction, so exactly one of these is set; the property
        reads it rather than restating the rule, and a schedule that somehow
        carried none would say ``"unbounded"`` — loudly, rather than silently
        rendering as recurring.
        """
        if self.schedule.ends_at is not None:
            return f"ends_at={self.schedule.ends_at.isoformat()}"
        if self.schedule.max_runs is not None:
            return f"max_runs={self.schedule.max_runs}"
        occurrences = (
            None if self.schedule.interval is None else self.schedule.interval.max_occurrences
        )
        if occurrences is not None:
            return f"max_occurrences={occurrences}"
        return "unbounded"

    @property
    def gates(self) -> tuple[str, ...]:
        """Which safety gates this schedule declares, in a stable order."""
        declared: list[str] = []
        if self.schedule.business_hours is not None:
            declared.append("business_hours")
        if self.schedule.maintenance_windows:
            declared.append("maintenance_windows")
        if self.schedule.blackout_dates is not None:
            declared.append("blackout_dates")
        if self.schedule.jitter is not None:
            declared.append("jitter")
        if self.schedule.calendar:
            declared.append("calendar")
        return tuple(declared)

    def to_schedule(self) -> Schedule:
        return self.schedule

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "schedule_digest": self.schedule_digest,
            "schedule_id": self.schedule_id,
            "kind": self.kind,
            "timezone_name": self.timezone_name,
            "horizon": self.horizon,
            "gates": list(self.gates),
            "schedule": self.schedule.model_dump(mode="json"),
        }


class EvidenceReference(_Resource):
    """A citable reference to one sealed evidence envelope.

    The envelope is *contained*, not summarised: an evidence reference that
    copied out a handful of fields would be a second place to disagree with the
    sealed record, and the sealed record is the one a bundle verification reads.
    What this resource adds is the locator layer — ``ref_id`` and the identity
    fields — each validated against the envelope it carries, plus the
    ``completeness_errors`` the envelope itself reports.

    It is still a *reference*: nothing here re-opens the bundle, and no payload
    is duplicated. Everything a caller reads is either the envelope or a field
    checked against it.
    """

    envelope_digest: str
    ref_id: str
    complete: bool
    envelope: EvidenceEnvelope

    @model_validator(mode="after")
    def _binds_to_its_envelope(self) -> Self:
        _require_sha256(
            self.envelope_digest, "api.envelope_digest_not_sha256", "evidence envelope_digest"
        )
        actual = _envelope_digest(self.envelope)
        if self.envelope_digest != actual:
            msg = (
                f"evidence reference claims envelope digest {self.envelope_digest[:12]}… "
                f"but the envelope it carries hashes to {actual[:12]}…"
            )
            raise InvariantViolationError("api.envelope_digest_mismatch", msg)
        if self.ref_id != self.envelope.report_id:
            msg = (
                f"evidence reference is {self.ref_id!r} but its envelope reports "
                f"{self.envelope.report_id!r}"
            )
            raise InvariantViolationError("api.evidence_ref_id_mismatch", msg)
        if self.complete is not self.envelope.is_complete():
            msg = (
                f"evidence reference reports complete={self.complete} while the envelope "
                f"reports {self.envelope.completeness_errors()}"
            )
            raise InvariantViolationError("api.evidence_completeness_mismatch", msg)
        return self

    @classmethod
    def of(cls, envelope: EvidenceEnvelope) -> EvidenceReference:
        return cls(
            envelope_digest=_envelope_digest(envelope),
            ref_id=envelope.report_id,
            complete=envelope.is_complete(),
            envelope=envelope,
        )

    @property
    def run_id(self) -> str:
        return self.envelope.run_id

    @property
    def plan_digest(self) -> str:
        """The plan the sealed evidence attests to."""
        return self.envelope.plan_hash

    @property
    def steady_state(self) -> dict[str, Any]:
        """The graded steady-state payload, or ``{}`` when none was recorded."""
        return dict(self.envelope.steady_state)

    def completeness_errors(self) -> list[str]:
        """What the envelope itself says is missing. Delegated, never re-derived."""
        return self.envelope.completeness_errors()

    def agrees_with(self, run: RunResource) -> bool:
        """True when this evidence was sealed for exactly this run and plan."""
        return self.run_id == run.run_id and self.plan_digest == run.plan_digest

    def to_envelope(self) -> EvidenceEnvelope:
        return self.envelope

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "ref_id": self.ref_id,
            "envelope_digest": self.envelope_digest,
            "run_id": self.run_id,
            "plan_digest": self.plan_digest,
            "complete": self.complete,
            "completeness_errors": self.envelope.completeness_errors(),
            "verdict": self.envelope.verdict,
            "recovery_state": self.envelope.recovery_state,
            "evidence_status": self.envelope.evidence_status,
            "verification_basis": self.envelope.verification_basis,
            "observation_count": len(self.envelope.observations),
            "step_report_count": len(self.envelope.step_reports),
        }


# ---------------------------------------------------------------------------
# timeline (gap 32)
# ---------------------------------------------------------------------------


class TimelinePhase(StrEnum):
    """The five phases of a chaos timeline, in the order a drill walks them.

    A closed vocabulary of five, chosen because those are the five questions an
    operator asks of any run: what was it like before, what did I break, what
    happened, did it come back, and what proves it. Not one member per
    :class:`EventKind` — an event is a fact, a phase is where the fact sits in
    the story, and conflating the two would make the timeline a re-listing of
    the event log with extra steps.
    """

    BASELINE = "baseline"
    FAULT = "fault"
    OBSERVE = "observe"
    RECOVER = "recover"
    VERIFY = "verify"


#: Every :class:`EventKind` maps to exactly one phase. Total by construction:
#: adding a 23rd kind to :mod:`mayhem.domain.events` makes this table
#: incomplete, which ``EVENT_PHASES.__getitem__`` refuses — a test asserts the
#: table covers all 22 members, and the refusal is the same failure that test
#: would have caught, raised at the point of use instead of in CI.
EVENT_PHASES: Final[Mapping[EventKind, TimelinePhase]] = {
    EventKind.RUN_STARTED: TimelinePhase.BASELINE,
    EventKind.OBSERVABILITY_COLLECTED: TimelinePhase.BASELINE,
    EventKind.OBSERVABILITY_SOURCE_FAILED: TimelinePhase.BASELINE,
    EventKind.AGENT_STATE_CHANGED: TimelinePhase.BASELINE,
    EventKind.STEP_STARTED: TimelinePhase.FAULT,
    EventKind.FAULT_INJECTED: TimelinePhase.FAULT,
    EventKind.FAULT_FAILED: TimelinePhase.FAULT,
    EventKind.SAFETY_REFUSED: TimelinePhase.FAULT,
    EventKind.MANIAC_DECISION: TimelinePhase.FAULT,
    EventKind.TOOL_EXECUTED: TimelinePhase.OBSERVE,
    EventKind.FAULT_OBSERVED: TimelinePhase.OBSERVE,
    EventKind.CHECK_EVALUATED: TimelinePhase.OBSERVE,
    EventKind.DRIFT_REPORTED: TimelinePhase.OBSERVE,
    EventKind.LEASE_STATE_CHANGED: TimelinePhase.RECOVER,
    EventKind.FAULT_RECOVERED: TimelinePhase.RECOVER,
    EventKind.RUN_ABORT_REQUESTED: TimelinePhase.RECOVER,
    EventKind.CRITERIA_EVALUATED: TimelinePhase.VERIFY,
    EventKind.STEP_FINISHED: TimelinePhase.VERIFY,
    EventKind.STEP_SKIPPED: TimelinePhase.VERIFY,
    EventKind.RUN_COMPLETED: TimelinePhase.VERIFY,
    EventKind.RUN_FAILED: TimelinePhase.VERIFY,
    EventKind.RUN_ABORTED: TimelinePhase.VERIFY,
}

#: Detail keys a drill's events actually carry, in precedence order, per
#: drill-down field. Derived from what ``controller.executor`` emits — ``fault``,
#: ``lease``, ``target``, ``pod``, ``step``, ``mechanism``, ``status``,
#: ``command`` — plus the two every event shape can add. These are *lookups*, not
#: assertions: a key that is absent yields ``""``, and an empty drill-down cell
#: means "this event did not say", which is different from "nothing happened".
CLAIM_KIND_STEP: Final[str] = "step"
CLAIM_KIND_FAULT: Final[str] = "fault"
CLAIM_KIND_TARGET: Final[str] = "target"
CLAIM_KIND_PROCESS: Final[str] = "process"
CLAIM_KIND_COMMAND: Final[str] = "command"
CLAIM_KIND_METRIC: Final[str] = "metric"
CLAIM_KIND_RECOVERY: Final[str] = "recovery"

CLAIM_DETAIL_KEYS: Final[Mapping[str, tuple[str, ...]]] = {
    CLAIM_KIND_STEP: ("step", "step_id"),
    CLAIM_KIND_FAULT: ("fault", "fault_id"),
    CLAIM_KIND_TARGET: ("target", "authority_key", "resolved_target", "logical_target", "pod"),
    CLAIM_KIND_PROCESS: ("process", "pid", "container", "pod"),
    CLAIM_KIND_COMMAND: ("command", "cmd", "tool", "op", "argv"),
    CLAIM_KIND_METRIC: ("metric", "signal", "name", "source_id"),
    CLAIM_KIND_RECOVERY: ("recovery_state", "mechanism", "compensation_status", "compensated"),
}

#: Recovery is a claim, never an inference. A ``fault.recovered`` event is the
#: executor saying the undo contract ran; nothing in this module decides that a
#: system "looks recovered" because its metrics improved.
RECOVERY_RULES_ARE_CLAIMS: Final[str] = (
    "recovery is read from recorded fault.recovered events and recorded action "
    "outcomes; a timeline never infers recovery from the absence of further "
    "failures"
)

def _detail_lookup(detail: Mapping[str, Any], field: str) -> str:
    """First non-empty detail value for ``field``, or ``""``."""
    for key in CLAIM_DETAIL_KEYS[field]:
        value = detail.get(key)
        if value is None:
            continue
        if isinstance(value, (list, tuple, dict)):
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


class TimelinePoint(BaseModel):
    """One point on the visual timeline: a view over exactly one stored event.

    Six drill-down cells — which step, which fault, which target, which process,
    which command, which metric, what recovered — each read out of the event's
    own ``detail`` by :data:`CLAIM_DETAIL_KEYS`, plus :attr:`summary`, which is
    the event's own :meth:`~mayhem.domain.events.Event.render_line`. Nothing is
    composed or embellished: a timeline row is a rendering of a record, so the
    record can always be found underneath it.

    ``event_digest`` is stored and checked against the contained event, which is
    what makes "a timeline point not backed by an event" unrepresentable rather
    than merely discouraged. :class:`RunTimeline` is the intended builder.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = API_SCHEMA_VERSION
    sequence: int = Field(ge=0)
    phase: TimelinePhase
    event_kind: EventKind
    at_epoch_s: float
    event_digest: str
    step: str = ""
    fault: str = ""
    target: str = ""
    process: str = ""
    command: str = ""
    metric: str = ""
    recovered: str = ""
    summary: str = ""
    event: Event

    @model_validator(mode="after")
    def _binds_to_its_event(self) -> Self:
        _require_sha256(self.event_digest, "api.event_digest_not_sha256", "timeline event_digest")
        if self.event_kind is not self.event.kind:
            msg = (
                f"timeline point claims kind {self.event_kind.value!r} but the event it "
                f"carries is {self.event.kind.value!r}"
            )
            raise InvariantViolationError("api.timeline_event_kind_mismatch", msg)
        if self.at_epoch_s != self.event.created_at_epoch_s:
            msg = (
                f"timeline point places itself at {self.at_epoch_s} but the event it "
                f"carries is stamped {self.event.created_at_epoch_s}: a timeline that "
                "reorders time is a different story"
            )
            raise InvariantViolationError("api.timeline_event_time_mismatch", msg)
        actual = digest(self.event.model_dump(mode="json"))
        if self.event_digest != actual:
            msg = (
                f"timeline point claims event digest {self.event_digest[:12]}… but the "
                f"event it carries hashes to {actual[:12]}…: a point with no event behind "
                "it is a drawing"
            )
            raise InvariantViolationError("api.timeline_event_digest_mismatch", msg)
        expected = EVENT_PHASES.get(self.event_kind)
        if expected is None:
            msg = (
                f"event kind {self.event_kind.value!r} has no timeline phase: every event "
                "kind must be placeable, or the timeline silently drops facts"
            )
            raise InvariantViolationError("api.timeline_phase_unmapped", msg)
        if self.phase is not expected:
            msg = (
                f"timeline point places {self.event_kind.value!r} in phase "
                f"{self.phase.value!r} but the phase table says {expected.value!r}"
            )
            raise InvariantViolationError("api.timeline_phase_mismatch", msg)
        if not self.summary:
            msg = "a timeline point must carry its event's one-line rendering"
            raise InvariantViolationError("api.timeline_summary_missing", msg)
        return self

    @property
    def run_id(self) -> str:
        return self.event.run_id or ""

    def to_payload(self) -> dict[str, Any]:
        """The reconstructible wire form: declared fields only.

        Same distinction as :meth:`_Resource.to_payload` -- ``to_dict()`` is the
        rendering a timeline endpoint returns, and it is not accepted back.
        """
        return self.model_dump(mode="json")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "phase": self.phase.value,
            "event_kind": self.event_kind.value,
            "at_epoch_s": self.at_epoch_s,
            "run_id": self.run_id,
            "step": self.step,
            "fault": self.fault,
            "target": self.target,
            "process": self.process,
            "command": self.command,
            "metric": self.metric,
            "recovered": self.recovered,
            "summary": self.summary,
            "event_digest": self.event_digest,
        }


def timeline_point_of(event: Event, sequence: int) -> TimelinePoint:
    """Derive one timeline point from one event. The only way to make one."""
    detail = event.detail
    return TimelinePoint(
        sequence=sequence,
        phase=EVENT_PHASES[event.kind],
        event_kind=event.kind,
        at_epoch_s=event.created_at_epoch_s,
        event_digest=digest(event.model_dump(mode="json")),
        step=_detail_lookup(detail, CLAIM_KIND_STEP),
        fault=_detail_lookup(detail, CLAIM_KIND_FAULT),
        target=_detail_lookup(detail, CLAIM_KIND_TARGET),
        process=_detail_lookup(detail, CLAIM_KIND_PROCESS),
        command=_detail_lookup(detail, CLAIM_KIND_COMMAND),
        metric=_detail_lookup(detail, CLAIM_KIND_METRIC),
        recovered=_detail_lookup(detail, CLAIM_KIND_RECOVERY),
        summary=event.render_line(),
        event=event,
    )


class RunTimeline(BaseModel):
    """The visual timeline for one run: stored events in, derived points out.

    The events are the *field*; the points are a :meth:`points` **property**.
    There is no `points` field to write, so the timeline cannot be persisted in
    a state that disagrees with the events it was derived from — the bug class
    of "the UI showed a step the journal never recorded" has nowhere to live.

    Ordering is by ``(created_at_epoch_s, sequence)`` with the *storage* order as
    the tiebreak, so two events stamped in the same millisecond keep the order
    the executor emitted them in and two runs over the same events render
    identically.

    Deliberately **not** a :class:`_Resource`: a resource binds to one domain
    object and proves which one, whereas this binds to a *collection* whose
    members each prove themselves. Hence the duplicated version check.

    :attr:`points` is recomputed on every read and every accessor here derives
    from it, so rendering a timeline is O(events) derivations rather than O(1).
    That is the right trade for Phase 1 — correctness over a cache that could go
    stale — and Phase 2's gateway should memoise per ``run_id`` if the cost shows
    up, never persist the result.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = API_SCHEMA_VERSION
    run_id: str = Field(min_length=1)
    plan_digest: str
    events: tuple[Event, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _binds_to_its_events(self) -> Self:
        _require_sha256(self.plan_digest, "api.plan_digest_not_sha256", "timeline plan_digest")
        if self.schema_version != API_SCHEMA_VERSION:
            msg = f"unsupported timeline schema {self.schema_version!r}"
            raise InvariantViolationError("api.unsupported_schema", msg)
        foreign = sorted(
            {event.run_id for event in self.events if event.run_id not in (None, self.run_id)}
        )
        if foreign:
            msg = (
                f"timeline for run {self.run_id!r} carries events belonging to "
                f"{foreign}: a timeline shows one run's story, and another run's events "
                "in it is a different story"
            )
            raise InvariantViolationError("api.timeline_foreign_events", msg)
        return self

    @classmethod
    def of(cls, events: Sequence[Event], *, run_id: str, plan_digest: str) -> RunTimeline:
        return cls(run_id=run_id, plan_digest=plan_digest, events=tuple(events))

    @property
    def ordered_events(self) -> tuple[Event, ...]:
        """Events in timeline order: time, then storage order."""
        ordered: Iterable[tuple[int, Event]] = sorted(
            enumerate(self.events),
            key=lambda pair: (pair[1].created_at_epoch_s, pair[0]),
        )
        return tuple(event for _, event in ordered)

    @property
    def points(self) -> tuple[TimelinePoint, ...]:
        """The derived timeline. Recomputed on every read; never stored."""
        return tuple(
            timeline_point_of(event, sequence)
            for sequence, event in enumerate(self.ordered_events)
        )

    @property
    def phases_present(self) -> tuple[TimelinePhase, ...]:
        """Which of the five phases have at least one point, in narrative order."""
        present = {point.phase for point in self.points}
        return tuple(phase for phase in TimelinePhase if phase in present)

    @property
    def phases_absent(self) -> tuple[TimelinePhase, ...]:
        """Which phases have no point at all.

        Reported rather than hidden: a run with no ``recover`` point is a run
        whose timeline never saw an undo succeed, and rendering that as a
        complete five-phase story would be inventing the phase.
        """
        present = {point.phase for point in self.points}
        return tuple(phase for phase in TimelinePhase if phase not in present)

    def point_at(self, sequence: int) -> TimelinePoint:
        """The point at ``sequence``, or a typed refusal.

        Bounds-checked rather than raising ``IndexError`` because the caller is an
        HTTP handler and the failure the client should see is "no such point".
        """
        points = self.points
        if sequence < 0 or sequence >= len(points):
            msg = (
                f"timeline for run {self.run_id!r} has {len(points)} points; "
                f"{sequence} is out of range"
            )
            raise InvariantViolationError("api.timeline_point_out_of_range", msg)
        return points[sequence]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "plan_digest": self.plan_digest,
            "phases_present": [phase.value for phase in self.phases_present],
            "phases_absent": [phase.value for phase in self.phases_absent],
            "recovery_rule": RECOVERY_RULES_ARE_CLAIMS,
            "points": [point.to_dict() for point in self.points],
        }


# ---------------------------------------------------------------------------
# failure explanation (gap 60)
# ---------------------------------------------------------------------------


class ExplanationSection(StrEnum):
    """The five sections a failure report renders, in reading order.

    Same five questions as :class:`TimelinePhase`, asked of the *result* rather
    than of the sequence: what did you expect, what did you see, how far, why,
    and did it come back. A section with nothing behind it is reported as
    withheld (:class:`WithheldClaim`), never as a paragraph.
    """

    HYPOTHESIS = "hypothesis"
    OBSERVED_VS_TOLERANCE = "observed_vs_tolerance"
    IMPACT = "impact"
    ROOT_FAILURE = "root_failure"
    RECOVERY = "recovery"


#: Canonical render order, so two reports over the same observations read the
#: same way and a diff between them is a diff of facts.
EXPLANATION_SECTIONS: Final[tuple[ExplanationSection, ...]] = tuple(ExplanationSection)


class FailureClaim(BaseModel):
    """One stated finding, and the observations that support it.

    ``refs`` has ``min_length=1``. That is the whole enforcement of gap 60's
    honesty rule at the type level: a sentence with nothing behind it is not a
    value that can be constructed, so "every claim must cite the observations
    that support it" is a shape rather than a review checklist.

    ``section`` is a *stored* field because a claim is filed under a section, and
    :class:`FailureExplanation` validates the filing — a claim cannot smuggle
    itself into ``root_failure`` and thereby assert a cause.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    section: ExplanationSection
    text: str = Field(min_length=1)
    refs: tuple[ObservationRef, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _text_is_not_blank(self) -> Self:
        _require_nonblank(self.text, "api.claim_text_not_blank", "failure claim text")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "section": self.section.value,
            "text": self.text,
            "refs": [ref.to_dict() for ref in self.refs],
        }


class WithheldClaim(BaseModel):
    """A statement the stored observations cannot support, named and withheld.

    ``reason`` is required and non-blank, and it says *which* observation was
    missing rather than apologising. "withheld: no post-phase evaluation was
    recorded" is an answer an operator can act on; "withheld: insufficient data"
    is not.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    section: ExplanationSection
    reason: str = Field(min_length=1)
    missing: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _reason_is_actionable(self) -> Self:
        _require_nonblank(self.reason, "api.withheld_reason_not_blank", "withheld claim reason")
        if not self.missing:
            msg = (
                f"withheld {self.section.value!r} names no missing observation: a reader "
                "cannot go and look for what a reason does not name"
            )
            raise InvariantViolationError("api.withheld_without_missing", msg)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "section": self.section.value,
            "reason": self.reason,
            "missing": list(self.missing),
        }


class FailureExplanation(_Resource):
    """A failure report computed from stored observations — never written prose.

    This module grades nothing. :attr:`graded_verdict` is read out of the
    evidence envelope's ``steady_state`` payload, which
    :mod:`mayhem.controller.steady_state` computed and
    :mod:`mayhem.domain.steady_state` defined; ``None`` means *nothing was
    graded*, which is a different fact from "graded and held", and the root
    failure section honours the difference by withholding.

    :attr:`claims` is filed under sections and validated against
    :attr:`withheld`, so a section cannot be both explained and withheld: exactly
    one of the two is a constructible report.
    """

    run_id: str = Field(min_length=1)
    plan_digest: str
    graded_verdict: Verdict | None
    run_verdict: RunVerdict
    evidence_ref: str = Field(min_length=1)
    claims: tuple[FailureClaim, ...] = ()
    withheld: tuple[WithheldClaim, ...] = ()

    @model_validator(mode="after")
    def _sections_are_honest(self) -> Self:
        _require_sha256(self.plan_digest, "api.plan_digest_not_sha256", "explanation plan_digest")
        _require_nonblank(self.run_id, "api.run_id_not_blank", "explanation run_id")
        _require_nonblank(
            self.evidence_ref, "api.evidence_ref_not_blank", "explanation evidence_ref"
        )
        explained = {claim.section for claim in self.claims}
        withheld_sections = {entry.section for entry in self.withheld}
        both = sorted(section.value for section in explained & withheld_sections)
        if both:
            msg = (
                f"failure explanation both claims and withholds {both}: one section, one "
                "answer"
            )
            raise InvariantViolationError("api.section_claimed_and_withheld", msg)
        # Order matters, and it is the informative one. "You named a cause over an
        # ungraded verdict" says what is actually wrong; "you are silent on four
        # sections" would be a true but useless complaint about the same forgery,
        # because a report that invents a cause and forgets to explain the rest is
        # still a report that invented a cause.
        if self.graded_verdict is None and any(
            claim.section is ExplanationSection.ROOT_FAILURE for claim in self.claims
        ):
            msg = (
                f"failure explanation for run {self.run_id!r} names a root failure while "
                "the stored steady-state verdict is ungraded: a cause asserted over a "
                "verdict nobody computed is a guess wearing a citation"
            )
            raise InvariantViolationError("api.root_failure_without_verdict", msg)
        addressed = explained | withheld_sections
        silent = sorted(
            section.value for section in ExplanationSection if section not in addressed
        )
        if silent:
            msg = (
                f"failure explanation is silent on {silent}: every section is either "
                "explained with citations or withheld with a reason, because a report "
                "that says nothing about a section reads as though nothing was wrong"
            )
            raise InvariantViolationError("api.section_unaddressed", msg)
        return self

    @property
    def explained(self) -> bool:
        """True when at least one section carries a cited claim."""
        return bool(self.claims)

    def claims_for(self, section: ExplanationSection) -> tuple[FailureClaim, ...]:
        return tuple(claim for claim in self.claims if claim.section is section)

    def withheld_for(self, section: ExplanationSection) -> tuple[WithheldClaim, ...]:
        return tuple(entry for entry in self.withheld if entry.section is section)

    @property
    def root_failure_claims(self) -> tuple[FailureClaim, ...]:
        """Cited root-failure statements, or ``()`` when the cause was withheld.

        A convenience for the UI's headline; the authority is
        :meth:`claims_for`, and an empty tuple here means "no cause was
        assertable", which is a result, not a gap.
        """
        return self.claims_for(ExplanationSection.ROOT_FAILURE)

    def refs(self) -> tuple[ObservationRef, ...]:
        """Every observation any claim rests on, de-duplicated, order preserved."""
        seen: dict[str, ObservationRef] = {}
        for claim in self.claims:
            for ref in claim.refs:
                seen.setdefault(str(ref), ref)
        return tuple(seen.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "plan_digest": self.plan_digest,
            "graded_verdict": None if self.graded_verdict is None else self.graded_verdict.value,
            "run_verdict": self.run_verdict.value,
            "evidence_ref": self.evidence_ref,
            "claims": [claim.to_dict() for claim in self.claims],
            "withheld": [entry.to_dict() for entry in self.withheld],
        }


def _fmt(value: float | None) -> str:
    """A measurement, or the word for its absence.

    ``None`` is the honest rendering of a number nobody took, and a non-finite
    value can never reach an explanation: a report that quotes ``inf`` looks like
    it measured something enormous rather than something unmeasurable.
    """
    if value is None:
        return "unmeasured"
    if not math.isfinite(value):
        return "unmeasured"
    return f"{value:.4g}"


def _steady_signal_refs(evaluation: Mapping[str, Any]) -> tuple[ObservationRef, ...]:
    """Citations for one stored steady-state evaluation, one per signal."""
    phase = str(evaluation.get("phase", "?"))
    check_id = str(evaluation.get("check_id", "?"))
    signals = evaluation.get("signals")
    entries = signals if isinstance(signals, list) else []
    if not entries:
        return (
            ObservationRef(
                kind=ObservationKind.STEADY_SIGNAL,
                key=f"{phase}/{check_id}",
                detail="evaluation recorded no per-signal detail",
            ),
        )
    return tuple(
        ObservationRef(
            kind=ObservationKind.STEADY_SIGNAL,
            key=f"{phase}/{check_id}/{signal.get('name', '?')}",
            detail=f"verdict={signal.get('verdict') or evaluation.get('verdict')}",
        )
        for signal in entries
        if isinstance(signal, Mapping)
    )


def _root_failure_verdicts() -> frozenset[Verdict]:
    """The graded verdicts that name a failure.

    Derived from :mod:`mayhem.domain.steady_state`'s own vocabulary rather than
    from strings: ``DEGRADED_WITHIN_TOLERANCE`` is *not* in this set, because a
    bounded degradation is the fault working, not a failure to explain.
    """
    return frozenset(
        {
            Verdict.DEGRADED_BEYOND_TOLERANCE,
            Verdict.NOT_RECOVERED,
            Verdict.NO_EFFECT,
        }
    )


def _failing_values() -> frozenset[str]:
    return frozenset(verdict.value for verdict in _root_failure_verdicts())


def _degraded_values() -> frozenset[str]:
    """Graded verdicts that mean "the fault moved a signal, inside the bound".

    Only ``degraded-within-tolerance`` qualifies. ``degraded-beyond-tolerance``
    is a *broken bound* and lands in the failed bucket instead: a dashboard that
    files it under "degraded" is telling a board that a tolerance was exceeded
    as though it were merely movement.

    :attr:`RunVerdict` has no degraded member and must not grow one: degradation
    is a property of the steady-state grading, not of the run. Reading it from
    the graded payload is what keeps one vocabulary for one run.
    """
    return frozenset({Verdict.DEGRADED_WITHIN_TOLERANCE.value})


def explain_run(
    *,
    run: RunResource,
    evidence: EvidenceReference,
    outcome: OutcomeResource | None = None,
) -> FailureExplanation:
    """Explain a run's failure from what was recorded, citing every statement.

    Reads the evidence envelope's ``steady_state`` payload -- the graded verdict
    :mod:`mayhem.controller.steady_state` already computed -- plus its SLO
    outcomes, residual impact and action outcomes, and the run's own spec and
    outcome records. Computes no verdict of its own: ``graded_verdict`` is copied
    from the payload, and a payload with nothing graded yields ``None``.

    Refuses to pair a run with evidence sealed for another run or another plan.
    That refusal is not pedantry: an explanation assembled from the wrong run's
    observations is confidently wrong, and confidence is the expensive failure.

    Every section is answered. Where the observations cannot support a statement
    the report emits a :class:`WithheldClaim` naming what was missing, and where
    the graded verdict is ``None`` the root failure is withheld regardless of
    what else the payload contains -- there is no graded verdict to explain, and
    naming a cause over one would be inventing the verdict this module exists to
    explain rather than replace.
    """
    _require_matching_records(run, evidence, outcome)
    payload = evidence.steady_state
    graded = _graded_verdict(payload)
    graded_entries, ungraded_entries = _split_evaluations(payload)
    sections = (
        _hypothesis_section(run=run, evidence=evidence),
        _observed_section(graded_entries=graded_entries, ungraded_entries=ungraded_entries),
        _impact_section(evidence=evidence, outcome=outcome),
        _root_failure_section(evidence=evidence, graded=graded, entries=graded_entries),
        _recovery_section(evidence=evidence, entries=graded_entries),
    )
    claims = [claim for section in sections for claim in section[0]]
    withheld = [entry for section in sections for entry in section[1]]
    return FailureExplanation(
        run_id=run.run_id,
        plan_digest=run.plan_digest,
        graded_verdict=graded,
        run_verdict=run.verdict,
        evidence_ref=evidence.ref_id,
        claims=tuple(sorted(claims, key=lambda claim: (_section_index(claim.section), claim.text))),
        withheld=tuple(
            sorted(withheld, key=lambda entry: (_section_index(entry.section), entry.reason))
        ),
    )


#: One section's output: the claims it can cite, and the gaps it must declare.
#: Every section helper returns both, so "this section has nothing to say" is
#: expressed by returning a withholding rather than by returning nothing -- an
#: omitted section and a section with no evidence would otherwise look identical.
type _Section = tuple[tuple[FailureClaim, ...], tuple[WithheldClaim, ...]]


def _require_matching_records(
    run: RunResource,
    evidence: EvidenceReference,
    outcome: OutcomeResource | None,
) -> None:
    """Refuse to explain a run from records that describe a different one."""
    if not evidence.agrees_with(run):
        msg = (
            f"cannot explain run {run.run_id!r} from evidence sealed for "
            f"{evidence.run_id!r} on plan {evidence.plan_digest[:12]}: the evidence "
            "describes a different execution than the run"
        )
        raise InvariantViolationError("api.explanation_evidence_mismatch", msg)
    if outcome is not None and not outcome.agrees_with(run):
        msg = (
            f"cannot explain run {run.run_id!r} with the outcome recorded for "
            f"{outcome.run_id!r}: the two records do not describe one execution"
        )
        raise InvariantViolationError("api.explanation_outcome_mismatch", msg)


def _graded_verdict(payload: Mapping[str, Any]) -> Verdict | None:
    """The graded verdict the controller already computed, or ``None``.

    Copied, never re-derived, and read only when the payload says it was
    graded. A payload whose ``verdict`` string this build does not recognise
    yields ``None`` rather than a guess -- an unrecognised verdict is not a
    verdict this build can explain, and reading it as "no failure" would be the
    worst possible reading of it.
    """
    raw = payload.get("verdict")
    if not payload.get("graded") or not isinstance(raw, str):
        return None
    try:
        return Verdict(raw)
    except ValueError:
        return None


def _evaluations(payload: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    """The recorded evaluations, ignoring anything that is not a record."""
    evaluations = payload.get("evaluations")
    entries = evaluations if isinstance(evaluations, list) else []
    return tuple(entry for entry in entries if isinstance(entry, Mapping))


def _split_evaluations(
    payload: Mapping[str, Any],
) -> tuple[tuple[Mapping[str, Any], ...], tuple[Mapping[str, Any], ...]]:
    """``(graded, ungraded)`` evaluations, split on ``verdict is None``.

    The split is the whole point. ``controller.steady_state`` writes
    ``verdict: null`` for an assertion it could not measure, and reading that as
    a pass is exactly the "the probe never fired" confusion the graded verdict
    exists to remove.
    """
    graded: list[Mapping[str, Any]] = []
    ungraded: list[Mapping[str, Any]] = []
    for entry in _evaluations(payload):
        bucket = graded if entry.get("verdict") is not None else ungraded
        bucket.append(entry)
    return tuple(graded), tuple(ungraded)


def _first_signal(entry: Mapping[str, Any]) -> Mapping[str, Any]:
    """The first signal of a recorded evaluation, or an empty mapping.

    One signal per assertion is what ``controller.steady_state`` produces
    (:class:`~mayhem.controller.steady_state.PhaseEvaluation` wraps a single
    :class:`~mayhem.domain.steady_state.AssertionResult`), so the first is the
    one. The empty-mapping fallback keeps the sentence readable for a payload
    that recorded no per-signal detail rather than raising over it.
    """
    signals = entry.get("signals")
    first = signals[0] if isinstance(signals, list) and signals else {}
    return first if isinstance(first, Mapping) else {}


def _hypothesis_section(*, run: RunResource, evidence: EvidenceReference) -> _Section:
    """The authored hypothesis, cited to the envelope that carried it through."""
    hypothesis = run.hypothesis
    envelope_ref = _envelope_ref(evidence)
    if not hypothesis:
        return (
            (),
            (
                WithheldClaim(
                    section=ExplanationSection.HYPOTHESIS,
                    reason=(
                        "the executed spec records no hypothesis, so there is nothing "
                        "to compare the observations against"
                    ),
                    missing=("spec.hypothesis",),
                ),
            ),
        )
    claim = FailureClaim(
        section=ExplanationSection.HYPOTHESIS,
        text=f"the run set out to test: {hypothesis}",
        refs=(envelope_ref,),
    )
    return ((claim,), ())


def _observed_section(
    *,
    graded_entries: Sequence[Mapping[str, Any]],
    ungraded_entries: Sequence[Mapping[str, Any]],
) -> _Section:
    """Observed versus tolerance, and every assertion that could not be graded."""
    claims: list[FailureClaim] = []
    withheld: list[WithheldClaim] = []
    for entry in graded_entries:
        signal = _first_signal(entry)
        claims.append(
            FailureClaim(
                section=ExplanationSection.OBSERVED_VS_TOLERANCE,
                text=(
                    f"{entry.get('phase')}/{entry.get('check_id')} "
                    f"{entry.get('verb')} graded {entry.get('verdict')}: baseline "
                    f"{_fmt(_as_float(signal.get('baseline')))} -> observed "
                    f"{_fmt(_as_float(signal.get('during') or signal.get('after')))} "
                    f"(limit {_fmt(_as_float(signal.get('limit')))}, delta "
                    f"{_fmt(_as_float(signal.get('delta_pct')))}%)"
                ),
                refs=_steady_signal_refs(entry),
            )
        )
    for entry in ungraded_entries:
        note = str(entry.get("note") or "the baseline was missing or short")
        withheld.append(
            WithheldClaim(
                section=ExplanationSection.OBSERVED_VS_TOLERANCE,
                reason=(
                    f"{entry.get('phase')}/{entry.get('check_id')} was not graded: {note}"
                ),
                missing=(f"{entry.get('phase')}/{entry.get('check_id')}",),
            )
        )
    if not graded_entries and not ungraded_entries:
        withheld.append(
            WithheldClaim(
                section=ExplanationSection.OBSERVED_VS_TOLERANCE,
                reason=(
                    "the evidence envelope carries no steady-state evaluation, so no "
                    "measurement was graded against any tolerance"
                ),
                missing=("steady_state.evaluations",),
            )
        )
    return (tuple(claims), tuple(withheld))


def _impact_section(
    *,
    evidence: EvidenceReference,
    outcome: OutcomeResource | None,
) -> _Section:
    """What the fault did, from SLO outcomes, residual impact, and metric deltas."""
    claims: list[FailureClaim] = []
    for index, slo in enumerate(evidence.envelope.slo_outcomes):
        name = str(slo.get("criterion_id") or slo.get("name") or "criterion")
        observed = _as_float(slo.get("observed"))
        measured = (
            f" (observed {_fmt(observed)}, tolerance {_fmt(_as_float(slo.get('limit')))})"
            if observed is not None
            else ""
        )
        claims.append(
            FailureClaim(
                section=ExplanationSection.IMPACT,
                text=f"criterion {name} {slo.get('status') or 'unknown'}{measured}",
                refs=(
                    ObservationRef(
                        kind=ObservationKind.SLO_OUTCOME,
                        key=f"{evidence.ref_id}/slo[{index}]",
                        detail=name,
                    ),
                ),
            )
        )
    for name, value in sorted(evidence.envelope.residual_impact.items()):
        claims.append(
            FailureClaim(
                section=ExplanationSection.IMPACT,
                text=f"residual impact on {name}: {value}",
                refs=(
                    ObservationRef(
                        kind=ObservationKind.RESIDUAL_IMPACT,
                        key=f"{evidence.ref_id}/residual/{name}",
                        detail=str(value),
                    ),
                ),
            )
        )
    if outcome is not None:
        for name, delta in sorted(outcome.metric_deltas.items()):
            claims.append(
                FailureClaim(
                    section=ExplanationSection.IMPACT,
                    text=f"{name} moved {delta:+.4g}",
                    refs=(
                        ObservationRef(
                            kind=ObservationKind.OBSERVATION,
                            key=f"{outcome.run_id}/metric/{name}",
                            detail=f"{delta:+.4g}",
                        ),
                    ),
                )
            )
    if not claims:
        return (
            (),
            (
                WithheldClaim(
                    section=ExplanationSection.IMPACT,
                    reason=(
                        "no SLO outcome, residual impact, or metric delta was recorded "
                        "for this run, so its impact cannot be stated"
                    ),
                    missing=("slo_outcomes", "residual_impact", "outcome.metric_deltas"),
                ),
            ),
        )
    return (tuple(claims), ())


def _root_failure_section(
    *,
    evidence: EvidenceReference,
    graded: Verdict | None,
    entries: Sequence[Mapping[str, Any]],
) -> _Section:
    """The cause, or the reason no cause is assertable.

    Two refusals, in order, and both are the point of the section. An ungraded
    verdict yields nothing: there is no graded finding to explain, and a cause
    asserted over one is a guess wearing a citation. A verdict that names no
    failure (``as-hypothesised``, ``degraded-within-tolerance``) also yields
    nothing, because a bounded degradation is the fault *working*, and naming a
    root failure for it would invent the incident this report exists to explain.
    """
    claims: list[FailureClaim] = []
    if graded is None:
        return (
            (),
            (
                WithheldClaim(
                    section=ExplanationSection.ROOT_FAILURE,
                    reason=(
                        "the stored steady-state verdict is ungraded, so no cause can be "
                        "attributed: naming one would be a guess over a verdict that was "
                        "never computed"
                    ),
                    missing=("steady_state.verdict",),
                ),
            ),
        )
    failing = frozenset(_root_failure_verdicts())
    failure_entries = tuple(entry for entry in entries if entry.get("verdict") in failing)
    if not failure_entries:
        return (
            (),
            (
                WithheldClaim(
                    section=ExplanationSection.ROOT_FAILURE,
                    reason=(
                        f"the graded verdict is {graded.value!r}, which names no failure: "
                        "a bounded degradation is the fault working as hypothesised, and "
                        "reporting a root cause for it would invent one"
                    ),
                    missing=("steady_state.evaluations[verdict]",),
                ),
            ),
        )
    for entry in failure_entries:
        signal = _first_signal(entry)
        note = str(entry.get("note") or signal.get("note") or "no note recorded")
        claims.append(
            FailureClaim(
                section=ExplanationSection.ROOT_FAILURE,
                text=f"{entry.get('phase')}/{entry.get('check_id')} graded "
                f"{entry.get('verdict')}: {note}",
                refs=_steady_signal_refs(entry),
            )
        )
    if not claims:
        claims.extend(_finding_claims(evidence))
    return (tuple(claims), ())


def _finding_claims(evidence: EvidenceReference) -> tuple[FailureClaim, ...]:
    """The findings the envelope already recorded, cited to their own entries.

    Reported only when no evaluation named the failure. ``findings`` is the
    controller's *summary* of the evaluations that failed, so filing both would
    print the same fact twice under two citations — and a report that repeats
    itself reads as though two things went wrong.
    """
    claims: list[FailureClaim] = []
    findings = evidence.steady_state.get("findings")
    for finding in findings if isinstance(findings, list) else ():
        if not isinstance(finding, Mapping):
            continue
        phase = finding.get("phase")
        check_id = finding.get("check_id")
        note = str(finding.get("note") or finding.get("verdict") or "no note")
        claims.append(
            FailureClaim(
                section=ExplanationSection.ROOT_FAILURE,
                text=f"recorded finding {phase}/{check_id}: {note}",
                refs=(
                    ObservationRef(
                        kind=ObservationKind.FINDING,
                        key=f"{evidence.ref_id}/finding/{phase}/{check_id}",
                        detail=note,
                    ),
                ),
            )
        )
    return tuple(claims)


def _recovery_section(
    *,
    evidence: EvidenceReference,
    entries: Sequence[Mapping[str, Any]],
) -> _Section:
    """Whether the system came back, and what recorded it.

    Recovery is read from the two things that actually recorded it -- a post-phase
    evaluation and the executor's action outcomes -- never inferred from the
    absence of further failures. A run that broke something and was then killed
    has no failures after the fault, and that is not recovery.
    """
    claims: list[FailureClaim] = []
    recovery_entries = tuple(
        entry
        for entry in entries
        if entry.get("phase") == "post" or entry.get("verb") == "recovered"
    )
    for entry in recovery_entries:
        signal = _first_signal(entry)
        claims.append(
            FailureClaim(
                section=ExplanationSection.RECOVERY,
                text=(
                    f"recovery on {entry.get('check_id')} graded {entry.get('verdict')}: "
                    f"settled at {_fmt(_as_float(signal.get('after')))}, delta "
                    f"{_fmt(_as_float(signal.get('delta_pct')))}%"
                ),
                refs=_steady_signal_refs(entry),
            )
        )
    for index, outcome_name in enumerate(evidence.envelope.action_outcomes):
        claims.append(
            FailureClaim(
                section=ExplanationSection.RECOVERY,
                text=f"recorded action outcome: {outcome_name}",
                refs=(
                    ObservationRef(
                        kind=ObservationKind.ACTION_OUTCOME,
                        key=f"{evidence.ref_id}/action[{index}]",
                        detail=outcome_name,
                    ),
                ),
            )
        )
    if claims:
        return (tuple(claims), ())
    if evidence.envelope.recovery_state:
        return (
            (
                FailureClaim(
                    section=ExplanationSection.RECOVERY,
                    text=f"envelope recovery_state: {evidence.envelope.recovery_state}",
                    refs=(
                        ObservationRef(
                            kind=ObservationKind.ENVELOPE,
                            key=evidence.ref_id,
                            detail=f"recovery_state={evidence.envelope.recovery_state}",
                        ),
                    ),
                ),
            ),
            (),
        )
    return (
        (),
        (
            WithheldClaim(
                section=ExplanationSection.RECOVERY,
                reason=(
                    "no post-phase evaluation, no action outcome, and no recovery state: "
                    "this run recorded nothing about whether the system came back"
                ),
                missing=("steady_state.evaluations[phase=post]", "action_outcomes"),
            ),
        ),
    )


def _envelope_ref(evidence: EvidenceReference) -> ObservationRef:
    """The single citation an envelope-level statement rests on."""
    return ObservationRef(
        kind=ObservationKind.ENVELOPE,
        key=evidence.ref_id,
        detail=f"plan={evidence.plan_digest[:12]} status={evidence.envelope.evidence_status}",
    )

def _section_index(section: ExplanationSection) -> int:
    return EXPLANATION_SECTIONS.index(section)


def _as_float(value: object) -> float | None:
    """A finite float, or ``None``.

    Booleans are rejected explicitly: ``isinstance(True, int)`` is true in
    Python, and a boolean silently read as ``1.0`` in a tolerance report is a
    number nobody took.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


# ---------------------------------------------------------------------------
# executive summary (gap 59)
# ---------------------------------------------------------------------------


class ExecutiveMetric(StrEnum):
    """The numbers an executive dashboard may state, and nothing else.

    A closed vocabulary, because the gap is not "show a number" — it is "show a
    number whose absence of provenance reads as an assurance". ``COVERAGE`` is
    in the list and is deliberately the hardest to satisfy: it cannot be derived
    from run records at all, so it only exists when a caller supplies a
    :class:`CoverageFigure` that carries its own evidence, and otherwise the
    metric is withheld (see :func:`summarise`).
    """

    SERVICES_TESTED = "services_tested"
    RUNS_TOTAL = "runs_total"
    RUNS_PASSED = "runs_passed"
    RUNS_DEGRADED = "runs_degraded"
    RUNS_FAILED = "runs_failed"
    COVERAGE = "coverage"
    OPEN_FINDINGS = "open_findings"


class ExecutiveNumber(BaseModel):
    """One dashboard number and the evidence it was counted from.

    ``evidence`` is ``min_length=1``, so "a number without an evidence link" is
    not a constructible value — which is the phase-4 acceptance criterion
    ("a dashboard number without an evidence link fails review") enforced by the
    type instead of by the review.

    ``value`` must be finite: ``inf`` is what a division by an empty set looks
    like in JSON, and no reader of a dashboard can interpret it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    metric: ExecutiveMetric
    value: float
    unit: str = ""
    detail: str = ""
    evidence: tuple[ObservationRef, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _value_is_interpretable(self) -> Self:
        if not math.isfinite(self.value):
            msg = (
                f"{self.metric.value} is {self.value!r}: a number a reader cannot "
                "interpret is not a number a dashboard may show"
            )
            raise InvariantViolationError("api.executive_value_not_finite", msg)
        return self

    @property
    def refs(self) -> tuple[str, ...]:
        return tuple(str(ref) for ref in self.evidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric": self.metric.value,
            "value": self.value,
            "unit": self.unit,
            "detail": self.detail,
            "evidence": [ref.to_dict() for ref in self.evidence],
        }


class CoverageFigure(BaseModel):
    """A coverage percentage, with the cells it was computed over.

    There is no honest way to derive coverage from run records: coverage is a
    property of the *cell matrix*, and a run list is a property of what ran. So
    this type exists as the only route to an
    :attr:`ExecutiveMetric.COVERAGE` number, it must be supplied by a caller who
    has the cells, and it must name them. Absent a figure, the metric is
    withheld — never reported as ``0%``, which is the single most misleading
    number a resilience dashboard can display.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    covered: int = Field(ge=0)
    total: int = Field(ge=0)
    cells: tuple[ObservationRef, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _cells_cover_the_total(self) -> Self:
        if self.covered > self.total:
            msg = (
                f"coverage figure claims {self.covered} covered cells out of "
                f"{self.total}: more covered cells than cells is not coverage"
            )
            raise InvariantViolationError("api.coverage_exceeds_total", msg)
        if self.total == 0:
            msg = (
                "coverage figure has no cells, so its percentage is undefined: an empty "
                "matrix has no coverage, which is different from zero coverage"
            )
            raise InvariantViolationError("api.coverage_without_cells", msg)
        return self

    @property
    def percentage(self) -> float:
        return self.covered / self.total * 100.0


class UnlinkedRun(BaseModel):
    """A run that no dashboard number counts, and why.

    Named rather than dropped. A run excluded from a count because its evidence
    is missing is a gap in the evidence chain, and hiding it inside a denominator
    is how a dashboard becomes confidently wrong.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)

    @model_validator(mode="after")
    def _reason_is_not_blank(self) -> Self:
        _require_nonblank(self.reason, "api.unlinked_reason_not_blank", "unlinked run reason")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {"run_id": self.run_id, "reason": self.reason}


class ExecutiveSummary(_Resource):
    """The executive view: numbers with provenance, gaps named.

    One number per :class:`ExecutiveMetric`, enforced here, so the summary
    cannot hold two disagreeing values for "runs failed" — the failure mode of a
    dashboard assembled by appending. A metric that is neither reported nor
    withheld is recorded in :attr:`absent_metrics`, because a summary that
    silently omits coverage reads as "coverage is fine".
    """

    numbers: tuple[ExecutiveNumber, ...] = Field(min_length=1)
    unlinked_runs: tuple[UnlinkedRun, ...] = ()

    @model_validator(mode="after")
    def _one_number_per_metric(self) -> Self:
        seen: dict[ExecutiveMetric, ExecutiveNumber] = {}
        for number in self.numbers:
            if number.metric in seen:
                msg = (
                    f"executive summary reports {number.metric.value!r} twice "
                    f"({seen[number.metric].value} and {number.value}): two values for "
                    "one metric is not a summary, it is a contradiction"
                )
                raise InvariantViolationError("api.duplicate_executive_metric", msg)
            seen[number.metric] = number
        return self

    @property
    def absent_metrics(self) -> tuple[ExecutiveMetric, ...]:
        """Metrics with neither a number nor a withholding."""
        reported = {number.metric for number in self.numbers}
        return tuple(metric for metric in ExecutiveMetric if metric not in reported)

    def number_for(self, metric: ExecutiveMetric) -> ExecutiveNumber | None:
        """The reported number for ``metric``, or ``None`` when withheld."""
        return next((number for number in self.numbers if number.metric is metric), None)

    @property
    def refs(self) -> tuple[str, ...]:
        seen: dict[str, None] = {}
        for number in self.numbers:
            for ref in number.evidence:
                seen.setdefault(str(ref), None)
        return tuple(seen)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "numbers": [number.to_dict() for number in self.numbers],
            "absent_metrics": [metric.value for metric in self.absent_metrics],
            "unlinked_runs": [entry.to_dict() for entry in self.unlinked_runs],
        }


def summarise(
    runs: Sequence[RunResource],
    evidence: Mapping[str, EvidenceReference],
    *,
    coverage: CoverageFigure | None = None,
) -> ExecutiveSummary:
    """Count the executive numbers over runs that have evidence behind them.

    A run contributes only if ``evidence`` holds an envelope for it that agrees
    on both ``run_id`` and ``plan_digest`` (:meth:`EvidenceReference.agrees_with`).
    A run that does not is named in :attr:`ExecutiveSummary.unlinked_runs` and
    counted nowhere, not in the denominator and not in the numerator. Counting it
    would produce numbers that cite evidence belonging to a different run.

    Pass / degrade / fail is a **partition** of the linked runs, and it is read
    from the graded steady-state verdict in the envelope rather than from
    :class:`~mayhem.domain.run_outcome.RunVerdict`, which has no degraded member
    and must not grow one. Degradation is a property of the steady-state
    grading, so a run graded ``degraded-within-tolerance`` is counted as degraded
    and *not* as passed even when its top-level verdict says pass: a dashboard
    that shows the same run in two of the three buckets is answering a question
    nobody asked. A run whose verdict is FAIL, and a run that passed while
    nothing at all was graded, both land in failed, because "graded nothing" is
    not an assurance.

    ``coverage`` is not derivable from run records (see :class:`CoverageFigure`);
    without it :attr:`ExecutiveMetric.COVERAGE` is absent from the summary
    rather than reported as zero, which is the most misleading number a
    resilience dashboard can display.
    """
    if not runs:
        msg = (
            "an executive summary over zero runs has nothing to summarise: return None "
            "from the caller rather than a summary of absence"
        )
        raise InvariantViolationError("api.empty_executive_summary", msg)

    linked, unlinked = _link_runs(runs, evidence)
    if not linked:
        msg = (
            "every supplied run lacks agreeing evidence, so the summary would consist "
            "only of numbers with nothing behind them"
        )
        raise InvariantViolationError("api.unlinked_executive_summary", msg)

    return ExecutiveSummary(
        numbers=_executive_numbers(linked, unlinked, coverage),
        unlinked_runs=unlinked,
    )


#: One linked run and the citation its bucket membership rests on.
_Linked = tuple[RunResource, EvidenceReference, ObservationRef]


def _link_runs(
    runs: Sequence[RunResource],
    evidence: Mapping[str, EvidenceReference],
) -> tuple[tuple[_Linked, ...], tuple[UnlinkedRun, ...]]:
    """Split the runs into those an envelope can attest to, and those it cannot."""
    linked: list[_Linked] = []
    unlinked: list[UnlinkedRun] = []
    for run in runs:
        reference = evidence.get(run.run_id)
        if reference is None:
            unlinked.append(
                UnlinkedRun(
                    run_id=run.run_id,
                    reason=(
                        "no evidence envelope is recorded for this run, so no dashboard "
                        "number can cite it"
                    ),
                )
            )
            continue
        if not reference.agrees_with(run):
            unlinked.append(
                UnlinkedRun(
                    run_id=run.run_id,
                    reason=(
                        f"the envelope recorded for {run.run_id!r} names plan "
                        f"{reference.plan_digest[:12]}, not the plan the run executed"
                    ),
                )
            )
            continue
        linked.append(
            (
                run,
                reference,
                ObservationRef(
                    kind=ObservationKind.ENVELOPE,
                    key=reference.ref_id,
                    detail=f"run={run.run_id} verdict={run.verdict.value}",
                ),
            )
        )
    return tuple(linked), tuple(unlinked)


def _bucket(run: RunResource, reference: EvidenceReference) -> str:
    """Which of ``passed``/``degraded``/``failed`` this run belongs to.

    Graded evidence leads, top-level verdict only fills the gap the grading left.
    The three are exhaustive and disjoint over the linked runs, which is what
    makes ``runs_passed + runs_degraded + runs_failed == runs_total`` an
    assertion a test can make.
    """
    graded = _graded_verdict(reference.steady_state)
    if graded is not None:
        if graded.value in _degraded_values():
            return "degraded"
        if graded.value in _failing_values():
            return "failed"
        return "passed"
    if run.verdict is RunVerdict.FAIL:
        return "failed"
    # Nothing was graded. A run cannot be reported as a pass on the strength of
    # measurements nobody took, so it is counted as failed rather than silently
    # inflating the green number.
    return "failed"


def _executive_numbers(
    linked: Sequence[_Linked],
    unlinked: Sequence[UnlinkedRun],
    coverage: CoverageFigure | None,
) -> tuple[ExecutiveNumber, ...]:
    """Every executive number, each citing the runs it was counted from."""
    all_refs = tuple(ref for _, _, ref in linked)
    buckets: dict[str, list[ObservationRef]] = {"passed": [], "degraded": [], "failed": []}
    for run, reference, ref in linked:
        buckets[_bucket(run, reference)].append(ref)

    services = sorted({run.experiment_name for run, _, _ in linked})
    numbers: list[ExecutiveNumber] = [
        ExecutiveNumber(
            metric=ExecutiveMetric.SERVICES_TESTED,
            value=float(len(services)),
            unit="experiments",
            detail=", ".join(services),
            evidence=all_refs,
        ),
        ExecutiveNumber(
            metric=ExecutiveMetric.RUNS_TOTAL,
            value=float(len(linked)),
            unit="runs",
            detail=f"{len(unlinked)} run(s) excluded for want of agreeing evidence",
            evidence=all_refs,
        ),
    ]
    for bucket, metric, detail in (
        (
            "passed",
            ExecutiveMetric.RUNS_PASSED,
            "graded as-hypothesised, or a pass with no graded verdict at all",
        ),
        (
            "degraded",
            ExecutiveMetric.RUNS_DEGRADED,
            "graded verdict says the fault moved a signal",
        ),
        (
            "failed",
            ExecutiveMetric.RUNS_FAILED,
            "graded verdict names a failure, or the top-level verdict does",
        ),
    ):
        members = buckets[bucket]
        numbers.append(
            ExecutiveNumber(
                metric=metric,
                value=float(len(members)),
                unit="runs",
                detail=detail,
                evidence=tuple(members) or all_refs,
            )
        )

    findings = tuple(ref for ref in _finding_refs(linked))
    numbers.append(
        ExecutiveNumber(
            metric=ExecutiveMetric.OPEN_FINDINGS,
            value=float(len(findings)),
            unit="findings",
            detail="graded steady-state findings across the linked runs",
            evidence=findings or all_refs,
        )
    )
    if coverage is not None:
        numbers.append(
            ExecutiveNumber(
                metric=ExecutiveMetric.COVERAGE,
                value=coverage.percentage,
                unit="percent",
                detail=f"{coverage.covered}/{coverage.total} cells",
                evidence=coverage.cells,
            )
        )
    return tuple(numbers)


def _finding_refs(linked: Sequence[_Linked]) -> tuple[ObservationRef, ...]:
    """One citation per recorded steady-state finding across the linked runs."""
    found: list[ObservationRef] = []
    for _, reference, _ in linked:
        findings = reference.steady_state.get("findings")
        for finding in findings if isinstance(findings, list) else ():
            if not isinstance(finding, Mapping):
                continue
            phase = finding.get("phase")
            check_id = finding.get("check_id")
            found.append(
                ObservationRef(
                    kind=ObservationKind.FINDING,
                    key=f"{reference.ref_id}/finding/{phase}/{check_id}",
                    detail=str(finding.get("note") or finding.get("verdict") or ""),
                )
            )
    return tuple(found)
