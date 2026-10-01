"""The API resource vocabulary: projections that cannot disagree, a timeline that
is only a view, and a failure report that withholds what it cannot cite (plan 08,
Phase 1).

Why this file exists
--------------------
Phase 1 of ``docs/v1.1.0/08_CONTROL_PLANE_API_UI.md`` is the seam the rest of the
plan rests on: phases 2 to 6 put a gateway, five services, a REST surface and a
UI in front of these types, and the plan's own Phase 1 acceptance is *"round-trip
tests: every API object converts losslessly to and from its domain source"*. So
the tests are grouped by the failure each group rules out:

* **lossless round trips** for every resource. Each resource *contains* its
  domain object and converts to and from it, through both the domain object and
  the JSON wire form, because a projection that drops a field is a resource that
  answers questions its source cannot.
* **the digest bindings**, which are the actual anti-divergence mechanism. A
  projection that names a plan it does not carry is refused at construction, so
  "the API showed a plan that was not the plan that ran" is not a bug class here,
  it is a ``ValidationError``.
* **the timeline**, derived and never stored: points come out of stored events,
  every event kind is placeable, the ordering is total, and a point cannot exist
  without the event behind it.
* **the failure explanation**, including the case the plan cares about most: a
  statement whose supporting evidence is absent is *withheld with a named
  reason*, never guessed. The root-failure section is checked from both sides.
* **executive numbers**, where a number with no evidence link is not
  constructible, a run with no envelope counts nowhere and is named, and coverage
  is absent rather than zero.
* **the negative controls**, written as the things that must not be possible: a
  projection disagreeing with its source, a run resource without a plan digest, a
  timeline point not backed by an event, an executive number without an evidence
  link, an explanation claiming a cause whose evidence is missing.
* **the envelope**, checked against ``src/mayhem/schemas/output_v1.json`` itself,
  so the JSON contract and the model cannot drift apart quietly.

The last test re-states the domain law locally: ``domain.api`` may not import the
toolkit, agents, controller, infra, or the IO modules. ``pyproject.toml``'s
import-linter contract enforces the same thing in CI, but that check needs an
extra dependency, so the guard also lives here.
"""

from __future__ import annotations

import ast
import json
from dataclasses import replace
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from pydantic import ValidationError

import mayhem.domain.api as api_module
from mayhem.domain.api import (
    API_SCHEMA_VERSION,
    EVENT_PHASES,
    RECOVERY_RULES_ARE_CLAIMS,
    ApiEnvelope,
    ApiStatus,
    ApprovalResource,
    CoverageFigure,
    EvidenceReference,
    ExecutiveMetric,
    ExecutiveNumber,
    ExecutiveSummary,
    ExperimentResource,
    ExplanationSection,
    FailureClaim,
    FailureExplanation,
    ObservationKind,
    ObservationRef,
    OutcomeResource,
    PlanResource,
    PlanStepResource,
    PolicyResource,
    RunResource,
    RunTimeline,
    ScheduleResource,
    TimelinePhase,
    TimelinePoint,
    UnlinkedRun,
    WithheldClaim,
    explain_run,
    plan_digest_of,
    spec_digest_of,
    summarise,
    timeline_point_of,
)
from mayhem.domain.approval import Approval, ApprovalState, evaluate_approval
from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.events import Event, EventKind
from mayhem.domain.evidence import EvidenceEnvelope
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
from mayhem.domain.hashing import digest
from mayhem.domain.identity import EnvironmentScope, Principal, Role, RoleGrant
from mayhem.domain.policy import PolicyDecision
from mayhem.domain.run_outcome import Outcome, RunRecord, RunStatus, RunVerdict
from mayhem.domain.safety_proof import (
    Obligation,
    ObligationName,
    ObligationStatus,
    ProofVerdict,
    SafetyProof,
)
from mayhem.domain.scheduling import (
    BlackoutDates,
    BusinessHours,
    CronSpec,
    DailyWindow,
    IntervalSpec,
    Jitter,
    MaintenanceWindow,
    Schedule,
    ScheduleKind,
)
from mayhem.domain.steady_state import Verdict
from mayhem.domain.topology import NodeKind, TargetSelector

if TYPE_CHECKING:
    from collections.abc import Sequence

RUN_ID = "run-0001"
OTHER_RUN_ID = "run-0002"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


# ── fixtures: real domain objects, never dicts shaped like them ────────────────


def _plan(run_id: str = RUN_ID) -> ExecutionPlan:
    selector = TargetSelector(kind=NodeKind.CONTAINER, expr="checkout")
    inject = InjectFault(fault="net.latency", selectors=(selector,), duration="10s")
    planned = PlannedStep(
        id="step-1",
        seq=0,
        raw_action=inject,
        fault=PlannedFault(
            fault_id="net.latency",
            targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"checkout"})),),
            duration=10.0,
        ),
    )
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        steps=(planned, PlannedStep(id="step-2", seq=1, raw_action=Wait(duration="5s"))),
        config_snapshot_id="cfg-0001",
        topology_snapshot_id="topo-0001",
        environment_fingerprint="env-fp-1",
        policy_id="policy-9",
        seed=7,
    )


def _spec(
    name: str = "checkout-latency",
    hypothesis: str = "p99 rises under packet loss",
) -> DrillSpec:
    return DrillSpec.model_validate(
        {
            "kind": "drill",
            "name": name,
            "hypothesis": hypothesis,
            "containers": {"checkout": {"faults": [{"fault": "net.latency", "duration": "5s"}]}},
            "execution": [{"sequential": ["checkout"]}],
        }
    )


def _record(
    run_id: str = RUN_ID,
    *,
    plan: ExecutionPlan | None = None,
    spec: DrillSpec | None = None,
    verdict: RunVerdict = RunVerdict.FAIL,
) -> RunRecord:
    frozen = plan if plan is not None else _plan(run_id)
    authored = spec if spec is not None else _spec()
    return RunRecord(
        run_id=run_id,
        experiment_name=authored.name,
        spec_json=authored.model_dump_json(),
        plan_json=frozen.model_dump_json(),
        seed=frozen.seed,
        status=RunStatus.COMPLETED,
        verdict=verdict,
        environment_fingerprint=frozen.environment_fingerprint,
        config_snapshot_id=frozen.config_snapshot_id,
        started_at="2026-01-01T00:00:00+00:00",
        ended_at="2026-01-01T00:00:30+00:00",
        tags=("nightly",),
    )


def _outcome(run_id: str = RUN_ID, *, deltas: dict[str, float] | None = None) -> Outcome:
    return Outcome(
        run_id=run_id,
        body_json='{"checks": 3}',
        body_hash=DIGEST_A,
        checks_passed=1,
        checks_failed=2,
        metric_deltas=deltas if deltas is not None else {"p99": 300.0},
        residual_effect="container left running",
        stability_signal="stable",
    )


def _evaluation(
    *,
    phase: str,
    check_id: str,
    verb: str,
    verdict: str | None,
    baseline: float | None = 100.0,
    observed: float | None = 400.0,
    limit: float | None = 250.0,
    delta_pct: float | None = 300.0,
    note: str = "",
) -> dict[str, Any]:
    """One stored steady-state evaluation, in the shape the controller writes.

    Built by hand rather than by calling ``controller.steady_state`` because the
    domain may not import upward, and because the payload under test is exactly
    the untyped dict that reaches the evidence envelope. So the fixture has to
    be that dict, and the test asserts the *reading* of it rather than the
    producer of it.
    """
    passed = verdict == Verdict.AS_HYPOTHESISED.value
    return {
        "phase": phase,
        "check_id": check_id,
        "verb": verb,
        "verdict": verdict,
        "sufficient": verdict is not None,
        "passed": passed,
        "note": note,
        "assertion": {"verb": verb, "name": check_id, "expect": None, "tolerance": None},
        "reading": observed,
        "signals": [
            {
                "name": check_id,
                "asserted": verb,
                "baseline": baseline,
                "during": None if phase == "post" else observed,
                "after": observed if phase == "post" else None,
                "delta_pct": delta_pct,
                "limit": limit,
                "within": None,
                "pass": passed,
                "note": note,
                "severity": "warning",
            }
        ],
    }


def _graded_payload(verdict: Verdict, run_id: str = RUN_ID) -> dict[str, Any]:
    """A payload ``controller.steady_state`` would have written for this run."""
    return {
        "schema_version": "1.0",
        "run_id": run_id,
        "graded": True,
        "verdict": verdict.value,
        "passed": False,
        "recovered": True,
        "evaluations": [
            _evaluation(
                phase="during",
                check_id="p99",
                verb="degraded",
                verdict=Verdict.DEGRADED_BEYOND_TOLERANCE.value,
                note="the signal moved further than the declared tolerance allows",
            ),
            _evaluation(
                phase="post",
                check_id="p99",
                verb="recovered",
                verdict=Verdict.AS_HYPOTHESISED.value,
                observed=102.0,
                limit=None,
                delta_pct=2.0,
            ),
        ],
        "ungraded": [],
        "findings": [
            {
                "phase": "during",
                "check_id": "p99",
                "verdict": Verdict.DEGRADED_BEYOND_TOLERANCE.value,
                "note": "beyond tolerance",
            }
        ],
    }


def _envelope(
    *,
    run_id: str = RUN_ID,
    plan_digest: str | None = None,
    steady_state: dict[str, Any] | None = None,
    **overrides: Any,
) -> EvidenceEnvelope:
    defaults: dict[str, Any] = {
        "run_id": run_id,
        "plan_hash": plan_digest if plan_digest is not None else plan_digest_of(_plan(run_id)),
        "report_id": f"report-{run_id}",
        "step_reports": ({"step_id": "step-1", "ok": False, "detail": "", "status": "failed"},),
        "verdict": "fail",
        "recovery_state": "recovered",
        "action_outcomes": ("compensated",),
        "slo_outcomes": (
            {"criterion_id": "p99<250ms", "status": "fail", "observed": 400.0, "limit": 250.0},
        ),
        "residual_impact": {"checkout": "degraded"},
    }
    defaults.update(overrides)
    if steady_state is not None:
        defaults["steady_state"] = steady_state
    return EvidenceEnvelope(**defaults)


def _events(run_id: str = RUN_ID) -> list[Event]:
    return [
        Event(kind=EventKind.RUN_STARTED, run_id=run_id, created_at_epoch_s=100.0),
        Event(
            kind=EventKind.STEP_STARTED,
            run_id=run_id,
            detail={"step": "step-1"},
            created_at_epoch_s=101.0,
        ),
        Event(
            kind=EventKind.FAULT_INJECTED,
            run_id=run_id,
            detail={
                "fault": "net.latency",
                "lease": "lease-7",
                "target": "checkout",
                "pod": "checkout-abc",
                "command": "tc qdisc add",
            },
            created_at_epoch_s=102.0,
        ),
        Event(
            kind=EventKind.FAULT_OBSERVED,
            run_id=run_id,
            detail={
                "fault": "net.latency",
                "lease": "lease-7",
                "impact_observed": True,
                "note": "p99 up",
            },
            created_at_epoch_s=105.0,
        ),
        Event(
            kind=EventKind.CHECK_EVALUATED,
            run_id=run_id,
            detail={"metric": "p99", "measured": 400.0},
            created_at_epoch_s=110.0,
        ),
        Event(
            kind=EventKind.FAULT_RECOVERED,
            run_id=run_id,
            detail={"fault": "net.latency", "lease": "lease-7", "mechanism": "normal"},
            created_at_epoch_s=115.0,
        ),
        Event(
            kind=EventKind.CRITERIA_EVALUATED,
            run_id=run_id,
            detail={"verdict": "fail", "all_satisfied": False},
            created_at_epoch_s=118.0,
        ),
        Event(kind=EventKind.RUN_COMPLETED, run_id=run_id, created_at_epoch_s=120.0),
    ]


def _proof(plan_digest: str = DIGEST_A) -> SafetyProof:
    return SafetyProof(
        plan_digest=plan_digest,
        verdict=ProofVerdict.PASS,
        obligations=tuple(
            Obligation(
                name=name.value,
                status=ObligationStatus.PASS,
                gate_digest=DIGEST_B,
                evidence_ref=f"evidence:{name.value}",
            )
            for name in ObligationName
        ),
    )


def _approval() -> tuple[Approval, RoleGrant, EnvironmentScope]:
    environment = EnvironmentScope(environment="staging")
    approver = Principal(principal_id="alice")
    approval = Approval.bind(
        approval_id="a-0001",
        proof=_proof(),
        policy_digest=DIGEST_C,
        approver=approver,
        environment=environment,
    )
    grant = RoleGrant(role=Role.APPROVE, scope=environment, principal=approver)
    return approval, grant, environment


def _approval_state(
    approval: Approval,
    environment: EnvironmentScope,
    *,
    grants: Sequence[RoleGrant],
) -> ApprovalState:
    return evaluate_approval(
        approval,
        plan_digest=approval.plan_digest,
        policy_digest=approval.policy_digest,
        proof_digest=approval.proof_digest,
        environment=environment,
        grants=grants,
        now=utc_now(),
    )


def _schedule() -> Schedule:
    created = datetime(2026, 1, 1, tzinfo=UTC)
    return Schedule(
        schedule_id="nightly-checkout",
        name="nightly checkout chaos",
        kind=ScheduleKind.CRON,
        cron=CronSpec(expression="0 2 * * *"),
        timezone_name="Europe/London",
        created_at=created,
        ends_at=created + timedelta(days=30),
    )


def _decision(outcome: str = "deny") -> PolicyDecision:
    return PolicyDecision(
        outcome=outcome,  # type: ignore[arg-type]
        reasons=("risk ceiling exceeded [risk.ceiling]",),
        matched_rules=("risk.ceiling",),
        bundle_id="default",
        bundle_version=9,
        rule_digest=DIGEST_A,
        policy_digest=DIGEST_B,
        facts_digest=DIGEST_C,
    )


def _ref(kind: ObservationKind = ObservationKind.ENVELOPE, key: str = "report-1") -> ObservationRef:
    return ObservationRef(kind=kind, key=key)


# ── round trips: every resource converts losslessly, both ways ─────────────────


def test_experiment_resource_round_trips_through_its_spec_and_its_wire_form() -> None:
    spec = _spec()
    resource = ExperimentResource.of(spec)

    assert resource.to_spec() is spec
    assert ExperimentResource.of(resource.to_spec()) == resource
    payload = resource.to_dict()
    assert payload["spec_digest"] == spec_digest_of(spec)
    assert payload["hypothesis"] == spec.hypothesis
    restored = ExperimentResource.model_validate(resource.to_payload())
    # Identity is the digest, not pydantic equality, and this is why. ``DrillConfig``
    # declares ``timeout: Duration = "30m"``, and pydantic returns an unpassed class
    # default *without* running the validator, so the in-memory spec holds the DSL
    # string while its own JSON round trip holds ``1800.0``. A DrillSpec is therefore
    # not ``==``-equal to itself after a JSON round trip -- a documented property of
    # ``mayhem.domain.common.Duration``, and the reason a citation is a digest rather
    # than an equality check.
    assert restored.spec_digest == resource.spec_digest == spec_digest_of(spec)
    assert restored.name == resource.name
    assert restored.spec.model_dump(mode="json") == spec.model_dump(mode="json")
    assert restored.spec.model_dump(mode="json") == spec.model_dump(mode="json")


def test_experiment_resource_reads_its_steady_state_signals_off_the_spec() -> None:
    bare = ExperimentResource.of(_spec())
    assert bare.steady_state_signals == ()

    with_signal = ExperimentResource.of(
        DrillSpec.model_validate(
            {
                **_spec().model_dump(mode="json"),
                "steady_state": {
                    "capture": {"samples": 5, "window": "10s"},
                    "signals": [
                        {
                            "name": "p99_latency",
                            "source_id": "prom",
                            "metric": "histogram_quantile",
                            "tolerance": {"at_most_relative": 1.5},
                        }
                    ],
                    "phases": [{"during": {"assert_degraded": ["p99_latency"]}}],
                },
            }
        )
    )
    assert with_signal.steady_state_signals == ("p99_latency",)


def test_plan_resource_round_trips_and_uses_the_one_plan_digest_definition() -> None:
    plan = _plan()
    resource = PlanResource.of(plan)

    assert resource.to_plan() == plan
    assert PlanResource.of(resource.to_plan()) == resource
    # plan_content_digest is what controller.approval_gate.candidate_plan_digest
    # computes, so an approval, an evidence envelope and this resource cannot
    # hold three different identities for one plan.
    assert resource.plan_digest == plan_digest_of(plan)
    assert resource.plan_digest == digest(plan.model_dump(mode="json"))

    restored = PlanResource.model_validate(resource.to_payload())
    assert restored == resource
    assert restored.plan == plan
    assert restored.run_id == plan.run_id
    assert restored.config_snapshot_id == "cfg-0001"
    assert restored.topology_snapshot_id == "topo-0001"
    assert restored.environment_fingerprint == "env-fp-1"
    assert restored.policy_id == "policy-9"


def test_plan_step_resources_pin_their_plan_and_read_resolution_off_the_plan() -> None:
    resource = PlanResource.of(_plan())
    steps = resource.steps

    assert [step.step_id for step in steps] == ["step-1", "step-2"]
    assert [step.seq for step in steps] == [0, 1]
    assert all(step.plan_digest == resource.plan_digest for step in steps)
    assert steps[0].to_step() is resource.plan.steps[0]
    assert steps[0].fault_id == "net.latency"
    assert steps[0].action_type == "inject_fault"
    # Resolved nodes, not the authored selector: a row showing the intent rather
    # than what was targeted is showing a plan, not a run.
    assert steps[0].resolve_target_ids == ("checkout",)
    assert steps[0].logical_target_id == ""
    assert steps[1].fault_id == ""
    assert steps[1].action_type == "wait"
    assert steps[1].resolve_target_ids == ()

    restored = PlanStepResource.model_validate(steps[0].to_payload())
    assert restored == steps[0]
    assert restored.to_step() == steps[0].to_step()


def test_run_resource_round_trips_and_derives_its_own_plan_digest() -> None:
    record = _record()
    resource = RunResource.of(record)

    assert resource.to_record() == record
    assert RunResource.of(resource.to_record()) == resource
    assert resource.plan_digest == plan_digest_of(_plan())
    assert resource.verdict is RunVerdict.FAIL
    assert resource.status == "completed"
    assert resource.experiment_name == "checkout-latency"
    assert resource.hypothesis == "p99 rises under packet loss"
    assert resource.record.wall_seconds == 30.0

    restored = RunResource.model_validate(resource.to_payload())
    assert restored == resource
    assert restored.to_record() == record
    assert restored.plan_digest == resource.plan_digest


def test_run_resource_reports_an_unhypothesised_or_unparseable_spec_as_no_hypothesis() -> None:
    unhypothesised = RunResource.of(_record(spec=_spec(hypothesis="")))
    assert unhypothesised.hypothesis == ""

    unparseable = RunResource.of(
        RunRecord(
            run_id=RUN_ID,
            experiment_name="checkout-latency",
            spec_json="not json at all",
            plan_json=_plan().model_dump_json(),
            verdict=RunVerdict.FAIL,
        )
    )
    assert unparseable.hypothesis == ""


def test_outcome_resource_round_trips_and_agrees_only_with_its_own_run() -> None:
    outcome = _outcome()
    resource = OutcomeResource.of(outcome, plan_digest=plan_digest_of(_plan()))

    assert resource.to_outcome() == outcome
    assert OutcomeResource.of(resource.to_outcome(), plan_digest=resource.plan_digest) == resource
    assert resource.checks_passed == 1
    assert resource.checks_failed == 2
    assert resource.metric_deltas == {"p99": 300.0}
    assert resource.all_checks_passed is False

    restored = OutcomeResource.model_validate(resource.to_payload())
    assert restored == resource
    assert restored.to_outcome() == outcome

    assert resource.agrees_with(RunResource.of(_record()))
    assert not resource.agrees_with(
        RunResource.of(_record(OTHER_RUN_ID, plan=_plan(OTHER_RUN_ID)))
    )


def test_outcome_resource_is_refused_when_its_observation_body_is_unhashed() -> None:
    unhashed = Outcome(run_id=RUN_ID, body_json='{"checks": 3}', checks_passed=1)
    with pytest.raises(InvariantViolationError) as excinfo:
        OutcomeResource.of(unhashed, plan_digest=DIGEST_A)
    assert excinfo.value.rule == "api.outcome_body_unhashed"


def test_approval_resource_round_trips_the_record_and_the_state_that_graded_it() -> None:
    approval, grant, environment = _approval()
    state = _approval_state(approval, environment, grants=(grant,))
    resource = ApprovalResource.of(approval, state)

    assert resource.to_approval() == approval
    assert resource.valid is state.valid is True
    assert resource.reasons == ()
    assert resource.approval_id == "a-0001"
    assert resource.plan_digest == approval.plan_digest
    assert resource.policy_digest == approval.policy_digest
    assert resource.proof_digest == approval.proof_digest
    assert resource.approver == "alice"

    restored = ApprovalResource.model_validate(resource.to_payload())
    assert restored.approval == approval
    assert restored.state == state


def test_approval_resource_reports_a_refusal_with_the_state_s_own_reasons() -> None:
    approval, _, environment = _approval()
    state = _approval_state(approval, environment, grants=())  # default-deny: no grant
    resource = ApprovalResource.of(approval, state)

    assert resource.valid is False
    assert "approver_role" in resource.reasons
    assert "quorum_not_met" in resource.reasons


def test_policy_resource_round_trips_and_reads_allowed_off_the_decision() -> None:
    decision = _decision()
    resource = PolicyResource.of(decision)

    assert resource.to_decision() == decision
    assert PolicyResource.of(resource.to_decision()) == resource
    assert resource.allowed is False
    assert resource.decision_digest == decision.decision_digest()
    assert (resource.bundle_id, resource.bundle_version) == ("default", 9)
    assert (resource.rule_digest, resource.policy_digest, resource.facts_digest) == (
        DIGEST_A,
        DIGEST_B,
        DIGEST_C,
    )

    restored = PolicyResource.model_validate(resource.to_payload())
    assert restored == resource
    assert restored.decision == decision

    allowed = PolicyResource.of(_decision("allow"))
    assert allowed.allowed is True
    assert allowed.decision.outcome == "allow"


def test_schedule_resource_round_trips_and_reads_its_horizon_off_the_schedule() -> None:
    schedule = _schedule()
    resource = ScheduleResource.of(schedule)

    assert resource.to_schedule() == schedule
    assert ScheduleResource.of(resource.to_schedule()) == resource
    assert resource.schedule_id == "nightly-checkout"
    assert resource.kind == "cron"
    assert resource.timezone_name == "Europe/London"
    assert resource.horizon == f"ends_at={schedule.ends_at.isoformat()}"
    assert resource.gates == ()

    restored = ScheduleResource.model_validate(resource.to_payload())
    assert restored == resource
    assert restored.schedule == schedule


def test_schedule_resource_reads_every_horizon_the_domain_allows() -> None:
    created = datetime(2026, 1, 1, tzinfo=UTC)

    capped_runs = ScheduleResource.of(
        Schedule(
            schedule_id="ten-runs",
            kind=ScheduleKind.INTERVAL,
            interval=IntervalSpec(every_s=3600.0, anchor_at=created),
            created_at=created,
            max_runs=10,
        )
    )
    assert capped_runs.horizon == "max_runs=10"

    capped_occurrences = ScheduleResource.of(
        Schedule(
            schedule_id="five-slots",
            kind=ScheduleKind.INTERVAL,
            interval=IntervalSpec(every_s=3600.0, anchor_at=created, max_occurrences=5),
            created_at=created,
        )
    )
    assert capped_occurrences.horizon == "max_occurrences=5"

    # ends_at wins when both are declared, because the earliest of the two bounds
    # is the one that actually stops the recurrence.
    both = ScheduleResource.of(
        Schedule(
            schedule_id="both",
            kind=ScheduleKind.INTERVAL,
            interval=IntervalSpec(every_s=3600.0, anchor_at=created),
            created_at=created,
            max_runs=10,
            ends_at=created + timedelta(days=2),
        )
    )
    assert both.horizon == f"ends_at={(created + timedelta(days=2)).isoformat()}"


def test_schedule_resource_names_the_gates_a_schedule_declares() -> None:
    created = datetime(2026, 1, 1, tzinfo=UTC)
    gated = ScheduleResource.of(
        Schedule(
            schedule_id="gated",
            kind=ScheduleKind.CRON,
            cron=CronSpec(expression="0 2 * * 1-5"),
            timezone_name="UTC",
            business_hours=BusinessHours(
                windows=(
                    DailyWindow(
                        label="weekdays",
                        days=frozenset({0, 1, 2, 3, 4}),
                        start_time=time(9, 0),
                        end_time=time(17, 0),
                    ),
                ),
            ),
            maintenance_windows=(
                MaintenanceWindow(
                    window_id="freeze",
                    starts_at=created,
                    ends_at=created + timedelta(days=1),
                ),
            ),
            blackout_dates=BlackoutDates(dates=frozenset({date(2026, 12, 25)})),
            jitter=Jitter(max_offset_s="60s"),
            created_at=created,
            ends_at=created + timedelta(days=90),
        )
    )
    assert gated.gates == (
        "business_hours",
        "maintenance_windows",
        "blackout_dates",
        "jitter",
    )


def test_evidence_reference_round_trips_and_names_the_sealed_envelope() -> None:
    envelope = _envelope(steady_state=_graded_payload(Verdict.DEGRADED_BEYOND_TOLERANCE))
    reference = EvidenceReference.of(envelope)

    assert reference.to_envelope() == envelope
    assert reference.ref_id == envelope.report_id
    assert reference.run_id == RUN_ID
    assert reference.plan_digest == envelope.plan_hash
    assert reference.complete is True
    assert reference.completeness_errors() == []
    assert reference.steady_state["verdict"] == Verdict.DEGRADED_BEYOND_TOLERANCE.value
    assert reference.agrees_with(RunResource.of(_record()))

    restored = EvidenceReference.model_validate(reference.to_payload())
    assert restored == reference
    assert restored.envelope == envelope


def test_evidence_reference_reports_an_incomplete_envelope_rather_than_hiding_it() -> None:
    incomplete = _envelope(step_reports=(), verdict="")
    reference = EvidenceReference.of(incomplete)

    assert reference.complete is False
    assert "step_reports empty" in reference.completeness_errors()
    assert "verdict missing" in reference.completeness_errors()


# ── negative controls: a projection that disagrees with its source ─────────────


def test_a_plan_resource_naming_a_digest_other_plans_have_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        PlanResource(plan_digest=DIGEST_A, plan=_plan())
    assert excinfo.value.rule == "api.plan_digest_mismatch"


def test_a_plan_resource_edited_over_the_wire_is_refused_on_reload() -> None:
    payload = PlanResource.of(_plan()).to_payload()
    payload["plan"]["run_id"] = OTHER_RUN_ID
    with pytest.raises(InvariantViolationError) as excinfo:
        PlanResource.model_validate(payload)
    assert excinfo.value.rule == "api.plan_digest_mismatch"


def test_an_experiment_resource_naming_another_spec_s_digest_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        ExperimentResource(name="checkout-latency", spec_digest=DIGEST_B, spec=_spec())
    assert excinfo.value.rule == "api.spec_digest_mismatch"

    renamed = ExperimentResource.of(_spec()).to_payload()
    renamed["name"] = "other-name"
    with pytest.raises(InvariantViolationError) as excinfo:
        ExperimentResource.model_validate(renamed)
    assert excinfo.value.rule == "api.experiment_name_mismatch"


def test_a_run_resource_naming_a_plan_its_own_plan_json_does_not_hash_to_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        RunResource(run_id=RUN_ID, plan_digest=DIGEST_C, record=_record())
    assert excinfo.value.rule == "api.plan_digest_mismatch"

    # Two plans, both well formed, same run id, different content. Only the
    # digest of the stored plan tells them apart, which is exactly the ambiguity
    # the binding removes.
    other_plan = ExecutionPlan(
        run_id=RUN_ID,
        kind=ExperimentKind.DRILL,
        steps=(PlannedStep(id="step-1", seq=0, raw_action=Wait(duration="30s")),),
        config_snapshot_id="cfg-0002",
        topology_snapshot_id="topo-0001",
        environment_fingerprint="env-fp-1",
    )
    other_record = _record(plan=other_plan)
    assert other_record.run_id == RUN_ID
    assert RunResource.of(other_record).plan_digest == plan_digest_of(other_plan)
    assert RunResource.of(other_record).plan_digest != plan_digest_of(_plan())


def test_a_run_resource_whose_plan_json_is_unreadable_cannot_be_projected() -> None:
    record = RunRecord(
        run_id=RUN_ID,
        experiment_name="checkout-latency",
        spec_json="{}",
        plan_json="{not json",
        verdict=RunVerdict.FAIL,
    )
    with pytest.raises(InvariantViolationError) as excinfo:
        RunResource.of(record)
    assert excinfo.value.rule == "api.run_plan_unreadable"

    # Parses as JSON but names no frozen plan: a list is not a plan, and hashing
    # it would produce a digest of a document rather than of a contract.
    with pytest.raises(InvariantViolationError) as excinfo:
        RunResource.of(replace(_record(), plan_json="[1, 2]"))
    assert excinfo.value.rule == "api.run_plan_unreadable"


def test_a_run_resource_that_cannot_name_its_plan_at_all_is_refused() -> None:
    # An empty digest is the "run exists, plan does not" state. It is refused
    # rather than projected, because a dashboard row that cannot name the plan
    # behind its number is reporting nothing.
    with pytest.raises(InvariantViolationError) as excinfo:
        RunResource(run_id=RUN_ID, plan_digest="", record=_record())
    assert excinfo.value.rule == "api.plan_digest_not_sha256"

    with pytest.raises(InvariantViolationError) as excinfo:
        RunResource(run_id=RUN_ID, plan_digest="not-a-digest", record=_record())
    assert excinfo.value.rule == "api.plan_digest_not_sha256"


def test_a_run_resource_carrying_another_run_s_record_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        RunResource(
            run_id=OTHER_RUN_ID,
            plan_digest=RunResource.of(_record()).plan_digest,
            record=_record(),
        )
    assert excinfo.value.rule == "api.run_id_mismatch"


def test_an_approval_resource_that_contradicts_its_state_is_refused() -> None:
    approval, grant, environment = _approval()
    state = _approval_state(approval, environment, grants=(grant,))

    with pytest.raises(InvariantViolationError) as excinfo:
        ApprovalResource(
            approval_digest=approval.approval_digest,
            valid=False,
            reasons=(),
            approval=approval,
            state=state,
        )
    assert excinfo.value.rule == "api.approval_state_mismatch"

    with pytest.raises(InvariantViolationError) as excinfo:
        ApprovalResource(
            approval_digest=approval.approval_digest,
            valid=True,
            reasons=("approver_role",),
            approval=approval,
            state=state,
        )
    assert excinfo.value.rule == "api.approval_reasons_mismatch"


def test_a_policy_resource_reporting_allowed_over_a_deny_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        PolicyResource(
            decision_digest=_decision().decision_digest(),
            allowed=True,
            decision=_decision(),
        )
    assert excinfo.value.rule == "api.policy_outcome_mismatch"


def test_a_policy_resource_with_another_decision_s_digest_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        PolicyResource(decision_digest=DIGEST_A, allowed=False, decision=_decision())
    assert excinfo.value.rule == "api.decision_digest_mismatch"


def test_a_schedule_or_evidence_resource_with_a_stale_digest_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as schedule_exc:
        ScheduleResource(schedule_digest=DIGEST_A, schedule=_schedule())
    assert schedule_exc.value.rule == "api.schedule_digest_mismatch"

    envelope = _envelope()
    with pytest.raises(InvariantViolationError) as evidence_exc:
        EvidenceReference(
            envelope_digest=DIGEST_A,
            ref_id=envelope.report_id,
            complete=envelope.is_complete(),
            envelope=envelope,
        )
    assert evidence_exc.value.rule == "api.envelope_digest_mismatch"


def test_an_evidence_reference_contradicting_the_envelope_s_completeness_is_refused() -> None:
    incomplete = _envelope(step_reports=(), verdict="")
    with pytest.raises(InvariantViolationError) as excinfo:
        EvidenceReference(
            envelope_digest=EvidenceReference.of(incomplete).envelope_digest,
            ref_id=incomplete.report_id,
            complete=True,
            envelope=incomplete,
        )
    assert excinfo.value.rule == "api.evidence_completeness_mismatch"


def test_a_step_resource_that_misattributes_its_step_or_sequence_is_refused() -> None:
    plan = _plan()
    with pytest.raises(InvariantViolationError) as excinfo:
        PlanStepResource(plan_digest=DIGEST_A, step_id="other", seq=0, step=plan.steps[0])
    assert excinfo.value.rule == "api.step_id_mismatch"

    with pytest.raises(InvariantViolationError) as seq_exc:
        PlanStepResource(plan_digest=DIGEST_A, step_id="step-1", seq=7, step=plan.steps[0])
    assert seq_exc.value.rule == "api.step_seq_mismatch"


def test_every_resource_refuses_an_unknown_schema_version() -> None:
    for factory in (
        lambda: PlanResource(schema_version="2.0", plan_digest=DIGEST_A, plan=_plan()),
        lambda: ExperimentResource(
            schema_version="2.0", name="x", spec_digest=DIGEST_A, spec=_spec()
        ),
        lambda: RunResource(
            schema_version="2.0", run_id=RUN_ID, plan_digest=DIGEST_A, record=_record()
        ),
    ):
        with pytest.raises(InvariantViolationError) as excinfo:
            factory()
        assert excinfo.value.rule == "api.unsupported_schema"


def test_every_resource_forbids_a_field_the_contract_does_not_declare() -> None:
    with pytest.raises(ValidationError):
        PlanResource.model_validate(
            {**PlanResource.of(_plan()).to_payload(), "published": True}
        )


# ── the timeline is derived from stored events, never stored beside them ───────


def test_timeline_points_are_derived_from_the_events_and_carry_a_digest_of_each() -> None:
    timeline = RunTimeline.of(_events(), run_id=RUN_ID, plan_digest=plan_digest_of(_plan()))
    points = timeline.points

    assert [point.event_kind for point in points] == [
        event.kind for event in timeline.ordered_events
    ]
    assert [point.sequence for point in points] == list(range(len(points)))
    for point, event in zip(points, timeline.ordered_events, strict=True):
        assert point.event is event
        assert point.event_digest == digest(event.model_dump(mode="json"))
        assert point.summary == event.render_line()
        assert point.run_id == RUN_ID
        # Re-deriving from the same event produces the same point, so the
        # timeline is a pure function of its events.
        assert timeline_point_of(event, point.sequence) == point


def test_timeline_orders_by_time_then_by_storage_order_and_is_deterministic() -> None:
    same_instant = [
        Event(kind=EventKind.FAULT_RECOVERED, run_id=RUN_ID, created_at_epoch_s=105.0),
        Event(kind=EventKind.FAULT_INJECTED, run_id=RUN_ID, created_at_epoch_s=100.0),
        Event(kind=EventKind.STEP_STARTED, run_id=RUN_ID, created_at_epoch_s=105.0),
    ]
    timeline = RunTimeline.of(same_instant, run_id=RUN_ID, plan_digest=DIGEST_A)

    assert [point.event_kind for point in timeline.points] == [
        EventKind.FAULT_INJECTED,
        EventKind.FAULT_RECOVERED,
        EventKind.STEP_STARTED,
    ]
    assert [point.sequence for point in timeline.points] == [0, 1, 2]
    # Two events in the same millisecond keep the order the executor emitted them
    # in, so a reordering that preserves it renders identically. The tiebreak is
    # storage order and not something else, because nothing recorded says which of
    # two same-instant events came first.
    reordered = RunTimeline.of(
        [same_instant[1], same_instant[0], same_instant[2]],
        run_id=RUN_ID,
        plan_digest=DIGEST_A,
    )
    assert reordered.to_dict() == timeline.to_dict()
    # Swapping the two same-instant events *does* move them, because storage order
    # is the tiebreak. Nothing recorded says which of them happened first, so the
    # order the executor emitted them in is the only honest tiebreak there is.
    swapped = RunTimeline.of(
        [same_instant[2], same_instant[1], same_instant[0]],
        run_id=RUN_ID,
        plan_digest=DIGEST_A,
    )
    assert [point.event_kind for point in swapped.points] == [
        EventKind.FAULT_INJECTED,
        EventKind.STEP_STARTED,
        EventKind.FAULT_RECOVERED,
    ]
    assert swapped.to_dict() != timeline.to_dict()
    # Distinct timestamps, shuffled storage: time wins, so the story is unchanged.
    distinct = [
        Event(kind=EventKind.RUN_STARTED, run_id=RUN_ID, created_at_epoch_s=1.0),
        Event(kind=EventKind.FAULT_INJECTED, run_id=RUN_ID, created_at_epoch_s=2.0),
        Event(kind=EventKind.RUN_COMPLETED, run_id=RUN_ID, created_at_epoch_s=3.0),
    ]
    assert (
        RunTimeline.of(distinct, run_id=RUN_ID, plan_digest=DIGEST_A).to_dict()
        == RunTimeline.of(
            list(reversed(distinct)), run_id=RUN_ID, plan_digest=DIGEST_A
        ).to_dict()
    )


def test_every_event_kind_has_a_timeline_phase_so_no_fact_is_silently_dropped() -> None:
    assert set(EVENT_PHASES) == set(EventKind)
    assert len(EVENT_PHASES) == 22
    assert set(EVENT_PHASES.values()) == set(TimelinePhase)


def test_timeline_drill_down_reports_what_the_event_recorded_and_blanks_the_rest() -> None:
    timeline = RunTimeline.of(_events(), run_id=RUN_ID, plan_digest=plan_digest_of(_plan()))
    points = {point.event_kind: point for point in timeline.points}

    injected = points[EventKind.FAULT_INJECTED]
    assert injected.phase is TimelinePhase.FAULT
    assert injected.step == ""
    assert injected.fault == "net.latency"
    assert injected.target == "checkout"
    assert injected.process == "checkout-abc"
    assert injected.command == "tc qdisc add"
    assert injected.recovered == ""
    assert injected.metric == ""

    started = points[EventKind.STEP_STARTED]
    assert started.step == "step-1"
    assert started.fault == ""

    evaluated = points[EventKind.CHECK_EVALUATED]
    assert evaluated.metric == "p99"
    assert evaluated.phase is TimelinePhase.OBSERVE

    recovered = points[EventKind.FAULT_RECOVERED]
    assert recovered.recovered == "normal"
    assert recovered.phase is TimelinePhase.RECOVER
    # Recovery is read from the recorded event, never inferred from the absence of
    # later failures, and the rendered timeline says so on its face.
    assert timeline.to_dict()["recovery_rule"] == RECOVERY_RULES_ARE_CLAIMS

    # An empty cell means "this event did not say", never "nothing happened".
    assert points[EventKind.RUN_COMPLETED].metric == ""
    assert points[EventKind.RUN_STARTED].summary == "run.started run=run-0001"


def test_timeline_reports_the_phases_present_and_names_the_ones_that_are_absent() -> None:
    timeline = RunTimeline.of(_events(), run_id=RUN_ID, plan_digest=plan_digest_of(_plan()))
    assert timeline.phases_present == tuple(TimelinePhase)
    assert timeline.phases_absent == ()

    no_recovery = RunTimeline.of(
        [
            Event(kind=EventKind.RUN_STARTED, run_id=RUN_ID, created_at_epoch_s=1.0),
            Event(kind=EventKind.FAULT_FAILED, run_id=RUN_ID, created_at_epoch_s=2.0),
        ],
        run_id=RUN_ID,
        plan_digest=DIGEST_A,
    )
    assert no_recovery.phases_present == (TimelinePhase.BASELINE, TimelinePhase.FAULT)
    assert TimelinePhase.RECOVER in no_recovery.phases_absent
    assert TimelinePhase.VERIFY in no_recovery.phases_absent


def test_timeline_point_at_is_bounds_checked_as_a_typed_refusal() -> None:
    timeline = RunTimeline.of(_events(), run_id=RUN_ID, plan_digest=plan_digest_of(_plan()))
    assert timeline.point_at(0).event_kind is EventKind.RUN_STARTED
    with pytest.raises(InvariantViolationError) as excinfo:
        timeline.point_at(len(timeline.points))
    assert excinfo.value.rule == "api.timeline_point_out_of_range"


def test_a_timeline_point_not_backed_by_an_event_cannot_be_produced() -> None:
    event = _events()[0]
    good = timeline_point_of(event, 0)

    # No event at all: the field is required, so a point without one is not a
    # value this type can hold.
    payload = good.to_payload()
    payload.pop("event")
    with pytest.raises(ValidationError):
        TimelinePoint.model_validate(payload)

    # An event, but a digest that is not that event's: the binding that makes
    # the point a view rather than a drawing.
    payload = good.to_payload()
    payload["event_digest"] = DIGEST_A
    with pytest.raises(InvariantViolationError) as excinfo:
        TimelinePoint.model_validate(payload)
    assert excinfo.value.rule == "api.timeline_event_digest_mismatch"


def test_a_timeline_point_that_relabels_its_event_or_its_phase_is_refused() -> None:
    event = _events()[2]  # fault.injected
    good = timeline_point_of(event, 0).to_payload()

    relabelled = {**good, "event_kind": EventKind.RUN_COMPLETED.value}
    with pytest.raises(InvariantViolationError) as excinfo:
        TimelinePoint.model_validate(relabelled)
    assert excinfo.value.rule == "api.timeline_event_kind_mismatch"

    moved = {**good, "phase": TimelinePhase.VERIFY.value}
    with pytest.raises(InvariantViolationError) as excinfo:
        TimelinePoint.model_validate(moved)
    assert excinfo.value.rule == "api.timeline_phase_mismatch"

    retimed = {**good, "at_epoch_s": 999.0}
    with pytest.raises(InvariantViolationError) as excinfo:
        TimelinePoint.model_validate(retimed)
    assert excinfo.value.rule == "api.timeline_event_time_mismatch"

    # The whole point list is re-derivable from the stored detail, so a point
    # whose cells were edited over the wire is not the point the event implies.
    payload = {**good, "event": {**event.model_dump(mode="json"), "detail": {"fault": "proc.kill"}}}
    with pytest.raises(InvariantViolationError) as excinfo:
        TimelinePoint.model_validate(payload)
    assert excinfo.value.rule == "api.timeline_event_digest_mismatch"

    # A point with no rendering is a point nobody can read, and the rendering is
    # the event's own line rather than prose written beside it.
    with pytest.raises(InvariantViolationError) as excinfo:
        TimelinePoint.model_validate({**good, "summary": ""})
    assert excinfo.value.rule == "api.timeline_summary_missing"


def test_a_timeline_refuses_events_from_another_run_and_an_unreadable_plan_digest() -> None:
    mixed = [*_events(), Event(kind=EventKind.RUN_STARTED, run_id=OTHER_RUN_ID)]
    with pytest.raises(InvariantViolationError) as excinfo:
        RunTimeline.of(mixed, run_id=RUN_ID, plan_digest=DIGEST_A)
    assert excinfo.value.rule == "api.timeline_foreign_events"

    with pytest.raises(InvariantViolationError) as excinfo:
        RunTimeline.of(_events(), run_id=RUN_ID, plan_digest="nope")
    assert excinfo.value.rule == "api.plan_digest_not_sha256"


def test_a_timeline_with_no_events_is_refused_rather_than_rendered_empty() -> None:
    with pytest.raises(ValidationError):
        RunTimeline.of([], run_id=RUN_ID, plan_digest=DIGEST_A)


# ── failure explanation: cites what it has, withholds what it does not ─────────


def test_failure_explanation_renders_every_section_from_the_stored_observations() -> None:
    run = RunResource.of(_record())
    evidence = EvidenceReference.of(
        _envelope(steady_state=_graded_payload(Verdict.DEGRADED_BEYOND_TOLERANCE))
    )
    outcome = OutcomeResource.of(_outcome(), plan_digest=run.plan_digest)

    report = explain_run(run=run, evidence=evidence, outcome=outcome)

    assert report.run_id == RUN_ID
    assert report.plan_digest == run.plan_digest
    assert report.run_verdict is RunVerdict.FAIL
    # The verdict is copied from the controller's payload, not re-derived.
    assert report.graded_verdict is Verdict.DEGRADED_BEYOND_TOLERANCE
    assert report.evidence_ref == evidence.ref_id
    assert report.explained
    assert report.withheld == ()

    hypothesis = report.claims_for(ExplanationSection.HYPOTHESIS)
    assert len(hypothesis) == 1
    assert hypothesis[0].text.endswith("p99 rises under packet loss")

    observed = report.claims_for(ExplanationSection.OBSERVED_VS_TOLERANCE)
    assert len(observed) == 2
    during = next(claim for claim in observed if "during/p99" in claim.text)
    assert "baseline 100 -> observed 400" in during.text
    assert "limit 250" in during.text
    assert "delta 300%" in during.text
    assert [str(ref) for ref in during.refs] == ["steady_signal:during/p99/p99"]

    post = next(claim for claim in observed if "post/p99" in claim.text)
    assert "settled at" not in post.text
    assert "observed 102" in post.text

    impact = report.claims_for(ExplanationSection.IMPACT)
    texts = " ".join(claim.text for claim in impact)
    assert "criterion p99<250ms fail" in texts
    assert "observed 400, tolerance 250" in texts
    assert "residual impact on checkout: degraded" in texts
    assert "p99 moved +300" in texts

    root = report.root_failure_claims
    assert len(root) == 1
    assert "during/p99 graded degraded-beyond-tolerance" in root[0].text
    assert "moved further than the declared tolerance allows" in root[0].text

    recovery = report.claims_for(ExplanationSection.RECOVERY)
    recovery_texts = " ".join(claim.text for claim in recovery)
    assert "recovery on p99 graded as-hypothesised" in recovery_texts
    assert "recorded action outcome: compensated" in recovery_texts


def test_every_claim_in_a_failure_explanation_cites_at_least_one_observation() -> None:
    run = RunResource.of(_record())
    evidence = EvidenceReference.of(
        _envelope(steady_state=_graded_payload(Verdict.DEGRADED_BEYOND_TOLERANCE))
    )
    report = explain_run(run=run, evidence=evidence)

    assert report.claims
    for claim in report.claims:
        assert claim.refs, f"uncited claim: {claim.text}"
        for ref in claim.refs:
            assert isinstance(ref, ObservationRef)
            assert str(ref)
    # The de-duplicated union is what a reader is handed to go and look.
    assert len(report.refs()) == len({str(ref) for claim in report.claims for ref in claim.refs})


def test_a_claim_without_evidence_is_unrepresentable() -> None:
    with pytest.raises(ValidationError):
        FailureClaim(section=ExplanationSection.IMPACT, text="something moved", refs=())
    with pytest.raises(ValidationError):
        FailureClaim(section=ExplanationSection.IMPACT, text="something moved", refs=[])
    with pytest.raises(InvariantViolationError) as excinfo:
        FailureClaim(section=ExplanationSection.IMPACT, text="   ", refs=(_ref(),))
    assert excinfo.value.rule == "api.claim_text_not_blank"


def test_an_explanation_withholds_the_root_cause_when_nothing_was_graded() -> None:
    run = RunResource.of(_record())
    ungraded = {
        "schema_version": "1.0",
        "graded": False,
        "verdict": None,
        "passed": False,
        "recovered": False,
        "evaluations": [],
        "ungraded": [],
        "findings": [],
    }
    evidence = EvidenceReference.of(
        _envelope(steady_state=ungraded, slo_outcomes=(), residual_impact={})
    )

    report = explain_run(run=run, evidence=evidence)

    assert report.graded_verdict is None
    assert report.root_failure_claims == ()
    withheld = report.withheld_for(ExplanationSection.ROOT_FAILURE)
    assert len(withheld) == 1
    assert "ungraded" in withheld[0].reason
    assert withheld[0].missing == ("steady_state.verdict",)
    # The other sections are still answered or still withheld, each with a reason.
    observed = report.withheld_for(ExplanationSection.OBSERVED_VS_TOLERANCE)
    assert observed and observed[0].missing == ("steady_state.evaluations",)
    impact = report.withheld_for(ExplanationSection.IMPACT)
    assert impact and "slo_outcomes" in impact[0].missing


def test_an_explanation_withholds_the_root_cause_when_what_was_graded_held() -> None:
    run = RunResource.of(_record())
    healthy = _graded_payload(Verdict.AS_HYPOTHESISED)
    healthy["evaluations"] = [
        _evaluation(
            phase="during",
            check_id="p99",
            verb="degraded",
            verdict=Verdict.DEGRADED_WITHIN_TOLERANCE.value,
            note="",
        )
    ]
    healthy["findings"] = []
    evidence = EvidenceReference.of(_envelope(steady_state=healthy))

    report = explain_run(run=run, evidence=evidence)

    # A bounded degradation is the fault working. Naming a root failure for it
    # would manufacture the incident the report exists to explain.
    assert report.root_failure_claims == ()
    withheld = report.withheld_for(ExplanationSection.ROOT_FAILURE)
    assert len(withheld) == 1
    assert "names no failure" in withheld[0].reason


def test_an_explanation_withholds_a_hypothesis_when_the_spec_authored_none() -> None:
    run = RunResource.of(_record(spec=_spec(hypothesis="")))
    evidence = EvidenceReference.of(
        _envelope(steady_state=_graded_payload(Verdict.DEGRADED_BEYOND_TOLERANCE))
    )

    report = explain_run(run=run, evidence=evidence)

    assert report.claims_for(ExplanationSection.HYPOTHESIS) == ()
    withheld = report.withheld_for(ExplanationSection.HYPOTHESIS)
    assert withheld[0].missing == ("spec.hypothesis",)


def test_an_explanation_withholds_each_ungraded_assertion_by_name() -> None:
    payload = {
        "graded": True,
        "verdict": Verdict.NO_EFFECT.value,
        "evaluations": [
            _evaluation(
                phase="pre",
                check_id="errors",
                verb="unchanged",
                verdict=None,
                baseline=None,
                observed=None,
                limit=None,
                delta_pct=None,
                note="insufficient baseline for errors: 2 of 5 samples",
            )
        ],
        "findings": [],
    }
    evidence = EvidenceReference.of(
        _envelope(steady_state=payload, slo_outcomes=(), residual_impact={}, action_outcomes=())
    )

    report = explain_run(run=RunResource.of(_record()), evidence=evidence)

    # An ungraded assertion is reported as ungraded, with the controller's own
    # reason, not smoothed into a pass or a failure.
    withheld = report.withheld_for(ExplanationSection.OBSERVED_VS_TOLERANCE)
    assert len(withheld) == 1
    assert withheld[0].missing == ("pre/errors",)
    assert "2 of 5 samples" in withheld[0].reason
    assert report.claims_for(ExplanationSection.OBSERVED_VS_TOLERANCE) == ()


def test_an_explanation_answers_every_section_and_may_never_do_both_at_once() -> None:
    run = RunResource.of(_record())
    evidence = EvidenceReference.of(
        _envelope(steady_state=_graded_payload(Verdict.DEGRADED_BEYOND_TOLERANCE))
    )
    report = explain_run(run=run, evidence=evidence)

    addressed = {claim.section for claim in report.claims} | {
        entry.section for entry in report.withheld
    }
    assert addressed == set(ExplanationSection)

    claim = report.claims_for(ExplanationSection.IMPACT)[0]
    with pytest.raises(InvariantViolationError) as excinfo:
        FailureExplanation(
            run_id=report.run_id,
            plan_digest=report.plan_digest,
            graded_verdict=report.graded_verdict,
            run_verdict=report.run_verdict,
            evidence_ref=report.evidence_ref,
            claims=report.claims,
            withheld=(
                *report.withheld,
                WithheldClaim(section=claim.section, reason="x", missing=("y",)),
            ),
        )
    assert excinfo.value.rule == "api.section_claimed_and_withheld"


def test_an_explanation_that_says_nothing_about_a_section_is_refused() -> None:
    report = explain_run(
        run=RunResource.of(_record()),
        evidence=EvidenceReference.of(
            _envelope(steady_state=_graded_payload(Verdict.DEGRADED_BEYOND_TOLERANCE))
        ),
    )
    with pytest.raises(InvariantViolationError) as excinfo:
        FailureExplanation(
            run_id=report.run_id,
            plan_digest=report.plan_digest,
            graded_verdict=report.graded_verdict,
            run_verdict=report.run_verdict,
            evidence_ref=report.evidence_ref,
            claims=report.claims[:1],  # every other section now silent
            withheld=(),
        )
    assert excinfo.value.rule == "api.section_unaddressed"


def test_an_explanation_cannot_name_a_root_cause_over_an_ungraded_verdict() -> None:
    """The negative control the whole section exists for.

    Every other section is properly addressed with a cited claim, so the report
    is complete in the only sense that matters except one: it names a cause. The
    graded verdict is ``None``, there is no verdict for the cause to explain, and
    the claim is refused. Both halves matter. A claim with no citation is not
    constructible at all (:class:`FailureClaim`), and a *well-cited* claim over
    an ungraded verdict is refused here, which is the case a type cannot express
    on its own.
    """
    cited = ObservationRef(kind=ObservationKind.FINDING, key="report-run-0001/finding/during/p99")
    claims = tuple(
        FailureClaim(section=section, text=f"{section.value} was observed", refs=(cited,))
        for section in ExplanationSection
    )
    with pytest.raises(InvariantViolationError) as excinfo:
        FailureExplanation(
            run_id=RUN_ID,
            plan_digest=plan_digest_of(_plan()),
            graded_verdict=None,
            run_verdict=RunVerdict.FAIL,
            evidence_ref="report-run-0001",
            claims=claims,
        )
    assert excinfo.value.rule == "api.root_failure_without_verdict"

    # The same report with the cause withheld instead is the constructible shape.
    explainable = FailureExplanation(
        run_id=RUN_ID,
        plan_digest=plan_digest_of(_plan()),
        graded_verdict=None,
        run_verdict=RunVerdict.FAIL,
        evidence_ref="report-run-0001",
        claims=tuple(c for c in claims if c.section is not ExplanationSection.ROOT_FAILURE),
        withheld=(
            WithheldClaim(
                section=ExplanationSection.ROOT_FAILURE,
                reason="the stored steady-state verdict is ungraded",
                missing=("steady_state.verdict",),
            ),
        ),
    )
    assert explainable.root_failure_claims == ()
    assert explainable.graded_verdict is None


def test_a_withheld_claim_must_name_the_observation_it_was_missing() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        WithheldClaim(section=ExplanationSection.IMPACT, reason="insufficient data", missing=())
    assert excinfo.value.rule == "api.withheld_without_missing"
    with pytest.raises(InvariantViolationError) as blank:
        WithheldClaim(section=ExplanationSection.IMPACT, reason="  ", missing=("x",))
    assert blank.value.rule == "api.withheld_reason_not_blank"


def test_an_explanation_refuses_evidence_or_outcome_from_a_different_execution() -> None:
    run = RunResource.of(_record())
    other_run = _record(OTHER_RUN_ID, plan=_plan(OTHER_RUN_ID))

    with pytest.raises(InvariantViolationError) as excinfo:
        explain_run(run=run, evidence=EvidenceReference.of(_envelope(run_id=OTHER_RUN_ID)))
    assert excinfo.value.rule == "api.explanation_evidence_mismatch"

    with pytest.raises(InvariantViolationError) as excinfo:
        explain_run(
            run=run,
            evidence=EvidenceReference.of(_envelope()),
            outcome=OutcomeResource.of(
                _outcome(OTHER_RUN_ID),
                plan_digest=plan_digest_of(_plan(OTHER_RUN_ID)),
            ),
        )
    assert excinfo.value.rule == "api.explanation_outcome_mismatch"
    assert other_run.run_id == OTHER_RUN_ID


def test_an_explanation_refuses_to_read_a_verdict_the_payload_says_was_never_graded() -> None:
    """``verdict`` is only read when ``graded`` says a verdict exists.

    A payload that carries a verdict string *and* says it graded nothing is
    self-contradictory, and the honest reading is the one the flag states. Trusting
    the string would let a half-written payload manufacture a graded failure and
    therefore a root cause.
    """
    contradictory = _graded_payload(Verdict.DEGRADED_BEYOND_TOLERANCE)
    contradictory["graded"] = False
    evidence = EvidenceReference.of(_envelope(steady_state=contradictory))

    report = explain_run(run=RunResource.of(_record()), evidence=evidence)

    assert report.graded_verdict is None
    assert report.root_failure_claims == ()


def test_an_observation_reference_may_not_name_nothing() -> None:
    with pytest.raises(ValidationError):
        ObservationRef(kind=ObservationKind.ENVELOPE, key="")
    with pytest.raises(InvariantViolationError) as excinfo:
        ObservationRef(kind=ObservationKind.ENVELOPE, key="   ")
    assert excinfo.value.rule == "api.observation_key_not_blank"
    assert str(_ref(key="report-1")) == "envelope:report-1"


def test_an_explanation_reads_an_unrecognised_verdict_as_ungraded_rather_than_as_a_pass() -> None:
    payload = _graded_payload(Verdict.DEGRADED_BEYOND_TOLERANCE)
    payload["verdict"] = "some-future-verdict"
    evidence = EvidenceReference.of(_envelope(steady_state=payload))

    report = explain_run(run=RunResource.of(_record()), evidence=evidence)

    assert report.graded_verdict is None
    assert report.root_failure_claims == ()


# ── executive numbers: every one carries the evidence it was counted from ──────


def test_executive_summary_partitions_the_linked_runs_and_cites_each_bucket() -> None:
    passing = RunResource.of(_record(RUN_ID, verdict=RunVerdict.PASS))
    degraded = RunResource.of(
        _record(OTHER_RUN_ID, plan=_plan(OTHER_RUN_ID), verdict=RunVerdict.PASS)
    )
    degraded_evidence = EvidenceReference.of(
        _envelope(
            run_id=OTHER_RUN_ID,
            steady_state=_graded_payload(Verdict.DEGRADED_WITHIN_TOLERANCE, OTHER_RUN_ID),
        )
    )

    summary = summarise(
        [passing, degraded],
        {
            RUN_ID: EvidenceReference.of(
                _envelope(steady_state=_graded_payload(Verdict.AS_HYPOTHESISED))
            ),
            OTHER_RUN_ID: degraded_evidence,
        },
    )

    assert summary.number_for(ExecutiveMetric.RUNS_TOTAL).value == 2.0
    assert summary.number_for(ExecutiveMetric.RUNS_PASSED).value == 1.0
    assert summary.number_for(ExecutiveMetric.RUNS_DEGRADED).value == 1.0
    assert summary.number_for(ExecutiveMetric.RUNS_FAILED).value == 0.0
    assert summary.number_for(ExecutiveMetric.SERVICES_TESTED).value == 1.0
    assert summary.unlinked_runs == ()
    # The partition is exhaustive and disjoint, which is why it is checkable.
    total = summary.number_for(ExecutiveMetric.RUNS_TOTAL).value
    parts = sum(
        summary.number_for(metric).value or 0.0
        for metric in (
            ExecutiveMetric.RUNS_PASSED,
            ExecutiveMetric.RUNS_DEGRADED,
            ExecutiveMetric.RUNS_FAILED,
        )
    )
    assert parts == total


def test_a_bounded_degradation_is_degraded_and_a_broken_bound_is_failed() -> None:
    within = RunResource.of(_record(RUN_ID, verdict=RunVerdict.PASS))
    within_summary = summarise(
        [within],
        {
            RUN_ID: EvidenceReference.of(
                _envelope(steady_state=_graded_payload(Verdict.DEGRADED_WITHIN_TOLERANCE))
            )
        },
    )
    assert within_summary.number_for(ExecutiveMetric.RUNS_DEGRADED).value == 1.0
    assert within_summary.number_for(ExecutiveMetric.RUNS_FAILED).value == 0.0

    beyond = RunResource.of(_record(RUN_ID, verdict=RunVerdict.PASS))
    beyond_summary = summarise(
        [beyond],
        {
            RUN_ID: EvidenceReference.of(
                _envelope(steady_state=_graded_payload(Verdict.DEGRADED_BEYOND_TOLERANCE))
            )
        },
    )
    # beyond-tolerance is a broken bound, not "some movement": filing it under
    # degraded would tell a board a tolerance was exceeded as though it were fine.
    assert beyond_summary.number_for(ExecutiveMetric.RUNS_FAILED).value == 1.0
    assert beyond_summary.number_for(ExecutiveMetric.RUNS_DEGRADED).value == 0.0


def test_a_run_that_passed_while_nothing_was_graded_is_not_counted_as_a_pass() -> None:
    summary = summarise(
        [RunResource.of(_record(verdict=RunVerdict.PASS))],
        {RUN_ID: EvidenceReference.of(_envelope(steady_state={"graded": False, "verdict": None}))},
    )
    assert summary.number_for(ExecutiveMetric.RUNS_PASSED).value == 0.0
    assert summary.number_for(ExecutiveMetric.RUNS_FAILED).value == 1.0


def test_a_run_with_no_envelope_is_named_and_counts_nowhere() -> None:
    linked = RunResource.of(_record(RUN_ID))
    orphan = RunResource.of(_record(OTHER_RUN_ID, plan=_plan(OTHER_RUN_ID)))

    summary = summarise(
        [linked, orphan],
        {RUN_ID: EvidenceReference.of(_envelope(steady_state=_graded_payload(Verdict.NO_EFFECT)))},
    )

    assert summary.number_for(ExecutiveMetric.RUNS_TOTAL).value == 1.0
    assert [entry.run_id for entry in summary.unlinked_runs] == [OTHER_RUN_ID]
    assert "no evidence envelope" in summary.unlinked_runs[0].reason
    assert summary.unlinked_runs[0] == UnlinkedRun(
        run_id=OTHER_RUN_ID, reason=summary.unlinked_runs[0].reason
    )


def test_a_run_whose_envelope_names_another_plan_is_unlinked_not_miscounted() -> None:
    agreeing = RunResource.of(_record(RUN_ID, verdict=RunVerdict.PASS))
    mismatched_run = RunResource.of(_record(OTHER_RUN_ID, plan=_plan(OTHER_RUN_ID)))
    ungraded = {"graded": False, "verdict": None}

    summary = summarise(
        [agreeing, mismatched_run],
        {
            RUN_ID: EvidenceReference.of(_envelope(steady_state=ungraded)),
            # The envelope is filed under this run id but was sealed against a plan
            # the run did not execute. Counting it would attribute another plan's
            # evidence to this run's number.
            OTHER_RUN_ID: EvidenceReference.of(
                _envelope(run_id=OTHER_RUN_ID, plan_digest=DIGEST_A, steady_state=ungraded)
            ),
        },
    )

    assert summary.number_for(ExecutiveMetric.RUNS_TOTAL).value == 1.0
    assert [entry.run_id for entry in summary.unlinked_runs] == [OTHER_RUN_ID]
    assert "not the plan the run executed" in summary.unlinked_runs[0].reason

    with pytest.raises(InvariantViolationError) as excinfo:
        summarise([agreeing], {})
    assert excinfo.value.rule == "api.unlinked_executive_summary"


def test_an_executive_number_without_an_evidence_link_is_unrepresentable() -> None:
    with pytest.raises(ValidationError):
        ExecutiveNumber(metric=ExecutiveMetric.RUNS_PASSED, value=3.0, evidence=())
    with pytest.raises(ValidationError):
        ExecutiveNumber(metric=ExecutiveMetric.RUNS_PASSED, value=3.0, evidence=[])


def test_an_executive_number_must_be_interpretable_and_carry_its_references() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        ExecutiveNumber(
            metric=ExecutiveMetric.RUNS_PASSED,
            value=float("inf"),
            evidence=(_ref(),),
        )
    assert excinfo.value.rule == "api.executive_value_not_finite"

    number = ExecutiveNumber(
        metric=ExecutiveMetric.RUNS_PASSED, value=1.0, unit="runs", evidence=(_ref(),)
    )
    assert number.refs == ("envelope:report-1",)


def test_every_reported_executive_number_carries_at_least_one_evidence_link() -> None:
    summary = summarise(
        [RunResource.of(_record())],
        {
            RUN_ID: EvidenceReference.of(
                _envelope(steady_state=_graded_payload(Verdict.DEGRADED_BEYOND_TOLERANCE))
            )
        },
    )
    assert summary.numbers
    for number in summary.numbers:
        assert number.evidence, f"{number.metric.value} has no evidence link"
        assert number.refs == tuple(str(ref) for ref in number.evidence)
    assert summary.refs


def test_coverage_is_absent_rather_than_zero_until_a_cited_figure_arrives() -> None:
    summary = summarise(
        [RunResource.of(_record())],
        {RUN_ID: EvidenceReference.of(_envelope(steady_state={"graded": False, "verdict": None}))},
    )
    assert summary.number_for(ExecutiveMetric.COVERAGE) is None
    assert ExecutiveMetric.COVERAGE in summary.absent_metrics

    figure = CoverageFigure(
        covered=3,
        total=4,
        cells=(
            ObservationRef(kind=ObservationKind.COVERAGE_CELL, key="checkout|net|container|5s"),
        ),
    )
    with_coverage = summarise(
        [RunResource.of(_record())],
        {RUN_ID: EvidenceReference.of(_envelope(steady_state={"graded": False, "verdict": None}))},
        coverage=figure,
    )
    assert with_coverage.number_for(ExecutiveMetric.COVERAGE).value == 75.0
    assert ExecutiveMetric.COVERAGE not in with_coverage.absent_metrics
    assert json.dumps(with_coverage.to_dict(), allow_nan=False)


def test_a_coverage_figure_that_cannot_be_a_percentage_is_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        CoverageFigure(covered=5, total=4, cells=(_ref(),))
    assert excinfo.value.rule == "api.coverage_exceeds_total"

    with pytest.raises(InvariantViolationError) as excinfo:
        CoverageFigure(covered=0, total=0, cells=(_ref(),))
    assert excinfo.value.rule == "api.coverage_without_cells"

    with pytest.raises(ValidationError):
        CoverageFigure(covered=1, total=2, cells=())


def test_a_summary_reporting_one_metric_twice_is_refused() -> None:
    number = ExecutiveNumber(
        metric=ExecutiveMetric.RUNS_PASSED, value=1.0, evidence=(_ref(),)
    )
    other = ExecutiveNumber(
        metric=ExecutiveMetric.RUNS_PASSED, value=2.0, evidence=(_ref(),)
    )
    with pytest.raises(InvariantViolationError) as excinfo:
        ExecutiveSummary(numbers=(number, other))
    assert excinfo.value.rule == "api.duplicate_executive_metric"


def test_an_empty_executive_summary_is_refused_rather_than_returned_as_zeroes() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        summarise([], {})
    assert excinfo.value.rule == "api.empty_executive_summary"


# ── the envelope versions forward from the CLI's own contract ─────────────────


def _output_schema() -> dict[str, Any]:
    path = Path(api_module.__file__).resolve().parent.parent / "schemas" / "output_v1.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_the_api_envelope_mirrors_the_cli_output_envelope_it_starts_from() -> None:
    schema = _output_schema()
    assert set(ApiEnvelope.model_fields) == set(schema["required"])
    assert set(ApiEnvelope.model_fields) == set(schema["properties"])
    assert schema["properties"]["schema_version"]["const"] == API_SCHEMA_VERSION
    assert set(ApiStatus) == {str(value) for value in schema["properties"]["status"]["enum"]}
    # additionalProperties: false in the schema, extra="forbid" on the model.
    assert schema["additionalProperties"] is False

    envelope = ApiEnvelope.ok({"run_id": RUN_ID}, evidence_refs=("report-run-0001",))
    payload = envelope.to_dict()
    assert set(payload) == set(schema["required"])
    assert json.loads(json.dumps(payload, allow_nan=False))["status"] == "ok"


def test_an_envelope_must_be_honest_about_its_own_status_and_version() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        ApiEnvelope(status=ApiStatus.ERROR)
    assert excinfo.value.rule == "api.error_without_message"

    with pytest.raises(InvariantViolationError) as excinfo:
        ApiEnvelope(status=ApiStatus.OK, errors=("boom",))
    assert excinfo.value.rule == "api.ok_with_errors"

    with pytest.raises(InvariantViolationError) as excinfo:
        ApiEnvelope(schema_version="1.1")
    assert excinfo.value.rule == "api.unsupported_schema"

    with pytest.raises(InvariantViolationError) as blank:
        ApiEnvelope.ok({}, evidence_refs=("  ",))
    assert blank.value.rule == "api.blank_evidence_ref"

    with pytest.raises(InvariantViolationError) as excinfo:
        ApiEnvelope.failed(())
    assert excinfo.value.rule == "api.error_without_message"


# ── the domain law, restated where the module lives ────────────────────────────

_FORBIDDEN_STDLIB = frozenset({"asyncio", "socket", "subprocess", "sqlite3", "pathlib", "os"})
_FORBIDDEN_LAYERS = ("mayhem.toolkit", "mayhem.agents", "mayhem.controller", "mayhem.infra")


def test_api_imports_nothing_the_domain_may_not_import() -> None:
    source = Path(api_module.__file__).read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module)
    assert not imported & _FORBIDDEN_STDLIB
    assert not [name for name in sorted(imported) if name.startswith(_FORBIDDEN_LAYERS)]
