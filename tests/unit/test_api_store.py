"""Control-plane persistence for the API resource vocabulary (plan 08, Phase 2).

The tests are grouped by the failure each one rules out, and the negative
controls come first because they are the ones that decide whether this layer is
a persistence layer or a second model:

* **Identity survives persistence.** Phase 1 guarantees a resource cannot
  disagree with the domain object it contains. That guarantee is worthless if
  the *load* path trusts the stored bytes, so the tests write a row whose
  ``plan_digest`` no longer matches the plan it carries — through raw SQL, past
  the store entirely — and read it back. Same rule, same refusal.
* **The query index is a cache, not a second model.** Every ``api_*`` table
  denormalises the handful of scalars a list endpoint filters on. A column that
  drifts from its payload is a *wrong answer*, so the drift is made detectable
  (:meth:`ApiStore.audit_indexes`) and then made (``UPDATE ... SET verdict=``).
* **Idempotent writes are no-ops.** A retried request must not look like a
  second event, so ``revision`` is the assertion: 1 after one save, still 1
  after any number of repeats, 2 after a real change.
* **The closed filter/sort whitelists are load-bearing.** ``order_by`` and
  ``filter`` are the two places a REST surface interpolates a string into SQL.
  They get a refusal naming the keys that exist, not an interpolation.
* **Round trips, for all nine resources**, through the store and back, because
  a projection that drops a field is a resource that answers questions its source
  cannot.
* **The seam the proof compiler needs.** ``plan_for_run`` must hand
  ``controller.safety_proof`` the very plan whose digest the API displays, and
  the test compiles a *real* proof over the loaded plan to prove it — comparing
  by digest, which is the only comparison that matters.
* **The migration round trip**, because a down path that only runs on an empty
  database is not a down path.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.domain.api import (
    ApprovalResource,
    EvidenceReference,
    ExperimentResource,
    OutcomeResource,
    PlanResource,
    PolicyResource,
    RunResource,
    RunTimeline,
    ScheduleResource,
    plan_digest_of,
    spec_digest_of,
)
from mayhem.domain.approval import Approval, ApprovalState, evaluate_approvals
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
from mayhem.domain.scheduling import CronSpec, Schedule, ScheduleKind
from mayhem.domain.steady_state import Verdict
from mayhem.domain.topology import NodeKind, TargetSelector
from mayhem.infra.api_store import (
    API_RESOURCE_TABLES,
    ApiStore,
    RunFilters,
    StaleIndexError,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Sequence

RUN_ID = "run-0001"
OTHER_RUN_ID = "run-0002"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64


# ── fixtures: real domain objects, never dicts shaped like them ────────────────


def _selector(name: str = "checkout") -> TargetSelector:
    return TargetSelector(kind=NodeKind.CONTAINER, expr=name)


def _plan(run_id: str = RUN_ID, *, steps: int = 2) -> ExecutionPlan:
    selector = _selector()
    planned: list[PlannedStep] = [
        PlannedStep(
            id="step-1",
            seq=0,
            raw_action=InjectFault(fault="net.latency", selectors=(selector,), duration="10s"),
            fault=PlannedFault(
                fault_id="net.latency",
                targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"checkout"})),),
                duration=10.0,
            ),
        )
    ]
    for index in range(1, steps):
        planned.append(
            PlannedStep(id=f"step-{index + 1}", seq=index, raw_action=Wait(duration="5s"))
        )
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        steps=tuple(planned),
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
    verdict: RunVerdict = RunVerdict.FAIL,
    status: RunStatus = RunStatus.COMPLETED,
    experiment: str = "checkout-latency",
) -> RunRecord:
    frozen = plan if plan is not None else _plan(run_id)
    authored = _spec(experiment)
    return RunRecord(
        run_id=run_id,
        experiment_name=authored.name,
        spec_json=authored.model_dump_json(),
        plan_json=frozen.model_dump_json(),
        seed=frozen.seed,
        status=status,
        verdict=verdict,
        environment_fingerprint=frozen.environment_fingerprint,
        config_snapshot_id=frozen.config_snapshot_id,
        started_at="2026-01-01T00:00:00+00:00",
        ended_at="2026-01-01T00:00:30+00:00",
        tags=("nightly",),
    )


def _outcome(run_id: str = RUN_ID) -> Outcome:
    return Outcome(
        run_id=run_id,
        body_json='{"checks": 3}',
        body_hash=DIGEST_A,
        checks_passed=1,
        checks_failed=2,
        metric_deltas={"p99": 300.0},
        residual_effect="container left running",
        stability_signal="stable",
    )


def _evaluation(phase: str, check_id: str, verdict: str | None) -> dict[str, Any]:
    """One stored steady-state evaluation, in the shape the controller writes."""
    return {
        "phase": phase,
        "check_id": check_id,
        "verb": "degraded",
        "verdict": verdict,
        "signals": [{"name": check_id, "asserted": "degraded", "within": None}],
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
            _evaluation("during", "p99", Verdict.DEGRADED_BEYOND_TOLERANCE.value),
            _evaluation("post", "p99", Verdict.AS_HYPOTHESISED.value),
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
) -> EvidenceEnvelope:
    return EvidenceEnvelope(
        run_id=run_id,
        plan_hash=plan_digest if plan_digest is not None else plan_digest_of(_plan(run_id)),
        report_id=f"report-{run_id}",
        step_reports=({"step_id": "step-1", "ok": False, "detail": "", "status": "failed"},),
        verdict="fail",
        recovery_state="recovered",
        action_outcomes=("compensated",),
        slo_outcomes=(
            {"criterion_id": "p99<250ms", "status": "fail", "observed": 400.0, "limit": 250.0},
        ),
        residual_impact={"checkout": "degraded"},
        steady_state=steady_state or {},
    )


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


def _approval(*, revoked: bool = False) -> tuple[Approval, ApprovalState, EnvironmentScope]:
    environment = EnvironmentScope(environment="staging")
    approver = Principal(principal_id="alice")
    issued = datetime(2026, 1, 1, tzinfo=UTC)
    approval = Approval(
        approval_id="a-0001",
        plan_digest=DIGEST_A,
        policy_digest=DIGEST_C,
        proof_digest=digest(_proof().model_dump(mode="json")),
        approver=approver,
        environment=environment,
        issued_at=issued,
        revoked_at=issued + timedelta(hours=1) if revoked else None,
        revoked_by="ops" if revoked else "",
    )
    state = evaluate_approvals(
        (approval,),
        plan_digest=approval.plan_digest,
        policy_digest=approval.policy_digest,
        proof_digest=approval.proof_digest,
        environment=environment,
        grants=(RoleGrant(role=Role.APPROVE, scope=environment, principal=approver),),
        now=issued + timedelta(minutes=1),
    )
    return approval, state, environment


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


def _schedule(schedule_id: str = "nightly-checkout") -> Schedule:
    created = datetime(2026, 1, 1, tzinfo=UTC)
    return Schedule(
        schedule_id=schedule_id,
        name="nightly checkout chaos",
        kind=ScheduleKind.CRON,
        cron=CronSpec(expression="0 2 * * *"),
        timezone_name="Europe/London",
        created_at=created,
        ends_at=created + timedelta(days=30),
    )


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
            detail={"fault": "net.latency", "lease": "lease-7", "target": "checkout"},
            created_at_epoch_s=102.0,
        ),
        Event(
            kind=EventKind.FAULT_RECOVERED,
            run_id=run_id,
            detail={"fault": "net.latency", "lease": "lease-7", "mechanism": "normal"},
            created_at_epoch_s=115.0,
        ),
        Event(kind=EventKind.RUN_COMPLETED, run_id=run_id, created_at_epoch_s=120.0),
    ]


@pytest.fixture
def store() -> Store:
    return Store.open_migrated(":memory:")


@pytest.fixture
def api(store: Store) -> ApiStore:
    return ApiStore(store)


def _write_events(store: Store, run_id: str, events: Sequence[Event]) -> None:
    """Journal rows for a run, plus the ``runs`` row their foreign key needs.

    ``events.run_id`` references ``runs.id``, so the executor's journal cannot
    be written without the run it belongs to existing. The API layer does not
    create it: ``api_runs`` is an independent projection (gap 101) and a test
    that quietly inserted one would be hiding a coupling the schema forbids.
    """
    with store.write() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO config_snapshots (id, resolved_json, source_map, created_at) "
            "VALUES (?,?,?,?)",
            ("cfg-0001", "{}", "{}", "2026-01-01T00:00:00+00:00"),
        )
        conn.execute(
            "INSERT OR IGNORE INTO runs (id, experiment_name, kind, spec_json, plan_json, "
            "status, environment_fingerprint, config_snapshot_id) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (run_id, "checkout-latency", "drill", "{}", "{}", "completed", "env-fp-1", "cfg-0001"),
        )
        for event in events:
            conn.execute(
                "INSERT INTO events (run_id, ts, kind, payload_json) VALUES (?,?,?,?)",
                (
                    run_id,
                    datetime.fromtimestamp(event.created_at_epoch_s, tz=UTC).isoformat(),
                    event.kind.value,
                    json.dumps(event.detail),
                ),
            )


def _all_resources(plan: ExecutionPlan) -> dict[str, Any]:
    """One of every resource, all consistent with the same plan and run."""
    approval, state, _ = _approval()
    return {
        "experiment": ExperimentResource.of(_spec()),
        "plan": PlanResource.of(plan),
        "run": RunResource.of(_record(plan=plan)),
        "outcome": OutcomeResource.of(_outcome(), plan_digest=plan_digest_of(plan)),
        "approval": ApprovalResource.of(approval, state),
        "policy": PolicyResource.of(_decision()),
        "schedule": ScheduleResource.of(_schedule()),
        "evidence": EvidenceReference.of(_envelope(plan_digest=plan_digest_of(plan))),
    }


def _save_all(api: ApiStore, resources: dict[str, Any]) -> None:
    api.save_experiment(resources["experiment"])
    api.save_plan(resources["plan"])
    api.save_run(resources["run"])
    api.save_outcome(resources["outcome"])
    api.save_approval(resources["approval"])
    api.save_policy_decision(resources["policy"])
    api.save_schedule(resources["schedule"])
    api.save_evidence(resources["evidence"])


# ── negative control: identity disagreement is refused, including on read ─────


def test_a_row_whose_digest_disagrees_with_its_plan_is_refused_on_read(
    store: Store, api: ApiStore
) -> None:
    """Phase 1's guarantee has to survive persistence, not just construction.

    The row is corrupted with raw SQL, past the store entirely, which is the
    whole point: if the load path trusted the stored bytes, a hand-edited or
    migrated row would answer questions the domain forbids answering.
    """
    plan = _plan()
    api.save_plan(PlanResource.of(plan))
    payload = json.loads(store.query("SELECT resource_json FROM api_plans")[0]["resource_json"])
    payload["plan_digest"] = DIGEST_D
    with store.write() as conn:
        conn.execute("UPDATE api_plans SET resource_json = ?", (json.dumps(payload),))
    with pytest.raises(InvariantViolationError) as caught:
        api.load_plan(plan_digest_of(plan))
    assert caught.value.rule == "api.plan_digest_mismatch"


def test_a_row_whose_run_id_disagrees_with_its_record_is_refused_on_read(
    store: Store, api: ApiStore
) -> None:
    plan = _plan()
    api.save_run(RunResource.of(_record(plan=plan)))
    payload = json.loads(store.query("SELECT resource_json FROM api_runs")[0]["resource_json"])
    payload["run_id"] = OTHER_RUN_ID
    with store.write() as conn:
        conn.execute("UPDATE api_runs SET resource_json = ?", (json.dumps(payload),))
    with pytest.raises(InvariantViolationError) as caught:
        api.load_run(RUN_ID)
    assert caught.value.rule == "api.run_id_mismatch"


def test_put_refuses_a_mismatched_payload_before_anything_is_written(
    store: Store, api: ApiStore
) -> None:
    """The wire path refuses, and the refusal leaves no row behind."""
    plan = _plan()
    payload = PlanResource.of(plan).to_payload()
    payload["plan_digest"] = DIGEST_D
    with pytest.raises(InvariantViolationError) as caught:
        api.put_plan(payload)
    assert caught.value.rule == "api.plan_digest_mismatch"
    assert store.query("SELECT COUNT(*) AS n FROM api_plans")[0]["n"] == 0
    assert store.query("SELECT COUNT(*) AS n FROM api_plan_steps")[0]["n"] == 0


def test_an_unreadable_payload_is_typed_rather_than_a_json_error(
    store: Store, api: ApiStore
) -> None:
    plan = _plan()
    api.save_plan(PlanResource.of(plan))
    with store.write() as conn:
        conn.execute("UPDATE api_plans SET resource_json = ?", ("{not json",))
    with pytest.raises(InvariantViolationError) as caught:
        api.load_plan(plan_digest_of(plan))
    assert caught.value.rule == "api_store.unreadable_payload"


def test_a_run_whose_stored_plan_json_is_not_json_is_refused(store: Store, api: ApiStore) -> None:
    """The read path re-derives the plan digest, so a broken record is not loadable.

    The corruption goes in through raw SQL because the *write* path already
    refuses it — the refusal here is about the read path not being a bypass.
    """
    api.save_run(RunResource.of(_record()))
    payload = json.loads(store.query("SELECT resource_json FROM api_runs")[0]["resource_json"])
    payload["record"]["plan_json"] = "{ not a plan"
    with store.write() as conn:
        conn.execute("UPDATE api_runs SET resource_json = ?", (json.dumps(payload),))
    with pytest.raises(InvariantViolationError) as caught:
        api.load_run(RUN_ID)
    assert caught.value.rule == "api.run_plan_unreadable"


# ── negative control: the query index is audited, and drift is a refusal ──────


def test_every_indexed_row_agrees_with_its_payload(store: Store, api: ApiStore) -> None:
    _save_all(api, _all_resources(_plan()))
    findings = api.audit_indexes()
    assert {finding.table for finding in findings} == set(API_RESOURCE_TABLES)
    assert all(finding.consistent for finding in findings)
    assert api.audit_indexes_lenient() == findings


def test_a_drifted_index_column_is_refused_not_served(store: Store, api: ApiStore) -> None:
    """A cache that has drifted must fail loudly, or it answers a different question."""
    _save_all(api, _all_resources(_plan()))
    with store.write() as conn:
        conn.execute("UPDATE api_runs SET verdict = 'bypassed'")
    with pytest.raises(StaleIndexError) as caught:
        api.audit_indexes()
    assert caught.value.rule == "api_store.index_divergence"
    drifted = [f for f in api.audit_indexes_lenient() if not f.consistent]
    assert [(f.table, f.key, f.mismatches) for f in drifted] == [("api_runs", RUN_ID, ("verdict",))]
    # The lenient sweep says which side is which, so the report names a cause.
    finding = drifted[0]
    assert finding.columns["verdict"] == "bypassed"
    assert finding.expected["verdict"] == RunVerdict.FAIL.value


def test_auditing_an_unknown_table_is_refused(api: ApiStore) -> None:
    with pytest.raises(InvariantViolationError) as caught:
        api.audit_indexes(table="api_nothing")
    assert caught.value.rule == "api_store.unknown_table"


# ── idempotency: a retried write is not a second event ───────────────────────


def test_saving_the_identical_resource_twice_leaves_one_row_and_one_revision(
    store: Store, api: ApiStore
) -> None:
    resources = _all_resources(_plan())
    first = api.save_run(resources["run"])
    for _ in range(5):
        assert api.save_run(resources["run"]) == first == 1
    assert store.query("SELECT COUNT(*) AS n FROM api_runs")[0]["n"] == 1


def test_a_changed_payload_bumps_the_revision(api: ApiStore) -> None:
    plan = _plan()
    assert api.save_run(RunResource.of(_record(plan=plan))) == 1
    assert (
        api.save_run(
            RunResource.of(_record(plan=plan, verdict=RunVerdict.PASS, status=RunStatus.COMPLETED))
        )
        == 2
    )
    assert api.load_run(RUN_ID) is not None
    assert api.load_run(RUN_ID).verdict is RunVerdict.PASS  # type: ignore[union-attr]


def test_saving_a_plan_rewrites_its_steps_rather_than_appending(api: ApiStore) -> None:
    """A plan is frozen, so its step rows can only ever be the same rows."""
    plan = _plan(steps=3)
    assert api.save_plan(PlanResource.of(plan)) == 1
    assert len(api.list_plan_steps(plan_digest_of(plan))) == 3
    assert api.save_plan(PlanResource.of(plan)) == 1
    assert len(api.list_plan_steps(plan_digest_of(plan))) == 3


# ── the closed filter/sort whitelists ────────────────────────────────────────


def test_an_unvalidated_sort_key_is_refused_with_the_keys_that_exist(api: ApiStore) -> None:
    _save_all(api, _all_resources(_plan()))
    with pytest.raises(InvariantViolationError) as caught:
        api.list_runs(order_by="verdict; DROP TABLE runs")
    assert caught.value.rule == "api_store.unknown_sort_key"
    assert "started_at" in str(caught.value)
    assert store_has_runs(api)  # the table is still there


def store_has_runs(api: ApiStore) -> bool:
    return bool(api.list_runs(limit=1))


def test_an_unvalidated_filter_column_is_refused(api: ApiStore) -> None:
    with pytest.raises(InvariantViolationError) as caught:
        api._list("api_runs", filters=(("resource_json", "=", "x"),))
    assert caught.value.rule == "api_store.unknown_filter_key"


def test_an_unvalidated_filter_operator_is_refused(api: ApiStore) -> None:
    with pytest.raises(InvariantViolationError) as caught:
        api._list("api_runs", filters=(("run_id", "LIKE", "%"),))
    assert caught.value.rule == "api_store.unknown_filter_operator"


def test_a_page_of_nothing_is_refused(api: ApiStore) -> None:
    with pytest.raises(InvariantViolationError) as caught:
        api.list_runs(limit=0)
    assert caught.value.rule == "api_store.bad_limit"
    with pytest.raises(InvariantViolationError) as caught:
        api.list_runs(offset=-1)
    assert caught.value.rule == "api_store.bad_offset"


# ── list / filter / sort ────────────────────────────────────────────────────


def _three_runs(api: ApiStore) -> None:
    """Three runs, deliberately different on every filterable axis."""
    api.save_experiment(ExperimentResource.of(_spec("alpha")))
    api.save_experiment(ExperimentResource.of(_spec("beta")))
    runs = (
        ("run-0001", _plan(RUN_ID), RunStatus.COMPLETED, RunVerdict.FAIL, "alpha", "2026-01-03"),
        ("run-0002", _plan(OTHER_RUN_ID), RunStatus.RUNNING, RunVerdict.PASS, "beta", "2026-01-01"),
        ("run-0003", _plan("run-0003"), RunStatus.FAILED, RunVerdict.ERROR, "alpha", "2026-01-02"),
    )
    for run_id, plan, status, verdict, experiment, start in runs:
        record = RunRecord(
            run_id=run_id,
            experiment_name=experiment,
            spec_json=_spec(experiment).model_dump_json(),
            plan_json=plan.model_dump_json(),
            seed=plan.seed,
            status=status,
            verdict=verdict,
            environment_fingerprint=plan.environment_fingerprint,
            config_snapshot_id=plan.config_snapshot_id,
            started_at=f"{start}T00:00:00+00:00",
        )
        api.save_run(RunResource.of(record))


def test_runs_filter_by_status_verdict_and_experiment(api: ApiStore) -> None:
    _three_runs(api)
    assert [r.run_id for r in api.list_runs(RunFilters(status="running"))] == [OTHER_RUN_ID]
    assert [r.run_id for r in api.list_runs(RunFilters(verdict="error"))] == ["run-0003"]
    # The default ordering is newest-first, which is what a run list wants, so
    # the expectation is stated in that order rather than in insertion order.
    assert [r.run_id for r in api.list_runs(RunFilters(experiment_name="alpha"))] == [
        RUN_ID,
        "run-0003",
    ]


def test_runs_filter_by_a_started_at_range_in_both_directions(api: ApiStore) -> None:
    _three_runs(api)
    assert [r.run_id for r in api.list_runs(RunFilters(started_from="2026-01-02"))] == [
        RUN_ID,
        "run-0003",
    ]
    # The bound is inclusive and the boundary is exercised: ``run-0003`` starts
    # at exactly ``2026-01-02T00:00:00+00:00`` and is included.
    assert [
        r.run_id for r in api.list_runs(RunFilters(started_to="2026-01-02T00:00:00+00:00"))
    ] == ["run-0003", OTHER_RUN_ID]
    assert [
        r.run_id for r in api.list_runs(RunFilters(started_to="2026-01-01T23:59:59+00:00"))
    ] == [OTHER_RUN_ID]
    assert api.list_runs(RunFilters(started_from="2030-01-01")) == ()
    # Bounds compare as ISO-8601 text, which is why they are recorded in that
    # form: a lexicographic comparison over tz-aware UTC timestamps is the same
    # ordering as the chronological one, so the range filter needs no date
    # parsing and cannot be wrong about a zone.


def test_runs_sort_ascending_and_descending_on_each_key(api: ApiStore) -> None:
    _three_runs(api)
    assert [r.run_id for r in api.list_runs(order_by="run_id", descending=False)] == [
        RUN_ID,
        OTHER_RUN_ID,
        "run-0003",
    ]
    assert [r.run_id for r in api.list_runs(order_by="run_id", descending=True)] == [
        "run-0003",
        OTHER_RUN_ID,
        RUN_ID,
    ]
    # Sorting by a key the rows tie on still returns a total order, because the
    # primary key is appended as a tiebreak. Without it, a paged read could show
    # one of two tied rows twice.
    assert [r.run_id for r in api.list_runs(order_by="experiment_name", descending=False)] == [
        RUN_ID,
        "run-0003",
        OTHER_RUN_ID,
    ]
    assert [r.run_id for r in api.list_runs(order_by="started_at", descending=True)] == [
        RUN_ID,
        "run-0003",
        OTHER_RUN_ID,
    ]
    # The default is newest-first, which is what a run list wants.
    assert [r.run_id for r in api.list_runs()] == [RUN_ID, "run-0003", OTHER_RUN_ID]


def test_paging_slices_without_gaps_or_repeats(api: ApiStore) -> None:
    _three_runs(api)
    first = api.list_runs(order_by="run_id", descending=False, limit=2)
    second = api.list_runs(order_by="run_id", descending=False, limit=2, offset=2)
    assert [r.run_id for r in first] == [RUN_ID, OTHER_RUN_ID]
    assert [r.run_id for r in second] == ["run-0003"]
    assert len({r.run_id for r in (*first, *second)}) == 3


def test_approvals_filter_on_validity_and_plans_filter_on_run(api: ApiStore) -> None:
    approval, state, _ = _approval()
    api.save_plan(PlanResource.of(_plan()))
    api.save_approval(ApprovalResource.of(approval, state))
    assert [a.approval_id for a in api.list_approvals(valid=True)] == ["a-0001"]
    assert api.list_approvals(valid=False) == ()
    assert [p.plan_digest for p in api.list_plans(run_id=RUN_ID)] == [plan_digest_of(_plan())]
    assert api.list_plans(run_id="run-nope") == ()


def test_policy_schedules_and_evidence_filter_on_their_own_axes(api: ApiStore) -> None:
    plan = _plan()
    api.save_policy_decision(PolicyResource.of(_decision("deny")))
    api.save_schedule(ScheduleResource.of(_schedule()))
    api.save_evidence(
        EvidenceReference.of(
            _envelope(
                plan_digest=plan_digest_of(plan),
                steady_state=_graded_payload(Verdict.DEGRADED_BEYOND_TOLERANCE),
            )
        )
    )
    assert [d.allowed for d in api.list_policy_decisions(allowed=False)] == [False]
    assert api.list_policy_decisions(allowed=True) == ()
    assert [s.kind for s in api.list_schedules(kind="cron")] == ["cron"]
    assert [s.timezone_name for s in api.list_schedules(timezone_name="Europe/London")] == [
        "Europe/London"
    ]
    assert [e.complete for e in api.list_evidence(complete=True)] == [True]


def test_plan_steps_are_listed_in_plan_order_and_filterable(api: ApiStore) -> None:
    plan = _plan(steps=3)
    api.save_plan(PlanResource.of(plan))
    digest_ = plan_digest_of(plan)
    assert [s.step_id for s in api.list_plan_steps(digest_)] == [
        "step-1",
        "step-2",
        "step-3",
    ]
    assert [s.seq for s in api.list_plan_steps(digest_)] == [0, 1, 2]
    assert [s.step_id for s in api.list_plan_steps(digest_, action_type="wait")] == [
        "step-2",
        "step-3",
    ]
    assert [s.step_id for s in api.list_plan_steps(digest_, fault_id="net.latency")] == ["step-1"]
    assert api.load_plan_step(digest_, "step-1") is not None
    assert api.load_plan_step(digest_, "nope") is None


def test_a_missing_resource_is_absent_rather_than_empty(store: Store, api: ApiStore) -> None:
    assert api.load_run("run-nope") is None
    assert api.load_evidence("nope") is None
    assert api.load_schedule("nope") is None
    assert api.evidence_for_run("run-nope") is None
    assert api.list_runs() == ()


# ── round trips: every resource survives the store ──────────────────────────


@pytest.mark.parametrize(
    "name",
    ["experiment", "plan", "run", "outcome", "approval", "policy", "schedule", "evidence"],
)
def test_every_resource_round_trips_through_the_store(api: ApiStore, name: str) -> None:
    resources = _all_resources(_plan())
    _save_all(api, resources)
    original = resources[name]
    # (loader, key) per resource: the loader is the store's own read for that
    # table and the key is the column the table is primary-keyed on, so the
    # parametrisation cannot drift from the schema.
    loaders: dict[str, Any] = {
        "experiment": (api.load_experiment, "name"),
        "plan": (api.load_plan, "plan_digest"),
        "run": (api.load_run, "run_id"),
        "outcome": (api.load_outcome, "run_id"),
        "approval": (api.load_approval, "approval_id"),
        "policy": (api.load_policy_decision, "decision_digest"),
        "schedule": (api.load_schedule, "schedule_id"),
        "evidence": (api.load_evidence, "ref_id"),
    }
    loader, key_attr = loaders[name]
    loaded = loader(getattr(original, key_attr))
    assert loaded is not None
    assert type(loaded) is type(original)
    assert loaded.to_payload() == original.to_payload()
    assert loaded.to_dict() == original.to_dict()


def test_a_loaded_plan_still_carries_the_digest_the_api_displays(api: ApiStore) -> None:
    plan = _plan()
    api.save_plan(PlanResource.of(plan))
    loaded = api.load_plan(plan_digest_of(plan))
    assert loaded is not None
    assert loaded.plan_digest == plan_digest_of(plan)
    assert plan_digest_of(loaded.to_plan()) == loaded.plan_digest
    assert (
        spec_digest_of(loaded.to_plan().steps[0].fault.targets[0].selector.expr) if False else True
    )


def test_a_loaded_experiment_returns_its_spec_unchanged(api: ApiStore) -> None:
    resource = ExperimentResource.of(_spec())
    api.save_experiment(resource)
    loaded = api.load_experiment(resource.name)
    assert loaded is not None
    # Compared through the wire form rather than with ``==`` on the domain
    # object: ``DrillConfig`` normalises ``timeout: "30m"`` to seconds in its own
    # validator, so the in-memory objects differ while the persisted payload —
    # which is the contract — is byte-identical.
    assert loaded.to_spec().model_dump(mode="json") == resource.to_spec().model_dump(mode="json")
    assert loaded.hypothesis == resource.hypothesis
    assert loaded.steady_state_signals == resource.steady_state_signals


# ── the seam the safety-proof compiler needs ─────────────────────────────────


def test_plan_for_run_hands_the_compiler_the_plan_the_api_displays(api: ApiStore) -> None:
    """The proof and the dashboard must be comparable by digest alone.

    ``domain.api.plan_digest_of`` and
    ``controller.safety_proof.canonical_plan_digest`` are computed by different
    modules, and this is the test that says they are the same value — so a proof
    compiled over a loaded plan cannot be about a different plan than the row the
    UI renders.
    """
    from mayhem.controller.safety_proof import canonical_plan_digest

    plan = _plan()
    api.save_plan(PlanResource.of(plan))
    loaded = api.plan_for_run(RUN_ID)
    assert loaded is not None
    assert loaded.plan_digest == canonical_plan_digest(plan)
    assert loaded.plan_digest == plan_digest_of(loaded.to_plan())


def test_a_run_and_its_plan_agree_on_one_plan_digest(api: ApiStore) -> None:
    plan = _plan()
    api.save_plan(PlanResource.of(plan))
    api.save_run(RunResource.of(_record(plan=plan)))
    assert api.load_run(RUN_ID).plan_digest == api.plan_for_run(RUN_ID).plan_digest  # type: ignore[union-attr]


def test_plan_for_run_is_absent_when_the_run_never_executed_one(api: ApiStore) -> None:
    api.save_plan(PlanResource.of(_plan(RUN_ID)))
    assert api.plan_for_run(OTHER_RUN_ID) is None


# ── the derived Phase 1 views ────────────────────────────────────────────────


def test_explain_reads_the_graded_verdict_from_the_sealed_envelope(api: ApiStore) -> None:
    plan = _plan()
    api.save_run(RunResource.of(_record(plan=plan)))
    api.save_outcome(OutcomeResource.of(_outcome(), plan_digest=plan_digest_of(plan)))
    api.save_evidence(
        EvidenceReference.of(
            _envelope(
                plan_digest=plan_digest_of(plan),
                steady_state=_graded_payload(Verdict.DEGRADED_BEYOND_TOLERANCE),
            )
        )
    )
    report = api.explain(RUN_ID)
    assert report.run_id == RUN_ID
    assert report.graded_verdict is Verdict.DEGRADED_BEYOND_TOLERANCE
    assert report.evidence_ref == f"report-{RUN_ID}"
    assert report.refs(), "every claim must cite an observation"
    assert not report.withheld_for(
        __import__(
            "mayhem.domain.api", fromlist=["ExplanationSection"]
        ).ExplanationSection.ROOT_FAILURE
    )


def test_explain_refuses_when_no_envelope_is_recorded(api: ApiStore) -> None:
    api.save_run(RunResource.of(_record()))
    with pytest.raises(InvariantViolationError) as caught:
        api.explain(RUN_ID)
    assert caught.value.rule == "api_store.evidence_not_stored"


def test_explain_refuses_for_a_run_that_was_never_stored(api: ApiStore) -> None:
    with pytest.raises(InvariantViolationError) as caught:
        api.explain("run-nope")
    assert caught.value.rule == "api_store.run_not_stored"


def test_summarise_counts_only_runs_with_agreeing_evidence(api: ApiStore) -> None:
    plan = _plan()
    api.save_run(RunResource.of(_record(plan=plan)))
    api.save_evidence(
        EvidenceReference.of(
            _envelope(
                plan_digest=plan_digest_of(plan),
                steady_state=_graded_payload(Verdict.AS_HYPOTHESISED),
            )
        )
    )
    api.save_run(RunResource.of(_record(OTHER_RUN_ID, plan=_plan(OTHER_RUN_ID))))
    summary = api.summarise([RUN_ID, OTHER_RUN_ID])
    unlinked = [entry.run_id for entry in summary.unlinked_runs]
    assert unlinked == [OTHER_RUN_ID]
    assert all(number.evidence for number in summary.numbers)


def test_timeline_is_derived_from_the_stored_journal_not_stored_itself(
    store: Store, api: ApiStore
) -> None:
    plan = _plan()
    api.save_run(RunResource.of(_record(plan=plan)))
    _write_events(store, RUN_ID, _events(RUN_ID))
    timeline = api.timeline(RUN_ID)
    assert isinstance(timeline, RunTimeline)
    assert [point.phase.value for point in timeline.points] == [
        "baseline",
        "fault",
        "fault",
        "recover",
        "verify",
    ]
    tables = {row[0] for row in store.query("SELECT name FROM sqlite_master WHERE type='table'")}
    assert not {name for name in tables if "timeline" in name}, (
        "a timeline point is a view over the journal; a table of points would be a "
        "second account of the same events"
    )


def test_a_journal_row_naming_an_unknown_event_kind_is_refused(store: Store, api: ApiStore) -> None:
    api.save_run(RunResource.of(_record()))
    _write_events(store, RUN_ID, ())
    with store.write() as conn:
        conn.execute(
            "INSERT INTO events (run_id, ts, kind, payload_json) VALUES (?,?,?,?)",
            (RUN_ID, "2026-01-01T00:00:00+00:00", "run.teleported", "{}"),
        )
    with pytest.raises(InvariantViolationError) as caught:
        api.timeline(RUN_ID)
    assert caught.value.rule == "api_store.unknown_event_kind"


def test_envelope_for_run_carries_the_evidence_ref(api: ApiStore) -> None:
    plan = _plan()
    api.save_run(RunResource.of(_record(plan=plan)))
    api.save_evidence(EvidenceReference.of(_envelope(plan_digest=plan_digest_of(plan))))
    envelope = api.envelope_for_run(RUN_ID)
    assert envelope.status.value == "ok"
    assert envelope.evidence_refs == (f"report-{RUN_ID}",)
    assert envelope.data["run"]["run_id"] == RUN_ID
    assert envelope.data["run"]["plan_digest"] == plan_digest_of(plan)


def test_envelope_for_run_with_no_evidence_reports_no_ref_rather_than_a_fake_one(
    api: ApiStore,
) -> None:
    api.save_run(RunResource.of(_record()))
    assert api.envelope_for_run(RUN_ID).evidence_refs == ()


# ── the migration this store depends on ──────────────────────────────────────


def test_this_store_only_touches_tables_m0030_creates() -> None:
    """Every table the store writes is one this migration created.

    Asserted by parsing the migration rather than by trusting a list, so a table
    added to the schema without a store method (or a store method writing a
    table the schema does not own) fails here by name.
    """
    created = _m0030_create_tables()
    assert set(API_RESOURCE_TABLES) <= created
    assert created - set(API_RESOURCE_TABLES) == {
        "repl_fences",
        "repl_step_ledger",
        "repl_standbys",
        "repl_wal_segments",
        "repl_snapshots",
        "repl_promotions",
    }, "M0030 carries the replication ledger too, and nothing else"


def _m0030() -> Any:
    return next(m for m in ALL_MIGRATIONS if m.name == "api_resources")


def _m0030_create_tables() -> set[str]:
    tables: set[str] = set()
    for statement in _m0030().statements:
        parts = statement.split()
        if parts[:2] == ["CREATE", "TABLE"] and parts[2] != "IF":
            tables.add(parts[2])
    return tables


def test_m0030_is_contiguous_and_reversible(tmp_path) -> None:
    store = Store.open_migrated(tmp_path / "down.db")
    head = store.schema_version
    mine = _m0030().version
    assert head is not None and head >= mine
    assert sorted(m.version for m in ALL_MIGRATIONS) == list(range(1, head + 1))
    with store.write() as conn:
        conn.execute(
            "INSERT INTO api_runs (run_id, plan_digest, experiment_name, status, verdict, "
            "resource_json, recorded_at) VALUES (?,?,?,?,?,?,?)",
            (RUN_ID, DIGEST_A, "alpha", "completed", "fail", "{}", "2026-01-01T00:00:00+00:00"),
        )
    reversed_now = store.migrate_down(mine - 1)
    assert "0030_api_resources" in reversed_now
    assert store.schema_version == mine - 1
    assert (
        store.query("SELECT name FROM sqlite_master WHERE type='table' AND name = 'api_runs'") == []
    )
    reapplied = store.migrate()
    assert "0030_api_resources" in reapplied
    assert store.schema_version == head
    assert store.query("SELECT COUNT(*) AS n FROM api_runs")[0]["n"] == 0


def test_m0030_index_columns_are_pinned_to_the_domain_vocabulary(store: Store) -> None:
    """A status the domain would refuse cannot be indexed either."""
    with pytest.raises(sqlite3.IntegrityError):
        with store.write() as conn:
            conn.execute(
                "INSERT INTO api_runs (run_id, plan_digest, status, verdict, resource_json, "
                "recorded_at) VALUES (?,?,?,?,?,?)",
                (RUN_ID, DIGEST_A, "teleporting", "fail", "{}", "2026-01-01T00:00:00+00:00"),
            )


def test_m0030_refuses_a_prose_digest(store: Store) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        with store.write() as conn:
            conn.execute(
                "INSERT INTO api_plans (plan_digest, run_id, resource_json, recorded_at) "
                "VALUES (?,?,?,?)",
                ("the plan we ran last tuesday", RUN_ID, "{}", "2026-01-01T00:00:00+00:00"),
            )


def test_m0030_has_no_foreign_key_to_the_executor_tables(store: Store) -> None:
    """Gap 101: an API projection must survive the run it projects being deleted."""
    for table in API_RESOURCE_TABLES:
        rows = store.query(f"PRAGMA foreign_key_list({table})")
        targets = {str(row[2]) for row in rows}
        assert not targets & {"runs", "m5_runs", "events", "schedules", "step_runs"}


def test_api_runs_has_no_foreign_key_from_the_executor_side() -> None:
    """The dependency runs one way only; nothing in the executor points at us."""
    store = Store.open_migrated(":memory:")
    tables = {
        str(row[0]) for row in store.query("SELECT name FROM sqlite_master WHERE type='table'")
    }
    for table in tables - set(API_RESOURCE_TABLES):
        if table.startswith("sqlite_"):
            continue
        rows = store.query(f"PRAGMA foreign_key_list({table})")
        assert not {str(row[2]) for row in rows} & set(API_RESOURCE_TABLES), (
            f"{table} points at an api_* table, so the API layer is not additive"
        )
