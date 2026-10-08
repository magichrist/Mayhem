"""Plan 10 Phase 3 (engine half) — the preflight that *refuses*.

``test_preflight.py`` proved the v1.0.0 preflight computes a preview.
``test_stop_engine.py`` proved a stop walks the ladder and seals a verdict.
Neither proves the thing this module exists for, which is the sentence in the
plan: "a preflight that warns-and-continues is a bug, not a feature."

So this suite is organised around the ways that sentence can be quietly undone,
each with its own test:

* **an unreachable witness never passes.** Every one of the five external ports,
  deprived of its answer four different ways — unbound, raising, answering
  ``None``, answering in the wrong shape — must report ``UNAVAILABLE``, and
  ``UNAVAILABLE`` must refuse. This is the load-bearing rule: a preflight that
  cannot see an incident manager and reports "no incidents open" is a rubber
  stamp with a checklist printed on it.
* **a gate that checked nothing is refused.** Zero checks is not a pass; it is
  the absence of a pass, and reporting it as one launders a missing check into
  the appearance of a completed one.
* **absence is byte-identical.** ``admit(gate=None, ...)`` reads nothing at all
  — no port, no budget, no field of ``inputs`` — pinned by the golden below to
  the same standard ``test_policy_gate.py`` set when it added an optional gate
  to ``validate_plan``.
* **every real check refuses when its witness is missing.** The matrix asserts a
  specific status *and* a specific evidence reference for each check, because a
  refusal that names nothing cannot be acted on at 3am or re-read a week later.
* **the postflight half agrees with ``domain/stop.py``.** The verdict is read
  through :meth:`mayhem.domain.stop.PostflightReport.verdict` on every call, and
  these tests hold the two to the same answer across clean, dirty, and unknown.

The negative controls each assert a *named* refusal rather than "it raised":
unreachable port, empty check set, a failed preflight that mutates nothing, an
agent that may inject but not undo, a budget-shaped object that governs nothing,
and a policy denial.

Timestamps are injected throughout; nothing here reads a wall clock.
"""

from __future__ import annotations

import dataclasses
import inspect
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from mayhem.agents.capabilities import AgentCapabilities, AgentIdentity, CapabilityKind
from mayhem.controller.preflight_gate import (
    ALL_CHECKS,
    CHECK_AGENT_AVAILABILITY,
    CHECK_AGENT_CAPABILITY,
    CHECK_BACKUP_STATE,
    CHECK_BUDGET_AVAILABLE,
    CHECK_CLUSTER_READY,
    CHECK_DEPENDENCY_HEALTH,
    CHECK_DEPLOYMENT_RECENT,
    CHECK_INCIDENT_ACTIVE,
    CHECK_PLAN_ADMITTED,
    CHECK_POLICY_AVAILABLE,
    CHECK_REPLICATION_HEALTH,
    CHECK_TARGET_HEALTH,
    PORT_CHECKS,
    REAL_CHECKS,
    RESIDUE_CHECK_PREFIX,
    BackupPort,
    BudgetGuard,
    CheckSource,
    CheckStatus,
    ClusterPort,
    DeploymentPort,
    IncidentPort,
    PortObservation,
    PreflightCheck,
    PreflightGate,
    PreflightInputs,
    PreflightPorts,
    PreflightRefusedError,
    PreflightReport,
    ReplicationPort,
    admit,
    check_agent_availability,
    check_agent_capability,
    check_budget_available,
    check_dependency_health,
    check_plan_admitted,
    check_policy_available,
    check_target_health,
    evaluate,
    may_close_clean,
    obligation_verdict,
    open_obligations,
    port_status,
    postflight_report_for,
    postflight_verdict_for,
    refuses_gate,
)
from mayhem.controller.stop_engine import (
    CompensationPath,
    Residue,
    SealedStop,
    StageReceipt,
    StopExecution,
    StopRecord,
    postflight_report,
)
from mayhem.domain.budgets import (
    ResourceBudget,
    ResourceDimension,
    ResourceEstimate,
    ResourceScope,
)
from mayhem.domain.cancellation import CancellationLevel
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.leases import FaultLease, LeaseState, UndoOp, VerifyProbe
from mayhem.domain.policy import PolicyDecision
from mayhem.domain.policy_gate import plan_faults
from mayhem.domain.preflight import Preflight
from mayhem.domain.stop import (
    STOP_FLOW,
    PostflightCheck,
    PostflightReport,
    PostflightVerdict,
    RunState,
    StopCommand,
    StopReason,
    StopScope,
    StopSignal,
    StopStage,
    StopTrigger,
)
from mayhem.domain.stop import CheckStatus as PostflightStatus
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    HostNode,
    NodeKind,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)
from mayhem.infra.budget_enforcement import RunBudgetGuard
from mayhem.infra.metering import ResourceBudgetEnforcer

T0 = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
"""When the gate ran. Injected, so no verdict here depends on the wall clock."""

RUN_ID = "run-1"
STOP_MOMENT = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
HOUR = 3600.0
DURATION_S = 5.0

#: ``PreflightPorts`` field -> (the check it feeds, the protocol, the single
#: method that protocol declares, which ``PreflightInputs`` field it is asked
#: about). One table, so the matrix below cannot accidentally cover four of the
#: five ports and quietly omit the incident manager.
PORT_SHAPES: tuple[tuple[str, str, type, str, str], ...] = (
    ("cluster", CHECK_CLUSTER_READY, ClusterPort, "cluster_ready", "environment"),
    ("incident", CHECK_INCIDENT_ACTIVE, IncidentPort, "active_incidents", "environment"),
    ("deployment", CHECK_DEPLOYMENT_RECENT, DeploymentPort, "recent_deployment", "environment"),
    ("backup", CHECK_BACKUP_STATE, BackupPort, "backup_state", "target"),
    ("replication", CHECK_REPLICATION_HEALTH, ReplicationPort, "replication_health", "environment"),
)


# ==============================================================================
# Fakes — the ports and the budget, both of which record how they were used
# ==============================================================================


class Answering:
    """A port that answers with whatever it was handed, and counts the call.

    ``answer=None`` makes it return ``None`` — the shape a port produces when it
    connected and had nothing to say, which is *not* the same thing as a port
    that reported "nothing to report".
    """

    def __init__(
        self,
        answer: object = None,
        *,
        raise_with: BaseException | None = None,
        name: str = "port",
    ) -> None:
        self._answer = answer
        self._raise_with = raise_with
        self._name = name
        self.calls: list[dict[str, str]] = []

    def __getattr__(self, method: str) -> Any:
        def probe(**kwargs: Any) -> object:
            self.calls.append({"port": self._name, "method": method, **kwargs})
            if self._raise_with is not None:
                raise self._raise_with
            return self._answer

        return probe


@dataclass
class CountingBudget:
    """A budget that is *read* by the gate and never driven.

    Records every read of :attr:`dimensions` and :attr:`estimates`, and any call
    to an ``admit`` method like the real :class:`RunBudgetGuard`'s. Those counts
    are what "the gate reads a budget exactly twice and judges none" is stated
    in, and they are the load-bearing half of the golden below.
    """

    dimensions: tuple[str, ...] = ("cpu",)
    estimates: tuple[int, ...] = (0,)
    reads: list[str] = dataclasses.field(default_factory=list)
    admit_calls: list[Any] = dataclasses.field(default_factory=list)

    def read_dimensions(self) -> tuple[object, ...]:
        self.reads.append("dimensions")
        return self.dimensions

    def read_estimates(self) -> tuple[object, ...]:
        self.reads.append("estimates")
        return self.estimates

    def admit(self, *args: Any, **kwargs: Any) -> None:
        self.admit_calls.append((args, kwargs))


class _ReadOnlyBudget:
    """:class:`CountingBudget` presented under the names the gate actually reads.

    ``dimensions``/``estimates`` have to be properties to satisfy
    :class:`~mayhem.controller.preflight_gate.BudgetGuard`, and the recording has
    to live somewhere, so the recording lives on the side.
    """

    def __init__(self, counter: CountingBudget) -> None:
        self._counter = counter

    @property
    def dimensions(self) -> tuple[object, ...]:
        return self._counter.read_dimensions()

    @property
    def estimates(self) -> tuple[object, ...]:
        return self._counter.read_estimates()


def counting_budget() -> tuple[CountingBudget, BudgetGuard]:
    counter = CountingBudget()
    return counter, _ReadOnlyBudget(counter)


def real_guard(*, with_estimate: bool = True, with_budget: bool = True) -> RunBudgetGuard:
    """The real plan-23 guard, so the gate reads a real ``ResourceDimension``."""
    budgets = (
        (
            ResourceBudget(
                dimension=ResourceDimension.CPU,
                scope=ResourceScope.RUN,
                scope_key=RUN_ID,
                limit=1e6,
                window_s=HOUR,
                description="preflight-gate fixture",
            ),
        )
        if with_budget
        else ()
    )
    estimates = (
        (
            ResourceEstimate(
                dimension=ResourceDimension.CPU,
                scope=ResourceScope.RUN,
                scope_key=RUN_ID,
                expected=DURATION_S,
                basis="preflight-gate fixture",
            ),
        )
        if with_estimate
        else ()
    )
    enforcer = ResourceBudgetEnforcer(
        budgets=budgets, scope=ResourceScope.RUN, anchor=T0, run_id=RUN_ID
    )
    return RunBudgetGuard(enforcer=enforcer, estimates=estimates)


def quiet_ports(*, healthy: bool = True) -> tuple[PreflightPorts, dict[str, Answering]]:
    """Five bound ports that all answer, and the recorders standing behind them."""
    recorders: dict[str, Answering] = {}
    for field, _, _, _, _ in PORT_SHAPES:
        recorders[field] = Answering(
            PortObservation(healthy=healthy, evidence_ref=f"obs/{field}", detail=f"{field} ok"),
            name=field,
        )
    return PreflightPorts(**recorders), recorders


# ==============================================================================
# Fixtures — a world in which all twelve checks pass, and the ways to break it
# ==============================================================================


class _Good:
    """Sentinel: 'use the healthy default for this witness'.

    Every optional field of :func:`_inputs` takes either a real witness or
    ``None``, and ``None`` means two different things across those fields
    (``graph=None`` is a broken gate; ``policy=None`` is a different broken
    gate). A sentinel keeps "absent" and "unset" apart without a builder.
    """

    __slots__ = ()

    def __repr__(self) -> str:
        return "GOOD"


_GOOD = _Good()


def _graph() -> TopologyGraph:
    """A graph with a real dependency chain: ``n-api`` depends on the target.

    ``dependents_closure("n-web")`` is therefore ``{"n-api"}``, which is what
    makes ``dependency:health`` able to say "a measurement, of something".
    """
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-web", name="web"),
            ServiceNode(id="n-api", name="api"),
            ServiceNode(id="n-db", name="db"),
        ),
        edges=(
            Edge(src="n-api", dst="n-web", kind=EdgeKind.DEPENDS_ON, weight=1.0),
            Edge(src="n-web", dst="n-db", kind=EdgeKind.DEPENDS_ON, weight=2.0),
        ),
    )


def _plan(*fault_ids: str, node_ids: frozenset[str] = frozenset({"n-web"})) -> ExecutionPlan:
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="web")
    steps = tuple(
        PlannedStep(
            id=f"s{seq}",
            seq=seq,
            raw_action=InjectFault(fault=fault_id, selectors=(selector,), duration=DURATION_S),
            fault=PlannedFault(
                fault_id=fault_id,
                targets=(ResolvedTarget(selector=selector, node_ids=node_ids),),
                duration=DURATION_S,
            ),
        )
        for seq, fault_id in enumerate(fault_ids)
    )
    return ExecutionPlan(
        run_id=RUN_ID,
        kind=ExperimentKind.DRILL,
        steps=steps,
        config_snapshot_id="c-1",
        topology_snapshot_id="t-1",
        environment_fingerprint="f-1",
    )


def _preview(
    plan: ExecutionPlan,
    *,
    blocked: tuple[str, ...] = (),
    blast: dict[str, object] | None = None,
) -> Preflight:
    return Preflight(
        resolved_target="web",
        config_snapshot_id="c-1",
        topology_snapshot_id="t-1",
        environment_fingerprint="f-1",
        plan=plan,
        blocked_items=blocked,
        warnings=("target fit: all fault targets resolve in topology",),
        blast_radius={"status": "within_budget", "services_pct": 33.3} if blast is None else blast,
    )


def _agent(
    agent_id: str = "agent-1",
    *,
    faults: tuple[str, ...] = (),
    kinds: tuple[CapabilityKind, ...] = (CapabilityKind.FAULT_INJECT, CapabilityKind.FAULT_UNDO),
) -> AgentIdentity:
    return AgentIdentity(
        agent_id=agent_id,
        capabilities=AgentCapabilities(allowed_faults=faults, capabilities=kinds),
    )


def _allow(bundle_id: str = "gate-test", version: int = 1) -> PolicyDecision:
    return PolicyDecision(
        outcome="allow",
        bundle_id=bundle_id,
        bundle_version=version,
        matched_rules=("staging.allows",),
    )


def _deny(bundle_id: str = "gate-test", version: int = 1) -> PolicyDecision:
    return PolicyDecision(
        outcome="deny",
        reasons=("production policy forbids this",),
        matched_rules=("prod.forbids",),
        bundle_id=bundle_id,
        bundle_version=version,
    )


def _inputs(
    *,
    plan: Any = _GOOD,
    preflight: Any = _GOOD,
    graph: Any = _GOOD,
    agents: Any = _GOOD,
    policy: Any = _GOOD,
    budget: Any = _GOOD,
) -> PreflightInputs:
    """A world in which every one of the twelve checks passes.

    ``_GOOD`` means "the healthy value", so a test overrides exactly the one
    witness it wants to remove and leaves the other eleven intact. A matrix
    built on ``dataclasses.replace(inputs, graph=None)`` is only ever as good as
    its defaults, and defaults are where coverage quietly goes to die.
    """
    the_plan = _plan("proc.pause") if plan is _GOOD else plan
    return PreflightInputs(
        plan=the_plan,
        now=T0,
        preflight=_preview(the_plan) if preflight is _GOOD else preflight,
        graph=_graph() if graph is _GOOD else graph,
        agents=(_agent(faults=("proc.pause",)),) if agents is _GOOD else agents,
        policy=_allow() if policy is _GOOD else policy,
        budget=real_guard() if budget is _GOOD else budget,
        environment="staging",
        target="web",
    )


def _gate(
    ports: PreflightPorts | None = None, *, checks: tuple[str, ...] | None = None
) -> PreflightGate:
    if ports is None:
        ports, _ = quiet_ports()
    if checks is None:
        return PreflightGate(ports=ports)
    return PreflightGate(ports=ports, checks=checks)


# ==============================================================================
# The catalogue
# ==============================================================================


def test_the_catalogue_names_twelve_checks_in_two_kinds() -> None:
    assert len(ALL_CHECKS) == 12
    assert len(set(ALL_CHECKS)) == 12
    assert ALL_CHECKS == REAL_CHECKS + PORT_CHECKS
    assert len(REAL_CHECKS) == 7
    assert len(PORT_CHECKS) == 5
    assert set(PORT_CHECKS) == {
        CHECK_CLUSTER_READY,
        CHECK_INCIDENT_ACTIVE,
        CHECK_DEPLOYMENT_RECENT,
        CHECK_BACKUP_STATE,
        CHECK_REPLICATION_HEALTH,
    }
    # The five port checks and the five ports are one-to-one, in the same order.
    assert [row[0] for row in PORT_SHAPES] == [
        "cluster",
        "incident",
        "deployment",
        "backup",
        "replication",
    ]


# ==============================================================================
# refuses_gate — the one expression that decides every status
# ==============================================================================


@pytest.mark.parametrize(
    ("status", "refuses"),
    [
        (CheckStatus.PASS, False),
        (CheckStatus.FAIL, True),
        (CheckStatus.UNAVAILABLE, True),
    ],
)
def test_only_pass_does_not_refuse(status: CheckStatus, refuses: bool) -> None:
    assert refuses_gate(status) is refuses


def test_an_unrecognised_status_refuses_rather_than_passing_by_omission() -> None:
    """``refuses_gate`` is ``is not PASS`` so a fourth status must be made to decide.

    Under a membership test a status added to :class:`CheckStatus` without a line
    here would fall through and read as a pass — the exact silent direction this
    module exists to close.
    """
    assert refuses_gate("pass") is True
    assert refuses_gate("warn") is True
    assert refuses_gate("") is True
    assert refuses_gate(CheckStatus("pass")) is False


def test_a_check_is_unjudged_by_its_status_and_nothing_else() -> None:
    passing = PreflightCheck(
        name=CHECK_INCIDENT_ACTIVE,
        status=CheckStatus.PASS,
        source=CheckSource.PORT,
        detail="no incident open",
        evidence_ref="obs/incident",
        port="incident",
    )
    unavailable = PreflightCheck(
        name=CHECK_INCIDENT_ACTIVE,
        status=CheckStatus.UNAVAILABLE,
        source=CheckSource.PORT,
        detail="unreachable",
        evidence_ref="port/incident",
        port="incident",
    )
    assert passing.is_pass and not passing.refuses
    assert unavailable.is_unavailable and unavailable.refuses
    assert passing.describe() == "incident:active=pass (obs/incident)"


# ==============================================================================
# The per-check refusal matrix
# ==============================================================================


def test_the_whole_catalogue_passes_when_every_witness_is_present() -> None:
    """The control. Without it, "everything refuses" would satisfy the matrix."""
    report = _gate().evaluate(_inputs())
    assert report.granted
    assert report.refusing_checks == ()
    assert [c.status for c in report.checks] == [CheckStatus.PASS] * 12
    assert [c.source for c in report.checks] == [CheckSource.REAL] * 7 + [CheckSource.PORT] * 5
    assert "granted: all 12 checks passed" in report.refusal_reason


#: check name -> (the witness removed, the status that must result, the evidence
#: reference the refusal must cite). Asserting the citation is the point.
REFUSAL_MATRIX: tuple[tuple[str, PreflightInputs, CheckStatus, str], ...] = (
    (CHECK_PLAN_ADMITTED, _inputs(preflight=None), CheckStatus.FAIL, f"plan/{RUN_ID}"),
    (
        CHECK_PLAN_ADMITTED,
        _inputs(preflight=_preview(_plan("proc.pause"), blocked=("blast radius exceeded",))),
        CheckStatus.FAIL,
        f"plan/{RUN_ID}",
    ),
    (CHECK_TARGET_HEALTH, _inputs(graph=None), CheckStatus.FAIL, f"plan/{RUN_ID}"),
    (
        CHECK_TARGET_HEALTH,
        _inputs(plan=_plan("proc.pause", node_ids=frozenset({"n-ghost"}))),
        CheckStatus.FAIL,
        "topology/n-ghost",
    ),
    (CHECK_DEPENDENCY_HEALTH, _inputs(graph=None), CheckStatus.FAIL, f"plan/{RUN_ID}"),
    (CHECK_AGENT_AVAILABILITY, _inputs(agents=()), CheckStatus.FAIL, f"plan/{RUN_ID}"),
    (
        CHECK_AGENT_CAPABILITY,
        _inputs(agents=(_agent(faults=("proc.pause",), kinds=(CapabilityKind.FAULT_INJECT,)),)),
        CheckStatus.FAIL,
        "fault/proc.pause",
    ),
    (CHECK_POLICY_AVAILABLE, _inputs(policy=None), CheckStatus.FAIL, f"plan/{RUN_ID}"),
    (CHECK_BUDGET_AVAILABLE, _inputs(budget=None), CheckStatus.FAIL, f"plan/{RUN_ID}"),
    (
        CHECK_BUDGET_AVAILABLE,
        _inputs(budget=real_guard(with_estimate=False)),
        CheckStatus.FAIL,
        "budget/cpu",
    ),
)


@pytest.mark.parametrize(
    ("name", "inputs", "status", "evidence_ref"),
    REFUSAL_MATRIX,
    ids=[f"{row[0]}-{row[2].value}-{row[3].replace('/', '-')}" for row in REFUSAL_MATRIX],
)
def test_a_real_check_refuses_and_cites_its_missing_witness(
    name: str, inputs: PreflightInputs, status: CheckStatus, evidence_ref: str
) -> None:
    report = _gate().evaluate(inputs)
    check = report.check(name)
    assert check is not None
    assert check.status is status
    assert check.refuses
    assert check.evidence_ref == evidence_ref
    # …and it is the *gate's* refusal, not only the check's.
    assert not report.granted
    assert name in tuple(c.name for c in report.refusing_checks)


def test_a_plan_the_preflight_never_saw_is_a_failure_not_a_pass() -> None:
    """The v1.0.0 bug in one assertion: "did not check" must not read as "fine"."""
    check = check_plan_admitted(_inputs(preflight=None))
    assert check.status is CheckStatus.FAIL
    assert "never run" in check.detail


def test_a_preview_with_no_blast_radius_verdict_is_a_failure() -> None:
    """A preview that measured nothing is not a preview that found nothing.

    ``build_preflight`` always writes a ``status`` into the blast record, so this
    is the hand-built-preview path — and it is exactly where a missing field
    would otherwise be read as permission to proceed.
    """
    plan = _plan("proc.pause")
    blank = check_plan_admitted(_inputs(plan=plan, preflight=_preview(plan, blast={})))
    assert blank.status is CheckStatus.FAIL
    assert "no blast-radius verdict" in blank.detail
    # The computed cases keep their existing readings.
    unknown = check_plan_admitted(
        _inputs(
            plan=plan, preflight=_preview(plan, blast={"status": "unknown", "error": "no graph"})
        )
    )
    assert unknown.status is CheckStatus.FAIL
    exceeded = check_plan_admitted(
        _inputs(
            plan=plan,
            preflight=_preview(plan, blast={"status": "exceeded", "error": "services_pct 90 > 50"}),
        )
    )
    assert exceeded.status is CheckStatus.FAIL
    assert "services_pct 90 > 50" in exceeded.detail
    # The control: a measured, within-budget preview still passes.
    assert check_plan_admitted(_inputs(plan=plan, preflight=_preview(plan))).status is (
        CheckStatus.PASS
    )


def test_dependency_health_refuses_an_empty_topology_rather_than_measuring_zero() -> None:
    """``0% of nothing`` is not a measurement and must not read as one."""
    assert check_dependency_health(_inputs()).status is CheckStatus.PASS
    # A graph of hosts alone: no service node, so the percentage has no denominator.
    no_services = TopologyGraph(nodes=(HostNode(id="h-1", name="host-a"),), edges=())
    check = check_dependency_health(
        _inputs(graph=no_services, plan=_plan("proc.pause", node_ids=frozenset({"h-1"})))
    )
    assert check.status is CheckStatus.FAIL
    assert "0% of nothing" in check.detail
    assert check.evidence_ref == "topology/graph"


def test_target_health_names_every_node_that_does_not_resolve() -> None:
    check = check_target_health(_inputs())
    assert check.status is CheckStatus.PASS
    assert check.detail == "all 1 target node id(s) resolve in the topology"
    assert check.evidence_ref == "topology/n-web"
    plan = _plan("proc.pause", node_ids=frozenset({"n-ghost", "n-other"}))
    ghost = check_target_health(_inputs(plan=plan, preflight=_preview(plan)))
    assert ghost.status is CheckStatus.FAIL
    assert "n-ghost, n-other" in ghost.detail
    assert ghost.evidence_ref == "topology/n-ghost"


def test_agent_capability_cites_the_fault_that_actually_went_unmet() -> None:
    """The evidence must support the finding it is attached to.

    A plan whose *second* fault has no undoer must not produce a refusal citing
    the first, which has both — an auditor following that reference would find a
    perfectly capable agent and conclude the evidence was wrong.
    """
    inject_only = _agent(
        "a-inject", faults=("k8s.node_drain",), kinds=(CapabilityKind.FAULT_INJECT,)
    )
    check = check_agent_capability(
        _inputs(
            plan=_plan("proc.pause", "k8s.node_drain"),
            agents=(_agent(faults=("proc.pause",)), inject_only),
        )
    )
    assert check.status is CheckStatus.FAIL
    assert "k8s.node_drain: injectable but no agent may undo it" in check.detail
    assert check.evidence_ref == "fault/k8s.node_drain"


def test_an_agent_that_may_not_inject_is_refused_before_the_undo_is_considered() -> None:
    undo_only = _agent("a-undo", faults=("proc.pause",), kinds=(CapabilityKind.FAULT_UNDO,))
    check = check_agent_capability(_inputs(agents=(undo_only,)))
    assert check.status is CheckStatus.FAIL
    assert "no agent may inject it" in check.detail


def test_no_registered_agent_refuses_both_the_availability_and_the_capability_check() -> None:
    assert check_agent_availability(_inputs(agents=())).status is CheckStatus.FAIL
    assert check_agent_capability(_inputs(agents=())).status is CheckStatus.FAIL


def test_a_policy_denial_is_refused_with_the_denys_own_reasons() -> None:
    """Plan 07 computed the reasons; the gate quotes them rather than re-deriving."""
    check = check_policy_available(_inputs(policy=_deny()))
    assert check.status is CheckStatus.FAIL
    assert "production policy forbids this" in check.detail
    assert check.evidence_ref == "policy/gate-test@1"
    # A denial carrying no reasons still refuses rather than reading as a bare yes.
    bare = _deny().model_copy(update={"reasons": ()})
    unreasoned = check_policy_available(_inputs(policy=bare))
    assert unreasoned.status is CheckStatus.FAIL
    assert "denied" in unreasoned.detail


def test_a_policy_decision_is_required_not_merely_a_denial() -> None:
    """Availability, not permission: no decision at all is the stronger failure."""
    check = check_policy_available(_inputs(policy=None))
    assert check.status is CheckStatus.FAIL
    assert "cannot see the policy" in check.detail


def test_a_budget_that_governs_nothing_is_refused_as_a_budget_that_admits_everything() -> None:
    check = check_budget_available(_inputs(budget=real_guard(with_budget=False)))
    assert check.status is CheckStatus.FAIL
    assert check.evidence_ref == "budget/none"
    assert "governs no dimension" in check.detail


def test_a_budget_with_dimensions_and_no_estimate_is_refused_as_vacuous_admission() -> None:
    check = check_budget_available(_inputs(budget=real_guard(with_estimate=False)))
    assert check.status is CheckStatus.FAIL
    assert "vacuous" in check.detail
    assert check.evidence_ref == "budget/cpu"


def test_the_gate_reads_a_budget_and_never_judges_one() -> None:
    """Two judges of one budget is how two different answers get produced.

    ``estimates`` is read twice on the granting path — once to test that the
    budget is not vacuous and once to count them for the detail line — which is
    a read, and a read is free. What must never happen is ``admit`` being called.
    """
    counter, guard = counting_budget()
    assert check_budget_available(_inputs(budget=guard)).status is CheckStatus.PASS
    assert counter.reads == ["dimensions", "estimates", "estimates"]
    assert counter.admit_calls == []


# ==============================================================================
# THE LOAD-BEARING RULE: an unreachable port must never yield PASS
# ==============================================================================


@pytest.mark.parametrize(("field", "check", "_proto", "_method", "argument"), PORT_SHAPES)
def test_an_unbound_port_is_unavailable_and_never_a_pass(
    field: str, check: str, _proto: type, _method: str, argument: str
) -> None:
    """Mayhem has no witness at all, so it certifies nothing about that system."""
    ports = PreflightPorts()
    assert field not in ports.bound()
    result = _gate(ports).evaluate(_inputs()).check(check)
    assert result is not None
    assert result.status is CheckStatus.UNAVAILABLE
    assert result.refuses
    assert result.source is CheckSource.PORT
    assert result.port == field
    assert result.evidence_ref == f"port/{field}"
    assert "unconsulted witness" in result.detail


@pytest.mark.parametrize(("field", "check", "_proto", "_method", "argument"), PORT_SHAPES)
@pytest.mark.parametrize("how", ["raises", "answers_none", "wrong_shape"])
def test_no_port_that_fails_to_answer_can_yield_a_pass(
    field: str, check: str, _proto: type, _method: str, argument: str, how: str
) -> None:
    """The ways a witness fails to speak, and the one status they all get.

    ``raises`` is a timeout or a refused connection; ``answers_none`` is a port
    that connected and returned nothing; ``wrong_shape`` is a port that satisfies
    the structural protocol and answers in some other type. All three are "no
    answer", and all three must refuse.
    """
    answer: object
    raise_with: BaseException | None = None
    if how == "raises":
        answer = None
        raise_with = ConnectionError("connection refused")
    elif how == "answers_none":
        answer = None
    else:
        answer = {"healthy": True}

    ports = PreflightPorts(**{field: Answering(answer, raise_with=raise_with, name=field)})
    result = _gate(ports).evaluate(_inputs()).check(check)
    assert result is not None
    assert result.status is CheckStatus.UNAVAILABLE
    assert result.status is not CheckStatus.PASS
    assert result.refuses
    assert result.evidence_ref == f"port/{field}"
    assert "unreachable" in result.detail


@pytest.mark.parametrize(("field", "check", "_proto", "_method", "argument"), PORT_SHAPES)
def test_an_unhealthy_but_reachable_port_is_a_fail_not_an_unavailable(
    field: str, check: str, _proto: type, _method: str, argument: str
) -> None:
    """The distinction the two status names exist to protect.

    ``FAIL`` says "mayhem looked, and the answer was no" — an operational fact.
    ``UNAVAILABLE`` says "mayhem has no witness" — a wiring problem. Collapsing
    them would let an operator read "the incident manager is down" as "the
    incident manager reports no incidents open", which are opposite findings.
    """
    ports = PreflightPorts(
        **{
            field: Answering(
                PortObservation(
                    healthy=False, evidence_ref=f"obs/{field}", detail="an incident is open"
                ),
                name=field,
            )
        }
    )
    result = _gate(ports).evaluate(_inputs()).check(check)
    assert result is not None
    assert result.status is CheckStatus.FAIL
    assert not result.is_unavailable
    assert result.refuses
    assert result.evidence_ref == f"obs/{field}"
    assert result.detail == "an incident is open"


@pytest.mark.parametrize(("field", "check", "_proto", "_method", "argument"), PORT_SHAPES)
def test_a_reachable_healthy_port_passes_and_cites_the_port_s_own_evidence(
    field: str, check: str, _proto: type, _method: str, argument: str
) -> None:
    ports, recorders = quiet_ports()
    result = _gate(ports).evaluate(_inputs()).check(check)
    assert result is not None
    assert result.status is CheckStatus.PASS
    assert result.evidence_ref == f"obs/{field}"
    assert result.port == field
    assert len(recorders[field].calls) == 1


def test_the_port_method_is_called_with_the_argument_its_protocol_declares() -> None:
    """``backup_state`` is asked about a target; the rest about an environment."""
    ports, recorders = quiet_ports()
    _gate(ports).evaluate(_inputs())
    assert recorders["backup"].calls == [
        {"port": "backup", "method": "backup_state", "target": "web"}
    ]
    assert recorders["incident"].calls == [
        {"port": "incident", "method": "active_incidents", "environment": "staging"}
    ]


def test_a_port_that_does_not_implement_its_method_is_unavailable_not_a_crash() -> None:
    """A structurally satisfied protocol with no method behind it is no witness."""

    class Empty:
        pass

    gate = _gate(PreflightPorts(incident=Empty()))
    result = gate.evaluate(_inputs()).check(CHECK_INCIDENT_ACTIVE)
    assert result is not None
    assert result.status is CheckStatus.UNAVAILABLE
    assert "unreachable" in result.detail


def test_the_whole_gate_refuses_when_any_single_port_cannot_be_reached() -> None:
    """One unreachable system out of five is a refusal, not a four-out-of-five pass."""
    ports, _ = quiet_ports()
    assert PreflightGate(ports=ports).evaluate(_inputs()).granted
    for field, check, _, _, _ in PORT_SHAPES:
        broken = dataclasses.replace(ports, **{field: None})
        gate = PreflightGate(ports=broken)
        report = gate.evaluate(_inputs())
        assert not report.granted, field
        assert [c.name for c in report.refusing_checks] == [check]
        assert report.refusing_checks[0].status is CheckStatus.UNAVAILABLE
        with pytest.raises(PreflightRefusedError):
            gate.admit(_inputs())


def test_port_status_is_a_pure_function_of_its_two_arguments() -> None:
    """The rule the plan states, isolated from any gate, plan, or port."""
    assert port_status(None) is CheckStatus.UNAVAILABLE
    assert port_status(None, error=ConnectionError("down")) is CheckStatus.UNAVAILABLE
    # An error alongside an answer is still an error: the answer is unverified.
    assert (
        port_status(PortObservation(healthy=True, evidence_ref="o"), error=RuntimeError())
        is CheckStatus.UNAVAILABLE
    )
    assert port_status(PortObservation(healthy=True, evidence_ref="o")) is CheckStatus.PASS
    assert port_status(PortObservation(healthy=False, evidence_ref="o")) is CheckStatus.FAIL
    # There is deliberately no fifth row: an error never degrades to FAIL.
    assert port_status(None, error=ConnectionError()) is not CheckStatus.FAIL


def test_a_port_observation_must_cite_something() -> None:
    with pytest.raises(InvariantViolationError) as refusal:
        PortObservation(healthy=True, evidence_ref="  ")
    assert refusal.value.rule == "port_observation_ref_not_blank"


def test_a_port_answer_that_is_not_an_observation_is_refused_rather_than_crashing() -> None:
    """``evaluate`` reports; only a defect *inside* a check propagates.

    Reading ``.healthy`` off an arbitrary object would raise ``AttributeError``
    straight out of ``evaluate`` — a crash where the honest answer is "this
    witness cannot speak", which is a finding, and one that refuses.
    """
    gate = _gate(PreflightPorts(incident=Answering({"healthy": True}, name="incident")))
    report = gate.evaluate(_inputs())
    result = report.check(CHECK_INCIDENT_ACTIVE)
    assert result is not None
    assert result.status is CheckStatus.UNAVAILABLE
    assert "is not a PortObservation" in result.detail
    assert not report.granted


# ==============================================================================
# A preflight with NO checks at all is REFUSED
# ==============================================================================


def test_a_gate_that_ran_no_checks_is_refused() -> None:
    """A gate that checked nothing and passed is worse than no gate."""
    gate = PreflightGate(checks=())
    report = gate.evaluate(_inputs())
    assert report.vacuous
    assert not report.granted
    assert "evaluated no checks" in report.refusal_reason
    with pytest.raises(PreflightRefusedError) as refusal:
        gate.admit(_inputs())
    assert refusal.value.report.vacuous
    assert "cannot certify a run" in str(refusal.value)


def test_a_vacuous_refusal_still_names_why_in_its_stop_trigger() -> None:
    """A ``preflight_failed`` sealed with an empty detail says nothing at all.

    The refusal whose cause most needs saying is the one with no refusing check
    to cite, so the trigger falls back to the report's own reason.
    """
    with pytest.raises(PreflightRefusedError) as refusal:
        PreflightGate(checks=()).admit(_inputs())
    trigger = refusal.value.trigger
    assert trigger.reason is StopReason.PREFLIGHT_FAILED
    assert trigger.reason == StopTrigger.for_signal(StopSignal.PREFLIGHT_REFUSAL).reason
    assert "evaluated no checks" in trigger.detail


def test_an_omitted_check_shows_up_as_an_absence_and_never_as_a_pass() -> None:
    """Narrowing the catalogue is an operator decision and it can only refuse more."""
    report = _gate(checks=(CHECK_INCIDENT_ACTIVE,)).evaluate(_inputs())
    assert [c.name for c in report.checks] == [CHECK_INCIDENT_ACTIVE]
    assert report.granted
    assert report.check(CHECK_CLUSTER_READY) is None
    # The narrowing is visible in the recorded evidence rather than silent.
    assert [entry["name"] for entry in report.inputs()["checks"]] == [CHECK_INCIDENT_ACTIVE]


def test_a_typo_in_the_catalogue_cannot_produce_a_gate_that_evaluates_nothing() -> None:
    """The failure mode this module exists to make impossible."""
    with pytest.raises(InvariantViolationError) as refusal:
        PreflightGate(checks=(CHECK_INCIDENT_ACTIVE, "typo:check"))
    assert refusal.value.rule == "preflight_unknown_check"
    assert "typo:check" in str(refusal.value)


def test_a_repeated_check_is_refused_at_construction() -> None:
    with pytest.raises(InvariantViolationError) as refusal:
        PreflightGate(checks=(CHECK_INCIDENT_ACTIVE, CHECK_INCIDENT_ACTIVE))
    assert refusal.value.rule == "preflight_duplicate_check"


def test_a_report_refuses_to_repeat_a_check_name() -> None:
    duplicate = PreflightCheck(
        name=CHECK_INCIDENT_ACTIVE,
        status=CheckStatus.PASS,
        source=CheckSource.PORT,
        detail="d",
        evidence_ref="o",
        port="incident",
    )
    with pytest.raises(InvariantViolationError) as refusal:
        PreflightReport(run_id=RUN_ID, checks=(duplicate, duplicate), generated_at=T0)
    assert refusal.value.rule == "preflight_check_names_unique"


# ==============================================================================
# admit — and the no-preflight path
# ==============================================================================


def test_a_gate_that_grants_returns_the_report_and_raises_nothing() -> None:
    report = _gate().admit(_inputs())
    assert report.granted
    assert len(report.checks) == 12
    assert report.generated_at == T0
    assert report.run_id == RUN_ID


def test_admit_never_returns_a_report_that_does_not_grant() -> None:
    """There is no ``(report, ok)`` pair for a caller to forget to check."""
    gate = PreflightGate(checks=(CHECK_POLICY_AVAILABLE,))
    with pytest.raises(PreflightRefusedError):
        gate.admit(_inputs(policy=_deny()))


def test_a_refusal_is_an_invariant_violation_carrying_the_stop_vocabulary() -> None:
    """A preflight refusal is the run-time answer to a question already asked."""
    with pytest.raises(PreflightRefusedError) as refusal:
        _gate().admit(_inputs(policy=_deny()))
    error = refusal.value
    assert isinstance(error, InvariantViolationError)
    assert error.rule == "preflight.refused"
    assert error.refusing_checks[0].describe() == "policy:available=fail (policy/gate-test@1)"
    trigger = error.trigger
    assert trigger.reason is StopReason.PREFLIGHT_FAILED
    assert "policy:available=fail @policy/gate-test@1" in trigger.detail


def test_the_refusal_line_names_every_refusal_in_the_order_the_gate_reached_it() -> None:
    report = _gate().evaluate(_inputs(policy=_deny(), graph=None))
    reason = report.refusal_reason
    # ``graph=None`` removes two witnesses at once, which is the point: a check
    # that cannot see the topology refuses independently of every other check.
    assert reason.startswith(f"preflight for run {RUN_ID} refused 3 of 12 checks: ")
    # Report order, not alphabetical: the gate evaluated them in catalogue order.
    assert reason.index(CHECK_TARGET_HEALTH) < reason.index(CHECK_DEPENDENCY_HEALTH)
    assert reason.index(CHECK_DEPENDENCY_HEALTH) < reason.index(CHECK_POLICY_AVAILABLE)


def test_refusing_names_previews_without_raising() -> None:
    assert _gate().refusing_names(_inputs(policy=_deny())) == (CHECK_POLICY_AVAILABLE,)


# ==============================================================================
# THE GOLDEN — admit(gate=None) leaves behaviour byte-identical
# ==============================================================================


def _admission_rendering(gate: PreflightGate | None, inputs: PreflightInputs) -> str:
    """Everything one admission attempt did, rendered stably.

    The lines are the ones a change would move: the result, every port call made,
    every budget read, whether the budget was *judged*, and which fields of
    ``inputs`` were even looked at. Nothing here is derived from the module's own
    vocabulary, so a reworded detail string cannot drift the golden.
    """
    probes: dict[str, Answering] = {}
    for field, _, _, _, _ in PORT_SHAPES:
        if gate is not None and isinstance(getattr(gate.ports, field, None), Answering):
            probes[field] = getattr(gate.ports, field)
    result = admit(gate, inputs)
    trace = tuple(
        f"{name}.{call['method']}" for name in sorted(probes) for call in probes[name].calls
    )
    budget = inputs.budget
    counter = getattr(budget, "_counter", None)
    return "\n".join(
        (
            f"result={'none' if result is None else 'report'}",
            f"port-calls={len(trace)}",
            f"port-call-trace={';'.join(trace)}",
            f"budget-type={type(budget).__name__}",
            f"budget-reads={','.join(counter.reads) if counter else 'n/a'}",
            f"budget-judged={bool(counter.admit_calls) if counter else 'n/a'}",
            f"plan-run-id={inputs.plan.run_id}",
            f"plan-steps={len(inputs.plan.steps)}",
            f"plan-faults={len(plan_faults(inputs.plan))}",
            f"plan-fingerprint={inputs.plan.environment_fingerprint}",
            f"preflight-present={inputs.preflight is not None}",
            f"graph-present={inputs.graph is not None}",
            f"agents={len(inputs.agents)}",
            f"policy-present={inputs.policy is not None}",
            f"budget-present={budget is not None}",
        )
    )


#: Golden rendering of the no-preflight path. Any drift in the additive contract
#: — a check run, a port called, a budget judged, a field read — breaks this.
GOLDEN_NO_GATE = "\n".join(
    (
        "result=none",
        "port-calls=0",
        "port-call-trace=",
        "budget-type=_ReadOnlyBudget",
        "budget-reads=",
        "budget-judged=False",
        f"plan-run-id={RUN_ID}",
        "plan-steps=1",
        "plan-faults=1",
        "plan-fingerprint=f-1",
        "preflight-present=True",
        "graph-present=True",
        "agents=1",
        "policy-present=True",
        "budget-present=True",
    )
)


def test_no_preflight_path_is_byte_identical_to_the_golden() -> None:
    """The additive contract, pinned the way ``test_policy_gate.py`` pins its own."""
    counter, guard = counting_budget()
    inputs = _inputs(budget=guard)
    assert admit(None, inputs) is None
    assert _admission_rendering(None, inputs) == GOLDEN_NO_GATE
    # The counts the golden renders are themselves the assertion.
    assert counter.reads == []
    assert counter.admit_calls == []


def test_configuring_a_gate_changes_what_the_admission_reads() -> None:
    """The contrast that gives the golden above its meaning.

    Same inputs, same recorders, same budget object — with a gate configured the
    five ports are probed, the budget is read twice and not judged, and the
    rendering is a different line.
    """
    counter, guard = counting_budget()
    assert _admission_rendering(None, _inputs(budget=guard)) == GOLDEN_NO_GATE
    gated = _admission_rendering(_gate(), _inputs(budget=guard))
    assert "result=report" in gated
    assert "port-calls=5" in gated
    assert "budget-reads=dimensions,estimates" in gated
    assert "budget-judged=False" in gated
    assert counter.admit_calls == []


def test_no_gate_is_the_default_and_there_is_no_bypass() -> None:
    """Plan 10 Phase 5 asks for a test asserting a bypass flag's absence.

    ``admit`` has exactly one way in — ``gate=None``, which means *nobody
    configured a preflight* — and nothing anywhere in the module offers to skip
    a check that has been configured.
    """
    import mayhem.controller.preflight_gate as module

    forbidden = ("bypass", "skip", "force", "override", "ignore", "waive")
    assert not [name for name in dir(module) if any(word in name.lower() for word in forbidden)]
    assert list(inspect.signature(module.admit).parameters) == ["gate", "inputs"]
    assert list(inspect.signature(PreflightGate).parameters) == ["ports", "checks"]
    assert list(inspect.signature(PreflightGate.evaluate).parameters) == ["self", "inputs"]


# ==============================================================================
# A failed preflight leaves zero mutations
# ==============================================================================


def _snapshot(plan: ExecutionPlan, preview: Preflight, graph: TopologyGraph) -> tuple[Any, ...]:
    """Everything the gate read, rendered for a byte comparison."""
    return (
        plan.model_dump_json(),
        preview.blocked_items,
        preview.warnings,
        tuple(preview.blast_radius.items()),
        graph.model_dump_json(),
    )


def test_a_refused_preflight_mutates_nothing_it_read() -> None:
    """A refusal is a decision, not a side effect.

    The gate's whole surface is read-only, and that is a property worth a byte
    comparison rather than a promise: a check that could spend a budget, write a
    lease, or annotate a policy decision would turn "preflight refused" into
    "preflight changed something and then refused".
    """
    plan = _plan("proc.pause", "net.latency")
    graph = _graph()
    preview = _preview(plan)
    agents = (_agent("a-1", faults=("proc.pause",)), _agent("a-2", faults=("net.latency",)))
    policy = _deny()
    guard = real_guard()
    inputs = PreflightInputs(
        plan=plan,
        now=T0,
        preflight=preview,
        graph=graph,
        agents=agents,
        policy=policy,
        budget=guard,
        environment="production",
        target="web",
    )
    before = (
        _snapshot(plan, preview, graph),
        tuple(a.model_dump_json() for a in agents),
        policy.model_dump_json(),
        guard.dimensions,
        guard.estimates,
        guard.admission,
        guard.paused,
        guard.stopped,
    )
    with pytest.raises(PreflightRefusedError):
        _gate().admit(inputs)
    after = (
        _snapshot(plan, preview, graph),
        tuple(a.model_dump_json() for a in agents),
        policy.model_dump_json(),
        guard.dimensions,
        guard.estimates,
        guard.admission,
        guard.paused,
        guard.stopped,
    )
    assert after == before


def test_a_refused_preflight_judges_no_budget_and_records_no_decision() -> None:
    """Zero mutations, stated as a count rather than as an unchanged snapshot."""
    counter, guard = counting_budget()
    inputs = _inputs(policy=_deny(), budget=guard)
    with pytest.raises(PreflightRefusedError):
        _gate().admit(inputs)
    assert counter.admit_calls == []
    assert counter.reads == ["dimensions", "estimates", "estimates"]


# ==============================================================================
# The postflight half
# ==============================================================================


def _operator_command() -> StopCommand:
    return StopCommand(
        id="sc-1",
        scope=StopScope.RUN,
        run_id=RUN_ID,
        principal="operator:ana",
        trigger=StopTrigger(reason=StopReason.HUMAN, detail="operator pressed stop"),
        issued_at=STOP_MOMENT,
    )


def _lease(lease_id: str = "l-1", *, settled: bool = True) -> FaultLease:
    """A lease carrying the write-ahead undo contract every real lease carries.

    ``settled=True`` walks it to ``RELEASED`` through the transition table rather
    than constructing the terminal state, because a lease cannot be *asserted*
    into one.
    """
    lease = FaultLease(
        id=lease_id,
        run_id=RUN_ID,
        fault_id="proc.pause",
        owner_agent="agent-1",
        targets=frozenset({"web"}),
        undo_ops=(UndoOp(op="signal", args={"target": "web"}),),
        verify_probes=(VerifyProbe(probe="exec", args={"cmd": "true"}),),
        ttl_seconds=HOUR,
        state=LeaseState.PENDING,
        created_at=STOP_MOMENT - timedelta(seconds=30),
    )
    if not settled:
        return lease.transition(LeaseState.ACTIVE, now=STOP_MOMENT - timedelta(seconds=29))
    return (
        lease.transition(LeaseState.ACTIVE, now=STOP_MOMENT - timedelta(seconds=29))
        .transition(LeaseState.RELEASING, mechanism="janitor", now=STOP_MOMENT)
        .transition(LeaseState.RELEASED, mechanism="janitor", now=STOP_MOMENT)
    )


def _sealed_execution(
    *, findings: tuple[Residue, ...] = (), leases: tuple[FaultLease, ...] = ()
) -> StopExecution:
    """A stop that walked the whole ladder and sealed, over the real postflight."""
    command = _operator_command()
    record = StopRecord(
        command=command,
        state=RunState.RUNNING,
        level=CancellationLevel.KILL,
        compensation=CompensationPath.CONTROLLER_RECOVERY,
        started_at=STOP_MOMENT,
        finished_at=STOP_MOMENT,
        completed_stages=STOP_FLOW,
        receipts=tuple(
            StageReceipt(stage=stage, evidence_ref=f"receipt/{stage.value}") for stage in STOP_FLOW
        ),
    )
    report = postflight_report(
        run_id=RUN_ID,
        stop=command.trigger,
        leases=leases,
        findings=findings,
        now=STOP_MOMENT,
    )
    sealed = SealedStop(
        record=record, report=report, report_digest=report.report_digest, sealed_at=STOP_MOMENT
    )
    return StopExecution(record=record, sealed=sealed)


def _stalled_execution() -> StopExecution:
    """A stop that never reached ``SEAL`` — recorded, not finished."""
    command = _operator_command()
    record = StopRecord(
        command=command,
        state=RunState.RUNNING,
        level=CancellationLevel.KILL,
        compensation=CompensationPath.CONTROLLER_RECOVERY,
        started_at=STOP_MOMENT,
        finished_at=STOP_MOMENT,
        completed_stages=(StopStage.FREEZE, StopStage.CANCEL_PENDING),
        stalled_at=StopStage.COMPENSATE_ACTIVE,
        stall_reason="compensate_active: RuntimeError: controller process gone",
        receipts=(
            StageReceipt(stage=StopStage.FREEZE, evidence_ref="dispatch/run-1/epoch-7"),
            StageReceipt(stage=StopStage.CANCEL_PENDING, evidence_ref="lease/l-1"),
        ),
    )
    return StopExecution(record=record)


def test_a_clean_stop_reads_clean_and_owes_nothing() -> None:
    execution = _sealed_execution(leases=(_lease("l-1"),))
    report = postflight_report_for(execution)
    assert report is not None
    assert postflight_verdict_for(execution, now=STOP_MOMENT) is PostflightVerdict.CLEAN
    assert open_obligations(report) == ()
    assert obligation_verdict(report, now=STOP_MOMENT) is True
    assert may_close_clean(execution, now=STOP_MOMENT) is True


def test_a_residue_finding_keeps_the_run_dirty_and_owes_one_obligation() -> None:
    execution = _sealed_execution(
        findings=(Residue(kind="qdisc", target="eth0", detail="netem rule still attached"),)
    )
    report = postflight_report_for(execution)
    assert report is not None
    assert postflight_verdict_for(execution, now=STOP_MOMENT) is PostflightVerdict.DIRTY
    assert [c.name for c in open_obligations(report)] == ["residue:qdisc:eth0"]
    assert obligation_verdict(report, now=STOP_MOMENT) is False
    assert may_close_clean(execution, now=STOP_MOMENT) is False


def test_a_stalled_stop_has_no_report_and_is_never_clean() -> None:
    """Unchecked is not clean, and unchecked is not dirty either."""
    execution = _stalled_execution()
    assert execution.sealed is None
    assert postflight_report_for(execution) is None
    assert postflight_verdict_for(execution, now=STOP_MOMENT) is PostflightVerdict.UNKNOWN
    assert open_obligations(None) == ()
    assert obligation_verdict(None) is False
    assert may_close_clean(execution, now=STOP_MOMENT) is False


def test_evidence_aged_past_its_ttl_is_unknown_rather_than_clean() -> None:
    """A recovery verified an hour ago has not been verified now."""
    execution = _sealed_execution()
    later = STOP_MOMENT + timedelta(hours=1)
    assert postflight_verdict_for(execution, now=STOP_MOMENT) is PostflightVerdict.CLEAN
    assert postflight_verdict_for(execution, now=later) is PostflightVerdict.UNKNOWN
    report = postflight_report_for(execution)
    assert report is not None
    assert obligation_verdict(report, now=later) is False
    assert may_close_clean(execution, now=later) is False


def test_a_stale_obligation_is_still_an_obligation() -> None:
    """An open residue does not expire; only evidence of recovery does."""
    execution = _sealed_execution(findings=(Residue(kind="netns", target="ns-9"),))
    report = postflight_report_for(execution)
    assert report is not None
    assert [c.name for c in open_obligations(report)] == ["residue:netns:ns-9"]
    assert obligation_verdict(report, now=STOP_MOMENT + timedelta(hours=1)) is False


def test_the_gate_agrees_with_domain_stop_on_every_verdict() -> None:
    """There must be exactly one place in the tree that decides what clean means.

    The preflight half *reads* ``PostflightReport.verdict`` rather than
    reimplementing it, and this holds the two to the same answer across all
    three verdicts — including the fail-closed ones, which are the ones a second
    implementation would quietly widen.
    """
    empty = PostflightReport(
        run_id=RUN_ID, stop=_operator_command().trigger, checks=(), generated_at=STOP_MOMENT
    )
    assert empty.verdict(STOP_MOMENT) is PostflightVerdict.UNKNOWN
    assert obligation_verdict(empty) is False
    for execution, expected in (
        (_sealed_execution(), PostflightVerdict.CLEAN),
        (
            _sealed_execution(findings=(Residue(kind="qdisc", target="eth0"),)),
            PostflightVerdict.DIRTY,
        ),
        (_stalled_execution(), PostflightVerdict.UNKNOWN),
        (_sealed_execution(leases=(_lease("l-9", settled=False),)), PostflightVerdict.DIRTY),
    ):
        report = postflight_report_for(execution)
        if report is None:
            assert expected is PostflightVerdict.UNKNOWN
            assert postflight_verdict_for(execution, now=STOP_MOMENT) is expected
            continue
        assert report.verdict(STOP_MOMENT) is expected
        assert postflight_verdict_for(execution, now=STOP_MOMENT) is expected
        assert obligation_verdict(report, now=STOP_MOMENT) is (expected is PostflightVerdict.CLEAN)


def test_the_verdict_is_recomputed_and_never_stored_and_trusted() -> None:
    """A caller cannot write ``verdict=clean`` over a failing check.

    Structurally: ``verdict`` is a property on both ``StopExecution`` and
    ``PostflightReport`` and there is no field to set. Behaviourally: the same
    stop, differing only by whether the undo missed something, reads clean and
    dirty respectively.
    """
    assert "verdict" not in PostflightReport.model_fields
    assert not hasattr(StopExecution, "model_fields")
    assert callable(PostflightReport.verdict)
    assert isinstance(StopExecution.verdict, property)
    clean = _sealed_execution()
    dirty = _sealed_execution(findings=(Residue(kind="qdisc", target="eth0"),))
    assert postflight_verdict_for(clean, now=STOP_MOMENT) is not postflight_verdict_for(
        dirty, now=STOP_MOMENT
    )
    assert may_close_clean(clean, now=STOP_MOMENT) is not may_close_clean(dirty, now=STOP_MOMENT)


def test_the_same_stop_reads_clean_once_the_obligation_is_gone() -> None:
    """A dropped residue is the *only* way to get here, which is the right way.

    Same run, same ladder, same stage receipts — only the finding differs, so
    the difference in verdict is attributable to the obligation alone.
    """
    clean_report = postflight_report_for(_sealed_execution())
    dirty_report = postflight_report_for(
        _sealed_execution(findings=(Residue(kind="qdisc", target="eth0"),))
    )
    assert clean_report is not None and dirty_report is not None
    assert clean_report.run_id == dirty_report.run_id
    assert obligation_verdict(dirty_report, now=STOP_MOMENT) is False
    assert obligation_verdict(clean_report, now=STOP_MOMENT) is True


def test_the_redundant_obligation_guard_rests_on_a_real_domain_property() -> None:
    """Why :func:`obligation_verdict`'s first conjunct cannot fail on its own.

    Every open obligation is a non-passing check, and
    :meth:`PostflightReport.verdict` returns ``DIRTY`` the moment *any* check is
    non-passing — precedence ahead of the stale-evidence branch. So deleting the
    conjunct is an **equivalent** mutant today, not an undetected defect: the
    suite cannot kill it, and pretending otherwise would be the dishonest result.

    What this test pins is the domain property the redundancy depends on. The day
    ``PostflightReport.verdict``'s precedence is edited — say, to stop letting a
    residue check settle the verdict — the guard stops being redundancy, and this
    is where somebody finds out.
    """
    for execution in (
        _sealed_execution(),
        _sealed_execution(findings=(Residue(kind="qdisc", target="eth0"),)),
        _sealed_execution(leases=(_lease("l-9", settled=False),)),
    ):
        report = postflight_report_for(execution)
        assert report is not None
        failing = {c.name for c in report.checks if not c.is_pass}
        assert {c.name for c in open_obligations(report)} <= failing
        assert (not open_obligations(report)) or (
            report.verdict(STOP_MOMENT) is PostflightVerdict.DIRTY
        )


def test_the_passing_residue_scan_is_a_receipt_and_never_an_obligation() -> None:
    report = postflight_report_for(_sealed_execution())
    assert report is not None
    names = [c.name for c in report.checks]
    assert f"{RESIDUE_CHECK_PREFIX}scan" in names
    assert [c.name for c in open_obligations(report)] == []
    assert all(not c.name.endswith(":scan") for c in open_obligations(report))


def test_a_failed_verify_gate_is_a_dirty_run_that_owes_nothing() -> None:
    """The obligation set is residue only; a failing verify gate is still ``DIRTY``.

    An unsettled lease is the run's problem, not a standing to-do an operator
    can discharge, so it must not masquerade as a residue obligation — but the
    verdict must not soften either.
    """
    unsettled = _sealed_execution(leases=(_lease("l-9", settled=False),))
    report = postflight_report_for(unsettled)
    assert report is not None
    gate = report.check("verify:run_completion_gate")
    assert gate is not None and not gate.is_pass
    assert postflight_verdict_for(unsettled, now=STOP_MOMENT) is PostflightVerdict.DIRTY
    assert open_obligations(report) == ()
    assert obligation_verdict(report, now=STOP_MOMENT) is False
    assert may_close_clean(unsettled, now=STOP_MOMENT) is False


def test_a_pass_with_no_evidence_is_refused_at_construction_on_both_sides() -> None:
    """The rule this half leans on, asserted where each half keeps it.

    ``PostflightCheck`` requires a citation on a ``PASS``; ``PreflightCheck``
    requires one on *every* status, so a refusal carries its witness too. Both
    are refusals at construction rather than findings at read time.
    """
    with pytest.raises(InvariantViolationError) as refusal:
        PostflightCheck(name="residue:scan", status=PostflightStatus.PASS)
    assert refusal.value.rule == "pass_requires_evidence_ref"
    with pytest.raises(InvariantViolationError) as refusal:
        PreflightCheck(
            name=CHECK_INCIDENT_ACTIVE,
            status=CheckStatus.PASS,
            source=CheckSource.PORT,
            detail="no incident open",
            evidence_ref="   ",
            port="incident",
        )
    assert refusal.value.rule == "preflight_check_evidence_ref_not_blank"


def test_a_refusal_may_cite_its_evidence_and_a_pass_may_not_name_a_port_it_never_read() -> None:
    with pytest.raises(InvariantViolationError) as refusal:
        PreflightCheck(
            name=CHECK_TARGET_HEALTH,
            status=CheckStatus.PASS,
            source=CheckSource.REAL,
            detail="resolved",
            evidence_ref="topology/graph",
            port="incident",
        )
    assert refusal.value.rule == "preflight_check_port_mismatch"


# ==============================================================================
# Negative controls, each naming its own refusal
# ==============================================================================


def test_control_unreachable_port_refuses_with_the_port_reference() -> None:
    with pytest.raises(PreflightRefusedError) as refusal:
        PreflightGate(ports=PreflightPorts()).admit(_inputs())
    refusing = {c.name: c for c in refusal.value.refusing_checks}
    assert set(refusing) == set(PORT_CHECKS)
    for field, check, _, _, _ in PORT_SHAPES:
        entry = refusing[check]
        assert entry.status is CheckStatus.UNAVAILABLE
        assert entry.evidence_ref == f"port/{field}"
        assert entry.port == field
    assert refusal.value.trigger.reason is StopReason.PREFLIGHT_FAILED
    assert "incident:active=unavailable @port/incident" in refusal.value.trigger.detail


def test_control_empty_check_set_is_refused_with_no_checks_to_name() -> None:
    with pytest.raises(PreflightRefusedError) as refusal:
        PreflightGate(checks=()).admit(_inputs())
    assert refusal.value.report.checks == ()
    assert refusal.value.refusing_checks == ()
    assert "cannot certify a run" in refusal.value.report.refusal_reason


def test_control_an_agent_that_cannot_undo_is_refused_even_though_it_can_inject() -> None:
    with pytest.raises(PreflightRefusedError) as refusal:
        _gate().admit(
            _inputs(agents=(_agent(faults=("proc.pause",), kinds=(CapabilityKind.FAULT_INJECT,)),))
        )
    entry = refusal.value.report.check(CHECK_AGENT_CAPABILITY)
    assert entry is not None
    assert entry.status is CheckStatus.FAIL
    assert entry.evidence_ref == "fault/proc.pause"
    # Only that one check refused: a refusal is not a blanket.
    assert [c.name for c in refusal.value.refusing_checks] == [CHECK_AGENT_CAPABILITY]


def test_control_budget_refusals_are_availability_never_a_second_headroom_verdict() -> None:
    """A budget with no headroom left is the real guard's refusal, not this gate's.

    ``check_budget_available`` deliberately judges *availability*: it refuses a
    budget-shaped object that would admit everything, and leaves the headroom
    question to the one guard that answers it. Were the gate to judge headroom
    too there would be two judges of one budget — the duplication the module's
    design note refuses, and the reason ``admit`` is never called on a guard.
    """
    counter, guard = counting_budget()
    assert check_budget_available(_inputs(budget=guard)).status is CheckStatus.PASS
    assert counter.admit_calls == []
    # What the gate *does* refuse is a budget that cannot mean anything at all.
    assert check_budget_available(_inputs(budget=None)).status is CheckStatus.FAIL
    assert check_budget_available(_inputs(budget=real_guard(with_budget=False))).status is (
        CheckStatus.FAIL
    )
    assert check_budget_available(_inputs(budget=real_guard(with_estimate=False))).status is (
        CheckStatus.FAIL
    )


def test_control_a_policy_denial_is_refused_by_name_and_by_citation() -> None:
    with pytest.raises(PreflightRefusedError) as refusal:
        _gate().admit(_inputs(policy=_deny()))
    entry = refusal.value.report.check(CHECK_POLICY_AVAILABLE)
    assert entry is not None
    assert entry.status is CheckStatus.FAIL
    assert "production policy forbids this" in entry.detail
    assert entry.evidence_ref == "policy/gate-test@1"


# ==============================================================================
# The machine-readable half — what a checklist surface would render
# ==============================================================================


def test_the_report_renders_machine_readably() -> None:
    report = _gate().evaluate(_inputs(policy=_deny()))
    recorded = report.inputs()
    assert recorded["run_id"] == RUN_ID
    assert recorded["granted"] is False
    assert recorded["vacuous"] is False
    assert len(recorded["checks"]) == 12
    assert recorded["checks"][0] == {
        "name": CHECK_PLAN_ADMITTED,
        "status": "pass",
        "source": "real",
        "evidence_ref": "topology/t-1",
        "port": "",
    }
    # Every refusal is findable by the pair a checklist would render.
    assert {c["name"] for c in recorded["checks"] if c["status"] != "pass"} == {
        CHECK_POLICY_AVAILABLE
    }


def test_a_report_for_a_vacuous_gate_still_renders_as_vacuous() -> None:
    recorded = PreflightGate(checks=()).evaluate(_inputs()).inputs()
    assert recorded["vacuous"] is True
    assert recorded["granted"] is False
    assert recorded["checks"] == []


def test_the_module_level_evaluate_is_the_method_and_reports_rather_than_raises() -> None:
    gate = PreflightGate(ports=PreflightPorts())
    report = evaluate(gate, _inputs())
    assert report == gate.evaluate(_inputs())
    assert len(report.refusing_checks) == 5
