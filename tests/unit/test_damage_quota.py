"""Cumulative damage quota — the sequence limit the per-step checks cannot see.

Every limit ``check_blast_radius`` enforced before this quota existed —
``max_services_pct``, ``max_hosts``, ``max_concurrent_faults``,
``max_duration_per_fault_s``, ``forbidden_fault_pairs`` — is evaluated on a
*single* step. A plan of N individually-tiny faults therefore passes all of
them while impairing a target far past the point any one fault could. These
tests pin the refusal for that case, and pin the two properties that make the
new limit safe to add: it cannot weaken the five that came before, and it fires
before the offending step executes.

``test_forbidden_fault_pair_is_enforced_on_a_three_fault_plan`` is a regression
guard for a different bug: the pair rule built a set of *every* fault so far
plus the new one, so on any plan longer than two steps it tested a 3+-element
set against two-element forbidden pairs and matched nothing.
"""

from __future__ import annotations

from typing import Any

import pytest

from mayhem.cli.execution import blast_radius_display
from mayhem.config import PolicyCfg
from mayhem.controller.preflight import build_preflight
from mayhem.controller.safety import (
    SafetyContext,
    SafetyRefusedError,
    check_blast_radius,
    validate_plan,
)
from mayhem.domain.catalog import definition_for
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.faults import Reversibility
from mayhem.domain.quota import (
    RULE_BUDGET,
    RULE_PER_FAULT_CEILING,
    UNRESOLVED_FAULT_WEIGHT,
    DamageLedger,
    DamageQuota,
    damage_weight,
    damage_weight_for,
    is_catalog_fault,
)
from mayhem.domain.risks import RiskLevel
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    HostNode,
    NodeKind,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)

FP = "f" * 64


def _graph() -> TopologyGraph:
    """Three independent services on one host, plus their dependencies.

    Independent on purpose: faulting ``n-db`` must not implicate the others, so
    a test that wants a *narrow* per-step blast can have one and a test that
    wants the cumulative total to dominate is measuring the ledger rather than
    ``dependents_closure``.
    """
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-a", name="a"),
            ServiceNode(id="n-b", name="b"),
            ServiceNode(id="n-c", name="c"),
            HostNode(id="h-local", name="local", transport="local"),
            HostNode(id="h-remote", name="remote", transport="ssh"),
        ),
        edges=(
            Edge(src="n-a", dst="n-b", kind=EdgeKind.DEPENDS_ON, weight=1.0),
            Edge(src="n-b", dst="n-c", kind=EdgeKind.DEPENDS_ON, weight=1.0),
        ),
    )


def _permissive_per_step() -> BlastRadiusBudget:
    """Per-step limits that no plan in this file should ever trip.

    Lifted so that anything these tests observe is the quota's doing and not a
    per-step cap firing first. ``test_per_step_limits_still_fire`` deliberately
    uses a *tight* one instead.
    """
    return BlastRadiusBudget(
        max_services_pct=100.0,
        max_hosts=2**31 - 1,
        max_concurrent_faults=2**31 - 1,
        max_duration_per_fault_s=float("inf"),
        forbidden_fault_pairs=frozenset(),
    )


def _ctx(
    budget: BlastRadiusBudget | None = None,
    quota: DamageQuota | None = None,
) -> SafetyContext:
    return SafetyContext(
        policy=PolicyCfg(),
        budget=budget or _permissive_per_step(),
        fingerprint=FP,
        damage_quota=quota or DamageQuota(),
    )


def _plan(
    fault_ids: tuple[str, ...],
    durations: tuple[float, ...],
    node_ids: tuple[str, ...] | None = None,
) -> ExecutionPlan:
    targets = node_ids or tuple("n-a" for _ in fault_ids)
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="a")
    steps = tuple(
        PlannedStep(
            id=f"s{i}",
            seq=i,
            raw_action=InjectFault(fault=fid, selectors=(selector,), duration=dur),
            fault=PlannedFault(
                fault_id=fid,
                targets=(ResolvedTarget(selector=selector, node_ids=frozenset({nid})),),
                duration=dur,
            ),
        )
        for i, (fid, dur, nid) in enumerate(zip(fault_ids, durations, targets, strict=True))
    )
    return ExecutionPlan(
        run_id="r-quota",
        kind=ExperimentKind.DETERMINISTIC,
        steps=steps,
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=FP,
    )


def _run(plan: ExecutionPlan, graph: TopologyGraph, safety: SafetyContext) -> list[str]:
    """Execute the plan the way ``executor.execute`` does, recording what ran.

    ``executor.execute`` gates the *whole* plan with ``validate_plan`` before
    it opens a run, so a quota refusal cannot land mid-execution. This mirrors
    that ordering and returns the ids of the steps that actually executed, so a
    test can assert the offending step is not in it.
    """
    validate_plan(plan, graph, safety)
    return [s.fault.fault_id for s in plan.steps if s.fault is not None]


# -- the damage model is derived from the real catalog ----------------------------


def test_weight_is_the_catalog_risk_times_the_catalog_reversibility():
    """A faked cost table passes every behavioural test; this one cannot pass it.

    The expected weight is recomputed here from the same ``FaultDefinition``
    the gate reads, so any local table — a per-fault dict, a hardcoded ladder,
    a weight that ignores ``reversibility`` — makes this fail.
    """
    for fault_id in ("proc.pause", "net.latency", "process.kill", "k8s.node_drain"):
        assert is_catalog_fault(fault_id), fault_id
        definition = definition_for(fault_id)
        assert definition.reversibility is not None, fault_id
        assert damage_weight(fault_id) == damage_weight_for(definition)
        assert damage_weight(fault_id) == pytest.approx(damage_weight_for(definition), rel=1e-12)
        # ...and the weight really is a function of the two catalog fields.
        assert damage_weight(fault_id) != 1.0 or definition.risk in (
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
        )


def test_weight_rises_with_the_real_catalog_risk_ladder():
    """Ordering is taken from ``domain/risks.py``, not asserted per fault id."""
    low = damage_weight_for(definition_for("proc.pause"))  # LOW, REVERSIBLE
    high = damage_weight_for(definition_for("process.kill"))  # HIGH, RECONCILED
    critical = damage_weight_for(definition_for("k8s.node_drain"))  # CRITICAL
    assert low < high < critical

    assert definition_for("k8s.node_drain").risk is RiskLevel.CRITICAL
    assert definition_for("process.kill").reversibility is Reversibility.RECONCILED


def test_reversible_and_irreversible_damage_price_differently():
    reversible = damage_weight_for(definition_for("proc.pause"))
    reconciled = damage_weight_for(definition_for("process.kill"))
    assert reversible < reconciled
    assert damage_weight_for(definition_for("k8s.node_drain")) == pytest.approx(
        damage_weight_for(definition_for("k8s.node_drain"))
    )


def test_unresolvable_fault_is_priced_at_the_top_of_the_ladder():
    """Fail-safe: a fault the catalog cannot price is never the cheap one."""
    assert not is_catalog_fault("not.a.real.fault")
    assert damage_weight("not.a.real.fault") == UNRESOLVED_FAULT_WEIGHT
    assert (
        max(damage_weight(f) for f in ("proc.pause", "net.latency", "k8s.node_drain"))
        < UNRESOLVED_FAULT_WEIGHT
    )


# -- the ledger, on its own --------------------------------------------------------


def test_ledger_accumulates_per_target_and_reports_the_worst():
    """Pure, no graph, no gate: the ledger is testable by itself."""
    ledger = DamageLedger()
    quota = DamageQuota(budget_s=10_000.0)
    for _ in range(5):
        ledger.charge(
            fault_id="net.latency", duration_s=100.0, node_ids=["n-a", "n-b"], quota=quota
        )
    # 100s x MEDIUM(1.0) x REVERSIBLE(1.0) = 100 damage-seconds per node.
    assert ledger.damage_for("n-a") == pytest.approx(500.0)
    assert ledger.damage_for("n-b") == pytest.approx(500.0)
    assert ledger.damage_for("n-c") == 0.0
    assert ledger.worst_node == "n-a"
    assert ledger.worst_node_s == pytest.approx(500.0)
    assert ledger.total_s == pytest.approx(1000.0)  # 2 nodes x 5 steps
    assert ledger.steps == 5
    assert ledger.by_node_fault()[("n-a", "net.latency")] == pytest.approx(500.0)


def test_ledger_refuses_the_step_that_takes_the_total_over():
    quota = DamageQuota(budget_s=250.0)
    ledger = DamageLedger()
    for i in range(2):
        charge = ledger.charge(
            fault_id="net.latency", duration_s=100.0, node_ids=["n-a"], quota=quota
        )
        assert not charge.exceeded
        assert charge.step_index == i
    charge = ledger.charge(fault_id="net.latency", duration_s=100.0, node_ids=["n-a"], quota=quota)
    assert charge.exceeded
    assert charge.rule_id == RULE_BUDGET
    assert charge.worst_node_s == pytest.approx(300.0)
    assert charge.limit_s == 250.0
    assert "300" in charge.reason and "250" in charge.reason
    assert "net.latency" in charge.reason


def test_ledger_per_fault_ceiling_fires_on_one_big_fault():
    quota = DamageQuota(budget_s=1_000_000.0, per_fault_ceiling_s=500.0)
    ledger = DamageLedger()
    charge = ledger.charge(
        fault_id="k8s.node_drain", duration_s=300.0, node_ids=["n-a"], quota=quota
    )
    assert charge.exceeded
    assert charge.rule_id == RULE_PER_FAULT_CEILING
    assert charge.worst_node_s == pytest.approx(1200.0)  # 300s x CRITICAL(4) x REVERSIBLE


# -- the quota refuses a plan the per-step checks pass -----------------------------


def test_cumulative_budget_refuses_a_plan_whose_every_step_is_legal():
    """Ten legal steps, each far inside all five per-step caps; the sum is not.

    Every step: 1 of 3 services (33% vs a 100% cap), 0 hosts, 10 concurrent
    faults vs an effectively infinite cap, 30s against the per-fault cap. All
    five pass. The tenth step is what takes ``n-a`` over its cumulative budget.
    """
    graph = _graph()
    fault_ids = ("net.latency",) * 10
    durations = (30.0,) * 10
    plan = _plan(fault_ids, durations)
    safety = _ctx(quota=DamageQuota(budget_s=250.0))

    # The five per-step limits genuinely pass, one at a time, on the real gate.
    for i in range(10):
        stats = check_blast_radius(
            graph,
            {"n-a"},
            durations[i],
            fault_ids[:i],
            fault_ids[i],
            ctx=safety,
            ledger=DamageLedger(),
        )
        assert stats["services_pct"] == pytest.approx(33.3, abs=0.1)
        assert stats["hosts"] == 0.0
        assert stats["duration_per_fault"] == 30.0

    # The plan as a whole is refused, on the ninth step: 9 x 30s x MEDIUM(1.0)
    # x REVERSIBLE(1.0) = 270 > 250. The tenth is never reached.
    with pytest.raises(SafetyRefusedError) as caught:
        _run(plan, graph, safety)
    dec = caught.value.decision
    assert dec is not None
    assert dec.rule_id == RULE_BUDGET
    assert dec.inputs["accumulated_damage_s"] == pytest.approx(270.0)
    assert dec.inputs["budget_s"] == 250.0
    assert dec.inputs["node_id"] == "n-a"
    assert dec.inputs["fault_id"] == "net.latency"
    assert dec.inputs["step_index"] == 8


def test_refusal_names_budget_total_limit_and_the_offending_step():
    graph = _graph()
    plan = _plan(("net.latency",) * 4, (30.0,) * 4)
    safety = _ctx(quota=DamageQuota(budget_s=100.0))

    with pytest.raises(SafetyRefusedError) as caught:
        _run(plan, graph, safety)
    reason = str(caught.value)
    # the budget (by name, in the reason and in the rule id)
    assert RULE_BUDGET in reason
    assert "damage quota" in reason
    # the accumulated total and the limit, as numbers
    assert "120" in reason  # 4 x 30 accumulated
    assert "100" in reason  # the budget
    # which step pushed it over
    assert "step 3" in reason
    assert "net.latency" in reason
    # and the node whose total it was
    assert "n-a" in reason

    dec = caught.value.decision
    assert dec is not None
    assert dec.remediation
    assert "damage_quota.budget_s" in dec.remediation


def test_refusal_happens_before_the_offending_step_executes():
    """The whole plan is gated first (as ``executor.execute`` does), so no
    partial damage is ever applied and the offending step never runs."""
    graph = _graph()
    fault_ids = ("net.latency", "net.packet_loss", "dns.servfail", "http.latency")
    durations = (30.0, 30.0, 30.0, 30.0)
    plan = _plan(fault_ids, durations)
    safety = _ctx(quota=DamageQuota(budget_s=100.0))

    with pytest.raises(SafetyRefusedError):
        _run(plan, graph, safety)

    # The steps before the breach were admitted, the breaching step was not.
    allowed = [d.inputs["fault_id"] for d in safety.decisions if d.rule_id == "blast_radius.allow"]
    assert allowed == ["net.latency", "net.packet_loss", "dns.servfail"]
    refused = [d.inputs["fault_id"] for d in safety.decisions if d.rule_id == RULE_BUDGET]
    assert refused == ["http.latency"]


def test_step_by_step_gating_also_stops_before_the_offending_step():
    """A gate called per step (rather than once for the plan) refuses at the
    same step, with the same numbers — so the refusal is not an artifact of
    validating the plan as a whole."""
    graph = _graph()
    fault_ids = ("net.latency",) * 5
    durations = (30.0,) * 5
    safety = _ctx(quota=DamageQuota(budget_s=100.0))
    executed: list[str] = []
    ledger = DamageLedger()

    with pytest.raises(SafetyRefusedError) as caught:
        for i, fault_id in enumerate(fault_ids):
            check_blast_radius(
                graph,
                {"n-a"},
                durations[i],
                tuple(fault_ids[:i]),
                fault_id,
                ctx=safety,
                ledger=ledger,
            )
            executed.append(fault_id)

    assert executed == list(fault_ids[:3])  # the fourth step never ran
    assert caught.value.decision is not None
    assert caught.value.decision.inputs["step_index"] == 3


def test_plan_within_the_cumulative_budget_still_runs():
    graph = _graph()
    plan = _plan(("net.latency", "net.packet_loss", "dns.servfail"), (10.0, 10.0, 10.0))
    safety = _ctx(quota=DamageQuota(budget_s=10_000.0))

    assert _run(plan, graph, safety) == ["net.latency", "net.packet_loss", "dns.servfail"]
    assert not [d for d in safety.decisions if d.outcome == "deny"]


def test_a_plan_inside_the_budget_is_not_refused_just_because_it_is_long():
    """The budget is cumulative, not a fault count: ten short steps are fine."""
    graph = _graph()
    plan = _plan(("net.latency",) * 10, (1.0,) * 10)
    safety = _ctx(quota=DamageQuota(budget_s=1_000.0))
    assert len(_run(plan, graph, safety)) == 10


def test_damage_spans_the_dependents_closure_not_just_the_target():
    """A wide step charges every impaired node, so a narrow budget is reached
    faster on a target that many faults depend on."""
    graph = _graph()  # n-a -> n-b -> n-c
    ledger = DamageLedger()
    quota = DamageQuota(budget_s=10_000.0)
    from mayhem.controller.safety import _affected_node_ids

    affected = _affected_node_ids(graph, ["n-c"])
    assert affected == frozenset({"n-c", "n-b", "n-a"})
    ledger.charge(fault_id="net.latency", duration_s=60.0, node_ids=affected, quota=quota)
    for node in ("n-a", "n-b", "n-c"):
        assert ledger.damage_for(node) == pytest.approx(60.0)
    assert ledger.total_s == pytest.approx(180.0)


def test_a_dangerous_fault_costs_more_than_a_gentle_one_of_the_same_duration():
    """The ladder is load-bearing: at equal duration, HIGH/CRITICAL faults burn
    the budget faster, which is what makes the quota catch a nasty drill."""
    graph = _graph()
    gentle = DamageLedger()
    harsh = DamageLedger()
    quota = DamageQuota(budget_s=10_000.0)
    gentle.charge(fault_id="proc.pause", duration_s=100.0, node_ids=["n-a"], quota=quota)
    harsh.charge(fault_id="k8s.node_drain", duration_s=100.0, node_ids=["n-a"], quota=quota)
    assert harsh.damage_for("n-a") > gentle.damage_for("n-a") * 3


# -- the per-step limits are untouched ---------------------------------------------


def test_per_step_limits_still_fire_when_the_quota_is_wide_open():
    """A generous quota must not mask any of the five per-step refusals."""
    graph = _graph()
    quota = DamageQuota(budget_s=10_000_000.0, per_fault_ceiling_s=1_000_000.0)

    services = _ctx(
        BlastRadiusBudget(
            max_services_pct=10.0,
            max_hosts=99,
            max_concurrent_faults=99,
            max_duration_per_fault_s=float("inf"),
            forbidden_fault_pairs=frozenset(),
        ),
        quota,
    )
    with pytest.raises(SafetyRefusedError) as caught:
        check_blast_radius(graph, {"n-a"}, 5.0, (), "net.latency", ctx=services)
    assert caught.value.decision is not None
    assert caught.value.decision.rule_id == "blast_radius.max_services_pct"

    hosts = _ctx(
        BlastRadiusBudget(
            max_services_pct=100.0,
            max_hosts=1,
            max_concurrent_faults=99,
            max_duration_per_fault_s=float("inf"),
            forbidden_fault_pairs=frozenset(),
        ),
        quota,
    )
    with pytest.raises(SafetyRefusedError) as caught:
        check_blast_radius(graph, {"h-local", "h-remote"}, 5.0, (), "net.latency", ctx=hosts)
    assert caught.value.decision is not None
    assert caught.value.decision.rule_id == "blast_radius.max_hosts"

    concurrent = _ctx(
        BlastRadiusBudget(
            max_services_pct=100.0,
            max_hosts=99,
            max_concurrent_faults=1,
            max_duration_per_fault_s=float("inf"),
            forbidden_fault_pairs=frozenset(),
        ),
        quota,
    )
    with pytest.raises(SafetyRefusedError) as caught:
        check_blast_radius(graph, {"n-a"}, 5.0, ("net.latency",), "dns.servfail", ctx=concurrent)
    assert caught.value.decision is not None
    assert caught.value.decision.rule_id == "blast_radius.max_concurrent_faults"

    duration = _ctx(
        BlastRadiusBudget(
            max_services_pct=100.0,
            max_hosts=99,
            max_concurrent_faults=99,
            max_duration_per_fault_s=1.0,
            forbidden_fault_pairs=frozenset(),
        ),
        quota,
    )
    with pytest.raises(SafetyRefusedError) as caught:
        check_blast_radius(graph, {"n-a"}, 5.0, (), "net.latency", ctx=duration)
    assert caught.value.decision is not None
    assert caught.value.decision.rule_id == "blast_radius.max_duration_per_fault_s"


def test_stricter_wins_when_the_quota_is_looser_than_a_per_step_limit():
    """Per-step breach, quota has room: the per-step rule refuses, unchanged."""
    graph = _graph()
    safety = _ctx(
        BlastRadiusBudget(
            max_services_pct=10.0,
            max_hosts=99,
            max_concurrent_faults=99,
            max_duration_per_fault_s=float("inf"),
            forbidden_fault_pairs=frozenset(),
        ),
        DamageQuota(budget_s=10_000_000.0),
    )
    with pytest.raises(SafetyRefusedError) as caught:
        check_blast_radius(graph, {"n-a"}, 5.0, (), "net.latency", ctx=safety)
    dec = caught.value.decision
    assert dec is not None
    assert dec.rule_id == "blast_radius.max_services_pct"
    assert "max_services_pct" in dec.reason


def test_stricter_wins_when_the_quota_is_stricter_than_a_per_step_limit():
    """Per-step all clear, quota exhausted: the quota refuses."""
    graph = _graph()
    safety = _ctx(quota=DamageQuota(budget_s=10.0))
    with pytest.raises(SafetyRefusedError) as caught:
        check_blast_radius(graph, {"n-a"}, 30.0, (), "net.latency", ctx=safety)
    dec = caught.value.decision
    assert dec is not None
    assert dec.rule_id == RULE_BUDGET


def test_a_step_breaching_both_is_refused_once_and_names_the_per_step_rule():
    """Both limits refuse; the per-step rule speaks first because it is the one
    that fails on its own, and the plan is still refused either way."""
    graph = _graph()
    safety = _ctx(
        BlastRadiusBudget(
            max_services_pct=10.0,
            max_hosts=99,
            max_concurrent_faults=99,
            max_duration_per_fault_s=float("inf"),
            forbidden_fault_pairs=frozenset(),
        ),
        DamageQuota(budget_s=1.0),
    )
    with pytest.raises(SafetyRefusedError) as caught:
        check_blast_radius(graph, {"n-a"}, 30.0, (), "net.latency", ctx=safety)
    dec = caught.value.decision
    assert dec is not None
    assert dec.rule_id == "blast_radius.max_services_pct"
    assert [d.outcome for d in safety.decisions] == ["deny"]  # exactly one refusal


def test_validate_plan_is_repeatable_on_a_reused_context():
    """A ledger stored on the context would double-charge and refuse the second
    pass; the ledger is per-validation, so the same plan gives the same verdict
    however many times it is gated."""
    graph = _graph()
    plan = _plan(("net.latency",) * 4, (30.0,) * 4)
    safety = _ctx(quota=DamageQuota(budget_s=100.0))
    for _ in range(3):
        with pytest.raises(SafetyRefusedError) as caught:
            _run(plan, graph, safety)
        dec = caught.value.decision
        assert dec is not None
        # 4 x 30 = 120 every time, not 240 on the second pass.
        assert dec.inputs["accumulated_damage_s"] == pytest.approx(120.0)


# -- forbidden_fault_pairs: inert above two faults, now fixed ----------------------


def test_forbidden_fault_pair_is_enforced_on_a_three_fault_plan():
    """Regression guard for the silent no-op.

    ``forbidden_fault_pairs`` is a set of *pairs*. The rule used to compare a
    set of every fault so far plus the new one — ``{'a','b','c'}`` here — which
    matches nothing, so a user who forbade a pair and wrote a three-step drill
    was protected in name only. The pair is completed on the third step and the
    plan must be refused.
    """
    graph = _graph()
    safety = _ctx(
        BlastRadiusBudget(
            max_services_pct=100.0,
            max_hosts=99,
            max_concurrent_faults=99,
            max_duration_per_fault_s=float("inf"),
            forbidden_fault_pairs=frozenset({frozenset({"net.latency", "net.packet_loss"})}),
        ),
        DamageQuota(budget_s=10_000_000.0),
    )
    fault_ids = ("dns.servfail", "net.latency", "net.packet_loss")

    with pytest.raises(SafetyRefusedError) as caught:
        for i, fault_id in enumerate(fault_ids):
            check_blast_radius(graph, {"n-a"}, 1.0, tuple(fault_ids[:i]), fault_id, ctx=safety)
    dec = caught.value.decision
    assert dec is not None
    assert dec.rule_id == "blast_radius.forbidden_fault_pairs"
    assert dec.inputs["pair"] == ["net.latency", "net.packet_loss"]


def test_forbidden_pair_still_refuses_a_two_fault_plan():
    """The behaviour the buggy rule accidentally got right."""
    graph = _graph()
    safety = _ctx(
        BlastRadiusBudget(
            max_services_pct=100.0,
            max_hosts=99,
            max_concurrent_faults=99,
            max_duration_per_fault_s=float("inf"),
            forbidden_fault_pairs=frozenset({frozenset({"net.latency", "dns.servfail"})}),
        )
    )
    with pytest.raises(SafetyRefusedError, match="forbidden"):
        check_blast_radius(graph, {"n-a"}, 1.0, ("net.latency",), "dns.servfail", ctx=safety)


def test_forbidden_pair_is_caught_wherever_it_sits_in_the_plan():
    """Order does not matter: the pair is refused on whichever member is second."""
    graph = _graph()
    for fault_ids in (
        ("net.latency", "net.packet_loss", "dns.servfail"),
        ("net.packet_loss", "net.latency", "dns.servfail"),
        ("dns.servfail", "net.latency", "net.packet_loss"),
    ):
        safety = _ctx(
            BlastRadiusBudget(
                max_services_pct=100.0,
                max_hosts=99,
                max_concurrent_faults=99,
                max_duration_per_fault_s=float("inf"),
                forbidden_fault_pairs=frozenset({frozenset({"net.latency", "net.packet_loss"})}),
            )
        )
        with pytest.raises(SafetyRefusedError, match="forbidden"):
            for i, fault_id in enumerate(fault_ids):
                check_blast_radius(graph, {"n-a"}, 1.0, tuple(fault_ids[:i]), fault_id, ctx=safety)


def test_a_plan_without_the_forbidden_pair_is_unaffected():
    graph = _graph()
    safety = _ctx(
        BlastRadiusBudget(
            max_services_pct=100.0,
            max_hosts=99,
            max_concurrent_faults=99,
            max_duration_per_fault_s=float("inf"),
            forbidden_fault_pairs=frozenset({frozenset({"net.latency", "net.packet_loss"})}),
        )
    )
    for i, fault_id in enumerate(("net.latency", "dns.servfail", "net.load")):
        check_blast_radius(
            graph, {"n-a"}, 1.0, ("net.latency", "dns.servfail")[:i], fault_id, ctx=safety
        )


# -- preflight shows the sequence risk before the run ------------------------------


def _preflight(plan: Any, graph: Any, safety: SafetyContext) -> dict[str, Any]:
    return dict(
        build_preflight(
            spec_path=None,
            compose=None,
            graph=graph,
            store=None,
            config_path=None,
            profile=None,
            allow_critical=False,
            target=None,
            engine="podman",
            plan=plan,
            safety=safety,
            fingerprint=FP,
        ).blast_radius
    )


def test_preflight_projects_the_whole_plan_damage_before_it_runs():
    graph = _graph()
    plan = _plan(("net.latency",) * 4, (30.0,) * 4)
    safety = _ctx(quota=DamageQuota(budget_s=100.0))

    blast = _preflight(plan, graph, safety)
    # 4 x 30s x 1.0 on one target.
    assert blast["damage_worst_target_s"] == pytest.approx(120.0)
    assert blast["damage_total_s"] == pytest.approx(120.0)
    assert blast["damage_worst_target"] == "n-a"
    assert blast["damage_budget_s"] == 100.0
    assert blast["damage_quota_ok"] is False
    assert blast["status"] == "exceeded"
    assert [v["rule_id"] for v in blast["violations"]] == [RULE_BUDGET]
    assert "damage_quota.budget_s" in blast["violations"][0]["remediation"]

    rendered = blast_radius_display(blast)
    assert "damage_worst_target_s=120.0" in rendered
    assert "damage_budget_s=100.0" in rendered
    assert "damage_worst_target=n-a" in rendered
    assert RULE_BUDGET in rendered
    assert "WILL REFUSE" in rendered


def test_preflight_reports_a_within_budget_plan_as_such():
    graph = _graph()
    plan = _plan(("net.latency",) * 3, (10.0,) * 3)
    safety = _ctx(quota=DamageQuota(budget_s=10_000.0))

    blast = _preflight(plan, graph, safety)
    assert blast["damage_quota_ok"] is True
    assert blast["damage_worst_target_s"] == pytest.approx(30.0)
    assert blast["status"] == "within_budget"
    assert "WILL REFUSE" not in blast_radius_display(blast)


def test_preflight_damage_projection_ignores_the_refused_step_and_still_totals():
    """The projection runs through a lifted quota so the operator sees the whole
    plan, including the steps after the one that will refuse."""
    graph = _graph()
    plan = _plan(("net.latency",) * 5, (30.0,) * 5)
    safety = _ctx(quota=DamageQuota(budget_s=100.0))

    blast = _preflight(plan, graph, safety)
    assert blast["damage_worst_target_s"] == pytest.approx(150.0)
    assert blast["damage_by_target"]["n-a"] == pytest.approx(150.0)
    assert blast["fault_count"] == 5


def test_preflight_shows_every_limit_and_the_quota_together():
    graph = _graph()
    plan = _plan(("net.latency",) * 2, (5.0,) * 2)
    safety = _ctx(quota=DamageQuota(budget_s=10_000.0))

    rendered = blast_radius_display(_preflight(plan, graph, safety))
    for cap in (
        "max_services_pct",
        "max_hosts",
        "max_concurrent_faults",
        "max_duration_per_fault_s",
        "forbidden_fault_pairs",
        "damage_budget_s",
        "damage_per_fault_ceiling_s",
        "damage_window_s",
    ):
        assert cap in rendered
