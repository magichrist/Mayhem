"""Preflight must show the *same* blast radius the safety gate enforces.

The preview used to be a looser re-derivation of
``controller.safety.check_blast_radius``: it omitted ``dependents_closure``,
mismatched node kinds between numerator and denominator, never surfaced
``max_concurrent_faults`` or ``max_duration_per_fault_s``, and swallowed every
error into ``{}`` — which rendered identically to a tool with no opinion.

The first test here is the drift guard: it compares the preflight's number
against the real gate's number for the same plan. If the two ever diverge, the
operator is shown one set of numbers and enforced against another.
"""

from __future__ import annotations

from typing import Any

import pytest

from mayhem.cli.execution import blast_radius_display
from mayhem.cli.render import render_preflight_human
from mayhem.config import PolicyCfg
from mayhem.controller.preflight import build_preflight
from mayhem.controller.safety import (
    SafetyContext,
    SafetyRefusedError,
    check_blast_radius,
    validate_plan,
)
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
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
    """web -> api -> db, all on one host.

    ``dependents_closure`` matters here: faulting ``db`` must be reported as
    hitting *all three* services, not just ``db``.
    """
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-api", name="api"),
            ServiceNode(id="n-web", name="web"),
            ServiceNode(id="n-db", name="db"),
            HostNode(id="h-local", name="local", transport="local"),
        ),
        edges=(
            Edge(src="n-web", dst="n-api", kind=EdgeKind.DEPENDS_ON, weight=1.0),
            Edge(src="n-api", dst="n-db", kind=EdgeKind.DEPENDS_ON, weight=2.0),
        ),
    )


def _ctx(budget: BlastRadiusBudget) -> SafetyContext:
    return SafetyContext(policy=PolicyCfg(), budget=budget, fingerprint=FP)


def _plan(
    *,
    node_ids: tuple[frozenset[str], ...] = (frozenset({"n-db"}),),
    durations: tuple[float, ...] = (10.0,),
    fault_ids: tuple[str, ...] = ("proc.pause",),
) -> ExecutionPlan:
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="db")
    steps = tuple(
        PlannedStep(
            id=f"s{i}",
            seq=i,
            raw_action=InjectFault(fault=fid, selectors=(selector,), duration=dur),
            fault=PlannedFault(
                fault_id=fid,
                targets=(ResolvedTarget(selector=selector, node_ids=ids),),
                duration=dur,
            ),
        )
        for i, (ids, dur, fid) in enumerate(zip(node_ids, durations, fault_ids, strict=True))
    )
    return ExecutionPlan(
        run_id="r1",
        kind=ExperimentKind.DETERMINISTIC,
        steps=steps,
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint=FP,
    )


def _preflight(plan: Any, graph: Any, safety: SafetyContext):
    return build_preflight(
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
    )


def _blast(preflight: Any) -> dict[str, Any]:
    """The preflight's blast record, typed for assertion."""
    return dict(preflight.blast_radius)


def _gate_pct(graph: TopologyGraph, plan: ExecutionPlan, safety: SafetyContext) -> float:
    """Run the real gate step by step exactly as ``validate_plan`` does."""
    probe = SafetyContext(
        policy=safety.policy,
        budget=safety.budget.model_copy(
            update={
                "max_services_pct": 100.0,
                "max_hosts": 2**31 - 1,
                "max_concurrent_faults": 2**31 - 1,
                "max_duration_per_fault_s": float("inf"),
                "forbidden_fault_pairs": frozenset(),
            }
        ),
        fingerprint=FP,
    )
    pct = 0.0
    seen: list[str] = []
    for step in plan.steps:
        if step.fault is None:
            continue
        ids = frozenset().union(*(t.node_ids for t in step.fault.targets))
        stats = check_blast_radius(
            graph, ids, float(step.fault.duration), tuple(seen), step.fault.fault_id, ctx=probe
        )
        pct = max(pct, stats["services_pct"])
        seen.append(step.fault.fault_id)
    return pct


# -- drift guard ------------------------------------------------------------------


def test_preflight_services_pct_equals_the_real_gate():
    """The headline number must be the gate's number, not a lookalike."""
    graph, plan = _graph(), _plan()
    safety = _ctx(BlastRadiusBudget(max_services_pct=100.0))

    blast = _blast(_preflight(plan, graph, safety))
    assert blast["services_pct"] == _gate_pct(graph, plan, safety)


def test_preflight_counts_dependents_closure_not_just_direct_targets():
    """Faulting ``db`` reaches web and api too — the preflight must say 100%."""
    blast = _blast(_preflight(_plan(), _graph(), _ctx(BlastRadiusBudget(max_services_pct=100.0))))
    assert blast["services_pct"] == 100.0
    assert blast["status"] == "within_budget"


def test_preflight_probing_adds_nothing_to_the_safety_record():
    """The preview probes the gate; the record the run is judged by is unchanged.

    ``check_blast_radius`` records a decision on every call. Preflight runs it
    once per step for numbers and again per step for the verdict, so it must
    do that on throwaway contexts — otherwise the safety record would carry
    preflight's own probe decisions.
    """
    plan, graph = _plan(), _graph()
    budget = BlastRadiusBudget(max_services_pct=100.0)

    baseline = _ctx(budget)
    validate_plan(plan, graph, baseline)

    probed = _ctx(budget)
    _preflight(plan, graph, probed)

    assert probed.decisions == baseline.decisions
    assert probed.warnings == baseline.warnings


# -- the two limits that were never shown -----------------------------------------


def test_rendered_preview_names_the_concurrency_and_duration_limits():
    """Both are enforced by the gate; before the fix neither appeared."""
    blast = _blast(_preflight(_plan(), _graph(), _ctx(BlastRadiusBudget(max_services_pct=100.0))))
    out = blast_radius_display(blast)

    assert "max_concurrent_faults" in out
    assert "max_duration_per_fault_s" in out
    assert "concurrent_faults=1" in out
    assert "duration_per_fault=10.0" in out


def test_rendered_preview_shows_every_limit_with_its_cap():
    out = blast_radius_display(
        _blast(_preflight(_plan(), _graph(), _ctx(BlastRadiusBudget(max_services_pct=100.0))))
    )
    for cap in (
        "max_services_pct",
        "max_hosts",
        "max_concurrent_faults",
        "max_duration_per_fault_s",
        "forbidden_fault_pairs",
    ):
        assert cap in out


# -- refusal is visible before execution -------------------------------------------


def test_refused_plan_shows_the_failing_limit_and_remediation_before_execution():
    """The reported symptom: preview silent, then ``[safety.refused]``."""
    graph = _graph()
    safety = _ctx(BlastRadiusBudget(max_services_pct=100.0, max_concurrent_faults=1))
    plan = _plan(
        node_ids=(frozenset({"n-db"}), frozenset({"n-api"})),
        durations=(10.0, 10.0),
        fault_ids=("proc.pause", "proc.cpu"),
    )

    # The real gate refuses this plan.
    with pytest.raises(SafetyRefusedError, match="max_concurrent_faults"):
        check_blast_radius(graph, {"n-api"}, 10.0, ("proc.pause",), "proc.cpu", ctx=safety)

    blast = _blast(_preflight(plan, graph, safety))
    assert blast["status"] == "exceeded"
    assert blast["concurrent_faults"] == 2.0
    assert blast["concurrent_faults_ok"] is False
    assert blast["max_concurrent_faults"] == 1
    assert [v["rule_id"] for v in blast["violations"]] == ["blast_radius.max_concurrent_faults"]

    out = blast_radius_display(blast)
    assert "WILL REFUSE" in out
    assert "blast_radius.max_concurrent_faults" in out
    assert "raise blast_radius.max_concurrent_faults" in out
    assert "OVER BUDGET" in out


def test_duration_overrun_names_the_duration_limit():
    graph = _graph()
    safety = _ctx(BlastRadiusBudget(max_services_pct=100.0, max_duration_per_fault_s=5.0))
    plan = _plan(durations=(60.0,))

    blast = _blast(_preflight(plan, graph, safety))
    assert blast["duration_per_fault"] == 60.0
    assert blast["duration_per_fault_ok"] is False
    assert [v["rule_id"] for v in blast["violations"]] == ["blast_radius.max_duration_per_fault_s"]
    assert "shorten duration" in blast_radius_display(blast)


def test_forbidden_fault_pair_names_the_pair():
    graph = _graph()
    safety = _ctx(
        BlastRadiusBudget(
            max_services_pct=100.0,
            forbidden_fault_pairs=frozenset({frozenset({"proc.pause", "proc.cpu"})}),
        )
    )
    plan = _plan(
        node_ids=(frozenset({"n-db"}), frozenset({"n-api"})),
        durations=(5.0, 5.0),
        fault_ids=("proc.pause", "proc.cpu"),
    )

    blast = _blast(_preflight(plan, graph, safety))
    assert blast["forbidden_fault_pairs_ok"] is False
    assert any(v["rule_id"] == "blast_radius.forbidden_fault_pairs" for v in blast["violations"])


# -- within budget -----------------------------------------------------------------


def test_passing_plan_shows_all_limits_within_budget():
    blast = _blast(_preflight(_plan(), _graph(), _ctx(BlastRadiusBudget(max_services_pct=100.0))))

    assert blast["status"] == "within_budget"
    assert blast["violations"] == []
    for key in (
        "services_pct",
        "hosts",
        "concurrent_faults",
        "duration_per_fault",
    ):
        assert blast[f"{key}_ok"] is True, key
    assert blast["forbidden_fault_pairs_ok"] is True
    assert "WILL REFUSE" not in blast_radius_display(blast)


def test_passing_plan_reports_measured_values_not_zeros():
    blast = _blast(_preflight(_plan(), _graph(), _ctx(BlastRadiusBudget(max_services_pct=100.0))))
    assert blast["services_pct"] == 100.0
    assert blast["fault_count"] == 1


# -- unknown is not zero and not absent ---------------------------------------------


def test_computation_failure_renders_unknown_with_a_reason():
    """A graph that cannot answer must never look like a radius of zero."""
    preflight = _preflight(_plan(), None, _ctx(BlastRadiusBudget()))

    assert _blast(preflight)["status"] == "unknown"
    assert _blast(preflight) != {}
    assert "topology" in _blast(preflight)["error"]

    out = blast_radius_display(_blast(preflight))
    assert "unknown" in out
    assert "could not compute" in out
    assert "0.0" not in out
    assert "within_budget" not in out


def test_missing_plan_renders_unknown():
    preflight = _preflight(None, _graph(), _ctx(BlastRadiusBudget()))
    assert _blast(preflight)["status"] == "unknown"
    assert "no plan" in _blast(preflight)["error"]


class _BrokenGraph:
    """A graph that raises the moment the gate tries to walk it."""

    def of_kind(self, _kind: Any) -> list[Any]:
        raise RuntimeError("topology index corrupt")

    def dependents_closure(self, _node_id: str) -> frozenset[str]:
        raise RuntimeError("topology index corrupt")

    def by_id(self, _node_id: str) -> Any:
        return None


def test_broken_graph_renders_unknown_not_an_empty_dict():
    blast = _blast(_preflight(_plan(), _BrokenGraph(), _ctx(BlastRadiusBudget())))

    assert blast["status"] == "unknown"
    assert "topology index corrupt" in blast["error"]


def test_unknown_state_reaches_the_human_renderer():
    preflight = _preflight(_plan(), None, _ctx(BlastRadiusBudget()))
    out = render_preflight_human(preflight)
    assert "blast_radius:" in out
    assert "could not compute" in out


# -- the human preview line carries the limits too ----------------------------------


def test_human_preview_names_the_limits_that_refuse():
    graph = _graph()
    safety = _ctx(BlastRadiusBudget(max_services_pct=100.0, max_concurrent_faults=1))
    plan = _plan(
        node_ids=(frozenset({"n-db"}), frozenset({"n-api"})),
        durations=(10.0, 10.0),
        fault_ids=("proc.pause", "proc.cpu"),
    )
    out = render_preflight_human(_preflight(plan, graph, safety))
    assert "max_concurrent_faults" in out
    assert "WILL REFUSE" in out
