"""Tests for the k-plan-4 multi-instance selection grammar (SP-4.1).

Covers:
- ``select_many`` dispatching one / count / percentage / all / random
- ``select_one`` backward compatibility
- Planner gate accepting non-reserved modes (reserved-mode flip removed)
- ``conflict.overlap`` refusal for same-target multi-instance faults
- ``selection.count_exceeds_eligible`` static error
"""

from __future__ import annotations

import pytest

from mayhem.domain.errors import SelectionError
from mayhem.domain.experiments import BlastRadiusBudget
from mayhem.domain.target import (
    ResourceKind,
    SelectionSpec,
    TargetScope,
)
from mayhem.domain.target_selector import select_many, select_one
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    K8sNode,
    PodNode,
    TopologyGraph,
)

# ── helpers ──────────────────────────────────────────────────────────────────


def _deploy_graph(*, n: int = 4) -> TopologyGraph:
    """Graph with ``n`` Running pods owned by Deployment ``web``."""
    pods = []
    edges = []
    for i in range(n):
        uid = f"pod-{i}"
        pods.append(
            PodNode(
                id=uid,
                name=f"web-{i:03d}",
                namespace="prod",
                node_name="worker-1",
                image="nginx:latest",
                state="Running",
                owner_kind="Deployment",
                owner_name="web",
                pod_uid=uid,
            )
        )
        edges.append(Edge(src=uid, dst="worker-1", kind=EdgeKind.RUNS_ON))
    nodes = (
        *pods,
        K8sNode(id="worker-1", name="worker-1", cluster="test-cluster", state="Ready"),
    )
    return TopologyGraph(nodes=nodes, edges=tuple(edges))


def _scope(
    kind: ResourceKind = ResourceKind.DEPLOYMENT,
    *,
    selection: SelectionSpec | None = None,
) -> TargetScope:
    return TargetScope(
        logical_id="web",
        runtime="kubernetes",
        kind=kind,
        authority={"namespace": "prod", "name": "web"},
        selection=selection,
    )


# ── select_many: mode one ───────────────────────────────────────────────────


class TestModeOne:
    def test_returns_deterministic_single_pick(self) -> None:
        graph = _deploy_graph()
        scope = _scope(selection=SelectionSpec(mode="one"))
        picked = select_many(graph, scope)
        assert picked is not None
        assert len(picked) == 1
        assert picked[0].name == "web-000"

    def test_select_one_matches_mode_one_pick(self) -> None:
        graph = _deploy_graph()
        scope = _scope(selection=SelectionSpec(mode="one"))
        assert select_one(graph, scope) == select_many(graph, scope)[0]


# ── select_many: mode count ─────────────────────────────────────────────────


class TestModeCount:
    def test_returns_exact_count(self) -> None:
        graph = _deploy_graph(n=5)
        scope = _scope(selection=SelectionSpec(mode="count", count=3))
        picked = select_many(graph, scope)
        assert picked is not None
        assert len(picked) == 3
        assert [p.name for p in picked] == ["web-000", "web-001", "web-002"]

    def test_count_exceeds_eligible_raises(self) -> None:
        graph = _deploy_graph(n=3)
        scope = _scope(selection=SelectionSpec(mode="count", count=5))
        with pytest.raises(SelectionError) as exc_info:
            select_many(graph, scope)
        assert exc_info.value.code == "selection.count_exceeds_eligible"


# ── select_many: mode percentage ────────────────────────────────────────────


class TestModePercentage:
    def test_ceil_eligible(self) -> None:
        graph = _deploy_graph(n=4)
        scope = _scope(selection=SelectionSpec(mode="percentage", percentage=30))
        picked = select_many(graph, scope)
        assert picked is not None
        # ceil(4 * 0.3) = 2
        assert len(picked) == 2

    def test_minimum_one(self) -> None:
        graph = _deploy_graph(n=20)
        scope = _scope(selection=SelectionSpec(mode="percentage", percentage=1))
        picked = select_many(graph, scope)
        assert picked is not None
        assert len(picked) == 1


# ── select_many: mode all ───────────────────────────────────────────────────


class TestModeAll:
    def test_returns_all_eligible(self) -> None:
        graph = _deploy_graph(n=5)
        scope = _scope(selection=SelectionSpec(mode="all"))
        picked = select_many(graph, scope)
        assert picked is not None
        assert len(picked) == 5
        assert [p.name for p in picked] == [f"web-{i:03d}" for i in range(5)]


# ── select_many: mode random ────────────────────────────────────────────────


class TestModeRandom:
    def test_returns_one_pod(self) -> None:
        graph = _deploy_graph(n=10)
        scope = _scope(selection=SelectionSpec(mode="random"))
        picked = select_many(graph, scope, seed=42)
        assert picked is not None
        assert len(picked) == 1

    def test_deterministic_under_same_seed(self) -> None:
        graph = _deploy_graph(n=10)
        scope = _scope(selection=SelectionSpec(mode="random"))
        a = select_many(graph, scope, seed=123)
        b = select_many(graph, scope, seed=123)
        assert [p.name for p in a] == [p.name for p in b]

    def test_scope_seed_default_deterministic(self) -> None:
        graph = _deploy_graph(n=10)
        scope = _scope(selection=SelectionSpec(mode="random"))
        a = select_many(graph, scope)
        b = select_many(graph, scope)
        assert [p.name for p in a] == [p.name for p in b]


# ── budget guard ────────────────────────────────────────────────────────────


class TestBudgetGuard:
    def test_out_of_budget_raises(self) -> None:
        graph = _deploy_graph(n=5)
        scope = _scope(selection=SelectionSpec(mode="count", count=3))
        budget = BlastRadiusBudget(max_concurrent_faults=2)
        with pytest.raises(SelectionError) as exc_info:
            select_many(graph, scope, budget=budget)
        assert exc_info.value.code == "selection.out_of_budget"
        assert "blast_radius.max_concurrent_faults" in str(exc_info.value)

    def test_within_budget_passes(self) -> None:
        graph = _deploy_graph(n=5)
        scope = _scope(selection=SelectionSpec(mode="count", count=2))
        budget = BlastRadiusBudget(max_concurrent_faults=3)
        picked = select_many(graph, scope, budget=budget)
        assert picked is not None
        assert len(picked) == 2


# ── eligibility filter ──────────────────────────────────────────────────────


class TestEligibility:
    def test_pending_deletion_excluded(self) -> None:
        graph = _deploy_graph(n=3)
        # Mutate first pod to be terminating
        pods = list(graph.nodes)
        pods[0] = pods[0].model_copy(update={"deletion_timestamp": "2026-09-13T00:00:00Z"})
        graph = TopologyGraph(nodes=tuple(pods), edges=graph.edges)
        scope = _scope(selection=SelectionSpec(mode="all"))
        picked = select_many(graph, scope)
        assert picked is not None
        assert len(picked) == 2
        assert all(p.pod_uid != "pod-0" for p in picked)

    def test_non_running_excluded(self) -> None:
        graph = _deploy_graph(n=3)
        pods = list(graph.nodes)
        pods[0] = pods[0].model_copy(update={"state": "Pending"})
        graph = TopologyGraph(nodes=tuple(pods), edges=graph.edges)
        scope = _scope(selection=SelectionSpec(mode="all"))
        picked = select_many(graph, scope)
        assert picked is not None
        assert len(picked) == 2

    def test_no_eligible_raises(self) -> None:
        graph = _deploy_graph(n=1)
        pods = [
            node.model_copy(update={"state": "Pending"})
            if getattr(node, "pod_uid", None) == "pod-0"
            else node
            for node in graph.nodes
        ]
        graph = TopologyGraph(nodes=tuple(pods), edges=graph.edges)
        scope = _scope(selection=SelectionSpec(mode="count", count=1))
        with pytest.raises(SelectionError) as exc_info:
            select_many(graph, scope)
        assert exc_info.value.code == "selection.no_eligible_pods"


# ── absent workload (logically pinned) ──────────────────────────────────────


class TestAbsentWorkload:
    def test_returns_none(self) -> None:
        graph = TopologyGraph(nodes=(), edges=())
        scope = _scope(selection=SelectionSpec(mode="count", count=2))
        assert select_many(graph, scope) is None


# ── node target refusal ─────────────────────────────────────────────────────


class TestNodeTarget:
    def test_k8s_node_refused(self) -> None:
        graph = _deploy_graph()
        scope = TargetScope(
            logical_id="worker-1",
            runtime="kubernetes",
            kind=ResourceKind.K8S_NODE,
            authority={"name": "worker-1"},
            selection=SelectionSpec(mode="count", count=1),
        )
        with pytest.raises(SelectionError) as exc_info:
            select_many(graph, scope)
        assert exc_info.value.code == "selection.node_target_unsupported"


# ── planner-level integration (SP-4.1 gate flip) ────────────────────────────


def _targeted_spec(
    *,
    faults: tuple = ("k8s.pod_kill",),
    selection: SelectionSpec | None = None,
) -> object:
    from mayhem.domain.experiments import (
        DrillConfig,
        DrillFault,
        DrillSpec,
        DrillTarget,
        ExecutionStep,
        KubernetesTargetSpec,
    )

    return DrillSpec(
        kind="drill",
        name="k8s-drill",
        config=DrillConfig(),
        targets={
            "web": DrillTarget(
                runtime="kubernetes",
                kubernetes=KubernetesTargetSpec(
                    kind=ResourceKind.DEPLOYMENT, namespace="prod", name="web"
                ),
                selection=selection,
                faults=tuple(DrillFault(fault=f) for f in faults),
            )
        },
        execution=(ExecutionStep(parallel=("web",)),),
    )


def _plan(spec) -> object:
    from mayhem.controller.planner import plan_drill

    return plan_drill(
        "r-k8s",
        spec,
        _deploy_graph(n=6),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
    )


class TestPlannerMultiMode:
    def test_count_mode_compiles(self) -> None:
        plan = _plan(_targeted_spec(selection=SelectionSpec(mode="count", count=2)))
        assert len(plan.steps) == 1

    def test_percentage_mode_compiles(self) -> None:
        plan = _plan(_targeted_spec(selection=SelectionSpec(mode="percentage", percentage=50)))
        assert len(plan.steps) == 1

    def test_all_mode_compiles(self) -> None:
        plan = _plan(_targeted_spec(selection=SelectionSpec(mode="all")))
        assert len(plan.steps) == 1

    def test_random_mode_compiles(self) -> None:
        plan = _plan(_targeted_spec(selection=SelectionSpec(mode="random")))
        assert len(plan.steps) == 1

    def test_count_exceeds_eligible_is_plan_error(self) -> None:
        from mayhem.domain.errors import SelectionError

        with pytest.raises(SelectionError) as exc_info:
            _plan(_targeted_spec(selection=SelectionSpec(mode="count", count=9)))
        assert exc_info.value.code == "selection.count_exceeds_eligible"

    def test_two_multi_faults_same_target_refused(self) -> None:
        from mayhem.controller.planner import PlanningError

        spec = _targeted_spec(
            faults=("k8s.pod_kill", "k8s.pod_evict"),
            selection=SelectionSpec(mode="count", count=2),
        )
        with pytest.raises(PlanningError) as exc_info:
            _plan(spec)
        assert "conflict.overlap" in str(exc_info.value)

    def test_two_single_pod_faults_same_target_allowed(self) -> None:
        spec = _targeted_spec(
            faults=("k8s.pod_kill", "k8s.pod_evict"),
            selection=SelectionSpec(mode="one"),
        )
        plan = _plan(spec)
        assert len(plan.steps) == 2
