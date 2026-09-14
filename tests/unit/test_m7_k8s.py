"""Milestone 7 — Kubernetes interface + model tests.

Phases:
  7.1  topology node-kind extensions (POD / K8S_NODE)
  7.2  KubernetesAdapter contract (ADR-M7-1)
  7.3  k8s fault categories + catalog entries (ADR-M7-3 / ADR-M7-4)
  7.4  optional harness stub + regression
"""

from __future__ import annotations

import pydantic
import pytest

from mayhem.config import PolicyCfg
from mayhem.controller.safety import (
    SafetyContext,
    SafetyRefusedError,
    validate_plan,
)
from mayhem.domain.capabilities import Capability
from mayhem.domain.catalog import CATALOG, definition_for
from mayhem.domain.execution_context import (
    ExecutionContext,
    infer_context_for_node,
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
from mayhem.domain.faults import FaultCategory
from mayhem.domain.identity import RuntimeIdentity, RuntimeLabel
from mayhem.domain.k8s_adapter import (
    ADR_M7_1,
    ADR_M7_2,
    ADR_M7_3,
    ADR_M7_4,
    UNSUPPORTED_MSG,
    KubernetesAdapter,
)
from mayhem.domain.risks import RiskLevel
from mayhem.domain.runtime_adapter import (
    CapabilityRequirements,
    CapabilityVerdict,
    RuntimeCapability,
)
from mayhem.domain.target import ResourceKind, TargetScope
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    K8sNode,
    NodeKind,
    PodNode,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)

# ── helpers ──────────────────────────────────────────────────────────────────


def _ctx(**policy_kwargs) -> SafetyContext:
    return SafetyContext(
        policy=PolicyCfg(**policy_kwargs),
        budget=BlastRadiusBudget(),
        fingerprint="f",
    )


def _k8s_graph() -> TopologyGraph:
    """Graph with both k8s node kinds for testing."""
    return TopologyGraph(
        nodes=(
            PodNode(
                id="pod-web",
                name="web-abc123",
                namespace="default",
                node_name="worker-1",
                image="nginx:latest",
            ),
            K8sNode(
                id="k8s-worker-1",
                name="worker-1",
                cluster="test-cluster",
                roles=("worker",),
                state="Ready",
            ),
            ServiceNode(id="n-api", name="api"),
        ),
        edges=(
            Edge(src="pod-web", dst="k8s-worker-1", kind=EdgeKind.RUNS_ON),
            Edge(src="pod-web", dst="n-api", kind=EdgeKind.CONNECTS_VIA),
        ),
    )


def _k8s_plan(fault_id: str = "k8s.pod_kill") -> ExecutionPlan:
    """Minimal plan targeting a k8s pod."""
    selector = TargetSelector(kind=NodeKind.POD, expr="web-abc123")
    return ExecutionPlan(
        run_id="run-m7",
        kind=ExperimentKind.DRILL,
        environment_fingerprint="f",
        topology_snapshot_id="ts-m7",
        config_snapshot_id="cs-m7",
        steps=(
            PlannedStep(
                id="step-1",
                seq=1,
                fault=PlannedFault(
                    fault_id=fault_id,
                    duration=10.0,
                    targets=(
                        ResolvedTarget(
                            selector=selector,
                            node_ids=frozenset({"pod-web"}),
                        ),
                    ),
                ),
                raw_action=InjectFault(
                    fault=fault_id,
                    selectors=(selector,),
                    duration=10.0,
                ),
            ),
        ),
    )


def _service_plan() -> ExecutionPlan:
    """Normal (non-k8s) plan targeting a service node."""
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="api")
    return ExecutionPlan(
        run_id="run-normal",
        kind=ExperimentKind.DRILL,
        environment_fingerprint="f",
        topology_snapshot_id="ts-normal",
        config_snapshot_id="cs-normal",
        steps=(
            PlannedStep(
                id="step-normal",
                seq=1,
                fault=PlannedFault(
                    fault_id="net.latency",
                    duration=10.0,
                    targets=(
                        ResolvedTarget(
                            selector=selector,
                            node_ids=frozenset({"n-api"}),
                        ),
                    ),
                ),
                raw_action=InjectFault(
                    fault="net.latency",
                    selectors=(selector,),
                    duration=10.0,
                ),
            ),
        ),
    )


def _normal_graph() -> TopologyGraph:
    return TopologyGraph(
        nodes=(ServiceNode(id="n-api", name="api"),),
        edges=(),
    )


# ═════════════════════════════════════════════════════════════════════════════
# Phase 7.1 — Topology node-kind extensions
# ═════════════════════════════════════════════════════════════════════════════


class TestNodeKindExtensions:
    def test_pod_and_k8s_node_kind_exist(self) -> None:
        assert NodeKind.POD == "pod"
        assert NodeKind.K8S_NODE == "k8s_node"

    def test_all_node_kinds_in_enum(self) -> None:
        kinds = set(NodeKind)
        assert NodeKind.SERVICE in kinds
        assert NodeKind.CONTAINER in kinds
        assert NodeKind.HOST in kinds
        assert NodeKind.PROCESS in kinds
        assert NodeKind.EXTERNAL_DEPENDENCY in kinds
        assert NodeKind.POD in kinds
        assert NodeKind.K8S_NODE in kinds

    def test_existing_node_kinds_unaffected(self) -> None:
        assert NodeKind.SERVICE.value == "service"
        assert NodeKind.CONTAINER.value == "container"
        assert NodeKind.HOST.value == "host"
        assert NodeKind.PROCESS.value == "process"
        assert NodeKind.EXTERNAL_DEPENDENCY.value == "external_dependency"


class TestPodNodeModel:
    def test_pod_node_parses(self) -> None:
        pod = PodNode(id="p1", name="nginx-abc", namespace="prod", node_name="w1")
        assert pod.kind == NodeKind.POD
        assert pod.namespace == "prod"
        assert pod.node_name == "w1"
        assert pod.pod_ip is None
        assert pod.labels == {}

    def test_pod_node_defaults(self) -> None:
        pod = PodNode(id="p2", name="minimal")
        assert pod.namespace == "default"
        assert pod.state == "unknown"

    def test_pod_node_frozen(self) -> None:
        pod = PodNode(id="p3", name="frozen")
        with pytest.raises(pydantic.ValidationError):
            pod.namespace = "changed"  # type: ignore[misc]


class TestK8sNodeModel:
    def test_k8s_node_parses(self) -> None:
        node = K8sNode(id="k1", name="worker-1", cluster="c1", roles=("worker",))
        assert node.kind == NodeKind.K8S_NODE
        assert node.cluster == "c1"
        assert node.roles == ("worker",)

    def test_k8s_node_defaults(self) -> None:
        node = K8sNode(id="k2", name="node2")
        assert node.cluster == ""
        assert node.roles == ()
        assert node.state == "unknown"


class TestInferContextForK8s:
    def test_pod_infers_remote_host(self) -> None:
        ctx = infer_context_for_node(NodeKind.POD)
        assert ctx == ExecutionContext.REMOTE_HOST

    def test_k8s_node_infers_remote_host(self) -> None:
        ctx = infer_context_for_node(NodeKind.K8S_NODE)
        assert ctx == ExecutionContext.REMOTE_HOST

    def test_existing_kinds_unaffected(self) -> None:
        assert infer_context_for_node(NodeKind.HOST) == ExecutionContext.HOST
        assert infer_context_for_node(NodeKind.CONTAINER) == ExecutionContext.CONTAINER
        assert infer_context_for_node(NodeKind.SERVICE) == ExecutionContext.CONTAINER
        assert infer_context_for_node(NodeKind.PROCESS) == ExecutionContext.PROCESS
        assert infer_context_for_node(NodeKind.EXTERNAL_DEPENDENCY) == ExecutionContext.REMOTE_HOST


class TestTopologyGraphWithK8sNodes:
    def test_k8s_graph_roundtrip(self) -> None:
        graph = _k8s_graph()
        pod = graph.by_id("pod-web")
        assert pod is not None
        assert pod.kind == NodeKind.POD
        assert isinstance(pod, PodNode)
        assert pod.namespace == "default"

        node = graph.by_id("k8s-worker-1")
        assert node is not None
        assert node.kind == NodeKind.K8S_NODE
        assert isinstance(node, K8sNode)
        assert node.cluster == "test-cluster"

    def test_k8s_nodes_in_topology(self) -> None:
        graph = _k8s_graph()
        k8s_nodes = [n for n in graph.nodes if n.kind in (NodeKind.POD, NodeKind.K8S_NODE)]
        assert len(k8s_nodes) == 2


# ═════════════════════════════════════════════════════════════════════════════
# Phase 7.1 + 7.2 — Safety gate: k8s targets refused (ADR-M7)
# ═════════════════════════════════════════════════════════════════════════════


class TestK8sSafetyGate:
    def test_k8s_plan_refused(self) -> None:
        """Plan targeting a k8s pod is refused with UNSUPPORTED message."""
        plan = _k8s_plan("k8s.pod_kill")
        graph = _k8s_graph()
        with pytest.raises(SafetyRefusedError, match=r"k8s\.unsupported") as exc_info:
            validate_plan(plan, graph, _ctx())
        assert "kubernetes execution not yet supported" in str(exc_info.value)
        assert ADR_M7_1 in str(exc_info.value)

    def test_k8s_node_plan_admitted(self) -> None:
        """k-plan-5 ships node execution: a node-targeting plan validates."""
        selector = TargetSelector(kind=NodeKind.K8S_NODE, expr="worker-1")
        node_scope = TargetScope(
            logical_id="workers",
            runtime=RuntimeLabel.KUBERNETES,
            kind=ResourceKind.K8S_NODE,
            authority={"name": "worker-1"},
        )
        plan = ExecutionPlan(
            run_id="run-m7-node",
            kind=ExperimentKind.DRILL,
            environment_fingerprint="f",
            topology_snapshot_id="ts-m7",
            config_snapshot_id="cs-m7",
            steps=(
                PlannedStep(
                    id="step-1",
                    seq=1,
                    fault=PlannedFault(
                        fault_id="k8s.node_drain",
                        duration=10.0,
                        target=node_scope,
                        targets=(
                            ResolvedTarget(
                                selector=selector,
                                node_ids=frozenset({"k8s-worker-1"}),
                            ),
                        ),
                    ),
                    raw_action=InjectFault(
                        fault="k8s.node_drain",
                        duration=10.0,
                        selectors=(selector,),
                    ),
                ),
            ),
        )
        graph = _k8s_graph()
        ctx = SafetyContext(
            policy=PolicyCfg(
                allow_critical=True,
                critical_fault_acks=("k8s.node_drain",),
            ),
            budget=_ctx().budget,
            fingerprint="f",
            allow_critical_cli=True,  # engine-level flag, mirrors CLI --allow-critical
        )
        validate_plan(plan, graph, ctx, adapter=None)  # no refusal

    def test_normal_plan_not_affected(self) -> None:
        """Non-k8s plans pass the k8s gate."""
        plan = _service_plan()
        graph = _normal_graph()
        try:
            validate_plan(plan, graph, _ctx())
        except SafetyRefusedError as exc:
            assert "k8s.unsupported" not in exc.reason_code

    def test_k8s_unsupported_message_is_loud(self) -> None:
        """The UNSUPPORTED message is actionable and references ADR-M7-1."""
        assert ADR_M7_1 in UNSUPPORTED_MSG
        assert "kubernetes" in UNSUPPORTED_MSG.lower()


# ═════════════════════════════════════════════════════════════════════════════
# Phase 7.2 — KubernetesAdapter contract (ADR-M7-1)
# ═════════════════════════════════════════════════════════════════════════════


class TestKubernetesAdapterContract:
    def test_adapter_id(self) -> None:
        adapter = KubernetesAdapter()
        assert adapter.id == "kubernetes"

    def test_adapter_not_available(self) -> None:
        assert KubernetesAdapter().is_available() is False

    def test_capabilities_all_unsupported(self) -> None:
        caps = KubernetesAdapter().capabilities()
        assert caps.engine == "kubernetes"
        assert len(caps.supported) == 0
        assert len(caps.alternatives) == 0

    def test_evaluate_all_verdicts_unsupported(self) -> None:
        adapter = KubernetesAdapter()
        reqs = CapabilityRequirements()
        result = adapter.evaluate(reqs)
        assert result.engine == "kubernetes"
        assert result.blocking is True
        for cap in RuntimeCapability:
            assert result.verdicts[cap.value] == CapabilityVerdict.UNSUPPORTED.value

    def test_evaluate_blocking_with_requirements(self) -> None:
        reqs = CapabilityRequirements(namespaces=frozenset({"kube-system"}))
        result = KubernetesAdapter().evaluate(reqs)
        assert result.blocking is True

    def test_inspect_raises_not_implemented(self) -> None:
        with pytest.raises(NotImplementedError, match="kubernetes execution not yet supported"):
            KubernetesAdapter().inspect("pod-xyz")

    def test_exec_raises_not_implemented(self) -> None:
        with pytest.raises(NotImplementedError, match="kubernetes execution not yet supported"):
            KubernetesAdapter().exec("pod-xyz", ["ls"])

    def test_signal_raises_not_implemented(self) -> None:
        with pytest.raises(NotImplementedError, match="kubernetes execution not yet supported"):
            KubernetesAdapter().signal("pod-xyz", 9)

    def test_pid_returns_none(self) -> None:
        assert KubernetesAdapter().pid("pod-xyz") is None

    def test_netns_returns_none(self) -> None:
        assert KubernetesAdapter().netns("pod-xyz") is None

    def test_ps_returns_empty(self) -> None:
        assert KubernetesAdapter().ps() == []

    def test_discover_returns_partial_graph(self) -> None:
        pg = KubernetesAdapter().discover()
        assert pg.source == "kubernetes"
        assert "interface-only" in str(pg.notes)

    def test_adr_constants_defined(self) -> None:
        assert ADR_M7_1 == "ADR-M7-1"
        assert ADR_M7_2 == "ADR-M7-2"
        assert ADR_M7_3 == "ADR-M7-3"
        assert ADR_M7_4 == "ADR-M7-4"

    def test_type_check(self) -> None:
        """Adapter satisfies the RuntimeAdapter protocol."""
        from mayhem.domain.runtime_adapter import RuntimeAdapter

        adapter: RuntimeAdapter = KubernetesAdapter()
        assert isinstance(adapter, RuntimeAdapter)


# ═════════════════════════════════════════════════════════════════════════════
# Phase 7.2 — Adapter registry includes kubernetes
# ═════════════════════════════════════════════════════════════════════════════


class TestK8sAdapterRegistry:
    def test_kubernetes_registered(self) -> None:
        from mayhem.topology.providers.adapter_registry import best_effort

        result = best_effort("kubernetes")
        assert result is None  # not available yet

    def test_kubernetes_adapter_class_importable(self) -> None:
        from mayhem.domain.k8s_adapter import KubernetesAdapter as K8sAdapterImport

        assert K8sAdapterImport.ENGINE == "kubernetes"


# ═════════════════════════════════════════════════════════════════════════════
# Phase 7.3 — k8s fault categories + catalog entries (ADR-M7-3 / ADR-M7-4)
# ═════════════════════════════════════════════════════════════════════════════


_K8S_FAULT_IDS = [
    "k8s.node_pressure",
    "k8s.pod_oom",
    "k8s.pod_pressure",
    "k8s.network_policy",
    "k8s.pod_latency",
    "k8s.pod_partition",
    "k8s.pod_evict",
    "k8s.pod_kill",
    "k8s.node_drain",
]


class TestK8sFaultCategory:
    def test_k8s_category_exists(self) -> None:
        assert FaultCategory.K8S == "k8s"

    def test_k8s_prefix_maps_to_k8s_category(self) -> None:
        for fid in _K8S_FAULT_IDS:
            assert FaultCategory.from_fault_id(fid) == FaultCategory.K8S

    def test_kubernetes_engine_capability_exists(self) -> None:
        assert Capability.KUBERNETES_ENGINE == "kubernetes_engine"


class TestK8sCatalogEntries:
    def test_all_k8s_faults_in_catalog(self) -> None:
        catalog_ids = {d.id for d in CATALOG}
        for fid in _K8S_FAULT_IDS:
            assert fid in catalog_ids, f"{fid} missing from catalog"

    def test_k8s_faults_have_fingerprint_compatible_risk(self) -> None:
        for fid in _K8S_FAULT_IDS:
            d = definition_for(fid)
            assert d.risk in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)
            assert d.category == FaultCategory.K8S

    def test_k8s_faults_require_kubernetes_engine(self) -> None:
        for fid in _K8S_FAULT_IDS:
            d = definition_for(fid)
            assert Capability.KUBERNETES_ENGINE in d.required_caps

    def test_capacity_stress_node_kinds(self) -> None:
        d = definition_for("k8s.node_pressure")
        assert NodeKind.K8S_NODE in d.applicable_node_kinds

    def test_capacity_stress_pod_kinds(self) -> None:
        for fid in ("k8s.pod_oom", "k8s.pod_pressure"):
            d = definition_for(fid)
            assert NodeKind.POD in d.applicable_node_kinds

    def test_network_category_node_kinds(self) -> None:
        d = definition_for("k8s.network_policy")
        assert NodeKind.POD in d.applicable_node_kinds
        assert NodeKind.K8S_NODE in d.applicable_node_kinds

    def test_preemption_pod_kinds(self) -> None:
        for fid in ("k8s.pod_evict", "k8s.pod_kill", "k8s.pod_partition"):
            d = definition_for(fid)
            assert NodeKind.POD in d.applicable_node_kinds

    def test_node_drain_k8s_node_kind(self) -> None:
        d = definition_for("k8s.node_drain")
        assert NodeKind.K8S_NODE in d.applicable_node_kinds
        assert d.risk == RiskLevel.CRITICAL


class TestK8sVerdictBlocksPlanning:
    """UNSUPPORTED verdicts block planning (ADR-M7-4)."""

    def test_k8s_adapter_produces_blocking_verdict(self) -> None:
        adapter = KubernetesAdapter()
        result = adapter.evaluate(CapabilityRequirements())
        assert result.blocking is True
        for verdict in result.verdicts.values():
            assert verdict == CapabilityVerdict.UNSUPPORTED.value


# ═════════════════════════════════════════════════════════════════════════════
# Phase 7.4 — Regression: existing functionality unaffected
# ═════════════════════════════════════════════════════════════════════════════


class TestK8sRegression:
    def test_existing_node_kinds_still_work(self) -> None:
        """All pre-existing node kinds parse and validate."""
        from mayhem.domain.topology import (
            ContainerNode,
            ExternalDependencyNode,
            HostNode,
            ProcessNode,
        )

        graph = TopologyGraph(
            nodes=(
                ServiceNode(id="s1", name="svc"),
                ContainerNode(
                    id="c1",
                    name="ctr",
                    engine="docker",
                    runtime_identity=RuntimeIdentity(
                        runtime="docker",
                        host_id="h1",
                        runtime_id="abc123",
                    ),
                ),
                HostNode(id="h1", name="host"),
                ProcessNode(id="p1", name="proc", host_id="h1"),
                ExternalDependencyNode(id="e1", name="dep", endpoint="db:5432"),
            ),
            edges=(),
        )
        assert len(graph.nodes) == 5

    def test_catalog_size_increased(self) -> None:
        """Catalog grew by 9 k8s archetypes (24 base + 9 k8s = 33 unique ids)."""
        assert len(CATALOG) >= 33  # 24 base + 9 k8s; unique ids

    def test_m7_archetype_coverage(self) -> None:
        """Every M7 archetype is in the catalog and has a valid category."""
        for fid in _K8S_FAULT_IDS:
            d = definition_for(fid)
            assert d.id == fid
            assert d.category == FaultCategory.K8S
            assert d.max_duration_s > 0
