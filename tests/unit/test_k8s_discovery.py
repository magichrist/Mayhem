"""Kubernetes topology provider tests — fake client, zero network.

Exercises `mayhem.topology.providers.kubernetes` against in-memory
kubernetes-style objects so the discovery pipeline (pods, services, worker
nodes), the ReplicaSet→Deployment owner fold, and the guarded-install banner
are all verifiable without a cluster.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from mayhem.domain.topology import EdgeKind, NodeKind, TopologyGraph
from mayhem.topology.providers.kubernetes import (
    KUBERNETES_IMPORT_ERROR,
    KUBERNETES_INSTALL_HINT,
    KubeApis,
    KubernetesProvider,
    pod_id,
    service_id,
)

# ── fake kubernetes client objects ─────────────────────────────────────────


def _ref(kind: str, name: str, uid: str) -> SimpleNamespace:
    return SimpleNamespace(kind=kind, name=name, uid=uid)


def _pod(
    name: str,
    namespace: str = "checkout",
    *,
    state: str = "Running",
    owner: SimpleNamespace | None = None,
    deletion_timestamp: str | None = None,
    node_name: str | None = "worker-1",
    pod_ip: str | None = "10.0.0.7",
    uid: str = "pod-x7z9k",
    labels: dict[str, str] | None = None,
    image: str = "nginx:1.25",
) -> SimpleNamespace:
    status = SimpleNamespace(
        phase=state,
        pod_ip=pod_ip,
        node_name=node_name,
        container_statuses=[SimpleNamespace(restart_count=1)],
    )
    spec = SimpleNamespace(containers=[SimpleNamespace(name="app", image=image)])
    meta = SimpleNamespace(
        name=name,
        namespace=namespace,
        uid=uid,
        labels=labels or {},
        owner_references=None if owner is None else [owner],
        deletion_timestamp=deletion_timestamp,
    )
    return SimpleNamespace(metadata=meta, spec=spec, status=status)


def _rs_dep() -> SimpleNamespace:
    return SimpleNamespace(
        metadata=SimpleNamespace(
            uid="rs-uid-1",
            name="checkout-6f9",
            namespace="checkout",
            owner_references=[_ref("Deployment", "checkout", "dep-uid-1")],
        ),
        spec=SimpleNamespace(),
    )


def _dep(
    name: str = "checkout", namespace: str = "checkout", uid: str = "dep-uid-1"
) -> SimpleNamespace:
    return SimpleNamespace(
        metadata=SimpleNamespace(uid=uid, name=name, namespace=namespace),
        spec=SimpleNamespace(),
    )


def _svc(name: str, namespace: str, selector: dict[str, str], pod_items: list) -> SimpleNamespace:
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name, namespace=namespace),
        spec=SimpleNamespace(selector=selector),
    )


class _Items:
    def __init__(self, items: list) -> None:
        self.items = items


class FakeCore:
    def __init__(
        self,
        pods: list | None = None,
        services: list | None = None,
        nodes: list | None = None,
    ) -> None:
        self._pods = pods or []
        self._services = services or []
        self._nodes = nodes or []

    def list_namespace(self, limit: int = 1) -> _Items:
        return _Items([SimpleNamespace(metadata=SimpleNamespace(name="default"))])

    def list_namespaced_pod(self, namespace: str) -> _Items:
        return _Items([p for p in self._pods if p.metadata.namespace == namespace])

    def list_pod_for_all_namespaces(self) -> _Items:
        return _Items(self._pods)

    def list_namespaced_service(self, namespace: str) -> _Items:
        return _Items([s for s in self._services if s.metadata.namespace == namespace])

    def list_service_for_all_namespaces(self) -> _Items:
        return _Items(self._services)

    def list_node(self) -> _Items:
        return _Items(self._nodes)


class FakeApps:
    def __init__(
        self,
        deployments: list | None = None,
        replicasets: list | None = None,
        statefulsets: list | None = None,
        daemonsets: list | None = None,
    ) -> None:
        self._deployments = deployments or []
        self._replicasets = replicasets or []
        self._statefulsets = statefulsets or []
        self._daemonsets = daemonsets or []

    def _scoped(self, items: list, namespace: str | None) -> list:
        if namespace is None:
            return items
        return [i for i in items if i.metadata.namespace == namespace]

    def list_namespaced_deployment(self, namespace: str) -> _Items:
        return _Items(self._scoped(self._deployments, namespace))

    def list_deployment_for_all_namespaces(self) -> _Items:
        return _Items(self._deployments)

    def list_namespaced_stateful_set(self, namespace: str) -> _Items:
        return _Items(self._scoped(self._statefulsets, namespace))

    def list_stateful_set_for_all_namespaces(self) -> _Items:
        return _Items(self._statefulsets)

    def list_namespaced_daemon_set(self, namespace: str) -> _Items:
        return _Items(self._scoped(self._daemonsets, namespace))

    def list_daemon_set_for_all_namespaces(self) -> _Items:
        return _Items(self._daemonsets)

    def list_namespaced_replica_set(self, namespace: str) -> _Items:
        return _Items(self._scoped(self._replicasets, namespace))

    def list_replica_set_for_all_namespaces(self) -> _Items:
        return _Items(self._replicasets)


def _worker_node(name: str = "worker-1") -> SimpleNamespace:
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name, labels={"kubernetes.io/hostname": name}),
        status=SimpleNamespace(
            capacity={"cpu": "4", "memory": "16Gi"},
            addresses=[SimpleNamespace(type="InternalIP", address="10.0.0.5")],
            conditions=[SimpleNamespace(type="Ready", status="True")],
        ),
    )


# ── discovery ──────────────────────────────────────────────────────────────


def _provider(
    pods,
    services=None,
    nodes=None,
    deployments=None,
    replicasets=None,
    statefulsets=None,
    daemonsets=None,
):
    if nodes is None:
        nodes = [_worker_node()]
    return KubernetesProvider(
        "kubernetes",
        namespace="checkout",
        _api=KubeApis(
            core=FakeCore(pods=pods, services=services, nodes=nodes),
            apps=FakeApps(
                deployments=deployments,
                replicasets=replicasets,
                statefulsets=statefulsets,
                daemonsets=daemonsets,
            ),
        ),
    )


def test_discover_emits_pod_service_node_and_edges() -> None:
    pod = _pod(
        "checkout-x7z9k",
        namespace="checkout",
        owner=_ref("ReplicaSet", "checkout-6f9", "rs-uid-1"),
    )
    svc = _svc("checkout", "checkout", {"app": "checkout"}, [])
    labels = {"app": "checkout"}
    pod.metadata.labels = labels
    provider = _provider(
        pods=[pod],
        services=[svc],
        nodes=[_worker_node()],
        deployments=[_dep()],
        replicasets=[_rs_dep()],
    )
    assert provider.is_available() is True
    partial = provider.discover()
    graph = TopologyGraph(nodes=partial.nodes, edges=partial.edges)

    kinds = {node.kind for node in graph.nodes}
    assert kinds == {NodeKind.POD, NodeKind.SERVICE, NodeKind.K8S_NODE}

    pod_node = next(n for n in graph.nodes if n.kind == NodeKind.POD)
    assert pod_node.id == "k8s::pod/checkout/checkout-x7z9k"
    assert pod_node.state == "Running"
    assert pod_node.owner_kind == "Deployment"  # RS folded → stable workload
    assert pod_node.owner_name == "checkout"

    svc_node = next(n for n in graph.nodes if n.kind == NodeKind.SERVICE)
    assert svc_node.id == "k8s::checkout/Service/checkout"

    node_node = next(n for n in graph.nodes if n.kind == NodeKind.K8S_NODE)
    assert node_node.name == "worker-1"
    assert node_node.capacity_cpu == "4"
    assert node_node.capacity_memory == "16Gi"
    assert node_node.state == "True"

    edges = graph.edges
    depends = {(e.src, e.dst) for e in edges if e.kind == EdgeKind.DEPENDS_ON}
    runs_on = {(e.src, e.dst) for e in edges if e.kind == EdgeKind.RUNS_ON}
    assert depends == {(service_id("checkout", "checkout"), pod_id("checkout", "checkout-x7z9k"))}
    assert runs_on == {
        (
            pod_id("checkout", "checkout-x7z9k"),
            "k8s::node/worker-1",
        )
    }


def test_all_namespaces_when_no_namespace_filter() -> None:
    pods = [
        _pod("a", namespace="ns1", node_name=None),
        _pod("b", namespace="ns2", node_name=None),
    ]
    provider = KubernetesProvider(
        "kubernetes",
        _api=KubeApis(core=FakeCore(pods=pods), apps=FakeApps()),
    )
    partial = provider.discover()
    graph = TopologyGraph(nodes=partial.nodes, edges=partial.edges)
    assert {n.name for n in graph.nodes if n.kind == NodeKind.POD} == {"a", "b"}


def test_selector_is_equality_match() -> None:
    pod = _pod("web-1", namespace="checkout", labels={"app": "web", "tier": "fe"})
    svc_nomatch = _svc("web", "checkout", {"app": "web", "tier": "be"}, [])
    svc_match = _svc("edge", "checkout", {"app": "web"}, [])
    provider = _provider(pods=[pod], services=[svc_nomatch, svc_match])
    partial = provider.discover()
    graph = TopologyGraph(nodes=partial.nodes, edges=partial.edges)
    edges = {e.src: e.dst for e in graph.edges if e.kind == EdgeKind.DEPENDS_ON}
    assert service_id("checkout", "edge") in edges
    assert service_id("checkout", "web") not in edges


def test_terminating_pod_still_discovered() -> None:
    pod = _pod("x", namespace="checkout", deletion_timestamp="2026-09-12T10:00:00Z")
    partial = _provider(pods=[pod]).discover()
    graph = TopologyGraph(nodes=partial.nodes, edges=partial.edges)
    pod_node = next(n for n in graph.nodes if n.kind == NodeKind.POD)
    assert pod_node.deletion_timestamp is not None


def test_availability_probe_switches_offs_when_list_fails() -> None:
    class _BrokenCore(FakeCore):
        def list_namespace(self, limit: int = 1) -> _Items:
            raise RuntimeError("no cluster")

    provider = KubernetesProvider("kubernetes", _api=KubeApis(core=_BrokenCore(), apps=FakeApps()))
    assert provider.is_available() is False


def test_discover_refuses_when_unavailable() -> None:
    class _BrokenCore(FakeCore):
        def list_namespace(self, limit: int = 1) -> _Items:
            raise RuntimeError("no cluster")

    provider = KubernetesProvider("kubernetes", _api=KubeApis(core=_BrokenCore(), apps=FakeApps()))
    with pytest.raises(RuntimeError, match="not available"):
        provider.discover()


def test_install_hint_present_when_sdk_missing() -> None:
    # Guarded import flags a stable message whether or not the SDK is installed
    # in this environment; the marker constant is always importable.
    assert "pip install" in KUBERNETES_INSTALL_HINT
    if KUBERNETES_IMPORT_ERROR is None:
        pytest.skip("kubernetes SDK is installed here")
    assert "mayhem[k8s]" in str(KUBERNETES_IMPORT_ERROR)
