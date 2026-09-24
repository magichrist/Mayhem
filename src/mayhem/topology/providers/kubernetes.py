"""Kubernetes topology provider — live discovery from a cluster (k-plan-2).

The provider is a **discovery** sibling of the docker/podman providers. It is
intentionally NOT gated behind the executor capability: ``KubernetesAdapter``
(domain/k8s_adapter.py) still reports UNSUPPORTED for execution, while this
provider reads its own availability from a live reachability probe
(k-plan-2 §2.6).

Guarded import — the ``kubernetes`` SDK ships behind the optional ``k8s``
extra; installing it is a one-liner:

    pip install "mayhem[k8s]"

Node kinds are a closed union (k-plan-2 §2.3), so discovery emits only
:class:`PodNode`, :class:`K8sNode`, and :class:`ServiceNode`:

- Workloads (Deployment/StatefulSet/DaemonSet) are **logical targets**, not
  nodes: a pod's owner identity rides ``PodNode.owner_kind``/``owner_name``
  (the stable workload name, never the generated pod name); ReplicaSets are
  folded into the same owner chain (pod → ReplicaSet → Deployment).
- k8s worker nodes materialize as :class:`K8sNode`; there is no cluster node,
  so ``K8sNode.cluster`` carries the cluster identity and no ``member_of``
  edges are emitted (nothing to anchor them to).
- Services materialize as :class:`ServiceNode`` (the existing SERVICE kind —
  no new kind) with ``service → pod`` ``DEPENDS_ON`` edges for every selector
  match (weight 1.0, health-gated semantics reused).
- ``pod → node`` edges are ``RUNS_ON``, mirroring the docker
  container → host edges.

Stable node ids (k-plan-2 §2.2):

    k8s::{namespace}/{kind}/{name}      workloads and Services, e.g.
                                        k8s::production/Deployment/checkout
    k8s::pod/{namespace}/{name}         pods, e.g. k8s::pod/production/checkout-x7z9k
    k8s::node/{name}                    worker nodes

Unit tests inject a :class:`KubeApis` fake (in-memory objects, zero network);
production builds real clients from kubeconfig/in-cluster config.
"""

from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
from importlib import import_module
from ipaddress import ip_address
from typing import Any

from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    K8sNode,
    PodNode,
    ServiceNode,
)
from mayhem.topology.providers.base import PartialGraph

#: One-line install hint surfaced whenever the k8s SDK is missing.
KUBERNETES_INSTALL_HINT = 'pip install "mayhem[k8s]"  # kubernetes topology discovery'

KUBERNETES_IMPORT_ERROR: ImportError | None = None


def _load_optional(name: str) -> Any | None:
    """Import an optional-extra module, returning None when it is absent."""

    try:
        return import_module(name)
    except ImportError:
        return None


#: Optional-extra modules (the ``k8s`` extra) — mypy-neutral via string import.
_client: Any | None = _load_optional("kubernetes.client")
_kube_config: Any | None = _load_optional("kubernetes.config")
if _client is None or _kube_config is None:  # pragma: no cover
    KUBERNETES_IMPORT_ERROR = ImportError(KUBERNETES_INSTALL_HINT)


@dataclass(frozen=True)
class KubeApis:
    """Client pair used by discovery; tests inject an in-memory fake."""

    core: Any
    apps: Any


def node_id(name: str) -> str:
    return f"k8s::node/{name}"


def pod_id(namespace: str, name: str) -> str:
    return f"k8s::pod/{namespace}/{name}"


def service_id(namespace: str, name: str) -> str:
    return f"k8s::{namespace}/Service/{name}"


def workload_id(namespace: str, kind: str, name: str) -> str:
    return f"k8s::{namespace}/{kind}/{name}"


class KubernetesProvider:
    """Live-cluster discovery (kubernetes SDK optional extra)."""

    def __init__(
        self,
        engine: str = "kubernetes",
        *,
        context: str | None = None,
        namespace: str | None = None,
        workload_selector: str | None = None,
        _api: KubeApis | None = None,
    ) -> None:
        self._engine = engine
        self.context = context
        self.namespace = namespace
        self.workload_selector = workload_selector
        self._api = _api
        self._probed: bool | None = None
        self._readiness_error = ""

    @property
    def id(self) -> str:
        return self._engine

    # ── availability ───────────────────────────────────────────────
    def _resolve_api(self) -> KubeApis:
        if self._api is not None:
            return self._api
        if _client is None or _kube_config is None:
            raise ImportError(KUBERNETES_INSTALL_HINT)
        if self.context is None:
            try:
                _kube_config.load_kube_config()
            except Exception:
                _kube_config.load_incluster_config()
        else:
            _kube_config.load_kube_config(context=self.context)
        return KubeApis(core=_client.CoreV1Api(), apps=_client.AppsV1Api())

    def is_available(self) -> bool:
        if self._probed is not None:
            return self._probed
        try:
            api = self._resolve_api()
            if self.namespace is None:
                api.core.list_namespace(limit=1)
            else:
                api.core.list_namespaced_pod(self.namespace)
        except Exception as exc:
            self._probed = False
            self._readiness_error = str(exc)
        else:
            self._probed = True
        return self._probed

    def manifest_inspection_available(self) -> bool:
        return False

    def live_readiness_available(self) -> bool:
        return self.is_available()

    def readiness_details(self) -> dict[str, object]:
        available = self.is_available()
        detail: dict[str, object] = {
            "available": available,
            "sdk_available": _client is not None and _kube_config is not None,
            "client_available": self._api is not None or self._probed is True,
            "context": self.context,
            "namespace": self.namespace,
            "workload_selector": self.workload_selector,
        }
        if not available:
            detail["error"] = (
                self._readiness_error or "kubeconfig context or namespace is not reachable"
            )
        return detail

    def discovery_status(self) -> dict[str, object]:
        return self.readiness_details()

    # ── discovery ─────────────────────────────────────────────────
    def discover(self) -> PartialGraph:
        api = self._resolve_api()
        if not self.is_available():
            self._probed = False
            raise RuntimeError(
                "kubernetes provider is not available (kubeconfig/context "
                f"unreachable, context={self.context!r})"
            )

        service_nodes, service_edges = self._discover_services(api)
        nodes: list[Any] = list(service_nodes)
        edges: list[Edge] = list(service_edges)

        worker_nodes = self._discover_nodes(api)
        nodes.extend(worker_nodes)

        pods, _owner_map = self._discover_pods(api)
        nodes.extend(pods)
        for pod in pods:
            if pod.node_name:
                edges.append(Edge(src=pod.id, dst=node_id(pod.node_name), kind=EdgeKind.RUNS_ON))

        notes = ("kubernetes SDK missing" if _client is None else "live cluster discovery",)
        return PartialGraph(
            source=self.id,
            nodes=tuple(nodes),
            edges=tuple(edges),
            notes=notes,
        )

    def _discover_services(self, api: KubeApis) -> tuple[list[ServiceNode], list[Edge]]:
        core = api.core
        if self.namespace:
            svc_list = core.list_namespaced_service(self.namespace).items
        else:
            svc_list = core.list_service_for_all_namespaces().items
        nodes: list[ServiceNode] = []
        edges: list[Edge] = []
        pods = self._all_pods(core)
        for svc in svc_list:
            meta = svc.metadata
            namespace = meta.namespace or "default"
            name = meta.name
            nodes.append(ServiceNode(id=service_id(namespace, name), name=name))
            selector = getattr(svc.spec, "selector", None) or {}
            if not selector:
                continue
            for pod in pods:
                labels = getattr(pod.metadata, "labels", None) or {}
                if _selector_matches(selector, labels):
                    edges.append(
                        Edge(
                            src=service_id(namespace, name),
                            dst=pod_id(namespace, pod.metadata.name),
                            kind=EdgeKind.DEPENDS_ON,
                            weight=1.0,
                        )
                    )
        return nodes, edges

    def _all_pods(self, core: Any) -> list[Any]:
        if self.namespace:
            return list(core.list_namespaced_pod(self.namespace).items)
        return list(core.list_pod_for_all_namespaces().items)

    def _discover_pods(self, api: KubeApis) -> tuple[list[PodNode], dict[str, tuple[str, str]]]:
        owner_map = self._owner_map(api)
        pod_nodes: list[PodNode] = []
        for pod in self._all_pods(api.core):
            meta = pod.metadata
            namespace = meta.namespace or "default"
            pod_name = meta.name
            owner_kind, owner_name = _effective_owner(meta, owner_map)
            state = getattr(pod.status, "phase", "Unknown") or "Unknown"
            containers = tuple(c.name for c in getattr(pod.spec, "containers", []) or [])
            image = None
            conts = getattr(pod.spec, "containers", []) or []
            if conts and getattr(conts[0], "image", None):
                image = conts[0].image
            restart_count = 0
            statuses = getattr(pod.status, "container_statuses", None) or []
            for container_status in statuses:
                restart_count = max(
                    restart_count, getattr(container_status, "restart_count", 0) or 0
                )
            pod_ip = None
            raw_ip = getattr(pod.status, "pod_ip", None)
            if raw_ip:
                pod_ip = ip_address(str(raw_ip))
            deletion_timestamp = None
            raw_deletion = getattr(meta, "deletion_timestamp", None)
            if raw_deletion is not None:
                deletion_timestamp = str(raw_deletion)
            if self.workload_selector:
                wanted = {
                    key: value
                    for item in self.workload_selector.split(",")
                    if "=" in item
                    for key, value in [item.split("=", 1)]
                }
                if not all(
                    dict(meta.labels or {}).get(key) == value for key, value in wanted.items()
                ):
                    continue
            pod_nodes.append(
                PodNode(
                    id=pod_id(namespace, pod_name),
                    name=pod_name,
                    namespace=namespace,
                    node_name=getattr(pod.status, "node_name", None),
                    pod_ip=pod_ip,
                    image=image,
                    labels=dict(meta.labels or {}),
                    state=state,
                    owner_kind=owner_kind,
                    owner_name=owner_name,
                    containers=containers,
                    pod_uid=getattr(meta, "uid", None),
                    restart_count=restart_count,
                    deletion_timestamp=deletion_timestamp,
                )
            )
        return pod_nodes, owner_map

    def _owner_map(self, api: KubeApis) -> dict[str, tuple[str, str]]:
        """uid → (kind, name) chain, folding ReplicaSet → owning workload."""
        direct: dict[str, tuple[str, str]] = {}
        apps = api.apps
        if self.namespace:
            deployments = apps.list_namespaced_deployment(self.namespace).items
            statefulsets = apps.list_namespaced_stateful_set(self.namespace).items
            daemonsets = apps.list_namespaced_daemon_set(self.namespace).items
            replicasets = apps.list_namespaced_replica_set(self.namespace).items
        else:
            deployments = apps.list_deployment_for_all_namespaces().items
            statefulsets = apps.list_stateful_set_for_all_namespaces().items
            daemonsets = apps.list_daemon_set_for_all_namespaces().items
            replicasets = apps.list_replica_set_for_all_namespaces().items
        for kind, items in (
            ("Deployment", deployments),
            ("StatefulSet", statefulsets),
            ("DaemonSet", daemonsets),
        ):
            for item in items:
                uid = getattr(item.metadata, "uid", None)
                if uid:
                    direct[uid] = (kind, item.metadata.name)
        # Fold ReplicaSet → owning Deployment: a pod's stable workload key is
        # the Deployment name (k-plan-1 §1.4), never the generated RS name.
        for item in replicasets:
            uid = getattr(item.metadata, "uid", None)
            if not uid:
                continue
            refs = getattr(item.metadata, "owner_references", None) or []
            if refs and getattr(refs[0], "kind", "") == "Deployment":
                direct[uid] = ("Deployment", getattr(refs[0], "name", ""))
            else:
                direct[uid] = ("ReplicaSet", item.metadata.name)
        return direct

    def _discover_nodes(self, api: KubeApis) -> list[K8sNode]:
        nodes: list[K8sNode] = []
        items = api.core.list_node().items
        for item in items:
            meta = item.metadata
            name = meta.name
            labels = meta.labels or {}
            role_labels = [key for key in labels if key.startswith("node-role.kubernetes.io/")]
            # Control-plane/master roles come from role labels; a node with no
            # role label at all is a worker (k-plan-2 §2.4).
            roles = [key.rsplit("/", 1)[-1] for key in role_labels] if role_labels else ["worker"]
            ip_address_value = None
            for address in getattr(item.status, "addresses", []) or []:
                if getattr(address, "type", "") == "InternalIP":
                    with suppress(ValueError):
                        ip_address_value = ip_address(str(address.address))
                    break
            capacity = getattr(item.status, "capacity", None) or {}
            state = "Unknown"
            for condition in getattr(item.status, "conditions", []) or []:
                if getattr(condition, "type", "") == "Ready":
                    state = getattr(condition, "status", "Unknown") or "Unknown"
                    break
            nodes.append(
                K8sNode(
                    id=node_id(name),
                    name=name,
                    roles=tuple(roles),
                    ip_address=ip_address_value,
                    capacity_cpu=str(capacity.get("cpu") or ""),
                    capacity_memory=str(capacity.get("memory") or ""),
                    state=state,
                    cluster=self.context or "kubeconfig",
                )
            )
        return nodes


def _selector_matches(selector: dict[str, Any], labels: dict[str, Any]) -> bool:
    """Service → pod selector match (equality labels only, phase 1)."""
    return all(labels.get(key) == value for key, value in selector.items())


def _effective_owner(
    meta: Any, owner_map: dict[str, tuple[str, str]]
) -> tuple[str | None, str | None]:
    """Resolve a pod's stable workload owner, folding ReplicaSet → owner.

    K8s pods are normally owned by a ReplicaSet owned by a Deployment; the
    *stable workload key* for selection is the Deployment (k-plan-1 §1.4).
    Pods owned directly by a StatefulSet/DaemonSet map 1:1.
    """
    refs = getattr(meta, "owner_references", None) or []
    if not refs:
        return None, None
    first = refs[0]
    kind = getattr(first, "kind", "") or ""
    name = getattr(first, "name", "") or ""
    if kind in ("ReplicaSet", "ReplicationController") and first.uid in owner_map:
        owner_kind, owner_name = owner_map[first.uid]
        return owner_kind, owner_name
    return kind, name
