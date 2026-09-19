"""Kubernetes manifest blueprint provider — offline graph from a YAML bundle.

The live ``KubernetesAdapter``-based discovery requires a reachable cluster
(and the optional ``k8s`` extra).  ``mayhem -k`` still has to work against
just the repo's ``examples/k8s/kubernetes.yaml``, so this provider materializes
a **blueprint graph** from a multi-document k8s manifest bundle without any
cluster access:

- Workloads (Deployment / StatefulSet / DaemonSet / ReplicaSet / Pod) emit
  one :class:`PodNode` placeholder per declared workload — ``state="blueprint"``,
  ``owner_kind``/``owner_name``/``containers`` carried so the planner can
  resolve logical targets and the maniac synthesizer can build the fault pool.
  Placeholders are *not* pickable pods: ``target_selector`` treats a blueprint
  pod as absent so workload targets stay logically pinned (k-plan-1).
- Services emit :class:`ServiceNode`` plus ``DEPENDS_ON`` edges to the workload
  placeholders they select.
- Nodes emit :class:`K8sNode``; pods pinned via ``nodeName`` get ``RUNS_ON``
  edges.

This mirrors the live provider's guarantees (k-plan-2 §2.3): workloads are
logical targets, generated pod names never appear, and the stable owner
identity is the look-up key.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    K8sNode,
    PodNode,
    ServiceNode,
)
from mayhem.topology.providers.base import PartialGraph
from mayhem.topology.providers.kubernetes import node_id as _node_id
from mayhem.topology.providers.kubernetes import pod_id as _pod_id
from mayhem.topology.providers.kubernetes import service_id as _service_id

_WORKLOAD_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"})
_NODE_KINDS = frozenset({"Node"})
_SUPPORTED_KINDS = _WORKLOAD_KINDS | _NODE_KINDS | {"Pod", "Service"}


def workload_id(namespace: str, kind: str, name: str) -> str:
    return f"k8s::workload/{namespace}/{kind.lower()}/{name}"


def _ns(meta: dict[str, Any] | None) -> str:
    return str((meta or {}).get("namespace") or "default")


def _labels(meta: dict[str, Any] | None) -> dict[str, str]:
    meta = meta or {}
    return {str(k): str(v) for k, v in (meta.get("labels") or {}).items()}


def _selectors(doc: dict[str, Any]) -> dict[str, str]:
    spec = doc.get("spec") or {}
    return {str(k): str(v) for k, v in (spec.get("selector") or {}).get("matchLabels", {}).items()}


def _containers(doc: dict[str, Any]) -> tuple[str, ...]:
    spec = doc.get("spec") or {}
    template = spec.get("template") or {}
    pod_spec = template.get("spec") or {}
    return tuple(str(c.get("name")) for c in pod_spec.get("containers") or [] if c.get("name"))


def _node_name(doc: dict[str, Any]) -> str | None:
    spec = doc.get("spec") or {}
    node = spec.get("nodeName")
    return str(node) if node else None


class KubernetesManifestProvider:
    """Blueprint topology provider reading a multi-doc k8s manifest bundle."""

    id = "k8s-manifest"

    def __init__(self, compose_path: str | Path) -> None:
        self._path = Path(compose_path)

    def is_available(self) -> bool:
        return self._path.exists()

    @property
    def resource_kinds(self) -> tuple[str, ...]:
        """Kinds declared by the bundle (empty for a non-k8s YAML file)."""
        return tuple(
            doc.get("kind")
            for doc in self._documents()
            if isinstance(doc, dict) and doc.get("kind") in _SUPPORTED_KINDS
        )

    def _documents(self) -> tuple[dict[str, Any], ...]:
        raw = self._path.read_text(encoding="utf-8")
        docs = tuple(d for d in yaml.safe_load_all(raw) if d)
        return tuple(d for d in docs if isinstance(d, dict))

    def discover(self) -> PartialGraph:  # noqa: PLR0912, PLR0915
        nodes_by_kind: dict[str, list[Any]] = {"workload": [], "service": [], "node": []}
        edges: list[Edge] = []
        notes: list[str] = []

        for doc in self._documents():
            kind = doc.get("kind")
            if kind in _WORKLOAD_KINDS:
                nodes_by_kind["workload"].append((kind, doc))
            elif kind == "Pod":
                nodes_by_kind["workload"].append(("Pod", doc))
            elif kind == "Service":
                nodes_by_kind["service"].append(doc)
            elif kind == "Node":
                nodes_by_kind["node"].append(doc)

        # Map for nodeName -> K8sNode id, and the K8sNode nodes themselves.
        node_nodes: list[K8sNode] = []
        node_by_name: dict[str, K8sNode] = {}

        for doc in nodes_by_kind["node"]:
            name = str((doc.get("metadata") or {}).get("name") or "")
            if not name:
                continue
            labels = _labels(doc.get("metadata"))
            roles = tuple(
                sorted(
                    key.rsplit("/", 1)[-1]
                    for key in labels
                    if key.startswith("node-role.kubernetes.io/")
                )
            )
            node = K8sNode(
                id=_node_id(name),
                name=name,
                cluster=str((doc.get("metadata") or {}).get("clusterName") or ""),
                roles=roles,
            )
            node_nodes.append(node)
            node_by_name[name] = node

        pod_nodes: list[PodNode] = []

        for kind, doc in nodes_by_kind["workload"]:
            meta = doc.get("metadata") or {}
            name = str(meta.get("name") or "")
            namespace = _ns(meta)
            if not name:
                continue
            if kind == "Pod":
                node_id = _pod_id(namespace, name)
                owner_kind, owner_name = "Pod", name
            else:
                node_id = workload_id(namespace, kind, name)
                owner_kind, owner_name = kind, name
            pod_nodes.append(
                PodNode(
                    id=node_id,
                    name=name,
                    namespace=namespace,
                    state="blueprint",
                    containers=_containers(doc),
                    owner_kind=owner_kind,
                    owner_name=owner_name,
                    labels=_labels(meta),
                )
            )
            pinned = _node_name(doc)
            if pinned and pinned in node_by_name:
                edges.append(Edge(src=node_id, dst=node_by_name[pinned].id, kind=EdgeKind.RUNS_ON))

        service_nodes: list[ServiceNode] = []
        for doc in nodes_by_kind["service"]:
            meta = doc.get("metadata") or {}
            name = str(meta.get("name") or "")
            namespace = _ns(meta)
            if not name:
                continue

            selector = _selectors(doc)
            service = ServiceNode(
                id=_service_id(namespace, name),
                name=name,
            )
            if selector:
                for pod in pod_nodes:
                    if pod.namespace == namespace and selector.items() <= pod.labels.items():
                        edges.append(Edge(src=service.id, dst=pod.id, kind=EdgeKind.DEPENDS_ON))
            service_nodes.append(service)

        notes.append(
            "blueprint manifest graph (offline) — pods are placeholders; "
            "execution still resolves live pods at the impact gate"
        )

        nodes: list[Any] = pod_nodes
        nodes.extend(node_nodes)
        nodes.extend(service_nodes)
        return PartialGraph(
            source=self.id,
            nodes=tuple(nodes),
            edges=tuple(edges),
            notes=tuple(notes),
        )
