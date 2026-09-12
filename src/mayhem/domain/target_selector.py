"""Deterministic ``selection: mode one`` picker for kubernetes targets (k-plan-2 §2.5).

The contract (same inputs → same Pod, reproducible plans):

1. Collect eligible Pods for the resolved workload:
   - Deployment/StatefulSet/DaemonSet → ``owner_kind+owner_name`` match;
   - Service → selector-resolved pods (via the ``service → pod``
     ``DEPENDS_ON`` edges the discovery provider emits);
   - Pod target → itself (only candidate);
   - k8s_node target → refused in this phase (k-plan-5).
2. Filter: ``phase == Running``, zero pending ``deletion_timestamp``.
3. Pick: sort by ``(namespace, name, uid)``, first. Hash-stable across
   re-discovery; a replaced Pod flips only when truly necessary (uid
   tie-break order is arbitrary but fixed).
4. No eligible Pod → :class:`SelectionError` ``selection.no_eligible_pods``
   (never a silent no-op).

A workload that does **not exist in the topology at all** returns ``None``:
that is the k-plan-1 "logically pinned" case, re-resolved at execution time.
The error is raised only when the workload is present in the graph but has
zero *eligible* pods.  ``SelectionSpec.mode`` values other than ``one`` are
refused by the planner's ``_require_implemented_selection`` with
:class:`SelectionError` ``selection.reserved_mode``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mayhem.domain.errors import SelectionError
from mayhem.domain.target import ResourceKind, SelectionMode, TargetScope
from mayhem.domain.topology import EdgeKind, NodeKind, PodNode

if TYPE_CHECKING:
    from mayhem.domain.topology import TopologyGraph, TopologyNode

#: Resource kinds whose pods are matched by the stable-workload owner identity
#: (``PodNode.owner_kind``/``owner_name`` — k-plan-2 §2.3).
_OWNER_KINDS: frozenset[ResourceKind] = frozenset(
    {
        ResourceKind.DEPLOYMENT,
        ResourceKind.STATEFULSET,
        ResourceKind.DAEMONSET,
    }
)

#: K8s object kind strings written onto ``PodNode.owner_kind`` by discovery.
_OWNER_LABEL_TO_RESOURCE_KIND: dict[str, ResourceKind] = {
    "Deployment": ResourceKind.DEPLOYMENT,
    "StatefulSet": ResourceKind.STATEFULSET,
    "DaemonSet": ResourceKind.DAEMONSET,
}


def _pods_in_namespace(
    graph: "TopologyGraph", namespace: str
) -> tuple[PodNode, ...]:
    ns = namespace or "default"
    return tuple(
        node
        for node in graph.nodes
        if node.kind == NodeKind.POD and getattr(node, "namespace", "default") == ns
    )


def _owner_match(pod: PodNode, scope: TargetScope) -> bool:
    """Deployment/StatefulSet/DaemonSet → ``owner_kind+owner_name`` match.

    ``scope.authority["name"]`` is the stable workload name (k-plan-1 §1.3),
    never a generated pod name; owner identity rides PodNode metadata so the
    match survives a pod replacement.
    """
    expected_kind = _OWNER_LABEL_TO_RESOURCE_KIND.get(pod.owner_kind or "")
    if expected_kind is None or expected_kind != scope.kind:
        return False
    return bool(pod.owner_name) and pod.owner_name == scope.authority.get("name")


def _service_match(graph: "TopologyGraph", pod: PodNode, scope: TargetScope) -> bool:
    """Service → selector-resolved pods via the discovery ``DEPENDS_ON`` edges.

    The provider emits ``Edge(service_id → pod_id, DEPENDS_ON, weight=1.0)``
    for every selector match, so the pick reuses the dependency edges rather
    than re-implementing label matching here.
    """
    namespace = scope.authority.get("namespace", "")
    service_name = scope.authority.get("name", "")
    service_ids = {
        edge.src
        for edge in graph.edges
        if edge.kind == EdgeKind.DEPENDS_ON and edge.dst == pod.id
    }
    for node in graph.nodes:
        if (
            node.kind == NodeKind.SERVICE
            and node.id in service_ids
            and node.name == service_name
            and getattr(node, "namespace", "default") == namespace
        ):
            return True
    return False


def _candidate_pods(graph: "TopologyGraph", scope: TargetScope) -> tuple[PodNode, ...] | None:
    """Pods a target can select, or ``None`` when the workload is not in the
    graph (k-plan-1 logically-pinned path — execution re-resolves)."""
    if scope.kind == ResourceKind.POD:
        namespace = scope.authority.get("namespace", "")
        name = scope.authority.get("name", "")
        return tuple(
            pod
            for pod in _pods_in_namespace(graph, namespace)
            if pod.name == name
        )
    if scope.kind in _OWNER_KINDS:
        namespace = scope.authority.get("namespace", "")
        pods = tuple(
            pod
            for pod in _pods_in_namespace(graph, namespace)
            if _owner_match(pod, scope)
        )
        if not pods:
            return None
        return pods
    if scope.kind == ResourceKind.SERVICE:
        namespace = scope.authority.get("namespace", "")
        service_name = scope.authority.get("name", "")
        services = [
            node
            for node in graph.nodes
            if node.kind == NodeKind.SERVICE
            and node.name == service_name
            and getattr(node, "namespace", "default") == namespace
        ]
        if not services:
            return None
        service_id = services[0].id
        return tuple(
            pod
            for pod in graph.nodes
            if pod.kind == NodeKind.POD
            and any(
                edge.src == service_id
                and edge.dst == pod.id
                and edge.kind == EdgeKind.DEPENDS_ON
                for edge in graph.edges
            )
        )
    return None  # k8s_node → refused by caller


def _is_eligible(pod: PodNode) -> bool:
    """Filter: ``phase == Running``, zero pending deletion timestamp."""
    if pod.state != "Running":
        return False
    return pod.deletion_timestamp is None


def select_one(
    graph: "TopologyGraph", scope: TargetScope
) -> PodNode | None:
    """Pick the deterministic ``mode: one`` pod, or refuse with the stable
    selection error.

    Returns ``None`` only when the workload is absent from the topology
    (logically pinned — execution re-resolves it, k-plan-3). Raises
    :class:`SelectionError` when the workload exists but nothing eligible is
    found.
    """
    if scope.kind == ResourceKind.K8S_NODE:
        raise SelectionError(
            "selection.node_target_unsupported",
            "k8s_node selection is reserved until k-plan-5",
        )
    if scope.selection is not None and scope.selection.mode != SelectionMode.ONE:
        raise SelectionError(
            "selection.reserved_mode",
            f"selection mode {scope.selection.mode.value!r} is reserved until k-plan-4",
        )

    candidates = _candidate_pods(graph, scope)
    if candidates is None:
        return None
    eligible = tuple(pod for pod in candidates if _is_eligible(pod))
    if not eligible:
        label = scope.authority.get("name", scope.logical_id)
        raise SelectionError(
            "selection.no_eligible_pods",
            f"target {scope.logical_id!r} ({scope.kind.value} '{label}') has "
            f"{len(candidates)} pod(s), none Running and not terminating",
        )
    return min(eligible, key=lambda pod: (pod.namespace, pod.name, pod.pod_uid or ""))