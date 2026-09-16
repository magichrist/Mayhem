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
implemented by :func:`select_many` (k-plan-4 §4.2); see
``selection.out_of_budget`` / ``conflict.overlap`` for the plan-time errors.
"""

from __future__ import annotations

import math
import random
import zlib
from typing import TYPE_CHECKING

from mayhem.domain.errors import SelectionError
from mayhem.domain.target import (
    ResourceKind,
    SelectionMode,
    SelectionSpec,
    TargetScope,
)
from mayhem.domain.topology import EdgeKind, NodeKind, PodNode

if TYPE_CHECKING:
    from mayhem.domain.experiments import BlastRadiusBudget
    from mayhem.domain.topology import TopologyGraph

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
    graph: TopologyGraph, namespace: str
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


def _service_match(graph: TopologyGraph, pod: PodNode, scope: TargetScope) -> bool:
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


def _candidate_pods(graph: TopologyGraph, scope: TargetScope) -> tuple[PodNode, ...] | None:
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


def _is_blueprint(pod: PodNode) -> bool:
    """Blueprint manifest placeholders are never pickable pods.

    The k8s manifest provider emits ``state="blueprint"`` PodNodes so a
    workload's logical presence survives offline planning; eligibility
    (and the impact gate) re-resolve live pods at execution time.
    """
    return pod.state == "blueprint"


def _deterministic_key(pod: PodNode) -> tuple[str, str, str]:
    """Hash-stable ordering: namespace, name, uid (k-plan-2 §2.5)."""
    return (pod.namespace, pod.name, pod.pod_uid or "")


def _dispatch(
    scope: TargetScope,
    eligible: tuple[PodNode, ...],
    *,
    seed: int | None = None,
) -> tuple[PodNode, ...]:
    """Apply the authored selection mode to the eligible set (k-plan-4 §4.2).

    ``count`` / ``percentage`` / ``all`` consume pods in deterministic order
    (no drops); ``random`` is a uniform single draw seeded for deterministic
    replay.  ``one`` is the deterministic first pick (k-plan-2 contract).
    """
    selection = scope.selection or SelectionSpec(mode=SelectionMode.ONE)
    ordered = tuple(sorted(eligible, key=_deterministic_key))
    mode = selection.mode
    if mode == SelectionMode.ONE:
        return ordered[:1]
    if mode == SelectionMode.RANDOM:
        rng = random.Random(
            seed
            if seed is not None
            else zlib.crc32(scope.logical_id.encode("utf-8"))
        )
        return (rng.choice(ordered),)
    if mode == SelectionMode.ALL:
        return ordered
    if mode == SelectionMode.COUNT:
        count = selection.count
        if count is None:
            raise SelectionError(
                "selection.count_required",
                f"selection.mode 'count' on target {scope.logical_id!r} "
                "requires selection.count",
            )
        if count > len(ordered):
            raise SelectionError(
                "selection.count_exceeds_eligible",
                f"selection count {count} on target {scope.logical_id!r} exceeds "
                f"{len(ordered)} eligible pod(s)",
            )
        return ordered[:count]
    if mode == SelectionMode.PERCENTAGE:
        pct = selection.percentage
        if pct is None:
            raise SelectionError(
                "selection.percentage_required",
                f"selection.mode 'percentage' on target {scope.logical_id!r} "
                "requires selection.percentage",
            )
        n = max(1, math.ceil(len(ordered) * pct / 100.0))
        return ordered[: min(n, len(ordered))]
    raise SelectionError(  # pragma: no cover - schema forbids unknown modes
        "selection.unknown_mode", f"unknown selection mode {mode.value!r}"
    )


def select_many(
    graph: TopologyGraph,
    scope: TargetScope,
    *,
    budget: BlastRadiusBudget | None = None,
    seed: int | None = None,
) -> tuple[PodNode, ...] | None:
    """Multi-instance selection (k-plan-4 §4.2) — count/percentage/all/random/one.

    Returns ``None`` only when the workload is absent from the topology
    (logically pinned — execution re-resolves it, k-plan-3).  Raises
    :class:`SelectionError` when the workload exists but nothing is eligible,
    when the authored ``count`` exceeds the eligible set, or when the picked
    set exceeds ``budget.max_concurrent_faults`` (``selection.out_of_budget``,
    pointing at the config knob that owns the cap).
    """
    if scope.kind == ResourceKind.K8S_NODE:
        raise SelectionError(
            "selection.node_target_unsupported",
            "k8s_node selection is reserved until k-plan-5",
        )

    candidates = _candidate_pods(graph, scope)
    if candidates is None:
        return None
    eligible = tuple(pod for pod in candidates if _is_eligible(pod))
    if not eligible:
        if candidates and all(_is_blueprint(pod) for pod in candidates):
            # Blueprint manifest placeholders (topology/providers/k8s_manifest.py)
            # are a workload's *logical presence*, not pickable pods: nothing
            # is live in the graph, so the target stays logically pinned the
            # same way an absent workload does (k-plan-1 §1.3).
            return None
        label = scope.authority.get("name", scope.logical_id)
        raise SelectionError(
            "selection.no_eligible_pods",
            f"target {scope.logical_id!r} ({scope.kind.value} '{label}') has "
            f"{len(candidates)} pod(s), none Running and not terminating",
        )
    picked = _dispatch(scope, eligible, seed=seed)
    if budget is not None and len(picked) > budget.max_concurrent_faults:
        raise SelectionError(
            "selection.out_of_budget",
            f"selection on target {scope.logical_id!r} picks {len(picked)} pod(s), "
            f"over policy.blast_radius.max_concurrent_faults="
            f"{budget.max_concurrent_faults}",
        )
    return picked


def select_one(
    graph: TopologyGraph, scope: TargetScope
) -> PodNode | None:
    """Determine the single-pod view of the selection (legacy surface).

    Returns ``None`` only when the workload is absent from the topology.
    Raises :class:`SelectionError` when nothing eligible is found.
    """
    picked = select_many(graph, scope)
    if picked is None:
        return None
    return picked[0]
