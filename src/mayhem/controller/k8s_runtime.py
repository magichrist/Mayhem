"""Kubernetes execution branch for the run engine (k-plan-3 SP-3.4).

The frozen plan pins a logical workload; at execution the engine must pin the
*resolved pod* and then deliver the mutation through the K8sExecutor. This
module owns the k8s-specific composition so the docker pipeline in
``controller.executor`` is untouched:

* :func:`make_k8s_resolver` — lazy resolver construction (kubectl / SDK);
* :func:`preferred_pod_from_graph` — recover the plan-time mode-one pod pick
  from the live topology so re-resolution can flag drift (ADR-M7-1 §3.1);
* :func:`k8s_undo_spec` — the write-ahead undo contract recorded on the lease
  (migration ``resolved_target``), carrying the pid/boot guard the executor
  consumed at inject.

Cluster I/O happens only in the resolver/client seam; everything here is
pure composition over in-memory objects.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from mayhem.agents.executors import (
    K8S_SIGNAL_FAULTS,
    K8S_UNDO_COMMAND,
    k8s_executor_for,
    k8s_unsupported_reason,
)
from mayhem.agents.k8s_resolve import KubernetesRuntimeResolver, default_client
from mayhem.domain.errors import ResolutionError, SelectionError
from mayhem.domain.resolution import ResolvedNodeTarget, ResolvedPodTarget
from mayhem.domain.topology import NodeKind

if TYPE_CHECKING:
    from mayhem.controller.executor import RunEngine

UNDO_OP = "k8s.exec"
NO_UNDO_MARKER = "noop"  # signal families with nothing live to undo (TERM/KILL)


# ── k-plan-4: mutation fault families ───────────────────────────────────────

K8S_MUTATION_FAULTS: frozenset[str] = frozenset(
    {
        "k8s.pod_kill",
        "k8s.pod_evict",
        "k8s.pod_oom",
        "k8s.pod_pressure",
        "k8s.network_policy",
        "k8s.pod_partition",
        "k8s.pod_latency",  # k-plan-5 §5.3: netns-routed pod fault
    }
)

K8S_DELETE_FAULTS: frozenset[str] = frozenset({"k8s.pod_kill", "k8s.pod_evict"})
# Network families ship their undo as a policy delete; pod_partition is the
# same mechanism targeting the pod's own isolation (k-plan-4 §4.1).
K8S_NETWORK_FAULTS: frozenset[str] = frozenset(
    {"k8s.network_policy", "k8s.pod_partition"}
)
# Families with a live lease-time undo (network policy delete, pressure
# restore signal); everything else relies on compensation (k-plan-4 §4.4/§4.5).
K8S_REVERSIBLE_FAULTS: frozenset[str] = frozenset(
    {
        "k8s.network_policy",
        "k8s.pod_pressure",
        "k8s.pod_partition",
        "k8s.node_drain",  # undo = uncordon (k-plan-5 §5.2)
        "k8s.node_pressure",  # undo = delete pressure workload (k-plan-5 §5.4)
        "k8s.pod_latency",  # undo = qdisc clear (k-plan-5 §5.3)
    }
)
# k-plan-5: node-scoped faults mutate the cluster node, not a container; they
# resolve to a ResolvedNodeTarget and ride the node pipeline in the engine.
K8S_NODE_FAULTS: frozenset[str] = frozenset(
    {"k8s.node_drain", "k8s.node_pressure"}
)
# k-plan-5 §5.3: network-namespace-injected pod faults (tc netem via nsenter).
# The NETNS capability gates delivery; without it the driver refuses with
# ``k8s.unsupported`` before any mutation (Band C).
K8S_NETNS_FAULTS: frozenset[str] = frozenset({"k8s.pod_latency"})


def make_k8s_resolver(
    resolver: KubernetesRuntimeResolver | None = None,
) -> KubernetesRuntimeResolver | None:
    """Return the injected resolver or a lazily-built process-wide one.

    ``None`` means "no cluster client available" and callers fail loud with
    the stable ``k8s.unsupported`` reason instead of planning-side refusals.
    """
    if resolver is not None:
        return resolver
    client = default_client()
    if client is None:
        return None
    return KubernetesRuntimeResolver(client)


def preferred_pod_from_graph(
    live_graph: Callable[[], object] | None,
    targets: frozenset[str],
) -> str | None:
    """Recover the plan-time mode-one pod pick, when the live graph still has it.

    The planner froze ``node_ids`` (which name the k8s pod nodes) at plan
    time; the resolver prefers that pod and reports ``drift`` when the live
    selection no longer picks it (ADR-M7-1 §3.1 note: k8s uses deterministic
    first; drift surfaces in the resolution note, execution continues).
    """
    if live_graph is None:
        return None
    graph = live_graph()
    for node_id in sorted(targets):
        node = getattr(graph, "by_id", lambda _n: None)(node_id)
        if node is not None and node.kind == NodeKind.POD and getattr(node, "name", None):
            return str(node.name)
    return None


def k8s_undo_spec(
    fault_id: str,
    target: ResolvedPodTarget,
    *,
    pid: int,
    boot: int,
) -> dict[str, object]:
    """The lease's write-ahead undo contract (SP-3.4 evidence shape).

    Records exactly how the mutation was (and will be) delivered: the kubectl
    exec base argv + pid/boot guard captured just before the inject, plus the
    undo command the K8sExecutor runs (``CONT`` for ``proc.pause``, ``noop``
    for the terminal signal families).
    """
    command = K8S_UNDO_COMMAND.get(fault_id, NO_UNDO_MARKER)
    return {
        "op": UNDO_OP,
        "args": {
            "fault_id": fault_id,
            "namespace": target.namespace,
            "pod": target.pod,
            "container": target.container,
            "pid": str(pid),
            "boot": str(boot),
            "undo_command": command,
            "exec_argv": " ".join(target.exec_argv),
        },
    }


def k8s_mutation_spec(
    fault_id: str,
    target: ResolvedPodTarget,
    params: dict[str, object] | None = None,
) -> dict[str, object]:
    """Write-ahead contract for pod-lifecycle mutations (k-plan-4 §4.4).

    The undo is live for reversible families (NetworkPolicy delete), a no-op
    for irreversible ones (delete/evict/oom — compensation is the pod
    replacement the engine watches for).  ``exec_argv`` stays as evidence even
    though lease-time undo is not argv-driven.  ``params`` rides along so the
    spec is the single source of truth for execution parameters
    (:func:`~mayhem.agents.executors._lease_fault_params`).
    """
    reversible = fault_id in K8S_REVERSIBLE_FAULTS
    # UndoOp.args is dict[str, str], so the params bag rides along JSON-encoded
    # (k-plan-4 §4.4); _lease_fault_params decodes it on the executor side.
    import json as _json  # noqa: PLC0415
    return {
        "op": "k8s.mutation" if reversible else "k8s.mutation.noop",
        "args": {
            "fault_id": fault_id,
            "namespace": target.namespace,
            "pod": target.pod,
            "container": target.container,
            "pod_uid": target.pod_uid,
            "pod_action": target.pod_action,
            "reversible": str(reversible).lower(),
            "labels": ",".join(
                f"{k}={v}" for k, v in sorted(target.labels.items())
            ),
            "exec_argv": " ".join(target.exec_argv),
            "params": _json.dumps(dict(params or {}), sort_keys=True, separators=(",", ":")),
        },
    }


def k8s_verify_spec(
    fault_id: str,
    target: ResolvedPodTarget,
) -> dict[str, object]:
    """Replacement/state verification contract for pod-lifecycle faults.

    * delete/evict/oom  → ``k8s.replaced`` — the engine polls the workload's
      eligible pod set and confirms the injected pod is no longer Running.
    * network policy    → ``k8s.policy_applied`` — the policy side-effect is
      confirmed undone by the delete (no live re-check).
    * pod_pressure      → ``k8s.pressure_restored`` — the pressure signal's
      undo was applied live; verify is evidence-only.
    """
    if fault_id == "k8s.pod_pressure":
        op = "k8s.pressure_restored"
        args = {"pod": target.pod, "container": target.container, "namespace": target.namespace}
    elif fault_id in K8S_NETWORK_FAULTS:
        op = "k8s.policy_applied"
        args: dict[str, object] = {"policy_name": target.pod_action}
    else:
        op = "k8s.replaced"
        args = {
            "uid": target.pod_uid,
            "pod": target.pod,
            "namespace": target.namespace,
        }
    return {"op": op, "args": args, "resolve": True}


def k8s_node_spec(
    fault_id: str,
    target: ResolvedNodeTarget,
    params: dict[str, object] | None = None,
) -> dict[str, object]:
    """Write-ahead contract for node-level mutations (k-plan-5 §5.1/§5.4).

    Node faults are reversible (uncordon / pressure-workload delete), so the
    spec always carries a live undo intent.  ``params`` rides along JSON-encoded
    so :func:`~mayhem.agents.executors._lease_fault_params` can recover it.
    """
    import json as _json  # noqa: PLC0415

    return {
        "op": "k8s.node.mutation",
        "args": {
            "fault_id": fault_id,
            "node": target.node,
            "node_uid": target.node_uid,
            "node_action": target.node_action or fault_id.removeprefix("k8s."),
            "reversible": "true",
            "labels": ",".join(f"{k}={v}" for k, v in sorted(target.labels.items())),
            "params": _json.dumps(dict(params or {}), sort_keys=True, separators=(",", ":")),
        },
    }


def k8s_node_undo_ops(
    fault_id: str,
    target: ResolvedNodeTarget,
    params: dict[str, object] | None = None,
) -> tuple[UndoOp, ...]:
    """UndoOps recorded on the lease for a node-level mutation (k-plan-5).

    * node_drain     → ``k8s.uncordon`` (live node facade restore);
    * node_pressure  → ``k8s.delete`` (pressure workload).

    Both ops carry the params bag (UndoOp.args is ``dict[str, str]``, so it
    rides along JSON-encoded, mirroring ``k8s_mutation_spec`` k-plan-4 §4.4)
    so :func:`~mayhem.agents.executors._lease_fault_params` recovers the
    authored ``grace_period`` / ``target_percent`` / ``resource`` at both
    injection and undo time.
    """
    from mayhem.domain.leases import UndoOp  # noqa: PLC0415

    import json as _json  # noqa: PLC0415

    bag = _json.dumps(dict(params or {}), sort_keys=True, separators=(",", ":"))
    if fault_id == "k8s.node_drain":
        return (
            UndoOp(
                op="k8s.uncordon",
                args={
                    "node": target.node,
                    "node_uid": target.node_uid,
                    "params": bag,
                },
            ),
        )
    if fault_id == "k8s.node_pressure":
        name = _node_pressure_workload(target.node)
        return (
            UndoOp(
                op="k8s.delete",
                args={
                    "node": target.node,
                    "workload": name,
                    "kind": "pod",
                    "params": bag,
                },
            ),
        )
    return ()


def _node_pressure_workload(node: str) -> str:
    """Deterministic pressure-workload name for a node (k-plan-5 §5.4)."""
    return "mayhem-node-pressure-" + node.lower().replace("_", "-")


def k8s_node_verify_spec(
    fault_id: str,
    target: ResolvedNodeTarget,
) -> dict[str, object]:
    """Post-hold verification contract for node-level faults (k-plan-5 §5.2).

    * node_drain    → ``k8s.node_restored`` — node Ready and schedulable;
    * node_pressure → ``k8s.node_restored`` with the pressure-workload name
      (evidence RHS: workload absent = capacity returned).
    """
    if fault_id == "k8s.node_pressure":
        op = "k8s.node_restored"
        args: dict[str, object] = {
            "node": target.node,
            "pressure_workload": _node_pressure_workload(target.node),
        }
    else:
        op = "k8s.node_restored"
        args = {
            "node": target.node,
            "node_uid": target.node_uid,
            "expect_ready": "true",
            "expect_unschedulable": "false",
        }
    return {"op": op, "args": args, "resolve": True}


def k8s_node_routing() -> dict[str, str]:
    """Node-family pipeline routing: node faults → the node pipeline step.

    Modes are per-fault (k-plan-5 §5.1): ``node_drain`` and ``node_pressure``
    both route through the node pipeline (``k8s.node``); everything else falls
    back to ``k8s.pod``.
    """
    return {fault: "k8s.node" for fault in K8S_NODE_FAULTS}


def k8s_undo_ops_for(fault_id: str, target: ResolvedPodTarget) -> tuple[UndoOp, ...]:
    """UndoOp payloads recorded on the lease for a mutation fault.

    Mirrors the docker pipeline: the engine calls
    ``k8s_executor_for(fault_id, KUBERNETES)`` and hands it a lease whose
    ``undo_ops`` carry the same semantic (live undo when reversible, noop
    otherwise) so confirmation runs uniformly.

    Every mutation family records an undo op so ``_lease_fault_params`` can
    recover the write-ahead params bag from ``args["params"]`` (k-plan-4 §4.4).
    """
    from mayhem.domain.leases import UndoOp  # noqa: PLC0415

    if fault_id in K8S_MUTATION_FAULTS:
        reversible = fault_id in K8S_REVERSIBLE_FAULTS
        if reversible:
            args: dict[str, object] = {}
            if fault_id == "k8s.network_policy":
                args["policy_name"] = f"mayhem-deny-{target.pod}"
            return (
                UndoOp(
                    op=f"k8s.undo.{fault_id.removeprefix('k8s.')}",
                    args=args,
                ),
            )
        return (
            UndoOp(
                op="k8s.mutation.noop",
                args={"reason": f"{fault_id} compensation is the pod replacement"},
            ),
        )
    return ()


def unsupported_reason(fault_id: str) -> str:
    """Stable refused reason for families the milestone driver does not admit."""
    return k8s_unsupported_reason(fault_id)


__all__ = (
    "K8S_DELETE_FAULTS",
    "K8S_MUTATION_FAULTS",
    "K8S_NETNS_FAULTS",
    "K8S_NETWORK_FAULTS",
    "K8S_NODE_FAULTS",
    "K8S_REVERSIBLE_FAULTS",
    "K8S_SIGNAL_FAULTS",
    "NO_UNDO_MARKER",
    "UNDO_OP",
    "ResolutionError",
    "SelectionError",
    "k8s_mutation_spec",
    "k8s_node_routing",
    "k8s_node_spec",
    "k8s_node_undo_ops",
    "k8s_node_verify_spec",
    "k8s_undo_ops_for",
    "k8s_undo_spec",
    "k8s_verify_spec",
    "make_k8s_resolver",
    "preferred_pod_from_graph",
    "unsupported_reason",
)