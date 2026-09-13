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

from mayhem.agents.executors import K8S_SIGNAL_FAULTS, K8S_UNDO_COMMAND, k8s_unsupported_reason
from mayhem.agents.k8s_resolve import KubernetesRuntimeResolver, default_client
from mayhem.domain.errors import ResolutionError, SelectionError
from mayhem.domain.resolution import ResolvedPodTarget
from mayhem.domain.topology import NodeKind

if TYPE_CHECKING:
    from mayhem.controller.executor import RunEngine

UNDO_OP = "k8s.exec"
NO_UNDO_MARKER = "noop"  # signal families with nothing live to undo (TERM/KILL)


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


def unsupported_reason(fault_id: str) -> str:
    """Stable refused reason for families the milestone driver does not admit."""
    return k8s_unsupported_reason(fault_id)


__all__ = (
    "K8S_SIGNAL_FAULTS",
    "NO_UNDO_MARKER",
    "UNDO_OP",
    "ResolutionError",
    "SelectionError",
    "k8s_undo_spec",
    "make_k8s_resolver",
    "preferred_pod_from_graph",
    "unsupported_reason",
)