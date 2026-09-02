"""Execution context model (ADR-0014).

A fault must declare *where* it runs — not just *what* it targets.  The execution
context distinguishes host-level, container-level, process-level, network-
namespace, and remote execution so the planner can validate feasibility before
any mutation occurs.

Backward compatibility: the ``execution`` field on ``InjectFault`` is optional.
When absent the planner infers the context from the target node kind, which
matches the pre-0.2.0 behaviour.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict

from mayhem.domain.errors import InvariantViolationError

if TYPE_CHECKING:
    from mayhem.domain.execution_loci import ThreeLocusContext
    from mayhem.domain.topology import NodeKind


class ExecutionContext(StrEnum):
    """Where a fault is injected relative to the target."""

    HOST = "host"
    CONTAINER = "container"
    PROCESS = "process"
    NETWORK_NAMESPACE = "network_namespace"
    REMOTE_HOST = "remote_host"
    REMOTE_CONTAINER = "remote_container"


# Which topology node-kinds are compatible with each context.
# The planner uses this to reject impossible combinations *before* execution.
_CONTEXT_COMPATIBILITY: dict[ExecutionContext, frozenset[NodeKind]] = {}


def _build_compatibility() -> dict[ExecutionContext, frozenset[NodeKind]]:
    from mayhem.domain.topology import NodeKind  # local import to break cycles

    return {
        ExecutionContext.HOST: frozenset({NodeKind.HOST}),
        ExecutionContext.CONTAINER: frozenset({NodeKind.CONTAINER, NodeKind.SERVICE}),
        ExecutionContext.PROCESS: frozenset({NodeKind.PROCESS, NodeKind.CONTAINER, NodeKind.HOST}),
        ExecutionContext.NETWORK_NAMESPACE: frozenset({NodeKind.CONTAINER, NodeKind.HOST}),
        ExecutionContext.REMOTE_HOST: frozenset({NodeKind.HOST, NodeKind.EXTERNAL_DEPENDENCY}),
        ExecutionContext.REMOTE_CONTAINER: frozenset({NodeKind.CONTAINER, NodeKind.SERVICE}),
    }


def _compatibility() -> dict[ExecutionContext, frozenset[NodeKind]]:
    """Lazy-init the compatibility map on first access."""
    if not _CONTEXT_COMPATIBILITY:
        _CONTEXT_COMPATIBILITY.update(_build_compatibility())
    return _CONTEXT_COMPATIBILITY


class ExecutionContextSpec(BaseModel):
    """Declared execution context for a fault step.

    Optional on ``InjectFault`` — when absent the planner infers from the
    resolved target node kinds.
    """

    model_config = ConfigDict(frozen=True)

    context: ExecutionContext

    def assert_compatible(self, node_kinds: frozenset[NodeKind]) -> None:
        """Raise if *none* of the resolved target node-kinds are compatible.

        Raises:
            InvariantViolationError: When no target kind matches this context.
        """
        compat = _compatibility()
        allowed = compat.get(self.context, frozenset())
        if not allowed.intersection(node_kinds):
            kinds_str = ", ".join(sorted(k.value for k in node_kinds))
            raise InvariantViolationError(
                "execution_context_incompatible",
                f"context '{self.context.value}' cannot execute against "
                f"node kinds {{{kinds_str}}}; "
                f"allowed: {{{', '.join(sorted(k.value for k in allowed))}}}",
            )

    def to_three_locus(self) -> ThreeLocusContext:
        """Bridge to the three-locus model (ADR-M3-3).

        Returns a ``ThreeLocusContext`` derived from this legacy single-locus
        spec.  Imported lazily to keep this module dependency-light.
        """
        from mayhem.domain.execution_loci import ThreeLocusContext

        return ThreeLocusContext.from_single(self.context)


def infer_context_for_node(node_kind: NodeKind) -> ExecutionContext:
    """Best-default execution context for a given node kind.

    This is the heuristic the planner uses when the author omits an explicit
    ``execution`` block — it must never be more permissive than the explicit
    path.
    """
    from mayhem.domain.topology import NodeKind as NK  # local import

    mapping: dict[NodeKind, ExecutionContext] = {
        NK.HOST: ExecutionContext.HOST,
        NK.CONTAINER: ExecutionContext.CONTAINER,
        NK.SERVICE: ExecutionContext.CONTAINER,
        NK.PROCESS: ExecutionContext.PROCESS,
        NK.EXTERNAL_DEPENDENCY: ExecutionContext.REMOTE_HOST,
    }
    return mapping.get(node_kind, ExecutionContext.HOST)
