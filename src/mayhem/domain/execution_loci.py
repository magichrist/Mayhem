"""Three-locus execution context (ADR-M3-3).

Replaces the single-locus ``ExecutionContext`` with three loci that let the
engine reason about *where the mutation lands* (target locus) vs *where the
agent/tool actually runs* (agent/tool locus) — local vs remote vs container.

Backward compatibility: ``from_single()`` derives all three loci from the
legacy single-locus value so pre-0.3.0 specs keep working unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from mayhem.domain.execution_context import ExecutionContext


class Locus(StrEnum):
    """Where a given locus physically runs."""

    LOCAL = "local"
    REMOTE = "remote"
    CONTAINER = "container"
    NETWORK_NAMESPACE = "network_namespace"


@dataclass(frozen=True)
class LocusSpec:
    """A single locus: the kind (where) plus the resolved identifier (what).

    For example a container locus carries the container id; a network-namespace
    locus carries the ns path.  The identifier is optional because the planner
    may not yet have resolved it.
    """

    kind: Locus
    identifier: str | None = None


@dataclass(frozen=True)
class ThreeLocusContext:
    """Target / agent / tool loci for one planned fault.

    ``plan_context`` is the required legacy ``ExecutionContext`` retained for
    M2 drift detection and planner compatibility.  The three loci trade it for
    higher precision where available.
    """

    target_locus: LocusSpec
    agent_locus: LocusSpec
    tool_locus: LocusSpec
    plan_context: ExecutionContext

    @classmethod
    def from_single(cls, ctx: ExecutionContext) -> ThreeLocusContext:
        """Derive a three-locus context from a legacy single locus.

        For host/remote contexts the agent and tool run on the same node as the
        target.  For container/process contexts the agent and tool run via the
        engine (inside the container), while the target is the container or its
        network namespace.
        """
        if ctx in (ExecutionContext.HOST, ExecutionContext.REMOTE_HOST):
            kind = Locus.LOCAL if ctx == ExecutionContext.HOST else Locus.REMOTE
            return cls(
                target_locus=LocusSpec(kind),
                agent_locus=LocusSpec(kind),
                tool_locus=LocusSpec(kind),
                plan_context=ctx,
            )
        if ctx in (ExecutionContext.CONTAINER, ExecutionContext.PROCESS):
            return cls(
                target_locus=LocusSpec(Locus.CONTAINER),
                agent_locus=LocusSpec(Locus.CONTAINER),
                tool_locus=LocusSpec(Locus.CONTAINER),
                plan_context=ctx,
            )
        if ctx == ExecutionContext.NETWORK_NAMESPACE:
            return cls(
                target_locus=LocusSpec(Locus.NETWORK_NAMESPACE),
                agent_locus=LocusSpec(Locus.LOCAL),
                tool_locus=LocusSpec(Locus.LOCAL),
                plan_context=ctx,
            )
        if ctx == ExecutionContext.REMOTE_CONTAINER:
            return cls(
                target_locus=LocusSpec(Locus.CONTAINER),
                agent_locus=LocusSpec(Locus.REMOTE),
                tool_locus=LocusSpec(Locus.REMOTE),
                plan_context=ctx,
            )
        raise ValueError(f"unsupported execution context: {ctx!r}")
