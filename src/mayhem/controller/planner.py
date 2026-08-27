"""Planner — compiles drill specs into frozen ExecutionPlans.

Drill plans resolve every container name against the topology snapshot and
attach a compensation contract to every fault (write-ahead undo). Wait and
check blocks compile to non-fault steps; parallel blocks emit one step per
container so the executor can run them concurrently (Phase 5, ADR-0019/0021).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mayhem.controller.compensation import compensated
from mayhem.domain.catalog import definition_for
from mayhem.domain.common import parse_duration
from mayhem.domain.errors import (
    InvariantViolationError,
    SchemaValidationError,
)
from mayhem.domain.experiments import (
    CheckHttp,
    DrillSpec,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
    Wait,
)
from mayhem.domain.topology import (
    TargetSelector,
    TopologyNode,
)

if TYPE_CHECKING:
    from mayhem.domain.experiments import DrillContainer
    from mayhem.domain.topology import TopologyGraph


class PlanningError(Exception):
    """Raised when a spec cannot be compiled into an honest plan."""


def plan_drill(
    run_id: str,
    spec: DrillSpec,
    graph: TopologyGraph,
    *,
    config_snapshot_id: str,
    topology_snapshot_id: str,
    environment_fingerprint: str,
    engine: str = "podman",
) -> ExecutionPlan:
    """Compile a :class:`DrillSpec` into an :class:`ExecutionPlan`.

    Drill plans are authored around container names rather than target
    selectors. Each fault on a container is resolved to its topology node and
    the relevant compensation contract is attached (write-ahead undo). Wait and
    check blocks compile to non-fault steps; parallel blocks emit one step per
    container so the executor can run them concurrently (Phase 5).
    """
    _validate_container_names(spec, graph)

    steps: list[PlannedStep] = []
    seq = 0
    for block in spec.execution:
        if block.parallel:
            # All containers in a parallel block share one `seq` so the
            # executor groups and runs them concurrently (Phase 5).
            for container_name in block.parallel:
                _plan_container_faults(
                    container_name,
                    spec.containers[container_name],
                    graph,
                    steps,
                    seq,
                )
            seq += 1
        elif block.sequential:
            for container_name in block.sequential:
                _plan_container_faults(
                    container_name,
                    spec.containers[container_name],
                    graph,
                    steps,
                    seq,
                )
                seq += 1
        elif block.wait is not None:
            steps.append(
                PlannedStep(
                    id=f"wait-{seq:04d}",
                    seq=seq,
                    raw_action=Wait(type="wait", duration=block.wait),
                )
            )
            seq += 1
        elif block.check:
            for i, probe in enumerate(block.check):
                expected = probe.expect.status if probe.expect else None
                steps.append(
                    PlannedStep(
                        id=f"check-{seq:04d}-{i}",
                        seq=seq,
                        raw_action=CheckHttp(
                            type="check_http",
                            url=probe.http or "",
                            expected_status=expected,
                        ),
                    )
                )
                seq += 1

    if not any(s.fault for s in steps):
        raise PlanningError(f"drill {spec.name!r} contains no fault injection")

    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        steps=tuple(steps),
        config_snapshot_id=config_snapshot_id,
        topology_snapshot_id=topology_snapshot_id,
        environment_fingerprint=environment_fingerprint,
    )


def _container_names(graph: TopologyGraph) -> set[str]:
    """Every ``container_name`` declared across the topology (services + containers)."""
    names: set[str] = set()
    for node in graph.nodes:
        value = getattr(node, "container_name", None)
        if isinstance(value, str):
            names.add(value)
    return names


def _validate_container_names(spec: DrillSpec, graph: TopologyGraph) -> None:
    """Every container name in the spec must exist in the topology."""
    graph_names = _container_names(graph)
    missing = [name for name in spec.containers if name not in graph_names]
    if missing:
        raise PlanningError(
            f"container(s) not found in topology: {sorted(missing)} — "
            f"available: {sorted(graph_names)}"
        )
    # Also validate execution-block references name defined containers.
    for block in spec.execution:
        referenced = list(block.parallel or ()) + list(block.sequential or ())
        for name in referenced:
            if name not in spec.containers:
                raise PlanningError(
                    f"execution references container {name!r} which is not defined "
                    f"under 'containers'"
                )


def _find_container_nodes(graph: TopologyGraph, container_name: str) -> tuple[TopologyNode, ...]:
    """All topology nodes whose ``container_name`` matches the drill name."""
    matched = tuple(
        node for node in graph.nodes if getattr(node, "container_name", None) == container_name
    )
    if not matched:
        raise PlanningError(f"container {container_name!r} not found in topology graph")
    return matched


def _plan_container_faults(
    container_name: str,
    container: DrillContainer,
    graph: TopologyGraph,
    out: list[PlannedStep],
    seq: int,
) -> None:
    """Plan the fault list of one drill container as a single fault step.

    The container's faults are fused into one :class:`PlannedFault`. When a
    container carries multiple faults, only the first is injected per step for
    now; each step is independently compensatable (write-ahead undo per step).
    """
    if not container.faults:
        # Container referenced in execution but defines no faults: emit a
        # no-op placeholder step so the plan stays traceable.
        out.append(
            PlannedStep(
                id=f"{container_name}-{seq:04d}",
                seq=seq,
                raw_action=Wait(type="wait", duration=0.0),
            )
        )
        return

    matched = _find_container_nodes(graph, container_name)
    drill_fault = container.faults[0]
    try:
        definition = definition_for(drill_fault.fault)
    except SchemaValidationError as exc:
        raise PlanningError(str(exc)) from None
    except LookupError as exc:
        raise PlanningError(str(exc)) from None

    # A container name matches the whole subtree (service, container, process).
    # The fault applies to a specific kind subset, so target only the nodes it
    # can actually act on rather than asserting every matched kind is supported.
    nodes = tuple(n for n in matched if n.kind in definition.applicable_node_kinds)
    if not nodes:
        kinds = ", ".join(sorted({n.kind.value for n in matched}))
        raise PlanningError(
            f"fault {definition.id!r} does not apply to any node matched by "
            f"container {container_name!r} (matched kinds: {kinds})"
        )

    resolved_targets = tuple(
        ResolvedTarget(
            selector=TargetSelector(kind=node.kind, expr=node.name), node_ids=frozenset({node.id})
        )
        for node in nodes
    )

    # Compensation needs a ProcessNode; walk RUNS_ON edges from each container.
    compensation_nodes = list(nodes)
    for node in nodes:
        procs = graph.connected_processes(node.id)
        compensation_nodes.extend(procs)

    duration_raw = drill_fault.duration
    if isinstance(duration_raw, (int, float)):
        duration_s = float(duration_raw)
    else:
        duration_s = parse_duration(duration_raw)
    if duration_s > definition.max_duration_s:
        raise PlanningError(
            f"fault {definition.id!r} duration {duration_s}s exceeds cap "
            f"{definition.max_duration_s}s"
        )
    params = definition.validate_params(getattr(drill_fault, "params", None) or {})
    planned = PlannedFault(
        fault_id=definition.id,
        targets=tuple(resolved_targets),
        params=params,
        duration=drill_fault.duration,
        backend=None,
    )
    planned = compensated(planned, tuple(compensation_nodes))
    if not planned.undo_ops:
        msg = f"fault {definition.id!r} compiled without undo contract"
        raise InvariantViolationError("plan_write_ahead_undo", msg)
    out.append(
        PlannedStep(
            id=f"{container_name}-{seq:04d}",
            seq=seq,
            fault=planned,
            raw_action=InjectFault(
                fault=definition.id,
                selectors=tuple(TargetSelector(kind=node.kind, expr=node.name) for node in nodes),
                params=params,
                duration=drill_fault.duration,
            ),
        )
    )
