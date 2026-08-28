"""Planner — compiles drill specs into frozen ExecutionPlans.

Drill plans resolve every container name against the topology snapshot and
attach a compensation contract to every fault (write-ahead undo). Wait and
check blocks compile to non-fault steps; parallel blocks emit one step per
container so the executor can run them concurrently (Phase 5, ADR-0019/0021).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from mayhem.controller.compensation import compensated
from mayhem.domain.catalog import definition_for
from mayhem.domain.common import parse_duration
from mayhem.domain.errors import (
    InvariantViolationError,
    SchemaValidationError,
)
from mayhem.domain.experiments import (
    CheckHttp,
    DrillFault,
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
            # executor groups and runs them concurrently (Phase 5); the block
            # advances by the longest container's fault chain.
            emitted = 0
            for container_name in block.parallel:
                container = spec.containers[container_name]
                planned = _plan_container_faults(container_name, container, graph, steps, seq)
                emitted = max(emitted, planned)
            seq += emitted
        elif block.sequential:
            for container_name in block.sequential:
                container = spec.containers[container_name]
                seq += _plan_container_faults(container_name, container, graph, steps, seq)
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
) -> int:
    """Plan every fault on the container as its own compensatable step.

    Each fault becomes an independently compensatable step (write-ahead undo
    per fault); steps advance ``seq`` by one so a multi-fault container never
    double-injects concurrently. Returns the number of steps emitted so the
    caller can advance its sequence counter.
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
        return 1

    # A container name matches the whole subtree (service, container, process).
    matched = tuple(_find_container_nodes(graph, container_name))
    for i, drill_fault in enumerate(container.faults):
        out.append(_plan_fault_step(container_name, matched, drill_fault, graph, seq + i))
    return len(container.faults)


def _plan_fault_step(
    container_name: str,
    matched: tuple[TopologyNode, ...],
    drill_fault: DrillFault,
    graph: TopologyGraph,
    seq: int,
) -> PlannedStep:
    """Compile one drill fault into a compensatable :class:`PlannedStep`."""
    try:
        definition = definition_for(drill_fault.fault)
    except (SchemaValidationError, LookupError) as exc:
        raise PlanningError(str(exc)) from None

    # The fault applies to a specific kind subset, so target only the nodes it
    # can actually act on.
    nodes = tuple(n for n in matched if n.kind in definition.applicable_node_kinds)
    if not nodes:
        kinds = ", ".join(sorted({n.kind.value for n in matched}))
        raise PlanningError(
            f"fault {definition.id!r} does not apply to any node matched by "
            f"container {container_name!r} (matched kinds: {kinds})"
        )

    # Compensation runs against the drill container's whole subtree: the
    # fault's own matching nodes plus the container/process address the undo op
    # executes in. Drill faults name containers; e.g. cpu.saturate targets
    # SERVICE only, but its payload undo must still reach the container that
    # backs the service (ADR-0020).
    compensation_nodes = list(matched)
    seen = {id(node) for node in compensation_nodes}
    for node in matched:
        for proc in graph.connected_processes(node.id):
            if id(proc) not in seen:
                seen.add(id(proc))
                compensation_nodes.append(proc)

    # ``duration`` is a Duration (float); the ``"10s"`` class default reaches
    # the runtime as an unvalidated str unless explicitly passed through
    # validation, so resolve both forms before comparing against the cap.
    raw_duration: int | float | str = cast("int | float | str", drill_fault.duration)
    duration_s = (
        parse_duration(raw_duration) if isinstance(raw_duration, str) else float(raw_duration)
    )
    if duration_s > definition.max_duration_s:
        raise PlanningError(
            f"fault {definition.id!r} duration {duration_s}s exceeds cap "
            f"{definition.max_duration_s}s"
        )
    # DrillFault accepts fault parameters as extra YAML keys on the fault
    # entry (e.g. ``percent: 80``), collected via ``model_extra``; an explicit
    # ``params:`` mapping is honored as well. ``duration``, ``on_failure`` and
    # ``targets`` are declared fields and never treated as parameters.
    raw_params: dict[str, object] = {}
    explicit = getattr(drill_fault, "params", None)
    if isinstance(explicit, dict):
        raw_params.update(explicit)
    for key, value in (getattr(drill_fault, "model_extra", None) or {}).items():
        if value is not None:
            raw_params.setdefault(key, value)
    params = definition.validate_params(raw_params)

    selectors = tuple(TargetSelector(kind=node.kind, expr=node.name) for node in nodes)
    planned = PlannedFault(
        fault_id=definition.id,
        targets=tuple(
            ResolvedTarget(selector=selector, node_ids=frozenset({node.id}))
            for selector, node in zip(selectors, nodes, strict=True)
        ),
        params=params,
        duration=drill_fault.duration,
        backend=None,
    )
    planned = compensated(planned, tuple(compensation_nodes))
    if not planned.undo_ops:
        msg = f"fault {definition.id!r} compiled without undo contract"
        raise InvariantViolationError("plan_write_ahead_undo", msg)
    return PlannedStep(
        id=f"{container_name}-{seq:04d}",
        seq=seq,
        fault=planned,
        raw_action=InjectFault(
            fault=definition.id,
            selectors=selectors,
            params=params,
            duration=drill_fault.duration,
        ),
    )
