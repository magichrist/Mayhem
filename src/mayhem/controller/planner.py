"""Planner — compiles experiment specs into frozen ExecutionPlans.

Deterministic plans resolve every selector against the topology snapshot and
attach a compensation contract to every fault (write-ahead undo). Random
plans pick from the catalog under the selection policy with a recorded seed.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from mayhem.controller.compensation import compensated, template_for
from mayhem.domain.catalog import all_definitions, definition_for
from mayhem.domain.errors import (
    InvariantViolationError,
    SchemaValidationError,
    TargetResolutionError,
)
from mayhem.domain.experiments import (
    DeterministicExperiment,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    RandomExperiment,
    ResolvedTarget,
)
from mayhem.domain.topology import (
    NodeKind,
    ProcessNode,
    TargetSelector,
    TopologyNode,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from mayhem.domain.experiments import SelectionPolicy, StepAction
    from mayhem.domain.risks import RiskLevel
    from mayhem.domain.topology import TopologyGraph


class PlanningError(Exception):
    """Raised when a spec cannot be compiled into an honest plan."""


def plan_deterministic(
    run_id: str,
    exp: DeterministicExperiment,
    graph: TopologyGraph,
    *,
    config_snapshot_id: str,
    topology_snapshot_id: str,
    environment_fingerprint: str,
) -> ExecutionPlan:
    steps: list[PlannedStep] = []
    for seq, step in enumerate(exp.steps):
        _plan_action(run_id, step.id, seq, step.action, graph, steps)

    if not any(s.fault for s in steps):
        # A plan that never injects is a checklist, not a chaos run.
        raise PlanningError(f"experiment {exp.metadata.name!r} contains no fault injection")

    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DETERMINISTIC,
        steps=tuple(steps),
        config_snapshot_id=config_snapshot_id,
        topology_snapshot_id=topology_snapshot_id,
        environment_fingerprint=environment_fingerprint,
    )


def _admitted_candidates(policy: SelectionPolicy, ceiling: RiskLevel | None) -> list[str]:
    """Faults eligible for the random lottery: compensatable + policy-admitted."""
    candidates: list[str] = []
    for definition in all_definitions():
        if template_for(definition.id) is None:
            continue  # uncompensatable faults never enter the lottery
        if definition.id in policy.exclude_faults:
            continue
        if policy.categories is not None and definition.category not in policy.categories:
            continue
        if ceiling is not None and definition.risk.at_least(ceiling.next_higher()):
            continue
        candidates.append(definition.id)
    return candidates


def _draw_chosen(
    rng: random.Random,
    policy: SelectionPolicy,
    candidates: list[str],
    weights: list[float],
) -> list[str]:
    """Weighted draw without repetition; forbidden pairs only bind when co-drawn."""
    chosen: list[str] = []
    attempts = 0
    while len(chosen) < min(policy.count, len(candidates)) and attempts < 200:
        attempts += 1
        candidate = rng.choices(candidates, weights=weights, k=1)[0]
        if any(frozenset({candidate, other}) in policy.forbidden_pairs for other in chosen):
            continue
        if candidate not in chosen:
            chosen.append(candidate)
    return chosen


def plan_random(
    run_id: str,
    exp: RandomExperiment,
    graph: TopologyGraph,
    *,
    config_snapshot_id: str,
    topology_snapshot_id: str,
    environment_fingerprint: str,
    rng_factory: Callable[[int], random.Random] = random.Random,
    seed_override: int | None = None,
    audit_sink: Callable[[dict[str, object]], None] | None = None,
) -> ExecutionPlan:
    seed = exp.seed if exp.seed is not None else random.SystemRandom().randrange(2**31)
    if seed_override is not None:
        seed = seed_override
    rng = rng_factory(seed)
    policy = exp.selection
    ceiling = exp.constraints.risk_ceiling

    candidates = _admitted_candidates(policy, ceiling)
    if not candidates:
        raise PlanningError("selection policy admits zero compensatable faults")
    weight_map = policy.weights or {}
    weights = [float(weight_map.get(fault_id, 1.0)) for fault_id in candidates]
    chosen = _draw_chosen(rng, policy, candidates, weights)

    steps: list[PlannedStep] = []
    for offset, fault_id in enumerate(chosen):
        selectors = _selectors_for(graph, fault_id, rng)
        if selectors is None:
            continue  # not resolvable against this topology
        action = InjectFault(
            fault=fault_id,
            selectors=selectors,
            params=_params_for(fault_id, rng),
            duration=10.0,
        )
        _plan_action(run_id, f"rnd-{offset}", offset, action, graph, steps)
    if not steps:
        raise PlanningError("random selection resolved no executable steps")
    if audit_sink is not None:
        state = rng.getstate()
        audit_sink(
            {
                "candidates": candidates,
                "weights": dict(zip(candidates, weights, strict=True)),
                "rng_state": [state[0], list(state[1]), state[2]],
                "seed": seed,
            }
        )
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.RANDOM,
        steps=tuple(steps),
        config_snapshot_id=config_snapshot_id,
        topology_snapshot_id=topology_snapshot_id,
        environment_fingerprint=environment_fingerprint,
        seed=seed,
    )


def _resolve_targets(
    action: InjectFault, step_id: str, graph: TopologyGraph
) -> tuple[list[ResolvedTarget], list[TopologyNode]]:
    """Resolve every selector of an inject_fault against the blueprint graph."""
    resolved_targets: list[ResolvedTarget] = []
    nodes: list[TopologyNode] = []
    try:
        for selector in action.selectors:
            matched = graph.resolve(selector)
            nodes.extend(matched)
            resolved_targets.append(
                ResolvedTarget(selector=selector, node_ids=frozenset(n.id for n in matched))
            )
    except TargetResolutionError as exc:
        msg = f"selector {exc.selector!s} in step {step_id!r}: {exc}"
        raise PlanningError(msg) from None
    return resolved_targets, nodes


def _plan_action(  # noqa: PLR0917 — internal flattener, positional by design
    run_id: str,
    step_id: str,
    seq: int,
    action: StepAction,
    graph: TopologyGraph,
    out: list[PlannedStep],
) -> None:
    """Flatten one authored step into >=1 planned steps; Parallel branches inline."""
    if action.type == "parallel":
        for branch_seq, branch in enumerate(action.branches):
            for inner_action in branch:
                _plan_action(run_id, f"{step_id}.{branch_seq}", seq, inner_action, graph, out)
        return
    if action.type != "inject_fault":
        out.append(PlannedStep(id=step_id, seq=seq, raw_action=action))
        return

    try:
        definition = definition_for(action.fault)
    except SchemaValidationError as exc:
        raise PlanningError(str(exc)) from None
    except LookupError as exc:
        raise PlanningError(str(exc)) from None
    resolved_targets, nodes = _resolve_targets(action, step_id, graph)

    for node in nodes:
        if node.kind not in definition.applicable_node_kinds:
            msg = (
                f"fault {definition.id!r} does not apply to node "
                f"{node.id!r} of kind {node.kind.value!r}"
            )
            raise PlanningError(msg)

    # When a process-level fault targets a service or container node,
    # walk RUNS_ON edges to find the underlying ProcessNode (with a PID).
    # The compensation template needs a real ProcessNode to build undo ops.
    if NodeKind.PROCESS not in {n.kind for n in nodes}:
        extra: list[TopologyNode] = []
        for node in nodes:
            procs = graph.connected_processes(node.id)
            if procs:
                extra.extend(procs)
        if extra:
            nodes = list(nodes) + extra

    duration_s = float(action.duration)
    if duration_s > definition.max_duration_s:
        msg = (
            f"fault {definition.id!r} duration {duration_s}s exceeds cap "
            f"{definition.max_duration_s}s"
        )
        raise PlanningError(msg)
    try:
        params = definition.validate_params(action.params)
    except (ValueError, InvariantViolationError) as exc:
        msg = f"fault {definition.id!r} params rejected: {exc}"
        raise PlanningError(msg) from None

    planned = PlannedFault(
        fault_id=definition.id,
        targets=tuple(resolved_targets),
        params=params,
        duration=action.duration,
        backend=action.backend,
    )
    planned = compensated(planned, tuple(nodes))
    if not planned.undo_ops:
        msg = f"fault {definition.id!r} compiled without undo contract"
        raise InvariantViolationError("plan_write_ahead_undo", msg)
    out.append(PlannedStep(id=step_id, seq=seq, fault=planned, raw_action=action))


def _selectors_for(
    graph: TopologyGraph, fault_id: str, rng: random.Random
) -> tuple[TargetSelector, ...] | None:
    definition = definition_for(fault_id)
    resolvable = [k for k in sorted(definition.applicable_node_kinds) if graph.of_kind(k)]
    if not resolvable:
        return None  # nothing in this graph the fault can attach to
    kind = rng.choice(resolvable)
    node = rng.choice(graph.of_kind(kind))
    return (TargetSelector(kind=kind, expr=node.name),)


def _params_for(fault_id: str, rng: random.Random) -> dict[str, object]:
    defaults: dict[str, object] = {}
    for spec in definition_for(fault_id).params_schema:
        if spec.default is not None:
            defaults[spec.name] = spec.default
        elif spec.type.value == "duration":
            defaults[spec.name] = "5s"
        elif spec.type.value == "percent":
            defaults[spec.name] = 50
        elif spec.type.value == "integer":
            defaults[spec.name] = max(int(spec.minimum or 1), 10)
    return defaults
