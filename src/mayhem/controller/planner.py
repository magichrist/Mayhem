"""Planner — compiles drill specs into frozen ExecutionPlans.

Drill plans resolve every container name against the topology snapshot and
attach a compensation contract to every fault (write-ahead undo). Wait and
check blocks compile to non-fault steps; parallel blocks emit one step per
container so the executor can run them concurrently (Phase 5, ADR-0019/0021).
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import TYPE_CHECKING, cast

from mayhem.controller.compensation import compensated
from mayhem.domain.capabilities import Capability
from mayhem.domain.catalog import all_definitions, definition_for
from mayhem.domain.common import parse_duration
from mayhem.domain.decisions import (
    DECISION_M4_1_ADDITIVE_DSL,
    DECISION_M4_3_SUCCESS_CRITERIA,
    DECISION_M4_4_OBSERVABILITY,
    DECISION_M4_5_SCHEMA_FREEZE,
    DECISION_M5_1_MANIAC,
    DecisionRef,
)
from mayhem.domain.errors import (
    InvariantViolationError,
    SchemaValidationError,
)
from mayhem.domain.experiments import (
    CheckHttp,
    CheckSpecStep,
    DrillContainer,
    DrillFault,
    DrillSpec,
    DrillTarget,
    ExecutionPlan,
    ExecutionStep,
    ExperimentKind,
    GroupMode,
    InjectFault,
    ManiacCfg,
    OnFailure,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
    Wait,
)
from mayhem.domain.faults import FaultDefinition, ParamType
from mayhem.domain.identity import RuntimeIdentity, RuntimeLabel
from mayhem.domain.maniac import draw_maniac_rounds
from mayhem.domain.target import (
    ResourceKind,
    SelectionMode,
    TargetScope,
)
from mayhem.domain.target_selector import select_many
from mayhem.domain.topology import (
    NodeKind,
    PortBinding,
    TargetSelector,
    TopologyNode,
)

if TYPE_CHECKING:
    from mayhem.domain.candidates import ExperimentCandidate
    from mayhem.domain.topology import TopologyGraph


class PlanningError(Exception):
    """Raised when a spec cannot be compiled into an honest plan."""


#: Capabilities only a Kubernetes runtime can provide. ``mayhem maniac``
#: synthesizes its config from a compose topology, so catalog faults gated on
#: these are never pooled (a compose graph cannot satisfy them at execution
#: time). Everything else — NET_ADMIN, PROCESS_CONTROL, engine flags, … — stays
#: in the pool and is resolved by the impact gate, which probes each container
#: and bypasses only the inert draws.
_MANIAC_EXCLUDED_CAPS = frozenset({Capability.KUBERNETES_ENGINE})


def synthesize_maniac_spec(graph: TopologyGraph, *, name: str = "maniac") -> DrillSpec:
    """Derive a drill spec purely from a compose-derived topology graph.

    ``mayhem maniac`` runs without an authored config file: this builder makes
    the draw pool self-describing. Every container in the topology authors the
    full container-addressable fault catalog, so
    :func:`draw_maniac_rounds` keeps a pure random walk over (container,
    fault) exactly like a hand-authored spec. The impact gate probes actual
    tooling at execution time and bypasses only the draws proven inert, so
    the compile never fails because an image lacks a binary.

    Safety is inherited, not authored: the synthesized spec carries no policy
    of its own (``config.maniac`` is left unset so the layered ``mayhem.yaml``
    ``maniac:`` block — or the CLI defaults — tune the draw), and every
    planned fault still passes the unchanged planner safety stack (risk
    ceiling, blast radius, ``max_faults``, timeout, compensation contract).

    Each pooled fault is authored with compile-ready parameters: catalog
    defaults are reused verbatim, and parameters the catalog declares
    mandatory are derived from the topology where an honest value exists
    (``port`` from the container's own published bindings, ``host`` from the
    container name, ``connections``/``delay_ms``/``rate``/``offset_ms`` at
    their least-disruptive minimums). Faults with a mandatory parameter that
    carries no derivable value (``net.bandwidth``'s host-side ``rate`` string,
    or a portless container) are left out of that container's pool — a draw
    must never name a fault it cannot compile. Faults that require a
    Kubernetes-only capability are pooled for no container.
    """
    containers: dict[str, DrillContainer] = {}
    for container_name in sorted(_container_names(graph)):
        matched = _find_container_nodes(graph, container_name)
        kinds = frozenset(node.kind for node in matched)
        ports = tuple(
            binding
            for node in matched
            for binding in (getattr(node, "exposed_ports", ()) or getattr(node, "ports", ()))
        )
        faults: list[DrillFault] = []
        for definition in all_definitions():
            if not definition.applicable_node_kinds & kinds:
                continue
            if not definition.required_caps.isdisjoint(_MANIAC_EXCLUDED_CAPS):
                continue
            params = _synthesized_params(definition, container_name, ports)
            if params is None:
                continue
            # ``params`` is an undeclared pydantic extra field on DrillFault
            # (extra="allow"), so construct through model_validate.
            faults.append(DrillFault.model_validate({"fault": definition.id, "params": params}))
        containers[container_name] = DrillContainer(faults=tuple(faults))
    return DrillSpec(
        kind="drill",
        name=name,
        hypothesis=(
            f"maniac: synthesized config for {len(containers)} container(s) "
            "from the compose topology"
        ),
        containers=containers,
        # ``plan_drill`` needs one execution step; the maniac planner replaces
        # the authored execution wholesale, so this placeholder never runs.
        execution=(ExecutionStep(wait="1s"),),
    )


def synthesize_candidate_spec(
    candidate: ExperimentCandidate, service: str, *, name: str = "explore"
) -> DrillSpec:
    """Build a single-fault DrillSpec from an Explore-loop candidate (plan-feat-2 §A1).

    This is the *Candidate → DrillSpec* seam: every explore cell becomes a
    normal ``DrillSpec`` that flows through the same ``plan_drill`` →
    ``engine.execute`` path as ``mayhem run``.  The service name is the
    *real* compose service (from ``ComposeFileProvider.service_names`` /
    ``build_graph``), never a host alias.

    The drill targets one container with one fault drawn from the candidate's
    ``fault_kinds`` and ``params``.  Catalog defaults are reused verbatim; no
    safety policy is authored (inherited from the layered ``mayhem.yaml`` or
    CLI defaults).
    """
    fault_id = candidate.primary_fault
    # Map candidate params into the DrillFault's extra-keys (model_extra):
    # the DrillSpec uses ``params:`` mapping plus ``model_extra`` for per-fault
    # YAML-style parameters; candidates carry a flat dict that must spread as
    # fault-level params.
    fault_params: dict[str, object] = {
        k: v for k, v in candidate.params.items() if k not in ("band",)
    }
    # DrillFault.model_validate accepts fault-level extra keys; pass params as
    # extra for the pydantic extra="allow" field.
    fault_dict: dict[str, object] = {"fault": fault_id, "duration": "10s"}
    fault_dict.update(fault_params)

    container = DrillContainer(faults=(DrillFault.model_validate(fault_dict),))
    return DrillSpec(
        kind="drill",
        name=name,
        hypothesis=candidate.expected_effect or f"explore: {fault_id} on {service}",
        containers={service: container},
        # The execution block must name the target container so ``plan_drill``
        # emts its fault steps — a wait-only block compiles to zero faults.
        execution=(ExecutionStep(sequential=(service,)),),
    )


def _synthesized_params(
    definition: FaultDefinition,
    container_name: str,
    ports: tuple[PortBinding, ...],
) -> dict[str, object] | None:
    """Auto-author a compile-ready param set for a synthesized fault.

    Catalog defaults win; the handful of parameters the catalog marks
    mandatory are filled from topology where an honest value exists, else
    ``None`` (the caller drops the fault from the pool).
    """
    params: dict[str, object] = {}
    mandatory: list[tuple[str, ParamType]] = []
    for spec in definition.params_schema:
        if spec.default is not None:
            params[spec.name] = spec.default
        elif spec.required:
            mandatory.append((spec.name, spec.type))
    for name, param_type in mandatory:
        if param_type is ParamType.STRING and name == "host":
            params[name] = container_name
            continue
        if param_type is ParamType.STRING:
            return None
        if name == "port":
            port = next(
                (binding.container_port for binding in ports if binding.protocol == "tcp"),
                next((binding.container_port for binding in ports), None),
            )
            if port is None:
                return None
            params[name] = port
        elif name in {"connections", "delay_ms", "rate", "offset_ms"}:
            params[name] = {"connections": 1, "delay_ms": 1000, "rate": 1, "offset_ms": 60000}[name]
        else:
            return None
    return params


def _embed_load_script(
    params: dict[str, object], fault_id: str, spec_dir: str | None
) -> dict[str, object]:
    """Embed a ``net.load`` ``script`` param into the frozen plan as content."""
    script_ref = params.get("script")
    if fault_id != "net.load" or not isinstance(script_ref, str) or not script_ref.strip():
        return params
    base = Path(spec_dir) if spec_dir else Path.cwd()
    script_path = Path(script_ref) if Path(script_ref).is_absolute() else base / script_ref
    try:
        content = script_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PlanningError(f"fault net.load script {script_path!s} unreadable: {exc}") from None
    except UnicodeDecodeError as exc:
        raise PlanningError(
            f"fault net.load script {script_path!s} must be UTF-8 text: {exc}"
        ) from None
    return {**params, "script_content": content}


def plan_drill(
    run_id: str,
    spec: DrillSpec,
    graph: TopologyGraph,
    *,
    config_snapshot_id: str,
    topology_snapshot_id: str,
    environment_fingerprint: str,
    engine: str = "podman",
    spec_dir: str | None = None,
) -> ExecutionPlan:
    """Compile a :class:`DrillSpec` into an :class:`ExecutionPlan`.

    Drill plans are authored around container names rather than target
    selectors. Each fault on a container is resolved to its topology node and
    the relevant compensation contract is attached (write-ahead undo). Wait and
    check blocks compile to non-fault steps; parallel blocks emit one step per
    container so the executor can run them concurrently (Phase 5). ``spec_dir``
    anchors assets referenced by the spec (e.g. the ``net.load`` ``script``
    parameter) so relative paths resolve against the drill file.

    ``targets:`` specs (k-plan-1) compile through :func:`_plan_targeted_drill`:
    the logical target is pinned on every planned fault, and kubernetes drills
    compile even though the live driver does not exist yet — that is the point
    of the plan.
    """
    if spec.targets is not None:
        return _plan_targeted_drill(
            run_id,
            spec,
            graph,
            config_snapshot_id=config_snapshot_id,
            topology_snapshot_id=topology_snapshot_id,
            environment_fingerprint=environment_fingerprint,
            spec_dir=spec_dir,
        )
    assert spec.containers is not None  # exactly-one-of enforced by DrillSpec
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
                planned = _plan_container_faults(
                    container_name,
                    container,
                    graph,
                    steps,
                    seq,
                    recovery_default=spec.config.recovery,
                    on_failure_default=spec.config.on_failure,
                    spec_dir=spec_dir,
                )
                emitted = max(emitted, planned)
            seq += emitted
        elif block.sequential:
            for container_name in block.sequential:
                container = spec.containers[container_name]
                seq += _plan_container_faults(
                    container_name,
                    container,
                    graph,
                    steps,
                    seq,
                    recovery_default=spec.config.recovery,
                    on_failure_default=spec.config.on_failure,
                    spec_dir=spec_dir,
                )
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
        elif block.check_spec:
            for i, cspec in enumerate(block.check_spec):
                steps.append(
                    PlannedStep(
                        id=f"check-{seq:04d}-{i}",
                        seq=seq,
                        raw_action=CheckSpecStep(
                            type="check_spec",
                            check_id=cspec.id,
                            probe=cspec.probe,
                            execution=cspec.execution,
                            target=cspec.target,
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
        success=spec.success,
        observability=spec.observability,
        decision_refs=_governing_decisions(spec),
    )


def _plan_targeted_drill(
    run_id: str,
    spec: DrillSpec,
    graph: TopologyGraph,
    *,
    config_snapshot_id: str,
    topology_snapshot_id: str,
    environment_fingerprint: str,
    spec_dir: str | None = None,
) -> ExecutionPlan:
    """Compile a ``targets:`` drill (k-plan-1 §1.2/§1.5).

    Mirrors :func:`plan_drill`'s execution walker, but each logical target
    desugars into the shared :class:`TargetScope` and is pinned on every fault.
    Kubernetes drills compile even without a live driver: topology resolution
    is best-effort while the plan always carries the authored logical target
    (the execution-side impact gate re-applies resolution k-plan-2+).
    """
    _validate_target_names(spec)
    assert spec.targets is not None
    steps: list[PlannedStep] = []
    seq = 0
    for block in spec.execution:
        if block.parallel:
            emitted = 0
            for logical_id in block.parallel:
                emitted = max(
                    emitted,
                    _plan_target_faults(
                        logical_id,
                        spec.targets[logical_id],
                        graph,
                        steps,
                        seq,
                        recovery_default=spec.config.recovery,
                        on_failure_default=spec.config.on_failure,
                        spec_dir=spec_dir,
                    ),
                )
            seq += emitted
        elif block.sequential:
            for logical_id in block.sequential:
                seq += _plan_target_faults(
                    logical_id,
                    spec.targets[logical_id],
                    graph,
                    steps,
                    seq,
                    recovery_default=spec.config.recovery,
                    on_failure_default=spec.config.on_failure,
                    spec_dir=spec_dir,
                )
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
        elif block.check_spec:
            for i, cspec in enumerate(block.check_spec):
                steps.append(
                    PlannedStep(
                        id=f"check-{seq:04d}-{i}",
                        seq=seq,
                        raw_action=CheckSpecStep(
                            type="check_spec",
                            check_id=cspec.id,
                            probe=cspec.probe,
                            execution=cspec.execution,
                            target=cspec.target,
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
        success=spec.success,
        observability=spec.observability,
        decision_refs=_governing_decisions(spec),
    )


def _validate_target_names(spec: DrillSpec) -> None:
    """Execution steps may only reference targets defined under ``targets:``
    (k-plan-1 §1.2). No topology coupling: kubernetes targets resolve against
    the graph later, at the execution-side impact gate."""
    assert spec.targets is not None
    for block in spec.execution:
        referenced = list(block.parallel or ()) + list(block.sequential or ())
        for logical_id in referenced:
            if logical_id not in spec.targets:
                raise PlanningError(
                    f"execution references target {logical_id!r} which is not defined "
                    f"under 'targets'"
                )


def _container_scope(container_name: str) -> TargetScope:
    """Normalized docker/podman locator desugared from ``containers:``
    (k-plan-1 §1.3) — the planner's single container → TargetRef point."""
    return TargetScope(
        logical_id=container_name,
        runtime=RuntimeLabel.DOCKER,
        kind=ResourceKind.CONTAINER,
        authority={"container_name": container_name},
    )


def _find_k8s_target_nodes(
    graph: TopologyGraph, scope: TargetScope
) -> tuple[TopologyNode, ...]:
    """Best-effort compile-time resolution of a kubernetes logical target.

    Only explicit ``kind: pod`` targets with a matching namespace+name resolve
    against the graph today (PodNode/K8sNode — topology.py:107-138); workload
    kinds (deployment/statefulset/…) stay logically pinned and resolve at the
    execution-side impact gate once a live driver exists (k-plan-2).
    """
    wanted_kind = NodeKind.POD if scope.kind == ResourceKind.POD else NodeKind.K8S_NODE
    if scope.kind not in (ResourceKind.POD, ResourceKind.K8S_NODE):
        return ()
    namespace = scope.authority.get("namespace", "")
    name = scope.authority.get("name", "")
    return tuple(
        node
        for node in graph.nodes
        if node.kind == wanted_kind
        and (getattr(node, "namespace", "default") or "default") == namespace
        and node.name == name
    )


def _plan_target_faults(
    logical_id: str,
    target: DrillTarget,
    graph: TopologyGraph,
    out: list[PlannedStep],
    seq: int,
    *,
    recovery_default: bool = True,
    on_failure_default: OnFailure = OnFailure.ABORT_AND_RECOVER,
    spec_dir: str | None = None,
) -> int:
    """Plan every fault on a logical target as its own compensatable step.

    The target desugars to one :class:`TargetScope` (``to_scope``), which is
    pinned on every planned fault. Reserved selection modes are schema-valid
    but refused here — they land in k-plan-4.
    """
    scope = target.to_scope(logical_id)
    _gate_k8s_selection_eligibility(graph, scope)

    if not target.faults:
        out.append(
            PlannedStep(
                id=f"{logical_id}-{seq:04d}",
                seq=seq,
                raw_action=Wait(type="wait", duration=0.0),
            )
        )
        return 1

    if scope.runtime == RuntimeLabel.KUBERNETES:
        matched = _find_k8s_target_nodes(graph, scope)
    else:
        matched = tuple(
            _find_container_nodes(graph, scope.authority.get("container_name", logical_id))
        )

    group_id = f"grp-{uuid.uuid4().hex[:12]}"
    mode = GroupMode.SEQUENTIAL
    path = f"/{logical_id}"
    seen_pods: set[str] = set()
    for i, drill_fault in enumerate(target.faults):
        _require_no_selection_conflict(scope, graph, seen_pods)
        out.append(
            _plan_fault_step(
                logical_id,
                matched,
                drill_fault,
                graph,
                seq + i,
                execution_group_id=group_id,
                group_mode=mode,
                group_path=path,
                recovery=(
                    drill_fault.recovery if drill_fault.recovery is not None else recovery_default
                ),
                on_failure=(
                    drill_fault.on_failure
                    if drill_fault.on_failure is not None
                    else on_failure_default
                ),
                spec_dir=spec_dir,
                target=scope,
                allow_unresolved=scope.runtime == RuntimeLabel.KUBERNETES,
            )
        )
    return len(target.faults)


def _gate_k8s_selection_eligibility(
    graph: TopologyGraph, scope: TargetScope
) -> None:
    """Mode-one eligibility gate (k-plan-2 §2.5).

    A kubernetes workload that IS in the live topology must yield at least one
    eligible pod (``Running``, not terminating) at plan time — otherwise
    planning fails with :class:`mayhem.domain.errors.SelectionError`
    rather than planning a target no executor could ever reach. A workload
    absent from the graph (logically pinned) passes through: execution
    resolves it. ``k8s_node`` has no mode-one pick until k-plan-5.
    """
    if scope.runtime != RuntimeLabel.KUBERNETES or scope.kind == ResourceKind.K8S_NODE:
        return
    select_many(graph, scope)  # multi-mode eligibility + static mode errors (k-plan-4 §4.2)


def _require_no_selection_conflict(
    scope: TargetScope, graph: TopologyGraph, seen_pods: set[str]
) -> bool:
    """Multi-instance overlap guard (k-plan-4 §4.2 ``conflict.overlap``).

    A second multi-instance step in the same round may not reuse pods an
    earlier step selected — refuse before any mutation is planned.  Returns
    ``True`` when the guard claimed pods (so the caller records them)."""
    if (
        scope.runtime != RuntimeLabel.KUBERNETES
        or scope.kind == ResourceKind.K8S_NODE
        or scope.selection is None
        or scope.selection.mode == SelectionMode.ONE
    ):
        return False
    picks = select_many(graph, scope)
    if picks is None:  # logically pinned workload: execution re-resolves
        return False
    picked = frozenset(pod.id for pod in picks)
    overlap = picked & seen_pods
    if overlap:
        raise PlanningError(
            f"conflict.overlap: selection on target {scope.logical_id!r} overlaps "
            f"earlier step pod(s) {sorted(overlap)}"
        )
    seen_pods |= set(picked)
    return True


def plan_maniac(
    run_id: str,
    spec: DrillSpec,
    graph: TopologyGraph,
    *,
    config_snapshot_id: str,
    topology_snapshot_id: str,
    environment_fingerprint: str,
    engine: str = "podman",
    spec_dir: str | None = None,
    maniac: ManiacCfg,
) -> ExecutionPlan:
    """Compile a maniac (random) drill into an :class:`ExecutionPlan` (ADR-M5-1).

    ``mayhem maniac`` compiles the spec exactly like ``plan_drill`` — container
    names resolved against the topology, compensation contracts attached — but
    replaces the authored ``execution`` with ``maniac.run_level`` random
    (container, fault) rounds drawn from the spec's own container map. Each
    round injects one fault, then replays the spec's authored check/check_spec
    steps so the M4 success criteria and observability sources produce the same
    machine verdict and evidence as a deterministic run. The spec's safety
    gates (risk ceiling, blast radius, ``max_faults``, timeout) apply unchanged
    to every round (ADR-M5-1).
    """
    if spec.targets is not None:
        raise PlanningError(
            "maniac random rounds require a `containers:` spec, got `targets:` "
            "(k-plan-1 §1.2)"
        )
    _validate_container_names(spec, graph)
    draws = draw_maniac_rounds(
        spec, level=maniac.level, run_level=maniac.run_level, seed=maniac.seed
    )

    steps: list[PlannedStep] = []
    seq = 0
    for draw in draws:
        matched = tuple(_find_container_nodes(graph, draw.container))
        steps.append(
            _plan_fault_step(
                draw.container,
                matched,
                draw.fault,
                graph,
                seq,
                execution_group_id=f"grp-{uuid.uuid4().hex[:12]}",
                group_mode=GroupMode.SEQUENTIAL,
                group_path=f"/{draw.container}",
                recovery=(
                    draw.fault.recovery if draw.fault.recovery is not None else spec.config.recovery
                ),
                on_failure=(
                    draw.fault.on_failure
                    if draw.fault.on_failure is not None
                    else spec.config.on_failure
                ),
                spec_dir=spec_dir,
            )
        )
        seq += 1
        seq = _plan_maniac_checks(steps, spec, seq)

    if not any(s.fault for s in steps):
        raise PlanningError(f"maniac drill {spec.name!r} drew no fault injection")

    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        steps=tuple(steps),
        config_snapshot_id=config_snapshot_id,
        topology_snapshot_id=topology_snapshot_id,
        environment_fingerprint=environment_fingerprint,
        success=spec.success,
        observability=spec.observability,
        decision_refs=(*_governing_decisions(spec), DECISION_M5_1_MANIAC),
    )


def _plan_maniac_checks(steps: list[PlannedStep], spec: DrillSpec, seq: int) -> int:
    """Replay the spec's authored check steps after a maniac round (ADR-M5-1).

    Waits, parallel/sequential grouping and the faults themselves are maniac's
    own business; only the check/check_spec blocks carry over so the success
    criteria can be evaluated per round. Ids keep the ``check-{seq:04d}-{i}``
    shape used by deterministic plans.
    """
    for block in spec.execution:
        if block.check:
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
        elif block.check_spec:
            for i, cspec in enumerate(block.check_spec):
                steps.append(
                    PlannedStep(
                        id=f"check-{seq:04d}-{i}",
                        seq=seq,
                        raw_action=CheckSpecStep(
                            type="check_spec",
                            check_id=cspec.id,
                            probe=cspec.probe,
                            execution=cspec.execution,
                            target=cspec.target,
                        ),
                    )
                )
                seq += 1
    return seq


def _governing_decisions(spec: DrillSpec) -> tuple[DecisionRef, ...]:
    """Decision ids + approved timestamps captured onto the plan (ADR-M4-1).

    The M4 decisions are the additivity/schema-freeze contracts every plan is
    compiled under; success and observability sections are included only when
    the spec actually exercises them, so each outcome records exactly the
    decisions that produced it.
    """
    refs = [
        DECISION_M4_1_ADDITIVE_DSL,
        DECISION_M4_5_SCHEMA_FREEZE,
    ]
    if spec.success is not None and not spec.success.empty:
        refs.append(DECISION_M4_3_SUCCESS_CRITERIA)
    if spec.observability is not None and not spec.observability.empty:
        refs.append(DECISION_M4_4_OBSERVABILITY)
    return tuple(refs)


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
    assert spec.containers is not None  # containers-path only (k-plan-1)
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
    *,
    recovery_default: bool = True,
    on_failure_default: OnFailure = OnFailure.ABORT_AND_RECOVER,
    spec_dir: str | None = None,
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
    # Every fault on this container belongs to one persistent group (ADR-M2-1):
    # members share an execution_group_id and run sequentially one-at-a-time so
    # a multi-fault container never double-injects concurrently.
    group_id = f"grp-{uuid.uuid4().hex[:12]}"
    mode = GroupMode.SEQUENTIAL
    path = f"/{container_name}"
    for i, drill_fault in enumerate(container.faults):
        out.append(
            _plan_fault_step(
                container_name,
                matched,
                drill_fault,
                graph,
                seq + i,
                execution_group_id=group_id,
                group_mode=mode,
                spec_dir=spec_dir,
                group_path=path,
                recovery=(
                    drill_fault.recovery if drill_fault.recovery is not None else recovery_default
                ),
                on_failure=(
                    drill_fault.on_failure
                    if drill_fault.on_failure is not None
                    else on_failure_default
                ),
            )
        )
    return len(container.faults)


def _resolve_fault_nodes(
    definition: FaultDefinition,
    matched: tuple[TopologyNode, ...],
    graph: TopologyGraph,
    container_name: str,
    allow_unresolved: bool,
) -> tuple[tuple[TopologyNode, ...], list[TopologyNode]]:
    """Pick the nodes a drill fault can act on plus its compensation subtree.

    A kubernetes logical target without a live node stays logically pinned
    (``allow_unresolved``): the plan carries the authored target and the
    execution-side impact gate re-resolves it (k-plan-1 §1.5). Compensation
    runs against the drill container's whole subtree — the fault's own
    matching nodes plus the container/process the undo op executes in
    (ADR-0020).
    """
    if not matched and allow_unresolved:
        return (), []
    nodes = tuple(n for n in matched if n.kind in definition.applicable_node_kinds)
    if not nodes:
        kinds = ", ".join(sorted({n.kind.value for n in matched}))
        raise PlanningError(
            f"fault {definition.id!r} does not apply to any node matched by "
            f"container {container_name!r} (matched kinds: {kinds})"
        )
    compensation_nodes = list(matched)
    seen = {id(node) for node in compensation_nodes}
    for node in matched:
        for proc in graph.connected_processes(node.id):
            if id(proc) not in seen:
                seen.add(id(proc))
                compensation_nodes.append(proc)
    return nodes, compensation_nodes




def _plan_fault_step(
    container_name: str,
    matched: tuple[TopologyNode, ...],
    drill_fault: DrillFault,
    graph: TopologyGraph,
    seq: int,
    *,
    execution_group_id: str,
    group_mode: GroupMode,
    group_path: str,
    recovery: bool,
    on_failure: OnFailure | None = None,
    spec_dir: str | None = None,
    target: TargetScope | None = None,
    allow_unresolved: bool = False,
) -> PlannedStep:
    """Compile one drill fault into a compensatable :class:`PlannedStep`."""
    try:
        definition = definition_for(drill_fault.fault)
    except (SchemaValidationError, LookupError) as exc:
        raise PlanningError(str(exc)) from None

    # The fault applies to a specific kind subset, so target only the nodes it
    # can actually act on. A kubernetes logical target without a live node
    # stays logically pinned (``allow_unresolved``): the plan carries the
    # authored target and the execution-side impact gate re-resolves it
    # (k-plan-1 §1.5).
    nodes, compensation_nodes = _resolve_fault_nodes(
        definition, matched, graph, container_name, allow_unresolved
    )

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
        if key == "params":
            continue  # already merged from the explicit ``params:`` group
        if value is not None:
            raw_params.setdefault(key, value)
    params = definition.validate_params(raw_params)

    # ``net.load`` accepts a host-side k6 ``script.js`` (param ``script``). The
    # script runs on the drill host at the target container's ip:port, so its
    # content is embedded into the frozen plan here — resolved relative to
    # the drill spec directory — rather than read at execution time.
    params = _embed_load_script(params, definition.id, spec_dir)

    scope = target or _container_scope(container_name)
    selectors = tuple(TargetSelector(kind=node.kind, expr=node.name) for node in nodes)
    planned = PlannedFault(
        fault_id=definition.id,
        targets=tuple(
            ResolvedTarget(selector=selector, node_ids=frozenset({node.id}))
            for selector, node in zip(selectors, nodes, strict=True)
        ),
        target=scope,
        params=params,
        duration=drill_fault.duration,
        backend=None,
        runtime_identity=_resolve_planned_identity(matched),
        recovery=recovery,
        on_failure=on_failure if on_failure is not None else OnFailure.ABORT_AND_RECOVER,
    )
    # Kuberares targets carry their undo contract with the driver (k-plan-2);
    # docker/podman faults must compile compensatably here (write-ahead undo).
    compiled_runtime = target.runtime if target is not None else RuntimeLabel.DOCKER
    if nodes and compiled_runtime != RuntimeLabel.KUBERNETES:
        planned = compensated(planned, tuple(compensation_nodes))
        if not planned.undo_ops:
            msg = f"fault {definition.id!r} compiled without undo contract"
            raise InvariantViolationError("plan_write_ahead_undo", msg)
    return PlannedStep(
        id=f"{container_name}-{seq:04d}",
        seq=seq,
        fault=planned,
        runtime_identity=_resolve_planned_identity(matched),
        execution_group_id=execution_group_id,
        group_mode=group_mode,
        group_path=group_path,
        raw_action=InjectFault(
            fault=definition.id,
            selectors=selectors,
            target=target,  # None for containers path; TargetScope for targets
            params=params,
            duration=drill_fault.duration,
        ),
    )


def _resolve_planned_identity(nodes: tuple[TopologyNode, ...]) -> RuntimeIdentity | None:
    """The canonical identity backing the authored name (ADR-M1-1).

    The plan targets the whole matched subtree (service/container/process), but
    the canonical ``RuntimeIdentity`` is contributed by the container node —
    the only node kind that carries it (topology.py). Resolver-key nodes
    (service/process) contribute no identity; their plan identity stays ``None``
    until a runtime adapter supplies one. This satisfies the milestone bar:
    identity is populated for a container-targeted fault whenever a provider is
    available.
    """
    for node in nodes:
        identity: object = getattr(node, "runtime_identity", None)
        if isinstance(identity, RuntimeIdentity):
            return identity
    return None


def restrict_plan_to_container(
    plan: ExecutionPlan, container_name: str, graph: TopologyGraph
) -> ExecutionPlan:
    """Scope a compiled plan to one container subtree (``mayhem --ctr``).

    Fault steps survive when any resolved target belongs to the container's
    service/container/process subtree; the subtree's own orchestration steps
    (``group_path == "/<container_name>"``) survive too. Faults, waits and
    checks for every other container are removed, so the run executes only
    against the requested container. All remaining steps keep their original
    ids and sequence — skipped ids are intentional (ADR-0021 traceability).

    Raises :class:`PlanningError` when the graph has no such container or the
    plan carries no fault step against it.
    """
    subtree = graph.node_ids_for_container(container_name)
    if not subtree:
        available = ", ".join(graph.container_names()) or "<none>"
        raise PlanningError(
            f"container {container_name!r} not found in topology graph (available: {available})"
        )

    kept: list[PlannedStep] = []
    for step in plan.steps:
        if step.fault is None:
            if step.group_path == f"/{container_name}":
                kept.append(step)
            continue
        if any(target.node_ids & subtree for target in step.fault.targets):
            kept.append(step)

    if not any(step.fault is not None for step in kept):
        raise PlanningError(
            f"plan {plan.run_id!r} has no fault steps targeting container {container_name!r}"
        )
    return plan.model_copy(update={"steps": tuple(kept)})
