"""Mechanical safety gates between planner and executor (ADR-0012, ADR-0014,
architecture/safety.md).

Gate stack enforced here:
  G1 config policy      — allowlists/denylists, risk ladder, critical opt-in
  G2 plan validation    — budgets fit the topology graph, fingerprint match
  G3 pre-exec assertion — resolved targets re-checked against *live* topology
  G4 execution context  — declared context must be feasible for target node kinds

Precedence: denylist beats allowlist beats selector beats default.
Every refusal is typed and carries a machine-readable reason.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mayhem.domain.errors import InvariantViolationError, TargetResolutionError
from mayhem.domain.execution_context import ExecutionContext
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.risks import RiskLevel
from mayhem.domain.runtime_adapter import (
    CapabilityRequirements,
    CapabilityVerdict,
    RuntimeAdapter,
)
from mayhem.domain.target_selector import select_many

if TYPE_CHECKING:
    from collections.abc import Iterable

    from mayhem.config import PolicyCfg
    from mayhem.domain.experiments import BlastRadiusBudget, ExecutionPlan, PlannedFault
    from mayhem.domain.topology import NodeKind, TargetSelector, TopologyGraph


class SafetyRefusedError(InvariantViolationError):
    """A mechanical safety gate refused a fault or plan (``safety.refused``)."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(reason_code, message)
        self.reason_code = reason_code


def environment_fingerprint(
    *,
    host_names: Iterable[str],
    compose_digest: str,
    profile: str | None = None,
) -> str:
    """SHA256(sorted host set + compose digest + profile name)."""
    payload = "|".join(
        (
            ",".join(sorted(host_names)),
            compose_digest,
            profile or "default",
        )
    )
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True)
class SafetyContext:
    """Everything G1/G2 need; built once per CLI invocation."""

    policy: PolicyCfg
    budget: BlastRadiusBudget
    fingerprint: str
    allow_critical_cli: bool = False
    warnings: list[str] = field(default_factory=list)


DEFAULT_DENY = frozenset({"node.reboot"})
"""Host-reboot class faults are forbidden unless explicitly allowlisted
([ADR-0012]: an explicit allowlist overrides default deny; the bare default
policy never grants them)."""


def check_fault_admission(fault_id: str, definition_risk: RiskLevel, ctx: SafetyContext) -> None:
    """G1: denylist → allowlist → risk ceiling → critical double-opt-in."""
    if fault_id in ctx.policy.deny_faults:
        raise SafetyRefusedError("safety.refused", f"{fault_id}: denied by policy denylist")
    if ctx.policy.allow_faults is not None:
        if fault_id not in ctx.policy.allow_faults:
            raise SafetyRefusedError(
                "safety.refused", f"{fault_id}: not present in policy allowlist"
            )
    elif fault_id in DEFAULT_DENY:
        raise SafetyRefusedError(
            "safety.refused",
            f"{fault_id}: denied by default; add it to policy.allow_faults to opt in",
        )
    ceiling = ctx.policy.risk_ceiling
    if ceiling is not None and definition_risk.at_least(ceiling.next_higher()):
        raise SafetyRefusedError(
            "safety.refused",
            f"{fault_id}: risk {definition_risk.value} exceeds policy ceiling {ceiling.value}",
        )
    if definition_risk is RiskLevel.CRITICAL and not (
        ctx.policy.allow_critical and ctx.allow_critical_cli
    ):
        raise SafetyRefusedError(
            "safety.refused",
            f"{fault_id}: critical risk requires config policy.allow_critical AND --allow-critical",
        )


def _affected_node_ids(graph: TopologyGraph, targets: Iterable[str]) -> frozenset[str]:
    affected: set[str] = set()
    for node_id in targets:
        affected.add(node_id)
        affected |= graph.dependents_closure(node_id)
    return frozenset(affected)


def check_blast_radius(
    graph: TopologyGraph,
    target_node_ids: Iterable[str],
    duration_s: float,
    fault_ids_so_far: tuple[str, ...],
    new_fault_id: str,
    *,
    ctx: SafetyContext,
) -> dict[str, float]:
    """G2 (budget half): topology-derived blast radius must fit; returns measured stats."""
    budget = ctx.budget
    affected = _affected_node_ids(graph, target_node_ids)
    services_total = len(graph.of_kind(_service_kind()))
    services_hit = sum(1 for n in graph.of_kind(_service_kind()) if n.id in affected)
    hosts_hit = sum(1 for n in graph.of_kind(_host_kind()) if n.id in affected)
    pct = (services_hit / services_total * 100.0) if services_total else 0.0
    stats = {
        "services_pct": round(pct, 1),
        "hosts": float(hosts_hit),
        "concurrent_faults": float(len(fault_ids_so_far) + 1),
        "duration_per_fault": duration_s,
    }
    if pct > budget.max_services_pct:
        raise SafetyRefusedError(
            "safety.refused",
            f"blast radius: {new_fault_id} would affect {pct:.0f}% of services"
            f" > budget {budget.max_services_pct}%",
        )
    if hosts_hit > budget.max_hosts:
        raise SafetyRefusedError(
            "safety.refused",
            f"blast radius: {new_fault_id} touches {hosts_hit} hosts > budget {budget.max_hosts}",
        )
    if len(fault_ids_so_far) + 1 > budget.max_concurrent_faults:
        raise SafetyRefusedError("safety.refused", "blast radius: max_concurrent_faults exceeded")
    if duration_s > budget.max_duration_per_fault_s:
        raise SafetyRefusedError(
            "safety.refused",
            f"{new_fault_id} duration {duration_s:.0f}s exceeds per-fault cap"
            f" {budget.max_duration_per_fault_s:.0f}s",
        )
    pair = frozenset((*fault_ids_so_far, new_fault_id)) if fault_ids_so_far else None
    if pair and pair in budget.forbidden_fault_pairs:
        raise SafetyRefusedError(
            "safety.refused",
            f"blast radius: forbidden fault pair {sorted(pair)}",
        )
    return stats


def _check_execution_context(fault: PlannedFault, graph: TopologyGraph) -> None:
    """G4: validate that the declared execution context is feasible for all targets.

    Prevents accidental host-level execution when the experiment intended
    container-level execution, or vice versa.
    """
    if fault.execution_context is None:
        return
    node_kinds: set[NodeKind] = set()
    for target in fault.targets:
        for node_id in target.node_ids:
            node = graph.by_id(node_id)
            if node is not None:
                node_kinds.add(node.kind)
    if not node_kinds:
        return  # no nodes resolved — G3 will catch this
    try:
        fault.execution_context.assert_compatible(frozenset(node_kinds))
    except InvariantViolationError as exc:
        raise SafetyRefusedError(
            "execution_context.refused",
            f"{fault.fault_id}: {exc}",
        ) from exc


_K8S_NODE_KIND_VALUES: frozenset[str] = frozenset({"pod", "k8s_node"})
_K8S_REFUSE_MSG = (
    "kubernetes execution not yet supported; see the RuntimeAdapter contract at ADR-M7-1"
)

_REMOTE_NODE_KIND_VALUES: frozenset[str] = frozenset({"external_dependency"})
_REMOTE_REFUSE_MSG = (
    "remote execution not yet supported; ADR-M3-5 ships only the "
    "RemoteAgentInterface contract — no transport is wired in this milestone"
)


def _check_k8s_targets(plan: ExecutionPlan, graph: TopologyGraph) -> None:
    """Eligibility gate for K8s targets (ADR-M7-1 flip, sub-plan SP-3.2).
    A kubernetes workload routed through ``targets:`` is admitted when the
    live topology yields at least one eligible pod (``Running``, not
    terminating) at plan time — ``select_one`` raises SelectionError when
    nothing eligible, mirroring the planner gate.  Node-kind targets
    (k8s_node) keep their hard refusal until k-plan-5; the planned-identity
    scan stays for ``containers:``-authored faults resolved into k8s nodes.
    """
    for step in plan.steps:
        fault = step.fault
        if fault is None:
            continue
        scope = getattr(fault, "target", None)
        if scope is not None and scope.runtime == RuntimeLabel.KUBERNETES:
            select_many(graph, scope)  # claims eligible set; SelectionError when none
        for target in fault.targets:
            for node_id in target.node_ids:
                node = graph.by_id(node_id)
                if node is not None and node.kind in _K8S_NODE_KIND_VALUES:
                    raise SafetyRefusedError(
                        "k8s.unsupported",
                        f"{fault.fault_id}: {_K8S_REFUSE_MSG}",
                    )


def _check_remote_targets(plan: ExecutionPlan, graph: TopologyGraph) -> None:
    """Hard planning gate for remote targets (ADR-M3-5) — defect register #4.

    Remote execution is interface-only (``RemoteAgentInterface``): the adapter
    rejects requirements at ``evaluate`` time, but that refusal was never
    auto-wired into ``validate_plan``, so a remote spec would plan and only
    fail mid-execution.  This gate mirrors the K8s one: a plan targeting an
    ``external_dependency`` node fails loud and early at plan time.
    """
    for step in plan.steps:
        fault = step.fault
        if fault is None:
            continue
        for target in fault.targets:
            for node_id in target.node_ids:
                node = graph.by_id(node_id)
                if node is not None and node.kind in _REMOTE_NODE_KIND_VALUES:
                    raise SafetyRefusedError(
                        "remote.unsupported",
                        f"{fault.fault_id}: {_REMOTE_REFUSE_MSG}",
                    )


def validate_plan(
    plan: ExecutionPlan,
    graph: TopologyGraph,
    ctx: SafetyContext,
    adapter: RuntimeAdapter | None = None,
) -> None:
    """G1+G2+G4 over every fault step of an already-compiled plan.

    When *adapter* is provided, capability requirements are derived from the
    plan's execution contexts and evaluated against the adapter.  UNSUPPORTED
    verdicts block the plan; ALTERNATIVE verdicts are tolerated but emit a
    warning (ADR-M3-2).
    """
    if plan.environment_fingerprint != ctx.fingerprint:
        raise SafetyRefusedError(
            "environment.mismatch",
            "plan fingerprint does not match current environment identity;"
            " re-plan against live topology",
        )
    _check_k8s_targets(plan, graph)
    _check_remote_targets(plan, graph)
    if adapter is not None:
        _validate_capability_requirements(plan, adapter, ctx)
    seen_faults: list[str] = []
    for step in plan.steps:
        fault = step.fault
        if fault is None:
            continue
        definition_risk = _risk_of(fault.fault_id)
        check_fault_admission(fault.fault_id, definition_risk, ctx)
        target_ids = frozenset().union(*(t.node_ids for t in fault.targets))
        check_blast_radius(
            graph,
            target_ids,
            float(fault.duration),
            tuple(seen_faults),
            fault.fault_id,
            ctx=ctx,
        )
        seen_faults.append(fault.fault_id)
        # G4: validate execution context compatibility
        if fault.execution_context is not None:
            _check_execution_context(fault, graph)


def _validate_capability_requirements(  # noqa: PLR0912 — capability axes checked per-source
    plan: ExecutionPlan,
    adapter: RuntimeAdapter,
    ctx: SafetyContext,
) -> None:
    """ADR-M3-2: evaluate plan capability requirements against an adapter.

    Unsupported verdicts block the plan; alternatives warn.
    """
    namespaces: set[str] = set()
    tools: set[str] = set()
    permissions: set[str] = set()
    for step in plan.steps:
        fault = step.fault
        if fault is None:
            continue
        if fault.execution_loci is not None:
            target = fault.execution_loci.get("target")
            if isinstance(target, str) and target.startswith("network_namespace"):
                namespaces.add(target)
        if fault.execution_context is not None and (
            fault.execution_context.context
            in (ExecutionContext.NETWORK_NAMESPACE, ExecutionContext.PROCESS)
        ):
            namespaces.add(fault.execution_context.context.value)
        for target in fault.targets:
            for node_id in target.node_ids:
                if node_id.startswith("net"):
                    namespaces.add(node_id)
                if node_id.startswith(("p-", "proc")):
                    permissions.add("limit")

    reqs = CapabilityRequirements(
        namespaces=frozenset(namespaces),
        tools=frozenset(tools),
        permissions=frozenset(permissions),
    )
    fallback = CapabilityRequirements(
        namespaces=frozenset({"network"}),
        tools=frozenset({"tool"}),
        permissions=frozenset({"limit"}),
    )
    if not (namespaces or tools or permissions):
        result = adapter.evaluate(fallback)
    else:
        result = adapter.evaluate(reqs)
    if result.blocking:
        message = result.refuse_with_message() or "unsupported capability requirements"
        raise SafetyRefusedError("capability.unsupported", f"{adapter.id}: {message}")
    for key, verdict in result.verdicts.items():
        if verdict == CapabilityVerdict.ALTERNATIVE:
            ctx.warnings.append(f"{adapter.id}: capability '{key}' satisfied via ALTERNATIVE path")


def pre_exec_assertion(
    target_selector_pairs: Iterable[tuple[TargetSelector, frozenset[str] | tuple[str, ...]]],
    live_graph: TopologyGraph,
) -> None:
    """G3: seconds before injection, re-check selectors against live topology."""
    for selector, expected_ids in target_selector_pairs:
        try:
            live = live_graph.resolve(selector)
        except TargetResolutionError as exc:
            raise SafetyRefusedError(
                "target.drift", f"G3 drift refusal for {selector}: {exc}"
            ) from None
        live_ids = frozenset(n.id for n in live)
        missing = set(expected_ids) - live_ids
        if missing:
            raise SafetyRefusedError(
                "target.drift",
                f"G3 drift refusal: nodes vanished since planning: {sorted(missing)}",
            )


# -- helpers ---------------------------------------------------------------------------


def _risk_of(fault_id: str) -> RiskLevel:
    from mayhem.domain.catalog import (
        definition_for,
    )  # local: keep module import graph flat
    from mayhem.domain.errors import SchemaValidationError

    try:
        return definition_for(fault_id).risk
    except SchemaValidationError:
        return RiskLevel.LOW


def _service_kind() -> NodeKind:
    from mayhem.domain.topology import NodeKind

    return NodeKind.SERVICE


def _host_kind() -> NodeKind:
    from mayhem.domain.topology import NodeKind

    return NodeKind.HOST
