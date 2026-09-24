from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mayhem.domain.decisions import SafetyDecision, SafetySeverity
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
    def __init__(
        self, reason_code: str, message: str, decision: SafetyDecision | None = None
    ) -> None:
        super().__init__(reason_code, message)
        self.reason_code = reason_code
        self.decision = decision


def environment_fingerprint(
    *,
    host_names: Iterable[str],
    compose_digest: str,
    profile: str | None = None,
    policy_id: str | None = None,
    target_profile: str | None = None,
) -> str:
    payload = "|".join(
        (
            ",".join(sorted(host_names)),
            compose_digest,
            profile or "default",
            policy_id or "",
            target_profile or "",
        )
    )
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True)
class SafetyContext:
    policy: PolicyCfg
    budget: BlastRadiusBudget
    fingerprint: str
    allow_critical_cli: bool = False
    warnings: list[str] = field(default_factory=list)
    policy_id: str = ""
    decisions: list[SafetyDecision] = field(default_factory=list)
    environment: str | None = None
    target_profile: str | None = None

    def record(self, decision: SafetyDecision) -> None:
        self.decisions.append(decision)
        if decision.severity == SafetySeverity.warning:
            self.warnings.append(decision.reason)


DEFAULT_DENY = frozenset({"node.reboot"})


def _deny_decision(
    rule_id: str, inputs: dict[str, object], reason: str, remediation: str
) -> SafetyDecision:
    return SafetyDecision(
        rule_id=rule_id,
        inputs=dict(inputs),
        outcome="deny",
        reason=reason,
        remediation=remediation,
        severity=SafetySeverity.error,
    )


def check_fault_admission(fault_id: str, definition_risk: RiskLevel, ctx: SafetyContext) -> None:
    if fault_id in ctx.policy.deny_faults:
        dec = _deny_decision(
            "policy.deny_faults",
            {"fault_id": fault_id, "risk": definition_risk.value},
            f"{fault_id}: denied by policy denylist [policy.deny_faults]",
            f"remove {fault_id!r} from policy.deny_faults or use a different policy",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    if ctx.policy.allow_faults is not None:
        if fault_id not in ctx.policy.allow_faults:
            dec = _deny_decision(
                "policy.allow_faults",
                {"fault_id": fault_id, "allow_faults": sorted(ctx.policy.allow_faults)},
                f"{fault_id}: not present in policy allowlist [policy.allow_faults]",
                f"add {fault_id!r} to policy.allow_faults or relax the allowlist",
            )
            ctx.record(dec)
            raise SafetyRefusedError("safety.refused", dec.reason, dec)
    elif fault_id in DEFAULT_DENY:
        dec = _deny_decision(
            "policy.default_deny",
            {"fault_id": fault_id},
            f"{fault_id}: denied by default; add it to policy.allow_faults to opt in [policy.default_deny]",
            f"add {fault_id!r} to policy.allow_faults",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    ceiling = ctx.policy.risk_ceiling
    if ceiling is not None and definition_risk.at_least(ceiling.next_higher()):
        dec = _deny_decision(
            "policy.risk_ceiling",
            {"fault_id": fault_id, "risk": definition_risk.value, "ceiling": ceiling.value},
            f"{fault_id}: risk {definition_risk.value} exceeds policy ceiling {ceiling.value} [policy.risk_ceiling]",
            f"raise policy.risk_ceiling to {definition_risk.value} or use lower-risk fault",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    if definition_risk is RiskLevel.CRITICAL and not (
        ctx.policy.allow_critical
        and ctx.allow_critical_cli
        and fault_id in ctx.policy.critical_fault_acks
    ):
        dec = _deny_decision(
            "policy.critical_triple_optin",
            {
                "fault_id": fault_id,
                "allow_critical": ctx.policy.allow_critical,
                "allow_critical_cli": ctx.allow_critical_cli,
            },
            f"{fault_id}: critical risk requires config policy.allow_critical, the CLI-level --allow-critical, and a per-fault ack in policy.critical_fault_acks [policy.critical_triple_optin]",
            f"set policy.allow_critical=true, acknowledge {fault_id!r} in policy.critical_fault_acks, and pass --allow-critical",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    ctx.record(
        SafetyDecision(
            rule_id="policy.allow",
            inputs={"fault_id": fault_id, "risk": definition_risk.value},
            outcome="allow",
            reason=f"{fault_id}: admitted",
            remediation="",
            severity=SafetySeverity.info,
        )
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
        dec = _deny_decision(
            "blast_radius.max_services_pct",
            {"fault_id": new_fault_id, "pct": pct, "budget": budget.max_services_pct},
            f"blast radius: {new_fault_id} would affect {pct:.0f}% of services > budget {budget.max_services_pct}% [blast_radius.max_services_pct]",
            "reduce blast or raise blast_radius.max_services_pct",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    if hosts_hit > budget.max_hosts:
        dec = _deny_decision(
            "blast_radius.max_hosts",
            {"fault_id": new_fault_id, "hosts_hit": hosts_hit, "budget": budget.max_hosts},
            f"blast radius: {new_fault_id} touches {hosts_hit} hosts > budget {budget.max_hosts} [blast_radius.max_hosts]",
            "reduce blast or raise blast_radius.max_hosts",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    if len(fault_ids_so_far) + 1 > budget.max_concurrent_faults:
        dec = _deny_decision(
            "blast_radius.max_concurrent_faults",
            {
                "fault_id": new_fault_id,
                "concurrent": len(fault_ids_so_far) + 1,
                "budget": budget.max_concurrent_faults,
            },
            "blast radius: max_concurrent_faults exceeded [blast_radius.max_concurrent_faults]",
            "reduce concurrent faults or raise blast_radius.max_concurrent_faults",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    if duration_s > budget.max_duration_per_fault_s:
        dec = _deny_decision(
            "blast_radius.max_duration_per_fault_s",
            {
                "fault_id": new_fault_id,
                "duration": duration_s,
                "budget": budget.max_duration_per_fault_s,
            },
            f"{new_fault_id} duration {duration_s:.0f}s exceeds per-fault cap {budget.max_duration_per_fault_s:.0f}s [blast_radius.max_duration_per_fault_s]",
            "shorten duration or raise blast_radius.max_duration_per_fault_s",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    pair = frozenset((*fault_ids_so_far, new_fault_id)) if fault_ids_so_far else None
    if pair and pair in budget.forbidden_fault_pairs:
        dec = _deny_decision(
            "blast_radius.forbidden_fault_pairs",
            {"pair": sorted(pair)},
            f"blast radius: forbidden fault pair {sorted(pair)} [blast_radius.forbidden_fault_pairs]",
            "remove the forbidden pair from blast_radius or change fault set",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)
    ctx.record(
        SafetyDecision(
            rule_id="blast_radius.allow",
            inputs={"fault_id": new_fault_id, "stats": stats},
            outcome="allow",
            reason=f"{new_fault_id}: blast radius within budget",
            remediation="",
            severity=SafetySeverity.info,
        )
    )
    return stats


def _check_execution_context(fault: PlannedFault, graph: TopologyGraph) -> None:
    if fault.execution_context is None:
        return
    node_kinds: set[NodeKind] = set()
    for target in fault.targets:
        for node_id in target.node_ids:
            node = graph.by_id(node_id)
            if node is not None:
                node_kinds.add(node.kind)
    if not node_kinds:
        return
    try:
        fault.execution_context.assert_compatible(frozenset(node_kinds))
    except InvariantViolationError as exc:
        dec = _deny_decision(
            "execution_context.compatibility",
            {"fault_id": fault.fault_id, "node_kinds": sorted(k.value for k in node_kinds)},
            f"{fault.fault_id}: {exc} [execution_context.compatibility]",
            "change execution_context or target kinds",
        )
        raise SafetyRefusedError("execution_context.refused", dec.reason, dec) from exc


_K8S_NODE_KIND_VALUES: frozenset[str] = frozenset({"pod", "k8s_node"})
_K8S_REFUSE_MSG = (
    "kubernetes execution not yet supported; see the RuntimeAdapter contract at ADR-M7-1"
)
_K8S_UNSUPPORTED_REMEDIATION_DETAIL = (
    "k8s.unsupported: kubernetes execution not yet supported or capability-gated; "
    "see ADR-M7-1; missing capability or cluster context; check --context/--namespace and "
    "adapter capability (NODE_CONTROL/NETNS/DNS_CONTROL); manifest mode remains usable for planning"
)
_REMOTE_NODE_KIND_VALUES: frozenset[str] = frozenset({"external_dependency"})
_REMOTE_REFUSE_MSG = "remote execution not yet supported; ADR-M3-5 ships only the RemoteAgentInterface contract — no transport is wired in this milestone"


def k8s_unsupported_remediation(
    fault_id: str, capability: str | None = None, context: str | None = None
) -> str:
    parts = [f"{fault_id}: {_K8S_UNSUPPORTED_REMEDIATION_DETAIL}"]
    if capability:
        parts.append(f"missing capability: {capability}")
    if context:
        parts.append(f"context: {context}")
    return " — ".join(parts)


def _check_k8s_targets(plan: ExecutionPlan, graph: TopologyGraph) -> None:
    for step in plan.steps:
        fault = step.fault
        if fault is None:
            continue
        from mayhem.domain.target import ResourceKind

        scope = getattr(fault, "target", None)
        is_node_scope = (
            scope is not None
            and scope.runtime == RuntimeLabel.KUBERNETES
            and scope.kind == ResourceKind.K8S_NODE
        )
        if scope is not None and scope.runtime == RuntimeLabel.KUBERNETES:
            if is_node_scope:
                continue
            select_many(graph, scope)
        for target in fault.targets:
            for node_id in target.node_ids:
                node = graph.by_id(node_id)
                if node is not None and node.kind in _K8S_NODE_KIND_VALUES:
                    if is_node_scope:
                        continue
                    raise SafetyRefusedError(
                        "k8s.unsupported",
                        k8s_unsupported_remediation(
                            fault.fault_id,
                            capability="Kubernetes capability",
                            context=(
                                str(scope.authority.get("namespace")) if scope is not None else None
                            ),
                        ),
                    )


def _check_remote_targets(plan: ExecutionPlan, graph: TopologyGraph) -> None:
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
                        f"{fault.fault_id}: {_REMOTE_REFUSE_MSG} [remote.unsupported]",
                    )


def _check_environment_policy(ctx: SafetyContext) -> None:
    if ctx.environment is None:
        return
    from mayhem.domain.policy import BUILTIN_PROFILES

    profile = BUILTIN_PROFILES.get(ctx.policy_id) if ctx.policy_id else None
    if profile is None:
        return
    if not profile.allowed_environments and not profile.denied_environments:
        return
    from mayhem.domain.policy import is_environment_allowed

    if not is_environment_allowed(profile, ctx.environment):
        dec = _deny_decision(
            "policy.environment_restriction",
            {"environment": ctx.environment, "policy_id": ctx.policy_id},
            f"environment {ctx.environment!r} denied by policy {ctx.policy_id!r} [policy.environment_restriction]",
            "use --policy with allowed environment or adjust policy allowed_environments",
        )
        ctx.record(dec)
        raise SafetyRefusedError("safety.refused", dec.reason, dec)


def validate_plan(
    plan: ExecutionPlan,
    graph: TopologyGraph,
    ctx: SafetyContext,
    adapter: RuntimeAdapter | None = None,
) -> None:
    if plan.policy_id and ctx.policy_id and plan.policy_id != ctx.policy_id:
        dec = _deny_decision(
            "policy.identity_mismatch",
            {"plan_policy": plan.policy_id, "ctx_policy": ctx.policy_id},
            f"policy identity mismatch: plan {plan.policy_id!r} vs context {ctx.policy_id!r} [policy.identity_mismatch]",
            "re-plan with matching --policy",
        )
        ctx.record(dec)
        raise SafetyRefusedError("environment.mismatch", dec.reason, dec)
    if plan.environment_fingerprint != ctx.fingerprint:
        dec = _deny_decision(
            "environment.fingerprint_mismatch",
            {"plan_fp": plan.environment_fingerprint[:12], "ctx_fp": ctx.fingerprint[:12]},
            "plan fingerprint does not match current environment identity; re-plan against live topology [environment.fingerprint_mismatch]",
            "re-plan",
        )
        ctx.record(dec)
        raise SafetyRefusedError("environment.mismatch", dec.reason, dec)
    _check_environment_policy(ctx)
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
        if fault.execution_context is not None:
            _check_execution_context(fault, graph)


def _validate_capability_requirements(
    plan: ExecutionPlan,
    adapter: RuntimeAdapter,
    ctx: SafetyContext,
) -> None:
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
        dec = _deny_decision(
            "capability.unsupported",
            {"adapter": adapter.id, "verdicts": result.verdicts},
            f"{adapter.id}: {message} [capability.unsupported]",
            "use adapter with required capability or change fault",
        )
        ctx.record(dec)
        raise SafetyRefusedError("capability.unsupported", dec.reason, dec)
    for key, verdict in result.verdicts.items():
        if verdict == CapabilityVerdict.ALTERNATIVE:
            ctx.warnings.append(
                f"{adapter.id}: capability '{key}' satisfied via ALTERNATIVE path [capability.alternative]"
            )
            ctx.record(
                SafetyDecision(
                    rule_id="capability.alternative",
                    inputs={"adapter": adapter.id, "key": key},
                    outcome="warn",
                    reason=f"{adapter.id}: capability '{key}' satisfied via ALTERNATIVE path",
                    remediation="",
                    severity=SafetySeverity.warning,
                )
            )


def pre_exec_assertion(
    target_selector_pairs: Iterable[tuple[TargetSelector, frozenset[str] | tuple[str, ...]]],
    live_graph: TopologyGraph,
) -> None:
    for selector, expected_ids in target_selector_pairs:
        try:
            live = live_graph.resolve(selector)
        except TargetResolutionError as exc:
            raise SafetyRefusedError(
                "target.drift", f"G3 drift refusal for {selector}: {exc} [target.drift]"
            ) from None
        live_ids = frozenset(n.id for n in live)
        missing = set(expected_ids) - live_ids
        if missing:
            raise SafetyRefusedError(
                "target.drift",
                f"G3 drift refusal: nodes vanished since planning: {sorted(missing)} [target.drift]",
            )


def dry_run_policy_evaluation(
    plan: ExecutionPlan, graph: TopologyGraph, ctx: SafetyContext
) -> list[SafetyDecision]:
    decisions: list[SafetyDecision] = []
    try:
        validate_plan(plan, graph, ctx)
        decisions.extend(list(ctx.decisions))
        decisions.append(
            SafetyDecision(
                rule_id="dry_run.allow",
                inputs={"plan_id": plan.run_id},
                outcome="allow",
                reason="dry-run: plan would be allowed",
                remediation="",
                severity=SafetySeverity.info,
            )
        )
    except SafetyRefusedError as exc:
        if exc.decision is not None:
            decisions.append(exc.decision)
        else:
            decisions.append(
                SafetyDecision(
                    rule_id=exc.reason_code,
                    inputs={},
                    outcome="deny",
                    reason=str(exc),
                    remediation="",
                    severity=SafetySeverity.error,
                )
            )
    return decisions


def explain_fault_refusal(exc: SafetyRefusedError) -> dict[str, str]:
    dec = exc.decision
    if dec is None:
        return {"rule_id": exc.reason_code, "reason": str(exc), "remediation": ""}
    return {
        "rule_id": dec.rule_id,
        "reason": dec.reason,
        "remediation": dec.remediation,
        "inputs": str(dec.inputs),
    }


def _risk_of(fault_id: str) -> RiskLevel:
    from mayhem.domain.catalog import definition_for

    try:
        return definition_for(fault_id).risk
    except Exception:
        return RiskLevel.LOW


def _service_kind() -> NodeKind:
    from mayhem.domain.topology import NodeKind

    return NodeKind.SERVICE


def _host_kind() -> NodeKind:
    from mayhem.domain.topology import NodeKind

    return NodeKind.HOST
