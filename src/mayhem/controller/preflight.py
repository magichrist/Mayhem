from __future__ import annotations

import hashlib
from dataclasses import replace as dataclass_replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mayhem.controller.safety import (
    SafetyContext,
    SafetyRefusedError,
    check_blast_radius,
    environment_fingerprint,
    validate_plan,
)
from mayhem.domain.preflight import Preflight, plan_hash_for
from mayhem.domain.quota import RULE_BUDGET, RULE_PER_FAULT_CEILING, DamageLedger
from mayhem.domain.runtime_context import reconcile_engine

if TYPE_CHECKING:
    from mayhem.domain.runtime_context import RuntimeContext


def _compose_digest(compose: str | None) -> str:
    if compose is None:
        return "no-compose"
    try:
        return hashlib.sha256(Path(compose).read_bytes()).hexdigest()
    except Exception:
        return hashlib.sha256(compose.encode()).hexdigest()


def _k8s_profile(profiles: dict[str, Any], target: str | None) -> tuple[Any | None, bool]:
    if target is not None:
        return profiles.get(target), False
    if len(profiles) == 1:
        return next(iter(profiles.values())), False
    return None, len(profiles) > 1


def _k8s_guidance(fault_ids: list[str]) -> tuple[str, str, str]:
    from mayhem.controller.k8s_runtime import k8s_family_for

    families = {k8s_family_for(fault_id) for fault_id in fault_ids if fault_id.startswith("k8s.")}
    recovery = {
        "node": "restore the node worker, then verify Ready and schedulable",
        "workload": "restore the workload snapshot, then verify rollout health",
        "dns": "restore the DNS add-on object, then verify resolution",
        "service": "restore the Service snapshot, then verify endpoints",
    }.get(next(iter(families), ""), "restore the recorded Kubernetes object and verify readiness")
    wait = {
        "node": "wait for node Ready and schedulable state",
        "workload": "wait for workload rollout and eligible pod replacement",
        "dns": "wait for DNS propagation and a successful resolution",
        "service": "wait for Service endpoints to repopulate",
    }.get(next(iter(families), ""), "wait for the Kubernetes controller to reconcile the mutation")
    compensation = "; ".join(sorted(families)) or "Kubernetes compensation contract unavailable"
    return compensation, wait, recovery


# A budget with every cap lifted, used *only* to make the authoritative gate
# return its ``stats`` for a step it would otherwise refuse. The numbers the
# gate computes do not depend on the budget — only the comparisons do — so a
# probe through this budget yields exactly the values ``check_blast_radius``
# would have reported had it not short-circuited on the first violation.
_UNRESTRICTED_BUDGET_UPDATE: dict[str, object] = {
    "max_services_pct": 100.0,
    "max_hosts": 2**31 - 1,
    "max_concurrent_faults": 2**31 - 1,
    "max_duration_per_fault_s": float("inf"),
    "forbidden_fault_pairs": frozenset(),
}

# Preflight key name -> the budget cap it is checked against, in the order the
# gate enforces them.
_BLAST_LIMITS: tuple[tuple[str, str], ...] = (
    ("services_pct", "max_services_pct"),
    ("hosts", "max_hosts"),
    ("concurrent_faults", "max_concurrent_faults"),
    ("duration_per_fault", "max_duration_per_fault_s"),
)

# The cumulative-damage rules, which are *not* per-step limits and so are not
# rendered by the loop above; they get their own block below.
_DAMAGE_RULES: frozenset[str] = frozenset({RULE_BUDGET, RULE_PER_FAULT_CEILING})


def _unknown_blast(reason: str) -> dict[str, object]:
    """The preflight blast-radius record for a radius that could not be computed.

    Deliberately *not* ``{}``: an empty dict renders as ``blast_radius: unknown``
    and is indistinguishable from a tool with no opinion. This carries the
    reason so the operator can tell "not computed" from "computed as zero".
    """
    return {"status": "unknown", "error": reason}


def _probe_context(safety: SafetyContext, *, unrestricted: bool) -> SafetyContext:
    """A throwaway clone of ``safety`` so preflight never pollutes the real one.

    ``check_blast_radius`` records a decision on every call; running it against
    the caller's context would append preflight's own probe decisions to the
    safety record the run is judged by. The cumulative damage quota is lifted
    alongside the five per-step caps for the same reason *and* the same
    necessity: the stats probe has to survive a step the quota would refuse,
    or the operator never sees the projected total for the steps after it.
    """
    budget = safety.budget
    damage_quota = safety.damage_quota
    if unrestricted:
        budget = budget.model_copy(update=_UNRESTRICTED_BUDGET_UPDATE)
        damage_quota = damage_quota.unrestricted()
    return dataclass_replace(
        safety, budget=budget, damage_quota=damage_quota, decisions=[], warnings=[]
    )


def _blast_radius_for(plan: Any, graph: Any, safety: SafetyContext | None) -> dict[str, object]:
    """The blast radius the real gate will enforce, for every limit it checks.

    This is a *preview* of :func:`mayhem.controller.safety.check_blast_radius`,
    not a re-derivation of it: the numbers come from calling that function once
    per fault step, in the same order and with the same ``fault_ids_so_far``
    accumulation that ``validate_plan`` uses. A step that the gate would refuse
    is probed a second time through an unrestricted budget so the operator still
    sees how far over the limit it is.

    Never raises and never returns ``{}`` — a computation failure is reported as
    an explicit ``unknown`` state carrying the reason.

    Alongside the five per-step limits it reports the **cumulative** damage
    quota projected over the whole plan, which is the only number here that
    describes the sequence rather than a step.
    """
    if plan is None:
        return _unknown_blast("no plan to compute a blast radius for")
    if graph is None:
        return _unknown_blast("no topology graph: cannot resolve affected nodes")
    if safety is None or getattr(safety, "budget", None) is None:
        return _unknown_blast("no safety budget resolved: cannot evaluate limits")

    try:
        fault_steps = [
            s for s in (getattr(plan, "steps", None) or []) if getattr(s, "fault", None) is not None
        ]
        stats_ctx = _probe_context(safety, unrestricted=True)
        gate_ctx = _probe_context(safety, unrestricted=False)

        # Worst case across steps: the gate refuses a plan as soon as any single
        # step breaches a limit, so the maximum is the number that decides.
        worst: dict[str, float] = {}
        violations: list[dict[str, str]] = []
        seen_faults: list[str] = []
        # One ledger per probe, threaded through the steps in plan order, so the
        # projected damage below is the *whole plan's* total and not a per-step
        # number the operator has to add up by hand.
        stats_ledger = DamageLedger()
        gate_ledger = DamageLedger()

        for step in fault_steps:
            fault = step.fault
            target_ids = frozenset().union(*(t.node_ids for t in fault.targets))
            duration = float(fault.duration)
            fault_id = fault.fault_id
            step_stats = check_blast_radius(
                graph,
                target_ids,
                duration,
                tuple(seen_faults),
                fault_id,
                ctx=stats_ctx,
                ledger=stats_ledger,
            )
            for key, value in step_stats.items():
                if float(value) > float(worst.get(key, float("-inf"))):
                    worst[key] = float(value)
            try:
                check_blast_radius(
                    graph,
                    target_ids,
                    duration,
                    tuple(seen_faults),
                    fault_id,
                    ctx=gate_ctx,
                    ledger=gate_ledger,
                )
            except SafetyRefusedError as exc:
                dec = exc.decision
                violations.append(
                    {
                        "rule_id": dec.rule_id if dec is not None else exc.reason_code,
                        "fault_id": fault_id,
                        "reason": dec.reason if dec is not None else str(exc),
                        "remediation": dec.remediation if dec is not None else "",
                    }
                )
            seen_faults.append(fault_id)

        budget = safety.budget
        quota = safety.damage_quota
        blast: dict[str, object] = {
            "status": "exceeded" if violations else "within_budget",
            "fault_count": len(fault_steps),
        }
        for key, cap_name in _BLAST_LIMITS:
            value = worst.get(key, 0.0)
            cap = float(getattr(budget, cap_name))
            blast[key] = value
            blast[cap_name] = cap
            blast[f"{key}_ok"] = value <= cap
        blast["forbidden_fault_pairs"] = [
            sorted(p) for p in sorted(budget.forbidden_fault_pairs, key=sorted)
        ]
        blast["forbidden_fault_pairs_ok"] = not any(
            v["rule_id"] == "blast_radius.forbidden_fault_pairs" for v in violations
        )
        # The cumulative budget, projected over the *whole plan*. Per-step limits
        # are all "is this step small?"; this is the only line on the screen
        # that answers "is this plan survivable?", and it is the one an operator
        # cannot compute for themselves by reading five separate maxima.
        quota_violations = [v for v in violations if v["rule_id"] in _DAMAGE_RULES]
        blast["damage_total_s"] = round(stats_ledger.total_s, 1)
        blast["damage_worst_target"] = stats_ledger.worst_node
        blast["damage_worst_target_s"] = round(stats_ledger.worst_node_s, 1)
        blast["damage_budget_s"] = quota.budget_s
        blast["damage_per_fault_ceiling_s"] = quota.per_fault_ceiling_s
        blast["damage_window_s"] = quota.window_s
        blast["damage_quota_ok"] = not quota_violations
        blast["damage_by_target"] = {
            node: round(value, 1) for node, value in stats_ledger.by_node().items()
        }
        blast["violations"] = violations
        return blast
    except SafetyRefusedError as exc:
        return _unknown_blast(f"gate refused while probing: {exc}")
    except Exception as exc:
        return _unknown_blast(f"{type(exc).__name__}: {exc}")


def build_preflight(
    *,
    spec_path: str | None,
    compose: str | None,
    graph: Any,
    store: Any,
    config_path: str | None,
    profile: str | None,
    allow_critical: bool,
    target: str | None,
    engine: str | None,
    plan: Any,
    safety: SafetyContext | None = None,
    fingerprint: str | None = None,
    config_snapshot_id: str | None = None,
    topology_snapshot_id: str | None = None,
    runtime: RuntimeContext | None = None,
) -> Preflight:
    # One resolved context per plan: the engine name and the runtime must
    # agree, checked *before* any safety validation, plan hashing, or lease
    # work. A legacy caller that passes only ``engine`` (or only ``runtime``)
    # is unaffected; see reconcile_engine.
    effective_engine = reconcile_engine(engine, runtime) or ""
    resolved_target: str | None = (
        target if target is not None else (runtime.target_profile if runtime else None)
    )
    plan_hash = plan_hash_for(plan)
    plan_id = getattr(plan, "run_id", "") or plan_hash[:12]

    cfg_snapshot = config_snapshot_id or ""
    topo_snapshot = topology_snapshot_id or ""
    fp = fingerprint or ""

    if fp == "" and graph is not None:
        try:
            from mayhem.domain.topology import NodeKind

            host_names = [n.name for n in graph.of_kind(NodeKind.HOST)] if graph is not None else []
            fp = environment_fingerprint(
                host_names=host_names,
                compose_digest=_compose_digest(compose),
                profile=profile,
            )
        except Exception:
            fp = "unknown"

    safety_decisions: list[str] = []
    blocked: list[str] = []
    warnings: list[str] = []
    try:
        if plan is not None and graph is not None and effective_engine:
            from mayhem.agents.impact import host_tooling_gaps

            gaps = host_tooling_gaps(plan)
            if gaps:
                warnings.append(
                    f"host tooling gaps: {', '.join(gaps)} — install on drill host before execution"
                )
            try:
                from mayhem.agents.impact import dependency_plan as _dep_plan

                deps = _dep_plan(plan, graph, effective_engine)
                for dp in deps:
                    for fault_id, reason in dp.unfixable:
                        warnings.append(
                            f"blocked fault {fault_id} on {dp.container}: "
                            f"{reason or 'inert for this engine'} — no package or"
                            " flag can unblock it"
                        )
                    if dp.installable or dp.manual or dp.caps_missing:
                        parts = []
                        if dp.packages:
                            parts.append(f"packages {', '.join(dp.packages)} via {dp.pm}")
                        if dp.manual:
                            parts.append(f"manual {', '.join(dp.manual)}")
                        if dp.caps_missing:
                            parts.append(f"caps {', '.join(dp.caps_missing)}")
                        warnings.append(
                            f"dependency gap {dp.container}: {'; '.join(parts)} — run mayhem prepare dependencies"
                        )
            except Exception:
                pass
            unresolved = 0
            for step in getattr(plan, "steps", []) or []:
                fault = getattr(step, "fault", None)
                if fault is None:
                    continue
                for resolved_fault_target in getattr(fault, "targets", []) or []:
                    for nid in getattr(resolved_fault_target, "node_ids", []) or []:
                        if graph.by_id(nid) is None:
                            unresolved += 1
            if unresolved:
                warnings.append(
                    f"target fit: {unresolved} target node ids not in topology — check compose"
                )
            else:
                warnings.append("target fit: all fault targets resolve in topology")
    except Exception:
        pass

    if safety is not None:
        blocked.extend(list(getattr(safety, "warnings", []) or []))
        try:
            if graph is not None and plan is not None:
                validate_plan(plan, graph, safety)
                safety_decisions.append("safety: plan validated")
        except Exception as exc:
            from mayhem.controller.safety import SafetyRefusedError

            if isinstance(exc, SafetyRefusedError):
                blocked.append(str(exc))
                safety_decisions.append(f"refused: {exc}")
            else:
                blocked.append(str(exc))
                safety_decisions.append(f"blocked: {exc}")
        if getattr(safety, "allow_critical_cli", False):
            safety_decisions.append("allow_critical: true")
        if safety_decisions == []:
            safety_decisions.append("allow")

    try:
        target_identity = ""
        if resolved_target is not None and graph is not None:
            target_identity = str(resolved_target)
        else:
            target_identity = effective_engine or "default"
    except Exception:
        target_identity = effective_engine or "default"

    blast = _blast_radius_for(plan, graph, safety)
    compensation_status = "compensated" if plan is not None else "unknown"
    fault_ids: list[str] = []
    durations: list[float] = []
    try:
        for step in getattr(plan, "steps", []) or []:
            fault = getattr(step, "fault", None)
            if fault is not None:
                fault_ids.append(getattr(fault, "fault_id", ""))
                try:
                    durations.append(float(getattr(fault, "duration", 0) or 0))
                except Exception:
                    durations.append(0.0)
    except Exception:
        pass

    expected_evidence = tuple(
        [
            "plan",
            "safety_decisions",
            "step_reports",
            "lease_timeline",
            "observations",
            "verdict",
            "recovery_state",
        ]
    )

    k8s_context = None
    k8s_namespace = None
    k8s_target_scope = None
    k8s_resolved_pod = None
    k8s_resolved_node = None
    k8s_capability_verdict = None
    k8s_compensation = None
    k8s_wait_strategy = None
    k8s_recovery_guidance = None
    k8s_drift_status = None
    if effective_engine == "kubernetes":
        from mayhem.config import effective_target_profiles

        # The *effective* configuration, overlay included: a Kubernetes target
        # profile declared only in `mayhem.{profile}.yaml` is the same profile
        # every other consumer resolves, so preflight never validates against
        # a different set of profiles than the run will use.
        profiles = effective_target_profiles(config_path, profile)
        # `selected` is the target profile; `profile` stays the overlay name.
        selected, ambiguous = _k8s_profile(profiles, target)
        if ambiguous:
            warnings.append(
                "target profile is ambiguous; pass --target NAME or use explicit context/namespace"
            )
        k8s_target_scope = str(target or getattr(selected, "name", "") or "unspecified")
        if runtime is not None:
            # The context and namespace come from the runtime resolved once; the
            # profile lookup above is a validation cross-check, not a second
            # resolution.
            k8s_context = runtime.context or ""
            k8s_namespace = runtime.namespace or ""
        else:
            k8s_context = getattr(selected, "context", None) or ""
            k8s_namespace = getattr(selected, "namespace", None) or ""
        if selected is not None and selected.engine != "kubernetes":
            blocked.append(f"target profile {selected.name!r} is not a Kubernetes profile")
        if not k8s_context:
            k8s_capability_verdict = "unconfigured: no Kubernetes context selected"
        elif not k8s_namespace:
            k8s_capability_verdict = "unconfigured: no Kubernetes namespace selected"
        else:
            k8s_capability_verdict = (
                f"unavailable: live client not probed; profile capability policy="
                f"{getattr(selected, 'capability_policy', None) or 'default'}"
            )
        k8s_resolved_pod = "runtime-resolved at execution"
        k8s_resolved_node = "runtime-resolved at execution"
        compensation, wait_strategy, recovery_guidance = _k8s_guidance(fault_ids)
        k8s_compensation = compensation
        k8s_wait_strategy = wait_strategy
        k8s_recovery_guidance = recovery_guidance
        k8s_drift_status = "not evaluated until live target resolution"

    return Preflight(
        resolved_target=resolved_target,
        config_snapshot_id=cfg_snapshot,
        topology_snapshot_id=topo_snapshot,
        environment_fingerprint=fp,
        plan=plan,
        safety_decisions=tuple(safety_decisions),
        blocked_items=tuple(blocked),
        warnings=tuple(warnings),
        target_profile=resolved_target,
        engine=effective_engine,
        blast_radius=dict(blast),
        compensation_status=compensation_status,
        expected_evidence=expected_evidence,
        plan_hash=plan_hash,
        plan_id=plan_id,
        target_identity=target_identity,
        k8s_context=k8s_context,
        k8s_namespace=k8s_namespace,
        k8s_target_scope=k8s_target_scope,
        k8s_resolved_pod=k8s_resolved_pod,
        k8s_resolved_node=k8s_resolved_node,
        k8s_capability_verdict=k8s_capability_verdict,
        k8s_compensation=k8s_compensation,
        k8s_wait_strategy=k8s_wait_strategy,
        k8s_recovery_guidance=k8s_recovery_guidance,
        k8s_drift_status=k8s_drift_status,
        runtime_context=runtime,
    )


def preflight_from_services(
    *,
    spec_path: str | None,
    compose: str | None,
    store: Any,
    config_path: str | None,
    profile: str | None,
    allow_critical: bool,
    target: str | None,
    engine: str | None,
    graph: Any = None,
    plan: Any = None,
    runtime: RuntimeContext | None = None,
) -> Preflight:
    # Reconcile (and refuse a disagreement) before the graph, config, or plan
    # work below runs.
    reconciled = reconcile_engine(engine, runtime)
    # The legacy planners take a plain engine name; an unspecified one keeps
    # the historical podman default they have always applied.
    plan_engine = reconciled or "podman"
    if runtime is not None and target is None:
        target = runtime.target_profile
    if graph is None:
        from mayhem.cli.services import build_graph as _build_graph

        try:
            graph = _build_graph(compose)
        except Exception:
            graph = None

    cfg_snapshot = ""
    topo_snapshot = ""
    fp = ""
    safety_ctx: SafetyContext | None = None

    if store is not None and graph is not None:
        try:
            from mayhem.cli.services import prepare as _prepare

            prepared = _prepare(
                config_path=config_path,
                profile=profile,
                allow_critical=allow_critical,
                store=store,
                graph=graph,
                compose=compose,
                spec_path=spec_path,
            )
            cfg_snapshot = prepared.config_snapshot_id
            topo_snapshot = prepared.topology_snapshot_id
            fp = prepared.fingerprint
            safety_ctx = prepared.safety
        except Exception:
            pass

    if plan is None and spec_path is not None and graph is not None and safety_ctx is not None:
        try:
            from mayhem.cli.services import plan_from_spec as _plan

            # Legacy: this path passes a SafetyContext where the planner
            # expects a Prepared; the call is guarded by try/except.
            compiled = _plan(
                spec_path,
                graph,
                prepared=safety_ctx,  # type: ignore[arg-type]
                engine=plan_engine,
            )
            plan = compiled.plan
            cfg_snapshot = cfg_snapshot or getattr(compiled, "run_id", "")
        except Exception:
            try:
                from mayhem.cli.services import plan_from_spec as _plan2
                from mayhem.cli.services import prepare as _prepare2

                if graph is not None and store is not None:
                    prepared2 = _prepare2(
                        config_path=config_path,
                        profile=profile,
                        allow_critical=allow_critical,
                        store=store,
                        graph=graph,
                        compose=compose,
                        spec_path=spec_path,
                    )
                    compiled2 = _plan2(spec_path, graph, prepared=prepared2, engine=plan_engine)
                    plan = compiled2.plan
                    cfg_snapshot = prepared2.config_snapshot_id
                    topo_snapshot = prepared2.topology_snapshot_id
                    fp = prepared2.fingerprint
                    safety_ctx = prepared2.safety
            except Exception:
                pass

    return build_preflight(
        spec_path=spec_path,
        compose=compose,
        graph=graph,
        store=store,
        config_path=config_path,
        profile=profile,
        allow_critical=allow_critical,
        target=target,
        engine=engine,
        plan=plan,
        safety=safety_ctx,
        fingerprint=fp,
        config_snapshot_id=cfg_snapshot,
        topology_snapshot_id=topo_snapshot,
        runtime=runtime,
    )
