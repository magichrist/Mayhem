from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from mayhem.controller.safety import SafetyContext, environment_fingerprint, validate_plan
from mayhem.domain.preflight import Preflight, plan_hash_for


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


def _blast_radius_for(plan: Any, graph: Any, safety: SafetyContext) -> dict[str, object]:
    try:
        from mayhem.domain.topology import NodeKind

        total_services = len(graph.of_kind(NodeKind.SERVICE)) if graph is not None else 0
        fault_steps = [
            s for s in getattr(plan, "steps", []) if getattr(s, "fault", None) is not None
        ]
        affected: set[str] = set()
        for step in fault_steps:
            for target in getattr(step.fault, "targets", []):
                affected.update(getattr(target, "node_ids", []))
        pct = round(len(affected) / max(total_services, 1) * 100, 1) if total_services else 0.0
        return {
            "services_pct": pct,
            "affected_node_count": len(affected),
            "fault_count": len(fault_steps),
            "max_services_pct": safety.budget.max_services_pct if hasattr(safety, "budget") else 0,
            "max_hosts": safety.budget.max_hosts if hasattr(safety, "budget") else 0,
        }
    except Exception:
        return {}


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
    engine: str,
    plan: Any,
    safety: SafetyContext | None = None,
    fingerprint: str | None = None,
    config_snapshot_id: str | None = None,
    topology_snapshot_id: str | None = None,
) -> Preflight:
    resolved_target: str | None = target
    effective_engine = engine or ""
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

    blast = (
        _blast_radius_for(plan, graph, safety) if safety is not None and plan is not None else {}
    )
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
        from mayhem.domain.target_profiles import load_profiles_from_mayhem_yaml

        profiles = load_profiles_from_mayhem_yaml(config_path)
        profile, ambiguous = _k8s_profile(profiles, target)
        if ambiguous:
            warnings.append(
                "target profile is ambiguous; pass --target NAME or use explicit context/namespace"
            )
        k8s_target_scope = str(target or getattr(profile, "name", "") or "unspecified")
        k8s_context = getattr(profile, "context", None) or ""
        k8s_namespace = getattr(profile, "namespace", None) or ""
        if profile is not None and profile.engine != "kubernetes":
            blocked.append(f"target profile {profile.name!r} is not a Kubernetes profile")
        if not k8s_context:
            k8s_capability_verdict = "unconfigured: no Kubernetes context selected"
        elif not k8s_namespace:
            k8s_capability_verdict = "unconfigured: no Kubernetes namespace selected"
        else:
            k8s_capability_verdict = (
                f"unavailable: live client not probed; profile capability policy="
                f"{getattr(profile, 'capability_policy', None) or 'default'}"
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
    engine: str,
    graph: Any = None,
    plan: Any = None,
) -> Preflight:
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

            compiled = _plan(spec_path, graph, prepared=safety_ctx, engine=engine)  # type: ignore[arg-type]
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
                    compiled2 = _plan2(spec_path, graph, prepared=prepared2, engine=engine)
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
    )
