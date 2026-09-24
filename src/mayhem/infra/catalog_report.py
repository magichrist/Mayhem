from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import date
from typing import TYPE_CHECKING

from mayhem.agents.executors import executor_for
from mayhem.controller.compensation import template_for
from mayhem.controller.k8s_runtime import k8s_available_faults, k8s_contract_for
from mayhem.domain.catalog import all_definitions, definition_for
from mayhem.domain.faults import EngineLane, FaultDefinition, MaturityLevel

if TYPE_CHECKING:
    from mayhem.domain.target_profiles import TargetProfile

MATURITY_PROMOTION_CRITERIA: dict[MaturityLevel, tuple[str, ...]] = {
    MaturityLevel.EXPERIMENTAL: (
        "catalog metadata is complete",
        "planner validates parameters and target applicability",
        "the execution path refuses unsupported use deterministically",
    ),
    MaturityLevel.VERIFIED_UNIT: (
        "all experimental criteria pass",
        "deterministic unit tests cover the parameters, refusal, and compensation contract",
        "a verification date is recorded in the catalog",
    ),
    MaturityLevel.VERIFIED_LIVE: (
        "all verified-unit criteria pass",
        "a supported live runtime completed injection and recovery",
        "the observation and recovery evidence is recorded",
    ),
    MaturityLevel.STABLE: (
        "all verified-live criteria pass",
        "the supported engine and platform matrix is verified",
        "the deprecation and rollback policy is documented",
    ),
}

_GOAL_FAULTS: dict[str, tuple[str, ...]] = {
    "availability": (
        "proc.pause",
        "net.latency",
        "dependency.timeout",
        "fs.io_stress",
        "process.stop",
    ),
    "latency": (
        "http.latency",
        "net.latency",
        "dependency.timeout",
        "k8s.pod_latency",
    ),
    "network-resilience": (
        "net.packet_loss",
        "net.partition",
        "net.duplicate",
        "net.reorder",
        "net.bandwidth",
        "net.connection_reset",
        "k8s.network_policy",
    ),
    "storage-resilience": (
        "fs.fill",
        "fs.inode_exhaust",
        "fs.io_stress",
        "fs.read_only",
        "k8s.persistent_volume_delay",
    ),
    "process-lifecycle": (
        "proc.pause",
        "process.stop",
        "process.crash_loop",
        "process.kill",
        "k8s.pod_crash_loop",
    ),
    "dependency-resilience": (
        "dns.timeout",
        "dependency.timeout",
        "dependency.connection_refuse",
        "dependency.rate_limit",
        "k8s.dns_failure",
    ),
    "recovery": (
        "proc.pause",
        "net.partition",
        "k8s.network_policy",
        "process.crash_loop",
    ),
}


@dataclass(frozen=True)
class Recommendation:
    fault_id: str
    engine: str
    status: str
    goal: str
    reason: str


def _engine_lane(engine: str) -> EngineLane | None:
    try:
        return EngineLane(engine)
    except ValueError:
        return None


def execution_status(definition: FaultDefinition, engine: str) -> str:
    lane = _engine_lane(engine)
    if definition.catalog_only:
        status = "catalog-only"
    elif lane is None or lane not in definition.engine_lanes:
        status = "unavailable"
    elif engine == "kubernetes":
        status = "supported" if definition.id in k8s_available_faults() else "catalog-only"
    elif (
        executor_for(definition.id) is None
        or template_for(definition.id) is None
        or definition.id.startswith("k8s.")
    ):
        status = "catalog-only"
    else:
        status = "supported"
    return status


def _executor_name(definition: FaultDefinition, engine: str) -> str:
    if definition.catalog_only:
        return "catalog.unsupported"
    executor = executor_for(definition.id)
    return executor.__class__.__name__ if executor is not None else "catalog.unsupported"


def _undo_description(definition: FaultDefinition, engine: str) -> str:
    if definition.catalog_only:
        return definition.refusal_reason or "catalog-only: no compensation"
    if engine == "kubernetes":
        try:
            return k8s_contract_for(definition.id).compensation
        except LookupError:
            return definition.refusal_reason or "no compensation"
    if template_for(definition.id) is not None:
        return {
            "reversible": "write-ahead undo and verification probe",
            "reconciled": "reconciliation evidence after the effect",
            "irreversible": "explicit compensation required",
        }[definition.reversibility.value]
    return definition.refusal_reason or "no compensation registered"


def _evidence(definition: FaultDefinition, engine: str) -> tuple[str, ...]:
    if engine == "kubernetes":
        try:
            return k8s_contract_for(definition.id).evidence
        except LookupError:
            return ("catalog entry", "explicit refusal")
    if definition.reversibility.value == "reversible":
        return ("undo operation", "verification probe")
    return ("executor result", "recovery result")


def explain_catalog_fault(fault_id: str, *, engine: str = "docker") -> dict[str, object]:
    definition = definition_for(fault_id)
    status = execution_status(definition, engine)
    return {
        "id": definition.id,
        "status": status,
        "category": definition.category.value,
        "failure_domain": definition.failure_domain.value if definition.failure_domain else None,
        "target_kind": definition.target_kind.value if definition.target_kind else None,
        "target_kinds": sorted(kind.value for kind in definition.target_kinds),
        "engine_lanes": sorted(lane.value for lane in definition.engine_lanes),
        "risk": definition.risk.value,
        "reversibility": definition.reversibility.value if definition.reversibility else None,
        "maturity": definition.maturity.value,
        "promotion_criteria": list(MATURITY_PROMOTION_CRITERIA[definition.maturity]),
        "verification_date": definition.verification_date.isoformat()
        if definition.verification_date
        else None,
        "parameters": [spec.model_dump(mode="json") for spec in definition.params_schema],
        "capability": sorted(cap.value for cap in definition.required_caps),
        "observable_effect": definition.observable_effect,
        "compensation_evidence": list(definition.compensation_evidence),
        "verification_method": definition.verification_method.value
        if definition.verification_method
        else None,
        "executor": _executor_name(definition, engine),
        "undo": _undo_description(definition, engine),
        "evidence": list(_evidence(definition, engine)),
        "refusal": definition.refusal_reason,
        "deprecation_path": definition.deprecation_path,
    }


def build_coverage(*, engine: str | None = None) -> dict[str, object]:
    definitions = all_definitions()
    selected = [
        definition
        for definition in definitions
        if engine is None or execution_status(definition, engine) != "unavailable"
    ]
    by_engine = Counter(
        lane.value
        for definition in selected
        for lane in definition.engine_lanes
        if engine is None or lane.value == engine
    )
    by_domain = Counter(
        definition.failure_domain.value
        for definition in selected
        if definition.failure_domain is not None
    )
    by_risk = Counter(definition.risk.value for definition in selected)
    by_reversibility = Counter(
        definition.reversibility.value
        for definition in selected
        if definition.reversibility is not None
    )
    by_maturity = Counter(definition.maturity.value for definition in selected)
    return {
        "total": len(selected),
        "by_engine": dict(sorted(by_engine.items())),
        "by_domain": dict(sorted(by_domain.items())),
        "by_risk": dict(sorted(by_risk.items())),
        "by_reversibility": dict(sorted(by_reversibility.items())),
        "by_maturity": dict(sorted(by_maturity.items())),
        "catalog_only": sum(definition.catalog_only for definition in selected),
        "generated_at": date(2026, 9, 24).isoformat(),
    }


def recommend_faults(profile: TargetProfile, *, goal: str) -> tuple[Recommendation, ...]:
    if goal not in _GOAL_FAULTS:
        choices = ", ".join(sorted(_GOAL_FAULTS))
        raise ValueError(f"unknown recommendation goal {goal!r}; choose from {choices}")
    recommendations: list[Recommendation] = []
    for fault_id in _GOAL_FAULTS[goal]:
        try:
            definition = definition_for(fault_id)
        except LookupError:
            continue
        status = execution_status(definition, profile.engine)
        if status != "supported":
            continue
        recommendations.append(
            Recommendation(
                fault_id=fault_id,
                engine=profile.engine,
                status=status,
                goal=goal,
                reason=definition.observable_effect,
            )
        )
    return tuple(recommendations)


def deprecation_status(fault_id: str) -> dict[str, str]:
    definition = definition_for(fault_id)
    if definition.id == "k8s.image_pull_slow":
        return {
            "state": "catalog-only",
            "replacement": "k8s.image_pull_failure",
            "migration": (
                "use the deterministic pull-failure family when image latency shaping is not "
                "required"
            ),
            "path": definition.deprecation_path or "document before removal",
        }
    if definition.catalog_only:
        return {
            "state": "catalog-only",
            "replacement": "an explicitly supported alternative",
            "migration": "migrate to a supported family or retain the explicit refusal",
            "path": definition.deprecation_path or "document before removal",
        }
    return {"state": "active", "replacement": "", "migration": "", "path": ""}
