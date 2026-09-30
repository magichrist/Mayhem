"""Catalog capability reporting — what Mayhem can actually execute, and how
that claim was earned.

This is a *composition* view: it reads the fault catalog (domain), the executor
registry (agents), the compensation registry and the k8s runtime contract
(controller), and the evidence store (infra), then reports one verdict per
fault. It therefore sits at the controller layer rather than in ``infra``:
under the layered-architecture contract infra sits below agents and controller
and must not reach upward into either.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import date
from importlib.util import find_spec
from shutil import which
from typing import TYPE_CHECKING

from mayhem.agents.executors import executor_for
from mayhem.controller.compensation import template_for
from mayhem.controller.k8s_runtime import k8s_available_faults, k8s_contract_for
from mayhem.domain.capability_status import CapabilityDashboard, CapabilityStatus
from mayhem.domain.catalog import all_definitions, definition_for
from mayhem.domain.faults import EngineLane, FaultDefinition
from mayhem.infra.promotion import (
    MATURITY_MEANING,
    MATURITY_PROMOTION_CRITERIA,
    CatalogProbe,
    EvidenceStore,
    PromotionDecision,
    build_probe,
    evaluate_maturity,
)

if TYPE_CHECKING:
    from mayhem.domain.target_profiles import TargetProfile

__all__ = [
    "MATURITY_MEANING",
    "MATURITY_PROMOTION_CRITERIA",
    "Recommendation",
    "build_capability_dashboard",
    "build_capability_report",
    "build_capability_statuses",
    "build_coverage",
    "build_probe",
    "capability_status",
    "deprecation_status",
    "execution_status",
    "explain_catalog_fault",
    "maturity_decision",
    "promotion_refusals",
    "recommend_faults",
]

#: Stated in every report that presents maturity, so a reader cannot mistake a
#: unit-verified catalogue for one that has been run against real systems.
Maturity_DISCLAIMER = (
    "verified-unit is a claim about mayhem's own parameter, refusal, and compensation code — "
    "not about the fault working. verified-live and stable are earned only from recorded "
    "live-run evidence and are zero until such a run is executed and recorded."
)

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


def _engine_available(engine: str) -> bool:
    if engine == "kubernetes":
        return find_spec("kubernetes") is not None
    return which(engine) is not None


# ── unit-verification provenance ────────────────────────────────────────────
#
# "the parameters, refusal, and compensation contract are covered by
# deterministic tests" is a claim about a test suite, and no amount of
# inspecting the catalog can settle it. It is therefore an explicit, named
# input to the promotion engine rather than a hidden constant, and the test
# that reads this list asserts the modules still exist — so renaming the
# coverage suite breaks a test instead of silently emptying the claim.
CATALOG_UNIT_COVERAGE: tuple[str, ...] = (
    "tests/unit/test_fault_catalog_exhaustive.py",
    "tests/unit/test_catalog_only_refusals.py",
    "tests/unit/test_compensation.py",
)


def catalog_unit_evidence() -> tuple[str, ...]:
    """The recorded unit coverage every catalog entry is unit-verified against."""
    return CATALOG_UNIT_COVERAGE


def _executor_present(fault_id: str) -> bool:
    return executor_for(fault_id) is not None


def _compensation_present(fault_id: str) -> bool:
    if template_for(fault_id) is not None:
        return True
    try:
        return k8s_contract_for(fault_id) is not None
    except LookupError:
        return False


def build_catalog_probe(
    definition: FaultDefinition,
    *,
    unit_evidence: tuple[str, ...] | None = None,
) -> CatalogProbe:
    """Recompute the facts ``verified-unit`` is supposed to rest on."""
    return build_probe(
        definition,
        executor_registered=_executor_present,
        compensation_registered=_compensation_present,
        unit_evidence=(catalog_unit_evidence() if unit_evidence is None else tuple(unit_evidence)),
    )


def maturity_decision(
    definition: FaultDefinition,
    *,
    evidence: EvidenceStore | None = None,
    probe: CatalogProbe | None = None,
) -> PromotionDecision:
    """The fault's *earned* maturity, evaluated from the evidence store.

    ``definition.maturity`` is the catalog's declaration. This is the
    recomputation, and the two are allowed to disagree: the declaration is
    reported alongside the derived value so a stale badge is visible rather
    than laundered.
    """
    return evaluate_maturity(
        definition,
        probe=probe if probe is not None else build_catalog_probe(definition),
        store=evidence,
    )


def promotion_refusals(
    definition: FaultDefinition,
    *,
    evidence: EvidenceStore | None = None,
) -> tuple[str, ...]:
    """Every unmet criterion for ``definition``, each naming what was observed."""
    return maturity_decision(definition, evidence=evidence).refusals


def _unmet_unit_criteria(decision: PromotionDecision) -> tuple[str, ...]:
    """Criterion names blocking ``verified-unit``, phrased for a blocked_reason.

    ``blocked_reason`` is a single string the dashboard already renders, and it
    is also asserted on by tests that expect the *capability* reason. Maturity
    is a separate axis, so a maturity shortfall is reported separately and only
    when nothing else already blocks the row.
    """
    if decision.at_least_unit_verified:
        return ()
    return tuple(outcome.name for outcome in decision.outcomes)


def capability_status(
    definition: FaultDefinition,
    engine: str,
    *,
    evidence: EvidenceStore | None = None,
) -> CapabilityStatus:
    lane = _engine_lane(engine)
    target_supported = lane is not None and lane in definition.engine_lanes
    if engine == "kubernetes":
        registered = definition.id in k8s_available_faults()
        try:
            compensation_complete = k8s_contract_for(definition.id) is not None
        except LookupError:
            compensation_complete = False
    else:
        registered = executor_for(definition.id) is not None
        compensation_complete = template_for(definition.id) is not None
    decision = maturity_decision(definition, evidence=evidence)
    if definition.catalog_only:
        blocked_reason = definition.refusal_reason or "catalog-only definition"
    elif lane is None:
        blocked_reason = "engine lane is not supported"
    elif not target_supported:
        blocked_reason = f"fault does not declare the {engine} engine lane"
    elif not registered:
        blocked_reason = "executor or runtime contract is not registered"
    elif not compensation_complete:
        blocked_reason = "compensation contract is not registered"
    elif not decision.at_least_unit_verified:
        unmet = ", ".join(_unmet_unit_criteria(decision)) or "verified-unit criteria"
        blocked_reason = f"not unit-verified: {unmet}"
    else:
        blocked_reason = ""
    return CapabilityStatus(
        fault_id=definition.id,
        engine=engine,
        registered=registered,
        available=_engine_available(engine),
        target_supported=target_supported,
        unit_verified=decision.at_least_unit_verified,
        live_verified=decision.live_verified,
        compensation_complete=compensation_complete,
        blocked_reason=blocked_reason,
        family=definition.id.split(".", 1)[0],
        maturity=decision.maturity.value,
        source_of_truth=_source_of_truth(definition, engine),
        remediation=_remediation(definition, engine, blocked_reason),
    )


def _source_of_truth(definition: FaultDefinition, engine: str) -> str:
    """Which artifact decides this row — never a guess."""
    if definition.catalog_only:
        return "fault catalog (catalog-only definition)"
    if engine == "kubernetes":
        return "kubernetes runtime contract + fault catalog"
    return "executor registry + undo template registry"


# Blocker text emitted by the engine-lane check -> the fix that clears it. Order
# is significant: the first marker found in the blocked reason wins.
_BLOCKED_REASON_REMEDIATIONS: tuple[tuple[str, str], ...] = (
    (
        "engine lane",
        "declare the {engine} engine lane on this fault, or run it on a supported engine",
    ),
    ("compensation", "register an undo template so compensation is complete"),
)

_FALLBACK_REMEDIATION = "register an executor for this fault"


def _remediation(definition: FaultDefinition, engine: str, blocked_reason: str) -> str:
    """Actionable next step for a blocked row; empty when nothing blocks it."""
    if not blocked_reason:
        return ""
    if definition.replacement_fault_id:
        return f"use {definition.replacement_fault_id} instead"
    if definition.catalog_only:
        return "catalog-only: no executor is planned; treat as documentation"
    if engine == "kubernetes":
        return "register a kubernetes contract (k8s_contract_for) for this fault"
    return _remediation_for_blocker(engine, blocked_reason)


def _remediation_for_blocker(engine: str, blocked_reason: str) -> str:
    """Map the blocking reason text onto the fix that clears it."""
    for marker, template in _BLOCKED_REASON_REMEDIATIONS:
        if marker in blocked_reason:
            return template.format(engine=engine)
    return _FALLBACK_REMEDIATION


def build_capability_statuses(
    *,
    engine: str | None = None,
    evidence: EvidenceStore | None = None,
) -> list[CapabilityStatus]:
    engines = (engine,) if engine else ("docker", "podman", "kubernetes")
    return [
        capability_status(definition, engine_name, evidence=evidence)
        for engine_name in engines
        for definition in all_definitions()
    ]


def build_capability_dashboard(
    *,
    engine: str | None = None,
    family: str | None = None,
    maturity: str | None = None,
    blocked: bool | None = None,
    evidence: EvidenceStore | None = None,
) -> CapabilityDashboard:
    """Read-only capability dashboard with the documented filters applied."""
    dashboard = CapabilityDashboard(
        engine=engine.lower() if engine else None,
        rows=tuple(build_capability_statuses(engine=engine, evidence=evidence)),
        # Local calendar date, deliberately not UTC: this is a human-readable
        # "report generated on" stamp, and a UTC date would read as the wrong
        # day for operators outside UTC. No tz-aware local-date API exists.
        generated_at=date.today().isoformat(),  # noqa: DTZ011
    )
    return dashboard.filtered(engine=engine, family=family, maturity=maturity, blocked=blocked)


def build_capability_report(
    *,
    engine: str | None = None,
    evidence: EvidenceStore | None = None,
) -> dict[str, object]:
    return build_capability_dashboard(engine=engine, evidence=evidence).to_dict()


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
    reversibility = definition.reversibility
    if template_for(definition.id) is not None and reversibility is not None:
        return {
            "reversible": "write-ahead undo and verification probe",
            "reconciled": "reconciliation evidence after the effect",
            "irreversible": "explicit compensation required",
        }[reversibility.value]
    return definition.refusal_reason or "no compensation registered"


def _evidence(definition: FaultDefinition, engine: str) -> tuple[str, ...]:
    if engine == "kubernetes":
        try:
            return k8s_contract_for(definition.id).evidence
        except LookupError:
            return ("catalog entry", "explicit refusal")
    if definition.reversibility is not None and definition.reversibility.value == "reversible":
        return ("undo operation", "verification probe")
    return ("executor result", "recovery result")


def explain_catalog_fault(
    fault_id: str,
    *,
    engine: str = "docker",
    evidence: EvidenceStore | None = None,
) -> dict[str, object]:
    definition = definition_for(fault_id)
    status = execution_status(definition, engine)
    decision = maturity_decision(definition, evidence=evidence)
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
        # ``maturity`` is the *earned* level, recomputed from evidence at read
        # time. The catalog's own claim is reported beside it as
        # ``declared_maturity`` so a stale badge is visible instead of laundered
        # into the headline.
        "maturity": decision.maturity.value,
        "declared_maturity": definition.maturity.value,
        "maturity_meaning": decision.meaning,
        "maturity_evidence": decision.to_dict(),
        "unmet_criteria": list(decision.refusals),
        "promotion_criteria": list(MATURITY_PROMOTION_CRITERIA[decision.maturity]),
        "maturity_disclaimer": Maturity_DISCLAIMER,
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


def build_coverage(
    *,
    engine: str | None = None,
    evidence: EvidenceStore | None = None,
) -> dict[str, object]:
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
    # The maturity tally is derived per fault, not read off the catalog, so a
    # fault whose declared badge its facts no longer earn is counted at the rung
    # it actually holds.
    decisions = [maturity_decision(definition, evidence=evidence) for definition in selected]
    by_maturity = Counter(decision.maturity.value for decision in decisions)
    live_verified = sorted(decision.fault_id for decision in decisions if decision.live_verified)
    return {
        "total": len(selected),
        "by_engine": dict(sorted(by_engine.items())),
        "by_domain": dict(sorted(by_domain.items())),
        "by_risk": dict(sorted(by_risk.items())),
        "by_reversibility": dict(sorted(by_reversibility.items())),
        "by_maturity": dict(sorted(by_maturity.items())),
        "verified_live": len(live_verified),
        "verified_live_faults": live_verified,
        "live_evidence_records": len(evidence) if evidence is not None else 0,
        "maturity_disclaimer": Maturity_DISCLAIMER,
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
