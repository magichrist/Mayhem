from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from pydantic import BaseModel, ConfigDict

from mayhem.toolkit.hashing import canonical_json


class PreflightPlanHash(BaseModel):
    model_config = ConfigDict(frozen=True)
    value: str


@dataclass(frozen=True, slots=True)
class ExecutionIntent:
    action: str
    target_profile: str | None
    plan_id: str
    plan_hash: str
    policy_decision: str
    approval_source: str
    fingerprint: str = ""
    engine: str = ""
    target_identity: str = ""


@dataclass(frozen=True, slots=True)
class Preflight:
    resolved_target: str | None
    config_snapshot_id: str
    topology_snapshot_id: str
    environment_fingerprint: str
    plan: object
    safety_decisions: tuple[str, ...] = ()
    blocked_items: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    target_profile: str | None = None
    engine: str = ""
    blast_radius: dict[str, object] = field(default_factory=dict)
    compensation_status: str = ""
    expected_evidence: tuple[str, ...] = ()
    plan_hash: str = ""
    plan_id: str = ""
    target_identity: str = ""
    k8s_context: str | None = None
    k8s_namespace: str | None = None
    k8s_target_scope: str | None = None
    k8s_resolved_pod: str | None = None
    k8s_resolved_node: str | None = None
    k8s_capability_verdict: str | None = None
    k8s_compensation: str | None = None
    k8s_wait_strategy: str | None = None
    k8s_recovery_guidance: str | None = None
    k8s_drift_status: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "resolved_target": self.resolved_target,
            "config_snapshot_id": self.config_snapshot_id,
            "topology_snapshot_id": self.topology_snapshot_id,
            "environment_fingerprint": self.environment_fingerprint,
            "plan": self.plan.model_dump(mode="json")
            if hasattr(self.plan, "model_dump")
            else self.plan,
            "safety_decisions": list(self.safety_decisions),
            "blocked_items": list(self.blocked_items),
            "warnings": list(self.warnings),
            "target_profile": self.target_profile,
            "engine": self.engine,
            "blast_radius": dict(self.blast_radius),
            "compensation_status": self.compensation_status,
            "expected_evidence": list(self.expected_evidence),
            "plan_hash": self.plan_hash,
            "plan_id": self.plan_id,
            "target_identity": self.target_identity,
            "k8s_context": self.k8s_context,
            "k8s_namespace": self.k8s_namespace,
            "k8s_target_scope": self.k8s_target_scope,
            "k8s_resolved_pod": self.k8s_resolved_pod,
            "k8s_resolved_node": self.k8s_resolved_node,
            "k8s_capability_verdict": self.k8s_capability_verdict,
            "k8s_compensation": self.k8s_compensation,
            "k8s_wait_strategy": self.k8s_wait_strategy,
            "k8s_recovery_guidance": self.k8s_recovery_guidance,
            "k8s_drift_status": self.k8s_drift_status,
        }


def plan_hash_for(plan: object) -> str:
    try:
        from mayhem.domain.experiments import ExecutionPlan

        if isinstance(plan, ExecutionPlan):
            payload = plan.model_dump(mode="json")
            return hashlib.sha256(canonical_json(payload).encode()).hexdigest()
    except Exception:
        pass
    try:
        raw = json.dumps(plan, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(raw.encode()).hexdigest()
    except Exception:
        return hashlib.sha256(str(plan).encode()).hexdigest()


def execution_intent_for(
    preflight: Preflight, action: str, approval_source: str
) -> ExecutionIntent:
    return ExecutionIntent(
        action=action,
        target_profile=preflight.target_profile,
        plan_id=preflight.plan_id,
        plan_hash=preflight.plan_hash,
        policy_decision=";".join(preflight.safety_decisions)
        if preflight.safety_decisions
        else "allow",
        approval_source=approval_source,
        fingerprint=preflight.environment_fingerprint,
        engine=preflight.engine,
        target_identity=preflight.target_identity,
    )
