from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EvidenceEnvelope(BaseModel):
    model_config = ConfigDict(frozen=True)

    run_id: str
    plan_hash: str
    report_id: str = ""
    plan_id: str = ""
    target_profile: str | None = None
    engine: str = ""
    safety_decisions: tuple[str, ...] = ()
    step_reports: tuple[dict[str, Any], ...] = ()
    lease_timeline: tuple[dict[str, Any], ...] = ()
    observations: tuple[dict[str, Any], ...] = ()
    verdict: str = ""
    recovery_state: str = ""
    remediation: tuple[str, ...] = ()
    environment_fingerprint: str = ""
    target_identity: str = ""
    blast_radius: dict[str, Any] = Field(default_factory=dict)
    compensation_status: str = ""
    logical_target: str = ""
    resolved_target: str = ""
    drift_status: str = ""
    k8s_context: str = ""
    k8s_namespace: str = ""
    k8s_capability_verdict: str = ""
    k8s_wait_strategy: str = ""
    k8s_recovery_guidance: str = ""
    created_at: str = ""
    engine_version: str | None = None
    topology_fingerprint: str | None = None
    verification_basis: str = "unit_tested"

    def completeness_errors(self) -> list[str]:
        missing: list[str] = []
        if not self.run_id:
            missing.append("run_id missing")
        if not self.plan_hash:
            missing.append("plan_hash missing")
        if not self.verdict:
            missing.append("verdict missing")
        if len(self.step_reports) == 0:
            missing.append("step_reports empty")
        return missing

    def is_complete(self) -> bool:
        return len(self.completeness_errors()) == 0

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
