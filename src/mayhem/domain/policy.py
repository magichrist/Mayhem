from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mayhem.domain.experiments import BlastRadiusBudget
from mayhem.domain.risks import RiskLevel


class PolicyProfile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
    risk_ceiling: RiskLevel | None = None
    allowed_faults: frozenset[str] | None = None
    denied_faults: frozenset[str] = Field(default_factory=frozenset)
    blast_radius: BlastRadiusBudget = Field(default_factory=BlastRadiusBudget)
    critical_fault_acks: frozenset[str] = Field(default_factory=frozenset)
    allow_critical: bool = False
    allowed_environments: frozenset[str] | None = None
    denied_environments: frozenset[str] = Field(default_factory=frozenset)
    allowed_targets: frozenset[str] | None = None
    description: str = ""


def profile_to_policy_cfg(profile: PolicyProfile) -> dict[str, Any]:
    return {
        "risk_ceiling": profile.risk_ceiling,
        "allow_faults": profile.allowed_faults,
        "deny_faults": profile.denied_faults,
        "allow_critical": profile.allow_critical,
        "critical_fault_acks": profile.critical_fault_acks,
    }


def profile_to_blast_budget(profile: PolicyProfile) -> BlastRadiusBudget:
    return profile.blast_radius


BUILTIN_PROFILES: dict[str, PolicyProfile] = {
    "default": PolicyProfile(name="default", description="permissive default"),
    "strict": PolicyProfile(
        name="strict",
        risk_ceiling=RiskLevel.MEDIUM,
        blast_radius=BlastRadiusBudget(
            max_services_pct=25.0,
            max_hosts=1,
            max_concurrent_faults=1,
            max_duration_per_fault_s=60.0,
        ),
        description="strict production guardrail",
    ),
    "permissive": PolicyProfile(
        name="permissive",
        risk_ceiling=None,
        blast_radius=BlastRadiusBudget(
            max_services_pct=100.0,
            max_hosts=10,
            max_concurrent_faults=10,
            max_duration_per_fault_s=600.0,
        ),
        description="permissive lab profile",
    ),
    "staging": PolicyProfile(
        name="staging",
        risk_ceiling=RiskLevel.HIGH,
        blast_radius=BlastRadiusBudget(max_services_pct=50.0, max_hosts=2, max_concurrent_faults=3),
        allowed_environments=frozenset({"staging", "dev"}),
        description="staging environment profile",
    ),
    "production": PolicyProfile(
        name="production",
        risk_ceiling=RiskLevel.MEDIUM,
        blast_radius=BlastRadiusBudget(max_services_pct=25.0, max_hosts=1, max_concurrent_faults=1),
        denied_environments=frozenset({"dev"}),
        allowed_environments=frozenset({"production"}),
        description="production environment profile",
    ),
}


def get_profile(name: str) -> PolicyProfile | None:
    return BUILTIN_PROFILES.get(name)


def list_profiles() -> list[PolicyProfile]:
    return list(BUILTIN_PROFILES.values())


def is_environment_allowed(profile: PolicyProfile, env: str | None) -> bool:
    if env is None:
        return True
    if profile.denied_environments and env in profile.denied_environments:
        return False
    return not (
        profile.allowed_environments is not None and env not in profile.allowed_environments
    )


_SECRET_KEYS = frozenset(
    {
        "password",
        "secret",
        "token",
        "credentials",
        "api_key",
        "apikey",
        "kubeconfig",
        "registry_token",
        "registry_tokens",
        "secret_value",
        "secrets",
    }
)


def contains_secret_key(data: dict[str, Any]) -> str | None:
    for key, value in data.items():
        if key.lower() in _SECRET_KEYS:
            return key
        if isinstance(value, dict):
            found = contains_secret_key(value)
            if found is not None:
                return found
    return None


def sanitize_for_logging(data: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in data.items():
        if key.lower() in _SECRET_KEYS:
            sanitized[key] = "***REDACTED***"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_for_logging(value)
        elif isinstance(value, list):
            sanitized[key] = [sanitize_for_logging(v) if isinstance(v, dict) else v for v in value]
        else:
            sanitized[key] = value
    return sanitized
