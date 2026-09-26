from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ReplayCapsule(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = "1.0"
    run_id: str
    spec: dict[str, Any] = Field(default_factory=dict)
    plan: dict[str, Any] = Field(default_factory=dict)
    policy: dict[str, Any] = Field(default_factory=dict)
    target: dict[str, Any] = Field(default_factory=dict)
    runtime: dict[str, Any] = Field(default_factory=dict)
    versions: dict[str, str] = Field(default_factory=dict)
    seed: int | None = None
    fingerprints: dict[str, str] = Field(default_factory=dict)
    digests: dict[str, str] = Field(default_factory=dict)

    def canonical_json(self) -> str:
        return json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        payload = self.model_dump(mode="json")
        digests = dict(payload.get("digests") or {})
        digests.pop("capsule", None)
        payload["digests"] = digests
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def with_digests(self) -> ReplayCapsule:
        return self.model_copy(update={"digests": {**self.digests, "capsule": self.digest()}})


@dataclass(frozen=True, slots=True)
class ReplayValidation:
    valid: bool
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    plan_hash: str = ""


def validate_replay_capsule(
    capsule: ReplayCapsule,
    *,
    mode: Literal["validate", "dry_run"] = "validate",
    current_fingerprint: str | None = None,
) -> ReplayValidation:
    errors: list[str] = []
    warnings: list[str] = []
    if capsule.schema_version != "1.0":
        errors.append(f"unsupported capsule schema: {capsule.schema_version}")
    if not capsule.run_id:
        errors.append("run_id is required")
    if not capsule.plan:
        errors.append("plan is required")
    recorded = capsule.digests.get("capsule")
    if recorded and recorded != capsule.digest():
        errors.append("capsule digest mismatch")
    expected_fingerprint = capsule.fingerprints.get("environment")
    if current_fingerprint and expected_fingerprint and current_fingerprint != expected_fingerprint:
        errors.append("environment fingerprint is stale")
    if mode == "dry_run" and not capsule.spec:
        warnings.append("capsule has no spec for dry-run reconstruction")
    plan_hash = hashlib.sha256(
        json.dumps(capsule.plan, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
    return ReplayValidation(not errors, tuple(errors), tuple(warnings), plan_hash)
