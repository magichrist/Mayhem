from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mayhem.domain.resolution import ResolvedNodeTarget, ResolvedPodTarget


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    allowed: bool
    code: str = ""
    reason: str = ""
    required_target_types: tuple[str, ...] = ()
    required_capabilities: tuple[str, ...] = ()

    @classmethod
    def allow(
        cls,
        *,
        required_target_types: tuple[str, ...] = (),
        required_capabilities: tuple[str, ...] = (),
    ) -> AdmissionDecision:
        return cls(
            allowed=True,
            required_target_types=required_target_types,
            required_capabilities=required_capabilities,
        )

    @classmethod
    def refuse(
        cls,
        code: str,
        reason: str,
        *,
        required_target_types: tuple[str, ...] = (),
        required_capabilities: tuple[str, ...] = (),
    ) -> AdmissionDecision:
        return cls(
            allowed=False,
            code=code,
            reason=reason,
            required_target_types=required_target_types,
            required_capabilities=required_capabilities,
        )


def target_type(target: Any) -> str | None:
    if isinstance(target, ResolvedPodTarget):
        return "pod"
    if isinstance(target, ResolvedNodeTarget):
        return "node"
    return None


def admit_resolved_target(
    fault_id: str,
    target: Any,
    *,
    required_target_types: tuple[str, ...],
    compensation_complete: bool,
    required_capabilities: tuple[str, ...] = (),
) -> AdmissionDecision:
    if target is None:
        return AdmissionDecision.refuse(
            "target.unresolved",
            f"fault {fault_id} has no resolved target",
            required_target_types=required_target_types,
            required_capabilities=required_capabilities,
        )
    actual = target_type(target)
    if actual is None or actual not in required_target_types:
        return AdmissionDecision.refuse(
            "target.type_mismatch",
            f"fault {fault_id} requires {required_target_types}, got {actual or 'unknown'}",
            required_target_types=required_target_types,
            required_capabilities=required_capabilities,
        )
    if not compensation_complete:
        return AdmissionDecision.refuse(
            "compensation.incomplete",
            f"fault {fault_id} has no complete compensation contract",
            required_target_types=required_target_types,
            required_capabilities=required_capabilities,
        )
    return AdmissionDecision.allow(
        required_target_types=required_target_types,
        required_capabilities=required_capabilities,
    )
