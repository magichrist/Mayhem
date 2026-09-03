"""ExperimentCandidate — ADR-M5-2 (M5 Phase 5.3).

A candidate is a *proposal* for an experiment: what to poke (target, fault
kinds, params), where (execution context), why (expected effect), and how
risky (risk band). It is not executable until it has passed the three gates:

    Safety → Feasibility → Resource-conflict

A candidate that fails a gate carries the failing gate and a reason; it is
rejected, never executed.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from mayhem.domain.risks import RiskLevel


class CandidateGate(StrEnum):
    """The three gates every executable candidate must pass (ADR-M5-2)."""

    SAFETY = "safety"  # ADR-M5 / controller safety checks
    FEASIBILITY = "feasibility"  # M3 runtime-capability verdicts
    RESOURCE_CONFLICT = "resource_conflict"  # M2 resource-conflict checks


class CandidateStatus(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


@dataclass(frozen=True)
class ExperimentCandidate:
    """A proposal to run one experiment against one target cell."""

    target: str
    fault_kinds: tuple[str, ...]
    params: dict[str, Any] = field(default_factory=dict)
    execution_context: str = "container"
    expected_effect: str = ""
    risk_band: RiskLevel = RiskLevel.LOW
    seed_hint: int = 0  # ties a candidate to a deterministic generator seed

    @property
    def id(self) -> str:
        """Stable id derived from the candidate's defining fields + seed."""
        digest = hashlib.sha256(
            f"{self.target}\x1f"
            f"{','.join(self.fault_kinds)}\x1f"
            f"{self.execution_context}\x1f"
            f"{self.risk_band.value}\x1f"
            f"{self.seed_hint}".encode()
        ).hexdigest()[:16]
        return f"cand-{digest}"

    @property
    def primary_fault(self) -> str:
        return self.fault_kinds[0] if self.fault_kinds else ""


@dataclass(frozen=True)
class CandidateDecision:
    """Outcome of routing a candidate through the three gates."""

    candidate: ExperimentCandidate
    status: CandidateStatus
    gate: CandidateGate | None = None  # which gate rejected it
    reason: str = ""

    @property
    def accepted(self) -> bool:
        return self.status is CandidateStatus.ACCEPTED

    @property
    def rejected(self) -> bool:
        return self.status is CandidateStatus.REJECTED

    @property
    def summary(self) -> str:
        if self.accepted:
            fault = self.candidate.primary_fault
            return f"ACCEPT {self.candidate.id} ({self.candidate.target}/{fault})"
        gate = self.gate.value if self.gate is not None else "unknown"
        return f"REJECT[{gate}] {self.candidate.id}: {self.reason}"


def accept(candidate: ExperimentCandidate) -> CandidateDecision:
    return CandidateDecision(candidate=candidate, status=CandidateStatus.ACCEPTED)


def reject(candidate: ExperimentCandidate, gate: CandidateGate, reason: str) -> CandidateDecision:
    return CandidateDecision(
        candidate=candidate,
        status=CandidateStatus.REJECTED,
        gate=gate,
        reason=reason,
    )
