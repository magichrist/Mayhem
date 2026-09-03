"""Candidate gate pipeline (ADR-M5-2, M5 Phase 5.3).

Routes an ``ExperimentCandidate`` through the three gates:

    Safety → Feasibility → Resource-conflict

A candidate that fails a gate is rejected with that gate and a reason; it is
never executed. Each gate is an injectable checker so the pipeline is fully
deterministic and unit-testable without a live runtime, while the concrete
checkers mirror the M2 (resource-conflict), M3 (capability verdicts), and
safety machinery already present in the codebase.
"""

from __future__ import annotations

from typing import Protocol

from mayhem.domain.candidates import (
    CandidateDecision,
    CandidateGate,
    ExperimentCandidate,
    accept,
    reject,
)


class GateChecker(Protocol):
    """A single gate: return ``None`` to pass, or a reason string to reject."""

    def check(self, candidate: ExperimentCandidate) -> str | None:
        """Return ``None`` if the candidate passes, else the rejection reason."""
        ...


class SafetyGate:
    """Gate 1 — safety (ADR-M5 / controller safety checks)."""

    def __init__(self, *, forbidden_faults: tuple[str, ...] = ()) -> None:
        # forbidden faults are e.g. host reboot / node kill not allowlisted.
        self._forbidden_faults = set(forbidden_faults)

    def check(self, candidate: ExperimentCandidate) -> str | None:
        for fault in candidate.fault_kinds:
            if fault in self._forbidden_faults:
                return f"fault {fault!r} is forbidden by safety policy"
        if not candidate.target:
            return "candidate has no target"
        return None


class FeasibilityGate:
    """Gate 2 — feasibility (M3 runtime-capability verdicts).

    ``S``/``A``/``U`` mark each fault as Supported / Alternative / Unsupported.
    Any ``U`` (unsupported) fault is not feasible.
    """

    def __init__(self, supported: tuple[str, ...], unsupported: tuple[str, ...] = ()) -> None:
        self._supported = set(supported)
        self._unsupported = set(unsupported)

    def check(self, candidate: ExperimentCandidate) -> str | None:
        for fault in candidate.fault_kinds:
            if fault in self._unsupported:
                return f"fault {fault!r} is UNSUPPORTED by the runtime (not feasible)"
            if fault not in self._supported:
                return f"fault {fault!r} is not in the supported capability set"
        return None


class ResourceConflictGate:
    """Gate 3 — resource conflict (M2).

    ``busy_targets`` are targets that already hold an in-flight mutation, so a
    new experiment against them would collide.
    """

    def __init__(self, busy_targets: tuple[str, ...] = ()) -> None:
        self._busy = set(busy_targets)

    def check(self, candidate: ExperimentCandidate) -> str | None:
        if candidate.target in self._busy:
            return f"target {candidate.target!r} has an in-flight resource conflict"
        return None


class CandidateGatePipeline:
    """Composes the three gates; returns the first rejection, else acceptance."""

    def __init__(
        self,
        *,
        safety: GateChecker | None = None,
        feasibility: GateChecker | None = None,
        resource_conflict: GateChecker | None = None,
    ) -> None:
        self._safety = safety if safety is not None else SafetyGate()
        self._feasibility = (
            feasibility if feasibility is not None else FeasibilityGate(supported=())
        )
        self._resource_conflict = (
            resource_conflict if resource_conflict is not None else ResourceConflictGate()
        )

    def gate(self, candidate: ExperimentCandidate) -> CandidateDecision:
        """Route a candidate through the three gates in fixed order."""
        # 1. Safety
        reason = self._safety.check(candidate)
        if reason is not None:
            return reject(candidate, CandidateGate.SAFETY, reason)
        # 2. Feasibility
        reason = self._feasibility.check(candidate)
        if reason is not None:
            return reject(candidate, CandidateGate.FEASIBILITY, reason)
        # 3. Resource-conflict
        reason = self._resource_conflict.check(candidate)
        if reason is not None:
            return reject(candidate, CandidateGate.RESOURCE_CONFLICT, reason)
        return accept(candidate)

    def gate_many(
        self, candidates: tuple[ExperimentCandidate, ...]
    ) -> tuple[CandidateDecision, ...]:
        return tuple(self.gate(c) for c in candidates)
