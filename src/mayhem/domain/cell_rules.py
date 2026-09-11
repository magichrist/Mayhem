"""Failure→cell-state mapping contract (feat-3 §5.1).

One pure function per §5.1 row; the two rows whose failure halts the session
(compensation failure, recovery-verification failure) carry ``session_stops``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.domain.coverage import CellState

if TYPE_CHECKING:
    from mayhem.domain.candidates import CandidateGate


@dataclass(frozen=True)
class FailureHandling:
    """How a §5.1 failure maps onto the cell record and the session."""

    state: CellState
    session_stops: bool = False


def gate_failure_state(gate: CandidateGate) -> FailureHandling:
    """§5.1 row 1 — a gate rejection blocks the cell; the session continues."""
    return FailureHandling(state=CellState.BLOCKED)


def injection_failure_state(phase: str) -> FailureHandling:
    """§5.1 row 2 — injection failure leaves the cell inconclusive."""
    return FailureHandling(state=CellState.INCONCLUSIVE)


def observation_failure_state() -> FailureHandling:
    """§5.1 row 3 — observation failure leaves the cell inconclusive."""
    return FailureHandling(state=CellState.INCONCLUSIVE)


def compensation_failure_state() -> FailureHandling:
    """§5.1 row 4 — compensation failure stops the session and blocks the cell."""
    return FailureHandling(state=CellState.BLOCKED, session_stops=True)


def recovery_verification_failure_state() -> FailureHandling:
    """§5.1 row 5 — recovery-verification failure stops the session and blocks."""
    return FailureHandling(state=CellState.BLOCKED, session_stops=True)
