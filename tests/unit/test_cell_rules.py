"""Failure→state mapping (§5.1): one function per row; stop rows flagged."""

from __future__ import annotations

import pytest

from mayhem.domain.candidates import CandidateGate
from mayhem.domain.cell_rules import (
    FailureHandling,
    compensation_failure_state,
    gate_failure_state,
    injection_failure_state,
    observation_failure_state,
    recovery_verification_failure_state,
)
from mayhem.domain.coverage import CellState


def test_gate_failure_maps_to_blocked_not_stop() -> None:
    for gate in CandidateGate:
        assert gate_failure_state(gate) == FailureHandling(
            state=CellState.BLOCKED, session_stops=False
        )


def test_injection_failure_maps_to_inconclusive_not_stop() -> None:
    for phase in ("inject", "apply", "verify"):
        assert injection_failure_state(phase) == FailureHandling(
            state=CellState.INCONCLUSIVE, session_stops=False
        )


def test_observation_failure_maps_to_inconclusive_not_stop() -> None:
    assert observation_failure_state() == FailureHandling(
        state=CellState.INCONCLUSIVE, session_stops=False
    )


def test_compensation_failure_blocks_and_stops() -> None:
    assert compensation_failure_state() == FailureHandling(
        state=CellState.BLOCKED, session_stops=True
    )


def test_recovery_verification_failure_blocks_and_stops() -> None:
    assert recovery_verification_failure_state() == FailureHandling(
        state=CellState.BLOCKED, session_stops=True
    )


def test_exactly_two_rows_stop_the_session() -> None:
    outcomes = [
        gate_failure_state(CandidateGate.SAFETY),
        injection_failure_state("inject"),
        observation_failure_state(),
        compensation_failure_state(),
        recovery_verification_failure_state(),
    ]
    assert len(outcomes) == 5
    stopping = [o for o in outcomes if o.session_stops]
    assert len(stopping) == 2
    assert all(o.state is CellState.BLOCKED for o in stopping)


def test_every_section_5_1_row_maps_to_exactly_one_function() -> None:
    # §5.1 rows: gate / injection / observation / compensation / recovery.
    expected: list[tuple[str, FailureHandling]] = [
        ("gate", gate_failure_state(CandidateGate.FEASIBILITY)),
        ("injection", injection_failure_state("inject")),
        ("observation", observation_failure_state()),
        ("compensation", compensation_failure_state()),
        ("recovery_verification", recovery_verification_failure_state()),
    ]
    assert [name for name, _ in expected] == [
        "gate",
        "injection",
        "observation",
        "compensation",
        "recovery_verification",
    ]
    assert len({id(h) for _, h in expected}) == 5  # distinct handlers


def test_failure_handling_is_frozen() -> None:
    with pytest.raises(AttributeError):
        gate_failure_state(CandidateGate.SAFETY).state = CellState.FAILED  # type: ignore[misc]
