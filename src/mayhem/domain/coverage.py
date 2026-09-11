"""Coverage accounting — ADR-M5-3 (coverage is the objective).

A ``CoverageCell`` is a point in the experiment landscape:
(``target``, ``fault_kind``, ``execution_context``, ``parameter_band``).

A recorded ``Outcome`` marks the cell for its run as *seen*; Maniac then
optimizes toward covering new (``UNKNOWN``) cells rather than re-running
already-covered ones. A re-run of the same cell never double-counts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


@dataclass(frozen=True)
class CoverageCell:
    """One point in the (target, fault-kind, context, parameter-band) landscape."""

    target: str
    fault_kind: str
    execution_context: str
    parameter_band: str

    @property
    def key(self) -> str:
        """Canonical, collision-resistant key for this cell."""
        return _cell_key(self.target, self.fault_kind, self.execution_context, self.parameter_band)

    def to_tuple(self) -> tuple[str, str, str, str]:
        return (self.target, self.fault_kind, self.execution_context, self.parameter_band)

    @classmethod
    def from_tuple(cls, row: tuple[str, str, str, str]) -> CoverageCell:
        return cls(*row)


def _cell_key(
    target: str,
    fault_kind: str,
    execution_context: str,
    parameter_band: str,
) -> str:
    """Deterministic key; ``"\x1f"`` (unit separator) is not valid in the parts."""
    if any("\x1f" in p for p in (target, fault_kind, execution_context, parameter_band)):
        raise ValueError("coverage cell parts must not contain the unit separator char")
    return "\x1f".join((target, fault_kind, execution_context, parameter_band))


def cell_key(
    target: str,
    fault_kind: str,
    execution_context: str,
    parameter_band: str,
) -> str:
    """Module-level helper mirroring ``CoverageCell.key``."""
    return _cell_key(target, fault_kind, execution_context, parameter_band)


@dataclass(frozen=True)
class CoverageRecord:
    """A persisted *seen* cell plus metadata about its originating run."""

    cell: CoverageCell
    run_id: str
    outcome_marks_seen: bool = True
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return self.cell.key


class CellState(StrEnum):
    """Five-state coverage model (feat-3 §4.2).

    ``unknown`` is the absence of a row and is never persisted.
    """

    COVERED = "covered"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"
    BLOCKED = "blocked"


_TESTED_STATES = frozenset({CellState.COVERED, CellState.INCONCLUSIVE, CellState.FAILED})


def transition(current: CellState | None, new: CellState) -> CellState:
    """Advance one cell's state under the §4.2 monotonicity rules.

    Rules (same cell):
    - ``unknown`` (``current is None``) → any of the four states.
    - Same-state re-run keeps the existing record (idempotent).
    - ``blocked`` → ``covered``/``inconclusive``/``failed`` (un-blocking is an
      explicit new write); ``blocked → blocked`` is the idempotent case.
    - ``failed`` is the strongest tested evidence: a later ``inconclusive``
      never erases it.
    - ``covered → inconclusive`` is explicitly allowed: a *fresh* run's
      inconclusive outcome is new evidence and coverage reflects evidence
      (feat-3 §5.3 roll-up correctness). Same-run re-processing never
      downgrades — that guard lives in the repository via ``run_id``.
    - Entering ``blocked`` from a tested state is impossible (``ValueError``);
      ``blocked`` is only ever entered from ``unknown``.

    Raises:
        ValueError: On an impossible move (e.g. a tested state → ``blocked``).
    """
    if current is None:
        return new
    if current is new:
        return current
    if current is CellState.BLOCKED:
        if new in _TESTED_STATES:
            return new
        raise ValueError(f"blocked cell cannot move to {new.value!r}")
    if current is CellState.FAILED and new is CellState.INCONCLUSIVE:
        return current
    if new is CellState.BLOCKED:
        raise ValueError(f"tested cell ({current.value}) cannot become blocked")
    return new


@dataclass(frozen=True)
class CellStatusRecord:
    """Full five-state record for one coverage cell (feat-3 §4.2)."""

    cell: CoverageCell
    state: CellState
    block_reason: str = ""
    scaffold_tier: int | None = None
    run_id: str = ""
    verdict: dict[str, Any] = field(default_factory=dict)
    updated_at: str = ""

    @property
    def key(self) -> str:
        return self.cell.key


@dataclass(frozen=True)
class CoverageSummary:
    """Aggregate view of covered vs unknown cells over a landscape."""

    covered_keys: frozenset[str]
    total_cells: int
    state_counts: dict[CellState, int] = field(default_factory=dict)

    @property
    def covered_count(self) -> int:
        return len(self.covered_keys)

    def state_count(self, state: CellState) -> int:
        return self.state_counts.get(state, 0)

    @property
    def blocked_count(self) -> int:
        return self.state_count(CellState.BLOCKED)

    @property
    def _noncovered_tested_count(self) -> int:
        return sum(count for s, count in self.state_counts.items() if s is not CellState.COVERED)

    @property
    def unknown_count(self) -> int:
        """Cells never recorded in any state (no row) — the §4.2 ``unknown``."""
        return self.total_cells - self.covered_count - self._noncovered_tested_count

    @property
    def testable_count(self) -> int:
        """Testable pool: covered+inconclusive+failed+unknown; blocked excluded."""
        return self.total_cells - self.blocked_count

    @property
    def fraction(self) -> float:
        """Fraction of the *testable pool* covered, in [0.0, 1.0].

        The denominator excludes blocked cells (feat-3 §5.3); without any
        blocked cells this equals the bare landscape fraction.
        """
        if self.testable_count == 0:
            return 0.0
        return self.covered_count / self.testable_count

    def is_covered(self, cell: CoverageCell) -> bool:
        return cell.key in self.covered_keys

    def unknown_cells(self, landscape: tuple[CoverageCell, ...]) -> tuple[CoverageCell, ...]:
        """Cells in ``landscape`` not yet covered, in landscape order."""
        return tuple(c for c in landscape if c.key not in self.covered_keys)

    def untested_cells(self, landscape: tuple[CoverageCell, ...]) -> tuple[CoverageCell, ...]:
        """Cells in ``landscape`` never tested (unknown), in landscape order.

        ``unknown`` is the shared notion of "untested" — the same set the
        ``next`` suggestion list ranks (feat-3 §5.3).
        """
        return self.unknown_cells(landscape)

    def cell_was_seen(self, value: CoverageCell) -> bool:
        """Alias of ``is_covered`` for call sites reading 'seen' language."""
        return self.is_covered(value)
