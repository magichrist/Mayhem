"""Coverage accounting — ADR-M5-3 (coverage is the objective).

A ``CoverageCell`` is a point in the experiment landscape:
(``target``, ``fault_kind``, ``execution_context``, ``parameter_band``).

A recorded ``Outcome`` marks the cell for its run as *seen*; Maniac then
optimizes toward covering new (``UNKNOWN``) cells rather than re-running
already-covered ones. A re-run of the same cell never double-counts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
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


@dataclass(frozen=True)
class CoverageSummary:
    """Aggregate view of covered vs unknown cells over a landscape."""

    covered_keys: frozenset[str]
    total_cells: int

    @property
    def covered_count(self) -> int:
        return len(self.covered_keys)

    @property
    def unknown_count(self) -> int:
        return self.total_cells - self.covered_count

    @property
    def fraction(self) -> float:
        """Fraction of the landscape covered, in [0.0, 1.0]."""
        if self.total_cells == 0:
            return 0.0
        return self.covered_count / self.total_cells

    def is_covered(self, cell: CoverageCell) -> bool:
        return cell.key in self.covered_keys

    def unknown_cells(self, landscape: tuple[CoverageCell, ...]) -> tuple[CoverageCell, ...]:
        """Cells in ``landscape`` not yet covered, in landscape order."""
        return tuple(c for c in landscape if c.key not in self.covered_keys)

    def cell_was_seen(self, value: CoverageCell) -> bool:
        """Alias of ``is_covered`` for call sites reading 'seen' language."""
        return self.is_covered(value)
