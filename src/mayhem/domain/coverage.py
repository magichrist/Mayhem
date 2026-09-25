"""Coverage accounting and the shared resilience-cell model."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


@dataclass(frozen=True)
class CoverageCell:
    """The stable identity of one target/fault/context/band landscape cell."""

    target: str
    fault_kind: str
    execution_context: str
    parameter_band: str

    @property
    def key(self) -> str:
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
    if any("\x1f" in p for p in (target, fault_kind, execution_context, parameter_band)):
        raise ValueError("coverage cell parts must not contain the unit separator char")
    return "\x1f".join((target, fault_kind, execution_context, parameter_band))


def cell_key(
    target: str,
    fault_kind: str,
    execution_context: str,
    parameter_band: str,
) -> str:
    return _cell_key(target, fault_kind, execution_context, parameter_band)


class CellState(StrEnum):
    """The complete persisted and derived coverage vocabulary."""

    UNKNOWN = "unknown"
    PLANNED = "planned"
    EXECUTED = "executed"
    PASSED = "passed"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"
    COVERED = PASSED

    @classmethod
    def _missing_(cls, value: object) -> CellState | None:
        if value == "covered":
            return cls.PASSED
        return None


@dataclass(frozen=True)
class CellFilters:
    """Optional dimensions shared by coverage queries and the operator loop."""

    target_profile: str | None = None
    engine: str | None = None
    service: str | None = None
    failure_domain: str | None = None
    risk: str | None = None
    maturity: str | None = None
    state: CellState | str | None = None

    def matches(self, cell: ResilienceCell) -> bool:
        state = self.state
        if state is not None:
            expected = state if isinstance(state, CellState) else CellState(str(state))
            if cell.state is not expected:
                return False
        return all(
            value is None or str(getattr(cell, name)) == str(value)
            for name, value in (
                ("target_profile", self.target_profile),
                ("engine", self.engine),
                ("service", self.service),
                ("failure_domain", self.failure_domain),
                ("risk", self.risk),
                ("maturity", self.maturity),
            )
        )


@dataclass(frozen=True)
class ResilienceCell:
    """A coverage candidate enriched with catalog and execution context."""

    target: str
    failure_domain: str = ""
    fault: str = ""
    engine: str = ""
    risk: str = ""
    maturity: str = ""
    state: CellState = CellState.UNKNOWN
    last_run: str = ""
    next_rationale: str = ""
    service: str = ""
    target_profile: str = ""
    execution_context: str = "container"
    parameter_band: str = "default"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def fault_kind(self) -> str:
        return self.fault

    @property
    def last_run_id(self) -> str:
        return self.last_run

    @property
    def coverage_cell(self) -> CoverageCell:
        return CoverageCell(
            target=self.target,
            fault_kind=self.fault,
            execution_context=self.execution_context,
            parameter_band=self.parameter_band,
        )

    @property
    def key(self) -> str:
        return self.coverage_cell.key

    @classmethod
    def from_coverage_cell(
        cls,
        cell: CoverageCell,
        *,
        state: CellState | str = CellState.UNKNOWN,
        **metadata: Any,
    ) -> ResilienceCell:
        return cls(
            target=cell.target,
            failure_domain=str(metadata.pop("failure_domain", "")),
            fault=cell.fault_kind,
            engine=str(metadata.pop("engine", "")),
            risk=str(metadata.pop("risk", "")),
            maturity=str(metadata.pop("maturity", "")),
            state=state if isinstance(state, CellState) else CellState(str(state)),
            last_run=str(metadata.pop("last_run", "")),
            next_rationale=str(metadata.pop("next_rationale", "")),
            service=str(metadata.pop("service", cell.target)),
            target_profile=str(metadata.pop("target_profile", "")),
            execution_context=cell.execution_context,
            parameter_band=cell.parameter_band,
            metadata=metadata,
        )

    def matches(self, filters: CellFilters) -> bool:
        return filters.matches(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cell_key": self.key,
            "target": self.target,
            "target_profile": self.target_profile,
            "service": self.service,
            "failure_domain": self.failure_domain,
            "fault": self.fault,
            "fault_kind": self.fault,
            "engine": self.engine,
            "risk": self.risk,
            "maturity": self.maturity,
            "state": self.state.value,
            "last_run": self.last_run,
            "next_rationale": self.next_rationale,
            "execution_context": self.execution_context,
            "parameter_band": self.parameter_band,
        }


@dataclass(frozen=True)
class CoverageRecord:
    """A persisted seen cell plus metadata about its originating run."""

    cell: CoverageCell
    run_id: str
    outcome_marks_seen: bool = True
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return self.cell.key


_TESTED_STATES = frozenset({CellState.PASSED, CellState.INCONCLUSIVE, CellState.FAILED})
_ALLOWED_TRANSITIONS: dict[CellState, frozenset[CellState]] = {
    CellState.UNKNOWN: frozenset(CellState),
    CellState.PLANNED: frozenset(
        {
            CellState.EXECUTED,
            CellState.PASSED,
            CellState.INCONCLUSIVE,
            CellState.FAILED,
            CellState.BLOCKED,
            CellState.SKIPPED,
        }
    ),
    CellState.EXECUTED: frozenset({CellState.PASSED, CellState.INCONCLUSIVE, CellState.FAILED}),
    CellState.PASSED: frozenset({CellState.EXECUTED, CellState.INCONCLUSIVE, CellState.FAILED}),
    CellState.INCONCLUSIVE: frozenset({CellState.EXECUTED, CellState.PASSED, CellState.FAILED}),
    CellState.FAILED: frozenset({CellState.EXECUTED, CellState.PASSED}),
    CellState.BLOCKED: frozenset(
        {
            CellState.PLANNED,
            CellState.EXECUTED,
            CellState.PASSED,
            CellState.INCONCLUSIVE,
            CellState.FAILED,
        }
    ),
    CellState.SKIPPED: frozenset(),
}


def transition(current: CellState | None, new: CellState) -> CellState:
    """Advance a cell under the explicit, monotonic-with-exceptions rules."""
    if current is None:
        return new
    if current is new:
        return current
    if current is CellState.FAILED and new is CellState.INCONCLUSIVE:
        return current
    if new not in _ALLOWED_TRANSITIONS.get(current, frozenset()):
        raise ValueError(f"invalid coverage transition {current.value} -> {new.value}")
    return new


@dataclass(frozen=True)
class CellStatusRecord:
    """Full status record for one coverage cell."""

    cell: CoverageCell
    state: CellState
    block_reason: str = ""
    scaffold_tier: int | None = None
    run_id: str = ""
    verdict: dict[str, Any] = field(default_factory=dict)
    updated_at: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return self.cell.key


@dataclass(frozen=True)
class CoverageSummary:
    """Aggregate view of covered and uncovered cells over a landscape."""

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
        return sum(
            count for state, count in self.state_counts.items() if state is not CellState.PASSED
        )

    @property
    def unknown_count(self) -> int:
        return self.total_cells - self.covered_count - self._noncovered_tested_count

    @property
    def testable_count(self) -> int:
        return self.total_cells - self.blocked_count

    @property
    def fraction(self) -> float:
        if self.testable_count == 0:
            return 0.0
        return self.covered_count / self.testable_count

    def is_covered(self, cell: CoverageCell) -> bool:
        return cell.key in self.covered_keys

    def unknown_cells(self, landscape: tuple[CoverageCell, ...]) -> tuple[CoverageCell, ...]:
        return tuple(cell for cell in landscape if cell.key not in self.covered_keys)

    def untested_cells(self, landscape: tuple[CoverageCell, ...]) -> tuple[CoverageCell, ...]:
        return self.unknown_cells(landscape)

    def cell_was_seen(self, value: CoverageCell) -> bool:
        return self.is_covered(value)
