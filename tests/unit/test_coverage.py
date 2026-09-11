"""Coverage accounting tests (ADR-M5-3, M5 Phase 5.2).

Covers the coverage-cell semantics: a recorded Outcome marks its cell seen;
re-running the same cell does not double-count; UNKNOWN cells enumerable.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from mayhem.domain.coverage import (
    CellState,
    CoverageCell,
    CoverageRecord,
    CoverageSummary,
    cell_key,
    transition,
)
from mayhem.infra.coverage_repository import SQLiteCoverageRepository
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path


def _cells() -> tuple[CoverageCell, ...]:
    return (
        CoverageCell("web-1", "net.delay", "prod", "50ms"),
        CoverageCell("web-1", "net.delay", "prod", "250ms"),
        CoverageCell("api-1", "cpu.spike", "staging", "50%"),
        CoverageCell("db-1", "fs.fill", "staging", "80%"),
    )


class TestCoverageCell:
    def test_key_is_canonical_and_order_dependent(self) -> None:
        a = CoverageCell("web-1", "net.delay", "prod", "50ms")
        b = CoverageCell("web-1", "net.delay", "prod", "50ms")
        c = CoverageCell("api-1", "net.delay", "prod", "50ms")
        assert a.key == b.key
        assert a.key != c.key

    def test_module_helper_matches_property(self) -> None:
        cell = CoverageCell("web-1", "net.delay", "prod", "50ms")
        assert cell.key == cell_key("web-1", "net.delay", "prod", "50ms")

    def test_rejects_embedded_unit_separator(self) -> None:
        cell = CoverageCell("web\x1f-1", "net.delay", "prod", "50ms")
        with pytest.raises(ValueError):
            _ = cell.key

    def test_to_from_tuple(self) -> None:
        cell = CoverageCell("web-1", "net.delay", "prod", "50ms")
        assert CoverageCell.from_tuple(cell.to_tuple()) == cell


class TestCoverageSummary:
    def test_counts(self) -> None:
        cells = _cells()
        summary = CoverageSummary(covered_keys=frozenset({cells[0].key}), total_cells=4)
        assert summary.covered_count == 1
        assert summary.unknown_count == 3
        assert summary.fraction == pytest.approx(0.25)

    def test_fraction_zero_when_empty_landscape(self) -> None:
        summary = CoverageSummary(covered_keys=frozenset(), total_cells=0)
        assert summary.fraction == 0.0

    def test_is_covered_and_unknown_cells(self) -> None:
        cells = _cells()
        summary = CoverageSummary(
            covered_keys=frozenset({cells[0].key, cells[1].key}),
            total_cells=4,
        )
        assert summary.is_covered(cells[0]) is True
        assert summary.is_covered(cells[2]) is False
        unknown = summary.unknown_cells(cells)
        assert unknown == (cells[2], cells[3])
        assert summary.unknown_count == 2


class TestCoverageRepository:
    @staticmethod
    def _repo(tmp_path: Path) -> SQLiteCoverageRepository:
        store = Store.open_migrated(tmp_path / "cov.db")
        return SQLiteCoverageRepository(store)

    @staticmethod
    def _store(tmp_path: Path) -> Store:
        return Store.open_migrated(tmp_path / "cov.db")

    def test_cell_starts_unknown_then_covered(self, tmp_path: Path) -> None:
        repo = self._repo(tmp_path)
        cells = _cells()
        assert repo.is_covered(cells[0]) is False
        repo.mark_seen(cells[0], run_id="r1")
        assert repo.is_covered(cells[0]) is True
        assert repo.is_covered(cells[1]) is False

    def test_increments_per_distinct_cell(self, tmp_path: Path) -> None:
        """Acceptance: coverage increments per distinct cell."""
        repo = self._repo(tmp_path)
        cells = _cells()
        for i, cell in enumerate(cells):
            repo.mark_seen(cell, run_id=f"r{i}")
        records = repo.covered_records()
        assert len(records) == 4
        assert {r.cell.key for r in records} == {c.key for c in cells}

    def test_rerun_same_cell_does_not_double_count(self, tmp_path: Path) -> None:
        """Acceptance: re-running the same cell does not double-count."""
        repo = self._repo(tmp_path)
        cells = _cells()
        # Mark the same cell 5 times (represents re-running the same cell)
        for _ in range(5):
            repo.mark_seen(cells[0], run_id="r1")
        records = repo.covered_records()
        assert len(records) == 1  # not 5
        assert repo.covered_keys() == frozenset({cells[0].key})

    def test_unknown_cells_are_enumerable(self, tmp_path: Path) -> None:
        """Acceptance: UNKNOWN cells are enumerable."""
        repo = self._repo(tmp_path)
        cells = _cells()
        # Cover two of four cells
        repo.mark_seen(cells[0], run_id="r1")
        repo.mark_seen(cells[2], run_id="r2")
        unknown = repo.unknown_cells(cells)
        assert set(unknown) == {cells[1], cells[3]}
        assert repo.summary(cells).unknown_count == 2
        assert repo.summary(cells).covered_count == 2

    def test_migration_applied_and_queryable(self, tmp_path: Path) -> None:
        store = self._store(tmp_path)
        repo = SQLiteCoverageRepository(store)
        assert store.schema_version == ALL_MIGRATIONS[-1].version
        cells = _cells()
        repo.mark_seen(cells[0], run_id="r1")
        assert store.query("SELECT COUNT(*) AS n FROM m5_coverage")[0]["n"] == 1

    def test_record_extra_round_trip(self, tmp_path: Path) -> None:
        repo = self._repo(tmp_path)
        cell = _cells()[0]
        repo.mark_seen(cell, run_id="r1", extra={"fault": "injected", "band": "50ms"})
        record: CoverageRecord = repo.covered_records()[0]
        assert record.run_id == "r1"
        assert record.extra == {"fault": "injected", "band": "50ms"}

    def test_covered_records_orderless(self, tmp_path: Path) -> None:
        repo = self._repo(tmp_path)
        cells = _cells()
        for i, cell in enumerate(cells):
            repo.mark_seen(cell, run_id=f"r{i}")
        keys = {r.cell.key for r in repo.covered_records()}
        assert keys == {c.key for c in cells}


class TestCellStateTransition:
    def test_unknown_enters_any_of_the_four_states(self) -> None:
        assert transition(None, CellState.COVERED) is CellState.COVERED
        assert transition(None, CellState.INCONCLUSIVE) is CellState.INCONCLUSIVE
        assert transition(None, CellState.FAILED) is CellState.FAILED
        assert transition(None, CellState.BLOCKED) is CellState.BLOCKED

    def test_same_state_rerun_is_idempotent(self) -> None:
        for state in CellState:
            assert transition(state, state) is state

    def test_blocked_unblocks_only_to_a_tested_state(self) -> None:
        assert transition(CellState.BLOCKED, CellState.COVERED) is CellState.COVERED
        assert transition(CellState.BLOCKED, CellState.INCONCLUSIVE) is CellState.INCONCLUSIVE
        assert transition(CellState.BLOCKED, CellState.FAILED) is CellState.FAILED

    def test_covered_to_inconclusive_allowed_as_fresh_evidence(self) -> None:
        # §5.3 roll-up correctness: a fresh inconclusive run drops the bar.
        assert transition(CellState.COVERED, CellState.INCONCLUSIVE) is CellState.INCONCLUSIVE

    def test_failed_never_downgraded_to_inconclusive(self) -> None:
        assert transition(CellState.FAILED, CellState.INCONCLUSIVE) is CellState.FAILED

    def test_testing_uprgades_are_allowed(self) -> None:
        assert transition(CellState.INCONCLUSIVE, CellState.COVERED) is CellState.COVERED
        assert transition(CellState.INCONCLUSIVE, CellState.FAILED) is CellState.FAILED
        assert transition(CellState.FAILED, CellState.COVERED) is CellState.COVERED

    def test_impossible_moves_raise_value_error(self) -> None:
        # Blocked is only ever entered from unknown — never from a tested state.
        for state in (CellState.COVERED, CellState.INCONCLUSIVE, CellState.FAILED):
            with pytest.raises(ValueError):
                transition(state, CellState.BLOCKED)


class TestCoverageSummaryFiveState:
    def test_state_counts_default_is_backwards_compatible(self) -> None:
        cells = _cells()
        summary = CoverageSummary(covered_keys=frozenset({cells[0].key}), total_cells=4)
        assert summary.unknown_count == 3
        assert summary.fraction == pytest.approx(0.25)

    def test_testable_pool_excludes_blocked(self) -> None:
        cells = _cells()
        summary = CoverageSummary(
            covered_keys=frozenset({cells[0].key}),
            total_cells=5,
            state_counts={
                CellState.COVERED: 1,
                CellState.INCONCLUSIVE: 1,
                CellState.FAILED: 0,
                CellState.BLOCKED: 1,
            },
        )
        assert summary.state_count(CellState.BLOCKED) == 1
        assert summary.blocked_count == 1
        assert summary.testable_count == 4
        assert summary.unknown_count == 2
        # blocked excluded from the denominator
        assert summary.fraction == pytest.approx(1.0 / 4.0)

    def test_untested_cells_are_the_unknown_cells(self) -> None:
        cells = _cells()
        summary = CoverageSummary(
            covered_keys=frozenset({cells[0].key}),
            total_cells=4,
            state_counts={
                CellState.COVERED: 1,
                CellState.INCONCLUSIVE: 0,
                CellState.FAILED: 0,
                CellState.BLOCKED: 0,
            },
        )
        assert summary.untested_cells(cells) == (cells[1], cells[2], cells[3])
        assert summary.untested_cells(cells) == summary.unknown_cells(cells)
