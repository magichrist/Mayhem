"""Five-state repository API (feat-3 §4.2/A3): idempotency, blocked handling,
fresh-run downgrade, and legacy ``covered`` column sync."""

from __future__ import annotations

from typing import TYPE_CHECKING

from mayhem.domain.coverage import CellState, CoverageCell
from mayhem.infra.coverage_repository import SQLiteCoverageRepository
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path


def _make_cells(n: int) -> tuple[CoverageCell, ...]:
    return tuple(
        CoverageCell(
            target=f"svc-{i}",
            fault_kind="net.delay",
            execution_context="container",
            parameter_band="default",
        )
        for i in range(n)
    )


def _open(tmp_path: Path) -> tuple[Store, SQLiteCoverageRepository]:
    store = Store.open_migrated(tmp_path / "coverage.db")
    return store, SQLiteCoverageRepository(store)


def test_record_same_cell_same_run_is_idempotent(tmp_path: Path) -> None:
    store, coverage = _open(tmp_path)
    cell = _make_cells(1)[0]
    coverage.record(cell, CellState.COVERED, run_id="r1")
    coverage.record(cell, CellState.COVERED, run_id="r1")

    assert coverage.cell_state(cell) is CellState.COVERED
    rows = store.query("SELECT cell_key, run_id, covered FROM m5_coverage")
    assert len(rows) == 1
    assert rows[0]["run_id"] == "r1"
    assert rows[0]["covered"] == 1
    store.close()


def test_record_same_cell_same_state_across_runs_stays_covered(tmp_path: Path) -> None:
    store, coverage = _open(tmp_path)
    cell = _make_cells(1)[0]
    coverage.record(cell, CellState.COVERED, run_id="r1")
    coverage.record(cell, CellState.COVERED, run_id="r2")

    assert coverage.cell_state(cell) is CellState.COVERED
    assert store.query("SELECT covered FROM m5_coverage")[0]["covered"] == 1
    store.close()


def test_blocked_excluded_from_testable(tmp_path: Path) -> None:
    store, coverage = _open(tmp_path)
    cells = _make_cells(4)
    coverage.record(cells[0], CellState.COVERED, run_id="r1")
    coverage.record(cells[1], CellState.INCONCLUSIVE, run_id="r2")
    coverage.record_blocked(cells[2], reason="fault unsupported by runtime")

    summary = coverage.summary(cells)
    assert summary.total_cells == 4
    assert summary.testable_count == 3
    assert summary.blocked_count == 1
    assert summary.state_counts[CellState.BLOCKED] == 1
    assert summary.state_counts[CellState.COVERED] == 1
    assert summary.state_counts[CellState.INCONCLUSIVE] == 1

    blocked = coverage.blocked_cells(cells)
    assert len(blocked) == 1
    assert blocked[0].cell.key == cells[2].key
    assert blocked[0].state is CellState.BLOCKED
    assert blocked[0].block_reason == "fault unsupported by runtime"
    store.close()


def test_covered_to_inconclusive_via_new_run_drops_rollup_bar(tmp_path: Path) -> None:
    store, coverage = _open(tmp_path)
    cell = _make_cells(1)[0]

    coverage.record(cell, CellState.COVERED, run_id="r1", verdict={"verdict": "pass"})
    assert coverage.cell_state(cell) is CellState.COVERED
    assert coverage.summary((cell,)).state_counts[CellState.COVERED] == 1

    coverage.record(
        cell,
        CellState.INCONCLUSIVE,
        run_id="r2",
        scaffold_tier=6,
        verdict={"verdict": "inconclusive"},
    )
    summary = coverage.summary((cell,))
    assert coverage.cell_state(cell) is CellState.INCONCLUSIVE
    assert summary.state_counts[CellState.COVERED] == 0
    assert summary.state_counts[CellState.INCONCLUSIVE] == 1
    assert summary.fraction == 0.0
    # legacy column tracks the five-state record: 1 iff state == covered
    assert store.query("SELECT covered FROM m5_coverage")[0]["covered"] == 0
    store.close()


def test_covered_column_is_one_iff_state_covered(tmp_path: Path) -> None:
    store, coverage = _open(tmp_path)
    cells = _make_cells(3)
    coverage.record(cells[0], CellState.COVERED, run_id="r1")
    coverage.record(cells[1], CellState.FAILED, run_id="r2")
    coverage.record(cells[2], CellState.INCONCLUSIVE, run_id="r3")

    rows = {
        r["cell_key"]: r["covered"]
        for r in store.query("SELECT cell_key, covered FROM m5_coverage")
    }
    assert rows[cells[0].key] == 1
    assert rows[cells[1].key] == 0
    assert rows[cells[2].key] == 0
    store.close()


def test_record_blocked_twice_is_idempotent(tmp_path: Path) -> None:
    store, coverage = _open(tmp_path)
    cell = _make_cells(1)[0]
    coverage.record_blocked(cell, reason="first reason")
    coverage.record_blocked(cell, reason="second reason")

    assert coverage.cell_state(cell) is CellState.BLOCKED
    assert store.query("SELECT state FROM m5_coverage")[0]["state"] == "blocked"
    store.close()


def test_states_map_missing_keys_are_unknown(tmp_path: Path) -> None:
    store, coverage = _open(tmp_path)
    cells = _make_cells(3)
    coverage.record(cells[0], CellState.COVERED, run_id="r1")

    states = coverage.states(cells)
    assert states[cells[0].key] is CellState.COVERED
    assert cells[1].key not in states
    assert cells[2].key not in states
    store.close()


def test_unblock_records_a_tested_state(tmp_path: Path) -> None:
    store, coverage = _open(tmp_path)
    cell = _make_cells(1)[0]
    coverage.record_blocked(cell, reason="gate rejected")
    coverage.record(cell, CellState.COVERED, run_id="r2")

    assert coverage.cell_state(cell) is CellState.COVERED
    blocked = coverage.blocked_cells((cell,))
    assert blocked == ()
    # block_reason cleared off the record once un-blocked
    assert store.query("SELECT block_reason FROM m5_coverage")[0]["block_reason"] == ""
    store.close()
