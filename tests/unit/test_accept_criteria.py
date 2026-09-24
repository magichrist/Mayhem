"""Feat-3 acceptance criteria (Phase D): AC1-AC5.

Each test maps one-to-one to an acceptance criterion in the feat-3 spec.
The full CLI flow (AC5) is exercised here through the repository + ranking
seam that Maniac's ``next`` suggestion path uses; the controller-level wiring
is covered by the existing M5 e2e suite.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mayhem.domain.coverage import CellState, CoverageCell
from mayhem.domain.risks import RiskLevel
from mayhem.infra.coverage_repository import SQLiteCoverageRepository
from mayhem.infra.ranking import rank
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

_LANDSCAPE = (
    CoverageCell("api-1", "net.delay", "prod", "50ms"),
    CoverageCell("api-1", "net.delay", "prod", "250ms"),
    CoverageCell("worker-1", "fs.fill", "staging", "80%"),
    CoverageCell("db-1", "mem.pressure", "staging", "70%"),
)


def _repo(tmp_path: Path) -> tuple[Store, SQLiteCoverageRepository]:
    store = Store.open_migrated(tmp_path / "acceptance.db")
    return store, SQLiteCoverageRepository(store)


def test_ac1_five_states_with_unknown_implied(tmp_path: Path) -> None:
    """AC1 - exactly five states; unknown = absent row."""
    store, coverage = _repo(tmp_path)
    states = set(CellState) | {None}  # None stands in for 'unknown'
    assert set(states) == {
        CellState.UNKNOWN,
        CellState.PLANNED,
        CellState.EXECUTED,
        CellState.PASSED,
        CellState.INCONCLUSIVE,
        CellState.FAILED,
        CellState.BLOCKED,
        CellState.SKIPPED,
        None,
    }

    coverage.record(_LANDSCAPE[0], CellState.COVERED, run_id="r1")
    coverage.record_blocked(_LANDSCAPE[1], reason="runtime lacks net.delay")
    coverage.record(_LANDSCAPE[2], CellState.INCONCLUSIVE, run_id="r2")

    assert coverage.cell_state(_LANDSCAPE[0]) is CellState.COVERED
    assert coverage.cell_state(_LANDSCAPE[1]) is CellState.BLOCKED
    assert coverage.cell_state(_LANDSCAPE[2]) is CellState.INCONCLUSIVE
    assert coverage.cell_state(_LANDSCAPE[3]) is None  # unknown by absence
    store.close()


def test_ac2_blocked_excluded_from_next_and_fraction(tmp_path: Path) -> None:
    """AC2 - blocked cells ARE recorded but are NOT next suggestions and are
    excluded from the coverage fraction (testable pool)."""
    store, coverage = _repo(tmp_path)
    coverage.record_blocked(_LANDSCAPE[0], reason="gate: unsupported")
    coverage.record(_LANDSCAPE[1], CellState.COVERED, run_id="r1")

    states = coverage.states(_LANDSCAPE)
    ranked = rank(
        _LANDSCAPE,
        state_map=states,
        division_map={},
        criticality_map={},
        risk_map={},
    )
    assert _LANDSCAPE[0].key not in {rc.cell.key for rc in ranked}
    assert {rc.cell.key for rc in ranked} <= {c.key for c in _LANDSCAPE[2:]}

    summary = coverage.summary(_LANDSCAPE)
    assert summary.blocked_count == 1
    # 4 cells, 1 blocked → 3 testable, 1 covered → 1/3; blocked never inflates.
    assert summary.fraction == 1.0 / 3.0
    store.close()


def test_ac3_rollup_bar_controlled_by_single_state_column(tmp_path: Path) -> None:
    """AC3 - roll-up bar is the state column exactly; no drift between it and
    the legacy covered flag."""
    store, coverage = _repo(tmp_path)
    cell = _LANDSCAPE[2]
    coverage.record(cell, CellState.COVERED, run_id="r1")
    coverage.record(cell, CellState.INCONCLUSIVE, run_id="r2")  # fresh-run downgrade
    state = store.query("SELECT state, covered FROM m5_coverage")[0]
    assert state["state"] == "inconclusive"
    assert state["covered"] == 0
    store.close()


def test_ac4_ranked_next_is_deterministic_and_carry_factors(tmp_path: Path) -> None:
    """AC4 - built-next uses a ranked order incl. --explain factors; running
    it twice (or on a reordered landscape) yields the same sequence."""
    store, coverage = _repo(tmp_path)
    coverage.record(_LANDSCAPE[0], CellState.COVERED, run_id="r1")
    coverage.record_blocked(_LANDSCAPE[1], reason="gate rejected")

    states = coverage.states(_LANDSCAPE)
    criticality_map: dict[str, float] = {}
    risk_map: dict[str, RiskLevel] = dict.fromkeys(
        ("net.delay", "fs.fill", "mem.pressure"),
        RiskLevel.MEDIUM,
    )
    division_map: dict[str, int] = {}
    once = rank(
        _LANDSCAPE,
        state_map=states,
        division_map=division_map,
        criticality_map=criticality_map,
        risk_map=risk_map,
    )
    twice = rank(
        list(reversed(_LANDSCAPE)),
        state_map=states,
        division_map=division_map,
        criticality_map=criticality_map,
        risk_map=risk_map,
    )
    assert [rc.cell.key for rc in once] == [rc.cell.key for rc in twice]
    assert len(once) == 2
    for rc in once:
        assert set(rc.factors) == {"info", "criticality", "diversity", "risk_rank", "recall"}
    store.close()


def test_ac5_route_through_repository_to_ranked_next(tmp_path: Path) -> None:
    """AC5 - a full loop: record outcomes, re-query, hand the landscape to the
    ranking seam, and observe blocked/unknown segregation end to end."""
    store, coverage = _repo(tmp_path)
    coverage.record_blocked(_LANDSCAPE[0], reason="infeasible on this runtime")
    coverage.record(_LANDSCAPE[1], CellState.COVERED, run_id="r1")
    coverage.record(_LANDSCAPE[3], CellState.FAILED, run_id="r2")

    states = coverage.states(_LANDSCAPE)
    ranked = rank(
        _LANDSCAPE,
        state_map=states,
        division_map={},
        criticality_map={},
        risk_map={},
    )
    ranked_keys = [rc.cell.key for rc in ranked]
    assert _LANDSCAPE[2].key in ranked_keys  # never tested → suggested
    assert _LANDSCAPE[0].key not in ranked_keys  # blocked → never suggested
    assert _LANDSCAPE[1].key not in ranked_keys  # covered → never re-suggested
    assert _LANDSCAPE[3].key not in ranked_keys  # failed → already tested

    summary = coverage.summary(_LANDSCAPE)
    assert summary.blocked_count == 1
    assert summary.testable_count == 3
    assert summary.unknown_count == 1
    assert summary.fraction == 1.0 / 3.0
    store.close()
