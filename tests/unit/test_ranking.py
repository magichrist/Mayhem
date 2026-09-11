"""Deterministic ranking (feat-3 §7): determinism, risk tie-breaks, factors."""

from __future__ import annotations

from mayhem.domain.coverage import CellState, CoverageCell
from mayhem.domain.risks import RiskLevel
from mayhem.infra.ranking import (
    W_CRIT,
    W_DIV,
    W_INFO,
    W_RECALL,
    RankedCell,
    RankInputs,
    rank,
    score,
)

_CELLS = tuple(
    CoverageCell(
        target=target,
        fault_kind=fault,
        execution_context="container",
        parameter_band=band,
    )
    for target, fault, band in (
        ("api", "net.delay", "default"),
        ("api", "cpu.spike", "default"),
        ("worker", "fs.fill", "small"),
        ("worker", "fs.fill", "large"),
        ("db", "mem.pressure", "default"),
    )
)


def _state_map(*keyed: tuple[str, CellState]) -> dict[str, CellState]:
    return dict(keyed)


def test_score_follows_weighted_formula() -> None:
    inputs = RankInputs(info=1.0, criticality=1.0, diversity=0.5, risk_rank=2)
    assert score(inputs) == 1.0 * 1.0 + 0.4 * 1.0 + 0.2 * 0.5


def test_rank_twice_is_identical() -> None:
    state_map: dict[str, CellState] = {}
    division_map: dict[str, int] = {}
    criticality_map: dict[str, float] = {}
    risk_map: dict[str, RiskLevel] = {}
    first = rank(
        _CELLS,
        state_map=state_map,
        division_map=division_map,
        criticality_map=criticality_map,
        risk_map=risk_map,
    )
    second = rank(
        _CELLS,
        state_map=state_map,
        division_map=division_map,
        criticality_map=criticality_map,
        risk_map=risk_map,
    )
    assert first == second
    assert [rc.cell.key for rc in first] == [rc.cell.key for rc in second]


def test_rank_is_rng_free_and_pure() -> None:
    state_map: dict[str, CellState] = {}
    division_map: dict[str, int] = {}
    criticality_map: dict[str, float] = {}
    risk_map: dict[str, RiskLevel] = {}
    a = rank(
        _CELLS,
        state_map=state_map,
        division_map=division_map,
        criticality_map=criticality_map,
        risk_map=risk_map,
    )
    b = rank(
        list(reversed(_CELLS)),
        state_map=state_map,
        division_map=division_map,
        criticality_map=criticality_map,
        risk_map=risk_map,
    )
    # Reordering the input never changes the output order (sort is by score).
    assert [rc.cell.key for rc in a] == [rc.cell.key for rc in b]


def test_only_unknown_cells_rank() -> None:
    recorded = {
        _CELLS[0].key: CellState.COVERED,
        _CELLS[1].key: CellState.BLOCKED,
        _CELLS[2].key: CellState.INCONCLUSIVE,
    }
    ranked = rank(
        _CELLS,
        state_map=recorded,
        division_map={},
        criticality_map={},
        risk_map={},
    )
    assert all(rc.cell.key not in recorded for rc in ranked)

    ranked_keys = {rc.cell.key for rc in ranked}
    assert _CELLS[3].key in ranked_keys
    assert _CELLS[4].key in ranked_keys


def test_risk_breaks_ties_high_below_low() -> None:
    # Force equal scores: same info/criticality/diversity by controlling the
    # division (no covered siblings) and criticality maps, then only differ on
    # risk so the sort must separate them deterministically.
    risk_map = {
        "net.delay": RiskLevel.HIGH,
        "cpu.spike": RiskLevel.LOW,
    }
    criticality_map = dict.fromkeys(("api", "worker", "db"), 1.0)
    ranked = rank(
        _CELLS[:2],  # api/net.delay (HIGH) vs api/cpu.spike (LOW)
        state_map={},
        division_map={},
        criticality_map=criticality_map,
        risk_map=risk_map,
    )
    assert len(ranked) == 2
    by_fault = {rc.cell.fault_kind: rc for rc in ranked}
    assert by_fault["cpu.spike"].factors["risk_rank"] < by_fault["net.delay"].factors["risk_rank"]
    # LOW-risk cell must appear before the equal-score HIGH-risk cell.
    assert ranked[0].cell.fault_kind == "cpu.spike"


def test_ranked_cells_carry_explain_factors() -> None:
    ranked = rank(
        _CELLS,
        state_map={},
        division_map={},
        criticality_map={"api": 2.0},
        risk_map={},
    )
    assert len(ranked) == len(_CELLS)
    for rc in ranked:
        assert set(rc.factors) == {"info", "criticality", "diversity", "risk_rank", "recall"}
        expected = (
            W_INFO * rc.factors["info"]
            + W_CRIT * rc.factors["criticality"]
            + W_DIV * rc.factors["diversity"]
            + W_RECALL * rc.factors["recall"]
        )
        assert rc.score == expected
    api = next(rc for rc in ranked if rc.cell.target == "api")
    assert api.factors["criticality"] == 2.0


def test_diversity_penalizes_cells_sharing_covered_category() -> None:
    # net.delay and cpu.spike share... no: net.delay → NETWORK, cpu.spike → CPU.
    # A covered cell in NETWORK makes a fresh NETWORK cell less diverse.
    division_map = {"network": 2}
    ranked = rank(
        _CELLS[:2],
        state_map={},
        division_map=division_map,
        criticality_map={"api": 1.0},
        risk_map={},
    )
    by_fault = {rc.cell.fault_kind: rc for rc in ranked}
    assert by_fault["net.delay"].score < by_fault["cpu.spike"].score
    assert by_fault["net.delay"].factors["diversity"] == 1.0 / 3.0


def test_criticality_lifts_topology_signalled_targets() -> None:
    criticality_map = {"db": 3.0}
    ranked = rank(
        _CELLS,
        state_map={},
        division_map={},
        criticality_map=criticality_map,
        risk_map={},
    )
    assert isinstance(ranked[0], RankedCell)
    assert ranked[0].cell.target == "db"
    assert ranked[0].factors["criticality"] == 3.0
