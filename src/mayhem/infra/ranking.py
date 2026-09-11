"""Deterministic cell ranking for ``next``/explore ordering (feat-3 §7).

Pure and RNG-free: identical inputs always produce the identical order.
Risk is a constraint and tie-breaker, never a primary objective — after
novelty (unknown-first), candidates score on informative value, target
criticality, then fault-category diversity (§7.2).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mayhem.domain.faults import FaultCategory
from mayhem.domain.risks import RiskLevel

if TYPE_CHECKING:
    from collections.abc import Mapping

    from mayhem.domain.coverage import CellState, CoverageCell

# §7.2 weights.
W_INFO = 1.0
W_CRIT = 0.4
W_DIV = 0.2

# Session memory boost for cells sharing target/fault with recent failures.
W_RECALL = 0.3


@dataclass(frozen=True)
class RankInputs:
    """Per-cell inputs to the scoring function (§7.2)."""

    info: float
    criticality: float
    diversity: float
    risk_rank: int


@dataclass(frozen=True)
class RankedCell:
    """A cell with its deterministic score and the --explain factors."""

    cell: CoverageCell
    score: float
    factors: dict[str, float] = field(default_factory=dict)


def score(inputs: RankInputs) -> float:
    """§7.2 score: ``w_info * info + w_crit * criticality + w_div * diversity``."""
    return W_INFO * inputs.info + W_CRIT * inputs.criticality + W_DIV * inputs.diversity


def _information_value(
    cell: CoverageCell,
    cells: tuple[CoverageCell, ...],
    division_map: Mapping[str, int],
) -> float:
    """§7.2 I(cell): 1.0 baseline for never-tested cells, adjusted by the
    fault's catalog parameterized variety (distinct bands observed in the
    landscape) and sibling-category history (covered cells in the parent
    category make a fresh cell marginally less novel)."""
    baseline = 1.0
    variety = len({c.parameter_band for c in cells if c.fault_kind == cell.fault_kind})
    variety_bonus = 0.1 * min(variety - 1, 5)
    category = FaultCategory.from_fault_id(cell.fault_kind).value
    sibling_penalty = 0.1 if division_map.get(category, 0) > 0 else 0.0
    return baseline + variety_bonus - sibling_penalty


def _diversity(cell: CoverageCell, division_map: Mapping[str, int]) -> float:
    """§7.2 D(cell): 1/(1+covered cells in the same fault category)."""
    category = FaultCategory.from_fault_id(cell.fault_kind).value
    return 1.0 / (1.0 + division_map.get(category, 0))


def _default_risk_rank(cell: CoverageCell, risk_map: Mapping[str, RiskLevel]) -> int:
    return risk_map.get(cell.fault_kind, RiskLevel.MEDIUM).rank


def _recall_bonus(
    cell: CoverageCell,
    failed_targets: frozenset[str],
    failed_faults: frozenset[str],
) -> float:
    """Session memory bonus: cells sharing a target or fault with recent failures.

    Returns 0.5 when the cell's target was recently failed, 0.3 when its
    fault_kind was recently failed, 0.6 when both match, and 0.0 otherwise.
    This biases ``next`` toward retesting problem areas without overriding
    the novelty-first ranking (the bonus is small relative to W_INFO).
    """
    target_match = cell.target in failed_targets
    fault_match = cell.fault_kind in failed_faults
    if target_match and fault_match:
        return 0.6
    if target_match:
        return 0.5
    if fault_match:
        return 0.3
    return 0.0


def rank(
    cells: tuple[CoverageCell, ...] | list[CoverageCell],
    *,
    state_map: Mapping[str, CellState],
    division_map: Mapping[str, int],
    criticality_map: Mapping[str, float],
    risk_map: Mapping[str, RiskLevel],
    failed_targets: frozenset[str] = frozenset(),
    failed_faults: frozenset[str] = frozenset(),
) -> tuple[RankedCell, ...]:
    """Rank ``cells`` deterministically, unknown cells only.

    A cell ranks iff its key is absent from ``state_map`` (missing = unknown
    per the repository contract). Blocked and other recorded states are never
    suggested (§7.1). Tie-breaks: score desc → lower risk rank → lexicographic
    ``cell.key`` — all seed-stable.

    When ``failed_targets`` or ``failed_faults`` are provided, cells sharing
    a target or fault_kind with recent failures receive a small recall bonus
    (session memory, feat-2 §5).
    """
    ranked: list[RankedCell] = []
    for cell in cells:
        if state_map.get(cell.key) is not None:
            continue
        info = _information_value(cell, tuple(cells), division_map)
        criticality = float(criticality_map.get(cell.target, 1.0))
        diversity = _diversity(cell, division_map)
        risk_rank = _default_risk_rank(cell, risk_map)
        recall = _recall_bonus(cell, failed_targets, failed_faults)
        s = W_INFO * info + W_CRIT * criticality + W_DIV * diversity + W_RECALL * recall
        ranked.append(
            RankedCell(
                cell=cell,
                score=s,
                factors={
                    "info": info,
                    "criticality": criticality,
                    "diversity": diversity,
                    "risk_rank": float(risk_rank),
                    "recall": recall,
                },
            )
        )
    ranked.sort(key=lambda rc: (-rc.score, rc.factors["risk_rank"], rc.cell.key))
    return tuple(ranked)
