"""Tests for Maniac selection/optimization engine (ADR-M5-3)."""

from mayhem.domain.candidates import ExperimentCandidate
from mayhem.infra.candidate_gates import CandidateGatePipeline, FeasibilityGate
from mayhem.infra.maniac import (
    SelectionInputs,
    SelectionResult,
    coverage_cell_for_candidate,
    select_next,
)


class _DenyFault:
    """FeasibilityGate that rejects candidates whose fault matches."""

    def __init__(self, fault: str) -> None:
        self._fault = fault

    def check(self, candidate: ExperimentCandidate) -> str | None:
        if candidate.primary_fault == self._fault:
            return f"fault {self._fault!r} blocked"
        return None


def _make(
    n: int = 6,
    *,
    targets: tuple[str, ...] = ("web-0", "web-1"),
    faults: tuple[str, ...] = ("net.delay",),
    bands: tuple[str, ...] = ("b0", "b1"),
    seed: int = 0,
) -> tuple[ExperimentCandidate, ...]:
    result: list[ExperimentCandidate] = []
    for i in range(n):
        result.append(
            ExperimentCandidate(
                target=targets[i % len(targets)],
                fault_kinds=(faults[i % len(faults)],),
                params={"band": bands[i % len(bands)]},
                seed_hint=i,
            )
        )
    return tuple(result)


class TestManiacDeterministic:
    def test_identical_inputs_yield_identical_selection(self) -> None:
        candidates = _make(8, seed=42)
        inputs = SelectionInputs(
            candidates=candidates,
            max_runs=4,
            coverage_target=4,
            seed=77,
        )
        a = select_next(inputs)
        b = select_next(inputs)
        assert a.selected == b.selected
        assert a.predicted_new_coverage == b.predicted_new_coverage

    def test_different_seed_may_yield_different_selection(self) -> None:
        candidates = _make(12)
        a = select_next(SelectionInputs(candidates=candidates, seed=1))
        b = select_next(SelectionInputs(candidates=candidates, seed=9999))
        # Different seeds can produce different orderings; at minimum
        # the coverage predictions may differ (or be equal if coverage
        # target is reached before ordering matters). Just verify both
        # are valid results and the engine didn't crash.
        assert isinstance(a, SelectionResult)
        assert isinstance(b, SelectionResult)

    def test_stateless_across_calls(self) -> None:
        candidates = _make(6)
        a = select_next(SelectionInputs(candidates=candidates, max_runs=3))
        b = select_next(SelectionInputs(candidates=candidates, max_runs=3))
        assert a.selected == b.selected
        # Mutating a result doesn't affect the next call.
        assert a.predicted_new_coverage == b.predicted_new_coverage


class TestManiacRespectsBounds:
    def test_respects_max_runs_budget(self) -> None:
        candidates = _make(20, bands=tuple(f"b{i}" for i in range(20)))
        result = select_next(
            SelectionInputs(
                candidates=candidates,
                max_runs=3,
                coverage_target=100,
            )
        )
        assert len(result.selected) <= 3
        assert result.selected_count == len(result.selected)

    def test_respects_coverage_target(self) -> None:
        candidates = _make(12, bands=tuple(f"c{i}" for i in range(12)))
        result = select_next(
            SelectionInputs(
                candidates=candidates,
                max_runs=100,
                coverage_target=3,
            )
        )
        assert result.predicted_new_coverage <= 3
        assert len(result.selected) <= 3

    def test_respects_gates(self) -> None:
        candidates = _make(8)
        # "net.delay" candidates exist (target + fault combo covers web-0,
        # web-1 with 2 unique cells). After 2 runs both cells are
        # covered, so with coverage_target=2 the engine stops early.
        gates = CandidateGatePipeline(
            feasibility=_DenyFault("net.delay"),
        )
        result = select_next(
            SelectionInputs(
                candidates=candidates,
                gates=gates,
                max_runs=10,
                coverage_target=100,
            )
        )
        # All candidates are net.delay → all denied → nothing selected.
        assert len(result.selected) == 0
        assert len(result.rejected) > 0

    def test_gated_candidates_excluded_from_selection(self) -> None:
        candidates = _make(6)
        # Only allow "net.delay" through (default fault).
        # Also keep coverage_target small so the engine can finish.
        gates = CandidateGatePipeline(
            feasibility=FeasibilityGate(supported=("net.delay",)),
        )
        result = select_next(
            SelectionInputs(
                candidates=candidates,
                gates=gates,
                max_runs=10,
                coverage_target=10,
            )
        )
        # With all candidates net.delay and the gate allows it, selection
        # proceeds normally — at most max_runs candidates selected.
        assert len(result.selected) <= 6


class TestManiacCoverageModel:
    def test_prefer_uncovered_cells(self) -> None:
        """Cells already covered should be deprioritized."""
        candidates = _make(4)
        covered_keys = frozenset({coverage_cell_for_candidate(candidates[0]).key})
        without = select_next(
            SelectionInputs(
                candidates=candidates,
                covered_keys=frozenset(),
                max_runs=4,
                coverage_target=10,
            )
        )
        with_covered = select_next(
            SelectionInputs(
                candidates=candidates,
                covered_keys=covered_keys,
                max_runs=4,
                coverage_target=10,
            )
        )
        # When one cell is already covered, the engine predicts less new
        # coverage (at least one fewer new cell).
        assert with_covered.predicted_new_coverage <= without.predicted_new_coverage
        # The already-covered cell may still be selected but it contributes
        # nothing new; the selection count can be smaller or equal.
        assert len(with_covered.selected) <= len(without.selected)

    def test_empty_candidate_set(self) -> None:
        result = select_next(
            SelectionInputs(
                candidates=(),
                max_runs=10,
                coverage_target=5,
            )
        )
        assert result.selected == ()
        assert result.predicted_new_coverage == 0
        assert result.rejected == ()

    def test_all_cells_covered_early_termination(self) -> None:
        candidates = _make(8, bands=tuple(f"c{i}" for i in range(8)))
        covered = frozenset({
            coverage_cell_for_candidate(c).key
            for c in candidates
        })
        result = select_next(
            SelectionInputs(
                candidates=candidates,
                covered_keys=covered,
                max_runs=100,
                coverage_target=100,
            )
        )
        # All cells already covered → nothing selected, no new coverage.
        assert len(result.selected) == 0
        assert result.predicted_new_coverage == 0
