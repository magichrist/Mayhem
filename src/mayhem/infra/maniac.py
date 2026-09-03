"""Maniac selection/optimization engine (ADR-M5-3, M5 Phase 5.5).

Maniac chooses *which experiment to run next* from the candidate set, grounded
in recorded outcome coverage and the campaign's bounds. It is:

- **stateless** across campaign runs (no in-memory carry-over; every selection
  is re-derived from its explicit inputs),
- **deterministic and reproducible**: identical inputs (candidates, covered
  cells, gates, bounds, seed) always yield the identical selection,
- **knowledge-transferable**: recorded coverage from prior campaigns is passed
  in explicitly, so learnings carry across campaign boundaries.

Selection is a greedy coverage-maximizing walk: gate every candidate, prefer
cells not yet covered, and stop once the budget or coverage target is met.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.domain.coverage import CoverageCell
from mayhem.infra.candidate_gates import CandidateGatePipeline

if TYPE_CHECKING:
    from mayhem.domain.candidates import CandidateDecision, ExperimentCandidate


def coverage_cell_for_candidate(candidate: ExperimentCandidate) -> CoverageCell:
    """The coverage cell a candidate explores, derived deterministically."""
    band = str(candidate.params.get("band") or "default") if candidate.params else "default"
    return CoverageCell(
        candidate.target,
        candidate.primary_fault,
        candidate.execution_context,
        band,
    )


@dataclass(frozen=True)
class SelectionInputs:
    """Every input Maniac is allowed to look at (no hidden state)."""

    candidates: tuple[ExperimentCandidate, ...]
    covered_keys: frozenset[str] = frozenset()
    gates: CandidateGatePipeline | None = None
    max_runs: int = 100
    coverage_target: int = 1
    seed: int = 0


@dataclass(frozen=True)
class SelectionResult:
    selected: tuple[ExperimentCandidate, ...]
    rejected: tuple[CandidateDecision, ...] = ()
    predicted_new_coverage: int = 0

    @property
    def selected_count(self) -> int:
        return len(self.selected)


def select_next(inputs: SelectionInputs) -> SelectionResult:
    """Pure, deterministic greedy selection (stateless, reproducible)."""
    gates = inputs.gates if inputs.gates is not None else CandidateGatePipeline()
    covered = set(inputs.covered_keys)

    accepted: list[ExperimentCandidate] = []
    rejected: list[CandidateDecision] = []
    for cand in inputs.candidates:
        decision = gates.gate(cand)
        if decision.accepted:
            accepted.append(cand)
        else:
            rejected.append(decision)

    # Deterministic ordering: seeded random tie-break over the candidates,
    # then rank so that already-covered cells come last (coverage first).
    rng = random.Random(inputs.seed)
    ordered = sorted(accepted, key=lambda c: rng.random())
    uncovered_first = sorted(
        ordered,
        key=lambda c: coverage_cell_for_candidate(c).key in covered,
    )

    selected: list[ExperimentCandidate] = []
    covered_now = set(covered)
    for cand in uncovered_first:
        if len(selected) >= inputs.max_runs:
            break
        if len(covered_now) >= inputs.coverage_target:
            break
        cell = coverage_cell_for_candidate(cand)
        covered_now.add(cell.key)
        selected.append(cand)

    projected = len(covered_now) - len(covered)
    return SelectionResult(
        selected=tuple(selected),
        rejected=tuple(rejected),
        predicted_new_coverage=projected,
    )
