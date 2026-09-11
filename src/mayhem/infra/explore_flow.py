"""Explore-flow — the core explore loop (plan-feat-2 §B).

``explore_flow`` generates candidates, runs them through gates, optionally
executes via CellRunner, and returns a summary.  It is **pure orchestration**:
no click, no TTY, no I/O — output formatting belongs to the CLI layer.

Key seams:
- ``SeededCandidateGenerator`` produces the ordered queue.
- ``CandidateGatePipeline`` filters gate-rejected cells.
- ``CellRunner`` executes (Invariant A).
- The session layer (Phase C) owns budget, deadline, and exit codes.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mayhem.domain.candidates import CandidateDecision, ExperimentCandidate
from mayhem.domain.coverage import CoverageCell
from mayhem.infra.candidate_generator import CandidateLandscape, SeededCandidateGenerator
from mayhem.infra.cell_runner import CellRunResult
from mayhem.infra.coverage_repository import SQLiteCoverageRepository
from mayhem.infra.maniac import coverage_cell_for_candidate

if TYPE_CHECKING:
    from mayhem.infra.cell_runner import CellRunner


@dataclass(frozen=True)
class ExploreQueueEntry:
    """A single entry in the ranked queue (for dry-run and session tracking)."""

    candidate: ExperimentCandidate
    cell: CoverageCell
    gate_decision: CandidateDecision | None = None  # None = not yet gated


@dataclass
class ExploreDryRun:
    """Result of a --dry-run explore: the ranked queue, no execution."""

    entries: tuple[ExploreQueueEntry, ...]
    total_candidates: int
    gate_rejected: int
    new_coverage_estimate: int = 0


@dataclass(frozen=True)
class ExploreRun:
    """Result of a live explore session: executed + blocked cells."""

    executed: tuple[CellRunResult, ...]
    blocked: tuple[CellRunResult, ...]
    denied: tuple[CandidateDecision, ...]  # supervised denies
    budget_used: int
    budget_limit: int
    stopped_early: bool = False  # compensation/recovery failure
    stop_reason: str = ""


@dataclass(frozen=True)
class ExploreSummary:
    """Combined summary for output formatting."""

    dry_run: ExploreDryRun | None = None
    run: ExploreRun | None = None


def build_queue(
    landscape: CandidateLandscape,
    *,
    seed: int = 0,
    covered_keys: frozenset[str] = frozenset(),
) -> tuple[ExperimentCandidate, ...]:
    """Generate the full ranked queue of candidates (§3.1.1 + §7 ranking).

    Uses ``SeededCandidateGenerator`` for deterministic Cartesian output,
    then filters to cells not yet covered (unknown cells get priority).
    """
    gen = SeededCandidateGenerator(landscape, seed=seed)
    all_candidates = list(gen.generate())
    # Filter to unknown cells (not yet covered) for priority.
    unknown: list[ExperimentCandidate] = []
    already_known: list[ExperimentCandidate] = []
    for c in all_candidates:
        cell = coverage_cell_for_candidate(c)
        if cell.key in covered_keys:
            already_known.append(c)
        else:
            unknown.append(c)
    # Unknown first, then already-known (for re-runs).
    return tuple(unknown + already_known)


def dry_run(
    landscape: CandidateLandscape,
    *,
    seed: int = 0,
    covered_keys: frozenset[str] = frozenset(),
    gate_pipeline: object | None = None,
) -> ExploreDryRun:
    """Execute the explore logic without running any drills (§3.1.8).

    Returns the ranked queue with gate results, no side effects.
    """
    from mayhem.infra.candidate_gates import CandidateGatePipeline
    from mayhem.infra.maniac import coverage_cell_for_candidate

    queue = build_queue(landscape, seed=seed, covered_keys=covered_keys)
    gates = gate_pipeline if isinstance(gate_pipeline, CandidateGatePipeline) else permissive_pipeline()

    entries: list[ExploreQueueEntry] = []
    rejected = 0
    new_cov = 0
    for candidate in queue:
        decision = gates.gate(candidate)
        cell = coverage_cell_for_candidate(candidate)
        entry = ExploreQueueEntry(
            candidate=candidate,
            cell=cell,
            gate_decision=decision,
        )
        entries.append(entry)
        if decision is not None and decision.rejected:
            rejected += 1
        elif cell.key not in covered_keys:
            new_cov += 1

    return ExploreDryRun(
        entries=tuple(entries),
        total_candidates=len(entries),
        gate_rejected=rejected,
        new_coverage_estimate=new_cov,
    )


def run_explore(
    landscape: CandidateLandscape,
    *,
    runner: CellRunner,
    coverage: SQLiteCoverageRepository,
    seed: int = 0,
    budget: int = 10,
    deadline_epoch: float | None = None,
    supervised: bool = False,
    gate_pipeline: object | None = None,
    approve_fn: object | None = None,
) -> ExploreRun:
    """Execute the explore loop: generate → gate → (approve) → execute.

    Parameters
    ----------
    landscape:
        The candidate generation landscape.
    runner:
        The CellRunner for executing cells.
    coverage:
        Coverage repository for state tracking.
    seed:
        RNG seed for deterministic generation.
    budget:
        Max number of cells to execute.
    deadline_epoch:
        Absolute deadline in epoch seconds (None = no deadline).
    supervised:
        If True, each accepted candidate requires user approval via approve_fn.
    gate_pipeline:
        Gate pipeline for safety/feasibility/resource checks.
    approve_fn:
        ``Callable[[ExperimentCandidate], bool]`` — returns True to approve,
        False to deny.  Required when ``supervised=True``.
    """
    from mayhem.infra.candidate_gates import CandidateGatePipeline

    covered_keys = coverage.covered_keys()
    queue = build_queue(landscape, seed=seed, covered_keys=covered_keys)
    gates = gate_pipeline if isinstance(gate_pipeline, CandidateGatePipeline) else permissive_pipeline()

    executed: list[CellRunResult] = []
    blocked: list[CellRunResult] = []
    denied: list[CandidateDecision] = []
    budget_used = 0
    stopped_early = False
    stop_reason = ""

    for candidate in queue:
        # Budget check
        if budget_used >= budget:
            break
        # Deadline check
        if deadline_epoch is not None and time.time() >= deadline_epoch:
            break

        cell = coverage_cell_for_candidate(candidate)
        # Already covered? Skip.
        if cell.key in covered_keys:
            continue

        # Gate check
        decision = gates.gate(candidate)
        if decision is not None and decision.rejected:
            denied.append(decision)
            result = runner.record_blocked(
                candidate,
                reason=f"{decision.gate.value}: {decision.reason}",
            )
            blocked.append(result)
            continue

        # Supervised approval
        if supervised:
            if approve_fn is None:
                raise ValueError("supervised mode requires approve_fn")
            approved = approve_fn(candidate)
            if not approved:
                from mayhem.domain.candidates import CandidateGate, CandidateStatus

                denied.append(
                    CandidateDecision(
                        candidate=candidate,
                        status=CandidateStatus.REJECTED,
                        gate=CandidateGate.SAFETY,
                        reason="supervised deny",
                    )
                )
                result = runner.record_blocked(
                    candidate,
                    reason="supervised: user denied",
                )
                blocked.append(result)
                continue

        # Execute
        result = runner.run(candidate)
        budget_used += 1

        if result.run_result is not None and result.run_result.status in ("failed", "aborted"):
            stopped_early = True
            stop_reason = f"run {result.run_id} ended with status {result.run_result.status}"

        executed.append(result)

    return ExploreRun(
        executed=tuple(executed),
        blocked=tuple(blocked),
        denied=tuple(denied),
        budget_used=budget_used,
        budget_limit=budget,
        stopped_early=stopped_early,
        stop_reason=stop_reason,
    )
