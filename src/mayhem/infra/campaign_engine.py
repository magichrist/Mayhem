"""M5 campaign execution engine (ADR-M5-4, M5 Phase 5.4).

Lifecycle: init → iterate (generate/select → gate → run) → stop.

Stop on the first of: coverage target reached, budget (max_runs) exhausted,
deadline passed, or an explicit stop-condition. A ``supervised`` campaign
never runs a drill until the injected approver approves it; denied candidates
are skipped and counted, never executed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from mayhem.domain.candidates import CandidateGate
from mayhem.domain.coverage import CoverageCell
from mayhem.domain.m5_campaign import (
    ApproveDecision,
    CampaignExecutionManifest,
    CampaignManifestEntry,
    CampaignMode,
    CampaignProgress,
    CampaignState,
    M5Campaign,
    StopReason,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from mayhem.domain.candidates import CandidateDecision, ExperimentCandidate
    from mayhem.infra.candidate_gates import CandidateGatePipeline

# A single executed drill result: the Run that ran, its Outcome, and the
# coverage cell it explored.
DrillResult = tuple[str, str, CoverageCell]  # (run_id, outcome_id, cell)


class CandidateSource(Protocol):
    """Yields candidates for the campaign to consider (in-order, may exhaust)."""

    def next_candidate(self) -> ExperimentCandidate | None: ...


class Approver(Protocol):
    """Gate for ``supervised`` mode: must explicitly approve before running."""

    def approve(self, candidate: ExperimentCandidate) -> bool: ...


class Runner(Protocol):
    """Executes a candidate to a Run/Outcome pair + the cell it covered."""

    def run(self, candidate: ExperimentCandidate) -> DrillResult: ...


@dataclass
class CampaignStopError(Exception):
    """Raised when the loop hits a stop condition."""

    reason: StopReason


class M5CampaignEngine:
    """Deterministic iterate-until-stop engine for one ADR-M5-4 campaign."""

    def __init__(
        self,
        campaign: M5Campaign,
        *,
        source: CandidateSource,
        gates: CandidateGatePipeline,
        runner: Runner,
        approver: Approver | None = None,
        coverage_target_fn: Callable[[M5Campaign, CampaignProgress], int] | None = None,
        blast_check: Callable[[ExperimentCandidate, CampaignProgress], str | None] | None = None,
        rationale_fn: Callable[[ExperimentCandidate], str] | None = None,
        now_epoch_s: Callable[[], float] = time.time,
        state_transition_fn: Callable[[CampaignState, CampaignState], None] | None = None,
    ) -> None:
        self.campaign = campaign
        self._source = source
        self._gates = gates
        self._runner = runner
        self._approver = approver
        self._coverage_target_fn = coverage_target_fn or (lambda c, p: c.coverage_target)
        self._blast_check = blast_check
        self._rationale_fn = rationale_fn
        self._now = now_epoch_s
        self.progress = CampaignProgress()
        self.state_stack: list[StopReason] = []
        self.covered_cells: set[str] = set()
        self._stop_requested = False
        self._state_transition_fn = state_transition_fn
        self.state = CampaignState.DRAFT
        self.recovery_status = "not_started"

    def _transition(self, new_state: CampaignState) -> None:
        allowed = {
            CampaignState.DRAFT: {CampaignState.APPROVED, CampaignState.ABORTED},
            CampaignState.APPROVED: {CampaignState.RUNNING, CampaignState.ABORTED},
            CampaignState.RUNNING: {
                CampaignState.PAUSED,
                CampaignState.COMPLETED,
                CampaignState.ABORTED,
            },
            CampaignState.PAUSED: {CampaignState.RUNNING, CampaignState.ABORTED},
            CampaignState.COMPLETED: {CampaignState.ARCHIVED},
            CampaignState.ABORTED: {CampaignState.ARCHIVED},
            CampaignState.ARCHIVED: set(),
        }
        if new_state not in allowed[self.state]:
            raise ValueError(f"invalid campaign transition {self.state.value} -> {new_state.value}")
        old_state = self.state
        self.state = new_state
        if self._state_transition_fn is not None:
            self._state_transition_fn(old_state, new_state)

    def start(self) -> None:
        if self.state is CampaignState.DRAFT:
            self._transition(CampaignState.APPROVED)
        if self.state is CampaignState.APPROVED:
            self._transition(CampaignState.RUNNING)
        self.recovery_status = "ready"

    def pause(self) -> None:
        self._transition(CampaignState.PAUSED)
        self.recovery_status = "paused"

    def resume(self) -> None:
        if self.state is not CampaignState.PAUSED:
            raise ValueError(f"cannot resume campaign in {self.state.value!r} state")
        self._transition(CampaignState.RUNNING)
        self.recovery_status = "resumed"

    def plan(self) -> CampaignExecutionManifest:
        source_candidates = getattr(self._source, "candidates", None)
        if source_candidates is None:
            source_candidates = getattr(self._source, "_items", ())
        entries = tuple(
            CampaignManifestEntry(
                candidate_id=candidate.id,
                target=candidate.target,
                fault=candidate.primary_fault,
            )
            for candidate in source_candidates
        )
        return CampaignExecutionManifest(
            campaign_id=self.campaign.id,
            entries=entries,
            engine_policy=self.campaign.engine_policy,
            target_profiles=self.campaign.target_profiles,
            budget=(
                self.campaign.budget if self.campaign.budget is not None else self.campaign.max_runs
            ),
            deadline_epoch_s=self.campaign.deadline_epoch_s,
            stop_conditions=self.campaign.stop_conditions or (self.campaign.stop_condition,)
            if self.campaign.stop_condition
            else self.campaign.stop_conditions,
        )

    def request_stop(self) -> None:
        """Explicitly request a manual stop (surfaces STOP_CONDITION)."""
        self._stop_requested = True

    # ── Stop-condition primitives ─────────────────────────────────────
    def _budget_exhausted(self) -> bool:
        return self.progress.runs_executed >= self.campaign.max_runs

    def _deadline_passed(self) -> bool:
        return (
            self.campaign.deadline_epoch_s is not None
            and self._now() > self.campaign.deadline_epoch_s
        )

    def _coverage_reached(self) -> bool:
        target = self._coverage_target_fn(self.campaign, self.progress)
        return len(self.covered_cells) >= target

    def _check_stop(self, *, raise_on_stop: bool = True) -> StopReason | None:
        if self._budget_exhausted():
            reason = StopReason.BUDGET_EXHAUSTED
        elif self._deadline_passed():
            reason = StopReason.DEADLINE_PASSED
        elif self._explicit_stop():
            reason = StopReason.STOP_CONDITION
        elif self._coverage_reached():
            reason = StopReason.COVERAGE_REACHED
        else:
            return None
        if raise_on_stop:
            raise CampaignStopError(reason)
        return reason

    def _explicit_stop(self) -> bool:
        # The caller triggers an explicit stop by raising the flag through the
        # ``stop_condition`` handle; here a non-empty free-form stop condition
        # with no remaining candidates is surfaced as a manual stop signal.
        return bool(self._stop_requested)

    # ── Iteration ─────────────────────────────────────────────────────
    def _remember_cell(self, cell: CoverageCell) -> None:
        self.covered_cells.add(cell.key)

    def _approval_required(self) -> bool:
        return self.campaign.mode is CampaignMode.SUPERVISED

    def iterate(self) -> CampaignProgress:
        """Advance one step (one candidate considered).

        Returns the progress snapshot after the step. Raises ``CampaignStopError``
        when a stop condition is reached.
        """
        self._check_stop()
        candidate = self._source.next_candidate()
        if candidate is None:
            # No more candidates to try — treat as budget-exhausted equivalent.
            self.state_stack.append(StopReason.BUDGET_EXHAUSTED)
            raise CampaignStopError(StopReason.BUDGET_EXHAUSTED)

        decision: CandidateDecision = self._gates.gate(candidate)
        if decision.rejected:
            if decision.gate is CandidateGate.RESOURCE_CONFLICT:
                # A violating candidate (in-flight conflict, over blast budget)
                # is a hard bound-abort: never executed out of bounds.
                self.progress.candidates_aborted += 1
                self.progress.record(
                    candidate.id,
                    ApproveDecision.DENIED,
                    rationale=decision.reason or "resource conflict",
                )
                raise CampaignStopError(StopReason.RESOURCE_CONFLICT)
            self.progress.candidates_rejected += 1
            # A rejected candidate is not executed and does not consume budget.
            return self.progress

        if self._approval_required():
            self.progress.candidates_pending_approval += 1
            rationale = self._rationale_fn(candidate) if self._rationale_fn else ""
            self.progress.record(candidate.id, ApproveDecision.PENDING, rationale=rationale)
            approved = self._approver.approve(candidate) if self._approver is not None else False
            if not approved:
                # denied candidates are skipped and recorded, never run.
                self.progress.candidates_denied += 1
                self.progress.record(candidate.id, ApproveDecision.DENIED, rationale=rationale)
                return self.progress
            self.progress.record(candidate.id, ApproveDecision.APPROVED, rationale=rationale)

        # Protective bound-check (autonomous): blast-radius / resource cap.
        if self._blast_check is not None:
            blast_reason = self._blast_check(candidate, self.progress)
            if blast_reason is not None:
                self.progress.candidates_aborted += 1
                self.progress.record(
                    candidate.id, ApproveDecision.DENIED, rationale=f"bound-abort: {blast_reason}"
                )
                raise CampaignStopError(StopReason.RESOURCE_CONFLICT)

        _run_id, _outcome_id, cell = self._runner.run(candidate)
        self.progress.runs_executed += 1
        self._remember_cell(cell)

        # Re-check stop after this run consumed budget and covered a cell.
        self._check_stop()
        return self.progress

    def run_until_stop(self) -> StopReason:
        """Drive the loop until a stop condition is met; return it."""
        if self.state is CampaignState.DRAFT:
            self.start()
        while True:
            try:
                self.iterate()
            except CampaignStopError as stop:
                self.state_stack.append(stop.reason)
                if stop.reason is StopReason.RESOURCE_CONFLICT:
                    self._transition(CampaignState.ABORTED)
                else:
                    self._transition(CampaignState.COMPLETED)
                return stop.reason
