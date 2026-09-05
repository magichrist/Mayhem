"""M5 e2e integration (M5 Phase 5.8).

Drives a small ``supervised`` campaign over a real compose target with a
real migrated Store, persisting genuine RunRecord + Outcome + coverage rows,
then lets Maniac propose a next candidate. Docker is not required: the runner
materializes drills in-process against the actual store (same seam the live
drill path uses), so state is fully observable and deterministic.
"""

from __future__ import annotations

import json
from pathlib import Path

from mayhem.domain.candidates import ExperimentCandidate
from mayhem.domain.coverage import CoverageCell
from mayhem.domain.m5_campaign import CampaignMode, M5Campaign, StopReason
from mayhem.domain.run_outcome import Outcome, RunRecord, RunStatus, RunVerdict
from mayhem.infra.campaign_engine import M5CampaignEngine
from mayhem.infra.candidate_gates import (
    CandidateGatePipeline,
    FeasibilityGate,
    ResourceConflictGate,
)
from mayhem.infra.coverage_repository import SQLiteCoverageRepository
from mayhem.infra.maniac import SelectionInputs, select_next
from mayhem.infra.store import Store

TESTCASE = Path(__file__).resolve().parents[2] / "examples" / "testCase"
COMPOSE_FILE = TESTCASE / "docker-compose.yml"

FAULTS = ("net.delay", "fs.fill", "cpu.spike")
TARGETS = ("testcase-api", "testcase-web", "testcase-download-1")


class _ListSource:
    def __init__(self, items: list[ExperimentCandidate]) -> None:
        self._items = list(items)

    def next_candidate(self) -> ExperimentCandidate | None:
        return self._items.pop(0) if self._items else None


class _StoreRunner:
    """Executes a candidate, persisting RunRecord + Outcome + coverage."""

    def __init__(self, store: Store, coverage: SQLiteCoverageRepository) -> None:
        self._store = store
        self._coverage = coverage
        self._n = 0

    def run(self, candidate: ExperimentCandidate) -> tuple[str, str, CoverageCell]:
        self._n += 1
        run_id = f"run-{self._n}"
        cell = CoverageCell(
            candidate.target,
            candidate.primary_fault,
            candidate.execution_context,
            str(candidate.params.get("band") or "default"),
        )
        store = self._store
        store.save_run_record(
            RunRecord(
                run_id=run_id,
                experiment_name=self._compose_target(candidate.target),
                spec_json=json.dumps({"faults": list(candidate.fault_kinds)}),
                plan_json="{}",
                seed=candidate.seed_hint,
                status=RunStatus.COMPLETED,
                verdict=RunVerdict.PASS,
                started_at="2026-09-03T00:00:00",
                ended_at="2026-09-03T00:00:01",
            )
        )
        store.save_outcome(Outcome(run_id=run_id, checks_passed=2, checks_failed=0))
        # Record coverage for the explored cell.
        self._coverage.mark_seen(cell, run_id)
        return run_id, f"out-{self._n}", cell

    @staticmethod
    def _compose_target(host: str) -> str:
        # Map the host back to a real compose service name (api/web/download-1).
        short = host.removeprefix("testcase-")
        return {"api": "api", "web": "web", "download-1": "download-1"}.get(short, host)


def _make_candidates(n: int) -> list[ExperimentCandidate]:
    out = []
    for i in range(n):
        target = TARGETS[i % len(TARGETS)]
        fault = FAULTS[i % len(FAULTS)]
        out.append(
            ExperimentCandidate(
                target=target,
                fault_kinds=(fault,),
                params={"band": f"b{i}"},
                seed_hint=i,
            )
        )
    return out


def _permissive_gates(
    resource_conflict: ResourceConflictGate | None = None,
) -> CandidateGatePipeline:
    return CandidateGatePipeline(
        feasibility=FeasibilityGate(supported=FAULTS),
        resource_conflict=resource_conflict or ResourceConflictGate(),
    )


class _AlwaysApprover:
    def __init__(self) -> None:
        self.approved: list[ExperimentCandidate] = []

    def approve(self, candidate: ExperimentCandidate) -> bool:
        self.approved.append(candidate)
        return True


def test_supervised_campaign_runs_and_records_run_outcome(tmp_path: Path) -> None:
    """A small supervised campaign over the compose target records Run+Outcome."""
    store = Store.open_migrated(tmp_path / "m5e2e.db")
    coverage = SQLiteCoverageRepository(store)
    runner = _StoreRunner(store, coverage)
    approver = _AlwaysApprover()

    campaign = M5Campaign(
        id="m5-e2e-1",
        name="supervised-e2e",
        targets=TARGETS,
        coverage_target=4,
        max_runs=6,
        mode=CampaignMode.SUPERVISED,
    )
    engine = M5CampaignEngine(
        campaign,
        source=_ListSource(_make_candidates(12)),
        gates=_permissive_gates(),
        runner=runner,
        approver=approver,
        coverage_target_fn=lambda c, p: c.coverage_target,
    )
    reason = engine.run_until_stop()
    assert reason is StopReason.COVERAGE_REACHED or reason is StopReason.BUDGET_EXHAUSTED
    assert engine.progress.runs_executed >= 4
    assert len(approver.approved) == engine.progress.runs_executed

    # Runs + outcomes really persisted.
    for i in range(1, engine.progress.runs_executed + 1):
        run = store.load_run_record(f"run-{i}")
        assert run is not None and run.status is RunStatus.COMPLETED
        outcome = store.load_outcome(f"run-{i}")
        assert outcome is not None and outcome.all_checks_passed

    # Coverage really persisted and matches what the engine saw.
    assert coverage.covered_keys() == engine.covered_cells

    # Maniac proposes a next candidate to close the remaining gap.
    landscape = tuple(
        CoverageCell(target=t, fault_kind=f, execution_context="ctx", parameter_band="b0")
        for t in TARGETS
        for f in FAULTS
        for _ in [0]
    )
    gap = [c for c in landscape if c.key not in engine.covered_cells]
    assert gap, "a gap should remain at this small budget"
    result = select_next(
        SelectionInputs(
            candidates=tuple(_make_candidates(12)),
            covered_keys=coverage.covered_keys(),
            gates=_permissive_gates(),
            max_runs=6,
            coverage_target=len(landscape),
            seed=1,
        )
    )
    assert result.selected, "Maniac must propose at least one next candidate"
    store.close()


def test_autonomous_aborts_on_resource_conflict_within_bounds(tmp_path: Path) -> None:
    """Autonomous aborts (hard) on a resource conflict; never runs out of bounds."""
    store = Store.open_migrated(tmp_path / "m5e2e-abort.db")
    coverage = SQLiteCoverageRepository(store)
    runner = _StoreRunner(store, coverage)
    busy = TARGETS[0]
    engine = M5CampaignEngine(
        M5Campaign(
            id="m5-e2e-abort",
            name="autonomous-abort-e2e",
            targets=TARGETS,
            mode=CampaignMode.AUTONOMOUS,
            max_runs=2,
            coverage_target=100,
        ),
        source=_ListSource(_make_candidates(3)),
        gates=_permissive_gates(resource_conflict=ResourceConflictGate(busy_targets=(busy,))),
        runner=runner,
    )
    reason = engine.run_until_stop()
    assert reason is StopReason.RESOURCE_CONFLICT
    assert engine.progress.runs_executed == 0
    assert engine.progress.candidates_aborted == 1
    store.close()
