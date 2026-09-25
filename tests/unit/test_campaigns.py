"""Tests for campaign model (ADR-0022) and M5 campaign semantics (ADR-M5-4)."""

from collections.abc import Callable

import pytest

from mayhem.cli.campaign import _transition_row
from mayhem.domain.campaigns import (
    Campaign,
    CampaignExperiment,
    CampaignPolicy,
    CampaignSchedule,
    CampaignStatus,
    ExperimentOnFailure,
    can_transition,
    transition_campaign,
)
from mayhem.domain.candidates import ExperimentCandidate
from mayhem.domain.coverage import CoverageCell
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.m5_campaign import (
    ApproveDecision,
    CampaignMode,
    CampaignState,
    M5Campaign,
    StopReason,
)
from mayhem.domain.risks import RiskLevel
from mayhem.infra.campaign_engine import M5CampaignEngine
from mayhem.infra.candidate_gates import (
    CandidateGatePipeline,
    FeasibilityGate,
    ResourceConflictGate,
)
from mayhem.infra.store import Store


class TestCampaignStatus:
    def test_all_values(self) -> None:
        assert {
            CampaignStatus.DRAFT,
            CampaignStatus.SCHEDULED,
            CampaignStatus.APPROVED,
            CampaignStatus.RUNNING,
            CampaignStatus.PAUSED,
            CampaignStatus.COMPLETED,
            CampaignStatus.ABORTED,
            CampaignStatus.ARCHIVED,
        }.issubset(set(CampaignStatus))

    def test_lifecycle_states_and_transitions(self) -> None:
        assert {
            CampaignStatus.DRAFT,
            CampaignStatus.APPROVED,
            CampaignStatus.RUNNING,
            CampaignStatus.PAUSED,
            CampaignStatus.COMPLETED,
            CampaignStatus.ABORTED,
            CampaignStatus.ARCHIVED,
        }.issubset(set(CampaignStatus))
        assert (
            transition_campaign(CampaignStatus.DRAFT, CampaignStatus.APPROVED)
            is CampaignStatus.APPROVED
        )
        assert (
            transition_campaign(CampaignStatus.RUNNING, CampaignStatus.PAUSED)
            is CampaignStatus.PAUSED
        )
        assert (
            transition_campaign(CampaignStatus.PAUSED, CampaignStatus.RUNNING)
            is CampaignStatus.RUNNING
        )
        with pytest.raises(ValueError):
            transition_campaign(CampaignStatus.DRAFT, CampaignStatus.RUNNING)
        assert can_transition(CampaignStatus.COMPLETED, CampaignStatus.ARCHIVED)

    def test_persisted_lifecycle_uses_legacy_storage_aliases(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "campaign.db")
        with store.write() as conn:
            conn.execute(
                "INSERT INTO campaigns (id, name, status, created_at, updated_at)"
                " VALUES ('c1', 'test', 'draft', '', '')"
            )
        assert _transition_row(store, "c1", CampaignStatus.APPROVED)["status"] == "scheduled"
        _transition_row(store, "c1", CampaignStatus.RUNNING)
        assert _transition_row(store, "c1", CampaignStatus.PAUSED)["status"] == "paused"
        assert _transition_row(store, "c1", CampaignStatus.RUNNING)["status"] == "running"
        store.close()

    def test_campaign_supports_operator_bounds(self) -> None:
        campaign = Campaign(
            id="c1",
            name="bounded",
            experiments=(CampaignExperiment(experiment_ref="a"),),
            target_profiles=("staging",),
            engine_policy="podman",
            budget=3,
            deadline_epoch_s=100.0,
            stop_conditions=("coverage_reached",),
        )
        assert campaign.model_dump(mode="json")["engine_policy"] == "podman"
        assert campaign.budget == 3

    def test_empty_experiments_rejected(self) -> None:
        with pytest.raises(InvariantViolationError, match="campaign_requires_experiments"):
            Campaign(id="c1", name="test", experiments=())

    def test_sorted_experiments(self) -> None:
        c = Campaign(
            id="c1",
            name="test",
            experiments=(
                CampaignExperiment(experiment_ref="low", priority=1),
                CampaignExperiment(experiment_ref="high", priority=10),
                CampaignExperiment(experiment_ref="mid", priority=5),
            ),
        )
        sorted_exp = c.sorted_experiments()
        assert sorted_exp[0].experiment_ref == "high"
        assert sorted_exp[1].experiment_ref == "mid"
        assert sorted_exp[2].experiment_ref == "low"

    def test_total_weight(self) -> None:
        c = Campaign(
            id="c1",
            name="test",
            experiments=(
                CampaignExperiment(experiment_ref="a", weight=1.0),
                CampaignExperiment(experiment_ref="b", weight=2.5),
            ),
        )
        assert c.total_weight() == 3.5

    def test_default_status_is_draft(self) -> None:
        c = Campaign(id="c1", name="test", experiments=(CampaignExperiment(experiment_ref="a"),))
        assert c.status == CampaignStatus.DRAFT

    def test_json_round_trip(self) -> None:
        c = Campaign(
            id="c1",
            name="smoke-test",
            description="Quick smoke test",
            experiments=(
                CampaignExperiment(experiment_ref="exp1", priority=5, delay_seconds=10),
                CampaignExperiment(experiment_ref="exp2", priority=1),
            ),
            policy=CampaignPolicy(
                on_experiment_failure=ExperimentOnFailure.SKIP_AND_CONTINUE,
                max_concurrent_experiments=2,
                max_risk_level=RiskLevel.MEDIUM,
            ),
            labels={"env": "staging"},
        )
        restored = Campaign.model_validate(c.model_dump(mode="json"))
        assert restored == c


class TestCampaignSchedule:
    def test_defaults(self) -> None:
        c = Campaign(id="c1", name="test", experiments=(CampaignExperiment(experiment_ref="a"),))
        sched = CampaignSchedule(campaign=c)
        assert sched.run_count == 0
        assert sched.next_experiment_idx == 0
        assert sched.last_run_epoch_s is None


# ─────────────────────────────────────────────────────────────────────
# ADR-M5-4 / M5 Phase 5.4 — M5 campaign semantics + execution loop
# ─────────────────────────────────────────────────────────────────────


class _ListSource:
    """Yields candidates from a fixed list, then exhausts."""

    def __init__(self, candidates: list[ExperimentCandidate]) -> None:
        self._items = list(candidates)

    def next_candidate(self) -> ExperimentCandidate | None:
        return self._items.pop(0) if self._items else None


class _Approver:
    def __init__(self, verdict: bool) -> None:
        self._verdict = verdict
        self.asked: list[ExperimentCandidate] = []

    def approve(self, candidate: ExperimentCandidate) -> bool:
        self.asked.append(candidate)
        return self._verdict


class _CallableApprover:
    """Approver backed by an injected callable (per-candidate verdicts)."""

    def __init__(self, fn: Callable[[ExperimentCandidate], bool]) -> None:
        self._fn = fn

    def approve(self, candidate: ExperimentCandidate) -> bool:
        return self._fn(candidate)


class _Runner:
    """Runs a candidate into a cell; remembers drill ids."""

    def __init__(self) -> None:
        self.calls: list[ExperimentCandidate] = []
        self._count = 0

    def run(self, candidate: ExperimentCandidate) -> tuple[str, str, CoverageCell]:
        self.calls.append(candidate)
        self._count += 1
        cell = CoverageCell(
            candidate.target,
            candidate.primary_fault,
            candidate.execution_context,
            str(candidate.params.get("band") or "default"),
        )
        return f"run-{self._count}", f"out-{self._count}", cell


def _passing_gates() -> CandidateGatePipeline:
    return CandidateGatePipeline(
        feasibility=FeasibilityGate(supported=("net.delay", "fs.fill", "cpu.spike"))
    )


def _campaign(**kwargs: object) -> M5Campaign:
    return M5Campaign(
        id="c1",
        name="m5",
        targets=("web-1", "api-1"),
        **kwargs,  # type: ignore[arg-type]
    )


def _make_candidates(n: int, *, fault: str = "net.delay") -> list[ExperimentCandidate]:
    return [
        ExperimentCandidate(
            target=f"web-{i % 2}",
            fault_kinds=(fault,),
            params={"band": f"b{i}"},
            seed_hint=i,
        )
        for i in range(n)
    ]


class TestM5Campaign:
    def test_defaults(self) -> None:
        c = _campaign()
        assert c.mode is CampaignMode.SUPERVISED
        assert c.max_runs == 100
        assert c.coverage_target == 1
        assert c.deadline_epoch_s is None

    def test_with_defaults_overrides(self) -> None:
        c = _campaign(coverage_target=5)
        c2 = c.with_defaults(max_runs=3)
        assert c2.max_runs == 3
        assert c2.coverage_target == 5  # preserved
        assert c.max_runs == 100  # original untouched

    def test_pause_resume_persisted_transition_callback(self) -> None:
        transitions: list[tuple[str, str]] = []
        engine = M5CampaignEngine(
            M5Campaign(id="c1", name="p", mode=CampaignMode.AUTONOMOUS),
            source=_ListSource(_make_candidates(1)),
            gates=_passing_gates(),
            runner=_Runner(),
            state_transition_fn=lambda old, new: transitions.append((old.value, new.value)),
        )
        engine.start()
        engine.pause()
        assert engine.state is CampaignState.PAUSED
        engine.resume()
        assert engine.state is CampaignState.RUNNING
        assert transitions[-2:] == [("running", "paused"), ("paused", "running")]

    def test_plan_is_side_effect_free_and_manifest_is_ordered(self) -> None:
        source = _ListSource(_make_candidates(3))
        engine = M5CampaignEngine(
            M5Campaign(id="c1", name="plan", mode=CampaignMode.AUTONOMOUS),
            source=source,
            gates=_passing_gates(),
            runner=_Runner(),
        )
        manifest = engine.plan()
        assert [entry.candidate_id for entry in manifest.entries] == [
            candidate.id for candidate in _make_candidates(3)
        ]
        assert source._items
        assert engine.progress.runs_executed == 0

    def test_budget_exhausted_stops(self) -> None:
        """Acceptance: a bounded campaign stops when the budget is exhausted."""
        engine = M5CampaignEngine(
            M5Campaign(
                id="c1", name="b", mode=CampaignMode.AUTONOMOUS, max_runs=3, coverage_target=100
            ),
            source=_ListSource(_make_candidates(20)),
            gates=_passing_gates(),
            runner=_Runner(),
        )
        reason = engine.run_until_stop()
        assert reason is StopReason.BUDGET_EXHAUSTED
        assert engine.progress.runs_executed == 3

    def test_coverage_reached_stops(self) -> None:
        engine = M5CampaignEngine(
            M5Campaign(id="c1", name="c", mode=CampaignMode.AUTONOMOUS, coverage_target=2),
            source=_ListSource(_make_candidates(10)),
            gates=_passing_gates(),
            runner=_Runner(),
        )
        reason = engine.run_until_stop()
        assert reason is StopReason.COVERAGE_REACHED
        assert engine.progress.runs_executed == 2

    def test_deadline_passed_stops(self) -> None:
        """Acceptance: deadline is respected (no run past the deadline)."""
        now = [100.0]
        engine = M5CampaignEngine(
            M5Campaign(
                id="c1", name="d", mode=CampaignMode.AUTONOMOUS, deadline_epoch_s=99.0, max_runs=10
            ),
            source=_ListSource(_make_candidates(10)),
            gates=_passing_gates(),
            runner=_Runner(),
            now_epoch_s=lambda: now[0],
        )
        reason = engine.run_until_stop()
        assert reason is StopReason.DEADLINE_PASSED
        assert engine.progress.runs_executed == 0
        now[0] = 60.0  # deadline not yet reached
        engine2 = M5CampaignEngine(
            M5Campaign(
                id="c1", name="d", mode=CampaignMode.AUTONOMOUS, deadline_epoch_s=99.0, max_runs=1
            ),
            source=_ListSource(_make_candidates(10)),
            gates=_passing_gates(),
            runner=_Runner(),
            now_epoch_s=lambda: now[0],
        )
        assert engine2.run_until_stop() is StopReason.BUDGET_EXHAUSTED

    def test_explicit_stop_condition(self) -> None:
        engine = M5CampaignEngine(
            M5Campaign(id="c1", name="s", max_runs=100),
            source=_ListSource(_make_candidates(100)),
            gates=_passing_gates(),
            runner=_Runner(),
        )
        engine.request_stop()
        reason = engine.run_until_stop()
        assert reason is StopReason.STOP_CONDITION

    def test_rejected_candidate_does_not_consume_budget(self) -> None:
        """Acceptance: a rejected candidate is not executed; budget is preserved."""
        gates = CandidateGatePipeline(feasibility=_DenyGate("fs.fill"))
        engine = M5CampaignEngine(
            M5Campaign(id="c1", name="r", mode=CampaignMode.AUTONOMOUS, max_runs=1),
            source=_ListSource(_make_candidates(5, fault="fs.fill")),
            gates=gates,
            runner=_Runner(),
        )
        reason = engine.run_until_stop()
        assert reason is StopReason.BUDGET_EXHAUSTED
        assert engine.progress.candidates_rejected == 5
        assert engine.progress.runs_executed == 0

    def test_exhausted_source_stops(self) -> None:
        engine = M5CampaignEngine(
            M5Campaign(
                id="c1",
                name="e",
                mode=CampaignMode.AUTONOMOUS,
                max_runs=100,
                coverage_target=100,
            ),
            source=_ListSource(_make_candidates(2)),
            gates=_passing_gates(),
            runner=_Runner(),
        )
        reason = engine.run_until_stop()
        assert reason is StopReason.BUDGET_EXHAUSTED
        assert engine.progress.runs_executed == 2


class TestSupervisedGate:
    def test_supervised_never_runs_without_approval(self) -> None:
        """Acceptance: supervised mode never executes a drill w/o an approve signal."""
        runner = _Runner()
        approver = _Approver(verdict=False)  # deny everything
        engine = M5CampaignEngine(
            M5Campaign(id="c1", name="su", max_runs=100, mode=CampaignMode.SUPERVISED),
            source=_ListSource(_make_candidates(5)),
            gates=_passing_gates(),
            runner=runner,
            approver=approver,
        )
        reason = engine.run_until_stop()
        assert reason is StopReason.BUDGET_EXHAUSTED  # all denied -> source exhausted
        assert runner.calls == []  # nothing executed
        assert engine.progress.runs_executed == 0
        assert engine.progress.candidates_pending_approval == 5
        assert len(approver.asked) == 5  # each candidate asked for approval

    def test_supervised_runs_only_approved(self) -> None:
        runner = _Runner()
        approver = _Approver(verdict=True)  # approve everything
        engine = M5CampaignEngine(
            M5Campaign(
                id="c1",
                name="sa",
                max_runs=2,
                coverage_target=100,
                mode=CampaignMode.SUPERVISED,
            ),
            source=_ListSource(_make_candidates(5)),
            gates=_passing_gates(),
            runner=runner,
            approver=approver,
        )
        reason = engine.run_until_stop()
        assert reason is StopReason.BUDGET_EXHAUSTED
        assert engine.progress.runs_executed == 2
        assert len(runner.calls) == 2


class _DenyGate:
    """A feasibility gate that rejects any candidate whose fault matches."""

    def __init__(self, fault: str) -> None:
        self._fault = fault

    def check(self, candidate: ExperimentCandidate) -> str | None:
        if candidate.primary_fault == self._fault:
            return f"fault {self._fault!r} blocked"
        return None


class TestExecutionGate:
    """M5 Phase 5.6 — supervised/autonomous execution gate + protective aborts."""

    def test_supervised_records_pending_approve_deny_in_log(self) -> None:
        """Acceptance: supervised blocks until approval; approvals + denials recorded."""
        runner = _Runner()

        def _flip(candidate: ExperimentCandidate) -> bool:
            return int(candidate.params.get("band", "b0")[1:]) % 2 == 0

        approver = _CallableApprover(_flip)
        engine = M5CampaignEngine(
            M5Campaign(
                id="c1",
                name="sg",
                max_runs=8,
                coverage_target=100,
                mode=CampaignMode.SUPERVISED,
            ),
            source=_ListSource(_make_candidates(8)),
            gates=_passing_gates(),
            runner=runner,
            approver=approver,
            rationale_fn=lambda c: f"cell={c.target}/{c.primary_fault}",
        )
        reason = engine.run_until_stop()
        assert reason is StopReason.BUDGET_EXHAUSTED
        assert len(engine.progress.log) > 0
        # Every pending candidate must have a terminal approve/deny recorded.
        assert all(e.rationale for e in engine.progress.log)
        # _make_candidates(8) bands b0..b7: even bands (b0,b2,b4,b6) approved.
        assert len(runner.calls) == 4
        assert engine.progress.candidates_denied == 4
        assert engine.progress.candidates_aborted == 0

    def test_supervised_without_approver_denies_all_and_leaves_pending(self) -> None:
        """Acceptance: supervised never runs without an approve signal."""
        runner = _Runner()
        engine = M5CampaignEngine(
            M5Campaign(id="c1", name="sn", max_runs=100, coverage_target=100),
            source=_ListSource(_make_candidates(5)),
            gates=_passing_gates(),
            runner=runner,
        )
        reason = engine.run_until_stop()
        assert reason is StopReason.BUDGET_EXHAUSTED
        assert runner.calls == []
        assert engine.progress.runs_executed == 0
        assert engine.progress.candidates_denied == 5
        # Each candidate: a PENDING probe followed by a terminal DENIED.
        terminal = [e for e in engine.progress.log if e.decision is not ApproveDecision.PENDING]
        assert len(terminal) == 5
        assert all(e.decision is ApproveDecision.DENIED for e in terminal)

    def test_resource_conflict_aborts_never_runs(self) -> None:
        """Acceptance: a resource-conflict candidate is a hard abort, never run."""
        busy_target = "web-0"
        gates = CandidateGatePipeline(
            feasibility=FeasibilityGate(supported=("net.delay",)),
            resource_conflict=ResourceConflictGate(busy_targets=(busy_target,)),
        )
        runner = _Runner()
        engine = M5CampaignEngine(
            M5Campaign(
                id="c1",
                name="rc",
                mode=CampaignMode.AUTONOMOUS,
                max_runs=10,
                coverage_target=100,
            ),
            source=_ListSource(_make_candidates(2)),
            gates=gates,
            runner=runner,
        )
        reason = engine.run_until_stop()
        assert reason is StopReason.RESOURCE_CONFLICT
        assert runner.calls == []  # never executed
        assert engine.progress.runs_executed == 0
        assert engine.progress.candidates_aborted == 1

    def test_blast_radius_over_bound_aborts(self) -> None:
        """Acceptance: an over-blast candidate is a bound-abort, never run."""

        def _blast(candidate: ExperimentCandidate, progress: object) -> str | None:
            if candidate.target == "web-0":
                return "would exceed blast radius budget (30% of services)"
            return None

        runner = _Runner()
        engine = M5CampaignEngine(
            M5Campaign(
                id="c1",
                name="bb",
                mode=CampaignMode.AUTONOMOUS,
                max_runs=10,
                coverage_target=100,
            ),
            source=_ListSource(_make_candidates(2)),
            gates=_passing_gates(),
            runner=runner,
            blast_check=_blast,
        )
        reason = engine.run_until_stop()
        assert reason is StopReason.RESOURCE_CONFLICT
        assert runner.calls == []
        assert engine.progress.runs_executed == 0

    def test_autonomous_executes_within_bounds(self) -> None:
        """Acceptance: autonomous executes directly within bounds."""
        runner = _Runner()
        engine = M5CampaignEngine(
            M5Campaign(
                id="c1",
                name="au",
                mode=CampaignMode.AUTONOMOUS,
                max_runs=3,
                coverage_target=100,
            ),
            source=_ListSource(_make_candidates(10)),
            gates=_passing_gates(),
            runner=runner,
        )
        reason = engine.run_until_stop()
        assert reason is StopReason.BUDGET_EXHAUSTED
        assert engine.progress.runs_executed == 3
        assert len(runner.calls) == 3
