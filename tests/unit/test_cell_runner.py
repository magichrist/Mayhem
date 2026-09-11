"""CellRunner unit tests (feat-2 Phase A2).

Tests the CellRunner with a minimal in-memory store and topology graph,
verifying the Invariant A path (candidate → spec → plan → execute) and
the record_blocked path.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from mayhem.domain.candidates import ExperimentCandidate
from mayhem.domain.coverage import CellState
from mayhem.infra.cell_runner import CellRunner, CellRunResult, _result_to_state
from mayhem.infra.coverage_repository import SQLiteCoverageRepository
from mayhem.infra.maniac import coverage_cell_for_candidate
from mayhem.infra.store import Store


# ---------------------------------------------------------------------------
# Minimal topology graph for testing
# ---------------------------------------------------------------------------


def _test_graph():
    from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
    from mayhem.domain.topology import (
        ContainerNode,
        Edge,
        EdgeKind,
        ProcessNode,
        ServiceNode,
        TopologyGraph,
    )

    return TopologyGraph(
        nodes=(
            ContainerNode(
                id="ctr-api",
                name="api",
                engine="podman",
                runtime_identity=RuntimeIdentity(
                    runtime="podman", host_id="h1", runtime_id="cid-api"
                ),
                runtime_metadata=RuntimeMetadata(service="api-svc", name="api"),
                container_name="testcase-api",
                ip_address="172.18.0.2",
                state="running",
            ),
            ServiceNode(id="svc-api", name="api-svc", container_name="testcase-api"),
            ProcessNode(
                id="proc-api",
                name="api-proc",
                pid=4242,
                host_id="h1",
                container_name="testcase-api",
            ),
        ),
        edges=(
            Edge(src="svc-api", dst="ctr-api", kind=EdgeKind.RUNS_ON),
            Edge(src="ctr-api", dst="proc-api", kind=EdgeKind.RUNS_ON),
        ),
    )


def _test_prepared():
    from mayhem.cli.services import Prepared
    from mayhem.config import PolicyCfg
    from mayhem.controller.safety import SafetyContext
    from mayhem.domain.experiments import BlastRadiusBudget
    from mayhem.domain.risks import RiskLevel

    return Prepared(
        config_snapshot_id="test-cfg",
        topology_snapshot_id="test-topo",
        fingerprint="test-fp",
        safety=SafetyContext(
            policy=PolicyCfg(),
            budget=BlastRadiusBudget(),
            fingerprint="test-fp",
            allow_critical_cli=False,
        ),
    )


def _test_candidate(**overrides) -> ExperimentCandidate:
    defaults = dict(
        target="testcase-api",
        fault_kinds=("proc.pause",),
        execution_context="container",
        expected_effect="process pause test",
    )
    defaults.update(overrides)
    return ExperimentCandidate(**defaults)


# ---------------------------------------------------------------------------
# _result_to_state tests
# ---------------------------------------------------------------------------


class TestResultToState:
    def test_completed_pass_is_covered(self) -> None:
        from mayhem.controller.executor import RunResult
        from mayhem.domain.run_outcome import RunVerdict

        result = RunResult(
            run_id="r1",
            status="completed",
            started_at_epoch_s=1.0,
            ended_at_epoch_s=2.0,
            verdict=RunVerdict.PASS,
        )
        assert _result_to_state(result) is CellState.COVERED

    def test_completed_fail_is_failed(self) -> None:
        from mayhem.controller.executor import RunResult
        from mayhem.domain.run_outcome import RunVerdict

        result = RunResult(
            run_id="r1",
            status="completed",
            started_at_epoch_s=1.0,
            ended_at_epoch_s=2.0,
            verdict=RunVerdict.FAIL,
        )
        assert _result_to_state(result) is CellState.FAILED

    def test_completed_no_verdict_is_inconclusive(self) -> None:
        from mayhem.controller.executor import RunResult

        result = RunResult(
            run_id="r1",
            status="completed",
            started_at_epoch_s=1.0,
            ended_at_epoch_s=2.0,
        )
        assert _result_to_state(result) is CellState.INCONCLUSIVE

    def test_failed_status_is_failed(self) -> None:
        from mayhem.controller.executor import RunResult

        result = RunResult(
            run_id="r1",
            status="failed",
            started_at_epoch_s=1.0,
            ended_at_epoch_s=2.0,
        )
        assert _result_to_state(result) is CellState.FAILED

    def test_aborted_status_is_inconclusive(self) -> None:
        from mayhem.controller.executor import RunResult

        result = RunResult(
            run_id="r1",
            status="aborted",
            started_at_epoch_s=1.0,
            ended_at_epoch_s=2.0,
        )
        assert _result_to_state(result) is CellState.INCONCLUSIVE


# ---------------------------------------------------------------------------
# CellRunner.record_blocked tests (no execution needed)
# ---------------------------------------------------------------------------


class TestCellRunnerRecordBlocked:
    def test_record_blocked_persists_state(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "test.db")
        coverage = SQLiteCoverageRepository(store)
        candidate = _test_candidate()

        runner = CellRunner(
            store=store,
            graph=_test_graph(),
            prepared=_test_prepared(),
            coverage=coverage,
        )
        result = runner.record_blocked(candidate, "safety gate refused")
        assert isinstance(result, CellRunResult)
        assert result.state is CellState.BLOCKED
        assert result.run_result is None
        assert result.run_id.startswith("blocked-")

        # Verify persisted in DB
        cell = coverage_cell_for_candidate(candidate)
        state = coverage.cell_state(cell)
        assert state is CellState.BLOCKED

    def test_record_blocked_preserves_cell_identity(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "test.db")
        coverage = SQLiteCoverageRepository(store)
        candidate = _test_candidate(fault_kinds=("net.delay",))

        runner = CellRunner(
            store=store,
            graph=_test_graph(),
            prepared=_test_prepared(),
            coverage=coverage,
        )
        result = runner.record_blocked(candidate, "feasibility gate")
        cell = coverage_cell_for_candidate(candidate)
        assert result.cell == cell
        assert result.cell.target == "testcase-api"
        assert result.cell.fault_kind == "net.delay"
