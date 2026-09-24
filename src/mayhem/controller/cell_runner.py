"""CellRunner — executes a single explore-loop candidate (plan-feat-2 §A2).

Invariant A: cell execution IS the ``run`` path, verbatim:

    prepare(...) → plan_drill(...) → engine_for(...) → engine.execute(plan)

The runner is a thin orchestrator: it takes a candidate, converts it to a
DrillSpec (via ``synthesize_candidate_spec``), resolves the real compose
service name, and runs the drill through the same path as ``mayhem run``.

The runner is injectable for testing: all external seams (prepared, engine,
store) are passed in — never imported as module-level singletons.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.cli.services import Prepared, engine_for
from mayhem.controller.planner import plan_drill, synthesize_candidate_spec
from mayhem.domain.coverage import CellState
from mayhem.domain.run_outcome import RunVerdict
from mayhem.infra.maniac import coverage_cell_for_candidate

if TYPE_CHECKING:
    from collections.abc import Callable

    from mayhem.controller.executor import RunResult
    from mayhem.domain.candidates import ExperimentCandidate
    from mayhem.domain.coverage import CoverageCell
    from mayhem.domain.topology import TopologyGraph
    from mayhem.infra.coverage_repository import SQLiteCoverageRepository
    from mayhem.infra.store import Store


def _result_to_state(result: RunResult) -> CellState:
    """Map a RunResult to a cell state per §5.1.

    - completed + PASS verdict → covered
    - completed + FAIL verdict → failed
    - failed / aborted → failed
    - incomplete / no verdict → inconclusive
    - compensation / dirty-leases failure → inconclusive (session_stops
      determined by the caller in the session layer)
    """
    if result.status == "completed":
        if result.verdict is RunVerdict.PASS:
            return CellState.COVERED
        if result.verdict is RunVerdict.FAIL:
            return CellState.FAILED
        # completed but no verdict or verdict=error → inconclusive
        return CellState.INCONCLUSIVE
    if result.status == "failed":
        return CellState.FAILED
    # aborted or any other terminal → inconclusive
    return CellState.INCONCLUSIVE


@dataclass(frozen=True)
class CellRunResult:
    """Result of executing a single cell via the explore loop."""

    run_id: str
    cell: CoverageCell
    run_result: RunResult | None  # None for blocked (never executed)
    state: CellState
    campaign_id: str = ""
    plan_id: str = ""
    evidence_id: str = ""

    @property
    def coverage_cell_key(self) -> str:
        return self.cell.key


class CellRunner:
    """Executes candidates through the canonical ``run`` path (Invariant A).

    Parameters
    ----------
    store:
        The open, migrated store.
    graph:
        The compose topology graph.
    prepared:
        The ``Prepared`` result from ``services.prepare(...)``.
    coverage:
        The coverage repository for state recording.
    engine_name:
        Engine name string (``"podman"`` or ``"docker"``).
    bypass:
        Gate bypass dict (or ``{}`` for none).
    live_graph:
        Callable returning the live topology graph, passed to the engine
        so ``@live-pid`` placeholders resolve to a real cont/engine address
        (ADR-0020). Without it payload faults cannot inject or undo.
    """

    def __init__(
        self,
        *,
        store: Store,
        graph: TopologyGraph,
        prepared: object,
        coverage: SQLiteCoverageRepository,
        engine_name: str = "podman",
        bypass: dict[tuple[str, str], str] | None = None,
        live_graph: Callable[[], TopologyGraph] | None = None,
        campaign_id: str = "",
    ) -> None:
        self._store = store
        self._graph = graph
        self._prepared = prepared
        self._coverage = coverage
        self._engine_name = engine_name
        self._bypass = bypass or {}
        self._live_graph = live_graph
        self._campaign_id = campaign_id

    def run(self, candidate: ExperimentCandidate) -> CellRunResult:
        """Execute the candidate through the canonical ``run`` path.

        Returns a ``CellRunResult`` with the executed cell's state.
        """
        cell = coverage_cell_for_candidate(candidate)
        spec = synthesize_candidate_spec(
            candidate, candidate.target, name=f"explore-{uuid.uuid4().hex[:8]}"
        )
        run_id = f"cell-{uuid.uuid4().hex[:12]}"

        assert isinstance(self._prepared, Prepared)
        plan = plan_drill(
            run_id,
            spec,
            self._graph,
            config_snapshot_id=self._prepared.config_snapshot_id,
            topology_snapshot_id=self._prepared.topology_snapshot_id,
            environment_fingerprint=self._prepared.fingerprint,
            engine=self._engine_name,
        )

        engine = engine_for(
            self._store,
            self._engine_name,
            bypass=self._bypass,
            live_graph=self._live_graph,
            recovery_grace=self._prepared.recovery_grace,
        )
        result = engine.execute(plan)

        state = _result_to_state(result)
        self._coverage.record(
            cell,
            state,
            run_id=run_id,
            verdict={
                "result_status": result.status,
                "verdict": result.verdict.value if result.verdict else None,
            },
        )
        return CellRunResult(
            run_id=run_id,
            cell=cell,
            run_result=result,
            state=state,
            campaign_id=self._campaign_id,
            plan_id=run_id,
        )

    def record_blocked(
        self,
        candidate: ExperimentCandidate,
        reason: str,
    ) -> CellRunResult:
        """Record a blocked cell without executing (gate rejects / denies)."""
        cell = coverage_cell_for_candidate(candidate)
        run_id = f"blocked-{uuid.uuid4().hex[:12]}"
        self._coverage.record_blocked(cell, reason)
        return CellRunResult(
            run_id=run_id,
            cell=cell,
            run_result=None,
            state=CellState.BLOCKED,
            campaign_id=self._campaign_id,
        )
