"""Campaign-level coverage delta aggregation (v0.9.0 expansion task 12)."""

from __future__ import annotations

from mayhem.domain.coverage import CellState, CoverageCell
from mayhem.domain.coverage_graph import CoverageDelta, build_graph
from mayhem.infra.coverage_repository import CoverageGraphRepository, SQLiteCoverageRepository
from mayhem.infra.store import Store


def _cell(target: str, fault_kind: str = "k8s.pod_kill") -> CoverageCell:
    return CoverageCell(
        target=target,
        fault_kind=fault_kind,
        execution_context="kubernetes",
        parameter_band="default",
    )


def test_campaign_delta_aggregates_every_experiment_run(tmp_path) -> None:
    store = Store.open_migrated(tmp_path / "campaign.db")
    try:
        graph_repo = CoverageGraphRepository(store)
        coverage_repo = SQLiteCoverageRepository(store)

        # Experiment 1: one cell verified, one blocked.
        # (Re-recording the same run id is a no-op by design, so each state is
        # recorded once under its own run id.)
        coverage_repo.record(_cell("checkout"), CellState.EXECUTED, run_id="exp-1")
        coverage_repo.record(_cell("checkout"), CellState.PASSED, run_id="exp-1-verify")
        coverage_repo.record_blocked(_cell("payments"), "impact gate")
        graph_repo.record_nodes(build_graph(graph_repo.records_from_coverage()).nodes)
        before = graph_repo.graph()
        graph_repo.save_baseline("campaign-start", before)

        # Experiment 2: a second service and a second fault family.
        coverage_repo.record(_cell("payments", "k8s.pod_latency"), CellState.PASSED, run_id="exp-2")
        coverage_repo.record(_cell("checkout", "net.latency"), CellState.PASSED, run_id="exp-2")
        graph_repo.record_nodes(build_graph(graph_repo.records_from_coverage()).nodes)

        delta = graph_repo.delta("campaign-start")
        assert delta is not None
        payload = delta.to_dict()
        assert payload["after"]["verified"] == 3, payload
        assert payload["net_covered"] == 2, payload
        assert delta.improved is True
        assert len(delta.added) == 2
        # The blocked cell is never counted as covered at any point.
        # The blocked cell keeps its own node and is never counted as verified.
        blocked = graph_repo.baseline("campaign-start")
        assert blocked is not None
        assert any(
            node.blocked_reason == "impact gate" and not node.verified for node in blocked.nodes
        )
    finally:
        store.close()


def test_campaign_delta_is_zero_when_nothing_new_is_verified(tmp_path) -> None:
    store = Store.open_migrated(tmp_path / "campaign.db")
    try:
        graph_repo = CoverageGraphRepository(store)
        coverage_repo = SQLiteCoverageRepository(store)
        coverage_repo.record(_cell("checkout"), CellState.PASSED, run_id="exp-1")
        graph_repo.record_nodes(build_graph(graph_repo.records_from_coverage()).nodes)
        graph_repo.save_baseline("start", graph_repo.graph())

        coverage_repo.record_blocked(_cell("payments"), "impact gate")
        graph_repo.record_nodes(build_graph(graph_repo.records_from_coverage()).nodes)

        delta = graph_repo.delta("start")
        assert delta is not None
        assert delta.to_dict()["net_covered"] == 0
        assert delta.improved is False
        assert any("payments" in node_id for node_id in delta.added)
    finally:
        store.close()


def test_baseline_survives_a_reopen(tmp_path) -> None:
    db = tmp_path / "campaign.db"
    store = Store.open_migrated(db)
    try:
        repo = CoverageGraphRepository(store)
        repo.record_nodes(build_graph([{"service": "a", "fault_family": "k8s", "covered": False}]).nodes)
        repo.save_baseline("start", repo.graph())
    finally:
        store.close()

    store = Store.open_migrated(db)
    try:
        repo = CoverageGraphRepository(store)
        assert repo.baseline_names() == ("start",)
        baseline = repo.baseline("start")
        assert baseline is not None
        assert [node.service for node in baseline.nodes] == ["a"]
        recomputed = CoverageDelta.between(baseline, repo.graph())
        assert recomputed.added == ()
        assert recomputed.removed == ()
    finally:
        store.close()
