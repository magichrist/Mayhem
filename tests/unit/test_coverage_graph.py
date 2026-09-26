"""v0.9.0 expansion task 12: resilience coverage graph."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from mayhem.domain.coverage_graph import (
    EVIDENCE_BLOCKED,
    EVIDENCE_NONE,
    EVIDENCE_VERIFIED,
    CoverageDelta,
    CoverageGraph,
    CoverageNode,
    build_edges,
    build_graph,
    evidence_status_for,
)


def _record(**overrides):
    base = {
        "service": "checkout",
        "fault_family": "k8s",
        "failure_domain": "node-a",
        "target_type": "pod",
        "engine": "kubernetes",
        "maturity": "verified-unit",
        "covered": True,
    }
    base.update(overrides)
    return base


def test_coverage_is_keyed_by_every_dimension() -> None:
    node = CoverageNode(
        service="checkout",
        fault_family="k8s",
        fault_kind="k8s.pod_kill",
        failure_domain="node-a",
        target_type="pod",
        engine="kubernetes",
        maturity="verified-unit",
        evidence_status=EVIDENCE_VERIFIED,
    )
    assert node.node_id == "checkout|k8s.pod_kill|node-a|pod|kubernetes"
    other = CoverageNode(
        service="checkout",
        fault_family="k8s",
        fault_kind="k8s.pod_kill",
        failure_domain="node-a",
        target_type="node",
        engine="kubernetes",
        maturity="verified-unit",
        evidence_status=EVIDENCE_VERIFIED,
    )
    assert other.node_id != node.node_id


def test_evidence_status_derives_from_coverage_facts() -> None:
    assert evidence_status_for(covered=True) == EVIDENCE_VERIFIED
    assert evidence_status_for(covered=False) == EVIDENCE_NONE
    assert evidence_status_for(covered=True, blocked_reason="gate") == EVIDENCE_BLOCKED
    assert evidence_status_for(covered=False, blocked_reason="gate") == EVIDENCE_BLOCKED


def test_blocked_cells_are_excluded_from_verified() -> None:
    graph = build_graph([_record(covered=True, block_reason="impact gate")])
    node = graph.nodes[0]
    assert node.evidence_status == EVIDENCE_BLOCKED
    assert node.verified is False
    assert node.blocked_reason == "impact gate"
    assert graph.summary()["verified"] == 0


def test_successful_run_marks_a_node_verified() -> None:
    graph = build_graph([_record()])
    assert graph.summary()["verified"] == 1
    assert graph.uncovered() == ()


def test_edges_connect_services_to_fault_families_with_strongest_evidence() -> None:
    nodes = (
        CoverageNode("a", "net", "net.latency", "d", "pod", "docker", "stable", EVIDENCE_NONE),
        CoverageNode("a", "net", "net.latency", "d2", "pod", "docker", "stable", EVIDENCE_VERIFIED),
    )
    edges = build_edges(nodes)
    assert len(edges) == 1
    assert edges[0].source == "a"
    assert edges[0].target == "net"
    assert edges[0].evidence_status == EVIDENCE_VERIFIED


def test_graph_filters_by_service_engine_and_evidence_status() -> None:
    graph = build_graph(
        [
            _record(),
            _record(engine="docker", covered=False),
            _record(service="payments", covered=False),
        ]
    )
    assert len(graph.services()) == 2
    by_service = graph.filtered(service="checkout")
    assert {node.service for node in by_service.nodes} == {"checkout"}
    assert "service" in by_service.filters
    assert {node.engine for node in graph.filtered(engine="docker").nodes} == {"docker"}
    assert {
        node.evidence_status for node in graph.filtered(evidence_status=EVIDENCE_VERIFIED).nodes
    } == {EVIDENCE_VERIFIED}


def test_uncovered_lists_untested_cells() -> None:
    graph = build_graph([_record(covered=False), _record(fault_family="net", covered=False)])
    assert len(graph.uncovered()) == 2


def test_graph_dict_is_json_serializable_and_versioned() -> None:
    payload = build_graph([_record()]).to_dict()
    assert json.loads(json.dumps(payload))["schema_version"] == "1.0"
    assert payload["summary"]["nodes"] == len(payload["nodes"])


def test_delta_reports_added_removed_and_changed() -> None:
    before = build_graph([_record(covered=False), _record(fault_family="net", covered=False)])
    after = build_graph(
        [
            _record(covered=True),
            _record(fault_family="disk", covered=False),
        ]
    )
    delta = CoverageDelta.between(before, after)
    assert delta.improved is True
    assert delta.to_dict()["net_covered"] == 1
    assert any("net" in node_id for node_id in delta.removed)
    assert any("disk" in node_id for node_id in delta.added)
    assert any("checkout|k8s" in node_id for node_id in delta.changed)


def test_delta_is_stable_for_identical_graphs() -> None:
    graph = build_graph([_record()])
    delta = CoverageDelta.between(graph, graph)
    assert delta.added == ()
    assert delta.removed == ()
    assert delta.changed == ()


def test_empty_graph_is_valid() -> None:
    graph = CoverageGraph()
    assert graph.summary()["nodes"] == 0
    assert graph.to_dict()["nodes"] == []


# ── persistence ──────────────────────────────────────────────────────────────
def test_repository_round_trips_nodes_and_baselines(tmp_path) -> None:
    from mayhem.infra.coverage_repository import CoverageGraphRepository
    from mayhem.infra.store import Store

    store = Store.open_migrated(tmp_path / "graph.db")
    try:
        repo = CoverageGraphRepository(store)
        assert repo.graph().summary()["nodes"] == 0
        baseline_graph = build_graph([_record(covered=False)])
        repo.record_nodes(baseline_graph.nodes)
        repo.save_baseline("before", repo.graph())
        assert repo.baseline_names() == ("before",)

        repo.record_nodes(build_graph([_record(covered=True)]).nodes)
        delta = repo.delta("before")
        assert delta is not None
        assert delta.improved is True
        assert repo.baseline("missing") is None
        assert repo.delta("missing") is None
    finally:
        store.close()


def test_repository_projects_the_existing_coverage_table(tmp_path) -> None:
    from mayhem.domain.coverage import CellState, CoverageCell
    from mayhem.infra.coverage_repository import CoverageGraphRepository, SQLiteCoverageRepository
    from mayhem.infra.store import Store

    store = Store.open_migrated(tmp_path / "graph.db")
    try:
        cell = CoverageCell(
            target="checkout",
            fault_kind="k8s.pod_kill",
            execution_context="kubernetes",
            parameter_band="default",
        )
        SQLiteCoverageRepository(store).record(cell, CellState.COVERED, run_id="r1")
        SQLiteCoverageRepository(store).record_blocked(
            CoverageCell(
                target="payments",
                fault_kind="k8s.pod_kill",
                execution_context="kubernetes",
                parameter_band="default",
            ),
            reason="impact gate",
        )
        records = CoverageGraphRepository(store).records_from_coverage()
        assert len(records) == 2
        statuses = {record["service"]: bool(record["covered"]) for record in records}
        assert statuses["checkout"] is True
        assert statuses["payments"] is False
    finally:
        store.close()


def test_graph_builds_from_existing_coverage_table(tmp_path) -> None:
    from mayhem.domain.coverage import CellState, CoverageCell
    from mayhem.infra.coverage_repository import CoverageGraphRepository, SQLiteCoverageRepository
    from mayhem.infra.store import Store

    store = Store.open_migrated(tmp_path / "graph.db")
    try:
        SQLiteCoverageRepository(store).record(
            CoverageCell(
                target="checkout",
                fault_kind="k8s.pod_kill",
                execution_context="kubernetes",
                parameter_band="default",
            ),
            CellState.COVERED,
            run_id="r1",
        )
        repo = CoverageGraphRepository(store)
        repo.record_nodes(build_graph(repo.records_from_coverage()).nodes)
        assert repo.graph().summary()["verified"] == 1
    finally:
        store.close()


# ── CLI ──────────────────────────────────────────────────────────────────────
def _ctx(db):
    from mayhem.cli.context import CliContext

    return CliContext(db=str(db))


def test_cli_graph_is_read_only_and_empty_by_default(tmp_path) -> None:
    from mayhem.cli import inspect as inspect_mod

    inspect_graph = inspect_mod.inspect_graph
    from mayhem.infra.store import Store

    db = tmp_path / "graph.db"
    Store.open_migrated(db).close()
    result = CliRunner().invoke(inspect_graph, ["--json"], obj=_ctx(db))
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["nodes"] == []
    assert payload["schema_version"] == "1.0"


def test_cli_graph_record_and_filter(tmp_path) -> None:
    from mayhem.cli import inspect as inspect_mod

    inspect_graph = inspect_mod.inspect_graph
    from mayhem.domain.coverage import CellState, CoverageCell
    from mayhem.infra.coverage_repository import SQLiteCoverageRepository
    from mayhem.infra.store import Store

    db = tmp_path / "graph.db"
    store = Store.open_migrated(db)
    try:
        SQLiteCoverageRepository(store).record(
            CoverageCell(
                target="checkout",
                fault_kind="k8s.pod_kill",
                execution_context="kubernetes",
                parameter_band="default",
            ),
            CellState.COVERED,
            run_id="r1",
        )
    finally:
        store.close()

    result = CliRunner().invoke(inspect_graph, ["--record", "--json"], obj=_ctx(db))
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["summary"]["verified"] == 1

    filtered = CliRunner().invoke(inspect_graph, ["--json", "--service", "payments"], obj=_ctx(db))
    assert json.loads(filtered.output)["nodes"] == []


def test_cli_graph_text_output(tmp_path) -> None:
    from mayhem.cli import inspect as inspect_mod

    inspect_graph = inspect_mod.inspect_graph
    from mayhem.infra.store import Store

    db = tmp_path / "graph.db"
    Store.open_migrated(db).close()
    result = CliRunner().invoke(inspect_graph, [], obj=_ctx(db))
    assert result.exit_code == 0, result.output
    assert "coverage graph:" in result.output


def test_cli_coverage_diff_save_then_compare(tmp_path) -> None:
    from mayhem.cli import inspect as inspect_mod

    inspect_coverage_diff = inspect_mod.inspect_coverage_diff
    from mayhem.infra.coverage_repository import CoverageGraphRepository
    from mayhem.infra.store import Store

    db = tmp_path / "graph.db"
    store = Store.open_migrated(db)
    try:
        repo = CoverageGraphRepository(store)
        repo.record_nodes(build_graph([_record(covered=False)]).nodes)
    finally:
        store.close()

    runner = CliRunner()
    saved = runner.invoke(inspect_coverage_diff, ["v1", "--save", "--json"], obj=_ctx(db))
    assert saved.exit_code == 0, saved.output
    assert json.loads(saved.output)["baseline"] == "v1"

    store = Store.open_migrated(db)
    try:
        CoverageGraphRepository(store).record_nodes(build_graph([_record(covered=True)]).nodes)
    finally:
        store.close()

    diffed = runner.invoke(inspect_coverage_diff, ["v1", "--json"], obj=_ctx(db))
    assert diffed.exit_code == 0, diffed.output
    payload = json.loads(diffed.output)
    assert payload["net_covered"] == 1
    assert payload["changed"]


def test_cli_coverage_diff_rejects_unknown_baseline(tmp_path) -> None:
    from mayhem.cli import inspect as inspect_mod

    inspect_coverage_diff = inspect_mod.inspect_coverage_diff
    from mayhem.infra.store import Store

    db = tmp_path / "graph.db"
    Store.open_migrated(db).close()
    result = CliRunner().invoke(inspect_coverage_diff, ["nope"], obj=_ctx(db))
    assert result.exit_code == 1
    assert "unknown baseline" in result.output


def test_cli_graph_rejects_an_unknown_evidence_status(tmp_path) -> None:
    from mayhem.cli import inspect as inspect_mod

    inspect_graph = inspect_mod.inspect_graph
    from mayhem.infra.store import Store

    db = tmp_path / "graph.db"
    Store.open_migrated(db).close()
    result = CliRunner().invoke(inspect_graph, ["--evidence-status", "nope"], obj=_ctx(db))
    assert result.exit_code == 2


def test_cli_graph_accepts_free_form_service_and_engine_filters(tmp_path) -> None:
    """Service and engine are open strings — an unknown value yields no rows, not an error."""
    from mayhem.cli import inspect as inspect_mod

    inspect_graph = inspect_mod.inspect_graph
    from mayhem.infra.store import Store

    db = tmp_path / "graph.db"
    Store.open_migrated(db).close()
    for flag in ("--service", "--engine"):
        result = CliRunner().invoke(inspect_graph, [flag, "not-a-value", "--json"], obj=_ctx(db))
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["nodes"] == []
