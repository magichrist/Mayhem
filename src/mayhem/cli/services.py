"""Application services for the CLI — the only place CLI touches mayhem internals.

Handlers stay thin: they translate arguments into service calls and results
into output. Everything here is UI-framework-agnostic so a future REST/UI
layer can reuse it verbatim.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mayhem.config import load_config, save_snapshot
from mayhem.controller.executor import RunEngine
from mayhem.controller.planner import plan_deterministic, plan_random
from mayhem.controller.safety import SafetyContext, environment_fingerprint
from mayhem.domain.experiments import BlastRadiusBudget, ExecutionPlan, RandomExperiment
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    HostNode,
    NodeKind,
    ProcessNode,
    ServiceNode,
    TopologyGraph,
)
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.store import Store
from mayhem.spec import load_spec

if TYPE_CHECKING:
    from mayhem.toolkit.registry import CapabilityReport

DEFAULT_DB = "mayhem.db"


def open_store(db: str) -> Store:
    return Store.open_migrated(Path(db))


def build_graph(
    process: list[str],
    service: list[str],
    host: str,
    compose: str | None,
) -> TopologyGraph:
    """Compose a topology graph from a compose blueprint or manual flags.

    ``--compose`` runs the provider pipeline ([ADR-0006]); manual flags build a
    minimal local graph suitable for quick experiments.
    """
    if compose is not None:
        from mayhem.cli.app import _STATE
        from mayhem.cli.topology import _resolve_engine
        from mayhem.topology.providers.compose import ComposeFileProvider
        from mayhem.topology.providers.docker_runtime import ContainerRuntimeProvider
        from mayhem.topology.service import TopologyService

        engine = _resolve_engine(str(_STATE.get("engine", "")))

        compose_provider = ComposeFileProvider(compose)
        runtime_provider = ContainerRuntimeProvider.best_effort(engine)
        if runtime_provider is not None:
            runtime_provider.filter_by_compose(
                compose_provider.project_name,
                compose_provider.service_names,
            )

        result = (
            TopologyService()
            .discover(
                [
                    provider
                    for provider in (compose_provider, runtime_provider)
                    if provider is not None
                ]
            )
            .graph
        )

        existing_process_names = {n.name for n in result.nodes if n.kind == NodeKind.PROCESS}
        extra_nodes: list[Any] = []
        extra_edges: list[Edge] = []
        for svc in result.nodes:
            if svc.kind == NodeKind.SERVICE and svc.name not in existing_process_names:
                proc_id = f"p-{svc.name}"
                extra_nodes.append(ProcessNode(id=proc_id, name=svc.name, pid=0, host_id="h-local"))
                extra_edges.append(Edge(src=svc.id, dst=proc_id, kind=EdgeKind.RUNS_ON))
        if extra_nodes:
            result = TopologyGraph(
                nodes=tuple(result.nodes) + tuple(extra_nodes),
                edges=tuple(result.edges) + tuple(extra_edges),
            )
        return result
    nodes: list[Any] = [HostNode(id="h-local", name=host, transport="local")]
    for spec in process:
        if "=" not in spec:
            raise ValueError(f"--process expects name=pid, got {spec!r}")
        name, _, pid_text = spec.partition("=")
        try:
            pid = int(pid_text)
        except ValueError as exc:
            raise ValueError(f"--process pid must be an integer, got {pid_text!r}") from exc
        nodes.append(ProcessNode(id=f"p-{name}", name=name, pid=pid, host_id="h-local"))
    for index, name in enumerate(service):
        svc_id = f"svc-{index}-{name}"
        nodes.append(ServiceNode(id=svc_id, name=name))
        nodes.append(ProcessNode(id=f"p-{name}", name=name, pid=0, host_id="h-local"))
    return TopologyGraph(nodes=tuple(nodes), edges=())


@dataclass(frozen=True, slots=True)
class Prepared:
    config_snapshot_id: str
    topology_snapshot_id: str
    fingerprint: str
    safety: SafetyContext


def prepare(
    *,
    config_path: str | None,
    profile: str | None,
    allow_critical: bool,
    store: Store,
    graph: TopologyGraph,
    compose: str | None,
) -> Prepared:
    cfg, sources = load_config(
        config_path=config_path, profile=profile, environ={"MAYHEM_LOG_LEVEL": "INFO"}
    )
    cfg_snapshot_id = save_snapshot(store, cfg, sources)

    fingerprint = environment_fingerprint(
        host_names=[n.name for n in graph.of_kind(NodeKind.HOST)],
        compose_digest=_compose_digest(compose),
        environment_name=cfg.environment.name,
        environment_class=cfg.environment.klass,
    )
    topo_snapshot_id = "topo-" + fingerprint[:12]
    with store.write() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO topology_snapshots (id, run_id, graph_json, drift_report,"
            " fingerprint) VALUES (?, NULL, ?, '{}', ?)",
            (topo_snapshot_id, graph.model_dump_json(), fingerprint),
        )

    budget = cfg.blast_radius or BlastRadiusBudget()
    return Prepared(
        config_snapshot_id=cfg_snapshot_id,
        topology_snapshot_id=topo_snapshot_id,
        fingerprint=fingerprint,
        safety=SafetyContext(
            policy=cfg.policy,
            budget=budget,
            fingerprint=fingerprint,
            allow_critical_cli=allow_critical,
        ),
    )


@dataclass(frozen=True, slots=True)
class CompiledPlan:
    run_id: str
    plan: ExecutionPlan


def plan_from_spec(
    spec_path: str,
    graph: TopologyGraph,
    *,
    prepared: Prepared,
    store: Store | None = None,  # receives the maniac decision audit row
) -> CompiledPlan:
    experiment = load_spec(spec_path)
    run_id = f"r-{experiment.metadata.name}"
    common: dict[str, str] = {
        "config_snapshot_id": prepared.config_snapshot_id,
        "topology_snapshot_id": prepared.topology_snapshot_id,
        "environment_fingerprint": prepared.fingerprint,
    }

    def _audit(row: dict[str, object]) -> None:
        if store is None:
            return
        store.query(
            "INSERT OR REPLACE INTO maniac_decisions (id, run_id, candidates_json,"
            " weights_json, rng_state, chosen_plan_json, decided_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                f"md-{uuid.uuid4().hex[:12]}",
                run_id,
                json.dumps(row["candidates"]),
                json.dumps(row["weights"]),
                json.dumps(row["rng_state"]),
                "{}",
                datetime.now(UTC).isoformat(),
            ),
        )

    if isinstance(experiment, RandomExperiment):
        plan = plan_random(run_id, experiment, graph, **common, audit_sink=_audit)  # type: ignore[arg-type]
    else:
        plan = plan_deterministic(run_id, experiment, graph, **common)
    return CompiledPlan(run_id=run_id, plan=plan)


def engine_for(store: Store) -> RunEngine:
    return RunEngine(store, SQLiteLeaseSink(store))


def recent_runs(store: Store, limit: int) -> list[dict[str, Any]]:
    rows = store.query(
        "SELECT id, kind, status, started_at FROM runs ORDER BY started_at DESC LIMIT ?",
        (limit,),
    )
    return [dict(row) for row in rows]


def run_detail(store: Store, run_id: str) -> dict[str, Any] | None:
    rows = store.query("SELECT * FROM runs WHERE id = ?", (run_id,))
    return dict(rows[0]) if rows else None


def run_journal(store: Store, run_id: str) -> dict[str, Any]:
    steps = [
        dict(row)
        for row in store.query(
            "SELECT seq, id, action_type, status, started_at, ended_at, error"
            " FROM step_runs WHERE run_id = ? ORDER BY seq",
            (run_id,),
        )
    ]
    events = [
        dict(row)
        for row in store.query(
            "SELECT ts, kind, payload_json FROM events WHERE run_id = ? ORDER BY ts",
            (run_id,),
        )
    ]
    leases = [
        dict(row)
        for row in store.query(
            "SELECT id, state, fault_id, release_mechanism FROM fault_leases"
            " WHERE run_id = ? ORDER BY created_epoch_s",
            (run_id,),
        )
    ]
    return {"steps": steps, "events": events, "leases": leases}


def effective_config(config_path: str | None, profile: str | None) -> tuple[Any, dict[str, str]]:
    return load_config(config_path=config_path, profile=profile, environ={})


def probe_capabilities(host: str) -> CapabilityReport:
    from mayhem.toolkit.registry import default_registry

    return default_registry().probe(host=host)


def _compose_digest(graph_source: str | None) -> str:
    if graph_source is None:
        return "no-compose"
    return hashlib.sha256(Path(graph_source).read_bytes()).hexdigest()
