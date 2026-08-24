"""mayhem — the chaos engineering toolkit CLI.

Commands map onto the lifecycle: author (faults/plan/discover) → execute (run)
→ observe (status) → repair (recover/janitor).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC
from pathlib import Path
from typing import Any

import typer

from mayhem.config import load_config, save_snapshot
from mayhem.controller.executor import RunEngine
from mayhem.controller.janitor import Janitor
from mayhem.controller.planner import plan_deterministic, plan_random
from mayhem.controller.safety import SafetyContext, SafetyRefusedError, environment_fingerprint
from mayhem.domain.catalog import all_definitions
from mayhem.domain.experiments import BlastRadiusBudget, ExecutionPlan, RandomExperiment
from mayhem.domain.topology import HostNode, NodeKind, ProcessNode, ServiceNode, TopologyGraph
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.store import Store
from mayhem.spec import load_spec

app = typer.Typer(help="mayhem — safe-by-construction chaos experiments.", no_args_is_help=True)
DEFAULT_DB = "mayhem.db"


def _store(db: str) -> Store:
    return Store.open_migrated(Path(db))


def _build_graph(
    process: list[str],
    service: list[str],
    host: str,
    compose: str | None,
) -> TopologyGraph:
    """Compose a topology graph from a compose blueprint or CLI flags.

    ``--compose`` runs the provider pipeline ([ADR-0006]); manual flags build a
    minimal local graph suitable for quick experiments.
    """
    if compose is not None:
        from mayhem.topology.providers.compose import ComposeFileProvider
        from mayhem.topology.providers.docker_runtime import ContainerRuntimeProvider
        from mayhem.topology.service import TopologyService

        return (
            TopologyService()
            .discover(
                [
                    provider
                    for provider in (
                        ComposeFileProvider(compose),
                        ContainerRuntimeProvider.best_effort(),
                    )
                    if provider is not None
                ]
            )
            .graph
        )
    nodes: list[Any] = [
        HostNode(id="h-local", name=host, transport="local"),
    ]
    for spec in process:
        if "=" not in spec:
            raise typer.BadParameter(f"--process expects name=pid, got {spec!r}")
        name, _, pid_text = spec.partition("=")
        try:
            pid = int(pid_text)
        except ValueError:
            raise typer.BadParameter(
                f"--process pid must be an integer, got {pid_text!r}"
            ) from None
        nodes.append(ProcessNode(id=f"p-{name}", name=name, pid=pid, host_id="h-local"))
    for index, name in enumerate(service):
        nodes.append(ServiceNode(id=f"svc-{index}-{name}", name=name))
    return TopologyGraph(nodes=tuple(nodes), edges=())


def _compose_digest(graph_source: str | None) -> str:
    if graph_source is None:
        return "no-compose"
    data = Path(graph_source).read_bytes()
    return hashlib.sha256(data).hexdigest()


def _prepare(
    *,
    config_path: str | None,
    profile: str | None,
    allow_critical: bool,
    store: Store,
    graph: TopologyGraph,
    compose: str | None,
) -> tuple[str, str, str, SafetyContext]:
    cfg, sources = load_config(
        config_path=config_path, profile=profile, environ={"MAYHEM_LOG_LEVEL": "INFO"}
    )
    cfg_snapshot_id = save_snapshot(store, cfg, sources)

    fingerprint = environment_fingerprint(
        host_names=[n.name for n in graph.of_kind(_host_kind())],
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
    ctx = SafetyContext(
        policy=cfg.policy,
        budget=budget,
        fingerprint=fingerprint,
        allow_critical_cli=allow_critical,
    )
    return cfg_snapshot_id, topo_snapshot_id, fingerprint, ctx


def _host_kind() -> NodeKind:
    from mayhem.domain.topology import NodeKind

    return NodeKind.HOST


def _plan_from_spec(
    spec_path: str,
    graph: TopologyGraph,
    *,
    config_snapshot_id: str,
    topology_snapshot_id: str,
    environment_fingerprint_value: str,
    store: Store | None = None,  # receives the maniac decision audit row
) -> tuple[str, ExecutionPlan]:
    experiment = load_spec(spec_path)
    run_id = f"r-{experiment.metadata.name}"
    common: dict[str, str] = {
        "config_snapshot_id": config_snapshot_id,
        "topology_snapshot_id": topology_snapshot_id,
        "environment_fingerprint": environment_fingerprint_value,
    }

    def _audit(row: dict[str, object]) -> None:
        if store is None:
            return
        import uuid
        from datetime import datetime

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
    return run_id, plan


@app.command()
def faults() -> None:
    """List the fault catalog with risk and compensatability."""
    for definition in sorted(all_definitions(), key=lambda d: d.id):
        undoable = "yes" if definition.reversible else "no"
        typer.echo(f"{definition.id:<24} risk={definition.risk.value:<6} undo={undoable}")


@app.command()
def discover(
    compose: str = typer.Option(..., "--compose", help="Path to docker-compose.yaml."),
) -> None:
    """Run topology discovery and print the merged graph + drift report."""
    from mayhem.topology.providers.compose import ComposeFileProvider
    from mayhem.topology.providers.docker_runtime import ContainerRuntimeProvider
    from mayhem.topology.service import TopologyService

    result = TopologyService().discover(
        [
            provider
            for provider in (
                ComposeFileProvider(compose),
                ContainerRuntimeProvider.best_effort(),
            )
            if provider is not None
        ]
    )
    typer.echo(
        json.dumps(
            {
                "graph": result.graph.model_dump(mode="json"),
                "drift": result.drift_report,
            },
            indent=2,
        )
    )


@app.command()
def plan(
    spec_path: str = typer.Argument(..., help="Path to the experiment spec YAML."),
    process: list[str] = typer.Option(
        [], "--process", "-p", help="Local process node as name=pid."
    ),
    service: list[str] = typer.Option([], "--service", help="Logical service node name."),
    host: str = typer.Option("local", "--host", help="Host node name."),
    compose: str | None = typer.Option(None, "--compose", help="docker-compose.yaml blueprint."),
    db: str = typer.Option(DEFAULT_DB, "--db", help="SQLite database path (snapshots)."),
    config: str | None = typer.Option(None, "--config", help="mayhem.yaml path."),
    profile: str | None = typer.Option(None, "--profile", help="Profile overlay name."),
    allow_critical: bool = typer.Option(
        False, "--allow-critical", help="CLI half of critical opt-in."
    ),
) -> None:
    """Plan an experiment against a topology and print it as JSON."""
    graph = _build_graph(list(process), list(service), host, compose)
    store = _store(db)
    try:
        cfg_id, topo_id, fingerprint, _ctx = _prepare(
            config_path=config,
            profile=profile,
            allow_critical=allow_critical,
            store=store,
            graph=graph,
            compose=compose,
        )
        _, plan_obj = _plan_from_spec(
            spec_path,
            graph,
            config_snapshot_id=cfg_id,
            topology_snapshot_id=topo_id,
            environment_fingerprint_value=fingerprint,
            store=store,
        )
        typer.echo(plan_obj.model_dump_json(indent=2))
    finally:
        store.close()

@app.command()
def run(
    spec_path: str = typer.Argument(..., help="Path to the experiment spec YAML."),
    db: str = typer.Option(DEFAULT_DB, "--db", help="SQLite database path."),
    process: list[str] = typer.Option(
        [], "--process", "-p", help="Local process node as name=pid."
    ),
    service: list[str] = typer.Option([], "--service", help="Logical service node name."),
    host: str = typer.Option("local", "--host", help="Host node name."),
    compose: str | None = typer.Option(None, "--compose", help="docker-compose.yaml blueprint."),
    config: str | None = typer.Option(None, "--config", help="mayhem.yaml path."),
    profile: str | None = typer.Option(None, "--profile", help="Profile overlay name."),
    allow_critical: bool = typer.Option(
        False, "--allow-critical", help="CLI half of critical opt-in."
    ),
) -> None:
    """Plan then execute an experiment; prints the run summary."""
    graph = _build_graph(list(process), list(service), host, compose)
    store = _store(db)
    try:
        cfg_id, topo_id, fingerprint, ctx = _prepare(
            config_path=config,
            profile=profile,
            allow_critical=allow_critical,
            store=store,
            graph=graph,
            compose=compose,
        )
        _, plan_obj = _plan_from_spec(
            spec_path,
            graph,
            config_snapshot_id=cfg_id,
            topology_snapshot_id=topo_id,
            environment_fingerprint_value=fingerprint,
            store=store,
        )
        engine = RunEngine(store, SQLiteLeaseSink(store), safety=ctx, live_graph=lambda: graph)
        result = engine.execute(plan_obj)
        typer.echo(result.summary_md())
        raise typer.Exit(code=0 if result.status == "completed" else 1)
    except SafetyRefusedError as exc:
        typer.echo(f"safety.refused [{exc.reason_code}] {exc}", err=True)
        raise typer.Exit(code=2) from None
    finally:
        store.close()


@app.command("status")
def status(
    db: str = typer.Option(DEFAULT_DB, "--db", help="SQLite database path."),
    run_id: str | None = typer.Option(None, "--run", help="Show one run in detail."),
) -> None:
    """Show runs recorded in the database."""
    store = _store(db)
    try:
        if run_id is not None:
            rows = store.query("SELECT * FROM runs WHERE id = ?", (run_id,))
            if not rows:
                typer.echo(f"no such run: {run_id}")
                raise typer.Exit(code=1)
            row = rows[0]
            typer.echo(json.dumps(dict(row), indent=2))
            return
        rows = store.query("SELECT id, kind, status, started_at FROM runs ORDER BY started_at DESC")
        for row in rows:
            typer.echo(
                f"{row['id']:<28} {row['kind']:<13} {row['status']:<10} {row['started_at'] or '-'}"
            )
        if not rows:
            typer.echo("(no runs yet)")
    finally:
        store.close()


@app.command()
def recover(
    run_id: str = typer.Argument(..., help="Run whose orphaned leases to compensate."),
    db: str = typer.Option(DEFAULT_DB, "--db", help="SQLite database path."),
) -> None:
    """Recover every orphaned fault lease belonging to a run."""
    store = _store(db)
    try:
        recovered = RunEngine(store, SQLiteLeaseSink(store)).recover_run(run_id)
        if not recovered:
            typer.echo(f"nothing to recover for {run_id}")
            return
        for lease_id in recovered:
            typer.echo(f"recovered lease {lease_id}")
    finally:
        store.close()


@app.command()
def janitor(
    db: str = typer.Option(DEFAULT_DB, "--db", help="SQLite database path."),
) -> None:
    """Run one janitor sweep over expired/orphaned leases."""
    store = _store(db)
    try:
        result = Janitor(SQLiteLeaseSink(store)).sweep()
        counts = (
            f"expired={len(result.expired)}"
            f" recovered={len(result.recovered)}"
            f" dirty={len(result.dirty)}"
        )
        typer.echo(counts)
        raise typer.Exit(code=1 if result.dirty else 0)
    finally:
        store.close()


if __name__ == "__main__":
    app()
