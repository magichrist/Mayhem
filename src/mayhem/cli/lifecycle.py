"""Lifecycle commands: validate -> plan -> run -> observe -> recover."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import TYPE_CHECKING

import click

from mayhem.cli.context import DEFAULT_DB, CliContext
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.services import (
    build_graph,
    engine_for,
    open_store,
    plan_from_spec,
    prepare,
    recent_runs,
    run_detail,
    run_journal,
)
from mayhem.controller.janitor import Janitor
from mayhem.infra.lease_repository import SQLiteLeaseSink

if TYPE_CHECKING:
    from mayhem.controller.janitor import SweepResult
    from mayhem.domain.topology import TopologyGraph

ProcessArgs = tuple[str, ...]


def _ctx(ctx: click.Context) -> CliContext:
    obj = ctx.obj
    assert isinstance(obj, CliContext)
    return obj


def _topology_options[F: Callable[..., object]](fn: F) -> F:
    for opt in reversed(
        (
            click.option("--process", "-p", multiple=True, help="Local process node as name=pid."),
            click.option("--service", multiple=True, help="Logical service node name."),
            click.option("--host", default="local", show_default=True, help="Host node name."),
            click.option(
                "--compose",
                type=str,
                default=None,
                help="docker-compose.yaml blueprint.",
            ),
        )
    ):
        fn = opt(fn)
    return fn


def _graph_from(
    ctx: click.Context,
    process: ProcessArgs,
    service: ProcessArgs,
    host: str,
    compose: str | None,
) -> TopologyGraph:
    from mayhem.cli.topology import _resolve_compose

    resolved = _resolve_compose(compose)
    try:
        return build_graph(list(process), list(service), host, resolved)
    except ValueError as exc:
        raise click.UsageError(str(exc), ctx=ctx) from None


@click.command("validate")
@_topology_options
@click.argument("experiment", type=click.Path())
@click.pass_context
def validate(
    ctx: click.Context,
    experiment: str,
    process: ProcessArgs,
    service: ProcessArgs,
    host: str,
    compose: str | None,
) -> None:
    """Compile an experiment and run every safety gate without executing it."""
    graph = _graph_from(ctx, process, service, host, compose)
    obj = _ctx(ctx)
    store = open_store(obj.db)
    try:
        prepared = prepare(
            config_path=obj.config,
            profile=obj.profile,
            allow_critical=obj.allow_critical,
            store=store,
            graph=graph,
            compose=compose,
        )
        compiled = plan_from_spec(experiment, graph, prepared=prepared, store=None)
    finally:
        store.close()
    click.echo(
        f"validated {compiled.run_id}: {len(compiled.plan.steps)} step(s), "
        f"fingerprint {prepared.fingerprint[:12]}"
    )


@click.command("plan")
@_topology_options
@click.argument("experiment", type=click.Path())
@click.pass_context
def plan(
    ctx: click.Context,
    experiment: str,
    process: ProcessArgs,
    service: ProcessArgs,
    host: str,
    compose: str | None,
) -> None:
    """Plan an experiment against a topology and print the frozen plan JSON."""
    graph = _graph_from(ctx, process, service, host, compose)
    obj = _ctx(ctx)
    store = open_store(obj.db)
    try:
        prepared = prepare(
            config_path=obj.config,
            profile=obj.profile,
            allow_critical=obj.allow_critical,
            store=store,
            graph=graph,
            compose=compose,
        )
        compiled = plan_from_spec(experiment, graph, prepared=prepared, store=None)
    finally:
        store.close()
    click.echo(compiled.plan.model_dump_json(indent=2))


@click.command("run")
@_topology_options
@click.argument("experiment", type=click.Path())
@click.pass_context
def run(
    ctx: click.Context,
    experiment: str,
    process: ProcessArgs,
    service: ProcessArgs,
    host: str,
    compose: str | None,
) -> None:
    """Plan then execute an experiment; prints the run summary."""
    graph = _graph_from(ctx, process, service, host, compose)
    obj = _ctx(ctx)
    store = open_store(obj.db)
    try:
        prepared = prepare(
            config_path=obj.config,
            profile=obj.profile,
            allow_critical=obj.allow_critical,
            store=store,
            graph=graph,
            compose=compose,
        )
        compiled = plan_from_spec(experiment, graph, prepared=prepared, store=None)
        engine = engine_for(store)
        result = engine.execute(compiled.plan)
        click.echo(result.summary_md())
        if result.status != "completed":
            ctx.exit(int(ExitCode.EXPERIMENT_FAILURE))
    finally:
        store.close()


@click.command("status")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--run", "run_id", default=None, help="Show one run in detail.")
@click.option("--limit", type=int, default=20, show_default=True, help="Rows to list.")
@click.pass_context
def status(ctx: click.Context, db_opt: str | None, run_id: str | None, limit: int) -> None:
    """Show runs recorded in the database."""
    db = db_opt or _ctx(ctx).db or DEFAULT_DB
    store = open_store(db)
    try:
        if run_id is not None:
            row = run_detail(store, run_id)
            if row is None:
                raise click.UsageError(f"no such run: {run_id}", ctx=ctx)
            click.echo(json.dumps(row, indent=2))
            return
        for row in recent_runs(store, limit):
            started = row["started_at"] or "-"
            click.echo(f"{row['id']:<28} {row['kind']:<13} {row['status']:<10} {started}")
    finally:
        store.close()


@click.command("history")
@click.argument("run_id")
@click.pass_context
def history(ctx: click.Context, run_id: str) -> None:
    """Print steps, events, and leases recorded for one run."""
    store = open_store(_ctx(ctx).db)
    try:
        journal = run_journal(store, run_id)
    finally:
        store.close()
    if not any(journal.values()):
        raise click.UsageError(f"no records for run: {run_id}", ctx=ctx)
    click.echo(json.dumps(journal, indent=2))


@click.command("recover")
@click.argument("run_id")
@click.pass_context
def recover(ctx: click.Context, run_id: str) -> None:
    """Recover every orphaned fault lease belonging to a run."""
    store = open_store(_ctx(ctx).db)
    try:
        recovered = engine_for(store).recover_run(run_id)
        if not recovered:
            click.echo(f"nothing to recover for {run_id}")
            return
        for lease_id in recovered:
            click.echo(f"recovered lease {lease_id}")
    finally:
        store.close()


@click.command("janitor")
@click.pass_context
def janitor(ctx: click.Context) -> None:
    """Sweep leases past their TTL; expire pending, compensate active ones."""
    store = open_store(_ctx(ctx).db)
    try:
        sweep: SweepResult = Janitor(SQLiteLeaseSink(store)).sweep()
    finally:
        store.close()
    if sweep.quiet:
        click.echo("janitor: nothing to do")
        return
    for lease_id in sweep.expired:
        click.echo(f"expired pending lease {lease_id}")
    for lease_id in sweep.recovered:
        click.echo(f"recovered orphaned lease {lease_id}")
    for lease_id in sweep.dirty:
        click.echo(f"DIRTY lease {lease_id}: compensation failed; manual action required")
    if sweep.dirty:
        ctx.exit(int(ExitCode.RECOVERY_FAILURE))
