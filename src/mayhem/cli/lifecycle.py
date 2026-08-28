"""Lifecycle commands: validate -> plan -> run -> observe -> recover."""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from pathlib import Path
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
from mayhem.domain.common import utc_now
from mayhem.domain.events import Event, EventKind
from mayhem.infra.lease_repository import SQLiteLeaseSink

if TYPE_CHECKING:
    from mayhem.controller.janitor import SweepResult
    from mayhem.domain.topology import TopologyGraph


def _ctx(ctx: click.Context) -> CliContext:
    obj = ctx.obj
    assert isinstance(obj, CliContext)
    return obj


def _gate_faults(engine_name: str, plan: object, graph: object) -> None:
    """Refuse a run whose faults are proven inert in the live environment.

    Gated here (not at plan time) because the verdict depends on what the
    *running* container actually has — binaries, capabilities and uid. Water
    user: an execution whose faults cannot perturb the targets degrades into
    a survey; we abort before any lease forms.
    """
    from mayhem.agents.impact import scan_plan_faults as _scan
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.topology import TopologyGraph

    if not isinstance(plan, ExecutionPlan) or not isinstance(graph, TopologyGraph):
        return
    if not engine_name:
        click.echo(
            "warning: no engine configured — skipping pre-run fault gate", err=True
        )
        return
    verdicts, engine_probed = _scan(plan, graph, engine_name)
    dead = [v for v in verdicts if not v.impact_possible and v.probed]
    unreachable = [v for v in verdicts if not v.probed and v.container != "?"]
    if dead:
        lines = "\n".join(
            f"  - {v.fault_id} → {v.container}: {v.note}"
            for v in dead
        )
        raise click.ClickException(
            "Fault gate: target containers cannot actually be perturbed "
            f"({len(dead)} inert injection(s)) — add the missing tooling and "
            "re-run.\n" + lines
        )
    if unreachable:
        click.echo(
            "warning: runtime unreachable for "
            + ", ".join(f"{v.fault_id}@{v.container}" for v in unreachable)
            + " — impact of those faults cannot be gate-checked before the run",
            err=True,
        )


def _debug_progress() -> Callable[[Event], None]:
    """Timestamped, step-by-step live renderer for ``mayhem --debug run``.

    Hooks the engine's in-process event observer (ADR-0009 journal): each step
    and fault transition is echoed the instant it happens, instead of the
    run summary appearing only at the end. Locked so parallel steps can't
    interleave mid-line.
    """

    lock = threading.Lock()

    def _line(event: Event) -> str | None:
        kind = event.kind
        ts = utc_now().strftime("%H:%M:%S")
        if kind is EventKind.RUN_STARTED:
            return f"{ts} run {event.run_id} started"
        if kind is EventKind.STEP_STARTED:
            return f"{ts}   -> {event.detail.get('step')}"
        if kind is EventKind.FAULT_INJECTED:
            return (
                f"{ts}      injected {event.detail.get('fault')}"
                f" (lease {event.detail.get('lease')})"
            )
        if kind is EventKind.STEP_FINISHED:
            return f"{ts}   [ok] {event.detail.get('step')}: {event.detail.get('detail')}"
        if kind is EventKind.STEP_SKIPPED:
            return f"{ts}   [FAIL] {event.detail.get('step')}: {event.detail.get('detail')}"
        return None

    def on_event(event: Event) -> None:
        line = _line(event)
        if line is None:
            return
        with lock:
            click.echo(line)

    return on_event


def _compose_option[F: Callable[..., object]](fn: F) -> F:
    """Only topology input for drill commands is the compose blueprint.

    ``--process``/``--service``/``--host`` were removed in Phase 6 — drill
    specs are compose-native and identify targets by ``container_name``.
    Omit ``--compose`` to auto-detect a compose file in the cwd.
    """
    return click.option(
        "--compose",
        type=str,
        default=None,
        help="docker-compose.yaml blueprint (auto-detected in cwd if omitted).",
    )(fn)


_SPEC_CANDIDATES = ("mayhem.yaml", "mayhem.yml")


def _resolve_spec(explicit: str | None) -> str:
    """Resolve the drill spec file from user input.

    Accepts two forms:

      * ``None`` or empty — auto-detect ``mayhem.yaml`` in the cwd.
      * A file path — use it directly (error if missing).

    ``mayhem run`` with no path therefore imports ``mayhem.yaml`` from the
    directory the user invokes it from, unless an explicit spec is given.
    """
    if explicit:
        target = Path(explicit)
        if not target.is_file():
            # A caller-provided path that does not exist is a validation
            # failure (schema/input error), not a usage mistake — map it to
            # EXIT code VALIDATION_ERROR via FileNotFoundError.
            raise FileNotFoundError(f"spec file not found: {target}")
        return str(target)
    for name in _SPEC_CANDIDATES:
        candidate = Path.cwd() / name
        if candidate.is_file():
            return str(candidate)
    raise click.UsageError(f"no spec file in cwd; expected one of: {', '.join(_SPEC_CANDIDATES)}")


def _resolve_engine_from_state() -> str:
    """Resolve the CLI engine flag (``--podman``) to a concrete engine name."""
    from mayhem.cli.app import _STATE
    from mayhem.cli.topology import _resolve_engine

    return _resolve_engine(str(_STATE.get("engine", ""))) or "podman"


def _graph_from(ctx: click.Context, compose: str | None) -> tuple[TopologyGraph, str | None]:
    from mayhem.cli.topology import _resolve_compose

    resolved = _resolve_compose(compose)
    try:
        return build_graph(resolved), resolved
    except ValueError as exc:
        raise click.UsageError(str(exc), ctx=ctx) from None


@click.command("validate")
@_compose_option
@click.argument("experiment", type=click.Path(), required=False, default=None)
@click.pass_context
def validate(ctx: click.Context, experiment: str | None, compose: str | None) -> None:
    """Compile a drill spec and run every safety gate without executing it."""
    graph, resolved_compose = _graph_from(ctx, compose)
    experiment = _resolve_spec(experiment)
    obj = _ctx(ctx)
    store = open_store(obj.db)
    try:
        prepared = prepare(
            config_path=obj.config,
            profile=obj.profile,
            allow_critical=obj.allow_critical,
            store=store,
            graph=graph,
            compose=resolved_compose,
            spec_path=experiment,
        )
        compiled = plan_from_spec(
            experiment, graph, prepared=prepared, engine=_resolve_engine_from_state()
        )
    finally:
        store.close()
    click.echo(
        f"validated {compiled.run_id}: {len(compiled.plan.steps)} step(s), "
        f"fingerprint {prepared.fingerprint[:12]}"
    )


@click.command("plan")
@_compose_option
@click.argument("experiment", type=click.Path(), required=False, default=None)
@click.pass_context
def plan(ctx: click.Context, experiment: str | None, compose: str | None) -> None:
    """Compile a drill spec against a topology and print the frozen plan JSON."""
    graph, resolved_compose = _graph_from(ctx, compose)
    experiment = _resolve_spec(experiment)
    obj = _ctx(ctx)
    store = open_store(obj.db)
    try:
        prepared = prepare(
            config_path=obj.config,
            profile=obj.profile,
            allow_critical=obj.allow_critical,
            store=store,
            graph=graph,
            compose=resolved_compose,
            spec_path=experiment,
        )
        compiled = plan_from_spec(
            experiment, graph, prepared=prepared, engine=_resolve_engine_from_state()
        )
    finally:
        store.close()
    click.echo(compiled.plan.model_dump_json(indent=2))


@click.command("run")
@_compose_option
@click.argument("experiment", type=click.Path(), required=False, default=None)
@click.pass_context
def run(ctx: click.Context, experiment: str | None, compose: str | None) -> None:
    """Compile then execute a drill spec; prints the run summary."""
    graph, resolved_compose = _graph_from(ctx, compose)
    experiment = _resolve_spec(experiment)
    obj = _ctx(ctx)
    store = open_store(obj.db)
    try:
        prepared = prepare(
            config_path=obj.config,
            profile=obj.profile,
            allow_critical=obj.allow_critical,
            store=store,
            graph=graph,
            compose=resolved_compose,
            spec_path=experiment,
        )
        compiled = plan_from_spec(
            experiment, graph, prepared=prepared, engine=_resolve_engine_from_state()
        )
        engine_name = _resolve_engine_from_state()
        _gate_faults(engine_name, compiled.plan, graph)
        engine = engine_for(
            store,
            engine_name,
            live_graph=lambda: build_graph(resolved_compose),
            on_event=_debug_progress() if obj.debug else None,
        )
        result = engine.execute(compiled.plan)
        if obj.debug:
            # per-step lines were streamed live; print the consolidated trailer
            trailer = [
                f"**status**: {result.status}",
                f"**wall**: {result.wall_seconds:.1f}s",
            ]
            trailer.extend(
                f"- **DIRTY LEASE** {lease_id}: manual remediation required"
                for lease_id in result.dirty_leases
            )
            click.echo("\n".join(trailer))
        else:
            click.echo(result.summary_md())
        if result.status != "completed":
            ctx.exit(int(ExitCode.EXPERIMENT_FAILURE))
    finally:
        store.close()


@click.command("status")
@click.option("--db", "db_opt", default=None, help="SQLite database path.")
@click.option("--run", "run_id", default=None, help="Show one run in detail.")
@click.option("--limit", type=int, default=20, show_default=True, help="Rows to list.")
@click.option("--json", "json_flag", is_flag=True, default=False, help="Output as JSON.")
@click.pass_context
def status(
    ctx: click.Context, db_opt: str | None, run_id: str | None, limit: int, json_flag: bool
) -> None:
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
        rows = recent_runs(store, limit)
        if json_flag:
            click.echo(json.dumps(rows, indent=2))
        else:
            for row in rows:
                started = row["started_at"] or "-"
                click.echo(f"{row['id']:<28} {row['kind']:<13} {row['status']:<10} {started}")
    finally:
        store.close()


@click.command("history")
@click.argument("run_id")
@click.option("--json", "json_flag", is_flag=True, default=False, help="Output as JSON.")
@click.pass_context
def history(ctx: click.Context, run_id: str, json_flag: bool) -> None:
    """Print steps, events, and leases recorded for one run."""
    store = open_store(_ctx(ctx).db)
    try:
        journal = run_journal(store, run_id)
    finally:
        store.close()
    click.echo(json.dumps(journal, indent=2))


@click.command("recover")
@click.argument("run_id")
@click.pass_context
def recover(ctx: click.Context, run_id: str) -> None:
    """Recover every orphaned fault lease belonging to a run."""
    store = open_store(_ctx(ctx).db)
    try:
        recovered = engine_for(store, _resolve_engine_from_state()).recover_run(run_id)
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
