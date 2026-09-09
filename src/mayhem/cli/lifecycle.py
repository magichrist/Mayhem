"""Lifecycle commands: validate -> plan -> run -> observe -> recover."""

from __future__ import annotations

import dataclasses
import json
import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

import click

from mayhem.cli import style
from mayhem.cli.context import DEFAULT_DB, CliContext
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.services import (
    build_graph,
    engine_for,
    open_store,
    plan_from_spec,
    plan_maniac_from_spec,
    prepare,
    recent_runs,
    run_detail,
    run_journal,
)
from mayhem.controller.janitor import Janitor
from mayhem.controller.planner import restrict_plan_to_container, synthesize_maniac_spec
from mayhem.domain.common import utc_now
from mayhem.domain.events import Event, EventKind
from mayhem.infra.lease_repository import SQLiteLeaseSink

if TYPE_CHECKING:
    from mayhem.controller.executor import RunResult
    from mayhem.controller.janitor import SweepResult
    from mayhem.domain.experiments import DrillSpec
    from mayhem.domain.topology import TopologyGraph
    from mayhem.infra.store import Store


def _ctx(ctx: click.Context) -> CliContext:
    obj = ctx.obj
    assert isinstance(obj, CliContext)
    return obj


def _pid_alive(pid: int) -> bool:
    """Best-effort local liveness probe (kill(pid, 0))."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else


def _run_liveness(store: Store, run_id: str) -> bool | None:
    """False when the controller owning ``run_id`` is provably gone.

    A terminal run (or a 'running' run whose controller pid is dead) cannot
    ever release its leases — the janitor reclaims them before TTL instead of
    leaving the next ``run`` to hit a ``LeaseConflictError``. Unknown runs
    and live controllers return True/None and stay on TTL policy.
    """
    rows = store.query("SELECT status, controller_pid FROM runs WHERE id = ?", (run_id,))
    if not rows:
        return None
    status, pid = rows[0]
    if status in ("completed", "failed", "aborted"):
        return False
    if pid and not _pid_alive(pid):
        return False
    return None


def _run_liveness_resolver(store: Store) -> Callable[[str], bool | None]:
    return lambda run_id: _run_liveness(store, run_id)


def _sweep_before_run(store: Store) -> None:
    """Best-effort sweep so a crashed run's sticky leases do not wedge
    the very next ``run`` (the users' reported pain: janitor 'did nothing'
    because it had to be invoked manually, and within-TTL leases were never
    reclaimed). Owner-gone leases are reclaimed before TTL; anything still
    live is skipped and acquire() re-attempts the reap."""
    sweep: SweepResult = Janitor(SQLiteLeaseSink(store)).sweep(
        run_liveness=_run_liveness_resolver(store)
    )
    for lease_id in sweep.expired:
        click.echo(style.info(f"cleaned stale lease {lease_id} (expired)"))
    for lease_id in sweep.recovered:
        click.echo(style.info(f"recovered orphaned lease {lease_id}"))


def _gate_enabled() -> bool:
    """Impact gate refusal on unless the user explicitly opted out."""
    from mayhem.cli.app import _STATE

    return _STATE.get("gate", "1") != "0"


def _gate_bypasses(engine_name: str, plan: object, graph: object) -> dict[tuple[str, str], str]:
    """Probe the live containers and mark proved-inert faults for bypass.

    Fail-safe by contract: a fault whose tooling is *proven absent* in its
    target container is bypassed at execution time (``bypass due to <reason>``)
    and the rest of the run proceeds — the whole run is never aborted because
    one image lacks a binary. Only probed verdicts become bypasses; an
    unreachable runtime is warned about but still attempted.
    """
    from mayhem.agents.impact import (
        bypass_from_verdicts,
    )
    from mayhem.agents.impact import (
        scan_plan_faults as _scan,
    )
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.topology import TopologyGraph

    if not isinstance(plan, ExecutionPlan) or not isinstance(graph, TopologyGraph):
        return {}
    if not engine_name:
        click.echo(
            style.warn("warning:") + " no engine configured — skipping pre-run fault gate",
            err=True,
        )
        return {}
    verdicts, _engine_probed = _scan(plan, graph, engine_name)
    bypass = bypass_from_verdicts(verdicts)
    unreachable = [v for v in verdicts if not v.probed and v.container != "?"]
    if bypass:
        n = sum(len(reasons) for reasons in bypass.values())
        click.echo(
            style.info("info:") + f" impact gate — bypassing {n} inert fault injection(s):",
            err=True,
        )
        for (fid, cont), why in sorted(bypass.items()):
            click.echo(
                style.yellow(f"  - {fid} → {cont}: bypass due to {why}"),
                err=True,
            )
        _echo_install_hints(engine_name, plan, graph)
    if unreachable:
        click.echo(
            style.warn("warning:")
            + " runtime unreachable for "
            + ", ".join(f"{v.fault_id}@{v.container}" for v in unreachable)
            + " — impact of those faults cannot be gate-checked before the run",
            err=True,
        )
    return bypass


def _echo_install_hints(engine_name: str, plan: object, graph: object) -> None:
    """Per-container install guidance for the bypassed tooling (best effort).

    Detects each container's package manager from the live probe (apt-get /
    apk / dnf / yum / microdnf / zypper), prints the concrete ``engine exec``
    command that restores the tooling, and points at ``mayhem dependency
    install`` — which runs the same commands automatically. Probe or detection
    hiccups must never fail the run: the whole helper degrades to a no-op.
    """
    from mayhem.agents.impact import dependency_plan as _dep_plan
    from mayhem.agents.impact import host_tooling_gaps as _host_gaps
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.topology import TopologyGraph

    if not isinstance(plan, ExecutionPlan) or not isinstance(graph, TopologyGraph):
        return
    try:
        host_gaps = _host_gaps(plan)
        deps = _dep_plan(plan, graph, engine_name)
    except Exception:
        return
    if host_gaps:
        click.echo(
            style.info("info:") + " host tooling missing for bypassed faults:",
            err=True,
        )
        for name in host_gaps:
            click.echo(
                f"  {style.yellow('*')} {name}: runs on the drill host, not in a container — "
                "install it on the host (mayhem cannot install host packages)",
                err=True,
            )
    if not deps:
        return
    click.echo(
        style.info("info:") + " install missing tooling to un-bypass those faults:",
        err=True,
    )
    for dp in deps:
        if dp.installable:
            cmd = " && ".join(" ".join(argv) for argv in dp.install_argv())
            click.echo(
                f"  {style.yellow('*')} {dp.container}: "
                f"install {', '.join(dp.packages)} via {dp.pm} — {cmd}",
                err=True,
            )
        if dp.manual:
            click.echo(
                f"  {style.yellow('*')} {dp.container}: manual tooling — {', '.join(dp.manual)}",
                err=True,
            )
        if dp.caps_missing:
            click.echo(
                f"  {style.yellow('*')} {dp.container}: {', '.join(dp.caps_missing)} are runtime "
                "flags, not packages — restart with --cap-add",
                err=True,
            )
    click.echo(
        f"  {style.cyan('mayhem dependency install')} applies the above automatically.",
        err=True,
    )


def _resilience_trailer_lines(result: RunResult) -> list[str]:
    """Resilience score + post-run diagnosis lines for the debug trailer."""
    if result.resilience_report is None:
        return []
    return [line for line in result.resilience_report.summary_md().splitlines() if line]


def _debug_progress() -> Callable[[Event], None]:
    """Timestamped, step-by-step live renderer for ``mayhem --debug run``.

    Hooks the engine's in-process event observer (ADR-0009 journal): each step
    and fault transition is echoed the instant it happens, instead of the
    run summary appearing only at the end. Locked so parallel steps can't
    interleave mid-line.
    """

    lock = threading.Lock()

    def _line(event: Event) -> str | None:  # noqa: PLR0911 (one return per event kind)
        kind = event.kind
        ts = style.ts(utc_now().strftime("%H:%M:%S"))
        if kind is EventKind.RUN_STARTED:
            return f"{ts} {style.cyan(f'run {event.run_id} started')}"
        if kind is EventKind.STEP_STARTED:
            return f"{ts}   -> {style.cyan(str(event.detail.get('step') or ''))}"
        if kind is EventKind.FAULT_INJECTED:
            return (
                f"{ts}      {style.cyan('injected')} {event.detail.get('fault')}"
                f" (lease {event.detail.get('lease')})"
            )
        if kind is EventKind.STEP_FINISHED:
            step = event.detail.get("step")
            return f"{ts}   {style.ok('[ok]')} {step}: {event.detail.get('detail')}"
        if kind is EventKind.STEP_SKIPPED:
            step = event.detail.get("step")
            detail = str(event.detail.get("detail") or "").strip()
            if detail.startswith("bypass due to"):
                return f"{ts}   {style.yellow('[bypass]', bold=True)} {step}: " + style.yellow(
                    detail
                )
            return f"{ts}   {style.danger('[FAIL]', err=False)} {step}: {detail}"
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
        "-c",
        "--compose",
        type=str,
        default=None,
        help="docker-compose.yaml blueprint (auto-detected in cwd if omitted).",
    )(fn)


_SPEC_CANDIDATES = ("mayhem.yaml", "mayhem.yml")


def _is_drill_spec_file(path: Path) -> bool:
    """Cheap kind check: does ``path`` name a drill spec (``kind: drill``)?"""
    import yaml

    try:
        data = yaml.safe_load(path.read_text()) or {}
    except (OSError, yaml.YAMLError):
        return False
    return isinstance(data, dict) and data.get("kind") == "drill"


def _resolve_spec(explicit: str | None, config_path: str | None = None) -> str:
    """Resolve the drill spec file from user input.

    Accepts three forms, in order of precedence:

      1. An explicit positional path — use it directly (error if missing).
      2. ``--config`` — when it names a drill spec itself (``kind: drill``),
         the config flag doubles as the spec path, so
         ``mayhem --config drill.yaml maniac`` works from any directory.
      3. Auto-detect ``mayhem.yaml`` / ``mayhem.yml`` in the cwd.

    ``mayhem run`` with no path therefore imports ``mayhem.yaml`` from the
    directory the user invokes it from, unless an explicit spec (or a drill
    spec passed via ``--config``) is given.
    """
    if explicit:
        target = Path(explicit)
        if not target.is_file():
            # A caller-provided path that does not exist is a validation
            # failure (schema/input error), not a usage mistake — map it to
            # EXIT code VALIDATION_ERROR via FileNotFoundError.
            raise FileNotFoundError(f"spec file not found: {target}")
        return str(target)
    if config_path:
        target = Path(config_path)
        if target.is_file() and _is_drill_spec_file(target):
            return str(target)
    for name in _SPEC_CANDIDATES:
        candidate = Path.cwd() / name
        if candidate.is_file():
            return str(candidate)
    raise click.UsageError(f"no spec file in cwd; expected one of: {', '.join(_SPEC_CANDIDATES)}")


def _resolve_spec_pair(explicit: str | None, config_path: str | None) -> tuple[str, str | None]:
    """Resolve ``(spec_path, config_path)`` for the layered config layering.

    When ``--config`` doubled as the drill spec file (case 2 of
    :func:`_resolve_spec`), the returned config path is ``None`` so the config
    layers fall back to defaults (plus the ``skip_default_file_if_spec``
    guard) instead of re-parsing the spec as a strictly-forbidden config
    document.
    """
    spec = _resolve_spec(explicit, config_path=config_path)
    if (
        explicit is None
        and config_path is not None
        and Path(config_path).resolve() == Path(spec).resolve()
    ):
        return spec, None
    return spec, config_path


def _resolve_maniac_sources(
    explicit: str | None,
    config_path: str | None,
    graph: TopologyGraph,
    *,
    pool: str | None = None,
) -> tuple[str | None, str | None, DrillSpec | None]:
    """Resolve ``(spec_path, layered_config_path, synthesized_spec)`` for maniac.

    ``mayhem maniac`` is the one drill command that runs *without* an authored
    config: with only a compose blueprint given, the drill spec is derived
    from the topology (:func:`mayhem.controller.planner.synthesize_maniac_spec`)
    so the draw pool always matches the running stack. Input precedence:

      1. An explicit positional path — always the spec (error if missing).
      2. ``--config`` (or a cwd ``mayhem.yaml`` / ``mayhem.yml``) that is a
         drill spec — the spec, exactly like every other drill command.
      3. ``--config`` (or a cwd config doc) that is a plain config document —
         the layered config, with the spec synthesized from the topology; its
         ``maniac:`` block tunes the random draw.
      4. Nothing — pure defaults (no config document anywhere).

    ``synthesized_spec`` is non-``None`` only when the spec was built from the
    graph; the layered config path is then still honored (case 3), so a
    user-supplied ``mayhem.yaml`` keeps working as the tuning dial. ``pool``
    (``--ctr``) additionally restricts the *synthesized* draw pool to a single
    container subtree, so every drawn round lands on the requested container.
    """
    pool_graph = graph.restrict_to(pool) if pool is not None else graph
    if explicit:
        return _resolve_spec(explicit, config_path=config_path), config_path, None
    if config_path:
        target = Path(config_path)
        if target.is_file() and _is_drill_spec_file(target):
            return str(target), None, None
        return None, str(target), synthesize_maniac_spec(pool_graph)
    for name in _SPEC_CANDIDATES:
        candidate = Path.cwd() / name
        if candidate.is_file():
            if _is_drill_spec_file(candidate):
                return str(candidate), config_path, None
            return None, str(candidate), synthesize_maniac_spec(pool_graph)
    return None, config_path, synthesize_maniac_spec(pool_graph)


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


def _require_container(ctr: str, graph: TopologyGraph, ctx: click.Context) -> None:
    """Loud guard for ``--ctr``: the container must exist in the topology."""
    if not graph.node_ids_for_container(ctr):
        available = ", ".join(graph.container_names()) or "<none>"
        raise click.UsageError(
            f"no container named {ctr!r} in the compose topology "
            f"(available: {available}) — tip: use a container_name: value "
            "from the blueprint or the runtime container name",
            ctx=ctx,
        )


@click.command("validate")
@_compose_option
@click.argument("experiment", type=click.Path(), required=False, default=None)
@click.pass_context
def validate(ctx: click.Context, experiment: str | None, compose: str | None) -> None:
    """Compile a drill spec and run every safety gate without executing it."""
    graph, resolved_compose = _graph_from(ctx, compose)
    obj = _ctx(ctx)
    experiment, config_for_layers = _resolve_spec_pair(experiment, obj.config)
    store = open_store(obj.db)
    try:
        prepared = prepare(
            config_path=config_for_layers,
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
        f"{style.ok('validated')} {style.cyan(compiled.run_id)}: "
        f"{len(compiled.plan.steps)} step(s), "
        f"fingerprint {prepared.fingerprint[:12]}"
    )


@click.command("plan")
@_compose_option
@click.argument("experiment", type=click.Path(), required=False, default=None)
@click.pass_context
def plan(ctx: click.Context, experiment: str | None, compose: str | None) -> None:
    """Compile a drill spec against a topology and print the frozen plan JSON."""
    graph, resolved_compose = _graph_from(ctx, compose)
    obj = _ctx(ctx)
    experiment, config_for_layers = _resolve_spec_pair(experiment, obj.config)
    store = open_store(obj.db)
    try:
        prepared = prepare(
            config_path=config_for_layers,
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
@click.option(
    "--ctr",
    "ctr",
    type=str,
    default=None,
    metavar="CONTAINER",
    help="Only execute faults on this container (container_name from the compose "
    "blueprint, or the runtime container name).",
)
@click.argument("experiment", type=click.Path(), required=False, default=None)
@click.pass_context
def run(ctx: click.Context, experiment: str | None, compose: str | None, ctr: str | None) -> None:
    """Compile then execute a drill spec; prints the run summary."""
    graph, resolved_compose = _graph_from(ctx, compose)
    obj = _ctx(ctx)
    if ctr is not None:
        _require_container(ctr, graph, ctx)
    experiment, config_for_layers = _resolve_spec_pair(experiment, obj.config)
    store = open_store(obj.db)
    try:
        _sweep_before_run(store)
        prepared = prepare(
            config_path=config_for_layers,
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
        if ctr is not None:
            compiled = dataclasses.replace(
                compiled, plan=restrict_plan_to_container(compiled.plan, ctr, graph)
            )
            click.echo(
                style.info("info:") + f" --ctr scoped the plan to container {style.cyan(ctr)}",
                err=True,
            )
        engine_name = _resolve_engine_from_state()
        bypass: dict[tuple[str, str], str] = {}
        if _gate_enabled():
            bypass = _gate_bypasses(engine_name, compiled.plan, graph)
        else:
            click.echo(
                style.warn("warning:") + " impact gate skipped (--skip-gate); inert faults may run",
                err=True,
            )
        engine = engine_for(
            store,
            engine_name,
            live_graph=lambda: build_graph(resolved_compose),
            on_event=_debug_progress() if obj.debug else None,
            bypass=bypass,
        )
        result = engine.execute(compiled.plan)
        if obj.debug:
            # per-step lines were streamed live; print the consolidated trailer
            trailer = [
                f"**status**: {style.state(result.status)}",
                f"**wall**: {style.ts(f'{result.wall_seconds:.1f}s')}",
            ]
            trailer.extend(
                style.danger(f"- **DIRTY LEASE** {lease_id}: manual remediation required")
                for lease_id in result.dirty_leases
            )
            trailer.extend(_resilience_trailer_lines(result))
            click.echo("\n".join(trailer))
        else:
            click.echo(result.summary_md())
        # Copy-paste handle for follow-up commands: `mayhem history <run_id>`.
        click.echo(
            f"\n{style.ok('run')} {style.cyan(compiled.run_id)} — "
            f"inspect with {style.yellow(f'mayhem history {compiled.run_id}')}"
        )
        if result.status != "completed":
            ctx.exit(int(ExitCode.EXPERIMENT_FAILURE))
    finally:
        store.close()


@click.command("maniac")
@_compose_option
@click.option(
    "-s",
    "--steps",
    "steps",
    type=click.IntRange(1, 500),
    default=None,
    help="Draw exactly N random fault rounds (overrides config.maniac.run_level).",
)
@click.option(
    "--ctr",
    "ctr",
    type=str,
    default=None,
    metavar="CONTAINER",
    help="Only draw random fault rounds against this container (container_name "
    "from the compose blueprint, or the runtime container name).",
)
@click.argument("experiment", type=click.Path(), required=False, default=None)
@click.pass_context
def maniac(
    ctx: click.Context,
    experiment: str | None,
    compose: str | None,
    steps: int | None,
    ctr: str | None,
) -> None:
    """Run a drill spec as random fault injection (ADR-M5-1).

    Compiles the spec exactly like ``mayhem run`` but replaces the authored
    execution with ``config.maniac.run_level`` random (container, fault)
    rounds dialed by ``config.maniac.level`` (1-5). ``-s/--steps`` overrides
    the round count on the command line. Safety gates, per-round
    compensation, success criteria and observability are unchanged; ``seed``
    makes the draw reproducible.

    With no spec given (positional, ``--config`` drill spec, or a cwd
    ``mayhem.yaml`` drill spec), the spec is synthesized from the compose
    topology — every container pooled with the full container-addressable
    fault catalog — so ``mayhem maniac -c docker-compose.yml`` works as a
    zero-config chaos run. A ``--config``/cwd ``mayhem.yaml`` that is a plain
    config document still tunes the draw via its ``maniac:`` block.
    ``--ctr`` narrows the draw pool to a single container (and, for authored
    specs, drops every other container's rounds), so the run can only ever
    perturbs the requested container.
    """
    graph, resolved_compose = _graph_from(ctx, compose)
    obj = _ctx(ctx)
    if ctr is not None:
        _require_container(ctr, graph, ctx)
    spec_path, config_for_layers, synthesized = _resolve_maniac_sources(
        experiment, obj.config, graph, pool=ctr
    )
    if spec_path is None and synthesized is None:
        raise click.UsageError("no drill spec, and nothing to synthesize")
    if spec_path is None:
        assert synthesized is not None  # resolver invariant, see above
        spec_path = f"<{synthesized.name}>"
    store = open_store(obj.db)
    try:
        prepared = prepare(
            config_path=config_for_layers,
            profile=obj.profile,
            allow_critical=obj.allow_critical,
            store=store,
            graph=graph,
            compose=resolved_compose,
            spec_path=spec_path,
        )
        compiled = plan_maniac_from_spec(
            spec_path,
            graph,
            prepared=prepared,
            engine=_resolve_engine_from_state(),
            config_path=config_for_layers,
            profile=obj.profile,
            steps=steps,
            spec=synthesized,
        )
        if ctr is not None:
            compiled = dataclasses.replace(
                compiled, plan=restrict_plan_to_container(compiled.plan, ctr, graph)
            )
            click.echo(
                style.info("info:") + f" --ctr scoped the draw to container {style.cyan(ctr)}",
                err=True,
            )
        draws = sum(1 for step in compiled.plan.steps if step.fault is not None)
        if synthesized is not None:
            click.echo(
                style.info("info:") + " maniac mode — no drill spec; synthesized config "
                f"from compose topology "
                f"({len(synthesized.containers)} container(s)), "
                f"{draws} random fault round(s) drawn",
                err=True,
            )
        else:
            click.echo(
                style.info("info:") + f" maniac mode — {draws} random fault round(s) drawn",
                err=True,
            )
        engine_name = _resolve_engine_from_state()
        bypass: dict[tuple[str, str], str] = {}
        if _gate_enabled():
            bypass = _gate_bypasses(engine_name, compiled.plan, graph)
        else:
            click.echo(
                style.warn("warning:") + " impact gate skipped (--skip-gate); inert faults may run",
                err=True,
            )
        engine = engine_for(
            store,
            engine_name,
            live_graph=lambda: build_graph(resolved_compose),
            on_event=_debug_progress() if obj.debug else None,
            bypass=bypass,
        )
        result = engine.execute(compiled.plan)
        if obj.debug:
            trailer = [
                f"**status**: {style.state(result.status)}",
                f"**wall**: {style.ts(f'{result.wall_seconds:.1f}s')}",
            ]
            trailer.extend(
                style.danger(f"- **DIRTY LEASE** {lease_id}: manual remediation required")
                for lease_id in result.dirty_leases
            )
            trailer.extend(_resilience_trailer_lines(result))
            click.echo("\n".join(trailer))
        else:
            click.echo(result.summary_md())
        click.echo(
            f"\n{style.ok('run')} {style.cyan(compiled.run_id)} — "
            f"inspect with {style.yellow(f'mayhem history {compiled.run_id}')}"
        )
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
                sid = style.state(f"{row['status']:<10}")
                click.echo(f"{row['id']:<28} {row['kind']:<13} {sid} {started}")
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
            click.echo(f"nothing to recover for {style.cyan(run_id)}")
            return
        for lease_id in recovered:
            click.echo(f"recovered lease {style.cyan(lease_id)}")
    finally:
        store.close()


@click.command("janitor")
@click.pass_context
def janitor(ctx: click.Context) -> None:
    """Reclaim leases past TTL — or owned by a controller that is gone."""
    store = open_store(_ctx(ctx).db)
    try:
        sweep: SweepResult = Janitor(SQLiteLeaseSink(store)).sweep(
            run_liveness=_run_liveness_resolver(store)
        )
    finally:
        store.close()
    if sweep.quiet:
        click.echo(style.cyan("janitor: nothing to do"))
        return
    for lease_id in sweep.expired:
        click.echo(f"expired pending lease {style.cyan(lease_id)}")
    for lease_id in sweep.recovered:
        click.echo(f"recovered orphaned lease {style.cyan(lease_id)}")
    for lease_id in sweep.dirty:
        click.echo(
            style.danger(f"DIRTY lease {lease_id}: compensation failed; manual action required")
        )
    if sweep.dirty:
        ctx.exit(int(ExitCode.RECOVERY_FAILURE))
