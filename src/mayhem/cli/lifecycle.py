"""Lifecycle commands: validate -> plan -> run -> observe -> recover."""

from __future__ import annotations

import contextlib
import dataclasses
import json
import json as _json
import os
import threading
from collections.abc import Callable, Mapping
from math import isfinite
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import click

from mayhem.cli import style
from mayhem.cli.context import DEFAULT_DB, CliContext
from mayhem.cli.execution import (
    blast_radius_display,
    compensation_display,
    expected_evidence_display,
    migration_warning,
    reject_if_stale,
)
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.render import (
    render_evidence_human,
    render_plan_diff,
    render_preflight_human,
    render_preflight_json,
)
from mayhem.cli.services import (
    build_graph,
    engine_for,
    open_store,
    plan_from_spec,
    plan_maniac_from_spec,
    prepare,
    recent_runs,
    resolve_runtime_context,
    run_detail,
    run_journal,
    with_topology_fingerprint,
)
from mayhem.controller.janitor import Janitor
from mayhem.controller.plan_diff import diff_plans
from mayhem.controller.planner import (
    restrict_plan_to_container,
    synthesize_k8s_maniac_spec,
    synthesize_maniac_spec,
)
from mayhem.controller.preflight import build_preflight
from mayhem.controller.recovery import RecoveryService
from mayhem.domain.common import utc_now
from mayhem.domain.events import Event, EventKind
from mayhem.domain.evidence import EvidenceEnvelope
from mayhem.domain.execution_intent import intent_for_plan, require_explicit_approval
from mayhem.infra.evidence import (
    build_evidence,
    load_evidence,
    verify_evidence,
    write_evidence,
    write_evidence_file,
)
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.report import report_id_for_run

if TYPE_CHECKING:
    from mayhem.controller.executor import RunResult
    from mayhem.controller.janitor import SweepResult
    from mayhem.controller.steady_state import SteadyStateReport
    from mayhem.domain.execution_intent import ExecutionIntent
    from mayhem.domain.experiments import DrillSpec
    from mayhem.domain.observations import ObservationProvider, ObservationQuery, SloCriterion
    from mayhem.domain.preflight import Preflight
    from mayhem.domain.runtime_context import RuntimeContext
    from mayhem.domain.steady_state import SteadyStateSpec
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


def _project_run_liveness(row: dict[str, object]) -> dict[str, object]:
    projected = dict(row)
    status = str(row.get("status", ""))
    if status != "running":
        projected["liveness_status"] = status
        projected["controller_alive"] = None
        return projected
    raw_pid = row.get("controller_pid")
    if raw_pid is None:
        projected["liveness_status"] = "stale"
        projected["controller_alive"] = None
        return projected
    try:
        # ``controller_pid`` is a SQLite scalar (int | str | None); the
        # surrounding except clause is the real guard against a driver that
        # hands back something ``int()`` will not take.
        alive = _pid_alive(int(cast("int | str | bytes | bytearray", raw_pid)))
    except (TypeError, ValueError):
        alive = False
    projected["liveness_status"] = "running" if alive else "stale"
    projected["controller_alive"] = alive
    return projected


def _run_liveness_resolver(store: Store) -> Callable[[str], bool | None]:
    return lambda run_id: _run_liveness(store, run_id)


def _sweep_before_run(store: Store) -> None:
    """Best-effort sweep so a crashed run's sticky leases do not wedge
    the very next ``run`` (the users' reported pain: janitor 'did nothing'
    because it had to be invoked manually, and within-TTL leases were never
    reclaimed). Owner-gone leases are reclaimed before TTL; anything still
    live is skipped and acquire() re-attempts the reap."""
    sweep: SweepResult = Janitor(SQLiteLeaseSink(store)).sweep(
        run_liveness=_run_liveness_resolver(store), execute=True
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
    command that restores the tooling, and points at ``mayhem prepare
    dependencies install`` — which runs the same commands automatically. Probe
    or detection hiccups must never fail the run: the whole helper degrades to
    a no-op.
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
        f"  {style.cyan('mayhem prepare dependencies install')} applies the above automatically.",
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

    def _line(event: Event) -> str | None:
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


def _resolve_spec(
    explicit: str | None, config_path: str | None = None, compose_path: str | None = None
) -> str:
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
    if compose_path:
        compose = Path(compose_path)
        directory = compose if compose.is_dir() else compose.parent
        for name in _SPEC_CANDIDATES:
            candidate = directory / name
            if candidate.is_file():
                return str(candidate)
    for name in _SPEC_CANDIDATES:
        candidate = Path.cwd() / name
        if candidate.is_file():
            return str(candidate)
    raise click.UsageError(f"no spec file in cwd; expected one of: {', '.join(_SPEC_CANDIDATES)}")


def _resolve_spec_pair(
    explicit: str | None, config_path: str | None, compose_path: str | None = None
) -> tuple[str, str | None]:
    """Resolve ``(spec_path, config_path)`` for the layered config layering.

    When ``--config`` doubled as the drill spec file (case 2 of
    :func:`_resolve_spec`), the returned config path is ``None`` so the config
    layers fall back to defaults (plus the ``skip_default_file_if_spec``
    guard) instead of re-parsing the spec as a strictly-forbidden config
    document.
    """
    spec = _resolve_spec(explicit, config_path=config_path, compose_path=compose_path)
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
    engine: str | None = None,
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
    With ``engine == "kubernetes"`` the synthesizer builds a ``targets:`` spec
    from the manifest blueprint graph instead (k-plan-3 SP-3.6); ``pool`` is
    then refused by the caller (k8s rounds are target-scoped, not container-
    scoped).
    """
    if (engine or "") == "kubernetes":
        synthesize = synthesize_k8s_maniac_spec
    else:
        synthesize = synthesize_maniac_spec
    pool_graph = graph.restrict_to(pool) if pool is not None else graph
    if explicit:
        return _resolve_spec(explicit, config_path=config_path), config_path, None
    if config_path:
        target = Path(config_path)
        if target.is_file() and _is_drill_spec_file(target):
            return str(target), None, None
        return None, str(target), synthesize(pool_graph)
    for name in _SPEC_CANDIDATES:
        candidate = Path.cwd() / name
        if candidate.is_file():
            if _is_drill_spec_file(candidate):
                return str(candidate), config_path, None
            return None, str(candidate), synthesize(pool_graph)
    return None, config_path, synthesize(pool_graph)


def _resolve_engine_from_state() -> str:
    """Resolve the CLI engine flag (``--podman``) to a concrete engine name.

    This is the *explicit* selection that seeds
    :func:`_runtime_context`; the podman default is the CLI's long-standing
    behaviour, so the automatic path never reaches engine auto-detection (and
    therefore never refuses an unflagged run for ambiguity).
    """
    from mayhem.cli.app import _STATE
    from mayhem.cli.topology import _resolve_engine

    return _resolve_engine(str(_STATE.get("engine", ""))) or "podman"


def _graph_from(
    ctx: click.Context,
    compose: str | None,
    *,
    engine: str | None = None,
    target: str | None = None,
) -> tuple[TopologyGraph, str | None]:
    from mayhem.cli.topology import _resolve_compose

    resolved = _resolve_compose(compose)
    try:
        config_path = getattr(ctx.obj, "config", None) if ctx.obj is not None else None
        # The configuration overlay travels with the config path, so discovery
        # resolves target profiles from the same effective configuration every
        # other stage uses.
        config_profile = getattr(ctx.obj, "profile", None) if ctx.obj is not None else None
        return build_graph(
            resolved,
            engine_name=engine,
            target=target,
            config_path=config_path,
            profile=config_profile,
        ), resolved
    except ValueError as exc:
        raise click.UsageError(str(exc), ctx=ctx) from None


def _require_container(ctr: str, graph: TopologyGraph, ctx: click.Context) -> None:
    if not graph.node_ids_for_container(ctr):
        available = ", ".join(graph.container_names()) or "<none>"
        raise click.UsageError(
            f"no container named {ctr!r} in the compose topology "
            f"(available: {available}) — tip: use a container_name: value "
            "from the blueprint or the runtime container name",
            ctx=ctx,
        )


def _runtime_context(
    *,
    engine: str | None,
    target: str | None,
    config_path: str | None,
    profile: str | None = None,
) -> RuntimeContext:
    """Resolve the runtime once for a command.

    Every downstream step (discovery, planning, preflight, execution) takes
    this object instead of re-deriving an engine from a flag. The topology
    fingerprint is attached afterwards by
    :func:`with_topology_fingerprint`, once the graph exists. ``profile`` is
    the configuration overlay, so a Kubernetes target profile declared only in
    ``mayhem.{profile}.yaml`` is resolved here too.
    """
    return resolve_runtime_context(
        engine=engine, target=target, config_path=config_path, profile=profile
    )


def _preflight_for_run(
    *,
    graph: object,
    store: object,
    prepared: object,
    plan: object,
    target: str | None,
    engine: str,
    config_path: str | None = None,
    profile: str | None = None,
    runtime: RuntimeContext | None = None,
) -> Preflight:
    """Build the run's preflight.

    ``profile`` is the configuration overlay and is forwarded, so preflight
    validates target profiles against the same effective configuration — overlay
    included — that the run resolved them from.
    """
    fingerprint = getattr(prepared, "fingerprint", "") if prepared is not None else ""
    cfg_id = getattr(prepared, "config_snapshot_id", "") if prepared is not None else ""
    topo_id = getattr(prepared, "topology_snapshot_id", "") if prepared is not None else ""
    safety = getattr(prepared, "safety", None) if prepared is not None else None
    return build_preflight(
        spec_path=None,
        compose=None,
        graph=graph,
        store=store,
        config_path=config_path,
        profile=profile,
        allow_critical=getattr(safety, "allow_critical_cli", False)
        if safety is not None
        else False,
        target=target,
        engine=engine,
        plan=plan,
        safety=safety,
        fingerprint=fingerprint,
        config_snapshot_id=cfg_id,
        topology_snapshot_id=topo_id,
        runtime=runtime,
    )


def _emit_preflight(preflight: object, as_json: bool) -> None:
    if as_json:
        click.echo(render_preflight_json(preflight))
    else:
        click.echo(render_preflight_human(preflight))
        blast = getattr(preflight, "blast_radius", {}) or {}
        if blast:
            click.echo(blast_radius_display(blast))
        comp = getattr(preflight, "compensation_status", "")
        if comp:
            click.echo(compensation_display(comp))
        expected = getattr(preflight, "expected_evidence", ()) or ()
        if expected:
            click.echo(expected_evidence_display(expected))


def _execution_intent(
    plan: object,
    *,
    engine: str,
    target: str | None = None,
    preflight: object | None = None,
    break_glass: bool = False,
) -> ExecutionIntent:
    """Mint the approval record that authorizes one concrete run (v0.9.0).

    Built from the *preflight* that was just shown to the user, so the
    approval names exactly the plan, policy, and blast radius that were
    reviewed — and the engine re-checks the plan hash and engine before it
    opens the run. When a preflight exists, its resolved target identity wins
    over the raw ``--target`` string so the record matches what actually ran;
    the argument is only the fallback for callers that have no preflight.
    """
    policy_id = ""
    blast: dict[str, object] = {}
    identity = str(target or engine or "default")
    if preflight is not None:
        decisions = tuple(str(d) for d in getattr(preflight, "safety_decisions", ()) or ())
        policy_id = ";".join(decisions) or "default"
        blast = dict(getattr(preflight, "blast_radius", {}) or {})
        identity = str(getattr(preflight, "target_identity", "") or identity)
    return intent_for_plan(
        plan,
        engine=engine,
        target_identity=identity,
        policy_id=policy_id,
        blast_radius=blast,
        actor="cli:--execute",
        break_glass=break_glass,
    )


def _require_baseline_reference(
    store: Store,
    baseline_from: str,
    spec: SteadyStateSpec | None,
    ctx: click.Context,
) -> None:
    """Refuse a ``--baseline-from`` that cannot serve as a reference.

    Plan 03 step 6. The first run establishes what "healthy" means for a
    stack; every later fault is judged against *that*, which is the composable
    property neither CNCF project has. Naming an earlier run as the reference
    is therefore a claim about provenance, and this is where the claim is
    checked — before the fault is injected, not after.

    Two reasons it cannot be deferred to the post-run evaluation:

    * the evaluation runs inside :func:`_write_evidence_after_run`, which
      degrades to "steady-state evaluation unavailable" on any failure, so a bad
      reference there is discovered *after* the drill has already hit the
      target; and
    * the only alternative to a real reference is a fresh capture, which is
      exactly the silent substitution this feature exists to remove. A user
      who asked to compare against run A and was handed run B's own baseline
      has been handed a comparison against nothing while believing otherwise —
      the same class of false assurance the whole plan exists to eliminate.

    The read is the *same* read the reuse path performs
    (:func:`baseline_from_run` against the named signals), so the guard cannot
    pass a reference the evaluation would then reject.

    A drill with no ``steady_state:`` block returns immediately: the option has
    nothing to thread into there, and such a drill must render byte-identically
    with and without the flag.
    """
    if not baseline_from:
        return
    if spec is None or spec.empty:
        return
    from mayhem.controller.steady_state import (
        BaselineUnavailableError,
        SteadyStateEvaluationRepository,
        baseline_from_run,
    )

    signal_names = [str(signal.name) for signal in spec.signals]
    if not SteadyStateEvaluationRepository(store).load(baseline_from):
        raise click.UsageError(
            f"--baseline-from {baseline_from!r}: no steady-state evaluations are "
            f"recorded for run {baseline_from!r}. A run only becomes a reference "
            f"once it has been graded at least once; run it first, then pass its "
            f"run id to --baseline-from",
            ctx=ctx,
        )
    try:
        baseline_from_run(store, baseline_from, signal_names)
    except BaselineUnavailableError as exc:
        raise click.UsageError(f"--baseline-from {baseline_from!r}: {exc}", ctx=ctx) from None


def _steady_readings_from(observations: tuple[dict[str, object], ...]) -> dict[str, float | None]:
    """The ``during``-phase reading per signal, lifted from executor observations.

    Plan 03 step 3: a hypothesis needs an observation, not an inference. The
    executor already collected observability while the fault was in force, so
    this reuses those records rather than re-reading the target.

    Last finite reading per signal wins: the executor records a series, and the
    one nearest the end of the fault window is the observation closest to the
    perturbation actually in place. Non-finite and non-numeric values are
    skipped rather than coerced — ``delta_pct`` returns ``None`` rather than
    ``inf`` for exactly this reason, and a bundle must never carry either.
    """
    if not observations:
        return {}
    readings: dict[str, float | None] = {}
    for obs in observations:
        # The caller has already normalised the executor's untyped
        # `observability` attribute into dicts, so there is nothing to
        # re-check here; a str/other would be a caller bug, and the enclosing
        # helper degrades it to an ungraded report rather than a crash.
        name = obs.get("signal") or obs.get("metric_name") or obs.get("source_id")
        if not isinstance(name, str) or not name:
            continue
        value = obs.get("value")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        number = float(value)
        if not isfinite(number):
            continue
        readings[name] = number
    return readings


def _steady_state_for_run(
    preflight: object,
    run_id: str,
    *,
    store: Store,
    bypasses: Mapping[tuple[str, str], str] | None = None,
    baseline_from: str = "",
    spec: SteadyStateSpec | None = None,
    config: object | None = None,
    during: Mapping[str, float | None] | None = None,
) -> tuple[SteadyStateReport | None, str]:
    """Evaluate a run's ``steady_state:`` block, never raising into the run.

    Returns ``(report, display)``. A drill with no ``steady_state`` block, or a
    capture that could not be taken, must not change the run's outcome — the
    steady-state verdict is *evidence about the fault*, not a gate on the run.
    Any failure here degrades to ``(None, "")`` with the reason surfaced by the
    caller rather than an exception escaping mid-drill.

    ``spec`` and ``config`` are the authored ``SteadyStateSpec`` and the
    drill's observability config, carried from the compiled spec: both live on
    the spec, not on the preflight, so a caller that has the spec passes it
    rather than having this module go looking for a file that may since have
    been edited. Both fall back to the preflight lookup for callers that
    attach them there.
    """
    try:
        from mayhem.cli.execution import evaluate_steady_state, steady_state_display

        report = evaluate_steady_state(
            spec if spec is not None else _steady_spec_from(preflight),
            run_id=run_id,
            config=_steady_config(preflight) if config is None else config,
            store=_steady_store(store),
            engine=str(getattr(preflight, "engine", "") or "podman"),
            bypasses=bypasses,
            baseline_from=baseline_from or None,
            during=during,
        )
        return report, steady_state_display(report)
    except Exception as exc:
        return None, f"steady-state evaluation unavailable: {exc}"


def _steady_spec_from(source: object) -> SteadyStateSpec | None:
    """The authored ``SteadyStateSpec``, or None when there is none.

    Accepts either the compiled ``DrillSpec`` itself or any object that carries
    one under ``spec``/``drill_spec``. Nothing is inferred: a source with no
    ``steady_state`` block yields None, and the caller then renders nothing.
    """
    from mayhem.domain.steady_state import SteadyStateSpec

    for candidate in (
        source,
        getattr(source, "spec", None),
        getattr(source, "drill_spec", None),
    ):
        value = getattr(candidate, "steady_state", None)
        if isinstance(value, SteadyStateSpec):
            return value
    return None


def _steady_config(preflight: object) -> object:
    """The run's observability config, which declares the sources to read.

    Never ``None`` when a spec is graded: the capture loop takes a config, and
    an empty one produces a fully *ungraded* report — every assertion marked
    insufficient, with the reason on screen — which is an honest report of
    "nothing could be measured". Raising on a missing config instead would
    lose that distinction and report an unavailable evaluation, which reads as
    a broken tool rather than an undeclared source.
    """
    from mayhem.domain.observability import ObservabilityConfig

    config = getattr(preflight, "config", None) or getattr(preflight, "observability", None)
    return ObservabilityConfig() if config is None else config


def _steady_store(store: Store) -> Store:
    """The evidence store the verdict persists into.

    Taken from the caller: this module never reaches for a global store, and a
    steady-state verdict must land in the *same* store as the run it describes
    or the evidence bundle and the evaluations table disagree.
    """
    return store


def _write_evidence_after_run(
    *,
    store: Store,
    preflight: object,
    result: object,
    engine: str,
    evidence_dir: str | None,
    skip_gate: bool = False,
    intent: ExecutionIntent | None = None,
    baseline_from: str = "",
    steady_spec: SteadyStateSpec | None = None,
    steady_config: object | None = None,
) -> EvidenceEnvelope | None:

    try:
        run_id = str(getattr(result, "run_id", getattr(preflight, "plan_id", "")) or "")
        plan = getattr(preflight, "plan", None)
        step_reports = tuple(
            {
                "step_id": str(getattr(s, "step_id", "")),
                "ok": bool(getattr(s, "ok", False)),
                "detail": str(getattr(s, "detail", "")),
                "status": str(getattr(s, "status", "")),
            }
            for s in getattr(result, "steps", []) or []
        )
        leases: tuple[dict[str, object], ...] = ()
        try:
            journal = run_journal(store, run_id) if hasattr(store, "query") else {"leases": []}
            leases = tuple(journal.get("leases", []) or [])
        except Exception:
            leases = ()
        resolved_targets: list[str] = []
        for lease in leases:
            raw_target = lease.get("resolved_target_json")
            if not isinstance(raw_target, str) or not raw_target:
                continue
            try:
                target_data = json.loads(raw_target)
            except (TypeError, ValueError):
                continue
            if isinstance(target_data, dict):
                authority = target_data.get("authority_key")
                if authority:
                    resolved_targets.append(str(authority))
                else:
                    resolved_targets.append(
                        f"{target_data.get('namespace', '?')}/{target_data.get('pod') or target_data.get('node') or '?'}"
                    )
        # The executor's ``observability`` is an untyped attribute, so the raw
        # sequence is genuinely unknown-element; declaring it as a tuple of
        # dicts would make the isinstance/else normalisation below provably
        # dead code to the checker even though it is the live path.
        raw_observations: tuple[object, ...] = tuple(getattr(result, "observability", []) or [])
        observations: tuple[dict[str, object], ...]
        try:
            obs_list: list[dict[str, object]] = []
            for item in raw_observations:
                if hasattr(item, "model_dump"):
                    try:
                        obs_list.append(item.model_dump(mode="json"))
                    except Exception:
                        obs_list.append({"raw": str(item)})
                elif isinstance(item, dict):
                    obs_list.append(item)
                else:
                    obs_list.append({"raw": str(item)})
            observations = tuple(obs_list)
        except Exception:
            observations = ()
        verdict = ""
        try:
            v = getattr(result, "verdict", None)
            if v is not None and hasattr(v, "value"):
                try:
                    verdict = str(v.value)
                except Exception:
                    verdict = str(v)
            else:
                verdict = str(v or "")
            if not verdict:
                verdict = str(getattr(result, "status", "") or "")
        except Exception:
            verdict = str(getattr(result, "status", "") or "")
        recovery_state = "recovered" if not getattr(result, "dirty_leases", None) else "dirty"
        raw_rem = getattr(result, "dirty_leases", []) or []
        try:
            remediation = tuple(str(x) for x in raw_rem)
        except Exception:
            remediation = ()
        # Plan 03: grade the authored steady-state hypothesis now that the run
        # is finished. Evidence about the fault, never a gate on the run.
        # ``baseline_from`` has already been proven usable by
        # ``_require_baseline_reference`` before anything was injected, so the
        # reuse below cannot degrade into a silent fresh capture.
        _ss_report, _ss_display = _steady_state_for_run(
            preflight,
            run_id,
            store=store,
            baseline_from=baseline_from,
            spec=steady_spec,
            config=steady_config,
            during=_steady_readings_from(observations),
        )
        _ss_payload = _ss_report.to_dict() if _ss_report is not None else None
        if _ss_display:
            for _line in _ss_display.splitlines():
                click.echo(_line)
        envelope = build_evidence(
            run_id=run_id,
            plan=plan,
            target_profile=getattr(preflight, "target_profile", None),
            engine=engine,
            safety_decisions=tuple(
                str(x) for x in getattr(preflight, "safety_decisions", []) or []
            ),
            step_reports=step_reports,
            lease_timeline=leases,
            observations=observations,
            steady_state=_ss_payload,
            verdict=str(verdict),
            recovery_state=str(recovery_state),
            remediation=remediation,
            environment_fingerprint=str(getattr(preflight, "environment_fingerprint", "") or ""),
            target_identity=str(getattr(preflight, "target_identity", "") or ""),
            blast_radius=dict(getattr(preflight, "blast_radius", {}) or {}),
            compensation_status=str(getattr(preflight, "compensation_status", "") or ""),
            logical_target=str(getattr(preflight, "k8s_target_scope", "") or ""),
            resolved_target=",".join(resolved_targets),
            drift_status=(
                "drift recorded"
                if any("drift" in str(report.get("detail", "")).lower() for report in step_reports)
                else "no drift recorded"
            ),
            k8s_context=str(getattr(preflight, "k8s_context", "") or ""),
            k8s_namespace=str(getattr(preflight, "k8s_namespace", "") or ""),
            k8s_capability_verdict=str(getattr(preflight, "k8s_capability_verdict", "") or ""),
            k8s_wait_strategy=str(getattr(preflight, "k8s_wait_strategy", "") or ""),
            k8s_recovery_guidance=str(getattr(preflight, "k8s_recovery_guidance", "") or ""),
            skip_gate=skip_gate,
            execution_intent=intent.to_dict() if intent is not None else None,
            action_outcomes=tuple(
                str(getattr(getattr(s, "outcome", ""), "value", ""))
                for s in getattr(result, "steps", [])
            ),
        )
        replay_digest = ""
        try:
            from mayhem.infra.replay_repository import ReplayRepository, build_capsule

            capsule = build_capsule(store, run_id, engine=engine, policy={"engine": engine})
            if capsule is not None:
                ReplayRepository(store).save(capsule)
                replay_digest = capsule.digest()
                envelope = envelope.model_copy(update={"replay_digest": replay_digest})
        except Exception:
            replay_digest = ""
        try:
            from mayhem.observability.otel import InMemorySpanSink, record_span

            span_sink = InMemorySpanSink()
            record_span(
                span_sink, "mayhem.plan", run_id=run_id, steps=len(getattr(plan, "steps", ()))
            )
            record_span(
                span_sink,
                "mayhem.approval",
                run_id=run_id,
                approved=intent is not None,
                engine=engine,
            )
            record_span(
                span_sink,
                "mayhem.lease",
                run_id=run_id,
                dirty=len(getattr(result, "dirty_leases", ())),
            )
            record_span(
                span_sink,
                "mayhem.mutation",
                run_id=run_id,
                status=str(getattr(result, "status", "")),
            )
            record_span(span_sink, "mayhem.verification", run_id=run_id, verdict=verdict)
            record_span(
                span_sink,
                "mayhem.compensation",
                run_id=run_id,
                recovery=recovery_state,
            )
            record_span(span_sink, "mayhem.evidence", run_id=run_id, evidence_status=verdict)
            envelope = envelope.model_copy(
                update={
                    "emitted_spans": span_sink.names(),
                }
            )
        except Exception as exc:
            envelope = envelope.model_copy(
                update={
                    "emitted_spans": (),
                    "remediation": (
                        *envelope.remediation,
                        f"span emission failed: {type(exc).__name__}",
                    ),
                }
            )
        try:
            from mayhem.domain.observations import (
                collect as collect_observations,
            )
            from mayhem.domain.observations import (
                evaluate_all,
                provenance_summary,
            )

            provider = _observation_provider_for(engine)
            if provider is not None:
                queries, criteria = _slo_from_plan(plan)
                observed = collect_observations(provider, queries)
                outcomes = evaluate_all(criteria, observed)
                envelope = envelope.model_copy(
                    update={
                        "observation_provenance": provenance_summary(observed),
                        "slo_outcomes": tuple(outcome.to_dict() for outcome in outcomes),
                    }
                )
        except Exception as exc:
            envelope = envelope.model_copy(
                update={
                    "observation_provenance": {
                        "status": "degraded",
                        "detail": f"observation collection failed: {type(exc).__name__}",
                    }
                }
            )
        try:
            write_evidence(store, envelope)
        except Exception as exc:
            envelope = envelope.model_copy(
                update={
                    "evidence_status": "degraded",
                    "remediation": (
                        *envelope.remediation,
                        f"evidence persistence failed: {type(exc).__name__}",
                    ),
                }
            )
        if evidence_dir:
            try:
                write_evidence_file(envelope, evidence_dir)
            except Exception as exc:
                envelope = envelope.model_copy(
                    update={
                        "evidence_status": "degraded",
                        "remediation": (
                            *envelope.remediation,
                            f"evidence artifact write failed: {type(exc).__name__}",
                        ),
                    }
                )
        return envelope
    except Exception:
        return None


def _suggest_next_cell(
    ctx: click.Context,
    db: str,
    graph: TopologyGraph,
    compose: str | None,
) -> None:
    """After a successful run, suggest the most valuable untested cell.

    This reuses the same ranking logic as ``mayhem inspect next`` but operates on
    the live topology graph and store already open in the run command.
    """
    from mayhem.cli.next_cmd import _landscape_cells
    from mayhem.domain.faults import FaultCategory
    from mayhem.infra.coverage_repository import SQLiteCoverageRepository
    from mayhem.infra.ranking import rank

    landscape, criticality_map, risk_map = _landscape_cells(graph)
    if not landscape:
        return

    store = open_store(db)
    try:
        coverage = SQLiteCoverageRepository(store)
        covered_keys = coverage.covered_keys()
        state_map = coverage.states(landscape)

        division_counter: dict[str, int] = {}
        for cell in landscape:
            if cell.key in covered_keys:
                cat = FaultCategory.from_fault_id(cell.fault_kind).value
                division_counter[cat] = division_counter.get(cat, 0) + 1

        # Session memory: recent failures bias ranking toward retesting problem areas.
        failed_targets, failed_faults = coverage.recent_failures()

        ranked = rank(
            landscape,
            state_map=state_map,
            division_map=division_counter,
            criticality_map=criticality_map,
            risk_map=risk_map,
            failed_targets=failed_targets,
            failed_faults=failed_faults,
        )
        if ranked:
            rc = ranked[0]
            click.echo(
                f"\n{style.info('next')} {style.cyan(rc.cell.target)} — "
                f"{style.yellow(rc.cell.fault_kind)} "
                f"(score {rc.score:.2f})"
            )
    finally:
        store.close()


def _observation_provider_for(engine: str) -> ObservationProvider | None:
    """Provider for read-only observation collection; ``None`` disables it."""
    from mayhem.providers.observation import StaticObservationProvider

    # Live providers are opt-in (task 19 wires the remote ones); the default is
    # a local provider so evidence never claims a measurement it did not take.
    return StaticObservationProvider()


def _slo_from_plan(
    plan: object,
) -> tuple[tuple[ObservationQuery, ...], tuple[SloCriterion, ...]]:
    """Extract observation queries and SLO criteria declared by the plan."""
    from mayhem.domain.observations import (
        CriterionKind,
        CriterionOperator,
        ObservationQuery,
        SloCriterion,
    )

    queries: list[ObservationQuery] = []
    criteria: list[SloCriterion] = []
    raw = getattr(plan, "slo", None) or []
    for item in raw:
        if not isinstance(item, dict):
            continue
        metric = str(item.get("metric") or "")
        if not metric:
            continue
        queries.append(
            ObservationQuery(
                metric=metric,
                window_s=float(item.get("window_s", 60.0) or 60.0),
                unit=str(item.get("unit") or "ms"),
                target=str(item.get("target") or ""),
            )
        )
        criteria.append(
            SloCriterion(
                kind=CriterionKind(str(item.get("kind", "latency"))),
                metric=metric,
                operator=CriterionOperator(str(item.get("operator", "lte"))),
                threshold=float(item.get("threshold", 0.0) or 0.0),
                unit=str(item.get("unit") or "ms"),
                window_s=float(item.get("window_s", 60.0) or 60.0),
                name=str(item.get("name") or ""),
            )
        )
    return tuple(queries), tuple(criteria)


@click.command("validate")
@_compose_option
@click.argument("experiment", type=click.Path(), required=False, default=None)
@click.pass_context
def validate(ctx: click.Context, experiment: str | None, compose: str | None) -> None:
    """Compile a drill spec and run every safety gate without executing it."""
    obj = _ctx(ctx)
    runtime = _runtime_context(
        engine=_resolve_engine_from_state(),
        target=obj.target,
        config_path=obj.config,
        profile=obj.profile,
    )
    graph, resolved_compose = _graph_from(ctx, compose, engine=runtime.engine, target=obj.target)
    runtime = with_topology_fingerprint(runtime, graph)
    experiment, config_for_layers = _resolve_spec_pair(experiment, obj.config, resolved_compose)
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
        compiled = plan_from_spec(experiment, graph, prepared=prepared, engine=runtime.engine)
    finally:
        store.close()
    click.echo(
        f"{style.ok('validated')} {style.cyan(compiled.run_id)}: "
        f"{len(compiled.plan.steps)} step(s), "
        f"fingerprint {prepared.fingerprint[:12]}"
    )


@click.command("plan")
@_compose_option
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option(
    "--diff",
    "diff_path",
    type=click.Path(exists=True),
    default=None,
    help="Compare authored plan with last accepted plan file.",
)
@click.option(
    "--evidence-dir", type=click.Path(), default=None, help="Directory to write evidence artifacts."
)
@click.argument("experiment", type=click.Path(), required=False, default=None)
@click.pass_context
def plan(
    ctx: click.Context,
    experiment: str | None,
    compose: str | None,
    as_json: bool,
    diff_path: str | None,
    evidence_dir: str | None,
) -> None:
    obj = _ctx(ctx)
    runtime = _runtime_context(
        engine=_resolve_engine_from_state(),
        target=obj.target,
        config_path=obj.config,
        profile=obj.profile,
    )
    graph, resolved_compose = _graph_from(ctx, compose, engine=runtime.engine, target=obj.target)
    runtime = with_topology_fingerprint(runtime, graph)
    experiment, config_for_layers = _resolve_spec_pair(experiment, obj.config, resolved_compose)
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
        compiled = plan_from_spec(experiment, graph, prepared=prepared, engine=runtime.engine)
        preflight = _preflight_for_run(
            graph=graph,
            store=store,
            prepared=prepared,
            plan=compiled.plan,
            target=obj.target,
            config_path=obj.config,
            profile=obj.profile,
            engine=runtime.engine,
            runtime=runtime,
        )
        if diff_path is not None:
            try:
                diff = diff_plans(compiled.plan, _json.loads(Path(diff_path).read_text()))
            except Exception:
                diff = diff_plans(compiled.plan.model_dump(mode="json"), {})
            if as_json:
                ordered = {k: diff[k] for k in sorted(diff.keys())}
                click.echo(_json.dumps(ordered, indent=2))
            else:
                click.echo(render_plan_diff(diff))
            return
        if as_json:
            click.echo(render_preflight_json(preflight))
        else:
            click.echo(compiled.plan.model_dump_json(indent=2))
        if evidence_dir is not None:
            from pathlib import Path as _Path

            env = build_evidence(
                run_id=compiled.run_id,
                plan=compiled.plan,
                target_profile=obj.target,
                engine=runtime.engine,
                safety_decisions=tuple(preflight.safety_decisions),
                step_reports=(),
                lease_timeline=(),
                observations=(),
                verdict="planned",
                recovery_state="pending",
                remediation=(),
                environment_fingerprint=preflight.environment_fingerprint,
                target_identity=preflight.target_identity,
                blast_radius=dict(preflight.blast_radius),
                compensation_status=preflight.compensation_status,
            )
            write_evidence_file(env, _Path(evidence_dir))
    finally:
        store.close()


@click.command("run")
@_compose_option
@click.option(
    "--ctr",
    "ctr",
    type=str,
    default=None,
    metavar="CONTAINER",
    help="Only execute faults on this container (container_name from the compose blueprint, or the runtime container name).",
)
@click.option(
    "--engine",
    "run_engine",
    type=click.Choice(["docker", "podman", "kubernetes"], case_sensitive=False),
    default=None,
    help="Engine for this run (overrides global --kubernetes/--podman).",
)
@click.option(
    "--target",
    "run_target",
    type=str,
    default=None,
    help="Target profile name for kubernetes runs (logical target).",
)
@click.option(
    "--next",
    "show_next",
    is_flag=True,
    default=False,
    help="After execution, suggest the most valuable untested cell to run next.",
)
@click.option(
    "-e",
    "--execute",
    is_flag=True,
    default=False,
    help="Explicit approval to execute the plan.",
)
@click.option(
    "--from-plan",
    "from_plan",
    type=click.Path(exists=True),
    default=None,
    help="Execute a reviewed plan file.",
)
@click.option(
    "--plan-id", type=str, default=None, help="Execute a plan previously stored by run id."
)
@click.option(
    "--diff",
    "diff_path",
    type=click.Path(exists=True),
    default=None,
    help="Compare authored plan with last accepted plan.",
)
@click.option(
    "--evidence-dir", type=click.Path(), default=None, help="Directory to write evidence artifacts."
)
@click.option(
    "--baseline-from",
    "baseline_from",
    type=str,
    default=None,
    metavar="RUN_ID",
    help=(
        "Grade this run's steady_state block against a previous run's captured "
        "baseline instead of capturing a fresh one (plan 03 step 6). The named "
        "run must already have recorded steady-state evaluations; if it does "
        "not, the run is refused rather than silently re-baselined. Omit the "
        "flag for today's behaviour: capture a fresh baseline."
    ),
)
@click.option("--json", "as_json", is_flag=True, default=False, help="Output preflight as JSON.")
@click.argument("experiment", type=click.Path(), required=False, default=None)
@click.pass_context
def run(
    ctx: click.Context,
    experiment: str | None,
    compose: str | None,
    ctr: str | None,
    run_engine: str | None,
    run_target: str | None,
    show_next: bool,
    execute: bool,
    from_plan: str | None,
    plan_id: str | None,
    diff_path: str | None,
    evidence_dir: str | None,
    baseline_from: str | None,
    as_json: bool,
) -> None:
    obj = _ctx(ctx)
    # The documented MAYHEM_ALLOW_IMPLICIT_EXECUTION=1 switch is resolved
    # exactly once, here at the CLI edge. Everything below — the implicit-path
    # decision and every engine built for this invocation — takes that one
    # answer; nothing downstream re-reads the environment.
    #
    # The deployment's refusing controls resolve the same way and for the same
    # reason. ``run_gate`` reads MAYHEM_GATE_WITNESSES and returns the gate this
    # deployment bound (None when it bound none — mayhem binds none of the five
    # port witnesses, so the shipped default is an ungated run, unchanged);
    # ``run_budget_guard`` reads MAYHEM_BUDGET_GUARD once, where the run id is
    # known. Both are passed down to ``engine_for`` as parameters: the controller
    # reads no environment and imports no CLI module, and a spec that cannot be
    # loaded raises here, before a store is opened, rather than downgrading
    # silently to "no gate".
    from mayhem.cli.app import implicit_execution_allowed, run_budget_guard, run_gate

    allow_implicit = implicit_execution_allowed()
    gate = run_gate()
    target_name = run_target or obj.target
    runtime = _runtime_context(
        engine=run_engine or _resolve_engine_from_state(),
        target=target_name,
        config_path=obj.config,
        profile=obj.profile,
    )
    effective_engine = runtime.engine
    graph, resolved_compose = _graph_from(ctx, compose, engine=effective_engine, target=target_name)
    runtime = with_topology_fingerprint(runtime, graph)
    if ctr is not None:
        if effective_engine == "kubernetes":
            raise click.UsageError(
                "--ctr is not a Kubernetes target selector; use --target", ctx=ctx
            )
        _require_container(ctr, graph, ctx)
    if baseline_from is not None and not (baseline_from or "").strip():
        # `--baseline-from "$REF"` with an unset REF is the common way to reach
        # here, and treating it as "no reference" would hand back a fresh
        # capture to someone who believes they named a run. An empty value is
        # named-but-nothing, so it is a usage error rather than an absence.
        raise click.UsageError(
            "--baseline-from needs a run id, but was given an empty value. "
            "Quote it in scripts: an unset variable must fail loudly here "
            "rather than degrade into a fresh capture",
            ctx=ctx,
        )
    store = open_store(obj.db)
    # One spelling of the reference for the whole command: the guard, the
    # evidence write, and the report all read this, so a whitespace-only value
    # cannot pass the guard as "set" and then be dropped as "" on the way down.
    reference = (baseline_from or "").strip()
    try:
        _sweep_before_run(store)
        if from_plan is not None or plan_id is not None:
            if from_plan is not None and plan_id is not None:
                raise click.UsageError("--from-plan and --plan-id are mutually exclusive", ctx=ctx)
            loaded = None
            if from_plan is not None:
                loaded = _json.loads(Path(from_plan).read_text())
                try:
                    from mayhem.domain.experiments import ExecutionPlan

                    loaded_plan = ExecutionPlan.model_validate(loaded)
                except Exception:
                    loaded_plan = None
                if loaded_plan is not None:
                    # Named before the guards so every branch below talks about
                    # the same plan object.
                    compiled_plan = loaded_plan
                    preflight = _preflight_for_run(
                        graph=graph,
                        store=store,
                        prepared=None,
                        plan=compiled_plan,
                        target=target_name,
                        config_path=obj.config,
                        profile=obj.profile,
                        engine=effective_engine,
                        runtime=runtime,
                    )
                    _emit_preflight(preflight, as_json)
                    if obj.dry_run:
                        # A dry run loads and previews the plan and stops: it
                        # must never reach the engine, and therefore never a
                        # lease, even when --execute was also passed.
                        click.echo(
                            f"dry-run: plan {style.cyan(compiled_plan.run_id)} loaded; "
                            "nothing executed",
                            err=True,
                        )
                        return
                    if not execute:
                        click.echo("plan loaded; pass --execute to run", err=True)
                        return
                    prepared_dummy = None
                    try:
                        from mayhem.cli.services import prepare as _prep

                        prepared_dummy = _prep(
                            config_path=None,
                            profile=obj.profile,
                            allow_critical=obj.allow_critical,
                            store=store,
                            graph=graph,
                            compose=resolved_compose,
                            spec_path=experiment or from_plan,
                            target=target_name,
                        )
                        reject_if_stale(
                            preflight_fingerprint=loaded_plan.environment_fingerprint,
                            current_fingerprint=prepared_dummy.fingerprint,
                            preflight_target=target_name,
                            current_target=target_name,
                        )
                    except ValueError as exc:
                        raise click.UsageError(str(exc), ctx=ctx) from None
                    engine_name = effective_engine
                    bypass: dict[tuple[str, str], str] = {}
                    if _gate_enabled():
                        bypass = _gate_bypasses(engine_name, compiled_plan, graph)
                    plan_intent = _execution_intent(
                        compiled_plan,
                        engine=engine_name,
                        target=target_name,
                        preflight=preflight,
                        break_glass=not _gate_enabled(),
                    )
                    # Before the engine exists: a reference that cannot be read
                    # is refused here, not discovered after the fault is in.
                    # A plan file carries no ``steady_state:`` block — it lives
                    # on the spec, which a stored plan does not — so there is
                    # nothing for the reference to grade.
                    _require_baseline_reference(store, reference, None, ctx)
                    eng = engine_for(
                        store,
                        engine_name,
                        live_graph=lambda: build_graph(
                            resolved_compose,
                            engine_name=effective_engine,
                            target=target_name,
                            config_path=obj.config,
                            profile=obj.profile,
                        ),
                        on_event=_debug_progress() if obj.debug else None,
                        bypass=bypass,
                        recovery_grace=prepared_dummy.recovery_grace if prepared_dummy else 300.0,
                        runtime=runtime,
                        intent=plan_intent,
                        require_intent=True,
                        allow_implicit=allow_implicit,
                        gate=gate,
                        budget_guard=run_budget_guard(compiled_plan.run_id),
                    )
                    result = eng.execute(compiled_plan)
                    preflight2 = _preflight_for_run(
                        graph=graph,
                        store=store,
                        prepared=prepared_dummy,
                        plan=compiled_plan,
                        target=target_name,
                        config_path=obj.config,
                        profile=obj.profile,
                        engine=engine_name,
                        runtime=runtime,
                    )
                    _write_evidence_after_run(
                        store=store,
                        preflight=preflight2,
                        result=result,
                        engine=engine_name,
                        evidence_dir=evidence_dir,
                        intent=plan_intent,
                        baseline_from=reference,
                    )
                    click.echo(result.summary_md())
                    return
            if plan_id is not None:
                rows = store.query("SELECT plan_json FROM runs WHERE id = ?", (plan_id,))
                if not rows:
                    raise click.UsageError(f"no such plan: {plan_id}", ctx=ctx)
                raw = (
                    rows[0]["plan_json"]
                    if isinstance(rows[0], dict) or hasattr(rows[0], "__getitem__")
                    else rows[0][0]
                )
                loaded = _json.loads(raw) if isinstance(raw, str) else {}
                try:
                    from mayhem.domain.experiments import ExecutionPlan

                    loaded_plan = ExecutionPlan.model_validate(loaded)
                except Exception:
                    raise click.UsageError(
                        f"stored plan {plan_id!r} is not a valid ExecutionPlan", ctx=ctx
                    ) from None
                if not execute or obj.dry_run:
                    preflight = _preflight_for_run(
                        graph=graph,
                        store=store,
                        prepared=None,
                        plan=loaded_plan,
                        target=target_name,
                        config_path=obj.config,
                        profile=obj.profile,
                        engine=effective_engine,
                        runtime=runtime,
                    )
                    _emit_preflight(preflight, as_json)
                    if obj.dry_run:
                        # Loading a stored plan is a preview under --dry-run,
                        # even with --execute: nothing is executed.
                        click.echo(
                            f"dry-run: plan {style.cyan(loaded_plan.run_id)} loaded; "
                            "nothing executed",
                            err=True,
                        )
                        return
                    click.echo("plan loaded; pass --execute to run", err=True)
                    return
                engine_name = effective_engine
                # The stored plan is compiled against a different run's
                # snapshots, so the preflight is resolved here (not reused from
                # the preview branch) and the intent is bound to the policy and
                # blast radius that were actually reviewed.
                preflight = _preflight_for_run(
                    graph=graph,
                    store=store,
                    prepared=None,
                    plan=loaded_plan,
                    target=target_name,
                    config_path=obj.config,
                    profile=obj.profile,
                    engine=engine_name,
                    runtime=runtime,
                )
                stored_intent = _execution_intent(
                    loaded_plan,
                    engine=engine_name,
                    target=target_name,
                    preflight=preflight,
                )
                # A stored plan carries no ``steady_state:`` block, so the flag
                # has nothing to grade here — same reason as --from-plan above.
                _require_baseline_reference(store, reference, None, ctx)
                eng = engine_for(
                    store,
                    engine_name,
                    live_graph=lambda: build_graph(
                        resolved_compose,
                        engine_name=effective_engine,
                        target=target_name,
                        config_path=obj.config,
                        profile=obj.profile,
                    ),
                    on_event=_debug_progress() if obj.debug else None,
                    bypass={},
                    recovery_grace=300.0,
                    runtime=runtime,
                    intent=stored_intent,
                    require_intent=True,
                    allow_implicit=allow_implicit,
                    gate=gate,
                    budget_guard=run_budget_guard(loaded_plan.run_id),
                )
                result = eng.execute(loaded_plan)
                _write_evidence_after_run(
                    store=store,
                    preflight=preflight,
                    result=result,
                    engine=engine_name,
                    evidence_dir=evidence_dir,
                    intent=stored_intent,
                    baseline_from=reference,
                )
                click.echo(result.summary_md())
                return
        if experiment is None:
            experiment, config_for_layers = _resolve_spec_pair(None, obj.config, resolved_compose)
        else:
            experiment, config_for_layers = _resolve_spec_pair(
                experiment, obj.config, resolved_compose
            )
        prepared = prepare(
            config_path=config_for_layers,
            profile=obj.profile,
            allow_critical=obj.allow_critical,
            store=store,
            graph=graph,
            compose=resolved_compose,
            spec_path=experiment,
            target=target_name,
        )
        compiled = plan_from_spec(experiment, graph, prepared=prepared, engine=effective_engine)
        if ctr is not None:
            compiled = dataclasses.replace(
                compiled, plan=restrict_plan_to_container(compiled.plan, ctr, graph)
            )
            click.echo(
                style.info("info:") + f" --ctr scoped the plan to container {style.cyan(ctr)}",
                err=True,
            )
        # Resolved once, from the compiled spec, and threaded to both the guard
        # and the post-run evaluation: the two must read the same block, or the
        # reference could be validated against one spec and graded against
        # another. Read defensively: a compiled plan handed in without the spec
        # it was compiled from has no steady-state block to grade, and says so
        # by rendering nothing.
        authored = getattr(compiled, "spec", None)
        steady_spec = _steady_spec_from(authored)
        steady_config = getattr(authored, "observability", None)
        preflight = _preflight_for_run(
            graph=graph,
            store=store,
            prepared=prepared,
            plan=compiled.plan,
            target=target_name,
            config_path=obj.config,
            profile=obj.profile,
            engine=effective_engine,
            runtime=runtime,
        )
        if diff_path is not None:
            try:
                diff = diff_plans(compiled.plan, _json.loads(Path(diff_path).read_text()))
            except Exception:
                diff = diff_plans(compiled.plan.model_dump(mode="json"), {})
            if as_json:
                ordered = {k: diff[k] for k in sorted(diff.keys())}
                click.echo(_json.dumps(ordered, indent=2))
            else:
                click.echo(render_plan_diff(diff))
            if obj.dry_run:
                # The diff *is* the preview; --dry-run must not fall through
                # into execution even when --execute was passed.
                click.echo("dry-run: plan diff shown; nothing executed", err=True)
                return
            if not execute:
                return
        _emit_preflight(preflight, as_json)
        # v0.9.0: the pre-v0.9.0 compatibility path — a bare
        # ``mayhem run SPEC`` that executed anyway — now requires the
        # documented MAYHEM_ALLOW_IMPLICIT_EXECUTION=1 switch (resolved once
        # at the top of this command). Without it the command previews,
        # exactly like --dry-run, and never reaches a lease.
        implicit = (
            experiment is not None
            and diff_path is None
            and from_plan is None
            and plan_id is None
            and allow_implicit
        )
        if not execute and not implicit and not obj.dry_run:
            click.echo("plan ready; pass --execute to run", err=True)
            return
        if not execute and not obj.dry_run:
            click.echo(migration_warning(), err=True)
            click.echo(
                "executing via compatibility adapter; use --execute --from-plan for plan-first flow",
                err=True,
            )
        engine_name = effective_engine
        run_intent = (
            _execution_intent(
                compiled.plan,
                engine=engine_name,
                target=target_name,
                preflight=preflight,
                break_glass=not _gate_enabled(),
            )
            if execute
            else None
        )
        if obj.dry_run:
            from mayhem.controller.safety import dry_run_policy_evaluation

            decisions = dry_run_policy_evaluation(compiled.plan, graph, prepared.safety)
            for d in decisions:
                click.echo(f"dry-run {d.rule_id}: {d.outcome} {d.reason} -> {d.remediation}")
            return
        # After the dry-run return, before the engine: a preview must not be
        # refused over a reference it never needed, and an executing run must
        # not reach the target with an unusable one.
        _require_baseline_reference(store, reference, steady_spec, ctx)
        skip_gate_used = not _gate_enabled()
        override = (
            os.getenv("MAYHEM_ALLOW_SKIP_GATE") == "1" or os.getenv("MAYHEM_BREAK_GLASS") == "1"
        )
        bypass2: dict[tuple[str, str], str] = {}
        if _gate_enabled():
            bypass2 = _gate_bypasses(engine_name, compiled.plan, graph)
        else:
            click.echo(
                style.danger("!!! BREAK-GLASS WARNING !!!")
                + " impact gate skipped (--skip-gate); inert faults may run; audit field break-glass: --skip-gate",
                err=True,
            )
            click.echo(
                style.warn("warning:")
                + " --skip-gate requires MAYHEM_ALLOW_SKIP_GATE=1 or MAYHEM_BREAK_GLASS=1 to be considered automation-success; otherwise evidence will be marked and automation must treat run as failed",
                err=True,
            )
        engine_obj = engine_for(
            store,
            engine_name,
            live_graph=lambda: build_graph(
                resolved_compose,
                engine_name=effective_engine,
                target=target_name,
                config_path=obj.config,
                profile=obj.profile,
            ),
            on_event=_debug_progress() if obj.debug else None,
            bypass=bypass2,
            recovery_grace=prepared.recovery_grace,
            runtime=runtime,
            intent=run_intent,
            require_intent=True,
            allow_implicit=allow_implicit,
            gate=gate,
            budget_guard=run_budget_guard(compiled.run_id),
        )
        result = engine_obj.execute(compiled.plan)
        _write_evidence_after_run(
            store=store,
            preflight=preflight,
            result=result,
            engine=engine_name,
            evidence_dir=evidence_dir,
            skip_gate=skip_gate_used,
            intent=run_intent,
            baseline_from=reference,
            steady_spec=steady_spec,
            steady_config=steady_config,
        )
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
            f"inspect with {style.yellow(f'mayhem inspect history {compiled.run_id}')}"
        )
        try:
            envelope = load_evidence(store, compiled.run_id)
            if envelope is not None:
                click.echo(render_evidence_human(envelope))
        except Exception:
            pass
        if show_next and result.status == "completed":
            _suggest_next_cell(ctx, obj.db, graph, resolved_compose)
        from mayhem.cli.app import _STATE as _S

        if skip_gate_used and not override and _S.get("format") == "json":
            ctx.exit(int(ExitCode.VALIDATION_ERROR))
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
@click.option(
    "--next",
    "show_next",
    is_flag=True,
    default=False,
    help="After execution, suggest the most valuable untested cell to run next.",
)
@click.option(
    "--execute",
    "execute",
    is_flag=True,
    default=False,
    help="Explicit approval to inject the drawn fault rounds.",
)
@click.argument("experiment", type=click.Path(), required=False, default=None)
@click.pass_context
def maniac(
    ctx: click.Context,
    experiment: str | None,
    compose: str | None,
    steps: int | None,
    ctr: str | None,
    show_next: bool,
    execute: bool,
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

    ``--execute`` is the explicit approval that lets a round mutate the
    target; without it (and without the documented
    ``MAYHEM_ALLOW_IMPLICIT_EXECUTION=1`` compatibility switch) the command
    refuses with ``execution_intent_required`` before any round is drawn. A
    global ``--dry-run`` is a preview: it needs no approval, reports how many
    rounds were drawn, and returns before the engine — so it can never inject,
    whatever else was passed.

    An intent is minted for ``--execute`` runs only. A run that proceeded
    through the compatibility switch records ``execution_intent: null`` on its
    evidence envelope, so an implicit maniac is never mistaken for an approved
    one.
    """
    obj = _ctx(ctx)
    from mayhem.cli.app import implicit_execution_allowed, run_budget_guard, run_gate

    # Resolved once here, at the CLI edge, and reused for the gate below and
    # for the engine; nothing downstream re-reads the environment. ``run_gate``
    # is the deployment's refusing preflight gate (None when it configured one —
    # the shipped default) and ``run_budget_guard`` its resource budget; both
    # travel down as parameters, exactly as ``allow_implicit`` does.
    allow_implicit = implicit_execution_allowed()
    gate = run_gate()
    runtime = _runtime_context(
        engine=_resolve_engine_from_state(),
        target=obj.target,
        config_path=obj.config,
        profile=obj.profile,
    )
    engine = runtime.engine
    graph, resolved_compose = _graph_from(ctx, compose, engine=engine, target=obj.target)
    runtime = with_topology_fingerprint(runtime, graph)
    if ctr is not None:
        if engine == "kubernetes":
            raise click.UsageError(
                "kubernetes maniac rounds are target-scoped (k-plan-3 SP-3.6) — "
                "--ctr applies to compose container subtrees only",
                ctx=ctx,
            )
        _require_container(ctr, graph, ctx)
    spec_path, config_for_layers, synthesized = _resolve_maniac_sources(
        experiment, obj.config, graph, pool=ctr, engine=engine
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
            engine=engine,
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
            if synthesized.targets:
                click.echo(
                    style.info("info:") + " maniac mode — no drill spec; synthesized "
                    f"kubernetes targets config from the blueprint topology "
                    f"({len(synthesized.targets)} target(s)), "
                    f"{draws} random fault round(s) drawn",
                    err=True,
                )
            else:
                # ``DrillSpec``'s validator guarantees ``containers`` is
                # non-empty whenever ``targets`` is absent; the ``or {}`` only
                # keeps a statically-unprovable ``None`` from becoming a
                # TypeError inside an f-string.
                click.echo(
                    style.info("info:") + " maniac mode — no drill spec; synthesized config "
                    f"from compose topology "
                    f"({len(synthesized.containers or {})} container(s)), "
                    f"{draws} random fault round(s) drawn",
                    err=True,
                )
        else:
            click.echo(
                style.info("info:") + f" maniac mode — {draws} random fault round(s) drawn",
                err=True,
            )
        bypass: dict[tuple[str, str], str] = {}
        if _gate_enabled():
            bypass = _gate_bypasses(engine, compiled.plan, graph)
        else:
            click.echo(
                style.warn("warning:") + " impact gate skipped (--skip-gate); inert faults may run",
                err=True,
            )
        if obj.dry_run:
            # A preview is not a mutation: report the draw and stop before the
            # engine (and therefore before any lease) is ever built.
            click.echo(
                f"dry-run: {draws} random fault round(s) drawn for "
                f"{style.cyan(compiled.run_id)}; nothing injected"
            )
            return
        # The approval gate sits here — after argument validation, spec
        # resolution, and the dry-run return, immediately before the engine
        # (and therefore any lease or subprocess) can be built. A --dry-run
        # invocation returns above, so a preview never reaches a mutation and
        # never needs approval; nothing below this line runs without it.
        require_explicit_approval(
            "maniac",
            approved=execute,
            allow_implicit=allow_implicit,
        )
        # NB: the RunEngine is a local named ``run_engine`` — the resolved
        # context owns the engine *name*, and rebinding it here used to leak a
        # RunEngine object into the preflight/evidence ``engine: str`` fields.
        # An intent is minted only for an *approved* run. Reaching this line
        # without --execute means the compatibility switch allowed an implicit
        # run, and an implicit run has no approval to record — so the evidence
        # carries ``execution_intent: null``, exactly like an implicit
        # `mayhem run` or `campaign run`.
        maniac_intent = (
            _execution_intent(
                compiled.plan, engine=engine, target=obj.target, break_glass=not _gate_enabled()
            )
            if execute
            else None
        )
        run_engine = engine_for(
            store,
            engine,
            live_graph=lambda: build_graph(
                resolved_compose,
                engine_name=engine,
                target=obj.target,
                config_path=obj.config,
                profile=obj.profile,
            ),
            on_event=_debug_progress() if obj.debug else None,
            bypass=bypass,
            recovery_grace=prepared.recovery_grace,
            runtime=runtime,
            intent=maniac_intent,
            require_intent=True,
            allow_implicit=allow_implicit,
            gate=gate,
            budget_guard=run_budget_guard(compiled.run_id),
        )
        result = run_engine.execute(compiled.plan)
        try:
            pf = _preflight_for_run(
                graph=graph,
                store=store,
                prepared=prepared,
                plan=compiled.plan,
                target=obj.target,
                config_path=obj.config,
                profile=obj.profile,
                engine=engine,
                runtime=runtime,
            )
            _write_evidence_after_run(
                store=store,
                preflight=pf,
                result=result,
                engine=engine,
                evidence_dir=None,
                intent=maniac_intent,
            )
        except Exception:
            pass
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
            f"inspect with {style.yellow(f'mayhem inspect history {compiled.run_id}')}"
        )
        if show_next and result.status == "completed":
            _suggest_next_cell(ctx, obj.db, graph, resolved_compose)
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
    db = db_opt or _ctx(ctx).db or DEFAULT_DB
    store = open_store(db)
    try:
        if run_id is not None:
            row = run_detail(store, run_id)
            if row is None:
                raise click.UsageError(f"no such run: {run_id}", ctx=ctx)
            row = _project_run_liveness(row)
            try:
                envelope = load_evidence(store, run_id)
                if envelope is not None:
                    row["evidence"] = envelope.model_dump(mode="json")
            except Exception:
                pass
            click.echo(json.dumps(row, indent=2))
            return
        rows = [_project_run_liveness(row) for row in recent_runs(store, limit)]
        if json_flag:
            click.echo(json.dumps(rows, indent=2))
        else:
            for row in rows:
                started = row["started_at"] or "-"
                sid = style.state(f"{row['liveness_status']:<16}")
                click.echo(f"{row['id']:<28} {row['kind']:<13} {sid} {started}")
    finally:
        store.close()


@click.command("verify")
@click.argument("run_id")
@click.option("--json", "json_flag", is_flag=True, default=False, help="Output as JSON.")
@click.pass_context
def verify(ctx: click.Context, run_id: str, json_flag: bool) -> None:
    store = open_store(_ctx(ctx).db)
    try:
        envelope = load_evidence(store, run_id)
        if envelope is None:
            journal = run_journal(store, run_id)
            if not journal.get("steps") and not journal.get("leases"):
                raise click.UsageError(f"no such run: {run_id}", ctx=ctx)
            envelope = EvidenceEnvelope(
                run_id=run_id,
                plan_hash="",
                verdict="",
                step_reports=tuple(journal.get("steps", [])),
                lease_timeline=tuple(journal.get("leases", [])),
            )
        result = verify_evidence(envelope)
        if json_flag:
            ordered = {k: result[k] for k in sorted(result.keys())}
            click.echo(json.dumps(ordered, indent=2, sort_keys=False))
        else:
            click.echo(f"verify {run_id}: {'complete' if result['complete'] else 'incomplete'}")
            if result["errors"]:
                for err in result["errors"]:
                    click.echo(f"  - {err}")
            else:
                click.echo("  evidence complete")
        if not result["complete"]:
            ctx.exit(int(ExitCode.VALIDATION_ERROR))
    finally:
        store.close()


@click.command("history")
@click.argument("run_id")
@click.option("--json", "json_flag", is_flag=True, default=False, help="Output as JSON.")
@click.option(
    "--evidence-dir", type=click.Path(), default=None, help="Directory for evidence artifacts."
)
@click.pass_context
def history(ctx: click.Context, run_id: str, json_flag: bool, evidence_dir: str | None) -> None:
    store = open_store(_ctx(ctx).db)
    try:
        journal = run_journal(store, run_id)
        if run_detail(store, run_id) is not None:
            journal["report_id"] = report_id_for_run(run_id)
        try:
            envelope = load_evidence(store, run_id)
            if envelope is not None:
                journal["evidence"] = envelope.model_dump(mode="json")
                journal["evidence_human"] = render_evidence_human(envelope)
                if evidence_dir is not None:
                    with contextlib.suppress(Exception):
                        write_evidence_file(envelope, Path(evidence_dir))

        except Exception:
            pass
    finally:
        store.close()
    if json_flag:
        click.echo(json.dumps(journal, indent=2))
    else:
        click.echo(json.dumps(journal, indent=2))
        try:
            envelope = load_evidence(open_store(_ctx(ctx).db), run_id)
            if envelope is not None:
                click.echo("---")
                click.echo(render_evidence_human(envelope))
        except Exception:
            pass


def _recovery_service(store: Store) -> RecoveryService:
    return RecoveryService(
        SQLiteLeaseSink(store),
        run_liveness=_run_liveness_resolver(store),
    )


class RecoverGroup(click.Group):
    def resolve_command(
        self, ctx: click.Context, args: list[str]
    ) -> tuple[str | None, click.Command | None, list[str]]:
        if args and args[0] not in self.commands:
            legacy = click.Command(
                "legacy",
                params=[
                    click.Argument(["run_id"]),
                    click.Option(
                        ["--execute"],
                        is_flag=True,
                        default=False,
                        help="Explicit approval to apply the recovery plan.",
                    ),
                ],
                callback=self._legacy_execute,
                help="Recover one run id (pass --execute to apply).",
            )
            return legacy.name, legacy, args
        return super().resolve_command(ctx, args)

    def _legacy_execute(self, run_id: str, execute: bool) -> None:
        # v0.9.0: this shim is an *implicit* spelling of a mutating command, so
        # it needs its own approval. The explicit `recover execute RUN_ID`
        # spelling never needed one — naming the sub-command is the approval.
        from mayhem.cli.app import implicit_execution_allowed

        ctx = click.get_current_context()
        # Structural: a global --dry-run skips the approval question and
        # returns before service.execute, so no compensation is attempted
        # whatever --execute or the compatibility switch say. Only the plan is
        # read.
        dry_run = bool(getattr(ctx.obj, "dry_run", False))
        if not dry_run:
            require_explicit_approval(
                "recover execute", approved=execute, allow_implicit=implicit_execution_allowed()
            )
        store = open_store(_ctx(ctx).db)
        try:
            service = _recovery_service(store)
            plan = service.plan((run_id,))
            if dry_run:
                _render_recovery_plan(plan, dry_run=True)
                return
            result = service.execute(plan)
        finally:
            store.close()
        if not result.recovered:
            click.echo(f"nothing to recover for {style.cyan(run_id)}")
            return
        for lease_id in result.recovered:
            click.echo(f"recovered lease {style.cyan(lease_id)}")


@click.group("recover", cls=RecoverGroup)
def recover() -> None:
    """Inspect and execute explicit run recovery."""


@recover.command("status")
@click.argument("run_ids", nargs=-1, required=True)
@click.option("--target", "target_profiles", multiple=True)
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def recover_status(
    ctx: click.Context,
    run_ids: tuple[str, ...],
    target_profiles: tuple[str, ...],
    as_json: bool,
) -> None:
    store = open_store(_ctx(ctx).db)
    try:
        result = _recovery_service(store).status(run_ids, target_profiles=target_profiles)
    finally:
        store.close()
    if as_json:
        click.echo(json.dumps(result.model_dump(mode="json"), default=str))
        return
    click.echo(f"recovery {result.state.value} for {', '.join(result.run_ids)}")
    for lease in result.leases:
        click.echo(
            f"  {lease.id} owner={lease.owner} expires={lease.expires_at} "
            f"target={','.join(lease.target)} fault={lease.fault} "
            f"state={lease.state} recovery={lease.recovery.value}"
        )


def _render_recovery_plan(plan: object, *, dry_run: bool = False) -> None:
    """Print a recovery *plan* — never apply it.

    Shared by ``recover plan`` and by the two mutating recovery paths when a
    global ``--dry-run`` turns them into previews, so the preview says the same
    thing on every spelling.
    """
    state = getattr(plan, "state", None)
    state_value = getattr(state, "value", state)
    click.echo(f"recovery plan {state_value}")
    for lease in getattr(plan, "leases", ()) or ():
        click.echo(
            f"  {lease.id}: compensate={json.dumps(list(lease.compensation))} "
            f"probe={json.dumps(list(lease.verification_probes))} "
            f"escalation={'; '.join(lease.escalation) or 'none'}"
        )
    if dry_run:
        click.echo("dry-run: recovery not executed; nothing compensated", err=True)


@recover.command("plan")
@click.argument("run_ids", nargs=-1, required=True)
@click.option("--target", "target_profiles", multiple=True)
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def recover_plan(
    ctx: click.Context,
    run_ids: tuple[str, ...],
    target_profiles: tuple[str, ...],
    as_json: bool,
) -> None:
    store = open_store(_ctx(ctx).db)
    try:
        result = _recovery_service(store).plan(run_ids, target_profiles=target_profiles)
    finally:
        store.close()
    if as_json:
        click.echo(json.dumps(result.model_dump(mode="json"), default=str))
        return
    _render_recovery_plan(result)


@recover.command("execute")
@click.argument("run_ids", nargs=-1, required=True)
@click.option("--target", "target_profiles", multiple=True)
@click.option("--artifact-dir", type=click.Path(), default=None)
@click.option("--json", "as_json", is_flag=True)
@click.pass_context
def recover_execute(
    ctx: click.Context,
    run_ids: tuple[str, ...],
    target_profiles: tuple[str, ...],
    artifact_dir: str | None,
    as_json: bool,
) -> None:
    """Apply a recovery plan: compensating leases is a mutation.

    Under a global ``--dry-run`` this prints the plan instead and compensates
    nothing — the preview never needs an approval and is never one.
    """

    # Naming the sub-command is the approval. A global --dry-run is a promise
    # that nothing mutates, so it is honoured *structurally* below — the
    # execute call is unreachable — rather than by an approval expression that
    # the compatibility switch could wave through.
    from mayhem.cli.app import implicit_execution_allowed

    obj = _ctx(ctx)
    store = open_store(obj.db)
    try:
        service = _recovery_service(store)
        plan = service.plan(run_ids, target_profiles=target_profiles)
        if obj.dry_run:
            _render_recovery_plan(plan, dry_run=True)
            if as_json:
                click.echo(json.dumps(plan.model_dump(mode="json"), default=str))
            return
        require_explicit_approval(
            "recover execute", approved=True, allow_implicit=implicit_execution_allowed()
        )
        result = service.execute(plan, artifact_dir=artifact_dir)
    finally:
        store.close()
    if as_json:
        click.echo(json.dumps(result.model_dump(mode="json"), default=str))
        if result.dirty:
            ctx.exit(int(ExitCode.RECOVERY_FAILURE))
        return
    for lease_id in result.recovered:
        click.echo(f"recovered lease {style.cyan(lease_id)}")
    for lease_id in result.expired:
        click.echo(f"expired lease {style.cyan(lease_id)}")
    for lease_id in result.dirty:
        click.echo(style.danger(f"DIRTY lease {lease_id}: manual action required"))
    if result.handoff_path is not None:
        click.echo(f"handoff artifact: {result.handoff_path}")
    if result.dirty:
        ctx.exit(int(ExitCode.RECOVERY_FAILURE))


@click.command("janitor")
@click.option(
    "-e", "--execute", is_flag=True, default=False, help="Apply the planned lease transitions."
)
@click.option("--json", "as_json", is_flag=True, help="Emit a JSON projection.")
@click.pass_context
def janitor(ctx: click.Context, execute: bool, as_json: bool) -> None:
    """Preview lease cleanup by default; pass --execute to apply it.

    A global ``--dry-run`` keeps it a preview even with ``--execute``: the
    planned transitions are reported, never applied.
    """
    obj = _ctx(ctx)
    # Structural first: a global --dry-run downgrades the command to the
    # preview branch, so sweep(execute=True) is unreachable whatever --execute
    # or the compatibility switch say. The approval then only guards the
    # mutation that is actually reachable.
    from mayhem.cli.app import implicit_execution_allowed

    execute = bool(execute) and not obj.dry_run
    if execute:
        require_explicit_approval(
            "janitor --execute", approved=True, allow_implicit=implicit_execution_allowed()
        )
    store = open_store(obj.db)
    try:
        janitor_service = Janitor(SQLiteLeaseSink(store))
        liveness = _run_liveness_resolver(store)
        sweep: SweepResult | None
        if execute:
            sweep = janitor_service.sweep(run_liveness=liveness, execute=True)
            # The rendered JSON carries the "execute" flag alongside the id
            # lists, so the value type is genuinely heterogeneous.
            payload: dict[str, Any] = {
                "execute": True,
                "expired": list(sweep.expired),
                "recovered": list(sweep.recovered),
                "dirty": list(sweep.dirty),
            }
        else:
            preview = janitor_service.plan(run_liveness=liveness)
            sweep = None
            payload = {
                "execute": False,
                "would_expire": list(preview.would_expire),
                "would_recover": list(preview.would_recover),
                "would_mark_dirty": list(preview.would_mark_dirty),
            }
    finally:
        store.close()
    if as_json:
        click.echo(json.dumps(payload))
        if execute and sweep is not None and sweep.dirty:
            ctx.exit(int(ExitCode.RECOVERY_FAILURE))
        return
    if not execute:
        if obj.dry_run:
            click.echo(
                style.cyan("janitor dry-run: --dry-run never applies changes (--execute ignored)")
            )
        else:
            click.echo(style.cyan("janitor dry-run: pass --execute to apply changes"))
        for lease_id in payload["would_expire"]:
            click.echo(f"would expire lease {style.cyan(lease_id)}")
        for lease_id in payload["would_recover"]:
            click.echo(f"would recover lease {style.cyan(lease_id)}")
        return
    if sweep is None or sweep.quiet:
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
