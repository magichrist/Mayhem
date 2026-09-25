"""Lifecycle commands: validate -> plan -> run -> observe -> recover."""

from __future__ import annotations

import contextlib
import dataclasses
import json
import json as _json
import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

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
    run_detail,
    run_journal,
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
        alive = _pid_alive(int(raw_pid))
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
    """Resolve the CLI engine flag (``--podman``) to a concrete engine name."""
    from mayhem.cli.app import _STATE
    from mayhem.cli.topology import _resolve_engine

    return _resolve_engine(str(_STATE.get("engine", ""))) or "podman"


def _k8s_context_for_target(config_path: str | None, target: str | None) -> str | None:
    if target is None:
        return None
    from mayhem.domain.target_profiles import load_profiles_from_mayhem_yaml

    profile = load_profiles_from_mayhem_yaml(config_path).get(target)
    return profile.context if profile is not None else None


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
        return build_graph(
            resolved, engine_name=engine, target=target, config_path=config_path
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


def _preflight_for_run(
    *,
    graph: object,
    store: object,
    prepared: object,
    plan: object,
    target: str | None,
    engine: str,
    config_path: str | None = None,
) -> object:
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
        profile=None,
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


def _write_evidence_after_run(
    *,
    store: object,
    preflight: object,
    result: object,
    engine: str,
    evidence_dir: str | None,
    skip_gate: bool = False,
) -> EvidenceEnvelope | None:
    import contextlib

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
        observations: tuple[dict[str, object], ...] = tuple(
            getattr(result, "observability", []) or []
        )
        try:
            obs_list: list[dict[str, object]] = []
            for item in observations:
                if hasattr(item, "model_dump"):
                    try:
                        obs_list.append(item.model_dump(mode="json"))  # type: ignore[call-arg]
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
                    verdict = str(v.value)  # type: ignore[attr-defined]
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
        )
        with contextlib.suppress(Exception):
            write_evidence(store, envelope)
        if evidence_dir:
            with contextlib.suppress(Exception):
                write_evidence_file(envelope, evidence_dir)
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

    This reuses the same ranking logic as ``mayhem next`` but operates on
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


@click.command("validate")
@_compose_option
@click.argument("experiment", type=click.Path(), required=False, default=None)
@click.pass_context
def validate(ctx: click.Context, experiment: str | None, compose: str | None) -> None:
    """Compile a drill spec and run every safety gate without executing it."""
    graph, resolved_compose = _graph_from(ctx, compose)
    obj = _ctx(ctx)
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
    graph, resolved_compose = _graph_from(ctx, compose)
    obj = _ctx(ctx)
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
        compiled = plan_from_spec(
            experiment, graph, prepared=prepared, engine=_resolve_engine_from_state()
        )
        preflight = _preflight_for_run(
            graph=graph,
            store=store,
            prepared=prepared,
            plan=compiled.plan,
            target=obj.target,
            engine=_resolve_engine_from_state(),
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
                engine=_resolve_engine_from_state(),
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
    "--execute", is_flag=True, default=False, help="Explicit approval to execute the plan."
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
    as_json: bool,
) -> None:
    obj = _ctx(ctx)
    effective_engine = run_engine or _resolve_engine_from_state()
    target_name = run_target or obj.target
    k8s_context = _k8s_context_for_target(obj.config, target_name)
    graph, resolved_compose = _graph_from(ctx, compose, engine=effective_engine, target=target_name)
    if ctr is not None:
        if effective_engine == "kubernetes":
            raise click.UsageError(
                "--ctr is not a Kubernetes target selector; use --target", ctx=ctx
            )
        _require_container(ctr, graph, ctx)
    store = open_store(obj.db)
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
                    preflight = _preflight_for_run(
                        graph=graph,
                        store=store,
                        prepared=None,
                        plan=loaded_plan,
                        target=target_name,
                        config_path=obj.config,
                        engine=effective_engine,
                    )
                    _emit_preflight(preflight, as_json)
                    if not execute:
                        click.echo("plan loaded; pass --execute to run", err=True)
                        return
                    compiled_plan = loaded_plan
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
                    eng = engine_for(
                        store,
                        engine_name,
                        live_graph=lambda: build_graph(
                            resolved_compose,
                            engine_name=effective_engine,
                            target=target_name,
                            config_path=obj.config,
                        ),
                        on_event=_debug_progress() if obj.debug else None,
                        bypass=bypass,
                        recovery_grace=prepared_dummy.recovery_grace if prepared_dummy else 300.0,
                        k8s_context=k8s_context,
                    )
                    result = eng.execute(compiled_plan)
                    preflight2 = _preflight_for_run(
                        graph=graph,
                        store=store,
                        prepared=prepared_dummy,
                        plan=compiled_plan,
                        target=target_name,
                        config_path=obj.config,
                        engine=engine_name,
                    )
                    _write_evidence_after_run(
                        store=store,
                        preflight=preflight2,
                        result=result,
                        engine=engine_name,
                        evidence_dir=evidence_dir,
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
                if not execute:
                    preflight = _preflight_for_run(
                        graph=graph,
                        store=store,
                        prepared=None,
                        plan=loaded_plan,
                        target=target_name,
                        config_path=obj.config,
                        engine=effective_engine,
                    )
                    _emit_preflight(preflight, as_json)
                    click.echo("plan loaded; pass --execute to run", err=True)
                    return
                engine_name = effective_engine
                eng = engine_for(
                    store,
                    engine_name,
                    live_graph=lambda: build_graph(
                        resolved_compose,
                        engine_name=effective_engine,
                        target=target_name,
                        config_path=obj.config,
                    ),
                    on_event=_debug_progress() if obj.debug else None,
                    bypass={},
                    recovery_grace=300.0,
                    k8s_context=k8s_context,
                )
                result = eng.execute(loaded_plan)
                preflight_tmp = _preflight_for_run(
                    graph=graph,
                    store=store,
                    prepared=None,
                    plan=loaded_plan,
                    target=target_name,
                    config_path=obj.config,
                    engine=engine_name,
                )
                _write_evidence_after_run(
                    store=store,
                    preflight=preflight_tmp,
                    result=result,
                    engine=engine_name,
                    evidence_dir=evidence_dir,
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
        preflight = _preflight_for_run(
            graph=graph,
            store=store,
            prepared=prepared,
            plan=compiled.plan,
            target=target_name,
            config_path=obj.config,
            engine=effective_engine,
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
            if not execute:
                return
        _emit_preflight(preflight, as_json)
        if not execute:
            if experiment is not None and not from_plan and not plan_id:
                click.echo(migration_warning(), err=True)
                click.echo(
                    "executing via compatibility adapter; use --execute --from-plan for plan-first flow",
                    err=True,
                )
            else:
                click.echo("plan ready; pass --execute to run", err=True)
                return
        if experiment is not None and not from_plan and not plan_id and not execute:
            pass
        should_execute = execute or (
            experiment is not None and diff_path is None and from_plan is None and plan_id is None
        )
        if not should_execute:
            return
        if obj.dry_run:
            from mayhem.controller.safety import dry_run_policy_evaluation

            decisions = dry_run_policy_evaluation(compiled.plan, graph, prepared.safety)
            for d in decisions:
                click.echo(f"dry-run {d.rule_id}: {d.outcome} {d.reason} -> {d.remediation}")
            return
        skip_gate_used = not _gate_enabled()
        override = (
            os.getenv("MAYHEM_ALLOW_SKIP_GATE") == "1" or os.getenv("MAYHEM_BREAK_GLASS") == "1"
        )
        engine_name = effective_engine
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
            ),
            on_event=_debug_progress() if obj.debug else None,
            bypass=bypass2,
            recovery_grace=prepared.recovery_grace,
            k8s_context=k8s_context,
        )
        result = engine_obj.execute(compiled.plan)
        _write_evidence_after_run(
            store=store,
            preflight=preflight,
            result=result,
            engine=engine_name,
            evidence_dir=evidence_dir,
            skip_gate=skip_gate_used,
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
            f"inspect with {style.yellow(f'mayhem history {compiled.run_id}')}"
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
@click.argument("experiment", type=click.Path(), required=False, default=None)
@click.pass_context
def maniac(
    ctx: click.Context,
    experiment: str | None,
    compose: str | None,
    steps: int | None,
    ctr: str | None,
    show_next: bool,
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
    engine = _resolve_engine_from_state()
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
            live_graph=lambda: build_graph(
                resolved_compose, engine_name=engine_name, target=obj.target
            ),
            on_event=_debug_progress() if obj.debug else None,
            bypass=bypass,
            recovery_grace=prepared.recovery_grace,
        )
        result = engine.execute(compiled.plan)
        try:
            pf = _preflight_for_run(
                graph=graph,
                store=store,
                prepared=prepared,
                plan=compiled.plan,
                target=obj.target,
                engine=engine,
            )
            _write_evidence_after_run(
                store=store, preflight=pf, result=result, engine=engine, evidence_dir=None
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
            f"inspect with {style.yellow(f'mayhem history {compiled.run_id}')}"
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
                params=[click.Argument(["run_id"])],
                callback=self._legacy_execute,
                help="Recover one run id.",
            )
            return legacy.name, legacy, args
        return super().resolve_command(ctx, args)

    def _legacy_execute(self, run_id: str) -> None:
        store = open_store(_ctx(click.get_current_context()).db)
        try:
            service = _recovery_service(store)
            result = service.execute(service.plan((run_id,)))
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
    click.echo(f"recovery plan {result.state.value}")
    for lease in result.leases:
        click.echo(
            f"  {lease.id}: compensate={json.dumps(list(lease.compensation))} "
            f"probe={json.dumps(list(lease.verification_probes))} "
            f"escalation={'; '.join(lease.escalation) or 'none'}"
        )


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
    store = open_store(_ctx(ctx).db)
    try:
        service = _recovery_service(store)
        result = service.execute(
            service.plan(run_ids, target_profiles=target_profiles),
            artifact_dir=artifact_dir,
        )
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
    """Preview lease cleanup by default; pass --execute to apply it."""
    store = open_store(_ctx(ctx).db)
    try:
        janitor_service = Janitor(SQLiteLeaseSink(store))
        liveness = _run_liveness_resolver(store)
        if execute:
            sweep: SweepResult = janitor_service.sweep(run_liveness=liveness, execute=True)
            payload = {
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
