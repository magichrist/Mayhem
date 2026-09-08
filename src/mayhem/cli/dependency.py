"""``mayhem dependency`` — inspect and install fault-tooling dependencies.

The impact gate ([bypass] ``... missing bin:python``) refuses faults whose
in-image tooling is proven absent. This command group closes that gap:

  * ``check``   — probe each container, report the missing packages and the
    exact ``engine exec`` install command per package manager.
  * ``install`` — detect the container's package manager (apt-get / apk / dnf /
    yum / microdnf / zypper), install the mapped packages, re-probe and report.

Capabilities (``cap:NET_ADMIN``) and uid(0) requirements are *not* packages —
they are runtime flags (``--cap-add``, root exec) and are reported as guidance,
never installed. Host-side tooling (``net.load`` → k6 on the drill host) is
reported by ``check`` but never installed: ``mayhem dependency`` manages
container compatibility only.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import click

from mayhem.cli import style
from mayhem.cli.context import CliContext
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.lifecycle import (
    _compose_option,
    _graph_from,
    _resolve_engine_from_state,
    _resolve_spec,
)
from mayhem.cli.services import open_store, plan_from_spec, prepare
from mayhem.toolkit.tool_runner import run_tool

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from mayhem.agents.impact import ContainerCompilePlan, ContainerDependencyPlan
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.topology import TopologyGraph


def _ctx(ctx: click.Context) -> CliContext:
    obj = ctx.obj
    assert isinstance(obj, CliContext)
    return obj


def _dependency_context(
    ctx: click.Context, compose: str | None, experiment: str | None
) -> tuple[ExecutionPlan, TopologyGraph, str]:
    """Resolve graph + compiled plan the same way ``mayhem run`` does."""
    graph, resolved_compose = _graph_from(ctx, compose)
    spec_path = _resolve_spec(experiment)
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
            spec_path=spec_path,
        )
        compiled = plan_from_spec(
            spec_path, graph, prepared=prepared, engine=_resolve_engine_from_state()
        )
    finally:
        store.close()
    engine_name = _resolve_engine_from_state()
    return compiled.plan, graph, engine_name


def _render_dependency(dp: ContainerDependencyPlan, *, detailed: bool) -> None:
    """One container's dependency outcome (used by check and install)."""
    from mayhem.agents.impact import _MANUAL_BINS

    status = style.state("ok") if dp.gaps_remain else style.yellow("missing")
    click.echo(f"{status} {dp.container}  (pm: {dp.pm or 'none'})")
    if dp.packages:
        click.echo(f"  install: {', '.join(dp.packages)}")
    for bin_name in dp.manual:
        hint = _MANUAL_BINS.get(bin_name)
        click.echo(f"  manual: {bin_name}" + (f" — {hint}" if hint else ""))
    for item in dp.caps_missing:
        click.echo(f"  runtime flag: {item} (not a package — add --cap-add)")
    if dp.need_root:
        click.echo("  runtime: needs uid(0); installs run as --user 0")
    if dp.pm is None and dp.manual:
        click.echo(
            "  note: no package manager detected — install tooling into this"
            " image at build time (distroless/scratch images have no PM)"
        )
    if dp.installable and detailed:
        for argv in dp.install_argv():
            click.echo(f"  cmd: {' '.join(argv)}")


@click.group(
    "dependency",
    help="Inspect and install in-image tooling that gates fault families.",
    no_args_is_help=True,
)
def dependency() -> None:
    """Manage container tooling required by planned fault families."""


@dependency.command("check")
@_compose_option
@click.argument("experiment", type=click.Path(), required=False, default=None)
@click.pass_context
def check(ctx: click.Context, experiment: str | None, compose: str | None) -> None:
    """Probe containers and report packages that would un-bypass faults."""
    from mayhem.agents.impact import dependency_plan as _dep_plan
    from mayhem.agents.impact import host_tooling_gaps as _host_gaps

    plan, graph, engine_name = _dependency_context(ctx, compose, experiment)
    deps = _dep_plan(plan, graph, engine_name)
    host_gaps = _host_gaps(plan)
    if not deps and not host_gaps:
        click.echo(style.ok("no missing tooling") + " — every planned fault can inject")
        return
    for dp in deps:
        _render_dependency(dp, detailed=True)
    for name in host_gaps:
        click.echo(
            f"  host: {style.yellow('missing')} {name}"
            " — runs on the drill host, not in a container; install it on the"
            " host (mayhem dependency manages containers only)"
        )


@dependency.command("install")
@_compose_option
@click.argument("experiment", type=click.Path(), required=False, default=None)
@click.option("-y", "--yes", is_flag=True, help="Install without confirmation.")
@click.option("--dry-run", is_flag=True, help="Print commands without executing.")
@click.pass_context
def install(
    ctx: click.Context,
    experiment: str | None,
    compose: str | None,
    yes: bool,
    dry_run: bool,
) -> None:
    """Detect each container's package manager and install the mapped packages."""
    from mayhem.agents.impact import dependency_plan as _dep_plan
    from mayhem.agents.impact import host_tooling_gaps as _host_gaps

    plan, graph, engine_name = _dependency_context(ctx, compose, experiment)
    deps = _dep_plan(plan, graph, engine_name)
    installable = [dp for dp in deps if dp.installable]
    if not installable:
        click.echo(style.ok("nothing to install") + " — no auto-installable tooling missing")
    for name in _host_gaps(plan):
        click.echo(
            f"  host: {style.yellow('manual')} {name}"
            " — host-side tooling (not a container package); install on the drill host"
        )
    if not yes and not dry_run and installable:
        click.confirm(
            f"install {sum(len(d.packages) for d in installable)} package(s) across "
            f"{len(installable)} container(s)?",
            abort=True,
        )
    failures = 0
    for dp in installable:
        if dry_run:
            _render_dependency(dp, detailed=True)
            continue
        _install_one(dp)
        if not _verify_container(dp):
            failures += 1
    for dp in deps:
        if not dp.installable:
            _render_dependency(dp, detailed=False)
    if failures:
        ctx.exit(int(ExitCode.EXPERIMENT_FAILURE))


def _install_one(dp: ContainerDependencyPlan) -> None:
    for argv in dp.install_argv():
        result = run_tool(argv)
        status = style.ok("[ok]") if result.succeeded else style.danger("[FAIL]")
        click.echo(f"{status} {' '.join(argv)}")
        if not result.succeeded:
            click.echo(f"      {result.stderr.strip()[:300]}")


def _verify_container(dp: ContainerDependencyPlan) -> bool:
    """Re-probe the container and report which planned bins are now present."""
    from mayhem.agents.impact import probe_container_runtime

    run = probe_container_runtime(dp.engine, dp.container)
    if run is None:
        click.echo(style.warn("  unreachable after install — cannot verify"))
        return False
    missing = [b for b in dp.bins if not run.has_bin(b)]
    if missing:
        bin_label = ", ".join(missing)
        click.echo(style.warn(f"  still missing: {bin_label}"))
        return False
    click.echo(style.ok("  verified") + f" {dp.container} now has {', '.join(dp.bins)}")
    return True


# ── compile: bake the tooling into a docker-compose.mayhem.yml ──────────


def _bin_missing_expr(bin_name: str) -> str:
    """``sh`` test that is true when ``bin_name`` is absent from the container.

    ``python`` is satisfied by either interpreter (the probe behaves the same),
    so the generated guard checks python OR python3.
    """
    if bin_name == "python":
        return "command -v python >/dev/null 2>&1 || command -v python3 >/dev/null 2>&1"
    return f"command -v {bin_name} >/dev/null 2>&1"


def _install_arms(bins: Sequence[str]) -> list[str]:
    """One ``sh`` conditional arm per package manager present in the image.

    Only managers that own the mapped packages get an arm — an arm is the
    ``command -v <pm> && { <pm> install ...; return; }`` line that runs when
    the container's real package manager is available. Package lists are the
    per-PM mappings from ``impact._PM_PACKAGES``.
    """
    from mayhem.agents.impact import _PACKAGE_MANAGERS, _PM_PACKAGES

    per_pm: dict[str, list[str]] = {}
    for bin_name in bins:
        mapping = _PM_PACKAGES.get(bin_name, {})
        for pm in _PACKAGE_MANAGERS:
            pkg = mapping.get(pm)
            if pkg is not None:
                per_pm.setdefault(pm, []).append(pkg)
    arms: list[str] = []
    for pm in _PACKAGE_MANAGERS:
        packages = sorted(set(per_pm.get(pm, ())))
        if not packages:
            continue
        joined = " ".join(packages)
        if pm == "apt-get":
            cmd = f"apt-get update && apt-get install -y {joined}"
        elif pm == "apk":
            cmd = f"apk add --no-cache {joined}"
        elif pm == "zypper":
            cmd = f"zypper --non-interactive install {joined}"
        else:
            cmd = f"{pm} install -y {joined}"
        arms.append(f"  command -v {pm} >/dev/null 2>&1 && {{ {cmd}; return; }}")
    return arms


def _bootstrap_script(bins: Sequence[str]) -> str:
    """``sh`` bootstrap for a compose ``entrypoint``.

    Idempotent: installs the mapped packages for whichever package manager the
    image actually runs (only when a required bin is absent), then execs the
    service's own command — compose appends the service ``command`` (or the
    image CMD) as ``$0 $@``, so ``exec "$0" "$@"`` preserves it exactly, with
    or without an explicit ``command:`` in the compose file.
    """
    if not bins:
        return ""
    missing = " || ".join(f"! ( {_bin_missing_expr(b)})" for b in bins)
    arms = _install_arms(bins)
    if not arms:
        return ""
    lines = [
        "mayhem_install() {",
        *arms,
        "}",
        f"if {missing}; then mayhem_install; fi",
        'if [ -n "$0" ]; then exec "$0" "$@"; fi',
        'echo "mayhem: no command to run after dependency bootstrap" >&2',
        "exit 1",
    ]
    return "\n".join(lines)


def _service_key_for(services: Mapping[str, object], container: str) -> str | None:
    """Compose service key that produces ``container`` (by name or key)."""
    for key, raw in services.items():
        if not isinstance(raw, dict):
            continue
        if raw.get("container_name") == container or key == container:
            return key
    return None


@dependency.command("compile")
@_compose_option
@click.argument("experiment", type=click.Path(), required=False, default=None)
@click.option(
    "-o",
    "--output",
    "output_path",
    default="docker-compose.mayhem.yml",
    show_default=True,
    help="Generated compose file (the input is never overwritten).",
)
@click.pass_context
def compile_cmd(
    ctx: click.Context,
    experiment: str | None,
    compose: str | None,
    output_path: str,
) -> None:
    """Emit a compose file with the drill's fault tooling baked in.

    Reads the drill spec and the ``-c`` compose blueprint, then writes
    ``docker-compose.mayhem.yml`` where every service the drill targets gains
    a ``cap_add:`` list for its capability requirements and a bootstrap
    entrypoint that installs the missing tooling on first start (apk /
    apt-get / dnf / yum / microdnf / zypper, whichever the image has) and then
    execs the service's own command. Start the stack with
    ``podman compose -f docker-compose.mayhem.yml up -d``.
    """
    import copy

    import yaml

    from mayhem.agents.impact import compile_requirements as _compile_reqs
    from mayhem.agents.impact import host_tooling_gaps as _host_gaps
    from mayhem.cli.topology import _resolve_compose

    plan, graph, _engine = _dependency_context(ctx, compose, experiment)
    source = _resolve_compose(compose)
    if source is None:
        raise click.UsageError("no compose file found — pass -c docker-compose.yml", ctx=ctx)
    source_path = Path(source)
    document = yaml.safe_load(source_path.read_text(encoding="utf-8")) or {}
    services = document.get("services")
    if not isinstance(services, dict):
        raise click.ClickException(f"{source}: no 'services' mapping to extend")

    out_path = Path(output_path)
    if out_path.resolve() == source_path.resolve():
        raise click.UsageError(
            "refusing to overwrite the input compose file — pick another -o",
            ctx=ctx,
        )

    out = copy.deepcopy(document)
    out_services = out.setdefault("services", {})
    changed: list[tuple[str, ContainerCompilePlan, str | None]] = []
    for compiled in _compile_reqs(plan, graph):
        key = _service_key_for(services, compiled.container)
        service = out_services.get(key) if key is not None else None
        if key is None or not isinstance(service, dict):
            click.echo(
                f"  {style.yellow('*')} {compiled.container}: not in the compose "
                "file — tooling cannot be compiled in; fix mayhem.yaml or the "
                "compose service name",
                err=True,
            )
            continue
        caps = _merge_caps(service, compiled.caps)
        script = _bootstrap_script(compiled.bins)
        if caps is not None:
            service["cap_add"] = caps
        if script:
            source_spec = services.get(key) if key is not None else None
            source_programless = isinstance(source_spec, dict) and not _service_has_program(
                source_spec
            )
            service["entrypoint"] = ["/bin/sh", "-c", script]
            if source_programless:
                click.echo(
                    f"  {style.yellow('*')} {compiled.container}: the service has no "
                    "'command' or 'entrypoint' of its own — it relies on the image "
                    "CMD, and a container engine that resets CMD when entrypoint is "
                    "overridden (e.g. podman-compose) drops it; the bootstrap "
                    "cannot exec a program and the container exits at first start. "
                    "Add an explicit 'command:' to the service.",
                    err=True,
                )
        changed.append((key, compiled, script))
        if compiled.manual:
            click.echo(
                f"  {style.yellow('*')} {compiled.container}: manual tooling "
                f"— {', '.join(compiled.manual)} (no distro package to install)"
            )

    if not changed:
        click.echo(style.ok("nothing to compile") + " — no planned fault needs tooling")
        return
    out_path.write_text(
        yaml.safe_dump(out, sort_keys=False, default_flow_style=False, allow_unicode=True)
    )
    for svc_key, compiled, bootstrap in changed:
        caps_label = ", ".join(compiled.caps) or "—"
        script_label = "bootstrap entrypoint" if bootstrap else "no packages"
        click.echo(f"  {style.ok('[added]')} {svc_key}: cap_add {caps_label}; {script_label}")
    for name in _host_gaps(plan):
        click.echo(
            f"  host: {style.yellow('manual')} {name}"
            " — runs on the drill host, not in a container; install on the drill host"
        )
    click.echo(
        f"{style.ok('wrote')} {style.cyan(str(out_path))} — extend {source_path.name} untouched"
    )
    click.echo(
        f"  next: {style.cyan('podman compose -f ' + str(out_path) + ' up -d')}"
        " then rerun the drill"
    )


def _merge_caps(service: dict[str, object], required: Sequence[str]) -> list[str] | None:
    """Union existing ``cap_add`` with the requirements; None when nothing needed."""
    existing = service.get("cap_add")
    base: list[str] = []
    if isinstance(existing, list):
        base = [str(c) for c in existing if c != "ALL"]
    elif existing not in (None, "ALL"):
        base = [str(existing)]
    merged = sorted(set(base) | set(required))
    return merged if merged else None


def _service_has_program(service: dict[str, object]) -> bool:
    """True when the service defines its own ``command`` or ``entrypoint``."""
    return service.get("command") is not None or service.get("entrypoint") is not None
