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
    from mayhem.agents.impact import ContainerDependencyPlan
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
