"""``mayhem explore`` — §3.1 command implementation.

Turn a window into highest-value, safety-gated, evidence-recorded chaos
experiments across the stack, and report the coverage delta gained.

Shape::

    mayhem explore [drill.yaml] [--compose PATH] [--budget N] [--deadline DUR]
                   [--seed N] [--supervised] [--dry-run] [--allow-critical]
                   [--json] [--quiet] [--no-color] [--db PATH] [--profile NAME]
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

import click

from mayhem.cli import style
from mayhem.cli.context import CliContext
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.services import (
    build_graph,
    open_store,
    prepare,
)
from mayhem.controller.cell_runner import CellRunner
from mayhem.domain.coverage import CellState
from mayhem.domain.topology import TopologyGraph
from mayhem.infra.candidate_generator import CandidateLandscape
from mayhem.infra.coverage_repository import SQLiteCoverageRepository

if TYPE_CHECKING:
    from mayhem.controller.explore_flow import ExploreDryRun, ExploreRun
    from mayhem.infra.candidate_gates import CandidateGatePipeline


def _runtime_gate_pipeline(allow_critical: bool = False) -> CandidateGatePipeline:
    """Build a gate pipeline from probe-hold runtime facts.

    Feasibility mirrors ``synthesize_maniac_spec``: faults that require the
    Kubernetes engine are infeasible on a compose (Docker/Podman) runtime, so
    they are surfaced as rejections in ``--dry-run`` and ``blocked`` at
    runtime.  Everything else is passed through — per-cell feasibility is
    proven by the plan/impact-gate pathway at execute time.
    """
    from mayhem.domain.capabilities import Capability
    from mayhem.domain.catalog import all_definitions
    from mayhem.infra.candidate_gates import (
        CandidateGatePipeline,
        FeasibilityGate,
        ResourceConflictGate,
        SafetyGate,
    )

    excluded = frozenset({Capability.KUBERNETES_ENGINE})
    supported = tuple(
        definition.id
        for definition in all_definitions()
        if definition.required_caps.isdisjoint(excluded)
    )
    safety = SafetyGate(forbidden_faults=() if allow_critical else ())
    return CandidateGatePipeline(
        safety=safety,
        feasibility=FeasibilityGate(supported=supported),
        resource_conflict=ResourceConflictGate(),
    )


def _ctx(ctx: click.Context) -> CliContext:
    return ctx.obj  # type: ignore[return-value]


def _compose_option[F: Callable[..., object]](fn: F) -> F:
    return click.option(
        "-c",
        "--compose",
        type=str,
        default=None,
        help="docker-compose.yaml blueprint (auto-detected in cwd if omitted).",
    )(fn)


def _graph_from(ctx: click.Context, compose: str | None) -> tuple[TopologyGraph, str | None]:
    from mayhem.cli.topology import _resolve_compose

    resolved = _resolve_compose(compose)
    try:
        return build_graph(resolved), resolved
    except ValueError as exc:
        raise click.UsageError(str(exc), ctx=ctx) from None


def _build_landscape(
    graph: TopologyGraph,
) -> CandidateLandscape:
    """Build a CandidateLandscape from the live topology graph (§3.1.1)."""
    from mayhem.domain.catalog import all_definitions
    from mayhem.infra.candidate_generator import CandidateLandscape

    # Targets: real service names from the compose graph (never aliases).
    targets = graph.container_names()
    # Fault kinds: every fault in the catalog.
    faults = tuple(defn.id for defn in all_definitions())
    return CandidateLandscape(
        targets=targets,
        fault_kinds=faults,
        execution_contexts=("container",),
        parameter_bands=("default",),
    )


def _format_state_char(state: CellState | None) -> str:
    """Map cell state to the §3.1.8 single-char symbol."""
    if state is None:
        return "·"
    return {
        CellState.COVERED: "█",
        CellState.INCONCLUSIVE: "~",
        CellState.FAILED: "!",
        CellState.BLOCKED: "#",
    }.get(state, "?")


def _render_dry_run(dry: ExploreDryRun, *, json_mode: bool = False) -> str:
    """Render the dry-run ranked queue (§3.1.8)."""
    if json_mode:
        return json.dumps(
            {
                "total_candidates": dry.total_candidates,
                "gate_rejected": dry.gate_rejected,
                "new_coverage_estimate": dry.new_coverage_estimate,
                "queue": [
                    {
                        "target": e.cell.target,
                        "fault_kind": e.cell.fault_kind,
                        "execution_context": e.cell.execution_context,
                        "parameter_band": e.cell.parameter_band,
                        "cell_key": e.cell.key,
                        "gate_status": (
                            e.gate_decision.status.value if e.gate_decision else "accepted"
                        ),
                        "gate_reason": (
                            e.gate_decision.reason
                            if e.gate_decision and e.gate_decision.rejected
                            else ""
                        ),
                    }
                    for e in dry.entries
                ],
            },
            indent=2,
        )

    lines: list[str] = []
    lines.append(style.cyan("explore queue") + f" ({dry.total_candidates} candidates)")
    lines.append("")
    for i, entry in enumerate(dry.entries, 1):
        gate_char = "✗" if entry.gate_decision and entry.gate_decision.rejected else "✓"
        gate_style = style.danger if gate_char == "✗" else style.green
        lines.append(
            f"  {i:>3}. {gate_style(gate_char)} "
            f"{style.cyan(entry.cell.target):>20s}  "
            f"{entry.cell.fault_kind:<20s}  "
            f"{_format_state_char(None)}"
        )
        if entry.gate_decision and entry.gate_decision.rejected:
            lines.append(
                f"       {style.yellow('rejected:')} {entry.gate_decision.gate.value}: {entry.gate_decision.reason}"
            )
    lines.append("")
    lines.append(
        style.info("summary:")
        + f" {dry.total_candidates} candidates, "
        + f"{dry.gate_rejected} rejected, "
        + f"~{dry.new_coverage_estimate} new coverage"
    )
    return "\n".join(lines)


def _render_run(run: ExploreRun, *, json_mode: bool = False) -> str:
    """Render the live run results (§3.1.9 status + §3.1.10 failure lines)."""
    if json_mode:
        return json.dumps(
            {
                "budget_used": run.budget_used,
                "budget_limit": run.budget_limit,
                "executed_count": len(run.executed),
                "blocked_count": len(run.blocked),
                "denied_count": len(run.denied),
                "stopped_early": run.stopped_early,
                "stop_reason": run.stop_reason,
                "cells": [
                    {
                        "run_id": r.run_id,
                        "target": r.cell.target,
                        "fault_kind": r.cell.fault_kind,
                        "state": r.state.value,
                    }
                    for r in run.executed + run.blocked
                ],
            },
            indent=2,
        )

    lines: list[str] = []
    # §3.1.9 status block
    lines.append(style.cyan("explore session"))
    lines.append(f"  budget: {run.budget_used}/{run.budget_limit} executed")
    lines.append(f"  blocked: {len(run.blocked)}  denied: {len(run.denied)}")
    if run.stopped_early:
        lines.append(style.danger("  STOPPED EARLY:") + f" {run.stop_reason}")
    lines.append("")

    # Cell outcomes
    for r in run.executed:
        state_char = _format_state_char(r.state)
        state_style = {
            CellState.COVERED: style.green,
            CellState.FAILED: style.danger,
            CellState.INCONCLUSIVE: style.yellow,
        }.get(r.state, style.info)
        lines.append(
            f"  {state_char} {r.cell.target} / {r.cell.fault_kind} → {state_style(r.state.value)}"
        )
        lines.append(f"    run_id: {r.run_id}")

    # §3.1.10 failure lines for blocked cells
    for r in run.blocked:
        lines.append(
            f"  {_format_state_char(CellState.BLOCKED)} {r.cell.target} / {r.cell.fault_kind} → {style.yellow('blocked')}"
        )
        lines.append("    reason: (see gate output)")

    return "\n".join(lines)


@click.command("explore")
@_compose_option
@click.option("--budget", type=int, default=10, help="Max cells to execute (default: 10).")
@click.option("--deadline", type=str, default=None, help="Session deadline (e.g. '30m', '1h').")
@click.option(
    "--seed", type=int, default=0, help="RNG seed for deterministic generation (default: 0)."
)
@click.option(
    "--supervised", is_flag=True, default=False, help="Require user approval for each cell."
)
@click.option(
    "--dry-run", is_flag=True, default=False, help="Print ranked queue without executing."
)
@click.option("--allow-critical", is_flag=True, default=False, help="Allow critical-risk faults.")
@click.option("--json", "json_output", is_flag=True, default=False, help="Output as JSON.")
@click.option("--quiet", is_flag=True, default=False, help="Minimal output.")
@click.option("--no-color", is_flag=True, default=False, help="Disable colored output.")
@click.option("--db", type=str, default=None, help="SQLite database path.")
@click.option("--profile", type=str, default=None, help="Configuration profile name.")
@click.argument("experiment", type=click.Path(), required=False, default=None)
@click.pass_context
def explore(
    ctx: click.Context,
    experiment: str | None,
    compose: str | None,
    budget: int,
    deadline: str | None,
    seed: int,
    supervised: bool,
    dry_run: bool,
    allow_critical: bool,
    json_output: bool,
    quiet: bool,
    no_color: bool,
    db: str | None,
    profile: str | None,
) -> None:
    """Run highest-value chaos experiments across the stack.

    Generates a ranked queue of candidates from the compose topology, gates
    them for safety/feasibility, and executes up to --budget cells. Use
    --dry-run to preview the queue without executing anything.

    \b
    Examples:
      mayhem explore --compose docker-compose.yml
      mayhem explore --dry-run --budget 5
      mayhem explore --supervised --deadline 30m
      mayhem explore --json --quiet
    """
    if no_color:
        import os

        os.environ["NO_COLOR"] = "1"

    graph, resolved_compose = _graph_from(ctx, compose)
    obj = _ctx(ctx)
    db_path = db or obj.db
    store = open_store(db_path)
    coverage = SQLiteCoverageRepository(store)

    # Resolve deadline to epoch seconds.
    deadline_epoch: float | None = None
    if deadline:
        from mayhem.domain.common import parse_duration

        deadline_s = parse_duration(deadline)
        deadline_epoch = time.time() + deadline_s

    # Build landscape from the live compose graph.
    landscape = _build_landscape(graph)

    if dry_run:
        from mayhem.controller.explore_flow import dry_run as explore_dry_run

        gates = _runtime_gate_pipeline(allow_critical=allow_critical)
        result = explore_dry_run(
            landscape,
            seed=seed,
            covered_keys=coverage.covered_keys(),
            gate_pipeline=gates,
        )
        if not quiet:
            click.echo(_render_dry_run(result, json_mode=json_output))
        ctx.exit(int(ExitCode.SUCCESS))
        return

    # Live explore: prepare → runner → execute loop.
    try:
        prepared = prepare(
            config_path=obj.config or "",
            profile=obj.profile or profile,
            allow_critical=obj.allow_critical or allow_critical,
            store=store,
            graph=graph,
            compose=resolved_compose,
            spec_path=experiment,
        )
    except FileNotFoundError as exc:
        click.echo(style.danger(f"error: {exc}"), err=True)
        ctx.exit(int(ExitCode.CONFIG_ERROR))
        return
    except Exception as exc:
        click.echo(style.danger(f"error: {exc}"), err=True)
        ctx.exit(int(ExitCode.CONFIG_ERROR))
        return

    runner = CellRunner(
        store=store,
        graph=graph,
        prepared=prepared,
        coverage=coverage,
        live_graph=lambda: build_graph(resolved_compose),
    )

    from mayhem.controller.explore_flow import run_explore

    result = run_explore(
        landscape,
        runner=runner,
        coverage=coverage,
        seed=seed,
        budget=budget,
        deadline_epoch=deadline_epoch,
        supervised=supervised,
        gate_pipeline=_runtime_gate_pipeline(allow_critical=allow_critical),
    )

    if not quiet:
        click.echo(_render_run(result, json_mode=json_output))

    # Exit code: §C3 mapping.
    if result.stopped_early:
        ctx.exit(int(ExitCode.EXPERIMENT_FAILURE))
    elif result.budget_used == 0 and not result.blocked:
        ctx.exit(int(ExitCode.SUCCESS))
    else:
        ctx.exit(int(ExitCode.SUCCESS))
