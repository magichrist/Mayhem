"""``mayhem coverage`` — §3.3 command implementation.

Show coverage map, per-service progress, untested/blocked lists, and state
filters.

Shape::

    mayhem coverage [drill.yaml] [--compose PATH] [--json] [--quiet]
                    [--no-color] [--db PATH] [--profile NAME]
                    [--service NAME] [--fault KIND | --fault-category CATEGORY]
                    [--state unknown|covered|inconclusive|failed|blocked]
"""

from __future__ import annotations

import json
from collections.abc import Callable

import click

from mayhem.cli import style
from mayhem.cli.context import CliContext
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.services import build_graph, open_store
from mayhem.domain.coverage import CellState, CoverageCell
from mayhem.domain.topology import TopologyGraph
from mayhem.infra.coverage_repository import SQLiteCoverageRepository

# §3.3.1 state character map (for matrix rendering).
_STATE_CHAR: dict[str | None, str] = {
    None: "\u00b7",  # unknown: ·
    CellState.COVERED: "\u2588",  # covered: █
    CellState.INCONCLUSIVE: "~",  # inconclusive: ~
    CellState.FAILED: "!",  # failed: !
    CellState.BLOCKED: "#",  # blocked: #
}

_STATE_LABEL: dict[str | None, str] = {
    None: "unknown",
    CellState.COVERED: "covered",
    CellState.INCONCLUSIVE: "inconclusive",
    CellState.FAILED: "failed",
    CellState.BLOCKED: "blocked",
}

_STATE_STYLE: dict[str | None, Callable[[str], str]] = {
    None: style.info,
    CellState.COVERED: style.green,
    CellState.INCONCLUSIVE: style.yellow,
    CellState.FAILED: style.danger,
    CellState.BLOCKED: style.warn,
}


def _compose_option[F: Callable[..., object]](fn: F) -> F:
    return click.option(
        "-c",
        "--compose",
        type=str,
        default=None,
        help="docker-compose.yaml blueprint (auto-detected in cwd if omitted).",
    )(fn)


def _graph_from(ctx: click.Context, compose: str | None) -> TopologyGraph:
    from mayhem.cli.topology import _resolve_compose

    resolved = _resolve_compose(compose)
    try:
        return build_graph(resolved)
    except ValueError as exc:
        raise click.UsageError(str(exc), ctx=ctx) from None


def _landscape_cells(graph: TopologyGraph, seed: int = 0) -> tuple[CoverageCell, ...]:
    """Build a CoverageCell landscape from a topology graph."""
    from mayhem.infra.candidate_generator import CandidateLandscape, SeededCandidateGenerator
    from mayhem.infra.maniac import coverage_cell_for_candidate

    targets = tuple(sorted({n.id for n in graph.nodes}))
    # Fault kinds: scoped to the engine selected at the root — with ``-k``
    # only kubernetes-executable families are counted in coverage land.
    from mayhem.cli.services import engine_fault_kinds

    fault_kinds = engine_fault_kinds()

    landscape_obj = CandidateLandscape(
        targets=targets,
        fault_kinds=fault_kinds,
    )

    gen = SeededCandidateGenerator(landscape_obj, seed=seed)
    cells: list[CoverageCell] = []
    seen_keys: set[str] = set()
    for candidate in gen.generate():
        cell = coverage_cell_for_candidate(candidate)
        if cell.key not in seen_keys:
            seen_keys.add(cell.key)
            cells.append(cell)

    return tuple(cells)


def _render_summary(
    cells: tuple[CoverageCell, ...],
    state_map: dict[str, CellState],
    service_filter: str | None,
    fault_filter: str | None,
    fault_category_filter: str | None,
    state_filter: str | None,
) -> str:
    """Render the §3.3 human summary block."""
    lines: list[str] = []

    # Apply filters
    filtered = cells
    if service_filter:
        filtered = tuple(c for c in filtered if service_filter.lower() in c.target.lower())
    if fault_filter:
        filtered = tuple(c for c in filtered if fault_filter.lower() in c.fault_kind.lower())
    if fault_category_filter:
        from mayhem.domain.faults import FaultCategory

        matching = set()
        for c in filtered:
            try:
                cat = FaultCategory.from_fault_id(c.fault_kind)
                if fault_category_filter.lower() in cat.value.lower():
                    matching.add(c.key)
            except Exception:
                pass
        filtered = tuple(c for c in filtered if c.key in matching)

    # Count states
    counts: dict[str, int] = {
        "unknown": 0,
        "covered": 0,
        "inconclusive": 0,
        "failed": 0,
        "blocked": 0,
    }
    for cell in filtered:
        st = state_map.get(cell.key)
        if st is None:
            counts["unknown"] += 1
        else:
            counts[st.value] += 1

    total = len(filtered)
    blocked = counts.get("blocked", 0)
    testable = total - blocked
    covered = counts.get("covered", 0)
    pct = (covered / testable * 100) if testable > 0 else 0.0

    lines.append(style.cyan("coverage summary"))
    lines.append(f"  total cells:       {total}")
    lines.append(f"  testable (excl. blocked): {testable}")
    lines.append(f"  covered:           {covered} ({pct:.1f}%)")
    lines.append(f"  inconclusive:      {counts.get('inconclusive', 0)}")
    lines.append(f"  failed:            {counts.get('failed', 0)}")
    lines.append(f"  blocked:           {counts.get('blocked', 0)}")
    lines.append(f"  unknown:           {counts.get('unknown', 0)}")

    # Per-service matrix (§3.3.1)
    targets = sorted({c.target for c in filtered})
    if targets:
        lines.append("")
        lines.append(style.cyan("per-target state"))
        for target in targets:
            target_cells = [c for c in filtered if c.target == target]
            # Pick the "worst" state per cell (blocked > failed > inconclusive > covered)
            worst_order = [
                CellState.BLOCKED,
                CellState.FAILED,
                CellState.INCONCLUSIVE,
                CellState.COVERED,
            ]
            symbols: list[str] = []
            for cell in target_cells:
                st = state_map.get(cell.key)
                char = _STATE_CHAR.get(st, "?")
                symbols.append(char)
            bar = "".join(symbols)
            lines.append(f"  {target:<30s} [{bar}] {len(target_cells)} cells")

    return "\n".join(lines)


def _render_json(
    cells: tuple[CoverageCell, ...],
    state_map: dict[str, CellState],
    service_filter: str | None,
    fault_filter: str | None,
    fault_category_filter: str | None,
    state_filter: str | None,
) -> str:
    """Render §3.3 JSON output."""
    filtered = cells
    if service_filter:
        filtered = tuple(c for c in filtered if service_filter.lower() in c.target.lower())
    if fault_filter:
        filtered = tuple(c for c in filtered if fault_filter.lower() in c.fault_kind.lower())
    if fault_category_filter:
        from mayhem.domain.faults import FaultCategory

        matching = set()
        for c in filtered:
            try:
                cat = FaultCategory.from_fault_id(c.fault_kind)
                if fault_category_filter.lower() in cat.value.lower():
                    matching.add(c.key)
            except Exception:
                pass
        filtered = tuple(c for c in filtered if c.key in matching)

    counts: dict[str, int] = {
        "unknown": 0,
        "covered": 0,
        "inconclusive": 0,
        "failed": 0,
        "blocked": 0,
    }
    cells_list: list[dict[str, object]] = []
    for cell in filtered:
        st = state_map.get(cell.key)
        label = _STATE_LABEL.get(st, "unknown")
        counts[label] += 1
        cells_list.append(
            {
                "cell_key": cell.key,
                "target": cell.target,
                "fault_kind": cell.fault_kind,
                "execution_context": cell.execution_context,
                "parameter_band": cell.parameter_band,
                "state": label,
            }
        )

    total = len(filtered)
    testable = total - counts.get("blocked", 0)
    covered = counts.get("covered", 0)
    pct = (covered / testable * 100) if testable > 0 else 0.0

    output = {
        "summary": {
            "total": total,
            "testable": testable,
            "covered": covered,
            "coverage_pct": round(pct, 1),
            **counts,
        },
        "cells": cells_list,
    }
    return json.dumps(output, indent=2)


@click.command("coverage")
@_compose_option
@click.argument("spec", required=False, type=click.Path(exists=True))
@click.option(
    "--service", default=None, help="Filter to a specific service name (substring match)."
)
@click.option("--fault", default=None, help="Filter to a specific fault kind (substring match).")
@click.option("--fault-category", default=None, help="Filter to an entire fault category.")
@click.option(
    "--state",
    "state_filter",
    type=click.Choice(["unknown", "covered", "inconclusive", "failed", "blocked"]),
    default=None,
    help="Show only cells in this state.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress human output.")
@click.option("--no-color", is_flag=True, default=False, help="Disable colored output.")
@click.pass_context
def coverage_cmd(
    ctx: click.Context,
    spec: str | None,
    compose: str | None,
    service: str | None,
    fault: str | None,
    fault_category: str | None,
    state_filter: str | None,
    as_json: bool,
    quiet: bool,
    no_color: bool,
) -> None:
    """Show coverage map, per-service progress, and untested/blocked lists (§3.3).

    Filters narrow the view: --service, --fault, --fault-category, --state.
    """
    ctx_obj: CliContext = ctx.obj

    if no_color:
        import os

        os.environ["NO_COLOR"] = "1"

    if fault and fault_category:
        click.echo(
            f"{style.danger('error:')} --fault and --fault-category are mutually exclusive",
            err=True,
        )
        ctx.exit(int(ExitCode.USAGE_ERROR))
        return

    graph = _graph_from(ctx, compose)
    landscape = _landscape_cells(graph)

    if not landscape:
        if not quiet:
            click.echo("no testable cells in the landscape.")
        ctx.exit(int(ExitCode.SUCCESS))
        return

    store = open_store(ctx_obj.db)
    coverage_repo = SQLiteCoverageRepository(store)

    state_map = coverage_repo.states(landscape)

    if as_json:
        click.echo(_render_json(landscape, state_map, service, fault, fault_category, state_filter))
    elif not quiet:
        click.echo(
            _render_summary(landscape, state_map, service, fault, fault_category, state_filter)
        )

    ctx.exit(int(ExitCode.SUCCESS))
