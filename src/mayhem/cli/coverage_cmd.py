"""``mayhem coverage`` — one coverage vocabulary for humans and JSON."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from typing import TYPE_CHECKING

import click

from mayhem.cli import style
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.services import build_graph, open_store
from mayhem.domain.coverage import CellFilters, CellState, CoverageCell, ResilienceCell
from mayhem.infra.coverage_repository import SQLiteCoverageRepository

if TYPE_CHECKING:
    from mayhem.cli.context import CliContext
    from mayhem.domain.topology import TopologyGraph

_STATE_CHAR: dict[CellState, str] = {
    CellState.UNKNOWN: "·",
    CellState.PLANNED: "P",
    CellState.EXECUTED: "E",
    CellState.PASSED: "█",
    CellState.INCONCLUSIVE: "~",
    CellState.FAILED: "!",
    CellState.BLOCKED: "#",
    CellState.SKIPPED: "-",
}

_STATE_LABEL = {state: state.value for state in CellState}


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
    from mayhem.cli.services import engine_fault_kinds
    from mayhem.infra.candidate_generator import CandidateLandscape, SeededCandidateGenerator
    from mayhem.infra.maniac import coverage_cell_for_candidate

    landscape_obj = CandidateLandscape(
        targets=tuple(sorted({node.id for node in graph.nodes})),
        fault_kinds=engine_fault_kinds(),
    )
    generated = SeededCandidateGenerator(landscape_obj, seed=seed).generate()
    cells: list[CoverageCell] = []
    seen: set[str] = set()
    for candidate in generated:
        cell = coverage_cell_for_candidate(candidate)
        if cell.key not in seen:
            seen.add(cell.key)
            cells.append(cell)
    return tuple(cells)


def _filter_cells(
    cells: tuple[ResilienceCell, ...],
    *,
    service: str | None,
    fault: str | None,
    fault_category: str | None,
    state_filter: str | None,
    target_profile: str | None,
    engine: str | None,
    failure_domain: str | None,
    risk: str | None,
    maturity: str | None,
) -> tuple[ResilienceCell, ...]:
    from mayhem.domain.faults import FaultCategory

    filters = CellFilters(
        target_profile=target_profile,
        engine=engine,
        service=service,
        failure_domain=failure_domain,
        risk=risk,
        maturity=maturity,
        state=state_filter,
    )
    result = tuple(cell for cell in cells if filters.matches(cell))
    if fault:
        result = tuple(cell for cell in result if fault.lower() in cell.fault.lower())
    if fault_category:
        result = tuple(
            cell
            for cell in result
            if cell.fault.split(".", 1)[0].lower() in fault_category.lower()
            or FaultCategory.from_fault_id(cell.fault).value == fault_category.lower()
        )
    return result


def _render_summary(cells: tuple[ResilienceCell, ...]) -> str:
    counts = dict.fromkeys(CellState, 0)
    for cell in cells:
        counts[cell.state] += 1
    total = len(cells)
    blocked = counts[CellState.BLOCKED]
    testable = total - blocked
    covered = counts[CellState.PASSED]
    percent = (covered / testable * 100) if testable else 0.0
    lines = [
        style.cyan("coverage summary"),
        f"  total cells:       {total}",
        f"  testable (excl. blocked): {testable}",
        f"  passed:            {covered} ({percent:.1f}%)",
        f"  unknown:           {counts[CellState.UNKNOWN]}",
        f"  planned:           {counts[CellState.PLANNED]}",
        f"  executed:          {counts[CellState.EXECUTED]}",
        f"  inconclusive:      {counts[CellState.INCONCLUSIVE]}",
        f"  failed:            {counts[CellState.FAILED]}",
        f"  blocked:           {blocked}",
        f"  skipped:           {counts[CellState.SKIPPED]}",
    ]
    targets = sorted({cell.target for cell in cells})
    if targets:
        lines.extend(("", style.cyan("per-target state")))
        for target in targets:
            target_cells = tuple(cell for cell in cells if cell.target == target)
            bar = "".join(_STATE_CHAR[cell.state] for cell in target_cells)
            lines.append(f"  {target:<30s} [{bar}] {len(target_cells)} cells")
    return "\n".join(lines)


def _render_json(cells: tuple[ResilienceCell, ...]) -> str:
    counts = dict.fromkeys(CellState, 0)
    for cell in cells:
        counts[cell.state] += 1
    total = len(cells)
    testable = total - counts[CellState.BLOCKED]
    covered = counts[CellState.PASSED]
    percent = (covered / testable * 100) if testable else 0.0
    output = {
        "summary": {
            "total": total,
            "testable": testable,
            "covered": covered,
            "coverage_pct": round(percent, 1),
            "coverage_delta": covered,
            "blocked": counts[CellState.BLOCKED],
            "unknown": counts[CellState.UNKNOWN],
            "planned": counts[CellState.PLANNED],
            "executed": counts[CellState.EXECUTED],
            "inconclusive": counts[CellState.INCONCLUSIVE],
            "failed": counts[CellState.FAILED],
            "skipped": counts[CellState.SKIPPED],
        },
        "cells": [cell.to_dict() for cell in cells],
    }
    return json.dumps(output, indent=2, sort_keys=True)


@click.command("coverage")
@_compose_option
@click.argument("spec", required=False, type=click.Path(exists=True))
@click.option("--service", default=None, help="Filter to a service name.")
@click.option("--fault", default=None, help="Filter to a fault kind.")
@click.option("--fault-category", default=None, help="Filter to a fault category.")
@click.option("--target-profile", default=None, help="Filter to a target profile.")
@click.option("--engine", default=None, help="Filter to an execution engine.")
@click.option("--failure-domain", default=None, help="Filter to a failure domain.")
@click.option("--risk", default=None, help="Filter to a risk level.")
@click.option("--maturity", default=None, help="Filter to a maturity level.")
@click.option(
    "--state",
    "state_filter",
    type=click.Choice([*(state.value for state in CellState), "covered"]),
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
    target_profile: str | None,
    engine: str | None,
    failure_domain: str | None,
    risk: str | None,
    maturity: str | None,
    state_filter: str | None,
    as_json: bool,
    quiet: bool,
    no_color: bool,
) -> None:
    """Show the same resilience cells in human and JSON output."""
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
    try:
        repository = SQLiteCoverageRepository(store)
        cells = repository.resilience_cells(landscape)
        if not engine:
            from mayhem.cli.services import selected_engine

            engine = selected_engine() or None
        if engine:
            cells = tuple(replace(cell, engine=engine) for cell in cells)
        if not target_profile:
            target_profile = ctx_obj.target
        cells = _filter_cells(
            cells,
            service=service,
            fault=fault,
            fault_category=fault_category,
            state_filter=state_filter,
            target_profile=target_profile,
            engine=engine,
            failure_domain=failure_domain,
            risk=risk,
            maturity=maturity,
        )
        if as_json:
            click.echo(_render_json(cells))
        elif not quiet:
            click.echo(_render_summary(cells))
    finally:
        store.close()
    ctx.exit(int(ExitCode.SUCCESS))
