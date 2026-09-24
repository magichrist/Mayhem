"""``mayhem next`` — §3.2 command implementation.

Answer the one question a solo user asks before every session:
*what should I test next?*

Shape::

    mayhem next [drill.yaml] [--compose PATH] [--limit N] [--seed N]
                [--explain] [--json] [--quiet] [--no-color]
                [--db PATH] [--profile NAME]
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import TYPE_CHECKING

import click

from mayhem.cli import style
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.services import build_graph, open_store
from mayhem.domain.coverage import CellFilters, CellState, CoverageCell
from mayhem.infra.coverage_repository import SQLiteCoverageRepository
from mayhem.infra.ranking import rank_resilience_cells

if TYPE_CHECKING:
    from mayhem.cli.context import CliContext
    from mayhem.domain.risks import RiskLevel
    from mayhem.domain.topology import TopologyGraph


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


def _landscape_cells(
    graph: TopologyGraph, seed: int = 0
) -> tuple[tuple[CoverageCell, ...], dict[str, float], dict[str, RiskLevel]]:
    """Build a CoverageCell landscape from a topology graph.

    Returns (cells, criticality_map, risk_map).
    """
    from mayhem.domain.catalog import CATALOG
    from mayhem.infra.candidate_generator import CandidateLandscape, SeededCandidateGenerator
    from mayhem.infra.maniac import coverage_cell_for_candidate

    targets = tuple(sorted({n.id for n in graph.nodes}))

    # Fault kinds: everything runnable on the selected engine — with ``-k``
    # this is the kubernetes-available subset, so ``next`` never suggests a
    # fault the selected engine cannot execute.
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

    # Criticality map: flat 0.5 per §7.2
    criticality_map: dict[str, float] = dict.fromkeys(targets, 0.5)

    # Risk map from catalog
    risk_map: dict[str, RiskLevel] = {}
    for fd in CATALOG:
        risk_map[fd.id] = fd.risk

    return tuple(cells), criticality_map, risk_map


def _operator_summary(enriched, ranked, suggestions) -> dict[str, object]:
    return {
        "coverage_delta": 0,
        "blocked_cells": sum(cell.state is CellState.BLOCKED for cell in enriched),
        "highest_risk_gaps": [
            rc.cell.to_dict()
            for rc in ranked
            if rc.cell.risk in {"high", "critical"}
        ][:3],
        "next_action": suggestions[0].cell.key if suggestions else "no-action",
    }


def _render_human(suggestions, ranked, operator_summary, explain: bool) -> str:
    if not suggestions:
        return "no matching untested cells remain."
    lines = [
        style.cyan("suggested next cells")
        + f" (top {len(suggestions)} of {len(ranked)} matching untested)",
        "",
        f"  operator summary: delta=0 blocked={operator_summary['blocked_cells']} "
        f"highest-risk-gaps={len(operator_summary['highest_risk_gaps'])}",
        f"  next action: {operator_summary['next_action']}",
    ]
    for i, rc in enumerate(suggestions, 1):
        cell = rc.cell
        lines.append(
            f"  {style.info(f'{i}.')} {style.cyan(cell.target)}/{style.info(cell.fault_kind)} "
            f"score={style.ok(str(round(rc.score, 3)))}"
        )
        if explain:
            lines.append(f"     why: {rc.explanation}")
            lines.append(
                f"     info={rc.factors['info']:.3f} criticality={rc.factors['criticality']:.3f} "
                f"diversity={rc.factors['diversity']:.3f} risk_rank={int(rc.factors['risk_rank'])}"
            )
    return "\n".join(lines)


@click.command("next")
@_compose_option
@click.argument("spec", required=False, type=click.Path(exists=True))
@click.option("--limit", type=int, default=5, help="Max suggestions to return (default: 5).")
@click.option(
    "--seed", type=int, default=0, help="RNG seed for deterministic generation (default: 0)."
)
@click.option(
    "--explain", is_flag=True, default=False, help="Print scoring rationale per suggestion."
)
@click.option("--target-profile", default=None, help="Filter to a target profile.")
@click.option("--engine", default=None, help="Filter to an execution engine.")
@click.option("--service", default=None, help="Filter to a service name.")
@click.option("--failure-domain", default=None, help="Filter to a failure domain.")
@click.option("--risk", default=None, help="Filter to a risk level.")
@click.option("--maturity", default=None, help="Filter to a maturity level.")
@click.option(
    "--state",
    "state_filter",
    type=click.Choice([*(state.value for state in CellState), "covered"]),
    default=None,
    help="Filter to a cell state.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit as JSON.")
@click.option("--quiet", "-q", is_flag=True, help="Suppress human output.")
@click.option("--no-color", is_flag=True, default=False, help="Disable colored output.")
@click.pass_context
def next_cmd(
    ctx: click.Context,
    spec: str | None,
    compose: str | None,
    limit: int,
    seed: int,
    explain: bool,
    target_profile: str | None,
    engine: str | None,
    service: str | None,
    failure_domain: str | None,
    risk: str | None,
    maturity: str | None,
    state_filter: str | None,
    as_json: bool,
    quiet: bool,
    no_color: bool,
) -> None:
    """Suggest the most valuable untested cell to run next (§3.2).

    Never suggests already-covered or blocked cells. Deterministic under the
    same seed/topology/config.
    """
    ctx_obj: CliContext = ctx.obj

    if no_color:
        import os

        os.environ["NO_COLOR"] = "1"

    graph = _graph_from(ctx, compose)

    landscape, criticality_map, risk_map = _landscape_cells(graph, seed=seed)
    if not landscape:
        if not quiet:
            click.echo("no testable cells in the landscape.")
        ctx.exit(int(ExitCode.SUCCESS))
        return

    store = open_store(ctx_obj.db)
    try:
        coverage = SQLiteCoverageRepository(store)
        enriched = coverage.resilience_cells(landscape)
        if engine is None:
            from mayhem.cli.services import selected_engine

            engine = selected_engine() or None
        if engine:
            from dataclasses import replace

            enriched = tuple(replace(cell, engine=engine) for cell in enriched)
        filters = CellFilters(
            target_profile=target_profile or ctx_obj.target,
            engine=engine,
            service=service,
            failure_domain=failure_domain,
            risk=risk,
            maturity=maturity,
            state=state_filter,
        )
        enriched = tuple(cell for cell in enriched if filters.matches(cell))
        failed_targets, failed_faults = coverage.recent_failures()
        from collections import Counter

        from mayhem.domain.faults import FaultCategory

        division_counter: Counter[str] = Counter(
            FaultCategory.from_fault_id(cell.fault_kind).value
            for cell in landscape
            if cell.key in coverage.covered_keys()
        )
        ranked = rank_resilience_cells(
            enriched,
            division_map=dict(division_counter),
            criticality_map=criticality_map,
            risk_map=risk_map,
            failed_targets=failed_targets,
            failed_faults=failed_faults,
        )
        suggestions = ranked[:limit]
        operator_summary = _operator_summary(enriched, ranked, suggestions)
        if as_json:
            output = {
                "operator_summary": operator_summary,
                "suggestions": [
                    {
                        "cell_key": rc.cell.key,
                        "target": rc.cell.target,
                        "fault_kind": rc.cell.fault_kind,
                        "execution_context": rc.cell.execution_context,
                        "parameter_band": rc.cell.parameter_band,
                        "state": rc.cell.state.value,
                        "next_rationale": rc.explanation,
                        "score": round(rc.score, 4),
                        "factors": {k: round(v, 4) for k, v in rc.factors.items()},
                    }
                    for rc in suggestions
                ],
                "total_ranked": len(ranked),
                "limit": limit,
            }
            click.echo(json.dumps(output, indent=2, sort_keys=True))
            ctx.exit(int(ExitCode.SUCCESS))
            return
        if not quiet:
            click.echo(_render_human(suggestions, ranked, operator_summary, explain))
    finally:
        store.close()
    ctx.exit(int(ExitCode.SUCCESS))
