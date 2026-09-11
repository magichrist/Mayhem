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

import click

from mayhem.cli import style
from mayhem.cli.context import CliContext
from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.services import build_graph, open_store
from mayhem.domain.coverage import CoverageCell
from mayhem.domain.risks import RiskLevel
from mayhem.domain.topology import TopologyGraph
from mayhem.infra.coverage_repository import SQLiteCoverageRepository
from mayhem.infra.ranking import rank


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

    # Collect fault kinds from catalog
    fault_kinds = tuple(sorted({fd.id for fd in CATALOG}))

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
    coverage = SQLiteCoverageRepository(store)

    covered_keys = coverage.covered_keys()
    state_map = coverage.states(landscape)

    # Division map: count covered cells per fault category
    from collections import Counter

    from mayhem.domain.faults import FaultCategory

    division_counter: Counter[str] = Counter()
    for cell in landscape:
        if cell.key in covered_keys:
            cat = FaultCategory.from_fault_id(cell.fault_kind).value
            division_counter[cat] += 1

    # Session memory: recent failures bias ranking toward retesting problem areas.
    failed_targets, failed_faults = coverage.recent_failures()

    ranked = rank(
        landscape,
        state_map=state_map,
        division_map=dict(division_counter),
        criticality_map=criticality_map,
        risk_map=risk_map,
        failed_targets=failed_targets,
        failed_faults=failed_faults,
    )

    # Apply limit
    suggestions = ranked[:limit]

    if as_json:
        output = {
            "suggestions": [
                {
                    "cell_key": rc.cell.key,
                    "target": rc.cell.target,
                    "fault_kind": rc.cell.fault_kind,
                    "execution_context": rc.cell.execution_context,
                    "parameter_band": rc.cell.parameter_band,
                    "score": round(rc.score, 4),
                    "factors": {k: round(v, 4) for k, v in rc.factors.items()},
                }
                for rc in suggestions
            ],
            "total_ranked": len(ranked),
            "limit": limit,
        }
        click.echo(json.dumps(output, indent=2))
        ctx.exit(int(ExitCode.SUCCESS))
        return

    if not quiet:
        if not suggestions:
            click.echo("no untested cells remain — the landscape is fully covered.")
        else:
            click.echo(
                style.cyan("suggested next cells")
                + f" (top {len(suggestions)} of {len(ranked)} untested)"
            )
            click.echo()
            for i, rc in enumerate(suggestions, 1):
                click.echo(
                    f"  {style.info(f'{i}.')} "
                    f"{style.cyan(rc.cell.target)}/{style.info(rc.cell.fault_kind)} "
                    f"score={style.ok(str(round(rc.score, 3)))}"
                )
                if explain:
                    factors = rc.factors
                    click.echo(
                        f"     info={factors['info']:.3f}  "
                        f"criticality={factors['criticality']:.3f}  "
                        f"diversity={factors['diversity']:.3f}  "
                        f"risk_rank={int(factors['risk_rank'])}"
                    )

    ctx.exit(int(ExitCode.SUCCESS))
