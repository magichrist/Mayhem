"""``mayhem inspect coverage --matrix`` — the servicexfault grid, absences included.

The summary view answers "how much is covered?". It cannot answer "what is
*not* covered?", which is the question a coverage map exists for, because a cell
with no run behind it has no row to render.

The rule this module exists to make true is the one in plan 22 Phase 3:
**an empty cell renders as untested, never as passing-by-absence.** It is
enforced structurally rather than by convention: :func:`coverage_matrix` takes
the *declared* services and faults as arguments and materialises their full
cross product, so a cell nobody has run still has somewhere to be. There is no
code path in which a missing cell is skipped, because the grid is built from
the declaration and the state is looked up.

Three further things the view owes its reader, and all three are properties
rather than styling choices:

* **Evidence, or nothing.** A cell claiming a state with no run behind it is
  rendered as untested with the discrepancy stated, not as its claimed state.
  :func:`_effective_state` is where that happens, and it is a single expression
  so there is one place for the rule to live.
* **The denominator, on the same screen.** A percentage without the population
  it divides is the single most misleading thing a coverage dashboard can show,
  and plan 22 Phase 6's acceptance criterion names it. :func:`coverage_matrix`
  returns the denominator next to the ratio, and both renderers print it.
* **Blocked cells are not testable cells.** A cell the environment refuses to run
  is not a gap and not a success; it is excluded from the denominator and shown
  separately, which is what makes the percentage mean "of what I could have run".

What this does not do
---------------------

* **It does not change what counts as covered.** Whether a cell is `PASSED` is
  decided by `infra.coverage_service` counting cited evidence; this module
  renders what it is told and reports a mismatch rather than reconciling it.
* **It does not fetch or join evidence.** `last_run` is carried on the cell; this
  module reads it and never resolves it, so a dangling run id is visible as
  "executed" rather than hidden.
* **It does not add a dimension.** Rows are services and columns are faults,
  because that is the grid the plan asks for. The other three coverage
  dimensions are filters over it, not axes of it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from mayhem.cli import style
from mayhem.domain.coverage import CellState

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from mayhem.domain.coverage import ResilienceCell

#: The character an absent cell renders as. Deliberately the same ``·`` the
#: summary uses for ``UNKNOWN``, because they mean the same thing to a reader:
#: nothing has been established about this cell either way.
ABSENT = CellState.UNKNOWN

#: States a cell may claim without a run behind it. Anything else -- a refusal,
#: a skip, a blocking decision -- can be true without ever having executed, so
#: requiring a run for them would erase exactly the information they carry.
NEEDS_RUN = frozenset({CellState.PASSED, CellState.FAILED, CellState.EXECUTED})


@dataclass(frozen=True, slots=True)
class MatrixCell:
    """One position in the grid, and everything the view must say about it.

    ``absent`` is the load-bearing field: it is ``True`` when the grid declared
    this servicexfault pair and no :class:`ResilienceCell` claimed it. An absent
    cell is *not* an error and *not* a pass; it is the thing the map is for.
    """

    service: str
    fault: str
    state: CellState
    absent: bool = False
    last_run: str = ""
    unevidenced: bool = False
    note: str = ""

    @property
    def counted(self) -> bool:
        """Is this cell in the denominator?

        **Absent cells are counted.** A never-run cell is the gap the map exists
        to surface, so excluding it would let a completely untested service
        report 100%. Only ``BLOCKED`` is excluded, because a refused environment
        is not a gap and counting it would let an operator raise the number by
        configuring less.
        """
        return self.state is not CellState.BLOCKED

    @property
    def covered(self) -> bool:
        """Does this cell count as covered?

        Requires the same condition as :attr:`counted` plus a passing state with
        a run behind it, so a cell cannot contribute to the numerator while
        being excluded from the denominator.
        """
        return self.counted and self.state is CellState.PASSED and not self.unevidenced

    def to_dict(self) -> dict[str, object]:
        return {
            "service": self.service,
            "fault": self.fault,
            "state": self.state.value,
            "absent": self.absent,
            "counted": self.counted,
            "covered": self.covered,
            "last_run": self.last_run,
            "unevidenced": self.unevidenced,
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class CoverageMatrix:
    """The grid, its cells, and the denominator its percentages divide by.

    ``denominator`` is stored rather than recomputed at render time so that a
    renderer cannot disagree with the number it is displaying. ``by_state``
    counts every cell including the absent ones, so a reader can reconcile the
    grid against the total rather than trusting the ratio.
    """

    services: tuple[str, ...]
    faults: tuple[str, ...]
    cells: tuple[tuple[MatrixCell, ...], ...] = field(default=())
    by_state: dict[CellState, int] = field(default_factory=dict)

    @property
    def flat(self) -> tuple[MatrixCell, ...]:
        return tuple(cell for row in self.cells for cell in row)

    @property
    def declared(self) -> int:
        """Every position the grid declares, absent ones included."""
        return len(self.services) * len(self.faults)

    @property
    def denominator(self) -> int:
        """What the percentage divides by: declared cells that could be run.

        Blocked cells are excluded because a refused environment is not a gap,
        and counting it would let an operator improve their number by
        configuring less.
        """
        return sum(1 for cell in self.flat if cell.counted)

    @property
    def numerator(self) -> int:
        return sum(1 for cell in self.flat if cell.covered)

    @property
    def absent(self) -> tuple[MatrixCell, ...]:
        return tuple(cell for cell in self.flat if cell.absent)

    @property
    def unevidenced(self) -> tuple[MatrixCell, ...]:
        return tuple(cell for cell in self.flat if cell.unevidenced)

    @property
    def percent(self) -> float:
        denominator = self.denominator
        return (self.numerator / denominator * 100.0) if denominator else 0.0

    def denominator_description(self) -> str:
        """The sentence that must appear beside every percentage.

        Quoting the population rather than describing it is what makes the
        number auditable: a reader can count the grid and check it.
        """
        return (
            f"{self.numerator} covered of {self.denominator} testable cells "
            f"({self.declared} declared, {len(self.absent)} never run, "
            f"{self.by_state.get(CellState.BLOCKED, 0)} blocked)"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "services": list(self.services),
            "faults": list(self.faults),
            "summary": {
                "declared": self.declared,
                "denominator": self.denominator,
                "numerator": self.numerator,
                "coverage_pct": round(self.percent, 1),
                "denominator_description": self.denominator_description(),
                "never_run": len(self.absent),
                "unevidenced": len(self.unevidenced),
                "by_state": {state.value: count for state, count in self.by_state.items()},
            },
            "rows": [[cell.to_dict() for cell in row] for row in self.cells],
        }


def _effective_state(cell: ResilienceCell | None) -> tuple[CellState, bool, str]:
    """``(state to render, unevidenced, note)`` for one grid position.

    The single place the "no state without a run" rule lives, so the human and
    JSON renderers cannot drift from each other. An absent cell renders as
    ``UNKNOWN`` with a note saying it was never run -- never as ``PASSED``, and
    never silently as ``UNKNOWN`` either, because "we do not know" and "nobody
    has looked" are different facts and the map is more useful when it can say
    which one this is.
    """
    if cell is None:
        return ABSENT, False, "never run"
    if cell.state in NEEDS_RUN and not cell.last_run:
        return (
            ABSENT,
            True,
            f"claims {cell.state.value} with no run behind it; rendered untested",
        )
    note = ""
    if cell.state is CellState.BLOCKED:
        note = cell.next_rationale or "blocked by the environment; excluded from the denominator"
    return cell.state, False, note


def coverage_matrix(
    cells: Iterable[ResilienceCell],
    *,
    services: Sequence[str] | None = None,
    faults: Sequence[str] | None = None,
) -> CoverageMatrix:
    """Materialise the full servicexfault grid over ``cells``.

    ``services`` and ``faults`` are the *declaration*. Passing them is what
    makes absences visible; omit them and the grid is built from the cells
    present, which is the summary view's weaker question and is offered only
    because a caller with nothing to declare still deserves a grid.
    """
    materialised = tuple(cells)
    observed_services = {cell.service or cell.target for cell in materialised}
    observed_faults = {cell.fault for cell in materialised}
    rows = tuple(sorted(services)) if services else tuple(sorted(s for s in observed_services if s))
    columns = tuple(sorted(faults)) if faults else tuple(sorted(f for f in observed_faults if f))

    index: dict[tuple[str, str], ResilienceCell] = {}
    for cell in materialised:
        key = (cell.service or cell.target, cell.fault)
        # A duplicate is kept rather than dropped: two cells claiming one
        # position is a data problem, and hiding the second would hide it.
        index.setdefault(key, cell)

    grid: list[tuple[MatrixCell, ...]] = []
    counts = dict.fromkeys(CellState, 0)
    for service in rows:
        row: list[MatrixCell] = []
        for fault in columns:
            found = index.get((service, fault))
            state, unevidenced, note = _effective_state(found)
            entry = MatrixCell(
                service=service,
                fault=fault,
                state=state,
                absent=found is None,
                last_run=found.last_run if found is not None else "",
                unevidenced=unevidenced,
                note=note,
            )
            counts[entry.state] += 1
            row.append(entry)
        grid.append(tuple(row))

    return CoverageMatrix(
        services=rows,
        faults=columns,
        cells=tuple(grid),
        by_state=counts,
    )


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


def render_coverage_matrix(matrix: CoverageMatrix, *, as_json: bool = False) -> str:
    """Render the grid. JSON and human carry the same facts, in that order.

    The percentage is never printed without :meth:`denominator_description` on
    the same output -- that pairing is plan 22 Phase 6's acceptance criterion,
    and it is structural here rather than left to the prose.
    """
    if as_json:
        return json.dumps(matrix.to_dict(), indent=2, sort_keys=True)

    if not matrix.services or not matrix.faults:
        return "\n".join(
            (
                style.cyan("coverage matrix"),
                "  no services or no fault kinds declared; the grid is empty",
                f"  {matrix.denominator_description()}",
            )
        )

    label_width = max(len(service) for service in matrix.services)
    body = (
        _render_grid(matrix, label_width)
        if _grid_fits(matrix.faults, label_width)
        else _render_grouped(matrix)
    )
    lines = [
        style.cyan("coverage matrix"),
        style.info(f"  {matrix.denominator_description()}"),
        *body,
    ]
    lines.append(style.info("  · never run or not established   # blocked (excluded above)"))
    for cell in matrix.unevidenced:
        lines.append(style.yellow(f"  ! {cell.service}/{cell.fault}: {cell.note}"))
    return "\n".join(lines)


#: Width budget for the human grid, in characters. Chosen so a row stays
#: readable rather than merely present; past this the grouped view is used.
GRID_WIDTH_BUDGET = 120


def _column_width(faults: Sequence[str]) -> int:
    """The narrowest header width that keeps every column distinguishable.

    Truncating to a constant is what made ``container.kill``,
    ``container.pause`` and ``container.restart`` all read ``contai`` in the
    first draft: the grid was widest exactly where it was least legible. The
    width is now derived from the data, so the fallback fires when the columns
    genuinely do not fit rather than when a constant happened to be too small.
    """
    return max((len(fault) for fault in faults), default=1)


def _grid_fits(faults: Sequence[str], label_width: int) -> bool:
    if not faults:
        return True
    return 2 + label_width + 2 + len(faults) * (_column_width(faults) + 1) <= GRID_WIDTH_BUDGET


def _render_grid(matrix: CoverageMatrix, label_width: int) -> list[str]:
    width = _column_width(matrix.faults)
    header = (
        "  "
        + " " * label_width
        + "  "
        + " ".join(fault[:width].ljust(width) for fault in matrix.faults)
    )
    lines = [header]
    for service, row in zip(matrix.services, matrix.cells, strict=True):
        bar = " ".join(_STATE_CHAR[cell.state] for cell in row)
        lines.append(f"  {service:<{label_width}s}  {bar}")
    return lines


def _render_grouped(matrix: CoverageMatrix) -> list[str]:
    """One line per service and fault family, when the grid will not fit.

    Same cells, same states, same denominator \u2014 the information is not reduced,
    only the layout changes. A 128-column table squashed into a terminal is not
    a map; a per-family breakdown is, and it names every fault rather than
    truncating it to an ambiguous prefix.
    """
    label_width = max(len(service) for service in matrix.services)
    families: dict[str, list[str]] = {}
    for fault in matrix.faults:
        families.setdefault(fault.split(".", 1)[0], []).append(fault)
    lines = [
        style.info(
            f"  {len(matrix.faults)} fault kinds across {len(families)} famil"
            f"{'y' if len(families) == 1 else 'ies'}; grouped so no column is truncated"
        )
    ]
    for family in sorted(families):
        members = set(families[family])
        lines.append(style.cyan(f"  {family}.*  ({len(members)} kinds)"))
        for service, row in zip(matrix.services, matrix.cells, strict=True):
            cells = [cell for cell in row if cell.fault in members]
            if not cells:
                continue
            bar = "".join(_STATE_CHAR[cell.state] for cell in cells)
            covered = sum(1 for cell in cells if cell.covered)
            lines.append(f"    {service:<{label_width}s}  [{bar}] {covered}")
    return lines
