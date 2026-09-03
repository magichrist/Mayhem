"""M5 report + experiment guidance builder (M5 Phase 5.7).

Consumes Run/Outcome history, coverage, and the Maniac candidate backlog to
produce a rich, model-only report:
  - a coverage heatmap (rendered ASCII grid),
  - per-cell verdicts with supported-by evidence (run links),
  - the candidate backlog ranked by Maniac score,
  - the guided "what to run next" list (untouched/``UNKNOWN`` cells).

The builder is deterministic and pure: given the same history it always
renders the same report. Assertions in tests are model/string level.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.infra.candidate_gates import CandidateGatePipeline
from mayhem.infra.maniac import SelectionInputs, select_next

if TYPE_CHECKING:
    from mayhem.domain.candidates import ExperimentCandidate
    from mayhem.domain.coverage import CoverageCell, CoverageRecord
    from mayhem.domain.run_outcome import Outcome, RunRecord

# Verdict / heatmap symbols.
_CELL_COVERED = "█"
_CELL_UNKNOWN = "·"


class _PermissiveGate:
    """A gate that passes every candidate (used when no gates are given)."""

    def check(self, candidate: object) -> str | None:
        return None


def _permissive_gates() -> CandidateGatePipeline:
    return CandidateGatePipeline(safety=_PermissiveGate(), feasibility=_PermissiveGate())


@dataclass(frozen=True)
class CellVerdictReport:
    """One cell's verdict plus the runs that support/evidence it."""

    cell: CoverageCell
    covered: bool
    run_ids: tuple[str, ...] = ()
    verdict: str = "UNKNOWN"


@dataclass(frozen=True)
class M5Report:
    """Rendered report over a landscape + recorded history."""

    landscape: tuple[CoverageCell, ...] = ()
    heatmap: str = ""
    cell_verdicts: tuple[CellVerdictReport, ...] = ()
    coverage_fraction: float = 0.0
    next_to_run: tuple[CoverageCell, ...] = ()
    ranked_backlog: tuple[ExperimentCandidate, ...] = ()

    def render_markdown(self) -> str:
        """Render the whole report as a markdown string."""
        lines = [
            "# M5 Campaign Report",
            "",
            "## Coverage",
            "",
            self.heatmap,
            "",
            f"**coverage**: {self.coverage_fraction:.1%} of the landscape covered",
            "",
            "## Per-cell verdicts",
            "",
        ]
        if not self.cell_verdicts:
            lines.append("_no cells recorded_")
        else:
            lines.append("| cell | verdict | evidence runs |")
            lines.append("| --- | --- | --- |")
            for v in self.cell_verdicts:
                ev = ", ".join(v.run_ids) if v.run_ids else "—"
                lines.append(f"| `{v.cell.key}` | {v.verdict} | {ev} |")
        lines.append("")
        lines.append("## What to run next")
        lines.append("")
        if self.next_to_run:
            for cell in self.next_to_run:
                lines.append(f"- `{cell.key}` (UNKNOWN)")
        else:
            lines.append("_no gap remains_")
        lines.append("")
        lines.append("## Candidate backlog (Maniac-ranked)")
        lines.append("")
        if self.ranked_backlog:
            for i, cand in enumerate(self.ranked_backlog, 1):
                lines.append(f"{i}. `{cand.id}` -> {cand.target} [{cand.primary_fault}]")
        else:
            lines.append("_backlog empty_")
        return "\n".join(lines) + "\n"


def _cell_verdict(
    covered: bool,
    run_ids: tuple[str, ...],
    runs: dict[str, RunRecord],
    outcomes: dict[str, Outcome],
) -> str:
    """Derive a verdict for a cell from its evidence (Runs/Outcomes)."""
    if not covered or not run_ids:
        return "UNKNOWN"
    # Use the most recent run's outcome as the cell verdict.
    for run_id in reversed(run_ids):
        outcome = outcomes.get(run_id)
        if outcome is not None and outcome.total_checks > 0:
            return "PASS" if outcome.all_checks_passed else "FAIL"
    # No outcome with checks; fall back to the run verdict if it FAILED.
    for run_id in reversed(run_ids):
        run = runs.get(run_id)
        if run is not None and run.verdict.value == "fail":
            return "FAIL"
    return "PASS"


def render_heatmap(
    landscape: tuple[CoverageCell, ...],
    covered_keys: frozenset[str],
) -> str:
    """Render a compact ASCII heatmap: targets (rows) x faults (cols).

    A cell is marked covered when any landscape cell in that (target, fault)
    group is covered. Unknown cells use ``·``, covered cells use ``█``.
    """
    targets: list[str] = []
    faults: list[str] = []
    seen_cells: dict[tuple[str, str], bool] = {}
    for cell in landscape:
        group = (cell.target, cell.fault_kind)
        covered = cell.key in covered_keys
        if group not in seen_cells or (covered and not seen_cells[group]):
            seen_cells[group] = covered
        if cell.target not in targets:
            targets.append(cell.target)
        if cell.fault_kind not in faults:
            faults.append(cell.fault_kind)

    header = "        " + " ".join(f"{f:<6}" for f in faults)
    lines = [header]
    for t in targets:
        row_parts = []
        for f in faults:
            covered = seen_cells.get((t, f), False)
            row_parts.append(f"{_CELL_COVERED if covered else _CELL_UNKNOWN:<6}")
        lines.append(f"{t:<8} " + " ".join(row_parts))
    lines.append("")
    lines.append(f"legend: {_CELL_COVERED}=covered  {_CELL_UNKNOWN}=unknown")
    return "\n".join(lines)


def build_m5_report(
    *,
    landscape: tuple[CoverageCell, ...],
    covered_records: tuple[CoverageRecord, ...] = (),
    runs: dict[str, RunRecord] | None = None,
    outcomes: dict[str, Outcome] | None = None,
    candidates: tuple[ExperimentCandidate, ...] = (),
    gates: CandidateGatePipeline | None = None,
    seed: int = 0,
    max_runs: int = 50,
) -> M5Report:
    """Assemble the report from recorded history (pure/deterministic)."""
    runs = runs or {}
    outcomes = outcomes or {}

    covered_keys: set[str] = set()
    run_ids_by_cell: dict[str, list[str]] = {}
    for rec in covered_records:
        covered_keys.add(rec.cell.key)
        run_ids_by_cell.setdefault(rec.cell.key, []).append(rec.run_id)

    covered_count = len(covered_keys)
    fraction = covered_count / len(landscape) if landscape else 0.0

    verdicts = tuple(
        CellVerdictReport(
            cell=cell,
            covered=cell.key in covered_keys,
            run_ids=tuple(run_ids_by_cell.get(cell.key, ())),
            verdict=_cell_verdict(
                cell.key in covered_keys,
                tuple(run_ids_by_cell.get(cell.key, ())),
                runs,
                outcomes,
            ),
        )
        for cell in landscape
    )

    unknown = [
        cell
        for cell in landscape
        if cell.key not in covered_keys
    ]

    # Candidate backlog ranked by Maniac (deterministic greedy coverage).
    ranked: tuple[ExperimentCandidate, ...] = ()
    if candidates:
        result = select_next(
            SelectionInputs(
                candidates=candidates,
                covered_keys=frozenset(covered_keys),
                gates=gates if gates is not None else _permissive_gates(),
                max_runs=max_runs,
                coverage_target=max(len(landscape), 1),
                seed=seed,
            )
        )
        ranked = result.selected

    heatmap = render_heatmap(landscape, frozenset(covered_keys))

    return M5Report(
        landscape=landscape,
        heatmap=heatmap,
        cell_verdicts=verdicts,
        coverage_fraction=fraction,
        next_to_run=tuple(unknown),
        ranked_backlog=ranked,
    )
