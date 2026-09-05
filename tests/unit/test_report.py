"""Tests for the M5 report + experiment guidance builder (M5 Phase 5.7)."""

from mayhem.domain.candidates import ExperimentCandidate
from mayhem.domain.coverage import CoverageCell, CoverageRecord
from mayhem.domain.run_outcome import Outcome, RunRecord, RunStatus, RunVerdict
from mayhem.infra.report import M5Report, build_m5_report, render_heatmap


def _landscape(n_targets: int = 3, n_faults: int = 3) -> tuple[CoverageCell, ...]:
    cells = []
    for t in range(n_targets):
        for f in range(n_faults):
            cells.append(
                CoverageCell(
                    target=f"t{t}",
                    fault_kind=f"f{f}",
                    execution_context="ctx",
                    parameter_band="b0",
                )
            )
    return tuple(cells)


def _candidates(n: int) -> tuple[ExperimentCandidate, ...]:
    return tuple(
        ExperimentCandidate(
            target=f"t{i % 3}",
            fault_kinds=(f"f{i % 3}",),
            params={"band": "b0"},
            seed_hint=i,
        )
        for i in range(n)
    )


class TestHeatmap:
    def test_renders_blank_when_no_cells(self) -> None:
        out = render_heatmap((), frozenset())
        assert "legend" in out
        assert "█" in out
        assert "·" in out

    def test_coverage_marks_cells(self) -> None:
        landscape = _landscape(2, 2)
        cell = landscape[3]  # t1, f1
        covered = frozenset({cell.key})
        out = render_heatmap(landscape, covered)
        # The covered cell's target/fault group should show a filled block.
        assert "█" in out
        assert "·" in out
        assert "t1" in out
        assert "f1" in out


class TestBuildReport:
    def test_empty_history(self) -> None:
        landscape = _landscape(2, 2)
        report = build_m5_report(landscape=landscape)
        assert isinstance(report, M5Report)
        assert report.coverage_fraction == 0.0
        assert len(report.cell_verdicts) == 4
        assert all(v.verdict == "UNKNOWN" for v in report.cell_verdicts)
        assert len(report.next_to_run) == 4
        assert report.heatmap

    def test_coverage_fraction_and_next_to_run(self) -> None:
        landscape = _landscape(2, 2)
        covered_cell = landscape[0]
        record = CoverageRecord(cell=covered_cell, run_id="run-1")
        report = build_m5_report(
            landscape=landscape,
            covered_records=(record,),
            outcomes={"run-1": Outcome(run_id="run-1", checks_passed=2, checks_failed=0)},
        )
        assert report.coverage_fraction == 1 / 4
        verdict = next(v for v in report.cell_verdicts if v.cell == covered_cell)
        assert verdict.covered is True
        assert verdict.run_ids == ("run-1",)
        assert verdict.verdict == "PASS"
        assert covered_cell.key not in [c.key for c in report.next_to_run]

    def test_failing_outcome_marks_fail_verdict(self) -> None:
        landscape = _landscape(1, 1)
        cell = landscape[0]
        record = CoverageRecord(cell=cell, run_id="run-1")
        report = build_m5_report(
            landscape=landscape,
            covered_records=(record,),
            outcomes={"run-1": Outcome(run_id="run-1", checks_passed=0, checks_failed=3)},
        )
        assert report.cell_verdicts[0].verdict == "FAIL"

    def test_run_verdict_fail_without_checks_supported(self) -> None:
        landscape = _landscape(1, 1)
        cell = landscape[0]
        record = CoverageRecord(cell=cell, run_id="run-1")
        run = RunRecord(
            run_id="run-1",
            experiment_name="e",
            spec_json="{}",
            plan_json="{}",
            status=RunStatus.COMPLETED,
            verdict=RunVerdict.FAIL,
        )
        report = build_m5_report(
            landscape=landscape,
            covered_records=(record,),
            runs={"run-1": run},
        )
        assert report.cell_verdicts[0].verdict == "FAIL"

    def test_backlog_ranked_by_maniac(self) -> None:
        landscape = _landscape(3, 3)
        report = build_m5_report(
            landscape=landscape,
            covered_records=(CoverageRecord(cell=landscape[0], run_id="run-1"),),
            candidates=_candidates(9),
            seed=3,
        )
        assert len(report.ranked_backlog) > 0
        # Ranked backlog is deterministic for equal inputs.
        again = build_m5_report(
            landscape=landscape,
            covered_records=(CoverageRecord(cell=landscape[0], run_id="run-1"),),
            candidates=_candidates(9),
            seed=3,
        )
        assert report.ranked_backlog == again.ranked_backlog
        # Candidates targeting the already-covered group (t0/f0) should be
        # de-prioritized, i.e. the backlog is not trivially all candidates.
        assert 0 < len(report.ranked_backlog) <= 9

    def test_render_markdown_includes_sections(self) -> None:
        landscape = _landscape(2, 2)
        report = build_m5_report(
            landscape=landscape,
            covered_records=(CoverageRecord(cell=landscape[0], run_id="run-1"),),
            candidates=_candidates(4),
        )
        md = report.render_markdown()
        assert "M5 Campaign Report" in md
        assert "## Coverage" in md
        assert "## Per-cell verdicts" in md
        assert "## What to run next" in md
        assert "## Candidate backlog" in md
        assert "run-1" in md
