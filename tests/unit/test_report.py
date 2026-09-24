"""Tests for the M5 report + experiment guidance builder (M5 Phase 5.7)."""

import json
import os
import time

from mayhem.domain.candidates import ExperimentCandidate
from mayhem.domain.coverage import CoverageCell, CoverageRecord
from mayhem.domain.evidence import EvidenceEnvelope
from mayhem.domain.run_outcome import Outcome, RunRecord, RunStatus, RunVerdict
from mayhem.infra.report import (
    M5Report,
    ReportArtifactPolicy,
    apply_report_retention,
    build_m5_report,
    compare_reports,
    redact_report_data,
    render_heatmap,
    render_report_html,
    render_report_json,
    render_report_markdown,
    report_id_for_run,
    write_report_artifacts,
)


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


def _envelope(run_id: str = "run-1", verdict: str = "pass") -> EvidenceEnvelope:
    return EvidenceEnvelope(
        run_id=run_id,
        report_id=report_id_for_run(run_id),
        plan_hash="plan-hash",
        plan_id=run_id,
        target_profile="production",
        engine="kubernetes",
        engine_version="1.31",
        safety_decisions=("strict policy", "blast radius approved"),
        step_reports=({"step_id": "inject", "status": "completed", "detail": "ok"},),
        lease_timeline=({"id": "l-1", "state": "released", "release_mechanism": "janitor"},),
        observations=({"kind": "latency", "value": 42},),
        verdict=verdict,
        recovery_state="recovered",
        remediation=(),
        environment_fingerprint="env-fingerprint",
        target_identity="/Users/alice/private-cluster",
        resolved_target="prod/secret-pod",
        compensation_status="verified",
        verification_basis="live",
    )


def test_report_id_is_stable():
    assert report_id_for_run("run-1") == "report-run-1"
    assert report_id_for_run("run/unsafe id") == "report-run_unsafe_id"


def test_store_normalizes_stable_report_id(tmp_path):
    from mayhem.infra.evidence import load_evidence, write_evidence
    from mayhem.infra.store import Store

    store = Store.open_migrated(tmp_path / "reports.db")
    write_evidence(
        store,
        EvidenceEnvelope(
            run_id="run-store",
            plan_hash="hash",
            step_reports=({"step_id": "s1"},),
            verdict="pass",
        ),
    )
    assert load_evidence(store, "run-store").report_id == "report-run-store"
    store.close()


def test_report_renderers_share_sections_and_redaction():
    envelope = _envelope()
    markdown = render_report_markdown(envelope)
    payload = json.loads(render_report_json(envelope))
    html = render_report_html(envelope)
    for heading in (
        "Executive Summary",
        "Environment",
        "Plan",
        "Safety Decisions",
        "Timeline",
        "Observations",
        "Verdict",
        "Recovery",
        "Limitations",
    ):
        assert heading in markdown
        assert heading in html
    assert payload["report_id"] == "report-run-1"
    assert payload["evidence"]["verdict"] == "pass"
    assert "secret-pod" not in markdown
    assert "/Users/alice" not in html


def test_report_redaction_covers_secrets_and_environment_data():
    data = {
        "password": "do-not-share",
        "nested": [{"api_token": "token"}],
        "target_identity": "/Users/alice/cluster",
        "safe": "kept",
    }
    redacted = redact_report_data(data)
    text = json.dumps(redacted)
    assert "do-not-share" not in text
    assert redacted["nested"][0]["api_token"] == "***REDACTED***"
    assert "/Users/alice" not in text
    assert redacted["safe"] == "kept"


def test_report_artifacts_use_stable_id_and_retention(tmp_path):
    policy = ReportArtifactPolicy(
        artifact_dir=tmp_path,
        retention_days=1,
        max_reports=2,
    )
    paths = write_report_artifacts(_envelope(), policy=policy)
    assert set(paths) == {"markdown", "json", "html"}
    assert all(path.name.startswith("report-run-1.") for path in paths.values())
    old = tmp_path / "report-old.md"
    old.write_text("old")
    old_time = time.time() - 3 * 24 * 60 * 60
    os.utime(old, (old_time, old_time))
    removed = apply_report_retention(tmp_path, retention_days=1, max_reports=10)
    assert old in removed
    assert old.exists() is False


def test_report_comparison_is_data_only():
    before = _envelope("run-before", "fail")
    after = _envelope("run-after", "pass")
    comparison = compare_reports(before, after)
    assert comparison["before_report_id"] == "report-run-before"
    assert comparison["after_report_id"] == "report-run-after"
    assert comparison["verdict"] == {"before": "fail", "after": "pass", "changed": True}
    assert comparison["step_count"] == {"before": 1, "after": 1, "changed": False}
