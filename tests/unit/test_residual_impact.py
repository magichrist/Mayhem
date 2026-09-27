"""v0.9.0 expansion task 16: residual impact."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from mayhem.domain.residual_impact import (
    CLEAN,
    PARTIAL,
    TOLERATED,
    UNAVAILABLE,
    VIOLATION,
    ImpactAcceptance,
    ImpactSnapshot,
    assess_residual_impact,
)


def _snap(**values) -> ImpactSnapshot:
    return ImpactSnapshot(label="snap", values=dict(values))


# ── clean recovery ───────────────────────────────────────────────────────────
def test_identical_snapshots_are_clean() -> None:
    assessment = assess_residual_impact(_snap(cpu=0.5, rps=100.0), _snap(cpu=0.5, rps=100.0))
    assert assessment.status == CLEAN
    assert assessment.clean is True
    assert assessment.violations == ()
    assert assessment.signals_compared == 2


def test_tolerance_absorbs_small_drift() -> None:
    assessment = assess_residual_impact(_snap(cpu=0.50), _snap(cpu=0.505), tolerance=0.01)
    assert assessment.status == CLEAN
    assert assessment.violations == ()


def test_drift_beyond_tolerance_is_a_violation() -> None:
    assessment = assess_residual_impact(_snap(cpu=0.5), _snap(cpu=0.9), tolerance=0.01)
    assert assessment.status == VIOLATION
    violation = assessment.violations[0]
    assert violation.signal == "cpu"
    assert violation.delta == pytest.approx(0.4)
    assert violation.tolerated is False


# ── partial recovery ─────────────────────────────────────────────────────────
def test_partial_recovery_is_partial() -> None:
    assessment = assess_residual_impact(_snap(cpu=0.5, rps=100.0), _snap(cpu=0.5, rps=120.0))
    assert assessment.status == VIOLATION
    assert [v.signal for v in assessment.violations] == ["rps"]


def test_some_accepted_and_some_not_is_partial() -> None:
    assessment = assess_residual_impact(
        _snap(cpu=0.5, rps=100.0),
        _snap(cpu=0.9, rps=120.0),
        acceptances=(
            ImpactAcceptance(
                signal="rps", accepted_by="sre@example", reason="expected during scale-out"
            ),
        ),
    )
    assert assessment.status == PARTIAL
    assert len(assessment.untolerated) == 1
    assert assessment.untolerated[0].signal == "cpu"


def test_fully_accepted_residual_is_tolerated() -> None:
    assessment = assess_residual_impact(
        _snap(rps=100.0),
        _snap(rps=120.0),
        acceptances=(ImpactAcceptance(signal="rps", accepted_by="sre@example", reason="accepted"),),
    )
    assert assessment.status == TOLERATED
    assert assessment.untolerated == ()
    assert assessment.violations[0].acceptance is not None
    assert assessment.violations[0].acceptance.accepted_by == "sre@example"


# ── unavailable source ───────────────────────────────────────────────────────
def test_unavailable_before_snapshot_is_not_clean() -> None:
    assessment = assess_residual_impact(
        ImpactSnapshot.unavailable("before", "topology provider timed out"),
        _snap(cpu=0.5),
    )
    assert assessment.status == UNAVAILABLE
    assert assessment.clean is False


def test_unavailable_after_snapshot_is_not_clean() -> None:
    assessment = assess_residual_impact(
        _snap(cpu=0.5), ImpactSnapshot.unavailable("after", "metrics endpoint down")
    )
    assert assessment.status == UNAVAILABLE
    assert assessment.signals_compared == 0


# ── acceptance requirements ──────────────────────────────────────────────────
def test_acceptance_requires_a_named_human_and_a_reason() -> None:
    acceptance = ImpactAcceptance(
        signal="rps", accepted_by="sre", reason="scale-out", accepted_at="t0"
    )
    payload = acceptance.to_dict()
    assert payload["accepted_by"] == "sre"
    assert payload["reason"] == "scale-out"


def test_no_silent_tolerance_without_acceptance_metadata() -> None:
    assessment = assess_residual_impact(_snap(rps=100.0), _snap(rps=101.0))
    assert assessment.status == VIOLATION
    assert assessment.violations[0].tolerated is False
    assert assessment.violations[0].acceptance is None


# ── serialisation ────────────────────────────────────────────────────────────
def test_assessment_dict_is_json_serializable() -> None:
    assessment = assess_residual_impact(_snap(cpu=0.5), _snap(cpu=0.9))
    payload = assessment.to_dict()
    assert json.loads(json.dumps(payload))["status"] == VIOLATION
    assert payload["untolerated_count"] == 1
    assert payload["before"]["values"] == {"cpu": 0.5}


def test_assessment_is_deterministic() -> None:
    before, after = _snap(a=1.0, b=2.0), _snap(a=1.5, b=2.0)
    assert (
        assess_residual_impact(before, after).to_dict()
        == assess_residual_impact(before, after).to_dict()
    )


def test_signals_present_in_only_one_snapshot_are_not_compared() -> None:
    assessment = assess_residual_impact(
        _snap(a=1.0), ImpactSnapshot(label="after", values={"b": 2.0})
    )
    assert assessment.signals_compared == 0
    assert assessment.status == CLEAN


# ── CLI ──────────────────────────────────────────────────────────────────────
def _ctx(db):
    from mayhem.cli.context import CliContext

    return CliContext(db=str(db))


def test_cli_residual_reports_violations(tmp_path) -> None:
    from mayhem.cli.inspect import inspect_residual
    from mayhem.infra.store import Store

    db = tmp_path / "r.db"
    Store.open_migrated(db).close()
    result = CliRunner().invoke(
        inspect_residual,
        ["run-1", "--expect", "cpu=0.5", "--observed", "cpu=0.9", "--json"],
        obj=_ctx(db),
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["status"] == VIOLATION
    assert payload["untolerated_count"] == 1


def test_cli_residual_reports_accepted_violations(tmp_path) -> None:
    from mayhem.cli.inspect import inspect_residual
    from mayhem.infra.store import Store

    db = tmp_path / "r.db"
    Store.open_migrated(db).close()
    result = CliRunner().invoke(
        inspect_residual,
        [
            "run-1",
            "--expect",
            "rps=100",
            "--observed",
            "rps=120",
            "--accept",
            "rps=sre:accepted scale-out",
        ],
        obj=_ctx(db),
    )
    assert result.exit_code == 0, result.output
    assert "tolerated" in result.output
    assert "accepted by sre" in result.output


def test_cli_residual_rejects_malformed_input(tmp_path) -> None:
    from mayhem.cli.inspect import inspect_residual
    from mayhem.infra.store import Store

    db = tmp_path / "r.db"
    Store.open_migrated(db).close()
    runner = CliRunner()
    assert runner.invoke(inspect_residual, ["r", "--expect", "cpu"], obj=_ctx(db)).exit_code == 2
    assert (
        runner.invoke(inspect_residual, ["r", "--expect", "cpu=abc"], obj=_ctx(db)).exit_code == 2
    )
    assert (
        runner.invoke(
            inspect_residual,
            ["r", "--expect", "cpu=1", "--observed", "cpu=2", "--accept", "cpu=sre"],
            obj=_ctx(db),
        ).exit_code
        == 2
    )


def test_cli_residual_reads_the_evidence_envelope(tmp_path) -> None:
    from mayhem.cli.inspect import inspect_residual
    from mayhem.infra.evidence import build_evidence, write_evidence
    from mayhem.infra.store import Store

    db = tmp_path / "r.db"
    store = Store.open_migrated(db)
    try:
        write_evidence(
            store,
            build_evidence(
                run_id="run-1",
                plan=None,
                target_profile=None,
                engine="kubernetes",
                safety_decisions=(),
                step_reports=(),
                lease_timeline=(),
                observations=({"metric": "cpu", "value": 0.5},),
                verdict="pass",
                recovery_state="none",
                remediation=(),
            ),
        )
    finally:
        store.close()
    result = CliRunner().invoke(
        inspect_residual, ["run-1", "--from-observations", "--json"], obj=_ctx(db)
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["status"] == CLEAN


def test_cli_residual_without_evidence_exits_nonzero(tmp_path) -> None:
    from mayhem.cli.inspect import inspect_residual
    from mayhem.infra.store import Store

    db = tmp_path / "r.db"
    Store.open_migrated(db).close()
    result = CliRunner().invoke(inspect_residual, ["missing", "--from-observations"], obj=_ctx(db))
    assert result.exit_code == 1


def test_residual_appears_in_human_evidence_output() -> None:
    from mayhem.cli.render import render_evidence_human
    from mayhem.infra.evidence import build_evidence

    envelope = build_evidence(
        run_id="r1",
        plan=None,
        target_profile=None,
        engine="kubernetes",
        safety_decisions=(),
        step_reports=(),
        lease_timeline=(),
        observations=(),
        verdict="pass",
        recovery_state="none",
        remediation=(),
        residual_impact=assess_residual_impact(_snap(cpu=0.5), _snap(cpu=0.9)).to_dict(),
    )
    text = render_evidence_human(envelope)
    assert "residual impact: violation" in text
    assert "1 untolerated" in text
