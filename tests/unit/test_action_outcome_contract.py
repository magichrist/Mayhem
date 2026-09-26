from __future__ import annotations

from mayhem.controller.executor import StepReport
from mayhem.domain.evidence import ActionOutcome, EvidenceEnvelope


def test_action_outcomes_visible_in_text_and_json() -> None:
    from mayhem.cli.render import render_evidence_human

    envelope = EvidenceEnvelope(
        run_id="r1",
        plan_hash="hash",
        engine="kubernetes",
        verdict="error",
        action_outcomes=("acknowledged_no_backend",),
    )
    text = render_evidence_human(envelope)
    assert "action outcomes: acknowledged_no_backend" in text
    assert envelope.model_dump(mode="json")["action_outcomes"] == ["acknowledged_no_backend"]


def test_no_backend_action_is_not_unqualified_success() -> None:
    report = StepReport(
        "step-1",
        False,
        "start_load has no execution backend; action acknowledged without effect",
        status="acknowledged_no_backend",
    )
    assert report.ok is False
    assert report.outcome is ActionOutcome.ACKNOWLEDGED_NO_BACKEND
    assert report.status == "acknowledged_no_backend"


def test_step_report_maps_core_outcomes() -> None:
    assert StepReport("a", True, "ok").outcome is ActionOutcome.APPLIED
    assert StepReport("a", True, "ok", status="verified").outcome is ActionOutcome.VERIFIED
    assert StepReport("a", True, "ok", status="compensated").outcome is ActionOutcome.COMPENSATED
    assert StepReport("a", False, "no", status="failed_to_apply").outcome is ActionOutcome.REFUSED
    assert StepReport("a", False, "no").outcome is ActionOutcome.FAILED
