from __future__ import annotations

from mayhem.controller.executor import StepReport
from mayhem.domain.evidence import ActionOutcome


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
