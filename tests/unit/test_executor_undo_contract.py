"""The undo-must-never-raise contract, enforced at the ToolExecutor boundary.

The module docstring of ``mayhem.agents.executors`` states it plainly: undo is
idempotent and never raises; a failed undo degrades to a falsy ``StepOutcome``
so the engine can mark the lease DIRTY and the controller can escalate. Every
other executor in the module already honours that with a ``try/except
ToolError`` around ``run_tool``; these tests pin the same guarantee for
``ToolExecutor``, whose argv pair is declarative and therefore most exposed to
a tool that has stopped existing (a removed binary, a vanished runtime).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from mayhem.agents import executors as executor_module
from mayhem.agents.executors import StepOutcome, ToolExecutor
from mayhem.domain.leases import FaultLease, LeaseState, UndoOp
from mayhem.toolkit.tool_runner import ToolError, ToolResult

if TYPE_CHECKING:
    import pytest


def _tool_result(*, exit_code: int, stderr: str = "") -> ToolResult:
    return ToolResult(
        argv=("tc", "qdisc", "del"),
        argv_digest="d1",
        env_digest="e1",
        host="h1",
        cwd=None,
        exit_code=exit_code,
        duration_ms=1,
        stdout="",
        stderr=stderr,
        truncated=False,
    )


def _lease() -> FaultLease:
    """A lease carrying both argv pairs, as ToolExecutor expects them."""
    return FaultLease(
        id="l-undo-contract",
        run_id="run",
        fault_id="net.congestion",
        owner_agent="test",
        targets=frozenset({"ctr-api"}),
        undo_ops=(
            UndoOp(
                op="tc.qdisc_del",
                args={
                    "inject_argv": json.dumps(["tc", "qdisc", "add"]),
                    "undo_argv": json.dumps(["tc", "qdisc", "del"]),
                },
            ),
        ),
        state=LeaseState.PENDING,
    )


def _boom(_argv: object, **_kwargs: object) -> ToolResult:
    raise ToolError("tc: command not found")


def test_undo_does_not_raise_when_the_tool_cannot_be_executed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A missing binary degrades to an outcome; it must not escape the executor."""
    monkeypatch.setattr(executor_module, "run_tool", _boom)
    outcome = ToolExecutor().undo(_lease())
    assert isinstance(outcome, StepOutcome)
    assert outcome.step == "undo"


def test_undo_reports_failure_rather_than_silent_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(executor_module, "run_tool", _boom)
    outcome = ToolExecutor().undo(_lease())
    assert outcome.ok is False


def test_undo_is_idempotent_across_repeated_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second undo on an already-dirty lease must fail the same quiet way."""
    monkeypatch.setattr(executor_module, "run_tool", _boom)
    executor = ToolExecutor()
    lease = _lease()
    first = executor.undo(lease)
    second = executor.undo(lease)
    assert (first.ok, second.ok) == (False, False)
    assert first.detail == second.detail


def test_failed_undo_records_a_detail_for_the_dirty_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DIRTY leases carry escalation notes — the detail must not be empty."""
    monkeypatch.setattr(executor_module, "run_tool", _boom)
    detail = ToolExecutor().undo(_lease()).detail
    assert detail
    assert "tc: command not found" in detail


def test_failed_tool_exit_is_reported_with_its_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-zero exit is a failed undo too, and its stderr is the evidence."""
    monkeypatch.setattr(
        executor_module,
        "run_tool",
        lambda _argv, **_kwargs: _tool_result(exit_code=2, stderr="qdisc not found"),
    )
    outcome = ToolExecutor().undo(_lease())
    assert outcome.ok is False
    assert "qdisc not found" in outcome.detail


def test_successful_undo_reports_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    """Control: the guard must not swallow a genuinely successful undo."""
    assert ToolExecutor().can_apply(_lease()) is None
    result = _tool_result(exit_code=0)
    monkeypatch.setattr(executor_module, "run_tool", lambda _argv, **_kw: result)
    outcome = ToolExecutor().undo(_lease())
    assert outcome.ok is True
    assert outcome.tool_result is result


def test_inject_happy_path_still_reports_ok(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control on the inject side: the change must not alter inject behaviour."""
    monkeypatch.setattr(
        executor_module, "run_tool", lambda _argv, **_kwargs: _tool_result(exit_code=0)
    )
    outcome = ToolExecutor().inject(_lease())
    assert outcome.step == "inject"
    assert outcome.ok is True


def test_inject_without_argv_is_still_a_falsy_outcome() -> None:
    """Control: the pre-existing missing-argv guard is untouched."""
    lease = FaultLease(
        id="l-no-argv",
        run_id="run",
        fault_id="net.congestion",
        owner_agent="test",
        targets=frozenset({"ctr-api"}),
        undo_ops=(),
        state=LeaseState.PENDING,
    )
    outcome = ToolExecutor().undo(lease)
    assert outcome.ok is False
    assert "lacks undo_argv" in outcome.detail
