"""Unit tests for the agent-side watchdog (ADR-0005 §3)."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from mayhem.agents.executors import ProcPauseExecutor, StepOutcome
from mayhem.agents.watchdog import AgentWatchdog


@dataclass
class FakeLease:
    id: str
    pid: int


class UndoTrackingExecutor(ProcPauseExecutor):
    def __init__(self, *, undo_ok: bool = True, raise_on_undo: bool = False) -> None:
        super().__init__()
        self.undo_calls: list[object] = []
        self._undo_ok = undo_ok
        self._raise_on_undo = raise_on_undo

    def undo(self, lease):  # type: ignore[no-untyped-def]
        self.undo_calls.append(lease)
        if self._raise_on_undo:
            raise RuntimeError("undo exploded")
        return StepOutcome("undo", self._undo_ok, f"undone={lease.id}")


@pytest.mark.asyncio
async def test_expired_lease_is_compensated_locally() -> None:
    executor = UndoTrackingExecutor()
    lease = FakeLease(id="l-1", pid=4242)
    wd = AgentWatchdog()

    wd.register(
        lease_id="l-1",
        lease=lease,
        executor=executor,
        ttl_seconds=0.0,
        now_epoch_s=100.0,
    )
    expired = await wd.sweep(now_epoch_s=100.5)

    assert expired == ["l-1"]
    assert [x.id for x in executor.undo_calls] == ["l-1"]
    assert wd.active_count() == 0


@pytest.mark.asyncio
async def test_live_lease_is_left_alone() -> None:
    executor = UndoTrackingExecutor()
    wd = AgentWatchdog()
    wd.clock = lambda: 101.0
    wd.register(
        lease_id="l-1",
        lease=FakeLease(id="l-1", pid=7),
        executor=executor,
        ttl_seconds=60.0,
        now_epoch_s=100.0,
    )

    expired = await wd.sweep(now_epoch_s=101.0)

    assert expired == []
    assert executor.undo_calls == []
    snap = wd.snapshot()
    assert snap[0]["state"] == "active"
    assert 58 <= snap[0]["expires_in_s"] <= 59


@pytest.mark.asyncio
async def test_failed_undo_marks_dirty_not_retried() -> None:
    executor = UndoTrackingExecutor(undo_ok=False)
    wd = AgentWatchdog()
    wd.register(
        lease_id="l-x",
        lease=FakeLease(id="l-x", pid=9),
        executor=executor,
        ttl_seconds=0.0,
        now_epoch_s=0.0,
    )

    await wd.sweep(now_epoch_s=1.0)

    assert wd.final_state("l-x") == "dirty"
    assert len(executor.undo_calls) == 1  # no blind retries (ADR-0005)


@pytest.mark.asyncio
async def test_raising_undo_is_survived_and_marked_dirty() -> None:
    executor = UndoTrackingExecutor(raise_on_undo=True)
    wd = AgentWatchdog()
    wd.register(
        lease_id="l-y",
        lease=FakeLease(id="l-y", pid=11),
        executor=executor,
        ttl_seconds=0.0,
        now_epoch_s=0.0,
    )

    expired = await wd.sweep(now_epoch_s=1.0)

    assert expired == ["l-y"]
    assert executor.undo_calls and wd.active_count() == 0
    assert wd.final_state("l-y") == "dirty"
