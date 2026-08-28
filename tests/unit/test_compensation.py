"""Payload compensation templates (ADR-0020): undo ops + injected source."""

import re

from mayhem.controller.compensation import _payload_source
from mayhem.domain.experiments import PlannedFault


def _mem_fault(amount: float = 0.0, percent: float = 60.0) -> PlannedFault:
    params: dict[str, object] = {"amount": amount} if amount > 0 else {"percent": percent}
    return PlannedFault(fault_id="mem.exhaust", targets=(), params=params, duration=10.0)


def test_mem_exhaust_amount_binding() -> None:
    source = _payload_source(_mem_fault(amount=256 * 1024 * 1024), "/tmp/mayhem.t.pid")
    assert "amount = 268435456" in source
    assert re.search(r"goal = amount if amount > 0", source)
    assert "min(goal, lim * 95 // 100)" in source


def test_mem_exhaust_percent_fallback() -> None:
    source = _payload_source(_mem_fault(percent=40), "/tmp/mayhem.t.pid")
    assert re.search(r"^amount = 0$", source, re.M)
    assert "percent = 40" in source
    assert re.search(r"goal = amount if amount > 0", source)


def test_payload_marks_pid_before_alloc() -> None:
    source = _payload_source(_mem_fault(amount=1024 * 1024), "/tmp/mayhem.t.pid")
    assert "open('/tmp/mayhem.t.pid', 'w').write(str(os.getpid()))" in source
    assert "chunks.append(bytearray(4 * 2 ** 20))" in source
