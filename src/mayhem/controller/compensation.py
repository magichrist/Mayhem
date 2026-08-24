"""Compensation synthesis — undo ops and verify probes decided at plan time.

The planner refuses any fault it cannot compensate for: a plan without a
write-ahead undo contract never leaves the planner. Templates are keyed by
fault prefix and may inspect resolved nodes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.leases import UndoOp, VerifyProbe

if TYPE_CHECKING:
    from collections.abc import Callable

    from mayhem.domain.experiments import PlannedFault
    from mayhem.domain.topology import TopologyNode

NO_UNDO = InvariantViolationError("undo_template_missing", "no compensation template")


def _first_process(nodes: tuple[TopologyNode, ...]):
    for node in nodes:
        if node.kind.value == "process":
            return node
    return None


def _proc_pause_undo(nodes: tuple[TopologyNode, ...]) -> tuple[UndoOp, ...]:
    proc = _first_process(nodes)
    if proc is None:
        raise NO_UNDO
    return (UndoOp(op="signal.cont", args={"pid": str(proc.pid)}),)  # type: ignore[union-attr]


def _proc_pause_verify(nodes: tuple[TopologyNode, ...]) -> tuple[VerifyProbe, ...]:
    proc = _first_process(nodes)
    if proc is None:
        raise NO_UNDO
    pid = str(proc.pid)  # type: ignore[union-attr]
    return (
        VerifyProbe(
            probe="exec",
            args={"cmd": ["ps", "-p", pid], "timeout_s": "5"},
            expect_present=True,
        ),
    )


_NOOP_UNDO: tuple[UndoOp, ...] = (UndoOp(op="noop", args={}),)
_NOOP_VERIFY: tuple[VerifyProbe, ...] = (
    VerifyProbe(probe="exec", args={"cmd": ["true"], "timeout_s": "5"}, expect_present=True),
)


class CompensationTemplate:
    """Undo/verify factory pair for one fault family."""

    def __init__(
        self,
        undo: Callable[[tuple[TopologyNode, ...]], tuple[UndoOp, ...]],
        verify: Callable[[tuple[TopologyNode, ...]], tuple[VerifyProbe, ...]],
    ) -> None:
        self._undo = undo
        self._verify = verify

    def build(
        self, nodes: tuple[TopologyNode, ...]
    ) -> tuple[tuple[UndoOp, ...], tuple[VerifyProbe, ...]]:
        return self._undo(nodes), self._verify(nodes)


_TEMPLATES: dict[str, CompensationTemplate] = {
    "proc.pause": CompensationTemplate(_proc_pause_undo, _proc_pause_verify),
    "fuzz.protocol_abuse": CompensationTemplate(lambda _: _NOOP_UNDO, lambda _: _NOOP_VERIFY),
    "load.spike": CompensationTemplate(lambda _: _NOOP_UNDO, lambda _: _NOOP_VERIFY),
}


def template_for(fault_id: str) -> CompensationTemplate | None:
    return _TEMPLATES.get(fault_id)


def compensated(fault: PlannedFault, nodes: tuple[TopologyNode, ...]) -> PlannedFault:
    """Return ``fault`` with undo/verify filled in; refuse uncompensatable faults."""
    if fault.undo_ops and fault.verify_probes:
        return fault
    tpl = template_for(fault.fault_id)
    if tpl is None:
        msg = (
            f"fault {fault.fault_id!r} has no compensation template; "
            f"planner refuses to emit an uncompensatable injection"
        )
        raise InvariantViolationError("plan_uncompensated_fault", msg)
    undo_ops, verify_probes = tpl.build(nodes)
    return fault.model_copy(update={"undo_ops": undo_ops, "verify_probes": verify_probes})
