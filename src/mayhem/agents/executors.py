"""Fault executors — the only code allowed to perturb the system.

An Executor owns inject + undo for a family of fault ids. Undo must be
idempotent and must never raise: if undo fails, the executor reports DIRTY and
the controller escalates; it does not retry blindly.
"""

from __future__ import annotations

import json
import os
import signal
from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.toolkit.tool_runner import ToolResult, run_tool

if TYPE_CHECKING:
    from mayhem.domain.leases import FaultLease

os_kill = os.kill


@dataclass(frozen=True)
class StepOutcome:
    step: str  # "inject" | "undo"
    ok: bool
    detail: str
    tool_result: ToolResult | None = None


class FaultExecutor:
    """Base class: subclasses declare which prefixes they own."""

    prefixes: tuple[str, ...] = ()

    def supports(self, fault_id: str) -> bool:
        return fault_id.split(".", 1)[0] in self.prefixes

    def capable_faults(self) -> tuple[str, ...]:
        """Fault families handled here; advertised via capabilities.query."""
        return self.prefixes

    def inject(self, lease: FaultLease) -> StepOutcome:  # pragma: no cover
        raise NotImplementedError

    def undo(self, lease: FaultLease) -> StepOutcome:  # pragma: no cover
        raise NotImplementedError


class ProcPauseExecutor(FaultExecutor):
    """proc.pause: SIGSTOP a pid, undo with SIGCONT. Fully reversible."""

    prefixes = ("proc",)

    def __init__(self) -> None:
        self._paused_pids: set[int] = set()

    def _pid_of(self, lease: FaultLease) -> int | None:
        for op in lease.undo_ops:
            raw = op.args.get("pid")
            try:
                return int(raw) if raw is not None else None
            except TypeError, ValueError:
                continue
        return None

    def inject(self, lease: FaultLease) -> StepOutcome:
        pid = self._pid_of(lease)
        if pid is None or pid <= 1:
            return StepOutcome("inject", False, f"lease {lease.id} carries no usable pid")
        try:
            os_kill(pid, signal.SIGSTOP)
        except ProcessLookupError:
            return StepOutcome("inject", False, f"pid {pid} already gone")
        except PermissionError as exc:
            return StepOutcome("inject", False, f"cannot signal pid {pid}: {exc}")
        self._paused_pids.add(pid)
        return StepOutcome("inject", True, f"SIGSTOP delivered to {pid}")

    def undo(self, lease: FaultLease) -> StepOutcome:
        pid = self._pid_of(lease)
        if pid is None:
            return StepOutcome("undo", True, "nothing to resume")
        try:
            os_kill(pid, signal.SIGCONT)
        except ProcessLookupError:
            self._paused_pids.discard(pid)
            return StepOutcome("undo", True, f"pid {pid} already gone; treated as resumed")
        except PermissionError as exc:
            return StepOutcome("undo", False, f"SIGCONT failed for {pid}: {exc}")
        self._paused_pids.discard(pid)
        return StepOutcome("undo", True, f"SIGCONT delivered to {pid}")


class NoopExecutor(FaultExecutor):
    """For fuzz.* and load.* faults whose effect is produced by the harness itself."""

    prefixes = ("fuzz", "load")

    def inject(self, lease: FaultLease) -> StepOutcome:
        return StepOutcome("inject", True, f"noop injection recorded for {lease.fault_id}")

    def undo(self, lease: FaultLease) -> StepOutcome:
        return StepOutcome("undo", True, "noop has nothing to undo")


class ToolExecutor(FaultExecutor):
    """Generic executor driven by argv pairs declared on the lease.

    Expects one undo_op whose args carry ``inject_argv`` / ``undo_argv`` as
    JSON-encoded ``list[str]`` (UndoOp.args is str→str by domain contract).
    Keeps exotic faults declarative without new executor classes.
    """

    prefixes = ("net", "cpu", "mem", "disk", "container", "node", "http", "db")

    def _argv_for(self, lease: FaultLease, key: str) -> list[str]:
        for op in lease.undo_ops:
            raw = op.args.get(key)
            if isinstance(raw, str):
                try:
                    decoded = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if (
                    isinstance(decoded, list)
                    and decoded
                    and all(isinstance(item, str) for item in decoded)
                ):
                    return decoded
        return []

    def inject(self, lease: FaultLease) -> StepOutcome:
        argv = self._argv_for(lease, "inject_argv")
        if not argv:
            return StepOutcome("inject", False, f"lease {lease.id} lacks inject_argv")
        result = run_tool(argv)
        return StepOutcome("inject", result.succeeded, result.stderr[:200], result)

    def undo(self, lease: FaultLease) -> StepOutcome:
        argv = self._argv_for(lease, "undo_argv")
        if not argv:
            return StepOutcome("undo", False, f"lease {lease.id} lacks undo_argv")
        result = run_tool(argv)
        return StepOutcome("undo", result.succeeded, result.stderr[:200], result)


EXECUTORS: tuple[FaultExecutor, ...] = (
    ProcPauseExecutor(),
    NoopExecutor(),
    ToolExecutor(),
)


def executor_for(fault_id: str) -> FaultExecutor | None:
    """First registered executor claiming this prefix wins."""
    for executor in EXECUTORS:
        if executor.supports(fault_id):
            return executor
    return None
