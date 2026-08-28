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

from mayhem.toolkit.tool_runner import ToolError, ToolResult, run_tool

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

    def _signal_spec(self, lease: FaultLease) -> tuple[int | None, str | None, str | None]:
        """Return (pid, container, engine) carried by the first usable undo op.

        ``pid`` is the process to signal (``.State.Pid`` resolved at execution
        time, valid both on the host and inside the owning container's pid
        namespace). When the op was annotated for container mode, ``container``
        and ``engine`` (podman/docker) are present so the signal can be delivered
        *inside* the container via ``engine exec <cont> kill`` — required when
        the container runtime lives in a detached VM (podman-machine on macOS)
        where a host ``os.kill`` cannot reach the container pid namespace.
        """
        for op in lease.undo_ops:
            raw = op.args.get("pid")
            try:
                pid = int(raw) if raw is not None else None
            except (TypeError, ValueError):
                continue
            if pid is not None:
                return pid, op.args.get("cont"), op.args.get("engine")
        return None, None, None

    def inject(self, lease: FaultLease) -> StepOutcome:
        pid, cont, engine = self._signal_spec(lease)
        if pid is None or pid <= 1:
            return StepOutcome("inject", False, f"lease {lease.id} carries no usable pid")
        outcome = self._signal(pid, signal.SIGSTOP, cont, engine, "inject")
        if outcome.ok:
            self._paused_pids.add(pid)
        return outcome

    def undo(self, lease: FaultLease) -> StepOutcome:
        pid, cont, engine = self._signal_spec(lease)
        if pid is None:
            return StepOutcome("undo", True, "nothing to resume")
        outcome = self._signal(pid, signal.SIGCONT, cont, engine, "undo")
        self._paused_pids.discard(pid)
        if outcome.ok:
            return StepOutcome("undo", True, f"SIGCONT delivered to {pid}")
        if "already gone" in outcome.detail:
            return StepOutcome("undo", True, f"pid {pid} already gone; treated as resumed")
        return outcome

    def _signal(
        self, pid: int, sig: int, cont: str | None, engine: str | None, op: str
    ) -> StepOutcome:
        """Deliver ``sig`` to the target, inside the container when annotated.

        Container mode uses ``engine kill --signal <SIG> <cont>`` so the signal is
        delivered to the container's main process from the runtime side. This is
        namespace-agnostic: unlike ``engine exec ... kill <pid>`` it does not
        require the resolved pid (``.State.Pid``, a VM/host pid) to be addressable
        inside the container's pid namespace. Host mode falls back to ``os.kill``.
        """
        if cont and engine:
            signame = signal.Signals(sig).name  # e.g. SIGSTOP / SIGCONT
            argv = [engine, "kill", "--signal", signame, cont]
            try:
                result = run_tool(argv, timeout_s=30)
                if result.succeeded:
                    return StepOutcome(op, True, f"{signame} sent to {cont}")
                return StepOutcome(
                    op,
                    False,
                    f"{signame} failed for {cont}: {result.stderr.strip()[:120]}",
                )
            except ToolError as exc:
                return StepOutcome(op, False, f"engine kill failed for {cont}: {exc}")
        try:
            os_kill(pid, sig)
        except ProcessLookupError:
            return StepOutcome(op, False, f"pid {pid} already gone")
        except PermissionError as exc:
            return StepOutcome(op, False, f"cannot signal pid {pid}: {exc}")
        return StepOutcome(op, True, f"signal delivered to {pid}")


class PayloadExecutor(FaultExecutor):
    """mem/cpu/fs/fd/load/fuzz: real in-container effects via ``engine exec -d``.

    Inject launches ``<engine> exec -d <cont> python -c <payload>``: a detached
    process inside the target container's pid + network namespaces that produces
    the fault's observable effect (memory balloon, CPU spin, fs fill, fd
    exhaustion, request flood, malformed HTTP abuse). Undo runs a small kill
    payload against the same container that SIGKILLs the recorded pid and
    removes the payload's marker files, so the effect is fully reversible and
    idempotent. Runs are driven entirely by the lease's ``payload.undo`` op,
    whose ``pid`` placeholder resolves to ``cont``/``engine`` at execution time.
    """

    prefixes = ("mem", "cpu", "fs", "fd", "load", "fuzz")

    _KILL = (
        "import os, signal, glob, sys\n"
        "mp = sys.argv[1]\n"
        "try:\n"
        "    p = int(open(mp).read().strip())\n"
        "    os.kill(p, signal.SIGKILL)\n"
        "except Exception:\n"
        "    pass\n"
        "for f in glob.glob(mp + '.*') + [mp]:\n"
        "    try:\n"
        "        os.unlink(f)\n"
        "    except OSError:\n"
        "        pass\n"
    )

    def _spec(self, lease: FaultLease) -> tuple[str, str, str, str] | None:
        """Return ``(engine, cont, payload, marker)`` from the undo op."""
        for op in lease.undo_ops:
            engine, cont = op.args.get("engine"), op.args.get("cont")
            payload, marker = op.args.get("payload"), op.args.get("marker")
            if engine and cont and payload and marker:
                return str(engine), str(cont), str(payload), str(marker)
        return None

    def inject(self, lease: FaultLease) -> StepOutcome:
        spec = self._spec(lease)
        if spec is None:
            return StepOutcome(
                "inject", False, f"lease {lease.id} lacks payload spec (no cont/engine)"
            )
        engine, cont, payload, _marker = spec
        argv = [engine, "exec", "-d", cont, "python", "-c", payload]
        try:
            result = run_tool(argv, timeout_s=30)
        except ToolError as exc:
            return StepOutcome("inject", False, f"payload launch failed: {exc}")
        detail = f"{lease.fault_id} payload launched in {cont}"
        if result.stderr:
            detail += f": {result.stderr.strip()[:120]}"
        return StepOutcome("inject", result.succeeded, detail, result)

    def undo(self, lease: FaultLease) -> StepOutcome:
        spec = self._spec(lease)
        if spec is None:
            return StepOutcome(
                "undo", False, f"lease {lease.id} lacks payload spec (no cont/engine)"
            )
        engine, cont, _payload, marker = spec
        argv = [engine, "exec", cont, "python", "-c", self._KILL, marker]
        try:
            result = run_tool(argv, timeout_s=30)
        except ToolError as exc:
            return StepOutcome("undo", False, f"payload cleanup failed: {exc}")
        return StepOutcome(
            "undo", result.succeeded, f"payload for {lease.fault_id} terminated", result
        )


class NoopExecutor(FaultExecutor):
    """Step-outcome-only executor for placeholder steps with no effect.

    Kept for emitters/callers that produce steps without real faults; real
    payload families are handled by :class:`PayloadExecutor`.
    """

    prefixes: tuple[str, ...] = ()

    def inject(self, lease: FaultLease) -> StepOutcome:
        return StepOutcome("inject", True, f"no-op injection recorded for {lease.fault_id}")

    def undo(self, lease: FaultLease) -> StepOutcome:
        return StepOutcome("undo", True, "noop has nothing to undo")


class ToolExecutor(FaultExecutor):
    """Generic executor driven by argv pairs declared on the lease.

    Expects one undo_op whose args carry ``inject_argv`` / ``undo_argv`` as
    JSON-encoded ``list[str]`` (UndoOp.args is str→str by domain contract).
    Keeps exotic faults declarative without new executor classes.
    """

    prefixes = ("net", "disk", "container", "node", "http", "db", "dns", "clock")

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
                    # Container-addressed faults embed @engine/@cont tokens that the
                    # live substitute resolves (ADR-0020); leave them untouched when
                    # the op carries no live address so a stale plan fails loudly.
                    engine = op.args.get("engine")
                    cont = op.args.get("cont")
                    if engine and cont:
                        return [
                            item.replace("@engine", engine).replace("@cont", cont)
                            for item in decoded
                        ]
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
    PayloadExecutor(),
    NoopExecutor(),
    ToolExecutor(),
)


def executor_for(fault_id: str) -> FaultExecutor | None:
    """First registered executor claiming this prefix wins."""
    for executor in EXECUTORS:
        if executor.supports(fault_id):
            return executor
    return None
