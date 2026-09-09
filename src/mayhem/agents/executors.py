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
from pathlib import Path
from typing import TYPE_CHECKING

from mayhem.toolkit.tool_runner import ToolError, ToolResult, run_tool

if TYPE_CHECKING:
    from mayhem.domain.leases import FaultLease

os_kill = os.kill


def read_boot_time(pid: int) -> int | None:
    """Read a process's start time (``/proc/<pid>/stat`` field 22).

    Used by the PID-reuse guard (ADR-M2 Phase 2.4 / ADR-M6-2): a PID alone is
    not an identity because the kernel recycles PIDs after exit. The boot time
    in clock ticks since boot disambiguates a recycled PID from the original
    target. Returns ``None`` on platforms without procfs or when the process
    is gone — the guard then degrades to pid-only signalling.
    """
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
        fields = raw.split(")", maxsplit=1)[1].split()
        return int(fields[19]) if len(fields) > 19 else None
    except (OSError, ValueError, IndexError):
        return None


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

    def can_apply(self, lease: FaultLease) -> str | None:
        """Execution-time capability revalidation (ADR-M2 Phase 2.3).

        Runs immediately before the mutation boundary inside ``inject``. Return
        ``None`` when the capability still holds; return a human-readable reason
        when it does not — the executor then records ``failed_to_apply`` and
        never mutates. The default assumes the capability holds; subclasses
        revalidate what they actually need.
        """
        return None

    def inject(self, lease: FaultLease) -> StepOutcome:  # pragma: no cover
        raise NotImplementedError

    def undo(self, lease: FaultLease) -> StepOutcome:  # pragma: no cover
        raise NotImplementedError


class ProcPauseExecutor(FaultExecutor):
    """Process signal faults against a live PID.

    ``proc.pause``   SIGSTOP, fully reversible with SIGCONT.
    ``process.stop`` SIGTERM (graceful shutdown); pid is gone — undo no-ops.
    ``process.kill`` SIGKILL; pid is gone — undo no-ops.

    All three are guarded by the PID-reuse boot_time check (ADR-M2 Phase 2.4).
    """

    prefixes = ("proc", "process")

    def __init__(self) -> None:
        self._paused_pids: set[int] = set()

    def _signal_for(self, fault_id: str) -> int | None:
        """Map a fault id to its signal, or ``None`` for a non-signal fault."""
        family = fault_id.split(".", 1)[0]
        if family == "proc" and fault_id == "proc.pause":
            return signal.SIGSTOP
        if family == "process":
            if fault_id.endswith("kill"):
                return signal.SIGKILL
            if fault_id.endswith("stop"):
                return signal.SIGTERM
        return None

    def can_apply(self, lease: FaultLease) -> str | None:
        """Revalidate the container-mode signal capability (ADR-M2 Phase 2.3).

        A container-addressed ``proc.pause`` needs the engine binary on PATH to
        deliver ``SIGSTOP`` inside the container's pid namespace. If the binary
        vanished between plan time and the mutation boundary, this fault cannot
        be applied — report ``failed_to_apply`` instead of mutating.
        """
        import shutil  # noqa: PLC0415

        _pid, cont, engine, _boot = self._signal_spec(lease)
        if cont is None or engine is None:
            return None  # host-mode signal needs no engine binary
        if shutil.which(engine) is None:
            return f"capability lost: container engine {engine!r} no longer on PATH"
        return None

    def _signal_spec(
        self, lease: FaultLease
    ) -> tuple[int | None, str | None, str | None, int | None]:
        """Return (pid, container, engine, boot_time) carried by the first usable undo op.

        ``pid`` is the process to signal (``.State.Pid`` resolved at execution
        time, valid both on the host and inside the owning container's pid
        namespace). ``boot_time`` is the process start time (``/proc/<pid>/stat``
        field 22) recorded when the target's identity was resolved; it feeds the
        PID-reuse guard so a recycled PID is never signalled. When the op was
        annotated for container mode, ``container`` and ``engine`` (podman/docker)
        are present so the signal can be delivered *inside* the container via
        ``engine exec <cont> kill`` — required when the container runtime lives in
        a detached VM (podman-machine on macOS) where a host ``os.kill`` cannot
        reach the container pid namespace.
        """
        for op in lease.undo_ops:
            raw = op.args.get("pid")
            try:
                pid = int(raw) if raw is not None else None
            except (TypeError, ValueError):
                continue
            if pid is not None:
                boot_raw = op.args.get("boot_time")
                try:
                    boot = int(boot_raw) if boot_raw is not None else None
                except (TypeError, ValueError):
                    boot = None
                return pid, op.args.get("cont"), op.args.get("engine"), boot
        return None, None, None, None

    def inject(self, lease: FaultLease) -> StepOutcome:
        sig = self._signal_for(lease.fault_id)
        if sig is None:
            return StepOutcome("inject", False, f"unplannable signal fault {lease.fault_id}")
        pid, cont, engine, _boot = self._signal_spec(lease)
        # Host mode needs a numeric pid; container/exec mode (ADR-0020) signals
        # via ``<engine> kill --signal <cont>`` and works even when the host PID
        # is a sentinel 0 (VM-contained engines like podman-machine on macOS).
        if cont and engine:
            pid = pid if pid is not None else 0
        elif pid is None or pid <= 1:
            return StepOutcome("inject", False, f"lease {lease.id} carries no usable pid")
        outcome = self._signal(pid, sig, cont, engine, _boot, "inject")
        if outcome.ok:
            self._paused_pids.add(pid)
        return outcome

    def undo(self, lease: FaultLease) -> StepOutcome:
        pid, cont, engine, boot = self._signal_spec(lease)
        if self._signal_for(lease.fault_id) not in (signal.SIGSTOP, signal.SIGCONT):
            # process.stop / process.kill terminate the pid; there is nothing to
            # resume. Report idempotent success so the lease releases cleanly.
            self._paused_pids.discard(pid or 0)
            return StepOutcome("undo", True, "process already terminated; no resume to perform")
        if pid is None:
            return StepOutcome("undo", True, "nothing to resume")
        outcome = self._signal(pid, signal.SIGCONT, cont, engine, boot, "undo")
        self._paused_pids.discard(pid)
        if outcome.ok:
            return StepOutcome("undo", True, f"SIGCONT delivered to {pid}")
        if "already gone" in outcome.detail:
            return StepOutcome("undo", True, f"pid {pid} already gone; treated as resumed")
        return outcome

    def _signal(
        self,
        pid: int,
        sig: int,
        cont: str | None,
        engine: str | None,
        boot: int | None,
        op: str,
    ) -> StepOutcome:
        """Deliver ``sig`` to the target, inside the container when annotated.

        Container mode uses ``engine kill --signal <SIG> <cont>`` so the signal is
        delivered to the container's main process from the runtime side. This is
        namespace-agnostic: unlike ``engine exec ... kill <pid>`` it does not
        require the resolved pid (``.State.Pid``, a VM/host pid) to be addressable
        inside the container's pid namespace. Host mode falls back to ``os.kill``,
        guarded by the PID-reuse check (ADR-M2 Phase 2.4): when a boot time was
        recorded at identity-resolution time, we re-read the current boot time
        and refuse to signal on mismatch (the PID was recycled by an unrelated
        process) — reported as ``target_drift`` rather than mutating the wrong
        process.
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
        drift = read_boot_time(pid)
        if boot is not None and drift is not None and drift != boot:
            return StepOutcome(
                op,
                False,
                f"pid-reuse guard: pid {pid} boot_time {drift} != expected {boot}; "
                "refusing to signal recycled PID",
                tool_result=None,
            )
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

    prefixes = (
        "net",
        "disk",
        "container",
        "node",
        "http",
        "db",
        "dns",
        "tls",
        "clock",
        "dependency",
    )

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


# cpu.throttle applies a container-engine CPU share (``update --cpus``), which
# is argv-pair work; it is not a burner payload, so it must not be claimed by
# the prefix-based PayloadExecutor. Registered faults bypass prefix matching.
_FAULT_EXECUTOR_OVERRIDES: dict[str, FaultExecutor] = {}


def _register_fault_executor(fault_id: str, executor: FaultExecutor) -> None:
    _FAULT_EXECUTOR_OVERRIDES[fault_id] = executor


EXECUTORS: tuple[FaultExecutor, ...] = (
    ProcPauseExecutor(),
    PayloadExecutor(),
    NoopExecutor(),
    ToolExecutor(),
)

_register_fault_executor("cpu.throttle", EXECUTORS[-1])
# fs.read_only remounts the filesystem in-place; it is argv-pair work, not a
# burner payload, so it must bypass the prefix-based PayloadExecutor (prefix
# ``fs``). process.crash_loop drives a container-engine restart cadence, which
# is also argv-pair work; the process-prefix ProcPauseExecutor only handles
# SIGSTOP/SIGTERM/SIGKILL, so it is bypassed the same way.
_register_fault_executor("fs.read_only", EXECUTORS[-1])
_register_fault_executor("process.crash_loop", EXECUTORS[-1])


def executor_for(fault_id: str) -> FaultExecutor | None:
    """Explicit fault-level override wins; otherwise first registered executor
    claiming this fault's prefix."""
    override = _FAULT_EXECUTOR_OVERRIDES.get(fault_id)
    if override is not None:
        return override
    for executor in EXECUTORS:
        if executor.supports(fault_id):
            return executor
    return None
