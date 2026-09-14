"""Fault executors — the only code allowed to perturb the system.

An Executor owns inject + undo for a family of fault ids. Undo must be
idempotent and must never raise: if undo fails, the executor reports DIRTY and
the controller escalates; it does not retry blindly.
"""

from __future__ import annotations

import functools
import json
import os
import signal
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.resolution import ResolvedNodeTarget, ResolvedPodTarget
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


class K8sExecutor(FaultExecutor):
    """Kubernetes pod-level executor (ADR-M7-1, k-plan-3 SP-3.3).

    The execution-time resolver (:mod:`mayhem.agents.k8s_resolve`) pins the
    exact pod + container into ``lease.resolved_target`` (migration 0017) at
    lease formation; this executor delivers the mutation through that pinned
    target via ``kubectl exec``.

    Executable this milestone — the signal family against the container's
    primary process (PID 1), guarded by the ``/proc/1`` start-time check read
    at resolution time (the k8s analogue of the docker ``boot_time`` PID-reuse
    guard, ADR-M2 Phase 2.4):

    * ``proc.pause``   → ``kill -STOP 1``, undo via ``kill -CONT 1``
    * ``process.stop`` → ``kill -TERM 1`` (no live undo; graceful exit)
    * ``process.kill`` → ``kill -KILL 1`` (no live undo)

    Everything else small-bit family stays refused with the stable
    ``k8s.unsupported`` code: payload faults (mem/cpu/fs/fd/load/fuzz) need
    their params carried through the lease, which is the SP-3.4 compensation
    contract, and pod-lifecycle faults (``k8s.pod.failure``) park in k-plan-4.
    """

    prefixes = ("k8s", "proc", "process", "mem", "cpu", "fs", "fd", "load", "fuzz")

    _SIGNAL_INJECT = {
        "proc.pause": "STOP",
        "process.stop": "TERM",
        "process.kill": "KILL",
    }
    # Each signal family's undo: ("CONT",) means a live CONT; ("",) is a no-op.
    _SIGNAL_UNDO_COMMAND = {
        "proc.pause": "CONT",
        "process.stop": "",
        "process.kill": "",
    }

    def supports(self, fault_id: str) -> bool:
        if fault_id.startswith("k8s."):
            return True
        return _is_k8s_applicable(fault_id)

    def capable_faults(self) -> tuple[str, ...]:
        return ("k8s.pod.failure", *sorted(self._SIGNAL_INJECT))

    def _target_or_none(self, lease: FaultLease) -> ResolvedPodTarget | None:
        return lease.resolved_target

    def _unsupported_reason(self, fault_id: str) -> str:
        return k8s_unsupported_reason(fault_id)

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id not in self._SIGNAL_INJECT:
            return self._unsupported_reason(lease.fault_id)
        if lease.resolved_target is None:
            return "k8s.unsupported: no resolved pod target on the lease"
        return None

    def inject(self, lease: FaultLease) -> StepOutcome:
        if lease.fault_id not in self._SIGNAL_INJECT or lease.resolved_target is None:
            return StepOutcome("inject", False, self._unsupported_reason(lease.fault_id))
        signame = self._SIGNAL_INJECT[lease.fault_id]
        argv = (*lease.resolved_target.exec_argv, "kill", f"-{signame}", "1")
        result = run_tool(argv)
        if result.exit_code != 0:
            return StepOutcome(
                "inject",
                False,
                f"kubectl exec failed (rc={result.exit_code}): {result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "inject",
            True,
            f"{lease.fault_id} delivered via kubectl exec: {signame} on primary pid 1",
            tool_result=result,
        )

    def undo(self, lease: FaultLease) -> StepOutcome:
        command = self._SIGNAL_UNDO_COMMAND.get(lease.fault_id, "")
        if not command or lease.resolved_target is None:
            return StepOutcome("undo", True, f"{lease.fault_id}: nothing live to undo")
        argv = (*lease.resolved_target.exec_argv, "kill", f"-{command}", "1")
        result = run_tool(argv)
        if result.exit_code != 0:
            return StepOutcome(
                "undo",
                False,
                f"kubectl exec CONT failed (rc={result.exit_code}): "
                f"{result.stdout.strip()} — DIRTY",
                tool_result=result,
            )
        return StepOutcome(
            "undo",
            True,
            f"CONT delivered on primary pid 1 (pod {lease.resolved_target.pod})",
            tool_result=result,
        )


_K8S_EXECUTOR = K8sExecutor()


# ── k8s runtime contract (k-plan-3 §3.3/§3.4, k-plan-4 §4.4) ────────────────
# The run engine shares these with the K8sExecutor: which fault ids the exec
# driver admits this milestone, and how their undo behaves.
K8S_SIGNAL_FAULTS: frozenset[str] = frozenset(K8sExecutor._SIGNAL_INJECT)
K8S_SIGNAL_INJECT_SIGNAL: dict[str, str] = dict(K8sExecutor._SIGNAL_INJECT)
K8S_UNDO_COMMAND: dict[str, str] = dict(K8sExecutor._SIGNAL_UNDO_COMMAND)


def _memory_bytes_from_spec(spec: str | None, default_mib: int = 64) -> int:
    """Best-effort parse of a Kubernetes memory string to bytes (k-plan-4 §4.4)."""
    if not spec:
        return default_mib * 1048576
    spec = spec.strip().lower()
    try:
        if spec.endswith("gi"):
            return int(float(spec[:-2]) * 1073741824)
        if spec.endswith("g"):
            return int(float(spec[:-1]) * 1000000000)
        if spec.endswith("mi"):
            return int(float(spec[:-2]) * 1048576)
        if spec.endswith("m"):
            return int(float(spec[:-1]) * 1000000)
        if spec.endswith("k"):
            return int(float(spec[:-1]) * 1000)
        return int(float(spec))
    except (ValueError, TypeError):
        return default_mib * 1048576


def _lease_fault_params(lease: FaultLease) -> dict[str, object]:
    """The fault params carried on the lease's write-ahead contract.

    k-plan-4 §4.4 carries params through the mutation spec (``args["params"]``),
    matching the k-plan-3 SP-3.4 evidence shape — the domain model has no
    free-form params bag on the lease.  ``UndoOp.args`` is ``dict[str, str]``,
    so the bag is JSON-encoded on the spec and decoded here.
    """
    import json as _json  # noqa: PLC0415
    for op in lease.undo_ops or ():
        params = op.args.get("params")
        if isinstance(params, dict):
            return dict(params)
        if isinstance(params, str):
            try:
                decoded = _json.loads(params)
            except (ValueError, TypeError):
                continue
            if isinstance(decoded, dict):
                return dict(decoded)
    return {}


class K8sPodKillExecutor(K8sExecutor):
    """Execute and undo ``k8s.pod_kill`` (SP-4.4, k-plan-4 §4.4)."""

    prefixes = ("k8s.pod_kill",)

    def _grace_period(self, lease: FaultLease) -> str:
        params = _lease_fault_params(lease)
        gp = params.get("grace_period") or params.get("timeout")
        return str(int(gp)) if gp else "30"

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id != "k8s.pod_kill":
            return None
        if lease.resolved_target is None:
            return "k8s.pod_kill: no resolved pod target on the lease"
        return None

    def inject(self, lease: FaultLease) -> StepOutcome:
        t = lease.resolved_target
        if t is None:
            return StepOutcome("inject", False, "k8s.pod_kill: no resolved target")
        argv: tuple[str, ...] = (
            "kubectl", "delete", "pod", t.pod, "-n", t.namespace,
            "--grace-period", self._grace_period(lease),
        )
        result = run_tool(argv, timeout_s=60)
        if result.exit_code != 0:
            return StepOutcome(
                "inject", False,
                f"kubectl delete pod failed (rc={result.exit_code}): "
                f"{result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "inject", True,
            f"k8s.pod_kill: deleted pod {t.pod} in namespace {t.namespace}",
            tool_result=result,
        )

    def undo(self, lease: FaultLease) -> StepOutcome:
        return StepOutcome("undo", True, "k8s.pod_kill: no live undo for delete")


class K8sPodEvictExecutor(K8sExecutor):
    """Execute and undo ``k8s.pod_evict`` (SP-4.4, k-plan-4 §4.4).

    Eviction is submitted via ``kubectl create -f -`` against the Eviction
    resource so the API server enforces PDBs natively.
    """

    prefixes = ("k8s.pod_evict",)

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id != "k8s.pod_evict":
            return None
        if lease.resolved_target is None:
            return "k8s.pod_evict: no resolved pod target on the lease"
        return None

    @staticmethod
    def _eviction_json(target: ResolvedPodTarget) -> str:
        import json as _json  # noqa: PLC0415
        return _json.dumps(
            {
                "apiVersion": "policy/v1",
                "kind": "Eviction",
                "metadata": {"name": target.pod, "namespace": target.namespace},
            }
        )

    def inject(self, lease: FaultLease) -> StepOutcome:
        t = lease.resolved_target
        if t is None:
            return StepOutcome("inject", False, "k8s.pod_evict: no resolved target")
        argv: tuple[str, ...] = ("kubectl", "create", "-f", "-", "-n", t.namespace)
        result = run_tool(argv, timeout_s=30, stdin_data=self._eviction_json(t))
        if result.exit_code != 0:
            return StepOutcome(
                "inject", False,
                f"kubectl eviction failed (rc={result.exit_code}): "
                f"{result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "inject", True,
            f"k8s.pod_evict: evicted pod {t.pod} in namespace {t.namespace}",
            tool_result=result,
        )

    def undo(self, lease: FaultLease) -> StepOutcome:
        return StepOutcome("undo", True, "k8s.pod_evict: no live undo for eviction")


class K8sPodOomExecutor(K8sExecutor):
    """Execute and undo ``k8s.pod_oom`` (SP-4.4, k-plan-4 §4.4).

    Spikes memory usage inside the container via ``/dev/shm`` writes so the
    kernel OOMKills the container.  The spike is bounded by an in-container
    ``sleep``; the engine's compensation then watches for the replacement pod.
    """

    prefixes = ("k8s.pod_oom",)

    def _bytes_spec(self, lease: FaultLease) -> int:
        params = _lease_fault_params(lease)
        return _memory_bytes_from_spec(
            str(params.get("memory_limit") or params.get("limit") or "64Mi"),
            default_mib=64,
        )

    def _duration(self, lease: FaultLease) -> int:
        params = _lease_fault_params(lease)
        raw = params.get("duration") or lease.ttl_seconds or 120
        try:
            return max(5, int(float(raw)))
        except (ValueError, TypeError):
            return 120

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id != "k8s.pod_oom":
            return None
        if lease.resolved_target is None:
            return "k8s.pod_oom: no resolved pod target on the lease"
        return None

    def inject(self, lease: FaultLease) -> StepOutcome:
        t = lease.resolved_target
        if t is None:
            return StepOutcome("inject", False, "k8s.pod_oom: no resolved target")
        nbytes = self._bytes_spec(lease)
        duration = self._duration(lease)
        sh_cmd = (
            f"d=/dev/shm/.mayhem_oom; rm -f $d; "
            f"head -c {nbytes} /dev/zero > $d 2>/dev/null & sleep {duration}"
        )
        argv: tuple[str, ...] = (*t.exec_argv, "sh", "-c", sh_cmd)
        result = run_tool(argv, timeout_s=duration + 30)
        # rc 0 means sleep exited normally; non-zero may mean the container
        # died (OOM) before sleep completed — both are acceptable as the
        # OOM effect, so the step succeeds and compensation verifies.
        return StepOutcome(
            "inject", True,
            f"k8s.pod_oom: memory spike ({nbytes} bytes) started in "
            f"pod {t.pod} container {t.container}",
            tool_result=result,
        )

    def undo(self, lease: FaultLease) -> StepOutcome:
        return StepOutcome("undo", True, "k8s.pod_oom: no live undo for OOM kill")


class K8sPodPressureExecutor(K8sExecutor):
    """Execute and undo ``k8s.pod_pressure`` (SP-4.4, k-plan-4 §4.4).

    Reuses the k-plan-3 exec plumbing: a bounded in-container stress loop
    (cpu or memory) terminated by an internal ``sleep`` matching the lease
    duration.  The stress self-terminates; no live undo is needed.
    """

    prefixes = ("k8s.pod_pressure",)

    def _resource(self, lease: FaultLease) -> str:
        params = _lease_fault_params(lease)
        return str(params.get("resource") or "cpu").lower()

    def _duration(self, lease: FaultLease) -> int:
        params = _lease_fault_params(lease)
        raw = params.get("duration") or lease.ttl_seconds or 300
        try:
            return max(5, int(float(raw)))
        except (ValueError, TypeError):
            return 300

    def _target_percent(self, lease: FaultLease) -> int:
        params = _lease_fault_params(lease)
        try:
            return max(1, min(100, int(float(params.get("target_percent") or 50))))
        except (ValueError, TypeError):
            return 50

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id != "k8s.pod_pressure":
            return None
        if lease.resolved_target is None:
            return "k8s.pod_pressure: no resolved pod target on the lease"
        return None

    def _cpu_stress_command(self, lease: FaultLease) -> str:
        pct = self._target_percent(lease)
        duration = self._duration(lease)
        return (
            f"n=$(nproc 2>/dev/null || echo 1); "
            f"c=$(echo \"$n {pct} 100\" | awk '{{printf \"%d\", ($1*$2+$99)/100}}'); "
            f"pids=''; i=0; while [ $i -lt $c ]; do "
            f"( while :; do :; done ) & pids=\"$pids $!\"; i=$((i+1)); done; "
            f"sleep {duration}; kill $pids 2>/dev/null; wait 2>/dev/null"
        )

    def _mem_stress_command(self, lease: FaultLease) -> str:
        duration = self._duration(lease)
        nbytes = 64 * 1048576
        return (
            f"p=$(mktemp -p /dev/shm 2>/dev/null || echo /dev/shm/.mayhem_pres); "
            f"head -c {nbytes} /dev/zero > $p 2>/dev/null & "
            f"sleep {duration}; kill $! 2>/dev/null; rm -f $p"
        )

    def inject(self, lease: FaultLease) -> StepOutcome:
        t = lease.resolved_target
        if t is None:
            return StepOutcome("inject", False, "k8s.pod_pressure: no resolved target")
        resource = self._resource(lease)
        duration = self._duration(lease)
        sh_cmd = (
            self._cpu_stress_command(lease)
            if resource == "cpu"
            else self._mem_stress_command(lease)
        )
        argv: tuple[str, ...] = (*t.exec_argv, "sh", "-c", sh_cmd)
        result = run_tool(argv, timeout_s=duration + 30)
        return StepOutcome(
            "inject", True,
            f"k8s.pod_pressure: {resource} stress started in pod {t.pod} "
            f"container {t.container} for {duration}s",
            tool_result=result,
        )

    def undo(self, lease: FaultLease) -> StepOutcome:
        return StepOutcome(
            "undo", True, "k8s.pod_pressure: stress self-terminates; no live undo"
        )


class K8sNetworkPolicyExecutor(K8sExecutor):
    """Execute and undo ``k8s.network_policy`` (SP-4.4, k-plan-4 §4.4).

    Applies an ingress/egress deny-all NetworkPolicy scoped to the target
    pod's ``podSelector``.  Undo deletes the policy by the deterministic
    name ``mayhem-deny-<pod_name>`` (or an explicit ``policy_name`` param).
    """

    prefixes = ("k8s.network_policy",)

    @staticmethod
    def _policy_name(target: ResolvedPodTarget, params: dict[str, object] | None) -> str:
        explicit = (params or {}).get("policy_name")
        if explicit:
            return str(explicit)
        return f"mayhem-deny-{target.pod}"

    @staticmethod
    def _policy_body(
        target: ResolvedPodTarget, name: str, params: dict[str, object] | None
    ) -> str:
        import json as _json  # noqa: PLC0415
        direction = str((params or {}).get("direction") or "ingress").lower()
        if direction not in ("ingress", "egress"):
            direction = "ingress"
        pod_selector = {"matchLabels": target.labels} if target.labels else {}
        spec: dict[str, object] = {
            "podSelector": pod_selector,
            "policyTypes": [direction.title()],
        }
        if direction == "ingress":
            spec["ingress"] = []
        else:
            spec["egress"] = []
        return _json.dumps(
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": name,
                    "namespace": target.namespace,
                    "labels": {
                        "app.kubernetes.io/managed-by": "mayhem",
                        "mayhem.k8s/policy-kind": direction,
                    },
                },
                "spec": spec,
            }
        )

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id != "k8s.network_policy":
            return None
        if lease.resolved_target is None:
            return "k8s.network_policy: no resolved pod target on the lease"
        return None

    def inject(self, lease: FaultLease) -> StepOutcome:
        t = lease.resolved_target
        if t is None:
            return StepOutcome("inject", False, "k8s.network_policy: no resolved target")
        params = _lease_fault_params(lease)
        name = self._policy_name(t, params)
        body = self._policy_body(t, name, params)
        argv: tuple[str, ...] = ("kubectl", "apply", "-f", "-", "-n", t.namespace)
        result = run_tool(argv, timeout_s=30, stdin_data=body)
        if result.exit_code != 0:
            return StepOutcome(
                "inject", False,
                f"kubectl apply NetworkPolicy failed (rc={result.exit_code}): "
                f"{result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "inject", True,
            f"k8s.network_policy: applied {name} in namespace {t.namespace}",
            tool_result=result,
        )

    def undo(self, lease: FaultLease) -> StepOutcome:
        t = lease.resolved_target
        if t is None:
            return StepOutcome("undo", True, "k8s.network_policy: nothing to undo")
        params = _lease_fault_params(lease)
        name = self._policy_name(t, params)
        argv: tuple[str, ...] = (
            "kubectl", "delete", "networkpolicy", name, "-n", t.namespace,
            "--ignore-not-found",
        )
        result = run_tool(argv, timeout_s=30)
        if result.exit_code != 0:
            return StepOutcome(
                "undo", False,
                f"kubectl delete NetworkPolicy failed (rc={result.exit_code}): "
                f"{result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome("undo", True, f"k8s.network_policy: deleted {name}")


class K8sPodPartitionExecutor(K8sNetworkPolicyExecutor):
    """Execute ``k8s.pod_partition`` (k-plan-4 §4.1).

    Reuses the NetworkPolicy mechanism with a separate policy-name prefix
    (``mayhem-isolate-``) so undo deletes only the partition policy and never
    collides with broader network_policy families.
    """

    prefixes = ("k8s.pod_partition",)

    @staticmethod
    def _policy_name(target: ResolvedPodTarget, params: dict[str, object] | None) -> str:
        explicit = (params or {}).get("policy_name")
        if explicit:
            return str(explicit)
        return f"mayhem-isolate-{target.pod}"

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id != "k8s.pod_partition":
            return None
        if lease.resolved_target is None:
            return "k8s.pod_partition: no resolved pod target on the lease"
        return None

    def inject(self, lease: FaultLease) -> StepOutcome:
        outcome = super().inject(lease)
        if outcome.detail:
            outcome = StepOutcome(
                outcome.step,
                outcome.ok,
                outcome.detail.replace("k8s.network_policy:", "k8s.pod_partition:"),
                tool_result=outcome.tool_result,
            )
        return outcome

    def undo(self, lease: FaultLease) -> StepOutcome:
        outcome = super().undo(lease)
        if outcome.detail:
            outcome = StepOutcome(
                outcome.step,
                outcome.ok,
                outcome.detail.replace("k8s.network_policy:", "k8s.pod_partition:"),
                tool_result=outcome.tool_result,
            )
        return outcome


# ── k-plan-5: node-level faults ──────────────────────────────────────────────
NETNS_UNSUPPORTED_MESSAGE = (
    "k8s.unsupported: k8s.pod_latency needs node-side network-namespace access "
    "(nsenter into the pod's netns); the NETNS runtime capability is "
    "UNSUPPORTED this milestone — see k-plan-5 §5.3"
)


def k8s_netns_supported() -> bool:
    """NETNS capability verdict from the kubernetes runtime adapter.

    Node-side netns (``nsenter tc netem``) is delivered through the kubernetes
    driver; the adapter's capability matrix is the single source of truth for
    whether that delivery path is wired this milestone (k-plan-5 §5.3).
    """
    from mayhem.domain.k8s_adapter import KubernetesAdapter  # noqa: PLC0415
    from mayhem.domain.runtime_adapter import RuntimeCapability  # noqa: PLC0415

    return RuntimeCapability.NETNS in KubernetesAdapter().capabilities().supported


class K8sNodeDrainExecutor(K8sExecutor):
    """Cordon + drain an exact node; undo via uncordon (k-plan-5 §5.1/§5.2).

    ``k8s.node_drain`` is CRITICAL-risk: admission requires
    ``policy.allow_critical`` + ``--allow-critical`` + a per-fault ``ack``
    (Band A6/B).  The drain is scoped to the resolved node; pods on other
    nodes are never touched.  Eviction honours PodDisruptionBudgets because
    ``kubectl drain`` lets the API server enforce PDBs natively (mirrors the
    Eviction path in :class:`K8sPodEvictExecutor`).
    """

    prefixes = ("k8s.node_drain",)

    def _grace_period(self, lease: FaultLease) -> str:
        params = _lease_fault_params(lease)
        grace = params.get("grace_period") or params.get("timeout")
        if grace is None:
            return "30"
        try:
            return str(int(grace))
        except (TypeError, ValueError):
            return "30"

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id != "k8s.node_drain":
            return None
        target = lease.resolved_target
        if not isinstance(target, ResolvedNodeTarget) or target.node in ("", "*"):
            return "k8s.node_drain: no resolved node target on the lease"
        return None

    def inject(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedNodeTarget):
            return StepOutcome("inject", False, "k8s.node_drain: no resolved node target")
        cordon = run_tool(("kubectl", "cordon", target.node), timeout_s=30)
        if cordon.exit_code != 0:
            return StepOutcome(
                "inject",
                False,
                "k8s.node_drain: kubectl cordon failed "
                f"(rc={cordon.exit_code}): {cordon.stdout.strip()}",
                tool_result=cordon,
            )
        drain = run_tool(
            (
                "kubectl",
                "drain",
                target.node,
                "--ignore-daemonsets",
                "--delete-emptydir-data",
                "--grace-period",
                self._grace_period(lease),
            ),
            timeout_s=60,
        )
        if drain.exit_code != 0:
            return StepOutcome(
                "inject",
                False,
                "k8s.node_drain: kubectl drain failed "
                f"(rc={drain.exit_code}): {drain.stdout.strip()}",
                tool_result=drain,
            )
        note = f"k8s.node_drain: node {target.node} cordoned and drained"
        if "evicted" not in drain.stdout:
            note += " (no pods evicted)"
        return StepOutcome("inject", True, note, tool_result=drain)

    def undo(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedNodeTarget):
            return StepOutcome("undo", False, "k8s.node_drain: no resolved node target")
        result = run_tool(("kubectl", "uncordon", target.node), timeout_s=30)
        if result.exit_code != 0:
            return StepOutcome(
                "undo",
                False,
                "k8s.node_drain: kubectl uncordon failed "
                f"(rc={result.exit_code}): {result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "undo", True, f"k8s.node_drain: node {target.node} uncordoned", tool_result=result
        )


class K8sNodePressureExecutor(K8sExecutor):
    """Node-level capacity pressure via a noisy-neighbour workload (k-plan-5 §5.4).

    The mutation applies a singleton workload pinned to the resolved node
    (``nodeName`` in the pod spec) requesting a share of the node's allocatable
    capacity; undo deletes that workload — live and reversible.
    """

    prefixes = ("k8s.node_pressure",)

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id != "k8s.node_pressure":
            return None
        target = lease.resolved_target
        if not isinstance(target, ResolvedNodeTarget) or target.node in ("", "*"):
            return "k8s.node_pressure: no resolved node target on the lease"
        return None

    def _target_percent(self, lease: FaultLease) -> int:
        params = _lease_fault_params(lease)
        try:
            return max(1, min(100, int(float(params.get("target_percent") or 50))))
        except (TypeError, ValueError):
            return 50

    def _workload_name(self, target: ResolvedNodeTarget) -> str:
        import re as _re  # noqa: PLC0415

        return "mayhem-node-pressure-" + _re.sub(r"[^a-z0-9-]", "-", target.node.lower())

    def _pressure_argv(self, lease: FaultLease, target: ResolvedNodeTarget) -> tuple[str, ...]:
        import json as _json  # noqa: PLC0415

        pct = self._target_percent(lease)
        resource = str((_lease_fault_params(lease).get("resource") or "cpu"))
        if resource == "memory":
            requests = {"memory": f"{pct}Mi"}
        else:
            requests = {"cpu": f"{pct}m"}
        body = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": self._workload_name(target), "labels": {"mayhem/pressure": "node"}},
            "spec": {
                "nodeName": target.node,
                "restartPolicy": "Never",
                "containers": [
                    {
                        "name": "burner",
                        "image": "busybox:1.36",
                        "imagePullPolicy": "IfNotPresent",
                        "command": ["sh", "-c", "while :; do :; done"],
                        "resources": {"requests": requests},
                    }
                ],
            },
        }
        return (
            "kubectl",
            "apply",
            "-f",
            "-",
            "--input",
            _json.dumps(body, separators=(",", ":")),
        )

    def inject(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedNodeTarget):
            return StepOutcome("inject", False, "k8s.node_pressure: no resolved node target")
        argv = self._pressure_argv(lease, target)
        result = run_tool(argv, timeout_s=30)
        if result.exit_code != 0:
            return StepOutcome(
                "inject",
                False,
                "k8s.node_pressure: applying pressure workload failed "
                f"(rc={result.exit_code}): {result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "inject",
            True,
            f"k8s.node_pressure: pressure workload {self._workload_name(target)} "
            f"applied to node {target.node}",
            tool_result=result,
        )

    def undo(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedNodeTarget):
            return StepOutcome("undo", False, "k8s.node_pressure: no resolved node target")
        name = self._workload_name(target)
        result = run_tool(
            ("kubectl", "delete", "pod", name, "--ignore-not-found", "--grace-period=0"),
            timeout_s=30,
        )
        if result.exit_code != 0:
            return StepOutcome(
                "undo",
                False,
                "k8s.node_pressure: deleting pressure workload failed "
                f"(rc={result.exit_code}): {result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "undo", True, f"k8s.node_pressure: pressure workload {name} deleted", tool_result=result
        )


class K8sPodLatencyExecutor(K8sPodPressureExecutor):
    """Per-pod network-latency fault via ``tc netem`` in the pod netns (k-plan-5 §5.3).

    NETNS delivery is UNSUPPORTED this milestone: ``can_apply`` refuses before
    any mutation with :data:`NETNS_UNSUPPORTED_MESSAGE` unless the kubernetes
    runtime adapter reports the NETNS capability (the M8 driver seam).  When
    available, inject adds qdisc delay on the pod's ``eth0``; undo removes it.
    """

    prefixes = ("k8s.pod_latency",)

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id != "k8s.pod_latency":
            return None
        if lease.resolved_target is None:
            return "k8s.pod_latency: no resolved pod target on the lease"
        if not k8s_netns_supported():
            return NETNS_UNSUPPORTED_MESSAGE
        return None

    def _delay_params(self, lease: FaultLease) -> tuple[str, str]:
        params = _lease_fault_params(lease)
        delay = params.get("delay_ms")
        jitter = params.get("jitter_ms")
        try:
            delay_ms = str(max(0, int(float(delay)) if delay is not None else 100))
        except (TypeError, ValueError):
            delay_ms = "100"
        try:
            jitter_ms = str(max(0, int(float(jitter)) if jitter is not None else 0))
        except (TypeError, ValueError):
            jitter_ms = "0"
        return delay_ms, jitter_ms

    def _tc_struct(self, lease: FaultLease) -> str:
        delay_ms, jitter_ms = self._delay_params(lease)
        return f"tc qdisc add dev eth0 root netem delay {delay_ms}ms {jitter_ms}ms 25%"

    def inject(self, lease: FaultLease) -> StepOutcome:
        t = lease.resolved_target
        if t is None:
            return StepOutcome("inject", False, "k8s.pod_latency: no resolved target")
        argv: tuple[str, ...] = (*t.exec_argv, "sh", "-c", self._tc_struct(lease))
        result = run_tool(argv, timeout_s=30)
        if result.exit_code != 0:
            return StepOutcome(
                "inject",
                False,
                f"k8s.pod_latency: tc netem failed (rc={result.exit_code}): "
                f"{result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "inject",
            True,
            f"k8s.pod_latency: delay {self._tc_struct(lease)} applied on "
            f"pod {t.pod} container {t.container}",
            tool_result=result,
        )

    def undo(self, lease: FaultLease) -> StepOutcome:
        t = lease.resolved_target
        if t is None:
            return StepOutcome("undo", False, "k8s.pod_latency: no resolved target")
        argv: tuple[str, ...] = (*t.exec_argv, "sh", "-c", "tc qdisc del dev eth0 root")
        result = run_tool(argv, timeout_s=30)
        if result.exit_code != 0:
            return StepOutcome(
                "undo",
                False,
                f"k8s.pod_latency: tc qdisc del failed (rc={result.exit_code}): "
                f"{result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "undo", True, f"k8s.pod_latency: qdisc removed from pod {t.pod}", tool_result=result
        )


_K8S_EXECUTORS: dict[str, type[K8sExecutor]] = {
    "k8s.pod_kill": K8sPodKillExecutor,
    "k8s.pod_evict": K8sPodEvictExecutor,
    "k8s.pod_oom": K8sPodOomExecutor,
    "k8s.pod_pressure": K8sPodPressureExecutor,
    "k8s.network_policy": K8sNetworkPolicyExecutor,
    "k8s.pod_partition": K8sPodPartitionExecutor,
    "k8s.node_drain": K8sNodeDrainExecutor,
    "k8s.node_pressure": K8sNodePressureExecutor,
    "k8s.pod_latency": K8sPodLatencyExecutor,
}


def k8s_executor_for(
    fault_id: str,
    runtime: RuntimeLabel = RuntimeLabel.DOCKER,
) -> K8sExecutor | None:
    """Return the k8s executor for *fault_id* or ``None``.

    Pod-lifecycle and network-policy families return their dedicated executors
    when ``runtime is KUBERNETES``; all other k8s-delivered faults return the
    shared ``_K8S_EXECUTOR`` so the signal path stays uniform.
    """
    if runtime is RuntimeLabel.KUBERNETES:
        specialized = _K8S_EXECUTORS.get(fault_id)
        if specialized is not None:
            return specialized()
        return _K8S_EXECUTOR
    return None


def k8s_unsupported_reason(fault_id: str) -> str:
    """Stable ``k8s.unsupported`` reason for faults the driver refuses."""
    if fault_id == "k8s.pod.failure":
        return (
            "k8s.unsupported: k8s.pod.failure is the umbrella refusal id; "
            "use k8s.pod_kill / k8s.pod_evict / k8s.pod_oom (k-plan-4)"
        )
    prefix = fault_id.split(".", 1)[0]
    if prefix in ("mem", "cpu", "fs", "fd", "load", "fuzz"):
        return (
            f"k8s.unsupported: {prefix}.* payloads need an argv compensation "
            "contract carrying their params (k-plan-3 SP-3.4)"
        )
    return f"k8s.unsupported: driver {fault_id!r} is not executable this milestone"


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
    _K8S_EXECUTOR,
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
_register_fault_executor("k8s.pod.failure", _K8S_EXECUTOR)


@functools.lru_cache(maxsize=512)
def _is_k8s_applicable(fault_id: str) -> bool:
    """True when the catalog pins ``fault_id`` to pod / k8s_node node kinds.

    Supplies the runtime-aware k8s dispatch without duplicating the catalog;
    imported lazily to keep executors import-order independent.
    """
    try:
        from mayhem.domain.catalog import definition_for  # noqa: PLC0415
        from mayhem.domain.topology import NodeKind  # noqa: PLC0415
    except Exception:  # noqa: BLE001  (catalog is always importable; defensive)
        return False
    try:
        definition = definition_for(fault_id)
    except Exception:  # noqa: BLE001  (unknown fault id ⇒ not k8s-applicable)
        return False
    return NodeKind.POD in definition.applicable_node_kinds or (
        NodeKind.K8S_NODE in definition.applicable_node_kinds
    )


def executor_for(
    fault_id: str,
    runtime: RuntimeLabel | None = None,
) -> FaultExecutor | None:
    """Dispatch a fault to its executor.

    ``runtime=KUBERNETES`` forces the k8s driver (every fault on a kubernetes
    step is delivered through the resolved pod — k-plan-3). With any other
    runtime (or None), the explicit fault-level override wins, then the first
    executor claiming the fault's prefix — the pre-k-plan-3 registry contract.
    """
    if runtime == RuntimeLabel.KUBERNETES:
        return k8s_executor_for(fault_id, runtime)
    override = _FAULT_EXECUTOR_OVERRIDES.get(fault_id)
    if override is not None:
        return override
    for executor in EXECUTORS:
        if executor.supports(fault_id):
            return executor
    return None
