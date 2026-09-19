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

from mayhem.agents.k8s_control import (
    ResourceRef,
    apply_patch,
    clear_annotation,
    configmap_ref_for_pod,
    delete_object,
    find_annotated,
    hpa_ref_for_pod,
    kubectl_apply_json,
    kubectl_json,
    preferred_mount_path,
    read_snapshot,
    rollout_control,
    scale,
    secret_ref_for_pod,
    service_ref_for_pod,
    workload_ref_for_pod,
    write_annotation,
)
from mayhem.domain.common import parse_duration
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
        # K8s dispatch goes through ``k8s_executor_for()`` when
        # ``runtime=KUBERNETES``; this executor never participates in
        # non-k8s (docker) dispatch so portable generic faults that are
        # also k8s-live continue to route to their ToolExecutors on docker.
        return False

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
            "kubectl",
            "delete",
            "pod",
            t.pod,
            "-n",
            t.namespace,
            "--grace-period",
            self._grace_period(lease),
        )
        result = run_tool(argv, timeout_s=60)
        if result.exit_code != 0:
            return StepOutcome(
                "inject",
                False,
                f"kubectl delete pod failed (rc={result.exit_code}): {result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "inject",
            True,
            f"k8s.pod_kill: deleted pod {t.pod} in namespace {t.namespace}",
            tool_result=result,
        )

    def undo(self, lease: FaultLease) -> StepOutcome:
        return StepOutcome("undo", True, "k8s.pod_kill: no live undo for delete")


class K8sPodEvictExecutor(K8sExecutor):
    """Execute and undo ``k8s.pod_evict`` (SP-4.4, k-plan-4 §4.4).

    Eviction is submitted via the kubernetes Python SDK's
    ``create_namespaced_pod_eviction`` (policy/v1 Eviction subresource) so
    the API server enforces PDBs natively.  ``kubectl create -f -`` does not
    work because kubectl lacks a resource mapping for the Eviction kind.
    """

    prefixes = ("k8s.pod_evict",)

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id != "k8s.pod_evict":
            return None
        if lease.resolved_target is None:
            return "k8s.pod_evict: no resolved pod target on the lease"
        return None

    def inject(self, lease: FaultLease) -> StepOutcome:
        t = lease.resolved_target
        if t is None:
            return StepOutcome("inject", False, "k8s.pod_evict: no resolved target")
        try:
            from kubernetes import client as _k8s_client  # noqa: PLC0415
            from kubernetes import config as _k8s_config  # noqa: PLC0415

            _k8s_config.load_kube_config()
            api = _k8s_client.CoreV1Api()
            eviction = _k8s_client.V1Eviction(
                metadata=_k8s_client.V1ObjectMeta(
                    name=t.pod,
                    namespace=t.namespace,
                ),
            )
            api.create_namespaced_pod_eviction(
                name=t.pod,
                namespace=t.namespace,
                body=eviction,
            )
        except Exception as exc:
            return StepOutcome(
                "inject",
                False,
                f"k8s.pod_evict: eviction API call failed: {exc}",
            )
        return StepOutcome(
            "inject",
            True,
            f"k8s.pod_evict: evicted pod {t.pod} in namespace {t.namespace}",
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
            "inject",
            True,
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
            f'c=$(echo "$n {pct} 100" | awk \'{{printf "%d", ($1*$2+$99)/100}}\'); '
            f"pids=''; i=0; while [ $i -lt $c ]; do "
            f'( while :; do :; done ) & pids="$pids $!"; i=$((i+1)); done; '
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
            "inject",
            True,
            f"k8s.pod_pressure: {resource} stress started in pod {t.pod} "
            f"container {t.container} for {duration}s",
            tool_result=result,
        )

    def undo(self, lease: FaultLease) -> StepOutcome:
        return StepOutcome("undo", True, "k8s.pod_pressure: stress self-terminates; no live undo")


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
    def _policy_body(target: ResolvedPodTarget, name: str, params: dict[str, object] | None) -> str:
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
                "inject",
                False,
                f"kubectl apply NetworkPolicy failed (rc={result.exit_code}): "
                f"{result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "inject",
            True,
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
            "kubectl",
            "delete",
            "networkpolicy",
            name,
            "-n",
            t.namespace,
            "--ignore-not-found",
        )
        result = run_tool(argv, timeout_s=30)
        if result.exit_code != 0:
            return StepOutcome(
                "undo",
                False,
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


# ── k-plan-6 §24: node-killer families (kubelet control-plane) ────────────────

# The node-killer executor families that admit on the NODE_CONTROL capability
# gate.  Kept here (not in k8s_runtime) to avoid an import cycle: the run
# engine imports executors, and this set is used at can_apply time.
K8S_NODE_CONTROL_FAULTS: frozenset[str] = frozenset(
    {"k8s.taint_evict", "k8s.nvidia_smi_error", "k8s.crash_loop"}
)

NODE_CONTROL_UNSUPPORTED_MESSAGE = (
    "k8s.unsupported: node-killer families (k8s.taint_evict / k8s.nvidia_smi_error / "
    "k8s.crash_loop) need node-level kubelet control-plane access (kubectl get "
    "nodes); the NODE_CONTROL runtime capability is UNSUPPORTED this milestone "
    "— see k-plan-6 §24"
)


def k8s_node_control_supported() -> bool:
    """NODE_CONTROL capability verdict from the kubernetes runtime adapter.

    Node-killer delivery (taints, node-pinned GPU/CRI workers) goes through
    the kubernetes driver; the adapter's capability matrix is the single
    source of truth for whether the kubelet control-plane path is wired this
    milestone (k-plan-6 §24, ADR-M7-1).
    """
    from mayhem.domain.k8s_adapter import KubernetesAdapter  # noqa: PLC0415
    from mayhem.domain.runtime_adapter import RuntimeCapability  # noqa: PLC0415

    return RuntimeCapability.NODE_CONTROL in KubernetesAdapter().capabilities().supported


def node_control_unsupported_reason(fault_id: str) -> str:
    """Stable refusal reason when the NODE_CONTROL gate is closed."""
    if fault_id in K8S_NODE_CONTROL_FAULTS:
        return NODE_CONTROL_UNSUPPORTED_MESSAGE
    return k8s_unsupported_reason(fault_id)


class K8sNodeDrainExecutor(K8sExecutor):
    """Cordon + drain an exact node; undo via uncordon (k-plan-5 §5.1/§5.2).

    ``k8s.node_drain`` is CRITICAL-risk: admission requires
    ``policy.allow_critical`` + ``--allow-critical`` + a per-fault ``ack``
    (Band A6/B).  The drain is scoped to the resolved node; pods on other
    nodes are never touched.  ``--force`` evicts controller-less pods
    (e.g. minikube's ``storage-provisioner``) that kubectl otherwise
    refuses; daemonsets are ignored so node-local agents survive.
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
                "--force",
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
        return ("kubectl", "apply", "-f", "-")

    def _pressure_body(self, lease: FaultLease, target: ResolvedNodeTarget) -> str:
        import json as _json  # noqa: PLC0415

        pct = self._target_percent(lease)
        resource = str(_lease_fault_params(lease).get("resource") or "cpu")
        if resource == "memory":
            requests = {"memory": f"{pct}Mi"}
        else:
            requests = {"cpu": f"{pct}m"}
        body = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": self._workload_name(target),
                "labels": {"mayhem/pressure": "node"},
            },
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
        return _json.dumps(body, separators=(",", ":"))

    def inject(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedNodeTarget):
            return StepOutcome("inject", False, "k8s.node_pressure: no resolved node target")
        argv = self._pressure_argv(lease, target)
        body = self._pressure_body(lease, target)
        result = run_tool(argv, timeout_s=30, stdin_data=body)
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


def _shq(value: object) -> str:
    """Shell-escape *value* for embedding in a ``sh -c`` payload string."""
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


#: fault_id -> undo verb: "reap" kills the recorded worker pids and sweeps
#: the token artifacts; "tc" clears the root qdisc on eth0.  The reverseable
#: argv lane (SP-3.1) is opt-in per fault id; a fault not listed here is not
#: a K8sArgvExecutor fault.
_K8S_ARGV_UNDO_VERB: dict[str, str] = {
    "cpu.saturate": "reap",
    "cpu.throttle": "reap",
    "mem.exhaust": "reap",
    "mem.leak": "reap",
    "fs.fill": "reap",
    "fs.inode_exhaust": "reap",
    "fs.io_stress": "reap",
    "fd.exhaust": "reap",
    "net.latency": "tc",
    "net.packet_loss": "tc",
    "net.duplicate": "tc",
    "net.reorder": "tc",
    "net.bandwidth": "tc",
    "net.partition": "tc",
}


class K8sArgvExecutor(K8sExecutor):
    """Portable generic faults delivered in-pod via ``kubectl exec`` argv.

    k-plan-3 SP-3.4: the generic payload families (``cpu.*``, ``mem.*``,
    ``fs.*``, ``fd.*``) become *live on cluster* through the argv
    compensation contract — inject launches a bounded in-pod worker
    (``sh -c`` payload) that records its pids into a marker file and arms a
    self-cleaning reaper; undo reaps the workers idempotently and removes
    the artifacts.  The ``net.*`` tc-netem families ride the same pipeline
    but stay gated on the adapter's NETNS capability (:func:`NETNS_UNSUPPORTED
    `): they mutate the pod netns qdisc, never an argv worker.
    """

    prefixes: tuple[str, ...] = ()

    def capable_faults(self) -> tuple[str, ...]:
        return tuple(sorted(_K8S_ARGV_UNDO_VERB))

    # -- helpers ------------------------------------------------------------

    def _token(self, lease: FaultLease) -> str:
        safe = "".join(ch for ch in lease.id if ch.isalnum())
        return safe[:24] or "mh"

    def _duration(self, lease: FaultLease) -> int:
        params = _lease_fault_params(lease)
        raw = params.get("duration") or lease.ttl_seconds or 120
        try:
            return max(5, int(float(raw)))
        except (ValueError, TypeError):
            return 120

    def _target_or_none(self, lease: FaultLease) -> ResolvedPodTarget | None:
        return lease.resolved_target

    def can_apply(self, lease: FaultLease) -> str | None:
        verb = _K8S_ARGV_UNDO_VERB.get(lease.fault_id)
        if verb is None:
            return self._unsupported_reason(lease.fault_id)
        if lease.resolved_target is None:
            return f"{lease.fault_id}: no resolved pod target on the lease"
        if verb == "tc" and not k8s_netns_supported():
            return NETNS_UNSUPPORTED_MESSAGE
        return None

    # -- payload builders ---------------------------------------------------

    def _worker_parts(  # noqa: PLR0911 (one branch per fault family)
        self, lease: FaultLease, token: str, duration: int
    ) -> str:
        """The ``sh -c`` fragment that spawns the in-pod workers.

        Every worker backgrounds itself and appends its pid to ``$r`` (the
        marker file), so the common reaper + undo sweep can address it.
        """
        params = _lease_fault_params(lease)

        def _pct(key: str, default: float) -> int:
            raw = params.get(key)
            if raw is None:
                return int(default)
            try:
                return max(1, min(100, int(float(raw))))
            except (TypeError, ValueError):
                return int(default)

        def _num(key: str, default: int, minimum: int = 1) -> int:
            raw = params.get(key)
            if raw is None:
                return default
            try:
                return max(minimum, int(float(raw)))
            except (TypeError, ValueError):
                return default

        def _spawn(body: str) -> str:
            return f"( {body} ) & echo $! >> $r;"

        fault = lease.fault_id
        if fault == "cpu.saturate":
            pct = _pct("percent", 100)
            return (
                "n=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4); "
                f"n=$(( n * {pct} / 100 )); [ $n -lt 1 ] && n=1; i=0; "
                "while [ $i -lt $n ]; do ( while :; do :; done ) & "
                "echo $! >> $r; i=$((i+1)); done"
            )
        if fault == "cpu.throttle":
            pct = _pct("percent", 50)
            return _spawn(
                "i=0; while :; do if [ $((i%100)) -lt "
                f"{pct} ]; then :; else sleep 0.01; fi; i=$((i+1)); done"
            )
        if fault == "mem.exhaust":
            nbytes = _memory_bytes_from_spec(
                str(params.get("amount") or params.get("limit") or "512M")
            )
            return _spawn(f"head -c {nbytes} /dev/zero > /dev/shm/mayhem-{token}.blk 2>/dev/null")
        if fault == "mem.leak":
            rate = _num("rate_mb", 64)
            return _spawn(
                "while :; do cat /dev/zero 2>/dev/null | head -c "
                f"{rate}M >> /dev/shm/mayhem-{token}.blk 2>/dev/null; "
                "sleep 1; done"
            )
        if fault == "fs.fill":
            pct = _pct("percent", 90)
            return (
                f"mb=$(df -m /tmp 2>/dev/null | awk 'NR==2 "
                f"{{ mb=int($4*{pct}/100); if (mb>0) print mb; }}'); "
                f'if [ -n "$mb" ]; then dd if=/dev/zero '
                f"of=/tmp/mayhem-{token}.fill bs=1M count=$mb 2>/dev/null & "
                "echo $! >> $r; fi"
            )
        if fault == "fs.inode_exhaust":
            return _spawn(
                f"d=/tmp/mayhem-{token}.in; mkdir -p $d; i=0; "
                "while :; do : > $d/f$i 2>/dev/null || break; i=$((i+1)); done"
            )
        if fault == "fs.io_stress":
            workers = _num("workers", 1, minimum=1)
            return (
                f"i=0; while [ $i -lt {workers} ]; do ( "
                "while :; do dd if=/dev/zero of=/tmp/mayhem-"
                f"{token}.io bs=64k count=1024 2>/dev/null; "
                f"dd if=/tmp/mayhem-{token}.io of=/dev/null bs=64k 2>/dev/null; "
                "done ) & echo $! >> $r; i=$((i+1)); done"
            )
        if fault == "fd.exhaust":
            limit = min(_num("limit", 64), 512)
            return (
                f"i=0; while [ $i -lt {limit} ]; do "
                "( eval 'exec 9<>/dev/null'; sleep "
                f"{duration} ) & echo $! >> $r; i=$((i+1)); done"
            )
        raise ValueError(f"{fault}: no argv worker payload builder")

    def _tc_argv(self, lease: FaultLease, target: ResolvedPodTarget) -> tuple[str, ...]:
        params = _lease_fault_params(lease)

        def _pct_raw(key: str, default: float = 50.0) -> str:
            raw = params.get(key)
            try:
                value = max(0.0, min(100.0, float(raw)))
            except (TypeError, ValueError):
                value = default
            return f"{value:g}"

        fault = lease.fault_id
        base = (*target.exec_argv, "tc")
        if fault == "net.latency":
            delay = params.get("delay_ms", 100)
            jitter = params.get("jitter_ms", 0)
            try:
                delay_s = f"{max(0, int(float(delay)))}"
            except (TypeError, ValueError):
                delay_s = "100"
            try:
                jitter_s = f"{max(0, int(float(jitter)))}"
            except (TypeError, ValueError):
                jitter_s = "0"
            return (
                *base,
                "qdisc",
                "add",
                "dev",
                "eth0",
                "root",
                "netem",
                "delay",
                f"{delay_s}ms",
                f"{jitter_s}ms",
                "25%",
            )
        if fault == "net.packet_loss":
            pct = _pct_raw("percent")
            return (*base, "qdisc", "add", "dev", "eth0", "root", "netem", "loss", f"{pct}%")
        if fault == "net.duplicate":
            pct = _pct_raw("percent")
            return (*base, "qdisc", "add", "dev", "eth0", "root", "netem", "duplicate", f"{pct}%")
        if fault == "net.reorder":
            pct = _pct_raw("percent")
            delay = params.get("delay_ms", 50)
            try:
                delay_s = f"{max(0, int(float(delay)))}"
            except (TypeError, ValueError):
                delay_s = "50"
            return (
                *base,
                "qdisc",
                "add",
                "dev",
                "eth0",
                "root",
                "netem",
                "delay",
                f"{delay_s}ms",
                "reorder",
                f"{pct}%",
                "50%",
            )
        if fault == "net.bandwidth":
            rate = str(params.get("rate") or "1mbit").strip()
            burst = str(params.get("burst") or "10k").strip()
            return (
                *base,
                "qdisc",
                "add",
                "dev",
                "eth0",
                "root",
                "tbf",
                "rate",
                rate,
                "burst",
                burst,
                "latency",
                "50ms",
            )
        if fault == "net.partition":
            return (*base, "qdisc", "add", "dev", "eth0", "root", "netem", "loss", "100%")
        raise ValueError(f"{fault}: no tc fault builder")

    # -- inject / undo ------------------------------------------------------

    def inject(self, lease: FaultLease) -> StepOutcome:  # noqa: PLR0911 (argv vs tc lane + per-lane failures)
        target = lease.resolved_target
        if target is None:
            return StepOutcome("inject", False, f"{lease.fault_id}: no resolved target")
        verb = _K8S_ARGV_UNDO_VERB.get(lease.fault_id)
        if verb == "tc":
            argv = self._tc_argv(lease, target)
            try:
                result = run_tool(argv, timeout_s=30)
            except ToolError as exc:
                return StepOutcome("inject", False, f"{lease.fault_id} tc failed: {exc}")
            if result.exit_code != 0:
                return StepOutcome(
                    "inject",
                    False,
                    f"{lease.fault_id} tc qdisc add failed (rc={result.exit_code}): "
                    f"{result.stdout.strip()}",
                    tool_result=result,
                )
            return StepOutcome(
                "inject",
                True,
                f"{lease.fault_id} netem/tbf applied to eth0 in {target.pod}",
                result,
            )
        token = self._token(lease)
        duration = self._duration(lease)
        workers = self._worker_parts(lease, token, duration)
        sh_cmd = (
            f"r=/tmp/mayhem-{token}.pids; rm -f $r; "
            f"{workers}; ( sleep {duration}; if [ -s $r ]; then cat $r | "
            "xargs kill 2>/dev/null; fi; rm -f $r; rm -rf "
            f"/tmp/mayhem-{token}.* /dev/shm/mayhem-{token}.* ) "
            ">/dev/null 2>&1 &"
        )
        argv: tuple[str, ...] = (*target.exec_argv, "sh", "-c", sh_cmd)
        try:
            result = run_tool(argv, timeout_s=duration + 30)
        except ToolError as exc:
            return StepOutcome("inject", False, f"{lease.fault_id} payload launch failed: {exc}")
        if result.exit_code != 0:
            return StepOutcome(
                "inject",
                False,
                f"{lease.fault_id} payload launch failed (rc={result.exit_code}): "
                f"{result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "inject",
            True,
            f"{lease.fault_id} argv payload launched in {target.pod}/{target.container}",
            result,
        )

    def undo(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if target is None:
            return StepOutcome("undo", False, f"{lease.fault_id}: no resolved target")
        verb = _K8S_ARGV_UNDO_VERB.get(lease.fault_id)
        if verb == "tc":
            argv = (*target.exec_argv, "tc", "qdisc", "del", "dev", "eth0", "root")
            try:
                result = run_tool(argv, timeout_s=30)
            except ToolError as exc:
                return StepOutcome("undo", False, f"{lease.fault_id} tc undo failed: {exc}")
            if result.exit_code != 0:
                return StepOutcome(
                    "undo",
                    False,
                    f"{lease.fault_id} tc qdisc del failed (rc={result.exit_code}): "
                    f"{result.stdout.strip()}",
                    tool_result=result,
                )
            return StepOutcome(
                "undo",
                True,
                f"{lease.fault_id} qdisc removed from {target.pod}",
                tool_result=result,
            )
        token = self._token(lease)
        sh_cmd = (
            f"r=/tmp/mayhem-{token}.pids; if [ -s $r ]; then cat $r | "
            "xargs kill 2>/dev/null; fi; rm -f $r; rm -rf "
            f"/tmp/mayhem-{token}.* /dev/shm/mayhem-{token}.* 2>/dev/null"
        )
        argv: tuple[str, ...] = (*target.exec_argv, "sh", "-c", sh_cmd)
        try:
            result = run_tool(argv, timeout_s=30)
        except ToolError as exc:
            return StepOutcome("undo", False, f"{lease.fault_id} cleanup failed: {exc}")
        return StepOutcome(
            "undo",
            result.succeeded,
            f"{lease.fault_id} argv payload reaped in {target.pod}",
            result,
        )


class K8sSnapshotExecutor(K8sExecutor):
    """Undo base for k-plan-6 controller-level mutations (docs/k8s-new.md).

    Reversible controller faults persist an undo snapshot on the *target
    object itself* (``mayhem.io/restore`` annotation): at inject the executor
    writes the snapshot, at undo it reads the annotation, asks a subclass
    to apply the restore patch, then clears the annotation.  Because the
    snapshot lives on the object the engine mutated (the workload / Service /
    ConfigMap), undo is *pod-independent*: a Deployment scaled to zero or a
    pod that was deleted still leaves the owning object carrying the restore
    contract — this is the crash-safe recovery anchor of k-plan-6 §5.
    """

    ref_kinds: tuple[str, ...] = ()

    def undo(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        namespace = target.namespace if isinstance(target, ResolvedPodTarget) else "default"
        ref = find_annotated(namespace, self.ref_kinds)
        if ref is None:
            return StepOutcome(
                "undo",
                True,
                f"{lease.fault_id}: no restore annotation found; nothing to undo",
            )
        snapshot = read_snapshot(ref)
        if snapshot is None:
            clear_annotation(ref)
            return StepOutcome(
                "undo",
                True,
                f"{lease.fault_id}: snapshot absent; cleared stale annotation",
            )
        if not self._restore(ref, snapshot):
            return StepOutcome(
                "undo",
                False,
                f"{lease.fault_id}: restore failed for {ref.kind}/{ref.name}",
            )
        clear_annotation(ref)
        return StepOutcome(
            "undo",
            True,
            f"{lease.fault_id}: restored {ref.kind}/{ref.name} from snapshot",
        )

    def _restore(self, ref: ResourceRef, snapshot: dict[str, object]) -> bool:
        raise NotImplementedError

    def _ref_kinds_for(self, lease: FaultLease) -> tuple[str, ...]:
        return self.ref_kinds


class K8sWorkloadExecutor(K8sSnapshotExecutor):
    """Workload-level mutations delivered via ``kubectl patch/scale/rollout``.

    Owns the probe (readiness/liveness/startup), scheduler (unschedulable,
    schedule_delay), registry-image patch, workload (replica_reduce,
    rollout_pause, rollout_failure) and PVC-detach families.  The restore
    snapshot is the owning object's full ``spec``; the engine mutates only
    this workload, so the spec is a faithful and idempotent restore contract.
    """

    prefixes = (
        "k8s.pod_readiness_fail",
        "k8s.pod_liveness_fail",
        "k8s.pod_startup_fail",
        "k8s.pod_unschedulable",
        "k8s.schedule_delay",
        "k8s.image_pull_failure",
        "k8s.replica_reduce",
        "k8s.rollout_pause",
        "k8s.rollout_failure",
        "k8s.persistent_volume_detach",
    )
    ref_kinds = ("Deployment", "StatefulSet", "DaemonSet")

    _PROBE_FIELDS = {
        "k8s.pod_readiness_fail": "readinessProbe",
        "k8s.pod_liveness_fail": "livenessProbe",
        "k8s.pod_startup_fail": "startupProbe",
    }

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id not in self.prefixes:
            return k8s_unsupported_reason(lease.fault_id)
        if not isinstance(lease.resolved_target, ResolvedPodTarget):
            return f"{lease.fault_id}: no resolved pod target on the lease"
        return None

    def inject(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedPodTarget):
            return StepOutcome("inject", False, f"{lease.fault_id}: no resolved pod target")
        workload = workload_ref_for_pod(target)
        if workload is None:
            return StepOutcome(
                "inject",
                False,
                f"{lease.fault_id}: no owning workload found for pod {target.pod}",
            )
        if lease.fault_id in (
            "k8s.replica_reduce",
            "k8s.rollout_pause",
            "k8s.rollout_failure",
            "k8s.persistent_volume_detach",
        ):
            if workload.kind not in ("Deployment", "StatefulSet"):
                return StepOutcome(
                    "inject",
                    False,
                    f"{lease.fault_id}: workload {workload.kind}/{workload.name} has no "
                    "replicas/rollout surface (DaemonSet refused)",
                )
        obj = kubectl_json(workload)
        if obj is None:
            return StepOutcome(
                "inject",
                False,
                f"{lease.fault_id}: workload {workload.kind}/{workload.name} not found",
            )
        snapshot = {"spec": obj.get("spec", {})}
        snapshot["rollout_paused"] = str(lease.fault_id == "k8s.rollout_pause").lower()
        if len(_serialize(snapshot)) > 100_000:
            return StepOutcome(
                "inject",
                False,
                f"{lease.fault_id}: workload spec too large for the restore annotation",
            )
        write_annotation(workload, snapshot)
        ok = self._mutate(lease, workload, obj)
        if ok:
            return StepOutcome(
                "inject",
                True,
                f"{lease.fault_id}: mutated {workload.kind}/{workload.name}",
            )
        clear_annotation(workload)
        return StepOutcome(
            "inject",
            False,
            f"{lease.fault_id}: kubectl mutation failed on {workload.kind}/{workload.name} "
            "(restore annotation cleared)",
        )

    def _mutate(
        self,
        lease: FaultLease,
        workload: ResourceRef,
        obj: dict[str, object],
    ) -> bool:
        params = _lease_fault_params(lease)
        container = self._container_name(obj)
        fault = lease.fault_id
        probe_field = self._PROBE_FIELDS.get(fault)
        if probe_field is not None:
            failing = {"exec": {"command": ["/bin/sh", "-c", "/bin/false"]}}
            return apply_patch(
                workload,
                {
                    "spec": {
                        "template": {
                            "spec": {"containers": [{"name": container, probe_field: failing}]}
                        }
                    }
                },
            )
        if fault == "k8s.pod_unschedulable":
            return apply_patch(
                workload,
                {
                    "spec": {
                        "template": {"spec": {"nodeSelector": {"mayhem.unschedulable": "true"}}}
                    }
                },
            )
        if fault == "k8s.schedule_delay":
            scheduler = params.get("scheduler_name") or "mayhem-scheduler-nope"
            return apply_patch(
                workload,
                {"spec": {"template": {"spec": {"schedulerName": str(scheduler)}}}},
            )
        if fault == "k8s.image_pull_failure":
            image = str(params.get("image") or "mayhem.invalid/pull-fail:latest")
            return apply_patch(
                workload,
                {
                    "spec": {
                        "template": {"spec": {"containers": [{"name": container, "image": image}]}}
                    }
                },
            )
        if fault == "k8s.rollout_failure":
            image = str(params.get("image") or "mayhem.invalid/rollout-fail:latest")
            failing = {"exec": {"command": ["/bin/sh", "-c", "/bin/false"]}}
            return apply_patch(
                workload,
                {
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    {
                                        "name": container,
                                        "image": image,
                                        "readinessProbe": failing,
                                    }
                                ]
                            }
                        }
                    }
                },
            )
        if fault == "k8s.replica_reduce":
            replicas = int(params.get("replicas") or 0)
            return scale(workload, replicas)
        if fault == "k8s.rollout_pause":
            return rollout_control(workload, pause=True)
        if fault == "k8s.persistent_volume_detach":
            pvc_vols = [
                vol
                for vol in obj.get("spec", {})
                .get("template", {})
                .get("spec", {})
                .get("volumes", [])
                if "persistentVolumeClaim" in vol
            ]
            if not pvc_vols:
                return False
            patch = {
                "spec": {
                    "template": {
                        "spec": {
                            "volumes": [{"name": vol["name"], "emptyDir": {}} for vol in pvc_vols]
                        }
                    }
                }
            }
            return apply_patch(workload, patch)
        return False

    @staticmethod
    def _container_name(obj: dict[str, object]) -> str:
        containers = obj.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
        for container in containers:
            name = container.get("name")
            if name:
                return str(name)
        return "app"

    def _restore(self, ref: ResourceRef, snapshot: dict[str, object]) -> bool:
        if snapshot.get("rollout_paused") == "true":
            rollout_control(ref, pause=False)
        return apply_patch(ref, {"spec": snapshot["spec"]})


class K8sServiceExecutor(K8sSnapshotExecutor):
    """Service-object mutations: selector removal, flap cycling, port mismatch."""

    prefixes = (
        "k8s.service_no_endpoints",
        "k8s.service_endpoint_flap",
        "k8s.service_port_mismatch",
    )
    ref_kinds = ("Service",)

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id not in self.prefixes:
            return k8s_unsupported_reason(lease.fault_id)
        if not isinstance(lease.resolved_target, ResolvedPodTarget):
            return f"{lease.fault_id}: no resolved pod target on the lease"
        return None

    def inject(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedPodTarget):
            return StepOutcome("inject", False, f"{lease.fault_id}: no resolved pod target")
        svc = service_ref_for_pod(target)
        if svc is None:
            return StepOutcome(
                "inject",
                False,
                f"{lease.fault_id}: no Service with a matching selector for pod {target.pod}",
            )
        obj = kubectl_json(svc)
        if obj is None:
            return StepOutcome("inject", False, f"{lease.fault_id}: Service {svc.name} not found")
        snapshot = {"spec": obj.get("spec", {})}
        write_annotation(svc, snapshot)
        ok = self._mutate(lease, svc, obj)
        if ok:
            return StepOutcome("inject", True, f"{lease.fault_id}: mutated Service {svc.name}")
        clear_annotation(svc)
        return StepOutcome(
            "inject",
            False,
            f"{lease.fault_id}: kubectl mutation failed on Service {svc.name}",
        )

    def _mutate(self, lease: FaultLease, svc: ResourceRef, obj: dict[str, object]) -> bool:
        fault = lease.fault_id
        params = _lease_fault_params(lease)
        if fault == "k8s.service_no_endpoints":
            key = str(params.get("selector_key") or "mayhem.no-endpoints")
            value = str(params.get("selector_value") or "true")
            return apply_patch(svc, {"spec": {"selector": {key: value}}})
        if fault == "k8s.service_port_mismatch":
            ports = obj.get("spec", {}).get("ports", [])
            if not ports:
                return False
            first = ports[0]
            port = int(first.get("port") or 0)
            requested = int(params.get("target_port") or 0)
            old_target = first.get("targetPort") or port
            if requested > 0:
                broken = requested
            elif isinstance(old_target, int) and old_target in (1, 65535):
                broken = old_target + 1
            elif isinstance(old_target, int):
                broken = max(2, min(65535, old_target + 1))
            else:
                broken = 65531
            return apply_patch(
                svc,
                {"spec": {"ports": [{"port": port, "targetPort": broken}]}},
            )
        if fault == "k8s.service_endpoint_flap":
            # Bounded synchronous flap: toggle the selector every interval_s
            # for ``cycles`` alternations, then leave the service pointing at
            # the broken selector (undo restores the original object).
            from time import sleep  # noqa: PLC0415

            key = str(params.get("selector_key") or "mayhem.no-endpoints")
            value = str(params.get("selector_value") or "true")
            cycles = max(1, min(20, int(params.get("cycles") or 3)))
            interval = max(1, min(120, int(params.get("interval_s") or 5)))
            ok = True
            for i in range(cycles):
                broken = i % 2 == 0
                patch = (
                    {"spec": {"selector": {key: value}}}
                    if broken
                    else {"spec": {"selector": self._original_selector(obj)}}
                )
                ok = apply_patch(svc, patch) and ok
                sleep(interval)
            return ok

    @staticmethod
    def _original_selector(obj: dict[str, object]) -> dict[str, object]:
        selector = obj.get("spec", {}).get("selector") or {}
        return dict(selector)

    def _restore(self, ref: ResourceRef, snapshot: dict[str, object]) -> bool:
        return apply_patch(ref, {"spec": snapshot["spec"]})


class K8sHpaExecutor(K8sSnapshotExecutor):
    """HorizontalPodAutoscaler mutations: scale-delay windows, scale pins.

    The target is the HPA whose ``spec.scaleTargetRef`` points at the pod's
    owning workload.  ``k8s.hpa_scale_delay`` raises
    ``spec.behavior.scaleUp.stabilizationWindowSeconds`` so the controller
    holds a scaled-up replica count for the window; ``k8s.hpa_scale_failure``
    pins ``spec.maxReplicas`` or ``spec.minReplicas`` to the current replica
    count so out-of-range scale requests fail.  Undo restores the full
    ``spec`` snapshot from the object annotation.
    """

    prefixes = (
        "k8s.hpa_scale_delay",
        "k8s.hpa_scale_failure",
    )
    ref_kinds = ("HorizontalPodAutoscaler",)

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id not in self.prefixes:
            return k8s_unsupported_reason(lease.fault_id)
        if not isinstance(lease.resolved_target, ResolvedPodTarget):
            return f"{lease.fault_id}: no resolved pod target on the lease"
        if lease.fault_id == "k8s.hpa_scale_failure":
            direction = str(_lease_fault_params(lease).get("direction") or "up")
            if direction not in ("up", "down"):
                return f"{lease.fault_id}: direction must be 'up' or 'down', got {direction!r}"
        return None

    def inject(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedPodTarget):
            return StepOutcome("inject", False, f"{lease.fault_id}: no resolved pod target")
        hpa = hpa_ref_for_pod(target)
        if hpa is None:
            return StepOutcome(
                "inject",
                False,
                f"{lease.fault_id}: no HorizontalPodAutoscaler targeting the owning "
                f"workload of pod {target.pod}",
            )
        obj = kubectl_json(hpa)
        if obj is None:
            return StepOutcome(
                "inject",
                False,
                f"{lease.fault_id}: HorizontalPodAutoscaler {hpa.name} not found",
            )
        snapshot = {"spec": obj.get("spec", {})}
        write_annotation(hpa, snapshot)
        ok = self._mutate(lease, hpa, obj)
        if ok:
            return StepOutcome(
                "inject",
                True,
                f"{lease.fault_id}: mutated HorizontalPodAutoscaler {hpa.name}",
            )
        clear_annotation(hpa)
        return StepOutcome(
            "inject",
            False,
            f"{lease.fault_id}: kubectl mutation failed on HorizontalPodAutoscaler "
            f"{hpa.name} (restore annotation cleared)",
        )

    def _mutate(
        self,
        lease: FaultLease,
        hpa: ResourceRef,
        obj: dict[str, object],
    ) -> bool:
        params = _lease_fault_params(lease)
        if lease.fault_id == "k8s.hpa_scale_delay":
            raw = params.get("seconds")
            window = int(parse_duration(str(raw))) if raw else 60
            window = max(1, min(window, 3600))
            return apply_patch(
                hpa,
                {"spec": {"behavior": {"scaleUp": {"stabilizationWindowSeconds": window}}}},
            )
        direction = str(params.get("direction") or "up")
        current = (obj.get("status") or {}).get("currentReplicas")
        spec = obj.get("spec", {})
        if current is None:
            current = spec.get("minReplicas", 1)
        if direction == "up":
            patch: dict[str, object] = {"spec": {"maxReplicas": int(current)}}
        else:
            patch = {"spec": {"minReplicas": int(current)}}
        return apply_patch(hpa, patch)

    def _restore(self, ref: ResourceRef, snapshot: dict[str, object]) -> bool:
        return apply_patch(ref, {"spec": snapshot["spec"]})


class K8sConfigExecutor(K8sSnapshotExecutor):
    """ConfigMap corruption and Secret deletion (recreate-on-undo).

    ``k8s.configmap_corrupt`` annotates the ConfigMap itself and corrupts
    its data.  ``k8s.secret_unavailable`` annotates the *pod* (the Secret
    object is deleted and cannot carry its own snapshot); undo recreates
    the Secret from the pod annotation.  ``kubectl delete`` faults a real
    deleted object, matching k-plan-6 §13 semantics (Fail pods / pod
    admission refusal).
    """

    prefixes = ("k8s.configmap_corrupt", "k8s.secret_unavailable")
    ref_kinds = ("ConfigMap",)

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id not in self.prefixes:
            return k8s_unsupported_reason(lease.fault_id)
        if not isinstance(lease.resolved_target, ResolvedPodTarget):
            return f"{lease.fault_id}: no resolved pod target on the lease"
        return None

    def inject(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedPodTarget):
            return StepOutcome("inject", False, f"{lease.fault_id}: no resolved pod target")
        if lease.fault_id == "k8s.configmap_corrupt":
            return self._inject_configmap(lease, target)
        return self._inject_secret(lease, target)

    def _inject_configmap(self, lease: FaultLease, target: ResolvedPodTarget) -> StepOutcome:
        params = _lease_fault_params(lease)
        explicit = params.get("configmap")
        cm = (
            ResourceRef(kind="ConfigMap", name=str(explicit), namespace=target.namespace)
            if explicit
            else configmap_ref_for_pod(target)
        )
        if cm is None:
            return StepOutcome(
                "inject",
                False,
                f"{lease.fault_id}: no ConfigMap mounted into {target.pod}",
            )
        obj = kubectl_json(cm)
        if obj is None:
            return StepOutcome("inject", False, f"{lease.fault_id}: ConfigMap {cm.name} not found")
        prefix = str(params.get("prefix") or "mayhem-corrupted-")
        data = dict(obj.get("data") or {})
        if not data:
            data = {"mayhem-corrupted": "empty-configmap"}
        snapshot = {"data": dict(data)}
        write_annotation(cm, snapshot)
        corrupted = {str(k): f"{prefix}{str(v)[:120]}" for k, v in data.items()}
        if not apply_patch(cm, {"data": corrupted}):
            clear_annotation(cm)
            return StepOutcome(
                "inject", False, f"{lease.fault_id}: patch failed on ConfigMap {cm.name}"
            )
        return StepOutcome("inject", True, f"{lease.fault_id}: corrupted ConfigMap {cm.name}")

    def _inject_secret(self, lease: FaultLease, target: ResolvedPodTarget) -> StepOutcome:
        params = _lease_fault_params(lease)
        explicit = params.get("name")
        synthetic = str(params.get("synthetic") or "true").lower() in ("1", "true", "yes")
        sec = (
            ResourceRef(kind="Secret", name=str(explicit), namespace=target.namespace)
            if explicit
            else secret_ref_for_pod(target)
        )
        if sec is None:
            return StepOutcome(
                "inject",
                False,
                f"{lease.fault_id}: no Secret mounted into {target.pod}",
            )
        if not synthetic and not sec.name.startswith("mayhem-"):
            return StepOutcome(
                "inject",
                False,
                f"{lease.fault_id}: refusing to delete non-mayhem Secret {sec.name} "
                "(set synthetic=false and an explicit mayhem-* name to force)",
            )
        obj = kubectl_json(sec)
        if obj is None:
            return StepOutcome("inject", False, f"{lease.fault_id}: Secret {sec.name} not found")
        snapshot = {
            "secret": {
                "kind": "Secret",
                "name": sec.name,
                "namespace": target.namespace,
                "type": str(obj.get("type") or "Opaque"),
                "data": dict(obj.get("data") or {}),
            }
        }
        pod_ref = ResourceRef(kind="Pod", name=target.pod, namespace=target.namespace)
        write_annotation(pod_ref, snapshot)
        if not delete_object(sec):
            clear_annotation(pod_ref)
            return StepOutcome(
                "inject", False, f"{lease.fault_id}: delete failed on Secret {sec.name}"
            )
        return StepOutcome("inject", True, f"{lease.fault_id}: deleted Secret {sec.name}")

    def undo(self, lease: FaultLease) -> StepOutcome:
        if lease.fault_id == "k8s.secret_unavailable":
            return self._undo_secret(lease)
        return super().undo(lease)

    def _undo_secret(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedPodTarget):
            return StepOutcome("undo", False, f"{lease.fault_id}: no resolved pod target")
        pod_ref = ResourceRef(kind="Pod", name=target.pod, namespace=target.namespace)
        snapshot = read_snapshot(pod_ref)
        if snapshot is None:
            return StepOutcome(
                "undo", True, f"{lease.fault_id}: no Secret snapshot on pod; nothing to undo"
            )
        secret = snapshot.get("secret")
        if not isinstance(secret, dict) or not secret.get("name"):
            clear_annotation(pod_ref)
            return StepOutcome("undo", False, f"{lease.fault_id}: malformed Secret snapshot")
        manifest = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": secret["name"],
                "namespace": secret.get("namespace") or target.namespace,
            },
            "type": secret.get("type") or "Opaque",
            "data": secret.get("data") or {},
        }
        if not kubectl_apply_json(manifest):
            return StepOutcome("undo", False, f"{lease.fault_id}: Secret recreation failed")
        clear_annotation(pod_ref)
        return StepOutcome("undo", True, f"{lease.fault_id}: recreated Secret {secret['name']}")

    def _restore(self, ref: ResourceRef, snapshot: dict[str, object]) -> bool:
        return apply_patch(ref, {"data": snapshot["data"]})


class K8sStorageExecutor(K8sExecutor):
    """In-pod persistent volume stress / permission faults (k-plan-6 §16–17).

    ``k8s.persistent_volume_delay`` short-circuits a path with ``chattr +i``
    style latency — the pragmatic primitive here is a bounded permission
    change (``chmod 000``) that self-restores after the authored duration:
    callers observe I/O errors / delays without permanent damage.
    ``k8s.persistent_volume_error`` makes the path unreadable/unwritable.

    Both workers are argv-reaped on undo (identical to ``K8sPodPressure``);
    the volume change is the *file mode inside the pod's mount* and is
    confined to the resolved container's mount namespace.
    """

    prefixes = ("k8s.persistent_volume_delay", "k8s.persistent_volume_error")

    def _token(self, lease: FaultLease) -> str:
        safe = "".join(ch for ch in lease.id if ch.isalnum())
        return safe[:24] or "mh"

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id not in self.prefixes:
            return k8s_unsupported_reason(lease.fault_id)
        if not isinstance(lease.resolved_target, ResolvedPodTarget):
            return f"{lease.fault_id}: no resolved pod target on the lease"
        return None

    def inject(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedPodTarget):
            return StepOutcome("inject", False, f"{lease.fault_id}: no resolved pod target")
        params = _lease_fault_params(lease)
        path = str(params.get("volume_path") or preferred_mount_path(target))
        hold = max(1, int(lease.ttl_seconds or 120))
        token = self._token(lease)
        pidfile = f"/tmp/mayhem-{token}.pids"
        if lease.fault_id == "k8s.persistent_volume_delay":
            body = (
                f"chmod 000 {path}; echo $$ > {pidfile}; "
                f"sleep {hold}; chmod 755 {path} 2>/dev/null; rm -f {pidfile}"
            )
        else:
            body = f"chmod 000 {path}; echo $$ > {pidfile}; sleep {hold}; rm -f {pidfile}"
        argv: tuple[str, ...] = (*target.exec_argv, "sh", "-c", body)
        try:
            result = run_tool(argv, timeout_s=60)
        except ToolError as exc:
            return StepOutcome("inject", False, f"{lease.fault_id} exec failed: {exc}")
        if result.exit_code != 0:
            return StepOutcome(
                "inject",
                False,
                f"{lease.fault_id} exec rc={result.exit_code}: {result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "inject",
            True,
            f"{lease.fault_id}: {path} made {self._mode_label(lease)} for {hold}s",
            tool_result=result,
        )

    def _mode_label(self, lease: FaultLease) -> str:
        return (
            "unreadable (I/O error horizon)"
            if lease.fault_id == "k8s.persistent_volume_error"
            else "slow (permission short-circuit)"
        )

    def undo(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if target is None:
            return StepOutcome("undo", False, f"{lease.fault_id}: no resolved target")
        token = self._token(lease)
        sh_cmd = (
            f"r=/tmp/mayhem-{token}.pids; if [ -s $r ]; then cat $r | "
            "xargs kill 2>/dev/null; fi; rm -f $r; rm -rf "
            f"/tmp/mayhem-{token}.* 2>/dev/null"
        )
        argv: tuple[str, ...] = (*target.exec_argv, "sh", "-c", sh_cmd)
        try:
            result = run_tool(argv, timeout_s=30)
        except ToolError as exc:
            return StepOutcome("undo", False, f"{lease.fault_id} cleanup failed: {exc}")
        return StepOutcome(
            "undo",
            result.succeeded,
            f"{lease.fault_id} worker reaped in {target.pod}",
            result,
        )


class K8sPodDeleteExecutor(K8sExecutor):
    """Uncontrolled pod deletion (``kubectl delete --force --grace-period=0``).

    The deletion has no object-level undo: recovery is the pod replacement
    the engine watches (k-plan-6 §12).  Undo is a verified no-op so lease
    release is always clean.
    """

    prefixes = ("k8s.pod_delete_uncontrolled",)

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id != "k8s.pod_delete_uncontrolled":
            return k8s_unsupported_reason(lease.fault_id)
        if not isinstance(lease.resolved_target, ResolvedPodTarget):
            return f"{lease.fault_id}: no resolved pod target on the lease"
        return None

    def inject(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedPodTarget):
            return StepOutcome("inject", False, f"{lease.fault_id}: no resolved pod target")
        ref = ResourceRef(kind="Pod", name=target.pod, namespace=target.namespace)
        if not delete_object(ref, force=True, grace_period=0):
            return StepOutcome(
                "inject", False, f"{lease.fault_id}: force delete failed for {target.pod}"
            )
        return StepOutcome("inject", True, f"{lease.fault_id}: {target.pod} force-deleted")

    def undo(self, lease: FaultLease) -> StepOutcome:
        return StepOutcome(
            "undo",
            True,
            f"{lease.fault_id}: irreversible; pod replacement is the recovery",
        )


class K8sNodeCordonExecutor(K8sExecutor):
    """Cordon a node (no eviction); undo via uncordon (k-plan-6 §19)."""

    prefixes = ("k8s.node_cordon",)

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id != "k8s.node_cordon":
            return k8s_unsupported_reason(lease.fault_id)
        if not isinstance(lease.resolved_target, ResolvedNodeTarget):
            return f"{lease.fault_id}: no resolved node target on the lease"
        return None

    def inject(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedNodeTarget):
            return StepOutcome("inject", False, f"{lease.fault_id}: no resolved node target")
        result = run_tool(("kubectl", "cordon", target.node), timeout_s=30)
        if result.exit_code != 0:
            return StepOutcome(
                "inject",
                False,
                f"{lease.fault_id}: kubectl cordon failed (rc={result.exit_code}): "
                f"{result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "inject", True, f"{lease.fault_id}: node {target.node} cordoned", tool_result=result
        )

    def undo(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedNodeTarget):
            return StepOutcome("undo", False, f"{lease.fault_id}: no resolved node target")
        result = run_tool(("kubectl", "uncordon", target.node), timeout_s=30)
        if result.exit_code != 0:
            return StepOutcome(
                "undo",
                False,
                f"{lease.fault_id}: kubectl uncordon failed (rc={result.exit_code}): "
                f"{result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "undo",
            True,
            f"{lease.fault_id}: node {target.node} schedulable again",
            tool_result=result,
        )


# ── k-plan-6 §24: node-killer families (NODE_CONTROL-gated) ───────────────────


def _sanitize_node(name: str) -> str:
    """k8s-safe object-name fragment for a node name (DNS-1123-ish)."""
    import re as _re  # noqa: PLC0415

    return _re.sub(r"[^a-z0-9-]", "-", (name or "").lower())


def node_control_worker_name(kind: str, node: str) -> str:
    """Deterministic node-pinned worker name for a node-killer family.

    * ``kind="nvidia-smi"`` → ``mayhem-nvidia-smi-<node>``;
    * ``kind="kubelet"``    → ``k8s-kubelet-crash-loop-<node>``;
    * ``kind="containerd"`` → ``k8s-runtime-crash-loop-<node>``.

    Shared between the executors and :func:`mayhem.controller.k8s_runtime.
    k8s_node_undo_ops` so the write-ahead undo contract and the live delete
    name can never drift apart (k-plan-6 §24).
    """
    if kind == "nvidia-smi":
        return "mayhem-nvidia-smi-" + _sanitize_node(node)
    if kind == "kubelet":
        return "k8s-kubelet-crash-loop-" + _sanitize_node(node)
    return "k8s-runtime-crash-loop-" + _sanitize_node(node)


class K8sNodeControlExecutor(K8sExecutor):
    """Node-killer base: held at the NODE_CONTROL admission gate.

    Node-killer families mutate the node's kubelet control-plane (eviction
    taints, GPU probe, container-runtime/kubelet crash loops).  They refuse at
    ``can_apply`` time with :data:`NODE_CONTROL_UNSUPPORTED_MESSAGE` unless the
    kubernetes runtime adapter reports the NODE_CONTROL capability (the M8
    driver seam; ``kubectl get nodes`` must succeed).  The resolved node is
    pinned into the lease at resolution time; a non-node target is always
    refused.
    """

    def can_apply(self, lease: FaultLease) -> str | None:
        if lease.fault_id not in self.prefixes:
            return k8s_unsupported_reason(lease.fault_id)
        if not isinstance(lease.resolved_target, ResolvedNodeTarget):
            return f"{lease.fault_id}: no resolved node target on the lease"
        if not k8s_node_control_supported():
            return NODE_CONTROL_UNSUPPORTED_MESSAGE
        return None

    @staticmethod
    def _params(lease: FaultLease) -> dict[str, object]:
        return _lease_fault_params(lease)


class K8sTaintEvictExecutor(K8sNodeControlExecutor):
    """NoExecute eviction taint on the resolved node (k-plan-6 §24).

    inject applies ``<key>=<value>:<effect>`` (default
    ``mayhem.io/taint-evict=mayhem:NoExecute``) to the node; kubelet then
    voluntarily evicts the node's pods for the lease duration.  undo removes
    the taint — live and reversible.  Removing an already-absent taint is
    idempotent (kubectl ``not found`` still settles OK so undo never dirties).
    """

    prefixes = ("k8s.taint_evict",)

    def _taint_parts(self, lease: FaultLease) -> tuple[str, str, str]:
        params = self._params(lease)
        key = str(params.get("key") or "mayhem.io/taint-evict").strip()
        value = str(params.get("value") or "mayhem").strip()
        effect = str(params.get("effect") or "NoExecute").strip()
        return key or "mayhem.io/taint-evict", value or "mayhem", effect or "NoExecute"

    def inject(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedNodeTarget):
            return StepOutcome("inject", False, f"{lease.fault_id}: no resolved node target")
        key, value, effect = self._taint_parts(lease)
        result = run_tool(
            ("kubectl", "taint", "node", target.node, f"{key}={value}:{effect}"),
            timeout_s=30,
        )
        if result.exit_code != 0:
            return StepOutcome(
                "inject",
                False,
                f"{lease.fault_id}: kubectl taint failed (rc={result.exit_code}): "
                f"{result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "inject",
            True,
            f"{lease.fault_id}: node {target.node} tainted {key}={value}:{effect} "
            "(kubelet will evict its pods for the lease duration)",
            tool_result=result,
        )

    def undo(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedNodeTarget):
            return StepOutcome("undo", False, f"{lease.fault_id}: no resolved node target")
        key, _, effect = self._taint_parts(lease)
        result = run_tool(
            ("kubectl", "taint", "node", target.node, f"{key}:{effect}-"),
            timeout_s=30,
        )
        if result.exit_code != 0 and "not found" not in (result.stdout + result.stderr).lower():
            return StepOutcome(
                "undo",
                False,
                f"{lease.fault_id}: kubectl untaint failed (rc={result.exit_code}): "
                f"{result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "undo",
            True,
            f"{lease.fault_id}: eviction taint {key}:{effect} removed from {target.node}",
            tool_result=result,
        )


class K8sNvidiaSmiErrorExecutor(K8sNodeControlExecutor):
    """Node-local CUDA GPU failure — single-shot nvidia-smi kill policy.

    inject applies a node-pinned DaemonSet worker (``mayhem-nvidia-smi
    -<node>``) — hostPID + privileged, tolerated onto the target node — that,
    each ``interval`` cycle, kills any running ``nvidia-smi`` process (the
    single-shot kill policy: every GPU probe fails) and appends a rotating
    kubelet log line under ``/var/lib/kubelet``.  undo deletes the worker —
    live and reversible (k-plan-6 §24).
    """

    prefixes = ("k8s.nvidia_smi_error",)

    def _worker_name(self, target: ResolvedNodeTarget) -> str:
        return node_control_worker_name("nvidia-smi", target.node)

    def _interval(self, lease: FaultLease) -> int:
        try:
            raw = self._params(lease).get("interval")
            return max(1, min(60, int(float(str(raw or 1)))))
        except (TypeError, ValueError):
            return 1

    def _worker_body(self, lease: FaultLease, target: ResolvedNodeTarget) -> str:
        import json as _json  # noqa: PLC0415

        name = self._worker_name(target)
        interval = self._interval(lease)
        loop = (
            "while :; do for p in $(pidof nvidia-smi 2>/dev/null); do "
            'kill -9 "$p" 2>/dev/null; done; '
            'echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [mayhem] nvidia-smi kill policy '
            f'cycle (interval={interval}s)" >> /var/lib/kubelet/mayhem-nvidia-smi.log; '
            f"sleep {interval}; done"
        )
        body = {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {
                "name": name,
                "labels": {
                    "app.kubernetes.io/name": name,
                    "mayhem.io/fault": "k8s.nvidia_smi_error",
                },
            },
            "spec": {
                "selector": {"matchLabels": {"app": name}},
                "template": {
                    "metadata": {
                        "labels": {"app": name, "mayhem.io/fault": "k8s.nvidia_smi_error"},
                    },
                    "spec": {
                        "nodeName": target.node,
                        "hostPID": True,
                        "tolerations": [{"operator": "Exists"}],
                        "containers": [
                            {
                                "name": "nvidia-smi",
                                "image": "busybox:1.36",
                                "command": ["/bin/sh", "-c", loop],
                                "securityContext": {"privileged": True, "runAsUser": 0},
                                "volumeMounts": [
                                    {"name": "kubelet", "mountPath": "/var/lib/kubelet"}
                                ],
                                "resources": {"requests": {"cpu": "10m"}},
                            }
                        ],
                        "volumes": [{"name": "kubelet", "hostPath": {"path": "/var/lib/kubelet"}}],
                        "restartPolicy": "Always",
                    },
                },
            },
        }
        return _json.dumps(body, separators=(",", ":"))

    def inject(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedNodeTarget):
            return StepOutcome("inject", False, f"{lease.fault_id}: no resolved node target")
        name = self._worker_name(target)
        result = run_tool(
            ("kubectl", "apply", "-f", "-"),
            timeout_s=30,
            stdin_data=self._worker_body(lease, target),
        )
        if result.exit_code != 0:
            return StepOutcome(
                "inject",
                False,
                f"{lease.fault_id}: applying nvidia-smi kill-policy worker failed "
                f"(rc={result.exit_code}): {result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "inject",
            True,
            f"{lease.fault_id}: nvidia-smi kill-policy worker {name} applied to node {target.node}",
            tool_result=result,
        )

    def undo(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedNodeTarget):
            return StepOutcome("undo", False, f"{lease.fault_id}: no resolved node target")
        name = self._worker_name(target)
        result = run_tool(
            ("kubectl", "delete", "daemonset", name, "--ignore-not-found"),
            timeout_s=30,
        )
        if result.exit_code != 0:
            return StepOutcome(
                "undo",
                False,
                f"{lease.fault_id}: deleting nvidia-smi worker {name} failed "
                f"(rc={result.exit_code}): {result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "undo", True, f"{lease.fault_id}: nvidia-smi worker {name} deleted", tool_result=result
        )


class K8sNodeCrashLoopExecutor(K8sNodeControlExecutor):
    """Node-local container-runtime / kubelet crash-loop failure (k-plan-6 §24).

    inject applies a node-pinned DaemonSet worker named
    ``k8s-kubelet-crash-loop-<node>`` (``runtime=kubelet``) or
    ``k8s-runtime-crash-loop-<node>`` (``runtime=containerd``) that repeatedly
    SIGKILLs the node's kubelet / container runtime for ``restarts`` cycles and
    writes rotating crash-loop log entries under ``/var/lib/kubelet`` (the
    node's runtime kubelet); the temp marker file is ``<worker>-tmp``.  The
    loop self-terminates after ``restarts``; undo deletes the worker — live
    and reversible, and idempotent via ``--ignore-not-found``.
    """

    prefixes = ("k8s.crash_loop",)

    def _runtime(self, lease: FaultLease) -> str:
        value = str(self._params(lease).get("runtime") or "kubelet").strip().lower()
        return "kubelet" if value == "kubelet" else "containerd"

    def _restarts(self, lease: FaultLease) -> int:
        try:
            raw = self._params(lease).get("restarts")
            return max(1, min(1000, int(float(str(raw or 10)))))
        except (TypeError, ValueError):
            return 10

    def _worker_name(self, target: ResolvedNodeTarget, lease: FaultLease | None = None) -> str:
        runtime = self._runtime(lease) if lease is not None else "kubelet"
        return node_control_worker_name(runtime, target.node)

    def _worker_body(self, lease: FaultLease, target: ResolvedNodeTarget) -> str:
        import json as _json  # noqa: PLC0415

        runtime = self._runtime(lease)
        restarts = self._restarts(lease)
        name = self._worker_name(target, lease)
        proc = "kubelet" if runtime == "kubelet" else "containerd"
        log_path = "/var/lib/kubelet/mayhem-kubelet-crash-loop.log"
        loop = (
            f": > /var/lib/kubelet/{name}-tmp; i=0; "
            f'while [ "$i" -lt {restarts} ]; do '
            f'for p in $(pidof {proc} 2>/dev/null); do kill -9 "$p" 2>/dev/null; done; '
            f'echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) [mayhem] {proc} crash-loop '
            f'cycle $i/{restarts}" >> {log_path}; '
            f"i=$((i+1)); sleep 1; done; "
            f"touch /var/lib/kubelet/{name}.finished 2>/dev/null || true"
        )
        volumes = [
            {"name": "kubelet", "hostPath": {"path": "/var/lib/kubelet"}},
        ]
        mounts = [{"name": "kubelet", "mountPath": "/var/lib/kubelet"}]
        if runtime == "containerd":
            volumes.append({"name": "containerd", "hostPath": {"path": "/var/lib/containerd"}})
            mounts.append({"name": "containerd", "mountPath": "/var/lib/containerd"})
        body = {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {
                "name": name,
                "labels": {"app.kubernetes.io/name": name, "mayhem.io/fault": "k8s.crash_loop"},
            },
            "spec": {
                "selector": {"matchLabels": {"app": name}},
                "template": {
                    "metadata": {
                        "labels": {"app": name, "mayhem.io/fault": "k8s.crash_loop"},
                    },
                    "spec": {
                        "nodeName": target.node,
                        "hostPID": True,
                        "tolerations": [{"operator": "Exists"}],
                        "containers": [
                            {
                                "name": "crash-loop",
                                "image": "busybox:1.36",
                                "command": ["/bin/sh", "-c", loop],
                                "securityContext": {"privileged": True, "runAsUser": 0},
                                "volumeMounts": mounts,
                                "resources": {"requests": {"cpu": "10m"}},
                            }
                        ],
                        "volumes": volumes,
                        "restartPolicy": "Always",
                    },
                },
            },
        }
        return _json.dumps(body, separators=(",", ":"))

    def inject(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedNodeTarget):
            return StepOutcome("inject", False, f"{lease.fault_id}: no resolved node target")
        name = self._worker_name(target, lease)
        result = run_tool(
            ("kubectl", "apply", "-f", "-"),
            timeout_s=30,
            stdin_data=self._worker_body(lease, target),
        )
        if result.exit_code != 0:
            return StepOutcome(
                "inject",
                False,
                f"{lease.fault_id}: applying crash-loop worker failed "
                f"(rc={result.exit_code}): {result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "inject",
            True,
            f"{lease.fault_id}: {self._runtime(lease)} crash-loop worker {name} "
            f"applied to node {target.node} (restarts={self._restarts(lease)})",
            tool_result=result,
        )

    def undo(self, lease: FaultLease) -> StepOutcome:
        target = lease.resolved_target
        if not isinstance(target, ResolvedNodeTarget):
            return StepOutcome("undo", False, f"{lease.fault_id}: no resolved node target")
        name = self._worker_name(target, lease)
        result = run_tool(
            ("kubectl", "delete", "daemonset", name, "--ignore-not-found"),
            timeout_s=30,
        )
        if result.exit_code != 0:
            return StepOutcome(
                "undo",
                False,
                f"{lease.fault_id}: deleting crash-loop worker {name} failed "
                f"(rc={result.exit_code}): {result.stdout.strip()}",
                tool_result=result,
            )
        return StepOutcome(
            "undo", True, f"{lease.fault_id}: crash-loop worker {name} deleted", tool_result=result
        )


def _serialize(snapshot: dict[str, object]) -> str:
    import json as _json  # noqa: PLC0415

    return _json.dumps(snapshot, sort_keys=True)


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
    "cpu.saturate": K8sArgvExecutor,
    "cpu.throttle": K8sArgvExecutor,
    "mem.exhaust": K8sArgvExecutor,
    "mem.leak": K8sArgvExecutor,
    "fs.fill": K8sArgvExecutor,
    "fs.inode_exhaust": K8sArgvExecutor,
    "fs.io_stress": K8sArgvExecutor,
    "fd.exhaust": K8sArgvExecutor,
    "net.latency": K8sArgvExecutor,
    "net.packet_loss": K8sArgvExecutor,
    "net.duplicate": K8sArgvExecutor,
    "net.reorder": K8sArgvExecutor,
    "net.bandwidth": K8sArgvExecutor,
    "net.partition": K8sArgvExecutor,
    # ── k-plan-6: next-20 controller-level families (docs/k8s-new.md) ────────
    "k8s.pod_readiness_fail": K8sWorkloadExecutor,
    "k8s.pod_liveness_fail": K8sWorkloadExecutor,
    "k8s.pod_startup_fail": K8sWorkloadExecutor,
    "k8s.pod_unschedulable": K8sWorkloadExecutor,
    "k8s.schedule_delay": K8sWorkloadExecutor,
    "k8s.image_pull_failure": K8sWorkloadExecutor,
    "k8s.replica_reduce": K8sWorkloadExecutor,
    "k8s.rollout_pause": K8sWorkloadExecutor,
    "k8s.rollout_failure": K8sWorkloadExecutor,
    "k8s.persistent_volume_detach": K8sWorkloadExecutor,
    "k8s.service_no_endpoints": K8sServiceExecutor,
    "k8s.service_endpoint_flap": K8sServiceExecutor,
    "k8s.service_port_mismatch": K8sServiceExecutor,
    "k8s.configmap_corrupt": K8sConfigExecutor,
    "k8s.secret_unavailable": K8sConfigExecutor,
    "k8s.persistent_volume_delay": K8sStorageExecutor,
    "k8s.persistent_volume_error": K8sStorageExecutor,
    "k8s.pod_delete_uncontrolled": K8sPodDeleteExecutor,
    "k8s.node_cordon": K8sNodeCordonExecutor,
    # ── k-plan-6 §24: node-killer families (NODE_CONTROL-gated) ───────────────
    "k8s.taint_evict": K8sTaintEvictExecutor,
    "k8s.nvidia_smi_error": K8sNvidiaSmiErrorExecutor,
    "k8s.crash_loop": K8sNodeCrashLoopExecutor,
    # ── k-plan-2 §14–§15: HPA scale mutations ────────────────────────────────
    "k8s.hpa_scale_delay": K8sHpaExecutor,
    "k8s.hpa_scale_failure": K8sHpaExecutor,
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
    except Exception:
        return False
    try:
        definition = definition_for(fault_id)
    except Exception:
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
