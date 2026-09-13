"""Execution-time Kubernetes target resolution (k-plan-3 §3.1/§3.4).

The frozen plan pins the logical workload; this resolver is invoked before
every injection round (and by the impact gate) to produce the *resolved pod*
that actually receives the fault. Flow (ADR-M7-1 §3.1):

  1. locate the workload via the cluster client (deployment/statefulset/…);
  2. fetch its eligible pods (``Running``, not terminating);
  3. pick one — ``preferred_pod`` from plan-time mode-one selection when it is
     still eligible, otherwise the deterministic first eligible pod (recorded
     as ``drift``);
  4. require the named container to exist in the pod spec;
  5. capture the evidence block (pod uid, container id, node) into a
     :class:`ResolvedPodTarget` (migration 0017 persists it on the lease).

Failures raise the stable error taxonomy:
``resolution.resource_missing`` (workload/pod gone), ``resolution.container_missing``
(named container absent), ``selection.no_eligible_pods`` (none Running).

Cluster I/O goes through the :class:`K8sClusterClient` protocol so unit tests
can drive the resolver with a fake client and no cluster.
"""

from __future__ import annotations

import importlib.util
import shutil
from dataclasses import dataclass, field
from typing import Protocol

from mayhem.domain.errors import ResolutionError, SelectionError
from mayhem.domain.experiments import TargetScope
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.resolution import ResolvedPodTarget


# ── client protocol ──────────────────────────────────────────────────────────
@dataclass(frozen=True)
class K8sContainerStatus:
    """``PodStatus.ContainerStatuses[]`` field the resolver actually reads."""

    name: str
    container_id: str = ""  # e.g. "containerd://06ab…" — runtime + uid evidence
    ready: bool = True


@dataclass(frozen=True)
class K8sPod:
    """The pod facts resolution needs (a filtered view of a live Pod object)."""

    uid: str
    name: str
    namespace: str
    phase: str  # "Running" | "Pending" | …
    node: str = ""
    deletion_timestamp: str | None = None
    containers: tuple[K8sContainerStatus, ...] = field(default_factory=tuple)
    creation_timestamp: str = ""

    @property
    def eligible(self) -> bool:
        """k-plan-2 §2.5: Running and not terminating."""
        return self.phase == "Running" and not self.deletion_timestamp


@dataclass(frozen=True)
class K8sWorkload:
    """Logical workload descriptor resolved from the scope authority."""

    namespace: str = "default"
    kind: str = "deployment"  # deployment | statefulset | daemonset | pod
    name: str = ""


class K8sClusterClient(Protocol):
    """The single cluster-facing seam (SDK client implements it; tests fake it)."""

    def workload(self, workload: K8sWorkload) -> K8sWorkload | None:
        """Return the workload when it exists, ``None`` when the API 404s."""
        ...

    def pods_for(self, workload: K8sWorkload) -> list[K8sPod]:
        """Every pod selected by the workload's label selector (no filtering)."""
        ...

    def exec(self, target: ResolvedPodTarget, argv: tuple[str, ...]) -> str:
        """Run ``argv`` inside the container; return stdout. Raises on rc != 0."""
        ...


# ── SDK-backed client ────────────────────────────────────────────────────────
@dataclass(frozen=True)
class SdkK8sClient:
    """kubectl-backed client (SP-3.3's kubectl gate; no mandatory SDK import).

    Discovery uses ``kubectl get`` JSON output through a hidden subprocess so
    the resolver stays usable in environments without the ``kubernetes``
    python package; ``exec`` shells out to ``kubectl exec``. This keeps the
    module importable and unit-testable everywhere (kubectl is only touched
    when actually used).
    """

    kubectl: str = "kubectl"

    @classmethod
    def available(cls) -> bool:
        if shutil.which("kubectl") is not None:
            return True
        return importlib.util.find_spec("kubernetes") is not None

    def workload(self, workload: K8sWorkload) -> K8sWorkload | None:  # pragma: no cover
        raise NotImplementedError("live cluster client: wired with the k-plan-6 driver")

    def pods_for(self, workload: K8sWorkload) -> list[K8sPod]:  # pragma: no cover
        raise NotImplementedError("live cluster client: wired with the k-plan-6 driver")

    def exec(self, target: ResolvedPodTarget, argv: tuple[str, ...]) -> str:  # pragma: no cover
        raise NotImplementedError("live cluster client: wired with the k-plan-6 driver")


def default_client() -> K8sClusterClient | None:
    """The process-wide client, lazily built once (kubectl gate, SP-3.3)."""
    return SdkK8sClient() if SdkK8sClient.available() else None


# ── resolver ────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class ResolutionOutcome:
    resolved: ResolvedPodTarget | None = None
    drift: bool = False          # live pick differs from plan-time preferred pod
    note: str = ""               # human-readable evidence summary


def _workload_from_scope(scope: TargetScope) -> K8sWorkload:
    authority = scope.authority
    return K8sWorkload(
        namespace=str(authority.get("namespace") or "default"),
        kind=str(authority.get("kind") or "deployment"),
        name=str(authority.get("name") or ""),
    )


def _exec_base(target: ResolvedPodTarget, kubectl: str = "kubectl") -> tuple[str, ...]:
    """The kubectl exec argv prefix for a resolved pod (evidence shape §3.4).

    The executor appends the actual command; this base is what the
    ``ResolvedPodTarget.exec_argv`` record carries so a persisted lease shows
    exactly how the mutation would be (and was) delivered.
    """
    return (
        kubectl,
        "exec",
        "-n",
        target.namespace,
        f"pod/{target.pod}",
        "-c",
        target.container,
        "--",
    )


def _parse_proc_stat(line: str) -> tuple[int, int]:
    """Parse ``/proc/<pid>/stat`` into (pid, start_time_ticks).

    ``comm`` may contain spaces and parenthesis, so split on the *last* ``)``:
    the pid is the token before the comm parens, ``starttime`` (field 22) is
    the 20th field after them.
    """
    head, _, tail = line.rpartition(")")
    fields = tail.split()
    if len(fields) < 20:
        raise ResolutionError(
            "resolution.primary_pid_unreadable",
            f"unexpected stat line: {line[:80]!r}",
        )
    try:
        pid = int(line.split(None, 1)[0])
        return pid, int(fields[19])
    except ValueError as exc:
        raise ResolutionError(
            "resolution.primary_pid_unreadable",
            f"unparseable stat line: {line[:80]!r}",
        ) from exc


class KubernetesRuntimeResolver:
    """Resolves a logical k8s scope to the exact pod that gets mutated."""

    KIBL = "sh"  # command language inside the container for the pid guard

    def __init__(
        self,
        client: K8sClusterClient | None = None,
        *,
        kubectl: str = "kubectl",
        timeout_s: float = 30.0,
    ) -> None:
        self._client = client if client is not None else default_client()
        self._kubectl = kubectl
        self._timeout_s = timeout_s

    @property
    def available(self) -> bool:
        return self._client is not None

    def resolve(
        self,
        scope: TargetScope,
        *,
        preferred_pod: str | None = None,
    ) -> ResolutionOutcome:
        """Run the 7-step resolution flow against the scoped workload."""
        if scope.runtime != RuntimeLabel.KUBERNETES:
            raise ResolutionError(
                "resolution.wrong_runtime",
                f"resolver only handles kubernetes scopes, got {scope.runtime}",
            )
        if self._client is None:
            raise ResolutionError(
                "resolution.no_client",
                "no cluster client available (kubectl not on PATH, SDK not importable)",
            )
        workload = _workload_from_scope(scope)
        if workload.name in ("", "*"):
            raise ResolutionError(
                "resolution.resource_missing",
                f"scope {scope.logical_id!r} has no concrete workload name to resolve",
            )
        if workload.kind != "pod":
            live = self._client.workload(workload)
            if live is None:
                raise ResolutionError(
                    "resolution.resource_missing",
                    f"{workload.kind}/{workload.name} not found in namespace {workload.namespace}",
                )
        pods = [pod for pod in self._client.pods_for(workload) if pod.eligible]
        if not pods:
            raise SelectionError(
                "selection.no_eligible_pods",
                f"no Running pod for {workload.kind}/{workload.name} in "
                f"namespace {workload.namespace}",
            )
        pod = self._select(pods, preferred_pod)
        drift = preferred_pod is not None and pod.name != preferred_pod
        container_name = getattr(scope, "container", None) or "app"
        statuses = {c.name: c for c in pod.containers}
        if container_name not in statuses:
            raise ResolutionError(
                "resolution.container_missing",
                f"container {container_name!r} absent from pod {pod.name} "
                f"(have: {', '.join(sorted(statuses)) or 'none'})",
            )
        status = statuses[container_name]
        target = ResolvedPodTarget(
            namespace=pod.namespace or "default",
            pod=pod.name,
            container=container_name,
            pod_uid=pod.uid,
            container_id=status.container_id,
            node=pod.node,
            exec_argv=_exec_base(
                ResolvedPodTarget(
                    namespace=pod.namespace or "default",
                    pod=pod.name,
                    container=container_name,
                ),
                self._kubectl,
            ),
        )
        note = (
            f"resolved {target.authority_key} container={container_name}"
            f" node={pod.node or '?'} runtime={target.container_runtime or '?'}"
        )
        if drift:
            note += f" (drift from planned pod {preferred_pod!r})"
        return ResolutionOutcome(resolved=target, drift=drift, note=note)

    def read_primary_pid(self, target: ResolvedPodTarget) -> tuple[int, int]:
        """Container-ns (pid, boot_time) of the primary process (``/proc/1/stat``).

        Feeds the signal family's PID-reuse guard — the same discipline as the
        docker ``proc.pause`` boot_time check (ADR-M2 Phase 2.4): a recycled
        PID 1 (container restart) is never signalled.
        """
        if self._client is None:
            raise ResolutionError("resolution.no_client", "no cluster client available")
        stdout = self._client.exec(target, (*target.exec_argv, "cat", "/proc/1/stat"))
        pid, boot = _parse_proc_stat(stdout.strip())
        if pid != 1:
            raise ResolutionError(
                "resolution.primary_pid_unreadable",
                f"container primary pid mismatch: expected 1, got {pid}",
            )
        return pid, boot

    @staticmethod
    def _select(pods: list[K8sPod], preferred_pod: str | None) -> K8sPod:
        """Deterministic mode-one pick: preferred when still eligible, else the
        lexicographically-first eligible pod (matches the planner's stable ordering)."""
        if preferred_pod is not None:
            for pod in pods:
                if pod.name == preferred_pod:
                    return pod
        return min(pods, key=lambda pod: (pod.creation_timestamp or "", pod.name))