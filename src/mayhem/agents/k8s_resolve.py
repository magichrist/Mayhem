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

import functools
import json
import math
import random
import shutil
import zlib
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from mayhem.domain.errors import InvariantViolationError, ResolutionError, SelectionError
from mayhem.domain.identity import RuntimeLabel
from mayhem.domain.resolution import ResolvedNodeTarget, ResolvedPodTarget
from mayhem.domain.target import SelectionMode, SelectionSpec
from mayhem.toolkit.tool_runner import ToolResult, run_tool

if TYPE_CHECKING:
    from mayhem.domain.experiments import TargetScope


class K8sEngineMode(StrEnum):
    MANIFEST = "manifest"
    LIVE = "live"
    DRY_RUN = "dry-run"


@dataclass(frozen=True)
class K8sTargetContext:
    context: str | None = None
    namespace: str | None = None
    workload_selector: str | None = None
    capability_policy: str | None = None
    mode: K8sEngineMode = K8sEngineMode.LIVE
    target_profile: str | None = None


def _reject_conflicting_selection(
    *,
    field: str,
    profile_value: str | None,
    explicit_value: str | None,
) -> str | None:
    if profile_value is not None and explicit_value is not None and profile_value != explicit_value:
        raise InvariantViolationError(
            "k8s.selection_ambiguous",
            f"conflicting Kubernetes {field}: profile={profile_value!r} "
            f"explicit={explicit_value!r}",
        )
    return explicit_value if explicit_value is not None else profile_value


def resolve_k8s_target_context(
    *,
    profile_context: str | None = None,
    explicit_context: str | None = None,
    profile_namespace: str | None = None,
    explicit_namespace: str | None = None,
    profile_workload_selector: str | None = None,
    workload_selector: str | None = None,
    profile_capability_policy: str | None = None,
    capability_policy: str | None = None,
    target_profile: str | None = None,
    mode: str | K8sEngineMode | None = None,
) -> K8sTargetContext:
    context = _reject_conflicting_selection(
        field="context", profile_value=profile_context, explicit_value=explicit_context
    )
    namespace = _reject_conflicting_selection(
        field="namespace", profile_value=profile_namespace, explicit_value=explicit_namespace
    )
    selected_workload_selector = _reject_conflicting_selection(
        field="workload selector",
        profile_value=profile_workload_selector,
        explicit_value=workload_selector,
    )
    selected_capability_policy = _reject_conflicting_selection(
        field="capability policy",
        profile_value=profile_capability_policy,
        explicit_value=capability_policy,
    )
    if mode is None:
        resolved_mode = K8sEngineMode.LIVE
    elif isinstance(mode, K8sEngineMode):
        resolved_mode = mode
    else:
        try:
            resolved_mode = K8sEngineMode(mode)
        except ValueError as exc:
            raise InvariantViolationError(
                "k8s.mode_invalid",
                f"invalid Kubernetes engine mode {mode!r}; choose manifest, live, or dry-run",
            ) from exc
    return K8sTargetContext(
        context=context,
        namespace=namespace,
        workload_selector=selected_workload_selector,
        capability_policy=selected_capability_policy,
        mode=resolved_mode,
        target_profile=target_profile,
    )


@dataclass(frozen=True)
class K8sDiscoveryStatus:
    manifest_available: bool
    live_ready: bool
    sdk_available: bool
    client_available: bool
    context: str | None
    namespace: str | None
    error: str = ""
    warning: str = ""

    @property
    def healthy(self) -> bool:
        return self.live_ready and self.sdk_available and self.client_available


def discover_k8s_status(
    *,
    manifest_path: str | None = None,
    client: K8sClusterClient | None = None,
    sdk_available: bool = True,
    context: str | None = None,
    namespace: str | None = None,
) -> K8sDiscoveryStatus:
    manifest_available = discover_k8s_manifest_available(manifest_path)
    if client is None:
        warning = (
            "Kubernetes live client is unavailable; manifest inspection may still be available"
        )
        return K8sDiscoveryStatus(
            manifest_available=manifest_available,
            live_ready=False,
            sdk_available=sdk_available,
            client_available=False,
            context=context,
            namespace=namespace,
            warning=warning,
        )
    if not sdk_available:
        return K8sDiscoveryStatus(
            manifest_available=manifest_available,
            live_ready=False,
            sdk_available=False,
            client_available=True,
            context=context,
            namespace=namespace,
            error="Kubernetes SDK is unavailable",
        )
    try:
        if hasattr(client, "nodes"):
            client.nodes()  # type: ignore[attr-defined]
    except Exception as exc:
        return K8sDiscoveryStatus(
            manifest_available=manifest_available,
            live_ready=False,
            sdk_available=True,
            client_available=True,
            context=context,
            namespace=namespace,
            error=f"Kubernetes live readiness probe failed: {exc}",
        )
    return K8sDiscoveryStatus(
        manifest_available=manifest_available,
        live_ready=True,
        sdk_available=True,
        client_available=True,
        context=context,
        namespace=namespace,
    )


def discover_k8s_manifest_available(manifest_path: str | None) -> bool:
    return manifest_path is not None and Path(manifest_path).is_file()


def discover_k8s_live_ready(client: K8sClusterClient | None) -> bool:
    return discover_k8s_status(client=client).live_ready


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
    labels: dict[str, str] = field(default_factory=dict)

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


@dataclass(frozen=True)
class K8sNodeInfo:
    """The node facts node-level resolution needs (k-plan-5 §5.1)."""

    name: str
    uid: str = ""
    ready: bool = False  # NodeReady condition
    unschedulable: bool = False  # node.Spec.Unschedulable
    labels: dict[str, str] = field(default_factory=dict)
    allocatable: dict[str, str] = field(default_factory=dict)  # cpu="4", memory="8Gi", …

    @property
    def schedulable(self) -> bool:
        return not self.unschedulable


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

    def node(self, name: str) -> K8sNodeInfo | None:
        """Return the node when it exists, ``None`` when the API 404s."""
        ...

    def nodes(self) -> list[K8sNodeInfo]:
        """Every cluster node (no filtering)."""
        ...


# ── kubectl-backed client (SP-4.3 live driver) ─────────────────────────────
@dataclass(frozen=True)
class SdkK8sClient:
    """kubectl-backed live cluster client (k-plan-4 §4.3).

    Discovery runs ``kubectl get`` JSON through :func:`mayhem.toolkit.tool_runner.run_tool`
    so the resolver stays usable without the ``kubernetes`` python package;
    ``exec`` shells out to ``kubectl exec``.  ``available()`` requires both a
    ``kubectl`` binary on PATH *and* a reachable kubeconfig context so the
    adapter's capability matrix only reports the driver as usable when a
    cluster is actually reachable.
    """

    kubectl: str = "kubectl"
    timeout_s: float = 30.0  # per-invocation kubectl budget
    context: str | None = None

    @classmethod
    @functools.lru_cache(maxsize=1)
    def available(cls) -> bool:
        if shutil.which(cls.kubectl) is None:
            return False
        try:
            result = run_tool(
                (cls.kubectl, "config", "current-context", "--request-timeout", "5s"),
                timeout_s=6,
            )
        except Exception:
            return False
        return result.succeeded and bool(result.stdout.strip())

    @staticmethod
    def _not_found(result: ToolResult) -> bool:
        return result.exit_code != 0 and "not found" in result.stderr

    def _run(
        self,
        argv: tuple[str, ...] | list[str],
        *,
        stdin_data: str | None = None,
    ) -> ToolResult:
        command = tuple(argv)
        if self.context and "--context" not in command:
            command = (command[0], "--context", self.context, *command[1:])
        return run_tool(command, timeout_s=self.timeout_s, stdin_data=stdin_data)

    def workload(self, workload: K8sWorkload) -> K8sWorkload | None:
        outcome = self._run(
            (
                self.kubectl,
                "get",
                str(workload.kind),
                workload.name,
                "-n",
                workload.namespace or "default",
                "-o",
                "json",
            )
        )
        if self._not_found(outcome):
            return None
        if not outcome.succeeded:
            raise ResolutionError(
                "resolution.resource_missing",
                f"kubectl get {workload.kind}/{workload.name} failed: "
                f"{outcome.stderr.strip()[:200]}",
            )
        try:
            document = json.loads(outcome.stdout)
        except json.JSONDecodeError as exc:
            raise ResolutionError(
                "resolution.resource_missing",
                f"unparseable workload JSON for {workload.kind}/{workload.name}",
            ) from exc
        metadata = document.get("metadata") or {}
        return K8sWorkload(
            namespace=metadata.get("namespace") or workload.namespace or "default",
            kind=workload.kind,
            name=metadata.get("name") or workload.name,
        )

    def pods_for(self, workload: K8sWorkload) -> list[K8sPod]:
        namespace = workload.namespace or "default"
        if str(workload.kind) == "pod":
            outcome = self._run(
                (
                    self.kubectl,
                    "get",
                    "pod",
                    workload.name,
                    "-n",
                    namespace,
                    "-o",
                    "json",
                )
            )
            if self._not_found(outcome):
                raise ResolutionError(
                    "resolution.resource_missing",
                    f"pod/{workload.name} not found in namespace {namespace}",
                )
            if not outcome.succeeded:
                raise ResolutionError(
                    "resolution.resource_missing",
                    f"kubectl get pod {workload.name} failed: {outcome.stderr.strip()[:200]}",
                )
            return [self._pod_from_json(json.loads(outcome.stdout))]
        workload_json = self._run(
            (
                self.kubectl,
                "get",
                str(workload.kind),
                workload.name,
                "-n",
                namespace,
                "-o",
                "json",
            )
        )
        if self._not_found(workload_json):
            raise ResolutionError(
                "resolution.resource_missing",
                f"{workload.kind}/{workload.name} not found in namespace {namespace}",
            )
        if not workload_json.succeeded:
            raise ResolutionError(
                "resolution.resource_missing",
                f"kubectl get {workload.kind}/{workload.name} failed: "
                f"{workload_json.stderr.strip()[:200]}",
            )
        selector = ((json.loads(workload_json.stdout).get("spec") or {}).get("selector") or {}).get(
            "matchLabels"
        ) or {}
        selector_argv = ",".join(f"{k}={v}" for k, v in sorted(selector.items()))
        pods_outcome = self._run(
            (
                self.kubectl,
                "get",
                "pods",
                "-n",
                namespace,
                "-l",
                selector_argv,
                "-o",
                "json",
            )
        )
        if not pods_outcome.succeeded:
            raise ResolutionError(
                "resolution.resource_missing",
                f"kubectl get pods (selector {selector_argv!r}) failed: "
                f"{pods_outcome.stderr.strip()[:200]}",
            )
        try:
            items = (json.loads(pods_outcome.stdout) or {}).get("items", [])
        except json.JSONDecodeError as exc:
            raise ResolutionError(
                "resolution.resource_missing", "unparseable pod list JSON"
            ) from exc
        return [self._pod_from_json(document) for document in items]

    @staticmethod
    def _pod_from_json(document: dict[str, object]) -> K8sPod:
        metadata = document.get("metadata") or {}
        status = document.get("status") or {}
        spec = document.get("spec") or {}
        container_statuses = {}
        for entry in status.get("containerStatuses") or []:
            if isinstance(entry, dict):
                container_statuses[str(entry.get("name") or "")] = K8sContainerStatus(
                    name=str(entry.get("name") or ""),
                    container_id=str(entry.get("containerID") or ""),
                    ready=bool(entry.get("ready")),
                )
        containers = tuple(
            container_statuses.get(str(entry.get("name") or ""))
            or K8sContainerStatus(name=str(entry.get("name") or ""))
            for entry in spec.get("containers") or []
            if isinstance(entry, dict)
        )
        return K8sPod(
            uid=str(metadata.get("uid") or ""),
            name=str(metadata.get("name") or ""),
            namespace=str(metadata.get("namespace") or "default"),
            phase=str(status.get("phase") or ""),
            node=str(spec.get("nodeName") or ""),
            deletion_timestamp=(
                str(metadata["deletionTimestamp"]) if metadata.get("deletionTimestamp") else None
            ),
            containers=containers,
            creation_timestamp=str(metadata.get("creationTimestamp") or ""),
            labels={
                str(k): str(v)
                for k, v in (metadata.get("labels") or {}).items()
                if isinstance(v, (str, int, float, bool))
            },
        )

    def node(self, name: str) -> K8sNodeInfo | None:
        outcome = self._run((self.kubectl, "get", "node", name, "-o", "json"))
        if self._not_found(outcome):
            return None
        if not outcome.succeeded:
            raise ResolutionError(
                "resolution.resource_missing",
                f"kubectl get node {name} failed: {outcome.stderr.strip()[:200]}",
            )
        try:
            return self._node_from_json(json.loads(outcome.stdout))
        except json.JSONDecodeError as exc:
            raise ResolutionError(
                "resolution.resource_missing", f"unparseable node JSON for {name!r}"
            ) from exc

    def nodes(self) -> list[K8sNodeInfo]:
        outcome = self._run((self.kubectl, "get", "nodes", "-o", "json"))
        if not outcome.succeeded:
            raise ResolutionError(
                "resolution.resource_missing",
                f"kubectl get nodes failed: {outcome.stderr.strip()[:200]}",
            )
        try:
            items = (json.loads(outcome.stdout) or {}).get("items", [])
        except json.JSONDecodeError as exc:
            raise ResolutionError(
                "resolution.resource_missing", "unparseable node list JSON"
            ) from exc
        return [self._node_from_json(document) for document in items]

    @staticmethod
    def _node_from_json(document: dict[str, object]) -> K8sNodeInfo:
        metadata = document.get("metadata") or {}
        status = document.get("status") or {}
        spec = document.get("spec") or {}
        conditions = {}
        for entry in status.get("conditions") or []:
            if isinstance(entry, dict):
                conditions[str(entry.get("type") or "")] = str(entry.get("status") or "")
        allocatable = {
            str(k): str(v)
            for k, v in ((status.get("allocatable") or {}).items())
            if isinstance(v, (str, int, float))
        }
        return K8sNodeInfo(
            name=str(metadata.get("name") or ""),
            uid=str(metadata.get("uid") or ""),
            ready=conditions.get("Ready") == "True",
            unschedulable=bool(spec.get("unschedulable")),
            labels={
                str(k): str(v)
                for k, v in (metadata.get("labels") or {}).items()
                if isinstance(v, (str, int, float, bool))
            },
            allocatable=allocatable,
        )

    def exec(self, target: ResolvedPodTarget, argv: tuple[str, ...]) -> str:
        head, _, tail = argv, "--", ()
        if "--" in argv:
            head, _, tail = argv.partition("--")
        outcome = self._run((*head, "--request-timeout", f"{self.timeout_s}s", "--", *tail))
        if not outcome.succeeded:
            raise ResolutionError(
                "resolution.exec_failed",
                f"kubectl exec into {target.authority_key} failed "
                f"(rc={outcome.exit_code}): {outcome.stderr.strip()[:200]}",
            )
        return outcome.stdout


def default_client(context: str | None = None) -> K8sClusterClient | None:
    """Build the kubectl-backed client when the local kubectl gate is present."""
    return SdkK8sClient(context=context) if SdkK8sClient.available() else None


# ── resolver ────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class ResolutionOutcome:
    resolved: ResolvedPodTarget | None = None
    drift: bool = False  # live pick differs from plan-time preferred pod
    note: str = ""  # human-readable evidence summary


def _workload_from_scope(scope: TargetScope) -> K8sWorkload:
    authority = scope.authority
    return K8sWorkload(
        namespace=str(authority.get("namespace") or "default"),
        kind=str(authority.get("kind") or "deployment"),
        name=str(authority.get("name") or ""),
    )


def _exec_base(
    target: ResolvedPodTarget, kubectl: str = "kubectl", context: str | None = None
) -> tuple[str, ...]:
    """The kubectl exec argv prefix for a resolved pod (evidence shape §3.4).

    The executor appends the actual command; this base is what the
    ``ResolvedPodTarget.exec_argv`` record carries so a persisted lease shows
    exactly how the mutation would be (and was) delivered.
    """
    context_args = ("--context", context) if context else ()
    return (
        kubectl,
        *context_args,
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
    _, _, tail = line.rpartition(")")

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
        context: str | None = None,
    ) -> None:
        self._client = client if client is not None else default_client(context)
        self._kubectl = kubectl
        self._timeout_s = timeout_s
        self._context = context

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
        target = self._build_target(pod, container_name, status)
        note = (
            f"resolved {target.authority_key} container={container_name}"
            f" node={pod.node or '?'} runtime={target.container_runtime or '?'}"
        )
        if drift:
            note += f" (drift from planned pod {preferred_pod!r})"
        return ResolutionOutcome(resolved=target, drift=drift, note=note)

    def _build_target(
        self,
        pod: K8sPod,
        container_name: str,
        status: K8sContainerStatus,
    ) -> ResolvedPodTarget:
        """Materialize the evidence record for one selected pod (k-plan-4 §4.4)."""
        return ResolvedPodTarget(
            namespace=pod.namespace or "default",
            pod=pod.name,
            container=container_name,
            pod_uid=pod.uid,
            container_id=status.container_id,
            node=pod.node,
            labels=dict(pod.labels),
            exec_argv=_exec_base(
                ResolvedPodTarget(
                    namespace=pod.namespace or "default",
                    pod=pod.name,
                    container=container_name,
                ),
                self._kubectl,
                self._context,
            ),
        )

    def resolve_many(
        self,
        scope: TargetScope,
        *,
        pod_action: str = "",
    ) -> list[ResolutionOutcome]:
        """Resolve the scoped workload to every pod the selection mode picks.

        k-plan-4 §4.2/§4.4: count/percentage/all/random/one are re-resolved
        against the *live* eligible set at injection time (the graph's pod set
        is only the plan-time view).  Each picked pod gets its own evidence
        record; the caller leases one pod per outcome.
        """
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
        picked = self._select_many(scope, pods)
        container_name = getattr(scope, "container", None) or "app"
        outcomes: list[ResolutionOutcome] = []
        for pod in picked:
            statuses = {c.name: c for c in pod.containers}
            if container_name not in statuses:
                raise ResolutionError(
                    "resolution.container_missing",
                    f"container {container_name!r} absent from pod {pod.name} "
                    f"(have: {', '.join(sorted(statuses)) or 'none'})",
                )
            target = self._build_target(pod, container_name, statuses[container_name])
            target = target.model_copy(
                update={"pod_action": pod_action},
            )
            note = (
                f"resolved {target.authority_key} container={container_name}"
                f" node={pod.node or '?'} action={pod_action or 'n/a'}"
            )
            outcomes.append(ResolutionOutcome(resolved=target, drift=False, note=note))
        return outcomes

    def resolve_node(
        self,
        scope: TargetScope,
        *,
        node_name: str | None = None,
    ) -> ResolutionOutcome:
        """Resolve a k8s *node* scope to the exact cluster node (k-plan-5 §5.1).

        Node faults (``k8s.node_drain`` / ``k8s.node_pressure``) have no
        container: the scope authority names the node (``name``) or matches one
        by label selector.  The record carries the node's live readiness and
        schedulability facts so the engine can verify post-undo state from the
        API instead of trusting local lease rows.
        """
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
        authority = scope.authority
        name = node_name or str(authority.get("name") or "")
        matches = self._select_node_by_selector(scope) if name in ("", "*") else [name]
        info = self._client.node(matches[0]) if matches else None
        if info is None:
            # fall back to a label-selector pass when a single node 404s only if
            # the scope asked for a selector; otherwise this is a hard missing
            # node (same taxonomy as a missing workload).
            raise ResolutionError(
                "resolution.resource_missing",
                f"node {matches[0]!r} not found in cluster",
            )
        target = self._build_node_target(info, scope)
        note = (
            f"resolved node {target.node} ready={target.ready} unschedulable={target.unschedulable}"
        )
        return ResolutionOutcome(resolved=target, drift=False, note=note)

    def _select_node_by_selector(self, scope: TargetScope) -> list[str]:
        """Nodes matching the scope authority's ``selector`` (k-plan-5 §5.1)."""
        selector = scope.authority.get("selector")
        if not selector or self._client is None:
            raise ResolutionError(
                "resolution.resource_missing",
                f"scope {scope.logical_id!r} has no concrete node name or selector",
            )
        wanted = {
            str(k): str(v) for k, v in selector.items() if isinstance(v, (str, int, float, bool))
        }
        matches = [
            node.name for node in self._client.nodes() if wanted.items() <= node.labels.items()
        ]
        if not matches:
            label = ",".join(f"{k}={v}" for k, v in sorted(wanted.items()))
            raise SelectionError(
                "selection.no_matching_nodes",
                f"no node matches selector {label!r}",
            )
        return matches

    def _build_node_target(self, info: K8sNodeInfo, scope: TargetScope) -> ResolvedNodeTarget:
        """Materialize the evidence record for one resolved node (k-plan-5)."""
        return ResolvedNodeTarget(
            node=info.name,
            node_uid=info.uid,
            ready=info.ready,
            unschedulable=info.unschedulable,
            labels=dict(info.labels),
            node_action=str(scope.authority.get("action") or ""),
        )

    @staticmethod
    def _pod_key(pod: K8sPod) -> tuple[str, str, str]:
        """Hash-stable pod ordering: namespace, name, uid (k-plan-2 §2.5)."""
        return (pod.namespace, pod.name, pod.uid)

    def _select_many(self, scope: TargetScope, eligible: list[K8sPod]) -> list[K8sPod]:
        """Author selection mode applied to the live eligible set (k-plan-4 §4.2).

        Mirrors :mod:`mayhem.domain.target_selector`'s deterministic semantics:
        ``count``/``percentage``/``all`` consume pods in sorted order, ``random``
        is a seedable single draw, ``one`` is the deterministic first pick.
        """
        selection = scope.selection or SelectionSpec(mode=SelectionMode.ONE)
        ordered = sorted(eligible, key=self._pod_key)
        mode = selection.mode
        if mode == SelectionMode.ONE:
            return ordered[:1]
        if mode == SelectionMode.RANDOM:
            rng = random.Random(zlib.crc32(scope.logical_id.encode("utf-8")))
            return [rng.choice(ordered)]
        if mode == SelectionMode.ALL:
            return ordered
        if mode == SelectionMode.COUNT:
            count = selection.count
            if count is None:
                raise SelectionError(
                    "selection.count_required",
                    f"selection.mode 'count' on target {scope.logical_id!r} "
                    "requires selection.count",
                )
            if count > len(ordered):
                raise SelectionError(
                    "selection.count_exceeds_eligible",
                    f"selection count {count} on target {scope.logical_id!r} "
                    f"exceeds {len(ordered)} eligible pod(s)",
                )
            return ordered[:count]
        if mode == SelectionMode.PERCENTAGE:
            pct = selection.percentage
            if pct is None:
                raise SelectionError(
                    "selection.percentage_required",
                    f"selection.mode 'percentage' on target {scope.logical_id!r} "
                    "requires selection.percentage",
                )
            n = max(1, math.ceil(len(ordered) * pct / 100.0))
            return ordered[:n]
        raise SelectionError("selection.invalid_mode", f"unknown selection mode {mode!r}")

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
