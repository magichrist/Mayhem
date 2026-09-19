"""kubectl composition helpers for k-plan-6 controller-level faults.

All helpers build deterministic ``run_tool`` argv lists and return plain
strings or dicts so callers never import a live k8s client.  The module
is intentionally independent of both :mod:`k8s_runtime` and
:mod:`executors` so either can import it without creating a cycle.

Key design decisions
--------------------
* **Snapshot annotation** — reversible mutations persist an undo snapshot
  on the *target* object itself (Deployment / Service / ConfigMap / Secret)
  keyed by :data:`RESTORE_ANNOTATION`.  At undo the executor reads the
  annotation, applies a strategic merge restore, then deletes the
  annotation.  This is crash-safe: a missed undo leaves the annotation in
  place and the compensation layer (``k8s.replaced``) can detect it.
* **Workload resolution** — the owning Deployment / StatefulSet /
  DaemonSet is recovered by walking ``metadata.ownerReferences`` up to
  three hops (Pod → ReplicaSet → Deployment).  Resolution only runs at
  inject time when the resolved pod is guaranteed live; at undo time the
  workload itself carries the annotation so the pod is not required.
"""

from __future__ import annotations

import json as _json
from dataclasses import dataclass
from typing import Any

from mayhem.domain.resolution import ResolvedPodTarget
from mayhem.toolkit.tool_runner import ToolResult, run_tool

RESTORE_ANNOTATION = "mayhem.io/restore"
WORKLOAD_KINDS = ("Deployment", "StatefulSet", "DaemonSet")
CONFIG_KINDS = ("ConfigMap",)
SECRET_KINDS = ("Secret",)
SERVICE_KINDS = ("Service",)
ALL_CTRL_KINDS = WORKLOAD_KINDS + SERVICE_KINDS + CONFIG_KINDS + SECRET_KINDS


@dataclass(frozen=True)
class ResourceRef:
    """Identifies a k8s API object."""

    kind: str
    name: str
    namespace: str = "default"


# ── low-level kubectl helpers ────────────────────────────────────────────────


def kubectl(args: tuple[str, ...], *, timeout_s: int = 30) -> ToolResult:
    """Run ``kubectl <args>`` via the tool seam and return the raw result."""
    return run_tool(("kubectl", *args), timeout_s=timeout_s)


def kubectl_json(ref: ResourceRef, *, timeout_s: int = 30) -> dict[str, Any] | None:
    """Fetch the full object JSON or return ``None`` when the object is absent."""
    result = kubectl(
        ("get", ref.kind, ref.name, "-n", ref.namespace, "-o", "json"),
        timeout_s=timeout_s,
    )
    if result.exit_code != 0:
        return None
    return _json.loads(result.stdout)


def kubectl_jsonpath(ref: ResourceRef, jsonpath: str) -> str | None:
    """Evaluate a JSONPath expression; returns raw stdout or ``None``."""
    result = kubectl(
        (
            "get",
            ref.kind,
            ref.name,
            "-n",
            ref.namespace,
            "-o",
            f"jsonpath={jsonpath}",
        )
    )
    if result.exit_code != 0 or not result.stdout.strip():
        return None
    return result.stdout.strip()


# ── workload resolution (ownerReferences walk) ───────────────────────────────


def workload_ref_for_pod(target: ResolvedPodTarget) -> ResourceRef | None:
    """Walk ownerReferences from the resolved pod up to the owning workload.

    The walk follows up to *three* hops and stops at the first ancestor
    whose ``kind`` is one of the recognised workload kinds
    (:data:`WORKLOAD_KINDS`).  Returns ``None`` when no match is found.
    """
    ref = ResourceRef(kind="Pod", name=target.pod, namespace=target.namespace)
    for _ in range(3):
        obj = kubectl_json(ref)
        if obj is None:
            return None
        owners = obj.get("metadata", {}).get("ownerReferences") or []
        matched = False
        for owner in owners:
            kind = str(owner.get("kind") or "")
            if kind in WORKLOAD_KINDS:
                return ResourceRef(
                    kind=kind,
                    name=str(owner.get("name", "")),
                    namespace=ref.namespace,
                )
        for owner in owners:
            kind = str(owner.get("kind") or "")
            if kind:
                ref = ResourceRef(
                    kind=kind,
                    name=str(owner.get("name", "")),
                    namespace=ref.namespace,
                )
                matched = True
                break
        if not matched:
            break
    return None


def hpa_ref_for_pod(target: ResolvedPodTarget) -> ResourceRef | None:
    """Find the HorizontalPodAutoscaler that targets *target*'s owning workload.

    HPAs reference their workload through ``spec.scaleTargetRef`` (kind +
    name), so the workload is resolved first (:func:`workload_ref_for_pod`)
    and the HPA list in the namespace is scanned for a matching target.
    Returns ``None`` when no workload or no matching HPA exists.
    """
    workload = workload_ref_for_pod(target)
    if workload is None:
        return None
    result = kubectl(("get", "hpa", "-n", target.namespace, "-o", "json"))
    if result.exit_code != 0:
        return None
    for obj in _json.loads(result.stdout).get("items", []):
        scale_target = obj.get("spec", {}).get("scaleTargetRef") or {}
        if scale_target.get("kind") == workload.kind and scale_target.get("name") == workload.name:
            return ResourceRef(
                kind="HorizontalPodAutoscaler",
                name=str(obj.get("metadata", {}).get("name", "")),
                namespace=target.namespace,
            )
    return None


def _service_ref_for_pod_impl(target: ResolvedPodTarget) -> ResourceRef | None:
    """Locate the first Service whose selector is a subset of *target.labels*.

    When ``params.get("service_name")`` is set the explicit name wins and no
    discovery is performed.  This mirrors the planner service name override
    without carrying a live client through the pure composition seam.
    """
    result = kubectl(
        ("get", "svc", "-n", target.namespace, "-o", "json"),
    )
    if result.exit_code != 0:
        return None
    items = _json.loads(result.stdout).get("items", [])
    for svc in items:
        svc_name = svc.get("metadata", {}).get("name", "")
        svc_selector = svc.get("spec", {}).get("selector") or {}
        # If the service selector matches the pod labels it is a candidate.
        if svc_selector and all(target.labels.get(k) == v for k, v in svc_selector.items()):
            return ResourceRef(kind="Service", name=svc_name, namespace=target.namespace)
    return None


def service_ref_for_pod(target: ResolvedPodTarget) -> ResourceRef | None:
    """Public wrapper around :func:`_service_ref_for_pod_impl`."""
    return _service_ref_for_pod_impl(target)


def _config_ref_for_pod_impl(target: ResolvedPodTarget) -> ResourceRef | None:
    """Find a ConfigMap mounted into the pod's resolved container."""
    obj = kubectl_json(ResourceRef(kind="Pod", name=target.pod, namespace=target.namespace))
    if obj is None:
        return None
    for container in obj.get("spec", {}).get("initContainers", []) + obj.get("spec", {}).get(
        "containers", []
    ):
        if container.get("name") != target.container:
            continue
        for vm in container.get("volumeMounts", []):
            if vm.get("name"):
                vol = _vol_named(obj, vm["name"])
                cm_name = vol.get("configMap", {}).get("name")
                if cm_name:
                    return ResourceRef(
                        kind="ConfigMap", name=str(cm_name), namespace=target.namespace
                    )
    return None


def configmap_ref_for_pod(target: ResolvedPodTarget) -> ResourceRef | None:
    """Public wrapper around :func:`_config_ref_for_pod_impl`."""
    return _config_ref_for_pod_impl(target)


def _secret_ref_for_pod_impl(target: ResolvedPodTarget) -> ResourceRef | None:
    """Find a Secret mounted into the pod's resolved container."""
    obj = kubectl_json(ResourceRef(kind="Pod", name=target.pod, namespace=target.namespace))
    if obj is None:
        return None
    for container in obj.get("spec", {}).get("initContainers", []) + obj.get("spec", {}).get(
        "containers", []
    ):
        if container.get("name") != target.container:
            continue
        for vm in container.get("volumeMounts", []):
            if vm.get("name"):
                vol = _vol_named(obj, vm["name"])
                sec_name = vol.get("secret", {}).get("secretName")
                if sec_name:
                    return ResourceRef(
                        kind="Secret", name=str(sec_name), namespace=target.namespace
                    )
    return None


def secret_ref_for_pod(target: ResolvedPodTarget) -> ResourceRef | None:
    """Public wrapper around :func:`_secret_ref_for_pod_impl`."""
    return _secret_ref_for_pod_impl(target)


def _vol_named(obj: dict[str, Any], vol_name: str) -> dict[str, Any]:
    for v in obj.get("spec", {}).get("volumes", []):
        if v.get("name") == vol_name:
            return v
    return {}


# ── mount-path helpers for in-pod storage faults ────────────────────────────


def preferred_mount_path(target: ResolvedPodTarget) -> str:
    """Return the first volumeMount path for the resolved container."""
    obj = kubectl_json(ResourceRef(kind="Pod", name=target.pod, namespace=target.namespace))
    if obj is None:
        return "/mnt/data"
    for container in obj.get("spec", {}).get("initContainers", []) + obj.get("spec", {}).get(
        "containers", []
    ):
        if container.get("name") == target.container:
            for vm in container.get("volumeMounts", []):
                mp = vm.get("mountPath")
                if mp:
                    return str(mp)
    return "/mnt/data"


# ── snapshot annotation helpers ──────────────────────────────────────────────


def write_annotation(ref: ResourceRef, snapshot: dict[str, Any]) -> None:
    """Write the restore annotation onto *ref*."""
    value = _json.dumps(snapshot, sort_keys=True)
    kubectl(
        (
            "annotate",
            ref.kind,
            ref.name,
            "-n",
            ref.namespace,
            f"{RESTORE_ANNOTATION}={value}",
            "--overwrite",
        )
    )


def clear_annotation(ref: ResourceRef) -> None:
    kubectl(
        (
            "annotate",
            ref.kind,
            ref.name,
            "-n",
            ref.namespace,
            f"{RESTORE_ANNOTATION}-",
        )
    )


def find_annotated(namespace: str, kinds: tuple[str, ...]) -> ResourceRef | None:
    """Return the first object in *namespace* carrying the restore annotation."""
    result = kubectl(
        ("get", *kinds, "-n", namespace, "-o", "json"),
    )
    if result.exit_code != 0:
        return None
    for obj in _json.loads(result.stdout).get("items", []):
        annotations = obj.get("metadata", {}).get("annotations") or {}
        if RESTORE_ANNOTATION in annotations:
            return ResourceRef(
                kind=obj.get("kind", ""),
                name=obj["metadata"].get("name", ""),
                namespace=namespace,
            )
    return None


def read_snapshot(ref: ResourceRef) -> dict[str, Any] | None:
    """Read and return the snapshot dict from the restore annotation."""
    obj = kubectl_json(ref)
    if obj is None:
        return None
    raw = (obj.get("metadata", {}).get("annotations") or {}).get(RESTORE_ANNOTATION)
    if not raw:
        return None
    return _json.loads(str(raw))


def apply_patch(ref: ResourceRef, patch: dict[str, Any]) -> bool:
    """Apply a JSON strategic-merge patch; returns ``True`` on success."""
    payload = _json.dumps(patch)
    result = kubectl(
        (
            "patch",
            ref.kind,
            ref.name,
            "-n",
            ref.namespace,
            "--type",
            "strategic",
            "-p",
            payload,
        )
    )
    return result.exit_code == 0


def rollout_control(ref: ResourceRef, *, pause: bool) -> bool:
    """``kubectl rollout pause/resume <kind>/<name>``."""
    verb = "pause" if pause else "resume"
    result = kubectl(("rollout", verb, ref.kind, ref.name, "-n", ref.namespace))
    return result.exit_code == 0


def scale(ref: ResourceRef, replicas: int) -> bool:
    result = kubectl(("scale", ref.kind, ref.name, f"--replicas={replicas}", "-n", ref.namespace))
    return result.exit_code == 0


def delete_object(ref: ResourceRef, *, force: bool = True, grace_period: int = 0) -> bool:
    argv = ["delete", ref.kind, ref.name, "-n", ref.namespace, f"--grace-period={grace_period}"]
    if force:
        argv.append("--force")
    result = kubectl(tuple(argv))
    return result.exit_code == 0


def kubectl_apply_json(obj: dict[str, Any]) -> bool:
    """Apply an object manifest via ``kubectl apply -f -`` (stdin)."""
    payload = _json.dumps(obj, sort_keys=True)
    result = run_tool(("kubectl", "apply", "-f", "-"), stdin_data=payload, timeout_s=30)
    return result.exit_code == 0


def pod_exec(target: ResolvedPodTarget, cmd: tuple[str, ...], *, timeout_s: int = 30) -> ToolResult:
    """``kubectl exec -n <ns> <pod> -c <container> -- <cmd>``."""
    return kubectl(
        ("exec", target.pod, "-n", target.namespace, "-c", target.container, "--", *cmd),
        timeout_s=timeout_s,
    )
