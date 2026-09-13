"""Execution-time resolution records (k-plan-3 §3.1/§3.4).

The frozen plan pins the *logical* target; execution writes the *resolved*
target.  ``ResolvedPodTarget`` is that record for a Kubernetes container-level
fault: the exact Pod the impact gate selected, its uid, the container id from
``PodStatus.ContainerStatuses[].containerID``, the hosting node, and the
``kubectl exec`` argv that delivered the mutation.  It is the evidence key
behind ``FaultLease.resolved_target`` (ADR-M7-1 §3.3) and defines what a
` resolved_drift`` note compares against.

The model lives in its own module (no imports from ``leases`` or
``experiments``) so both may reference it without a dependency cycle.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class ResolvedPodTarget(BaseModel):
    """The exact live Pod a k8s container-level fault resolved to (k-plan-3)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    namespace: str = "default"
    pod: Annotated[str, Field(min_length=1)]
    container: Annotated[str, Field(min_length=1)]  # named container inside the pod
    pod_uid: str = ""
    container_id: str = ""  # ContainerStatuses[].containerID, e.g. "containerd://…"
    node: str = ""  # hosting cluster node
    exec_argv: tuple[str, ...] = ()  # the argv that delivered the mutation (evidence)

    @property
    def container_runtime(self) -> str:
        """Runtime scheme from the container id (``containerd``, ``docker``, …)."""
        return self.container_id.split("://", 1)[0] if "://" in self.container_id else ""

    @property
    def authority_key(self) -> str:
        """Stable logical key backing this resolved pod (deployment/… identity)."""
        return f"{self.namespace}/{self.pod}"