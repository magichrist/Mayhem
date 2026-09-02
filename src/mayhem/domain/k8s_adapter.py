"""Kubernetes adapter interface (ADR-M3-6).

Defines the ``RuntimeAdapter``-compatible seam for Kubernetes.  **No
Kubernetes runtime is implemented in this milestone** — the adapter returns
UNSUPPORTED for every capability until a future milestone (M7) implements it.

Node-kind extensions (``NodeKind.POD`` / ``K8S_NODE``) are future additions to
the closed union (ADR-0013); this module only declares the capability
contract so the planner can refuse K8s plans with a clear message.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mayhem.domain.runtime_adapter import (
    AdapterCapabilities,
    CapabilityRequirements,
    CapabilityVerdict,
    RuntimeAdapter,
    VerdictResult,
)
from mayhem.topology.providers.base import PartialGraph

if TYPE_CHECKING:
    from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata


class KubernetesAdapter(RuntimeAdapter):
    """Stub Kubernetes adapter — every capability UNSUPPORTED until M7."""

    @property
    def id(self) -> str:
        return "kubernetes"

    def is_available(self) -> bool:
        # No transport implemented; never "available" for execution yet.
        return False

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            engine="kubernetes",
            supported=frozenset(),
            alternatives=frozenset(),
            version=None,
        )

    def evaluate(self, reqs: CapabilityRequirements) -> VerdictResult:
        blocking = bool(reqs.namespaces or reqs.tools or reqs.runtimes)
        verdicts = {
            "kubernetes_execution": CapabilityVerdict.UNSUPPORTED.value,
        }
        return VerdictResult(
            engine=self.id,
            requirements=reqs,
            verdicts=verdicts,
            blocking=blocking or True,
        )

    def ps(self) -> list[dict[str, Any]]:
        return []

    def inspect(self, container_id: str) -> tuple[RuntimeIdentity, RuntimeMetadata | None]:
        raise NotImplementedError("kubernetes inspection is not supported until a future milestone")

    def exec(self, container_id: str, cmd: list[str], *, timeout_s: float = 30) -> str:
        raise NotImplementedError("kubernetes exec is not supported until a future milestone")

    def pid(self, container_id: str) -> int | None:
        return None

    def signal(self, container_id: str, signo: int) -> None:
        raise NotImplementedError("kubernetes signalling is not supported until a future milestone")

    def netns(self, container_id: str) -> str | None:
        return None

    def filter_by_compose(self, project: str, services: tuple[str, ...] | None = None) -> None:
        return None

    def filter_by_names(self, names: list[str]) -> None:
        return None

    def discover(self) -> PartialGraph:
        return PartialGraph(source=self.id, notes=("kubernetes adapter is interface-only",))
