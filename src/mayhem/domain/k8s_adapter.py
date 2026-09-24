"""Kubernetes adapter interface (ADR-M7-1).

Defines the ``RuntimeAdapter``-compatible seam for Kubernetes.  **No
Kubernetes runtime is implemented in this milestone** — the adapter returns
``UNSUPPORTED`` for every capability until a future cluster driver ships.

Node-kind extensions (``NodeKind.POD`` / ``NodeKind.K8S_NODE``) are declared
in the topology model (ADR-M7-2); this module provides the capability contract
so the planner can refuse K8s plans with a clear, actionable message pointing
back to this ADR.

Design decisions
----------------
* ``is_available()`` returns ``False`` — no transport is wired yet.
* ``capabilities()`` reports an empty supported set so that the verdict
  matrix yields ``UNSUPPORTED`` for every ``RuntimeCapability``, except
  ``NODE_CONTROL`` which the driver reports once ``is_available()`` is live
  (the gate the node-killer families admit on).
* ``list_nodes`` / ``list_pods`` are stubs returning empty lists — real
  discovery belongs to the cluster-driver implementation (M8).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mayhem.domain.runtime_adapter import (
    AdapterCapabilities,
    CapabilityRequirements,
    CapabilityVerdict,
    RuntimeAdapter,
    RuntimeCapability,
    VerdictResult,
)
from mayhem.topology.providers.base import PartialGraph

if TYPE_CHECKING:
    from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata

# ── ADR-M7 reference constants ──────────────────────────────────────────────

ADR_M7_1 = "ADR-M7-1"
"""k8s RuntimeAdapter interface contract."""

ADR_M7_2 = "ADR-M7-2"
"""Topology node-kind extensions (PodNode / K8sNode)."""

ADR_M7_3 = "ADR-M7-3"
"""k8s fault categories (capacity / network / preemption)."""

ADR_M7_4 = "ADR-M7-4"
"""Capability matrix rows for k8s (default UNSUPPORTED)."""

UNSUPPORTED_MSG = (
    "kubernetes execution not yet supported; see the RuntimeAdapter contract at ADR-M7-1"
)

K8S_UNSUPPORTED_REMEDIATION = (
    "k8s.unsupported: attach a live cluster (kubeconfig context/namespace) "
    "and ensure required capability is available; manifest mode remains usable for planning"
)


def k8s_unsupported_remediation(
    fault_id: str,
    *,
    capability: str | None = None,
    context: str | None = None,
    namespace: str | None = None,
) -> str:
    details = [K8S_UNSUPPORTED_REMEDIATION, f"fault: {fault_id}"]
    if capability:
        details.append(f"missing capability: {capability}")
    if context:
        details.append(f"context: {context}")
    if namespace:
        details.append(f"namespace: {namespace}")
    return " — ".join(details)


def k8s_adapter_doctor_status() -> dict[str, object]:
    adapter = KubernetesAdapter()
    return {
        "available": adapter.is_available(),
        "engine": adapter.id,
        "remediation": K8S_UNSUPPORTED_REMEDIATION if not adapter.is_available() else "",
        "supported": sorted(c.value for c in adapter.capabilities().supported),
        "client": "not wired to the legacy adapter",
    }


class KubernetesAdapter(RuntimeAdapter):
    """Stub Kubernetes adapter — every capability UNSUPPORTED (ADR-M7-1).

    Registered in the adapter registry as ``"kubernetes"`` so that
    ``best_effort("kubernetes")`` can locate the contract.  The adapter is
    never *available* (``is_available() → False``) until a live-cluster
    driver is implemented.
    """

    ENGINE = "kubernetes"

    def __init__(
        self,
        engine: str = ENGINE,
        *,
        client: object | None = None,
        context: str | None = None,
        namespace: str | None = None,
    ) -> None:
        self._engine = engine
        self._client = client
        self.context = context
        self.namespace = namespace

    # ── RuntimeAdapter contract ──────────────────────────────────────────────

    @property
    def id(self) -> str:
        return self._engine

    def is_available(self) -> bool:
        """The compatibility adapter is available only with an explicit client."""
        return self._client is not None

    def capabilities(self) -> AdapterCapabilities:
        """Capability snapshot for the k8s driver seam.

        Every RuntimeCapability is UNSUPPORTED until a live cluster driver
        ships, **except** ``NODE_CONTROL``: the moment ``is_available()``
        flips true (M8 driver), the adapter reports ``NODE_CONTROL``
        alongside the engine — node-killer families (``k8s.taint_evict`` /
        ``k8s.nvidia_smi_error`` / ``k8s.crash_loop``) read this verdict
        before any mutation (k-plan-6 §24).
        """
        supported: frozenset[RuntimeCapability] = frozenset()
        if self.is_available():
            supported = frozenset({RuntimeCapability.NODE_CONTROL})
        return AdapterCapabilities(
            engine=self._engine,
            supported=supported,
            alternatives=frozenset(),
            version=None,
        )

    def evaluate(self, reqs: CapabilityRequirements) -> VerdictResult:
        """Every capability returns UNSUPPORTED (ADR-M7-1, ADR-M7-4)."""
        verdicts = {cap.value: CapabilityVerdict.UNSUPPORTED.value for cap in RuntimeCapability}
        # Any explicit requirement makes this blocking.
        blocking = bool(reqs.namespaces or reqs.tools or reqs.runtimes) or True
        return VerdictResult(
            engine=self._engine,
            requirements=reqs,
            verdicts=verdicts,
            blocking=blocking,
        )

    # ── discovery stubs ─────────────────────────────────────────────────────

    def ps(self) -> list[dict[str, Any]]:
        return []

    def inspect(self, container_id: str) -> tuple[RuntimeIdentity, RuntimeMetadata | None]:
        raise NotImplementedError(f"{UNSUPPORTED_MSG}; inspect({container_id!r})")

    def exec(self, container_id: str, cmd: list[str], *, timeout_s: float = 30) -> str:
        raise NotImplementedError(f"{UNSUPPORTED_MSG}; exec({container_id!r}, {cmd!r})")

    def pid(self, container_id: str) -> int | None:
        return None

    def signal(self, container_id: str, signo: int) -> None:
        raise NotImplementedError(f"{UNSUPPORTED_MSG}; signal({container_id!r}, {signo})")

    def netns(self, container_id: str) -> str | None:
        return None

    def filter_by_compose(self, project: str, services: tuple[str, ...] | None = None) -> None:
        return None

    def filter_by_names(self, names: list[str]) -> None:
        return None

    def discover(self) -> PartialGraph:
        return PartialGraph(
            source=self._engine,
            notes=("kubernetes adapter is interface-only (ADR-M7-1)",),
        )
