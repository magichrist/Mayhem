"""ADR-M3-2: adapter capability-requirement validation in validate_plan."""

from __future__ import annotations

import pytest

from mayhem.config import PolicyCfg
from mayhem.controller.safety import (
    SafetyContext,
    SafetyRefusedError,
    validate_plan,
)
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    ExecutionPlan,
    ExperimentKind,
    InjectFault,
    PlannedFault,
    PlannedStep,
    ResolvedTarget,
)
from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
from mayhem.domain.k8s_adapter import KubernetesAdapter, k8s_unsupported_remediation
from mayhem.domain.runtime_adapter import (
    AdapterCapabilities,
    CapabilityRequirements,
    CapabilityVerdict,
    RuntimeAdapter,
    RuntimeCapability,
    VerdictResult,
)
from mayhem.domain.topology import (
    Edge,
    EdgeKind,
    NodeKind,
    ServiceNode,
    TargetSelector,
    TopologyGraph,
)


class _UnsupportedAdapter(RuntimeAdapter):
    """An adapter that blocks every capability requirement."""

    @property
    def id(self) -> str:
        return "fake-unsupported"

    def is_available(self) -> bool:
        return True

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            engine=self.id, supported=frozenset(), alternatives=frozenset(), version=None
        )

    def evaluate(self, reqs: CapabilityRequirements) -> VerdictResult:
        return VerdictResult(
            engine=self.id,
            requirements=reqs,
            verdicts={"namespace": CapabilityVerdict.UNSUPPORTED.value},
            blocking=True,
        )

    def ps(self) -> list[dict]:
        return []

    def inspect(self, container_id: str) -> tuple[RuntimeIdentity, RuntimeMetadata | None]:
        return (RuntimeIdentity(runtime="fake", host_id="h", runtime_id=container_id), None)

    def exec(self, container_id: str, cmd: list[str], *, timeout_s: float = 30) -> str:
        return ""

    def pid(self, container_id: str) -> int | None:
        return None

    def signal(self, container_id: str, signo: int) -> None:
        return None

    def netns(self, container_id: str) -> str | None:
        return None

    def filter_by_compose(self, project: str, services=None) -> None:
        return None

    def filter_by_names(self, names: list[str]) -> None:
        return None

    def discover(self):
        return _empty_partial_graph(self.id)


class _HealthyAdapter(RuntimeAdapter):
    """An adapter that supports everything required."""

    @property
    def id(self) -> str:
        return "fake-healthy"

    def is_available(self) -> bool:
        return True

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            engine=self.id,
            supported=frozenset({RuntimeCapability.NETNS, RuntimeCapability.PID}),
            alternatives=frozenset(),
            version=None,
        )

    def evaluate(self, reqs: CapabilityRequirements) -> VerdictResult:
        return VerdictResult(
            engine=self.id,
            requirements=reqs,
            verdicts={"namespace": CapabilityVerdict.SUPPORTED.value},
            blocking=False,
        )

    def ps(self) -> list[dict]:
        return []

    def inspect(self, container_id: str) -> tuple[RuntimeIdentity, RuntimeMetadata | None]:
        return (RuntimeIdentity(runtime="fake", host_id="h", runtime_id=container_id), None)

    def exec(self, container_id: str, cmd: list[str], *, timeout_s: float = 30) -> str:
        return ""

    def pid(self, container_id: str) -> int | None:
        return None

    def signal(self, container_id: str, signo: int) -> None:
        return None

    def netns(self, container_id: str) -> str | None:
        return None

    def filter_by_compose(self, project: str, services=None) -> None:
        return None

    def filter_by_names(self, names: list[str]) -> None:
        return None

    def discover(self):
        return _empty_partial_graph(self.id)


def _empty_partial_graph(source: str):
    from mayhem.topology.providers.base import PartialGraph

    return PartialGraph(source=source)


def _ctx() -> SafetyContext:
    return SafetyContext(
        policy=PolicyCfg(),
        budget=BlastRadiusBudget(),
        fingerprint="f",
    )


def _graph() -> TopologyGraph:
    # Three services so targeting a single one keeps blast radius under 50%.
    return TopologyGraph(
        nodes=(
            ServiceNode(id="n-web", name="web"),
            ServiceNode(id="n-api", name="api"),
            ServiceNode(id="n-db", name="db"),
        ),
        edges=(
            Edge(src="n-web", dst="n-api", kind=EdgeKind.DEPENDS_ON, weight=1.0),
            Edge(src="n-api", dst="n-db", kind=EdgeKind.DEPENDS_ON, weight=1.0),
        ),
    )


def _plan() -> ExecutionPlan:
    selector = TargetSelector(kind=NodeKind.SERVICE, expr="web")
    return ExecutionPlan(
        run_id="r",
        kind=ExperimentKind.DETERMINISTIC,
        steps=(
            PlannedStep(
                id="s1",
                seq=0,
                raw_action=InjectFault(fault="net.partition", selectors=(selector,), duration=5.0),
                fault=PlannedFault(
                    fault_id="net.partition",
                    targets=(ResolvedTarget(selector=selector, node_ids=frozenset({"n-web"})),),
                    duration=5.0,
                ),
            ),
        ),
        config_snapshot_id="c",
        topology_snapshot_id="t",
        environment_fingerprint="f",
    )


def test_validate_plan_blocked_by_unsupported_capability() -> None:
    with pytest.raises(SafetyRefusedError, match="UNSUPPORTED"):
        validate_plan(_plan(), _graph(), _ctx(), adapter=_UnsupportedAdapter())


def test_validate_plan_pass_with_healthy_adapter() -> None:
    # Should not raise.
    validate_plan(_plan(), _graph(), _ctx(), adapter=_HealthyAdapter())


def test_validate_plan_without_adapter_unchanged() -> None:
    # No adapter arg — legacy behaviour preserved.
    validate_plan(_plan(), _graph(), _ctx())


def test_remote_agent_adapter_refuses_remote_execution() -> None:
    from mayhem.domain.remote_agent_interface import RemoteAgentAdapter

    result = RemoteAgentAdapter().evaluate(CapabilityRequirements())
    assert result.blocking is True
    assert result.verdicts["remote_execution"] == CapabilityVerdict.UNSUPPORTED.value


def test_kubernetes_adapter_refuses_every_capability() -> None:
    from mayhem.domain.k8s_adapter import KubernetesAdapter
    from mayhem.domain.runtime_adapter import AdapterCapabilities

    adapter = KubernetesAdapter()
    assert adapter.id == "kubernetes"
    assert adapter.is_available() is False
    caps = adapter.capabilities()
    assert isinstance(caps, AdapterCapabilities)
    assert caps.supported == frozenset()
    assert caps.alternatives == frozenset()


def test_kubernetes_unsupported_remediation_is_stable_and_detailed() -> None:
    reason = k8s_unsupported_remediation(
        "k8s.dns_failure", capability="DNS_CONTROL", context="prod", namespace="pay"
    )
    assert reason.startswith("k8s.unsupported:")
    assert "missing capability: DNS_CONTROL" in reason
    assert "context: prod" in reason
    assert "namespace: pay" in reason


def test_kubernetes_adapter_can_be_explicitly_wired_for_capability_probe() -> None:
    adapter = KubernetesAdapter(client=object())
    assert adapter.is_available() is True
    assert "node_control" in adapter.capabilities().supported
