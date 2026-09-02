"""RuntimeAdapter contract tests (ADR-M3-1, ADR-M3-2).

Uses a FakeAdapter stub to exercise the ABC without a live engine.
"""

from __future__ import annotations

import pytest

from mayhem.domain.runtime_adapter import (
    AdapterCapabilities,
    CapabilityRequirements,
    CapabilityVerdict,
    RuntimeAdapter,
    RuntimeCapability,
    VerdictResult,
)


class FakeAdapter(RuntimeAdapter):
    """Minimal stub satisfying every abstract method."""

    def __init__(self, *, engine: str = "fake") -> None:
        self._engine = engine
        self._caps = AdapterCapabilities(
            engine=engine,
            supported=frozenset(RuntimeCapability),
        )

    @property
    def id(self) -> str:
        return self._engine

    def is_available(self) -> bool:
        return True

    def capabilities(self) -> AdapterCapabilities:
        return self._caps

    def ps(self) -> list[dict]:
        return []

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

    def inspect(self, container_id: str):
        from mayhem.domain.identity import RuntimeIdentity

        return (RuntimeIdentity(runtime="fake", host_id="host", runtime_id=container_id), None)

    def discover(self):
        from mayhem.topology.providers.base import PartialGraph

        return PartialGraph(source=self._engine)


class RootlessFake(FakeAdapter):
    """Rootless podman-like: NETNS=ALTERNATIVE, RESOURCE_LIMITS=UNSUPPORTED."""

    def __init__(self) -> None:
        super().__init__(engine="podman")
        self._caps = AdapterCapabilities(
            engine="podman",
            rootless=True,
            supported=frozenset(
                {
                    RuntimeCapability.EXEC,
                    RuntimeCapability.PID,
                    RuntimeCapability.SIGNAL,
                    RuntimeCapability.INSPECT,
                    RuntimeCapability.COMPOSE_FILTER,
                }
            ),
            alternatives=frozenset({RuntimeCapability.NETNS}),
        )


def test_abc_cannot_instantiate_directly() -> None:
    with pytest.raises(TypeError):
        RuntimeAdapter()  # type: ignore[abstract]


def test_fakeadapter_satisfies_abc() -> None:
    adapter = FakeAdapter()
    assert adapter.is_available()
    assert adapter.id == "fake"


def test_fakeadapter_capabilities_valid() -> None:
    caps = FakeAdapter().capabilities()
    assert isinstance(caps, AdapterCapabilities)
    assert caps.verdict(RuntimeCapability.EXEC) == CapabilityVerdict.SUPPORTED


def test_best_effort_docker_injected(monkeypatch) -> None:
    """best_effort returns DockerAdapter when docker is available."""
    import shutil

    from mayhem.topology.providers import adapter_registry

    monkeypatch.setattr(
        shutil, "which", lambda name: (name == "docker" and "/usr/bin/docker") or None
    )
    adapter = adapter_registry.best_effort("docker")
    assert adapter is not None
    assert adapter.id == "docker"


def test_best_effort_unknown_returns_none(monkeypatch) -> None:
    import shutil

    from mayhem.topology.providers import adapter_registry

    monkeypatch.setattr(
        shutil, "which", lambda name: (name == "docker" and "/usr/bin/docker") or None
    )
    adapter = adapter_registry.best_effort("unknown")
    assert adapter is None


def test_verdict_matrix_docker_rootful() -> None:
    caps = AdapterCapabilities(
        engine="docker",
        supported=frozenset(RuntimeCapability),
    )
    assert caps.verdict(RuntimeCapability.EXEC) == CapabilityVerdict.SUPPORTED
    assert caps.verdict(RuntimeCapability.NETNS) == CapabilityVerdict.SUPPORTED
    assert caps.verdict(RuntimeCapability.RESOURCE_LIMITS) == CapabilityVerdict.SUPPORTED


def test_verdict_matrix_podman_rootless() -> None:
    caps = RootlessFake().capabilities()
    assert caps.verdict(RuntimeCapability.EXEC) == CapabilityVerdict.SUPPORTED
    assert caps.verdict(RuntimeCapability.NETNS) == CapabilityVerdict.ALTERNATIVE
    assert caps.verdict(RuntimeCapability.RESOURCE_LIMITS) == CapabilityVerdict.UNSUPPORTED


def test_evaluate_nonblocking_when_supported() -> None:
    adapter = FakeAdapter()
    reqs = CapabilityRequirements(
        namespaces=frozenset({"net"}),
        tools=frozenset({"ip"}),
    )
    result = adapter.evaluate(reqs)
    assert isinstance(result, VerdictResult)
    assert result.blocking is False
    assert result.refuse_with_message() is None


def test_evaluate_blocking_when_unsupported() -> None:
    adapter = RootlessFake()
    # permissions map to RESOURCE_LIMITS capability in default evaluate()
    reqs = CapabilityRequirements(permissions=frozenset({"limit"}))
    result = adapter.evaluate(reqs)
    assert result.blocking is True
    msg = result.refuse_with_message()
    assert msg is not None
    assert "UNSUPPORTED" in msg


def test_evaluate_alternative_is_nonblocking() -> None:
    adapter = RootlessFake()
    reqs = CapabilityRequirements(namespaces=frozenset({"net"}))
    result = adapter.evaluate(reqs)
    assert result.blocking is False
    assert result.verdicts["namespaces"] == CapabilityVerdict.ALTERNATIVE
