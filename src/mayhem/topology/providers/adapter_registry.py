"""Adapter registry — lookup and instantiate RuntimeAdapter by engine name.

``best_effort(engine)`` returns the first available adapter, preferring
Docker when *engine* is None (preserving existing semantics from
``ContainerRuntimeProvider.best_effort``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mayhem.domain.runtime_adapter import RuntimeAdapter

_REGISTRY: dict[str, type[RuntimeAdapter]] = {}


def register(name: str, cls: type[RuntimeAdapter]) -> None:
    """Register an adapter class under *name*."""
    _REGISTRY[name] = cls


def best_effort(engine: str | None = None) -> RuntimeAdapter | None:
    """Return an adapter for *engine*, or the first available one.

    When *engine* is None the lookup order is ``["docker", "podman"]``
    so Docker is preferred, matching the prior
    ``ContainerRuntimeProvider.best_effort`` behaviour.
    """
    if engine is not None:
        cls = _REGISTRY.get(engine)
        if cls is not None:
            adapter = cls(engine)  # type: ignore[call-arg]
            if adapter.is_available():
                return adapter
        return None

    for candidate in ("docker", "podman"):
        cls = _REGISTRY.get(candidate)
        if cls is not None:
            adapter = cls()
            if adapter.is_available():
                return adapter
    return None


# Auto-register on import.
from mayhem.topology.providers.docker_adapter import DockerAdapter  # noqa: E402
from mayhem.topology.providers.podman_adapter import PodmanAdapter  # noqa: E402

register("docker", DockerAdapter)
register("podman", PodmanAdapter)
