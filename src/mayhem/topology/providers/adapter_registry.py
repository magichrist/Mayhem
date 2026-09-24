"""Adapter registry — lookup and instantiate RuntimeAdapter by engine name.

``best_effort(engine)`` returns the first available adapter, preferring
Docker when *engine* is None (preserving existing semantics from
``ContainerRuntimeProvider.best_effort``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.runtime_adapter import resolve_engine_selection

if TYPE_CHECKING:
    from mayhem.domain.runtime_adapter import RuntimeAdapter

_REGISTRY: dict[str, type[RuntimeAdapter]] = {}


def register(name: str, cls: type[RuntimeAdapter]) -> None:
    """Register an adapter class under *name*."""
    _REGISTRY[name] = cls


def _available_adapter(name: str, *, with_engine: bool) -> RuntimeAdapter | None:
    cls = _REGISTRY.get(name)
    if cls is None:
        return None
    adapter = cls(name) if with_engine else cls()
    return adapter if adapter.is_available() else None


def best_effort(engine: str | None = None) -> RuntimeAdapter | None:
    if engine is not None:
        return _available_adapter(engine, with_engine=True)
    try:
        resolved = resolve_engine_selection(None)
    except Exception:
        for candidate in ("docker", "podman"):
            adapter = _available_adapter(candidate, with_engine=False)
            if adapter is not None:
                return adapter
        return None
    return _available_adapter(resolved.name, with_engine=True)


def resolve_or_raise(engine: str | None) -> RuntimeAdapter:
    if engine is not None:
        cls = _REGISTRY.get(engine)
        if cls is None:
            raise InvariantViolationError("engine_unknown", f"unknown engine {engine!r}")
        adapter = cls(engine)  # type: ignore[call-arg]
        if not adapter.is_available():
            raise InvariantViolationError(
                "engine_unavailable",
                f"engine {engine!r} selected but not available; check binary on PATH",
            )
        return adapter
    resolved = resolve_engine_selection(None)
    cls = _REGISTRY.get(resolved.name)
    if cls is None:
        raise InvariantViolationError("engine_unknown", f"no adapter for {resolved.name!r}")
    adapter = cls(resolved.name)  # type: ignore[call-arg]
    if not adapter.is_available():
        raise InvariantViolationError(
            "engine_unavailable",
            f"resolved engine {resolved.name!r} not available after detection",
        )
    return adapter


# Auto-register on import.
from mayhem.topology.providers.docker_adapter import DockerAdapter  # noqa: E402
from mayhem.topology.providers.podman_adapter import PodmanAdapter  # noqa: E402

register("docker", DockerAdapter)
register("podman", PodmanAdapter)

# ── Kubernetes adapter (ADR-M7-1) ───────────────────────────────────────────
# Registered so ``best_effort("kubernetes")`` can locate the contract.
# ``KubernetesAdapter.is_available()`` always returns ``False``; the adapter
# is purely interface-level until a live-cluster driver ships (M8).
from mayhem.domain.k8s_adapter import KubernetesAdapter  # noqa: E402

register("kubernetes", KubernetesAdapter)
