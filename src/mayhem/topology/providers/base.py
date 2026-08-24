"""Provider seam: every discovery source implements :class:`TopologyProvider`."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from mayhem.domain.topology import Edge, TopologyNode


@dataclass(frozen=True)
class PartialGraph:
    """One provider's fragment of the world; merged by the TopologyService."""

    source: str  # provider id, e.g. "compose", "docker", "podman", "host"
    nodes: tuple[TopologyNode, ...] = ()
    edges: tuple[Edge, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)  # provider-level caveats


@runtime_checkable
class TopologyProvider(Protocol):
    """``async discover()`` is the contract (ADR-0006); sync MVP uses discover_sync."""

    @property
    def id(self) -> str: ...

    def is_available(self) -> bool: ...

    def discover(self) -> PartialGraph: ...
