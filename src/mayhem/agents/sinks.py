"""Lease persistence boundary for the agent SDK.

Agents never touch SQLite directly (the controller is the single writer,
ADR-0007); they depend on this protocol. The controller binds a SQLite-backed
implementation at wiring time; tests use the in-memory fake.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from mayhem.domain.leases import FaultLease


class LeaseSink(Protocol):
    def save(self, lease: FaultLease) -> None: ...

    def load(self, lease_id: str) -> FaultLease | None: ...

    def active_leases(self) -> tuple[FaultLease, ...]: ...


class InMemoryLeaseSink:
    """Thread-hostile by design: the agent event loop is single-threaded."""

    def __init__(self) -> None:
        self._leases: dict[str, FaultLease] = {}

    def save(self, lease: FaultLease) -> None:
        self._leases[lease.id] = lease

    def load(self, lease_id: str) -> FaultLease | None:
        return self._leases.get(lease_id)

    def active_leases(self) -> tuple[FaultLease, ...]:
        return tuple(lease for lease in self._leases.values() if not lease.is_safe_terminal)

    def all_leases(self) -> tuple[FaultLease, ...]:
        return tuple(self._leases.values())
