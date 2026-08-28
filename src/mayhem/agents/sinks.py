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

    def next_sequence(self) -> int:
        """Highest ``l-<n>`` sequence already persisted (0 when empty).

        Lets a fresh run continue the counter instead of restarting from one,
        so repeated runs against a shared DB never reuse a lease id
        (``fault_leases.id`` / ``fault_invocations.lease_id`` are unique).
        """
        ...


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

    def next_sequence(self) -> int:
        highest = 0
        for lease_id in self._leases:
            if not lease_id.startswith("l-"):
                continue
            try:
                highest = max(highest, int(lease_id[2:]))
            except ValueError:
                continue
        return highest

    def all_leases(self) -> tuple[FaultLease, ...]:
        return tuple(self._leases.values())
