"""LeaseClient — the only way an agent touches lease state.

Every mutation is a legal state-machine transition (the domain module enforces
it) followed by an immediate sink write, so a crash between inject and release
still leaves a durable trail for the janitor.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any

from mayhem.domain.common import utc_now
from mayhem.domain.leases import FaultLease, LeaseState

if TYPE_CHECKING:
    from datetime import datetime

    from mayhem.agents.sinks import LeaseSink
from mayhem.toolkit.fingerprint import interpreter_marker


def _lease_id(sequence: int) -> str:
    return f"l-{sequence:08d}"


class LeaseConflictError(Exception):
    """Two agents raced for the same target; the second one loses."""


class LeaseClient:
    def __init__(self, sink: LeaseSink, agent_id: str = f"ag-{interpreter_marker()}") -> None:
        self._sink = sink
        self._agent_id = agent_id
        # Continue the counter from the store's high-water mark so lease ids stay
        # unique across runs against a shared DB (the sink is single-writer per
        # run; parallel steps within a run share this client).
        self._sequence = sink.next_sequence()

    @property
    def agent_id(self) -> str:
        return self._agent_id

    def acquire(
        self,
        *,
        run_id: str,
        fault_id: str,
        targets: frozenset[str] | set[str],
        undo_ops: tuple[dict[str, Any], ...],
        verify_probes: tuple[dict[str, Any], ...] = (),
        ttl_seconds: float = 120.0,
        runtime_identity: str | None = None,
    ) -> FaultLease:
        """Create a PENDING lease; the caller must activate() before injecting."""
        self._sequence += 1
        lease = FaultLease.model_validate(
            {
                "id": _lease_id(self._sequence),
                "run_id": run_id,
                "fault_id": fault_id,
                "owner_agent": self._agent_id,
                "targets": sorted(targets),
                "undo_ops": list(undo_ops),
                "verify_probes": list(verify_probes),
                "ttl_seconds": ttl_seconds,
                "runtime_identity": runtime_identity,
            }
        )
        now = utc_now()
        live: list[FaultLease] = []
        overlap = [x for x in self._sink.active_leases() if x.targets & set(targets)]
        for existing in overlap:
            deadline = existing.created_at.timestamp() + float(existing.ttl_seconds)
            if deadline < now.timestamp():
                # Past TTL is abandoned by definition (ADR-0007 / janitor
                # contract) — expire it durably so a crashed run cannot wedge
                # every later run on the same targets.
                self._expire_quietly(existing, now)
            else:
                live.append(existing)
        if live:
            holders = ", ".join(f"{x.id} ({x.owner_agent})" for x in live)
            raise LeaseConflictError(
                f"targets {sorted(targets)} already leased by {holders} "
                "-- retry after the lease owner releases them"
            )
        self._sink.save(lease)
        return lease

    def _expire_quietly(self, lease: FaultLease, now: datetime) -> None:
        """Best-effort TTL reap; a failed reap just gets retried next acquire."""
        with contextlib.suppress(Exception):
            expired = lease.transition(LeaseState.EXPIRED, mechanism="past-ttl", now=now)
            self._sink.save(expired)

    def activate(self, lease_id: str) -> FaultLease:
        lease = self._require(lease_id)
        activated = lease.transition(LeaseState.ACTIVE)
        self._sink.save(activated)
        return activated

    def mark_releasing(self, lease_id: str) -> FaultLease:
        lease = self._require(lease_id)
        releasing = lease.transition(LeaseState.RELEASING)
        self._sink.save(releasing)
        return releasing

    def confirm_release(self, lease_id: str, *, mechanism: str) -> FaultLease:
        lease = self._require(lease_id)
        released = lease.transition(LeaseState.RELEASED, mechanism=mechanism)
        self._sink.save(released)
        return released

    def mark_dirty(self, lease_id: str, *, notes: str) -> FaultLease:
        lease = self._require(lease_id)
        dirty = lease.transition(LeaseState.DIRTY, escalation_notes=notes)
        self._sink.save(dirty)
        return dirty

    def mark_orphaned(self, lease_id: str, *, notes: str | None = None) -> FaultLease:
        lease = self._require(lease_id)
        orphaned = lease.transition(
            LeaseState.ORPHANED,
            escalation_notes=notes or f"owner {lease.owner_agent} missed its heartbeat",
        )
        self._sink.save(orphaned)
        return orphaned

    def get(self, lease_id: str) -> FaultLease | None:
        return self._sink.load(lease_id)

    def active_leases(self) -> tuple[FaultLease, ...]:
        return self._sink.active_leases()

    def _require(self, lease_id: str) -> FaultLease:
        lease = self._sink.load(lease_id)
        if lease is None:
            raise KeyError(f"unknown lease {lease_id!r}")
        return lease
