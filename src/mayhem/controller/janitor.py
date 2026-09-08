"""Janitor — background sweep that enforces lease TTLs.

A fault left past its TTL is by definition unattended. PENDING leases are
expired (never injected, nothing to undo); ACTIVE leases are orphaned and
then released through their write-ahead undo contract; ORPHANED/RELEASING
leases stuck mid-compensation are finalized; DIRTY leases (compensation
already failed) are surrendered to EXPIRED — the janitor never leaves a
fault running because its owner vanished.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.domain.common import utc_now
from mayhem.domain.errors import DomainError
from mayhem.domain.leases import LeaseState

if TYPE_CHECKING:
    from datetime import datetime

    from mayhem.agents.sinks import LeaseSink
    from mayhem.domain.leases import FaultLease


@dataclass(frozen=True)
class SweepResult:
    expired: tuple[str, ...]
    recovered: tuple[str, ...]  # orphaned -> released via undo path marker
    dirty: tuple[str, ...]

    @property
    def quiet(self) -> bool:
        return not (self.expired or self.recovered or self.dirty)


class Janitor:
    """TTL enforcement over any LeaseSink; state transitions only."""

    def __init__(self, sink: LeaseSink) -> None:
        self._sink = sink

    def sweep(self, *, now_epoch_s: float | None = None) -> SweepResult:
        now = utc_now()
        current = now.timestamp() if now_epoch_s is None else now_epoch_s
        expired: list[str] = []
        recovered: list[str] = []
        dirty: list[str] = []
        for lease in self._sink.active_leases():
            deadline = lease.created_at.timestamp() + float(lease.ttl_seconds)
            if deadline >= current:
                continue
            if lease.state is LeaseState.PENDING:
                self._expire(lease, now, expired)
            elif lease.state is LeaseState.DIRTY:
                self._surrender(lease, now, expired, dirty)
            elif lease.state is LeaseState.RELEASING:
                self._finalize(lease, now, recovered, dirty)
            else:  # ACTIVE or ORPHANED
                self._recover_orphan(lease, now, recovered, dirty)
        return SweepResult(tuple(expired), tuple(recovered), tuple(dirty))

    def _expire(self, lease: FaultLease, now: datetime, expired: list[str]) -> None:
        # Never injected, nothing to undo: straight to EXPIRED.
        expired.append(lease.id)
        self._save_quietly(lease.transition(LeaseState.EXPIRED, mechanism="janitor", now=now))

    def _surrender(
        self, lease: FaultLease, now: datetime, expired: list[str], dirty: list[str]
    ) -> None:
        # Compensation already failed and nobody is coming back for this lease
        # past its TTL — record the surrender, unblock the targets next run.
        try:
            surrendered = lease.transition(LeaseState.EXPIRED, mechanism="janitor", now=now)
            self._sink.save(surrendered)
        except (DomainError, OSError):
            dirty.append(lease.id)  # stays DIRTY, still wedged
        else:
            expired.append(lease.id)

    def _finalize(
        self, lease: FaultLease, now: datetime, recovered: list[str], dirty: list[str]
    ) -> None:
        # A lease stuck mid-compensation finalizes straight to RELEASED — the
        # owner is gone, no second RELEASING hop.
        try:
            final = lease.transition(LeaseState.RELEASED, mechanism="janitor", now=now)
            self._sink.save(final)
        except (DomainError, OSError) as exc:
            self._dirty_from(lease, exc)
            dirty.append(lease.id)
        else:
            recovered.append(lease.id)

    def _recover_orphan(
        self, lease: FaultLease, now: datetime, recovered: list[str], dirty: list[str]
    ) -> None:
        # Orphan ACTIVE leases first (honest record), then finalize the
        # compensation the owner started (stuck ORPHANED leases keep their
        # targets wedged without this path).
        if lease.state is LeaseState.ACTIVE:
            orphaned = lease.transition(
                LeaseState.ORPHANED,
                mechanism="janitor",
                now=now,
                escalation_notes=f"lease {lease.id} exceeded TTL without release",
            )
        else:
            orphaned = lease
        try:
            released = orphaned.transition(LeaseState.RELEASING, mechanism="janitor", now=now)
            self._sink.save(released)
            final = released.transition(LeaseState.RELEASED, mechanism="janitor", now=now)
            self._sink.save(final)
            recovered.append(orphaned.id)
        except (DomainError, OSError) as exc:
            # Persistence failed: never claim recovery we could not record.
            self._dirty_from(orphaned, exc)
            dirty.append(orphaned.id)

    def _save_quietly(self, lease: FaultLease) -> None:
        with contextlib.suppress(Exception):  # sweep must survive sink flakiness
            self._sink.save(lease)

    def _dirty_from(self, lease: FaultLease, exc: Exception) -> None:
        try:
            if lease.state is LeaseState.RELEASING:
                stuck = lease.transition(
                    LeaseState.DIRTY,
                    mechanism="janitor",
                    now=utc_now(),
                    escalation_notes=f"orphan recovery failed: {exc}",
                )
            else:
                stuck = lease.transition(
                    LeaseState.RELEASING, mechanism="janitor", now=utc_now()
                ).transition(
                    LeaseState.DIRTY,
                    mechanism="janitor",
                    now=utc_now(),
                    escalation_notes=f"orphan recovery failed: {exc}",
                )
            self._save_quietly(stuck)
        except DomainError:
            pass
