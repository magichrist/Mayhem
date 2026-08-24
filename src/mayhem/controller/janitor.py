"""Janitor — background sweep that enforces lease TTLs.

A fault left past its TTL is by definition unattended. PENDING leases are
expired (never injected, nothing to undo); ACTIVE leases are orphaned and
then released through their write-ahead undo contract — the janitor never
leaves a fault running because its owner vanished.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.domain.common import utc_now
from mayhem.domain.errors import DomainError
from mayhem.domain.leases import LeaseState

if TYPE_CHECKING:
    from mayhem.agents.sinks import LeaseSink


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
                expired.append(lease.id)
                self._save_quietly(
                    lease.transition(LeaseState.EXPIRED, mechanism="janitor", now=now)
                )
            elif lease.state is LeaseState.ACTIVE:
                # Orphan first (honest record), then compensate to RELEASED.
                orphaned = lease.transition(
                    LeaseState.ORPHANED,
                    mechanism="janitor",
                    now=now,
                    escalation_notes=f"lease {lease.id} exceeded TTL without release",
                )
                try:
                    released = orphaned.transition(
                        LeaseState.RELEASING, mechanism="janitor", now=now
                    )
                    self._sink.save(released)
                    final = released.transition(
                        LeaseState.RELEASED, mechanism="janitor", now=now
                    )
                    self._sink.save(final)
                    recovered.append(orphaned.id)
                except (DomainError, OSError) as exc:
                    # Persistence failed: never claim recovery we could not record.
                    self._dirty_from(orphaned, exc)
                    dirty.append(orphaned.id)
        return SweepResult(tuple(expired), tuple(recovered), tuple(dirty))

    def _save_quietly(self, lease) -> None:
        with contextlib.suppress(Exception):  # sweep must survive sink flakiness
            self._sink.save(lease)

    def _dirty_from(self, orphaned, exc: Exception) -> None:
        try:
            stuck = orphaned.transition(
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
