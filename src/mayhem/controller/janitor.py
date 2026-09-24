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
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.domain.common import utc_now
from mayhem.domain.errors import DomainError
from mayhem.domain.leases import LeaseState

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

    from mayhem.agents.sinks import LeaseSink
    from mayhem.domain.leases import FaultLease

_LOST_OWNER = "owner run no longer live; reclaimed before TTL"


def _owner_gone(run_liveness: Callable[[str], bool | None], run_id: str) -> bool:
    """True only when the resolver can *prove* the owning controller is gone.

    Unknown (``None``) or an absent owner row never triggers the early reclaim —
    TTL policy stays in charge of those, and a LiveLonger cycling pid can only
    read "alive", which delays cleanup rather than wrongly reclaiming a lease
    a live owner still needs.
    """
    try:
        verdict = run_liveness(run_id)
    except LookupError:
        return False
    return verdict is False


@dataclass(frozen=True)
class SweepResult:
    expired: tuple[str, ...]
    recovered: tuple[str, ...]  # orphaned -> released via undo path marker
    dirty: tuple[str, ...]

    @property
    def quiet(self) -> bool:
        return not (self.expired or self.recovered or self.dirty)


@dataclass(frozen=True)
class SweepPlan:
    would_expire: tuple[str, ...]
    would_recover: tuple[str, ...]
    would_mark_dirty: tuple[str, ...]

    @property
    def quiet(self) -> bool:
        return not (self.would_expire or self.would_recover or self.would_mark_dirty)


class Janitor:
    """TTL enforcement over any LeaseSink; state transitions only.

    ``run_liveness`` is an optional resolver (run_id -> bool | None) the
    caller supplies when it can see the runs table. It returns ``True`` while
    the owning controller is alive, ``False`` when the owner is provably gone,
    and ``None`` when unknown. A lease whose owner is provably gone is
    reclaimed *before* its TTL — without this, a crashed ``run`` wedges its
    targets for the whole TTL and the next ``run`` conflicts with a lease the
    janitor "did nothing about".
    """

    def __init__(self, sink: LeaseSink) -> None:
        self._sink = sink

    def sweep(
        self,
        *,
        now_epoch_s: float | None = None,
        run_liveness: Callable[[str], bool | None] | None = None,
        run_ids: tuple[str, ...] = (),
        include_states: tuple[LeaseState, ...] | None = None,
        execute: bool = True,
    ) -> SweepResult:
        now = utc_now()
        current = now.timestamp() if now_epoch_s is None else now_epoch_s
        expired: list[str] = []
        recovered: list[str] = []
        dirty: list[str] = []
        for lease in self._sink.active_leases():
            if run_ids and lease.run_id not in run_ids:
                continue
            if include_states is not None and lease.state not in include_states:
                continue
            deadline = lease.created_at.timestamp() + float(lease.ttl_seconds)
            owner_gone = run_liveness is not None and _owner_gone(run_liveness, lease.run_id)
            if deadline >= current and not owner_gone:
                continue
            if not execute:
                if lease.state in {LeaseState.PENDING, LeaseState.DIRTY}:
                    expired.append(lease.id)
                else:
                    recovered.append(lease.id)
                continue
            notes = _LOST_OWNER if owner_gone else None
            if lease.state is LeaseState.PENDING:
                self._expire(lease, now, expired, notes=notes)
            elif lease.state is LeaseState.DIRTY:
                self._surrender(lease, now, expired, dirty)
            elif lease.state is LeaseState.RELEASING:
                self._finalize(lease, now, recovered, dirty)
            else:  # ACTIVE or ORPHANED
                self._recover_orphan(lease, now, recovered, dirty, notes=notes)
        return SweepResult(tuple(expired), tuple(recovered), tuple(dirty))

    def plan(
        self,
        *,
        now_epoch_s: float | None = None,
        run_liveness: Callable[[str], bool | None] | None = None,
        run_ids: tuple[str, ...] = (),
    ) -> SweepPlan:
        current = time.time() if now_epoch_s is None else now_epoch_s
        expired: list[str] = []
        recovered: list[str] = []
        dirty: list[str] = []
        for lease in self._sink.active_leases():
            if run_ids and lease.run_id not in run_ids:
                continue
            deadline = lease.created_at.timestamp() + float(lease.ttl_seconds)
            owner_gone = run_liveness is not None and _owner_gone(run_liveness, lease.run_id)
            if deadline >= current and not owner_gone:
                continue
            if lease.state in {LeaseState.PENDING, LeaseState.DIRTY}:
                expired.append(lease.id)
            else:
                recovered.append(lease.id)
        return SweepPlan(tuple(expired), tuple(recovered), tuple(dirty))

    def _expire(
        self, lease: FaultLease, now: datetime, expired: list[str], *, notes: str | None = None
    ) -> None:
        # Never injected, nothing to undo: straight to EXPIRED.
        expired.append(lease.id)
        self._save_quietly(
            lease.transition(
                LeaseState.EXPIRED,
                mechanism="janitor",
                now=now,
                escalation_notes=notes,
            )
        )

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
        self,
        lease: FaultLease,
        now: datetime,
        recovered: list[str],
        dirty: list[str],
        *,
        notes: str | None = None,
    ) -> None:
        # Orphan ACTIVE leases first (honest record), then finalize the
        # compensation the owner started (stuck ORPHANED leases keep their
        # targets wedged without this path).
        if lease.state is LeaseState.ACTIVE:
            orphaned = lease.transition(
                LeaseState.ORPHANED,
                mechanism="janitor",
                now=now,
                escalation_notes=notes or f"lease {lease.id} exceeded TTL without release",
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
