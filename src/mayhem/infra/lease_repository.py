"""SQLite-backed LeaseSink — the durable half of the lease protocol (ADR-0007).

The controller is the single writer; agents receive this sink through the
SDK boundary and never open the database themselves. Rows are self-contained:
run/fault/targets context is denormalized onto the lease row (migration 002)
so janitor and watchdog sweeps never need joins.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from mayhem.domain.leases import FaultLease, LeaseState

if TYPE_CHECKING:
    from collections.abc import Mapping

    from mayhem.infra.store import Store

_TERMINAL_STATES = ("released", "expired")


class SQLiteLeaseSink:
    """Implements ``agents.sinks.LeaseSink`` over the fault_leases table."""

    def __init__(self, store: Store) -> None:
        self._store = store

    def save(self, lease: FaultLease) -> None:
        created = lease.created_at
        expires_at = created + timedelta(seconds=float(lease.ttl_seconds))
        with self._store.write() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO fault_leases (
                    id, state, owner_agent, undo_json, verify_json,
                    ttl_seconds, expires_at, injected_at, released_at,
                    release_mechanism, escalation_notes,
                    run_id, fault_id, targets_json, created_epoch_s,
                    runtime_identity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    lease.id,
                    lease.state.value,
                    lease.owner_agent,
                    json.dumps([op.model_dump(mode="json") for op in lease.undo_ops]),
                    json.dumps([probe.model_dump(mode="json") for probe in lease.verify_probes]),
                    float(lease.ttl_seconds),
                    expires_at.isoformat(),
                    _iso_or_none(lease.injected_at),
                    _iso_or_none(lease.released_at),
                    lease.release_mechanism,
                    lease.escalation_notes,
                    lease.run_id,
                    lease.fault_id,
                    json.dumps(sorted(lease.targets)),
                    created.timestamp(),
                    lease.runtime_identity,
                ),
            )

    def load(self, lease_id: str) -> FaultLease | None:
        rows = self._store.query("SELECT * FROM fault_leases WHERE id = ?", (lease_id,))
        return _row_to_lease(dict(rows[0])) if rows else None

    def active_leases(self) -> tuple[FaultLease, ...]:
        placeholders = ", ".join("?" for _ in _TERMINAL_STATES)
        rows = self._store.query(
            f"SELECT * FROM fault_leases WHERE state NOT IN ({placeholders})"
            " ORDER BY created_epoch_s",
            _TERMINAL_STATES,
        )
        return tuple(_row_to_lease(dict(row)) for row in rows)

    def expired_pending(self, now_epoch_s: float) -> tuple[FaultLease, ...]:
        rows = self._store.query(
            "SELECT * FROM fault_leases WHERE created_epoch_s + ttl_seconds < ? "
            "AND state IN ('pending', 'active')",
            (now_epoch_s,),
        )
        return tuple(_row_to_lease(dict(row)) for row in rows)

    def next_sequence(self) -> int:
        # Max trailing integer of every `l-<n>` id ever persisted. Seed the next
        # run's counter here so ids never collide in a shared DB.
        rows = self._store.query(
            "SELECT MAX(CAST(substr(id, 3) AS INTEGER)) AS seq FROM fault_leases"
            " WHERE id LIKE 'l-%'"
        )
        if not rows:
            return 0
        seq = rows[0]["seq"]
        return int(seq) if seq is not None else 0


def _row_to_lease(row: Mapping[str, object]) -> FaultLease:
    return FaultLease.model_validate(
        {
            "id": str(row["id"]),
            "state": LeaseState(str(row["state"])),
            "owner_agent": str(row["owner_agent"]),
            "undo_ops": json.loads(str(row["undo_json"])),
            "verify_probes": json.loads(str(row["verify_json"])),
            "ttl_seconds": float(str(row["ttl_seconds"])),
            "injected_at": _dt_or_none(row.get("injected_at")),
            "released_at": _dt_or_none(row.get("released_at")),
            "release_mechanism": row["release_mechanism"],
            "escalation_notes": row["escalation_notes"],
            "run_id": str(row["run_id"] or ""),
            "fault_id": str(row["fault_id"] or ""),
            "targets": frozenset(json.loads(str(row["targets_json"]))),
            "created_at": datetime.fromtimestamp(float(str(row["created_epoch_s"])), tz=UTC),
            "runtime_identity": row.get("runtime_identity"),
        }
    )


def _iso_or_none(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment is not None else None


def _dt_or_none(raw: object) -> datetime | None:
    if raw is None:
        return None
    parsed = datetime.fromisoformat(str(raw))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
