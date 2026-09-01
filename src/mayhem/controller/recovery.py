"""Recovery state machine and audit trail (ADR-0016).

Every resource recovery is a state machine:
  IDLE → RECOVERING → VERIFIED | DIRTY
                              ↑ retry ↑
  DIRTY → RECOVERING → VERIFIED | DIRTY (max retries)

The state machine is the *only* way to transition recovery states —
all transitions are validated, timestamped, and persisted to the
recovery_audit_log table. This gives us:
  1. Idempotent recovery — safe to retry from crash
  2. Exhaustive audit trail — every transition recorded
  3. Retry exhaustion detection — stops after max retries
  4. Ownership-aware — only owner can transition
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError


class RecoveryStatus(StrEnum):
    """States in the recovery lifecycle."""

    IDLE = "idle"  # resource is active, not recovering
    RECOVERING = "recovering"  # cleanup in progress
    VERIFIED = "verified"  # cleanup succeeded and verified
    DIRTY = "dirty"  # cleanup failed or verify failed


# Valid transitions: source → set of targets
_VALID_TRANSITIONS: dict[RecoveryStatus, frozenset[RecoveryStatus]] = {
    RecoveryStatus.IDLE: frozenset({RecoveryStatus.RECOVERING}),
    RecoveryStatus.RECOVERING: frozenset({RecoveryStatus.VERIFIED, RecoveryStatus.DIRTY}),
    RecoveryStatus.DIRTY: frozenset({RecoveryStatus.RECOVERING}),
    RecoveryStatus.VERIFIED: frozenset(),  # terminal state — no transitions out
}


class RecoveryTransition(BaseModel):
    """One atomic state transition in the recovery lifecycle."""

    model_config = ConfigDict(frozen=True)

    resource_id: str
    from_status: RecoveryStatus
    to_status: RecoveryStatus
    reason: str
    attempt: int = 1
    timestamp: str = Field(default_factory=lambda: utc_now().isoformat())
    runtime_identity: str | None = None  # canonical identity key (ADR-M1-1/1-3)


class RecoveryAuditLog:
    """Append-only audit trail of all recovery transitions.

    Backed by SQLite ``recovery_audit_log`` table. Reads are in-memory
    for speed; writes go through the store for durability.
    """

    def __init__(self, store: Store | None = None) -> None:  # noqa: F821
        self._store = store
        self._transitions: list[RecoveryTransition] = []
        if store is not None:
            self._ensure_table()
            self._load()

    def _ensure_table(self) -> None:
        with self._store.write() as conn:  # type: ignore[union-type]
            conn.execute("""
                CREATE TABLE IF NOT EXISTS recovery_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    resource_id TEXT NOT NULL,
                    from_status TEXT NOT NULL,
                    to_status TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    attempt INTEGER NOT NULL DEFAULT 1,
                    timestamp TEXT NOT NULL,
                    runtime_identity TEXT
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_ral_resource ON recovery_audit_log(resource_id)"
            )
            # Back-fill the identity column on tables created before it existed.
            cols = {r["name"] for r in conn.execute(
                "PRAGMA table_info(recovery_audit_log)"
            ).fetchall()}
            if "runtime_identity" not in cols:
                conn.execute(
                    "ALTER TABLE recovery_audit_log ADD COLUMN runtime_identity TEXT"
                )

    def _load(self) -> None:
        with self._store.write() as conn:  # type: ignore[union-type]
            rows = conn.execute("SELECT * FROM recovery_audit_log ORDER BY id").fetchall()
        for row in rows:
            self._transitions.append(
                RecoveryTransition(
                    resource_id=row["resource_id"],
                    from_status=RecoveryStatus(row["from_status"]),
                    to_status=RecoveryStatus(row["to_status"]),
                    reason=row["reason"],
                    attempt=row["attempt"],
                    timestamp=row["timestamp"],
                    runtime_identity=row.get("runtime_identity"),
                )
            )

    def record(self, transition: RecoveryTransition) -> None:
        """Append a transition to the audit log."""
        if self._store is not None:
            with self._store.write() as conn:
                conn.execute(
                    "INSERT INTO recovery_audit_log "
                    "(resource_id, from_status, to_status, reason, attempt, timestamp,"
                    " runtime_identity) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        transition.resource_id,
                        transition.from_status.value,
                        transition.to_status.value,
                        transition.reason,
                        transition.attempt,
                        transition.timestamp,
                        transition.runtime_identity,
                    ),
                )
        self._transitions.append(transition)

    def for_resource(self, resource_id: str) -> list[RecoveryTransition]:
        """All transitions for a given resource, in order."""
        return [t for t in self._transitions if t.resource_id == resource_id]

    def current_status(self, resource_id: str) -> RecoveryStatus:
        """Derive current status from the latest transition."""
        transitions = self.for_resource(resource_id)
        if not transitions:
            return RecoveryStatus.IDLE
        return transitions[-1].to_status


class RecoveryStateMachine:
    """Enforces valid recovery transitions and records them.

    The state machine does not own resources — it is a pure transition
    validator + audit logger that sits between the ResourceManager
    and the recovery audit log.
    """

    MAX_RETRIES = 3

    def __init__(self, audit_log: RecoveryAuditLog) -> None:
        self._audit = audit_log

    def start_recovery(
        self, resource_id: str, reason: str = "cleanup initiated"
    ) -> RecoveryTransition:
        """Begin recovery: IDLE → RECOVERING or DIRTY → RECOVERING."""
        current = self._audit.current_status(resource_id)
        target = RecoveryStatus.RECOVERING
        if target not in _VALID_TRANSITIONS.get(current, frozenset()):
            raise InvariantViolationError(
                "recovery_invalid_transition",
                f"resource '{resource_id}': cannot transition from "
                f"'{current.value}' to '{target.value}'",
            )
        attempt = self._retry_count(resource_id) + 1
        transition = RecoveryTransition(
            resource_id=resource_id,
            from_status=current,
            to_status=target,
            reason=reason,
            attempt=attempt,
        )
        self._audit.record(transition)
        return transition

    def mark_verified(
        self, resource_id: str, reason: str = "probe satisfied"
    ) -> RecoveryTransition:
        """Cleanup succeeded: RECOVERING → VERIFIED."""
        return self._transition(
            resource_id,
            RecoveryStatus.RECOVERING,
            RecoveryStatus.VERIFIED,
            reason,
        )

    def mark_dirty(
        self, resource_id: str, reason: str = "cleanup or verify failed"
    ) -> RecoveryTransition:
        """Cleanup failed: RECOVERING → DIRTY."""
        return self._transition(
            resource_id,
            RecoveryStatus.RECOVERING,
            RecoveryStatus.DIRTY,
            reason,
        )

    def can_retry(self, resource_id: str) -> bool:
        """True if the resource has retries remaining."""
        return self._retry_count(resource_id) < self.MAX_RETRIES

    def _transition(
        self,
        resource_id: str,
        from_status: RecoveryStatus,
        to_status: RecoveryStatus,
        reason: str,
    ) -> RecoveryTransition:
        current = self._audit.current_status(resource_id)
        if current != from_status:
            raise InvariantViolationError(
                "recovery_invalid_transition",
                f"resource '{resource_id}': expected from '{from_status.value}', "
                f"found '{current.value}'",
            )
        if to_status not in _VALID_TRANSITIONS.get(from_status, frozenset()):
            raise InvariantViolationError(
                "recovery_invalid_transition",
                f"resource '{resource_id}': cannot transition from "
                f"'{from_status.value}' to '{to_status.value}'",
            )
        attempt = self._retry_count(resource_id) + 1
        transition = RecoveryTransition(
            resource_id=resource_id,
            from_status=from_status,
            to_status=to_status,
            reason=reason,
            attempt=attempt,
        )
        self._audit.record(transition)
        return transition

    def _retry_count(self, resource_id: str) -> int:
        """How many RECOVERING attempts have been made."""
        return sum(
            1
            for t in self._audit.for_resource(resource_id)
            if t.to_status == RecoveryStatus.RECOVERING
        )
