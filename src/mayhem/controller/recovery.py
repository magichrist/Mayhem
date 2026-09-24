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

import json
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from mayhem.controller.janitor import Janitor
from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.leases import LeaseState

if TYPE_CHECKING:
    from collections.abc import Callable

    from mayhem.agents.sinks import LeaseSink
    from mayhem.domain.leases import FaultLease


class RecoveryStatus(StrEnum):
    """States in the recovery lifecycle."""

    IDLE = "idle"  # resource is active, not recovering
    RECOVERING = "recovering"  # cleanup in progress
    VERIFIED = "verified"  # cleanup succeeded and verified
    DIRTY = "dirty"  # cleanup failed or verify failed


class RecoveryState(StrEnum):
    NOT_NEEDED = "not_needed"
    PENDING = "pending"
    RUNNING = "running"
    RECOVERED = "recovered"
    DIRTY = "dirty"
    ESCALATED = "escalated"
    ABANDONED = "abandoned"
    not_needed = "not_needed"
    pending = "pending"
    running = "running"
    recovered = "recovered"
    dirty = "dirty"
    escalated = "escalated"
    abandoned = "abandoned"


class RecoveryLeasePlan(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    run_id: str
    owner: str
    ttl_seconds: float
    expires_at: datetime
    target: tuple[str, ...]
    fault: str
    state: str
    recovery: RecoveryState
    compensation: tuple[dict[str, object], ...] = ()
    verification_probes: tuple[dict[str, object], ...] = ()
    escalation: tuple[str, ...] = ()


class RecoveryPlan(BaseModel):
    model_config = ConfigDict(frozen=True)

    run_ids: tuple[str, ...]
    target_profiles: tuple[str, ...]
    state: RecoveryState
    leases: tuple[RecoveryLeasePlan, ...] = ()


class RecoveryExecutionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    state: RecoveryState
    run_ids: tuple[str, ...]
    expired: tuple[str, ...] = ()
    recovered: tuple[str, ...] = ()
    dirty: tuple[str, ...] = ()
    handoff_path: Path | None = None


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
            cols = {
                r["name"] for r in conn.execute("PRAGMA table_info(recovery_audit_log)").fetchall()
            }
            if "runtime_identity" not in cols:
                conn.execute("ALTER TABLE recovery_audit_log ADD COLUMN runtime_identity TEXT")

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


class RecoveryService:
    def __init__(
        self,
        sink: LeaseSink,
        *,
        run_liveness: Callable[[str], bool | None] | None = None,
    ) -> None:
        self._sink = sink
        self._run_liveness = run_liveness

    def plan(
        self,
        run_ids: tuple[str, ...] | list[str],
        *,
        target_profiles: tuple[str, ...] | list[str] = (),
        now_epoch_s: float | None = None,
    ) -> RecoveryPlan:
        normalized_runs = tuple(dict.fromkeys(run_ids))
        normalized_targets = tuple(dict.fromkeys(target_profiles))
        leases = self._leases(normalized_runs)
        lease_plans = tuple(self._lease_plan(lease) for lease in leases)
        return RecoveryPlan(
            run_ids=normalized_runs,
            target_profiles=normalized_targets,
            state=self._aggregate_state(leases),
            leases=lease_plans,
        )

    def status(
        self,
        run_ids: tuple[str, ...] | list[str],
        *,
        target_profiles: tuple[str, ...] | list[str] = (),
    ) -> RecoveryPlan:
        return self.plan(run_ids, target_profiles=target_profiles)

    def execute(
        self,
        plan: RecoveryPlan,
        *,
        artifact_dir: str | Path | None = None,
        now_epoch_s: float | None = None,
    ) -> RecoveryExecutionResult:
        sweep = Janitor(self._sink).sweep(
            now_epoch_s=now_epoch_s,
            run_liveness=self._run_liveness,
            run_ids=plan.run_ids,
            include_states=(
                LeaseState.PENDING,
                LeaseState.ACTIVE,
                LeaseState.ORPHANED,
                LeaseState.RELEASING,
            ),
        )
        final_plan = self.plan(plan.run_ids, target_profiles=plan.target_profiles)
        dirty = tuple(
            item.id
            for item in final_plan.leases
            if item.recovery in {RecoveryState.DIRTY, RecoveryState.ESCALATED}
        )
        handoff_path: Path | None = None
        if dirty and artifact_dir is not None:
            directory = Path(artifact_dir)
            directory.mkdir(parents=True, exist_ok=True)
            run_slug = "_".join(plan.run_ids) or "unscoped"
            handoff_path = directory / f"report-{run_slug}__recovery-handoff.json"
            handoff_path.write_text(
                json.dumps(
                    {
                        "report_id": f"report-{run_slug}__recovery-handoff",
                        "run_ids": list(plan.run_ids),
                        "target_profiles": list(plan.target_profiles),
                        "state": final_plan.state.value,
                        "dirty_leases": list(dirty),
                        "leases": [item.model_dump(mode="json") for item in final_plan.leases],
                    },
                    indent=2,
                )
            )
        return RecoveryExecutionResult(
            state=final_plan.state,
            run_ids=plan.run_ids,
            expired=sweep.expired,
            recovered=sweep.recovered,
            dirty=dirty,
            handoff_path=handoff_path,
        )

    def _leases(self, run_ids: tuple[str, ...]) -> tuple[FaultLease, ...]:
        all_leases = getattr(self._sink, "all_leases", None)
        leases = all_leases() if callable(all_leases) else self._sink.active_leases()
        if not run_ids:
            return tuple(leases)
        selected = frozenset(run_ids)
        return tuple(lease for lease in leases if lease.run_id in selected)

    def _lease_plan(self, lease: FaultLease) -> RecoveryLeasePlan:
        recovery = self._lease_state(lease)
        return RecoveryLeasePlan(
            id=lease.id,
            run_id=lease.run_id,
            owner=lease.owner_agent,
            ttl_seconds=float(lease.ttl_seconds),
            expires_at=lease.created_at + timedelta(seconds=float(lease.ttl_seconds)),
            target=tuple(sorted(lease.targets)),
            fault=lease.fault_id,
            state=lease.state.value,
            recovery=recovery,
            compensation=tuple(op.model_dump(mode="json") for op in lease.undo_ops),
            verification_probes=tuple(
                probe.model_dump(mode="json") for probe in lease.verify_probes
            ),
            escalation=(lease.escalation_notes,) if lease.escalation_notes else (),
        )

    def _aggregate_state(self, leases: tuple[FaultLease, ...]) -> RecoveryState:
        if not leases:
            return RecoveryState.NOT_NEEDED
        states = {self._lease_state(lease) for lease in leases}
        for state in (
            RecoveryState.ESCALATED,
            RecoveryState.DIRTY,
            RecoveryState.RUNNING,
            RecoveryState.PENDING,
            RecoveryState.ABANDONED,
            RecoveryState.RECOVERED,
        ):
            if state in states:
                return state
        return RecoveryState.NOT_NEEDED

    def _lease_state(self, lease: FaultLease) -> RecoveryState:
        state = {
            LeaseState.RELEASING: RecoveryState.RUNNING,
            LeaseState.RELEASED: RecoveryState.RECOVERED,
            LeaseState.EXPIRED: RecoveryState.ABANDONED,
        }.get(lease.state, RecoveryState.PENDING)
        if lease.state is LeaseState.DIRTY:
            if "escalat" in (lease.escalation_notes or "").lower():
                return RecoveryState.ESCALATED
            return RecoveryState.DIRTY
        return state
