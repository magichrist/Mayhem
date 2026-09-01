"""Fault leases: the recovery guarantee's core object (ADR-0005).

A lease is created *before* any mutation and persisted with write-ahead undo
data. The state machine below is the single source of truth for legal
transitions; the janitor, watchdog, and release paths all go through it.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mayhem.domain.common import Duration, utc_now
from mayhem.domain.errors import InvalidTransitionError, InvariantViolationError


class LeaseState(StrEnum):
    PENDING = "pending"  # undo written, injection not yet started
    ACTIVE = "active"  # fault applied
    RELEASING = "releasing"  # compensation in progress
    RELEASED = "released"  # compensated AND verified (safe terminal)
    EXPIRED = "expired"  # watchdog TTL fired, agent self-compensated (safe terminal)
    ORPHANED = "orphaned"  # owner unreachable; janitor will reclaim
    DIRTY = "dirty"  # compensation failed; LOUD escalation (ack required)


_TRANSITIONS: dict[LeaseState, frozenset[LeaseState]] = {
    LeaseState.PENDING: frozenset({LeaseState.ACTIVE, LeaseState.EXPIRED}),
    LeaseState.ACTIVE: frozenset({LeaseState.RELEASING, LeaseState.EXPIRED, LeaseState.ORPHANED}),
    LeaseState.ORPHANED: frozenset({LeaseState.RELEASING}),
    LeaseState.RELEASING: frozenset({LeaseState.RELEASED, LeaseState.DIRTY}),
    # Safe terminals: released, expired. Dirty is terminal-pending-acknowledgment.
    LeaseState.RELEASED: frozenset(),
    LeaseState.EXPIRED: frozenset(),
    LeaseState.DIRTY: frozenset(),
}

_SAFE_TERMINALS: frozenset[LeaseState] = frozenset({LeaseState.RELEASED, LeaseState.EXPIRED})


class UndoOp(BaseModel):
    """One compensation primitive; MUST be idempotent-first by convention."""

    model_config = ConfigDict(frozen=True)

    op: str  # executor operation name, e.g. "tc.del_qdisc"
    args: dict[str, str] = Field(default_factory=dict)
    idempotent: bool = True


class VerifyProbe(BaseModel):
    """Post-recovery assertion proving the fault is really gone."""

    model_config = ConfigDict(frozen=True)

    probe: str  # e.g. "exec", "tc.qdisc_absent", "iptables.chain_absent"
    args: dict[str, object] = Field(default_factory=dict)
    expect_present: bool = False


class FaultLease(BaseModel):
    """Immutable lease value object; transitions produce new instances."""

    model_config = ConfigDict(frozen=True)

    id: str  # l-<hex>
    run_id: str
    fault_id: str
    owner_agent: str
    targets: frozenset[str]
    undo_ops: tuple[UndoOp, ...] = ()
    verify_probes: tuple[VerifyProbe, ...] = ()
    ttl_seconds: Duration = 120.0
    state: LeaseState = LeaseState.PENDING
    created_at: datetime = Field(default_factory=utc_now)
    injected_at: datetime | None = None
    released_at: datetime | None = None
    release_mechanism: str | None = None  # normal|watchdog|janitor|manual
    escalation_notes: str | None = None
    runtime_identity: str | None = None  # canonical identity key (ADR-M1-1/1-3)

    @field_validator("id")
    @classmethod
    def _id_prefix(cls, value: str) -> str:
        if not value.startswith("l-"):
            msg = f"lease ids start with 'l-', got {value!r}"
            raise InvariantViolationError("lease_id_prefix", msg)
        return value

    @model_validator(mode="after")
    def _check_invariants(self) -> FaultLease:
        if self.state is LeaseState.ACTIVE and not self.undo_ops:
            raise InvariantViolationError(
                "undo_required_before_active",
                f"lease {self.id} cannot be ACTIVE without write-ahead undo ops",
            )
        if self.state in (LeaseState.ACTIVE, LeaseState.RELEASING) and not self.verify_probes:
            raise InvariantViolationError(
                "verify_required_before_release",
                f"lease {self.id} in {self.state.value} needs verify probes",
            )
        if self.state is LeaseState.DIRTY and not self.escalation_notes:
            raise InvariantViolationError(
                "dirty_requires_escalation_notes",
                f"lease {self.id} marked dirty without escalation notes",
            )
        if self.injected_at is not None and self.created_at > self.injected_at:
            raise InvariantViolationError(
                "lease_time_ordering", f"lease {self.id} injected before creation"
            )
        if self.released_at is not None and self.state not in _SAFE_TERMINALS:
            raise InvariantViolationError(
                "lease_time_ordering",
                f"lease {self.id} has released_at while in state {self.state.value}",
            )
        return self

    # -- state machine ------------------------------------------------------------
    def can_transition(self, target: LeaseState) -> bool:
        return target in _TRANSITIONS[self.state]

    def transition(
        self,
        target: LeaseState,
        *,
        mechanism: str | None = None,
        now: datetime | None = None,
        escalation_notes: str | None = None,
    ) -> FaultLease:
        """Return a new lease advanced to ``target``.

        Raises:
            InvalidTransitionError: If the transition is illegal.
            InvariantViolationError: If target-specific preconditions are unmet.
        """
        if not self.can_transition(target):
            raise InvalidTransitionError("fault_lease", self.id, self.state.value, target.value)
        updates: dict[str, object] = {"state": target}
        moment = now if now is not None else utc_now()
        if target is LeaseState.ACTIVE:
            updates["injected_at"] = moment
        if target in (LeaseState.RELEASED, LeaseState.EXPIRED):
            updates["released_at"] = moment
        if mechanism is not None:
            updates["release_mechanism"] = mechanism
        if escalation_notes is not None:
            updates["escalation_notes"] = escalation_notes
        # model_copy skips validators; transitions MUST re-check every invariant.
        return self.__class__.model_validate({**self.model_dump(), **updates})

    # -- classification -------------------------------------------------------------
    @property
    def is_terminal(self) -> bool:
        return not _TRANSITIONS[self.state]

    @property
    def is_safe_terminal(self) -> bool:
        return self.state in _SAFE_TERMINALS

    @property
    def needs_janitor_attention(self) -> bool:
        return self.state in (
            LeaseState.PENDING,
            LeaseState.ACTIVE,
            LeaseState.ORPHANED,
            LeaseState.DIRTY,
        )


def assert_all_recovered(leases: list[FaultLease]) -> None:
    """Run-completion invariant: no non-safe-terminal leases may remain.

    Raises:
        InvariantViolationError: Naming every offending lease.
    """
    offenders = [lease for lease in leases if not lease.is_safe_terminal]
    if offenders:
        detail = ", ".join(f"{o.id}:{o.state.value}" for o in offenders)
        raise InvariantViolationError(
            "all_leases_recovered_before_run_completion",
            f"non-recovered leases remain: {detail}",
        )
