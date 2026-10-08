"""Durable schedule state for the Phase 2 scheduler (plan 13).

Three tables, three different jobs, and the split is the point:

``schedules``
    The registry: which schedules exist, which campaign run each one fires
    into, and the per-schedule counters (``run_count`` for the schedule's own
    budget, ``window_index`` for the fairness window it last took part in). The
    schedule body is stored as JSON beside a digest of itself, so an edited
    recurrence is recognisable as a different body instead of silently
    continuing a run its author changed underneath it.

``schedule_runs``
    The **claim ledger**, and the mechanism the whole no-double-fire guarantee
    rests on. One row per fire attempt that got as far as intending to execute,
    keyed by ``idempotency_key`` -- the primary key. A controller that restarts
    re-derives the same key for the same slot, so a second attempt to fire an
    already-fired slot is a primary-key violation *in the database* rather than
    a race the application has to remember to prevent.
    :meth:`ScheduleStore.claim_slot` is the only writer, and it is a plain
    ``INSERT``; nothing in this module ever replaces a claim.

``game_day_dispatch_steps``
    The game-day half: dispatch injected as a session step whose facilitator
    hold is durable state the scheduler reads *at fire time*. A hold is a gate
    checked against this table, not a delay the scheduler waits out, which is
    what makes it survive a restart that happens while the game day is paused.

Two refusals that would otherwise be silent:

* :meth:`ScheduleStore.delete_schedule` refuses to delete a schedule that has
  claims. The foreign key would refuse it anyway; doing it here means the
  operator gets a typed error naming the reason instead of a driver-level
  ``IntegrityError``.
* A ``claimed`` row with no ``settled_at`` is *not* retried. The controller
  that wrote it may have died between claiming and executing, and re-running an
  unknown-outcome dispatch is precisely the double-fire this ledger prevents.
  Resolving it is an operator decision, recorded as one.

The state vocabularies live here rather than in the controller because they are
the values the ``CHECK`` constraints above pin: a typo in a state string is a
migration-level refusal, not a runtime surprise.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import digest
from mayhem.domain.scheduling import ConcurrencyClass, GrantRecord, Schedule

if TYPE_CHECKING:
    from mayhem.infra.store import Store

#: How long a scheduled run holds the resources it declared, when the entry does
#: not say. Long enough to cover a drill, short enough that a controller which
#: dies holding a lock does not fence a resource for ever.
DEFAULT_LOCK_WINDOW_S: float = 3600.0


class RunClaimState(StrEnum):
    """How far one claimed dispatch got. Pinned by the ``schedule_runs`` CHECK."""

    CLAIMED = "claimed"
    """Intent recorded; execution not confirmed. Retried by nobody."""

    DISPATCHED = "dispatched"
    """The pipeline returned a run id. This slot is spent."""

    FAILED = "failed"
    """The pipeline was entered and returned a refusal or an error."""


class HoldState(StrEnum):
    """A game-day dispatch step's facilitator hold. Pinned by its CHECK."""

    HELD = "held"
    RELEASED = "released"
    DISPATCHED = "dispatched"


class ClaimOutcome(StrEnum):
    """What :meth:`ScheduleStore.claim_slot` did."""

    CLAIMED = "claimed"
    ALREADY_CLAIMED = "already_claimed"


@dataclass(frozen=True)
class ClaimResult:
    """The outcome of one claim attempt and the row that decided it.

    ``record`` is the row now in the table: the one this call wrote when the
    outcome is ``CLAIMED``, and the one that was *already* there when it is
    ``ALREADY_CLAIMED``. :attr:`holder` separates the two by name so a caller
    cannot mistake "I claimed it" for "somebody else already did".
    """

    outcome: ClaimOutcome
    record: ScheduleRunRecord

    @property
    def fresh(self) -> bool:
        return self.outcome is ClaimOutcome.CLAIMED

    @property
    def holder(self) -> ScheduleRunRecord | None:
        """The row that already held this key, or ``None`` when this call took it."""
        return None if self.fresh else self.record


class ScheduleEntry(BaseModel):
    """One registered schedule and the campaign run it fires into.

    ``team`` is read off the schedule body rather than restated, because two
    copies of a team's name is one copy too many for a fairness policy to trust.
    A schedule with no team is refused: fairness is by team, and a schedule that
    cannot be attributed to one has no share to hold.

    The concurrency triple is how the schedule declares what its run touches,
    and it is part of the *binding* rather than of the fire-time inputs on
    purpose: a schedule that says nothing about the resources it uses cannot be
    serialised against anything, and refusing that at registration is far
    cheaper than discovering it when two drills collide. A non-``PARALLEL``
    class with no resources is therefore refused here rather than being admitted
    as a run that silently conflicts with nothing.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schedule: Schedule
    campaign_id: str = Field(min_length=1)
    experiment_id: str = Field(min_length=1)
    concurrency_class: ConcurrencyClass = ConcurrencyClass.EXCLUSIVE
    resources: tuple[str, ...] = ()
    lock_window_s: float = Field(default=DEFAULT_LOCK_WINDOW_S, gt=0.0)
    enabled: bool = True
    #: The fairness window this schedule last took part in. Caller-owned
    #: numbering, persisted so a restarted controller can resume the same
    #: sequence rather than restarting the count and starving everyone.
    window_index: int = Field(default=0, ge=0)
    #: How many runs this schedule has dispatched, which is what
    #: :meth:`mayhem.domain.scheduling.Schedule.evaluate` charges against
    #: ``max_runs``.
    run_count: int = Field(default=0, ge=0)
    last_slot_start: datetime | None = None
    last_dispatch_at: datetime | None = None
    #: Cached next fire instant for the ``idx_schedules_due`` index. Derived from
    #: the schedule body, never read as truth: a stale cache costs a query, and
    #: the authoritative answer is always ``Schedule.next_fire_time``.
    next_fire_at: datetime | None = None
    created_at: str = ""
    updated_at: str = ""

    @model_validator(mode="after")
    def _check_entry(self) -> ScheduleEntry:
        if not self.schedule.team:
            msg = (
                f"schedule {self.schedule.schedule_id!r} names no team; fairness "
                "allocates by team, so an unattributable schedule has no share"
            )
            raise InvariantViolationError("schedule.entry_team", msg)
        if len(set(self.resources)) != len(self.resources):
            msg = (
                f"schedule {self.schedule.schedule_id!r} names a resource twice: "
                f"{list(self.resources)}"
            )
            raise InvariantViolationError("schedule.entry_resource_duplicate", msg)
        if self.concurrency_class is ConcurrencyClass.PARALLEL and self.resources:
            msg = (
                f"schedule {self.schedule.schedule_id!r} is parallel but names "
                f"{list(self.resources)}; a parallel run takes no resource locks, so it "
                "cannot also reserve one"
            )
            raise InvariantViolationError("schedule.entry_parallel_resources", msg)
        if self.concurrency_class is not ConcurrencyClass.PARALLEL and not self.resources:
            msg = (
                f"schedule {self.schedule.schedule_id!r} is "
                f"{self.concurrency_class.value} but names no resource; a run that "
                "declares nothing it touches can never be serialised against another"
            )
            raise InvariantViolationError("schedule.entry_resources", msg)
        return self

    @property
    def schedule_id(self) -> str:
        return self.schedule.schedule_id

    @property
    def team(self) -> str:
        return self.schedule.team

    @property
    def body_digest(self) -> str:
        return digest(self.schedule.model_dump(mode="json"))

    def after_dispatch(
        self, *, slot_start: datetime, at: datetime, window_index: int
    ) -> ScheduleEntry:
        """This entry with its run budget and window advanced by one dispatch."""
        return self.model_copy(
            update={
                "run_count": self.run_count + 1,
                "last_slot_start": slot_start,
                "last_dispatch_at": at,
                "window_index": max(self.window_index, window_index),
                "next_fire_at": self.schedule.next_fire_time(at),
            }
        )

    def seen_in(self, *, window_index: int) -> ScheduleEntry:
        """This entry as of a tick that evaluated it, dispatched or not.

        Deliberately does **not** refresh ``next_fire_at``.
        :meth:`mayhem.domain.scheduling.Schedule.next_fire_time` walks the cron
        minute by minute inside a bounded search (``max_steps``, up to a year of
        minutes), so a sparse expression such as ``@yearly`` costs six figures of
        iterations to answer. Paying that on every tick of every schedule, for a
        cache that is only ever a *hint* — the authoritative answer is always
        :meth:`Schedule.next_fire_time` — would be a scheduler that spends its
        time computing something it is allowed to be stale about. The cache is
        refreshed when the schedule actually dispatches.
        """
        return self.model_copy(update={"window_index": max(self.window_index, window_index)})


class ScheduleRunRecord(BaseModel):
    """One row of the claim ledger: a fire attempt that reached the pipeline."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    idempotency_key: str = Field(min_length=1)
    schedule_id: str = Field(min_length=1)
    team: str = ""
    campaign_id: str = ""
    experiment_id: str = ""
    window_index: int = Field(default=0, ge=0)
    slot_start: datetime
    effective_at: datetime
    state: RunClaimState = RunClaimState.CLAIMED
    #: The ``FireCode`` or ``DispatchCode`` the attempt settled on, as text.
    #: Text rather than an enum so one ledger can hold both vocabularies.
    code: str = ""
    reason: str = ""
    run_id: str = ""
    controller_id: str = ""
    detail: dict[str, Any] = Field(default_factory=dict)
    recorded_at: datetime
    settled_at: datetime | None = None

    @property
    def settled(self) -> bool:
        return self.settled_at is not None

    def is_live_claim(self) -> bool:
        """True when an attempt was recorded but never settled.

        A live claim is an unknown outcome, not a pending one, and the
        difference is the whole reason the ledger does not retry it.
        """
        return self.state is RunClaimState.CLAIMED and not self.settled


class GameDayStepRecord(BaseModel):
    """One game-day session step that dispatches through the scheduler.

    ``hold_state`` is a gate, not a countdown. The scheduler reads this table
    at fire time; a step still ``held`` refuses its dispatch however clear
    every other condition is, and ``released_by`` names the facilitator who let
    it go.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    session_id: str = Field(min_length=1)
    step_id: str = Field(min_length=1)
    step_seq: int = Field(default=0, ge=0)
    scenario: str = ""
    schedule_id: str = Field(min_length=1)
    hold_state: HoldState = HoldState.HELD
    hold_reason: str = ""
    released_by: str = ""
    released_at: str = ""
    dispatched_at: str = ""
    note: str = ""
    created_at: str = ""
    updated_at: str = ""

    @property
    def key(self) -> str:
        return f"{self.session_id}:{self.step_id}"

    @property
    def released(self) -> bool:
        return self.hold_state in {HoldState.RELEASED, HoldState.DISPATCHED}

    @property
    def held(self) -> bool:
        return self.hold_state is HoldState.HELD


class ScheduleStore:
    """Persistence for the scheduler. Single-writer, like every other store."""

    def __init__(self, store: Store) -> None:
        self._store = store

    # -- schedules ----------------------------------------------------------

    def save_schedule(self, entry: ScheduleEntry) -> ScheduleEntry:
        schedule = entry.schedule
        stamp = entry.updated_at or _now()
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO schedules "
                "(schedule_id, name, team, campaign_id, experiment_id, concurrency_class, "
                " resources_json, lock_window_s, kind, timezone_name, enabled, window_index, "
                " run_count, last_slot_start, last_dispatch_at, next_fire_at, "
                " schedule_digest, schedule_json, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    schedule.schedule_id,
                    schedule.name,
                    schedule.team,
                    entry.campaign_id,
                    entry.experiment_id,
                    entry.concurrency_class.value,
                    json.dumps(list(entry.resources)),
                    entry.lock_window_s,
                    schedule.kind.value,
                    schedule.timezone_name,
                    int(entry.enabled),
                    entry.window_index,
                    entry.run_count,
                    _iso(entry.last_slot_start),
                    _iso(entry.last_dispatch_at),
                    _iso(entry.next_fire_at),
                    entry.body_digest,
                    schedule.model_dump_json(),
                    entry.created_at or stamp,
                    stamp,
                ),
            )
        return entry.model_copy(update={"updated_at": stamp})

    def load_schedule(self, schedule_id: str) -> ScheduleEntry | None:
        rows = self._store.query(
            f"SELECT {_ENTRY_COLUMNS} FROM schedules WHERE schedule_id = ?", (schedule_id,)
        )
        return _entry(rows[0]) if rows else None

    def list_schedules(self, *, enabled_only: bool = False) -> tuple[ScheduleEntry, ...]:
        """Every registered schedule, id-sorted.

        Sorted because the fairness layer's tiebreak is a name comparison: an
        unordered listing would make the same set of due schedules dispatch in
        a different order on a different SQLite version.
        """
        sql = f"SELECT {_ENTRY_COLUMNS} FROM schedules"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY schedule_id"
        return tuple(_entry(row) for row in self._store.query(sql))

    def set_enabled(self, schedule_id: str, *, enabled: bool) -> ScheduleEntry | None:
        """Flip a schedule's enabled flag; ``None`` when it is not registered."""
        existing = self.load_schedule(schedule_id)
        if existing is None:
            return None
        return self.save_schedule(existing.model_copy(update={"enabled": enabled}))

    def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a schedule that has never dispatched anything.

        Raises:
            InvariantViolationError: If the schedule has claims. Deleting one
                would orphan the evidence that it ran, so the refusal is here
                with a name rather than left to the foreign key.
        """
        claims = self._store.query(
            "SELECT idempotency_key FROM schedule_runs WHERE schedule_id = ? "
            "ORDER BY idempotency_key",
            (schedule_id,),
        )
        if claims:
            msg = (
                f"schedule {schedule_id!r} has {len(claims)} dispatch record(s) and "
                "will not be deleted; the evidence that it ran outlives the trigger"
            )
            raise InvariantViolationError("schedule.delete_with_claims", msg)
        with self._store.write() as conn:
            cursor = conn.execute("DELETE FROM schedules WHERE schedule_id = ?", (schedule_id,))
        return bool(cursor.rowcount)

    # -- the claim ledger ---------------------------------------------------

    def claim_slot(self, record: ScheduleRunRecord) -> ClaimResult:
        """Take the claim for one fire slot, or report that it is already taken.

        The only path that writes a ``schedule_runs`` row, and it is a bare
        ``INSERT`` -- never ``INSERT OR REPLACE``. A repeat of an existing key
        is the whole no-double-fire guarantee, so the statement has to fail
        rather than succeed quietly; that is why the conflict is caught and
        *reported* here instead of being prevented by a read a moment earlier.
        """
        with self._store.write() as conn:
            try:
                conn.execute(
                    "INSERT INTO schedule_runs "
                    "(idempotency_key, schedule_id, team, campaign_id, experiment_id, "
                    " window_index, slot_start, effective_at, state, code, reason, run_id, "
                    " controller_id, detail_json, recorded_at, settled_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        record.idempotency_key,
                        record.schedule_id,
                        record.team,
                        record.campaign_id,
                        record.experiment_id,
                        record.window_index,
                        _iso(record.slot_start),
                        _iso(record.effective_at),
                        record.state.value,
                        record.code,
                        record.reason,
                        record.run_id,
                        record.controller_id,
                        json.dumps(record.detail, sort_keys=True),
                        _iso(record.recorded_at),
                        _iso(record.settled_at),
                    ),
                )
            except sqlite3.IntegrityError:
                existing = self.load_run(record.idempotency_key)
                if existing is None:
                    # The conflict was the foreign key, not the primary key:
                    # this run claims a schedule nobody registered. Surfacing
                    # that as "already claimed" would hide an authoring bug.
                    raise
                return ClaimResult(outcome=ClaimOutcome.ALREADY_CLAIMED, record=existing)
        return ClaimResult(outcome=ClaimOutcome.CLAIMED, record=record)

    def settle_slot(
        self,
        idempotency_key: str,
        *,
        state: RunClaimState,
        code: str,
        reason: str,
        at: datetime,
        run_id: str = "",
        detail: dict[str, Any] | None = None,
    ) -> ScheduleRunRecord:
        """Record how a claimed dispatch ended.

        Raises:
            InvariantViolationError: If no claim exists for ``idempotency_key``.
                Settling a claim that was never taken means the caller reached
                the pipeline without claiming, and that is a bug worth a loud
                failure rather than a no-op update.
        """
        with self._store.write() as conn:
            cursor = conn.execute(
                "UPDATE schedule_runs SET state = ?, code = ?, reason = ?, settled_at = ?, "
                "run_id = CASE WHEN ? = '' THEN run_id ELSE ? END, detail_json = ? "
                "WHERE idempotency_key = ?",
                (
                    state.value,
                    code,
                    reason,
                    _iso(at),
                    run_id,
                    run_id,
                    json.dumps(detail or {}, sort_keys=True),
                    idempotency_key,
                ),
            )
            missing = not cursor.rowcount
        if missing:
            msg = (
                f"cannot settle dispatch {idempotency_key!r}: no claim was ever taken "
                "for it, so there is no outcome to record"
            )
            raise InvariantViolationError("schedule.claim_missing", msg)
        settled = self.load_run(idempotency_key)
        if settled is None:  # pragma: no cover - the UPDATE matched a row
            msg = f"dispatch {idempotency_key!r} vanished while it was being settled"
            raise InvariantViolationError("schedule.claim_missing", msg)
        return settled

    def load_run(self, idempotency_key: str) -> ScheduleRunRecord | None:
        rows = self._store.query(
            "SELECT * FROM schedule_runs WHERE idempotency_key = ?", (idempotency_key,)
        )
        return _run(rows[0]) if rows else None

    def runs_for_schedule(self, schedule_id: str) -> tuple[ScheduleRunRecord, ...]:
        rows = self._store.query(
            "SELECT * FROM schedule_runs WHERE schedule_id = ? ORDER BY slot_start, "
            "idempotency_key",
            (schedule_id,),
        )
        return tuple(_run(row) for row in rows)

    def dispatch_count(self, schedule_id: str) -> int:
        rows = self._store.query(
            "SELECT COUNT(*) FROM schedule_runs WHERE schedule_id = ? AND state = ?",
            (schedule_id, RunClaimState.DISPATCHED.value),
        )
        return int(rows[0][0]) if rows else 0

    def grant_history(self, *, upto_window: int | None = None) -> tuple[GrantRecord, ...]:
        """Every dispatched slot as a fairness grant, in window order.

        Read from the ledger rather than from an in-memory counter, which is
        what makes fairness survive a controller restart: the history a
        restarted controller compares against is the same history the previous
        one built, not a fresh start.
        """
        sql = (
            "SELECT window_index, team, schedule_id FROM schedule_runs "
            "WHERE state = ? AND team != ''"
        )
        params: tuple[object, ...] = (RunClaimState.DISPATCHED.value,)
        if upto_window is not None:
            sql += " AND window_index <= ?"
            params = (*params, upto_window)
        sql += " ORDER BY window_index, team, schedule_id"
        return tuple(
            GrantRecord(window_index=int(row[0]), team=str(row[1]), schedule_id=str(row[2]))
            for row in self._store.query(sql, params)
        )

    def max_window_index(self) -> int:
        """The highest window index any schedule or claim has recorded."""
        rows = self._store.query(
            "SELECT MAX(window_index) FROM ("
            " SELECT MAX(window_index) AS window_index FROM schedules"
            " UNION ALL SELECT MAX(window_index) FROM schedule_runs)"
        )
        value = rows[0][0] if rows else None
        return int(value) if value is not None else 0

    # -- game-day steps -----------------------------------------------------

    def save_step(self, step: GameDayStepRecord) -> GameDayStepRecord:
        stamp = step.updated_at or _now()
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO game_day_dispatch_steps "
                "(session_id, step_id, step_seq, scenario, schedule_id, hold_state, "
                " hold_reason, released_by, released_at, dispatched_at, step_json, "
                " created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    step.session_id,
                    step.step_id,
                    step.step_seq,
                    step.scenario,
                    step.schedule_id,
                    step.hold_state.value,
                    step.hold_reason,
                    step.released_by,
                    step.released_at,
                    step.dispatched_at,
                    step.model_dump_json(),
                    step.created_at or stamp,
                    stamp,
                ),
            )
        return step.model_copy(update={"updated_at": stamp})

    def load_step(self, session_id: str, step_id: str) -> GameDayStepRecord | None:
        rows = self._store.query(
            "SELECT step_json FROM game_day_dispatch_steps WHERE session_id = ? AND step_id = ?",
            (session_id, step_id),
        )
        if not rows:
            return None
        return GameDayStepRecord.model_validate_json(str(dict(rows[0])["step_json"]))

    def steps_for_session(self, session_id: str) -> tuple[GameDayStepRecord, ...]:
        rows = self._store.query(
            "SELECT step_json FROM game_day_dispatch_steps WHERE session_id = ? "
            "ORDER BY step_seq, step_id",
            (session_id,),
        )
        return tuple(
            GameDayStepRecord.model_validate_json(str(dict(row)["step_json"])) for row in rows
        )

    def steps_for_schedule(self, schedule_id: str) -> tuple[GameDayStepRecord, ...]:
        """Every game-day step that dispatches ``schedule_id``, seq-ordered."""
        rows = self._store.query(
            "SELECT step_json FROM game_day_dispatch_steps WHERE schedule_id = ? "
            "ORDER BY step_seq, step_id",
            (schedule_id,),
        )
        return tuple(
            GameDayStepRecord.model_validate_json(str(dict(row)["step_json"])) for row in rows
        )

    # -- evidence -----------------------------------------------------------

    def record_tick(self, report: dict[str, Any], *, controller_id: str = "") -> None:
        """Record one scheduler tick's decisions as an observation.

        The claim ledger records what *ran*; this records what was *asked*.
        A refusal that never reached a claim -- a blackout, a closed window, an
        active incident -- is a fact about an evaluation, and putting it in the
        same table whose primary key means "this slot ran" would make the two
        indistinguishable.
        """
        self._store.save_observation(
            "schedule.tick",
            source=controller_id,
            data=report,
        )


# =============================================================================
# Row decoding
# =============================================================================

#: Every column :func:`_entry` reads. Named once so the two queries that build
#: entries cannot drift apart and fail only on the second of them.
_ENTRY_COLUMNS = (
    "schedule_json, campaign_id, experiment_id, concurrency_class, resources_json, "
    "lock_window_s, enabled, window_index, run_count, last_slot_start, last_dispatch_at, "
    "next_fire_at, created_at, updated_at"
)


def _entry(row: sqlite3.Row) -> ScheduleEntry:
    data = dict(row)
    return ScheduleEntry(
        schedule=Schedule.model_validate_json(str(data["schedule_json"])),
        campaign_id=str(data["campaign_id"]),
        experiment_id=str(data["experiment_id"]),
        concurrency_class=ConcurrencyClass(str(data["concurrency_class"])),
        resources=tuple(str(name) for name in json.loads(str(data["resources_json"]))),
        lock_window_s=float(data["lock_window_s"]),
        enabled=bool(data["enabled"]),
        window_index=int(data["window_index"]),
        run_count=int(data["run_count"]),
        last_slot_start=_parse(data["last_slot_start"]),
        last_dispatch_at=_parse(data["last_dispatch_at"]),
        next_fire_at=_parse(data["next_fire_at"]),
        created_at=str(data["created_at"]),
        updated_at=str(data["updated_at"]),
    )


def _run(row: sqlite3.Row) -> ScheduleRunRecord:
    data = dict(row)
    return ScheduleRunRecord(
        idempotency_key=str(data["idempotency_key"]),
        schedule_id=str(data["schedule_id"]),
        team=str(data["team"]),
        campaign_id=str(data["campaign_id"]),
        experiment_id=str(data["experiment_id"]),
        window_index=int(data["window_index"]),
        slot_start=_required(data["slot_start"], "slot_start"),
        effective_at=_required(data["effective_at"], "effective_at"),
        state=RunClaimState(str(data["state"])),
        code=str(data["code"]),
        reason=str(data["reason"]),
        run_id=str(data["run_id"]),
        controller_id=str(data["controller_id"]),
        detail=json.loads(str(data["detail_json"])),
        recorded_at=_required(data["recorded_at"], "recorded_at"),
        settled_at=_parse(data["settled_at"]),
    )


def _required(value: object, column: str) -> datetime:
    parsed = _parse(value)
    if parsed is None:
        msg = f"schedule_runs.{column} is not a timestamp: {value!r}"
        raise InvariantViolationError("schedule.run_column", msg)
    return parsed


def _parse(value: object) -> datetime | None:
    if value is None or value == "":
        return None
    return datetime.fromisoformat(str(value))


def _iso(value: datetime | None) -> str:
    return "" if value is None else value.isoformat()


def _now() -> str:
    return datetime.now(UTC).isoformat()
