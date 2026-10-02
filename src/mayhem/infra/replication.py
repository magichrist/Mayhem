"""Durability for the control plane: WAL archive, snapshot ship, fenced promotion
(plan 08, Phase 2).

Plan 08's decided storage strategy is *SQLite plus replication* — keep SQLite
(the single-writer discipline of ADR-0007 and the migration chain intact) and
buy durability with replication. This module is that replication, and the part
of it that matters is the third piece:

**Fenced standby promotion.** Two primaries must never own the same run. The
mechanism is a durable, monotonic fence ledger (``repl_fences``) plus
:class:`~mayhem.domain.fabric.FencingToken` — read here, never modified, because
it is plan 03's and the whole point is that the control plane reuses the token
the agent already refuses to serve below. Every write path in this module calls
:meth:`FenceLedger.assert_current` first, so a writer that has been superseded
is refused by the store rather than discovering it at the agent.

The fence ledger is a ledger, not a flag. A fence is superseded by writing a
*strictly newer* epoch (``FencingToken.next_fence`` is the only way to grow one,
and the ``repl_fences_no_regression`` trigger refuses any UPDATE that does not
increase the epoch), and DELETE is refused outright. So the recorded epoch is
monotone by schema, and "who held this step, at which epoch" is answerable for
the whole life of a run.

The three refusals this module exists to make possible
------------------------------------------------------

* **A standby that lost its lease cannot promote.** Promotion takes the
  ``observed`` token the standby last saw. If the ledger has moved past it, the
  standby's view is stale — somebody else already took over — and promotion is
  refused with :class:`LostLeaseError`. There is no ``force=`` parameter, for
  the same reason ``evidence_bundle_io`` has no ``guard=``: a flag that skips the
  check is a flag nobody sets and everybody wishes existed.
* **A snapshot or WAL segment from a deposed primary is refused.** The check is
  made by the *receiver*, against its own fence ledger, before the first byte
  moves (:meth:`SnapshotShipper.ship`, :meth:`WalArchive.ship`). A sender
  asserting that it is still primary proves nothing; the receiver's record of
  the newest epoch is the only thing that settles it.
* **A deposed primary cannot write.** :meth:`StepLedger.record` requires the
  presenting token to be the newest one recorded for that step, and
  ``repl_step_ledger`` additionally refuses a second ``completed`` row for the
  same ``(run_id, step_id)`` through a partial unique index. Duplicate step
  execution is therefore not "prevented by convention" — the second one is a
  constraint violation.

How the drill proves it, and what the drill does not prove
----------------------------------------------------------

``tests/unit/test_replication.py`` runs a real controller-kill drill: a primary
is killed with ``SIGKILL`` in the middle of a step, a standby is promoted from a
shipped snapshot, and the promoted primary re-drives exactly the steps that were
not completed. The assertion is on *which steps ran*, counted from the ledger,
not on a claim that nothing would have run twice.

What that drill does **not** prove, stated plainly because the difference
matters for a rollout decision:

* **The standby is a cold file, in the same process.** Two ``Store`` objects in
  one interpreter, not two hosts. The filesystem, the page cache, and the
  process boundary are all shared, so this says nothing about latency, partial
  writes over a real network, or clock skew between machines.
* **The fence ledger is replicated, not quorum-witnessed**, and that is the one
  a reviewer should press on. Promotion mints ``recorded_epoch + 1`` from the
  ledger that arrived with the snapshot. Correct whenever the standby's snapshot
  is at least as new as every epoch the previous primary ever issued — a
  property of the shipping discipline, not of this code. A *partitioned* standby
  whose snapshot predates a later promotion would mint an epoch that has already
  been used.

  The consequence is worth stating as plainly as the plan allows, because it is
  the one that would be overclaimed: **a deposed primary's own database file is
  a divergent copy, and nothing in this module can refuse its writes.** Its
  ``repl_fences`` row still says epoch 1 and its ``repl_step_ledger`` still
  says the step it was halfway through is ``running``, so the checks in
  :class:`StepLedger` pass against it. What *is* refused, and what the tests
  assert, is every write and every shipped byte **checked against a ledger that
  has seen the newer epoch** — which is the check that happens in a real
  deployment, because a step write reaches whichever node currently holds the
  run, and a shipped byte is judged by the receiver.

  Closing the remaining gap needs an external witness for the epoch counter
  (etcd/consul, or one arbiter process), so that a deposed primary cannot reach
  a ledger at all. That is a deployment decision plan 08 Phase 6 owns. The
  refusal paths are all here and all tested; the end-to-end guarantee is honest
  only once the witness exists, and this is the line that would move.
"""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.fabric import FencingToken

if TYPE_CHECKING:
    from collections.abc import Sequence

    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.infra.store import Store

__all__ = [
    "RUN_SCOPE",
    "FenceLedger",
    "LostLeaseError",
    "Promotion",
    "ReplicationError",
    "ReplicationService",
    "Snapshot",
    "SnapshotRefusedError",
    "SnapshotShipper",
    "StaleFenceError",
    "StepExecution",
    "StepLedger",
    "WalArchive",
    "WalSegment",
]

#: The scope a run's *ownership* lease is fenced over.
#:
#: :class:`~mayhem.domain.fabric.FencingToken` is scoped to
#: ``(run_id, step_id)`` because plan 03 fences step ownership. A run does not
#: have a step called "itself", so the run-level lease uses this reserved scope
#: and the same table — one mechanism, two scopes, rather than a second kind of
#: lease that would need its own monotonicity argument. ``run-control`` matches
#: the token's identifier grammar, and it is reserved here so no plan step can
#: accidentally claim the same scope.
RUN_SCOPE: Final[str] = "run-control"

#: Terminal step states. ``running`` is the only non-terminal one, and it is
#: the state a step is left in when its primary dies mid-step.
TERMINAL_STEP_STATES: Final[frozenset[str]] = frozenset({"completed", "failed", "abandoned"})


class ReplicationError(InvariantViolationError):
    """Base refusal for this module. Carries a ``replication.*`` rule id.

    Subclasses :class:`~mayhem.domain.errors.InvariantViolationError` so a caller
    that only knows the domain error vocabulary still catches every one of these
    without a second hierarchy to learn.
    """


class StaleFenceError(ReplicationError):
    """A deposed writer tried to act: its fence is older than the recorded one."""


class LostLeaseError(ReplicationError):
    """A node that is no longer the primary tried to ship bytes or take over."""


class SnapshotRefusedError(ReplicationError):
    """A snapshot or WAL segment was refused by the receiver, with a reason."""


@dataclass(frozen=True, slots=True)
class StepExecution:
    """One row of the replicated step ledger: what happened to one step.

    The *head* of a step's history, not the history: ``repl_step_ledger`` keeps
    one row per ``(run_id, step_id)`` and a promotion rewrites the in-flight row
    at a newer epoch. The full ordering lives in ``repl_wal_segments``.
    """

    run_id: str
    step_id: str
    plan_digest: str
    epoch: int
    holder: str
    status: str
    started_at: str
    ended_at: str
    detail: str

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_STEP_STATES

    @property
    def completed(self) -> bool:
        return self.status == "completed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "step_id": self.step_id,
            "plan_digest": self.plan_digest,
            "epoch": self.epoch,
            "holder": self.holder,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class WalSegment:
    """One archived copy of the primary's database file, as shipped."""

    segment_seq: int
    standby_id: str
    path: Path
    digest: str
    byte_size: int
    schema_version: int | None
    fenced_epoch: int
    shipped_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "segment_seq": self.segment_seq,
            "standby_id": self.standby_id,
            "path": str(self.path),
            "digest": self.digest,
            "byte_size": self.byte_size,
            "schema_version": self.schema_version,
            "fenced_epoch": self.fenced_epoch,
            "shipped_at": self.shipped_at,
        }


@dataclass(frozen=True, slots=True)
class Snapshot:
    """One shipped copy of the primary's database, with the epoch that shipped it."""

    snapshot_id: str
    standby_id: str
    path: Path
    digest: str
    byte_size: int
    schema_version: int | None
    fenced_epoch: int
    shipped_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "standby_id": self.standby_id,
            "path": str(self.path),
            "digest": self.digest,
            "byte_size": self.byte_size,
            "schema_version": self.schema_version,
            "fenced_epoch": self.fenced_epoch,
            "shipped_at": self.shipped_at,
        }


@dataclass(frozen=True, slots=True)
class Promotion:
    """The record of one standby taking over a run, and what it must re-drive.

    ``superseded_step_ids`` are the steps the *previous* primary left in flight:
    they are the only ones a promoted primary may re-drive, and
    ``reclaimed_step_ids`` are the ones nobody had started. A step the previous
    primary completed appears in neither, which is the mechanical reason it
    cannot be executed twice.
    """

    run_id: str
    standby_id: str
    previous_holder: str
    observed_epoch: int
    fenced_epoch: int
    superseded_step_ids: tuple[str, ...]
    reclaimed_step_ids: tuple[str, ...]
    orphaned_step_ids: tuple[str, ...]
    promoted_at: str

    @property
    def resumed_step_ids(self) -> tuple[str, ...]:
        """Every step this primary owns the right to drive, in plan order."""
        return tuple(sorted({*self.superseded_step_ids, *self.reclaimed_step_ids}))

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "standby_id": self.standby_id,
            "previous_holder": self.previous_holder,
            "observed_epoch": self.observed_epoch,
            "fenced_epoch": self.fenced_epoch,
            "superseded_step_ids": list(self.superseded_step_ids),
            "reclaimed_step_ids": list(self.reclaimed_step_ids),
            "orphaned_step_ids": list(self.orphaned_step_ids),
            "resumed_step_ids": list(self.resumed_step_ids),
            "promoted_at": self.promoted_at,
        }


# ---------------------------------------------------------------------------
# the fence ledger
# ---------------------------------------------------------------------------

_FENCE_COLUMNS: Final[str] = "run_id, step_id, holder, epoch, issued_at, supersedes_epoch"
_LEDGER_COLUMNS: Final[str] = (
    "run_id, step_id, plan_digest, epoch, holder, status, started_at, ended_at, detail"
)


def _fence_from_row(row: sqlite3.Row) -> FencingToken:
    return FencingToken(
        run_id=str(row["run_id"]),
        step_id=str(row["step_id"]),
        holder=str(row["holder"]),
        epoch=int(row["epoch"]),
        issued_at=datetime.fromisoformat(str(row["issued_at"])),
        supersedes_epoch=None if row["supersedes_epoch"] is None else int(row["supersedes_epoch"]),
    )


def _execution_from_row(row: sqlite3.Row) -> StepExecution:
    return StepExecution(
        run_id=str(row["run_id"]),
        step_id=str(row["step_id"]),
        plan_digest=str(row["plan_digest"]),
        epoch=int(row["epoch"]),
        holder=str(row["holder"]),
        status=str(row["status"]),
        started_at=str(row["started_at"]),
        ended_at=str(row["ended_at"]),
        detail=str(row["detail"]),
    )


def _optional_int(value: Any) -> int | None:
    """``None`` or an int — for the nullable ``schema_version`` columns."""
    return None if value is None else int(value)


def _digest_file(path: Path) -> str:
    """sha256 of a file, streamed. A copy's integrity is checked, not asserted."""
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(block)
    return hasher.hexdigest()


class FenceLedger:
    """The durable, monotone record of who owns each fenced scope.

    One instance per database. :meth:`mint` is the only way to obtain a token and
    it always mints from what is already recorded, so an epoch can never be
    reused — not by a promotion, and not by a process that crashed between
    minting and using one. A minted-but-unused epoch is harmless; a reused one
    is the failure this ledger exists to make impossible.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    def current(self, run_id: str, step_id: str = RUN_SCOPE) -> FencingToken | None:
        rows = self._store.query(
            f"SELECT {_FENCE_COLUMNS} FROM repl_fences WHERE run_id = ? AND step_id = ?",
            (run_id, step_id),
        )
        return _fence_from_row(rows[0]) if rows else None

    def highest_epoch(self, run_id: str, step_id: str = RUN_SCOPE) -> int:
        token = self.current(run_id, step_id)
        return 0 if token is None else token.epoch

    def fences(self, run_id: str | None = None) -> tuple[FencingToken, ...]:
        if run_id is None:
            rows = self._store.query(
                f"SELECT {_FENCE_COLUMNS} FROM repl_fences ORDER BY run_id, step_id"
            )
        else:
            rows = self._store.query(
                f"SELECT {_FENCE_COLUMNS} FROM repl_fences WHERE run_id = ? ORDER BY step_id",
                (run_id,),
            )
        return tuple(_fence_from_row(row) for row in rows)

    def mint(
        self,
        run_id: str,
        holder: str,
        *,
        step_id: str = RUN_SCOPE,
        now: datetime | None = None,
    ) -> FencingToken:
        """The next fence for a scope, strictly newer than the recorded one.

        One transaction: read the current epoch and write its successor. A fresh
        scope starts at epoch 1 — never 0, because a zero-epoch token is "no
        ownership", which is exactly what a deposed writer would need to say.
        """
        with self._store.write() as conn:
            return self.mint_in(conn, run_id, holder, step_id=step_id, now=now)

    def mint_in(
        self,
        conn: sqlite3.Connection,
        run_id: str,
        holder: str,
        *,
        step_id: str = RUN_SCOPE,
        now: datetime | None = None,
    ) -> FencingToken:
        """Mint inside a caller's transaction.

        Separate from :meth:`mint` because a promotion has to move the epoch and
        write its own record *together* — a nested ``Store.write`` would commit
        the fence on the inner exit, leaving a promotion row that could be lost
        after the epoch had already moved. One transaction, one outcome.
        """
        issued = now or utc_now()
        row = conn.execute(
            f"SELECT {_FENCE_COLUMNS} FROM repl_fences WHERE run_id = ? AND step_id = ?",
            (run_id, step_id),
        ).fetchone()
        if row is None:
            token = FencingToken.issue(run_id=run_id, step_id=step_id, holder=holder, now=issued)
        else:
            token = _fence_from_row(row).next_fence(holder=holder, now=issued)
        conn.execute(
            f"INSERT INTO repl_fences ({_FENCE_COLUMNS}) VALUES (?,?,?,?,?,?) "
            "ON CONFLICT(run_id, step_id) DO UPDATE SET "
            "holder = excluded.holder, epoch = excluded.epoch, "
            "issued_at = excluded.issued_at, supersedes_epoch = excluded.supersedes_epoch",
            (
                token.run_id,
                token.step_id,
                token.holder,
                token.epoch,
                token.issued_at.isoformat(),
                token.supersedes_epoch,
            ),
        )
        return token

    def is_current(self, token: FencingToken) -> bool:
        recorded = self.current(token.run_id, token.step_id)
        return recorded is not None and recorded.is_at_least(token)

    def assert_current(self, token: FencingToken) -> FencingToken:
        """The recorded fence, or a refusal naming what superseded ``token``.

        Raises:
            StaleFenceError: If the recorded epoch is newer than ``token``'s, or
                the scope has no fence at all (a token from nowhere is not a
                token this ledger can vouch for).
        """
        recorded = self.current(token.run_id, token.step_id)
        if recorded is None:
            msg = (
                f"fence for {token.run_id}/{token.step_id} epoch {token.epoch} presented "
                "by a ledger that has never recorded that scope: a token this store did "
                "not mint is not a token it can vouch for"
            )
            raise StaleFenceError("replication.unknown_fence", msg)
        if recorded.epoch > token.epoch:
            msg = (
                f"{token.holder} presented epoch {token.epoch} for {token.run_id}/"
                f"{token.step_id}, but epoch {recorded.epoch} is recorded and held by "
                f"{recorded.holder}: the writer was superseded before it wrote, and two "
                "primaries must never both own a run"
            )
            raise StaleFenceError("replication.stale_fence", msg)
        if recorded.epoch == token.epoch and recorded.holder != token.holder:
            msg = (
                f"{token.holder} presented epoch {token.epoch} for {token.run_id}/"
                f"{token.step_id}, but that epoch is held by {recorded.holder}: an epoch "
                "belongs to exactly one holder"
            )
            raise StaleFenceError("replication.fence_holder_mismatch", msg)
        return recorded

    def assert_lease(self, token: FencingToken) -> FencingToken:
        """Assert a *run-level* lease, naming the loss in the refusal.

        Same predicate as :meth:`assert_current` and a separate method because
        the two failures mean different things to an operator: a stale *step*
        fence is a lost race for one step, a stale *run* fence is a node that
        has been superseded wholesale and must stop shipping bytes.
        """
        if token.step_id != RUN_SCOPE:
            msg = (
                f"{token.run_id}/{token.step_id} is a step fence, not a run lease; "
                f"the run lease is fenced over the reserved {RUN_SCOPE!r} scope"
            )
            raise LostLeaseError("replication.not_a_lease", msg)
        try:
            return self.assert_current(token)
        except StaleFenceError as exc:
            raise LostLeaseError("replication.lost_lease", str(exc)) from exc


class StepLedger:
    """The replicated record of which steps have run, and under which epoch.

    Two independent mechanisms make duplicate execution impossible, and it is
    worth keeping them apart because they fail differently:

    * **Fencing** (:class:`FenceLedger`) stops a *superseded* writer. It is
      about who is allowed to write, and it fails with :class:`StaleFenceError`.
    * **The partial unique index** on ``repl_step_ledger`` stops a *second
      completion of one step*. It is about what may be true of a step, and it
      fails as a ``sqlite3.IntegrityError`` that this module re-raises as
      :class:`ReplicationError`.

    Either alone would leave a hole: fencing without the index still lets two
    epochs each believe they completed the same step, and the index without
    fencing lets a deposed primary complete one the promoted primary already
    re-drove.
    """

    def __init__(self, store: Store) -> None:
        self._store = store
        self._fences = FenceLedger(store)

    def claim(
        self,
        run_id: str,
        step_id: str,
        holder: str,
        *,
        plan_digest: str = "",
        now: datetime | None = None,
    ) -> FencingToken:
        """Take the step, at a fence strictly newer than any previous holder's."""
        return self._fences.mint(run_id, holder, step_id=step_id, now=now)

    def record(
        self,
        token: FencingToken,
        status: str,
        *,
        plan_digest: str,
        detail: str = "",
        started_at: str = "",
        now: datetime | None = None,
    ) -> StepExecution:
        """Write the step's current state, if and only if ``token`` still holds it.

        Args:
            token: The step fence the writer holds. Checked against the ledger
                first, so a superseded writer is refused before the row moves.
            status: One of ``running``/``completed``/``failed``/``abandoned``.
            plan_digest: The plan the step belongs to. Stored so a ledger row
                can be tied back to the plan a promotion is resuming.
            detail: Free text for the operator; never interpreted.
            started_at: When the step began, for the ledger's own timeline.
            now: Injection point for the timestamp, so a test is deterministic.

        Raises:
            StaleFenceError: If ``token`` has been superseded.
            ReplicationError: On a second ``completed`` record for the same step.
        """
        if status not in TERMINAL_STEP_STATES and status != "running":
            msg = (
                f"step status {status!r} is not one of {sorted({*TERMINAL_STEP_STATES, 'running'})}"
            )
            raise ReplicationError("replication.bad_step_status", msg)
        self._fences.assert_current(token)
        stamp = (now or utc_now()).isoformat()
        ended = "" if status == "running" else stamp
        with self._store.write() as conn:
            existing = conn.execute(
                "SELECT status FROM repl_step_ledger WHERE run_id = ? AND step_id = ?",
                (token.run_id, token.step_id),
            ).fetchone()
            if (
                existing is not None
                and str(existing["status"]) == "completed"
                and status != "completed"
            ):
                msg = (
                    f"step {token.run_id}/{token.step_id} is already recorded completed; "
                    f"{token.holder} at epoch {token.epoch} cannot move it to {status!r}"
                )
                raise ReplicationError("replication.step_already_completed", msg)
            try:
                conn.execute(
                    f"INSERT INTO repl_step_ledger ({_LEDGER_COLUMNS}) "
                    "VALUES (?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(run_id, step_id) DO UPDATE SET "
                    "plan_digest = excluded.plan_digest, epoch = excluded.epoch, "
                    "holder = excluded.holder, status = excluded.status, "
                    "started_at = excluded.started_at, ended_at = excluded.ended_at, "
                    "detail = excluded.detail",
                    (
                        token.run_id,
                        token.step_id,
                        plan_digest,
                        token.epoch,
                        token.holder,
                        status,
                        started_at or stamp,
                        ended,
                        detail,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                msg = (
                    f"step {token.run_id}/{token.step_id} cannot be recorded {status!r} a "
                    f"second time ({exc}); the step ledger admits one completed record "
                    "per step, so duplicate step execution is a constraint violation "
                    "rather than something a careful writer avoids"
                )
                raise ReplicationError("replication.duplicate_step_execution", msg) from exc
        found = self.execution(token.run_id, token.step_id)
        assert found is not None  # the row was just written in the transaction above
        return found

    def execution(self, run_id: str, step_id: str) -> StepExecution | None:
        rows = self._store.query(
            f"SELECT {_LEDGER_COLUMNS} FROM repl_step_ledger WHERE run_id = ? AND step_id = ?",
            (run_id, step_id),
        )
        return _execution_from_row(rows[0]) if rows else None

    def executions(self, run_id: str) -> tuple[StepExecution, ...]:
        rows = self._store.query(
            f"SELECT {_LEDGER_COLUMNS} FROM repl_step_ledger WHERE run_id = ? ORDER BY step_id",
            (run_id,),
        )
        return tuple(_execution_from_row(row) for row in rows)

    def completed(self, run_id: str) -> tuple[str, ...]:
        return tuple(step.step_id for step in self.executions(run_id) if step.completed)

    def in_flight(self, run_id: str) -> tuple[str, ...]:
        """Steps the ledger still shows as ``running`` — nobody finished these."""
        return tuple(step.step_id for step in self.executions(run_id) if not step.terminal)


# ---------------------------------------------------------------------------
# transport: WAL archive and snapshot ship
# ---------------------------------------------------------------------------


def _require_shipping_lease(
    receiver: FenceLedger | None, token: FencingToken
) -> FencingToken | None:
    """Refuse to ship bytes from a node that is not the primary any more.

    The check runs against the **receiver's** ledger, and that is the whole
    reason it is an argument rather than an internal lookup. A sender's own
    ledger cannot referee the sender: a deposed primary's database is a
    divergent copy that still believes it is primary at epoch 1, so asking it
    would approve every byte it ever wanted to ship. The receiver's record of
    the newest epoch is the only thing that settles it, and it has to be settled
    before the first byte is copied.

    ``receiver=None`` is the bootstrap case and is not a loophole dressed as
    one: it means the standby has no fence ledger yet, because it has no
    database yet. There is genuinely nothing to fence against on a first ship,
    so the epoch that shipped is *recorded* on the snapshot row, and the second
    ship onwards is checked against it. ``tests/unit/test_replication.py``
    exercises both halves: the first ship with no receiver, and a second ship
    refused because the receiver's epoch has moved on.
    """
    if receiver is None:
        return None
    return receiver.assert_lease(token)


class SnapshotShipper:
    """Ships a consistent copy of a primary's database to a standby's file.

    The copy uses SQLite's online backup API rather than a file copy. A file copy
    of a live WAL database can tear — the main file and the ``-wal`` are updated
    by separate writes — and the result is a database that opens and then answers
    questions wrongly. ``Connection.backup`` walks the page graph under the
    source's read lock, so the destination is a consistent snapshot at a single
    point in time without pausing the writer.

    The destination is written through a temporary file and
    :func:`os.replace`, so a crash mid-ship leaves either the previous standby
    file or the new one, never a half-written one at the live path.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    def ship(
        self,
        source_path: Path,
        destination_path: Path,
        *,
        standby_id: str,
        lease: FencingToken,
        receiver: FenceLedger | None = None,
        run_id: str = "",
    ) -> Snapshot:
        """Copy the primary at ``source_path`` to ``destination_path``.

        Args:
            source_path: The primary's database file.
            destination_path: Where to leave the standby's copy. Must not be an
                open :class:`~mayhem.infra.store.Store`; a standby that is
                already serving is shipped to by shipping a new file and
                reopening, which is the sequence the drill uses.
            standby_id: Which standby this copy is for.
            lease: The run-level fence the sender holds. Checked against
                ``receiver``'s ledger first, never against the sender's.
            receiver: The fence ledger of the node that will own the shipped
                copy, or ``None`` for the first ship to a standby that has no
                database yet.
            run_id: The run whose lease ``lease`` is for, for the refusal message.

        Raises:
            LostLeaseError: If ``receiver`` records an epoch newer than ``lease``.
        """
        _require_shipping_lease(receiver, lease)
        source = Path(source_path)
        destination = Path(destination_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        staging = destination.with_suffix(destination.suffix + ".incoming")
        if staging.exists():
            staging.unlink()
        schema_version = self._checkpoint_and_copy(source, staging)
        digest = _digest_file(staging)
        staging.replace(destination)
        fenced_epoch = lease.epoch
        shipped_at = utc_now().isoformat()
        snapshot_id = f"snap-{digest[:16]}"
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO repl_snapshots "
                "(snapshot_id, standby_id, source_db, digest, byte_size, schema_version, "
                " fenced_epoch, shipped_at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    snapshot_id,
                    standby_id,
                    str(source),
                    digest,
                    destination.stat().st_size,
                    schema_version,
                    fenced_epoch,
                    shipped_at,
                ),
            )
            conn.execute(
                "INSERT INTO repl_standbys (standby_id, last_applied_segment, "
                "last_promoted_epoch, registered_at, updated_at) VALUES (?,0,0,?,?) "
                "ON CONFLICT(standby_id) DO UPDATE SET last_promoted_epoch = "
                "MAX(repl_standbys.last_promoted_epoch, excluded.last_promoted_epoch), "
                "updated_at = excluded.updated_at",
                (standby_id, shipped_at, shipped_at),
            )
        return Snapshot(
            snapshot_id=snapshot_id,
            standby_id=standby_id,
            path=destination,
            digest=digest,
            byte_size=destination.stat().st_size,
            schema_version=schema_version,
            fenced_epoch=fenced_epoch,
            shipped_at=shipped_at,
        )

    def _checkpoint_and_copy(self, source: Path, staging: Path) -> int | None:
        """Fold the WAL in, then take the online backup. Returns the schema version.

        Checkpointing first is belt-and-braces rather than necessity: ``backup``
        already includes committed WAL frames. It is done because it keeps the
        shipped file's contents explainable — the destination holds the same
        pages the primary's main file plus everything the WAL had committed, and
        a reader comparing digests is comparing committed data either way.
        """
        connection = sqlite3.connect(source)
        try:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            version_row = connection.execute(
                "SELECT MAX(version) FROM _schema_migrations"
            ).fetchone()
            schema_version = (
                None if version_row is None or version_row[0] is None else int(version_row[0])
            )
            target = sqlite3.connect(staging)
            try:
                connection.backup(target)
            finally:
                target.close()
        finally:
            connection.close()
        return schema_version

    def verify(self, snapshot: Snapshot) -> bool:
        """Whether the bytes on disk are still the bytes that were shipped.

        A digest recorded next to a file proves nothing about the file, so this
        is how a standby checks it received what the primary sent.
        """
        return snapshot.path.exists() and _digest_file(snapshot.path) == snapshot.digest

    def snapshots(self, standby_id: str = "") -> tuple[Snapshot, ...]:
        sql = (
            "SELECT snapshot_id, standby_id, source_db, digest, byte_size, "
            "schema_version, fenced_epoch, shipped_at FROM repl_snapshots"
        )
        params: tuple[Any, ...] = ()
        if standby_id:
            sql += " WHERE standby_id = ?"
            params = (standby_id,)
        sql += " ORDER BY shipped_at, snapshot_id"
        return tuple(
            Snapshot(
                snapshot_id=str(row["snapshot_id"]),
                standby_id=str(row["standby_id"]),
                path=Path(str(row["source_db"])).with_name(str(row["snapshot_id"])),
                digest=str(row["digest"]),
                byte_size=int(row["byte_size"]),
                schema_version=None
                if row["schema_version"] is None
                else int(row["schema_version"]),
                fenced_epoch=int(row["fenced_epoch"]),
                shipped_at=str(row["shipped_at"]),
            )
            for row in self._store.query(sql, params)
        )


class WalArchive:
    """Timestamped copies of the primary's database, kept for point-in-time recovery.

    Distinct from :class:`SnapshotShipper` in what it is for. A snapshot exists
    to be *promoted*; an archived segment exists to be *restored from* when a
    snapshot turns out to predate a write somebody needed. The archive keeps
    every segment rather than replacing one, and each is named for its
    monotonically increasing sequence, so "the file as it was at segment 7" is a
    question with an answer.

    The segment sequence is allocated inside the writing transaction from
    ``MAX(segment_seq) + 1``, so it is strictly increasing per archive and two
    concurrent ships cannot be handed the same number.
    """

    def __init__(self, store: Store, *, archive_dir: Path) -> None:
        self._store = store
        self._archive_dir = Path(archive_dir)

    @property
    def archive_dir(self) -> Path:
        return self._archive_dir

    def ship(
        self,
        source_path: Path,
        *,
        standby_id: str,
        lease: FencingToken,
        receiver: FenceLedger | None = None,
    ) -> WalSegment:
        """Archive one copy of the primary's database.

        Refused with :class:`LostLeaseError` when ``receiver`` records an epoch
        newer than ``lease`` — the same check the snapshot ship makes, against
        the same authority, for the same reason: an archive written by a deposed
        primary is a second divergent history of the same run, and restoring from
        it months later would resurrect that history as though it were the run.
        """
        _require_shipping_lease(receiver, lease)
        self._archive_dir.mkdir(parents=True, exist_ok=True)
        shipped_at = utc_now().isoformat()
        source = Path(source_path)
        with self._store.write() as conn:
            row = conn.execute("SELECT MAX(segment_seq) FROM repl_wal_segments").fetchone()
            segment_seq = 1 if row is None or row[0] is None else int(row[0]) + 1
            target = self._archive_dir / f"segment-{segment_seq:06d}.db"
            staging = target.with_suffix(".db.incoming")
            connection = sqlite3.connect(source)
            try:
                connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                version_row = connection.execute(
                    "SELECT MAX(version) FROM _schema_migrations"
                ).fetchone()
                schema_version = (
                    None if version_row is None or version_row[0] is None else int(version_row[0])
                )
                handle = sqlite3.connect(staging)
                try:
                    connection.backup(handle)
                finally:
                    handle.close()
            finally:
                connection.close()
            staging.replace(target)
            digest = _digest_file(target)
            conn.execute(
                "INSERT INTO repl_wal_segments (segment_seq, standby_id, source_db, "
                "byte_size, digest, schema_version, shipped_at) VALUES (?,?,?,?,?,?,?)",
                (
                    segment_seq,
                    standby_id,
                    str(source),
                    target.stat().st_size,
                    digest,
                    schema_version,
                    shipped_at,
                ),
            )
        return WalSegment(
            segment_seq=segment_seq,
            standby_id=standby_id,
            path=target,
            digest=digest,
            byte_size=target.stat().st_size,
            schema_version=schema_version,
            fenced_epoch=lease.epoch,
            shipped_at=shipped_at,
        )

    def segments(self, standby_id: str = "") -> tuple[WalSegment, ...]:
        sql = (
            "SELECT segment_seq, standby_id, source_db, byte_size, digest, "
            "schema_version, shipped_at FROM repl_wal_segments"
        )
        params: tuple[Any, ...] = ()
        if standby_id:
            sql += " WHERE standby_id = ?"
            params = (standby_id,)
        sql += " ORDER BY segment_seq"
        return tuple(
            WalSegment(
                segment_seq=int(row["segment_seq"]),
                standby_id=str(row["standby_id"]),
                path=self._archive_dir / f"segment-{int(row['segment_seq']):06d}.db",
                digest=str(row["digest"]),
                byte_size=int(row["byte_size"]),
                schema_version=None
                if row["schema_version"] is None
                else int(row["schema_version"]),
                fenced_epoch=0,
                shipped_at=str(row["shipped_at"]),
            )
            for row in self._store.query(sql, params)
        )

    def verify(self, segment: WalSegment) -> bool:
        """Whether an archived segment is still byte-identical to what was recorded."""
        return segment.path.exists() and _digest_file(segment.path) == segment.digest

    def restore(self, segment: WalSegment, destination_path: Path) -> Path:
        """Copy an archived segment back out, refusing a corrupted one first.

        The digest check is the reason the archive records one. Restoring a
        segment whose bytes have drifted would produce a database that opens and
        answers questions wrongly, which is the worst outcome available to a
        recovery path — so the refusal happens before the copy.
        """
        if not self.verify(segment):
            msg = (
                f"archived segment {segment.segment_seq} no longer hashes to the digest "
                f"recorded for it ({segment.digest[:12]}…): restoring it would produce a "
                "database that opens and answers wrongly, which is worse than no recovery"
            )
            raise SnapshotRefusedError("replication.corrupt_segment", msg)
        destination = Path(destination_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(segment.path, destination)
        return destination


# ---------------------------------------------------------------------------
# the service the controller and the drill both drive
# ---------------------------------------------------------------------------


class ReplicationService:
    """The fenced control plane over one node's database.

    Composes the three pieces a caller actually needs in sequence — take the
    lease, ship bytes, take over after a crash — without exposing the orderings
    that make those safe. :meth:`promote` in particular is the only place a run's
    ownership changes hands, and it is deliberately the only place: a caller that
    wants a newer epoch has to say which standby is taking over and which token
    it last observed, because those two arguments are what make the refusal
    possible.
    """

    def __init__(self, store: Store, *, node_id: str, db_path: Path | str) -> None:
        self._store = store
        self._node_id = node_id
        self._db_path = Path(db_path)
        self.fences = FenceLedger(store)
        self.steps = StepLedger(store)
        self.shipper = SnapshotShipper(store)
        self.archive = WalArchive(store, archive_dir=Path(db_path).parent / "repl-archive")

    @property
    def store(self) -> Store:
        """The underlying store, for a caller that needs a non-replication write."""
        return self._store

    @property
    def node_id(self) -> str:
        return self._node_id

    @property
    def db_path(self) -> Path:
        return self._db_path

    def claim_lease(self, run_id: str, *, now: datetime | None = None) -> FencingToken:
        """Take (or re-take) the run-level lease. Idempotent for the same holder.

        Re-claiming while already holding the lease still mints a newer epoch,
        because a node that cannot prove it is still primary must assume it is
        not. That costs a re-ship of the fencing state; it cannot cost two
        primaries, which is the trade the fence exists to make.
        """
        return self.fences.mint(run_id, self._node_id, step_id=RUN_SCOPE, now=now)

    def lease(self, run_id: str) -> FencingToken | None:
        return self.fences.current(run_id, RUN_SCOPE)

    def require_lease(self, token: FencingToken) -> FencingToken:
        return self.fences.assert_lease(token)

    def ship_snapshot(
        self,
        destination_path: Path | str,
        *,
        standby_id: str,
        lease: FencingToken,
        receiver: FenceLedger | None = None,
    ) -> Snapshot:
        return self.shipper.ship(
            self._db_path,
            Path(destination_path),
            standby_id=standby_id,
            lease=lease,
            receiver=receiver,
        )

    def archive_segment(
        self,
        *,
        standby_id: str,
        lease: FencingToken,
        receiver: FenceLedger | None = None,
    ) -> WalSegment:
        return self.archive.ship(
            self._db_path, standby_id=standby_id, lease=lease, receiver=receiver
        )

    def promote(
        self,
        run_id: str,
        *,
        standby_id: str,
        observed: FencingToken,
        plan: ExecutionPlan,
        now: datetime | None = None,
        reason: str = "",
    ) -> Promotion:
        """Take ownership of a run, and say which steps must be re-driven.

        The order is the safety property, so it is worth stating:

        1. **The observed token is checked against the ledger before anything is
           written.** A standby whose last-seen fence is behind the recorded one
           has lost its lease, and is refused with :class:`LostLeaseError`. This
           is the check that makes a deposed standby unable to promote, and it
           runs first because a promotion that later fails has already moved the
           epoch.
        2. **The ledger is reconciled against the plan.** A ledger row naming a
           step the plan does not contain is *orphaned state*, and a node that
           cannot account for its own step set is not a node that should own a
           run — so the promotion is refused rather than completed with a
           footnote.
        3. **A strictly newer run lease is minted and recorded** in the same
           transaction as the ``repl_promotions`` row, so the record of who took
           over and the epoch they took it at cannot come apart.
        4. **The in-flight steps are reported, not rewritten.** The rows stay as
           the dead primary left them; the promoted primary re-drives them with
           :meth:`StepLedger.claim`, which mints a strictly newer step fence and
           therefore *is* the write that supersedes them. Leaving them untouched
           is what lets the test assert that the previous primary's completed
           steps were never revisited.

        Args:
            run_id: The run being taken over.
            standby_id: The standby being promoted. Must be this node, so a
                service cannot record a promotion for somebody else.
            observed: The newest fence the standby last saw. Not a token it
                wishes it had.
            plan: The frozen plan, whose step ids are the authority on which
                steps exist.
            now: Timestamp injection point.
            reason: Recorded on the promotion row for the operator.

        Raises:
            LostLeaseError: If ``observed`` is behind the recorded fence, or if
                ``standby_id`` is not this node.
            ReplicationError: If the ledger names a step the plan does not.
        """
        if standby_id != self._node_id:
            msg = (
                f"node {self._node_id!r} cannot record a promotion for {standby_id!r}: "
                "the node taking over and the node recording it are the same one, or the "
                "promotion record is a claim about somebody else's node"
            )
            raise LostLeaseError("replication.promotion_by_proxy", msg)
        if observed.step_id != RUN_SCOPE or observed.run_id != run_id:
            msg = (
                f"observed fence is for {observed.run_id}/{observed.step_id}, not the "
                f"run lease for {run_id}/{RUN_SCOPE}: a promotion is gated on the run's "
                "own lease, and a step fence says nothing about who owns the run"
            )
            raise LostLeaseError("replication.not_a_lease", msg)
        recorded = self.fences.current(run_id, RUN_SCOPE)
        if recorded is not None and recorded.epoch > observed.epoch:
            msg = (
                f"{standby_id} last observed epoch {observed.epoch} for run {run_id!r}, "
                f"but epoch {recorded.epoch} is recorded and held by {recorded.holder}: "
                "the standby's view is stale, its lease is lost, and promoting here would "
                "mint an epoch that has already been used"
            )
            raise LostLeaseError("replication.lost_lease", msg)
        previous_holder = recorded.holder if recorded is not None else ""
        plan_step_ids = tuple(step.id for step in plan.steps)
        ledger_rows = self.steps.executions(run_id)
        orphans = tuple(
            sorted({row.step_id for row in ledger_rows if row.step_id not in plan_step_ids})
        )
        if orphans:
            msg = (
                f"run {run_id!r} has replicated step records for {list(orphans)}, which its "
                f"plan does not contain (plan steps: {list(plan_step_ids)}): a node that "
                "cannot account for its own step set must not take ownership of the run, "
                "because there is no way to know what else the previous holder did"
            )
            raise ReplicationError("replication.orphaned_step_records", msg)
        completed = {row.step_id for row in ledger_rows if row.completed}
        in_flight = {row.step_id for row in ledger_rows if not row.terminal}
        superseded = tuple(step_id for step_id in plan_step_ids if step_id in in_flight)
        reclaimed = tuple(
            step_id
            for step_id in plan_step_ids
            if step_id not in completed and step_id not in in_flight
        )
        promoted_at = (now or utc_now()).isoformat()
        with self._store.write() as conn:
            new_lease = self.fences.mint_in(conn, run_id, standby_id, step_id=RUN_SCOPE, now=now)
            conn.execute(
                "INSERT INTO repl_promotions (promotion_id, standby_id, run_id, "
                "previous_holder, fenced_epoch, observed_epoch, reason, promoted_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    f"promo-{run_id}-{new_lease.epoch}",
                    standby_id,
                    run_id,
                    previous_holder,
                    new_lease.epoch,
                    observed.epoch,
                    reason,
                    promoted_at,
                ),
            )
            conn.execute(
                "INSERT INTO repl_standbys (standby_id, last_applied_segment, "
                "last_promoted_epoch, registered_at, updated_at) VALUES (?,0,?,?,?) "
                "ON CONFLICT(standby_id) DO UPDATE SET last_promoted_epoch = "
                "excluded.last_promoted_epoch, updated_at = excluded.updated_at",
                (standby_id, new_lease.epoch, promoted_at, promoted_at),
            )
        return Promotion(
            run_id=run_id,
            standby_id=standby_id,
            previous_holder=previous_holder,
            observed_epoch=observed.epoch,
            fenced_epoch=new_lease.epoch,
            superseded_step_ids=superseded,
            reclaimed_step_ids=reclaimed,
            orphaned_step_ids=orphans,
            promoted_at=promoted_at,
        )

    def promotions(self, run_id: str = "") -> tuple[dict[str, Any], ...]:
        """Every promotion on record. Append-only in the schema, so this is history."""
        sql = (
            "SELECT promotion_id, standby_id, run_id, previous_holder, fenced_epoch, "
            "observed_epoch, reason, promoted_at FROM repl_promotions"
        )
        params: tuple[Any, ...] = ()
        if run_id:
            sql += " WHERE run_id = ?"
            params = (run_id,)
        sql += " ORDER BY fenced_epoch, promotion_id"
        return tuple(dict(row) for row in self._store.query(sql, params))

    def record_step(
        self,
        lease: FencingToken,
        token: FencingToken,
        status: str,
        *,
        plan_digest: str,
        detail: str = "",
    ) -> StepExecution:
        """The one call a controller makes to record a step's progress.

        Both checks live here because both are needed and neither implies the
        other: the *run lease* says this node is the primary at all, and the
        *step fence* says this node still owns this step. A node that has lost the
        run cannot write a step even with a step fence it minted while it was
        primary, and a node whose step was taken over cannot write it even while
        it still holds the run.
        """
        self.fences.assert_lease(lease)
        return self.steps.record(token, status, plan_digest=plan_digest, detail=detail)

    def resume_order(self, plan: ExecutionPlan, completed: Sequence[str]) -> tuple[str, ...]:
        """The steps a resumed run still owes, in plan order.

        Kept as a named function because the drill's whole claim rests on it: the
        answer is "every plan step that is not in ``completed``", and a step in
        ``completed`` is therefore structurally unable to be chosen.
        """
        done = set(completed)
        return tuple(step.id for step in plan.steps if step.id not in done)
