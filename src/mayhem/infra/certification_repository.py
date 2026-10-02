"""Persistence for certification records (plan 01, Phase 2).

What this module is
-------------------
The IO half of :mod:`mayhem.domain.certification`. The domain owns the rules —
which transitions are legal, what a certified claim must carry, when a claim
lapses — and this module only moves records in and out of SQLite behind
migration ``M0024_CERTIFICATION_RECORDS``.

Three properties are load-bearing, and each is why the API looks the way it
does:

**A claim is appended, never overwritten.** The store is a *sequence per fault*
(``PRIMARY KEY (fault_id, sequence)``, dense and 1-based). Re-certifying a fault
whose claim expired writes a new row; it does not revive the old one, because
:func:`mayhem.domain.certification.certify` refuses every non-pending record and
:func:`expire_by_time` makes a lapsed record terminal. The single exception is
:meth:`CertificationRepository.store_transition`, which exists for exactly the
moves that are *in place* — ageing into ``expiring``/``stale``, a regression
demotion to ``failed``, an invalidation to ``incompatible`` — and which refuses
to write a row that was not already stored.

**Phase 4: the store answers "who depends on this evidence?".**
:meth:`records_citing_bundle` is the reverse index Phase 4's retention guard is
built on. Without it a bundle's bytes could be deleted while a record still
cited them, and the claim would go on reporting a level with nothing behind it —
the one failure mode :func:`mayhem.controller.certification_evidence.expire_certification_evidence`
exists to make impossible. It deliberately does *not* answer "which claims are
live": that is the domain's ageing, and a second opinion about expiry in the
persistence layer is how two implementations of one rule drift apart.

**Reads are aged, writes are not.** :meth:`certification_gate` applies
:func:`expire_by_time` in memory and returns the mapping
:func:`mayhem.infra.promotion.evaluate_maturity` consumes. A report therefore
never mutates the database to answer a question: a claim that lapsed an hour ago
stops counting an hour ago, whether or not anybody has run the ageing sweep yet.
:meth:`expire_all` is the explicit, mutating sweep that writes those transitions
down; Phase 4 owns scheduling it.

**The gate has one arming point.** :meth:`certification_gate` returns a mapping
keyed by fault id, which is exactly the ``records`` argument
``evaluate_maturity(..., records=...)`` takes. An *empty* mapping is not the
same thing as ``None``: ``None`` means "this caller does not use certification"
and preserves 1.0.0 behaviour exactly, while an empty mapping is the assertion
that nothing is certified and therefore caps every fault at ``verified-unit``.
See :func:`mayhem.infra.promotion.CERTIFICATION_RECORDED`.

Conventions followed here are the package's, not this module's invention: one
transaction per write, ``record_json`` beside the derived columns so reloading
is exact, and a strictly increasing migration id.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from mayhem.domain.certification import (
    DEFAULT_EXPIRY_WARNING,
    CertificationRecord,
    expire_by_time,
)
from mayhem.domain.common import utc_now

if TYPE_CHECKING:
    import sqlite3
    from collections.abc import Mapping

    from mayhem.domain.certification import MatrixCell
    from mayhem.infra.store import Store

__all__ = [
    "CERTIFICATION_STATES",
    "CertificationRepository",
    "StoredCertification",
]


#: The states the ``state`` CHECK constraint accepts. Mirrors
#: :class:`mayhem.domain.certification.CertificationState`; kept as a literal so
#: the DDL and the domain can be compared in a test without importing SQLite
#: types into the domain.
CERTIFICATION_STATES: tuple[str, ...] = (
    "pending",
    "certified",
    "expiring",
    "stale",
    "failed",
    "incompatible",
)


@dataclass(frozen=True, slots=True)
class StoredCertification:
    """A record together with the store coordinates the domain never sees.

    :class:`~mayhem.domain.certification.CertificationRecord` is frozen and
    carries no identity beyond ``fault_id`` and cell, because *what the record
    says* is domain law. *Which row it is* — the per-fault sequence, the run
    that produced it, when it was last written — is persistence state, so it
    travels beside the record instead of inside it. Keeping the two apart is
    what lets the domain model stay free of a ``sequence`` field that nothing
    there would validate.
    """

    record: CertificationRecord
    sequence: int
    run_id: str = ""
    created_at: str = ""
    updated_at: str = ""

    @property
    def cell_fingerprint(self) -> str:
        return self.record.cell.fingerprint


class CertificationRepository:
    """Reads and writes the ``certification_records`` table.

    One transaction per write, the pattern every repository in this package
    follows. Writes never partially apply: appending a record and recording the
    run that produced it is a single statement, and a transition is a single
    ``UPDATE`` that refuses to touch a row it did not find.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    # -- writes ---------------------------------------------------------------

    def append(
        self,
        record: CertificationRecord,
        *,
        run_id: str = "",
        now: datetime | None = None,
    ) -> StoredCertification:
        """Append ``record`` as the next certification for its fault.

        The sequence is derived inside the same transaction that inserts the row,
        so two concurrent appends cannot claim the same number: the primary key
        rejects the loser rather than letting two rows share an identity.

        Args:
            record: The record to persist. Its own validators have already
                refused anything that could not be true (a ``certified`` claim
                with no evidence, a state with no reason).
            run_id: The run that produced the record, recorded for audit. It is
                *not* a foreign key: a certification must survive the deletion of
                the run row that describes it.
            now: Write stamp. Defaults to the wall clock; tests pass it
                explicitly so a policy can be replayed instead of waited for.

        Raises:
            ValueError: If ``record`` is not a constructible record.
        """
        CertificationRecord.model_validate(record.model_dump())
        stamp = _iso(now) or utc_now().isoformat()
        with self._store.write() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(sequence), 0) AS seq FROM certification_records "
                "WHERE fault_id = ?",
                (record.fault_id,),
            ).fetchone()
            sequence = int(row["seq"]) + 1
            conn.execute(
                "INSERT INTO certification_records "
                "(fault_id, sequence, cell_label, cell_fingerprint, engine, state, outcome, "
                " reason, bundle_hash, run_id, record_json, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.fault_id,
                    sequence,
                    record.cell.label,
                    record.cell.fingerprint,
                    record.cell.engine.value,
                    record.state.value,
                    record.outcome,
                    record.reason,
                    _primary_bundle(record),
                    run_id,
                    record.model_dump_json(),
                    stamp,
                    stamp,
                ),
            )
        return StoredCertification(
            record=record, sequence=sequence, run_id=run_id, created_at=stamp, updated_at=stamp
        )

    def store_transition(
        self,
        stored: StoredCertification,
        record: CertificationRecord,
        *,
        now: datetime | None = None,
    ) -> StoredCertification:
        """Write an in-place state change over an already-stored row.

        This is the *only* way a stored record changes without becoming a new
        one, and it is deliberately narrow: ``record`` must share the stored
        row's ``(fault_id, sequence)`` and its cell fingerprint, so ageing,
        demotion, and invalidation can be recorded while re-certification cannot
        masquerade as a transition.

        Args:
            stored: The row being replaced, as returned by a read.
            record: The transitioned record. Re-validated on the way in, so a
                transition that construction would have refused cannot be stored.
            now: Write stamp.

        Returns:
            The row as it now stands.

        Raises:
            ValueError: If the identity moved: a different fault, a different
                sequence, or a different cell.
        """
        CertificationRecord.model_validate(record.model_dump())
        if record.fault_id != stored.record.fault_id or record.cell != stored.record.cell:
            raise ValueError(
                f"refusing to store a transition that moves identity: "
                f"{stored.record.label} -> {record.label}; a transition changes state, "
                "a different cell or fault is a new record"
            )
        stamp = _iso(now) or utc_now().isoformat()
        with self._store.write() as conn:
            cursor = conn.execute(
                "UPDATE certification_records SET cell_label = ?, cell_fingerprint = ?, "
                "engine = ?, state = ?, outcome = ?, reason = ?, bundle_hash = ?, "
                "record_json = ?, updated_at = ? WHERE fault_id = ? AND sequence = ?",
                (
                    record.cell.label,
                    record.cell.fingerprint,
                    record.cell.engine.value,
                    record.state.value,
                    record.outcome,
                    record.reason,
                    _primary_bundle(record),
                    record.model_dump_json(),
                    stamp,
                    record.fault_id,
                    stored.sequence,
                ),
            )
            if not cursor.rowcount:
                raise ValueError(
                    f"no stored certification for {stored.record.fault_id} at sequence "
                    f"{stored.sequence}: refusing to write a transition over a row "
                    "that is not there"
                )
        return StoredCertification(
            record=record,
            sequence=stored.sequence,
            run_id=stored.run_id,
            created_at=stored.created_at,
            updated_at=stamp,
        )

    def expire_all(
        self,
        *,
        now: datetime | None = None,
        warning_window: timedelta = DEFAULT_EXPIRY_WARNING,
    ) -> tuple[StoredCertification, ...]:
        """Age every stored record against the clock and persist the moves.

        The mutating half of :meth:`certification_gate`. Reading a record never
        ages it; this sweep is how a lapsed claim becomes a durable ``stale`` row
        rather than a value that only changes when someone looks.
        """
        moment = now or utc_now()
        changed: list[StoredCertification] = []
        for stored in self.all():
            aged = expire_by_time(stored.record, now=moment, warning_window=warning_window)
            if aged.state is stored.record.state:
                continue
            changed.append(self.store_transition(stored, aged, now=moment))
        return tuple(changed)

    def delete_fault(self, fault_id: str) -> int:
        """Delete every certification for ``fault_id``.

        Exists so the *negative control* is executable rather than theoretical:
        a test must be able to remove a record and watch the reported maturity
        drop with it, which is the whole claim of Phase 1.
        """
        with self._store.write() as conn:
            cursor = conn.execute(
                "DELETE FROM certification_records WHERE fault_id = ?", (fault_id,)
            )
        return int(cursor.rowcount or 0)

    # -- reads ----------------------------------------------------------------

    def all(self) -> tuple[StoredCertification, ...]:
        """Every stored row, ordered by fault then sequence."""
        rows = self._store.query(
            "SELECT fault_id, sequence, run_id, record_json, created_at, updated_at "
            "FROM certification_records ORDER BY fault_id, sequence"
        )
        return tuple(_hydrate(row) for row in rows)

    def load(self, fault_id: str) -> tuple[StoredCertification, ...]:
        """Every stored certification for ``fault_id``, oldest sequence first."""
        rows = self._store.query(
            "SELECT fault_id, sequence, run_id, record_json, created_at, updated_at "
            "FROM certification_records WHERE fault_id = ? ORDER BY sequence",
            (fault_id,),
        )
        return tuple(_hydrate(row) for row in rows)

    def latest(self, fault_id: str) -> StoredCertification | None:
        """The most recently appended certification for ``fault_id``."""
        rows = self._store.query(
            "SELECT fault_id, sequence, run_id, record_json, created_at, updated_at "
            "FROM certification_records WHERE fault_id = ? ORDER BY sequence DESC LIMIT 1",
            (fault_id,),
        )
        return _hydrate(rows[0]) if rows else None

    def latest_on_cell(self, fault_id: str, cell: MatrixCell) -> StoredCertification | None:
        """The most recent certification of ``fault_id`` on exactly ``cell``.

        Matched on the cell *fingerprint*, not the label: two cells that print
        the same label but disagree on a capability are different cells, and
        only the fingerprint can tell them apart. Unchanged cells are the only
        ones a re-certification can supersede — a claim on a cell that no longer
        describes the runtime is not superseded, it is invalidated (Phase 4).
        """
        rows = self._store.query(
            "SELECT fault_id, sequence, run_id, record_json, created_at, updated_at "
            "FROM certification_records WHERE fault_id = ? AND cell_fingerprint = ? "
            "ORDER BY sequence DESC LIMIT 1",
            (fault_id, cell.fingerprint),
        )
        return _hydrate(rows[0]) if rows else None

    def records_citing_bundle(self, bundle_hash: str) -> tuple[StoredCertification, ...]:
        """Every stored row whose evidence references ``bundle_hash``.

        Scans the rows rather than querying the ``bundle_hash`` column, because
        that column only carries the *first* reference: a record citing two
        bundles would be invisible to a column query. That matters because this
        lookup is what a retention deletion guard is built on — "invisible to the
        guard" is precisely the failure it exists to prevent.

        Stored state is returned, not aged state: the caller decides which claims
        are still live, using the domain's own ageing rather than a second
        opinion about expiry.
        """
        return tuple(
            stored
            for stored in self.all()
            if any(ref.bundle_hash == bundle_hash for ref in stored.record.evidence)
        )

    def live_records(
        self,
        *,
        now: datetime | None = None,
    ) -> tuple[StoredCertification, ...]:
        """Rows whose claim still holds at ``now``, aged in memory.

        Reads the same way :meth:`certification_gate` does, so a caller that only
        wants "what is certified right now" does not have to assemble the
        mapping itself.
        """
        moment = now or utc_now()
        aged = []
        for stored in self.all():
            record = expire_by_time(stored.record, now=moment)
            if record.grants_live_verification:
                aged.append(
                    StoredCertification(
                        record=record,
                        sequence=stored.sequence,
                        run_id=stored.run_id,
                        created_at=stored.created_at,
                        updated_at=stored.updated_at,
                    )
                )
        return tuple(aged)

    def certification_gate(
        self,
        *,
        now: datetime | None = None,
    ) -> Mapping[str, tuple[CertificationRecord, ...]]:
        """The record store in the shape :func:`evaluate_maturity` consumes.

        Returns a mapping keyed by fault id whose values are that fault's
        time-aged records across cells. Passing the result as
        ``evaluate_maturity(..., records=...)`` is what arms the certification
        gate: from then on no rung above ``verified-unit`` survives unless a
        record still certifies the fault on every required engine.

        A store with no rows returns an *empty mapping*, not ``None``. That
        distinction is the whole gate: ``None`` is the caller's statement that it
        does not use certification, while ``{}`` is the assertion that nothing is
        certified — and an assertion is what caps the reported level.
        """
        moment = now or utc_now()
        by_fault: dict[str, list[CertificationRecord]] = {}
        for stored in self.all():
            aged = expire_by_time(stored.record, now=moment)
            by_fault.setdefault(stored.record.fault_id, []).append(aged)
        return {fault_id: tuple(records) for fault_id, records in by_fault.items()}


def _primary_bundle(record: CertificationRecord) -> str:
    """The first evidence bundle's hash, or empty for a record with none.

    A column, not a relation: the row already carries the full reference list in
    ``record_json``, and the indexed column exists so "is this claim backed by a
    bundle at all" is answerable without parsing JSON.
    """
    return record.evidence[0].bundle_hash if record.evidence else ""


def _hydrate(row: sqlite3.Row) -> StoredCertification:
    """Rebuild a stored row through the domain's validators."""
    data = dict(row)
    return StoredCertification(
        record=CertificationRecord.model_validate_json(str(data["record_json"])),
        sequence=int(str(data["sequence"])),
        run_id=str(data["run_id"]),
        created_at=str(data["created_at"]),
        updated_at=str(data["updated_at"]),
    )


def _iso(moment: datetime | None) -> str:
    if moment is None:
        return ""
    if moment.tzinfo is None:
        raise ValueError("certification write stamps must be timezone-aware")
    return moment.astimezone(UTC).isoformat()
