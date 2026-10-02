"""Durable dispatch journal for the execution fabric (plan 03, Phase 4).

Phase 2 (:mod:`mayhem.controller.fabric_engine`) declared
:class:`~mayhem.controller.fabric_engine.FabricJournal` as a *protocol* and
recorded, honestly, that nothing implemented it: the whole crash-safety story was
"every decision is a projection over durable objects", and the durable object was
missing. This module is that object — the SQLite table plus the row discipline
that makes a journal row worth reading.

What lives here, and what does not
----------------------------------

This module owns the **table**: the DDL, the migration object, and a row model
that knows how to check *itself* against the payload it stores. It deliberately
does **not** own :class:`~mayhem.controller.fabric_engine.JournalEntry`. Those
types live in the controller layer, and the layering contract
(``controller`` above ``toolkit | infra`` above ``domain``) forbids ``infra``
importing ``controller``. So the split is:

* :class:`FabricJournalRow` + :class:`FabricJournalTable` — plain scalars and
  canonical JSON. No fabric vocabulary, no pydantic domain types, no upward
  imports.
* :class:`mayhem.controller.fabric_evidence.SqliteFabricJournal` — the adapter
  that maps ``DispatchClaim``/``DispatchSettlement`` onto rows. It lives above.

A row carries its *own* bytes and a digest over them
----------------------------------------------------

Every row stores ``entry_json`` (the canonical serialisation of the journal
entry) *and* the denormalised scalars an auditor's SQL filters on
(``run_id``, ``step_id``, ``phase``, ``command_id``, ``epoch``, ``controller_id``)
*and* ``payload_digest`` over the JSON. Both redundancies are load-bearing and
both are checked on read:

* the digest makes an edit that bypasses the model detectable
  (:meth:`FabricJournalTable.rows` recomputes it), and
* the index columns are compared against the paths they claim to summarise, so a
  row whose ``run_id`` was edited to move a claim between runs is refused rather
  than believed.

This is the same discipline :mod:`mayhem.infra.attestation_store` uses when it
checks a stored ``chain_root`` against a recomputed one, and for the same
reason: a store that only ever re-verified its own in-memory objects would pass
every positive test and still be worthless.

Ownership rules encoded in the schema
-------------------------------------

* **Append-only and single-writer.** ``sequence`` is an ``AUTOINCREMENT``
  primary key, so a row's position in the log is assigned by the database and
  cannot be rewritten. There is no ``UPDATE`` path in :class:`FabricJournalTable`
  at all.
* **One row per ``(run_id, step_id, phase, command_id)``.** A UNIQUE index
  makes a duplicate append a loud refusal rather than a second copy of one
  claim. The engine appends exactly one claim and one settlement per command,
  so a duplicate is a controller bug — the same bug class the attestation
  repository treats as "refuse, do not repair".
* **No foreign key to ``runs``** (gap 101, as in ``M0023`` and ``M0032``): the
  journal is what a run's ownership survives in, so it must outlive the row that
  describes the run.
* **No secrets, and no signature bytes.** The envelope's ``signature`` is
  key-derived material that plan 19's store already refuses to persist; the row
  is written through :func:`~mayhem.infra.secret_resolver.require_persistable_document`
  like every other evidence write path, which is what enforces that rather than
  a comment.

Registration
------------

This migration **is** registered in
:data:`mayhem.infra.migrations.ALL_MIGRATIONS`, imported rather than re-spelled
there, as version 33 immediately after ``M0032_HA_DR``. Two consequences are
worth stating plainly, because both were the reason registration used to be
deferred:

* **The DDL has exactly one home.** ``migrations.py`` imports
  ``FABRIC_JOURNAL_MIGRATION`` instead of copying ``MIGRATION_SQL``, so the
  table a deployment migrates to and the table :class:`FabricJournalTable`
  inserts into cannot drift into two spellings that pass their own tests.
* **The journal is now covered by a *real* migrated database.** Registration was
  deferred while ``ALL_MIGRATIONS`` was being appended to by concurrent lanes,
  so the table existed only where a caller spliced the migration in — which is
  what every test here did. That arrangement proves the row discipline works and
  proves nothing about whether the table is present in production, because a
  fixture built to fit the code under test cannot fail for want of it. The crash-
  resume claim in plan 03 Phase 4 is a claim about a migrated database, and it
  needed this line before it was entitled to be one.

There is no import cycle to manage: this module imports
:mod:`mayhem.infra.migrator` (for :class:`~mayhem.infra.migrator.Migration`) and
never ``migrations``, so the dependency runs one way. ``infra`` importing ``infra``
is permitted by the layering contract, which constrains *upward* imports only.

:data:`FABRIC_JOURNAL_VERSION` is the id this work item reserved when the head
was 32. The migrator keys on ``version`` and refuses duplicates and inversions, so
a collision would surface at startup rather than silently overwriting a
neighbour — which is why the id was reserved rather than chosen by renumbering
anything already shipped.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from mayhem.domain.attestation import canonical_event_json, content_digest
from mayhem.domain.errors import InvariantViolationError
from mayhem.infra.migrator import Migration
from mayhem.infra.secret_resolver import require_persistable_document

if TYPE_CHECKING:
    from mayhem.infra.store import Store

#: The migration id reserved for this work item. The chain head was 32
#: (``M0032_HA_DR``) when this was written; 33 is what plan 03 Phase 4 takes.
FABRIC_JOURNAL_VERSION = 33

#: The table the durable journal lives in.
FABRIC_JOURNAL_TABLE = "fabric_journal"

#: The two phase values a journal row may carry, CHECK-pinned in the schema so
#: the column can never hold a value the domain's
#: :class:`~mayhem.controller.fabric_engine.DispatchPhase` cannot produce.
FABRIC_JOURNAL_PHASES: tuple[str, ...] = ("claimed", "settled")

#: The ``artifact`` label the evidence boundary reports a journal refusal under.
#: Named per write path for the reason :mod:`mayhem.infra.audit_stream` names its
#: own: an operator reading a refusal has to be able to tell *which* write path
#: refused.
FABRIC_JOURNAL_ARTIFACT_PREFIX = "fabric:journal:"


def journal_artifact(run_id: str) -> str:
    """The boundary label for one run's journal writes."""
    return f"{FABRIC_JOURNAL_ARTIFACT_PREFIX}{run_id}"


# --------------------------------------------------------------------------- #
# Schema                                                                       #
# --------------------------------------------------------------------------- #

#: Forward DDL. Kept as a module constant (rather than inline in the
#: :class:`~mayhem.infra.migrator.Migration`) so ``migrations.py`` can import the
#: migration object whole and a reader of that tuple never has to diff a 60-line
#: string to see what a lane added.
MIGRATION_SQL: tuple[str, ...] = (
    f"""
    CREATE TABLE {FABRIC_JOURNAL_TABLE} (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL,
        step_id TEXT NOT NULL,
        phase TEXT NOT NULL CHECK (phase IN ('claimed','settled')),
        command_id TEXT NOT NULL,
        epoch INTEGER NOT NULL CHECK (epoch >= 1),
        controller_id TEXT NOT NULL DEFAULT '',
        recorded_at TEXT NOT NULL,
        -- sha256 over entry_json, recomputed on every read. 64 lowercase hex or
        -- nothing: a digest column that could hold prose is not a digest column.
        payload_digest TEXT NOT NULL CHECK (
            length(payload_digest) = 64 AND payload_digest NOT GLOB '*[^0-9a-f]*'
        ),
        entry_json TEXT NOT NULL
    )
    """,
    # The only read the engine performs is "entries for a run, optionally one
    # step, in append order" — so this index *is* the read path.
    f"CREATE INDEX idx_fabric_journal_run ON {FABRIC_JOURNAL_TABLE}(run_id, step_id, sequence)",
    f"CREATE INDEX idx_fabric_journal_command ON {FABRIC_JOURNAL_TABLE}(command_id)",
    f"CREATE INDEX idx_fabric_journal_step ON {FABRIC_JOURNAL_TABLE}(run_id, step_id, phase)",
    # One row per (step, phase, command). The engine appends exactly one claim
    # and one settlement per command, so a duplicate is a controller bug and is
    # refused rather than absorbed.
    f"CREATE UNIQUE INDEX idx_fabric_journal_once "
    f"ON {FABRIC_JOURNAL_TABLE}(run_id, step_id, phase, command_id)",
)

#: Reverse DDL. Dropped child-first, the shape ``run_down_migrations`` expects.
DOWN_SQL: tuple[str, ...] = (
    "DROP INDEX idx_fabric_journal_once",
    "DROP INDEX idx_fabric_journal_step",
    "DROP INDEX idx_fabric_journal_command",
    "DROP INDEX idx_fabric_journal_run",
    f"DROP TABLE {FABRIC_JOURNAL_TABLE}",
)

#: The migration object, registered in
#: :data:`~mayhem.infra.migrations.ALL_MIGRATIONS` as version 33.
FABRIC_JOURNAL_MIGRATION = Migration(
    version=FABRIC_JOURNAL_VERSION,
    name="fabric_journal",
    statements=MIGRATION_SQL,
    down_statements=DOWN_SQL,
)


# --------------------------------------------------------------------------- #
# Row discipline                                                               #
# --------------------------------------------------------------------------- #


class FabricJournalIntegrityError(InvariantViolationError):
    """A stored row disagrees with the payload it claims to summarise.

    A subclass of :class:`~mayhem.domain.errors.InvariantViolationError` on
    purpose: this is the same *kind* of failure the domain raises for an
    incoherent record (a settlement whose outcome contradicts its reason), and a
    caller catching one should catch the other. The ``rule`` names which
    disagreement was found so the refusal is diagnosable from the message alone.
    """

    #: Rule names, kept as constants so a test and the writer cannot spell them
    #: differently.
    RULE_DIGEST = "fabric_journal_payload_digest"
    RULE_INDEX_COLUMNS = "fabric_journal_index_disagreement"
    RULE_PAYLOAD_SHAPE = "fabric_journal_payload_shape"
    RULE_STAMP = "fabric_journal_stamp_disagreement"


class FabricJournalDuplicateEntryError(InvariantViolationError):
    """The same ``(step, phase, command)`` was appended twice.

    Not repairable and not repaired: the journal is append-only, the engine
    appends one row per phase per command, and a second row for the same claim
    means two controllers (or one looping one) believe they own the same effect.
    """

    RULE = "fabric_journal_duplicate_entry"


#: Which stored scalar must equal which JSON path, per phase.
#:
#: A claim's index columns all come from *inside* the envelope, because that is
#: the only place :class:`~mayhem.controller.fabric_engine.DispatchClaim` stores
#: them — its ``run_id``/``step_id`` are derived properties, not fields. Checking
#: the envelope's own values is what makes the row's summary trustworthy rather
#: than a copy of a copy.
_INDEX_COLUMNS: dict[str, dict[str, tuple[str, ...]]] = {
    "claimed": {
        "run_id": ("command", "run_id"),
        "step_id": ("command", "step_id"),
        "command_id": ("command", "command_id"),
        "epoch": ("command", "fencing_token", "epoch"),
    },
    "settled": {
        "run_id": ("run_id",),
        "step_id": ("step_id",),
        "command_id": ("command_id",),
    },
}

#: Which JSON path carries the row's own timestamp, per phase.
_STAMP_PATHS: dict[str, tuple[str, ...]] = {
    "claimed": ("claimed_at",),
    "settled": ("settled_at",),
}


def _dig(payload: dict[str, Any], path: tuple[str, ...]) -> Any:
    """Read ``path`` out of ``payload``, or ``None`` when it is absent."""
    node: Any = payload
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def _as_instant(value: Any) -> datetime | None:
    """Read an ISO-8601 stamp as a UTC instant, or ``None``.

    Compared as instants rather than as text because two spellings of the same
    moment are still the same moment: pydantic's JSON mode renders UTC as ``Z``
    while :func:`mayhem.domain.common.iso_utc` renders it ``+00:00``, and a
    refusal over that difference would be the *formatter* failing a journal
    rather than the journal failing its integrity check.
    """
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str):
        try:
            moment = datetime.fromisoformat(value)
        except ValueError:
            return None
    else:
        return None
    if moment.tzinfo is None:
        return None
    return moment.astimezone(UTC)


class FabricJournalRow(BaseModel):
    """One durable row: the journal entry's canonical bytes plus its index.

    The index columns are derived from the payload by :meth:`of`, never supplied
    independently, so the two cannot be built inconsistently — and
    :meth:`check_payload` re-derives them on read anyway, because a row written
    by one build of this code has to be checkable by the next one.

    Attributes:
        sequence: The position the database assigned. **Not** part of the payload
            check — the payload cannot speak about its own ordinal, and a row
            whose ``sequence`` was edited would still hash correctly. Ordering is
            the primary key's job and is re-applied on every read.
        run_id: Run the entry belongs to.
        step_id: Step the entry acts on.
        phase: ``claimed`` or ``settled``.
        command_id: Envelope the entry is a record of.
        epoch: Fence epoch the effect was claimed under.
        controller_id: Which controller wrote it (claims only; ``""`` elsewhere).
        recorded_at: ISO-8601 stamp, tz-aware.
        payload_digest: sha256 over ``entry_json``.
        entry_json: Canonical JSON of the journal entry.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    sequence: int | None = None
    run_id: str
    step_id: str
    phase: str
    command_id: str
    epoch: int = Field(ge=1)
    controller_id: str = ""
    recorded_at: str
    payload_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    entry_json: str

    @classmethod
    def of(
        cls,
        *,
        run_id: str,
        step_id: str,
        phase: str,
        command_id: str,
        epoch: int,
        entry: Any,
        controller_id: str = "",
        recorded_at: str,
    ) -> FabricJournalRow:
        """Build a row from a journal entry's JSON-mode dump.

        Args:
            run_id: Restated run id; must match the payload (checked below).
            step_id: Restated step id.
            phase: ``claimed`` or ``settled``.
            command_id: Envelope id.
            epoch: Fence epoch (claims only; ``1`` for a settlement, which the
                engine does not need to index).
            entry: The journal entry, dumped to JSON-native values.
            controller_id: Claiming controller, for a claim.
            recorded_at: ISO-8601 stamp for the row.

        Returns:
            A row whose digest and index columns were derived from ``entry``.

        Raises:
            FabricJournalIntegrityError: If the supplied index columns disagree
                with the payload. Raised at *write* time as well as read time,
                because a row that cannot be checked later should never land.
        """
        payload = json.loads(canonical_event_json(entry))
        if not isinstance(payload, dict):  # pragma: no cover - canonical JSON of a model
            raise FabricJournalIntegrityError(
                FabricJournalIntegrityError.RULE_PAYLOAD_SHAPE,
                f"a journal entry for '{command_id}' serialised to {type(payload).__name__}, "
                "not a JSON object",
            )
        row = cls(
            run_id=run_id,
            step_id=step_id,
            phase=phase,
            command_id=command_id,
            epoch=epoch,
            controller_id=controller_id,
            recorded_at=recorded_at,
            payload_digest=content_digest(payload),
            entry_json=canonical_event_json(payload),
        )
        row.check_payload()
        return row

    def payload(self) -> dict[str, Any]:
        """The parsed payload.

        Raises:
            FabricJournalIntegrityError: If ``entry_json`` is not a JSON object.
        """
        try:
            parsed = json.loads(self.entry_json)
        except json.JSONDecodeError as exc:
            raise FabricJournalIntegrityError(
                FabricJournalIntegrityError.RULE_PAYLOAD_SHAPE,
                f"journal row for command '{self.command_id}' carries unparsable JSON: {exc}",
            ) from exc
        if not isinstance(parsed, dict):
            raise FabricJournalIntegrityError(
                FabricJournalIntegrityError.RULE_PAYLOAD_SHAPE,
                f"journal row for command '{self.command_id}' carries a "
                f"{type(parsed).__name__}, not a JSON object",
            )
        return parsed

    def check_payload(self) -> None:
        """Refuse this row if it disagrees with the payload it stores.

        Three independent disagreements are named, because they have different
        causes and an operator acts differently on each:

        * the digest moved (the JSON was edited, or the digest was);
        * an index column moved (the row was redirected to another run, step or
          command — the edit that would let a fabricated row pass a query);
        * the stamp moved (the row's own clock disagrees with the entry's).

        Raises:
            FabricJournalIntegrityError: With the rule naming which one.
        """
        payload = self.payload()
        recomputed = content_digest(payload)
        if recomputed != self.payload_digest:
            raise FabricJournalIntegrityError(
                FabricJournalIntegrityError.RULE_DIGEST,
                f"journal row for command '{self.command_id}' stores payload digest "
                f"{self.payload_digest[:12]}… but its JSON hashes to {recomputed[:12]}…; "
                "the row was edited behind the model",
            )
        expected = _INDEX_COLUMNS.get(self.phase)
        if expected is None:
            raise FabricJournalIntegrityError(
                FabricJournalIntegrityError.RULE_PAYLOAD_SHAPE,
                f"journal row for command '{self.command_id}' declares phase "
                f"{self.phase!r}, which is not one of {list(FABRIC_JOURNAL_PHASES)}",
            )
        for column, path in expected.items():
            stored = getattr(self, column)
            actual = _dig(payload, path)
            if actual is None:
                raise FabricJournalIntegrityError(
                    FabricJournalIntegrityError.RULE_PAYLOAD_SHAPE,
                    f"journal row for command '{self.command_id}' names no "
                    f"{'.'.join(path)} in its payload, so its {column} column "
                    f"({stored!r}) summarises nothing",
                )
            if stored != actual:
                raise FabricJournalIntegrityError(
                    FabricJournalIntegrityError.RULE_INDEX_COLUMNS,
                    f"journal row for command '{self.command_id}' records "
                    f"{column}={stored!r} but its payload says "
                    f"{'.'.join(path)}={actual!r}; an index column that disagrees "
                    "with the bytes it summarises is refused, not believed",
                )
        stamp_path = _STAMP_PATHS[self.phase]
        stamp = _dig(payload, stamp_path)
        if _as_instant(stamp) != _as_instant(self.recorded_at):
            raise FabricJournalIntegrityError(
                FabricJournalIntegrityError.RULE_STAMP,
                f"journal row for command '{self.command_id}' is stamped "
                f"{self.recorded_at!r} but its payload says "
                f"{'.'.join(stamp_path)}={stamp!r}",
            )


class FabricJournalTable:
    """The append-only table, over the store that owns the connection.

    One transaction per append (repo convention, ADR-0007), and the evidence
    boundary is crossed **before** that transaction opens, on the document the
    columns receive — the same placement :mod:`mayhem.infra.attestation_store`
    chose, and for the same reason: the row's ``entry_json`` is a free-form JSON
    column by construction, so it is exactly the surface a caller could plant a
    resolved value under a field name nobody graded.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    def append(self, row: FabricJournalRow) -> int:
        """Append one row and return its assigned ``sequence``.

        Raises:
            InvariantViolationError: From the evidence boundary, if the row
                carries a secret-classified field or a value this run resolved.
                Nothing is written.
            FabricJournalDuplicateEntryError: If this ``(run_id, step_id, phase,
                command_id)`` is already recorded.
            FabricJournalIntegrityError: If the row disagrees with its payload.
        """
        row.check_payload()
        require_persistable_document(
            {
                "run_id": row.run_id,
                "step_id": row.step_id,
                "phase": row.phase,
                "command_id": row.command_id,
                "epoch": row.epoch,
                "controller_id": row.controller_id,
                "recorded_at": row.recorded_at,
                "entry_json": row.payload(),
            },
            artifact=journal_artifact(row.run_id),
        )
        with self._store.write() as conn:
            try:
                cursor = conn.execute(
                    f"INSERT INTO {FABRIC_JOURNAL_TABLE} "
                    "(run_id, step_id, phase, command_id, epoch, controller_id,"
                    " recorded_at, payload_digest, entry_json)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        row.run_id,
                        row.step_id,
                        row.phase,
                        row.command_id,
                        row.epoch,
                        row.controller_id,
                        row.recorded_at,
                        row.payload_digest,
                        row.entry_json,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise FabricJournalDuplicateEntryError(
                    FabricJournalDuplicateEntryError.RULE,
                    f"journal already holds a {row.phase} row for command "
                    f"'{row.command_id}' on step '{row.step_id}' of run "
                    f"'{row.run_id}' ({exc}); the journal is append-only and one "
                    "command cannot be claimed or settled twice",
                ) from exc
        return int(cursor.lastrowid or 0)

    def rows(self, run_id: str, step_id: str | None = None) -> tuple[FabricJournalRow, ...]:
        """Every stored row for ``run_id``, in append order, checked.

        The check is on read as well as write: a row this build did not write, or
        one edited with ``UPDATE``, has to be refused here rather than handed to
        the engine as if it were a record of a real dispatch.

        Raises:
            FabricJournalIntegrityError: If any row disagrees with its payload.
        """
        if step_id is None:
            found = self._store.query(
                f"SELECT * FROM {FABRIC_JOURNAL_TABLE} WHERE run_id = ? ORDER BY sequence",
                (run_id,),
            )
        else:
            found = self._store.query(
                f"SELECT * FROM {FABRIC_JOURNAL_TABLE}"
                " WHERE run_id = ? AND step_id = ? ORDER BY sequence",
                (run_id, step_id),
            )
        rows: list[FabricJournalRow] = []
        for raw in found:
            row = FabricJournalRow.model_validate(dict(raw))
            row.check_payload()
            rows.append(row)
        return tuple(rows)

    def count(self, run_id: str | None = None) -> int:
        """How many rows are stored, for one run or for the whole journal."""
        if run_id is None:
            found = self._store.query(f"SELECT COUNT(*) FROM {FABRIC_JOURNAL_TABLE}")
        else:
            found = self._store.query(
                f"SELECT COUNT(*) FROM {FABRIC_JOURNAL_TABLE} WHERE run_id = ?", (run_id,)
            )
        return int(dict(found[0])["COUNT(*)"]) if found else 0

    def table_exists(self) -> bool:
        """Whether the journal table is present in this database."""
        found = self._store.query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (FABRIC_JOURNAL_TABLE,),
        )
        return bool(found)
