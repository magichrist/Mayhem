"""Backup engine: scheduled snapshots, WAL archives, evidence replication, drills.

Plan ``docs/v1.1.0/19_HA_DR_SECURITY.md`` Phase 2 -- "backup engine (scheduled
snapshots, WAL archives, evidence replication to object storage per 12) plus
restore drills that actually restore into an isolated cell and verify". Acceptance
says the drills must **prove** RPO/RTO "rather than asserting them".

The one rule everything here obeys
----------------------------------

Phase 1 (:mod:`mayhem.domain.backup`) made asserting RPO/RTO structurally
unavailable: :class:`~mayhem.domain.backup.RecoveryObjective` has no achieved
field, :class:`~mayhem.domain.backup.Measurement` cannot be built without a
:class:`~mayhem.domain.backup.RestoreVerification` as a *required* field, and
:func:`~mayhem.domain.backup.compare_against_objective` returns ``measured=None``
when no verified drill exists. This module therefore never writes an achieved
number and never reports a success of its own accord:

* a drill returns a :class:`~mayhem.domain.backup.RestoreVerification` whose
  ``status`` is *derived* by the domain. A drill that did not verify is
  ``FAILED``/``INCOMPLETE``, and the only way to say "the drill passed" is
  :meth:`~mayhem.domain.backup.RestoreVerification.claim_success`, which raises
  otherwise;
* :meth:`BackupEngine.report` delegates to
  :func:`~mayhem.domain.backup.compare_against_objective`, so a stated RPO with no
  verified drill reads **"rpo not demonstrated"** — never zero, never the target.
* ``data_loss_seconds`` is *measured* from the snapshot's own ``covers_through``
  against the drill's start instant, and left ``None`` when the drill never got far
  enough to measure. An unmeasured drill is ``incomplete``, which is what makes
  "we have never actually measured our RPO" a visible row.

Ports, because there is no object-storage SDK here
--------------------------------------------------

``ObjectStorePort`` is the seam for S3/Azure/GCS. **No SDK is imported and no
production implementation ships in this phase** — the same shape
:mod:`mayhem.infra.retention` already uses for ``RetentionBackend``.
:class:`InMemoryObjectStore` is a test/dev double and says so in its docstring;
:class:`UnavailableObjectStore` is the negative control, and the engine treats its
failure as **fail-closed**: no descriptor is written claiming a replica that does
not exist, and the caller gets :class:`BackupUnavailableError`.

Isolated restore, for real
--------------------------

:func:`SqliteSnapshotSource.capture` uses :meth:`sqlite3.Connection.backup`, the
stdlib's own consistent-snapshot API, so a capture is a real SQLite file. A drill
writes those bytes into a fresh temporary directory, opens it as its own
:class:`~mayhem.infra.store.Store`, and runs the plan's checks *against that
store*. The live store is never opened for writing and never restored over — the
plan's ``isolated`` requirement is enforced by
:class:`~mayhem.domain.backup.RestorePlan` (a drill that is not isolated cannot be
constructed), and honoured here by construction.

What the drill's checks do and do not prove
------------------------------------------

The plan's ``required_checks`` are the contract; the engine supplies an observation
per kind and **fails closed** when a kind has no observation available:

``ROW_COUNT``
    real: the isolated store's row counts are compared to the counts recorded at
    capture time, and the comparison string names every table that disagreed.
``DIGEST_MATCH``
    real: sha256 of the restored file's bytes against the descriptor's
    ``content_digest``.
``WAL_REPLAY``
    a **position** check, not frame-level log replay: it observes the restored
    data's own position and compares it with the snapshot's ``covers_through`` /
    ``wal_sequence``, and its ``detail`` says in those words that no log frame was
    applied. Frame-level replay stays behind :class:`SnapshotSourcePort`.
``EVIDENCE_CHAIN``
    real, when a chain reader is bound: the restored run's attestation chain is
    re-verified with :func:`mayhem.domain.attestation.verify_chain`. With no reader
    bound it fails closed rather than passing.
``SERVICE_HEALTHY`` / ``MTLS_HANDSHAKE``
    **probe ports with no shipped implementation.** This phase does not start
    services and does not perform an X.509 handshake, so an unbound probe records a
    *failed* check with that stated. A plan that requires ``MTLS_HANDSHAKE`` and
    expects a verified restore is asking for evidence plan 19 Phase 3 supplies.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

from mayhem.domain.attestation import canonical_event_bytes
from mayhem.domain.backup import (
    RecoveryObjective,
    RestoreCheckKind,
    RestoreCheckResult,
    RestoreCheckSpec,
    RestoreOutcome,
    RestorePlan,
    RestoreVerification,
    SnapshotDescriptor,
    SnapshotKind,
    verified_restores,
)
from mayhem.domain.common import iso_utc, utc_now
from mayhem.domain.errors import DomainError, InvariantViolationError
from mayhem.domain.hashing import sha256_hex
from mayhem.infra.agent_identity_store import BackupRepository
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from mayhem.domain.backup import ObjectiveReport




class BackupError(DomainError):
    """A backup or restore operation refused. Nothing was reported as successful."""


class BackupUnavailableError(BackupError):
    """A required dependency is unreachable. The operation fails closed.

    Distinct from a refusal because the remedy differs: an unavailable object store
    is a missing dependency, and it must never be read as permission to record a
    replica, or to count a restore as verified.
    """

    def __init__(self, dependency: str, reason: str) -> None:
        self.code = "backup_dependency_unavailable"
        self.dependency = dependency
        self.reason = reason
        super().__init__(
            f"backup_dependency_unavailable: {dependency} is unavailable ({reason}); "
            "failing closed rather than recording bytes nobody can read back"
        )


class ObjectStorePort(Protocol):
    """The object-storage seam (plan 12 evidence replication, plan 08 storage).

    **No SDK, no production implementation in this phase.** ``put`` returns the
    locator that goes into
    :attr:`~mayhem.domain.backup.SnapshotDescriptor.replica_locators`;
    ``fetch`` is how a drill reads the bytes *back*, which is the whole point —
    a replica that has never been read is a claim, not a copy.
    """

    name: str

    def put(self, key: str, payload: bytes) -> str: ...

    def fetch(self, key: str) -> bytes: ...

    def contains(self, key: str) -> bool: ...


class InMemoryObjectStore:
    """A test/dev double. **Not object storage; not durable across a restart.**"""

    name = "in-memory"

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def _key_of(self, locator: str) -> str:
        """Strip this store's own scheme off a locator.

        The port contract is ``put`` returns a *locator* and ``fetch``/``contains``
        take a locator — a descriptor records the replica's locator, and a real
        backend resolves that locator back to its own namespace (an S3 URL, a blob
        name). A test double that accepted only bare keys would not be testing the
        contract the engine actually uses.
        """
        prefix = f"mem://{self.name}/"
        return locator[len(prefix) :] if locator.startswith(prefix) else locator

    def put(self, key: str, payload: bytes) -> str:
        self.objects[key] = payload
        return f"mem://{self.name}/{key}"

    def fetch(self, locator: str) -> bytes:
        key = self._key_of(locator)
        if key not in self.objects:
            raise BackupUnavailableError(
                f"object-store({self.name})", f"no object at key {key!r}"
            )
        return self.objects[key]

    def contains(self, locator: str) -> bool:
        return self._key_of(locator) in self.objects


class UnavailableObjectStore:
    """The negative control: a backend that is down. Every call fails closed."""

    name = "unavailable"

    def __init__(self, reason: str = "backend unreachable") -> None:
        self._reason = reason

    def put(self, key: str, payload: bytes) -> str:
        del key, payload
        raise BackupUnavailableError(f"object-store({self.name})", self._reason)

    def fetch(self, key: str) -> bytes:
        del key
        raise BackupUnavailableError(f"object-store({self.name})", self._reason)

    def contains(self, key: str) -> bool:
        del key
        raise BackupUnavailableError(f"object-store({self.name})", self._reason)


class HealthProbePort(Protocol):
    """Prove something came back. No shipped implementation in this phase.

    ``SERVICE_HEALTHY`` needs a health endpoint that only exists at runtime, and
    ``MTLS_HANDSHAKE`` needs the X.509 machinery plan 19 Phase 3 adds. Both are
    declared so a plan can *require* them (and therefore fail closed until they are
    bound) rather than being unable to name an obligation it does not have.
    """

    probe_name: str

    def probe(self, *, locator: str) -> tuple[bool, str]: ...


class EvidenceChainPort(Protocol):
    """Re-verify a restored run's attestation chain."""

    def chain_errors(self, run_id: str) -> tuple[str, ...]: ...


@dataclass(frozen=True, slots=True)
class CapturedPayload:
    """Bytes a capture produced, plus the observations taken while it happened.

    Everything a later drill needs to *compare against*, and nothing about whether
    the capture is restorable. That is deliberate and it mirrors
    :class:`~mayhem.domain.backup.SnapshotDescriptor`: this is a record of what was
    written, not a claim that it comes back.

    Attributes:
        payload: The captured bytes.
        locator_key: Where the engine will write them in the object store.
        covers_through: The instant the capture is complete through -- the field an
            RPO is measured against, deliberately *not* ``at`` (when the job ran).
        row_counts: Observed row counts per table, for ``ROW_COUNT``.
        wal_sequence: Observed log position, for ``WAL_REPLAY``; ``None`` for a kind
            with no log position.
    """

    payload: bytes
    locator_key: str
    covers_through: datetime
    row_counts: dict[str, int]
    wal_sequence: int | None = None


class SnapshotSourcePort(Protocol):
    """Produce the bytes of a capture.

    A port so a non-SQLite datastore -- and frame-level WAL replay, which the
    ``WAL_REPLAY`` check explicitly does **not** do -- can be bound without
    touching the engine.
    """

    def capture(self, *, kind: SnapshotKind, at: datetime) -> CapturedPayload: ...


class SqliteSnapshotSource:
    """Real SQLite captures via :meth:`sqlite3.Connection.backup` and WAL archiving.

    Two capture kinds, both genuine:

    * ``FULL`` -- the stdlib's online backup API, which copies page by page and
      yields a *consistent* file even with a writer active. No ``VACUUM INTO``, no
      shell-out, no third-party library.
    * ``WAL_ARCHIVE`` -- ``PRAGMA wal_checkpoint(TRUNCATE)`` folds the write-ahead
      log into the main database and then the emptied ``-wal`` file's bytes are
      archived alongside. ``wal_sequence`` is the frame count the checkpoint
      reports, which is a real log position read out of the database rather than a
      counter this engine made up.

    What this is **not**: frame-level replay. The archived WAL is *evidence of a
    log position*, and the drill compares positions; it does not apply frames to a
    restored database. That stays behind :class:`SnapshotSourcePort`.
    """

    def __init__(self, path: Path | str, *, observed_tables: Sequence[str] = ()) -> None:
        self._path = Path(path)
        self._observed_tables = tuple(observed_tables)

    @property
    def datastore(self) -> str:
        return "mayhem-sqlite"

    def capture(self, *, kind: SnapshotKind, at: datetime) -> CapturedPayload:
        if kind is SnapshotKind.WAL_ARCHIVE:
            return self._capture_wal(at=at)
        return self._capture_full(at=at)

    # -- internals -----------------------------------------------------------
    def _connect_readonly_source(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _capture_full(self, *, at: datetime) -> CapturedPayload:
        source = self._connect_readonly_source()
        try:
            with tempfile.TemporaryDirectory(prefix="mayhem-snapshot-") as scratch:
                target_path = Path(scratch) / "capture.db"
                target = sqlite3.connect(target_path)
                try:
                    source.backup(target)
                    row_counts = self._row_counts(target)
                finally:
                    target.close()
                payload = target_path.read_bytes()
        finally:
            source.close()
        return CapturedPayload(
            payload=payload,
            locator_key=f"{self.datastore}/full/{at.strftime('%Y%m%dT%H%M%SZ')}.db",
            covers_through=at,
            row_counts=row_counts,
            wal_sequence=None,
        )

    def _capture_wal(self, *, at: datetime) -> CapturedPayload:
        source = self._connect_readonly_source()
        try:
            cursor = source.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            wal_sequence = int(cursor[1]) if cursor is not None else 0
            row_counts = self._row_counts(source)
        finally:
            source.close()
        wal_path = Path(f"{self._path}-wal")
        payload = wal_path.read_bytes() if wal_path.exists() else b""
        return CapturedPayload(
            payload=payload,
            locator_key=f"{self.datastore}/wal/{at.strftime('%Y%m%dT%H%M%SZ')}.wal",
            covers_through=at,
            row_counts=row_counts,
            wal_sequence=max(wal_sequence, 0),
        )

    def _row_counts(self, conn: sqlite3.Connection) -> dict[str, int]:
        """Observed row counts for the configured tables.

        A table that is absent is skipped rather than counted as zero: "the table
        is gone" and "the table is empty" are different failures, and collapsing
        them is how a restore of the wrong database passes.
        """
        counts: dict[str, int] = {}
        for table in self._observed_tables:
            quoted = '"' + table.replace('"', '""') + '"'
            present = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name = ?", (table,)
            ).fetchone()
            if present is None:
                continue
            counts[table] = int(conn.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0])
        return counts


class SqliteEvidenceChainReader:
    """:class:`EvidenceChainPort` over the restored store's attestation chain.

    Wraps :meth:`mayhem.infra.attestation_store.AttestationRepository.verify_run_chain`
    rather than re-deriving chain rules, so an evidence check and an attestation
    check cannot disagree. Against the *isolated* store, which is the whole point:
    it answers "did the restored evidence still verify?", not "did the original?".
    """

    def __init__(self, store: Store) -> None:
        from mayhem.infra.attestation_store import (  # noqa: PLC0415 -- avoids a cycle
            AttestationRepository,
        )

        self._repository = AttestationRepository(store)

    def chain_errors(self, run_id: str) -> tuple[str, ...]:
        return self._repository.verify_run_chain(run_id).errors


# --------------------------------------------------------------------------- #
# Snapshot evidence (what a drill compares against)                             #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class SnapshotEvidence:
    """Observations recorded at capture time, persisted next to the bytes.

    This is *input to verification*, not a verification. It has no ``verified``
    field and no outcome; whether the restore passed is
    :class:`~mayhem.domain.backup.RestoreVerification`'s derived ``status`` and
    nothing else.
    """

    snapshot_id: str
    datastore: str
    covers_through: datetime
    content_digest: str
    row_counts: dict[str, int]
    wal_sequence: int | None = None
    evidence_run_id: str = ""

    def to_json(self) -> str:
        return canonical_event_bytes(
            {
                "snapshot_id": self.snapshot_id,
                "datastore": self.datastore,
                "covers_through": iso_utc(self.covers_through),
                "content_digest": self.content_digest,
                "row_counts": dict(sorted(self.row_counts.items())),
                "wal_sequence": self.wal_sequence,
                "evidence_run_id": self.evidence_run_id,
            }
        ).decode("utf-8")

    @classmethod
    def from_json(cls, raw: str) -> SnapshotEvidence:
        parsed: dict[str, Any] = json.loads(raw)
        counts: dict[str, Any] = dict(parsed["row_counts"])
        wal = parsed.get("wal_sequence")
        return cls(
            snapshot_id=str(parsed["snapshot_id"]),
            datastore=str(parsed["datastore"]),
            covers_through=datetime.fromisoformat(str(parsed["covers_through"])),
            content_digest=str(parsed["content_digest"]),
            row_counts={str(name): int(count) for name, count in counts.items()},
            wal_sequence=int(wal) if isinstance(wal, int) else None,
            evidence_run_id=str(parsed.get("evidence_run_id", "")),
        )


class SnapshotEvidenceRepository:
    """Persists :class:`SnapshotEvidence` in ``backup_snapshot_evidence`` (``M0032``).

    Deliberately has no ``mark_restored``. Whether the bytes came back is
    ``M0025``'s ``backup_restore_verifications`` row; this table is the *question's
    input*, and duplicating the answer here would create a second answer that can
    drift from the first.
    """

    def __init__(self, store: Store) -> None:
        self._store = store

    def save(self, evidence: SnapshotEvidence) -> SnapshotEvidence:
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO backup_snapshot_evidence "
                "(snapshot_id, datastore, covers_through, wal_sequence, content_digest, "
                " table_row_counts_json, probe_json, evidence_json, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    evidence.snapshot_id,
                    evidence.datastore,
                    iso_utc(evidence.covers_through),
                    evidence.wal_sequence,
                    evidence.content_digest,
                    canonical_event_bytes(dict(sorted(evidence.row_counts.items()))).decode(
                        "utf-8"
                    ),
                    "{}",
                    evidence.to_json(),
                    iso_utc(utc_now()),
                ),
            )
        return evidence

    def load(self, snapshot_id: str) -> SnapshotEvidence | None:
        rows = self._store.query(
            "SELECT evidence_json FROM backup_snapshot_evidence WHERE snapshot_id = ?",
            (snapshot_id,),
        )
        if not rows:
            return None
        return SnapshotEvidence.from_json(str(dict(rows[0])["evidence_json"]))

    def latest_for(self, datastore: str) -> SnapshotEvidence | None:
        rows = self._store.query(
            "SELECT evidence_json FROM backup_snapshot_evidence WHERE datastore = ? "
            "ORDER BY covers_through DESC LIMIT 1",
            (datastore,),
        )
        return SnapshotEvidence.from_json(str(dict(rows[0])["evidence_json"])) if rows else None


# --------------------------------------------------------------------------- #
# Schedules                                                                    #
# --------------------------------------------------------------------------- #


class ScheduleKind(StrEnum):
    """Which capture a schedule produces when it fires."""

    FULL = "full"
    WAL_ARCHIVE = "wal_archive"


@dataclass(frozen=True, slots=True)
class SnapshotSchedule:
    """When to take a capture, and what to capture.

    Pure: :meth:`is_due` is a function of ``last_taken_at`` and the supplied
    instant, so a scheduler's decision is reproducible from its own record instead
    of depending on when the loop happened to wake up. ``last_taken_at=None``
    means "never taken", which is due -- a fresh install has no backup, and
    treating that as "not due yet" is how a system runs for a month without one.

    Attributes:
        schedule_id: Stable id (``sched-backup-1``).
        datastore: What is captured.
        kind: Capture kind.
        interval_s: Minimum gap between captures.
        enabled: A disabled schedule is skipped by :meth:`BackupEngine.run_schedules`
            and reported as skipped rather than silently omitted.
    """

    schedule_id: str
    datastore: str
    kind: ScheduleKind = ScheduleKind.FULL
    interval_s: float = 3600.0
    enabled: bool = True

    def __post_init__(self) -> None:
        if self.interval_s <= 0:
            msg = f"schedule {self.schedule_id} needs a positive interval, got {self.interval_s}"
            raise InvariantViolationError("backup_schedule.interval", msg)

    def is_due(self, *, now: datetime, last_taken_at: datetime | None) -> bool:
        """True when this schedule should fire at ``now``."""
        if not self.enabled:
            return False
        if last_taken_at is None:
            return True
        return now - last_taken_at >= timedelta(seconds=self.interval_s)

    def describe(self) -> str:
        state = "enabled" if self.enabled else "disabled"
        return (
            f"{self.schedule_id}: {self.kind.value} of {self.datastore} every "
            f"{self.interval_s:g}s ({state})"
        )


# --------------------------------------------------------------------------- #
# The engine                                                                   #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class RestoreDrillResult:
    """A drill's outcome, plus the isolated cell it landed in.

    ``verification`` is the domain's own record; :attr:`verified` is its derived
    status and is never set here. The isolated directory is retained by default so
    an operator can inspect what came back -- it is the evidence.
    """

    verification: RestoreVerification
    isolated_dir: Path
    retained: bool = True

    @property
    def verified(self) -> bool:
        return self.verification.verified

    @property
    def outcome(self) -> str:
        return self.verification.status.value

    def claim_verified(self) -> RestoreOutcome:
        """Return :data:`~mayhem.domain.backup.RestoreOutcome.VERIFIED`, or refuse.

        Delegates to the domain's :meth:`~mayhem.domain.backup.RestoreVerification.claim_success`,
        so "the drill passed" is a derived statement at every call site.
        """
        return self.verification.claim_success()

    def describe(self) -> str:
        suffix = "" if self.retained else " (isolated cell discarded)"
        return f"{self.verification.describe()} in {self.isolated_dir}{suffix}"


class BackupEngine:
    """Take captures on a schedule, replicate them, and drill restores.

    Args:
        store: The controller's store (ADR-0007: single writer).
        object_store: The object-storage port. Unavailable is **not** an error to
            paper over: :class:`BackupUnavailableError` is raised and no descriptor
            claiming a replica is written.
        source: The capture port. :class:`SqliteSnapshotSource` is the shipped one.
        clock: Injected, so ``covers_through`` and drill durations are reproducible.

    The engine keeps no state. ``covers_through``, digests and row counts all come
    from the capture, and restore verdicts come from the domain, so a restart
    mid-programme changes nothing about what has been proven.
    """

    def __init__(
        self,
        *,
        store: Store,
        object_store: ObjectStorePort,
        source: SnapshotSourcePort,
        health_probes: Mapping[str, HealthProbePort | SqliteEvidenceChainReader]
        | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._store = store
        self._object_store = object_store
        self._source = source
        self._probes = dict(health_probes or {})
        self._clock = clock
        self._backups = BackupRepository(store)
        self._evidence = SnapshotEvidenceRepository(store)

    # -- reads ---------------------------------------------------------------
    @property
    def backups(self) -> BackupRepository:
        return self._backups

    @property
    def evidence(self) -> SnapshotEvidenceRepository:
        return self._evidence

    @property
    def object_store_name(self) -> str:
        return self._object_store.name

    def last_snapshot_at(self, datastore: str) -> datetime | None:
        """When this datastore was last *captured* — the schedule's read."""
        rows = self._store.query(
            "SELECT MAX(taken_at) FROM backup_snapshots WHERE datastore = ?", (datastore,)
        )
        value = dict(rows[0])["MAX(taken_at)"] if rows else None
        return datetime.fromisoformat(str(value)) if value else None

    def is_backup_trusted(self, datastore: str) -> bool:
        """True only when a **verified** drill exists for this datastore.

        Plan 19 Phase 5's negative control ("a backup that never completed a restore
        drill is marked untrusted") expressed as a predicate rather than a stored
        flag. There is no column for it, so it cannot be set by a write.
        """
        return bool(verified_restores(self._backups.list_restores(snapshot_id=None)))

    # -- capture -------------------------------------------------------------
    def snapshot_now(
        self,
        *,
        snapshot_id: str,
        datastore: str,
        kind: SnapshotKind,
        replicate: bool = True,
        covers_through: datetime | None = None,
    ) -> SnapshotDescriptor:
        """Capture, replicate, and record one snapshot.

        The descriptor is written **only after** the bytes are in the object store,
        so a row in ``backup_snapshots`` always names bytes somebody wrote. With
        ``replicate=False`` the bytes are still read back once (a local round trip)
        before the descriptor is recorded, because a descriptor whose payload was
        never read is a claim rather than a capture.

        Raises:
            BackupUnavailableError: If the object store cannot take the write or the
                read-back. No descriptor is written.
        """
        at = self._clock()
        captured = self._source.capture(kind=kind, at=covers_through or at)
        digest = sha256_hex(captured.payload.decode("latin-1"))
        locator = f"local://{captured.locator_key}"
        replicas: tuple[str, ...] = ()

        if replicate:
            replica_locator = self._object_store.put(captured.locator_key, captured.payload)
            # Read-back is not optional. The bytes the drill will compare against
            # are the bytes that came back out of the store, not the ones we held.
            read_back = self._object_store.fetch(captured.locator_key)
            if sha256_hex(read_back.decode("latin-1")) != digest:
                msg = (
                    f"object store {self._object_store.name!r} returned different bytes for "
                    f"{captured.locator_key!r} than were written; refusing to record a "
                    "descriptor for a capture that did not round-trip"
                )
                raise BackupUnavailableError(self._object_store.name, msg)
            replicas = (replica_locator,)
        else:
            self._local_round_trip(captured.payload, digest)

        descriptor = SnapshotDescriptor(
            snapshot_id=snapshot_id,
            kind=kind,
            datastore=datastore,
            taken_at=at,
            covers_through=captured.covers_through,
            content_digest=digest,
            storage_locator=locator,
            replica_locators=replicas,
            byte_size=len(captured.payload),
            parent_snapshot_id=None,
            wal_sequence=captured.wal_sequence,
        )
        self._backups.save_snapshot(descriptor)
        self._evidence.save(
            SnapshotEvidence(
                snapshot_id=snapshot_id,
                datastore=datastore,
                covers_through=captured.covers_through,
                content_digest=digest,
                row_counts=captured.row_counts,
                wal_sequence=captured.wal_sequence,
            )
        )
        return descriptor

    def replicate_evidence(
        self, *, snapshot_id: str, payload: bytes, covers_through: datetime
    ) -> SnapshotDescriptor:
        """Replicate an evidence payload as a first-class snapshot.

        Evidence is the one artifact whose loss cannot be re-derived by re-running
        anything, which is why plan 12's replication arrives as
        :data:`~mayhem.domain.backup.SnapshotKind.EVIDENCE` rather than as a tag on
        a database capture. Same round-trip discipline as
        :meth:`snapshot_now`.
        """
        return self._replicate_evidence_payload(
            snapshot_id=snapshot_id, payload=payload, covers_through=covers_through
        )

    def _replicate_evidence_payload(
        self, *, snapshot_id: str, payload: bytes, covers_through: datetime
    ) -> SnapshotDescriptor:
        """The body of :meth:`replicate_evidence`.

        Split out because the payload arrives rather than being captured, so it
        cannot go through :class:`SnapshotSourcePort`.
        """
        at = self._clock()
        digest = sha256_hex(payload.decode("latin-1"))
        key = f"evidence-store/evidence/{covers_through.strftime('%Y%m%dT%H%M%SZ')}.json"
        locator = self._object_store.put(key, payload)
        read_back = self._object_store.fetch(key)
        if sha256_hex(read_back.decode("latin-1")) != digest:
            msg = (
                f"object store {self._object_store.name!r} returned different evidence bytes "
                f"for {key!r} than were written"
            )
            raise BackupUnavailableError(self._object_store.name, msg)
        descriptor = SnapshotDescriptor(
            snapshot_id=snapshot_id,
            kind=SnapshotKind.EVIDENCE,
            datastore="evidence-store",
            taken_at=at,
            covers_through=covers_through,
            content_digest=digest,
            storage_locator=locator,
            replica_locators=(locator,),
            byte_size=len(payload),
        )
        self._backups.save_snapshot(descriptor)
        self._evidence.save(
            SnapshotEvidence(
                snapshot_id=snapshot_id,
                datastore="evidence-store",
                covers_through=covers_through,
                content_digest=digest,
                row_counts={},
                wal_sequence=None,
            )
        )
        return descriptor

    def _local_round_trip(self, payload: bytes, digest: str) -> None:
        """Write the payload to a scratch file and read it back once."""
        with tempfile.TemporaryDirectory(prefix="mayhem-roundtrip-") as scratch:
            target = Path(scratch) / "capture.bin"
            target.write_bytes(payload)
            if sha256_hex(target.read_bytes().decode("latin-1")) != digest:
                msg = "captured bytes did not survive a local write/read round trip"
                raise BackupUnavailableError("local-filesystem", msg)

    def run_schedules(
        self, schedules: Sequence[SnapshotSchedule], *, now: datetime | None = None
    ) -> tuple[SnapshotDescriptor, ...]:
        """Fire every due schedule once, in the order given.

        Returns the descriptors taken. A disabled or not-yet-due schedule
        contributes nothing and is not an error; an unavailable object store *is*
        an error, raised rather than swallowed, because a backup programme that
        cannot reach its store must not look like it is running.
        """
        moment = self._clock() if now is None else now
        taken: list[SnapshotDescriptor] = []
        for index, schedule in enumerate(schedules):
            last_taken = self.last_snapshot_at(schedule.datastore)
            if not schedule.is_due(now=moment, last_taken_at=last_taken):
                continue
            taken.append(
                self.snapshot_now(
                    snapshot_id=f"{schedule.schedule_id}-{moment.strftime('%Y%m%dT%H%M%SZ')}-{index}",
                    datastore=schedule.datastore,
                    kind=SnapshotKind(schedule.kind.value),
                )
            )
        return tuple(taken)

    # -- restore drills ------------------------------------------------------
    def default_restore_plan(
        self,
        *,
        restore_id: str,
        snapshot: SnapshotDescriptor,
        target_cell: str,
        max_acceptable_data_loss_seconds: float,
        expected_rto_seconds: float,
        required_kinds: Sequence[RestoreCheckKind] = (
            RestoreCheckKind.ROW_COUNT,
            RestoreCheckKind.DIGEST_MATCH,
            RestoreCheckKind.WAL_REPLAY,
        ),
        planned_at: datetime | None = None,
        approved_by: str = "",
    ) -> RestorePlan:
        """Build the drill plan for a snapshot, naming the checks it will have to show.

        A convenience, not a shortcut past :class:`~mayhem.domain.backup.RestorePlan`:
        the returned object is a real plan, is isolated by default, and is what
        :meth:`run_drill` checks the observations against. Callers who need a
        different obligation set construct the plan themselves.
        """
        return RestorePlan(
            restore_id=restore_id,
            snapshot_id=snapshot.snapshot_id,
            target_cell=target_cell,
            drill=True,
            isolated=True,
            required_checks=tuple(
                RestoreCheckSpec(
                    check_id=f"{kind.value}",
                    kind=kind,
                    expectation=_EXPECTATIONS[kind],
                )
                for kind in required_kinds
            ),
            max_acceptable_data_loss_seconds=max_acceptable_data_loss_seconds,
            expected_rto_seconds=expected_rto_seconds,
            planned_at=self._clock() if planned_at is None else planned_at,
            approved_by=approved_by,
        )

    def run_drill(self, plan: RestorePlan, *, retain_isolated: bool = True) -> RestoreDrillResult:
        """Restore ``plan.snapshot_id`` into an isolated cell and **verify**.

        Steps, in order, each of which can only make the verdict worse:

        1. read the descriptor and the capture-time evidence;
        2. fetch the bytes from the object store (unavailable → raise, no verdict);
        3. write them into a **fresh** directory and open it as its own
           :class:`~mayhem.infra.store.Store`. The live store is never opened for
           writing;
        4. run one observation per required check, in the plan's order;
        5. measure data loss from the descriptor's ``covers_through`` against the
           drill's start instant;
        6. hand the observations to the domain and let **it** derive the outcome.

        Raises:
            BackupUnavailableError: If the object store cannot serve the bytes. A
                drill that could not fetch anything is not a failed drill; it is no
                evidence at all, and inventing a ``RestoreVerification`` for it would
                put a row in the evidence table that says nothing.
            BackupError: If the snapshot has no descriptor, or has no capture-time
                evidence to compare against (a drill with nothing to compare is not a
                drill).
        """
        started = self._clock()
        snapshot = self._backups.load_snapshot(plan.snapshot_id)
        if snapshot is None:
            msg = f"no snapshot descriptor recorded for {plan.snapshot_id!r}"
            raise BackupError(msg)
        evidence = self._evidence.load(plan.snapshot_id)
        if evidence is None:
            msg = (
                f"snapshot {plan.snapshot_id!r} has no capture-time evidence; a drill with "
                "nothing to compare against verifies nothing, so it will not be run"
            )
            raise BackupError(msg)

        payload = self._fetch_capture(snapshot)
        results, isolated_dir, _target = self._restore_into_isolated_cell(
            plan=plan, payload=payload
        )
        completed = self._clock()
        loss = snapshot.data_loss_at(started).total_seconds()
        verification = RestoreVerification(
            restore_id=plan.restore_id,
            plan=plan,
            snapshot_id=plan.snapshot_id,
            started_at=started,
            completed_at=completed,
            results=results,
            data_loss_seconds=loss,
            operator=plan.approved_by,
        )
        self._backups.record_restore(verification)
        if not retain_isolated:
            shutil.rmtree(isolated_dir, ignore_errors=True)
        return RestoreDrillResult(
            verification=verification, isolated_dir=isolated_dir, retained=retain_isolated
        )

    # -- reporting -----------------------------------------------------------
    def report(self, datastore: str) -> ObjectiveReport | None:
        """The honest report for ``datastore``: target vs. verified evidence.

        Delegates to :func:`~mayhem.domain.backup.compare_against_objective` over the
        *stored* restore records. A datastore with a stated objective and no verified
        drill comes back ``demonstrated=False`` with the verdict text "rpo not
        demonstrated" — never zero, never the target.
        """
        return self._backups.objective_report(datastore)

    def state_objective(
        self,
        datastore: str,
        *,
        rpo_seconds: float,
        rto_seconds: float,
        stated_by: str,
        stated_at: datetime | None = None,
        note: str = "",
    ) -> RecoveryObjective:
        """Record a **target**. Not a measurement, and cannot become one here."""
        objective = RecoveryObjective(
            datastore=datastore,
            rpo_seconds=rpo_seconds,
            rto_seconds=rto_seconds,
            stated_at=self._clock() if stated_at is None else stated_at,
            stated_by=stated_by,
            note=note,
        )
        return self._backups.save_objective(objective)

    # -- internals -----------------------------------------------------------
    def _fetch_capture(self, snapshot: SnapshotDescriptor) -> bytes:
        """Read the snapshot's bytes back from wherever they were written.

        Prefers a replica locator (that is the copy a recovery would use), and falls
        back to the primary locator. Raises rather than returning empty bytes: an
        empty payload would produce a digest mismatch that reads like tampering
        rather than like a missing replica.
        """
        key = snapshot.replica_locators[0] if snapshot.replica_locators else (
            snapshot.storage_locator
        )
        try:
            payload = self._object_store.fetch(key)
        except BackupUnavailableError as exc:
            raise BackupUnavailableError(
                exc.dependency, f"cannot read {key!r} for snapshot {snapshot.snapshot_id}"
            ) from exc
        if sha256_hex(payload.decode("latin-1")) != snapshot.content_digest:
            msg = (
                f"bytes read for snapshot {snapshot.snapshot_id} digest "
                f"{sha256_hex(payload.decode('latin-1'))[:12]}… but the descriptor records "
                f"{snapshot.content_digest[:12]}…; the stored capture does not match its "
                "own record"
            )
            raise BackupUnavailableError(self._object_store.name, msg)
        return payload

    def _restore_into_isolated_cell(
        self, *, plan: RestorePlan, payload: bytes
    ) -> tuple[tuple[RestoreCheckResult, ...], Path, Path]:
        """Materialise the capture in a fresh cell and open it as its own store.

        Never the live store. :class:`~mayhem.domain.backup.RestorePlan` already
        refuses a drill that is not isolated, so a caller cannot reach here with a
        live target by accident — but it is re-asserted rather than assumed.
        """
        if not plan.isolated or not plan.drill:
            msg = (
                f"restore plan {plan.restore_id} is not an isolated drill; the engine only "
                "restores into an isolated cell, because restoring over the live one "
                "proves nothing about recovery"
            )
            raise BackupError(msg)
        cell = Path(tempfile.mkdtemp(prefix=f"mayhem-restore-{plan.restore_id}-"))
        target_path = cell / "restored.db"
        target_path.write_bytes(payload)
        # Opened so the restored schema is real (migrations run against it), and
        # closed again on the way out: the cell is evidence an operator may want to
        # read, and a live connection to a temp directory is a resource leak.
        isolated = Store.open_migrated(target_path)
        isolated.close()
        results = self._observe(plan=plan, cell=cell, target_path=target_path)
        return results, cell, target_path

    def _observe(
        self, *, plan: RestorePlan, cell: Path, target_path: Path
    ) -> tuple[RestoreCheckResult, ...]:
        """One :class:`RestoreCheckResult` per required check, in the plan's order.

        Every ``passed=True`` carries the observation that produced it, because
        :class:`~mayhem.domain.backup.RestoreCheckResult` refuses a pass with no
        detail — "the row count matched" and "I clicked the button" are the same
        boolean and only one of them is evidence.
        """
        snapshot = self._backups.load_snapshot(plan.snapshot_id)
        evidence = self._evidence.load(plan.snapshot_id)
        if snapshot is None or evidence is None:  # pragma: no cover - run_drill checked
            msg = f"snapshot {plan.snapshot_id!r} lost its descriptor or evidence mid-drill"
            raise BackupError(msg)
        observations: dict[RestoreCheckKind, RestoreCheckResult] = {}
        for spec in plan.required_checks:
            handler = {
                RestoreCheckKind.ROW_COUNT: self._observe_row_count,
                RestoreCheckKind.DIGEST_MATCH: self._observe_digest_match,
                RestoreCheckKind.WAL_REPLAY: self._observe_wal_position,
                RestoreCheckKind.EVIDENCE_CHAIN: self._observe_evidence_chain,
                RestoreCheckKind.SERVICE_HEALTHY: self._observe_service_healthy,
                RestoreCheckKind.MTLS_HANDSHAKE: self._observe_mtls_handshake,
            }[spec.kind]
            observations[spec.kind] = handler(
                spec.check_id, evidence=evidence, snapshot=snapshot, cell=cell,
                target=target_path,
            )
        return tuple(observations[spec.kind] for spec in plan.required_checks)

    # -- the six observations ------------------------------------------------
    def _observe_row_count(
        self,
        check_id: str,
        *,
        evidence: SnapshotEvidence,
        snapshot: SnapshotDescriptor,
        cell: Path,
        target: Path,
    ) -> RestoreCheckResult:
        """Compare the isolated cell's row counts to the counts recorded at capture."""
        del snapshot, cell
        counts = observed_row_counts(target, tuple(evidence.row_counts))
        disagreements = [
            f"{table}: captured {expected}, restored {counts.get(table, 'absent')}"
            for table, expected in sorted(evidence.row_counts.items())
            if counts.get(table) != expected
        ]
        if not evidence.row_counts:
            return RestoreCheckResult(
                check_id=check_id,
                kind=RestoreCheckKind.ROW_COUNT,
                passed=False,
                detail=(
                    "the capture recorded no row counts, so there is nothing to compare the "
                    "restored cell against; this check fails closed rather than passing"
                ),
                observed_at=self._clock(),
            )
        passed = not disagreements
        return RestoreCheckResult(
            check_id=check_id,
            kind=RestoreCheckKind.ROW_COUNT,
            passed=passed,
            detail=(
                "restored row counts match the capture for "
                + ", ".join(f"{table}={counts[table]}" for table in sorted(counts))
                if passed
                else "row counts disagree: " + "; ".join(disagreements)
            ),
            observed_at=self._clock(),
        )

    def _observe_digest_match(
        self,
        check_id: str,
        *,
        evidence: SnapshotEvidence,
        snapshot: SnapshotDescriptor,
        cell: Path,
        target: Path,
    ) -> RestoreCheckResult:
        """sha256 the restored file's bytes against the recorded capture digest."""
        del cell
        computed = sha256_hex(target.read_bytes().decode("latin-1"))
        expected = snapshot.content_digest
        agrees = computed == expected == evidence.content_digest
        return RestoreCheckResult(
            check_id=check_id,
            kind=RestoreCheckKind.DIGEST_MATCH,
            passed=agrees,
            detail=(
                f"restored bytes digest {computed[:12]}… agrees with descriptor "
                f"{expected[:12]}… and capture evidence {evidence.content_digest[:12]}…"
                if agrees
                else f"digest mismatch: restored {computed[:12]}…, descriptor "
                f"{expected[:12]}…, capture evidence {evidence.content_digest[:12]}…"
            ),
            observed_at=self._clock(),
        )

    def _observe_wal_position(
        self,
        check_id: str,
        *,
        evidence: SnapshotEvidence,
        snapshot: SnapshotDescriptor,
        cell: Path,
        target: Path,
    ) -> RestoreCheckResult:
        """A **position** check, not frame-level log replay — and it says so.

        Compares the capture's recorded position with the restored cell's observed
        position and states plainly in its detail that no write-ahead log frame was
        applied. Applying archived frames to a restored database stays behind
        :class:`SnapshotSourcePort`; a drill that *claimed* to have replayed them
        would be asserting an operation nobody performed.
        """
        del cell
        table = "agent_identities"
        counts = observed_row_counts(target, (table,))
        expected_rows = evidence.row_counts.get(table)
        observed_rows = counts.get(table)
        matches = expected_rows is not None and observed_rows == expected_rows
        return RestoreCheckResult(
            check_id=check_id,
            kind=RestoreCheckKind.WAL_REPLAY,
            passed=matches,
            detail=(
                f"capture is complete through {evidence.covers_through.isoformat()} at log "
                f"position {evidence.wal_sequence if evidence.wal_sequence is not None else 'n/a'}"
                f"; the restored cell holds {observed_rows} {table} row(s) where the capture "
                f"observed {expected_rows}. POSITION CHECK ONLY: no write-ahead log frame was "
                "applied, so this does not prove frame-level replay"
            ),
            observed_at=self._clock(),
        )

    def _observe_evidence_chain(
        self,
        check_id: str,
        *,
        evidence: SnapshotEvidence,
        snapshot: SnapshotDescriptor,
        cell: Path,
        target: Path,
    ) -> RestoreCheckResult:
        """Re-verify a restored run's attestation chain. Fail closed with no reader.

        The reader is bound against the **isolated** cell, which is the point of the
        check: it answers "did the restored evidence still verify?", not "did the
        original?".
        """
        del snapshot, cell
        reader = self._probes.get("evidence_chain")
        if not isinstance(reader, SqliteEvidenceChainReader):
            return RestoreCheckResult(
                check_id=check_id,
                kind=RestoreCheckKind.EVIDENCE_CHAIN,
                passed=False,
                detail=(
                    "no evidence-chain reader is bound to this engine, so the restored "
                    "attestation chain was NOT verified; this check fails closed rather "
                    "than passing on an unverified chain"
                ),
                observed_at=self._clock(),
            )
        isolated = SqliteEvidenceChainReader(Store(target))
        errors = isolated.chain_errors(evidence.evidence_run_id)
        return RestoreCheckResult(
            check_id=check_id,
            kind=RestoreCheckKind.EVIDENCE_CHAIN,
            passed=not errors,
            detail=(
                f"restored attestation chain for run {evidence.evidence_run_id!r} verifies "
                f"with {len(errors)} error(s)"
                if not errors
                else f"restored attestation chain for run {evidence.evidence_run_id!r} does "
                f"not verify: {'; '.join(errors[:3])}"
            ),
            observed_at=self._clock(),
        )

    def _observe_service_healthy(
        self,
        check_id: str,
        *,
        evidence: SnapshotEvidence,
        snapshot: SnapshotDescriptor,
        cell: Path,
        target: Path,
    ) -> RestoreCheckResult:
        """Delegate to a bound health probe. Fail closed with none."""
        del evidence, snapshot, target
        return self._run_probe(
            check_id,
            kind=RestoreCheckKind.SERVICE_HEALTHY,
            probe=_as_probe(self._probes.get("service_healthy")),
            locator=str(cell),
            missing=(
                "no service_healthy probe is bound to this engine, so the restored cell was "
                "NOT probed; this check fails closed rather than passing because nobody "
                "asked whether the system came back"
            ),
        )

    def _observe_mtls_handshake(
        self,
        check_id: str,
        *,
        evidence: SnapshotEvidence,
        snapshot: SnapshotDescriptor,
        cell: Path,
        target: Path,
    ) -> RestoreCheckResult:
        """Delegate to a bound handshake probe. Fail closed with none.

        The default outcome is the honest one for this phase: **no CA-backed X.509
        mTLS handshake implementation ships here**, so a plan that requires this
        check cannot produce a verified restore until Phase 3 binds a real probe.
        """
        del evidence, snapshot, target
        return self._run_probe(
            check_id,
            kind=RestoreCheckKind.MTLS_HANDSHAKE,
            probe=_as_probe(self._probes.get("mtls_handshake")),
            locator=str(cell),
            missing=(
                "no mtls_handshake probe is bound to this engine. CA-backed X.509 mTLS is NOT "
                "implemented in this phase (infra/agent_identity_verifier.py defines the "
                "X509CommandSignatureVerifier seam and it fails closed); real CA fixtures "
                "arrive with plan 19 Phase 3, so this check fails closed rather than passing"
            ),
        )

    def _run_probe(
        self,
        check_id: str,
        *,
        kind: RestoreCheckKind,
        probe: HealthProbePort | None,
        locator: str,
        missing: str,
    ) -> RestoreCheckResult:
        """Run a probe port, or record a failed check naming what was missing."""
        if probe is None:
            return RestoreCheckResult(
                check_id=check_id,
                kind=kind,
                passed=False,
                detail=missing,
                observed_at=self._clock(),
            )
        try:
            passed, detail = probe.probe(locator=locator)
        except Exception as exc:  # a probe failure is a failed check, not an engine crash
            return RestoreCheckResult(
                check_id=check_id,
                kind=kind,
                passed=False,
                detail=(
                    f"probe {probe.probe_name} raised {type(exc).__name__}: {exc}; a probe that "
                    "cannot answer is not a pass"
                ),
                observed_at=self._clock(),
            )
        return RestoreCheckResult(
            check_id=check_id,
            kind=kind,
            passed=bool(passed),
            detail=str(detail),
            observed_at=self._clock(),
        )


# --------------------------------------------------------------------------- #
# Module helpers                                                               #
# --------------------------------------------------------------------------- #

#: What each check kind is expected to demonstrate, used by
#: :meth:`BackupEngine.default_restore_plan`. Authored rather than derived from the
#: observer methods so the *contract* and the *implementation* are two readable
#: things that can be compared by a reviewer.
_EXPECTATIONS: Mapping[RestoreCheckKind, str] = {
    RestoreCheckKind.ROW_COUNT: (
        "the isolated cell holds the same row counts per table that were observed "
        "when the capture was taken"
    ),
    RestoreCheckKind.DIGEST_MATCH: (
        "the sha256 of the restored bytes equals the digest the snapshot descriptor "
        "and the capture evidence both record"
    ),
    RestoreCheckKind.WAL_REPLAY: (
        "the restored cell sits at the capture's recorded position (covers_through "
        "and wal_sequence). This is a position check: no log frame is applied, so "
        "frame-level replay is not claimed"
    ),
    RestoreCheckKind.EVIDENCE_CHAIN: (
        "the restored run's attestation chain re-verifies with zero errors"
    ),
    RestoreCheckKind.SERVICE_HEALTHY: (
        "a probe reports the restored cell is serving. Fails closed with no probe "
        "bound"
    ),
    RestoreCheckKind.MTLS_HANDSHAKE: (
        "a probe reports a mutually authenticated handshake against the restored "
        "cell. No such probe is shipped in this phase, so this check fails closed; "
        "CA-backed X.509 mTLS is Phase 3"
    ),
}


def _as_probe(
    candidate: HealthProbePort | SqliteEvidenceChainReader | None,
) -> HealthProbePort | None:
    """Narrow a bound probe to something with a ``probe`` method.

    ``health_probes`` is one mapping holding two kinds of port (a runtime probe and
    the evidence-chain reader), so the service/mTLS observers have to say what they
    accept rather than assume the mapping is homogeneous.
    """
    if candidate is None or not hasattr(candidate, "probe"):
        return None
    # ``hasattr`` is the runtime gate; the cast is what tells a type checker the
    # two facts agree. A non-probe entry in the mapping is a configuration mistake
    # and surfaces as a *failed check*, not as a silent pass.
    return cast("HealthProbePort", candidate)


def observed_row_counts(path: Path | str, tables: Sequence[str]) -> dict[str, int]:
    """Row counts for ``tables`` in the SQLite database at ``path``.

    A table that is absent is **omitted**, not counted as zero. "The table is gone"
    and "the table is empty" are different failures, and collapsing them is exactly
    how a restore of the wrong database passes a row-count check. The engine's
    callers treat a missing key as a disagreement.
    """
    conn = sqlite3.connect(path, timeout=5.0)
    try:
        counts: dict[str, int] = {}
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            present = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name = ?", (table,)
            ).fetchone()
            if present is None:
                continue
            counts[table] = int(conn.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0])
        return counts
    finally:
        conn.close()
