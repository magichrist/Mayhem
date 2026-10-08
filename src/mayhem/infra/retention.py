"""Retention-class enforcement for attested evidence (plan 12, Phase 2, gap 57).

Phase 1 named the classes (``RetentionClass``: ephemeral, hot, cold, archive,
legal hold) without enforcing any of them. This module enforces them, and it is
the *only* thing that decides whether an attestation's evidence may be deleted.

The ladder
----------

``hot → cold → archive → deleted``. Movement toward ``deleted`` is allowed;
movement back toward ``hot`` is not, because a retention class that can be
downgraded is not a retention promise. ``legal_hold`` overlays every rung:
a held record never expires, whatever its clock says.

Deletion is the dangerous operation, so it carries two independent guards:

* **Dual control.** Two named people, and the engine refuses when they are the
  same identity or either is empty. There is no "system deletes automatically"
  path — an unattended deletion is a policy hole, not a convenience.
* **A tombstone.** Every successful deletion writes a row naming the deleted
  manifest, its digest, both approvers, and when. The manifest bytes go away; the
  record that they were sealed, and who authorised their removal, does not.

Fail closed on the storage seam
-------------------------------

Archive and deletion both need external immutable storage, and Phase 2 ships
none. :class:`RetentionBackend` is the seam; with no backend configured, or with
a backend that raises, :meth:`RetentionEngine.archive` and
:meth:`RetentionEngine.expire` refuse and change nothing. The refusal is the
point: an unavailable store must never be read as "nothing left to keep".

Deletion additionally requires the external copy to *exist* first. Removing the
last local copy without one archived elsewhere is the evidence-loss failure gap
101 exists to prevent, so the engine walks the ladder instead of skipping it.

No signing anywhere in this module: retention governs how long sealed evidence
lives, never who vouched for it.

How this composes with the audit stream (Phase 4)
-------------------------------------------------

Every operation that *changes* a retention record now writes an
:class:`~mayhem.infra.audit_stream.AuditEntry`, so the answer to "who moved this
record, and on whose authority" is in a hash-chained, offline-verifiable stream
rather than only in the mutable ``evidence_retention`` row.

The deletion case is the load-bearing one, and it composes the way it must:

* the tombstone (who requested, who approved, over which manifest digest) is
  written in the same transaction as the state change — unchanged from Phase 2;
* the audit entry is written **after** that transaction, into a different table,
  with no foreign key to anything the deletion touches;
* :data:`UNSIGNED_REASON_NO_SIGNING` still applies: the stream proves the recorded
  bytes are unaltered, not who wrote them.

So a deletion removes the manifest and leaves behind two independent records of
itself — the tombstone row and the audit chain entry — and neither is reachable by
the deletion. :meth:`RetentionEngine.expire` reports the audit entry it wrote, so
a caller can see the record was made rather than assume it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

from mayhem.domain.attestation import AttestedEvent, Manifest, RetentionClass
from mayhem.domain.common import utc_now
from mayhem.domain.errors import DomainError
from mayhem.infra.attestation_store import AttestationRepository
from mayhem.infra.audit_stream import (
    KIND_EVIDENCE_ARCHIVED,
    KIND_EVIDENCE_REGISTERED,
    KIND_LEGAL_HOLD_PLACED,
    KIND_LEGAL_HOLD_RELEASED,
    AuditEntry,
    AuditStream,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from mayhem.infra.store import Store

#: Bumped when :data:`RETENTION_TTL_SECONDS` or the ladder changes, and stamped
#: on every stored record so a policy change is visible in old rows.
RETENTION_POLICY_VERSION = "1.0"

#: Default lifetime per class. ``LEGAL_HOLD`` has no lifetime: "never delete" is
#: the class's whole meaning.
RETENTION_TTL_SECONDS: dict[RetentionClass, int | None] = {
    RetentionClass.EPHEMERAL: 7 * 86_400,
    RetentionClass.HOT: 30 * 86_400,
    RetentionClass.COLD: 90 * 86_400,
    RetentionClass.ARCHIVE: 365 * 86_400,
    RetentionClass.LEGAL_HOLD: None,
}


class RetentionState(StrEnum):
    """Where a record sits on the ladder."""

    HOT = "hot"
    COLD = "cold"
    ARCHIVE = "archive"
    DELETED = "deleted"


#: The only legal moves. Anything else is a policy violation, not a preference.
ALLOWED_TRANSITIONS: dict[RetentionState, tuple[RetentionState, ...]] = {
    RetentionState.HOT: (RetentionState.COLD,),
    RetentionState.COLD: (RetentionState.ARCHIVE,),
    RetentionState.ARCHIVE: (RetentionState.DELETED,),
    RetentionState.DELETED: (),
}


class RetentionError(DomainError):
    """Retention enforcement failed."""


class RetentionRefusedError(RetentionError):
    """A policy rule refused a retention operation. Nothing was changed."""


class RetentionBackendUnavailableError(RetentionError):
    """No usable external store: the operation fails closed.

    Distinct from :class:`RetentionRefusedError` because the remedy differs. A refusal
    is a policy decision ("too early", "held", "needs two people"); an unavailable
    backend is a missing dependency, and it must never be read as permission.
    """


class RetentionBackend(Protocol):
    """The external-immutable-storage seam (gap 101).

    **No production implementation is shipped in Phase 2.** WORM/object-lock
    semantics — an S3 Object Lock bucket in governance mode, Azure immutable
    blobs, a GCS retention policy — are Phase 3 work.

    ``put`` stores a manifest's sealed bytes under a key; ``contains`` reports
    whether an external copy exists; ``delete`` removes it and is *expected to
    raise* while the store's own lock is in force. The engine treats such a
    refusal as fail-closed: the local record stays too, so external immutability
    can never leave the control plane claiming a deletion that did not happen.
    """

    name: str

    def put(self, key: str, payload: bytes) -> None: ...

    def contains(self, key: str) -> bool: ...

    def delete(self, key: str) -> None: ...


class InMemoryRetentionBackend:
    """A test/dev double. **Not durable, not immutable, never a production backend.**

    It exists so the archive/delete flows can be exercised without pretending a
    process-local dict is object storage. A production deployment must supply a
    real backend whose ``delete`` refuses while a lock holds.
    """

    name = "in-memory"

    def __init__(self) -> None:
        self._objects: dict[str, bytes] = {}

    def put(self, key: str, payload: bytes) -> None:
        self._objects[key] = payload

    def contains(self, key: str) -> bool:
        return key in self._objects

    def delete(self, key: str) -> None:
        if key not in self._objects:
            raise RetentionBackendUnavailableError(f"no external object at {key!r}")
        del self._objects[key]


def backend_key(manifest: Manifest) -> str:
    """The stable external key for a manifest's archived bytes."""
    return f"{manifest.run_id}/{manifest.manifest_id}.manifest.json"


def expiry_for(retention_class: RetentionClass, *, from_instant: datetime) -> datetime | None:
    """When a record of ``retention_class`` expires, or ``None`` if never."""
    seconds = RETENTION_TTL_SECONDS[retention_class]
    if seconds is None:
        return None
    return from_instant + timedelta(seconds=seconds)


# --------------------------------------------------------------------------- #
# Records                                                                      #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class RetentionRecord:
    """One manifest's retention state."""

    manifest_id: str
    run_id: str
    retention_class: RetentionClass
    state: RetentionState
    legal_hold: bool
    hold_reason: str
    expires_at: datetime | None
    manifest_digest: str
    policy_version: str
    created_at: str
    updated_at: str

    def is_expired(self, now: datetime) -> bool:
        """Whether the class lifetime has elapsed.

        A held record, or one that never expires, is never expired: expiry is a
        clock statement, and the hold is a policy statement that outranks it.
        """
        if self.legal_hold or self.expires_at is None:
            return False
        return now >= self.expires_at

    def to_dict(self) -> dict[str, object]:
        return {
            "manifest_id": self.manifest_id,
            "run_id": self.run_id,
            "retention_class": self.retention_class.value,
            "state": self.state.value,
            "legal_hold": self.legal_hold,
            "hold_reason": self.hold_reason,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "manifest_digest": self.manifest_digest,
            "policy_version": self.policy_version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass(frozen=True, slots=True)
class RetentionAssessment:
    """What the policy says about one record right now, without changing it."""

    record: RetentionRecord
    expired: bool
    deletable: bool
    blocked_by: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "record": self.record.to_dict(),
            "expired": self.expired,
            "deletable": self.deletable,
            "blocked_by": self.blocked_by,
        }


@dataclass(frozen=True, slots=True)
class RetentionTombstone:
    """What a deletion left behind: who authorised it, and over which manifest."""

    tombstone_id: str
    manifest_id: str
    run_id: str
    manifest_digest: str
    retention_class: RetentionClass
    requester: str
    approver: str
    reason: str
    backend: str
    deleted_at: str

    @property
    def dual_control_satisfied(self) -> bool:
        """Two distinct, named identities approved the deletion."""
        return bool(self.requester and self.approver and self.requester != self.approver)

    def to_dict(self) -> dict[str, object]:
        return {
            "tombstone_id": self.tombstone_id,
            "manifest_id": self.manifest_id,
            "run_id": self.run_id,
            "manifest_digest": self.manifest_digest,
            "retention_class": self.retention_class.value,
            "requester": self.requester,
            "approver": self.approver,
            "reason": self.reason,
            "backend": self.backend,
            "deleted_at": self.deleted_at,
            "dual_control_satisfied": self.dual_control_satisfied,
        }


def _require_dual_control(requester: str, approver: str, manifest_id: str) -> tuple[str, str]:
    """Enforce the two-person rule and return the cleaned identities.

    Raises:
        RetentionRefusedError: If either identity is empty, or they are the same one.
            Self-approval is not dual control however the two strings were typed.
    """
    requester = requester.strip()
    approver = approver.strip()  # " Ana " and "ana" are one person, not two
    if not requester or not approver:
        raise RetentionRefusedError(
            f"deleting evidence for manifest {manifest_id!r} needs dual control: "
            "both a requester and a distinct approver must be named"
        )
    if requester == approver:
        raise RetentionRefusedError(
            f"deleting evidence for manifest {manifest_id!r} needs dual control: "
            f"{requester!r} requested and approved it; self-approval is refused"
        )
    return requester, approver


def _require_backend(backend: RetentionBackend | None, operation: str) -> RetentionBackend:
    """The backend, or a fail-closed refusal.

    Raises:
        RetentionBackendUnavailableError: If no backend is configured. Phase 2
            ships no object store, so the default deployment *always* fails
            closed here rather than pretending evidence is durably archived.
    """
    if backend is None:
        raise RetentionBackendUnavailableError(
            f"{operation} requires an external immutable store and none is "
            "configured: plan 12 Phase 2 defines the seam but ships no WORM/object-lock "
            "backend, so the operation fails closed and nothing is changed"
        )
    return backend


# --------------------------------------------------------------------------- #
# Repository                                                                   #
# --------------------------------------------------------------------------- #


class RetentionRepository:
    """Reads and writes the M0023 retention tables, one transaction per write."""

    def __init__(self, store: Store) -> None:
        self._store = store

    def save_record(self, record: RetentionRecord) -> RetentionRecord:
        """Insert or replace one retention record."""
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO evidence_retention "
                "(manifest_id, run_id, retention_class, state, legal_hold, hold_reason,"
                " expires_at, manifest_digest, policy_version, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    record.manifest_id,
                    record.run_id,
                    record.retention_class.value,
                    record.state.value,
                    1 if record.legal_hold else 0,
                    record.hold_reason,
                    record.expires_at.isoformat() if record.expires_at else None,
                    record.manifest_digest,
                    record.policy_version,
                    record.created_at,
                    record.updated_at,
                ),
            )
        return record

    def load_record(self, manifest_id: str) -> RetentionRecord | None:
        """One retention record, or ``None`` when the manifest is not registered."""
        rows = self._store.query(
            "SELECT * FROM evidence_retention WHERE manifest_id = ?", (manifest_id,)
        )
        return _record_from_row(dict(rows[0])) if rows else None

    def list_records(self) -> tuple[RetentionRecord, ...]:
        """Every registered retention record, oldest first."""
        rows = self._store.query(
            "SELECT * FROM evidence_retention ORDER BY created_at, manifest_id"
        )
        return tuple(_record_from_row(dict(row)) for row in rows)

    def save_tombstone(self, tombstone: RetentionTombstone) -> RetentionTombstone:
        """Insert or replace one tombstone. Called only from a successful delete."""
        with self._store.write() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO retention_tombstones "
                "(tombstone_id, manifest_id, run_id, manifest_digest, retention_class,"
                " requester, approver, reason, backend, deleted_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    tombstone.tombstone_id,
                    tombstone.manifest_id,
                    tombstone.run_id,
                    tombstone.manifest_digest,
                    tombstone.retention_class.value,
                    tombstone.requester,
                    tombstone.approver,
                    tombstone.reason,
                    tombstone.backend,
                    tombstone.deleted_at,
                ),
            )
        return tombstone

    def save_deletion(
        self, record: RetentionRecord, tombstone: RetentionTombstone
    ) -> RetentionTombstone:
        """Mark a record deleted and write its tombstone in one transaction.

        One transaction is what keeps the two facts consistent: there is no state
        in which a record reads as deleted with no tombstone explaining who
        authorised it.
        """
        with self._store.write() as conn:
            conn.execute(
                "UPDATE evidence_retention SET state = ?, updated_at = ? WHERE manifest_id = ?",
                (RetentionState.DELETED.value, tombstone.deleted_at, record.manifest_id),
            )
            conn.execute(
                "INSERT INTO retention_tombstones "
                "(tombstone_id, manifest_id, run_id, manifest_digest, retention_class,"
                " requester, approver, reason, backend, deleted_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    tombstone.tombstone_id,
                    tombstone.manifest_id,
                    tombstone.run_id,
                    tombstone.manifest_digest,
                    tombstone.retention_class.value,
                    tombstone.requester,
                    tombstone.approver,
                    tombstone.reason,
                    tombstone.backend,
                    tombstone.deleted_at,
                ),
            )
        return tombstone

    def load_tombstone(self, manifest_id: str) -> RetentionTombstone | None:
        """The tombstone for a deleted manifest, or ``None``."""
        rows = self._store.query(
            "SELECT * FROM retention_tombstones WHERE manifest_id = ?", (manifest_id,)
        )
        return _tombstone_from_row(dict(rows[0])) if rows else None

    def list_tombstones(self) -> tuple[RetentionTombstone, ...]:
        """Every tombstone, oldest first."""
        rows = self._store.query(
            "SELECT * FROM retention_tombstones ORDER BY deleted_at, manifest_id"
        )
        return tuple(_tombstone_from_row(dict(row)) for row in rows)


def _parse_instant(value: object) -> datetime | None:
    """Read a stored ISO stamp into an aware datetime, or ``None``."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _record_from_row(row: dict[str, object]) -> RetentionRecord:
    return RetentionRecord(
        manifest_id=str(row["manifest_id"]),
        run_id=str(row["run_id"]),
        retention_class=RetentionClass(str(row["retention_class"])),
        state=RetentionState(str(row["state"])),
        legal_hold=bool(row["legal_hold"]),
        hold_reason=str(row["hold_reason"]),
        expires_at=_parse_instant(row["expires_at"]),
        manifest_digest=str(row["manifest_digest"]),
        policy_version=str(row["policy_version"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _tombstone_from_row(row: dict[str, object]) -> RetentionTombstone:
    return RetentionTombstone(
        tombstone_id=str(row["tombstone_id"]),
        manifest_id=str(row["manifest_id"]),
        run_id=str(row["run_id"]),
        manifest_digest=str(row["manifest_digest"]),
        retention_class=RetentionClass(str(row["retention_class"])),
        requester=str(row["requester"]),
        approver=str(row["approver"]),
        reason=str(row["reason"]),
        backend=str(row["backend"]),
        deleted_at=str(row["deleted_at"]),
    )


# --------------------------------------------------------------------------- #
# Engine                                                                       #
# --------------------------------------------------------------------------- #


class RetentionEngine:
    """Enforces the per-class retention ladder over sealed manifests.

    The engine never decides *what* to keep — that is the manifest's retention
    class. It decides whether a record may move, may expire, and may finally be
    deleted, and it writes the tombstone when it does.

    With no ``backend`` every storage-touching operation fails closed. That is
    the Phase 2 default, and it is deliberate: no object store ships yet, so the
    safe answer to "may this be archived?" is no.

    Movement reasons are not recorded in Phase 2; the two places an audit asks
    *why* — the legal hold and the deletion — both store their reason.
    """

    def __init__(
        self,
        store: Store,
        *,
        backend: RetentionBackend | None = None,
        clock: Callable[[], datetime] = utc_now,
        audit: AuditStream | None = None,
        audit_principal: str = "mayhem.controller",
    ) -> None:
        self._store = store
        self._backend = backend
        self._clock = clock
        self._retention = RetentionRepository(store)
        self._attestations = AttestationRepository(store)
        # Phase 4. Built here rather than required, so an existing caller keeps
        # working unchanged and a deletion still leaves its audit record — the
        # default *is* to audit, not to opt in to auditing.
        self._audit = audit if audit is not None else AuditStream(store)
        self._audit_principal = audit_principal

    @property
    def backend(self) -> RetentionBackend | None:
        """The configured external store, or ``None`` — which means fail closed."""
        return self._backend

    @property
    def audit(self) -> AuditStream:
        """The attested stream every state change is recorded in (Phase 4)."""
        return self._audit

    def _record(
        self,
        *,
        action: str,
        target: str,
        run_id: str,
        detail: dict[str, object] | None = None,
    ) -> AttestedEvent:
        """Write one audit entry, named after the actor that asked for the change.

        Failures are *not* swallowed: an audit entry that could not be written is
        a gap in the record, and a caller that believes it was logged when it was
        not is worse off than one that gets the error. The retention change has
        already committed by this point, so the exception is raised after the fact
        — deliberately, and the ordering is what the tests assert.
        """
        return self._audit.record(
            AuditEntry(
                principal=self._audit_principal,
                action=action,
                target=target,
                subject_run_id=run_id,
                detail=detail,
            )
        )

    def _moment(self, now: datetime | None) -> datetime:
        moment = now or self._clock()
        return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)

    def _manifest(self, manifest_id: str) -> Manifest:
        """The stored manifest whose bytes get archived.

        Raises:
            RetentionRefusedError: If the manifest is not in the attestation store. An
                archive of bytes nobody can verify is not an archive.
        """
        manifest = self._attestations.load_manifest(manifest_id)
        if manifest is None:
            raise RetentionRefusedError(
                f"manifest {manifest_id!r} is not stored; there are no sealed bytes to archive"
            )
        return manifest

    # -- registration -------------------------------------------------------- #

    def register(self, manifest: Manifest, *, now: datetime | None = None) -> RetentionRecord:
        """Start a retention record from a sealed manifest's class.

        A ``LEGAL_HOLD`` manifest is registered already held and with no expiry.
        Registering is idempotent by manifest id, so re-registering a re-sealed
        manifest refreshes the clock rather than creating a second record.

        Raises:
            RetentionRefusedError: If the manifest covers no events — there is nothing
                to retain, and a retention row pointing at an empty chain would
                look like evidence that does not exist.
        """
        if manifest.covered_events == 0:
            raise RetentionRefusedError(
                f"manifest {manifest.manifest_id!r} covers no events; there is nothing to retain"
            )
        moment = self._moment(now)
        stamp = moment.isoformat()
        held = manifest.retention_class is RetentionClass.LEGAL_HOLD
        record = self._retention.save_record(
            RetentionRecord(
                manifest_id=manifest.manifest_id,
                run_id=manifest.run_id,
                retention_class=manifest.retention_class,
                state=RetentionState.HOT,
                legal_hold=held,
                hold_reason="retention class legal_hold" if held else "",
                expires_at=expiry_for(manifest.retention_class, from_instant=moment),
                manifest_digest=manifest.manifest_digest,
                policy_version=RETENTION_POLICY_VERSION,
                created_at=stamp,
                updated_at=stamp,
            )
        )
        self._record(
            action=KIND_EVIDENCE_REGISTERED,
            target=record.manifest_id,
            run_id=record.run_id,
            detail={
                "retention_class": record.retention_class.value,
                "manifest_digest": record.manifest_digest,
                "expires_at": record.expires_at.isoformat() if record.expires_at else "never",
                "legal_hold": record.legal_hold,
            },
        )
        return record

    def get(self, manifest_id: str) -> RetentionRecord:
        """The stored record.

        Raises:
            RetentionRefusedError: If the manifest is not registered for retention.
        """
        record = self._retention.load_record(manifest_id)
        if record is None:
            raise RetentionRefusedError(
                f"manifest {manifest_id!r} has no retention record; register the manifest "
                "before applying a retention policy to it"
            )
        return record

    def assess(self, manifest_id: str, *, now: datetime | None = None) -> RetentionAssessment:
        """What the *policy* says about one record, changing nothing.

        The non-raising twin of :meth:`expire`: a caller that needs to *ask*
        ("is this deletable?") gets an answer with a reason instead of an
        exception, and the reasons are the ones :meth:`expire` refuses with.

        ``deletable`` is a policy verdict only. It does not claim the deletion
        *would succeed*: storage availability is the operation's own check, so a
        ``deletable: true`` with no backend configured still fails closed.
        """
        record = self.get(manifest_id)
        moment = self._moment(now)
        expired = record.is_expired(moment)
        deadline = record.expires_at.isoformat() if record.expires_at else "never"
        blocked = ""
        if record.state is RetentionState.DELETED:
            blocked = "already deleted; a tombstone records the deletion"
        elif record.legal_hold:
            blocked = f"under legal hold ({record.hold_reason or 'no reason recorded'})"
        elif not expired:
            blocked = f"not expired until {deadline}"
        elif record.state is not RetentionState.ARCHIVE:
            blocked = "no external copy: archive before deleting, or the evidence would not survive"
        return RetentionAssessment(
            record=record,
            expired=expired,
            deletable=not blocked,
            blocked_by=blocked,
        )

    def due(self, *, now: datetime | None = None) -> tuple[RetentionRecord, ...]:
        """Records whose class lifetime has elapsed, held records excluded.

        A list to work through, not a delete: expiry still needs an archived copy
        and two named approvers.
        """
        moment = self._moment(now)
        return tuple(
            record for record in self._retention.list_records() if record.is_expired(moment)
        )

    # -- the ladder ---------------------------------------------------------- #

    @staticmethod
    def _check_move(record: RetentionRecord, target: RetentionState) -> None:
        """Refuse a move the ladder or a legal hold does not permit.

        Raises:
            RetentionRefusedError: If the move is not permitted from the current state,
                or a legal hold blocks it.
        """
        if target not in ALLOWED_TRANSITIONS[record.state]:
            allowed = ", ".join(state.value for state in ALLOWED_TRANSITIONS[record.state])
            raise RetentionRefusedError(
                f"manifest {record.manifest_id!r} in state {record.state.value!r} cannot move "
                f"to {target.value!r} (allowed: {allowed or 'none'})"
            )
        if record.legal_hold:
            raise RetentionRefusedError(
                f"manifest {record.manifest_id!r} is under legal hold "
                f"({record.hold_reason or 'no reason recorded'}); release the hold first"
            )

    def _move(
        self, manifest_id: str, target: RetentionState, *, now: datetime | None
    ) -> RetentionRecord:
        """Move a record one rung, refusing anything not on the ladder."""
        record = self.get(manifest_id)
        self._check_move(record, target)
        return self._retention.save_record(
            RetentionRecord(
                manifest_id=record.manifest_id,
                run_id=record.run_id,
                retention_class=record.retention_class,
                state=target,
                legal_hold=record.legal_hold,
                hold_reason=record.hold_reason,
                expires_at=record.expires_at,
                manifest_digest=record.manifest_digest,
                policy_version=record.policy_version,
                created_at=record.created_at,
                updated_at=self._moment(now).isoformat(),
            )
        )

    def cool(self, manifest_id: str, *, now: datetime | None = None) -> RetentionRecord:
        """Hot → cold. Local only; no external store is touched."""
        return self._move(manifest_id, RetentionState.COLD, now=now)

    def archive(self, manifest_id: str, *, now: datetime | None = None) -> RetentionRecord:
        """Cold → archive, writing the sealed manifest to external storage first.

        The external copy is written *before* the state moves, so an interruption
        between the two leaves a record still marked cold: recoverable, and never
        one claiming an archive that does not exist.

        Raises:
            RetentionBackendUnavailableError: If no backend is configured, or the
                backend raises. The record is untouched either way.
            RetentionRefusedError: If the manifest is not stored, or the move is illegal.
        """
        manifest = self._manifest(manifest_id)
        # Policy first: a record that may not move should be told *why* without
        # first hearing that a dependency happens to be missing.
        self._check_move(self.get(manifest_id), RetentionState.ARCHIVE)
        backend = _require_backend(self._backend, "archiving retained evidence")
        key = backend_key(manifest)
        try:
            backend.put(key, manifest.model_dump_json().encode("utf-8"))
        except Exception as exc:
            raise RetentionBackendUnavailableError(
                f"backend {getattr(backend, 'name', backend)!r} failed to store {key!r}: {exc}"
            ) from exc
        moved = self._move(manifest_id, RetentionState.ARCHIVE, now=now)
        self._record(
            action=KIND_EVIDENCE_ARCHIVED,
            target=manifest_id,
            run_id=moved.run_id,
            detail={
                "backend": str(getattr(backend, "name", type(backend).__name__)),
                "key": key,
                "manifest_digest": moved.manifest_digest,
            },
        )
        return moved

    # -- legal hold ---------------------------------------------------------- #

    def place_legal_hold(
        self, manifest_id: str, *, reason: str, now: datetime | None = None
    ) -> RetentionRecord:
        """Put a hold on a record. A hold blocks every move and every expiry.

        Raises:
            RetentionRefusedError: If the record is already deleted or already held, or
                the hold carries no reason.
        """
        if not reason.strip():
            raise RetentionRefusedError(
                f"a legal hold on manifest {manifest_id!r} needs a recorded reason"
            )
        record = self.get(manifest_id)
        if record.state is RetentionState.DELETED:
            raise RetentionRefusedError(
                f"manifest {manifest_id!r} is deleted; a hold cannot be placed after the fact"
            )
        if record.legal_hold:
            raise RetentionRefusedError(
                f"manifest {manifest_id!r} is already held ({record.hold_reason})"
            )
        moved = self._retention.save_record(
            RetentionRecord(
                manifest_id=record.manifest_id,
                run_id=record.run_id,
                retention_class=record.retention_class,
                state=record.state,
                legal_hold=True,
                hold_reason=reason,
                expires_at=record.expires_at,
                manifest_digest=record.manifest_digest,
                policy_version=record.policy_version,
                created_at=record.created_at,
                updated_at=self._moment(now).isoformat(),
            )
        )
        self._record(
            action=KIND_LEGAL_HOLD_PLACED,
            target=record.manifest_id,
            run_id=record.run_id,
            detail={"reason": reason},
        )
        return moved

    def release_legal_hold(
        self,
        manifest_id: str,
        *,
        actor: str,
        reason: str,
        now: datetime | None = None,
    ) -> RetentionRecord:
        """Lift a hold. The release is recorded, because the next deletion relies on it.

        Raises:
            RetentionRefusedError: If no hold is recorded, or the release names no actor.
        """
        if not actor.strip():
            raise RetentionRefusedError(
                f"releasing the legal hold on manifest {manifest_id!r} needs a named actor"
            )
        record = self.get(manifest_id)
        if not record.legal_hold:
            raise RetentionRefusedError(f"manifest {manifest_id!r} is not under legal hold")
        moved = self._retention.save_record(
            RetentionRecord(
                manifest_id=record.manifest_id,
                run_id=record.run_id,
                retention_class=record.retention_class,
                state=record.state,
                legal_hold=False,
                hold_reason=f"released by {actor}: {reason or 'no reason given'}",
                expires_at=record.expires_at,
                manifest_digest=record.manifest_digest,
                policy_version=record.policy_version,
                created_at=record.created_at,
                updated_at=self._moment(now).isoformat(),
            )
        )
        self._record(
            action=KIND_LEGAL_HOLD_RELEASED,
            target=record.manifest_id,
            run_id=record.run_id,
            detail={"actor": actor, "reason": reason},
        )
        return moved

    # -- deletion ------------------------------------------------------------ #

    def expire(
        self,
        manifest_id: str,
        *,
        requester: str,
        approver: str,
        reason: str = "",
        now: datetime | None = None,
    ) -> RetentionTombstone:
        """Delete an expired record, with dual control, leaving a tombstone.

        The order of the checks is the order of the objections: who asked, then
        whether policy allows it, then whether the external store can be trusted.
        Nothing is written until all three pass.

        Args:
            manifest_id: The manifest whose evidence is being deleted.
            requester: The person requesting deletion.
            approver: A *different* named person approving it.
            reason: Recorded on the tombstone; blank is allowed but recorded blank.
            now: The instant to evaluate expiry against.

        Returns:
            The tombstone, naming both approvers and the deleted manifest digest.

        Raises:
            RetentionRefusedError: If dual control is absent, or policy blocks the
                deletion (held, not expired, not archived, already deleted).
            RetentionBackendUnavailableError: If the external copy is missing or
                the backend raises. The local record survives: an unavailable store
                never authorises deleting the last copy.
        """
        requester, approver = _require_dual_control(requester, approver, manifest_id)
        record = self.get(manifest_id)
        assessment = self.assess(manifest_id, now=now)
        if not assessment.deletable:
            raise RetentionRefusedError(
                f"deleting evidence for manifest {manifest_id!r} refused: {assessment.blocked_by}"
            )
        backend = _require_backend(self._backend, "deleting retained evidence")
        manifest = self._manifest(manifest_id)
        key = backend_key(manifest)
        if not backend.contains(key):
            raise RetentionBackendUnavailableError(
                f"no external object at {key!r}; the evidence is not archived anywhere "
                "else, so deleting it would destroy the only copy (gap 101)"
            )
        try:
            backend.delete(key)
        except Exception as exc:
            raise RetentionBackendUnavailableError(
                f"backend {getattr(backend, 'name', backend)!r} refused to delete {key!r}: "
                f"{exc}; an object store under a retention lock is expected to refuse, "
                "and the local record is kept"
            ) from exc
        tombstone = RetentionTombstone(
            tombstone_id=f"tombstone:{manifest_id}",
            manifest_id=record.manifest_id,
            run_id=record.run_id,
            manifest_digest=record.manifest_digest,
            retention_class=record.retention_class,
            requester=requester,
            approver=approver,
            reason=reason,
            backend=str(getattr(backend, "name", type(backend).__name__)),
            deleted_at=self._moment(now).isoformat(),
        )
        saved = self._retention.save_deletion(record, tombstone)
        # Phase 4: the tombstone attestation. Written *after* the deletion commits
        # and into a table the deletion does not touch, so the record of the
        # deletion is not part of what the deletion removes. `requester` is the
        # principal because they asked for it; `approver` is in the payload,
        # because dual control is the whole point and an entry naming only the
        # requester would under-record it.
        self._audit.record_evidence_deleted(
            principal=requester,
            manifest_id=record.manifest_id,
            run_id=record.run_id,
            approver=approver,
            detail={
                "tombstone_id": saved.tombstone_id,
                "manifest_digest": saved.manifest_digest,
                "retention_class": saved.retention_class.value,
                "reason": reason,
                "backend": saved.backend,
                "deleted_at": saved.deleted_at,
            },
        )
        return saved
