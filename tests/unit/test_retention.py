"""Plan 12 Phase 2: the retention engine — expiry, archive, dual-control delete.

Every deletion path here has a negative control beside it, because the failure
mode that matters is not "delete failed to work" — it is "evidence was deleted
without two people agreeing, without an external copy, or while it was under a
legal hold". Those three are asserted explicitly, plus the fail-closed behaviour
when no backend exists (the Phase 2 default, since no WORM/object-lock store
ships yet).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from mayhem.domain.attestation import AttestedTimestamp, RetentionClass
from mayhem.domain.evidence import EvidenceEnvelope
from mayhem.infra.attestation_store import seal_run_evidence
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.retention import (
    RETENTION_TTL_SECONDS,
    RetentionBackendUnavailableError,
    RetentionEngine,
    RetentionRefusedError,
    RetentionRepository,
    RetentionState,
    backend_key,
)
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

T0 = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)
READING = AttestedTimestamp(wall_clock=T0, monotonic_ns=1_000_000, source="system")

#: Comfortably past the ephemeral window, comfortably before anything else moves.
EXPIRED_AT = T0 + timedelta(days=RETENTION_TTL_SECONDS[RetentionClass.EPHEMERAL] + 1)  # type: ignore[operator]


def open_store(tmp_path: Path) -> Store:
    return Store.open_migrated(tmp_path / "mayhem.db", migrations=ALL_MIGRATIONS)


def engine_with(store: Store, *, backend: object = None) -> RetentionEngine:
    return RetentionEngine(store, backend=backend)  # type: ignore[arg-type]


def sealed_manifest(store: Store, run_id: str, retention_class: RetentionClass):
    """Seal a run at T0 and return (SealedRun, RetentionEngine) holding its record."""
    envelope = EvidenceEnvelope.model_validate(
        {
            "run_id": run_id,
            "plan_hash": "plan-hash-1",
            "verdict": "pass",
            "step_reports": ({"step_id": "s1", "status": "completed"},),
            "created_at": T0.isoformat(),
            "redaction_metrics": {"policy_version": "redaction-v9", "redacted_path_count": 0},
        }
    )
    sealed = seal_run_evidence(
        store,
        envelope,
        run_status="completed",
        verdict="pass",
        retention_class=retention_class,
        manifest_id=f"{run_id}:manifest",
        recorded_at=READING,
        created_at=READING,
    )
    engine = RetentionEngine(store)
    engine.register(sealed.manifest, now=T0)
    return sealed, engine


def archived_engine(tmp_path: Path, retention_class: RetentionClass = RetentionClass.EPHEMERAL):
    """A store whose record is cold→archive in an in-memory backend, ready to delete."""
    from mayhem.infra.retention import InMemoryRetentionBackend

    store = open_store(tmp_path)
    backend = InMemoryRetentionBackend()
    sealed, engine = sealed_manifest(store, "run-1", retention_class)
    engine = RetentionEngine(store, backend=backend)
    engine.cool("run-1:manifest", now=T0)
    engine.archive("run-1:manifest", now=T0)
    return store, engine, backend, sealed


# --------------------------------------------------------------------------- #
# Registration and the ladder                                                  #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("retention_class", list(RetentionClass))
def test_register_derives_expiry_from_the_class(
    tmp_path: Path, retention_class: RetentionClass
) -> None:
    store = open_store(tmp_path)

    _sealed, engine = sealed_manifest(store, "run-1", retention_class)
    record = engine.get("run-1:manifest")

    assert record.retention_class is retention_class
    assert record.state is RetentionState.HOT
    assert record.policy_version
    seconds = RETENTION_TTL_SECONDS[retention_class]
    if seconds is None:
        assert record.expires_at is None
        assert not record.is_expired(T0 + timedelta(days=3650))
    else:
        assert record.expires_at == T0 + timedelta(seconds=seconds)
        assert not record.is_expired(T0)
        assert record.is_expired(T0 + timedelta(seconds=seconds))
    store.close()


def test_legal_hold_class_registers_already_held(tmp_path: Path) -> None:
    store = open_store(tmp_path)

    _sealed, engine = sealed_manifest(store, "run-1", RetentionClass.LEGAL_HOLD)
    record = engine.get("run-1:manifest")

    assert record.legal_hold
    assert record.hold_reason == "retention class legal_hold"
    assert record.expires_at is None
    store.close()


def test_register_refuses_a_manifest_that_covers_nothing(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    _sealed, engine = sealed_manifest(store, "run-1", RetentionClass.HOT)
    empty = _sealed.manifest.model_copy(
        update={"event_ids": (), "event_roots": (), "manifest_digest": ""}
    ).seal()

    with pytest.raises(RetentionRefusedError, match="covers no events"):
        engine.register(empty, now=T0)

    store.close()


def test_get_refuses_an_unregistered_manifest(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    engine = engine_with(store)

    with pytest.raises(RetentionRefusedError, match="no retention record"):
        engine.get("never-sealed")


def test_ladder_moves_one_rung_at_a_time_and_never_backwards(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    _sealed, engine = sealed_manifest(store, "run-1", RetentionClass.HOT)

    with pytest.raises(RetentionRefusedError, match="cannot move to 'archive'"):
        engine.archive("run-1:manifest", now=T0)

    assert engine.cool("run-1:manifest", now=T0).state is RetentionState.COLD
    with pytest.raises(RetentionRefusedError, match="cannot move to 'cold'"):
        engine.cool("run-1:manifest", now=T0)
    store.close()


# --------------------------------------------------------------------------- #
# The storage seam, failing closed                                             #
# --------------------------------------------------------------------------- #


def test_archive_without_a_backend_fails_closed(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    _sealed, engine = sealed_manifest(store, "run-1", RetentionClass.HOT)
    engine.cool("run-1:manifest", now=T0)

    with pytest.raises(RetentionBackendUnavailableError, match="fails closed"):
        engine.archive("run-1:manifest", now=T0)

    assert engine.get("run-1:manifest").state is RetentionState.COLD
    store.close()


def test_archive_writes_the_external_copy_before_moving_state(tmp_path: Path) -> None:
    store, engine, backend, sealed = archived_engine(tmp_path)
    key = backend_key(sealed.manifest)

    assert backend.contains(key)
    assert backend._objects[key] == sealed.manifest.model_dump_json().encode("utf-8")
    assert engine.get("run-1:manifest").state is RetentionState.ARCHIVE
    store.close()


def test_a_backend_that_raises_leaves_the_record_untouched(tmp_path: Path) -> None:
    class BrokenBackend:
        name = "broken"

        def put(self, key: str, payload: bytes) -> None:
            raise OSError("object store unreachable")

        def contains(self, key: str) -> bool:
            return False

        def delete(self, key: str) -> None:
            raise OSError("object store unreachable")

    store = open_store(tmp_path)
    _sealed, engine = sealed_manifest(store, "run-1", RetentionClass.HOT)
    engine = RetentionEngine(store, backend=BrokenBackend())
    engine.cool("run-1:manifest", now=T0)

    with pytest.raises(RetentionBackendUnavailableError, match="unreachable"):
        engine.archive("run-1:manifest", now=T0)

    assert engine.get("run-1:manifest").state is RetentionState.COLD
    store.close()


# --------------------------------------------------------------------------- #
# Expiry                                                                       #
# --------------------------------------------------------------------------- #


def test_due_lists_expired_records_and_hides_held_ones(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    _a, engine = sealed_manifest(store, "run-1", RetentionClass.EPHEMERAL)
    sealed_manifest(store, "run-2", RetentionClass.EPHEMERAL)
    sealed_manifest(store, "run-3", RetentionClass.LEGAL_HOLD)

    assert [record.manifest_id for record in engine.due(now=EXPIRED_AT)] == [
        "run-1:manifest",
        "run-2:manifest",
    ]
    assert [record.manifest_id for record in engine.due(now=T0)] == []
    store.close()


def test_assess_answers_without_raising_and_names_the_obstacle(tmp_path: Path) -> None:
    store = open_store(tmp_path)
    _sealed, engine = sealed_manifest(store, "run-1", RetentionClass.EPHEMERAL)

    early = engine.assess("run-1:manifest", now=T0)
    assert not early.deletable
    assert not early.expired
    assert "not expired until" in early.blocked_by

    engine.cool("run-1:manifest", now=T0)
    unarchived = engine.assess("run-1:manifest", now=EXPIRED_AT)
    assert unarchived.expired
    assert not unarchived.deletable
    assert "no external copy" in unarchived.blocked_by
    store.close()


def test_unexpired_evidence_cannot_be_deleted(tmp_path: Path) -> None:
    store, engine, _backend, _sealed = archived_engine(tmp_path)

    with pytest.raises(RetentionRefusedError, match="not expired until"):
        engine.expire("run-1:manifest", requester="ana", approver="bo", now=T0, reason="tidy up")

    assert engine.get("run-1:manifest").state is RetentionState.ARCHIVE
    assert RetentionRepository(store).load_tombstone("run-1:manifest") is None
    store.close()


# --------------------------------------------------------------------------- #
# Legal hold                                                                   #
# --------------------------------------------------------------------------- #


def test_expired_but_held_evidence_survives(tmp_path: Path) -> None:
    store, engine, _backend, _sealed = archived_engine(tmp_path, RetentionClass.EPHEMERAL)
    engine.place_legal_hold("run-1:manifest", reason="incident 4471", now=T0)

    with pytest.raises(RetentionRefusedError, match="under legal hold"):
        engine.expire("run-1:manifest", requester="ana", approver="bo", now=EXPIRED_AT)

    assert engine.get("run-1:manifest").state is RetentionState.ARCHIVE
    assert not engine.get("run-1:manifest").is_expired(EXPIRED_AT)
    store.close()


def test_a_hold_needs_a_reason_and_blocks_further_holds(tmp_path: Path) -> None:
    store, engine, _backend, _sealed = archived_engine(tmp_path)

    with pytest.raises(RetentionRefusedError, match="recorded reason"):
        engine.place_legal_hold("run-1:manifest", reason="  ", now=T0)
    engine.place_legal_hold("run-1:manifest", reason="incident 4471", now=T0)
    with pytest.raises(RetentionRefusedError, match="already held"):
        engine.place_legal_hold("run-1:manifest", reason="second opinion", now=T0)
    with pytest.raises(RetentionRefusedError, match="named actor"):
        engine.release_legal_hold("run-1:manifest", actor="", reason="cleared", now=T0)
    store.close()


def test_released_then_deleted(tmp_path: Path) -> None:
    """The Phase 5 sequence: held-then-released deletes with a tombstone."""
    store, engine, _backend, _sealed = archived_engine(tmp_path, RetentionClass.EPHEMERAL)
    engine.place_legal_hold("run-1:manifest", reason="incident 4471", now=T0)
    engine.release_legal_hold("run-1:manifest", actor="casey", reason="case closed", now=T0)

    tombstone = engine.expire(
        "run-1:manifest", requester="ana", approver="bo", reason="lapsed", now=EXPIRED_AT
    )

    assert tombstone.requester == "ana"
    assert tombstone.approver == "bo"
    assert tombstone.reason == "lapsed"
    assert engine.get("run-1:manifest").state is RetentionState.DELETED
    store.close()


# --------------------------------------------------------------------------- #
# Dual control and the tombstone                                               #
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("requester", "approver", "message"),
    [
        ("ana", "", "needs dual control"),
        ("", "bo", "needs dual control"),
        ("ana", "ana", "self-approval is refused"),
        ("ana", "ana  ", "self-approval is refused"),
    ],
)
def test_expired_delete_without_real_dual_control_is_refused(
    tmp_path: Path, requester: str, approver: str, message: str
) -> None:
    store, engine, _backend, _sealed = archived_engine(tmp_path)

    with pytest.raises(RetentionRefusedError, match=message):
        engine.expire("run-1:manifest", requester=requester, approver=approver, now=EXPIRED_AT)

    assert engine.get("run-1:manifest").state is RetentionState.ARCHIVE
    assert RetentionRepository(store).list_tombstones() == ()
    store.close()


def test_dual_control_delete_leaves_a_tombstone_that_survives_reload(tmp_path: Path) -> None:
    store, engine, backend, sealed = archived_engine(tmp_path)
    key = backend_key(sealed.manifest)

    tombstone = engine.expire(
        "run-1:manifest",
        requester="ana",
        approver="bo",
        reason="lapsed after 7 days",
        now=EXPIRED_AT,
    )

    assert not backend.contains(key)
    assert tombstone.manifest_digest == sealed.manifest.manifest_digest
    assert tombstone.backend == "in-memory"
    assert tombstone.dual_control_satisfied
    store.close()

    reopened = Store(tmp_path / "mayhem.db")
    repository = RetentionRepository(reopened)
    reloaded = repository.load_tombstone("run-1:manifest")

    assert reloaded is not None
    assert reloaded.to_dict() == tombstone.to_dict()
    assert reloaded.requester != reloaded.approver
    assert repository.list_tombstones() == (tombstone,)
    assert repository.load_record("run-1:manifest").state is RetentionState.DELETED
    reopened.close()


def test_a_manifest_is_only_deleted_once(tmp_path: Path) -> None:
    store, engine, _backend, _sealed = archived_engine(tmp_path)
    engine.expire("run-1:manifest", requester="ana", approver="bo", now=EXPIRED_AT)

    with pytest.raises(RetentionRefusedError, match="already deleted"):
        engine.expire("run-1:manifest", requester="ana", approver="bo", now=EXPIRED_AT)

    assert len(RetentionRepository(store).list_tombstones()) == 1
    store.close()


def test_delete_without_a_backend_fails_closed(tmp_path: Path) -> None:
    """A backend that vanished between archive and delete must not authorise deletion."""
    store, backend_engine, backend, _sealed = archived_engine(tmp_path)
    engine = RetentionEngine(store, backend=None)

    with pytest.raises(RetentionBackendUnavailableError, match="fails closed"):
        engine.expire("run-1:manifest", requester="ana", approver="bo", now=EXPIRED_AT)

    assert backend.contains(backend_key(_sealed.manifest))
    assert backend_engine.get("run-1:manifest").state is RetentionState.ARCHIVE
    assert RetentionRepository(store).list_tombstones() == ()
    store.close()


def test_a_backend_under_a_lock_refuses_deletion_and_keeps_the_local_record(
    tmp_path: Path,
) -> None:
    class LockedBackend:
        """What a WORM store does while its own retention lock is in force."""

        name = "locked"

        def __init__(self) -> None:
            self.objects: dict[str, bytes] = {}

        def put(self, key: str, payload: bytes) -> None:
            self.objects[key] = payload

        def contains(self, key: str) -> bool:
            return key in self.objects

        def delete(self, key: str) -> None:
            raise PermissionError("object lock in governance mode")

    backend = LockedBackend()
    store = open_store(tmp_path)
    sealed_manifest(store, "run-1", RetentionClass.EPHEMERAL)
    engine = RetentionEngine(store, backend=backend)
    engine.cool("run-1:manifest", now=T0)
    engine.archive("run-1:manifest", now=T0)

    with pytest.raises(RetentionBackendUnavailableError, match="object lock"):
        engine.expire("run-1:manifest", requester="ana", approver="bo", now=EXPIRED_AT)

    assert backend.objects
    assert engine.get("run-1:manifest").state is RetentionState.ARCHIVE
    assert RetentionRepository(store).list_tombstones() == ()
    store.close()


def test_delete_refuses_when_the_external_copy_is_missing(tmp_path: Path) -> None:
    """A lost archive is not permission to delete the last remaining copy."""
    store, engine, backend, sealed = archived_engine(tmp_path)
    backend._objects.clear()

    with pytest.raises(RetentionBackendUnavailableError, match="destroy the only copy"):
        engine.expire("run-1:manifest", requester="ana", approver="bo", now=EXPIRED_AT)

    assert backend.contains(backend_key(sealed.manifest)) is False
    assert engine.get("run-1:manifest").state is RetentionState.ARCHIVE
    store.close()


def test_archive_refuses_a_manifest_that_is_not_stored(tmp_path: Path) -> None:
    from mayhem.infra.retention import InMemoryRetentionBackend

    store = open_store(tmp_path)
    _sealed, engine = sealed_manifest(store, "run-1", RetentionClass.HOT)
    engine = RetentionEngine(store, backend=InMemoryRetentionBackend())
    engine.cool("run-1:manifest", now=T0)
    with store.write() as conn:
        conn.execute("DELETE FROM attestation_manifests WHERE manifest_id = 'run-1:manifest'")

    with pytest.raises(RetentionRefusedError, match="no sealed bytes to archive"):
        engine.archive("run-1:manifest", now=T0)

    assert engine.get("run-1:manifest").state is RetentionState.COLD
    store.close()
