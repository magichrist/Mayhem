"""Tests for the backup engine, restore drills, and RPO/RTO reporting (plan 19 Phase 2).

The phase's acceptance is restore drills that **prove** RPO/RTO "rather than
asserting them". Phase 1 made asserting structurally impossible; this file proves
the engine does not route around it:

* a drill really restores into an **isolated** cell (a fresh directory, a fresh
  store) and really compares what came back against what was recorded at capture;
* a drill that does not verify is ``FAILED``/``INCOMPLETE``, and
  :meth:`~mayhem.domain.backup.RestoreVerification.claim_success` **raises** — there
  is no way to report it as successful;
* a stated RPO with no verified drill reads ``not demonstrated``, never zero and
  never the target;
* an **unavailable** object store fails closed: no descriptor claiming a replica is
  written, and the drill raises rather than inventing a verification;
* the ``MTLS_HANDSHAKE`` check fails closed because **no CA-backed X.509 mTLS
  implementation ships in this phase** — asserted, so the gap cannot quietly become
  a pass.

Real IO: an on-disk SQLite source (the stdlib's ``sqlite3.Connection.backup`` is the
capture), an in-memory object store double, and the migrated store. Every clock is
injected.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from mayhem.domain.agent_identity import (
    AgentCredential,
    AgentIdentity,
    Revocation,
    RevocationReason,
)
from mayhem.domain.backup import (
    RecoveryObjective,
    RestoreCheckKind,
    RestoreOutcome,
    RestoreVerification,
    SnapshotKind,
    UnverifiedRestoreError,
)
from mayhem.domain.identity import EnvironmentScope, Principal, PrincipalKind
from mayhem.infra.agent_identity_store import AgentIdentityRepository, BackupRepository
from mayhem.infra.backup_engine import (
    BackupEngine,
    BackupError,
    BackupUnavailableError,
    InMemoryObjectStore,
    SnapshotEvidence,
    SnapshotSchedule,
    SqliteSnapshotSource,
    UnavailableObjectStore,
    observed_row_counts,
)
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Iterator

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
DATASTORE = "mayhem-sqlite"
AGENT_TABLE = "agent_identities"
LOSS_BUDGET_S = 60.0
RPO_TARGET_S = 300.0
RTO_TARGET_S = 900.0


class Clock:
    """A hand-advanced clock. Durations are therefore exact, not approximate.

    ``tick_s`` optionally advances on every read, which is how a drill acquires a
    non-zero duration: :meth:`BackupEngine.run_drill` reads the clock twice
    (``started_at`` then ``completed_at``), so a frozen clock would measure an RTO of
    exactly zero and make the RTO side of the report untestable.
    """

    def __init__(self, start: datetime = NOW, *, tick_s: float = 0.0) -> None:
        self.now = start
        self.tick_s = tick_s

    def __call__(self) -> datetime:
        current = self.now
        if self.tick_s:
            self.now = self.now + timedelta(seconds=self.tick_s)
        return current

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store() -> Iterator[Store]:
    opened = Store.open_migrated(":memory:")
    yield opened
    opened.close()


def identity(agent_id: str = "ag-1") -> AgentIdentity:
    return AgentIdentity(
        agent_id=agent_id,
        controller_id="ctl-a",
        principal=Principal(principal_id=f"sa-{agent_id}", kind=PrincipalKind.WORKLOAD),
        scope=EnvironmentScope(environment="staging"),
        credential=AgentCredential(
            credential_id=f"cr-{agent_id}",
            agent_id=agent_id,
            issued_at=NOW - timedelta(seconds=60),
            expires_at=NOW + timedelta(seconds=900),
        ),
    )


@pytest.fixture
def source_path(tmp_path: Path) -> Iterator[Path]:
    """A real on-disk SQLite database with rows worth losing."""
    path = tmp_path / "source.db"
    controller_store = Store.open_migrated(path)
    identities = AgentIdentityRepository(controller_store)
    for index in range(3):
        identities.save(identity(f"ag-{index}"))
    identities.revoke_credential(
        "ag-1", Revocation(reason=RevocationReason.COMPROMISED, revoked_at=NOW, revoked_by="ctl-a")
    )
    controller_store.close()
    yield path


@pytest.fixture
def object_store() -> InMemoryObjectStore:
    return InMemoryObjectStore()


def check_detail(verification: RestoreVerification, kind: RestoreCheckKind) -> str:
    """The recorded observation for one check kind.

    A helper rather than ``verification.outcome_for(...)`` because
    :class:`~mayhem.domain.backup.RestoreVerification` is not this lane's file and
    has no such method: the drill's observations are read out of its ``results``
    tuple, exactly as any other consumer would.
    """
    for result in verification.results:
        if result.kind is kind:
            return result.detail
    msg = f"no {kind.value} observation was recorded"
    raise AssertionError(msg)


def engine(
    store: Store,
    source_path: Path,
    object_store: object,
    clock: Clock,
    **kwargs: object,
) -> BackupEngine:
    return BackupEngine(
        store=store,
        object_store=object_store,  # type: ignore[arg-type]
        source=SqliteSnapshotSource(source_path, observed_tables=(AGENT_TABLE,)),
        clock=clock,
        **kwargs,  # type: ignore[arg-type]
    )


def take_full(store: Store, source_path: Path, object_store: object, clock: Clock) -> object:
    return engine(store, source_path, object_store, clock).snapshot_now(
        snapshot_id="snap-1", datastore=DATASTORE, kind=SnapshotKind.FULL
    )


# --------------------------------------------------------------------------- #
# Capture                                                                       #
# --------------------------------------------------------------------------- #


def test_snapshot_is_captured_replicated_and_recorded(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    backup = take_full(store, source_path, object_store, clock)

    assert backup.snapshot_id == "snap-1"
    assert backup.kind is SnapshotKind.FULL
    assert backup.byte_size > 0
    assert backup.is_replicated
    assert len(backup.replica_locators) == 1
    # The replica locator is the store's own answer, not a string we invented.
    assert backup.replica_locators[0].startswith("mem://")
    assert BackupRepository(store).load_snapshot("snap-1") is not None


def test_capture_evidence_records_what_was_observed(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """Row counts and the covered position are recorded so a drill has something to compare."""
    take_full(store, source_path, object_store, clock)

    evidence = engine(store, source_path, object_store, clock).evidence.load("snap-1")
    assert evidence is not None
    assert evidence.row_counts == {AGENT_TABLE: 3}
    assert evidence.covers_through == NOW
    assert observed_row_counts(source_path, (AGENT_TABLE,)) == {AGENT_TABLE: 3}


def test_the_capture_really_is_a_restorable_sqlite_file(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """Not a JSON envelope of a database — an actual SQLite file, via the stdlib backup API."""
    backup = take_full(store, source_path, object_store, clock)
    # The descriptor's replica locator is exactly the store's own locator for the key.
    (key,) = object_store.objects
    assert backup.replica_locators[0].endswith(key)
    payload = object_store.fetch(key)

    scratch = source_path.parent / "reopened.db"
    scratch.write_bytes(payload)
    reopened = sqlite3.connect(scratch)
    try:
        assert reopened.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert int(reopened.execute(f"SELECT COUNT(*) FROM {AGENT_TABLE}").fetchone()[0]) == 3
    finally:
        reopened.close()


def test_wal_archive_records_a_real_log_position(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """The WAL archive reads its position out of SQLite, not out of a counter we invented."""
    backup = engine(store, source_path, object_store, clock).snapshot_now(
        snapshot_id="snap-wal-1", datastore=DATASTORE, kind=SnapshotKind.WAL_ARCHIVE
    )

    assert backup.kind is SnapshotKind.WAL_ARCHIVE
    assert backup.wal_sequence is not None
    assert backup.wal_sequence >= 0


def test_a_failed_replication_writes_no_descriptor(
    store: Store, source_path: Path, clock: Clock
) -> None:
    """NEGATIVE CONTROL: an unavailable object store fails closed.

    No row in ``backup_snapshots`` may claim a replica that does not exist, because
    a descriptor that names a copy nobody wrote is how a backup programme comes to
    believe it is replicating when it is not.
    """
    with pytest.raises(BackupUnavailableError):
        take_full(store, source_path, UnavailableObjectStore(), clock)

    assert BackupRepository(store).list_snapshots() == ()


def test_a_store_that_returns_different_bytes_is_refused(
    store: Store, source_path: Path, clock: Clock
) -> None:
    """NEGATIVE CONTROL: a silent-corruption backend fails closed too."""

    class CorruptingStore(InMemoryObjectStore):
        name = "corrupting"

        def fetch(self, key: str) -> bytes:
            return super().fetch(key) + b"tamper"

    with pytest.raises(BackupUnavailableError, match="different bytes"):
        take_full(store, source_path, CorruptingStore(), clock)

    assert BackupRepository(store).list_snapshots() == ()


def test_evidence_replication_is_a_first_class_snapshot(
    store: Store, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """Plan 12's evidence replication arrives as a snapshot kind, not as a database tag."""
    backup = engine(
        store, Path("unused.db"), object_store, clock
    ).replicate_evidence(
        snapshot_id="snap-ev-1", payload=b'{"attested":true}', covers_through=NOW
    )

    assert backup.kind is SnapshotKind.EVIDENCE
    assert backup.datastore == "evidence-store"
    assert backup.is_replicated


# --------------------------------------------------------------------------- #
# Scheduling                                                                   #
# --------------------------------------------------------------------------- #


def test_a_schedule_with_no_prior_capture_is_due(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """A fresh install has no backup, and that is due — not "not yet"."""
    schedule = SnapshotSchedule(schedule_id="sched-1", datastore=DATASTORE)

    taken = engine(store, source_path, object_store, clock).run_schedules((schedule,))

    assert len(taken) == 1


def test_a_schedule_is_not_due_before_its_interval_elapses(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    schedule = SnapshotSchedule(
        schedule_id="sched-1", datastore=DATASTORE, interval_s=3600.0
    )
    backup = engine(store, source_path, object_store, clock)

    assert len(backup.run_schedules((schedule,))) == 1
    assert backup.run_schedules((schedule,)) == ()  # same instant
    clock.advance(3599.0)
    assert backup.run_schedules((schedule,)) == ()
    clock.advance(2.0)
    assert len(backup.run_schedules((schedule,))) == 1


def test_a_disabled_schedule_is_skipped(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    schedule = SnapshotSchedule(schedule_id="sched-1", datastore=DATASTORE, enabled=False)

    assert engine(store, source_path, object_store, clock).run_schedules((schedule,)) == ()


def test_a_non_positive_interval_is_refused() -> None:
    with pytest.raises(Exception, match="interval"):
        SnapshotSchedule(schedule_id="sched-1", datastore=DATASTORE, interval_s=0.0)


# --------------------------------------------------------------------------- #
# Restore drills: restore into an isolated cell and verify                      #
# --------------------------------------------------------------------------- #


def test_a_drill_restores_into_an_isolated_cell_and_verifies(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """The happy path, and it is a real restore: bytes fetched, file written, rows read."""
    backup = take_full(store, source_path, object_store, clock)
    backup_engine = engine(store, source_path, object_store, clock)
    plan = backup_engine.default_restore_plan(
        restore_id="restore-1",
        snapshot=backup,  # type: ignore[arg-type]
        target_cell="cell-drill-1",
        max_acceptable_data_loss_seconds=LOSS_BUDGET_S,
        expected_rto_seconds=RTO_TARGET_S,
    )

    clock.advance(30.0)  # the drill happens 30s after the capture
    result = backup_engine.run_drill(plan)

    assert result.verified
    assert result.outcome == RestoreOutcome.VERIFIED.value
    assert result.isolated_dir.exists()
    assert result.isolated_dir != source_path.parent  # a genuinely separate cell
    assert (result.isolated_dir / "restored.db").exists()
    assert observed_row_counts(result.isolated_dir / "restored.db", (AGENT_TABLE,)) == {
        AGENT_TABLE: 3
    }
    assert result.verification.data_loss_seconds == pytest.approx(30.0)
    assert len(result.verification.results) == len(plan.required_checks)
    assert BackupRepository(store).load_restore("restore-1").verified is True


def test_the_live_store_is_never_restored_over(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """The drill's writes land in the isolated cell, not in the control plane's store."""
    take_full(store, source_path, object_store, clock)
    backup_engine = engine(store, source_path, object_store, clock)
    plan = backup_engine.default_restore_plan(
        restore_id="restore-1",
        snapshot=backup_engine.backups.load_snapshot("snap-1"),  # type: ignore[arg-type]
        target_cell="cell-drill-1",
        max_acceptable_data_loss_seconds=LOSS_BUDGET_S,
        expected_rto_seconds=RTO_TARGET_S,
    )
    before = {str(row["name"]) for row in store.query("SELECT name FROM sqlite_master")}

    result = backup_engine.run_drill(plan)

    after = {str(row["name"]) for row in store.query("SELECT name FROM sqlite_master")}
    assert after == before
    assert str(result.isolated_dir) != str(store._path)


def test_the_isolated_cell_can_be_discarded(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    backup = take_full(store, source_path, object_store, clock)
    backup_engine = engine(store, source_path, object_store, clock)
    plan = backup_engine.default_restore_plan(
        restore_id="restore-1",
        snapshot=backup,  # type: ignore[arg-type]
        target_cell="cell-drill-1",
        max_acceptable_data_loss_seconds=LOSS_BUDGET_S,
        expected_rto_seconds=RTO_TARGET_S,
    )

    result = backup_engine.run_drill(plan, retain_isolated=False)

    assert result.retained is False
    assert not result.isolated_dir.exists()
    # Discarding the evidence does not change the verdict; it is already recorded.
    assert result.verified


# --------------------------------------------------------------------------- #
# NEGATIVE CONTROL: a drill that does not verify is not a success               #
# --------------------------------------------------------------------------- #


def test_a_drill_against_tampered_bytes_fails_and_cannot_be_claimed_successful(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """NEGATIVE CONTROL: "the restore did not verify" is not reportable as success.

    The bytes in the object store are altered after the descriptor was written, so
    the drill refuses at the fetch: it cannot even produce a verdict, which is
    stronger than producing a failing one.
    """
    backup = take_full(store, source_path, object_store, clock)
    backup_engine = engine(store, source_path, object_store, clock)
    plan = backup_engine.default_restore_plan(
        restore_id="restore-1",
        snapshot=backup,  # type: ignore[arg-type]
        target_cell="cell-drill-1",
        max_acceptable_data_loss_seconds=LOSS_BUDGET_S,
        expected_rto_seconds=RTO_TARGET_S,
    )
    for key in list(object_store.objects):
        object_store.objects[key] = object_store.objects[key] + b"corrupt"

    with pytest.raises(BackupUnavailableError, match="does not match its own record"):
        backup_engine.run_drill(plan)

    assert BackupRepository(store).list_restores() == ()


def test_a_drill_whose_data_loss_exceeds_the_budget_is_failed_not_verified(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """NEGATIVE CONTROL: a technically perfect restore that lost too much is not a pass."""
    backup = take_full(store, source_path, object_store, clock)
    backup_engine = engine(store, source_path, object_store, clock)
    plan = backup_engine.default_restore_plan(
        restore_id="restore-1",
        snapshot=backup,  # type: ignore[arg-type]
        target_cell="cell-drill-1",
        max_acceptable_data_loss_seconds=10.0,
        expected_rto_seconds=RTO_TARGET_S,
    )

    clock.advance(600.0)  # ten times the budget
    result = backup_engine.run_drill(plan)

    assert result.verified is False
    assert result.outcome == RestoreOutcome.FAILED.value
    assert result.verification.data_loss_seconds == pytest.approx(600.0)
    with pytest.raises(UnverifiedRestoreError):
        result.claim_verified()


def test_a_drill_missing_a_required_check_is_failed(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """NEGATIVE CONTROL: a plan can only be satisfied by observations, not by silence.

    ``EVIDENCE_CHAIN`` has no reader bound in this engine, so it records a *failed*
    check rather than passing — and the derived outcome is ``failed`` even though
    every other check passed.
    """
    backup = take_full(store, source_path, object_store, clock)
    backup_engine = engine(store, source_path, object_store, clock)
    plan = backup_engine.default_restore_plan(
        restore_id="restore-1",
        snapshot=backup,  # type: ignore[arg-type]
        target_cell="cell-drill-1",
        max_acceptable_data_loss_seconds=LOSS_BUDGET_S,
        expected_rto_seconds=RTO_TARGET_S,
        required_kinds=(
            RestoreCheckKind.ROW_COUNT,
            RestoreCheckKind.DIGEST_MATCH,
            RestoreCheckKind.EVIDENCE_CHAIN,
        ),
    )

    result = backup_engine.run_drill(plan)

    assert result.outcome == RestoreOutcome.FAILED.value
    chain_detail = check_detail(result.verification, RestoreCheckKind.EVIDENCE_CHAIN)
    assert "NOT verified" in chain_detail
    assert "fails closed" in chain_detail
    assert result.verification.failed == ("evidence_chain",)


def test_mtls_handshake_check_fails_closed_because_mtls_is_not_implemented(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """NEGATIVE CONTROL: the mTLS obligation cannot be satisfied in this phase.

    **CA-backed X.509 mTLS is not implemented here.** The check exists so a plan can
    name the obligation, and it fails closed with that stated rather than passing —
    so a plan that requires it can never produce a *verified* restore by accident.
    """
    backup = take_full(store, source_path, object_store, clock)
    backup_engine = engine(store, source_path, object_store, clock)
    plan = backup_engine.default_restore_plan(
        restore_id="restore-1",
        snapshot=backup,  # type: ignore[arg-type]
        target_cell="cell-drill-1",
        max_acceptable_data_loss_seconds=LOSS_BUDGET_S,
        expected_rto_seconds=RTO_TARGET_S,
        required_kinds=(RestoreCheckKind.MTLS_HANDSHAKE,),
    )

    result = backup_engine.run_drill(plan)

    assert result.verified is False
    detail = check_detail(result.verification, RestoreCheckKind.MTLS_HANDSHAKE)
    assert "X.509 mTLS is NOT" in detail
    assert "plan 19 Phase 3" in detail


def test_a_bound_probe_can_satisfy_the_service_health_obligation(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """The port works both ways: bind a probe and the obligation can be met."""

    class HealthyProbe:
        probe_name = "http-get"

        def probe(self, *, locator: str) -> tuple[bool, str]:
            return True, f"GET {locator}/healthz returned 200"

    backup = take_full(store, source_path, object_store, clock)
    backup_engine = engine(
        store,
        source_path,
        object_store,
        clock,
        health_probes={"service_healthy": HealthyProbe()},
    )
    plan = backup_engine.default_restore_plan(
        restore_id="restore-1",
        snapshot=backup,  # type: ignore[arg-type]
        target_cell="cell-drill-1",
        max_acceptable_data_loss_seconds=LOSS_BUDGET_S,
        expected_rto_seconds=RTO_TARGET_S,
        required_kinds=(RestoreCheckKind.SERVICE_HEALTHY,),
    )

    result = backup_engine.run_drill(plan)

    assert result.verified
    assert "healthz returned 200" in check_detail(
        result.verification, RestoreCheckKind.SERVICE_HEALTHY
    )


def test_a_probe_that_raises_is_a_failed_check_not_a_pass(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """A probe that cannot answer is not a pass. The engine does not crash on it either."""

    class BrokenProbe:
        probe_name = "http-get"

        def probe(self, *, locator: str) -> tuple[bool, str]:
            raise TimeoutError("connection refused")

    backup = take_full(store, source_path, object_store, clock)
    backup_engine = engine(
        store,
        source_path,
        object_store,
        clock,
        health_probes={"service_healthy": BrokenProbe()},
    )
    plan = backup_engine.default_restore_plan(
        restore_id="restore-1",
        snapshot=backup,  # type: ignore[arg-type]
        target_cell="cell-drill-1",
        max_acceptable_data_loss_seconds=LOSS_BUDGET_S,
        expected_rto_seconds=RTO_TARGET_S,
        required_kinds=(RestoreCheckKind.SERVICE_HEALTHY,),
    )

    result = backup_engine.run_drill(plan)

    assert result.outcome == RestoreOutcome.FAILED.value
    detail = check_detail(result.verification, RestoreCheckKind.SERVICE_HEALTHY)
    assert "TimeoutError" in detail
    assert "not a pass" in detail


def test_a_drill_with_no_evidence_recorded_is_refused_rather_than_run(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """A drill with nothing to compare against verifies nothing, so it is not attempted."""
    backup = take_full(store, source_path, object_store, clock)
    backup_engine = engine(store, source_path, object_store, clock)
    plan = backup_engine.default_restore_plan(
        restore_id="restore-1",
        snapshot=backup,  # type: ignore[arg-type]
        target_cell="cell-drill-1",
        max_acceptable_data_loss_seconds=LOSS_BUDGET_S,
        expected_rto_seconds=RTO_TARGET_S,
    )
    with store.write() as conn:
        conn.execute("DELETE FROM backup_snapshot_evidence WHERE snapshot_id = 'snap-1'")

    with pytest.raises(BackupError, match="nothing to compare"):
        backup_engine.run_drill(plan)


def test_a_drill_for_an_unknown_snapshot_is_refused(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    backup_engine = engine(store, source_path, object_store, clock)
    plan = backup_engine.default_restore_plan(
        restore_id="restore-1",
        snapshot=type(
            "Fake", (), {"snapshot_id": "snap-nope"}
        )(),  # only .snapshot_id is read
        target_cell="cell-drill-1",
        max_acceptable_data_loss_seconds=LOSS_BUDGET_S,
        expected_rto_seconds=RTO_TARGET_S,
    )

    with pytest.raises(BackupError, match="no snapshot descriptor"):
        backup_engine.run_drill(plan)


# --------------------------------------------------------------------------- #
# NEGATIVE CONTROL: a stated RPO is a target, never an achieved measurement      #
# --------------------------------------------------------------------------- #


def test_a_stated_rpo_with_no_drill_reads_not_demonstrated(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """The headline honesty property, end to end through the engine.

    Stating an RPO/RTO is free and always allowed. Reporting it as *met* requires a
    verified restore, and with none the answer is "not demonstrated" — not zero,
    not the target, and not a pass.
    """
    backup_engine = engine(store, source_path, object_store, clock)
    backup_engine.state_objective(
        DATASTORE,
        rpo_seconds=RPO_TARGET_S,
        rto_seconds=RTO_TARGET_S,
        stated_by="sre-oncall",
    )

    report = backup_engine.report(DATASTORE)

    assert report is not None
    assert report.demonstrated is False
    assert report.met is False
    assert "no restore was attempted" in report.rpo.verdict
    assert "not demonstrated" in report.describe()
    assert backup_engine.is_backup_trusted(DATASTORE) is False


def test_a_verified_drill_turns_a_target_into_a_measurement(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """With a verified drill, the achieved value is quoted **with its restore id**.

    This is the only path by which an achieved number exists, and the evidence is a
    required field of the measurement rather than a comment beside it.
    """
    backup = take_full(store, source_path, object_store, clock)
    backup_engine = engine(store, source_path, object_store, clock)
    backup_engine.state_objective(
        DATASTORE,
        rpo_seconds=RPO_TARGET_S,
        rto_seconds=RTO_TARGET_S,
        stated_by="sre-oncall",
    )
    plan = backup_engine.default_restore_plan(
        restore_id="restore-1",
        snapshot=backup,  # type: ignore[arg-type]
        target_cell="cell-drill-1",
        max_acceptable_data_loss_seconds=LOSS_BUDGET_S,
        expected_rto_seconds=RTO_TARGET_S,
    )
    clock.advance(30.0)
    clock.tick_s = 120.0  # every clock read inside the drill costs two minutes
    result = backup_engine.run_drill(plan)
    clock.tick_s = 0.0

    report = backup_engine.report(DATASTORE)

    assert result.verified
    assert report is not None
    assert report.demonstrated is True
    assert report.rpo.has_evidence and report.rto.has_evidence
    assert report.rpo.measured is not None
    assert report.rpo.measured.restore_id == "restore-1"
    assert report.rpo.measured.value_seconds == pytest.approx(30.0)
    # The RTO *is* the drill's measured wall time — asserted as an equality with the
    # recorded duration rather than as a literal, so it does not depend on how many
    # times the engine reads the clock (which is an implementation detail that should
    # be free to change).
    assert report.rto.measured.value_seconds == pytest.approx(result.verification.duration_seconds)
    assert report.rto.measured.value_seconds > 0.0
    assert report.rpo.met is True
    assert "restore-1" in report.rpo.verdict
    assert backup_engine.is_backup_trusted(DATASTORE) is True


def test_a_failed_drill_demonstrates_nothing(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """NEGATIVE CONTROL: an all-failed drill set yields no number, not a derived one.

    This is the failure mode Phase 1 exists to prevent: quoting a number computed
    from a restore that failed.
    """
    backup = take_full(store, source_path, object_store, clock)
    backup_engine = engine(store, source_path, object_store, clock)
    backup_engine.state_objective(
        DATASTORE,
        rpo_seconds=RPO_TARGET_S,
        rto_seconds=RTO_TARGET_S,
        stated_by="sre-oncall",
    )
    plan = backup_engine.default_restore_plan(
        restore_id="restore-1",
        snapshot=backup,  # type: ignore[arg-type]
        target_cell="cell-drill-1",
        max_acceptable_data_loss_seconds=1.0,  # any loss at all blows the budget
        expected_rto_seconds=RTO_TARGET_S,
    )
    clock.advance(300.0)
    result = backup_engine.run_drill(plan)

    report = backup_engine.report(DATASTORE)

    assert result.verified is False
    assert report is not None
    assert report.demonstrated is False
    assert report.rpo.measured is None
    assert "no verified restore evidence" in report.rpo.verdict
    # The restore that ran is still listed, so the report says what it considered.
    assert report.rpo.considered_restore_ids == ("restore-1",)


def test_a_stated_target_cannot_be_constructed_as_a_measurement() -> None:
    """Type-level honesty, asserted from this lane too.

    :class:`~mayhem.domain.backup.RecoveryObjective.is_measured` is always ``False``
    and a :class:`~mayhem.domain.backup.Measurement` requires its evidence. Nothing
    this phase added changes that, and an engine bug cannot route around it.
    """
    objective = RecoveryObjective(
        datastore=DATASTORE,
        rpo_seconds=RPO_TARGET_S,
        rto_seconds=RTO_TARGET_S,
        stated_at=NOW,
        stated_by="sre-oncall",
    )
    assert objective.is_measured is False
    assert objective.achieved_rpo([]) is None
    assert objective.achieved_rto([]) is None


def test_reporting_for_a_datastore_with_no_stated_objective_is_none(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """No target, no report — rather than a report with invented numbers in it."""
    assert engine(store, source_path, object_store, clock).report("never-stated") is None


def test_snapshot_evidence_round_trips_through_json(
    store: Store, source_path: Path, object_store: InMemoryObjectStore, clock: Clock
) -> None:
    """The sidecar is canonical JSON, so a restore from another cell reads it identically."""
    take_full(store, source_path, object_store, clock)
    repository = engine(store, source_path, object_store, clock).evidence

    saved = repository.load("snap-1")
    assert saved is not None
    assert SnapshotEvidence.from_json(saved.to_json()) == saved
    assert repository.latest_for(DATASTORE) is not None
    assert repository.latest_for("never-captured") is None


def test_the_unavailable_backend_fails_closed_on_every_operation() -> None:
    """NEGATIVE CONTROL: the down-backend raises on ``put``, ``fetch`` *and* ``contains``.

    ``contains`` matters as much as the other two: a backend that answers
    "is this object there?" with an exception rather than a boolean is what stops a
    caller treating "I could not ask" as "no", which would silently drop a replica.
    """
    down = UnavailableObjectStore("connection refused")
    for call in (
        lambda: down.put("k", b"v"),
        lambda: down.fetch("k"),
        lambda: down.contains("k"),
    ):
        with pytest.raises(BackupUnavailableError):
            call()


def test_the_in_memory_backend_is_labelled_as_not_object_storage() -> None:
    """The double says what it is, so no reader mistakes it for a shipped backend."""
    assert InMemoryObjectStore.name == "in-memory"
    assert UnavailableObjectStore.name == "unavailable"
    assert "object storage" in (InMemoryObjectStore.__doc__ or "").lower()
