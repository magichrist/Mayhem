"""Tests for backup descriptors, restore verification, and RPO/RTO as data.

Plan 19 Phase 1 asks for snapshot descriptors, restore plans, and "RPO/RTO
objectives as data". The Phase 2 acceptance says restore drills must *prove*
RPO/RTO "rather than asserting them", which is a property of the types, not of a
test that happens to pass. So this file is mostly negative controls:

* an unverified restore cannot be reported as successful (:meth:`claim_success`
  raises, and ``RestoreOutcome`` has no ``SUCCESS`` member to reach for);
* a stated RPO with no restore evidence is never an achieved RPO
  (:meth:`RecoveryObjective.achieved_rpo` returns ``None``, and
  :class:`~mayhem.domain.backup.Measurement` cannot be built without its
  evidence);
* a snapshot descriptor cannot claim that it restores.

Everything is a value here, so nothing is mocked: no clock reads (callers pass
``now``), no IO except the in-memory migrated store in the last section.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from mayhem.domain.backup import (
    EncryptionDescriptor,
    Measurement,
    MetricKind,
    ObjectiveComparison,
    RecoveryObjective,
    RestoreCheckKind,
    RestoreCheckResult,
    RestoreCheckSpec,
    RestoreOutcome,
    RestorePlan,
    RestoreVerification,
    SnapshotDescriptor,
    SnapshotKind,
    UnverifiedRestoreError,
    compare_against_objective,
    verified_restores,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.infra.agent_identity_store import BackupRepository
from mayhem.infra.store import Store

NOW = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
DATASTORE = "mayhem-sqlite"
SNAPSHOT = "snap-1"
CELL = "cell-drill-1"
LOSS_BUDGET_S = 60.0
RTO_TARGET_S = 600.0


# --------------------------------------------------------------------------- #
# Builders                                                                     #
# --------------------------------------------------------------------------- #


def snapshot(
    *,
    snapshot_id: str = SNAPSHOT,
    kind: SnapshotKind = SnapshotKind.FULL,
    datastore: str = DATASTORE,
    taken_at: datetime = NOW,
    covers_through: datetime | None = None,
    content_digest: str = "a" * 64,
    storage_locator: str = "s3://mayhem-backups/snap-1",
    replica_locators: tuple[str, ...] = (),
    byte_size: int = 4096,
    parent_snapshot_id: str | None = None,
    wal_sequence: int | None = None,
    encryption: EncryptionDescriptor | None = None,
    note: str = "",
) -> SnapshotDescriptor:
    """A full capture written now, complete through 30s ago."""
    return SnapshotDescriptor(
        snapshot_id=snapshot_id,
        kind=kind,
        datastore=datastore,
        taken_at=taken_at,
        covers_through=(
            NOW - timedelta(seconds=30) if covers_through is None else covers_through
        ),
        content_digest=content_digest,
        storage_locator=storage_locator,
        replica_locators=replica_locators,
        byte_size=byte_size,
        parent_snapshot_id=parent_snapshot_id,
        wal_sequence=wal_sequence,
        encryption=encryption,
        note=note,
    )


def required_checks() -> tuple[RestoreCheckSpec, ...]:
    return (
        RestoreCheckSpec(
            check_id="c-rows", kind=RestoreCheckKind.ROW_COUNT, expectation="row count matches"
        ),
        RestoreCheckSpec(
            check_id="c-digest",
            kind=RestoreCheckKind.DIGEST_MATCH,
            expectation="content digest matches",
        ),
        RestoreCheckSpec(
            check_id="c-wal",
            kind=RestoreCheckKind.WAL_REPLAY,
            expectation="WAL replays to sequence 42",
        ),
    )


def plan(
    *,
    restore_id: str = "res-1",
    snapshot_id: str = SNAPSHOT,
    target_cell: str = CELL,
    drill: bool = True,
    isolated: bool = True,
    checks: tuple[RestoreCheckSpec, ...] | None = None,
    max_acceptable_data_loss_seconds: float = LOSS_BUDGET_S,
    expected_rto_seconds: float = RTO_TARGET_S,
    planned_at: datetime | None = None,
) -> RestorePlan:
    return RestorePlan(
        restore_id=restore_id,
        snapshot_id=snapshot_id,
        target_cell=target_cell,
        drill=drill,
        isolated=isolated,
        required_checks=required_checks() if checks is None else checks,
        max_acceptable_data_loss_seconds=max_acceptable_data_loss_seconds,
        expected_rto_seconds=expected_rto_seconds,
        planned_at=NOW - timedelta(hours=1) if planned_at is None else planned_at,
    )


def passing_checks() -> tuple[RestoreCheckResult, ...]:
    return (
        RestoreCheckResult(
            check_id="c-rows",
            kind=RestoreCheckKind.ROW_COUNT,
            passed=True,
            detail="4182 rows, expected 4182",
        ),
        RestoreCheckResult(
            check_id="c-digest",
            kind=RestoreCheckKind.DIGEST_MATCH,
            passed=True,
            detail="sha256 matches the descriptor",
        ),
        RestoreCheckResult(
            check_id="c-wal",
            kind=RestoreCheckKind.WAL_REPLAY,
            passed=True,
            detail="replayed to sequence 42",
        ),
    )


def restore(
    *,
    restore_id: str = "res-1",
    restore_plan: RestorePlan | None = None,
    results: tuple[RestoreCheckResult, ...] | None = None,
    data_loss_seconds: float | None = 30.0,
    duration_s: float = 300.0,
) -> RestoreVerification:
    against = restore_plan or (plan() if restore_id == "res-1" else plan(restore_id=restore_id))
    return RestoreVerification(
        restore_id=restore_id,
        plan=against,
        snapshot_id=against.snapshot_id,
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=duration_s),
        results=passing_checks() if results is None else results,
        data_loss_seconds=data_loss_seconds,
    )


def objective(
    *,
    datastore: str = DATASTORE,
    rpo_seconds: float = LOSS_BUDGET_S,
    rto_seconds: float = RTO_TARGET_S,
    stated_at: datetime | None = None,
    stated_by: str = "sre-lead",
) -> RecoveryObjective:
    return RecoveryObjective(
        datastore=datastore,
        rpo_seconds=rpo_seconds,
        rto_seconds=rto_seconds,
        stated_at=NOW - timedelta(days=1) if stated_at is None else stated_at,
        stated_by=stated_by,
    )


# --------------------------------------------------------------------------- #
# Snapshot descriptors                                                          #
# --------------------------------------------------------------------------- #


def test_descriptor_records_what_was_written() -> None:
    described = snapshot()
    assert described.covers_through == NOW - timedelta(seconds=30)
    assert described.byte_size == 4096
    assert not described.is_replicated
    assert not described.is_encrypted


def test_descriptor_has_no_claim_field() -> None:
    """A descriptor is bytes that were written; it cannot say they restore."""
    for forbidden in ("restored", "verified", "good", "healthy", "outcome"):
        assert not hasattr(SnapshotDescriptor, forbidden)
    assert SnapshotDescriptor.model_config.get("extra") == "forbid"
    with pytest.raises(ValidationError):
        SnapshotDescriptor.model_validate({**snapshot().model_dump(), "verified": True})


def test_descriptor_digest_covers_the_window() -> None:
    later = snapshot(covers_through=NOW)
    assert snapshot().descriptor_digest() != later.descriptor_digest()


def test_a_snapshot_cannot_cover_the_future() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        snapshot(covers_through=NOW + timedelta(seconds=1))
    assert excinfo.value.rule == "snapshot.covers_future"


def test_an_incremental_needs_a_parent_and_a_log_position() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        snapshot(kind=SnapshotKind.INCREMENTAL, wal_sequence=42)
    assert excinfo.value.rule == "snapshot.incremental_without_parent"

    with pytest.raises(InvariantViolationError) as excinfo:
        snapshot(kind=SnapshotKind.INCREMENTAL, parent_snapshot_id="snap-0")
    assert excinfo.value.rule == "snapshot.wal_sequence_required"

    chained = snapshot(
        snapshot_id="snap-2",
        kind=SnapshotKind.INCREMENTAL,
        parent_snapshot_id=SNAPSHOT,
        wal_sequence=42,
    )
    assert chained.wal_sequence == 42


def test_a_full_snapshot_is_its_own_base() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        snapshot(parent_snapshot_id="snap-0")
    assert excinfo.value.rule == "snapshot.full_with_parent"


def test_a_wal_archive_needs_a_log_position() -> None:
    with pytest.raises(InvariantViolationError):
        snapshot(kind=SnapshotKind.WAL_ARCHIVE)
    assert snapshot(kind=SnapshotKind.WAL_ARCHIVE, wal_sequence=41).wal_sequence == 41


def test_duplicate_replica_locators_are_refused() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        snapshot(replica_locators=("s3://vault/s1", "s3://vault/s1"))
    assert excinfo.value.rule == "snapshot.duplicate_replica"


def test_replication_is_a_claim_about_locators_only() -> None:
    """``is_replicated`` says a locator was recorded, not that a copy was read back."""
    replicated = snapshot(replica_locators=("s3://vault/s1",))
    assert replicated.is_replicated
    assert "2 replica(s)" not in replicated.describe()


def test_encryption_is_a_reference_not_a_key() -> None:
    encrypted = snapshot(
        encryption=EncryptionDescriptor(
            algorithm="aes-256-gcm", key_ref="kms-key-1", key_custodian="kms"
        )
    )
    assert encrypted.is_encrypted
    assert "kms-key-1" in encrypted.encryption.key_ref
    for field in EncryptionDescriptor.model_fields:
        assert "key" not in field or field in {"key_ref", "key_custodian"}


def test_data_loss_is_derived_from_what_the_capture_covers() -> None:
    described = snapshot()
    assert described.data_loss_at(NOW) == timedelta(seconds=30)
    assert described.data_loss_at(NOW - timedelta(seconds=60)) == timedelta(0)
    with pytest.raises(InvariantViolationError):
        described.data_loss_at(datetime(2026, 3, 1, 11, 59))  # noqa: DTZ001 — naive on purpose


# --------------------------------------------------------------------------- #
# Restore plans                                                                 #
# --------------------------------------------------------------------------- #


def test_a_plan_that_requires_nothing_is_unrepresentable() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        plan(checks=())
    assert excinfo.value.rule == "restore_plan.no_required_checks"


def test_a_drill_must_restore_into_an_isolated_cell() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        plan(isolated=False)
    assert excinfo.value.rule == "restore_plan.drill_requires_isolation"
    live = plan(drill=False, isolated=False, target_cell="cell-prod-1")
    assert not live.drill, "a live recovery is allowed to name a live cell"


def test_a_plan_cannot_require_the_same_check_twice() -> None:
    first = required_checks()[0]
    with pytest.raises(InvariantViolationError) as excinfo:
        plan(checks=(first, first))
    assert excinfo.value.rule == "restore_plan.duplicate_check_id"


def test_plan_reports_what_it_requires() -> None:
    described = plan()
    assert described.required_check_ids == ("c-rows", "c-digest", "c-wal")
    assert described.requires_kind(RestoreCheckKind.WAL_REPLAY)
    assert not described.requires_kind(RestoreCheckKind.MTLS_HANDSHAKE)
    assert len(described.required_kinds) == 3


def test_a_passing_check_must_say_what_it_observed() -> None:
    """A bare ``passed=True`` is a claim; the detail is the evidence."""
    with pytest.raises(InvariantViolationError) as excinfo:
        RestoreCheckResult(
            check_id="c-rows", kind=RestoreCheckKind.ROW_COUNT, passed=True, detail=""
        )
    assert excinfo.value.rule == "restore_check.pass_without_detail"


# --------------------------------------------------------------------------- #
# Restore verification — the negative controls                                 #
# --------------------------------------------------------------------------- #


def test_a_fully_checked_restore_with_measured_loss_verifies() -> None:
    verified = restore()
    assert verified.status is RestoreOutcome.VERIFIED
    assert verified.verified is True
    assert verified.claim_success() is RestoreOutcome.VERIFIED
    assert verified.duration_seconds == 300.0


def test_an_unverified_restore_cannot_be_reported_as_successful() -> None:
    """NEGATIVE CONTROL: the whole point of the derived ``status``."""
    unmeasured = restore(data_loss_seconds=None)
    assert unmeasured.missing_required == ()
    assert unmeasured.failed == ()
    assert unmeasured.has_measured_data_loss is False
    assert unmeasured.status is RestoreOutcome.INCOMPLETE
    with pytest.raises(UnverifiedRestoreError) as excinfo:
        unmeasured.claim_success()
    assert excinfo.value.code == "restore_unverified"
    assert excinfo.value.status == RestoreOutcome.INCOMPLETE.value


def test_restore_outcome_has_no_success_member() -> None:
    """There is no ``SUCCESS``/``OK`` to reach for; ``VERIFIED`` must be derived."""
    members = set(RestoreOutcome)
    assert members == {
        RestoreOutcome.VERIFIED,
        RestoreOutcome.FAILED,
        RestoreOutcome.INCOMPLETE,
    }


def test_a_failed_check_makes_the_restore_failed() -> None:
    checks = (
        *passing_checks()[:2],
        RestoreCheckResult(
            check_id="c-wal",
            kind=RestoreCheckKind.WAL_REPLAY,
            passed=False,
            detail="replay stopped at sequence 39",
        ),
    )
    failed = restore(results=checks)
    assert failed.failed == ("c-wal",)
    assert failed.status is RestoreOutcome.FAILED
    with pytest.raises(UnverifiedRestoreError) as excinfo:
        failed.claim_success()
    assert excinfo.value.failed_checks == ("c-wal",)


def test_a_missing_required_check_is_named() -> None:
    partial = restore(results=passing_checks()[:1])
    assert partial.missing_required == ("c-digest", "c-wal")
    assert partial.status is RestoreOutcome.FAILED
    with pytest.raises(UnverifiedRestoreError) as excinfo:
        partial.claim_success()
    assert excinfo.value.missing_checks == ("c-digest", "c-wal")


def test_loss_over_the_budget_fails_the_restore() -> None:
    over = restore(data_loss_seconds=LOSS_BUDGET_S + 1)
    assert not over.within_loss_budget
    assert over.status is RestoreOutcome.FAILED
    assert over.within_loss_budget is not True


def test_an_unmeasured_restore_does_not_pass_a_budget() -> None:
    unmeasured = restore(data_loss_seconds=None)
    assert unmeasured.within_loss_budget is False, (
        "an absent measurement must not read as meeting the budget"
    )


def test_a_restore_must_name_the_plan_it_ran() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        RestoreVerification(
            restore_id="res-other",
            plan=plan(),
            snapshot_id=SNAPSHOT,
            started_at=NOW,
            completed_at=NOW + timedelta(seconds=5),
            results=passing_checks(),
            data_loss_seconds=1.0,
        )
    assert excinfo.value.rule == "restore.plan_mismatch"


def test_a_restore_must_name_the_snapshot_its_plan_restores() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        RestoreVerification(
            restore_id="res-1",
            plan=plan(),
            snapshot_id="snap-other",
            started_at=NOW,
            completed_at=NOW + timedelta(seconds=5),
            results=passing_checks(),
            data_loss_seconds=1.0,
        )
    assert excinfo.value.rule == "restore.snapshot_mismatch"


def test_a_restore_cannot_start_before_it_was_planned() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        RestoreVerification(
            restore_id="res-1",
            plan=plan(),
            snapshot_id=SNAPSHOT,
            started_at=NOW - timedelta(days=2),
            completed_at=NOW,
            results=passing_checks(),
            data_loss_seconds=1.0,
        )
    assert excinfo.value.rule == "restore.planned_after_start"


def test_a_restore_cannot_complete_before_it_starts() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        RestoreVerification(
            restore_id="res-1",
            plan=plan(),
            snapshot_id=SNAPSHOT,
            started_at=NOW,
            completed_at=NOW - timedelta(seconds=1),
            results=passing_checks(),
            data_loss_seconds=1.0,
        )
    assert excinfo.value.rule == "restore.time_order"


def test_a_check_the_plan_did_not_require_cannot_be_smuggled_in() -> None:
    """A plan is the contract: adding an unrequired check is refused, not ignored."""
    with pytest.raises(InvariantViolationError) as excinfo:
        restore(
            results=(
                *passing_checks(),
                RestoreCheckResult(
                    check_id="c-mtls",
                    kind=RestoreCheckKind.MTLS_HANDSHAKE,
                    passed=True,
                    detail="handshake ok",
                ),
            )
        )
    assert excinfo.value.rule == "restore.unplanned_check"


def test_the_same_check_cannot_be_recorded_twice() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        restore(results=(*passing_checks(), passing_checks()[0]))
    assert excinfo.value.rule == "restore.duplicate_check"


def test_describe_reports_the_verdict_and_the_gap() -> None:
    assert "verified" in restore().describe()
    assert "unmeasured" in restore(data_loss_seconds=None).describe()


# --------------------------------------------------------------------------- #
# Objectives as data — never measurements                                        #
# --------------------------------------------------------------------------- #


def test_an_objective_is_a_target_not_a_measurement() -> None:
    target = objective()
    assert target.is_measured is False
    assert target.describe().startswith("TARGET for")
    for forbidden in ("achieved", "met", "measured"):
        assert not hasattr(target, forbidden)


def test_an_objective_must_name_who_stated_it() -> None:
    with pytest.raises(ValidationError):
        objective(stated_by="")
    with pytest.raises(InvariantViolationError):
        objective(stated_by="   ")


# --------------------------------------------------------------------------- #
# Negative control: a stated RPO is never an achieved RPO                       #
# --------------------------------------------------------------------------- #


def test_a_stated_rpo_with_no_restore_evidence_is_not_an_achieved_rpo() -> None:
    """The control the plan's Phase 2 acceptance turns on."""
    target = objective()
    assert target.achieved_rpo(()) is None
    assert target.achieved_rto(()) is None


def test_an_incomplete_drill_is_not_evidence() -> None:
    target = objective()
    unmeasured = restore(data_loss_seconds=None)
    assert unmeasured.verified is False
    assert target.achieved_rpo([unmeasured]) is None
    assert verified_restores([unmeasured]) == ()


def test_a_failed_drill_is_not_evidence() -> None:
    target = objective()
    checks = (
        RestoreCheckResult(
            check_id="c-rows", kind=RestoreCheckKind.ROW_COUNT, passed=True, detail="42 rows"
        ),
        *passing_checks()[1:],
    )
    broken = restore(
        restore_id="res-broken",
        results=(
            checks[0],
            RestoreCheckResult(
                check_id="c-digest",
                kind=RestoreCheckKind.DIGEST_MATCH,
                passed=False,
                detail="digest mismatch",
            ),
            checks[2],
        ),
    )
    assert broken.status is RestoreOutcome.FAILED
    assert target.achieved_rpo([broken]) is None


def test_the_achieved_value_is_the_worst_verified_drill() -> None:
    """Not the best one ever run: that is a marketing number."""
    target = objective()
    good = restore(restore_id="res-good", data_loss_seconds=10.0, duration_s=120.0)
    bad = restore(restore_id="res-bad", data_loss_seconds=45.0, duration_s=480.0)
    measured = target.achieved_rpo([good, bad])
    assert measured is not None
    assert measured.value_seconds == 45.0
    assert measured.restore_id == "res-bad"
    assert measured.metric is MetricKind.RPO

    elapsed = target.achieved_rto([good, bad])
    assert elapsed is not None
    assert elapsed.value_seconds == 480.0


def test_a_measurement_cannot_be_built_without_its_evidence() -> None:
    """Evidence is a required field, not an annotation."""
    with pytest.raises(ValidationError):
        Measurement.model_validate(
            {
                "metric": MetricKind.RPO.value,
                "value_seconds": 1.0,
                "datastore": DATASTORE,
            }
        )
    proven = restore()
    measured = Measurement(
        metric=MetricKind.RPO, value_seconds=30.0, datastore=DATASTORE, evidence=proven
    )
    assert measured.restore_id == "res-1"
    assert measured.is_within(LOSS_BUDGET_S)
    assert not measured.is_within(1.0)


def test_a_measurement_cannot_cite_an_unverified_restore() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        Measurement(
            metric=MetricKind.RPO,
            value_seconds=0.0,
            datastore=DATASTORE,
            evidence=restore(data_loss_seconds=None),
        )
    assert excinfo.value.rule == "measurement.unverified_evidence"


# --------------------------------------------------------------------------- #
# The report                                                                    #
# --------------------------------------------------------------------------- #


def test_report_without_evidence_demonstrates_nothing() -> None:
    report = compare_against_objective(objective(), ())
    assert report.demonstrated is False
    assert report.met is False
    assert report.rpo.has_evidence is False
    assert "not demonstrated" in report.rpo.verdict
    assert "no restore was attempted" in report.rpo.verdict


def test_report_names_the_drills_that_ran_but_did_not_verify() -> None:
    """A failed drill is a fact; it just is not evidence."""
    report = compare_against_objective(objective(), [restore(data_loss_seconds=None)])
    assert report.demonstrated is False
    assert "1 restore(s) ran, none verified" in report.rpo.verdict


def test_report_is_met_when_both_halves_are_evidenced_and_inside_target() -> None:
    report = compare_against_objective(objective(), [restore()])
    assert report.demonstrated is True
    assert report.met is True
    assert report.verified_restore_ids == ("res-1",)
    assert report.rpo.measured is not None
    assert report.rpo.measured.restore_id == "res-1"
    assert "met" in report.describe()


def test_report_is_not_met_when_the_loss_exceeds_the_target() -> None:
    report = compare_against_objective(objective(), [restore(data_loss_seconds=900.0)])
    assert report.demonstrated is False, "an over-budget restore is not evidence"
    assert report.met is False


def test_report_quotes_both_halves_together() -> None:
    """Reporting the flattering half alone is the failure mode this prevents."""
    report = compare_against_objective(objective(), [restore()])
    assert "rpo" in report.rpo.verdict
    assert "rto" in report.rto.verdict
    assert report.rpo.verdict in report.describe()
    assert report.rto.verdict in report.describe()


def test_comparison_without_evidence_is_never_met() -> None:
    comparison = ObjectiveComparison(metric=MetricKind.RPO, target_seconds=60.0)
    assert comparison.has_evidence is False
    assert comparison.met is False
    assert "not demonstrated" in comparison.verdict


def test_comparison_refuses_a_mismatched_metric() -> None:
    with pytest.raises(InvariantViolationError) as excinfo:
        ObjectiveComparison(
            metric=MetricKind.RTO,
            target_seconds=60.0,
            measured=Measurement(
                metric=MetricKind.RPO,
                value_seconds=1.0,
                datastore=DATASTORE,
                evidence=restore(),
            ),
        )
    assert excinfo.value.rule == "objective_comparison.metric_mismatch"


def test_comparison_refuses_evidence_it_does_not_list() -> None:
    measured = Measurement(
        metric=MetricKind.RPO, value_seconds=1.0, datastore=DATASTORE, evidence=restore()
    )
    with pytest.raises(InvariantViolationError) as excinfo:
        ObjectiveComparison(
            metric=MetricKind.RPO,
            target_seconds=60.0,
            measured=measured,
            evidence_restore_ids=(),
        )
    assert excinfo.value.rule == "objective_comparison.unlisted_evidence"


def test_verified_restores_filters_unevidenced_records() -> None:
    good = restore(restore_id="res-good")
    unmeasured = restore(restore_id="res-unmeasured", data_loss_seconds=None)
    assert verified_restores([good, unmeasured]) == (good,)


# --------------------------------------------------------------------------- #
# Store round-trip (the only IO in this file)                                   #
# --------------------------------------------------------------------------- #


@pytest.fixture
def store() -> Store:
    opened = Store.open_migrated(":memory:")
    yield opened
    opened.close()


def test_snapshot_survives_a_store_round_trip(store: Store) -> None:
    repo = BackupRepository(store)
    repo.save_snapshot(snapshot())
    loaded = repo.load_snapshot(SNAPSHOT)
    assert loaded is not None
    assert loaded == snapshot()
    assert loaded.descriptor_digest() == snapshot().descriptor_digest()


def test_store_lists_snapshots_by_datastore_and_kind(store: Store) -> None:
    repo = BackupRepository(store)
    repo.save_snapshot(snapshot())
    repo.save_snapshot(
        snapshot(
            snapshot_id="snap-wal",
            kind=SnapshotKind.WAL_ARCHIVE,
            wal_sequence=41,
            covers_through=NOW,
            content_digest="b" * 64,
            taken_at=NOW + timedelta(minutes=1),
        )
    )
    assert [found.snapshot_id for found in repo.list_snapshots()] == ["snap-wal", SNAPSHOT]
    archives = repo.list_snapshots(kind=SnapshotKind.WAL_ARCHIVE)
    assert [found.snapshot_id for found in archives] == ["snap-wal"]
    assert len(repo.list_snapshots(datastore=DATASTORE)) == 2
    assert repo.list_snapshots(datastore="other") == ()


def test_store_asks_what_a_capture_covers_not_when_it_was_written(store: Store) -> None:
    repo = BackupRepository(store)
    repo.save_snapshot(snapshot(covers_through=NOW - timedelta(minutes=5)))
    assert repo.snapshots_covering(datastore=DATASTORE, at=NOW) == ()
    assert len(repo.snapshots_covering(datastore=DATASTORE, at=NOW - timedelta(minutes=6))) == 1


def test_store_persists_the_derived_outcome_not_a_caller_supplied_one(store: Store) -> None:
    repo = BackupRepository(store)
    repo.record_restore(restore(data_loss_seconds=None))
    rows = store.query(
        "SELECT restore_id, outcome, data_loss_seconds FROM backup_restore_verifications"
    )
    stored = [tuple(row) for row in rows]
    assert stored == [("res-1", "incomplete", None)], (
        "an unmeasured restore must stay NULL in the database, not read as a zero"
    )


def test_store_reloads_a_restore_and_re_derives_its_verdict(store: Store) -> None:
    repo = BackupRepository(store)
    repo.record_restore(restore())
    loaded = repo.load_restore("res-1")
    assert loaded is not None
    assert loaded.status is RestoreOutcome.VERIFIED
    assert [found.restore_id for found in repo.verified_restores()] == ["res-1"]


def test_store_filters_restores_by_outcome(store: Store) -> None:
    repo = BackupRepository(store)
    repo.record_restore(restore(restore_id="res-ok"))
    repo.record_restore(restore(restore_id="res-unmeasured", data_loss_seconds=None))
    assert len(repo.list_restores()) == 2
    assert len(repo.list_restores(outcome=RestoreOutcome.INCOMPLETE)) == 1
    assert len(repo.list_restores(snapshot_id=SNAPSHOT)) == 2
    assert repo.list_restores(snapshot_id="snap-other") == ()


def test_stored_objective_is_a_target_only(store: Store) -> None:
    """No achieved column exists, so a target cannot be read back as a result."""
    repo = BackupRepository(store)
    repo.save_objective(objective())
    assert repo.load_objective(DATASTORE) == objective()
    assert repo.objective_report(DATASTORE) is not None
    columns = {str(row[1]) for row in store.query('PRAGMA table_info("recovery_objectives")')}
    assert not [name for name in columns if name.startswith("achieved")]
    assert "data_loss_seconds" not in columns


def test_stored_report_reports_never_run_as_undemonstrated(store: Store) -> None:
    repo = BackupRepository(store)
    repo.save_objective(objective())
    report = repo.objective_report(DATASTORE)
    assert report is not None
    assert report.demonstrated is False
    assert report.met is False


def test_stored_report_becomes_met_only_with_a_verified_drill(store: Store) -> None:
    repo = BackupRepository(store)
    repo.save_objective(objective())
    repo.record_restore(restore(data_loss_seconds=None))
    interim = repo.objective_report(DATASTORE)
    assert interim is not None
    assert interim.demonstrated is False

    repo.record_restore(restore(restore_id="res-2", data_loss_seconds=30.0))
    final = repo.objective_report(DATASTORE)
    assert final is not None
    assert final.demonstrated is True
    assert final.met is True
    assert final.rpo.measured is not None
    assert final.rpo.measured.value_seconds == 30.0


def test_report_is_none_when_no_objective_was_stated(store: Store) -> None:
    assert BackupRepository(store).objective_report(DATASTORE) is None


def test_objective_history_is_versioned_by_statement_time(store: Store) -> None:
    repo = BackupRepository(store)
    repo.save_objective(
        objective(rpo_seconds=300.0, stated_at=NOW - timedelta(days=30))
    )
    repo.save_objective(objective(rpo_seconds=60.0, stated_at=NOW - timedelta(days=1)))
    assert len(repo.list_objectives()) == 2
    assert repo.load_objective(DATASTORE).rpo_seconds == 60.0, (
        "the most recent statement wins"
    )
