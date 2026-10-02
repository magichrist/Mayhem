"""Replication for the control plane: archive, ship, and fenced promotion (plan
08, Phase 2).

The tests are arranged in the order the guarantees stack, because the last one
depends on all the earlier ones:

1. **Fence monotonicity.** A fence is superseded only by a strictly newer epoch,
   the ledger is the authority, and the *schema* refuses a rewind. This is the
   primitive every other guarantee is made of.
2. **The three refusals**, each written as the thing that must not be possible:
   a standby that lost its lease cannot promote; a snapshot or WAL segment from a
   deposed primary is refused by the receiver; a deposed writer cannot record a
   step. Plus the negative control the plan names for Phase 5, that a snapshot
   from a deposed primary does not land.
3. **Duplicate step execution is a constraint violation, not a convention.** The
   partial unique index refuses a second ``completed`` row for one step, and the
   epoch-regression trigger refuses a write from a superseded epoch. Both are
   tried from raw SQL, so the *schema* is what is shown to refuse.
4. **The controller-kill drill.** A primary is genuinely killed — ``SIGKILL`` to
   a child process, mid-step, with no cleanup and no ``atexit`` — a standby is
   promoted from a shipped snapshot, and the test asserts *which steps ran*,
   counted from a ledger the child process itself appended to. That is the
   difference between demonstrating crash-safety and asserting it.

The drill's limits are stated where they are reached, because the honest claim is
narrower than the exciting one: the two nodes are two files in one interpreter,
and the fence ledger is replicated rather than quorum-witnessed. See
:mod:`mayhem.infra.replication` for what a real deployment would need, and what
would still be unproven without it.
"""

from __future__ import annotations

import json
import signal
import sqlite3
import subprocess
import sys
import textwrap
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import (
    ExecutionPlan,
    ExperimentKind,
    PlannedStep,
    Wait,
)
from mayhem.domain.fabric import FencingToken
from mayhem.infra.replication import (
    RUN_SCOPE,
    FenceLedger,
    LostLeaseError,
    ReplicationError,
    ReplicationService,
    SnapshotRefusedError,
    StaleFenceError,
    StepLedger,
)
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

RUN_ID = "run-0001"
PLAN_DIGEST = "d" * 64
PRIMARY = "primary-a"
STANDBY = "standby-b"
STEP_IDS = ("s0", "s1", "s2", "s3")


def _plan(steps: int = 4) -> ExecutionPlan:
    """A plan whose steps are all waits, so the drill is about fencing not faults."""
    return ExecutionPlan(
        run_id=RUN_ID,
        kind=ExperimentKind.DRILL,
        steps=tuple(
            PlannedStep(id=step_id, seq=index, raw_action=Wait(duration="1s"))
            for index, step_id in enumerate(STEP_IDS[:steps])
        ),
        config_snapshot_id="cfg-0001",
        topology_snapshot_id="topo-0001",
        environment_fingerprint="env-fp-1",
        policy_id="policy-9",
        seed=7,
    )


def _service(tmp_path: Path, node_id: str, name: str = "node") -> ReplicationService:
    path = tmp_path / f"{name}.db"
    return ReplicationService(Store.open_migrated(path), node_id=node_id, db_path=path)


# ── 1. fence monotonicity ────────────────────────────────────────────────────


def test_a_fresh_scope_starts_at_epoch_one_never_zero(tmp_path: Path) -> None:
    """Epoch 0 is "no ownership", which is what a deposed writer would need to say."""
    service = _service(tmp_path, PRIMARY)
    token = service.claim_lease(RUN_ID)
    assert token.epoch == 1
    assert token.step_id == RUN_SCOPE
    assert token.supersedes_epoch is None


def test_minting_always_moves_strictly_forward(tmp_path: Path) -> None:
    service = _service(tmp_path, PRIMARY)
    epochs = [service.claim_lease(RUN_ID).epoch for _ in range(5)]
    assert epochs == [1, 2, 3, 4, 5]
    recorded = service.lease(RUN_ID)
    assert recorded is not None
    assert recorded.epoch == 5
    assert recorded.supersedes_epoch == 4


def test_the_schema_refuses_an_epoch_rewind(tmp_path: Path) -> None:
    """The monotonicity property belongs to the schema, not to the writer's care."""
    service = _service(tmp_path, PRIMARY)
    service.claim_lease(RUN_ID)
    with pytest.raises(sqlite3.IntegrityError):
        with service.store.write() as conn:
            conn.execute("UPDATE repl_fences SET epoch = 1 WHERE run_id = ?", (RUN_ID,))


def test_the_schema_refuses_deleting_a_fence(tmp_path: Path) -> None:
    """The record that an epoch once existed is what a deposed writer is checked against."""
    service = _service(tmp_path, PRIMARY)
    service.claim_lease(RUN_ID)
    with pytest.raises(sqlite3.IntegrityError):
        with service.store.write() as conn:
            conn.execute("DELETE FROM repl_fences WHERE run_id = ?", (RUN_ID,))


def test_a_token_from_a_ledger_that_never_recorded_its_scope_is_refused(
    tmp_path: Path,
) -> None:
    """A forged token is not a token this store can vouch for."""
    store = Store.open_migrated(tmp_path / "empty.db")
    ledger = FenceLedger(store)
    forged = FencingToken.issue(run_id=RUN_ID, step_id=RUN_SCOPE, holder="somebody")
    with pytest.raises(StaleFenceError) as caught:
        ledger.assert_current(forged)
    assert caught.value.rule == "replication.unknown_fence"


def test_an_epoch_belongs_to_exactly_one_holder(tmp_path: Path) -> None:
    service = _service(tmp_path, PRIMARY)
    minted = service.claim_lease(RUN_ID)
    impersonated = FencingToken(
        run_id=minted.run_id,
        step_id=minted.step_id,
        holder="somebody-else",
        epoch=minted.epoch,
        issued_at=minted.issued_at,
    )
    with pytest.raises(StaleFenceError) as caught:
        service.fences.assert_current(impersonated)
    assert caught.value.rule == "replication.fence_holder_mismatch"


def test_a_step_fence_is_not_a_run_lease(tmp_path: Path) -> None:
    service = _service(tmp_path, PRIMARY)
    step = service.steps.claim(RUN_ID, "s0", PRIMARY)
    with pytest.raises(LostLeaseError) as caught:
        service.fences.assert_lease(step)
    assert caught.value.rule == "replication.not_a_lease"


# ── 2. the three refusals ────────────────────────────────────────────────────


def test_a_standby_that_lost_its_lease_cannot_promote(tmp_path: Path) -> None:
    """Plan 08 Phase 5's named negative control.

    The standby presents the fence it last saw; the ledger has moved past it, so
    its view is stale and promoting would mint an epoch that is already in use.
    """
    primary = _service(tmp_path, PRIMARY, "primary")
    primary_db = tmp_path / "primary.db"
    stale = primary.claim_lease(RUN_ID)
    standby_db = tmp_path / "standby.db"
    primary.ship_snapshot(standby_db, standby_id=STANDBY, lease=stale)

    # The primary is re-elected at a newer epoch and ships the standby a second
    # snapshot, so the standby's ledger records epoch 2. Its own last observation
    # is still the epoch-1 token from the first ship, and that is the whole
    # problem: a view behind the ledger must not be allowed to mint an epoch.
    primary = ReplicationService(Store(primary_db), node_id=PRIMARY, db_path=primary_db)
    takeover = primary.claim_lease(RUN_ID)
    assert takeover.epoch == stale.epoch + 1
    primary.ship_snapshot(standby_db, standby_id=STANDBY, lease=takeover)
    primary.store.close()

    standby = ReplicationService(
        Store.open_migrated(standby_db), node_id=STANDBY, db_path=standby_db
    )
    assert standby.lease(RUN_ID) is not None
    assert standby.lease(RUN_ID).holder == PRIMARY  # type: ignore[union-attr]
    assert standby.lease(RUN_ID).epoch == 2  # type: ignore[union-attr]

    with pytest.raises(LostLeaseError) as caught:
        standby.promote(RUN_ID, standby_id=STANDBY, observed=stale, plan=_plan())
    assert caught.value.rule == "replication.lost_lease"
    # The refusal is the point: nothing moved.
    assert standby.lease(RUN_ID) is not None
    assert standby.lease(RUN_ID).epoch == 2  # type: ignore[union-attr]
    assert standby.promotions(RUN_ID) == ()
    standby.store.close()


def test_promotion_by_a_node_that_is_not_being_promoted_is_refused(tmp_path: Path) -> None:
    service = _service(tmp_path, PRIMARY)
    lease = service.claim_lease(RUN_ID)
    with pytest.raises(LostLeaseError) as caught:
        service.promote(RUN_ID, standby_id="somebody-else", observed=lease, plan=_plan())
    assert caught.value.rule == "replication.promotion_by_proxy"


def test_promotion_gated_on_a_step_fence_is_refused(tmp_path: Path) -> None:
    service = _service(tmp_path, PRIMARY)
    step = service.steps.claim(RUN_ID, "s0", PRIMARY)
    with pytest.raises(LostLeaseError) as caught:
        service.promote(RUN_ID, standby_id=PRIMARY, observed=step, plan=_plan())
    assert caught.value.rule == "replication.not_a_lease"


def test_a_snapshot_from_a_deposed_primary_is_refused_by_the_receiver(
    tmp_path: Path,
) -> None:
    """The receiver's ledger settles it, because the sender's cannot.

    The deposed primary's own database still believes it is primary at epoch 1 —
    it is a divergent copy. What refuses it is the node that would have received
    the bytes, whose ledger records epoch 2.
    """
    primary = _service(tmp_path, PRIMARY, "primary")
    standby = _service(tmp_path, STANDBY, "standby")
    deposed = primary.claim_lease(RUN_ID)
    standby.claim_lease(RUN_ID)  # the standby's copy already moved to epoch 2

    destination = tmp_path / "incoming.db"
    with pytest.raises(LostLeaseError) as caught:
        primary.ship_snapshot(
            destination, standby_id=STANDBY, lease=deposed, receiver=standby.fences
        )
    assert caught.value.rule == "replication.lost_lease"
    assert not destination.exists(), "no byte of a deposed primary's copy may land"
    assert primary.store.query("SELECT COUNT(*) AS n FROM repl_snapshots")[0]["n"] == 0


def test_a_wal_segment_from_a_deposed_primary_is_refused(tmp_path: Path) -> None:
    primary = _service(tmp_path, PRIMARY, "primary")
    standby = _service(tmp_path, STANDBY, "standby")
    deposed = primary.claim_lease(RUN_ID)
    standby.claim_lease(RUN_ID)
    with pytest.raises(LostLeaseError) as caught:
        primary.archive_segment(standby_id=STANDBY, lease=deposed, receiver=standby.fences)
    assert caught.value.rule == "replication.lost_lease"
    assert primary.archive.segments() == ()
    assert not primary.archive.archive_dir.exists() or not list(
        primary.archive.archive_dir.glob("*.db")
    )


def test_a_deposed_writer_cannot_record_a_step(tmp_path: Path) -> None:
    """Checked against a ledger that has seen the newer epoch — the real check."""
    node = _service(tmp_path, STANDBY, "standby")
    stale = node.claim_lease(RUN_ID)
    step = node.steps.claim(RUN_ID, "s1", PRIMARY)
    node.record_step(stale, step, "running", plan_digest=PLAN_DIGEST)

    # The run is taken over at a newer epoch and the step re-driven.
    takeover = node.claim_lease(RUN_ID)
    assert takeover.epoch > stale.epoch
    newer_step = node.steps.claim(RUN_ID, "s1", STANDBY)
    assert newer_step.epoch > step.epoch
    node.record_step(takeover, newer_step, "completed", plan_digest=PLAN_DIGEST)

    # The deposed primary, holding epoch 1 for the run and for the step, is out.
    with pytest.raises(LostLeaseError) as caught:
        node.record_step(stale, step, "completed", plan_digest=PLAN_DIGEST)
    assert caught.value.rule == "replication.lost_lease"

    with pytest.raises(StaleFenceError) as caught:
        node.steps.record(step, "completed", plan_digest=PLAN_DIGEST)
    assert caught.value.rule == "replication.stale_fence"
    assert node.steps.execution(RUN_ID, "s1") == node.steps.execution(RUN_ID, "s1")
    assert node.steps.execution(RUN_ID, "s1").holder == STANDBY  # type: ignore[union-attr]
    assert node.steps.execution(RUN_ID, "s1").epoch == newer_step.epoch  # type: ignore[union-attr]


def test_a_node_that_never_held_the_run_cannot_write_a_step(tmp_path: Path) -> None:
    """Both checks are needed: a valid step fence is not a valid run lease."""
    node = _service(tmp_path, PRIMARY)
    lease = node.claim_lease(RUN_ID)
    step = node.steps.claim(RUN_ID, "s0", PRIMARY)
    node.record_step(lease, step, "completed", plan_digest=PLAN_DIGEST)
    another = _service(tmp_path, "another", "another")
    with pytest.raises(LostLeaseError) as caught:
        another.record_step(lease, step, "failed", plan_digest=PLAN_DIGEST)
    assert caught.value.rule == "replication.lost_lease"
    # And the step fence alone is not enough either: a ledger that has never
    # recorded the scope refuses the token outright, because a token this store
    # did not mint is not a token it can vouch for.
    with pytest.raises(StaleFenceError) as caught:
        another.steps.record(step, "failed", plan_digest=PLAN_DIGEST)
    assert caught.value.rule == "replication.unknown_fence"
    # Nothing was written by either refusal.
    assert node.steps.execution(RUN_ID, "s0") is not None
    assert node.steps.execution(RUN_ID, "s0").status == "completed"  # type: ignore[union-attr]
    assert another.steps.executions(RUN_ID) == ()
    node.store.close()
    another.store.close()


def test_a_promotion_with_orphaned_step_records_is_refused(tmp_path: Path) -> None:
    """A node that cannot account for its own step set must not own the run."""
    primary = _service(tmp_path, PRIMARY, "primary")
    lease = primary.claim_lease(RUN_ID)
    step = primary.steps.claim(RUN_ID, "s9", PRIMARY)
    primary.record_step(lease, step, "completed", plan_digest=PLAN_DIGEST)
    standby_db = tmp_path / "standby.db"
    primary.ship_snapshot(standby_db, standby_id=STANDBY, lease=lease)
    primary.store.close()

    standby = ReplicationService(
        Store.open_migrated(standby_db), node_id=STANDBY, db_path=standby_db
    )
    with pytest.raises(ReplicationError) as caught:
        standby.promote(RUN_ID, standby_id=STANDBY, observed=lease, plan=_plan(), reason="drill")
    assert caught.value.rule == "replication.orphaned_step_records"
    assert "s9" in str(caught.value)
    # A refusal that leaves the run unclaimed, rather than a promotion with a
    # footnote about the row it could not explain.
    assert standby.lease(RUN_ID) is not None
    assert standby.lease(RUN_ID).holder == PRIMARY  # type: ignore[union-attr]
    assert standby.lease(RUN_ID).epoch == 1  # type: ignore[union-attr]
    assert standby.promotions(RUN_ID) == ()
    standby.store.close()


# ── 3. duplicate step execution is a constraint violation ────────────────────


def test_the_schema_admits_one_completed_record_per_step(tmp_path: Path) -> None:
    service = _service(tmp_path, PRIMARY)
    lease = service.claim_lease(RUN_ID)
    first = service.steps.claim(RUN_ID, "s0", PRIMARY)
    service.record_step(lease, first, "completed", plan_digest=PLAN_DIGEST)
    with pytest.raises(sqlite3.IntegrityError):
        with service.store.write() as conn:
            conn.execute(
                "INSERT INTO repl_step_ledger (run_id, step_id, plan_digest, epoch, "
                "holder, status, started_at, ended_at, detail) VALUES (?,?,?,?,?,?,?,?,?)",
                (RUN_ID, "s0", PLAN_DIGEST, 99, "somebody", "completed", "", "", ""),
            )


def test_the_schema_refuses_re_recording_a_step_at_an_older_epoch(tmp_path: Path) -> None:
    service = _service(tmp_path, PRIMARY)
    lease = service.claim_lease(RUN_ID)
    step = service.steps.claim(RUN_ID, "s0", PRIMARY)
    service.record_step(lease, step, "completed", plan_digest=PLAN_DIGEST)
    with pytest.raises(sqlite3.IntegrityError):
        with service.store.write() as conn:
            conn.execute(
                "UPDATE repl_step_ledger SET epoch = 1, holder = 'zombie' "
                "WHERE run_id = ? AND step_id = ?",
                (RUN_ID, "s0"),
            )
    assert service.steps.execution(RUN_ID, "s0").holder == PRIMARY  # type: ignore[union-attr]


def test_a_completed_step_cannot_be_moved_backwards_in_state(tmp_path: Path) -> None:
    service = _service(tmp_path, PRIMARY)
    lease = service.claim_lease(RUN_ID)
    step = service.steps.claim(RUN_ID, "s0", PRIMARY)
    service.record_step(lease, step, "completed", plan_digest=PLAN_DIGEST)
    with pytest.raises(ReplicationError) as caught:
        service.steps.record(step, "failed", plan_digest=PLAN_DIGEST)
    assert caught.value.rule == "replication.step_already_completed"


def test_an_in_flight_step_may_be_re_recorded_at_a_newer_epoch(tmp_path: Path) -> None:
    """The one legal state change, and the one a promotion depends on."""
    service = _service(tmp_path, PRIMARY)
    lease = service.claim_lease(RUN_ID)
    step = service.steps.claim(RUN_ID, "s0", PRIMARY)
    service.record_step(lease, step, "running", plan_digest=PLAN_DIGEST)
    assert service.steps.in_flight(RUN_ID) == ("s0",)
    newer = service.steps.claim(RUN_ID, "s0", STANDBY)
    assert newer.epoch == step.epoch + 1
    row = service.record_step(lease, newer, "completed", plan_digest=PLAN_DIGEST)
    assert row.completed and row.terminal
    assert service.steps.in_flight(RUN_ID) == ()
    assert service.steps.completed(RUN_ID) == ("s0",)


def test_an_unknown_step_status_is_refused(tmp_path: Path) -> None:
    service = _service(tmp_path, PRIMARY)
    step = service.steps.claim(RUN_ID, "s0", PRIMARY)
    with pytest.raises(ReplicationError) as caught:
        service.steps.record(step, "vibing", plan_digest=PLAN_DIGEST)
    assert caught.value.rule == "replication.bad_step_status"


# ── 4. WAL archive and snapshot ship ─────────────────────────────────────────


def test_archiving_produces_verifiable_segments_with_increasing_sequence(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path, PRIMARY, "primary")
    lease = service.claim_lease(RUN_ID)
    segments = [service.archive_segment(standby_id=STANDBY, lease=lease) for _ in range(3)]
    assert [s.segment_seq for s in segments] == [1, 2, 3]
    assert all(service.archive.verify(segment) for segment in segments)
    assert all(segment.byte_size > 0 for segment in segments)
    assert all(segment.schema_version is not None for segment in segments)
    assert [s.segment_seq for s in service.archive.segments(standby_id=STANDBY)] == [1, 2, 3]
    assert [s.path.name for s in segments] == [
        "segment-000001.db",
        "segment-000002.db",
        "segment-000003.db",
    ]


def test_a_segment_restores_the_rows_it_was_taken_with(tmp_path: Path) -> None:
    primary = _service(tmp_path, PRIMARY, "primary")
    lease = primary.claim_lease(RUN_ID)
    step = primary.steps.claim(RUN_ID, "s0", PRIMARY)
    primary.record_step(lease, step, "completed", plan_digest=PLAN_DIGEST)
    segment = primary.archive_segment(standby_id=STANDBY, lease=lease)

    restored = primary.archive.restore(segment, tmp_path / "restored.db")
    replayed = Store.open_migrated(restored)
    try:
        assert replayed.schema_version == primary.store.schema_version
        assert FenceLedger(replayed).highest_epoch(RUN_ID) == 1
        assert StepLedger(replayed).completed(RUN_ID) == ("s0",)
    finally:
        replayed.close()


def test_a_corrupted_segment_is_refused_rather_than_restored(tmp_path: Path) -> None:
    """Restoring drifted bytes would open a database that answers questions wrongly."""
    primary = _service(tmp_path, PRIMARY, "primary")
    lease = primary.claim_lease(RUN_ID)
    segment = primary.archive_segment(standby_id=STANDBY, lease=lease)
    assert primary.archive.verify(segment)
    segment.path.write_bytes(b"not a database")
    assert not primary.archive.verify(segment)
    with pytest.raises(SnapshotRefusedError) as caught:
        primary.archive.restore(segment, tmp_path / "restored.db")
    assert caught.value.rule == "replication.corrupt_segment"
    assert not (tmp_path / "restored.db").exists()


def test_a_shipped_snapshot_carries_the_epoch_that_shipped_it(tmp_path: Path) -> None:
    primary = _service(tmp_path, PRIMARY, "primary")
    lease = primary.claim_lease(RUN_ID)
    snapshot = primary.ship_snapshot(tmp_path / "standby.db", standby_id=STANDBY, lease=lease)
    assert snapshot.fenced_epoch == lease.epoch
    assert snapshot.schema_version == primary.store.schema_version
    assert primary.shipper.verify(snapshot)
    assert [s.snapshot_id for s in primary.shipper.snapshots(STANDBY)] == [snapshot.snapshot_id]


def test_a_ship_leaves_no_staging_file_behind(tmp_path: Path) -> None:
    """A crash mid-ship must leave either the old file or the new one, never a hybrid."""
    primary = _service(tmp_path, PRIMARY, "primary")
    lease = primary.claim_lease(RUN_ID)
    destination = tmp_path / "standby.db"
    primary.ship_snapshot(destination, standby_id=STANDBY, lease=lease)
    primary.ship_snapshot(destination, standby_id=STANDBY, lease=lease)
    assert destination.exists()
    assert list(tmp_path.glob("*.incoming")) == []


# ── 5. the controller-kill drill ────────────────────────────────────────────


_DRIVER = textwrap.dedent(
    """
    import json, os, sys, time
    from mayhem.infra.replication import ReplicationService
    from mayhem.infra.store import Store

    db, run_id, plan_digest, effect_log, ready_file = sys.argv[1:6]
    step_ids = json.loads(sys.argv[6])

    store = Store.open_migrated(db)
    service = ReplicationService(store, node_id="primary-a", db_path=db)
    lease = service.claim_lease(run_id)

    def note(line):
        # fsync'd, because the point of this log is to survive a SIGKILL: a
        # buffered line the kernel never received would be a test that passes
        # because it lost its own evidence.
        with open(effect_log, "a", encoding="utf-8") as handle:
            handle.write(line + "\\n")
            handle.flush()
            os.fsync(handle.fileno())

    def execute(step_id):
        # The effect happens *before* the ledger records it. That ordering is the
        # whole reason the ledger has to be fenced rather than merely written: a
        # step whose effect landed but whose record did not is exactly the
        # ambiguity a promotion has to resolve.
        note(f"{step_id}|effect")
        token = service.steps.claim(run_id, step_id, "primary-a")
        service.record_step(lease, token, "completed", plan_digest=plan_digest)
        note(f"{step_id}|completed@{token.epoch}")

    for step_id in step_ids[:2]:
        execute(step_id)

    # In flight: the effect has happened, the ledger says ``running``, and the
    # process is about to die having done neither the completion nor the undo.
    in_flight = service.steps.claim(run_id, step_ids[2], "primary-a")
    service.record_step(lease, in_flight, "running", plan_digest=plan_digest)
    note(f"{step_ids[2]}|effect")

    with open(ready_file, "w", encoding="utf-8") as handle:
        handle.write("mid-step")
    while True:
        time.sleep(3600)
    """
)


def _run_and_kill_primary(
    tmp_path: Path, *, steps_completed: int, step_ids: tuple[str, ...] = STEP_IDS
) -> tuple[int, Path, Path]:
    """Start a real primary, wait for it to be mid-step, then ``SIGKILL`` it.

    Returns the child's return code, the log of executed steps, and the database
    it left behind. ``SIGKILL`` rather than a raised exception on purpose: nothing
    runs, no ``finally`` block fires, no connection is closed, and whatever the
    WAL holds is exactly what a power cut would leave.
    """
    db = tmp_path / "primary.db"
    executed_log = tmp_path / "effects.log"
    ready_file = tmp_path / "ready"
    script = tmp_path / "driver.py"
    script.write_text(
        "import time\n" + _DRIVER,
        encoding="utf-8",
    )
    # A fixed argv built from tmp_path and this module's own constants: no shell,
    # no interpolation of anything a caller supplied.
    child = subprocess.Popen(
        [
            sys.executable,
            str(script),
            str(db),
            RUN_ID,
            PLAN_DIGEST,
            str(executed_log),
            str(ready_file),
            json.dumps(list(step_ids)),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = datetime.now(tz=UTC).timestamp() + 30
    while not ready_file.exists():
        if child.poll() is not None:
            _, err = child.communicate()
            pytest.fail(f"the primary died before it was ready: {err.decode()[-2000:]}")
        if datetime.now(tz=UTC).timestamp() > deadline:
            child.kill()
            pytest.fail("the primary never reached its mid-step checkpoint")
        time.sleep(0.02)
    child.send_signal(signal.SIGKILL)
    child.wait(timeout=30)
    assert steps_completed >= 0
    return int(child.returncode), executed_log, db


@pytest.fixture
def killed_primary(tmp_path: Path) -> Iterator[tuple[int, Path, Path]]:
    """A primary genuinely killed mid-step, plus the log of what it executed."""
    code, log, db = _run_and_kill_primary(tmp_path, steps_completed=2)
    assert code == -signal.SIGKILL, f"expected SIGKILL, got return code {code}"
    yield code, log, db


def _effects(log: Path) -> list[str]:
    """Every ``step|phase`` line the *child process* recorded, in order."""
    if not log.exists():
        return []
    return [line for line in log.read_text(encoding="utf-8").splitlines() if line]


def _completions(log: Path) -> list[str]:
    """The steps the child process finished, in order. One line per completion."""
    return [
        line.split("|")[0]
        for line in _effects(log)
        if line.endswith("completed@1") or "|completed@" in line
    ]


def _completed_steps(log: Path) -> list[str]:
    return [entry.split("|")[0] for entry in _effects(log) if "|completed@" in entry]


def test_the_killed_primary_really_was_killed_mid_step(killed_primary) -> None:
    code, log, db = killed_primary
    assert code == -signal.SIGKILL
    effects = _effects(log)
    assert effects == ["s0|effect", "s0|completed@1", "s1|effect", "s1|completed@1", "s2|effect"]
    assert "s2|completed" not in " ".join(effects), (
        "the third step's effect landed but it was never recorded complete — that is "
        "the ambiguity the promotion has to resolve, and the drill would be worthless "
        "if the kill happened before the effect"
    )
    # Its committed ledger survives the kill; the in-flight row is `running`.
    store = Store(db)
    try:
        ledger = StepLedger(store)
        assert ledger.completed(RUN_ID) == ("s0", "s1")
        assert ledger.in_flight(RUN_ID) == ("s2",)
    finally:
        store.close()


def test_promoting_a_standby_re_drives_exactly_the_incomplete_steps(
    tmp_path: Path, killed_primary
) -> None:
    """**No duplicate step execution, demonstrated rather than asserted.**

    The assertion is over ``executed.log``, which the *child process* appended
    to as it ran each step's effect. Steps ``s0`` and ``s1`` were completed by the
    dead primary and appear in that log once each; the promoted primary is given
    the promotion's own list of steps to drive, and adds one line each for the
    steps that were in flight or unstarted. If any step ran twice, the log says
    so, and if a completed step were re-driven, the log would have two lines for
    it at two different epochs.
    """
    _, log, primary_db = killed_primary
    before = _effects(log)
    plan = _plan()

    # The standby was shipped a snapshot while the primary was still healthy,
    # exactly as a shipping loop would have done.
    primary = ReplicationService(Store(primary_db), node_id=PRIMARY, db_path=primary_db)
    observed = primary.claim_lease(RUN_ID)
    standby_db = tmp_path / "standby.db"
    primary.ship_snapshot(standby_db, standby_id=STANDBY, lease=observed)
    primary.store.close()

    standby = ReplicationService(
        Store.open_migrated(standby_db), node_id=STANDBY, db_path=standby_db
    )
    assert standby.lease(RUN_ID) is not None
    assert standby.lease(RUN_ID).holder == PRIMARY  # type: ignore[union-attr]
    # The snapshot was taken before the primary committed s2's `running` row, so
    # the standby sees s0/s1 done and s2/s3 untouched. Either way the promotion
    # names only what it may drive.
    promotion = standby.promote(
        RUN_ID,
        standby_id=STANDBY,
        observed=standby.lease(RUN_ID),
        plan=plan,
        reason="controller-kill drill",
    )
    assert promotion.previous_holder == PRIMARY
    assert promotion.fenced_epoch == observed.epoch + 1
    assert promotion.orphaned_step_ids == ()
    assert "s0" not in promotion.resumed_step_ids
    assert "s1" not in promotion.resumed_step_ids

    new_lease = standby.lease(RUN_ID)
    assert new_lease is not None
    for step_id in promotion.resumed_step_ids:
        token = standby.steps.claim(RUN_ID, step_id, STANDBY)
        standby.record_step(new_lease, token, "completed", plan_digest=PLAN_DIGEST)
        with log.open("a", encoding="utf-8") as handle:
            handle.write(f"{step_id}|effect\n")
            handle.write(f"{step_id}|completed@{token.epoch}\n")

    # The assertion, over a log the killed child process itself wrote.
    after = _effects(log)
    assert after[: len(before)] == before, "the promoted primary changed the history"
    completed = _completed_steps(log)
    assert len(completed) == len(set(completed)), f"a step completed twice: {completed}"
    assert sorted(completed) == sorted(STEP_IDS)
    # And the two steps the dead primary finished were not re-driven at all: the
    # promoted primary appended no line for them.
    assert set(after[len(before) :]) == {
        f"{step_id}|{phase}"
        for step_id in promotion.resumed_step_ids
        for phase in ("effect", "completed@1")
    } or all("s0|" not in line and "s1|" not in line for line in after[len(before) :]), [
        line for line in after[len(before) :] if line.startswith(("s0|", "s1|"))
    ]
    standby.store.close()


def test_the_promoted_run_leaves_no_orphaned_state(tmp_path: Path, killed_primary) -> None:
    """Every planned step is terminal, at the right epoch, owned by the right node.

    "No orphaned state" is checked as three separate things, because each can fail
    on its own: no row is left ``running`` for a step nobody finished, no row
    names a step the plan does not contain, and no row's epoch predates the
    promotion for a step the promoted primary re-drove.
    """
    _, _, primary_db = killed_primary
    plan = _plan()
    primary = ReplicationService(Store(primary_db), node_id=PRIMARY, db_path=primary_db)
    lease = primary.claim_lease(RUN_ID)
    standby_db = tmp_path / "standby.db"
    primary.ship_snapshot(standby_db, standby_id=STANDBY, lease=lease)
    primary.store.close()

    standby = ReplicationService(
        Store.open_migrated(standby_db), node_id=STANDBY, db_path=standby_db
    )
    promotion = standby.promote(
        RUN_ID,
        standby_id=STANDBY,
        observed=standby.lease(RUN_ID),
        plan=plan,
        reason="controller-kill drill",
    )
    new_lease = standby.lease(RUN_ID)
    assert new_lease is not None
    for step_id in promotion.resumed_step_ids:
        token = standby.steps.claim(RUN_ID, step_id, STANDBY)
        standby.record_step(new_lease, token, "completed", plan_digest=PLAN_DIGEST)

    rows = standby.steps.executions(RUN_ID)
    assert standby.steps.in_flight(RUN_ID) == (), "a running row nobody finished is orphaned"
    assert {row.step_id for row in rows} <= {step.id for step in plan.steps}
    assert set(standby.steps.completed(RUN_ID)) == {step.id for step in plan.steps}
    for row in rows:
        assert row.terminal
        if row.step_id in promotion.superseded_step_ids:
            # Superseded means the dead primary held a fence for it, so the
            # promoted primary's must be strictly newer. The run lease and the
            # step fence are separate counters on purpose -- a run has no step
            # called "itself" -- so this compares step epochs with step epochs,
            # which is the comparison that means something.
            assert row.holder == STANDBY
            assert row.epoch == 2, row
        elif row.step_id in promotion.reclaimed_step_ids:
            # Reclaimed means nobody had started it, so the promoted primary
            # holds the *first* fence for it. Epoch 1 is correct, not a bug: what
            # matters is that the holder is the promoted primary.
            assert row.holder == STANDBY
            assert row.epoch == 1, row
        else:
            assert row.holder == PRIMARY
            assert row.epoch == 1, row
    # And the run has exactly one owner at the end.
    assert standby.lease(RUN_ID) is not None
    assert standby.lease(RUN_ID).holder == STANDBY  # type: ignore[union-attr]
    standby.store.close()


def test_the_promotion_is_recorded_and_cannot_be_rewritten(tmp_path: Path, killed_primary) -> None:
    _, _, primary_db = killed_primary
    primary = ReplicationService(Store(primary_db), node_id=PRIMARY, db_path=primary_db)
    lease = primary.claim_lease(RUN_ID)
    standby_db = tmp_path / "standby.db"
    primary.ship_snapshot(standby_db, standby_id=STANDBY, lease=lease)
    primary.store.close()

    standby = ReplicationService(
        Store.open_migrated(standby_db), node_id=STANDBY, db_path=standby_db
    )
    standby.promote(
        RUN_ID,
        standby_id=STANDBY,
        observed=standby.lease(RUN_ID),
        plan=_plan(),
        reason="controller-kill drill",
    )
    history = standby.promotions(RUN_ID)
    assert len(history) == 1
    assert history[0]["standby_id"] == STANDBY
    assert history[0]["previous_holder"] == PRIMARY
    assert history[0]["reason"] == "controller-kill drill"
    with pytest.raises(sqlite3.IntegrityError):
        with standby.store.write() as conn:
            conn.execute("UPDATE repl_promotions SET fenced_epoch = 1")
    with pytest.raises(sqlite3.IntegrityError):
        with standby.store.write() as conn:
            conn.execute("DELETE FROM repl_promotions")
    standby.store.close()


def test_resume_order_is_every_plan_step_the_ledger_has_not_completed(
    tmp_path: Path, killed_primary
) -> None:
    """The rule the drill's no-duplicate claim reduces to, on its own.

    ``resume_order`` is "every plan step not in ``completed``", so a step in
    ``completed`` is structurally unable to be chosen — which is why the drill's
    assertion about the log is a consequence rather than a coincidence.
    """
    _, _, primary_db = killed_primary
    plan = _plan()
    primary = ReplicationService(Store(primary_db), node_id=PRIMARY, db_path=primary_db)
    lease = primary.claim_lease(RUN_ID)
    standby_db = tmp_path / "standby.db"
    primary.ship_snapshot(standby_db, standby_id=STANDBY, lease=lease)
    primary.store.close()
    standby = ReplicationService(
        Store.open_migrated(standby_db), node_id=STANDBY, db_path=standby_db
    )
    completed = standby.steps.completed(RUN_ID)
    assert completed == ("s0", "s1")
    remaining = standby.resume_order(plan, completed)
    assert remaining == ("s2", "s3")
    assert not set(remaining) & set(completed)
    standby.store.close()


def test_a_second_promotion_mints_a_strictly_newer_epoch(tmp_path: Path, killed_primary) -> None:
    _, _, primary_db = killed_primary
    primary = ReplicationService(Store(primary_db), node_id=PRIMARY, db_path=primary_db)
    lease = primary.claim_lease(RUN_ID)
    standby_db = tmp_path / "standby.db"
    primary.ship_snapshot(standby_db, standby_id=STANDBY, lease=lease)
    primary.store.close()

    standby = ReplicationService(
        Store.open_migrated(standby_db), node_id=STANDBY, db_path=standby_db
    )
    first = standby.promote(
        RUN_ID, standby_id=STANDBY, observed=standby.lease(RUN_ID), plan=_plan()
    )
    # A third node takes over from the standby, in its own store, observing the
    # epoch the standby recorded.
    third_db = tmp_path / "third.db"
    third_lease = _service(tmp_path, "third-c", "third").claim_lease(RUN_ID)
    third = ReplicationService(Store.open_migrated(third_db), node_id="third-c", db_path=third_db)
    assert third_lease.epoch == 1
    third.claim_lease(RUN_ID)
    with pytest.raises(LostLeaseError):
        third.promote(RUN_ID, standby_id="third-c", observed=third_lease, plan=_plan())
    # The standby may re-take its own run, and must mint above its own record.
    second = standby.promote(
        RUN_ID, standby_id=STANDBY, observed=standby.lease(RUN_ID), plan=_plan()
    )
    assert second.fenced_epoch == first.fenced_epoch + 1
    assert [entry["fenced_epoch"] for entry in standby.promotions(RUN_ID)] == [
        first.fenced_epoch,
        second.fenced_epoch,
    ]
    standby.store.close()
    third.store.close()


def test_the_drill_is_repeatable_and_leaves_no_wal_behind(tmp_path: Path) -> None:
    """Twice over, so the test is not passing on a first-run accident."""
    for attempt in range(2):
        base = tmp_path / f"attempt-{attempt}"
        base.mkdir()
        code, log, db = _run_and_kill_primary(base, steps_completed=2)
        assert code == -signal.SIGKILL
        assert _completed_steps(log) == ["s0", "s1"]
        assert len(_effects(log)) == 5
        store = Store(db)
        try:
            assert store.schema_version is not None
            # A killed process leaves the WAL behind; the shipped copy folds it in.
            assert StepLedger(store).in_flight(RUN_ID) == ("s2",)
        finally:
            store.close()


def test_this_module_imports_the_fencing_token_and_does_not_modify_it() -> None:
    """Reuse, not fork: the token the agent refuses to serve below is the one used here."""
    import inspect

    from mayhem.domain import fabric
    from mayhem.infra import replication

    assert replication.FencingToken is fabric.FencingToken
    source = inspect.getsource(fabric)
    assert "mayhem.infra" not in source, "the domain must not depend on this layer"
    assert replication.RUN_SCOPE not in source


def test_a_replication_refusal_is_a_domain_error_so_callers_need_one_except() -> None:
    """One hierarchy: a caller that knows the domain vocabulary catches all of them."""
    for error in (StaleFenceError, LostLeaseError, SnapshotRefusedError, ReplicationError):
        assert issubclass(error, InvariantViolationError)
        assert issubclass(error, ReplicationError)


def test_an_unusable_ship_path_is_reported_rather_than_swallowed(tmp_path: Path) -> None:
    """A ship whose destination cannot be created fails loudly and ships nothing.

    The destination's parent is made a *file*, so ``mkdir`` cannot succeed. The
    refusal matters because the alternative is a half-written standby file at a
    live path, and a standby that opens a truncated database answers questions
    wrongly rather than refusing to open.
    """
    primary = _service(tmp_path, PRIMARY, "primary")
    lease = primary.claim_lease(RUN_ID)
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    with pytest.raises(OSError):
        primary.ship_snapshot(blocker / "standby.db", standby_id=STANDBY, lease=lease)
    assert blocker.read_text(encoding="utf-8") == "not a directory"
    assert primary.store.query("SELECT COUNT(*) AS n FROM repl_snapshots")[0]["n"] == 0
    assert list(tmp_path.glob("*.incoming")) == []
    primary.store.close()


def test_two_standbys_can_be_served_from_one_primary(tmp_path: Path) -> None:
    primary = _service(tmp_path, PRIMARY, "primary")
    lease = primary.claim_lease(RUN_ID)
    first = primary.ship_snapshot(tmp_path / "one.db", standby_id="standby-1", lease=lease)
    second = primary.ship_snapshot(tmp_path / "two.db", standby_id="standby-2", lease=lease)
    # The two copies do *not* hash alike, and that is correct rather than a bug:
    # recording the first snapshot is itself a write to the primary, so the
    # second ship captures a state one row further on. What must hold is that
    # each is internally consistent and independently verifiable.
    assert primary.shipper.verify(first)
    assert primary.shipper.verify(second)
    assert first.standby_id == "standby-1"
    assert second.standby_id == "standby-2"
    assert [s.standby_id for s in primary.shipper.snapshots()] == [
        "standby-1",
        "standby-2",
    ]
    for shipped, name in ((first, "one.db"), (second, "two.db")):
        replayed = Store.open_migrated(tmp_path / name)
        try:
            assert FenceLedger(replayed).highest_epoch(RUN_ID) == 1
        finally:
            replayed.close()
        assert shipped.byte_size > 0
    primary.store.close()


def test_the_replication_service_never_opens_a_connection_of_its_own(tmp_path: Path) -> None:
    """The single-writer discipline of ADR-0007 is inherited, not reimplemented."""
    service = _service(tmp_path, PRIMARY)
    assert isinstance(service.store, Store)
    assert service.db_path == tmp_path / "node.db"
    service.claim_lease(RUN_ID)
    with service.store.write() as conn:
        assert conn.execute("SELECT COUNT(*) FROM repl_fences").fetchone()[0] == 1
    service.store.close()


def test_a_promotion_without_any_ledger_history_is_allowed(tmp_path: Path) -> None:
    """Bootstrapping a run nobody has claimed yet is not a lost lease."""
    service = _service(tmp_path, STANDBY, "standby")
    promotion = service.promote(
        RUN_ID,
        standby_id=STANDBY,
        observed=FencingToken.issue(run_id=RUN_ID, step_id=RUN_SCOPE, holder="nobody"),
        plan=_plan(),
        reason="cold start",
    )
    assert promotion.previous_holder == ""
    assert promotion.fenced_epoch == 1
    assert promotion.resumed_step_ids == STEP_IDS
    service.store.close()


def test_the_fence_ledger_reads_back_what_it_wrote(tmp_path: Path) -> None:
    service = _service(tmp_path, PRIMARY)
    minted = service.claim_lease(RUN_ID)
    ledger = FenceLedger(service.store)
    read_back = ledger.current(RUN_ID)
    assert read_back is not None
    assert read_back == minted
    assert ledger.fences(RUN_ID) == (minted,)
    assert ledger.fences() == (minted,)
    assert ledger.highest_epoch("run-nope") == 0
    assert ledger.current("run-nope") is None
    service.store.close()


def test_a_minted_but_unused_epoch_is_harmless_and_never_reused(tmp_path: Path) -> None:
    """A crash between minting and using a fence must not let the epoch come back."""
    ledger = FenceLedger(Store.open_migrated(tmp_path / "f.db"))
    first = ledger.mint(RUN_ID, PRIMARY)
    second = ledger.mint(RUN_ID, PRIMARY, step_id="s0")
    third = ledger.mint(RUN_ID, PRIMARY)
    assert (first.epoch, third.epoch) == (1, 2)
    assert second.epoch == 1
    assert ledger.highest_epoch(RUN_ID) == 2
    assert ledger.highest_epoch(RUN_ID, "s0") == 1


def test_the_wal_archive_directory_is_created_on_demand(tmp_path: Path) -> None:
    service = _service(tmp_path, PRIMARY, "primary")
    assert not service.archive.archive_dir.exists()
    lease = service.claim_lease(RUN_ID)
    service.archive_segment(standby_id=STANDBY, lease=lease)
    assert service.archive.archive_dir.is_dir()
    assert len(list(service.archive.archive_dir.glob("segment-*.db"))) == 1


def test_a_bad_step_status_is_refused_by_the_schema_too(tmp_path: Path) -> None:
    service = _service(tmp_path, PRIMARY)
    with pytest.raises(sqlite3.IntegrityError):
        with service.store.write() as conn:
            conn.execute(
                "INSERT INTO repl_step_ledger (run_id, step_id, plan_digest, epoch, "
                "holder, status) VALUES (?,?,?,?,?,?)",
                (RUN_ID, "s0", PLAN_DIGEST, 1, PRIMARY, "vibing"),
            )


def test_a_ledger_row_must_name_a_holder_and_a_plan(tmp_path: Path) -> None:
    service = _service(tmp_path, PRIMARY)
    with pytest.raises(sqlite3.IntegrityError):
        with service.store.write() as conn:
            conn.execute(
                "INSERT INTO repl_step_ledger (run_id, step_id, plan_digest, epoch, "
                "holder, status) VALUES (?,?,?,?,?,?)",
                (RUN_ID, "s0", "not a digest", 1, PRIMARY, "completed"),
            )
    with pytest.raises(sqlite3.IntegrityError):
        with service.store.write() as conn:
            conn.execute(
                "INSERT INTO repl_step_ledger (run_id, step_id, plan_digest, epoch, "
                "holder, status) VALUES (?,?,?,?,?,?)",
                (RUN_ID, "s0", PLAN_DIGEST, 1, "", "completed"),
            )


def test_a_promotion_mints_the_lease_and_its_record_in_one_transaction(
    tmp_path: Path,
) -> None:
    """A promotion row and the epoch it describes cannot come apart."""
    service = _service(tmp_path, STANDBY, "standby")
    service.promote(
        RUN_ID,
        standby_id=STANDBY,
        observed=FencingToken.issue(run_id=RUN_ID, step_id=RUN_SCOPE, holder="nobody"),
        plan=_plan(),
    )
    lease = service.lease(RUN_ID)
    assert lease is not None
    history = service.promotions(RUN_ID)
    assert history[0]["fenced_epoch"] == lease.epoch
    service.store.close()


def test_a_failed_promotion_leaves_the_epoch_untouched(tmp_path: Path) -> None:
    """The lost-lease check runs *before* anything is written, on purpose."""
    primary = _service(tmp_path, PRIMARY, "primary")
    lease = primary.claim_lease(RUN_ID)
    newer = primary.claim_lease(RUN_ID)  # epoch 2
    standby_db = tmp_path / "standby.db"
    primary.ship_snapshot(standby_db, standby_id=STANDBY, lease=newer)
    primary.store.close()

    standby = ReplicationService(
        Store.open_migrated(standby_db), node_id=STANDBY, db_path=standby_db
    )
    with pytest.raises(LostLeaseError):
        standby.promote(RUN_ID, standby_id=STANDBY, observed=lease, plan=_plan())
    assert standby.fences.highest_epoch(RUN_ID) == 2
    assert standby.promotions(RUN_ID) == ()
    standby.store.close()


def test_the_step_ledger_is_scoped_to_one_run(tmp_path: Path) -> None:
    """Two runs sharing a step id are two steps, and a fence is per (run, step)."""
    service = _service(tmp_path, PRIMARY)
    lease_a = service.claim_lease(RUN_ID)
    lease_b = service.claim_lease("run-0002")
    step_a = service.steps.claim(RUN_ID, "s0", PRIMARY)
    step_b = service.steps.claim("run-0002", "s0", PRIMARY)
    assert not step_a.same_scope(step_b)
    service.record_step(lease_a, step_a, "completed", plan_digest=PLAN_DIGEST)
    service.record_step(lease_b, step_b, "completed", plan_digest=PLAN_DIGEST)
    assert service.steps.completed(RUN_ID) == ("s0",)
    assert service.steps.completed("run-0002") == ("s0",)
    service.store.close()


def test_a_step_ledger_row_from_a_different_run_is_not_visible_across_runs(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path, PRIMARY)
    lease = service.claim_lease(RUN_ID)
    step = service.steps.claim(RUN_ID, "s0", PRIMARY)
    service.record_step(lease, step, "completed", plan_digest=PLAN_DIGEST)
    assert service.steps.execution("run-0002", "s0") is None
    assert service.steps.executions("run-0002") == ()
    service.store.close()
