"""Pre-run sweep: leases owned by a dead controller are reclaimed before TTL.

Regression for the reported pain — a crashed ``mayhem run`` left an active
lease inside its TTL window, so ``mayhem janitor`` "did nothing" and the very
next run failed with a LeaseConflictError. The controller now records its pid
on the run row, and the sweep (CLI + pre-run) reclaims leases whose owner is
provably gone even though TTL has not elapsed.
"""

import json
from datetime import timedelta

from mayhem.cli.app import main
from mayhem.cli.lifecycle import _run_liveness, _sweep_before_run
from mayhem.domain.common import utc_now
from mayhem.domain.leases import FaultLease, LeaseState
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.store import Store


def _lease(run_id: str, lease_id: str, state: LeaseState, *, ttl: float = 120.0) -> FaultLease:
    payload: dict[str, object] = {
        "id": lease_id,
        "run_id": run_id,
        "fault_id": "proc.pause",
        "owner_agent": "ag-1",
        "targets": ["n1"],
        "undo_ops": ({"op": "noop", "args": {}},),
        "verify_probes": ({"probe": "exec", "args": {"cmd": ["true"]}, "expect_present": True},),
        "ttl_seconds": ttl,
        "state": state,
        "created_at": utc_now(),
    }
    return FaultLease.model_validate(payload)


def _run_row(store: Store, run_id: str, status: str, controller_pid: int | None) -> None:
    with store.write() as conn:
        conn.execute(
            "INSERT INTO config_snapshots (id, resolved_json, source_map, created_at)"
            " VALUES (?, '{}', '{}', 'now')",
            (f"c-{run_id}",),
        )
        conn.execute(
            "INSERT INTO runs (id, experiment_name, kind, spec_json, plan_json, seed,"
            " status, environment_fingerprint, config_snapshot_id, controller_pid)"
            " VALUES (?, 'exp', 'deterministic', '{}', '{}', 1, ?, 'env', ?, ?)",
            (run_id, status, f"c-{run_id}", controller_pid),
        )


class TestRunLivenessResolver:
    def test_terminal_run_is_dead(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "l.db")
        _run_row(store, "r-dead", "failed", None)
        assert _run_liveness(store, "r-dead") is False
        store.close()

    def test_running_run_with_no_pid_is_unknown(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "l.db")
        _run_row(store, "r-unknown", "running", None)
        assert _run_liveness(store, "r-unknown") is None
        store.close()

    def test_running_run_with_live_pid_is_unknown(self, tmp_path) -> None:
        import os

        store = Store.open_migrated(tmp_path / "l.db")
        _run_row(store, "r-live", "running", os.getpid())  # this process is alive
        assert _run_liveness(store, "r-live") is None
        store.close()

    def test_missing_run_row_is_unknown(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "l.db")
        assert _run_liveness(store, "r-absent") is None
        store.close()

    def test_running_run_with_dead_recorded_pid_is_dead(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "l.db")
        _run_row(store, "r-zombie", "running", 2_147_483_647)
        assert _run_liveness(store, "r-zombie") is False
        store.close()


class TestPreRunSweepReclaimsLeakedLeases:
    def test_crashed_run_active_lease_reclaimed_before_ttl(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "l.db")
        # The crashed run: status stuck 'running', controller pid not alive.
        _run_row(store, "r-crashed", "running", 2_147_483_647)
        sink = SQLiteLeaseSink(store)
        lease = _lease("r-crashed", "l-1", LeaseState.ACTIVE)
        sink.save(lease)

        _sweep_before_run(store)

        reclaimed = sink.load("l-1")
        assert reclaimed is not None
        assert reclaimed.state is LeaseState.RELEASED
        assert reclaimed.release_mechanism == "janitor"
        store.close()

    def test_crashed_run_pending_lease_expired_before_ttl(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "l.db")
        _run_row(store, "r-crashed", "running", 2_147_483_647)
        sink = SQLiteLeaseSink(store)
        sink.save(_lease("r-crashed", "l-2", LeaseState.PENDING))

        _sweep_before_run(store)

        assert sink.load("l-2") is not None
        assert sink.load("l-2").state is LeaseState.EXPIRED
        store.close()

    def test_live_runs_leases_untouched(self, tmp_path) -> None:
        import os

        store = Store.open_migrated(tmp_path / "l.db")
        _run_row(store, "r-live", "running", os.getpid())
        sink = SQLiteLeaseSink(store)
        sink.save(_lease("r-live", "l-3", LeaseState.ACTIVE))

        _sweep_before_run(store)

        assert sink.load("l-3") is not None
        assert sink.load("l-3").state is LeaseState.ACTIVE
        store.close()

    def test_lease_with_no_run_row_keeps_ttl_policy(self, tmp_path) -> None:
        store = Store.open_migrated(tmp_path / "l.db")
        sink = SQLiteLeaseSink(store)
        sink.save(_lease("r-absent", "l-4", LeaseState.ACTIVE, ttl=120.0))

        _sweep_before_run(store)

        assert sink.load("l-4") is not None
        assert sink.load("l-4").state is LeaseState.ACTIVE
        store.close()


def test_janitor_cli_dry_run_is_default_and_execute_is_explicit(tmp_path, capsys):
    db = tmp_path / "janitor.db"
    store = Store.open_migrated(db)
    sink = SQLiteLeaseSink(store)
    lease = _lease("r-expired", "l-cli", LeaseState.ACTIVE, ttl=1).model_copy(
        update={"created_at": utc_now() - timedelta(seconds=10)}
    )
    sink.save(lease)
    store.close()
    assert main(["--db", str(db), "janitor", "--json"]) == 0
    preview = json.loads(capsys.readouterr().out)
    assert preview["execute"] is False
    assert preview["would_recover"] == ["l-cli"]
    store = Store.open_migrated(db)
    assert SQLiteLeaseSink(store).load("l-cli").state is LeaseState.ACTIVE
    store.close()
    assert main(["--db", str(db), "janitor", "--json", "--execute"]) == 0
    executed = json.loads(capsys.readouterr().out)
    assert executed["execute"] is True
    assert executed["recovered"] == ["l-cli"]
    store = Store.open_migrated(db)
    assert SQLiteLeaseSink(store).load("l-cli").state is LeaseState.RELEASED
    store.close()


def test_recover_group_status_and_plan_accept_explicit_run_ids(tmp_path, capsys):
    db = tmp_path / "recover.db"
    store = Store.open_migrated(db)
    sink = SQLiteLeaseSink(store)
    sink.save(_lease("run-explicit", "l-explicit", LeaseState.ACTIVE, ttl=1).model_copy(
        update={"created_at": utc_now() - timedelta(seconds=10)}
    ))
    store.close()
    assert main(["--db", str(db), "recover", "status", "run-explicit", "--json"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["state"] == "pending"
    assert status["run_ids"] == ["run-explicit"]
    assert main([
        "--db",
        str(db),
        "recover",
        "plan",
        "run-explicit",
        "--target",
        "production",
        "--json",
    ]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["target_profiles"] == ["production"]
    assert plan["leases"][0]["id"] == "l-explicit"
    store = Store.open_migrated(db)
    assert SQLiteLeaseSink(store).load("l-explicit").state is LeaseState.ACTIVE
    store.close()
