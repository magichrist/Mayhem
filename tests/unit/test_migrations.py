"""Schema migrations: forward-only upgrades preserve data and admit new kinds."""

from pathlib import Path

from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store


def _insert_deterministic_run(store: Store, run_id: str) -> None:
    with store.write() as conn:
        conn.execute(
            "INSERT INTO config_snapshots (id, resolved_json, source_map, created_at)"
            " VALUES ('c1', '{}', '{}', 'now')"
        )
        conn.execute(
            "INSERT INTO runs (id, experiment_name, kind, spec_json, plan_json, seed,"
            " status, environment_fingerprint, config_snapshot_id)"
            " VALUES (?, 'exp', 'deterministic', '{}', '{}', 1, 'completed', 'env', 'c1')",
            (run_id,),
        )


def test_m0004_drill_run_kind_preserves_data_and_allows_drill(
    tmp_path: Path,
) -> None:
    store = Store.open_migrated(tmp_path / "tg.db", migrations=ALL_MIGRATIONS[:3])
    _insert_deterministic_run(store, "r1")
    assert store.query("SELECT kind FROM runs WHERE id='r1'")[0]["kind"] == "deterministic"

    applied = store.migrate()
    assert "0004_drill_run_kind" in applied
    assert store.schema_version == ALL_MIGRATIONS[-1].version

    assert store.query("SELECT id, kind FROM runs WHERE id='r1'")[0]["kind"] == "deterministic"
    assert store.query("PRAGMA foreign_key_check") == []

    with store.write() as conn:
        conn.execute(
            "INSERT INTO runs (id, experiment_name, kind, spec_json, plan_json, seed,"
            " status, environment_fingerprint, config_snapshot_id)"
            " VALUES ('r2', 'drill1', 'drill', '{}', '{}', NULL, 'completed', 'env', 'c1')"
        )
    assert store.query("SELECT kind FROM runs WHERE id='r2'")[0]["kind"] == "drill"
    store.close()


def test_m0005_step_run_bypass_status_preserves_data_and_admits_bypassed(
    tmp_path: Path,
) -> None:
    store = Store.open_migrated(tmp_path / "tg.db", migrations=ALL_MIGRATIONS[:4])
    _insert_deterministic_run(store, "r1")
    with store.write() as conn:
        conn.execute(
            "INSERT INTO step_runs (id, run_id, seq, action_type, action_json, status)"
            " VALUES ('s1', 'r1', 1, 'inject', '{}', 'skipped')"
        )
    assert store.query("SELECT status FROM step_runs WHERE id='s1'")[0]["status"] == "skipped"

    applied = store.migrate()
    assert "0005_step_run_bypass_status" in applied
    assert store.schema_version == ALL_MIGRATIONS[-1].version
    assert store.query("SELECT status FROM step_runs WHERE id='s1'")[0]["status"] == "skipped"
    assert store.query("PRAGMA foreign_key_check") == []

    with store.write() as conn:
        conn.execute(
            "INSERT INTO step_runs (id, run_id, seq, action_type, action_json, status)"
            " VALUES ('s2', 'r1', 2, 'inject', '{}', 'bypassed')"
        )
    assert store.query("SELECT status FROM step_runs WHERE id='s2'")[0]["status"] == "bypassed"
    store.close()


def test_migrations_are_strictly_increasing() -> None:
    versions = [m.version for m in ALL_MIGRATIONS]
    assert versions == sorted(versions)
    assert len(versions) == len(set(versions))
    assert versions[0] == 1


def test_m0006_runtime_identity_adds_identity_columns_and_target_drift(
    tmp_path: Path,
) -> None:
    store = Store.open_migrated(tmp_path / "tg.db", migrations=ALL_MIGRATIONS[:5])
    _insert_deterministic_run(store, "r1")
    with store.write() as conn:
        conn.execute(
            "INSERT INTO step_runs (id, run_id, seq, action_type, action_json, status)"
            " VALUES ('s1', 'r1', 1, 'inject', '{}', 'completed')"
        )
        conn.execute(
            "INSERT INTO fault_leases (id, run_id, fault_id, state, owner_agent,"
            " undo_json, verify_json, targets_json, ttl_seconds, expires_at,"
            " created_epoch_s)"
            " VALUES ('l1', 'r1', 'proc.pause', 'released', 'ag', '[]', '[]', '[]',"
            " 30, 'now', 1)"
        )
        conn.execute(
            "INSERT INTO observations (kind, run_id, data_json, timestamp)"
            " VALUES ('signal', 'r1', '{}', 'now')"
        )
        conn.execute(
            "INSERT INTO recovery_records (id, lease_id, attempt, mechanism,"
            " undo_results_json, verified, at)"
            " VALUES ('rr1', 'l1', 1, 'normal', '{}', 1, 'now')"
        )

    applied = store.migrate()
    assert "0006_runtime_identity" in applied
    assert store.schema_version == ALL_MIGRATIONS[-1].version

    for table in (
        "runs",
        "fault_leases",
        "observations",
        "recovery_records",
    ):
        cols = {row["name"] for row in store.query(f"PRAGMA table_info({table})")}
        assert "runtime_identity" in cols, f"{table} missing runtime_identity"

    step_cols = {row["name"] for row in store.query("PRAGMA table_info(step_runs)")}
    assert "runtime_identity" in step_cols

    # target_drift is now a legal persisted step status.
    with store.write() as conn:
        conn.execute("UPDATE step_runs SET status = 'target_drift' WHERE id = 's1'")
    assert store.query("SELECT status FROM step_runs WHERE id='s1'")[0]["status"] == "target_drift"

    # Identity can be written and read back round-trippably.
    with store.write() as conn:
        conn.execute("UPDATE runs SET runtime_identity = 'podman|h1|cid-x' WHERE id = 'r1'")
    assert (
        store.query("SELECT runtime_identity FROM runs WHERE id='r1'")[0]["runtime_identity"]
        == "podman|h1|cid-x"
    )
    assert store.query("PRAGMA foreign_key_check") == []
    store.close()


def test_m0007_fault_groups_add_group_columns(tmp_path: Path) -> None:
    store = Store.open_migrated(tmp_path / "tg.db", migrations=ALL_MIGRATIONS[:6])
    _insert_deterministic_run(store, "r1")
    with store.write() as conn:
        conn.execute(
            "INSERT INTO step_runs (id, run_id, seq, action_type, action_json, status)"
            " VALUES ('s1', 'r1', 1, 'inject', '{}', 'completed')"
        )
        conn.execute(
            "INSERT INTO fault_leases (id, run_id, fault_id, state, owner_agent,"
            " undo_json, verify_json, targets_json, ttl_seconds, expires_at,"
            " created_epoch_s)"
            " VALUES ('l1', 'r1', 'proc.pause', 'released', 'ag', '[]', '[]', '[]',"
            " 30, 'now', 1)"
        )
        conn.execute(
            "INSERT INTO fault_invocations (id, run_id, step_run_id, fault_id,"
            " targets_json, params_json, backend, lease_id)"
            " VALUES ('fi1', 'r1', 's1', 'proc.pause', '[]', '{}', 'podman', 'l1')"
        )

    applied = store.migrate()
    assert "0007_fault_groups" in applied
    assert store.schema_version == ALL_MIGRATIONS[-1].version

    step_cols = {row["name"] for row in store.query("PRAGMA table_info(step_runs)")}
    for col in ("execution_group_id", "group_mode", "group_path"):
        assert col in step_cols, f"step_runs missing {col}"
    inv_cols = {row["name"] for row in store.query("PRAGMA table_info(fault_invocations)")}
    assert "execution_group_id" in inv_cols

    # Group fields round-trip on step_runs.
    with store.write() as conn:
        conn.execute(
            "UPDATE step_runs SET execution_group_id='grp-1', group_mode='sequential',"
            " group_path='/testcase-api' WHERE id='s1'"
        )
    row = store.query(
        "SELECT execution_group_id, group_mode, group_path FROM step_runs WHERE id='s1'"
    )[0]
    assert row["execution_group_id"] == "grp-1"
    assert row["group_mode"] == "sequential"
    assert row["group_path"] == "/testcase-api"
    assert store.query("PRAGMA foreign_key_check") == []
    store.close()


def test_m0015_run_controller_pid_forwards(tmp_path: Path) -> None:
    """0015 adds a nullable controller_pid without disturbing prior data."""
    store = Store.open_migrated(tmp_path / "tg.db", migrations=ALL_MIGRATIONS[:14])
    _insert_deterministic_run(store, "r1")
    with store.write() as conn:
        conn.execute(
            "INSERT INTO config_snapshots (id, resolved_json, source_map, created_at)"
            " VALUES ('c2', '{}', '{}', 'now')"
        )
        conn.execute(
            "INSERT INTO runs (id, experiment_name, kind, spec_json, plan_json, seed,"
            " status, environment_fingerprint, config_snapshot_id)"
            " VALUES ('r2', 'exp', 'deterministic', '{}', '{}', 1, 'running', 'env', 'c2')"
        )
    applied = store.migrate()
    assert "0015_run_controller_pid" in applied
    run_cols = {row["name"] for row in store.query("PRAGMA table_info(runs)")}
    assert "controller_pid" in run_cols
    assert store.query("SELECT controller_pid FROM runs WHERE id='r1'")[0]["controller_pid"] is None
    assert store.query("SELECT controller_pid FROM runs WHERE id='r2'")[0]["controller_pid"] is None
    with store.write() as conn:
        conn.execute("UPDATE runs SET controller_pid = 4242 WHERE id = 'r2'")
    assert store.query("SELECT controller_pid FROM runs WHERE id='r2'")[0]["controller_pid"] == 4242
    assert store.query("PRAGMA foreign_key_check") == []
    store.close()


def test_m0016_five_state_coverage_forwards(tmp_path: Path) -> None:
    """0016 adds the five-state columns to m5_coverage with legacy defaults."""
    store = Store.open_migrated(tmp_path / "tg.db", migrations=ALL_MIGRATIONS[:15])
    with store.write() as conn:
        conn.execute(
            "INSERT INTO m5_coverage (cell_key, target, fault_kind, execution_context,"
            " parameter_band, run_id, covered, extra_json)"
            " VALUES ('w|net.delay|prod|50ms', 'web-1', 'net.delay', 'prod', '50ms',"
            " 'r1', 1, '{}')"
        )
    applied = store.migrate()
    assert "0016_five_state_coverage" in applied
    assert store.schema_version == ALL_MIGRATIONS[-1].version
    cover_cols = {row["name"] for row in store.query("PRAGMA table_info(m5_coverage)")}
    assert {"state", "block_reason", "scaffold_tier", "updated_at", "verdict_json"} <= cover_cols
    row = store.query("SELECT * FROM m5_coverage WHERE cell_key = 'w|net.delay|prod|50ms'")[0]
    # Legacy row defaults: covered stays 1, five-state columns get defaults.
    assert row["covered"] == 1
    assert row["state"] == "covered"
    assert row["block_reason"] == ""
    assert row["scaffold_tier"] is None
    assert row["updated_at"] == ""
    assert row["verdict_json"] == "{}"
    indexes = {r["name"] for r in store.query("PRAGMA index_list(m5_coverage)")}
    assert "idx_m5_coverage_state" in indexes
    assert store.query("PRAGMA foreign_key_check") == []
    store.close()
