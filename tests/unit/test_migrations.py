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
    assert store.schema_version == 4

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


def test_migrations_are_strictly_increasing() -> None:
    versions = [m.version for m in ALL_MIGRATIONS]
    assert versions == sorted(versions)
    assert len(versions) == len(set(versions))
    assert versions[0] == 1
