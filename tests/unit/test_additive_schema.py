"""feat-5 §0 schema-additive guard (plan-feat-5 Phase A2).

Snapshot of migration versions and the ``m5_coverage`` / ``runs`` rows that
0.6 depends on. Any change to ``ALL_MIGRATIONS`` must be *additive*:

* new versions are appended after the last existing version;
* every new migration ships ``down_statements`` (reversibility);
* the ``m5_coverage`` state column and the ``runs`` identity columns survive.

The snapshot is taken from a *migrated store* (sqlite ``PRAGMA table_info``),
not from static DDL text — DDL refactors (table rename + copy) in later
migrations can't silently drop columns that 0.6 reads. A hand-edited
temporary disallowed migration (e.g. a ``DROP`` without a new version) fails
this file's snapshot diff.
"""

from __future__ import annotations

from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

# Canonical version snapshot — new versions only ever append.
VERSION_SNAPSHOT: tuple[int, ...] = tuple(sorted(m.version for m in ALL_MIGRATIONS))

# Canonical migration names snapshot (order matters).
NAME_SNAPSHOT: tuple[str, ...] = tuple(m.name for m in ALL_MIGRATIONS)

# Columns 0.6 reads from these two tables (m5_coverage / m5_runs).
M5_COVERAGE_COLUMNS_SNAPSHOT: frozenset[str] = frozenset({
    "cell_key",
    "target",
    "fault_kind",
    "execution_context",
    "parameter_band",
    "run_id",
    "covered",
    "extra_json",
    "state",
    "block_reason",
    "scaffold_tier",
    "updated_at",
    "verdict_json",
})

M5_RUNS_COLUMNS_SNAPSHOT: frozenset[str] = frozenset({
    "id",
    "experiment_name",
    "spec_json",
    "plan_json",
    "seed",
    "status",
    "environment_fingerprint",
    "config_snapshot_id",
    "started_at",
    "ended_at",
    "description",
    "verdict",
    "tags_json",
    "extra_json",
})


def _migrated_schema() -> dict[str, frozenset[str]]:
    """Run all migrations in-memory and return per-table column sets."""
    store = Store.open_migrated(":memory:")
    rows = store.query(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    )
    tables: dict[str, set[str]] = {}
    for row in rows:
        for col_row in store.query(f'PRAGMA table_info("{row[0]}")'):
            tables.setdefault(str(row[0]), set()).add(str(col_row[1]))
    store.close()
    return {name: frozenset(cols) for name, cols in tables.items()}


def test_migration_versions_are_contiguous_ascending() -> None:
    assert VERSION_SNAPSHOT == tuple(range(1, len(VERSION_SNAPSHOT) + 1)), (
        "migration versions must start at 1 and be contiguous; a removal or "
        "reorder breaks the additive contract."
    )
    assert len(VERSION_SNAPSHOT) == len(set(VERSION_SNAPSHOT)), "no duplicate versions"


def test_every_new_migration_has_down_statements() -> None:
    """Forward-only migrations are forbidden for 0.6 — reversibility is
    the escape hatch that keeps additive changes safe."""
    for migration in ALL_MIGRATIONS:
        if migration.version > 16:
            assert migration.down_statements, (
                f"migration {migration.migration_id} has no down_statements — "
                "additive schema changes must be reversible."
            )


def test_migrated_schema_keeps_m5_coverage_columns() -> None:
    schema = _migrated_schema()
    assert "m5_coverage" in schema, "m5_coverage table is gone"
    assert M5_COVERAGE_COLUMNS_SNAPSHOT <= schema["m5_coverage"], (
        "m5_coverage lost 0.6-needed columns: "
        f"{sorted(M5_COVERAGE_COLUMNS_SNAPSHOT - schema['m5_coverage'])}"
    )


def test_migrated_schema_keeps_m5_runs_columns() -> None:
    schema = _migrated_schema()
    assert "m5_runs" in schema, "m5_runs table is gone"
    assert M5_RUNS_COLUMNS_SNAPSHOT <= schema["m5_runs"], (
        "m5_runs lost 0.6-needed columns: "
        f"{sorted(M5_RUNS_COLUMNS_SNAPSHOT - schema['m5_runs'])}"
    )


def test_name_snapshot_is_stable() -> None:
    """The exact ordered name sequence is part of the contract snapshot."""
    assert NAME_SNAPSHOT == (
        "initial",
        "lease_context",
        "campaigns_and_observations",
        "drill_run_kind",
        "step_run_bypass_status",
        "runtime_identity",
        "fault_groups",
        "failed_to_apply",
        "fork_atomicity",
        "network_path",
        "m5_run_outcome",
        "m5_coverage",
        "m4_success_observability",
        "m4_observability_decisions",
        "run_controller_pid",
        "five_state_coverage",
    ), "migration name sequence drifted from the snapshot — append-only."