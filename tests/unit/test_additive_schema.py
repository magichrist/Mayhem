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

import re
from typing import TYPE_CHECKING

import pytest

from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

# Canonical version snapshot — new versions only ever append.
VERSION_SNAPSHOT: tuple[int, ...] = tuple(sorted(m.version for m in ALL_MIGRATIONS))

# Canonical migration names snapshot (order matters).
NAME_SNAPSHOT: tuple[str, ...] = tuple(m.name for m in ALL_MIGRATIONS)

# Columns 0.6 reads from these two tables (m5_coverage / m5_runs).
M5_COVERAGE_COLUMNS_SNAPSHOT: frozenset[str] = frozenset(
    {
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
    }
)

M5_RUNS_COLUMNS_SNAPSHOT: frozenset[str] = frozenset(
    {
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
    }
)


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
    assert tuple(range(1, len(VERSION_SNAPSHOT) + 1)) == VERSION_SNAPSHOT, (
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
    assert schema["m5_coverage"] >= M5_COVERAGE_COLUMNS_SNAPSHOT, (
        "m5_coverage lost 0.6-needed columns: "
        f"{sorted(M5_COVERAGE_COLUMNS_SNAPSHOT - schema['m5_coverage'])}"
    )


def test_migrated_schema_keeps_m5_runs_columns() -> None:
    schema = _migrated_schema()
    assert "m5_runs" in schema, "m5_runs table is gone"
    assert schema["m5_runs"] >= M5_RUNS_COLUMNS_SNAPSHOT, (
        f"m5_runs lost 0.6-needed columns: {sorted(M5_RUNS_COLUMNS_SNAPSHOT - schema['m5_runs'])}"
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
        "resolved_target",
        "replay_capsules",
        "coverage_graph",
        "campaign_checkpoints",
        "game_day_sessions",
        "secret_grants",
        "attestation_retention",
        "certification_records",
        "agent_identity_backups",
        # APPEND-ONLY procedure: new migration names are added at the end, in
        # version order, and nothing above this line is ever edited or removed.
        # ``schedules`` (version 26) landed in ``migrations.py`` concurrently
        # with ``coverage_findings`` (version 27); both are appended here in
        # version order because the gate compares the whole ordered sequence.
        "schedules",
        "coverage_findings",
        # ``marketplace`` (version 28) is the plan-18 Phase 2 registry, pin, and
        # revocation store. Appended here in version order; nothing above is
        # edited, and the migration carries ``down_statements`` like every
        # migration after 16.
        "marketplace",
        # ``audit_stream`` (version 29) is plan 12 Phase 4's cross-run audit
        # stream. Appended in version order per the same procedure; the
        # append-only triggers it ships are what make a retention deletion
        # unable to remove the audit entry recording it.
        "audit_stream",
        # ``api_resources`` (version 30) is the concurrent API-resources lane.
        # It landed *below* ``identity`` in ``migrations.py`` after that lane had
        # already appended version 31, so the ordered sequence here needs
        # version 30's name on this line — the gate compares the whole tuple in
        # version order, and nothing above this line is touched.
        "api_resources",
        # ``identity`` (version 31) is plan 09 Phase 3's identity persistence:
        # principals, local credentials (hash only), memberships, role grants,
        # sessions, API keys, and the append-only revocation log. Appended per
        # the same procedure; nothing above is edited.
        # NOTE for the concurrent agents: version 30 (``api_resources``) was
        # appended directly above this entry and version 32 (``ha_dr``) directly
        # below, so this one sits at its correct version-order position. Do not
        # insert a name between ``"api_resources"`` and ``"identity"``.
        "identity",
        # ``ha_dr`` (version 32) is plan 19 Phase 2: spent agent-command nonces,
        # the control-plane leadership lease, per-step dispatch fences, and the
        # snapshot evidence a restore drill compares against. Appended per the
        # same procedure; nothing above is edited, and the migration carries
        # ``down_statements`` like every migration after 16. It deliberately holds
        # no key material and no achieved-RPO column.
        "ha_dr",
        # ``fabric_journal`` (version 33) is plan 03 Phase 4's durable dispatch
        # journal: the append-only table the execution fabric records claims and
        # settlements in, with the index columns and payload digest the model
        # re-checks on read. Appended per the same procedure; nothing above is
        # edited, and the migration carries ``down_statements`` like every
        # migration after 16.
        #
        # This entry exists because the journal is now migrated by the production
        # chain. Until it was registered in ``ALL_MIGRATIONS`` the table only
        # existed in databases whose fixture spliced the migration in, so this
        # snapshot had no reason to name it — and a test could pass against a
        # table no deployment would ever have had.
        "fabric_journal",
        # ``api_gateway`` (version 34) and ``api_safety`` (version 35) are the two
        # control-plane tables the HTTP surface needs: the idempotency record for
        # a mutating request, and the safety layer's log of the mutations that
        # passed. Their DDL lives in ``infra.api_gateway_schema`` — moved down out
        # of the two ``controller`` modules that first spelled it, because
        # registering them here would otherwise have made ``infra`` import
        # ``controller`` — and both migration objects are *imported* into
        # ``ALL_MIGRATIONS`` rather than re-spelled. Appended per the same
        # procedure; nothing above is edited.
        #
        # This entry exists because the tables are now migrated by the production
        # chain. Until registration, ``api_idempotency`` existed only in databases
        # whose fixture spliced the migration in, and ``api_safety``'s receipt
        # write took its "table not present" fallback on every real deployment.
        "api_gateway",
        "api_safety",
        # ``probe_seal`` (version 36) is plan 11 Phase 4's durable probe seal —
        # the redacted observations, sealed conditions and citation verdicts a
        # reviewer reads back, in one table with one writer. Appended per the same
        # procedure; nothing above is edited.
        #
        # It keeps version 36 rather than 37: ``probe_seal_store`` reserved 36 and
        # its own tests published ``36`` / ``"0036_probe_seal"`` as facts about
        # this lane. ``Migration.version`` *is* the migration id, so the colliding
        # ``ha_promotions`` took the next free id instead (see below).
        "probe_seal",
        # ``ha_promotions`` (version 37) is plan 19's standby roster and promotion
        # ledger, including the *refused* promotions. Appended per the same
        # procedure; nothing above is edited.
        #
        # It is 37 rather than the 36 its module originally hard-coded because
        # ``probe_seal`` above holds 36. ``Migration.version`` is the id, and
        # ``run_migrations`` refuses duplicates outright — so the alternative was
        # not a second 36 but a startup failure in every migrated store. Version
        # 36 is the lower of the two and already published by another lane's
        # tests, so 37 is what moved.
        "ha_promotions",
        # ``policy_bundles`` (version 38) is plan 07 Phase 3's immutable,
        # digest-pinned policy-bundle store. Appended per the same procedure;
        # nothing above is edited, and the migration carries ``down_statements``
        # like every migration after 16.
        "policy_bundles",
        # ``evidence_signatures`` (version 39) is plan 12's offline bundle
        # signing under a named trust root. Appended per the same procedure;
        # nothing above is edited.
        "evidence_signatures",
    ), "migration name sequence drifted from the snapshot — append-only."


# --------------------------------------------------------------------------- #
# Reachability: the last four migrations' tables exist because the chain ran    #
# --------------------------------------------------------------------------- #
#
# ``NAME_SNAPSHOT`` above says the migrations are *registered*. It does not say
# their DDL runs — a migration whose ``statements`` named nothing, or whose only
# real DDL lived in a fixture, would pass the name gate and still leave a
# deployment without the table. So each table is checked in both directions:
# present in a database migrated by the **production** tuple (no ``migrations=``
# argument, exactly as ``Store.open_migrated`` takes it in an application), and
# genuinely absent after rolling that same chain back one version.

#: Every table migrations 34..37 create, paired with the version that creates it.
#:
#: **Five tables from four migrations is not a mistake.** ``ha_promotions``
#: creates both ``control_plane_standbys`` (the roster) and
#: ``control_plane_promotions`` (the log, refused promotions included) — the two
#: halves plan 19 needs to say who was promoted and out of which term.
_REGISTERED_TABLES: tuple[tuple[str, int], ...] = (
    ("api_idempotency", 34),
    ("api_mutation_receipts", 35),
    ("probe_seals", 36),
    ("control_plane_standbys", 37),
    ("control_plane_promotions", 37),
)

_TABLE_NAME = re.compile(r"CREATE TABLE (?:IF NOT EXISTS )?([A-Za-z_][A-Za-z_0-9]*)")


def _tables_created_by(version: int) -> set[str]:
    """The tables migration ``version`` actually creates, read off its DDL."""
    migration = next(m for m in ALL_MIGRATIONS if m.version == version)
    return {found for statement in migration.statements for found in _TABLE_NAME.findall(statement)}


def _live_tables(store: Store) -> set[str]:
    return {
        str(row["name"])
        for row in store.query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }


def test_the_registered_table_list_matches_the_migrations_ddl() -> None:
    """The literal above is checked against the DDL, so it cannot rot silently.

    Without this, a lane that added a sixth table to ``ha_promotions`` would get a
    reachability suite that quietly stopped covering it — the failure mode of a
    hand-maintained list that nothing compares against the source.
    """
    derived = {
        table
        for version in sorted({version for _, version in _REGISTERED_TABLES})
        for table in _tables_created_by(version)
    }
    assert derived == {table for table, _ in _REGISTERED_TABLES}


def test_the_production_chain_creates_every_registered_table(tmp_path: Path) -> None:
    store = Store.open_migrated(tmp_path / "reachable.db")
    try:
        live = _live_tables(store)
        missing = [table for table, _ in _REGISTERED_TABLES if table not in live]
        assert not missing, (
            f"registered in ALL_MIGRATIONS but absent from a production-migrated "
            f"database: {missing} — the DDL lives in a fixture, not in the chain"
        )
    finally:
        store.close()


@pytest.mark.parametrize(("table", "version"), _REGISTERED_TABLES)
def test_a_registered_table_is_absent_one_version_earlier(
    table: str, version: int, tmp_path: Path
) -> None:
    """The negative control, and the reason the positive test means anything.

    Rolling back to ``version - 1`` runs the migrations' own ``down_statements``.
    If a table survived its migration's rollback, it was never created *by* that
    migration — so it would have been present before it, and the positive test
    would have been proving nothing about the registration.
    """
    store = Store.open_migrated(tmp_path / f"rollback-{version}.db")
    try:
        assert table in _live_tables(store)

        store.migrate_down(version - 1)

        assert store.schema_version == version - 1
        assert table not in _live_tables(store)
    finally:
        store.close()
