"""The durable fabric journal is created by the **production** migration chain.

Why this file exists
--------------------

Plan 03 Phase 4's ``FABRIC_JOURNAL_MIGRATION`` was defined in
:mod:`mayhem.infra.fabric_journal` but never appeared in
:data:`mayhem.infra.migrations.ALL_MIGRATIONS`. Every test of the journal
therefore built its database with a *hand-spliced* list,
``(*ALL_MIGRATIONS, FABRIC_JOURNAL_MIGRATION)`` — a fixture constructed to fit
the code under test. That arrangement proved the row discipline (digest check,
index-column check, duplicate refusal) and proved nothing about whether a
deployment had the table, because a fixture that splices the migration in cannot
fail for want of it. In production the chain stopped at ``M0032_HA_DR`` and the
first real dispatch write failed with ``no such table``.

So the tests here take ``ALL_MIGRATIONS`` exactly as the application takes it:
:meth:`~mayhem.infra.store.Store.open_migrated` is called with no ``migrations``
argument, so the default — the production tuple — is what migrates the database.

The negative control is the point
---------------------------------

A positive test alone would pass for the wrong reason. If the table were never
needed, or if it were created by some other fixture, "it exists after
migration" proves nothing about who created it. So each positive assertion is
paired with one that can only hold if registration is what made it true:
:meth:`test_the_table_is_absent_at_version_32` migrates the same production chain
*down* to the previous head and asserts the table is genuinely gone. Together the
two pin the table's existence to version 33 of this chain — remove the
registration and both fail, from opposite directions.

What is deliberately not asserted
---------------------------------

No claim is made here about *behaviour* — append semantics, digest enforcement
and duplicate refusal belong to :mod:`tests.unit.test_fabric_evidence`, which
exercises them against the controller's real ``JournalEntry`` types. This file
asserts one thing: the table is reachable from a migrated production database,
and the schema constraints that make the journal append-only are actually
installed by the production chain rather than by a fixture.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from mayhem.infra.fabric_journal import (
    FABRIC_JOURNAL_MIGRATION,
    FABRIC_JOURNAL_TABLE,
    FABRIC_JOURNAL_VERSION,
    FabricJournalDuplicateEntryError,
    FabricJournalRow,
    FabricJournalTable,
)
from mayhem.infra.migrations import ALL_MIGRATIONS
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

#: The id the journal took and the head it leaves behind. Both are literals on
#: purpose: the whole claim under test is "the chain head is now this", which a
#: ``len(ALL_MIGRATIONS)``-relative assertion could not distinguish from a chain
#: that had merely grown.
JOURNAL_VERSION = 33
PRIOR_HEAD = JOURNAL_VERSION - 1

NOW = "2026-03-05T09:00:00+00:00"
LATER = "2026-03-05T09:00:45+00:00"

RUN_ID = "r-registration"
STEP_ID = "s-1"
COMMAND_ID = "fc-1"


def _claim(run_id: str = RUN_ID, step_id: str = STEP_ID, command_id: str = COMMAND_ID) -> dict:
    """A minimal ``claimed`` envelope in the shape ``DispatchClaim`` serialises to.

    A plain dict rather than the controller's ``DispatchClaim``, deliberately: this
    file is about *migration*, and building the row from the same literal JSON the
    model digests keeps it from needing signature machinery it has no opinion
    about. The digest and index-column checks in ``FabricJournalRow.of`` still run
    in full — that is the model enforcing itself, not a fixture agreeing with it.
    """
    return {
        "command": {
            "command_id": command_id,
            "run_id": run_id,
            "step_id": step_id,
            "fencing_token": {"epoch": 1, "scope": "control-plane"},
            "plan_digest": "d" * 64,
            "target": "pod/web-0",
        },
        "controller_id": "ctl-a",
        "claimed_at": NOW,
    }


def _claim_row(
    run_id: str = RUN_ID,
    step_id: str = STEP_ID,
    command_id: str = COMMAND_ID,
    claimed_at: str = NOW,
) -> FabricJournalRow:
    return FabricJournalRow.of(
        run_id=run_id,
        step_id=step_id,
        phase="claimed",
        command_id=command_id,
        epoch=1,
        entry=_claim(run_id, step_id, command_id),
        controller_id="ctl-a",
        recorded_at=claimed_at,
    )


@pytest.fixture
def store(tmp_path: Path) -> Store:
    """A store migrated by the **production** chain — no spliced list.

    The absence of a ``migrations=`` argument is the assertion. Every fixture in
    this repo that wants a custom chain passes one explicitly; this one does not,
    so it tracks whatever ``ALL_MIGRATIONS`` says at import time.
    """
    return Store.open_migrated(tmp_path / "registration.db")


class TestRegistration:
    def test_the_journal_migration_is_in_the_production_chain(self) -> None:
        # Identity, not just equality: a re-spelled copy of the same DDL would
        # pass an equality check while the journal's own object stayed unregistered,
        # and the drift this file guards against is exactly that second spelling.
        assert any(m is FABRIC_JOURNAL_MIGRATION for m in ALL_MIGRATIONS), (
            "FABRIC_JOURNAL_MIGRATION is not in ALL_MIGRATIONS; the journal "
            "table exists only where a caller splices the migration in, so no "
            "real deployment has it"
        )
        assert FABRIC_JOURNAL_MIGRATION.version == JOURNAL_VERSION
        assert FABRIC_JOURNAL_MIGRATION.name == "fabric_journal"

    def test_the_journal_migration_is_the_chain_head(self) -> None:
        # Last *by version*, and last in tuple order. The migrator requires
        # strictly increasing versions as it walks the tuple, so a registration
        # placed after a higher id would be a startup failure, not a silent
        # misordering — this asserts the placement is the working one.
        head = max(ALL_MIGRATIONS, key=lambda m: m.version)
        assert head is FABRIC_JOURNAL_MIGRATION
        assert ALL_MIGRATIONS[-1] is FABRIC_JOURNAL_MIGRATION
        assert len(ALL_MIGRATIONS) == FABRIC_JOURNAL_VERSION

    def test_the_chain_is_contiguous_ascending_and_duplicate_free(self) -> None:
        versions = [m.version for m in ALL_MIGRATIONS]
        assert versions == list(range(1, JOURNAL_VERSION + 1))
        assert len(set(versions)) == len(versions), "duplicate migration version"
        assert ALL_MIGRATIONS[-1].migration_id == "0033_fabric_journal"


class TestProductionMigratedDatabase:
    def test_the_journal_table_exists_at_the_production_head(self, store: Store) -> None:
        assert store.schema_version == JOURNAL_VERSION
        assert FabricJournalTable(store).table_exists() is True
        tables = {
            str(row["name"])
            for row in store.query(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        assert FABRIC_JOURNAL_TABLE in tables

    def test_the_journal_is_usable_on_a_production_migrated_database(self, store: Store) -> None:
        """A row written and read back, with no fixture having created the table."""
        journal = FabricJournalTable(store)
        assert journal.count() == 0

        sequence = journal.append(_claim_row())

        assert sequence == 1
        assert journal.count(RUN_ID) == 1
        stored = journal.rows(RUN_ID)
        assert len(stored) == 1
        assert stored[0].command_id == COMMAND_ID
        assert stored[0].step_id == STEP_ID
        assert stored[0].phase == "claimed"
        # The read path re-derives the digest and the index columns, so a
        # successful read here is the integrity check passing on production DDL.
        stored[0].check_payload()
        store.close()

    def test_a_second_claim_for_one_command_is_refused_by_the_production_schema(
        self, store: Store
    ) -> None:
        """The UNIQUE index ships with the migration, so append-only is schema-backed.

        If the registration had been replaced by an inline re-spelling that dropped
        the index, this would raise ``sqlite3.OperationalError`` on the second
        insert instead of the typed refusal.
        """
        journal = FabricJournalTable(store)
        journal.append(_claim_row())
        with pytest.raises(FabricJournalDuplicateEntryError):
            journal.append(_claim_row())
        assert journal.count(RUN_ID) == 1
        store.close()

    def test_rows_for_one_run_are_returned_in_append_order(self, store: Store) -> None:
        journal = FabricJournalTable(store)
        journal.append(_claim_row(command_id="fc-1"))
        journal.append(_claim_row(step_id="s-2", command_id="fc-2"))
        journal.append(_claim_row(step_id="s-1", command_id="fc-3"))

        assert [row.command_id for row in journal.rows(RUN_ID)] == ["fc-1", "fc-2", "fc-3"]
        assert [row.command_id for row in journal.rows(RUN_ID, "s-1")] == ["fc-1", "fc-3"]
        store.close()

    def test_the_run_index_selects_only_that_runs_rows(self, store: Store) -> None:
        journal = FabricJournalTable(store)
        journal.append(_claim_row(run_id="r-a"))
        journal.append(_claim_row(run_id="r-b"))

        assert [row.run_id for row in journal.rows("r-a")] == ["r-a"]
        assert journal.count("r-b") == 1
        assert journal.count() == 2
        store.close()


class TestNegativeControl:
    """The control that makes the positive tests mean something.

    Without these, "the table exists after migrating the production chain" could
    be satisfied by a schema that never needed version 33 at all. The table is
    therefore shown to be genuinely absent at the previous head of the *same*
    chain, and genuinely re-created by applying version 33 and nothing else.
    """

    def test_the_table_is_absent_at_version_32(self, store: Store) -> None:
        journal = FabricJournalTable(store)
        assert journal.table_exists() is True

        reversed_ids = store.migrate_down(PRIOR_HEAD)

        assert reversed_ids == ["0033_fabric_journal"]
        assert store.schema_version == PRIOR_HEAD
        assert journal.table_exists() is False
        assert FABRIC_JOURNAL_TABLE not in {
            str(row["name"])
            for row in store.query(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        store.close()

    def test_the_journal_writes_are_refused_while_the_table_is_absent(
        self, store: Store
    ) -> None:
        """What an un-migrated deployment actually experiences.

        This is the failure the registration removes: not a degraded read, but an
        insert against a table that does not exist. Asserting it here means the
        positive test cannot be passing for free.
        """
        store.migrate_down(PRIOR_HEAD)
        with pytest.raises(Exception, match="fabric_journal"):
            FabricJournalTable(store).append(_claim_row())
        store.close()

    def test_reapplying_the_head_restores_exactly_the_journal(self, store: Store) -> None:
        journal = FabricJournalTable(store)
        journal.append(_claim_row())
        store.migrate_down(PRIOR_HEAD)
        assert journal.table_exists() is False

        assert store.migrate() == ["0033_fabric_journal"]

        assert store.schema_version == JOURNAL_VERSION
        assert journal.table_exists() is True
        # The down path dropped the rows with the table; an append-only journal
        # that survived its own rollback would be a journal with two histories.
        assert journal.count() == 0
        journal.append(_claim_row())
        assert journal.count() == 1
        store.close()

    def test_the_down_path_leaves_the_neighbouring_migration_intact(
        self, store: Store
    ) -> None:
        """Rolling back 33 must not disturb 32.

        ``migrate_down`` reverses every applied version above its target, so a
        wrong target would take ``ha_dr``'s tables with it. Asserted on the names
        rather than on the returned id list alone, because the id list says what
        was *attempted* and the table set says what survived.
        """
        store.migrate_down(PRIOR_HEAD)
        tables = {
            str(row["name"])
            for row in store.query(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        assert {"control_plane_leaders", "control_plane_step_fences"} <= tables
        assert "agent_command_nonces" in tables
        store.close()
