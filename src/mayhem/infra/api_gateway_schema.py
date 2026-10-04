"""DDL for the two control-plane tables the HTTP surface needs: versions 34 and 35.

Why this module exists, and why it lives here
--------------------------------------------

Both tables were originally spelled inside ``mayhem/controller`` —
``api_gateway`` in :mod:`mayhem.controller.api_service` and ``api_safety`` in
:mod:`mayhem.controller.api_safety`. That is an upward dependency once the
migration is *registered*: :mod:`mayhem.infra.migrations` would have to import
``mayhem.controller``, and the layering contract
(``domain <- infra/toolkit/agents <- controller``) reports an upward edge as
``BROKEN``. So the DDL moved down here, beside the row models it creates, and
the two controller modules re-export the same objects — one spelling, no copy.

**One spelling is the point.** :mod:`mayhem.infra.migrations`'s own docstring
exists so that "the table the engine writes to and the table a deployment
migrates to" cannot drift: a second, hand-written copy of this DDL inside
``migrations.py`` would satisfy every test that compares an object for equality
while leaving the row models writing to a different schema. So the migration
objects are *imported* from here, whole, by ``ALL_MIGRATIONS`` — exactly as
:mod:`mayhem.infra.fabric_journal`'s journal is.

What these two tables are
-------------------------

``api_idempotency`` (version 34)
    One row per mutating request's idempotency key, holding the request
    fingerprint and the response envelope, so a retry of the same mutation
    replays the first answer instead of performing the action twice. The key is
    the primary key, which is what makes "a second, different request under the
    same key" a constraint violation rather than a silent overwrite.

``api_mutation_receipts`` (version 35)
    The append-only log of mutations that *passed* the safety layer, naming the
    principal, the command path and the plan digest they were authorized
    against. It is a log rather than a copy of the response because the claim it
    supports is "this mutation was authorized", and the response body is not
    what an incident review reads.

Both are **additive only**: neither takes a foreign key, neither drops or
rewrites a table from an earlier migration, and each ships a complete
``down_statements`` path in the child-first shape
:func:`~mayhem.infra.store.Store.migrate_down` expects. That is what makes them
safe to roll back in isolation, and what ``test_additive_schema``'s
reachability gate asserts from both directions.
"""

from __future__ import annotations

from typing import Final

from mayhem.infra.migrator import Migration

__all__ = [
    "API_GATEWAY_MIGRATION",
    "API_GATEWAY_VERSION",
    "API_SAFETY_MIGRATION",
    "API_SAFETY_VERSION",
    "DOWN_SQL",
    "IDEMPOTENCY_TABLE",
    "MIGRATION_SQL",
    "MUTATION_RECEIPT_TABLE",
]


# --------------------------------------------------------------------------- #
# 34 — the gateway's idempotency table                                            #
# --------------------------------------------------------------------------- #

#: The migration id reserved for the gateway. See
#: :data:`mayhem.infra.fabric_journal.FABRIC_JOURNAL_VERSION` for why an id is
#: reserved rather than chosen by renumbering anything already shipped.
API_GATEWAY_VERSION: Final[int] = 34

#: The table a mutating request's idempotency record lives in.
IDEMPOTENCY_TABLE: Final[str] = "api_idempotency"

#: Forward DDL. Kept as a module constant so ``migrations.py`` imports the
#: :class:`~mayhem.infra.migrator.Migration` object whole and a reader of
#: ``ALL_MIGRATIONS`` never has to diff a DDL string to see what a lane added.
MIGRATION_SQL: tuple[str, ...] = (
    f"""
    CREATE TABLE {IDEMPOTENCY_TABLE} (
        idempotency_key TEXT PRIMARY KEY,
        request_fingerprint TEXT NOT NULL,
        status INTEGER NOT NULL,
        envelope_json TEXT NOT NULL,
        recorded_at TEXT NOT NULL
    )
    """,
)

#: Reverse DDL. Child-first, the shape ``run_down_migrations`` expects.
DOWN_SQL: tuple[str, ...] = (f"DROP TABLE {IDEMPOTENCY_TABLE}",)

API_GATEWAY_MIGRATION = Migration(
    version=API_GATEWAY_VERSION,
    name="api_gateway",
    statements=MIGRATION_SQL,
    down_statements=DOWN_SQL,
)


# --------------------------------------------------------------------------- #
# 35 — the safety layer's mutation receipts                                       #
# --------------------------------------------------------------------------- #

#: The receipt table the safety layer appends to. Version 35, next after the
#: gateway's 34, because the receipt row records the outcome of a request the
#: idempotency table already has a row for — the chain says so.
MUTATION_RECEIPT_TABLE: Final[str] = "api_mutation_receipts"

API_SAFETY_VERSION: Final[int] = 35

SAFETY_MIGRATION_SQL: tuple[str, ...] = (
    f"""
    CREATE TABLE {MUTATION_RECEIPT_TABLE} (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        idempotency_key TEXT NOT NULL DEFAULT '',
        route TEXT NOT NULL,
        command_path TEXT NOT NULL,
        principal_id TEXT NOT NULL,
        plan_digest TEXT NOT NULL,
        recorded_at TEXT NOT NULL
    )
    """,
    f"CREATE INDEX idx_api_mutation_receipts_route "
    f"ON {MUTATION_RECEIPT_TABLE}(route)",
)

SAFETY_DOWN_SQL: tuple[str, ...] = (
    "DROP INDEX idx_api_mutation_receipts_route",
    f"DROP TABLE {MUTATION_RECEIPT_TABLE}",
)

API_SAFETY_MIGRATION = Migration(
    version=API_SAFETY_VERSION,
    name="api_safety",
    statements=SAFETY_MIGRATION_SQL,
    down_statements=SAFETY_DOWN_SQL,
)
