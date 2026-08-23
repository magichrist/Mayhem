# 0007. Persistence: SQLite WAL with a Single-Writer Repository Behind a Storage Protocol

- **Date:** 2026-08-23
- **Status:** Accepted

## Context

Tgondi must durably record experiments, steps, fault invocations, leases, tool runs, observations,
evaluations, recovery events, agent state, config snapshots, and Maniac decisions — today on a
single controller machine, potentially multi-tenant later. The spec mandates SQLite first, Postgres
later without changing the domain model. Multiple agents report concurrently.

## Options considered

1. **PostgreSQL from day one.** Rejected: an external database server is a deployment tax for a
   single-controller OSS tool; contradicts zero-dependency posture.
2. **SQLite accessed ad hoc from anywhere.** Rejected: concurrent writers corrupt throughput;
   schema logic scatters across layers.
3. **ORM (SQLAlchemy) + Alembic.** Rejected for MVP: heavyweight for a schema this size and adds a
   migration framework dependency before the schema stabilizes.
4. **SQLite (WAL) + single-writer repository service + plain-SQL numbered migrations behind a
   `Storage` Protocol.** Chosen.

## Decision

- Only the controller writes; agents stream events upward over their channel — SQLite's concurrency
  limits never meet real contention.
- WAL mode enabled; all SQL lives in `persistence/sqlite.py`; the rest of the system depends on the
  `Storage` Protocol (async methods). Portability rule: no SQLite-dialect constructs outside that
  module beyond WAL pragmas set there.
- Migrations: numbered plain-SQL files in `persistence/migrations/` applied by a ~100-line runner
  tracking `schema_migrations(version)`; forward-only.
- Full DDL: [reference/sqlite-schema.md](../reference/sqlite-schema.md).

## Consequences

- **Positive:** zero operational footprint; file-level backup/inspection (`sqlite3 state.db`);
  Postgres port later is a new `Storage` implementation, not a refactor of callers.
- **Negative / accepted trade-offs:** no cross-controller HA or remote dashboards directly on the
  DB (a future reporting layer reads via API, not by attaching to the DB file); hand-written SQL
  requires care — mitigated by the small table count and integration tests covering migrations.
