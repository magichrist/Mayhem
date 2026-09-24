# SQLite schema reference

The store is created and migrated by `src/mayhem/infra/migrations.py` and `src/mayhem/infra/migrator.py`.

## Core tables

- `config_snapshots`: canonical effective configuration JSON, source provenance, and creation time.
- `runs`: run lifecycle state, plan/config/topology snapshot ids, environment fingerprint, and timestamps.
- `step_runs`: ordered execution steps, status, detail, and measured observations.
- `fault_invocations`: injected fault records and compensation state.
- `recovery_records`: undo and verification evidence.
- `lease_snapshots`: durable Kubernetes lease evidence.
- `events`: append-only run event journal.

Schema changes must be expressed as migrations and exercised by unit tests. Do not treat this page as a substitute for the migration source.
