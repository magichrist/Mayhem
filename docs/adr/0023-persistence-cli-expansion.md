# 0023. Persistence & CLI Expansion

- **Date:** 2026-08-25
- **Status:** Accepted
- **Related:** [ADR-0007](0007-sqlite-single-writer.md) (SQLite store), [ADR-0022](0022-campaign-model.md) (campaign model)

## Context

The new campaign and observation models need durable storage. The existing SQLite schema has no tables for campaigns or observations. The CLI has no commands for managing campaigns.

## Decision

**Schema migration v3** adds two new tables:

```sql
CREATE TABLE campaigns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'draft',
    experiments_json TEXT NOT NULL DEFAULT '[]',
    window_json TEXT NOT NULL DEFAULT '{}',
    policy_json TEXT NOT NULL DEFAULT '{}',
    labels_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    run_id TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    data_json TEXT NOT NULL DEFAULT '{}',
    timestamp TEXT NOT NULL
);
```

Indexes on `campaigns(status)` and `observations(run_id, kind)`.

**CLI commands** under `mayhem campaign`:
- `list` — table view of all campaigns
- `describe <id>` — detailed view with experiment list
- `create <name> [-d desc] [-f config.json]` — create draft campaign
- `delete <id> [-y]` — delete draft/completed/aborted campaign (with confirmation)

Delete is restricted to non-running campaigns to prevent accidental data loss.

## Consequences

- Campaigns are persisted and queryable alongside runs and leases.
- Observations are append-only in SQLite with auto-increment IDs.
- The `campaign` CLI prefix resolves uniquely (no ambiguity with existing commands).
- Migration is forward-only — existing data is untouched.
