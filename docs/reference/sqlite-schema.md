# SQLite Schema Reference

Single-writer controller storage in WAL mode ([ADR-0007](../adr/0007-sqlite-wal-single-writer-persistence.md)).
Managed by the migration runner; DDL below is v1 canonical. All timestamps ISO-8601 UTC text;
JSON columns validated by domain schemas on read.

---

```sql
-- Environments & runs -------------------------------------------------------
CREATE TABLE config_snapshots (
  id TEXT PRIMARY KEY,                -- hash of resolved config
  resolved_json TEXT NOT NULL,        -- full merged config
  source_map TEXT NOT NULL,           -- key → layer that supplied it
  created_at TEXT NOT NULL
);

CREATE TABLE topology_snapshots (
  id TEXT PRIMARY KEY,
  run_id TEXT REFERENCES runs(id),
  graph_json TEXT NOT NULL,           -- TopologyGraph
  drift_report TEXT NOT NULL,
  fingerprint TEXT NOT NULL
);

CREATE TABLE runs (
  id TEXT PRIMARY KEY,                -- r-YYYYMMDD-HHMMSS-xxxx
  experiment_name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('deterministic','random')),
  spec_json TEXT NOT NULL,
  plan_json TEXT NOT NULL,
  seed INTEGER,                       -- NULL = derived & recorded here
  status TEXT NOT NULL CHECK (status IN
    ('created','planning','validated','running','recovering',
     'completed','failed','aborted')),
  environment_fingerprint TEXT NOT NULL,
  config_snapshot_id TEXT NOT NULL REFERENCES config_snapshots(id),
  topology_snapshot_id TEXT REFERENCES topology_snapshots(id),
  started_at TEXT, ended_at TEXT,
  summary_md TEXT                     -- final journal block
);
CREATE INDEX idx_runs_status ON runs(status);
CREATE INDEX idx_runs_started ON runs(started_at DESC);

-- Steps & faults -------------------------------------------------------------
CREATE TABLE step_runs (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id),
  seq INTEGER NOT NULL,
  parent_step_id TEXT REFERENCES step_runs(id),   -- parallel branches
  action_type TEXT NOT NULL,
  action_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN
    ('pending','running','completed','failed','skipped','cancelled')),
  started_at TEXT, ended_at TEXT,
  error TEXT
);

CREATE TABLE fault_invocations (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id),
  step_run_id TEXT NOT NULL REFERENCES step_runs(id),
  fault_id TEXT NOT NULL,             -- e.g. net.latency (FK to catalog at compile time)
  targets_json TEXT NOT NULL,
  params_json TEXT NOT NULL,
  backend TEXT NOT NULL,              -- resolved backend/tool
  lease_id TEXT UNIQUE NOT NULL REFERENCES fault_leases(id)
);

CREATE TABLE fault_leases (
  id TEXT PRIMARY KEY,                -- l-<hex>
  state TEXT NOT NULL CHECK (state IN
    ('pending','active','releasing','released','expired','orphaned','dirty')),
  owner_agent TEXT NOT NULL,
  undo_json TEXT NOT NULL,            -- write-ahead: set BEFORE activation
  verify_json TEXT NOT NULL,
  ttl_seconds INTEGER NOT NULL,
  expires_at TEXT NOT NULL,
  injected_at TEXT, released_at TEXT,
  release_mechanism TEXT,             -- normal|watchdog|janitor|manual
  escalation_notes TEXT
);
CREATE INDEX idx_leases_state ON fault_leases(state);

CREATE TABLE recovery_records (
  id TEXT PRIMARY KEY,
  lease_id TEXT NOT NULL REFERENCES fault_leases(id),
  attempt INTEGER NOT NULL,
  mechanism TEXT NOT NULL,
  undo_results_json TEXT NOT NULL,    -- per-step outcomes
  verified BOOLEAN NOT NULL,
  at TEXT NOT NULL
);

-- Tools & agents --------------------------------------------------------------
CREATE TABLE tool_runs (
  id TEXT PRIMARY KEY,                -- art-… artifact ref for full output
  invocation_ref TEXT,                -- lease or load id
  argv_digest TEXT NOT NULL,
  argv_json TEXT NOT NULL,            -- audit: recorded before exec (see audit_log)
  env_digest TEXT NOT NULL,
  host TEXT NOT NULL,
  exit_code INTEGER,
  duration_ms INTEGER,
  truncated BOOLEAN NOT NULL DEFAULT 0,
  stdout_ref TEXT, stderr_ref TEXT    -- artifact store refs
);

CREATE TABLE agent_states (
  id TEXT PRIMARY KEY,
  host TEXT NOT NULL,
  roles_json TEXT NOT NULL,
  capabilities_json TEXT NOT NULL,    -- CapabilityReport
  state TEXT NOT NULL CHECK (state IN ('ready','busy','dead','retired')),
  last_heartbeat TEXT NOT NULL
);

-- Observation -----------------------------------------------------------------
CREATE TABLE events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT REFERENCES runs(id),
  ts TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE INDEX idx_events_run_ts ON events(run_id, ts);

CREATE TABLE steady_state_evaluations (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id),
  check_id TEXT NOT NULL,
  phase TEXT NOT NULL CHECK (phase IN ('pre','during','post')),
  passed BOOLEAN NOT NULL,
  measured_json TEXT NOT NULL,
  expectation_json TEXT NOT NULL,
  evaluated_at TEXT NOT NULL
);

-- Maniac ----------------------------------------------------------------------
CREATE TABLE maniac_decisions (
  id TEXT PRIMARY KEY,
  run_id TEXT UNIQUE REFERENCES runs(id),
  candidates_json TEXT NOT NULL,      -- [{fault, score_components, total}]
  weights_json TEXT NOT NULL,
  rng_state TEXT NOT NULL,
  chosen_plan_json TEXT NOT NULL,
  decided_at TEXT NOT NULL
);
```

## Conventions

| Rule | Detail |
|---|---|
| IDs | prefixed human-sortable (`r-`, `s-`, `l-`, `art-`) |
| Writes | controller-only; single connection + WAL; busy_timeout 5s |
| Migrations | forward-only numbered scripts; every migration tested against empty DB and all prior snapshots ([testing-strategy](../architecture/testing-strategy.md) §5) |
| JSON | read paths validate via pydantic — corrupt rows fail loudly, not silently |
| Retention | `tgondi db prune --older-than 90d` deletes artifacts first, then rows |
