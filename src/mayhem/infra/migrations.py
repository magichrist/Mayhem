"""Schema v1 — canonical DDL from docs/reference/sqlite-schema.md."""

from mayhem.infra.migrator import Migration

M0001_INITIAL = Migration(
    version=1,
    name="initial",
    statements=(
        """
        CREATE TABLE config_snapshots (
            id TEXT PRIMARY KEY,
            resolved_json TEXT NOT NULL,
            source_map TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE topology_snapshots (
            id TEXT PRIMARY KEY,
            run_id TEXT REFERENCES runs(id),
            graph_json TEXT NOT NULL,
            drift_report TEXT NOT NULL,
            fingerprint TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE runs (
            id TEXT PRIMARY KEY,
            experiment_name TEXT NOT NULL,
            kind TEXT NOT NULL CHECK (kind IN ('deterministic','random')),
            spec_json TEXT NOT NULL,
            plan_json TEXT NOT NULL,
            seed INTEGER,
            status TEXT NOT NULL CHECK (status IN
                ('created','planning','validated','running','recovering',
                 'completed','failed','aborted')),
            environment_fingerprint TEXT NOT NULL,
            config_snapshot_id TEXT NOT NULL REFERENCES config_snapshots(id),
            topology_snapshot_id TEXT REFERENCES topology_snapshots(id),
            started_at TEXT,
            ended_at TEXT,
            summary_md TEXT
        )
        """,
        "CREATE INDEX idx_runs_status ON runs(status)",
        "CREATE INDEX idx_runs_started ON runs(started_at DESC)",
        """
        CREATE TABLE step_runs (
            id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(id),
            seq INTEGER NOT NULL,
            parent_step_id TEXT REFERENCES step_runs(id),
            action_type TEXT NOT NULL,
            action_json TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN
                ('pending','running','completed','failed','skipped','cancelled')),
            started_at TEXT,
            ended_at TEXT,
            error TEXT
        )
        """,
        """
        CREATE TABLE fault_leases (
            id TEXT PRIMARY KEY,
            state TEXT NOT NULL CHECK (state IN
                ('pending','active','releasing','released','expired','orphaned','dirty')),
            owner_agent TEXT NOT NULL,
            undo_json TEXT NOT NULL,
            verify_json TEXT NOT NULL,
            ttl_seconds REAL NOT NULL,
            expires_at TEXT NOT NULL,
            injected_at TEXT,
            released_at TEXT,
            release_mechanism TEXT,
            escalation_notes TEXT
        )
        """,
        "CREATE INDEX idx_leases_state ON fault_leases(state)",
        """
        CREATE TABLE fault_invocations (
            id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(id),
            step_run_id TEXT NOT NULL REFERENCES step_runs(id),
            fault_id TEXT NOT NULL,
            targets_json TEXT NOT NULL,
            params_json TEXT NOT NULL,
            backend TEXT NOT NULL,
            lease_id TEXT UNIQUE NOT NULL REFERENCES fault_leases(id)
        )
        """,
        """
        CREATE TABLE recovery_records (
            id TEXT PRIMARY KEY,
            lease_id TEXT NOT NULL REFERENCES fault_leases(id),
            attempt INTEGER NOT NULL,
            mechanism TEXT NOT NULL,
            undo_results_json TEXT NOT NULL,
            verified INTEGER NOT NULL CHECK (verified IN (0, 1)),
            at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE tool_runs (
            id TEXT PRIMARY KEY,
            invocation_ref TEXT,
            argv_digest TEXT NOT NULL,
            argv_json TEXT NOT NULL,
            env_digest TEXT NOT NULL,
            host TEXT NOT NULL,
            exit_code INTEGER,
            duration_ms INTEGER,
            truncated INTEGER NOT NULL DEFAULT 0 CHECK (truncated IN (0, 1)),
            stdout_ref TEXT,
            stderr_ref TEXT
        )
        """,
        """
        CREATE TABLE agent_states (
            id TEXT PRIMARY KEY,
            host TEXT NOT NULL,
            roles_json TEXT NOT NULL,
            capabilities_json TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('ready','busy','dead','retired')),
            last_heartbeat TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT REFERENCES runs(id),
            ts TEXT NOT NULL,
            kind TEXT NOT NULL,
            payload_json TEXT NOT NULL
        )
        """,
        "CREATE INDEX idx_events_run_ts ON events(run_id, ts)",
        """
        CREATE TABLE steady_state_evaluations (
            id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(id),
            check_id TEXT NOT NULL,
            phase TEXT NOT NULL CHECK (phase IN ('pre','during','post')),
            passed INTEGER NOT NULL CHECK (passed IN (0, 1)),
            measured_json TEXT NOT NULL,
            expectation_json TEXT NOT NULL,
            evaluated_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE maniac_decisions (
            id TEXT PRIMARY KEY,
            run_id TEXT UNIQUE REFERENCES runs(id),
            candidates_json TEXT NOT NULL,
            weights_json TEXT NOT NULL,
            rng_state TEXT NOT NULL,
            chosen_plan_json TEXT NOT NULL,
            decided_at TEXT NOT NULL
        )
        """,
    ),
)

M0002_LEASE_CONTEXT = Migration(
    version=2,
    name="lease_context",
    statements=(
        "ALTER TABLE fault_leases ADD COLUMN run_id TEXT",
        "ALTER TABLE fault_leases ADD COLUMN fault_id TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE fault_leases ADD COLUMN targets_json TEXT NOT NULL DEFAULT '[]'",
        "ALTER TABLE fault_leases ADD COLUMN created_epoch_s REAL NOT NULL DEFAULT 0",
    ),
)

M0003_CAMPAIGNS_OBSERVATIONS = Migration(
    version=3,
    name="campaigns_and_observations",
    statements=(
        """
        CREATE TABLE campaigns (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'draft'
                CHECK (status IN ('draft','scheduled','running','paused','completed','aborted')),
            experiments_json TEXT NOT NULL DEFAULT '[]',
            window_json TEXT NOT NULL DEFAULT '{}',
            policy_json TEXT NOT NULL DEFAULT '{}',
            labels_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX idx_campaigns_status ON campaigns(status)",
        """
        CREATE TABLE observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            run_id TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT '',
            data_json TEXT NOT NULL DEFAULT '{}',
            timestamp TEXT NOT NULL
        )
        """,
        "CREATE INDEX idx_observations_run ON observations(run_id)",
        "CREATE INDEX idx_observations_kind ON observations(kind)",
    ),
)

M0004_DRILL_RUN_KIND = Migration(
    version=4,
    name="drill_run_kind",
    statements=(
        # Rebuild `runs` (no ALTER support for CHECK constraints in SQLite) so the
        # `kind` column admits 'drill' plans (Phase 5). FK enforcement is disabled
        # for the migration by run_migrations; id values are preserved.
        """
        CREATE TABLE runs_new (
            id TEXT PRIMARY KEY,
            experiment_name TEXT NOT NULL,
            kind TEXT NOT NULL CHECK (kind IN ('deterministic','random','drill')),
            spec_json TEXT NOT NULL,
            plan_json TEXT NOT NULL,
            seed INTEGER,
            status TEXT NOT NULL CHECK (status IN
                ('created','planning','validated','running','recovering',
                 'completed','failed','aborted')),
            environment_fingerprint TEXT NOT NULL,
            config_snapshot_id TEXT NOT NULL REFERENCES config_snapshots(id),
            topology_snapshot_id TEXT REFERENCES topology_snapshots(id),
            started_at TEXT,
            ended_at TEXT,
            summary_md TEXT
        )
        """,
        """
        INSERT INTO runs_new (id, experiment_name, kind, spec_json, plan_json, seed,
            status, environment_fingerprint, config_snapshot_id, topology_snapshot_id,
            started_at, ended_at, summary_md)
        SELECT id, experiment_name, kind, spec_json, plan_json, seed,
            status, environment_fingerprint, config_snapshot_id, topology_snapshot_id,
            started_at, ended_at, summary_md
        FROM runs
        """,
        "DROP TABLE runs",
        "ALTER TABLE runs_new RENAME TO runs",
        "CREATE INDEX idx_runs_status ON runs(status)",
        "CREATE INDEX idx_runs_started ON runs(started_at DESC)",
    ),
)

M0005_STEP_RUN_BYPASS_STATUS = Migration(
    version=5,
    name="step_run_bypass_status",
    statements=(
        # Rebuild `step_runs` so `status` admits 'bypassed' — the per-fault
        # fail-safe outcome where the impact gate proved tooling absent and the
        # engine skipped the injection instead of failing the run.
        """
        CREATE TABLE step_runs_new (
            id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(id),
            seq INTEGER NOT NULL,
            parent_step_id TEXT REFERENCES step_runs(id),
            action_type TEXT NOT NULL,
            action_json TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN
                ('pending','running','completed','failed','skipped','cancelled','bypassed')),
            started_at TEXT,
            ended_at TEXT,
            error TEXT
        )
        """,
        """
        INSERT INTO step_runs_new (id, run_id, seq, parent_step_id, action_type,
            action_json, status, started_at, ended_at, error)
        SELECT id, run_id, seq, parent_step_id, action_type,
            action_json, status, started_at, ended_at, error
        FROM step_runs
        """,
        "DROP TABLE step_runs",
        "ALTER TABLE step_runs_new RENAME TO step_runs",
    ),
)

M0006_RUNTIME_IDENTITY = Migration(
    version=6,
    name="runtime_identity",
    statements=(
        # Rebuild `step_runs` adding the canonical `runtime_identity` column and
        # admitting `'target_drift'` as a first-class persisted step status
        # (ADR-M1-3 Phase 1.4). `'bypassed'` and all prior statuses are retained
        # so pre-M1 rows read identically (ADR-M1-4).
        """
        CREATE TABLE step_runs_v6 (
            id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(id),
            seq INTEGER NOT NULL,
            parent_step_id TEXT REFERENCES step_runs(id),
            action_type TEXT NOT NULL,
            action_json TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN
                ('pending','running','completed','failed','skipped','cancelled',
                 'bypassed','target_drift')),
            started_at TEXT,
            ended_at TEXT,
            error TEXT,
            runtime_identity TEXT
        )
        """,
        """
        INSERT INTO step_runs_v6 (id, run_id, seq, parent_step_id, action_type,
            action_json, status, started_at, ended_at, error, runtime_identity)
        SELECT id, run_id, seq, parent_step_id, action_type,
            action_json, status, started_at, ended_at, error, NULL
        FROM step_runs
        """,
        "DROP TABLE step_runs",
        "ALTER TABLE step_runs_v6 RENAME TO step_runs",
        # Nullable identity columns on every persisted record (ADR-M1-3).
        "ALTER TABLE runs ADD COLUMN runtime_identity TEXT",
        "ALTER TABLE fault_leases ADD COLUMN runtime_identity TEXT",
        "ALTER TABLE observations ADD COLUMN runtime_identity TEXT",
        "ALTER TABLE recovery_records ADD COLUMN runtime_identity TEXT",
    ),
)


M0007_FAULT_GROUPS = Migration(
    version=7,
    name="fault_groups",
    statements=(
        # Persistent fault-group attribution (ADR-M2-1/2-2): every executed
        # step and fault invocation carries the group it belongs to. In-place
        # column additions per Q9 (schema freeze enforced at M4).
        "ALTER TABLE step_runs ADD COLUMN execution_group_id TEXT",
        "ALTER TABLE step_runs ADD COLUMN group_mode TEXT",
        "ALTER TABLE step_runs ADD COLUMN group_path TEXT",
        "ALTER TABLE fault_invocations ADD COLUMN execution_group_id TEXT",
        "CREATE INDEX idx_step_runs_group ON step_runs(execution_group_id)",
    ),
)


M0008_FAILED_TO_APPLY = Migration(
    version=8,
    name="failed_to_apply",
    statements=(
        # Execution-time capability revalidation (ADR-M2 Phase 2.3): a fault
        # that reaches the mutation boundary but whose capability no longer
        # holds (engine binary gone, tooling removed after plan time) is
        # recorded as `'failed_to_apply'` instead of mutating or bypassing.
        # Rebuild `step_runs` to admit the new persisted status; every prior
        # status remains so pre-M8 rows read identically (ADR-M1-4).
        """
        CREATE TABLE step_runs_v8 (
            id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(id),
            seq INTEGER NOT NULL,
            parent_step_id TEXT REFERENCES step_runs(id),
            action_type TEXT NOT NULL,
            action_json TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN
                ('pending','running','completed','failed','skipped','cancelled',
                 'bypassed','target_drift','failed_to_apply')),
            started_at TEXT,
            ended_at TEXT,
            error TEXT,
            runtime_identity TEXT,
            execution_group_id TEXT,
            group_mode TEXT,
            group_path TEXT
        )
        """,
        """
        INSERT INTO step_runs_v8 (id, run_id, seq, parent_step_id, action_type,
            action_json, status, started_at, ended_at, error, runtime_identity,
            execution_group_id, group_mode, group_path)
        SELECT id, run_id, seq, parent_step_id, action_type,
            action_json, status, started_at, ended_at, error, runtime_identity,
            execution_group_id, group_mode, group_path
        FROM step_runs
        """,
        "DROP TABLE step_runs",
        "ALTER TABLE step_runs_v8 RENAME TO step_runs",
        "CREATE INDEX idx_step_runs_group ON step_runs(execution_group_id)",
    ),
)


M0009_FORK_ATOMICITY = Migration(
    version=9,
    name="fork_atomicity",
    statements=(
        # ADR-M2 Phase 2.8 — fork atomicity. A run starts by snapshotting the
        # topology fork and committing a plan *as a pair*; either both land or
        # neither. The staging table records the commit phase so a crash
        # between "fork durable" and "plan committed" leaves a durable marker
        # the next startup can reconcile (orphaned fork -> cleaned up).
        """
        CREATE TABLE run_fork_staging (
            run_id TEXT PRIMARY KEY,
            topo_id TEXT NOT NULL,
            phase TEXT NOT NULL CHECK (phase IN ('planning','committed')),
            created_at TEXT NOT NULL,
            committed_at TEXT
        )
        """,
        # Rebuild step_runs to admit the persisted `resource_conflict` status
        # (ADR-M2 Phase 2.7).
        """
        CREATE TABLE step_runs_v9 (
            id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES runs(id),
            seq INTEGER NOT NULL,
            parent_step_id TEXT REFERENCES step_runs(id),
            action_type TEXT NOT NULL,
            action_json TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN
                ('pending','running','completed','failed','skipped','cancelled',
                 'bypassed','target_drift','failed_to_apply','resource_conflict')),
            started_at TEXT,
            ended_at TEXT,
            error TEXT,
            runtime_identity TEXT,
            execution_group_id TEXT,
            group_mode TEXT,
            group_path TEXT
        )
        """,
        """
        INSERT INTO step_runs_v9 (id, run_id, seq, parent_step_id, action_type,
            action_json, status, started_at, ended_at, error, runtime_identity,
            execution_group_id, group_mode, group_path)
        SELECT id, run_id, seq, parent_step_id, action_type,
            action_json, status, started_at, ended_at, error, runtime_identity,
            execution_group_id, group_mode, group_path
        FROM step_runs
        """,
        "DROP TABLE step_runs",
        "ALTER TABLE step_runs_v9 RENAME TO step_runs",
        "CREATE INDEX idx_step_runs_group ON step_runs(execution_group_id)",
    ),
)


# M0010 — NetworkPath target columns (ADR-M3-7).
#
# A fault step may target a first-class NetworkPath rather than a bare
# container name.  The structured fault is already serialized in action_json;
# these three *nullable* columns make the path target queryable without parsing
# the blob and provide a stable place for the fingerprint.  They are added with
# ALTER TABLE ADD COLUMN (nullable, no default) so existing step_runs rows are
# untouched — no table rebuild, no CHECK evolution needed.
M0010_NETWORK_PATH = Migration(
    version=10,
    name="network_path",
    statements=(
        "ALTER TABLE step_runs ADD COLUMN network_path TEXT",
        "ALTER TABLE step_runs ADD COLUMN path_namespace TEXT",
        "ALTER TABLE step_runs ADD COLUMN path_interface TEXT",
        "ALTER TABLE step_runs ADD COLUMN network_fingerprint TEXT",
    ),
)


ALL_MIGRATIONS: tuple[Migration, ...] = (
    M0001_INITIAL,
    M0002_LEASE_CONTEXT,
    M0003_CAMPAIGNS_OBSERVATIONS,
    M0004_DRILL_RUN_KIND,
    M0005_STEP_RUN_BYPASS_STATUS,
    M0006_RUNTIME_IDENTITY,
    M0007_FAULT_GROUPS,
    M0008_FAILED_TO_APPLY,
    M0009_FORK_ATOMICITY,
    M0010_NETWORK_PATH,
)
