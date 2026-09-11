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


# ── M4-3/4-4/4-5: Success criteria verdict + observability (ADR-M4-3/4-4) ─
M0013_M4_SUCCESS_OBSERVABILITY = Migration(
    version=13,
    name="m4_success_observability",
    statements=(
        # A drill's machine-evaluable verdict (ADR-M4-3) and the raw criteria
        # evaluation, persisted on the run row; both nullable — runs without
        # declared criteria keep a NULL verdict and the existing status flow.
        "ALTER TABLE runs ADD COLUMN verdict TEXT",
        "ALTER TABLE runs ADD COLUMN criteria_json TEXT",
    ),
    down_statements=(
        # ADR-M4-5: a DB at the M4 schema can be restored to the frozen baseline.
        "ALTER TABLE runs DROP COLUMN criteria_json",
        "ALTER TABLE runs DROP COLUMN verdict",
    ),
)


# ── M4-4/4-1: Observability evidence + governing-decision trace (ADR-M4-4) ──
M0014_M4_OBSERVABILITY_AND_DECISIONS = Migration(
    version=14,
    name="m4_observability_decisions",
    statements=(
        # Collected observability evidence (ADR-M4-4) and the decision refs
        # (ADR ids + decided-on timestamps, ADR-M4-1) that produced the run,
        # both persisted on the run row; additive and nullable.
        "ALTER TABLE runs ADD COLUMN observability_json TEXT",
        "ALTER TABLE runs ADD COLUMN governing_decisions_json TEXT",
    ),
    down_statements=(
        "ALTER TABLE runs DROP COLUMN governing_decisions_json",
        "ALTER TABLE runs DROP COLUMN observability_json",
    ),
)


# ── M5-1: Run and Outcome domain persistence (ADR-M5-1) ──────────────
M0011_M5_RUN_OUTCOME = Migration(
    version=11,
    name="m5_run_outcome",
    statements=(
        """
        CREATE TABLE m5_runs (
            id TEXT PRIMARY KEY,
            experiment_name TEXT NOT NULL,
            spec_json TEXT NOT NULL,
            plan_json TEXT NOT NULL,
            seed INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            environment_fingerprint TEXT NOT NULL DEFAULT '',
            config_snapshot_id TEXT NOT NULL DEFAULT '',
            started_at TEXT NOT NULL DEFAULT '',
            ended_at TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            verdict TEXT NOT NULL DEFAULT 'pass',
            tags_json TEXT NOT NULL DEFAULT '[]',
            extra_json TEXT NOT NULL DEFAULT '{}'
        )
        """,
        "CREATE INDEX idx_m5_runs_status ON m5_runs(status)",
        "CREATE INDEX idx_m5_runs_experiment ON m5_runs(experiment_name)",
        """
        CREATE TABLE m5_outcomes (
            run_id TEXT PRIMARY KEY REFERENCES m5_runs(id),
            body_json TEXT NOT NULL DEFAULT '{}',
            body_hash TEXT NOT NULL DEFAULT '',
            checks_passed INTEGER NOT NULL DEFAULT 0,
            checks_failed INTEGER NOT NULL DEFAULT 0,
            metric_deltas_json TEXT NOT NULL DEFAULT '{}',
            residual_effect TEXT NOT NULL DEFAULT '',
            stability_signal TEXT NOT NULL DEFAULT '',
            extra_json TEXT NOT NULL DEFAULT '{}'
        )
        """,
    ),
)


# ── M5-2: Coverage accounting (ADR-M5-3) ─────────────────────────────
M0012_M5_COVERAGE = Migration(
    version=12,
    name="m5_coverage",
    statements=(
        """
        CREATE TABLE m5_coverage (
            cell_key TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            fault_kind TEXT NOT NULL,
            execution_context TEXT NOT NULL,
            parameter_band TEXT NOT NULL,
            run_id TEXT NOT NULL,
            covered INTEGER NOT NULL DEFAULT 1,
            extra_json TEXT NOT NULL DEFAULT '{}'
        )
        """,
        "CREATE INDEX idx_m5_coverage_target ON m5_coverage(target)",
        "CREATE INDEX idx_m5_coverage_fault ON m5_coverage(fault_kind)",
    ),
)


# ── Run liveness: the controller records its pid so the janitor can tell
# ── a dead owner from a live one and reclaim within-TTL leases it left.
# ── Without this, a crashed ``run`` wedges its targets until TTL (the
# ── reported "janitor did nothing" pain).
M0015_RUN_CONTROLLER_PID = Migration(
    version=15,
    name="run_controller_pid",
    statements=("ALTER TABLE runs ADD COLUMN controller_pid INTEGER",),
    down_statements=("ALTER TABLE runs DROP COLUMN controller_pid",),
)


# ── M5: Five-state coverage model (feat-3 §4.2) ─────────────────────
# Existing columns are preserved: ``covered`` stays 1 iff ``state='covered'``
# so Maniac / report.py keep working. ``unknown`` is the absence of a row
# and is never persisted.
M0016_FIVE_STATE_COVERAGE = Migration(
    version=16,
    name="five_state_coverage",
    statements=(
        "ALTER TABLE m5_coverage ADD COLUMN state TEXT NOT NULL DEFAULT 'covered'",
        "ALTER TABLE m5_coverage ADD COLUMN block_reason TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE m5_coverage ADD COLUMN scaffold_tier INTEGER",
        "ALTER TABLE m5_coverage ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE m5_coverage ADD COLUMN verdict_json TEXT NOT NULL DEFAULT '{}'",
        "CREATE INDEX idx_m5_coverage_state ON m5_coverage(state)",
    ),
    down_statements=(
        "DROP INDEX idx_m5_coverage_state",
        "ALTER TABLE m5_coverage DROP COLUMN verdict_json",
        "ALTER TABLE m5_coverage DROP COLUMN updated_at",
        "ALTER TABLE m5_coverage DROP COLUMN scaffold_tier",
        "ALTER TABLE m5_coverage DROP COLUMN block_reason",
        "ALTER TABLE m5_coverage DROP COLUMN state",
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
    M0011_M5_RUN_OUTCOME,
    M0012_M5_COVERAGE,
    M0013_M4_SUCCESS_OBSERVABILITY,
    M0014_M4_OBSERVABILITY_AND_DECISIONS,
    M0015_RUN_CONTROLLER_PID,
    M0016_FIVE_STATE_COVERAGE,
)
