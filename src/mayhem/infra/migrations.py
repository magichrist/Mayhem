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


# ── k-plan-3 (ADR-M7-1 §3.3): resolved-target evidence on the lease ──────
# Nullable JSON column; resolved pod evidence for k8s exec-family faults,
# NULL for docker leases. Additive + backward compatible; docker rows simply
# keep NULL.
M0017_RESOLVED_TARGET = Migration(
    version=17,
    name="resolved_target",
    statements=("ALTER TABLE fault_leases ADD COLUMN resolved_target_json TEXT",),
    down_statements=("ALTER TABLE fault_leases DROP COLUMN resolved_target_json",),
)


M0018_REPLAY_CAPSULES = Migration(
    version=18,
    name="replay_capsules",
    statements=(
        """
        CREATE TABLE replay_capsules (
            run_id TEXT PRIMARY KEY,
            capsule_json TEXT NOT NULL,
            digest TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX idx_replay_capsules_created ON replay_capsules(created_at DESC)",
    ),
    down_statements=(
        "DROP INDEX idx_replay_capsules_created",
        "DROP TABLE replay_capsules",
    ),
)


M0019_COVERAGE_GRAPH = Migration(
    version=19,
    name="coverage_graph",
    statements=(
        """
        CREATE TABLE coverage_graph_nodes (
            node_id TEXT PRIMARY KEY,
            service TEXT NOT NULL,
            fault_family TEXT NOT NULL,
            fault_kind TEXT NOT NULL DEFAULT '',
            failure_domain TEXT NOT NULL,
            target_type TEXT NOT NULL,
            engine TEXT NOT NULL,
            maturity TEXT NOT NULL,
            evidence_status TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            verified INTEGER NOT NULL DEFAULT 0,
            blocked_reason TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX idx_coverage_graph_service ON coverage_graph_nodes(service)",
        "CREATE INDEX idx_coverage_graph_family ON coverage_graph_nodes(fault_family)",
        """
        CREATE TABLE coverage_graph_baselines (
            name TEXT PRIMARY KEY,
            graph_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """,
    ),
    down_statements=(
        "DROP TABLE coverage_graph_baselines",
        "DROP INDEX idx_coverage_graph_family",
        "DROP INDEX idx_coverage_graph_service",
        "DROP TABLE coverage_graph_nodes",
    ),
)


M0020_CAMPAIGN_CHECKPOINTS = Migration(
    version=20,
    name="campaign_checkpoints",
    statements=(
        """
        CREATE TABLE campaign_checkpoints (
            campaign_id TEXT NOT NULL,
            experiment_id TEXT NOT NULL,
            state TEXT NOT NULL,
            lease_id TEXT NOT NULL DEFAULT '',
            attempt INTEGER NOT NULL DEFAULT 0,
            fingerprint TEXT NOT NULL DEFAULT '',
            resume_safe INTEGER NOT NULL DEFAULT 1,
            detail TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL,
            PRIMARY KEY (campaign_id, experiment_id)
        )
        """,
        "CREATE INDEX idx_campaign_checkpoints_state ON campaign_checkpoints(state)",
    ),
    down_statements=(
        "DROP INDEX idx_campaign_checkpoints_state",
        "DROP TABLE campaign_checkpoints",
    ),
)


M0021_GAME_DAY_SESSIONS = Migration(
    version=21,
    name="game_day_sessions",
    statements=(
        """
        CREATE TABLE game_day_sessions (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            state TEXT NOT NULL,
            session_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX idx_game_day_state ON game_day_sessions(state)",
    ),
    down_statements=("DROP INDEX idx_game_day_state", "DROP TABLE game_day_sessions"),
)


# Plan 12 Phase 2 — attestation sealing + retention.
#
# Id note: several agents append migrations during the v1.1.0 wave and the
# migrator keys on ``version`` alone, so ids collided here and were handed back
# and forth. Resolution: 22 is M0022_SECRET_GRANTS (earlier claimant), 23 is
# this one. Ordering in ALL_MIGRATIONS below and contiguity 1..23 are what
# ``test_migrations_run_once`` (schema_version == len(ALL_MIGRATIONS)) requires;
# re-check both if a third migration lands alongside.
M0023_ATTESTATION_RETENTION = Migration(
    version=23,
    name="attestation_retention",
    statements=(
        """
        CREATE TABLE attestation_chains (
            run_id TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            chain_root TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            first_event_id TEXT NOT NULL DEFAULT '',
            last_event_id TEXT NOT NULL DEFAULT '',
            sealed_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX idx_attestation_chains_created ON attestation_chains(created_at)",
        """
        CREATE TABLE attestation_events (
            run_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            event_id TEXT NOT NULL,
            event_kind TEXT NOT NULL,
            digest TEXT NOT NULL,
            chain_link TEXT NOT NULL,
            previous_digest TEXT NOT NULL DEFAULT '',
            recorded_at TEXT NOT NULL,
            event_json TEXT NOT NULL,
            PRIMARY KEY (run_id, sequence)
        )
        """,
        "CREATE UNIQUE INDEX idx_attestation_events_identity"
        " ON attestation_events(run_id, event_id)",
        "CREATE INDEX idx_attestation_events_digest ON attestation_events(digest)",
        """
        CREATE TABLE attestation_manifests (
            manifest_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            manifest_digest TEXT NOT NULL,
            signature_state TEXT NOT NULL,
            signature_reason TEXT NOT NULL DEFAULT '',
            signer_identity TEXT NOT NULL DEFAULT '',
            trust_root_ref TEXT NOT NULL DEFAULT '',
            retention_class TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            previous_manifest_digest TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            manifest_json TEXT NOT NULL
        )
        """,
        "CREATE INDEX idx_attestation_manifests_run"
        " ON attestation_manifests(run_id, created_at)",
        """
        CREATE TABLE evidence_retention (
            manifest_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            retention_class TEXT NOT NULL,
            state TEXT NOT NULL,
            legal_hold INTEGER NOT NULL DEFAULT 0,
            hold_reason TEXT NOT NULL DEFAULT '',
            expires_at TEXT,
            manifest_digest TEXT NOT NULL DEFAULT '',
            policy_version TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX idx_evidence_retention_due ON evidence_retention(state, expires_at)",
        """
        CREATE TABLE retention_tombstones (
            tombstone_id TEXT PRIMARY KEY,
            manifest_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            manifest_digest TEXT NOT NULL,
            retention_class TEXT NOT NULL,
            requester TEXT NOT NULL,
            approver TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            backend TEXT NOT NULL DEFAULT '',
            deleted_at TEXT NOT NULL
        )
        """,
        "CREATE UNIQUE INDEX idx_retention_tombstones_manifest"
        " ON retention_tombstones(manifest_id)",
    ),
    down_statements=(
        "DROP INDEX idx_retention_tombstones_manifest",
        "DROP TABLE retention_tombstones",
        "DROP INDEX idx_evidence_retention_due",
        "DROP TABLE evidence_retention",
        "DROP INDEX idx_attestation_manifests_run",
        "DROP TABLE attestation_manifests",
        "DROP INDEX idx_attestation_events_digest",
        "DROP INDEX idx_attestation_events_identity",
        "DROP TABLE attestation_events",
        "DROP INDEX idx_attestation_chains_created",
        "DROP TABLE attestation_chains",
    ),
)


# Plan 29 Phase 2 — late secret resolution: grant records only.
#
# This table holds *permissions*, never values. That is not an oversight to be
# fixed later, it is the schema's central claim: there is no column a credential
# value could occupy, so no code path can persist one through this repository
# even if a future author tries. `environments_json` and `scopes_json` are
# globs evaluated by `domain.secrets`; expiry is enforced against an explicit
# clock rather than by a WHERE clause, so an expired grant stays readable as
# evidence that a permission once existed.
#
# Id note: 21 is the committed head, so 22 is the lowest free id above it and
# the only one that keeps ``test_migration_versions_are_contiguous_ascending``
# green. A concurrent v1.1.0 agent is oscillating its own attestation migration
# between 22 and 23 while this file is open; if it settles back on 22 the two
# must be renumbered together at integration time. The migrator keys on
# ``version`` alone and refuses duplicates outright ("migrations must be
# strictly increasing"), so a collision is a loud startup failure rather than a
# silent overwrite.
M0022_SECRET_GRANTS = Migration(
    version=22,
    name="secret_grants",
    statements=(
        """
        CREATE TABLE secret_grants (
            principal TEXT NOT NULL,
            credential_pattern TEXT NOT NULL,
            environments_json TEXT NOT NULL DEFAULT '[]',
            scopes_json TEXT NOT NULL DEFAULT '[]',
            expires_at TEXT NOT NULL,
            issued_at TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (principal, credential_pattern)
        )
        """,
        "CREATE INDEX idx_secret_grants_expiry ON secret_grants(expires_at)",
    ),
    down_statements=(
        "DROP INDEX idx_secret_grants_expiry",
        "DROP TABLE secret_grants",
    ),
)


# Plan 01 Phase 2 — the certification record store.
#
# The store is a *sequence per fault*, not a mutable cell: re-certifying a fault
# after its claim expired appends a new row rather than reviving the old one
# (``domain.certification`` makes a lapsed claim terminal on purpose). The key
# is therefore ``(fault_id, sequence)`` and ``sequence`` is dense and 1-based
# per fault, so a gap means a write was lost rather than renumbered.
#
# Every row carries both the denormalised columns an auditor's SQL needs
# (``state``, ``cell_fingerprint``, ``bundle_hash``, ``outcome``, ``reason``) and
# the canonical ``record_json`` the row was derived from. The columns make
# "which faults are certified right now" a single indexed query; the JSON makes
# reloading the exact frozen record — through the same validators that refused an
# impossible one at construction time — possible without re-deriving it.
#
# No foreign key to ``runs``. A certification outlives the run that produced it
# on purpose: deleting the control-plane row that describes the run must not
# silently withdraw a live claim, and equally a claim is only re-earned by a new
# run, never by resurrecting an old one.
#
# Id note: 23 is ``M0023_ATTESTATION_RETENTION`` (see its own comment above), so
# 24 is the reserved id for this migration and the chain stays contiguous 1..24.
M0024_CERTIFICATION_RECORDS = Migration(
    version=24,
    name="certification_records",
    statements=(
        """
        CREATE TABLE certification_records (
            fault_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            cell_label TEXT NOT NULL,
            cell_fingerprint TEXT NOT NULL,
            engine TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN
                ('pending','certified','expiring','stale','failed','incompatible')),
            outcome TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            bundle_hash TEXT NOT NULL DEFAULT '',
            run_id TEXT NOT NULL DEFAULT '',
            record_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (fault_id, sequence)
        )
        """,
        "CREATE INDEX idx_certification_records_state ON certification_records(state)",
        "CREATE INDEX idx_certification_records_cell ON certification_records(cell_fingerprint)",
    ),
    down_statements=(
        "DROP INDEX idx_certification_records_cell",
        "DROP INDEX idx_certification_records_state",
        "DROP TABLE certification_records",
    ),
)


# Plan 19 Phase 1 — agent identity/credential state and backup descriptors.
#
# Id note: 24 is ``M0024_CERTIFICATION_RECORDS`` (a concurrent v1.1.0 lane), so
# ``M0025_AGENT_IDENTITY_BACKUPS`` is the id reserved for this migration and the
# chain stays contiguous 1..25. If a further migration lands alongside, take the
# next free id rather than renumbering this one — the migrator keys on
# ``version`` alone and refuses duplicates outright, so a collision would be a
# loud startup failure rather than a silent overwrite.
#
# What these tables hold, and what they deliberately do not:
#
# * **No key material, anywhere.** ``agent_identities`` and
#   ``agent_credential_revocations`` name credentials and revocations, never a
#   secret. Same rule as ``M0022_SECRET_GRANTS`` above: no column a credential
#   value could occupy, so no code path can persist one through this repository.
# * **No "this restored fine" column.** ``backup_snapshots`` describes bytes that
#   were written and has no ``restored``/``verified``/``good`` field, because
#   that is a fact about a drill, not about a capture.
#   ``backup_restore_verifications`` is where restore outcomes live, and its
#   ``outcome`` column stores the *derived* verdict
#   (``verified``/``failed``/``incomplete``) together with a nullable
#   ``data_loss_seconds`` — an unmeasured restore stays NULL, which is what makes
#   "we have never actually measured our RPO" visible in the database rather
#   than a zero.
# * **``recovery_objectives`` has no achieved columns.** It stores the *target*
#   only. An achieved value is a join against verified restore evidence, never a
#   number written next to a promise.
# * No foreign key to ``runs``, for the same reason plan 12 omits one (gap 101):
#   credential and backup state must survive the control plane deleting the run
#   it describes.
M0025_AGENT_IDENTITY_BACKUPS = Migration(
    version=25,
    name="agent_identity_backups",
    statements=(
        """
        CREATE TABLE agent_identities (
            agent_id TEXT PRIMARY KEY,
            controller_id TEXT NOT NULL,
            credential_id TEXT NOT NULL,
            credential_generation INTEGER NOT NULL,
            rotation_state TEXT NOT NULL,
            identity_version INTEGER NOT NULL,
            identity_digest TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            rotation_due_at TEXT NOT NULL,
            identity_revoked INTEGER NOT NULL DEFAULT 0,
            identity_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX idx_agent_identities_controller ON agent_identities(controller_id)",
        "CREATE INDEX idx_agent_identities_expires ON agent_identities(expires_at)",
        """
        CREATE TABLE agent_credential_revocations (
            agent_id TEXT NOT NULL,
            credential_id TEXT NOT NULL,
            scope TEXT NOT NULL CHECK (scope IN ('credential','identity')),
            reason TEXT NOT NULL,
            revoked_at TEXT NOT NULL,
            revoked_by TEXT NOT NULL,
            note TEXT NOT NULL DEFAULT '',
            revocation_json TEXT NOT NULL,
            PRIMARY KEY (agent_id, credential_id, scope, revoked_at)
        )
        """,
        "CREATE INDEX idx_agent_revocations_agent "
        "ON agent_credential_revocations(agent_id, revoked_at)",
        """
        CREATE TABLE backup_snapshots (
            snapshot_id TEXT PRIMARY KEY,
            kind TEXT NOT NULL CHECK (kind IN ('full','incremental','wal_archive','evidence')),
            datastore TEXT NOT NULL,
            taken_at TEXT NOT NULL,
            covers_through TEXT NOT NULL,
            content_digest TEXT NOT NULL,
            parent_snapshot_id TEXT,
            wal_sequence INTEGER,
            byte_size INTEGER NOT NULL DEFAULT 0,
            replica_count INTEGER NOT NULL DEFAULT 0,
            descriptor_digest TEXT NOT NULL,
            descriptor_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX idx_backup_snapshots_store ON backup_snapshots(datastore, taken_at DESC)",
        "CREATE INDEX idx_backup_snapshots_kind ON backup_snapshots(datastore, kind)",
        """
        CREATE TABLE backup_restore_verifications (
            restore_id TEXT PRIMARY KEY,
            snapshot_id TEXT NOT NULL,
            target_cell TEXT NOT NULL,
            drill INTEGER NOT NULL,
            outcome TEXT NOT NULL CHECK (outcome IN ('verified','failed','incomplete')),
            data_loss_seconds REAL,
            duration_seconds REAL NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            plan_json TEXT NOT NULL,
            verification_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX idx_backup_restores_snapshot ON backup_restore_verifications(snapshot_id)",
        "CREATE INDEX idx_backup_restores_outcome ON backup_restore_verifications(outcome)",
        """
        CREATE TABLE recovery_objectives (
            datastore TEXT NOT NULL,
            stated_at TEXT NOT NULL,
            rpo_seconds REAL NOT NULL,
            rto_seconds REAL NOT NULL,
            stated_by TEXT NOT NULL,
            objective_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (datastore, stated_at)
        )
        """,
        "CREATE INDEX idx_recovery_objectives_latest "
        "ON recovery_objectives(datastore, stated_at DESC)",
    ),
    down_statements=(
        "DROP INDEX idx_recovery_objectives_latest",
        "DROP TABLE recovery_objectives",
        "DROP INDEX idx_backup_restores_outcome",
        "DROP INDEX idx_backup_restores_snapshot",
        "DROP TABLE backup_restore_verifications",
        "DROP INDEX idx_backup_snapshots_kind",
        "DROP INDEX idx_backup_snapshots_store",
        "DROP TABLE backup_snapshots",
        "DROP INDEX idx_agent_revocations_agent",
        "DROP TABLE agent_credential_revocations",
        "DROP INDEX idx_agent_identities_expires",
        "DROP INDEX idx_agent_identities_controller",
        "DROP TABLE agent_identities",
    ),
)


# Plan 13 Phase 2 — durable schedule state.
#
# Id note: 25 is ``M0025_AGENT_IDENTITY_BACKUPS`` (a concurrent v1.1.0 lane), so
# ``M0026_SCHEDULES`` is the id reserved for this migration and the chain stays
# contiguous 1..26. Same rule as 22/23/24/25 above: take the next free id rather
# than renumbering, because the migrator keys on ``version`` alone and refuses
# duplicates outright.
#
# What these tables hold, and what they deliberately do not:
#
# * **``schedule_runs.idempotency_key`` is the primary key, and that is the
#   whole no-double-fire mechanism.** A recurring schedule re-derives the same
#   key for the same slot after a controller restart, so a second attempt to
#   fire an already-fired slot is a *primary-key violation* rather than a race
#   the application has to remember to prevent. The column is deliberately
#   un-normalised (a digest, not a surrogate id) for that reason: uniqueness is
#   enforced over the value the caller recomputes, not over a row counter.
# * **``state`` is a claim lifecycle, not a run lifecycle.** ``claimed`` means
#   a controller wrote the intent to fire and may or may not have executed it;
#   ``dispatched`` means the pipeline returned a run id. A ``claimed`` row left
#   behind by a controller that died mid-dispatch is *not* retried, because
#   retrying it is exactly the double-fire this table exists to prevent. An
#   operator resolves it, which is an incident, not a guess.
# * **No "this fired successfully" boolean and no outcome column.** Whether a
#   dispatched run passed is the run's own record (``m5_runs`` /
#   ``m5_run_outcomes``), joined by ``run_id``; duplicating it here would be a
#   second answer to the same question that can drift from the first.
# * **Non-fires are not rows.** A refusal that never reached the claim stage (a
#   blackout, a closed window, an active incident) is evidence about an
#   evaluation, and those go to ``observations`` via
#   :meth:`mayhem.infra.store.Store.save_observation` rather than to a table
#   whose primary key means "this slot ran".
# * ``schedules`` holds the *binding* (which campaign, which experiment, which
#   team) alongside the schedule body, and the body itself as JSON. The digest
#   column is over the body, so an edited schedule is recognisable as a
#   different body rather than silently continuing a recurrence its author
#   changed underneath it.
# * ``game_day_dispatch_steps`` hangs off ``game_day_sessions`` by reference, so
#   a dispatch step cannot exist for a session nobody approved. Its hold state
#   is the game-day half of the scheduler: ``held`` is a *gate* the scheduler
#   reads at fire time, not a delay it waits out, and ``released`` records the
#   named facilitator who released it.
M0026_SCHEDULES = Migration(
    version=26,
    name="schedules",
    statements=(
        """
        CREATE TABLE schedules (
            schedule_id TEXT PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            team TEXT NOT NULL DEFAULT '',
            campaign_id TEXT NOT NULL,
            experiment_id TEXT NOT NULL,
            concurrency_class TEXT NOT NULL DEFAULT 'exclusive' CHECK (concurrency_class IN
                ('parallel', 'exclusive', 'shared_resource', 'conflicting', 'preemptible')),
            resources_json TEXT NOT NULL DEFAULT '[]',
            lock_window_s REAL NOT NULL DEFAULT 3600.0,
            kind TEXT NOT NULL CHECK (kind IN ('cron', 'interval', 'calendar')),
            timezone_name TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
            window_index INTEGER NOT NULL DEFAULT 0,
            run_count INTEGER NOT NULL DEFAULT 0,
            last_slot_start TEXT,
            last_dispatch_at TEXT,
            next_fire_at TEXT,
            schedule_digest TEXT NOT NULL,
            schedule_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX idx_schedules_team ON schedules(team)",
        "CREATE INDEX idx_schedules_campaign ON schedules(campaign_id)",
        "CREATE INDEX idx_schedules_due ON schedules(enabled, next_fire_at)",
        "CREATE INDEX idx_schedules_class ON schedules(concurrency_class)",
        """
        CREATE TABLE schedule_runs (
            idempotency_key TEXT PRIMARY KEY,
            schedule_id TEXT NOT NULL REFERENCES schedules(schedule_id),
            team TEXT NOT NULL DEFAULT '',
            campaign_id TEXT NOT NULL DEFAULT '',
            experiment_id TEXT NOT NULL DEFAULT '',
            window_index INTEGER NOT NULL,
            slot_start TEXT NOT NULL,
            effective_at TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('claimed', 'dispatched', 'failed')),
            code TEXT NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            run_id TEXT NOT NULL DEFAULT '',
            controller_id TEXT NOT NULL DEFAULT '',
            detail_json TEXT NOT NULL DEFAULT '{}',
            recorded_at TEXT NOT NULL,
            settled_at TEXT
        )
        """,
        "CREATE INDEX idx_schedule_runs_schedule ON schedule_runs(schedule_id, slot_start)",
        "CREATE INDEX idx_schedule_runs_window ON schedule_runs(window_index, team)",
        "CREATE INDEX idx_schedule_runs_state ON schedule_runs(state)",
        """
        CREATE TABLE game_day_dispatch_steps (
            session_id TEXT NOT NULL REFERENCES game_day_sessions(id),
            step_id TEXT NOT NULL,
            step_seq INTEGER NOT NULL,
            scenario TEXT NOT NULL DEFAULT '',
            schedule_id TEXT NOT NULL,
            hold_state TEXT NOT NULL CHECK (hold_state IN ('held', 'released', 'dispatched')),
            hold_reason TEXT NOT NULL DEFAULT '',
            released_by TEXT NOT NULL DEFAULT '',
            released_at TEXT,
            dispatched_at TEXT,
            step_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (session_id, step_id)
        )
        """,
        "CREATE INDEX idx_game_day_steps_session "
        "ON game_day_dispatch_steps(session_id, step_seq)",
        "CREATE INDEX idx_game_day_steps_schedule ON game_day_dispatch_steps(schedule_id)",
    ),
    down_statements=(
        "DROP INDEX idx_game_day_steps_schedule",
        "DROP INDEX idx_game_day_steps_session",
        "DROP TABLE game_day_dispatch_steps",
        "DROP INDEX idx_schedule_runs_state",
        "DROP INDEX idx_schedule_runs_window",
        "DROP INDEX idx_schedule_runs_schedule",
        "DROP TABLE schedule_runs",
        "DROP INDEX idx_schedules_due",
        "DROP INDEX idx_schedules_campaign",
        "DROP INDEX idx_schedules_class",
        "DROP INDEX idx_schedules_team",
        "DROP TABLE schedules",
    ),
)


# M0027 — plan 22 phase 2: coverage over the new cell dimensions, run
# comparison, and advisory suite suggestions.
#
# Version note: this migration was authored while the head was M0025 and was
# provisionally numbered 26; M0026_SCHEDULES landed in this file concurrently, so
# this one sits at 27 to keep the chain strictly increasing. Nothing about the
# schema depends on the number.
#
# Additive only. ``m5_coverage`` is neither altered nor rebuilt: the plan-22
# dimensions table stores the decomposition and a pointer at the legacy
# ``cell_key``, and the coverage *state* stays where it already was. There is
# therefore exactly one place a cell's state lives and nothing to drift.
#
# Three constraints in this migration are load-bearing rather than tidy:
#
# * ``coverage_dimension_sightings`` refuses a sighting that cites nothing. An
#   ``executed``/``certified`` row must name a run and a 64-char lowercase-hex
#   evidence digest (and, when certified, a certification reference); a
#   ``catalog`` row must name neither. This is plan 22's "coverage counts
#   executed/certified evidence, never catalog presence" enforced in the place
#   that survives a refactor of the Python that writes it.
# * ``regression_findings`` admits no outcome but ``regressed`` and refuses a
#   row whose baseline and candidate runs are the same id. "A regression
#   finding without two cited runs" is unrepresentable here as well as in
#   ``mayhem.domain.comparison``.
# * ``suite_suggestions`` has CHECKs admitting no value but 1 for ``advisory``
#   and ``requires_approval``, and has no ``run_id``, ``status``, or
#   ``started_at`` column at all. There is nowhere for a suggestion to record
#   that it ran, because a suggestion never does.
M0027_COVERAGE_FINDINGS = Migration(
    version=27,
    name="coverage_findings",
    statements=(
        """
        CREATE TABLE coverage_dimension_cells (
            service TEXT NOT NULL,
            dependency TEXT NOT NULL,
            fault TEXT NOT NULL,
            environment TEXT NOT NULL,
            version TEXT NOT NULL,
            probe_class TEXT NOT NULL,
            certification_state TEXT NOT NULL CHECK (certification_state IN (
                'uncertified', 'pending', 'certified', 'expiring', 'stale',
                'failed', 'incompatible')),
            cell_key TEXT NOT NULL,
            declared_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (service, dependency, fault, environment, version),
            CHECK (instr(service, char(31)) = 0),
            CHECK (instr(dependency, char(31)) = 0),
            CHECK (instr(fault, char(31)) = 0),
            CHECK (instr(environment, char(31)) = 0),
            CHECK (instr(version, char(31)) = 0)
        )
        """,
        "CREATE INDEX idx_coverage_dimension_cells_cell_key "
        "ON coverage_dimension_cells(cell_key)",
        "CREATE INDEX idx_coverage_dimension_cells_certification "
        "ON coverage_dimension_cells(certification_state)",
        """
        CREATE TABLE coverage_dimension_sightings (
            sighting_id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            dependency TEXT NOT NULL,
            fault TEXT NOT NULL,
            environment TEXT NOT NULL,
            version TEXT NOT NULL,
            kind TEXT NOT NULL CHECK (kind IN ('executed', 'certified', 'catalog')),
            run_id TEXT NOT NULL DEFAULT '',
            evidence_digest TEXT NOT NULL DEFAULT '',
            certification_ref TEXT NOT NULL DEFAULT '',
            recorded_at TEXT NOT NULL,
            CHECK (
                (
                    kind IN ('executed', 'certified')
                    AND run_id <> ''
                    AND length(evidence_digest) = 64
                    AND evidence_digest NOT GLOB '*[^0-9a-f]*'
                    AND (kind <> 'certified' OR certification_ref <> '')
                )
                OR (
                    kind = 'catalog'
                    AND run_id = ''
                    AND evidence_digest = ''
                    AND certification_ref = ''
                )
            )
        )
        """,
        # Partial: catalog sightings accumulate (they count), evidence sightings
        # are idempotent per (cell, kind, run, digest).
        "CREATE UNIQUE INDEX idx_coverage_dimension_sightings_evidence "
        "ON coverage_dimension_sightings("
        "service, dependency, fault, environment, version, kind, run_id, evidence_digest) "
        "WHERE kind IN ('executed', 'certified')",
        "CREATE INDEX idx_coverage_dimension_sightings_kind "
        "ON coverage_dimension_sightings(kind, recorded_at)",
        """
        CREATE TABLE comparison_runs (
            run_id TEXT PRIMARY KEY,
            experiment TEXT NOT NULL,
            release TEXT NOT NULL,
            environment TEXT NOT NULL,
            equivalence_key TEXT NOT NULL,
            evidence_digest TEXT NOT NULL,
            report_json TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            CHECK (length(evidence_digest) = 64),
            CHECK (evidence_digest NOT GLOB '*[^0-9a-f]*'),
            CHECK (run_id <> '')
        )
        """,
        "CREATE INDEX idx_comparison_runs_equivalence "
        "ON comparison_runs(equivalence_key, release)",
        "CREATE INDEX idx_comparison_runs_experiment ON comparison_runs(experiment, release)",
        """
        CREATE TABLE regression_findings (
            finding_id TEXT PRIMARY KEY,
            experiment TEXT NOT NULL,
            baseline_release TEXT NOT NULL,
            candidate_release TEXT NOT NULL,
            baseline_run TEXT NOT NULL,
            candidate_run TEXT NOT NULL,
            baseline_evidence_digest TEXT NOT NULL,
            candidate_evidence_digest TEXT NOT NULL,
            outcome TEXT NOT NULL CHECK (outcome = 'regressed'),
            regressed_metrics TEXT NOT NULL,
            finding_json TEXT NOT NULL,
            opened_at TEXT NOT NULL,
            CHECK (finding_id <> ''),
            CHECK (baseline_run <> '' AND candidate_run <> ''),
            CHECK (baseline_run <> candidate_run),
            CHECK (length(baseline_evidence_digest) = 64),
            CHECK (length(candidate_evidence_digest) = 64),
            CHECK (baseline_evidence_digest <> candidate_evidence_digest),
            CHECK (regressed_metrics <> '[]')
        )
        """,
        "CREATE INDEX idx_regression_findings_experiment "
        "ON regression_findings(experiment, opened_at DESC)",
        """
        CREATE TABLE suite_suggestions (
            suggestion_id TEXT NOT NULL,
            event_kind TEXT NOT NULL CHECK (event_kind IN (
                'nightly', 'post_deploy', 'post_infra_change', 'post_incident',
                'dependency_version_change', 'cache_topology_change',
                'database_upgrade')),
            event_subject TEXT NOT NULL,
            event_fingerprint TEXT NOT NULL,
            suites_json TEXT NOT NULL,
            fault_kinds_json TEXT NOT NULL,
            rationale TEXT NOT NULL,
            advisory INTEGER NOT NULL DEFAULT 1 CHECK (advisory = 1),
            requires_approval INTEGER NOT NULL DEFAULT 1 CHECK (requires_approval = 1),
            suggested_at TEXT NOT NULL,
            PRIMARY KEY (suggestion_id, event_kind, event_fingerprint),
            CHECK (suggestion_id <> ''),
            CHECK (event_subject <> ''),
            CHECK (length(event_fingerprint) = 64),
            CHECK (suites_json <> '[]'),
            CHECK (fault_kinds_json <> '[]'),
            CHECK (rationale <> '')
        )
        """,
        "CREATE INDEX idx_suite_suggestions_kind "
        "ON suite_suggestions(event_kind, suggested_at DESC)",
    ),
    down_statements=(
        "DROP INDEX idx_suite_suggestions_kind",
        "DROP TABLE suite_suggestions",
        "DROP INDEX idx_regression_findings_experiment",
        "DROP TABLE regression_findings",
        "DROP INDEX idx_comparison_runs_experiment",
        "DROP INDEX idx_comparison_runs_equivalence",
        "DROP TABLE comparison_runs",
        "DROP INDEX idx_coverage_dimension_sightings_kind",
        "DROP INDEX idx_coverage_dimension_sightings_evidence",
        "DROP TABLE coverage_dimension_sightings",
        "DROP INDEX idx_coverage_dimension_cells_certification",
        "DROP INDEX idx_coverage_dimension_cells_cell_key",
        "DROP TABLE coverage_dimension_cells",
    ),
)


# Plan 18 Phase 2 — the marketplace catalog: artifacts, the label inputs a
# trust label is *derived* from, supply-chain records, revocations, and pins.
#
# Id note: 28 is reserved for this migration and the chain stays contiguous
# 1..28. If a further migration lands alongside, take the next free id rather
# than renumbering this one — the migrator keys on ``version`` alone and refuses
# duplicates outright.
#
# What these tables hold, and what they deliberately do not:
#
# * **No trust class column, anywhere.** There is no ``artifact_class`` and no
#   ``verified`` on any of these tables, because
#   :class:`mayhem.domain.marketplace.TrustLabel` derives its class from three
#   stored facts and a persisted copy of that derivation would be a claim
#   somebody could rewrite without producing a record. What *is* persisted is
#   the evidence a derivation reads: the registry (distribution), the
#   deprecation notice (withdrawal), and the artifact-digest-keyed certification
#   pairings (evidence). A reader re-derives the class every time.
# * **``marketplace_certifications`` stores the digest the record was made
#   against, in the primary key.** A plan-01
#   :class:`~mayhem.domain.certification.CertificationRecord` names a fault on a
#   cell and never an artifact, so a row here that carried only ``fault_id``
#   would let any artifact be "verified" by any record. There is deliberately
#   **no foreign key to ``certification_records``**: that table's rows move in
#   place as records age, and the catalog has to be able to answer "were these
#   bytes ever certified" without a join a later transition could erase.
# * **``marketplace_supply_chain.signature_verified`` is
#   ``CHECK (signature_verified = 0)``.** Mayhem cannot verify a signature in
#   this build
#   (``mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED is False``), so
#   the only value the column can ever hold is a 0. The column exists so the
#   shape is already there when a signing lane lands, and the CHECK means
#   nothing may write a 1 without a migration that admits it. Same technique as
#   ``suite_suggestions.advisory`` above, and it is the reason this table can
#   never be read as provenance.
# * **No "in force" column on revocations.** A revocation becomes enforceable
#   when the clock reaches ``propagation_deadline``, whether or not anybody ran
#   a sweep. Storing that verdict would create a column that is silently wrong
#   between the deadline and the next write, so enforcement reads the deadline
#   against the caller's ``now`` on every decision instead.
# * **A pin names its bytes.** ``marketplace_pins`` is keyed by
#   ``(artifact_id, version)`` and CHECKs a 64-character lowercase-hex digest,
#   because "pinned" and "resolved to some other version" are different words.
#   The partial unique index admits one *live* install per version while keeping
#   removed pins as history, so an uninstall/reinstall drill is replayable.
M0028_MARKETPLACE = Migration(
    version=28,
    name="marketplace",
    statements=(
        """
        CREATE TABLE marketplace_registries (
            registry_id TEXT NOT NULL,
            display_name TEXT NOT NULL,
            scope TEXT NOT NULL CHECK (scope IN
                ('official', 'community', 'organization_private')),
            organization TEXT NOT NULL DEFAULT '',
            federates_with_json TEXT NOT NULL,
            registry_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (registry_id),
            CHECK (instr(registry_id, char(31)) = 0),
            -- A private catalogue with no owner is not a boundary, and a public
            -- one that names an owner is claiming a scope it does not have.
            -- Same rule as ``RegistryRef``'s own validator, expressed where a
            -- row cannot be written that breaks it.
            CHECK (
                (scope = 'organization_private' AND organization <> '')
                OR (scope <> 'organization_private' AND organization = '')
            )
        )
        """,
        "CREATE INDEX idx_marketplace_registries_scope ON marketplace_registries(scope)",
        """
        CREATE TABLE marketplace_artifacts (
            artifact_id TEXT NOT NULL,
            version TEXT NOT NULL,
            digest TEXT NOT NULL,
            registry_id TEXT NOT NULL REFERENCES marketplace_registries(registry_id),
            publisher_id TEXT NOT NULL,
            license_id TEXT NOT NULL,
            changelog_ref TEXT NOT NULL,
            deprecation_json TEXT NOT NULL DEFAULT '',
            permissions_json TEXT NOT NULL,
            dependencies_json TEXT NOT NULL,
            artifact_json TEXT NOT NULL,
            published_at TEXT NOT NULL,
            PRIMARY KEY (artifact_id, version),
            CHECK (instr(artifact_id, char(31)) = 0),
            CHECK (artifact_id <> '' AND version <> ''),
            CHECK (length(digest) = 64),
            CHECK (digest NOT GLOB '*[^0-9a-f]*'),
            CHECK (publisher_id <> ''),
            CHECK (instr(registry_id, char(31)) = 0)
        )
        """,
        # One id resolves to one digest per version, and the same bytes cannot
        # be republished under one id under a second version: two versions of
        # one artifact carrying one digest is a catalog that cannot tell which
        # label a reader is looking at.
        "CREATE UNIQUE INDEX idx_marketplace_artifacts_digest "
        "ON marketplace_artifacts(artifact_id, digest)",
        "CREATE INDEX idx_marketplace_artifacts_registry "
        "ON marketplace_artifacts(registry_id)",
        "CREATE INDEX idx_marketplace_artifacts_publisher "
        "ON marketplace_artifacts(publisher_id)",
        """
        CREATE TABLE marketplace_certifications (
            artifact_digest TEXT NOT NULL,
            fault_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            cell_fingerprint TEXT NOT NULL,
            cell_label TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN
                ('pending','certified','expiring','stale','failed','incompatible')),
            expires_at TEXT NOT NULL,
            certification_json TEXT NOT NULL,
            linked_at TEXT NOT NULL,
            PRIMARY KEY (artifact_digest, fault_id, sequence),
            CHECK (length(artifact_digest) = 64),
            CHECK (artifact_digest NOT GLOB '*[^0-9a-f]*'),
            CHECK (sequence >= 1),
            CHECK (fault_id <> ''),
            CHECK (cell_fingerprint <> '')
        )
        """,
        "CREATE INDEX idx_marketplace_certifications_state "
        "ON marketplace_certifications(artifact_digest, state)",
        "CREATE INDEX idx_marketplace_certifications_cell "
        "ON marketplace_certifications(cell_fingerprint)",
        """
        CREATE TABLE marketplace_supply_chain (
            artifact_id TEXT NOT NULL,
            version TEXT NOT NULL,
            digest TEXT NOT NULL,
            publisher_id TEXT NOT NULL,
            publisher_json TEXT NOT NULL,
            verification_state TEXT NOT NULL CHECK (verification_state IN
                ('not_checked', 'digest_matched', 'digest_mismatched')),
            -- Integrity only. No value but 0 can be written, so this table can
            -- never be read as saying a signature was checked.
            signature_verified INTEGER NOT NULL DEFAULT 0 CHECK (signature_verified = 0),
            sbom_digest TEXT NOT NULL DEFAULT '',
            sbom_json TEXT NOT NULL DEFAULT '',
            dependency_count INTEGER NOT NULL DEFAULT 0,
            declared_permissions_json TEXT NOT NULL,
            release_count INTEGER NOT NULL DEFAULT 0,
            release_head_digest TEXT NOT NULL DEFAULT '',
            record_json TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (artifact_id, version),
            CHECK (length(digest) = 64),
            CHECK (digest NOT GLOB '*[^0-9a-f]*'),
            CHECK (dependency_count >= 0),
            CHECK (release_count >= 1),
            -- The newest release entry must be the bytes this record describes,
            -- or the release history is describing an artifact that is not here.
            CHECK (release_head_digest = digest)
        )
        """,
        "CREATE INDEX idx_marketplace_supply_chain_digest "
        "ON marketplace_supply_chain(digest)",
        """
        CREATE TABLE marketplace_revocations (
            revocation_id TEXT NOT NULL,
            scope TEXT NOT NULL CHECK (scope IN
                ('artifact_version', 'publisher', 'registry')),
            reason TEXT NOT NULL CHECK (reason IN
                ('security_defect', 'license', 'malformed', 'superseded', 'policy', 'other')),
            artifact_id TEXT NOT NULL DEFAULT '',
            version TEXT NOT NULL DEFAULT '',
            digest TEXT NOT NULL DEFAULT '',
            publisher_id TEXT NOT NULL DEFAULT '',
            registry_id TEXT NOT NULL DEFAULT '',
            issued_at TEXT NOT NULL,
            propagation_deadline TEXT NOT NULL,
            detail TEXT NOT NULL,
            revocation_json TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            PRIMARY KEY (revocation_id),
            CHECK (instr(revocation_id, char(31)) = 0),
            -- ISO-8601 in UTC, so the lexicographic comparison is the
            -- chronological one. Enforced in the domain too; a CHECK here means
            -- a row claiming to be in force before it was issued cannot be written.
            CHECK (propagation_deadline > issued_at),
            CHECK (detail <> ''),
            -- Each scope names exactly its own target. A revocation that
            -- over-reaches reads as "we withdrew something" while matching
            -- nothing, so the shape is refused by the schema too.
            CHECK (
                (scope = 'artifact_version'
                    AND artifact_id <> '' AND version <> '' AND digest <> ''
                    AND publisher_id = '' AND registry_id = '')
                OR (scope = 'publisher' AND publisher_id <> ''
                    AND artifact_id = '' AND version = '' AND digest = ''
                    AND registry_id = '')
                OR (scope = 'registry' AND registry_id <> ''
                    AND artifact_id = '' AND version = '' AND digest = ''
                    AND publisher_id = '')
            ),
            CHECK (digest = '' OR (length(digest) = 64 AND digest NOT GLOB '*[^0-9a-f]*'))
        )
        """,
        "CREATE INDEX idx_marketplace_revocations_target "
        "ON marketplace_revocations(scope, artifact_id, version, publisher_id, registry_id)",
        "CREATE INDEX idx_marketplace_revocations_deadline "
        "ON marketplace_revocations(propagation_deadline)",
        """
        CREATE TABLE marketplace_pins (
            artifact_id TEXT NOT NULL,
            version TEXT NOT NULL,
            digest TEXT NOT NULL,
            registry_id TEXT NOT NULL,
            provider_id TEXT NOT NULL,
            state TEXT NOT NULL CHECK (state IN ('installed', 'removed')),
            installed_at TEXT NOT NULL,
            removed_at TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (artifact_id, version, digest),
            CHECK (instr(artifact_id, char(31)) = 0),
            -- A pin without its bytes is a version range wearing a pin's name.
            CHECK (length(digest) = 64),
            CHECK (digest NOT GLOB '*[^0-9a-f]*'),
            CHECK (provider_id <> ''),
            -- A removed pin has a removal stamp; a live one has none.
            CHECK (
                (state = 'installed' AND removed_at = '')
                OR (state = 'removed' AND removed_at <> '')
            )
        )
        """,
        "CREATE UNIQUE INDEX idx_marketplace_pins_live "
        "ON marketplace_pins(artifact_id, version) WHERE state = 'installed'",
        "CREATE INDEX idx_marketplace_pins_provider ON marketplace_pins(provider_id, state)",
    ),
    down_statements=(
        "DROP INDEX idx_marketplace_pins_provider",
        "DROP INDEX idx_marketplace_pins_live",
        "DROP TABLE marketplace_pins",
        "DROP INDEX idx_marketplace_revocations_deadline",
        "DROP INDEX idx_marketplace_revocations_target",
        "DROP TABLE marketplace_revocations",
        "DROP INDEX idx_marketplace_supply_chain_digest",
        "DROP TABLE marketplace_supply_chain",
        "DROP INDEX idx_marketplace_certifications_cell",
        "DROP INDEX idx_marketplace_certifications_state",
        "DROP TABLE marketplace_certifications",
        "DROP INDEX idx_marketplace_artifacts_publisher",
        "DROP INDEX idx_marketplace_artifacts_registry",
        "DROP INDEX idx_marketplace_artifacts_digest",
        "DROP TABLE marketplace_artifacts",
        "DROP INDEX idx_marketplace_registries_scope",
        "DROP TABLE marketplace_registries",
    ),
)


# Plan 12 Phase 4 — the audit log as an attested event stream.
#
# This is a *cross-run* stream, and that is the whole reason it needs its own
# table rather than living in `attestation_events`. Phase 1's verifier defines a
# chain as starting at genesis and requires every event in it to share one
# `run_id`, so a per-run chain physically cannot hold entries about many runs.
# `infra/audit_stream.py` therefore gives every stream entry the *same*
# `run_id` — the stream's own id — and records the run being acted on in the
# payload. One format, one canonicalizer, one `verify_chain`: this is a second
# *table*, never a second *format*.
#
# What these tables do and do not claim:
#
# * **Append-only is enforced by triggers, not by convention.** `BEFORE UPDATE`
#   and `BEFORE DELETE` triggers RAISE, so an audit row cannot be edited or
#   removed even by a direct SQL writer. The application code has no update or
#   delete path at all; the triggers are the backstop for the case where
#   somebody goes around it. This is what lets requirement 4 close honestly: a
#   retention deletion removes the *manifest*, and the audit entry recording that
#   deletion is not reachable by the same deletion.
# * **No `signature_state` column.** The stream is unsigned, and the reason is
#   in `infra/attestation_store.UNSIGNED_REASON_NO_SIGNING` plus a module-level
#   constant — not in a per-row column nobody would read. Authorship is not
#   claimed anywhere (Phase 6).
# * **No foreign keys to `runs`, `attestation_manifests`, or anything else**, for
#   the gap-101 reason: the audit trail must survive the control plane deleting
#   the very records it describes.
# * `audit_stream_heads` holds one row per stream naming the current root and
#   count, so a verifier can detect a *truncated* stream — a chain whose tail was
#   removed is still internally consistent, so only a recorded head can catch it.
M0029_AUDIT_STREAM = Migration(
    version=29,
    name="audit_stream",
    statements=(
        """
        CREATE TABLE audit_entries (
            stream_id TEXT NOT NULL,
            sequence INTEGER NOT NULL,
            event_id TEXT NOT NULL,
            event_kind TEXT NOT NULL,
            principal TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            subject_run_id TEXT NOT NULL DEFAULT '',
            policy_digest TEXT NOT NULL DEFAULT '',
            approval_digest TEXT NOT NULL DEFAULT '',
            decision_digest TEXT NOT NULL DEFAULT '',
            previous_digest TEXT NOT NULL DEFAULT '',
            digest TEXT NOT NULL,
            chain_link TEXT NOT NULL,
            recorded_at TEXT NOT NULL,
            event_json TEXT NOT NULL,
            PRIMARY KEY (stream_id, sequence),
            -- An entry names an actor, an action, and a target. An entry with
            -- any of them blank is not an audit record, it is a row.
            CHECK (principal <> ''),
            CHECK (action <> ''),
            CHECK (target <> ''),
            CHECK (instr(principal, char(31)) = 0),
            CHECK (instr(action, char(31)) = 0),
            CHECK (instr(target, char(31)) = 0),
            -- Digest columns are digests or empty, never prose: the same rule
            -- `M0028_MARKETPLACE` applies to its own digest columns.
            CHECK (digest = '' OR (length(digest) = 64 AND digest NOT GLOB '*[^0-9a-f]*')),
            CHECK (
                chain_link = ''
                OR (length(chain_link) = 64 AND chain_link NOT GLOB '*[^0-9a-f]*')
            ),
            CHECK (
                previous_digest = ''
                OR (length(previous_digest) = 64 AND previous_digest NOT GLOB '*[^0-9a-f]*')
            ),
            CHECK (
                policy_digest = ''
                OR (length(policy_digest) = 64 AND policy_digest NOT GLOB '*[^0-9a-f]*')
            ),
            CHECK (
                approval_digest = ''
                OR (length(approval_digest) = 64 AND approval_digest NOT GLOB '*[^0-9a-f]*')
            ),
            CHECK (
                decision_digest = ''
                OR (length(decision_digest) = 64 AND decision_digest NOT GLOB '*[^0-9a-f]*')
            )
        )
        """,
        "CREATE UNIQUE INDEX idx_audit_entries_identity "
        "ON audit_entries(stream_id, event_id)",
        "CREATE INDEX idx_audit_entries_principal "
        "ON audit_entries(stream_id, principal, sequence)",
        "CREATE INDEX idx_audit_entries_target "
        "ON audit_entries(stream_id, target, sequence)",
        "CREATE INDEX idx_audit_entries_subject_run "
        "ON audit_entries(subject_run_id, sequence)",
        "CREATE TRIGGER audit_entries_no_update BEFORE UPDATE ON audit_entries "
        "BEGIN SELECT RAISE(ABORT, 'audit_entries is append-only: UPDATE is refused'); END",
        "CREATE TRIGGER audit_entries_no_delete BEFORE DELETE ON audit_entries "
        "BEGIN SELECT RAISE(ABORT, 'audit_entries is append-only: DELETE is refused'); END",
        """
        CREATE TABLE audit_stream_heads (
            stream_id TEXT PRIMARY KEY,
            chain_root TEXT NOT NULL DEFAULT '',
            entry_count INTEGER NOT NULL DEFAULT 0,
            last_event_id TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT ''
        )
        """,
        "CREATE TRIGGER audit_stream_heads_no_delete BEFORE DELETE ON audit_stream_heads "
        "BEGIN SELECT RAISE(ABORT, 'audit_stream_heads is append-only: DELETE is refused'); END",
    ),
    down_statements=(
        "DROP TRIGGER audit_stream_heads_no_delete",
        "DROP TABLE audit_stream_heads",
        "DROP TRIGGER audit_entries_no_delete",
        "DROP TRIGGER audit_entries_no_update",
        "DROP INDEX idx_audit_entries_subject_run",
        "DROP INDEX idx_audit_entries_target",
        "DROP INDEX idx_audit_entries_principal",
        "DROP INDEX idx_audit_entries_identity",
        "DROP TABLE audit_entries",
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
    M0017_RESOLVED_TARGET,
    M0018_REPLAY_CAPSULES,
    M0019_COVERAGE_GRAPH,
    M0020_CAMPAIGN_CHECKPOINTS,
    M0021_GAME_DAY_SESSIONS,
    M0022_SECRET_GRANTS,
    M0023_ATTESTATION_RETENTION,
    M0024_CERTIFICATION_RECORDS,
    M0025_AGENT_IDENTITY_BACKUPS,
    M0026_SCHEDULES,
    M0027_COVERAGE_FINDINGS,
    M0028_MARKETPLACE,
    M0029_AUDIT_STREAM,
)
