# Plan 10 — Diagnostics, Recovery, and Reporting

## Builder brief

Make Mayhem feel professional when things fail. The product should explain what happened, preserve evidence, help an operator recover safely, and produce a useful report without requiring source-code knowledge or manual database inspection.

## Phase 1 — Unify diagnostics and run inspection

### Work

- Build a diagnostic model with check id, severity, status, evidence, remediation, and related run.
- Upgrade `expert` into a structured diagnostic workflow while keeping its existing flags.
- Add `inspect doctor` and `inspect run` projections.
- Add `inspect leases` with owner, TTL, target, fault, state, and recovery status.
- Add a stable report identifier shared by CLI, store, and artifacts.

### Files

- `src/mayhem/infra/diagnostics.py`
- `src/mayhem/cli/expert.py`
- `src/mayhem/cli/inspect.py`
- `src/mayhem/infra/report.py`
- `tests/unit/test_report.py`
- `tests/unit/test_diagnostics.py`

### Verification

- Tests cover healthy, warning, blocked, dirty, and missing-runtime diagnostics.
- Diagnostics never claim an external service is healthy based on a stale local cache.

## Phase 2 — Make recovery explicit and safe

### Work

- Define recovery states: not needed, pending, running, recovered, dirty, escalated, abandoned.
- Add `recover status`, `recover plan`, and `recover execute` with explicit run ids and target profiles.
- Show lease ownership, expiry, compensation, verification probe, and escalation path.
- Make janitor dry-run the default and require explicit execution for cleanup.
- Add a dirty-state handoff artifact for manual remediation.

### Files

- `src/mayhem/controller/recovery.py`
- `src/mayhem/controller/janitor.py`
- `src/mayhem/cli/lifecycle.py`
- `src/mayhem/domain/leases.py`
- `tests/unit/test_recovery.py`
- `tests/unit/test_janitor.py`
- `tests/unit/test_lifecycle_run_liveness.py`

### Verification

- Recovery tests cover orphan, expired, active, dirty, idempotent, and escalated cases.
- No recovery command silently changes a run’s terminal verdict.
- Dry-run recovery has no side effects.

## Phase 3 — Add portable reports and evidence exports

### Work

- Add Markdown, JSON, and HTML report renderers from the same evidence envelope.
- Include executive summary, environment, plan, safety decisions, timeline, observations, verdict, recovery, and limitations.
- Add artifact directory and retention policy.
- Add redaction rules for secrets and environment-specific data.
- Add a report comparison view for two runs.

### Acceptance criteria

- A user can share a report that explains the experiment without access to the database or source tree.
- Reports distinguish unit-tested behavior from live-verified behavior.
- Recovery and reporting remain separate from mutation execution.

### Verification

- Run report, recovery, janitor, CLI, documentation, and full unit tests.
- Run Ruff and record its result.
