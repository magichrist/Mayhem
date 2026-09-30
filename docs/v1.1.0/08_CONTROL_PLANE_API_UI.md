# Plan 08 — Production Control Plane, API, and UI

**Priority:** P0. Gap items 10, 31, 32, 59, 60, 61.

## Objective
Turn Mayhem into a multi-user product without weakening the CLI-first workflow — and fold in the visual timeline (32), executive reporting surface (59), failure-explanation engine (60), and parameter UX (61) as views over the same API objects, not separate systems.

## Builds on
- `cli/command_registry.py` single inventory plus `PrefixGroup` resolution: every API mutation maps to a command path with identical validation, so CLI and UI create identical immutable plan objects.
- `schemas/output_v1.json` envelope: the API's response shape starts here and versions forward (`/api/v1`, then `/api/v2` by extension, never by breakage).
- `RunEngine` ordering, evidence envelope, graded verdicts: the UI explains them; it never reimplements them.

## Decided: SQLite plus replication
Per program decision, the control plane keeps SQLite as the store (single-writer discipline, existing 23-migration chain intact) and adds durability and scale through replication: WAL archiving, snapshot shipping to standbys, standby promotion fenced by the 03 fencing tokens so two primaries can never own the same run, plus object-store evidence offload per 12. No second database engine, no migration-chain fork.

## Services
API gateway, authentication (09), authorization (09), planner service,
policy service (07), scheduler (13), orchestrator (03), agent registry,
evidence service (12), notification service.

## API
OpenAPI, versioned `/api/v1`, pagination/filtering/sorting, idempotency
keys, request IDs, webhooks, server-sent events/WebSocket live updates,
normalized errors. SDKs (Python, Go, Rust, TypeScript) generated from
the OpenAPI contract once v1 is stable.

## UI
Dashboard, experiment builder, live run view, topology, fault catalog,
policies, approvals, schedules, campaigns/game days, evidence,
agents/clusters, teams/users, reports. The experiment screen shows
hypothesis, targets, faults, timeline, blast radius, safety proof (30),
probes, stop conditions, expected impact, approval, execute — all as
projections of API objects.

## UI principle
Everything visible in the UI must map back to a machine-readable API object. No UI-only state for core execution concepts.

## Phase 1 — Domain model: API resource vocabulary
Add `domain/api.py`: resource shapes for experiments, plans, runs, approvals, policies, schedules, evidence references — each a thin projection of existing domain types, never a parallel model. Timeline events (gap 32: baseline → fault → observe → recover → verify with per-point drill-down) defined as views over stored events. Failure explanations (gap 60: hypothesis, observed vs. tolerance, impact chain, recovery result, evidence refs) defined as a report type computed from observations, never hand-written prose. Acceptance: round-trip tests — every API object converts losslessly to and from its domain source.

## Phase 2 — Engine: services over existing seams
Planner/policy/scheduler/orchestrator/evidence services as thin facades over `plan_drill`, `validate_plan`, the 13 scheduler, `RunEngine`, and the bundle store. Replication: WAL archive + snapshot ship + fenced standby promotion, exercised by controller-kill drills. Acceptance: killing the primary mid-run promotes the standby with no duplicate step execution (fencing test, not faith).

## Phase 3 — Surface: REST, UI MVP, parameter UX
Ship `/api/v1` with OpenAPI, then the UI MVP (dashboard, builder, live run, evidence, approvals). Parameter UX (gap 61: sliders, direction selectors, risk/impact/capability annotations per fault) renders from catalog parameter schemas — the schema is the single source, so CLI `--help` and UI controls cannot disagree. Acceptance: CLI and UI submissions produce byte-identical frozen plans for the same inputs.

## Phase 4 — Safety and evidence integration
All mutations carry execution intent and policy decisions; approvals bind to plan digests (09); every number on the executive dashboard (gap 59: services tested, pass/degrade/fail counts, coverage, open findings) links to sealed evidence. The failure-explanation engine cites exact probe observations. Acceptance: a dashboard number without an evidence link fails review.

## Phase 5 — Tests, regression guards, negative controls
API contract tests (OpenAPI validated against live routes), plan-equivalence tests (CLI vs UI), replication failover drills, RBAC tests per endpoint (with 09). Negative controls: an API call that bypasses approval is refused at the service layer even with a valid session; a standby that lost fencing cannot promote. Acceptance: full suite green; failover drill in CI.

## Phase 6 — Docs, honesty gates, rollout
API reference generated from OpenAPI (never hand-maintained), UI operator guide, replication runbook (RPO/RTO stated and tested). Rollout: read-only API and dashboard first, mutations behind existing approval gates, standby promotion only after three clean drills. Acceptance: no UI label claims a capability the API cannot prove.

## Dependencies
03 (orchestrator/fencing), 07 (policy service), 09 (auth/RBAC/approvals), 12 (evidence service), 13 (scheduler), 30 (proof view).

## STATUS — planning only, 0%
