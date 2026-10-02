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

## STATUS
- Phase 1 (domain model): DONE — `domain/api.py` lands the resource vocabulary as digest-bound projections of the existing domain types (experiments, plans, plan steps, runs, outcomes, approvals, policy decisions, schedules, evidence references), the derived timeline over stored events (32), the withholding failure explanation over the recorded graded verdict (60), and the provenance-carrying executive summary (59)
- Phase 2 (engine): DONE — `infra/api_store.py` persists all nine Phase 1 resources behind `M0030_API_RESOURCES` (nested `resource_json` is authoritative; the denormalised filter/sort columns are a *query index* with an auditor, `ApiStore.audit_indexes`, so drift is a refusal rather than a wrong answer), and `infra/replication.py` lands the SQLite-plus-replication strategy: WAL archiving, snapshot shipping over SQLite's online backup API, and **fenced** standby promotion on plan 03's `FencingToken`. Resource shape decision: **nested on disk, flat at the query boundary** — the ledger's response shape stays Phase 1's nested one and the flat columns exist only so `WHERE status = ?` never parses JSON, with every one of them re-derived and checked on read.
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

### What the Phase 2 failover drill proved, and what it did not

`tests/unit/test_replication.py` runs the drill the plan asks for — a **fencing test, not faith**. A primary is genuinely killed with `SIGKILL` mid-step in a child process (no cleanup, no `atexit`, nothing flushed), a standby is promoted from a shipped snapshot, and the assertion is over an effect log the *child process itself* wrote: each step completes exactly once, the two steps the dead primary had already completed are provably not re-driven, the in-flight step is re-driven under a strictly newer step fence, and no `running` row is left behind.

Two mechanisms, deliberately kept apart because they fail differently:

- **Fencing** stops a *superseded writer*, via `repl_fences` (monotone by schema — an UPDATE that does not increase the epoch RAISEs, DELETE RAISEs) plus `FencingToken.next_fence` as the only way to grow one. A standby whose last-seen fence is behind the ledger cannot promote; a snapshot or WAL segment from a deposed primary is refused **by the receiver, against the receiver's own ledger, before the first byte moves**; a promotion whose replicated step ledger names a step the plan does not contain is refused rather than completed with a footnote.
- **The partial unique index** on `repl_step_ledger` stops a *second completion of one step* as a constraint violation. Either mechanism alone leaves a hole: fencing without the index still lets two epochs each believe they completed the same step, and the index without fencing lets a deposed primary complete one the promoted primary already re-drove.

What the drill does **not** prove, stated plainly because the difference matters for the rollout decision:

1. **Two nodes are two files in one interpreter, not two hosts.** No network, no separate page cache, no process-boundary latency, no clock skew. It says nothing about RPO/RTO in real time.
2. **The fence ledger is replicated, not quorum-witnessed.** Promotion mints `recorded_epoch + 1` from the ledger that arrived with the snapshot, which is correct whenever the snapshot is at least as new as every epoch the previous primary ever issued — a property of the shipping discipline, not of this code. A *partitioned* standby whose snapshot predates a later promotion would mint an epoch already in use. Consequently **a deposed primary's own database file is a divergent copy and nothing here can refuse its writes**; what is refused is every write and every shipped byte checked against a ledger that has seen the newer epoch, which is the check that happens in a real deployment. Closing the remaining gap needs an external witness for the epoch counter (etcd/consul, or a single arbiter process) — a deployment decision Phase 6 owns. The refusal paths are all implemented and all tested; the end-to-end guarantee is honest only once the witness exists.
3. **No service facades yet.** The seam they need is in place (`ApiStore.plan_for_run` hands `controller.safety_proof` the exact `ExecutionPlan` whose digest the API displays, and `explain`/`summarise`/`timeline` run Phase 1's report functions over what is stored), but the planner/policy/scheduler/orchestrator/evidence facades and the gateway are Phase 3's.

Overall: 2 of 6 phases complete.
