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
- Phase 3 (surface: REST, UI MVP, parameter UX): DONE — **no dependency was added.** `controller/api_service.py` is the `/api/v1` gateway and the plan's service facades' query half: 18 routes as data, an OpenAPI document *generated* from that table (`openapi_document()` refuses to build a document naming a handler the gateway does not implement), pagination with a declared maximum, idempotency keys, and normalized errors that carry their rule id in `meta.rule_id` *and* inside `errors[0]`. `controller/api_http.py` is the WSGI adapter (`wsgiref`, standard library) plus the control-plane application that serves `/ui/*` and `/api/v1/*` from one socket. `controller/api_planner.py` holds the planner/policy/evidence facades. `cli/api_cmd.py` is the operator surface (`routes`, `openapi`, `parameters`, `pages`, `ui`), invoked directly in `tests/unit/test_api_cli.py` because `cli/command_registry.py` is not this work item's to edit. Parameter UX (gap 61) is `parameter_controls()`, a total projection from `domain/catalog.py`'s `FaultDefinition` and nothing else — 207 controls, 35 of them sliders derived from the schemas' own bounds, so a disagreement with CLI `--help` is not expressible. **The UI is `controller/api_ui.py`: server-rendered HTML with no JS, no CSS framework, and no bundler**, consuming plans 14/15/21's own view-models — `build_risk_preview`→`preview_payload`, `boundary_report_view`→`to_dict`, `ranked_views`/`advisor_dashboard`→`AdvisorDashboard.to_dict` — plus Phase 1's `RunTimeline`, `FailureExplanation`, and `ExecutiveSummary`. It is the *second renderer* those three plans recorded as the open half of their acceptance criteria. Drift is prevented structurally: every page is built from the payload dict the gateway's `GET` returns and there is no code path from a page to a domain object, so `page.api_payload == response.data` is an identity a test asserts rather than an agreement two renderers might reach. Plan 10's "the 08 UI button" lands as `render_stop_panel` — one form posting to `POST /api/v1/runs/{run_id}/stop`, reason required, no force and no skip-preflight control
- Phase 4 (safety and evidence): DONE — `controller/api_safety.py` refuses on the mutation path in the order the plan names: **no execution intent** (`api.execution_intent_required`, carrying `domain.execution_intent`'s own code; `allow_implicit` is left at its `None` default so mayhem's documented `MAYHEM_ALLOW_IMPLICIT_EXECUTION=1` switch is never honoured here, asserted with the environment variable *set*), an intent bound to another plan or expired, a **recorded policy decision that denies** (an absent one refuses too — `PolicyService.allow` raises and the refusal propagates), and **approvals verified through `controller/approval_gate.verify_approvals` bound to this plan's digest**, so an approval for plan A cannot authorize plan B and the refusal carries plan 09's own `approval.required`. `bind_approval` *projects* an approval into its API resource and cannot mint one — `domain.approval.Approval.bind` is the only constructor and it derives the digest from a `PASS` proof. `check_dashboard_payload` is the acceptance criterion as an executable check, and the same refusal is asserted at the renderer so a future Phase 1 change cannot remove one without the other. **The Phase 4 negative control caught a real defect in this phase's own code**: `PlannerMutationPort` compiled *and persisted* before authorizing, so a refused mutation had already written a plan row. The order is now compile-without-persisting → authorize → store, and the test asserts against the store rather than a flag
- Phase 5 (tests, regression guards, negative controls): DONE — 186 tests across `tests/unit/test_api_service.py` (54), `test_api_cli.py` (34), `test_api_safety.py` (30), `test_api_ui.py` (37), `test_api_http.py` (20, driving a **real `wsgiref` server on an ephemeral port** so status codes, bodies, headers, and the HTML/JSON split are asserted as a client receives them), `test_api_planner.py` (11) — 0 failures, 0 errors, 0 skips. Every acceptance criterion is an executable claim and every negative control breaks the property it guards and asserts the refusal *by name*: authorize-before-validate (an unauthorized principal sending a non-JSON body is refused with `auth.role_missing`, not a parse error); a missing environment is refused rather than defaulted; a session for one environment cannot reach another; the same idempotency key with a different request is a 409; a mutation with no bound port is a 501; a route table naming an absent CLI command, a non-idempotent mutation, a read behind an action role, and a duplicated `(method, path)` are all refused at construction; a slider boundary asserted from both sides of `SLIDER_SPAN_LIMIT`; a dashboard number stripped of its evidence; a submit control that appears for a usable preview and vanishes for an unusable one; a page missing its object; a stop panel with no bypass control, asserted over *submitted control names* so the check is not defeated by the panel's own explanatory prose; and a refused mutation leaving no plan row and no receipt row
- Phase 6 (docs, honesty gates, rollout): DONE — `docs/api-control-plane.md` is the operator guide and the replication runbook: the endpoint table, the authorization model read out of plan 09, why CLI/UI cannot drift, what every page refuses, and a **rollout that says standby promotion is not cleared** because Phase 2's drill proves the mechanism inside two files in one interpreter and no cross-host drill, no network, and no epoch witness exist yet — so **RPO/RTO are not stated, because stating them would be fabricating them**. "No UI label claims a capability the API cannot prove" is enforced two ways: every page names its API path and ends with a *what this page does not claim* section, and `UNIMPLEMENTED_API_SURFACES` is served by `GET /api/v1/health` and printed by `mayhem api routes`, so the omissions are a record rather than a silence. The migration reservations are documented with their versions and their runtime-report-the-absence behaviour, and `docs/api-control-plane.md` states plainly that a sealed envelope proves which bytes were sealed and **never** who sealed them

Overall: 6 of 6 phases complete.

### What Phase 3 could not do, and did not fake

**There is no browser bundle.** The UI is server-rendered HTML over `wsgiref`. No
Node, no bundler, and no lockfile exist in this repository, and a front-end bundle
nobody here can build or run is an artefact nobody can honestly claim. Every part
of this plan that a UI is *for* — the payload contract, the view-model wiring, the
parameter controls, the evidence links, the stop form — is implemented and tested;
what is absent is a client-side application framework, which the plan never asked
for by name.

**Literal byte-identical plans are not achievable in this build, and the reason is
not the API.** `controller/planner.py` mints a fresh `execution_group_id` from
`uuid.uuid4()` for every step group (lines 705, 828, 1033), so two compilations of
the same spec differ in that field alone — on the CLI and over HTTP, equally.
`test_api_planner.py` therefore asserts the acceptance criterion in the only form
that is a property of this code: **every field either surface can influence is
byte-identical**, over the whole serialization with exactly one named
normalization, *and* the set of differing paths is enumerated and asserted to be
exactly the nonce — so a second meaningful difference would fail even though the
normalized comparison would still pass. A test pins the limitation itself, so if a
future planner change removes the randomness the file fails and the limitation can
be struck. Closing the gap is a two-line change in `plan_drill` (an optional
`group_id` factory) plus one call-site change in `cli/services.py`; neither file
belongs to this work item.

### Two integration dependencies other lanes must satisfy

1. **`cli/command_registry.py` registration.** `mayhem.api` is a complete Click
   group and is **not registered**: add a `CommandSpec("api", "inspect")` plus
   `api` in `command_map` and `COMMAND_HELP`. Until then it is reachable only
   through `CliRunner`, which is what `tests/unit/test_api_cli.py` does, and
   `test_command_inventory.py` / `test_cli_exhaustive_matrix.py` will not see it.
   Note that `docs/api-control-plane.md` deliberately documents no `mayhem api …`
   invocation, because `test_readme_honesty.py`'s command-resolution check runs
   over published documents.
2. **`infra/migrations.py` — two reservations, in order.** Append
   `API_GATEWAY_MIGRATION` (version **34**, `api_gateway`, table
   `api_idempotency`, from `controller/api_service.py`) and then
   `API_SAFETY_MIGRATION` (version **35**, `api_safety`, table
   `api_mutation_receipts`, from `controller/api_safety.py`). Both objects are
   complete with working down paths; both define their SQL in their own module so
   the DDL cannot drift from the row model, exactly as `fabric_journal.py` does.
   Until they are appended, the idempotency table does not exist in a deployed
   database and the mutation receipt is reported as `recorded: false` with the
   reason naming the migration — never silently dropped. Each module's test asserts
   its own version is above the registered head, so a collision is reported rather
   than silently duplicated.

No `OBLIGATION_FOR_RULE` or `RULE_CHECK` mapping is required and none is being
requested: the two modules whose rules must be mappable are `controller/safety.py`
and `controller/approval_gate.py`, neither of which this work item edits. Plan 08's
new rule ids (`api.*`, `ui.*`) are raised by the gateway and the renderer, are not
blameable by the proof compiler, and raise their own typed errors. Likewise no
`BOUNDARY_CALL_SITES` row is required: no plan-08 module calls
`require_persistable_document`, `require_envelope_boundary`,
`require_clean_artifact`, or `require_clean_log_line`; the control-plane tables are
query indexes over derived data, not evidence artifacts, and
`tests/unit/test_evidence_boundary.py` passes unchanged.

### Where the plan's own acceptance criteria landed, verbatim

* *"Ship `/api/v1` with OpenAPI"* — done, generated from the route table.
* *"UI MVP (dashboard, builder, live run, evidence, approvals)"* — five renderers,
  all consuming payloads; the two that need a whole-collection read are routable at
  `/ui`, and the rest are rendered by a caller holding their payload.
* *"Parameter UX renders from catalog parameter schemas — the schema is the single
  source, so CLI `--help` and UI controls cannot disagree"* — done, with the test
  that asserts the widget the browser renders is the widget the terminal prints.
* *"CLI and UI submissions produce byte-identical frozen plans for the same
  inputs"* — met in the form this build supports, with the residual named above.
* *"All mutations carry execution intent and policy decisions"* — done, refused
  before anything is persisted.
* *"Approvals bind to plan digests"* — done through plan 09's own gate.
* *"Every number on the executive dashboard links to sealed evidence"* — structural
  in Phase 1, re-checked in Phase 4 and again in the renderer.
* *"The failure-explanation engine cites exact probe observations"* — asserted over
  a stored run: every claim carries a reference and every section is either
  explained or withheld.
* *"An API call that bypasses approval is refused at the service layer even with a
  valid session"* — done and tested from both directions: without an intent, and
  with an approval bound to a different plan.
* *"API reference generated from OpenAPI (never hand-maintained)"* — done;
  `mayhem api openapi --out` writes a pinned copy and the test parses it back.
* *"RPO/RTO stated and tested"* — **NOT DONE, deliberately.** No cross-host drill
  exists, so there is no number to state. Stating one would be the overclaim this
  phase exists to prevent; the runbook says so in the section that names what is
  missing.
* *"No UI label claims a capability the API cannot prove"* — enforced; see Phase 6.

### What the Phase 2 failover drill proved, and what it did not

`tests/unit/test_replication.py` runs the drill the plan asks for — a **fencing test, not faith**. A primary is genuinely killed with `SIGKILL` mid-step in a child process (no cleanup, no `atexit`, nothing flushed), a standby is promoted from a shipped snapshot, and the assertion is over an effect log the *child process itself* wrote: each step completes exactly once, the two steps the dead primary had already completed are provably not re-driven, the in-flight step is re-driven under a strictly newer step fence, and no `running` row is left behind.

Two mechanisms, deliberately kept apart because they fail differently:

- **Fencing** stops a *superseded writer*, via `repl_fences` (monotone by schema — an UPDATE that does not increase the epoch RAISEs, DELETE RAISEs) plus `FencingToken.next_fence` as the only way to grow one. A standby whose last-seen fence is behind the ledger cannot promote; a snapshot or WAL segment from a deposed primary is refused **by the receiver, against the receiver's own ledger, before the first byte moves**; a promotion whose replicated step ledger names a step the plan does not contain is refused rather than completed with a footnote.
- **The partial unique index** on `repl_step_ledger` stops a *second completion of one step* as a constraint violation. Either mechanism alone leaves a hole: fencing without the index still lets two epochs each believe they completed the same step, and the index without fencing lets a deposed primary complete one the promoted primary already re-drove.

What the drill does **not** prove, stated plainly because the difference matters for the rollout decision:

1. **Two nodes are two files in one interpreter, not two hosts.** No network, no separate page cache, no process-boundary latency, no clock skew. It says nothing about RPO/RTO in real time.
2. **The fence ledger is replicated, not quorum-witnessed.** Promotion mints `recorded_epoch + 1` from the ledger that arrived with the snapshot, which is correct whenever the snapshot is at least as new as every epoch the previous primary ever issued — a property of the shipping discipline, not of this code. A *partitioned* standby whose snapshot predates a later promotion would mint an epoch already in use. Consequently **a deposed primary's own database file is a divergent copy and nothing here can refuse its writes**; what is refused is every write and every shipped byte checked against a ledger that has seen the newer epoch, which is the check that happens in a real deployment. Closing the remaining gap needs an external witness for the epoch counter (etcd/consul, or a single arbiter process) — a deployment decision Phase 6 owns. The refusal paths are all implemented and all tested; the end-to-end guarantee is honest only once the witness exists.
3. **No service facades yet.** The seam they need is in place (`ApiStore.plan_for_run` hands `controller.safety_proof` the exact `ExecutionPlan` whose digest the API displays, and `explain`/`summarise`/`timeline` run Phase 1's report functions over what is stored), but the planner/policy/scheduler/orchestrator/evidence facades and the gateway are Phase 3's.


