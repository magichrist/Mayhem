# The control plane: API, UI, and replication

This is the operator guide for plan 08 (`docs/v1.1.0/08_CONTROL_PLANE_API_UI.md`).
It is written to be checked against the code: every claim below names the module
that implements it, and every limitation below is stated rather than implied.

Read the plan's `## STATUS` for what landed and what did not. This document does
not repeat it.

---

## What this is

- A transport-neutral gateway over SQLite: `mayhem.controller.api_service`.
- A server-rendered UI that reads **only** API payloads:
  `mayhem.controller.api_ui` and `mayhem.controller.api_http`.
- Three service facades over seams that already existed:
  `mayhem.controller.api_planner` (planner, policy, evidence).
- A safety layer on the mutation path: `mayhem.controller.api_safety`.

**No dependency was added.** The HTTP surface is WSGI over `wsgiref` from the
standard library, because the declared dependency list is pydantic, typer, click,
pyyaml, structlog, and kubernetes, and a control plane that needs a web framework
installed is a control plane nobody can run from the artifact they already have.

## What this is not

Stated first, because the omissions are the ones a reader would otherwise assume:

| Not implemented | Why it matters |
|---|---|
| Webhooks, SSE, WebSocket live updates | A route table that looked like it supported them would be a lie in the place a client reads to find out what the control plane does. `UNIMPLEMENTED_API_SURFACES` names them, and `GET /api/v1/health` reports them. |
| Generated SDKs (Python, Go, Rust, TypeScript) | The plan defers them until v1 is stable. |
| Rate limiting | Not a gate, an omission. Say so in a deployment's edge, not here. |
| TLS, HSTS, CORS | A WSGI callable is an application protocol, not a security control. Terminate TLS in front of it. CORS is **default-deny**: no `Access-Control-Allow-Origin` is emitted. |
| A browser bundle or an SPA | No Node, no bundler, no lockfile in this repository. Server-rendered HTML is the whole UI, and it is a real, runnable, tested UI. |
| An approval *write* endpoint | There is no `mayhem approve` command in the single inventory for one to map to. Approvals are readable over HTTP and writable nowhere over HTTP. |
| `mayhem api serve` on the CLI | The function exists and works (`mayhem.controller.api_http.serve`); binding a network listener is a deployment action with a security surface, and putting it behind a one-word flag next to a command that prints a route table is how it gets bound by accident. |
| Signature verification | `mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` is `False`. A sealed evidence envelope proves **which bytes were sealed**, never **who sealed them**. Nothing in plan 08 changes that. |

## The authorization model

There is exactly one, and it is plan 09's. The gateway does not add a role, does
not add a hierarchy, and does not have a permission table.

1. **Authenticate** — `AuthService.authenticate_token`. Its refusal codes
   (`auth.session_unknown`, `auth.credential_invalid`, `auth.session_expired`, …)
   are *re-raised*, not restated, so a refusal means the same thing whether it came
   from the CLI, ChatOps, or HTTP.
2. **Authorize** — `AuthService.authorize` against the route's required
   `Role`, resolved through `domain.identity.effective_roles` over
   `IdentityStore` grants. For the mutating routes whose action is a ChatOps
   command, the required role is **read from**
   `check_gate.CHATOPS_REQUIRED_ROLE`, never restated.
3. **Then** parse the body, resolve idempotency, dispatch.

The ordering is the security property, and
`tests/unit/test_api_service.py::TestAuthorizeHappensBeforeValidate` asserts it by
sending an unauthorized principal a body that is not JSON and requiring the
*authorization* rule, not the parse rule. A validation message describes a
request; returning one to somebody who may not read the resource is an oracle.

Two further refusals worth knowing:

- **A request that names no environment is refused** (`auth.session_scope`).
  Resolving against a default would mean resolving against whichever environment
  happened to be granted first. Send `X-Mayhem-Environment`.
- **A session minted for `staging` cannot reach `production`**, even when the
  same principal holds a production grant, because plan 09's *reach* check runs
  with the authentication passed through.

## Endpoints

`mayhem api routes` prints the live table. `mayhem api openapi` prints the
generated OpenAPI document. Both read
`mayhem.controller.api_service.ROUTES`; neither can describe an endpoint that is
not served, because `openapi_document()` refuses to build a document naming a
handler the gateway does not implement.

| Method | Path | Role | Notes |
|---|---|---|---|
| GET | `/api/v1/health` | none | Liveness, version, and what is *not* served. |
| GET | `/api/v1/openapi.json` | none | The generated reference. |
| GET | `/api/v1/experiments` | `view` | |
| GET | `/api/v1/experiments/{name}` | `view` | |
| GET | `/api/v1/plans` | `view` | |
| POST | `/api/v1/plans` | `plan` | Compiles through the CLI's planner. Idempotency key required. Maps to `mayhem run`. |
| GET | `/api/v1/plans/{plan_digest}` | `view` | |
| GET | `/api/v1/runs` | `view` | Paged, filtered, sorted through the store's closed whitelists. |
| GET | `/api/v1/runs/{run_id}` | `view` | |
| GET | `/api/v1/runs/{run_id}/timeline` | `view` | Derived from stored events; nothing is stored as a point. |
| GET | `/api/v1/runs/{run_id}/explanation` | `view` | Cites probe observations; withholds what the observations cannot support. |
| GET | `/api/v1/runs/{run_id}/evidence` | `evidence_admin` | |
| GET | `/api/v1/approvals` | `view` | |
| GET | `/api/v1/policy-decisions` | `view` | |
| GET | `/api/v1/schedules` | `view` | |
| POST | `/api/v1/runs/{run_id}/stop` | `emergency_stop` | Maps to `mayhem stop`. Answers 501 until a deployment binds a port. |
| GET | `/api/v1/parameters` | `view` | The parameter UX (gap 61), projected from catalog schemas. |
| GET | `/api/v1/dashboard` | `view` | Executive numbers (gap 59), each carrying its evidence link. |

Every response is the Phase 1 `ApiEnvelope` — the CLI's own `output_v1` shape —
so there is exactly one response shape to parse. Every refusal carries its rule
id in `meta.rule_id` **and** inside `errors[0]`, so it is greppable without
parsing metadata.

### Idempotency

Every mutation requires an `Idempotency-Key` header. The same key with the same
request returns the recorded response byte for byte with `Idempotent-Replay:
true` and does **not** dispatch again. The same key with a *different* request is
a `409`, never the first response — returning a recorded result for a request that
differs is how a client concludes its second call did something.

## The UI

Server-rendered HTML at `/ui`. `/ui` itself is an index; `/ui/dashboard` and
`/ui/builder` render from a whole-collection API read; every other page needs a
*named* object and is rendered by a caller through
`mayhem.controller.api_ui.render_page`, which is what `mayhem api ui <page>
--payload <file>` does.

`/ui` routes need an internal render credential (`ControlPlaneApplication(
ui_token=...)`). With none bound they answer `501` naming the missing
configuration, because a UI that quietly read around its own authorization would
be the exact defect the gateway exists to prevent.

### Why the CLI and the UI cannot drift

The pages are built from **payload dictionaries** — the exact object the gateway's
`GET` returns — and every helper reads keys out of that dict. There is no code path
from a page to a domain object. The view-models are:

| Page | Renders from |
|---|---|
| builder / plan display | plan 14's `build_risk_preview` → `preview_payload` |
| boundaries | plan 15's `boundary_report_view` → `BoundaryReportView.to_dict` |
| recommendations | plan 21's `ranked_views` / `advisor_dashboard` → `AdvisorDashboard.to_dict` |
| dashboard | Phase 1's `ExecutiveSummary.to_dict` |
| live run | Phase 1's `RunTimeline.to_dict` and `FailureExplanation.to_dict` |
| parameter controls | `mayhem.domain.catalog` — the catalog and nothing else |

`tests/unit/test_api_ui.py` builds each of those view-models as the real frozen
dataclass from its owning module, projects it the way its CLI renderer does, and
asserts the page renders from that projection. That is an *identity*, not an
agreement between two renderers.

### What a page refuses

- A payload missing the key the page is about (`ui.no_api_object`) — an empty
  page reads as "nothing happened here", which is a finding.
- A dashboard number with no evidence link (`ui.number_without_evidence`).
  Phase 1 makes that payload unconstructible; the renderer re-checks so a future
  change to Phase 1 cannot quietly remove the refusal.
- An untraceable recommendation — refused upstream, *in the view-model*, by plan
  21's `ranked_views`, so deleting the Click callback cannot make the UI
  permissive.
- An unwitnessed value renders as unavailable or withheld, never as zero.

Every page ends with **"what this page does not claim"**. That is not decoration:
a surface that omits its own limitations reads as though it has none.

### The stop button

Plan 10 assigned plan 08 the stop UI affordance. It is
`mayhem.controller.api_ui.render_stop_panel`: one form posting to
`POST /api/v1/runs/{run_id}/stop`. A `--reason` is **required**, because a stop
with no reason cannot be sealed. There is no force control, no skip-preflight
control, and no client-side-only gate — the only gate is the endpoint's, which
resolves `emergency_stop` before writing anything.

**What is not claimed:** the button is rendered and the endpoint is routed, but the
ledger it seals is the CLI's, and plan 10's *stop-latency bound* has not been
measured against a request from this page. That bound remains plan 10's open item.

## Replication runbook

`mayhem.infra.replication` lands WAL archiving, snapshot shipping over SQLite's
online backup API, and **fenced** standby promotion.

**RPO / RTO are not stated here, because they are not known.** Phase 2's drill
proves the *mechanism* — a primary killed with `SIGKILL` mid-step, a standby
promoted, each step completing exactly once — inside **two files in one
interpreter**. It says nothing about network latency, partition, or clock skew, so
any number written here would be a fabrication. Stating RPO/RTO requires three
things Phase 2's STATUS line already names as absent:

1. **A witness for the epoch counter.** Promotion mints `recorded_epoch + 1` from
   the ledger that arrived with the snapshot, which is correct whenever the
   snapshot is at least as new as every epoch the previous primary issued — a
   property of the *shipping discipline*, not of the code. A partitioned standby
   whose snapshot predates a later promotion mints an epoch already in use.
   Closing this needs etcd/consul or a single arbiter process.
2. **A partitioned-primary story.** A deposed primary's own database file is a
   divergent copy and nothing in this build can refuse its writes. What *is*
   refused is every write and every shipped byte checked against a ledger that has
   seen the newer epoch.
3. **A cross-host drill.** Two hosts, a real network, a real clock.

The rollout rule the plan states — standby promotion only after three clean
drills — is **not met**. Do not promote a standby in a deployment that has not run
the drill three times across hosts.

## Safety on the mutation path

`mayhem.controller.api_safety` refuses, in this order:

1. **No execution intent** → `api.execution_intent_required`, carrying the
   domain's own code. `allow_implicit` is left at its `None` default, which is
   itself a refusal: mayhem's documented
   `MAYHEM_ALLOW_IMPLICIT_EXECUTION=1` switch is **never** honoured here.
2. **An intent bound to another plan, or an expired one** → refused with
   `INTENT_MISMATCH` / `APPROVAL_EXPIRED` from `domain.execution_intent`.
3. **A recorded policy decision that denies** → refused. An *absent* decision is
   not an allowance: `PolicyService.allow` raises and this propagates it.
4. **Approvals**, through `controller.approval_gate.verify_approvals` bound to
   *this* plan's digest. An approval for plan A cannot authorize plan B, and the
   refusal carries plan 09's own `approval.required`.
5. **A dashboard number with no evidence link** → `api.dashboard_number_without_evidence`.

A refused mutation writes nothing. That is asserted against the store, not against
a flag: `tests/unit/test_api_safety.py` requires no plan row and no receipt row
after a refusal. (That test caught a real defect — the port compiled *and
persisted* before authorizing — which is why the assertion is against the store.)

`bind_approval` **projects** an approval into its API resource and cannot **mint**
one: `domain.approval.Approval.bind` is the only constructor, and it derives the
plan digest from a `PASS` safety proof.

## Migrations this module needs registered

`infra/migrations.py` was read-only for this work item. Two migrations are
**defined but not registered**, and both report their own absence at runtime
rather than failing a legitimate request:

| Module | Version | Table | What happens today |
|---|---|---|---|
| `controller.api_service` | 34 (`api_gateway`) | `api_idempotency` | Fixtures splice it; a deployment that has not registered it cannot serve idempotency, and the endpoint's `501`/`500` will say so. |
| `controller.api_safety` | 35 (`api_safety`) | `api_mutation_receipts` | The compile succeeds and the response carries `mutation.receipt.recorded: false` with the reason naming the migration. |

Both have working down paths. `tests/unit/test_api_service.py` and
`tests/unit/test_api_safety.py` each build their fixture chain as
`(<their version from ALL_MIGRATIONS, theirs)`, so they keep working whatever
concurrent lanes append around them, and each asserts its own version is above the
registered head — so the day it collides, the suite says so.

## Rollout

The plan's order, and where this build sits in it:

1. **Read-only API and dashboard first.** Everything above except the two POSTs
   is read-only, and read-only is where this build is most complete. Serve it
   behind a reverse proxy that terminates TLS and sets `client_max_body_size`.
2. **Mutations behind existing approval gates.** The endpoints exist and are
   authorized; a mutation with no bound port answers `501` rather than
   acknowledging a write nothing performed. Bind a port only after the approval
   path has been exercised against a real proof.
3. **Standby promotion only after three clean drills.** Not met. See the runbook.

**No UI label claims a capability the API cannot prove.** Every page states its
API path, and every page ends with what it does not claim.

## Reproducing the checks

```bash
.venv/bin/python -m pytest tests/unit/test_api_service.py \
  tests/unit/test_api_planner.py tests/unit/test_api_ui.py \
  tests/unit/test_api_http.py tests/unit/test_api_safety.py \
  tests/unit/test_api_cli.py -p no:cacheprovider -q
```

186 tests: `test_api_service.py` (54), `test_api_cli.py` (34),
`test_api_safety.py` (30), `test_api_ui.py` (37), `test_api_http.py` (20),
`test_api_planner.py` (11). Zero failures, zero errors, zero skips.

The gateway's tests call `dispatch` directly; `test_api_http.py` drives a real
`wsgiref` server on an ephemeral port, so status codes, bodies, headers, and the
HTML/JSON split are asserted as a client receives them.