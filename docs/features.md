# Feature Innovation Plan — Mayhem 0.6+

**Status:** planning only (no code changes).

**Inputs:** `docs/re-design.md` (vision), `docs/drill-spec.md`, `CHANGELOG.md`,
live grill-me interview (2026-09-10, decisions marked **[interview]** below),
repository exploration.

**Product moment we are chasing:** Mayhem stops being a "fault engine you
drive" and becomes a tool that *chooses what to test next*, safely, proves
what happened, and measures how much of your system has been proven. That is
the strongest differentiation available to us — the execution/safety/evidence
loop is already unusually mature; what is missing is the intelligence layer on
top of it.

---

## 1. Where the project is right now (evidence)

### What is genuinely strong

- **The core loop is closed.** `topology → frozen plan → gated injection →
  observe → compensate → machine verdict → SQLite evidence` is real and
  tested (`README.md`, `docs/drill-spec.md`).
- **Fault catalog is wide and gated.** 40+ fault kinds with per-fault risk
  level, max duration, node kinds, required capability, typed parameters
  (`docs/drill-spec.md:407` Fault Catalog, `mayhem.domain.catalog`).
- **Compensation is a contract, not a hope.** Every planned fault carries
  undo ops; the planner bakes compensation in (`controller/planner.py:641`,
  `docs/compensation.md`); the watchdog/janitor sweep dirty and stolen leases
  (`controller/janitor.py`, changelog 0.5.1).
- **Drill DSL is declarative and versioned** (`kind: drill`, `apiVersion:
  mayhem/v1`), with config layering, snapshots, profiles
  (`config.py`, ADR-0008).
- **Verdicts are typed and evidence-backed.** Success criteria → PASS/FAIL
  evaluated over recorded observations (`domain/success.py`,
  `controller/resilience_report.py`, `docs/drill-spec.md:320`).
- **The intelligence machinery exists but is orphaned from the CLI:**
  - `infra/candidate_generator.py` — `SeededCandidateGenerator` +
    `CandidateLandscape` (deterministic, risk-ceiling aware)
  - `infra/candidate_gates.py` — Safety → Feasibility → Resource-conflict
    pipeline (`domain/candidates.py:23`)
  - `infra/campaign_engine.py` — M5 campaign lifecycle with `CandidateSource`
    / `Approver` / `Runner` protocols, `autonomous | supervised` modes,
    stop-on `coverage_target | max_runs | deadline`
  - `domain/coverage.py` + `infra/coverage_repository.py` — the cell model
    `(target, fault_kind, execution_context, parameter_band)` with
    `mark_seen` / `unknown_cells` / `summary`, persisted in SQLite
  - `infra/report.py` — `build_m5_report` + heatmap render
  - `cli/campaign.py` — session lifecycle (list/create/show/status/start/
    abort/archive) *for manually-authorable* campaigns
- **Frozen plans + leases + janitor + exit codes** make it CI-safe today
  (`cli/exit_codes.py`, 0.5.1 "janitor reclaims crashed controllers' leases").

### What is weak / unfinished (gaps this plan must respect)

- M5 candidate machinery is **not reachable from regular usage**: no command
  generates candidates from a live topology, runs them through the gates, and
  records coverage. `campaign run` iterates a list of authored drill specs
  (`cli/campaign.py:362`); the generator/campaign-engine/coverage pieces are
  exercised mostly by tests.
- **CLI surface is broad and internally consistent but not workflow-shaped**:
  14 top-level commands; there is no single "what should I do next" entry
  point, no readiness preflight, no init, no explain.
- **Coverage is a concept with tables but no user-facing home** (no
  `mayhem coverage`, no "what's untested", no `mayhem next`).
- **Doc/CLI drift exists** (re-design.md §24): stale refs, dead command
  examples, non-migrated ad-hoc tables (`tracked_resources`,
  `mutation_journal`), fake `--host` on toolkit probing, unwired JSON. Ruff is
  deliberately not a hard gate.
- **Kubernetes is interface-only** (`domain/k8s_adapter.py`, refusal gate
  `k8s.unsupported`; `examples/k8s/README.md`) — by design, M8 not done.

---

## 2. Personas (who we build for)

| Persona | Goals | Pain today |
|---|---|---|
| **Solo operator (primary; [interview])** | Get a verdict on "does my stack recover", fast, and trust it; not re-learn the CLI every month | Must write a drill by hand before first run; 14 commands; no guidance on *what* to test next; failure debugging is manual (`docker inspect` by hand) |
| **CI pipeline (secondary)** | A gate: run chaos, get exit code + evidence artifact, don't flake | Works today, but no min-coverage gate, no JUnit-style output, no trend |
| **SRE on a small team (aspirational)** | Cover a composed stack systematically; compare before/after a deploy | No coverage map, no baseline/compare, no session-level report |

**Design rule:** every 0.6 feature must work for the solo operator with zero
authored configuration *and* deepen automatically as they author more.

---

## 3. 0.6.0 — The Explore Loop (In Scope)

Three new commands, one objective, all grounded in existing machinery:

```
mayhem explore    # generates candidates, gates them, runs them, records coverage
mayhem next       # "what untested cell is most valuable to run next?"
mayhem coverage   # coverage map + heatmap + untested list
```

Everything runs through the **same** safety stack (risk ceiling, impact gate,
allowed/critical acknowledgement, compensation) as `mayhem run` — explore is
**not** a weaker execution mode.

### 3.1 `mayhem explore`

**Purpose.** Turn a 30-minute window into highest-value, safety-gated,
evidence-recorded chaos experiments across the stack, and report the coverage
delta gained.

**Shape**

```text
mayhem explore [drill.yaml] [--compose PATH] [--budget N] [--deadline DUR]
               [--seed N] [--supervised] [--dry-run] [--allow-critical]
               [--keep-faults] [--json] [--db PATH] [--profile NAME]
```

**Behavior (decisions marked [interview])**

- **Candidate generation.** Build a `CandidateLandscape` from the live
  topology: targets = discovered services/containers (or, if a drill is given,
  the drill's containers); fault kinds = catalog entries whose node kinds and
  capabilities are compatible; execution contexts = `container`; parameter
  bands = `default` (band expansion is a future extension). Draw with
  `SeededCandidateGenerator` (deterministic; `--seed` for reproducibility —
  `seed_hint` is already on `ExperimentCandidate`).
- **Gating.** Run every candidate through the existing `CandidateGatePipeline`
  (Safety → Feasibility → Resource-conflict). Rejected candidates are counted
  and reported, never executed — the existing contract
  (`domain/candidates.py:9`).
- **Execution is autonomous by default [interview Q3].** `--dry-run` prints
  the ranked queue (target, fault, risk band, predicted gate outcome) without
  running anything. `--supervised` inverts to interactive approve/skip per
  candidate using the M5 `Approver` protocol.
- **Cell-run contents — layered scaffold [interview Q4].** For each candidate,
  select probe/observability scaffolding in priority order:
  1. an authored drill in cwd (its probes / success criteria / observability)
     keyed to the target, with the candidate fault substituted;
  2. default health probes synthesized from the topology (ports, healthcheck
     metadata) via the check catalog;
  3. bare inject → observe → compensate → outcome.
  Verdict quality therefore deepens as the user authors without explore ever
  being blocked on authoring.
- **Safety envelope [interview Q6].** Sequential single-fault loop (no
  concurrency in 0.6); compensation forced on per cell (`--keep-faults` to opt
  out, mirroring `config.recovery: false`); `--budget` default **10** runs;
  existing `risk_ceiling` from config respected; `--allow-critical` still
  required to raise it; impact gate armed. Stop on: budget reached, deadline
  passed, or landscape exhausted.
- **Session = campaign.** Each `explore` run creates and drives an `M5Campaign`
  row (autonomous approver), so `mayhem campaign list/status/abort/show`
  already gives session lifecycle for free, and every executed cell is a
  normal run record in SQLite (evidence core unchanged).
- **Coverage accounting.** On each outcome, mark the cell with the existing
  `SQLiteCoverageRepository.mark_seen` (idempotent — re-runs never
  double-count, `coverage_repository.py:33`).
- **Output.** Terminal summary (budget used, cells covered/new, gates
  rejected, verdicts) + the M5 heatmap/report; `--json` for the same data;
  `--dry-run` prints the queue.

### 3.2 `mayhem next`

**Purpose.** Answer the one question a solo user asks before every session:
*what should I test next?*

**Shape**

```text
mayhem next [drill.yaml] [--compose PATH] [--limit N] [--seed N] [--json]
```

**Behavior [interview Q5].** Rank UNKNOWN cells of the current landscape:

1. **Novelty first** — never re-suggest a covered cell (the M5 "coverage is
   the objective" ADR).
2. **Risk ascending** — within unknowns, lowest risk band first (blast-radius
   aware exploration).
3. **Target criticality** — topology signal (core vs. support service) as the
   final ordering key in 0.6; declarative criticality **tags** are explicitly
   deferred (config for config's sake).

Output: the top-1 cell with a one-line *why* ("never tested cpu.saturate on
checkout-api; risk low; support target"), or `--limit N` for a shortlist.
`--json` gives the machine form.

### 3.3 `mayhem coverage`

**Purpose.** Make coverage a first-class, inspectable map.

**Shape**

```text
mayhem coverage [drill.yaml] [--compose PATH] [--service NAME]
                [--fault KIND] [--json] [--db PATH]
```

**Behavior.** Render coverage as target × fault-type matrix (the heatmap
already implemented in `infra/report.py:render_heatmap`), per-service summary,
and an **untested list** (`unknown_cells`). `--service`/`--fault` filter.
`--json` for pipeline consumption. Reads only — no writes, safe in CI.

### 3.4 Ride-along hygiene (doc drift)

As part of 0.6, fix the documentation/CLI drift that would otherwise make the
new docs wrong on day one (re-design.md §24):

- remove dead references (obsolete `janitor sweep`, obsolete `--process`,
  old campaign `--name` syntax, `mayhem recover` examples without run id);
- reconcile the `check` / `check_spec` docs;
- add a CI check that every documented command string in `README.md` /
  `docs/drill-spec.md` / new feature docs parses (`--help` smoke test).

**Explicitly out of 0.6 ([interview Q7]; see backlog):** `mayhem doctor`,
`mayhem init`, `mayhem explain`, `mayhem report --html`, `mayhem watch`,
`mayhem compare` / baselines, artifact collection, scenario/progressive DSL,
CLI restructure/renames, remote agents, k8s execution, fault-catalog growth.

---

## 4. Implementation notes (engineering handoff)

### 4.1 What already exists and is reusable

| Needed | Exists at | Gap |
|---|---|---|
| Candidate gen | `infra/candidate_generator.py` | needs topology→`CandidateLandscape` adapter |
| Gate pipeline | `infra/candidate_gates.py` | none — wire as-is |
| Campaign lifecycle + stop conditions | `infra/campaign_engine.py`, `domain/m5_campaign.py` | needs the autonomous `Approver` wired + a `Runner` that materializes a cell |
| Coverage store | `infra/coverage_repository.py` | mark cells from runner outcomes |
| Heatmap/report | `infra/report.py` | expose verbatim via `mayhem coverage` |
| Session lifecycle | `cli/campaign.py` | `explore` creates a campaign internally |
| Plan/run/safety stack | `cli/lifecycle.py`, `controller/planner.py` | reuse, do not fork |

### 4.2 What must be built (the real work)

1. **Candidate source from topology.** Map `TopologyNode` → `CandidateLandscape`
   targets; intersect fault kinds with node-kind + capability compatibility and
   `risk_ceiling`. (`topology/service.py` is the hook.)
2. **A cell `Runner`.** Convert an approved `ExperimentCandidate` into a
   frozen plan (layered scaffold per 3.1) and execute it through the normal
   lifecycle, returning `(run_id, outcome_id, cell)` — the
   `campaign_engine.DrillResult` contract already defines this shape.
3. **Autonomous + supervised approvers.** Thin adapters over `Approver`;
   supervised = `click.confirm`/picker per candidate.
4. **CLI.** `cli/explore.py` (and `next`, `coverage`), registered as
   top-level commands in `cli/app.py:93`.
5. **Ranking (`mayhem next`).** `unknown_cells` + risk-ascending +
   criticality ordering; one function, unit-testable.
6. **Session naming/UX.** `explore` summaries point back to `campaign show`
   and to the run ids involved.

### 4.3 Open questions the planner must verify (do not guess)

- Does `campaign_engine`'s runner in tests already synthesize a drill from a
  candidate? If yes, that's the scaffold seam — confirm the layered fallback
  (2)/(3) slot in there.
- How does topology expose a per-service "default health probe" (ports /
  healthcheck metadata)? If absent, scaffold tier (2) starts as bare cells
  until the check catalog has a service-probe heuristic; that's acceptable —
  tier ordering makes it monotonic.
- Parameter bands: `CandidateGenerator` emits `{"band": "default"}`; keep the
  band axis but do not multiply bands in 0.6.

### 4.4 Acceptance criteria

- `mayhem explore --compose examples/testCase/docker-compose.yml --budget 2`
  runs two cells sequentially, each with compensation verified, and prints a
  heatmap + coverage delta; re-running the same command marks **zero** new
  cells for the already-covered ones (idempotent).
- `mayhem explore ... --dry-run` prints the queue and executes nothing
  (assert: no run records created, no faults injected).
- `mayhem next` never suggests a covered cell; ordering is risk-ascending.
- Every executed cell survives as a normal run + outcome in SQLite; a
  simulated controller crash mid-explore leaves the janitor able to reclaim
  the lease (no stuck state).
- All gate rejections are counted and displayed, never executed.
- New documented commands pass the doc-smoke CI check.

### 4.5 Success metrics / KPIs

- Time from `git clone` + `compose up` to first coverage heatmap < 15 minutes
  (zero authored config).
- `mayhem next` suggestion followed (executed) ≥ 60% of the time by the
  primary user in the first month (qualitative signal sentinel — if it's
  ignored, ordering is wrong).
- Coverage delta per 10-run session ≥ 8 new cells in a fresh environment.
- Zero regressions in the nightly "chaos of the chaos" tier.

### 4.6 Testing / rollout / rollback

- **Testing:** unit (ranking, scaffold selection, approvers, idempotent
  coverage), integration (real compose stack, `examples/testCase`), e2e/nightly
  as today (`tests/e2e`, marker `nightly`).
- **Rollout:** new commands are additive — nothing is renamed or removed in
  0.6.0 (rename pass deferred to backlog). Safe to release as one PyPI minor.
- **Rollback:** delete/flag the new command registrations; command exists
  behind no feature flag because it is purely additive and gate-enforced.

### 4.7 Future extensions (reserved, not built)

- Parameter-band expansion, cross-target concurrency (0.7+), business-weighted
  ordering via declared tags, adaptive mid-session re-planning, coverage policy
  gates for CI (`min_coverage`).

---

## 5. Backlog (out of 0.6, prioritized)

Each entry: **purpose → scope → why now/why later.** All drawn from
`docs/re-design.md`; do not build any before the one above it unless priorities
change.

### P1 — Onboarding & trust (next release after explore)

- **`mayhem doctor`** — canonical environment preflight (docker/compose
  versions, per-fault capability table, permission status, topology lock,
  "X/Y faults executable", blocked-with-reason). Replaces the fragmented
  `toolkit list` + `dependency check` + `validate` flow for "is this stack
  ready". *After explore*, doctor's capability matrix feeds explore's dry-run
  directly.
- **`mayhem init`** — scaffold a `kind: drill` from a discovered compose
  (services → default health checks, suggested first faults, sensible
  risk_ceiling). Turns "hours to first drill" into minutes.
- **`mayhem explain run <id>`** — rerun the recorded decision trace into a
  plain-language "why did this fail" walk (decision/janitor/observation
  records already exist; this is presentation, not new telemetry).

### P2 — Diagnosability

- **`mayhem watch`** — live event stream during a run (topology locked →
  inject → degradation → recovery → verdict) from journaled events.
- **`mayhem report <id> --format html|markdown|junit|json`** — self-contained
  run report for sharing/archiving; JUnit for CI gates.
- **Artifact collection** — on failure, capture `docker inspect`, stats,
  process/network/tc state into the artifacts dir.

### P3 — Comparison & trend

- **`mayhem baseline create` / `mayhem run --compare` / `mayhem compare A B`**
  — measured deltas (metrics, recovery time, criteria, dirty leases) across
  deploys; makes resilience verifiable as a trend instead of a one-off PASS.
- **Git-aware run context** (commit, branch, compose hash) on run records.

### P4 — Intelligence, part 2

- **Fault combinations / sequences** (repeat, ramp, pulse, soak) with explicit
  `max_concurrent_faults` and allowed-combination policy — *only after*
  explore proves the cell engine.
- **Adaptive experiments** (`if criterion then inject`) — requires the
  scenario DSL; do not approach until P1-P3 landed.

### P5 — Scale (deliberately last)

- **Remote agents** — make `agent`/transport the execution path for real
  multi-host (already has leases/watchdog semantics; `--host` today is a
  misleading local probe).
- **Kubernetes execution** — M8 driver behind the existing `k8s_adapter`
  seam; nine `k8s.*` faults already catalogued and refused
  (`examples/k8s/README.md`). Nothing here before explore proves value.

### P6 — Continuous hygiene (ride along, wherever)

- Move `tracked_resources` / `mutation_journal` into the migration system.
- Adopt real `--host` probing or remove the flag.
- Universal `--json`/`--no-color`/`--quiet` output contract across commands.
- Make Ruff a hard gate once the existing debt is cleared.

---

## 6. Six Month Vision

Mayhem's 0.7 identity: **"discover → explore → prove → compare"** is the
default daily loop. A user with a compose stack and ten minutes can stand up
coverage (`explore --budget 10`), get a heatmap, and be told what to test next
(`next`); a failed cell explains itself (`explain`); a deploy validates
against a baseline (`compare`). The CLI is workflow-shaped, onboarding takes
minutes (`init`/`doctor`), and CI can gate on coverage/JUnit. M8 k8s execution
lands as *another adapter* once the product loop is proven on Docker/Podman.

## 7. Two Year Vision

Mayhem is the "verdict-first" chaos platform: an agent-per-host execution tier
for multi-node compose, a k8s runtime behind the stable adapter seam, a
declarative scenario DSL for realistic progressive incidents, and business-
weighted coverage that drives "what to test next" from the product's own
risk taxonomy. The evidence core (frozen plan, leases, decision trace, SQLite
journal) remains the load-bearing floor — everything above it is additive.

## 8. Platform Foundations (leveraging now)

- **Coverage as a core, persisted metric** (already seeded) — every other
  intelligence feature (next, baselines, CI gates, scenario planning) reads it.
- **The campaign/runner seam** — make the cell `Runner` the *normal* execution
  entry so `run`, `explore`, and `scenario` share one code path.
- **Uniform output contract** (`--json` everywhere) — unlocks CI, web UI/dash
  later, and machine comparison without per-command duct tape.
- **Event/decision trace** (exists) — the substrate for `watch`, `explain`,
  and HTML reports; keep it append-only.

---

## 9. Constraints (what we will NOT do in 0.6)

- No new fault kinds (catalog is wide enough; depth comes from scenarios).
- No config for config's sake (no criticality tags until P4).
- No concurrency, no renaming of existing commands, no new DSL keywords.
- No weakening of any safety gate to make explore "easier".
- No features that duplicate existing commands; if a command already does it,
  extend it.