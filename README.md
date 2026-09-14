# Mayhem

**Chaos engineering for Docker, Podman, and Kubernetes.** Mayhem discovers your
system from a compose blueprint (Docker/Podman) or a live cluster (Kubernetes),
compiles one declarative
`kind: drill` YAML file into a frozen, safety-gated execution plan, injects
faults through a capability-aware toolkit, and ends every run with a machine
verdict derived from the observations it actually recorded.

Everything lands in SQLite — steps, probes, criteria evaluations, decisions —
so nothing is ever "trust me, it worked."

```
compose blueprint ─▶ topology graph ─▶ compile drill spec ─▶ frozen plan
                                                              │
                        verdict ◀── machine criteria ◀── inject → observe → recover
                                                              │
                                                SQLite evidence + decision trace
```

- [Quickstart](#quickstart)
- [A Run in One Screen](#a-run-in-one-screen)
- [Authoring a Drill](#authoring-a-drill)
- [Configuration](#configuration)
- [CLI Reference](#cli-reference)
- [Campaigns](#campaigns)
- [Safety Model](#safety-model)
- [Exit Codes](#exit-codes)
- [Architecture](#architecture)
- [Status](#status)
- [Development](#development)

---

## Quickstart

**Prerequisites**

- Python 3.12+
- Docker with Compose v2 (or Podman, used via the `--podman` flag)
- *(Optional)* A running Kubernetes cluster and `kubectl` for `k8s.*` faults

**Install**

```bash
pip install mayhem-cli        # console command is `mayhem`
```

**Run the bundled example**

A complete, self-contained six-service stack lives in
[`examples/testCase/`](examples/testCase/).

```bash
cd examples/testCase
docker compose up -d                          # 0. bring the stack up
mayhem topology discover --compose docker-compose.yml   # 1. blueprint → live graph
mayhem validate mayhem.yaml --compose docker-compose.yml  # 2. compile + safety gates (injects nothing)
mayhem run mayhem.yaml --compose docker-compose.yml      # 3. inject → observe → recover → verdict
```

Omit `--compose` and Mayhem auto-detects `docker-compose.yml` (or
`compose.yml`) in the current directory.

`validate` and `plan` work against the blueprint alone and never touch live
containers. `run` re-proves every fault at the impact gate against the live
graph and bypasses — or, without `--skip-gate`, refuses — anything it cannot
prove injectable.

The bundled spec exercises **38 distinct faults** across the `testcase-lb`
load-balancer — one concurrent fault (`max_faults: 1`, `risk_ceiling:
critical`), auto-recovery off — so the checks observe whether the stack
self-heals on its own. The nine `k8s.*` catalog faults are exercised against a
Kubernetes blueprint in [`examples/k8s`](examples/k8s) — see
[Top-level fields (targets)](docs/drill-spec.md#top-level-fields) for the
cross-runtime target syntax, so **every fault in the catalog has an example.**

---

## A Run in One Screen

A clean run needs no interpretation — the verdict is one line away.

```
$ mayhem run mayhem.yaml --compose docker-compose.yml

# Run r-process-drill-8f2a1c
**status**: completed
**verdict**: pass
**success criteria**: ALL PASS
- [PASS] status:api-up.status PASS (expected 200, got 200)
- [PASS] latency:api-up.latency_ms PASS (31.2 <= 500.0)
**observations**: 2/2 sources collected
**decisions**: 5 governing decision revisions (snapshot in the run row)
**wall**: 32.4s

run r-process-drill-8f2a1c — inspect with `mayhem history r-process-drill-8f2a1c`
```

Reading the transcript, top to bottom:

1. **Status** — the run's machine state: `completed` (or `failed`/`aborted`
   with a non-zero exit and dirty-lease warnings).
2. **Verdict** — `pass`/`fail` derived from the success criteria you declared
   in the spec; `undecided` when a run aborts or the spec has no success block.
3. **Success criteria** — every criterion evaluated against real observations,
   one line each, so a failure tells you exactly what drifted.
4. **Observations** — how many configured evidence sources actually delivered
   data (probes, logs, metrics …).
5. **Decisions** — the governing decision revisions that shaped this run; the
   decision trace is queryable afterward via `mayhem history`.
6. **Copy-paste handle** — the run id for the follow-up commands below.

From there: `mayhem status` lists recent runs, `mayhem status --run <run-id>`
shows full recorded metadata, and `mayhem history <run-id>` replays the
complete event journal (every step, probe sample, and lease for that run).
Add `--debug` to `mayhem run` to stream each step live as it happens
(`[ok] injected proc.pause 10s into testcase-api`,
`[ok] recovered ... (compensation ok)`).

---

## Authoring a Drill

A drill is one `kind: drill` YAML file — the complete DSL reference lives in
[`docs/drill-spec.md`](docs/drill-spec.md). The shape:

```yaml
apiVersion: "mayhem/v1"
kind: drill
name: checkout-recovery
hypothesis: "checkout stays available while cart writes are throttled"

config:
  risk_ceiling: high      # refuse faults riskier than this (policy ceilings only tighten)
  max_faults: 1           # never inject more than one fault at once
  timeout: 30m

containers:
  cart-api:               # keys ARE compose container_name values
    faults:
      - fault: net.latency
        duration: 10s
        params:
          delay_ms: 300
          jitter_ms: 25

execution:
  strategy: sequential    # sequential | parallel | random (ADR-M5-1)

checks:
  preconditions:          # everything must hold before anything is injected
    - type: container_running
      container: cart-api
    - type: http
      url: http://cart-api:8080/_health
      expected: 200

success:
  require_all: true
  criteria:
    - type: status
      source_id: cart-health.status
      expected: 200
    - type: latency
      source_id: cart-health.latency_ms
      lt_ms: 800

observability:            # evidence sources
  sources:
    - kind: logs
      source_id: cart-logs
      container: cart-api
      tail: 200
    - kind: probe
      source_id: cart-probe
      probe: { type: http, url: http://cart-api:8080/_health }
      cadence: 2s
```

Validate with `mayhem validate mayhem.yaml`; unknown parameters, out-of-range
durations, untargetable node kinds, and capability gaps are all compile-time
errors — before anything is injected.

Faults are drawn from the catalog (net.latency, proc.kill, net.packet_loss,
TLS failure, container pause, HTTP error injection, dependency and database
faults, k8s.pod_kill, k8s.node_drain, …). The full per-fault reference —
every id, its capabilities, risk level, and compensation contract — is in
[`docs/drill-spec.md`](docs/drill-spec.md#fault-catalog).

The `containers:` block above is the docker-family authoring shape. To fault a
Kubernetes workload or node — or mix runtimes in one spec — use the
cross-runtime `targets:` block instead (exactly one of `containers:` /
`targets:` defines a spec); see
[Targets (cross-runtime)](docs/drill-spec.md#targets-cross-runtime).

---

## Configuration

Runtime policies live in `mayhem.yaml` — the *configuration* file, distinct
from a `kind: drill` spec — auto-detected in the cwd or given with `--config`.
The effective view is one command away: `mayhem config show` (alias `cfg`)
prints the resolved configuration and the provenance of every section;
`mayhem config validate` refuses unknown keys, a missing or wrong
`apiVersion`, and out-of-range sections before anything runs.

```yaml
apiVersion: mayhem/v1        # required; anything else is rejected
policy:
  allow_faults: null         # null = whole catalog; set to restrict
  deny_faults: []            # fault ids never injectable
  risk_ceiling: null         # tightened by the drill ceiling at plan time
  allow_critical: false      # config-side half of the critical opt-in
  critical_fault_acks: []    # per-fault acks; critical faults need allow_critical + ack + --allow-critical
  kubernetes:                # discovery overrides for k8s drills
    context: null            # kubeconfig context (null = current-context)
    namespace: null          # namespace filter (null = all)
blast_radius:
  max_services_pct: 50.0
  max_hosts: 2
  max_concurrent_faults: 3
  max_duration_per_fault_s: 300.0
  forbidden_fault_pairs: []  # e.g. ["net.packet_loss", "net.bandwidth"]
storage:
  path: mayhem.db            # SQLite database (same default as --db)
  artifacts_dir: .mayhem/artifacts
toolkit:
  binaries: {}               # pin a named tool's binary, keyed by fault backend
runtime: docker              # docker | podman | kubernetes (CLI: --podman)
target:
  containers: []             # explicit targets when no compose file is used
log_level: INFO              # DEBUG | INFO | WARNING | ERROR
maniac:                      # fallback for `mayhem maniac` when the spec omits config.maniac
  level: 2
  run_level: 10
  seed: null                 # null = fresh random seed each run
```

Layering, in increasing precedence: **built-in defaults → `mayhem.yaml` →
`mayhem.{profile}.yaml` → environment variables → CLI flags**. Profile
overlays are separate per-profile files (selected with `--profile NAME`) —
there is no `profiles:` key inside `mayhem.yaml`. The environment layer only
honours allowlisted variables: `MAYHEM_STORAGE_PATH`,
`MAYHEM_ARTIFACTS_DIR`, `MAYHEM_LOG_LEVEL`.

Drill-level `config.risk_ceiling` composes with the policy ceiling and can
only tighten it.

The full configuration reference is in
[`docs/config.md`](docs/config.md).

---

## CLI Reference

Global options (accepted at any level, before or after the command):

| Option | Meaning |
|--------|---------|
| `--db PATH` | SQLite database path (default `mayhem.db`). |
| `--config PATH` | Path to `mayhem.yaml` (overrides auto-detection). |
| `--profile NAME` | Configuration profile to merge. |
| `--allow-critical` | Acknowledge `critical`-risk faults (e.g. `k8s.node_drain`). |
| `--skip-gate` | Run even when the impact gate proved some faults inert. |
| `-p, --podman` | Use Podman instead of Docker. |
| `-d, --debug` | Re-raise errors instead of rendering them. |

Every command (and the whole tree) abbreviates to any unique prefix: `mayhem
ex valid`, `mayhem t f`.

| Command | Description |
|---------|-------------|
| `mayhem topology discover` | Discover live services/hosts/dependency edges from the blueprint. `--runtime kubernetes` (with `--kube-context` / `--namespace`) discovers a live cluster instead of a compose stack. |
| `mayhem validate SPEC` | Compile a drill spec and run every safety gate without injecting. |
| `mayhem plan SPEC` | Compile against the topology and print the frozen plan JSON. |
| `mayhem run SPEC` | Compile and execute a drill; print the run summary. `--ctr CONTAINER` scopes execution to one container; `--next` prints the plan that would run. |
| `mayhem maniac SPEC` | Compile and execute a random-injection drill — draws `run_level` single-fault rounds governed by the maniac seed/level (spec `config.maniac`, falling back to the `maniac:` layer of `mayhem.yaml`). `--steps N` overrides the round count; `--ctr CONTAINER` narrows draws to one container. |
| `mayhem explore [EXPERIMENT]` | Generate a ranked candidate queue from the topology, gate it, execute the highest-value cells, and report coverage gained. |
| `mayhem next [SPEC]` | Suggest the most valuable untested cell to run next (§3.2). Deterministic under the same inputs. |
| `mayhem coverage [SPEC]` | Show the coverage map, per-service progress, and untested/blocked lists (§3.3). Filters: `--service`, `--fault`, `--fault-category`, `--state`. |
| `mayhem expert` | Run diagnostic probes and analyze recent failures. |
| `mayhem dependency …` | Inspect and install in-image tooling that gates fault families (`check`, `compile`, `install`). |
| `mayhem status` | Show runs recorded in the database (`--json` supported). |
| `mayhem history RUN_ID` | Replay steps, events, and leases recorded for one run. |
| `mayhem recover RUN_ID` | Recover every orphaned fault lease belonging to a run. |
| `mayhem janitor` | Sweep leases past their TTL; expire pending runs; compensate. |
| `mayhem toolkit faults` | List the fault catalog with risk and compensatability. |
| `mayhem toolkit list` | Probe the host for the tools/capabilities faults require. |
| `mayhem experiment show SPEC` | Print the parsed drill spec as JSON. |
| `mayhem experiment validate` | Alias of `validate`. |
| `mayhem config show` / `validate` | Inspect / validate the effective layered configuration (alias: `cfg`). `show --json` reports each section's provenance. |
| `mayhem campaign …` | See [Campaigns](#campaigns) below. |

---

## Campaigns

A campaign groups drill specs under one execution umbrella (ADR-0022/0023):
experiments run sequentially in priority order, and the campaign's failure
policy and time window govern the whole run.

```bash
mayhem campaign create black-friday \
  --description "BFCM chaos" --hypothesis "checkout survives every single-fault failure"
mayhem campaign add-experiment black-friday mayhem.yaml
mayhem campaign add-experiment black-friday checkout-recovery.yaml
mayhem campaign start black-friday                      # draft -> running
mayhem campaign run black-friday --compose docker-compose.yml
```

A campaign is born `draft` and moves through
`scheduled → running → paused → completed / aborted` (`archive` closes a
finished campaign). Per-experiment results land in the observations table
under the campaign id, and the failure policy selects the next action when
one experiment fails:

| `on_experiment_failure` | Meaning |
|-------------------------|---------|
| `abort_campaign` (default) | Stop the remaining experiments. |
| `skip_and_continue` | Record the failure and run the next experiment. |
| `retry_then_abort` | Retry the failed experiment once, then abort the campaign. |

Window fields (`window_json`): `start_epoch_s` / `end_epoch_s`,
`max_duration_s` (hard stop), and `cooldown_between_experiments_s` between
successive experiments.

**Campaign subcommands:** `create`, `list`, `show`, `status`, `delete`,
`add-experiment`, `start`, `abort`, `archive`, `run`.

---

## Safety Model

- **Risk ceilings.** Every catalog fault carries a risk level; injection is
  refused when either the policy or the drill ceiling is exceeded.
  `critical`-risk faults (e.g. `k8s.node_drain`) need a **triple opt-in**:
  `policy.allow_critical: true`, a per-fault ack in `policy.critical_fault_acks`,
  and the `--allow-critical` CLI flag.
- **Concurrency budget.** `max_faults` caps simultaneously-injected faults;
  a wider `parallel:` step queues into rounds.
- **Duration caps.** Per-fault `duration` beyond the catalog maximum is a
  compile error.
- **Capability gating.** Faults declare the capabilities they need
  (docker engine, kubernetes_engine, net_admin, process control, …); the plan
  is proven against the live graph by the impact gate before run — never
  assumed.
- **Compensation contracts.** Reversible faults run their declared inverse;
  irreversible ones are followed by workload reconciliation. A failed round
  aborts-and-recovers its own faults first, then propagates.
- **Lease hygiene.** Fault rounds hold leases with a TTL; `mayhem janitor`
  sweeps orphaned leases and expires pending runs, `mayhem recover` repairs a
  run's orphans on demand.

---

## Exit Codes

Stable contract for scripts and CI (definition:
[`src/mayhem/cli/exit_codes.py`](src/mayhem/cli/exit_codes.py)):

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General failure |
| 2 | Usage error (bad flags/arguments) |
| 3 | Configuration layering/validation failed |
| 4 | Spec/target validation failed |
| 5 | A safety gate refused the operation |
| 6 | Experiment ran and did not complete |
| 7 | Recovery/janitor left dirty state behind |
| 8 | Agent transport/runtime failure |
| 9 | External tool invocation failed structurally |
| 10 | Command prefix matched multiple commands |

---

## Architecture

The pipeline is staged so everything expensive is done up front and execution
is as small as possible:

1. **Discover** — the topology provider builds a graph (services, hosts,
   dependency edges) from the compose blueprint (Docker/Podman) or a live
   Kubernetes cluster, plus live containers/nodes.
2. **Prepare** — `mayhem config` layering (defaults → `mayhem.yaml` → profile →
   env → flags) plus topology, drift detection, and target revalidation.
3. **Compile & plan** — the drill spec becomes a frozen `ExecutionPlan` with
   step sequences, per-fault compensations, success criteria, and observability
   sources; every fault, target kind, capability, and duration is validated
   against the catalog.
4. **Execute** — the engine runs rounds (inject → observe → compensate) through
   the runtime adapter, evaluates criteria, collects observability, and writes
   step/event/lease rows with the governing-decision trace.
5. **Recover & report** — the janitor sweeps orphaned leases; `status`,
   `history`, and run summaries replay the evidence.

**Documentation**

| Document | Contents |
|----------|----------|
| [`docs/drill-spec.md`](docs/drill-spec.md) | **The drill DSL reference** — config, containers, execution, checks, success criteria, observability, and the full fault catalog. |
| [`docs/config.md`](docs/config.md) | **Configuration reference** — discovery order, merged syntax, every field with type and default, env/CLI overrides. |
| [`docs/compensation.md`](docs/compensation.md) | **Fault compensation lifecycle** — inject / undo / verify contracts, executor routing, marker conventions, and the per-fault template table. |

---

## Status

| Area | Status |
|------|--------|
| Domain models, configuration system | Complete |
| Topology discovery (Docker/Podman/Kubernetes) + compose project filtering + drift detection | Complete |
| Fault catalog + registry + capability probing (`toolkit`) | Complete |
| Drill spec DSL (config / containers / execution / checks) | Complete |
| Deterministic + random planners, frozen plans | Complete |
| Success criteria + machine verdict | Complete |
| Declarative observability sources | Complete |
| Run engine with compensation + leases + janitor + recover | Complete |
| Safety gates + impact gate | Complete |
| CLI with prefix abbreviation, stable exit codes | Complete |
| SQLite persistence + restart, migrations (schema freeze) | Complete |
| Campaigns (multi-spec runs) | Complete |
| Tests, ruff, mypy (per-file strict) | Complete |
| Kubernetes topology discovery + runtime | Complete (see [`examples/k8s`](examples/k8s)) |
| Web UI / REST API | Planned |

---

## Development

```bash
# Clone, then sync the dev dependency group (requires https://docs.astral.sh/uv/):
uv sync --group dev

# Run all tests
uv run pytest

# Lint
uv run ruff check src/

# Type check (strict is configured per module)
uv run mypy
```