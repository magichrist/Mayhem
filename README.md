# Mayhem

**Chaos engineering for Docker and Podman, with separately scoped Kubernetes
planning and execution seams.** The documented quickstart uses a compose
blueprint. Mayhem compiles a declarative `kind: drill` document into a frozen,
safety-gated plan, injects supported faults through a capability-aware toolkit,
and derives the run verdict from recorded observations.

Everything lands in SQLite — steps, probes, criteria evaluations, decisions —
so nothing is ever "trust me, it worked."

Kubernetes source support is layered and must not be collapsed into one
"supported" claim: manifest planning, planner support, executor support, and
live resolution are separate states. The legacy `KubernetesAdapter` remains
unavailable, and catalog-only faults are not executable merely because they are
defined. See the [Kubernetes status](#kubernetes-status) section and the
[documentation authority index](docs/README.md).

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
- Docker with Compose v2, or Podman selected with `--podman`

The Kubernetes paths have additional SDK, client, cluster, and capability
requirements. The checked-in documentation does not certify any live cluster.

**Install**

```bash
pip install mayhem-cli        # one bundle; console command is `mayhem`
```

**Run the bundled example**

A complete, self-contained six-service stack lives in
[`examples/testCase/`](examples/testCase/).

```bash
cd examples/testCase
docker compose up -d                          # 0. bring the stack up
mayhem discover topology --compose docker-compose.yml   # 1. blueprint → live graph
mayhem prepare validate mayhem.yaml --compose docker-compose.yml  # 2. compile + safety gates (injects nothing)
mayhem run mayhem.yaml --compose docker-compose.yml      # 3. inject → observe → recover → verdict
```

Omit `--compose` and Mayhem auto-detects `docker-compose.yml` (or
`compose.yml`) in the current directory.

`validate` and `plan` compile from the compose blueprint and do not inject a
fault. Topology construction may still inspect an available container runtime
for current-state data. `run` applies its impact gate and records the actual
execution outcome.

The bundled spec exercises the compose-supported fault families used by the
example stack. The [`examples/k8s`](examples/k8s) directory is a separate
manifest-backed planning example. Its presence does not prove live-cluster
execution, and the current catalog is larger than the original nine-fault
example. See [Targets (cross-runtime)](docs/drill-spec.md#targets-cross-runtime)
for the authored target syntax.

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

run r-process-drill-8f2a1c — inspect with `mayhem inspect history r-process-drill-8f2a1c`
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
   decision trace is queryable afterward via `mayhem inspect history`.
6. **Copy-paste handle** — the run id for the follow-up commands below.

From there: `mayhem inspect runs` lists recent runs, `mayhem inspect runs --run <run-id>`
shows full recorded metadata, and `mayhem inspect history <run-id>` replays the
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
  risk_ceiling: high
  max_faults: 1
  timeout: 30m
  recovery: true

containers:
  cart-api:
    faults:
      - fault: net.latency
        duration: 10s
        params:
          delay_ms: 300
          jitter_ms: 25

execution:
  - sequential: [cart-api]
  - check:
      - http: http://cart-api:8080/_health
        expect:
          status: 200
```

Validate with `mayhem prepare validate mayhem.yaml`; unknown parameters, out-of-range
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
The effective view is one command away: `mayhem prepare config show` prints the
resolved configuration and provenance; `mayhem prepare config validate` refuses
unknown keys, a missing or wrong `apiVersion`, and out-of-range sections before
anything runs.

```yaml
apiVersion: mayhem/v1        # required; anything else is rejected
policy:
  allow_faults: null         # null = whole catalog; set to restrict
  deny_faults: []            # fault ids never injectable
  risk_ceiling: null         # tightened by the drill ceiling at plan time
  allow_critical: false      # config-side half of the critical opt-in
  critical_fault_acks: []    # per-fault acks; critical faults need allow_critical + ack + --allow-critical
blast_radius:
  max_services_pct: 50.0
  max_hosts: 2
  max_concurrent_faults: 3
  max_duration_per_fault_s: 300.0
  forbidden_fault_pairs: []  # pairs such as [net.packet_loss, net.bandwidth]
storage:
  path: mayhem.db
  artifacts_dir: .mayhem/artifacts
toolkit:
  binaries: {}               # pin a named tool's binary
runtime: docker              # docker | podman | kubernetes
target:
  containers: []             # explicit discovery targets without compose
kubernetes:
  context: null              # kubeconfig context
  namespace: null            # null = no namespace filter
recovery_grace: 300.0
log_level: INFO              # DEBUG | INFO | WARNING | ERROR
maniac:
  level: 2
  run_level: 10
  seed: null
```

Layering, in increasing precedence: **built-in defaults → selected YAML →
`mayhem.{profile}.yaml` → allowlisted environment variables → programmatic
CLI overrides**. Profile overlays are separate files selected with `--profile
NAME`; there is no `profiles:` key inside the base file. The environment layer
only honours `MAYHEM_STORAGE_PATH`, `MAYHEM_ARTIFACTS_DIR`, and
`MAYHEM_LOG_LEVEL`. The current CLI uses `--config` and `--profile` to select
layers; it does not expose a generic flag that maps arbitrary fields into
configuration.

Drill-level `config.risk_ceiling` composes with the policy ceiling and can
only tighten it.

The full configuration reference is in
[`docs/config.md`](docs/config.md).

---

## CLI surface

The active CLI is workflow-oriented: `discover`, `prepare`, `experiment`, `run`, `inspect`, `recover`, and `extend`. Guided `init` and `doctor` are active, and all legacy root commands and aliases have been removed. Exit codes, machine-readable fields, and database migrations remain stable.

See [`docs/product/cli-product-direction.md`](docs/product/cli-product-direction.md), [`docs/product/command-architecture.md`](docs/product/command-architecture.md), and [`docs/new-plan/README.md`](docs/new-plan/README.md).

Root options precede the command. Unique prefixes work at the root and in the workflow groups.

| Command group | Purpose |
|---------------|---------|
| `mayhem discover` | Discover topology, engines, faults, and capabilities. |
| `mayhem prepare` | Validate configuration, prepare dependencies, and compile plans. |
| `mayhem experiment` | Show, validate, and explore authored experiments. |
| `mayhem run`, `mayhem maniac` | Execute authored or randomized drills. |
| `mayhem inspect` | Inspect runs, history, coverage, next actions, leases, and diagnostics. |
| `mayhem recover`, `mayhem janitor` | Recover runs and clean leases. |
| `mayhem extend` | Inspect and extend faults, capabilities, dependencies, and providers. |
| `mayhem campaign`, `mayhem commands`, `mayhem init`, `mayhem doctor`, `mayhem verify` | Manage campaigns, inspect the command map, onboard, diagnose, and verify evidence. |

Use each command's current `--help` output for accepted arguments. See the complete [`docs/reference/cli.md`](docs/reference/cli.md) for options and workflow examples.

---

## Campaigns

A campaign groups authored drill-spec paths and runs them sequentially.

```bash
mayhem campaign create black-friday \
  --description "BFCM chaos" --hypothesis "checkout survives every single-fault failure"
mayhem campaign add-experiment black-friday mayhem.yaml
mayhem campaign add-experiment black-friday checkout-recovery.yaml
mayhem campaign start black-friday
mayhem campaign run black-friday --compose docker-compose.yml
```

The current CLI creates campaigns in `draft`, `start` moves a draft to
`running`, `run` executes the stored spec paths, and `archive` or `abort` sets
the corresponding terminal status. The current command surface does not expose
campaign scheduling, pause, resume, priority-order, or policy/window editing
options. See the [campaign reference](docs/reference/cli.md#campaign-commands).

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

The stable identifiers and numeric values are defined in
[`src/mayhem/cli/exit_codes.py`](src/mayhem/cli/exit_codes.py) and documented in
[`docs/reference/cli.md`](docs/reference/cli.md#exit-codes). The deterministic
documentation test rejects identifiers that are not declared in source.

---

## Architecture

The pipeline is staged so everything expensive is done up front and execution
is as small as possible:

1. **Discover** — compose discovery builds a Docker/Podman graph. Kubernetes
   has separate live-discovery and offline-manifest providers; the manifest
   provider creates logical placeholders, not live pod selections.
2. **Prepare** — `mayhem prepare config` layering (defaults → selected YAML → separate
   profile overlay → allowlisted environment values → programmatic overrides),
   plus topology, drift detection, and target revalidation.
3. **Compile & plan** — the drill spec becomes a frozen `ExecutionPlan` with
   step sequences, per-fault compensations, success criteria, and observability
   sources; fault, target, capability, and duration inputs are validated
   against the current models.
4. **Execute** — supported runtimes execute inject → hold → compensate rounds
   and record evidence. Kubernetes planner/executor presence does not by itself
   establish a reachable cluster or an available capability.
5. **Recover & report** — the janitor sweeps orphaned leases; `status`,
   `history`, and run summaries replay recorded evidence.

**Documentation**

| Document | Contents |
|----------|----------|
| [`docs/README.md`](docs/README.md) | Documentation authority, classifications, source-of-truth map, and Kubernetes status vocabulary. |
| [`docs/drill-spec.md`](docs/drill-spec.md) | Drill DSL reference. |
| [`docs/config.md`](docs/config.md) | Current layered configuration contract. |
| [`docs/reference/cli.md`](docs/reference/cli.md) | Current commands, options, and stable exit codes. |
| [`docs/compensation.md`](docs/compensation.md) | Compensation lifecycle and verification contracts. |

---

## Status

| Area | Status |
|------|--------|
| Compose-oriented Docker/Podman workflow | Documented user path |
| Layered configuration, drill planning, SQLite evidence, CLI exit codes | Current checked-in references |
| Kubernetes manifest topology | Supported as an offline planning input; blueprint pods are placeholders |
| Kubernetes planner | Supports normalized `targets:` scopes and frozen-plan metadata |
| Kubernetes executor/resolver seams | Present in source and unit-tested with fakes; availability is runtime/capability dependent |
| Legacy `KubernetesAdapter` | Compatibility seam only; reports unavailable |
| Live Kubernetes cluster acceptance | Not claimed by repository documentation |
| Catalog-only Kubernetes faults | `k8s.image_pull_slow`; excluded from the available-fault register and refused before mutation |
| Web UI / REST API | Planned |

### Kubernetes status

The [examples/k8s README](examples/k8s/README.md) and
[documentation authority index](docs/README.md#kubernetes-status-vocabulary)
explain the separate Kubernetes states. Historical discovery reports and the
dated [grounding log](docs/grounding-log.md) are retained for traceability and
must not be treated as live-cluster evidence.

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