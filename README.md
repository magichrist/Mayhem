# Mayhem

**Chaos engineering for Docker & Podman (Kubernetes on the roadmap): discover
your system, break it on purpose, prove it recovers — every time, with
evidence.**

Mayhem is a drill engine, not a command library. It turns your
`docker-compose` blueprint into a live topology graph, compiles one declarative
`kind: drill` YAML file into a frozen, safety-gated execution plan, injects
faults through a capability-aware toolkit, and ends every run with a machine
verdict derived from the observations it actually recorded. Steps, probes,
criteria evaluations, and decisions all land in SQLite — nothing is "trust me,
it worked."

```
compose blueprint ─▶ topology graph ─▶ compile drill spec ─▶ frozen plan
                                                              │
                        verdict ◀── machine criteria ◀── inject → observe → recover
                                                              │
                                                SQLite evidence + decision trace
```

**Contents**
- [Why Mayhem](#why-mayhem)
- [What a Run Looks Like](#what-a-run-looks-like)
- [Quickstart](#quickstart)
- [Authoring a Drill](#authoring-a-drill)
- [CLI Reference](#cli-reference)
- [Configuration](#configuration)
- [Safety Model](#safety-model)
- [Exit Codes](#exit-codes)
- [Architecture](#architecture)
- [Development](#development)

---

## Why Mayhem

Most chaos tooling hands you a list of commands — "kill this container," "add
latency here" — and leaves you to figure out the blast radius, the cleanup, and
what "healthy" means. Mayhem treats a drill as a **planned, gated, evidenced
experiment** instead.

| | Hand-rolled chaos scripts | Mayhem |
|---|---|---|
| **Targeting** | You pick a container and hope | Faults plan against a discovered topology graph, so targets stay real |
| **Safety** | Your discipline | Risk ceiling, `max_faults` budget, and an impact gate that re-proves every fault before anything is injected |
| **Definition** | Throwaway shell one-liners | One `kind: drill` YAML: per-container faults, ordering, checks, success criteria, observability |
| **Cleanup** | You remember to | Every fault ships a compensation contract; the janitor sweeps dirty leases after crashes |
| **Verdict** | Eyeball the dashboards | `PASS`/`FAIL` from typed success criteria evaluated over recorded observations |
| **Evidence** | Shell history | Immutable SQLite journal: steps, probes, decisions, outcome |

Concretely:

1. **Topology-aware planning.** Mayhem reads your compose blueprint and
   discovers the live services, hosts, and dependencies to build a graph.
   Faults are planned against that graph, not applied blind; compose project
   filtering keeps unrelated stacks out.

2. **Drill specs, not scripts.** One YAML file declares everything — faults,
   cross-container ordering, checks, success criteria, observability sources —
   and you define what "healthy" looks like *before* you break anything.

3. **Machine verdicts.** Optional typed success criteria turn every run into a
   `PASS`/`FAIL` verdict derived from the observations actually recorded — no
   eyeballing.

4. **Automatic recovery.** Every fault ships a compensation contract: an undo
   op plus a verification probe generated from the same plan parameters, so
   what was injected is exactly what gets removed and re-proven healthy. If a
   round fails or the controller crashes, the janitor sweeps dirty leases and
   reconciles the workload — no manual cleanup. The per-fault lifecycle is
   documented in [`docs/compensation.md`](docs/compensation.md).

5. **Honest evidence.** Runs persist an immutable event journal, criteria
   evaluations, and a governing-decision trace in SQLite. No "trust me, it
   worked."

6. **Prefix-shortened CLI.** Type `mayhem r` instead of `mayhem run`;
   `mayhem e v` means `mayhem experiment validate`. Every command abbreviates
   to any unique prefix.

---

## What a Run Looks Like

A clean run needs no interpretation — the verdict is one line away. Truncated
for readability:

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
Add `--debug` to `mayhem run` to stream each step live as it happens (`[ok]
injected proc.pause 10s into testcase-api`, `[ok] recovered ... (compensation
ok)`).

---

## Quickstart

**Prerequisites**

- Python 3.12+
- Docker with Compose v2 (or Podman, used via the `--podman` flag)
- No host tooling required up front: `mayhem toolkit list` probes for the
  capabilities (docker, podman, network tooling, `k6`, …) each fault needs,
  and the impact gate refuses to run anything it cannot prove.

**Install**

```bash
pip install -e .
```

**Run the bundled example**

A complete, self-contained example lives in `examples/testCase/` — a
six-service compose stack (API, web, load balancer, dual download builders, and
Postgres), its drill spec, and the fixtures it relies on.

```bash
# 0. Bring the stack up.
cd examples/testCase
docker compose up -d

# 1. See the topology Mayhem will plan against (blueprint ─▶ live graph).
mayhem topology discover --compose docker-compose.yml

# 2. Compile the spec and run every safety gate — injects nothing.
mayhem validate mayhem.yaml --compose docker-compose.yml

# 3. Print the frozen execution plan as JSON.
mayhem plan mayhem.yaml --compose docker-compose.yml

# 4. Execute the drill and print the run summary.
mayhem run mayhem.yaml --compose docker-compose.yml

# 5. Replay any run's evidence.
mayhem status --run <run-id>
mayhem history <run-id>
```

`mayhem run` prints a copy-paste `run <run-id> — inspect with mayhem history
<run-id>` line at the end; that id is all you need for the evidence commands.

The example spec exercises **38 distinct faults** (every catalog entry that
applies to a Docker/Podman compose service) across the `testcase-lb`
load-balancer — CPU/memory/fd/disk pressure, load spikes, protocol abuse,
network latency/bandwidth/packet-loss, dependency and database and DNS faults,
TLS failure, container kill/restart/pause, HTTP error injection —
capped at one concurrent fault (`max_faults: 1`, `risk_ceiling: critical`)
with auto-recovery off (`recovery: false`), so the downstream checks observe
whether the stack self-heals on its own. The remaining nine `k8s.*` catalog
faults are exercised against a Kubernetes blueprint in
[`examples/k8s`](examples/k8s) (planning-only until the M8 driver lands), so
**every fault in the catalog has an example**.

Omit `--compose` and Mayhem auto-detects `docker-compose.yml` (or
`compose.yml`) in the current directory.

> `validate` and `plan` work against the blueprint alone and never touch live
> containers. `run` re-proves every fault at the impact gate against the live
> graph and bypasses — or, without `--skip-gate`, refuses — anything it cannot
> prove injectable.

---

## Authoring a Drill

A drill is one `kind: drill` YAML file — the DSL reference lives in
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
        params: { seconds: 5s, jitter_ms: 10 }

execution:
  - parallel: [cart-api]
  - check_spec:           # locus-aware checks
      - id: cart-health
        probe: { type: http, url: http://cart-api:8080/_health, expected_status: 200 }
        execution: service
        target: cart-api

success:                  # machine verdict
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

### Campaigns

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
| `--podman` | Use Podman instead of Docker. |
| `--debug` | Re-raise errors instead of rendering them. |

Commands:

| Command | Description |
|---------|-------------|
| `mayhem topology discover` | Discover live services/hosts and the dependency edges from the blueprint. |
| `mayhem validate SPEC` | Compile a drill spec and run every safety gate without injecting. |
| `mayhem plan SPEC` | Compile against the topology and print the frozen plan JSON. |
| `mayhem run SPEC` | Compile and execute a drill; print the run summary. |
| `mayhem maniac SPEC` | Compile and execute a random-injection drill — draws `run_level` single-fault rounds governed by the maniac seed/level (spec `config.maniac`, falling back to the `maniac:` layer of `mayhem.yaml`). |
| `mayhem status` | Show runs recorded in the database (`--json` supported). |
| `mayhem history RUN_ID` | Replay steps, events, and leases recorded for one run. |
| `mayhem recover RUN_ID` | Recover every orphaned fault lease belonging to a run. |
| `mayhem janitor` | Sweep leases past their TTL; expire pending runs; compensate. |
| `mayhem toolkit faults` | List the fault catalog with risk and compensatability. |
| `mayhem toolkit list` | Probe the host for the tools/capabilities faults require. |
| `mayhem experiment show SPEC` | Print the parsed drill spec as JSON. |
| `mayhem experiment validate` | Alias of `validate`. |
| `mayhem config show` / `mayhem config validate` | Inspect / validate the effective layered configuration (alias `cfg`). `show --json` also reports each section's provenance. |
| `mayhem campaign list` | List campaigns (draft/scheduled/running/…; `--json`). |
| `mayhem campaign create NAME` | Create a draft campaign (`--description`, `--hypothesis`). |
| `mayhem campaign show / status / delete ID` | Inspect, poll, or delete a campaign. |
| `mayhem campaign add-experiment ID SPEC` | Append a drill spec file to a campaign. |
| `mayhem campaign start / abort / archive ID` | Move a campaign through its lifecycle. |
| `mayhem campaign run ID` | Execute every experiment sequentially against the compose topology, honoring the campaign policy and window (`--no-gate` bypasses the impact gate). |

Every command (and the whole tree) abbreviates to any unique prefix: `mayhem
ex valid`, `mayhem t f`.

---

## Configuration

Runtime policies live in `mayhem.yaml` — the *configuration* file, distinct
from a `kind: drill` spec — auto-detected in the cwd or given with
`--config`. The effective view is one command away: `mayhem config show`
(alias `cfg`) prints the resolved configuration and the provenance of every
section; `mayhem config validate` refuses unknown keys, a missing or wrong
`apiVersion`, and out-of-range sections before anything runs.

```yaml
apiVersion: mayhem/v1        # required; anything else is rejected
policy:
  allow_faults: null         # null = whole catalog; set to restrict
  deny_faults: []            # fault ids never injectable
  risk_ceiling: null         # tightened by the drill ceiling at plan time
  allow_critical: false      # config-side half of the critical opt-in
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
runtime: docker              # docker | podman (CLI: --podman)
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

```bash
mayhem config show            # YAML + sourced-from comments
mayhem config show --json     # {"config": …, "sources": …}
mayhem config validate        # exit 0 / 3 on invalid layers
```

Drill-level `config.risk_ceiling` composes with the policy ceiling and can
only tighten it.

---

## Safety Model

- **Risk ceilings.** Every catalog fault carries a risk level; injection is
  refused when either the policy or the drill ceiling is exceeded.
  `--allow-critical` is the operator-side acknowledgment.
- **Concurrency budget.** `max_faults` caps simultaneously-injected faults;
  a wider `parallel:` step queues into rounds.
- **Duration caps.** Per-fault `duration` beyond the catalog maximum is a
  compile error.
- **Capability gating.** Faults declare the capabilities they need
  (docker engine, net_admin, process control, …); the plan is proven against
  the live graph by the impact gate before run — never assumed.
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
   dependency edges) from the compose blueprint and live containers.
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

### Documentation

| Document | Contents |
|----------|----------|
| [README.md](README.md) | This file. |
| [docs/drill-spec.md](docs/drill-spec.md) | **The drill DSL reference** — config, containers, execution, checks, success criteria, observability, and the full fault catalog. |
| [docs/compensation.md](docs/compensation.md) | **Fault compensation lifecycle** — inject / undo / verify contracts, executor routing, marker conventions, and the per-fault template table. |

### Status

| Area | Status |
|------|--------|
| Domain models, configuration system | Complete |
| Topology discovery (Docker/Podman) + compose project filtering + drift detection | Complete |
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
| Tests (859 collected: 752 unit + 95 e2e + 12 integration), ruff, mypy (per-file strict) | Complete |
| Kubernetes execution | Planned (interface-only; see [`examples/k8s`](examples/k8s)) |
| Web UI / REST API | Planned |

---

## Development

```bash
pip install -e ".[test]"

# Run all tests
pytest

# Lint
ruff check src/

# Type check (strict is configured per module)
mypy
```