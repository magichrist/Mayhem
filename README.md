# Mayhem

**Chaos engineering for Docker, Podman (and Kubernetes on the roadmap) — discover
your system, break it on purpose, prove it recovers.**

Mayhem builds a model of your running containers from the `docker-compose`
blueprint, plans controlled fault-injection *drills* against that model,
executes them through a capability-aware toolkit, derives a machine verdict
from the observations it recorded, and stores an immutable evidence trail.

```
docker-compose blueprint ─▶ topology graph ─▶ compile drill spec ─▶ plan ─▶ inject → observe → recover → verdict
                                                                                             └──▶ SQLite evidence + decision trace
```

---

## Why Mayhem

Most chaos tools hand you a list of commands: "kill this container," "add
latency here." Mayhem does something different — it **understands your system
first**.

1. **Topology-aware.** Mayhem reads your compose blueprint and discovers the
   live services, hosts, and dependencies to build a graph. Faults are planned
   against that graph, not applied blind. Compose project filtering keeps out
   unrelated stacks.

2. **Drill specs, not scripts.** One YAML file (`kind: drill`) declares
   per-container faults, cross-container ordering, checks, success criteria,
   and observability sources — with safety constraints baked in. You define
   what "healthy" looks like *before* you break anything.

3. **Machine verdicts.** Optional typed success criteria turn every run into a
   `PASS`/`FAIL` verdict derived from the observations actually recorded —
   no eyeballing.

4. **Automatic recovery.** Every fault ships a compensation contract. If a
   round fails or the controller crashes, the janitor sweeps dirty leases and
   reconciles the workload — no manual cleanup.

5. **Honest evidence.** Runs persist an immutable event journal, criteria
   evaluations, and a governing-decision trace in SQLite. No "trust me, it
   worked."

6. **Prefix-shortened CLI.** Type `mayhem r` instead of `mayhem run`.
   `mayhem e v` means `mayhem experiment validate`. Every level abbreviates
   to any unique prefix.

---

## What a Run Looks Like

```
$ mayhem run example.yaml --compose docker-compose.yml

validated r-process-drill-8f2a1c: 3 step(s), fingerprint 9f3c71ab12cd
[ok] round-1: injected proc.pause 10s into testcase-api
[ok] round-1-recover: recovered proc.pause from testcase-api (compensation ok)
[ok] api-up: HTTP 200 in 40.1ms (locus service, target testcase-api)

# Run r-process-drill-8f2a1c
**status**: completed
**verdict**: pass
**success criteria**: ALL PASS
- [PASS] status:api-up.status PASS (expected 200, got 200)
- [PASS] latency:api-up.latency_ms PASS (31.2 <= 500.0)
**observations**: 2/2 sources collected
**decisions**: ADR-M4-3 2026-09-05 (Machine-evaluable success criteria)
**wall**: 32.4s
```

`status` reflects the run machine state; `verdict` is the criteria-derived
outcome (undecided when a run fails/aborts, or has no `success` block). `mayhem
history <run-id>` replays the full event journal for any run.

---

## Quickstart

A complete, self-contained example lives in `examples/testCase/` — a three-tier
compose stack, its drill spec, and the nginx/data fixtures it relies on.

```bash
# 1. Bring the stack up and confirm the topology matches the blueprint.
cd examples/testCase
docker compose up -d
mayhem topology discover --compose docker-compose.yml

# 2. Compile the drill spec and run every safety gate (injects nothing).
mayhem validate mayhem.yaml --compose docker-compose.yml

# 3. Print the frozen execution plan as JSON.
mayhem plan mayhem.yaml --compose docker-compose.yml

# 4. Execute the drill and print the run summary.
mayhem run mayhem.yaml --compose docker-compose.yml

# 5. Inspect the evidence.
mayhem status
mayhem history <run-id>
```

Omit `--compose` and Mayhem auto-detects `docker-compose.yml` (or `compose.yml`)
in the current directory. The example drill targets the stack with 17 distinct
faults across 14 catalog categories (process pause, memory exhaust, CPU
saturate, storage fill, fd exhaust, load spike, protocol abuse, network
latency/partition, container kill, service stop, http error injection, db slow
query, DNS failures, TLS expiry, clock skew) — capped at one concurrently
injected fault (`max_faults: 1`, `risk_ceiling: critical`).

> Running the drill requires live containers. `validate`/`plan` work against the
> compose blueprint alone; the impact gate at `run` time re-proves every fault's
> injectability against the live graph and bypasses (or, without `--skip-gate`,
> refuses) the ones it cannot prove.

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
  - check_spec:           # locus-aware checks (ADR-M4-2)
      - id: cart-health
        probe: { type: http, url: http://cart-api:8080/_health, expected_status: 200 }
        execution: service
        target: cart-api

success:                  # machine verdict (ADR-M4-3)
  require_all: true
  criteria:
    - type: status
      source_id: cart-health.status
      expected: 200
    - type: latency
      source_id: cart-health.latency_ms
      lt_ms: 800

observability:            # evidence sources (ADR-M4-4)
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
| `mayhem status` | Show runs recorded in the database (`--json` supported). |
| `mayhem history RUN_ID` | Replay steps, events, and leases recorded for one run. |
| `mayhem recover RUN_ID` | Recover every orphaned fault lease belonging to a run. |
| `mayhem janitor` | Sweep leases past their TTL; expire pending runs; compensate. |
| `mayhem toolkit faults` | List the fault catalog with risk and compensatability. |
| `mayhem toolkit list` | Probe the host for the tools/capabilities faults require. |
| `mayhem experiment show SPEC` | Print the parsed drill spec as JSON. |
| `mayhem experiment validate` | Alias of `validate`. |
| `mayhem cfg show` / `mayhem cfg validate` | Inspect / validate the effective layered configuration. |
| `mayhem campaign …` | Create, list, and inspect chaos campaigns. |

Every command (and the whole tree) abbreviates to any unique prefix: `mayhem
ex valid`, `mayhem t f`.

---

## Configuration

Policy lives in `mayhem.yaml` (the *configuration* file — distinct from a
`kind: drill` spec), auto-detected in the cwd or given with `--config`:

```yaml
policy:
  risk_ceiling: high
profiles:
  prod:
    policy:
      risk_ceiling: medium
```

Layering, in increasing precedence: **built-in defaults → `mayhem.yaml` →
selected profile → environment variables (`MAYHEM_*`) → CLI flags**. The
effective view is always one command away: `mayhem cfg show` (and
`mayhem cfg validate`). Drill-level `config.risk_ceiling` composes with the
policy ceiling and can only tighten it.

---

## Safety Model

- **Risk ceilings.** Every catalog fault carries a risk level; injection is
  refused when either the policy or the drill ceiling is exceeded.
  `--allow-critical` is the operator-side acknowledgment.
- **Concurrency budget.** `max_faults` caps simultaneously-injected faults;
  a wider `parallel:` step queues into rounds.
- **Duration caps.** Per-fault `duration` beyond the catalog maximum is a
  compile error ([ADR-M3-8](docs/adr/ADR-M3-8-fault-registry.md)).
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
   dependency edges) from the compose blueprint and live containers
   ([ADR-0020](docs/adr/ADR-0020-container-name-pid-resolution.md),
   [ADR-M1-1](docs/adr/ADR-M1-1-runtime-identity-is-the-identity.md)).
2. **Prepare** — `mayhem config` layering (defaults → `mayhem.yaml` → profile →
   env → flags) plus topology, drift detection, and target revalidation
   ([ADR-M1-3](docs/adr/ADR-M1-3-target-drift-and-identity-persistence.md)).
3. **Compile & plan** — the drill spec becomes a frozen `ExecutionPlan` with
   step sequences, per-fault compensations, success criteria, and observability
   sources; every fault, target kind, capability, and duration is validated
   against the catalog ([ADR-M3-8](docs/adr/ADR-M3-8-fault-registry.md)).
4. **Execute** — the engine runs rounds (inject → observe → compensate) through
   the runtime adapter, evaluates criteria, collects observability, and writes
   step/event/lease rows with the governing-decision trace
   ([ADR-M1-2](docs/adr/ADR-M1-2-runtime-metadata-is-descriptive.md),
   [ADR-M4-1](docs/adr/ADR-M4-1-additive-duration.md)).
5. **Recover & report** — the janitor sweeps orphaned leases; `status`,
   `history`, and run summaries replay the evidence.

### Documentation

| Document | Contents |
|----------|----------|
| [README.md](README.md) | This file. |
| [docs/drill-spec.md](docs/drill-spec.md) | **The drill DSL reference** — config, containers, execution, checks, success criteria, observability, and the full fault catalog. |
| [docs/adr/](docs/adr/) | Architecture Decision Records (20 accepted). |

The living decision index (drill DSL → ADR):

| ADR | Title |
|-----|-------|
| [ADR-0019](docs/adr/ADR-0019-unified-drill-spec.md) | Unified drill spec (the DSL) |
| [ADR-0020](docs/adr/ADR-0020-container-name-pid-resolution.md) | Container-name → process resolution |
| [ADR-0021](docs/adr/ADR-0021-clean-break.md) | Clean break (older ADRs dropped; 0019/0020 consolidated) |
| [ADR-M1-1 … M1-4](docs/adr/) | Runtime identity, descriptive metadata, target drift, backward compatibility |
| [ADR-M3-1 … M3-8](docs/adr/) | Runtime adapter, capabilities, execution loci, network paths, fault registry |
| [ADR-M4-1](docs/adr/ADR-M4-1-additive-duration.md) | Additive DSL + typed Duration |
| [ADR-M4-2](docs/adr/ADR-M4-2-execution-locus-checks.md) | Execution-locus checks |
| [ADR-M4-3](docs/adr/ADR-M4-3-success-criteria.md) | Success criteria / run verdict |
| [ADR-M4-4](docs/adr/ADR-M4-4-observability.md) | Declarative observability |
| [ADR-M4-5](docs/adr/ADR-M4-5-schema-freeze-migrations.md) | Schema freeze + versioned migrations |

### Status

| Area | Status |
|------|--------|
| Domain models, configuration system | Complete |
| Topology discovery (Docker/Podman) + compose project filtering + drift detection | Complete |
| Fault catalog + registry + capability probing (`toolkit`) | Complete |
| Drill spec DSL (config / containers / execution / checks) | Complete |
| Deterministic + random planners, frozen plans | Complete |
| Success criteria + machine verdict (ADR-M4-3) | Complete |
| Declarative observability sources (ADR-M4-4) | Complete |
| Run engine with compensation + leases + janitor + recover | Complete |
| Safety gates + impact gate | Complete |
| CLI with prefix abbreviation, stable exit codes | Complete |
| SQLite persistence + restart, migrations (schema freeze, ADR-M4-5) | Complete |
| Campaigns (multi-spec runs) | Complete |
| Tests (825 collected: 718 unit + 107 e2e), ruff, mypy (per-file strict) | Complete |
| Kubernetes execution | Planned (interface-only per ADR-M3-6) |
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