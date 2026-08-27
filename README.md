# Mayhem

**Chaos engineering for Docker and Podman — discover your system, break it on purpose, prove it recovers.**

Mayhem is an orchestration engine that builds a model of your running services,
plans controlled fault injection experiments against that model, executes them
through a capability-aware toolkit, verifies recovery with health checks, and
records an immutable audit trail.

```
discover topology → plan experiment → inject fault → observe → verify recovery → record evidence
```

---

## Why Mayhem

Most chaos tools give you a list of commands: "kill this container," "add
latency here." Mayhem does something different — it **understands your system
first**.

1. **Topology-aware.** Mayhem reads your `docker-compose.yaml` and queries
   live containers to build a graph of services, dependencies, and hosts. Faults
   are planned against this graph, not blindly applied.

2. **Controlled experiments, not scripts.** Experiments are YAML files with
   hypotheses, step sequences, health checks, and safety constraints. You define
   what "healthy" looks like before you break anything.

3. **Automatic recovery.** Every fault comes with a compensation contract.
   If an experiment fails or the controller crashes, the janitor repairs
   dirty state — no manual cleanup.

4. **Honest evidence.** Every run produces an immutable event journal, a
   pass/fail evaluation, and a full audit trail stored in SQLite. No
   "trust me, it worked."

5. **Prefix-shortened CLI.** Type `mayhem r` instead of `mayhem run`.
   `mayhem e v` means `mayhem experiment validate`. Every level abbreviates.

---

## What a Run Looks Like

```
$ mayhem run examples/experiments/proc-pause-drill.yaml --compose examples/

topology discovered: 4 services, 1 host, 3 edges
safety gate: passed
planning drill experiment: proc-pause-drill (3 steps)
  step 1/3  pause (inject fault: proc.pause, target: svc/api)
    lease acquired → fault injected → checks running...
    ✓ http_check passed (status=200, latency=42ms)
    → recovery: SIGCONT sent
  step 2/3  verify (http_check: GET http://localhost:8080/health)
    ✓ passed
  step 3/3  note (message: "process survived a 10s pause")

run r-proc-pause-drill completed in 18.2s — 3/3 steps passed
```

---

## Quickstart

### Install

```bash
pip install -e .
```

### See what faults are available

```bash
mayhem toolkit faults
```

### Discover your topology

```bash
# Auto-detect docker-compose.yaml in current directory
mayhem topology discover

# Or point to a specific compose file
mayhem topology discover --compose docker-compose.yaml
```

Output is a JSON graph of your services, containers, hosts, and edges — plus any
drift between the compose blueprint and what's actually running.

### Validate an experiment (no execution)

```bash
mayhem validate examples/experiments/proc-pause-drill.yaml --compose examples/
```

This compiles the experiment, resolves targets against your topology, runs all
safety gates, and reports the plan — without injecting anything.

### Plan an experiment (see the full plan)

```bash
mayhem plan examples/experiments/proc-pause-drill.yaml --compose examples/
```

Prints the frozen execution plan as JSON — every step, every resolved target,
every parameter.

### Run an experiment

```bash
mayhem run examples/experiments/proc-pause-drill.yaml --compose examples/
```

Executes the experiment end-to-end: acquires leases, injects faults, runs
health checks, verifies recovery, journals every event.

### Check what happened

```bash
mayhem status                    # recent runs
mayhem history r-proc-pause-drill  # full event journal for a run
```

### Repair dirty state

```bash
mayhem janitor                   # sweep all dirty leases
mayhem recover r-proc-pause-drill  # repair a specific run
```

---

## Writing an Experiment

Experiments are YAML files. Here's a minimal one:

```yaml
kind: drill
name: http-latency-drill
hypothesis: "adding 200ms latency to the api service is survivable"
config:
  risk_ceiling: medium
  max_faults: 1
  timeout: 10m
containers:
  api:
    faults:
      - fault: net.latency
        duration: 30s
        params:
          delay_ms: 200
execution:
  - parallel: [api]
  - wait: 5s
```

Run it:

```bash
mayhem run http-latency-drill.yaml --compose docker-compose.yaml
```

See [docs/mayhem-yml.md](docs/mayhem-yml.md) for the complete experiment
format and configuration reference.

---

## Configuration

Mayhem uses a `mayhem.yaml` file for project-level configuration:

```yaml
apiVersion: mayhem/v1

environment:
  name: staging
  klass: staging

policy:
  deny_faults:
    - proc.kill          # never kill processes in staging
  risk_ceiling: medium

blast_radius:
  max_concurrent_faults: 2
  cooldown_seconds: 60

storage:
  path: .mayhem/state.db
  artifacts_dir: .mayhem/artifacts

runtime: docker
log_level: INFO
```

Configuration layers (later wins): defaults → `mayhem.yaml` → profile overlay
→ environment variables → CLI flags.

See [docs/mayhem-yml.md](docs/mayhem-yml.md) for the complete configuration
reference.

---

## CLI Reference

```
mayhem [OPTIONS] COMMAND [ARGS]...

Options:
  --db PATH                    SQLite database (default: .mayhem/mayhem.db)
  --config PATH                Config file
  --profile TEXT               Config profile overlay
  --allow-critical             Allow critical-risk faults
  --podman                     Use Podman instead of Docker
  --debug                      Re-raise errors instead of formatting

Commands:
  topology discover            Discover and graph your system
  topology drift               Compare live state to a snapshot
  validate EXPERIMENT          Compile + safety check (no execution)
  plan EXPERIMENT              Compile + print frozen plan
  run EXPERIMENT               Execute experiment end-to-end
  status                       Show recent runs
  history RUN_ID               Show full event journal
  recover RUN_ID               Repair dirty state
  janitor                      Sweep all dirty leases
  toolkit faults               List available fault IDs
  toolkit probe                Probe which tools are installed
  config show                  Print effective config + sources
```

### Topology Options (for validate/plan/run)

```
--compose PATH        docker-compose.yaml blueprint
--process NAME=PID    Local process node (multiple allowed)
--service NAME        Logical service node (multiple allowed)
--host NAME           Host node name (default: local)
```

### Prefix Shortcuts

Every command abbreviates to its shortest unique prefix:

```
mayhem r examples/experiment.yaml          → mayhem run
mayhem t d --compose examples/             → mayhem topology discover
mayhem e v examples/experiment.yaml        → mayhem experiment validate
mayhem j                                   → mayhem janitor
mayhem s                                   → mayhem status
```

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General failure |
| 2 | Usage error (bad flags/args) |
| 3 | Config error |
| 4 | Validation error |
| 5 | Safety refused |
| 6 | Experiment failure |
| 7 | Recovery failure |
| 8 | Agent error |
| 9 | Toolkit error |
| 10 | Ambiguous command |

---

## Fault Catalog

| ID | Category | What It Does | Risk |
|---|---|---|---|
| `proc.pause` | process | SIGSTOP a process | medium |
| `proc.kill` | process | SIGKILL a process | critical |
| `proc.cpu` | process | Burn CPU in a process | medium |
| `container.kill` | container | Kill a container | high |
| `container.pause` | container | Pause a container | medium |
| `container.exec` | container | Execute inside a container | medium |
| `net.latency` | network | Add delay to network traffic | medium |
| `net.loss` | network | Drop packets | medium |
| `net.partition` | network | Split the network | high |
| `cpu.pressure` | cpu | CPU stress via stress-ng | medium |
| `mem.pressure` | memory | Memory pressure via stress-ng | medium |
| `io.stress` | io | Disk I/O stress via stress-ng | medium |
| `disk.fill` | disk | Fill disk space | high |
| `disk.latency` | disk | Add disk I/O latency | medium |

Tools are resolved via a fallback chain — if `tc` isn't available, `toxiproxy`
handles network faults. Run `mayhem toolkit probe` to see what's installed.

---

## Project Status

| Area | Status |
|---|---|
| Domain models | Complete |
| Configuration system | Complete |
| Topology discovery (Docker/Podman) | Complete |
| Compose project filtering | Complete |
| Drift detection | Complete |
| Fault catalog + registry | Complete |
| Deterministic + random planners | Complete |
| Run engine with leases + recovery | Complete |
| Safety gates | Complete |
| Janitor | Complete |
| CLI with prefix abbreviation | Complete |
| JSON-RPC agent protocol | Complete |
| SQLite persistence | Complete |
| Structured metrics | Complete |
| Tests (~290, all passing) | Complete |
| Kubernetes support | Planned |
| Web UI | Planned |
| REST API | Planned |

---

## Documentation

| Document | Description |
|---|---|
| [docs/state.md](docs/state.md) | Complete repo state — architecture, CLI, schemas, models, tests |
| [docs/mayhem-yml.md](docs/mayhem-yml.md) | Full `mayhem.yaml` configuration reference |
| [docs/roadmap.md](docs/roadmap.md) | What's next |
| [docs/adr/](docs/adr/) | Architecture Decision Records (13 accepted) |
| [docs/fault-catalog/](docs/fault-catalog/) | Fault coverage matrix |

---

## Development

```bash
pip install -e ".[test]"

# Run all tests
pytest

# Lint
ruff check src/

# Type check
mypy --strict src/mayhem/config.py
```

### Architecture

Mayhem is a Python single-package layered monolith (ADR-0002). Internal layers
are enforced by import-linter:

```
domain → config → topology → toolkit → protocol → agents → controller → persistence → cli
```

The `domain` layer has zero I/O. Container runtime imports are restricted to
`topology/providers/`. The CLI is a thin layer over service interfaces.

See [docs/adr/](docs/adr/) for all 13 Architecture Decision Records.

---

## License

MIT
