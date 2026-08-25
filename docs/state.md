# Mayhem — Complete Repository State

> Machine-readable reference for agentic systems. Covers architecture, CLI
> surface, configuration schema, experiment format, domain models, execution
> pipeline, fault catalog, storage, safety gates, and current project status.

---

## 1. Project Identity

| Field | Value |
|---|---|
| Name | `mayhem` |
| Version | `0.1.0.dev0` |
| Python | `>=3.12` |
| License | MIT |
| Entry point | `mayhem = mayhem.cli.app:main` (Click CLI) |
| Protocol | `mayhem/1` (ndjson JSON-RPC 2.0 over Unix socket / TCP) |
| Config API | `mayhem/v1` |
| Source layout | `src/mayhem/` (src-layout) |
| Test runner | `pytest` |
| Linting | `ruff` |
| Type checking | `mypy --strict` |

---

## 2. What Mayhem Does

Mayhem is a **chaos engineering orchestration engine**. It does not just inject
faults — it builds a model of your system, plans experiments against that model,
executes them through a capability-oriented toolkit, observes effects with
steady-state checks, guarantees recovery through leases and write-ahead undo,
and records honest evidence (journals, evaluations, full audit trail).

### Core Loop

```
DISCOVER topology → UNDERSTAND system → SELECT target → SELECT fault → SELECT tool
→ EXECUTE → OBSERVE → EVALUATE → RECOVER → LEARN → NEXT experiment
```

### Supported Runtimes

- **Docker** (primary)
- **Podman** (flag `--podman`)
- **Bare-metal / VM processes** (via `--process name=pid`)
- Kubernetes is planned but not yet implemented (ADR-0013 deferred)

### Fault Categories

| Category | Fault IDs | Description |
|---|---|---|
| `process` | `proc.pause`, `proc.kill`, `proc.cpu` | Process-level faults (SIGSTOP, SIGKILL, CPU burn) |
| `container` | `container.kill`, `container.pause`, `container.exec` | Container-level faults via Docker/Podman CLI |
| `network` | `net.latency`, `net.loss`, `net.partition` | Network impairment via tc-netem or toxiproxy |
| `disk` | `disk.fill`, `disk.latency` | Disk pressure faults |
| `cpu` | `cpu.pressure` | CPU stress via stress-ng |
| `memory` | `mem.pressure` | Memory pressure via stress-ng |
| `io` | `io.stress` | I/O stress via stress-ng |

---

## 3. Architecture

### 3.1 Layered Monolith (ADR-0002)

One installable distribution with enforced internal layers:

```
domain/          — pure models, zero IO
config/          — layered config loading
topology/        — provider pipeline for system discovery
toolkit/         — capability registry, manifests, tool runner
protocol/        — JSON-RPC 2.0 transport
agents/          — executors, probes, lease client
controller/      — planner, executor, janitor, compensation, safety
persistence/     — SQLite repositories
metrics/         — counters, histograms, structured events
cli/             — thin Click commands over service layer
```

Import linter enforces: `domain` has zero IO; container-runtime imports only in
`topology/providers/*`; CLI is thin over `api` service interfaces.

### 3.2 Key Components

| Component | Location | Purpose |
|---|---|---|
| **TopologyService** | `topology/service.py` | Runs provider pipeline, merges nodes/edges, computes drift |
| **ComposeFileProvider** | `topology/providers/compose.py` | Parses docker-compose YAML into blueprint nodes |
| **ContainerRuntimeProvider** | `topology/providers/docker_runtime.py` | Queries live Docker/Podman, filters by project/names |
| **CapabilityRegistry** | `toolkit/registry.py` | Loads YAML manifests, probes tools, builds fallback chains |
| **Planner** | `controller/planner.py` | Compiles experiment spec → frozen `ExecutionPlan` |
| **RunEngine** | `controller/executor.py` | Executes plan step-by-step with leases, recovery, events |
| **Janitor** | `controller/janitor.py` | Repairs dirty state left by crashed controllers |
| **Safety** | `controller/safety.py` | Pre-execution assertions (blast radius, deny_faults) |
| **LeaseClient** | `agents/lease_client.py` | Write-ahead lease lifecycle (acquire → dirty → clean/abort) |
| **Probes** | `agents/probes.py` | HTTP, exec, TCP health probes with expectation matching |

---

## 4. CLI Surface

### 4.1 Root Group

```
mayhem [OPTIONS] COMMAND [ARGS]...
```

| Option | Type | Default | Description |
|---|---|---|---|
| `--db` | PATH | `.mayhem/mayhem.db` | SQLite database path |
| `--config` | PATH | None | Config file (`mayhem.yaml`) |
| `--profile` | TEXT | None | Config profile overlay |
| `--allow-critical` | FLAG | False | Allow critical-risk faults |
| `--podman` | FLAG | False | Use Podman instead of Docker |
| `--debug` | FLAG | False | Re-raise errors instead of formatting |

### 4.2 Prefix Abbreviation System

Every command group uses `PrefixGroup` which resolves unique prefixes:

```
mayhem e v examples/experiments/proc-pause-drill.yaml
# resolves to: mayhem experiment validate examples/experiments/proc-pause-drill.yaml

mayhem t d --compose examples/
# resolves to: mayhem topology discover --compose examples/

mayhem r examples/experiments/proc-pause-drill.yaml
# resolves to: mayhem run examples/experiments/proc-pause-drill.yaml
```

Resolution rules:
- Minimum 1 character
- Must be unambiguous among siblings
- Works at every nesting level

### 4.3 Default Help

Running `mayhem` with no arguments prints a contextual help summary showing all
available commands and the active runtime engine, not Click's auto-generated help.

### 4.4 Commands

#### Topology Group

| Command | Usage | Description |
|---|---|---|
| `mayhem topology discover` | `[--compose PATH]` | Run provider pipeline, print graph + drift JSON |
| `mayhem topology drift` | `--snapshot ID` | Compare live state against a saved snapshot |

#### Lifecycle Commands (top-level)

| Command | Usage | Description |
|---|---|---|
| `mayhem validate EXPR` | `[TOPOLOGY_OPTIONS]` | Compile + safety gates, no execution |
| `mayhem plan EXPR` | `[TOPOLOGY_OPTIONS]` | Compile + print frozen plan JSON |
| `mayhem run EXPR` | `[TOPOLOGY_OPTIONS]` | Execute experiment end-to-end |
| `mayhem status` | | Show recent runs with status |
| `mayhem history ID` | | Show full event journal for a run |
| `mayhem recover ID` | | Repair dirty state from a specific run |
| `mayhem janitor` | | Sweep and repair all dirty leases |

**Topology Options** (shared by validate/plan/run):

| Option | Type | Description |
|---|---|---|
| `--process` / `-p` | `NAME=PID` (multiple) | Local process node |
| `--service` | NAME (multiple) | Logical service node |
| `--host` | TEXT (default: `local`) | Host node name |
| `--compose` | PATH | docker-compose.yaml blueprint |

#### Experiment Group

| Command | Usage | Description |
|---|---|---|
| `mayhem experiment validate EXPR` | `[TOPOLOGY_OPTIONS]` | Alias for `mayhem validate` |
| `mayhem experiment plan EXPR` | `[TOPOLOGY_OPTIONS]` | Alias for `mayhem plan` |
| `mayhem experiment run EXPR` | `[TOPOLOGY_OPTIONS]` | Alias for `mayhem run` |
| `mayhem experiment history ID` | | Alias for `mayhem history` |

#### Toolkit Group

| Command | Usage | Description |
|---|---|---|
| `mayhem toolkit faults` | | List available fault IDs from manifest catalog |
| `mayhem toolkit probe` | | Probe which tools are installed and return versions |

#### Config Group

| Command | Usage | Description |
|---|---|---|
| `mayhem config show` | | Print effective config + source map |

### 4.5 Exit Codes

| Code | Name | Meaning |
|---|---|---|
| 0 | `SUCCESS` | Operation succeeded |
| 1 | `GENERAL_FAILURE` | Unclassified error |
| 2 | `USAGE_ERROR` | Bad flags/arguments (Click native) |
| 3 | `CONFIG_ERROR` | Config layering/validation failed |
| 4 | `VALIDATION_ERROR` | Experiment/spec/target validation failed |
| 5 | `SAFETY_REFUSAL` | Safety gate refused the operation |
| 6 | `EXPERIMENT_FAILURE` | Experiment ran but did not complete |
| 7 | `RECOVERY_FAILURE` | Recovery/janitor left dirty state |
| 8 | `AGENT_ERROR` | Agent transport/runtime failure |
| 9 | `TOOLKIT_ERROR` | External tool invocation failed |
| 10 | `AMBIGUOUS_COMMAND` | Prefix matched multiple commands |

---

## 5. Configuration (`mayhem.yaml`)

### 5.1 Loading Order (later wins)

```
built-in defaults → mayhem.yaml → profile overlay (mayhem.{profile}.yaml)
→ MAYHEM_* env vars (allowlisted) → CLI flags
```

### 5.2 Full Schema

```yaml
apiVersion: mayhem/v1          # REQUIRED, must be "mayhem/v1"

environment:
  name: staging                # string, default "default"
  klass: staging               # "production" | "staging" | "development"

policy:
  allow_faults: null              # list of fault IDs — when set, ONLY these are permitted
  deny_faults:                    # list of fault IDs to block
    - proc.kill
  risk_ceiling: medium            # max risk level ("low" | "medium" | "high" | "critical" | null)
  allow_critical: false           # opt-in for critical-risk faults

blast_radius:
  max_services_pct: 50.0       # float 0-100, default 50
  max_hosts: 2                 # int ≥1, default 2
  max_concurrent_faults: 3     # int ≥1, default 3
  cooldown_seconds: 30.0       # float ≥0, default 30

storage:
  path: .mayhem/state.db                  # SQLite database path
  artifacts_dir: .mayhem/artifacts         # run artifacts directory

toolkit:
  binaries: {}                             # tool name → binary path overrides

runtime: docker                # "docker" | "podman", default "docker"

target:
  containers:                  # explicit container names (used when no compose file)
    - my-api
    - my-worker

log_level: INFO                # "DEBUG" | "INFO" | "WARNING" | "ERROR"
```

### 5.3 Environment Variables

Only these are recognized (case-sensitive):

| Variable | Maps To |
|---|---|
| `MAYHEM_STORAGE_PATH` | `storage.path` |
| `MAYHEM_ARTIFACTS_DIR` | `storage.artifacts_dir` |
| `MAYHEM_LOG_LEVEL` | `log_level` |

---

## 6. Experiment Format (YAML)

### 6.1 Top-Level Fields

```yaml
kind: deterministic            # REQUIRED: "deterministic" | "random"
name: my-experiment            # REQUIRED: string identifier
hypothesis: "..."              # string — what you believe will happen
labels:                        # key-value metadata
  team: platform
  severity: medium

constraints:
  risk_ceiling: medium         # "low" | "medium" | "high" | "critical"
  max_faults: 5                # int ≥1, default unlimited
  timeout: 300s                # Duration, overall timeout

on_failure: abort_and_recover  # "abort_and_recover" | "continue"
on_pre_failure: skip_run       # "skip_run" | "abort"

steps:                         # REQUIRED: list of step objects
  - id: step-name
    inject_fault: ...          # or: start_load, stop_load, wait, check, notify, parallel
```

### 6.2 Step Types

#### `inject_fault`

```yaml
- id: my-fault
  inject_fault:
    fault: proc.pause           # REQUIRED: from fault catalog
    selectors:                  # REQUIRED: ≥1 TargetSelector
      - kind: process
        expr: "name=api"
    params:                     # fault-specific parameters
      duration: 10s
      signal: SIGSTOP
    duration: 30s               # total fault duration
```

#### `wait`

```yaml
- id: settle
  wait: 5s                     # Duration shorthand
```

#### `check` (steady-state check)

```yaml
- id: health
  check:
    ref: health-probe          # references a steady_state_checks probe id
```

#### `start_load` / `stop_load`

```yaml
- id: ramp-up
  start_load:
    generator: k6
    target: service=api
    params:
      rps: 100

- id: ramp-down
  stop_load: k6
```

#### `notify`

```yaml
- id: alert
  notify:
    channel: slack             # "slack" | "webhook"
    message: "Fault injected"
```

#### `parallel`

```yaml
- id: concurrent-checks
  parallel:
    branches:
      - - check: { ref: health-probe }
      - - wait: 2s

### 6.3 TargetSelector Syntax

```
service=api              # match by compose service name
kind=container           # match by node kind
kind=process             # match process nodes
kind=host                # match host nodes
name=web-1               # match by node name
engine=docker            # match by runtime engine
```

Multiple selectors in a list act as OR (any match counts).

### 6.4 Duration Format

Accepts: `10s`, `5m`, `300ms`, `1.5s`, or a bare number (seconds).

### 6.5 Random Experiment (additional fields)

```yaml
kind: random
name: random-drill
selection_policy:
  fault_categories: [process, network, container]
  exclude_faults: [proc.kill]
  max_faults: 3
seed: 42                     # optional, for reproducibility
```

---

## 7. Domain Models

### 7.1 Topology

**Node Kinds** (closed union):

| Kind | Class | Key Fields |
|---|---|---|
| `service` | `ServiceNode` | `image`, `exposed_ports` |
| `container` | `ContainerNode` | `engine`, `runtime_id`, `ip_address`, `host_id`, `service_name`, `ports`, `state` |
| `host` | `HostNode` | `address`, `transport` (local/ssh), `ssh_user` |
| `process` | `ProcessNode` | `pid`, `host_id` |
| `external_dependency` | `ExternalDependencyNode` | `address`, `transport` (dns/tcp/udp), `port` |

**Edges**: `(src, dst, kind)` where kind is `runs_on`, `depends_on`, `exposes`,
`contained_in`.

**TargetSelector**: parsed from `key=value` syntax, matched against node fields.
Validates against a graph and raises `TargetResolutionError` if nothing matches.

### 7.2 Faults

**FaultCategory** (enum): `process`, `container`, `network`, `disk`, `cpu`, `memory`, `io`

**FaultDefinition**:
- `id`: dotted identifier (e.g., `proc.pause`)
- `category`: derived from prefix
- `description`: human-readable
- `params`: list of `ParamSpec` (name, type, default, minimum, maximum, required)
- `required_targets`: tuple of `NodeKind` — which node kinds this fault can target
- `risk`: `RiskLevel`

**FaultInvocation** (in experiment spec):
- `fault`: string (fault ID)
- `selectors`: tuple of `TargetSelector`
- `params`: dict of parameter values

### 7.3 Risk Levels

```python
class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
```

### 7.4 Events

```python
class EventKind(StrEnum):
    (
        RUN_STARTED,
        RUN_COMPLETED,
        RUN_FAILED,
    )
    (
        RUN_ABORT_REQUESTED,
        RUN_ABORTED,
    )
    (
        STEP_STARTED,
        STEP_COMPLETED,
        STEP_SKIPPED,
    )
    (
        FAULT_INJECTED,
        FAULT_RECOVERED,
        FAULT_FAILED,
    )
    (
        RECOVERY_STARTED,
        RECOVERY_COMPLETED,
    )
    (
        CHECK_PASSED,
        CHECK_FAILED,
    )
    SAFETY_REFUSED, LEASE_ACQUIRED, LEASE_RELEASED, LEASE_EXPIRED
```

Every event is journal-serialized as ndjson with `run_id`, `timestamp`, `kind`,
and `payload`.

### 7.5 Experiment Models

| Model | Purpose |
|---|---|
| `DeterministicExperiment` | Authoring surface — named steps, ordered |
| `RandomExperiment` | Selection policy + seed |
| `ExecutionPlan` | Frozen, validated output of compilation |
| `PlannedStep` | Single step in a plan with resolved targets |
| `PlannedFault` | Resolved fault with attached compensation contract |
| `ResolvedTarget` | Target selector resolved to a concrete node ID |
| `RunResult` | Status + per-step reports after execution |

### 7.6 Checks

Three probe types:

| Type | Fields |
|---|---|
| `http` | `url`, `method`, `timeout`, `expected_status` |
| `exec` | `cmd`, `timeout`, `expected_exit_code` |
| `tcp` | `host`, `port`, `timeout` |

**Expectation** fields: `status_eq`, `exit_code_eq`, `latency_max_ms`,
`latency_min_ms`, `body_contains`, `body_not_contains`.

Evaluation phases: `pre` (baseline gate), `during` (violation policy), `post`
(recovery proof).

---

## 8. Execution Pipeline

### 8.1 Lifecycle

```
1. CLI parses args → builds topology graph (compose/process/service/host)
2. Config loaded (layered: defaults → file → env → CLI)
3. Safety validation (deny_faults, blast radius, risk ceiling)
4. Planner compiles spec → ExecutionPlan (frozen, with compensation contracts)
5. RunEngine opens run (run_id, status=running, events journal)
6. For each step:
   a. Acquire lease
   b. Execute fault via agent executor
   c. Run checks (pre/during/post)
   d. Release lease
   e. Journal event
7. If any step fails: abort_and_recover
8. Janitor sweeps dirty leases
9. Run closed with final status
```

### 8.2 Agent Protocol

JSON-RPC 2.0 over ndjson, transport via Unix socket or TCP.

Messages:
- `handshake` — capability exchange, tool probe results
- `task.execute` — inject a fault (with fault, params, selectors)
- `task.recover` — execute compensation (undo operation)
- `task.verify` — run a verification probe

### 8.3 Lease System

Write-ahead lifecycle: `acquired → dirty → clean` (success) or `dirty → aborted`
(failure/recovery). Prevents orphaned fault state from crashed controllers.

---

## 9. Toolkit / Fault Registry

### 9.1 Manifest Format (YAML)

```yaml
tool: docker
provides: [container.kill, container.pause, container.exec]
probe:
  cmd: [docker, --version]
  version_regex: 'Docker version (?P<v>[\d.]+)'
privilege: sudo_patterns      # none | sudo | sudo_patterns | root
risk: high
fallback_groups:
  container.kill: fallback_1
  container.pause: fallback_1
  container.exec: primary
```

### 9.2 Built-in Manifests

| Manifest | Tool | Capabilities | Privilege |
|---|---|---|---|
| `docker.yaml` | docker | `container.kill`, `container.pause`, `container.exec` | `sudo_patterns` |
| `podman.yaml` | podman | `container.kill`, `container.pause`, `container.exec` | `sudo_patterns` |
| `stress-ng.yaml` | stress-ng | `cpu.pressure`, `mem.pressure`, `io.stress` | `none` |
| `tc-netem.yaml` | tc | `net.latency`, `net.loss`, `net.partition` | `root` |
| `toxiproxy.yaml` | toxiproxy | `net.latency`, `net.partition` | `none` |

### 9.3 Fallback Chains

Tools are grouped into fallback chains. If the primary tool is unavailable, the
next tool in the chain is tried. The `--prefer` config option can override
ordering.

---

## 10. Storage

### 10.1 SQLite Schema

| Table | Purpose |
|---|---|
| `runs` | Run metadata (id, status, config_snapshot_id, topology_snapshot_id, timestamps) |
| `step_runs` | Per-step execution records (run_id, step_id, status, fault_id, duration, etc.) |
| `config_snapshots` | Immutable config snapshots keyed by SHA-256 fingerprint |
| `topology_snapshots` | Immutable topology snapshots keyed by SHA-256 fingerprint |
| `leases` | Write-ahead lease records (id, run_id, status=acquired/dirty/clean/aborted) |
| `fault_invocations` | Fault execution records with params, targets, undo_ops |
| `recovery_records` | Recovery attempt records |
| `events` | Full event journal (ndjson rows) |

### 10.2 Journal

Events are stored in the `event_journal` table in the SQLite database.
Every event (run start/complete, step start/complete, fault inject/recover,
check pass/fail, safety refusal, lease acquire/release) is recorded with
timestamp and payload. Retrieved via `mayhem history <run_id>`.

---

## 11. Safety Gates

| Gate | Description |
|---|---|
| **Denylist** | Fault IDs in `policy.deny_faults` are blocked before planning |
| **Risk ceiling** | `constraints.risk_ceiling` in experiment spec limits max fault risk |
| **Blast radius** | `blast_radius` config limits concurrent faults, services affected, hosts |
| **Critical faults** | Critical-risk faults require `--allow-critical` CLI flag |

---

## 12. Tests

### 12.1 Test Files

| File | Tests | What It Covers |
|---|---|---|
| `test_cli_resolver.py` | 13 | Prefix resolution, ambiguity detection, `--help` at root/ambiguous/valid |
| `test_cli.py` | 5 | Exit codes, `--debug`, config show |
| `test_config.py` | 25 | Config loading, layered merge, profiles, env vars, CLI overrides, snapshot IDs |
| `test_topology.py` | 14 | Target resolution, selector matching |
| `test_domain_properties.py` | 12 | FaultDefinition params, FaultInvocation, Edge invariants |
| `test_spec.py` | 12 | Spec compilation edge cases, step types, inject_fault, wait, parallel |
| `test_executor.py` | 10 | RunEngine execution, lease lifecycle, event journaling |
| `test_safety.py` | 15 | Denylist, risk ceiling, blast radius, lease, dry run |
| `test_lease_repository.py` | 12 | Lease CRUD, state transitions, expiry |
| `test_janitor.py` | 12 | Dirty lease sweep, repair, recovery |
| `test_tool_runner.py` | 14 | Tool execution, hashing, canonical JSON |
| `test_agent_protocol.py` | 11 | JSON-RPC messages, handshake, task.execute, task.recover |
| `test_agents.py` | 9 | Executors, probe, fingerprint |
| `test_cli_exit_codes.py` | 8 | Exit code mapping for all error types |
| `test_faults.py` | 8 | Fault catalog, all_definitions, definition_for |
| `test_risks.py` | 6 | RiskLevel ordering, EnvironmentClass |
| `test_leases.py` | 8 | Lease model, expiry, dirty state |
| `test_planner.py` | 10 | Deterministic/random planning |
| `test_watchdog.py` | 5 | Watchdog, metrics sink |
| `test_fingerprint.py` | 6 | Config/topology fingerprinting |
| `test_capability_registry.py` | 7 | Manifest loading, probe, resolve |
| **Total** | **~290** | |

### 12.2 Running Tests

```bash
pip install -e ".[test]"
pytest                    # all tests
pytest tests/unit/        # unit only
pytest -x                 # stop on first failure
```

---

## 13. Project Status

### Implemented

- Full domain model layer (topology, faults, experiments, checks, events)
- Configuration system with layered loading and snapshotting
- Topology discovery pipeline (Compose + Container Runtime providers)
- Runtime scoping (compose project filtering, explicit container names)
- Drift detection (live vs. blueprint)
- Capability registry with YAML manifests and fallback chains
- Deterministic and random experiment planners
- Run engine with lease lifecycle, compensation, and event journaling
- Safety gates (deny_faults, risk ceiling, blast radius, critical flag)
- Janitor for dirty-state repair
- CLI with prefix abbreviation, contextual help, exit codes
- JSON-RPC 2.0 agent protocol (server, handshake, task dispatch)
- SQLite persistence (runs, steps, leases, snapshots, events)
- Structured metrics (counters, histograms)
- ~290 tests, all passing

### Not Yet Implemented

- Kubernetes runtime provider (ADR-0013 deferred)
- Live monitoring/observability integration
- Web UI / dashboard
- REST API (planned per ADR-0011)
- CI/CD pipeline setup
- `pip install mayhem` on PyPI (source-install only)
- `mayhem.yaml` example file in repo root

---

## 14. File Tree

```
mayhem/
├── pyproject.toml
├── README.md
├── MANIFEST.in
├── Dockerfile
├── docker-compose.yml
├── Justfile
├── Makefile
├── AGENTS.md
├── .claude/
│   ├── commands/         # custom slash commands
│   └── rules/            # agent behavior rules
├── docs/
│   ├── state.md          # THIS FILE
│   ├── mayhem-yml.md     # mayhem.yaml reference
│   ├── roadmap.md
│   ├── architecture/     # system-overview, domain-model, safety, toolkit, etc.
│   ├── reference/        # cli.md, configuration-schema.md, experiment-dsl.md, sqlite-schema.md
│   ├── fault-catalog/
│   └── adr/
│       ├── 0001-record-architecture-decisions.md
│       ├── 0002-python-single-package-layered-monorepo.md
│       ├── 0003-controller-agent-split.md
│       ├── 0004-external-tool-capability-manifest.md
│       ├── 0005-leaderless-recovery.md
│       ├── 0006-topology-graph-model.md
│       ├── 0007-leaderless-recovery-with-compensation.md
│       ├── 0008-experiment-spec-grammar.md
│       ├── 0009-persistence-sqlite.md
│       ├── 0010-fault-injection-through-agent-layer.md
│       ├── 0011-agent-protocol-jsonrpc.md
│       ├── 0012-safety-gates-and-blast-radius.md
│       └── 0013-kubernetes-runtime.md
├── examples/
│   ├── docker-compose.yml
│   ├── nginx.conf
│   ├── data/
│   └── experiments/
│       ├── proc-pause-drill.yaml
│       └── maniac-hour.yaml
├── src/mayhem/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli/
│   │   ├── app.py           # root group + error mapping
│   │   ├── context.py       # CliContext dataclass
│   │   ├── exit_codes.py    # ExitCode enum
│   │   ├── resolver.py      # PrefixGroup + abbreviation
│   │   ├── topology.py      # topology discover/drift
│   │   ├── lifecycle.py     # validate/plan/run/status/history/recover/janitor
│   │   ├── experiment.py    # experiment group (aliases)
│   │   ├── toolkit.py       # toolkit faults/probe
│   │   ├── config_cmd.py    # config show
│   │   └── services.py      # shared service layer
│   ├── config.py            # layered config loading + snapshot
│   ├── domain/
│   │   ├── topology.py      # nodes, edges, graph, selectors
│   │   ├── faults.py        # FaultDefinition, FaultInvocation, FaultCategory
│   │   ├── experiments.py   # Experiment models, ExecutionPlan, PlannedStep
│   │   ├── checks.py        # probes, expectations, violations
│   │   ├── events.py        # EventKind, Event
│   │   ├── risks.py         # RiskLevel, EnvironmentClass
│   │   ├── capabilities.py  # Identifier, Capability
│   │   ├── common.py        # Duration, parse_duration
│   │   ├── errors.py        # DomainError hierarchy
│   │   ├── catalog.py       # fault catalog (all_definitions, definition_for)
│   │   └── leases.py        # UndoOp, VerifyProbe
│   ├── topology/
│   │   ├── service.py       # TopologyService.discover()
│   │   └── providers/
│   │       ├── base.py      # TopologyProvider ABC
│   │       ├── compose.py   # ComposeFileProvider
│   │       └── docker_runtime.py  # ContainerRuntimeProvider
│   ├── toolkit/
│   │   ├── registry.py      # CapabilityRegistry, manifest loading
│   │   ├── tool_runner.py   # run_tool() subprocess wrapper
│   │   ├── hashing.py       # canonical JSON, SHA-256
│   │   ├── fingerprint.py   # config/topology fingerprinting
│   │   └── manifests/       # built-in YAML manifests (docker, podman, stress-ng, tc-netem, toxiproxy)
│   ├── controller/
│   │   ├── planner.py       # plan_deterministic, plan_random
│   │   ├── executor.py      # RunEngine
│   │   ├── janitor.py       # dirty-state sweep + repair
│   │   ├── compensation.py  # undo op generation
│   │   └── safety.py        # SafetyEngine, validate_plan, pre_exec_assertion
│   ├── agents/
│   │   ├── executors.py     # executor_for() dispatch
│   │   ├── server.py        # JSON-RPC server
│   │   ├── protocol.py      # JSON-RPC 2.0 message types
│   │   ├── lease_client.py  # LeaseClient
│   │   ├── probes.py        # run_probe, verify_all
│   │   ├── transports.py    # transport layer (Unix socket / TCP)
│   │   ├── sinks.py         # event sinks
│   │   └── watchdog.py      # agent watchdog
│   ├── agent/
│   │   └── cli.py           # agent CLI entry point
│   └── infra/
│       ├── store.py         # SQLite store
│       ├── lease_repository.py  # SQLiteLeaseSink
│       ├── migrations.py    # schema migrations
│       └── migrator.py      # migration runner
└── tests/
    └── unit/                # ~290 tests
```
