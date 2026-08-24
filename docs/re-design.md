# Task: Deep Architectural Audit of the Existing Mayhem Repository

Act as the **Principal Architect / Distributed Systems / Chaos Engineering / Python Reliability Engineer**. Audit the **existing Mayhem repository**, not a greenfield design.

Your job is to determine whether the current architecture can evolve into the intended Mayhem platform **without a major rewrite**, identify structural weaknesses, and give precise corrections mapped to the existing code.

## Repository

```text
docs/
  adr/0001...0013
  architecture/
  reference/
examples/
src/mayhem/
  agents/
  controller/
  domain/
  infra/
  toolkit/
  topology/
  cli.py
  config.py
  spec.py
tests/
  chaos_of_the_chaos/
  integration/
  unit/
```

Read the actual source, tests, ADRs, architecture docs, configuration, and examples. **Do not infer behavior from filenames.**

ADRs are evidence, not authority. Compare:

```text
ADR ↔ documentation ↔ implementation ↔ tests
```

Classify each ADR as implemented, partial, different, obsolete, missing, or unverifiable.

---

# 1. Target Architecture

Mayhem is intended to become:

```text
Controller
   │
Configuration
   │
Planner / Maniac Engine
   │
~12 Agents
   │
Toolkit Arsenal
   │
native + external tools
   │
Target system
   │
Observation
   │
Evaluation
   │
Recovery
   │
SQLite history
```

Mandatory targets:

* local Linux processes
* bare-metal Linux
* Docker
* Podman
* Docker Compose
* host/process/container faults
* container-internal execution
* container network/IP targeting
* CPU/memory/disk/I/O faults
* network faults
* load generation
* fuzzing
* controlled overload/attack simulation
* multi-fault experiments
* randomized experiments
* reliable recovery
* detailed logging

Future:

* Kubernetes
* cloud/remote infrastructure
* REST API
* Web UI
* adaptive/learning-based planning

Existing architectural decisions such as JSON-RPC + stdio/SSH, capability registry, lease/journal/janitor recovery, Compose-first topology, SQLite WAL, layered configuration, weighted stochastic Maniac, tiered network backends, toolkit-based extensibility, and environment/risk gates should be preserved where they are sound.

Do not redesign the project merely because another architecture is fashionable.

---

# 2. Audit These Areas

Inspect and evaluate:

### Domain

```text
domain/
  capabilities.py
  catalog.py
  checks.py
  events.py
  experiments.py
  faults.py
  leases.py
  risks.py
  topology.py
```

Determine whether the semantic model can represent the lifecycle and relationships of:

```text
Experiment
Execution
Target
Service
Node
Container
Process
Fault
Capability
Tool
ToolRun
Observation
Hypothesis
Recovery
Risk
BlastRadius
Topology
Result
```

Look for missing entities, overloaded concepts, weak invariants, duplicated state, and incorrect ownership.

### Controller / Experiment Engine

Audit:

```text
controller/
  compensation.py
  executor.py
  janitor.py
  planner.py
  safety.py
```

Verify the lifecycle:

```text
prepare → validate → inject → observe → evaluate → recover → verify → cleanup
```

Check cancellation, concurrency, partial failure, persistence, idempotency, and controller restart.

### Agents

Audit:

```text
agents/
  executors.py
  lease_client.py
  probes.py
  sinks.py
```

Determine whether the architecture can scale to ~12 specialized agents.

Audit:

* registration/identity
* capabilities
* heartbeat
* task execution
* cancellation
* timeout
* retry
* reconnect
* result reporting
* agent failure
* controller failure
* concurrency

Trace a real controller → JSON-RPC → agent → toolkit → result flow.

### Toolkit

Audit:

```text
toolkit/
  fingerprint.py
  hashing.py
  tool_runner.py
```

against the intended abstraction:

```text
Agent → Fault Capability → Toolkit → Tool Adapter → executable
```

It must eventually support tools such as:

```text
tc, ip, kill, stress-ng, dd, fallocate,
Docker, Podman, SSH, k6, Locust,
Toxiproxy, Schemathesis, etc.
```

Check tool discovery, capability resolution, versions, privileges, timeout, cancellation, output capture, errors, cleanup, and alternative implementations.

### Maniac Engine

Audit `planner.py`, `catalog.py`, `experiments.py`, ADR 0009 and the Maniac documentation.

It should separate:

```text
candidate generation
→ capability filtering
→ safety/risk filtering
→ topology relevance
→ weighted stochastic selection
→ execution
```

Check deterministic seeds, reproducibility, history, fault combinations, intensity, duration, exclusions, and auditability.

### Topology

Audit Compose parsing and runtime discovery.

It must eventually understand:

```text
host
node
service
container
process
network
IP
port
dependency
volume/filesystem
```

and especially container ↔ host ↔ network relationships.

### Docker / Podman

Determine whether both can support:

* host → container
* exec inside container
* process kill/pause
* container networking/IP targeting
* resource faults
* host-level faults affecting containers

Do not allow Docker-specific abstractions to make Podman impossible.

### Network / Resource Faults

Audit whether the architecture can support:

```text
latency
jitter
packet loss
corruption
bandwidth
partition
reset/refusal
DNS failure/delay
port blocking
route manipulation
CPU
memory
disk
filesystem
I/O
process exhaustion
```

and whether backend selection is capability-driven.

### Load / Fuzzing / Attack Simulation

Determine whether Mayhem can orchestrate:

```text
k6
Locust
Schemathesis
Toxiproxy
custom tools
```

without confusing chaos faults, load generation, fuzzing, and security testing into one vague abstraction.

### Observation

Audit whether every experiment can record:

```text
what ran
where
when
why
tool
parameters
stdout/stderr
observations
failure
recovery
final result
```

while leaving clean seams for Prometheus, OpenTelemetry, logs, traces, Slack, etc.

### Recovery

Audit leases/journal/janitor and test:

```text
controller crash
agent crash
SSH disconnect
tool timeout
partial recovery
duplicate recovery
stale lease
orphaned process
orphaned network rules
```

Recovery must be idempotent, durable, observable, and safe after restart.

### Safety

Audit environment identity, allowlists, blast radius, duration, rate limits, privileges, dangerous tools, confirmation, dry-run, abort conditions, and automatic cleanup.

Ensure CLI, future REST/UI, agents, and Maniac cannot bypass the same safety model.

### Persistence / Configuration / CLI

Audit:

```text
infra/
config.py
spec.py
cli.py
```

Check SQLite WAL/concurrency/migrations, configuration layering/versioning/validation, and whether the CLI can scale to nested commands, unique-prefix resolution, ambiguity handling, and future REST/UI parity without embedding business logic.

### Testing

Evaluate whether tests actually protect architecture, especially:

* agent failure
* toolkit failure
* recovery failure
* deterministic Maniac
* capability resolution
* Docker/Podman
* network cleanup
* concurrent faults
* controller restart
* "chaos of the chaos" scenarios

---

# 3. Stress the Architecture Conceptually

Walk the existing implementation through these scenarios:

1. Process CPU/memory fault.
2. Docker FastAPI container fault.
3. Podman equivalent.
4. FastAPI → PostgreSQL latency + packet loss.
5. Host resource exhaustion.
6. Controller dies during injection.
7. Agent dies before recovery.
8. Toolkit command hangs.
9. Three concurrent faults.
10. Maniac chooses a multi-fault experiment.
11. Future Kubernetes provider.
12. Future REST/Web UI.

For each, identify where the current design succeeds, fails, or requires changes.

---

# 4. Find Hidden Architectural Debt

Look for:

* circular dependencies
* god classes/modules
* stringly-typed state
* implicit state machines
* global mutable state
* CLI/business-logic coupling
* tool-specific assumptions
* Docker-only assumptions
* SSH/stdio leakage into domain logic
* SQLite-specific domain coupling
* non-idempotent recovery
* missing cancellation/deadlines
* race conditions
* unbounded subprocess output
* unsafe privilege boundaries
* orphaned system state

---

# 5. Required Output

Produce:

## A. Executive verdict

Choose:

```text
YES
YES, WITH TARGETED CORRECTIONS
NO, MAJOR REWORK REQUIRED
```

and justify it using actual code evidence.

## B. Actual architecture

Show the real dependency graph.

## C. Intended vs actual

```text
Subsystem | Intended | Actual | Gap | Severity
```

## D. ADR audit

Review ADR 0001–0013 individually.

## E. Findings

Classify:

```text
CRITICAL / HIGH / MEDIUM / LOW / INFO
```

For important findings include:

```text
problem
evidence
impact
recommended correction
affected files
```

## F. Fitness scores

Score 0–10:

```text
Domain
Controller
Agents
Communication
Toolkit
Capabilities
Fault model
Experiment engine
Maniac
Topology
Docker
Podman
Network
Resources
Recovery
Safety
Observation
Persistence
Configuration
CLI
Testing
Kubernetes readiness
```

## G. Required changes

Separate:

```text
Must fix now
Before MVP
Before v1
Future
```

Map each change to exact existing files or explicitly justified new files.

## H. ADR changes

Identify ADRs requiring amendment and genuinely missing ADRs.

## I. Implementation order

Give the safest sequence for corrections.

## J. Preserve

Explicitly list architectural decisions that are already strong and should **not** be changed.

---

# Final Question

The central question is:

> **Is this repository's foundation strong enough to safely grow from its current implementation into the broad Mayhem chaos orchestration platform, without accumulating architectural debt that will eventually force a rewrite?**

Judge the architecture by its ability to support the future **fault arsenal**, not by how many faults have been implemented today.

Be evidence-driven, skeptical, and specific. Do not produce generic chaos-engineering advice. Audit the actual Mayhem repository.
