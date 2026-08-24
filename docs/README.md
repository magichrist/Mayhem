# Mayhem Documentation

**Mayhem** is a general-purpose chaos engineering and resilience-testing framework:
a *chaos experiment orchestration engine* — not a collection of chaos commands.

```
DISCOVER → UNDERSTAND SYSTEM → SELECT TARGET → SELECT FAULT → SELECT TOOL
        → EXECUTE → OBSERVE → EVALUATE → RECOVER → LEARN → NEXT EXPERIMENT
```

- **Controller**: plans experiments, coordinates agents, enforces safety policy.
- **Agents** (~12 roles): execute fault capabilities on their host — local or over SSH.
- **Toolkit Arsenal**: capability-oriented registry wrapping native tools (`tc`, `stress-ng`,
  `iptables`, `docker`, `podman`, …) and external tools (`k6`, `toxiproxy`, `schemathesis`).
- **Maniac Engine**: controlled-random experiment generation with auditable selection.
- **Recovery**: leases + write-ahead undo journal + janitor reconciliation. A fault is never
  silently left behind.
- **Observation**: human-readable journal + SQLite history; Prometheus/OTel/Slack later via sinks.

## Status

Pre-implementation planning baseline. These documents are the contract the first implementation
must satisfy. Code exists nowhere yet; Phase 0 of [roadmap.md](roadmap.md) starts from here.

## Reading order

| # | Document | What you get |
|---|----------|--------------|
| 1 | [architecture/system-overview.md](architecture/system-overview.md) | Subsystems, boundaries, deployment topologies |
| 2 | [architecture/domain-model.md](architecture/domain-model.md) | Entities, relationships, invariants |
| 3 | [adr/](adr/) (13 records) | Why each pivotal decision was made |
| 4 | [architecture/agent-architecture.md](architecture/agent-architecture.md) | Agent runtime, roles, protocol |
| 5 | [architecture/toolkit.md](architecture/toolkit.md) | Toolkit arsenal design |
| 6 | [architecture/experiment-engine.md](architecture/experiment-engine.md) | Lifecycle state machine |
| 7 | [reference/experiment-dsl.md](reference/experiment-dsl.md) | Experiment YAML reference |
| 8 | [reference/configuration-schema.md](reference/configuration-schema.md) | `mayhem.yaml` reference |
| 9 | [architecture/maniac-engine.md](architecture/maniac-engine.md) | Random experiment planner |
| 10 | [architecture/fault-taxonomy.md](architecture/fault-taxonomy.md) | Fault arsenal + coverage matrix |
| 11 | [architecture/topology-discovery.md](architecture/topology-discovery.md) | Compose/Docker/Podman discovery |
| 12 | [architecture/recovery.md](architecture/recovery.md) | Leases, janitor, verification |
| 13 | [architecture/safety.md](architecture/safety.md) | Risk gates, blast radius, abort |
| 14 | [architecture/observation.md](architecture/observation.md) | Journal, events, future sinks |
| 15 | [reference/sqlite-schema.md](reference/sqlite-schema.md) | Persistence schema |
| 16 | [reference/cli.md](reference/cli.md) · [reference/repository-layout.md](reference/repository-layout.md) | CLI + repo layout |
| 17 | [architecture/testing-strategy.md](architecture/testing-strategy.md) | Test tiers incl. chaos-of-the-chaos |
| 18 | [roadmap.md](roadmap.md) | Phases, MVP definition, future tracks |

## Document map

```
docs/
├── README.md                 ← you are here
├── adr/                      # immutable decision records (Nygard format)
├── architecture/             # living design documents (one per subsystem)
├── reference/                # schemas, DSL, schema DDL, CLI, repo layout
└── fault-catalog/            # generated coverage matrix (populated from Phase 8)
```

## Glossary

| Term | Meaning |
|------|---------|
| Controller | Central orchestrator process; single writer to storage; owns all connections |
| Agent | Per-host worker process (`mayhem-agent`) executing tasks; never listens on ports |
| Role | A set of fault capabilities bundled into one agent specialization (e.g. `network`) |
| Toolkit / Arsenal | Capability registry + tool adapters agents invoke instead of raw binaries |
| Fault | Declarative definition (`net.latency`) + lifecycle implementation (prepare/inject/recover) |
| Lease | Ownership record guaranteeing every injected fault has an owner until released |
| Janitor | Reconciliation sweep that cleans orphaned faults after crashes |
| Maniac Engine | Controlled-random experiment generator with recorded, replayable selections |
| devstack | Sample nginx→fastapi→postgres→redis Compose app used as the canonical test fixture |

## Change process

- **ADRs are immutable once Accepted.** New decisions supersede old ones by number.
- **Architecture docs are living** but must stay consistent with accepted ADRs; contradictions
  are bugs — fix the doc or write a superseding ADR.
- The **fault catalog** is generated from `FaultDefinition` metadata by tests; hand edits are lost.
