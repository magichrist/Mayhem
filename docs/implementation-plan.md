# Mayhem Evolution: Production-Grade Implementation Plan

Generated: 2025-07-20

## Current State Assessment

### Existing Strengths (preserve)
- Layered Python architecture (domain / application / infrastructure)
- Domain model: topology graph, faults, experiments, checks, leases, compensation
- Compose-first discovery with Docker/Podman runtime providers
- Capability registry with YAML manifests
- JSON-RPC agents over stdio (ADR-0003)
- Write-ahead lease lifecycle + journal + janitor
- Safety gates G1-G3 (config policy, plan validation, pre-execution)
- SQLite WAL persistence
- Deterministic + weighted-stochastic planners
- CLI with prefix resolution
- 186 unit tests

### Gap Analysis

| Capability | Current State | Gap |
|---|---|---|
| Execution Context | Implicit (host/container/process in target selectors) | No explicit context model, no validation |
| Resource Ownership | Lease-only (per-run, not per-resource) | No per-resource tracking, no conflict detection |
| Recovery | UndoOps + Janitor | No per-resource verification, no ownership-aware cleanup |
| Agent Architecture | Basic JSON-RPC + handshake + tool manifest | No auth, no heartbeat, no protocol versioning, no cancellation |
| Fault Arsenal | 3 catalog faults (proc.pause, proc.kill, proc.cpu) | Needs ~60+ capability-oriented faults |
| Network Path Model | Basic net.latency with tc backend | No source/dest/port/direction model |
| Container Hardening | Docker + Podman providers exist | No exec-inside-container, no resource limits, no filesystem faults |
| Load Generation | StartLoad/StopLoad steps in spec | No actual LoadGenerator interface or adapters |
| Fuzzing | None | Separate subsystem needed |
| Observation | Basic http_check + exec_check probes | No generic Observer/Evaluator/Notifier |
| Hypothesis Evaluation | String hypothesis only | No machine-evaluable hypothesis |
| Knowledge/Coverage | None | No ExperimentOutcome, CoverageModel |
| Campaigns | None | Higher-level grouping concept needed |
| Scheduling | None | One-shot only, no recurring/continuous |
| Production Safety | G1-G3 + blast radius | No environment/target identity, no emergency abort, no destructive classification |
| Database Schema | events, run_steps, leases | Missing: campaigns, resources, observations, evaluations, coverage |
| CLI | ~12 commands | Needs campaign, coverage, agent, topology, target |
| Testing | 186 unit tests | No integration tests, no recovery chaos tests, no property-based tests |

## Implementation Phases

### Phase 1: Execution Context + Resource Ownership (foundation)
**Why first:** Everything else depends on knowing WHERE a fault runs and WHAT it modifies.

Files to create/modify:
- `src/mayhem/domain/execution_context.py` — ExecutionContext enum + ExecutionTarget model
- `src/mayhem/domain/resources.py` — TrackedResource, ResourceLease, ResourceOwnershipGraph
- `src/mayhem/domain/experiments.py` — Add execution context to InjectFault, validation
- `src/mayhem/controller/safety.py` — Context validation gate (G4)
- `src/mayhem/controller/executor.py` — Resource tracking during execution
- Tests: `test_execution_context.py`, `test_resources.py`
- ADR-0014: Execution Context Model
- ADR-0015: Resource Ownership

### Phase 2: Strengthened Recovery
**Why second:** Resource ownership enables ownership-aware recovery.

Files to create/modify:
- `src/mayhem/domain/recovery.py` — RecoveryPlan, RecoveryStep, RecoveryVerification
- `src/mayhem/controller/recovery.py` — Ownership-aware recovery engine
- `src/mayhem/controller/janitor.py` — Enhanced orphan detection with resource graph
- Tests: `test_recovery.py`, `test_janitor_orphans.py`
- ADR-0016: Durable Recovery Model

### Phase 3: Agent Hardening + Security
**Why third:** Secure agents before expanding capabilities.

Files to create/modify:
- `src/mayhem/agents/identity.py` — AgentIdentity, AgentCapability
- `src/mayhem/agents/auth.py` — HMAC-based authentication
- `src/mayhem/agents/heartbeat.py` — Heartbeat, health, watchdog
- `src/mayhem/agents/protocol.py` — Protocol version negotiation, auth handshake
- `src/mayhem/agents/cancellation.py` — Cancellation tokens, deadlines
- Tests: `test_agent_auth.py`, `test_agent_heartbeat.py`
- ADR-0017: Agent Security Model

### Phase 4: Expanded Fault Arsenal + Capability Taxonomy
Files to create/modify:
- `src/mayhem/toolkit/catalogs/process.yaml` — Process faults
- `src/mayhem/toolkit/catalogs/cpu.yaml` — CPU pressure faults
- `src/mayhem/toolkit/catalogs/memory.yaml` — Memory pressure faults
- `src/mayhem/toolkit/catalogs/storage.yaml` — Storage/disk faults
- `src/mayhem/toolkit/catalogs/network.yaml` — Network faults
- `src/mayhem/toolkit/catalogs/container.yaml` — Container faults
- `src/mayhem/toolkit/catalogs/node.yaml` — Node/host faults
- `src/mayhem/toolkit/catalogs/dependency.yaml` — Database/dependency faults
- `src/mayhem/domain/capabilities.py` — Extended Capability enum
- Tests: `test_fault_catalog_expanded.py`

### Phase 5: Network Path Model + Container Hardening
Files to create/modify:
- `src/mayhem/domain/network.py` — NetworkPath, NetworkDirection, NetworkEndpoint
- `src/mayhem/topology/network.py` — Network topology enrichment
- Container exec-inside-container support
- Tests: `test_network_path.py`

### Phase 6: Observation Engine + Evaluation + Knowledge
Files to create/modify:
- `src/mayhem/observation/__init__.py` — Observation engine package
- `src/mayhem/observation/probe.py` — Generic probe interface
- `src/mayhem/observation/evaluator.py` — Hypothesis evaluation
- `src/mayhem/observation/notifier.py` — Notification adapters
- `src/mayhem/knowledge/__init__.py` — Knowledge store
- `src/mayhem/knowledge/coverage.py` — Coverage model
- `src/mayhem/knowledge/outcomes.py` — Experiment outcomes
- Tests: `test_evaluation.py`, `test_coverage.py`

### Phase 7: Load Generation + Fuzzing + Maniac 2.0
Files to create/modify:
- `src/mayhem/loadgen/__init__.py` — LoadGenerator interface
- `src/mayhem/loadgen/k6.py` — K6 adapter
- `src/mayhem/fuzzing/__init__.py` — Fuzzing subsystem
- `src/mayhem/controller/maniac.py` — Upgraded Maniac planner
- Tests: `test_loadgen.py`, `test_maniac.py`

### Phase 8: Campaigns + Scheduling + Safety Expansion
Files to create/modify:
- `src/mayhem/domain/campaigns.py` — Campaign model
- `src/mayhem/scheduler/__init__.py` — Scheduler
- Safety expansion: destructive classification, emergency abort
- Tests: `test_campaigns.py`, `test_scheduler.py`

### Phase 9: Persistence + CLI Expansion
- Schema migrations for new tables
- New CLI commands
- Tests

### Phase 10: Testing + CI/CD + Documentation
- Integration test framework
- Property-based tests
- CI/CD pipeline
- Documentation updates

## Execution Strategy
- Implement one phase at a time
- Run full test suite after each phase
- Update ADRs with each phase
- Maintain backward compatibility for existing experiments
- Each phase produces working, tested, documented code
