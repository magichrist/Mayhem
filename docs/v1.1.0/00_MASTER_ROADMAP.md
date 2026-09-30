# Mayhem Market-Ready Roadmap

Status: **planning only.** Program overview for the v1.1.0 planning
package. Sequencing spine: the M1–M8 milestones in
27_IMPLEMENTATION_BACKLOG.md.

## Goal
Turn Mayhem from a safety-first local chaos runner into a production-grade resilience platform that can compete with and integrate with Chaos Mesh, LitmusChaos, Steadybit, Gremlin, AWS FIS, Chaos Toolkit, and specialist injectors.

## Strategic position
Mayhem should not try to win only by having the largest fault catalog. The core differentiator should remain:

- safety compilation and admission
- explicit execution intent
- bounded blast radius and cumulative damage
- structural compensation contracts
- tolerance-bearing verdicts
- runtime certification
- cryptographically verifiable evidence
- topology-aware and adaptive experiments

Execution breadth should be expanded through a modular provider/agent architecture so Mayhem can use native engines and external injectors without making the control plane dependent on any one injector implementation.

## Priority model
- P0: required for production-market credibility
- P1: major competitive parity or differentiation
- P2: advanced platform capabilities
- P3: ecosystem/long-term moat

## Program phases

### Phase 1 — Trust the runtime (M1)
Land 01_RUNTIME_CERTIFICATION.md (CertificationRecord overlay on the
existing maturity harness) and the 30_SAFETY_PROOF.md compiler output.
Nothing downstream may claim a capability until this phase defines how
capabilities are proven. Exit: 24_RELEASE_GATES.md fault-gate section
passes on the certification pipeline itself.

### Phase 2 — Safe distributed execution (M2)
Land 03_EXECUTION_FABRIC.md (protocol, fencing, idempotent retries),
19_HA_DR_SECURITY.md (mTLS, command authenticity), and
10_EMERGENCY_STOP_PREFLIGHT.md. Exit: killing the controller mid-fault
recovers without duplicate execution or orphaned state.

### Phase 3 — Production control plane (M3)
Land 08_CONTROL_PLANE_API_UI.md (SQLite plus replication, REST API,
UI MVP), 09_IDENTITY_RBAC_APPROVALS.md, 29_SECRETS_MANAGEMENT.md, and
12_CRYPTOGRAPHIC_EVIDENCE.md through the extended bundle surface.
Exit: the 20_ENTERPRISE_PRODUCT_HARDENING.md acceptance walkthrough
runs without engineering intervention.

### Phase 4 — Kubernetes parity (M4)
Land 02_KUBERNETES_RUNTIME.md on top of the existing resolver and
executor seams. Exit: PDB-aware refusal demonstrated live; target
resolution frozen into the plan with resolved-target evidence.

### Phase 5 — Evidence and observability (M5)
Land 11_OBSERVABILITY_PROBES_STOP_CONDITIONS.md and complete the
12_CRYPTOGRAPHIC_EVIDENCE.md signing and object-store work. Exit:
evidence verifies offline without contacting the control plane.

### Phase 6 — Reach and moat (M6–M8)
Fault depth (04, 05, 06), ecosystem (17, 18), workflows (13, 16),
analytics and adaptive search (14, 15, 21, 22), scale (23), guided by
26_COMPETITIVE_GAPS_MATRIX.md and executed per
27_IMPLEMENTATION_BACKLOG.md. Exit: 24_RELEASE_GATES.md fully green
for a production-class release.

## Definition of market readiness
Mayhem is not market-ready merely because it has a large fault catalog. A production release should be able to:

- prove what environment and targets were selected
- prove the exact plan that was approved
- reject unsafe plans before mutation
- execute through crash-safe distributed agents
- stop automatically on declared conditions
- recover and verify recovery
- produce independently verifiable evidence
- explain the verdict from raw observations
- expose compatibility/certification status per fault/runtime/version
- survive controller/agent failure
- support enterprise identity, RBAC, approvals, secrets, audit, backups, and upgrades

## STATUS — planning only, 0%
Program scaffolding. Becomes authoritative as feature lanes open and
each file's STATUS block starts moving.
