# Mayhem Market-Ready Roadmap

Status: **phases delivered.** Program overview for the v1.1.0 package.
Sequencing spine: the M1–M8 milestones in 27_IMPLEMENTATION_BACKLOG.md.
Per-file `## STATUS` blocks are authoritative; see the STATUS section at the
end for what is actually open.

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

## STATUS — phases 1–6 delivered; three phases PARTIAL on live acceptances

The program ran to completion on every lane that a unit test can prove. What is
open is the part a unit test cannot reach.

* **Phase 1 (trust the runtime)** — delivered. Certification schema, store,
  runner, `mayhem certify` surface, evidence sealing, residue scan, and the
  safety-proof compiler all landed. The cross-cutting zero remains:
  `certified_faults = 0`, because no live cell has certified a fault.
* **Phase 2 (safe distributed execution)** — delivered: the fabric, leases,
  fencing, crash reconciliation, emergency stop, mTLS refusals, and leader
  election.
* **Phase 3 (production control plane)** — delivered: replicated SQLite, the
  REST gateway with a generated OpenAPI document, the no-JS UI, local auth and
  RBAC, approvals, the audit stream, and secret references.
* **Phase 4 (Kubernetes parity)** — delivered through CRDs, the controller,
  workload-aware admission, and fabric dispatch. **Two phases PARTIAL**: no
  DaemonSet agent transport and no live-cluster cells, so no "live execution"
  claim ships.
* **Phase 5 (evidence and observability)** — delivered for local-key (HMAC)
  signing, the retention engine, and the audit stream. KMS/HSM, Sigstore/Cosign,
  and WORM storage remain unimplemented by rollout order.
* **Phase 6 (reach and moat)** — delivered: fault descriptors and their refusal
  vocabulary, the cloud adapter ports, the provider SDK, marketplace artifacts
  (including the experiment template type), CI/GitOps integrations, topology and
  resilience analytics, and coverage/regression.

**Open, precisely:** `02_KUBERNETES_RUNTIME.md` Phases 4 and 5,
`20_ENTERPRISE_PRODUCT_HARDENING.md` Phase 4 — every one of them waiting on a
cluster, an IdP, a human, or a container runtime, not on missing code.
Program scaffolding. Becomes authoritative as feature lanes open and
each file's STATUS block starts moving.
