# v1.1.0 — production control plane program

Status: **implemented and closing out.** The "planning only" line this file used
to carry was stale; the per-file `## STATUS` blocks below are authoritative and
describe landed code. See "Implementation status" at the end.
Research date **2026-09-30**. Branch `v1.1.0`.

## The one-line thesis

> **Stop being a CLI that injects faults; become the control, safety,
> verification, and evidence layer that decides whether an experiment is
> allowed, what it means, when it must stop, whether recovery happened,
> and whether the result can be proven later.**

v1.0.0 made the verdict mean something (steady state with tolerance, the
preflight that is the real gate, damage quota, integrity-checked packs).
v1.1.0 makes Mayhem deployable in production: runtime certification,
Kubernetes as a first-class lane, a distributed control plane, identity,
approvals, emergency stop, cryptographic evidence, and the workflows
(CI/CD, GitOps, ChatOps, Game Days) that turn a tool into a platform.

## What this program is not

- Not 200 more fault ids. One new mechanism is worth ten new ids; a new
  parameter axis beats a new id (see the new-faults OUTCOME record).
- Not a kernel project by itself. eBPF/JVM/deep-IO breadth comes via the
  provider architecture, with Chaos Mesh and similar injectors as backends
  under Mayhem's safety compiler — not by reimplementing them.
- Not a second verdict model. Every feature plan below extends the
  existing graded verdict, lease state machine, compensation contract,
  and evidence envelope; none of them replaces those.

## File index (actual files)

Feature plans carry six phases each: 1 domain model, 2 engine, 3 surface,
4 safety and evidence integration, 5 tests with negative controls, 6 docs
and rollout. Meta documents (00, 24, 25, 26, 27, 28) are program
scaffolding, not feature lanes.

| File | Kind | Gap items | Priority |
| ---- | ---- | --------- | -------- |
| 00_MASTER_ROADMAP.md | program overview | all | — |
| 01_RUNTIME_CERTIFICATION.md | feature | 1, 107, 108, 109 | P0 |
| 02_KUBERNETES_RUNTIME.md | feature | 2 | P0 |
| 03_EXECUTION_FABRIC.md | feature | 3, 16, 28 | P0 |
| 04_EBPF_KERNEL_IO_JVM.md | feature | 4 | P1 |
| 05_APP_AND_DEPENDENCY_FAULTS.md | feature | 5 | P1 |
| 06_CLOUD_PROVIDERS.md | feature | 6, 69 | P1 |
| 07_POLICY_SAFETY_ENGINE.md | feature | 7, 66, 67, 86 | P0 |
| 08_CONTROL_PLANE_API_UI.md | feature | 10, 31, 32, 59, 60, 61 | P0 |
| 09_IDENTITY_RBAC_APPROVALS.md | feature | 8, 11 | P0 |
| 10_EMERGENCY_STOP_PREFLIGHT.md | feature | 9, 63, 64 | P0 |
| 11_OBSERVABILITY_PROBES_STOP_CONDITIONS.md | feature | 14, 15 | P0 |
| 12_CRYPTOGRAPHIC_EVIDENCE.md | feature | 12, 57, 98, 99, 100, 101 | P0 |
| 13_SCHEDULING_CAMPAIGNS_GAMEDAYS.md | feature | 41, 48, 84, 85 | P1 |
| 14_TOPOLOGY_BLAST_RADIUS.md | feature | 19, 26, 54, 62, 72 | P1 |
| 15_RESILIENCE_ANALYTICS_ADAPTIVE.md | feature | 25, 52, 53, 90, 91, 92, 93, 94, 95, 96 | P1/P2 |
| 16_CI_GITOPS_INTEGRATIONS.md | feature | 42, 43, 44, 45, 46, 47 | P1 |
| 17_EXTENSION_SDK_PROVIDER_PROTOCOL.md | feature | 34, 35, 37, 74, 75 | P1 |
| 18_MARKETPLACE_CATALOG.md | feature | 33, 73, 76 | P2 |
| 19_HA_DR_SECURITY.md | feature | 30, 38, 40 | P0/P1 |
| 20_ENTERPRISE_PRODUCT_HARDENING.md | feature | 39, 55, 56, 58, 70, 71, 77, 78, 110 | P1/P2 |
| 21_RELIABILITY_ADVISOR.md | feature | 21, 22, 23, 24, 49 | P2/P3 |
| 22_RESILIENCE_COVERAGE_REGRESSION.md | feature | 20, 50, 51, 102, 103, 104, 105, 106 | P1 |
| 23_PERFORMANCE_SCALE.md | feature | 68, 82, 83 | P1 |
| 24_RELEASE_GATES.md | release gates | all | P0 |
| 25_REFERENCE_ARCHITECTURE.md | architecture | all | — |
| 26_COMPETITIVE_GAPS_MATRIX.md | tracking matrix | all | — |
| 27_IMPLEMENTATION_BACKLOG.md | sequencing spine | all | — |
| 28_EXECUTION_CHECKLIST.md | run checklist | all | — |
| 29_SECRETS_MANAGEMENT.md | feature | 13 | P0 |
| 30_SAFETY_PROOF.md | feature | 27, 65 | P0 |

## The absolute P0 list

Before Mayhem is positioned as a production-market competitor:

| Capability | Owning file |
| ---------- | ----------- |
| Live verification of existing faults | 01_RUNTIME_CERTIFICATION.md |
| Kubernetes live execution | 02_KUBERNETES_RUNTIME.md |
| Kubernetes agent | 02_KUBERNETES_RUNTIME.md, 03_EXECUTION_FABRIC.md |
| Durable control-plane storage (SQLite plus replication) | 08_CONTROL_PLANE_API_UI.md |
| REST API | 08_CONTROL_PLANE_API_UI.md |
| Web UI | 08_CONTROL_PLANE_API_UI.md |
| Authentication, RBAC, teams | 09_IDENTITY_RBAC_APPROVALS.md |
| Organizations / environments | 09_IDENTITY_RBAC_APPROVALS.md, 20_ENTERPRISE_PRODUCT_HARDENING.md |
| Approval workflow | 09_IDENTITY_RBAC_APPROVALS.md |
| Emergency stop | 10_EMERGENCY_STOP_PREFLIGHT.md |
| Preflight / postflight checks | 10_EMERGENCY_STOP_PREFLIGHT.md |
| Continuous stop conditions | 11_OBSERVABILITY_PROBES_STOP_CONDITIONS.md |
| Real cryptographic evidence signing | 12_CRYPTOGRAPHIC_EVIDENCE.md |
| Evidence / object-store backend | 12_CRYPTOGRAPHIC_EVIDENCE.md |
| Agent mTLS and command authenticity | 19_HA_DR_SECURITY.md |
| Distributed leases / fencing | 03_EXECUTION_FABRIC.md |
| Crash-safe recovery | 03_EXECUTION_FABRIC.md, 30_SAFETY_PROOF.md |
| Kubernetes PDB / workload-aware safety | 02_KUBERNETES_RUNTIME.md |
| Full target selection engine | 02_KUBERNETES_RUNTIME.md |
| Fault certification matrix | 01_RUNTIME_CERTIFICATION.md |
| Observability integrations | 11_OBSERVABILITY_PROBES_STOP_CONDITIONS.md |
| GitHub / GitLab CI integration | 16_CI_GITOPS_INTEGRATIONS.md |
| Helm deployment | 20_ENTERPRISE_PRODUCT_HARDENING.md |
| Experiment versioning | 16_CI_GITOPS_INTEGRATIONS.md, 22_RESILIENCE_COVERAGE_REGRESSION.md |
| Audit log | 12_CRYPTOGRAPHIC_EVIDENCE.md |
| Secrets management | 29_SECRETS_MANAGEMENT.md |
| Production compatibility matrix | 01_RUNTIME_CERTIFICATION.md |
| Safety proof | 30_SAFETY_PROOF.md |

## Sequencing spine

The authoritative lane order is the M1–M8 milestones in
27_IMPLEMENTATION_BACKLOG.md (trust the runtime, safe distributed
execution, production control plane, Kubernetes parity, evidence and
observability, fault depth, cloud plus ecosystem, differentiation moat).
Wave grouping (trust, platform, reach, intelligence) is descriptive only.

## Conventions every feature plan follows

1. Domain first: new vocabulary lands in `domain/` as pure types with
   zero IO, honoring the import-linter layering contract
   (`controller` ← `agents` ← `toolkit|infra` ← `domain`).
2. The safety compiler stays load-bearing: admission, blast radius,
   damage quota, compensation, leases, and execution intent extend to
   every new lane; a lane that bypasses them is refused, not shipped.
3. Evidence before prose: every behavior ships with the test that
   proves it, including a negative control where a check could be
   decoration.
4. Honesty is a gate: no plan may claim live verification, cluster
   acceptance, or authorship authentication it does not implement.
   Pack signatures are NOT verified in this build; any document that
   discusses pack signing must say so in the same breath.
5. Each feature plan closes with docs updates and a rollout note, never
   with "code complete".

## Implementation status

**This README's own "planning only" header is stale and says so.** Implementation
lanes opened some time after this package was written; the per-file `## STATUS`
blocks are the only authoritative record, and they now describe implemented
code. Read those, not this file's summary.

Where the program stands (from the 24 per-file STATUS blocks, not from the prose
above):

* Most feature plans report **6 of 6 phases DONE**.
* **Three phases are PARTIAL**, all three because they name a *live* acceptance
  that has not run rather than because code is missing:
  * `02_KUBERNETES_RUNTIME.md` Phase 4 — no DaemonSet agent transport, no live
    controller-kill recovery. (Its verifier gap is closed.)
  * `02_KUBERNETES_RUNTIME.md` Phase 5 — the fake half landed; the first
    live-cluster cells are plan 01's.
  * `20_ENTERPRISE_PRODUCT_HARDENING.md` Phase 4 — the walkthrough harness is
    proven with fakes; live IdP, a human approver, a container runtime, and a
    live Helm install remain open by construction.
* Cross-cutting zeros that stay zeros until cells run: `certified_faults = 0`
  (every fault is capped at `verified-unit`), `verified-live = 0` for eBPF
  primitives (04) and remote probes (11), no live cloud (06), nothing ever
  executed against a Terraform forge (16), and no soak run (23).
