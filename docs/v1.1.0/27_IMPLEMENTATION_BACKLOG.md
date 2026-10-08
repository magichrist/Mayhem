# Plan 27 — Suggested Engineering Backlog

Status: **lanes landed.** Meta document and the authoritative
sequencing spine for the program (per README decision): lanes open in
milestone order, and a milestone exits only on its 24 gates.

## Milestone M1 — Trust the runtime
- certification schema (01 phase 1)
- live test runner (01 phase 2)
- Docker certification (01 cells)
- Podman certification (01 cells)
- first Kubernetes agent (02 discovery path, 03 enrollment)
- fault compatibility matrix (01 phase 3)
- residue scanner (01 phase 4)
- safety-proof output (30 phases 1–2)

## Milestone M2 — Safe distributed execution
- agent protocol (03 phase 1)
- mTLS (19 phase 2)
- leases/fencing (03 phase 2)
- crash recovery (03 phase 2, 10 phase 2)
- emergency stop (10 phases 1–5)
- distributed locks (07 phase 1, 03 phase 2)

## Milestone M3 — Production control plane
- replicated SQLite store (08 phase 2)
- REST API (08 phase 3)
- auth (09 phases 1–2)
- RBAC (09 phases 1–2)
- environments (09 org model, 20 deployment)
- approvals (09 phases 2–4)
- audit log (12 phase 4)
- secrets management (29 phases 1–4)
- Web UI MVP (08 phase 3)

## Milestone M4 — Kubernetes parity
- CRDs (02 phase 3)
- controller (02 phase 3)
- target selectors (02 phase 1)
- PDB awareness (02 phases 1–2)
- workload-aware safety (02 phase 2)
- Kubernetes events (02 phase 4)
- Helm (02 phase 3)

## Milestone M5 — Evidence and observability
- cryptographic signing (12 phase 2)
- object storage (12 phase 2)
- OpenTelemetry (11 phase 3)
- Prometheus (11 phase 3)
- stop conditions (11 phases 1–2)
- richer probes (11 phase 3)

## Milestone M6 — Fault depth
- eBPF (04 family lanes)
- IO (04 family lanes)
- block (04 family lanes)
- JVM (04 family lanes)
- advanced time (04 clock lane)
- application/dependency faults (05, post collision audit)

## Milestone M7 — Cloud + ecosystem
- AWS (06 adapter lane)
- GCP (06 adapter lane)
- Azure (06 adapter lane)
- provider SDK (17)
- marketplace (18)
- Terraform (16 phase 3)
- GitHub/GitLab integrations (16 phase 3)

## Milestone M8 — Differentiation moat
- topology impact model (14)
- adaptive experiments (15 search runner)
- resilience boundary discovery (15 boundary reports)
- counterexample minimization (15 minimization)
- regression detection (22 comparison service)
- incident replay (21 replay compiler)
- reliability advisor (21 findings)

## Lane rules
Lanes open top-down by milestone; a lane may start early only if its
dependencies' exit gates are already green. Cross-milestone
dependencies (e.g. M6 fault lanes needing M1 certification cells) are
satisfied by the earliest milestone that provides them, not redefined.

## STATUS — milestones M1–M8 landed; three phases PARTIAL on live acceptances

The M1–M8 lane order below is still the authoritative sequencing spine, and the
lanes are built. Per-file `## STATUS` blocks are the record. The honest summary:

* Most milestones are complete across all their lanes.
* **M1–M8 are gated on certification cells that have not run.** Nothing here
  certifies a fault live (`certified_faults = 0`; every fault is capped at
  `verified-unit`), so the cross-cutting zeros remain: no verified-live eBPF (04)
  or remote probe (11), no live cloud (06), no forge-driven Terraform (16), no
  soak (23).
* **Three phases are PARTIAL**, each because it names a live acceptance rather
  than because code is missing: `02_KUBERNETES_RUNTIME.md` Phases 4 and 5 (no
  DaemonSet transport, no live-cluster cells) and
  `20_ENTERPRISE_PRODUCT_HARDENING.md` Phase 4 (live IdP, human approver,
  container runtime, Helm install).
* This file's "planning only, 0%" header was stale and has been corrected.
