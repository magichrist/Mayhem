# ADR-M3-6: Kubernetes — interface only, no cluster execution
**Status:** Approved
**Date:** 2026-09-02
**Deciders:** Ali
**Relates to:** ADR-M3-1, ADR-M3-2, ADR-M3-5, ADR-0013
## Context
Kubernetes is a first-class execution target (fault categories: capacity, network,
preemption). But wiring a real cluster transport — client-go lifecycle, RBAC,
pod readiness gates, eviction, node taints — is a large effort with tight coupling
to cluster state. Doing it speculatively alongside the container engines would
balloon this milestone and add unexercised attack surface. Node-kind extensions
(`NodeKind.POD` / `K8S_NODE`) belong to a closed union bounded by ADR-0013, so they
must not be half-added now.
## Decision
Define the **Kubernetes `RuntimeAdapter`-compatible seam as interface only**:
- `KubernetesAdapter` satisfies the full `RuntimeAdapter` contract but returns
  `UNSUPPORTED` for every capability and is never `available()` (no transport).
- Node-kind extensions and fault categories are deferred to M7; only the capability
  contract is declared here so the planner can **refuse K8s plans** with a clear
  `UNSUPPORTED` message instead of failing mid-run.
- `capabilities()` is empty — every capability resolves `UNSUPPORTED` — and
  `is_available()` is always `False`, so no cluster execution path is reachable
  until M7 replaces the stub with a real transport.
## Consequences
- Kubernetes plans are refused deterministically at plan time until M7.
- The `RuntimeAdapter` contract is satisfied end-to-end for k8s, so wiring a real
  transport later is additive, not a rework.
- No cluster SDK dependency, RBAC, or credential handling ships prematurely.