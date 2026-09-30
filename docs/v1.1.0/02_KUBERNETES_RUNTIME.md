# Plan 02 — Kubernetes-Native Runtime

**Priority:** P0. Gap item 2.

## Objective
Make Kubernetes a first-class Mayhem execution environment rather than only a planning target.

## Builds on (existing code — extend, do not rebuild)
- `agents/k8s_resolve.py` `KubernetesRuntimeResolver` (locate workload → eligible Running pods → deterministic pick with drift recorded → named container → `ResolvedPodTarget` evidence) becomes the live-selection path; manifest placeholders stay ineligible by construction.
- `agents/executors.py` k8s dispatch registers (`k8s_executor_for`, `_K8S_EXECUTORS`) and undo contracts stay the injection path.
- `controller/k8s_runtime.py` `k8s_available_faults()` stays the executability boundary; `k8s.image_pull_slow` stays catalog-only.
- `topology/providers/kubernetes.py` (live discovery) and `k8s_manifest.py` (offline blueprint) stay the two graph sources.
- `domain/k8s_adapter.py` `KubernetesAdapter.is_available() == False` stays false; nothing here rehabilitates it as evidence.

## Scope
- Live cluster discovery (API-driven, RBAC-scoped)
- Pod / container / init-container / node targeting
- Workload-aware targeting (Deployment, StatefulSet, DaemonSet, Job)
- Namespace, label, and annotation selection; percentage and random selection; zone/region selection
- CRDs for Drill/Experiment/Run plus a controller
- Node agent integration via the 03 fabric (DaemonSet form of `mayhem-agent`)
- Kubernetes events and status reporting
- Helm deployment and a `kubectl mayhem` plugin

## Target model
```text
Cluster
  -> Namespace
     -> Workload
        -> Pod
           -> Container
```

Target selectors must support: name, namespace, labels, annotations,
workload kind, node, percentage/random selection, topology zone/region.
Resolution output is frozen into the `ExecutionPlan` as resolved-target
evidence; anything resolved after freeze is drift, not a target.

## Phase 1 — Domain model: selectors and workload safety facts
Add `domain/k8s_targets.py`: `K8sSelector` (all dimensions above), `WorkloadFacts` (replicas, PDB `minAvailable`, readiness/liveness, workload kind semantics), `K8sAdmissionVerdict`. Pure types; the PDB rule ("kill 4 of 10 with minAvailable 8 → DENY with the arithmetic shown") is a pure function over these types. Acceptance: property tests over selector combinations; the PDB denial test shows expected availability vs. required.

## Phase 2 — Engine: live resolution and workload-aware admission
Wire the resolver to a real cluster client through the existing 5-step flow; extend `controller/safety.py` with a K8s admission check (PDB, StatefulSet semantics, DaemonSet awareness, anti-affinity, topology spread, cluster health, active incidents, recent deployments) that refuses before mutation. Acceptance: unsafe workload plans refused with the reason naming the violated rule and the observed numbers.

## Phase 3 — Surface: CRDs, controller, Helm, plugin
Ship CRDs (Drill/Experiment/Run), a controller that compiles CRs through `plan_drill` (never a parallel planner), a Helm chart, RBAC roles, and the kubectl plugin as a thin client over the 08 API. Acceptance: CR-created runs produce the same frozen plan objects as CLI-created runs.

## Phase 4 — Safety and evidence integration
Node-agent execution goes through the 03 fabric (leases, fencing, signed commands); agent loss triggers the fencing/recovery policy; controller restart cannot orphan active experiments (reconciliation on startup via the lease sink). Kubernetes events emitted per run phase; namespace protection and RBAC integration enforced at admission. Acceptance: controller-kill mid-fault recovers with evidence proving it.

## Phase 5 — Tests, regression guards, negative controls
Fake-client unit suites (existing pattern) plus live cells via the 01 pipeline; PDB-denial regression tests; a negative control asserting manifest-blueprint pods can never become live selections. Acceptance: first live-cluster cells certified in 01 before any "first-class" claim ships.

## Phase 6 — Docs, honesty gates, rollout
Update the Kubernetes status vocabulary in docs/README.md (a new "live execution" row only when cells certify), the examples/k8s README, and the competitive matrix. No checked-in document may claim a particular external cluster passed validation. Rollout: discovery and read-only paths first, single-pod faults, then workload-aware faults.

## Dependencies
01 (live cells), 03 (fabric/agents), 07 (policy dimensions), 08 (API backing the plugin), 09 (RBAC/approvals).

## STATUS — planning only, 0%
