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

## STATUS
- Phase 1 (domain model): DONE — `domain/k8s_targets.py` landed `K8sSelector` (name, namespace, labels, annotations, workload kind/name, node, zone/region, and `one`/`all`/`count`/`percentage`/`random` selection with an *injected* seed), `WorkloadFacts` (replicas, PDB `minAvailable`/`maxUnavailable`, readiness/liveness, workload-kind semantics, anti-affinity, topology spread, cluster health), `K8sAdmissionVerdict`, and the six pure refusal rules — the PDB rule shows its arithmetic ("replicas=10, PDB minAvailable=8, requested kill 4 → DENY, expected availability after fault = 6, PDB requires >= 8"); unresolved candidates land as drift, manifest blueprint placeholders are never live-eligible, and an empty selection is explicit; 74 tests.
- Phase 2: DONE — `controller/k8s_admission.py` collects `WorkloadFacts` for a planned Kubernetes target through an injected client and refuses the plan *inside* `validate_plan` (one optional `SafetyContext.k8s_admission` field, placed after the identity/environment checks and before the generic `k8s.unsupported` placeholder) — the six Phase-1 rules are now reachable from the real gate and their refusals name the violated rule and the observed numbers, the injected authorization predicate is consulted before any cluster read (namespace protection ships as its worked example; the RBAC half is plan 09's), and the facts Phase 1 carried but no rule read are consumed: `updated_replicas` refuses an in-flight rollout, `ready_replicas` refuses an already-unready workload when a readiness probe makes it a health signal, and an absent liveness/startup probe is recorded as a warning; 40 tests.
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 2 of 6 phases complete.

Known limitation: **the gate is wired but nothing drives it, and no live cluster has been accepted.** No production caller constructs a `K8sAdmissionInput` — neither `cli/services.py` nor the executor does — so in production today every run reaches the gate with `k8s_admission=None`, which is a single `is not None` test and leaves every existing decision, refusal, and message exactly where it was. Nothing implements `K8sAdmissionClient` against a real cluster either: the seam is a protocol, and every refusal tested here came from a fake client, so this phase has certified *the gate*, not any cluster. `SdkK8sClient` implements the resolver's `K8sClusterClient` (pods/exec), not the admission's fact read; wiring that is the live-cell work plan 01 owns.

Also unchanged, deliberately: manifest-blueprint pods remain ineligible for live selection. An offline `k8s_manifest.py` placeholder resolves to no `ResolvedPodTarget`, so admission refuses such a step as `k8s.no_live_target` naming the blueprint bucket; a manifest graph can still plan, never select. Node-scoped faults (`k8s.node_drain` / `k8s.node_pressure`) stay with `resolve_node` and `ResolvedNodeTarget` — workload admission does not model them, because a node fault's safety is not a replica count's.

Live resolution is still Phase 1 of the existing resolver: admission consumes the `ResolvedPodTarget` records that flow produced and never calls `workload()`/`pods_for()`. A resolved record carrying no pod uid is refused (`k8s.no_live_target`) rather than trusted, because without that uid admission cannot tell a deposed pod from a live one and deliberately does not re-read pods to find out.

One more deliberate limit: a fact of `0` is read as *not observed* rather than as evidence — a client that does not populate `updated_replicas` would otherwise refuse every plan, which is a check that is unusable rather than safe. A populated-but-incomplete rollout (`0 < updated_replicas < replicas`) and a populated health signal (`ready_replicas > 0`) are the shapes that do refuse.
