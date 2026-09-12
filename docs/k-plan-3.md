# k-plan-3 — Execution-time resolution and live container-level faults

> **Phase 3 of 5**. Predecessors: k-plan-1 (TargetRef, `--runtime`, schema),
> k-plan-2 (topology provider, `mode: one`). Exit: the first Kubernetes drill
> *executes* — container-level faults (proc.pause, process.kill, fd.exhaust,
> …) applied inside a pod's container via `kubectl exec`, with full resolved
> evidence and reconciliation-safe re-resolution.

---

## Goal

Close the loop that k-plan-1/2 opened: compile-time logical targets +
discovered topology now become **live execution**. The impact gate resolves
workload → eligible Pod → container at injection time, the executor speaks
`kubectl exec`, and every run records the *resolved* target (pod, uid,
container id, node) as evidence. Pod-level faults (pod_kill, pod_evict) stay
out — they land in k-plan-4.

---

## Locked decisions (k-plan-1 interview)

- **[interview] Fault scope** — first executable plan is **container-level via
  `kubectl exec`** (proc.*, fd.*, cpu.* families applied inside a pod
  container). Pod-lifecycle faults are k-plan-4.
- **[interview] Driver strategy** — discovery through the kubernetes SDK
  (k-plan-2); mutation through `kubectl exec`, mirroring the existing
  docker-exec-via-agent model.
- **[interview] Evidence model** — the frozen plan pins the **logical** target;
  execution writes the **resolved** target; `RuntimeIdentity` equality
  unchanged.
- **[interview] Compensation** — for reversible container faults the existing
  undo/verify pairs apply; irreversible pod faults get their reconciliation
  model in k-plan-4.

---

## 3.1 Execution-time resolution (the impact gate for k8s)

The two-stage contract from k-plan-1 §1.4 becomes real. A new
`KubernetesRuntimeResolver` (in `src/mayhem/agents/impact.py` alongside the
docker resolve path, or a sibling `k8s_resolve.py`) is invoked **before every
injection round**, same timing as the existing docker live-substitute resolve
(ADR-0020):

```text
1. locator:  Deployment/production/checkout      (TargetRef authority)
2. workload: AppsV1 read {kind, namespace, name} (404 → resolution_resource_missing)
3. eligible Pods: Running, no deletionTimestamp
4. selection: mode one (k-plan-2 selector) — re-run live, not replayed
5. container: named container must exist       (missing → resolution_container_missing)
6. loci: kubectl exec obtains
         - container_id (PodStatus.ContainerStatuses[].containerID)
         - env string (which python/sh exists inside the image)
         - netns/node facts recorded for evidence
7. inject via the k-plan-3 executor (3.3)
```

If a Pod selected at plan time is gone, re-resolution picks a replacement and
records it — never a stale-Pod fault. A **re-resolution difference** between
plan-time recording and the impact gate is surfaced as a run note (evidence
field `resolved_drift`), not an error, because the selection contract is
logical, not physical.

---

## 3.2 Capability matrix flip (`domain/runtime_adapter.py`, `domain/k8s_adapter.py`)

`KubernetesAdapter` becomes *available for container-level execution*:

```python
def is_available(self) -> bool:   # (k-plan-2 reachability probe) AND kubectl on PATH

def capabilities(self) -> AdapterCapabilities:
    # exec, pid, signal, inspect → SUPPORTED (via kubectl exec)
    # netns, resource_limits, compose_filter → UNSUPPORTED for now
    # (netns returns in k-plan-4 with pod-level net faults)
```

The container-execute family (proc.pause, process.kill, proc.mem, fd.exhaust,
cpu.throttle, mem.exhaust payload) passes `Capability.KUBERNETES_ENGINE`
gating for the first time. The safety gate `_check_k8s_targets`
(safety.py:203) flips from blanket refusal to **capability-supervised
admission** for this family: supported fault ids on a `POD`-resolved target
run; still-refused families (pod-lifecycle, node) keep their k-plan-specific
refusal message.

Planner `_MANIAC_EXCLUDED_CAPS` (planner.py:73) stays as-is until k-plan-5.

---

## 3.3 Executor (`src/mayhem/agents/executors.py`)

New `K8sExecExecutor` implementing the existing `FaultExecutor.inject(lease)`
contract (lease = `FaultLease`, domain/leases.py:64):

- Builds `kubectl exec` argv into the target namespace/pod/container:
  `kubectl exec -n production deploy/checkout -c app -- <cmd>` — the kubectl
  *resource shorthand* form keeps the executor agnostic to which Pod the
  selection landed on (the impact gate already pinned the exact Pod, so the
  executor may also use the plain `pod/name` selector; see task list).
- Reuses the existing payload sources (`_payload_source`/`_payload_marker`
  in controller/compensation.py:139-139) so proc-pause/burn scripts are the
  *same* scripts as docker, just delivered via `exec`.
- Locale/tooling shims (`ContainerRuntime`, impact.py) are consulted against
  the pod image (env string recorded during resolution) exactly as for docker;
  fatalities (no shell) are a `capability` refusal, not a crash.
- Locus: `ThreeLocusContext` with `target_locus =
  LocusSpec(Locus.KUBERNETES, f"{ns}/{pod}/{container}")` — `Locus.KUBERNETES`
  already exists (execution_loci.py:26); the planner's compatibility mapping
  (execution_context.py:47-53) is extended so `POD`-kind granularity integrates
  with the existing remote-agent plumbing.

Undo for reversible container faults follows the docker model: the same
signal/cleanup is delivered via a second `kubectl exec` (e.g. `kill -CONT`),
because the container itself is not replaced mid-fault.

---

## 3.4 Evidence recording

Per-round, beside the existing observation/decision records:

```json
{
  "planned_target": {
    "logical_id": "checkout",
    "runtime": "kubernetes",
    "authority": {"kind": "Deployment", "namespace": "production", "name": "checkout"},
    "container": "app"
  },
  "resolved_target": {
    "pod": "checkout-7b8d9f6c5d-x7z9k",
    "pod_uid": "…",
    "container_id": "containerd://…",
    "node": "worker-3",
    "exec_argv": ["kubectl", "exec", "-n", "production", "pod/checkout-7b…", "-c", "app", "--", "…"]
  },
  "resolved_drift": null
}
```

- `FaultLease` keeps `runtime_identity` (the docker-style key) and gains an
  optional `resolved_target` JSON column/migration populated by this resolver
  — a **stronger, richer** evidence key for the already-recorded
  results/coverage tables.
- Success criteria probe `checkout.status` (HTTP 200) is untouched — critera
  evaluate against the same observations, now sourced over the cluster.

---

## 3.5 Task breakdown (ordered)

1. Migration: `FaultLease.resolved_target` (nullable JSON) + evidence repo
   support (infra/lease_repository.py); backfilled from existing stamp columns.
2. `KubernetesRuntimeResolver` in agents/impact.py (or sibling module):
   SDK read + `mode: one` + container-id/env capture; error taxonomy
   (`resolution_resource_missing`, `resolution_container_missing`,
   `selection.no_eligible_pods`).
3. Adapter capability flip + per-family safety-gate reclassification
   (exec family admissible; others still refused).
4. `K8sExecExecutor`: exec argv builder, container-runtime shim reuse,
   undo via second exec, three-locus wiring (`Locus.KUBERNETES`).
5. Planner compatibility: `POD`-resolved targets reach the executor without
   the old blanket gate; `--allow-exec`-style surface unchanged.
6. `resolved_drift` note when impact gate re-picks a different Pod than
   plan-time.
7. Unit tests (fake client, no cluster): resolver selection, container-id
   parse, missing namespace/container errors, drift detection, executor argv
   build.
8. Live e2e (autoskip): proc.pause on a real Deploy → probe-verified outcome,
   evidence JSON contains resolved_target with pod+uid+container_id+node;
   undo round leaves a Running pod.
9. Docs: drill-spec.md gains the container-level k8s example + evidence format;
   features.md M8 status moved to "container-level execution landed
   (pod-level k-plan-4)"; README CLI table pointed at k-plan-3.

## 3.6 Acceptance criteria

- A k8s drill with `proc.pause` on `deploy/checkout` compiles, gates, executes,
  records resolved evidence and verifies recovery — against a real cluster
  (e2e) *and* against fake-client units (CI-fast).
- Executing the *same* drill with a `k8s.node_drain` fault is still refused
  with the k-plan-5 message (unsupported family).
- `mayhem run docker.yaml --ctr testcase-api` byte-identical to pre-k8s
  behaviour (no regression in the docker adapters).
- Empty/missing namespace → clear `resolution.resource_missing` plan/run
  error; zero eligible pods → `selection.no_eligible_pods`.
- `uv run pytest`, `ruff`, `mypy` green; e2e autoskip when no cluster.

## 3.7 Out of scope

- Pod-level faults / reconciliation compensation (k-plan-4).
- Multi-instance selection (k-plan-4).
- Node-level faults (k-plan-5).
- Maniac/explore/coverage re-enable (k-plan-5).