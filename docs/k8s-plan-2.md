# k8s-plan-2 — Autoscaling, disruption budgets, and cluster DNS

> **Phase 7b of 7b**. Predecessor: `docs/k8s-plan-1.md` (node health, crash
> loops, scheduling, controller convergence).
> Exit: the next ten Kubernetes failure classes execute through the same
> reversible-lease pipeline — image-pull latency, termination delay,
> preemption failure, HPA scale delay/failure, PDB violation, eviction
> blocking, and CoreDNS failure/delay/mismatch.

---

## Goal

Finish the remaining gap classes: **autoscaling reaction**, **disruption
budgeting**, **image/termination lifecycle**, and **cluster Service DNS**. Like
`k8s-plan-1`, every fault maps to an existing primitive seam (`K8sSnapshotExecutor`
patch/rollout + `K8sWorkloadExecutor` template snapshots) plus **one new seam
for DNS** (CoreDNS Corefile edit + rollout restart). No new revocation model.

---

## Locked decisions

- **DNS is a first-class family.** `k8s.dns_failure`, `k8s.dns_delay`, and
  `k8s.service_dns_mismatch` all deliver through the cluster DNS add-on
  (CoreDNS Corefile ConfigMap + `kubectl rollout restart`), gated on a new
  `DNS_CONTROL` capability. They stay distinct from the lower-level generic
  `net.*` families: these exercise *Kubernetes service discovery*, not raw
  packet shaping.
- **Duration-shaped faults are lease-shaped.** `k8s.hpa_scale_delay`,
  `k8s.dns_delay`, `k8s.pod_image_pull_delay`, and
  `k8s.container_termination_delay` inject a value that *outlives* their own
  drill; the lease clock is the source of truth, and undo restores the
  pre-inject value.
- **Autoscaler faults never fight the HPA.** `hpa_scale_delay` slows a scaling
  decision (stabilization window); `hpa_scale_failure` pins one direction
  (`maxReplicas` for `up`, `minReplicas` for `down`). Both snapshot and restore
  the HPA `spec`.
- **Disruption faults are accounting faults.** `pdb_violation` and
  `eviction_block` mutate the PDB, not the workload, so the "availability
  assumption" itself is what is tested.
- **Everything here is reversible.** No entry joins `K8S_DELETE_FAULTS`.

---

## New taxonomy (controller + catalog)

Add to `src/mayhem/controller/k8s_runtime.py`:

```python
K8S_HPA_FAULTS = {"k8s.hpa_scale_delay", "k8s.hpa_scale_failure"}
K8S_DISRUPTION_FAULTS = {"k8s.pdb_violation", "k8s.eviction_block"}
K8S_DNS_FAULTS = {
    "k8s.dns_failure",
    "k8s.dns_delay",
    "k8s.service_dns_mismatch",
}
K8S_LIFECYCLE_FAULTS = {
    "k8s.pod_image_pull_delay",
    "k8s.container_termination_delay",
}
K8S_PREEMPT_FAULTS = {"k8s.preemption_failure"}
```

Fold into the unions:

```python
K8S_CONTROLLER_FAULTS = (
    K8S_CONTROLLER_FAULTS
    | K8S_HPA_FAULTS
    | K8S_DISRUPTION_FAULTS
    | K8S_DNS_FAULTS
    | K8S_LIFECYCLE_FAULTS
    | K8S_PREEMPT_FAULTS
)
K8S_MUTATION_FAULTS = K8S_MUTATION_FAULTS | K8S_CONTROLLER_FAULTS
K8S_REVERSIBLE_FAULTS = K8S_REVERSIBLE_FAULTS | K8S_CONTROLLER_FAULTS
```

New capabilities:

- `DNS_CONTROL` — edit the CoreDNS add-on and restart its Deployment.
- `NODE_CONTROL` — reused by `k8s.pod_image_pull_delay` (node egress shaping).

---

## Delivery

### 11. `k8s.pod_image_pull_delay` — medium · lane `node`

**Primitive.** Node-pinned worker that `nsenter`s the host network namespace and
adds egress `netem delay` on traffic toward the registry hosts, so a newly
created container's image pull is slow but eventually succeeds. This is the
executable answer to the catalog-only `k8s.image_pull_slow` (which has no
kubectl primitive): the *node* shapes the pull, not the Pod spec.

```sh
nsenter -t 1 -n tc qdisc add dev <egress_if> root handle 1: netem delay 3000ms
```

**Params.**

```yaml
params:
  seconds: 30s      # duration string, default 30s, 1s..5m (pull latency to add)
```

**Undo.** `tc qdisc del` via host ns, delete the worker.

**Gating.** `NODE_CONTROL`; reversible. (`k8s.image_pull_slow` stays
catalog-only; this family is the executable sibling.)

---

### 12. `k8s.container_termination_delay` — medium · lane `in-pod-signal`

**Primitive.** Patch the owning workload's pod template to add a `preStop`
hook that sleeps beyond the application's expected shutdown window, and raise
`terminationGracePeriodSeconds` to cover it:

```yaml
lifecycle:
  preStop:
    exec: { command: ["/bin/sh","-c","sleep <seconds>"] }
terminationGracePeriodSeconds: <seconds + slack>
```

Rollouts and evictions now drain slowly, exercising connection draining and
rolling-update timing. Distinct from a crash: the container *stops correctly*,
just late. `K8sWorkloadExecutor` template snapshot.

**Params.**

```yaml
params:
  seconds: 20s      # duration string, default 20s, 1s..5m
```

**Undo.** Restore the template snapshot (removes the hook and restores the
grace period); clear annotation.

**Gating.** `KUBERNETES_ENGINE`; reversible.

---

### 13. `k8s.preemption_failure` — high · lane `scheduler`

**Primitive.** Prevent the scheduler from preempting lower-priority victims for
a pending high-priority workload: patch the would-be victim's
`priorityClassName` to the preemptor's class (removing the priority gap) or add
a `PreferNoSchedule` taint/affinity that removes the preemption trigger.
The high-priority pod stays Pending instead of evicting its way in.

**Params.**

```yaml
params: {}
```

**Undo.** Restore the victim template snapshot; clear annotation.
`K8sWorkloadExecutor`.

**Gating.** `KUBERNETES_ENGINE`; reversible.

---

### 14. `k8s.hpa_scale_delay` — medium · lane `autoscaler`

**Primitive.** New `K8sHpaExecutor(K8sSnapshotExecutor)` over
`HorizontalPodAutoscaler`. Snapshot `spec`, then set an oversized
`spec.behavior.scaleUp.stabilizationWindowSeconds` (default 300) so the HPA
reacts slower than the load demands.

**Params.**

```yaml
params:
  seconds: 60s      # duration string, default 60s, 1s..1h (window to set)
```

**Undo.** Restore the HPA `spec` snapshot; clear annotation. `ref_kinds` =
`("HorizontalPodAutoscaler",)`.

**Gating.** `KUBERNETES_ENGINE`; reversible.

---

### 15. `k8s.hpa_scale_failure` — high · lane `autoscaler`

**Primitive.** Same executor; pin one direction so the HPA cannot move:

| `direction` | mutation |
| --- | --- |
| `up` | `spec.maxReplicas = status.currentReplicas` |
| `down` | `spec.minReplicas = status.currentReplicas` |

**Params.**

```yaml
params:
  direction: up     # enum up|down, default up
```

**Undo.** Restore the HPA `spec` snapshot; clear annotation.

**Gating.** `KUBERNETES_ENGINE`; reversible.

---

### 16. `k8s.pdb_violation` — high · lane `disruption-budget`

**Primitive.** New `K8sPdbExecutor(K8sSnapshotExecutor)` over
`PodDisruptionBudget`. Snapshot `spec`, then set
`spec.maxUnavailable: <unavailable>` (or lower `minAvailable`) to a value the
workload's current ready count cannot satisfy, so the budget is *violated* —
voluntary disruptions are either blocked or the workload runs outside its own
stated availability assumption.

**Params.**

```yaml
params:
  unavailable: 2    # integer, required (pods allowed unavailable)
```

**Undo.** Restore the PDB `spec` snapshot; clear annotation. `ref_kinds` =
`("PodDisruptionBudget",)`.

**Gating.** `KUBERNETES_ENGINE`; reversible.

---

### 17. `k8s.eviction_block` — medium · lane `pod-delete`

**Primitive.** Same executor, opposite intent: set
`spec.maxUnavailable: 0` (or `minAvailable: 100%`) so the eviction API refuses
every voluntary eviction. Node drains that depend on eviction stall, exposing
workloads whose availability (or maintenance) depends on successful eviction.

**Params.**

```yaml
params: {}
```

**Undo.** Restore the PDB `spec` snapshot; clear annotation.

**Gating.** `KUBERNETES_ENGINE`; reversible.

---

### 18. `k8s.dns_failure` — high · lane `dns`

**Primitive.** New `K8sDnsExecutor(K8sSnapshotExecutor)` over the CoreDNS
add-on. Snapshot the Corefile (`coredns` ConfigMap), insert a `template` (or
`hosts`) block that returns the requested failure mode for `domain`, then
`kubectl rollout restart deployment/coredns -n kube-system` and wait for a
ready CoreDNS replica.

| `mode` | response |
| --- | --- |
| `servfail` | `SERVFAIL` |
| `nxdomain` | `NXDOMAIN` |
| `refused` | `REFUSED` |

**Params.**

```yaml
params:
  domain: api.default.svc.cluster.local   # string, required
  mode: servfail                           # enum servfail|nxdomain|refused, default servfail
```

**Undo.** Restore the ConfigMap snapshot and rollout-restart CoreDNS; wait for
readiness. `ref_kinds` = `("ConfigMap",)` scoped to `kube-system/coredns`.

**Gating.** `DNS_CONTROL`; reversible.

---

### 19. `k8s.dns_delay` — medium · lane `dns`

**Primitive.** Same executor: insert a CoreDNS `template` with a `sleep`-style
delay or `forward` to a deliberately slow upstream for `domain`, then restart
CoreDNS. Applications doing per-request service discovery see resolution
latency without hard failure.

**Params.**

```yaml
params:
  delay_ms: 500     # integer, default 500, 1..30000
```

**Undo.** Restore the ConfigMap snapshot + rollout restart; wait for readiness.

**Gating.** `DNS_CONTROL`; reversible.

---

### 20. `k8s.service_dns_mismatch` — high · lane `dns`

**Primitive.** Same executor, stronger than an outage: insert a CoreDNS
`hosts`/`template` override so `domain` resolves **successfully** to `address`
(a wrong ClusterIP/endpoint). DNS stays healthy on the wire while clients are
sent to the wrong destination — testing misdirected traffic rather than
missing traffic.

**Params.**

```yaml
params:
  domain: payments.default.svc.cluster.local   # string, required
  address: 10.0.0.99                            # string (IPv4/IPv6), required
```

**Undo.** Restore the ConfigMap snapshot + rollout restart; wait for readiness.

**Gating.** `DNS_CONTROL`; reversible.

---

## Register & catalog deltas

`_K8S_EXECUTORS` additions:

```python
"k8s.pod_image_pull_delay": K8sNodeImagePullExecutor,   # new (node worker)
"k8s.container_termination_delay": K8sWorkloadExecutor,
"k8s.preemption_failure": K8sWorkloadExecutor,
"k8s.hpa_scale_delay": K8sHpaExecutor,                  # new (snapshot)
"k8s.hpa_scale_failure": K8sHpaExecutor,
"k8s.pdb_violation": K8sPdbExecutor,                    # new (snapshot)
"k8s.eviction_block": K8sPdbExecutor,
"k8s.dns_failure": K8sDnsExecutor,                      # new (CoreDNS snapshot)
"k8s.dns_delay": K8sDnsExecutor,
"k8s.service_dns_mismatch": K8sDnsExecutor,
```

`k8s_available_faults()` gains all ten; controller/reversible unions gain the
whole family. `k8s.image_pull_slow` remains catalog-only and continues to
refuse at can-apply time.

---

## Test plan

Extend the fake-kubectl harness with state for `HorizontalPodAutoscaler`,
`PodDisruptionBudget`, and the `kube-system/coredns` ConfigMap.

- **HPA** — assert `up` pins `maxReplicas` to current, `down` pins
  `minReplicas`; snapshot round-trip is byte-identical after undo.
- **PDB** — `pdb_violation` lowers availability; `eviction_block` forbids
  disruption; both restore the exact `spec`.
- **DNS** — assert each `mode`/`delay_ms`/`address` appears in the mutated
  Corefile, the rollout restart is issued, and undo restores the original
  Corefile and restarts again. `can_apply` refuses with `k8s.unsupported` when
  `DNS_CONTROL` is absent.
- **Lifecycle** — `termination_delay` adds the `preStop` hook + grace period and
  restores both; `image_pull_delay` pins the node worker and clears the qdisc.
- **Preemption** — assert the priority gap is removed and restored.
- **Ordering** — the full file passes standalone and in-suite (fake patches
  deep-copy stored objects; snapshots never alias mutated specs).

## Acceptance criteria

- Ten new faults planned, gated, executed, and undone; `mayhem plan` compiles an
  example naming each without schema error.
- DNS families refuse cleanly without `DNS_CONTROL`; no family joins
  `K8S_DELETE_FAULTS`.
- All new undo paths restore byte-identical snapshots; CoreDNS restarts are
  awaited for readiness, not fire-and-forget.
- `uv run pytest`, `ruff`, and `mypy` green; catalog + README/`features` list the
  ten ids; `-k` fault-kind assertion includes them.

## Deliberately out of scope

Multi-cluster / cross-context DNS, service-mesh (Istio/Linkerd) specific
failure injection, and any fault requiring a mutating admission webhook.
