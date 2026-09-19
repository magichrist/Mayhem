# k8s-plan-1 — Node health, crash loops, scheduling, controller convergence

> **Phase 7a of 7b**. Predecessors: k-plan-1…6 (M7/M8 k8s driver).
> Companion: `docs/k8s-plan-2.md` (autoscaler, disruption budget, DNS).
> Exit: the ten highest-value remaining Kubernetes failure classes execute
> through the existing reversible-lease pipeline — node disappearance,
> CrashLoopBackOff, Pending/FailedScheduling, node network partition,
> Deployment/StatefulSet replica drift, namespace quota admission failure,
> PV mount/claim startup failure, and kube-proxy Service-proxy loss.

---

## Goal

Close the most consequential gaps left by the previous k8s catalog. Every fault
on this phase is a **real operating failure mode** that Kubernetes itself
documents (`NotReady` nodes, `FailedScheduling`, resource quotas, image policy,
kube-proxy Service/EndpointSlice programming) and every fault is delivered
through a primitive that already exists in the driver stack — `kubectl patch`,
`kubectl exec`, `kubectl scale`, `kubectl rollout restart`, node-scoped
privileged workers, and workload-template snapshots — so no new execution
subsystem is required.

The governing principle is unchanged from k-plan-6:

> A k8s fault mutates a live object (or a live process) and records enough
> evidence at inject time to restore it (or reap it) at lease release. The
> **resolved target** is the evidence key; the **snapshot annotation** is the
> undo contract.

---

## Locked decisions

- **Families reuse, not rebuild.** All workload/service/config/storage faults
  ride `K8sSnapshotExecutor` + `K8sWorkloadExecutor` (annotate → patch →
  restore-from-snapshot). No new revocation model.
- **Node faults get one new capability, `NODE_CONTROL`.** `k8s.node_not_ready`,
  `k8s.node_network_partition`, and `k8s.kube_proxy_failure` mutate the host
  from a node-pinned privileged worker (`nsenter` into the host PID/net
  namespace). The register refuses with the stable `k8s.unsupported` reason when
  the capability is absent — identical to how `K8S_NETNS_FAULTS` gate on `NETNS`.
- **Critical ≈ refuse-by-default.** `k8s.node_network_partition` and
  `k8s.kube_proxy_failure` are `RiskLevel.CRITICAL` and are refused
  pre-execution under the default risk ceiling without `--allow-critical`,
  exactly like the existing critical node families.
- **Node faults resolve to `ResolvedNodeTarget`.** They join `K8S_NODE_FAULTS`
  and ride the node pipeline; everything else resolves to `ResolvedPodTarget`.
- **Every family here is reversible.** There is no new irreversible entry.
  `k8s.pod_crash_loop` reaps its supervisor; node workers are deleted and the
  node is waited back to `Ready`; quota/PVC/template patches restore the
  snapshot. `K8S_DELETE_FAULTS` is untouched.
- **`params_schema` is authoritative.** Each fault ships a typed `ParamSpec`
  list; the planner rejects unsatisfiable parameter combinations before any
  cluster I/O.

---

## New taxonomy (controller + catalog)

Add to `src/mayhem/controller/k8s_runtime.py`:

```python
K8S_NODE_HEALTH_FAULTS = {"k8s.node_not_ready", "k8s.kube_proxy_failure"}
K8S_NODE_NET_FAULTS = {"k8s.node_network_partition"}
K8S_CRASH_FAULTS = {"k8s.pod_crash_loop"}
K8S_PENDING_FAULTS = {"k8s.pod_pending", "k8s.preemption_failure"}  # 7b adds preemption
K8S_CONTROLLER_SCALE_FAULTS = {
    "k8s.deployment_scale_failure",
    "k8s.statefulset_scale_failure",
}
K8S_QUOTA_FAULTS = {"k8s.resource_quota_exhaust"}
K8S_PVC_FAULTS = {"k8s.persistent_volume_claim_pending"}
K8S_MOUNT_FAULTS = {"k8s.persistent_volume_mount_failure"}
```

and fold them into the existing unions:

```python
K8S_NODE_FAULTS = K8S_NODE_FAULTS | K8S_NODE_HEALTH_FAULTS | K8S_NODE_NET_FAULTS
K8S_CONTROLLER_FAULTS = (
    K8S_CONTROLLER_FAULTS
    | K8S_CRASH_FAULTS
    | K8S_PENDING_FAULTS
    | K8S_CONTROLLER_SCALE_FAULTS
    | K8S_QUOTA_FAULTS
    | K8S_PVC_FAULTS
    | K8S_MOUNT_FAULTS
)
K8S_MUTATION_FAULTS = K8S_MUTATION_FAULTS | K8S_CONTROLLER_FAULTS
K8S_REVERSIBLE_FAULTS = K8S_REVERSIBLE_FAULTS | K8S_CONTROLLER_FAULTS
```

One new catalog family (`FaultCategory.K8S`, all `required_caps` include
`Capability.KUBERNETES_ENGINE`):

- `NODE_CONTROL` — host-PID/net-namespace privileges for node-scoped workers.
- `DNS_CONTROL` — reserved here, spent in `k8s-plan-2` §17–20.

---

## Delivery

### 1. `k8s.node_not_ready` — high · lane `node`

**Primitive.** Node-pinned privileged worker (`nodeName:` pinned, `hostPID:
true`, `hostNetwork: true`) that `nsenter`s the host PID namespace and masks
the kubelet (`systemctl mask --now kubelet`). The kubelet heartbeat stops and
the `Ready` condition flips to `Unknown`/`False`, which the control plane
reports as `NotReady`. Wait for the condition transition before returning.

**Params.**

```yaml
params:
  duration: 30s          # lease already owns the wall-clock; param is the worker's self-heal deadline
```

**Undo.** Delete the worker workload, then `systemctl unmask --now kubelet` via
the host ns and wait until the node reports `Ready` again (bounded by the
`NODE_CONTROL` capability's readiness timeout). If the node never recovers,
surface `k8s.node_unrecoverable` so the janitor escalates.

**Gating.** `NODE_CONTROL`; node family; reversible.

**Groups.** `ResolvedNodeTarget`; `K8S_NODE_FAULTS`.

---

### 2. `k8s.pod_crash_loop` — high · lane `in-pod-signal`

**Primitive.** A **detached supervisor worker** launched with the argv seam
(`setsid` so it survives the container restart it triggers) that repeatedly
terminates the resolved container's application process:

```sh
setsid sh -c 'for i in $(seq 1 N); do kill -KILL <app_pid>; sleep <interval>; done' \
  >/tmp/mh-crashloop.log 2>&1 & echo $! >/tmp/mh-crashloop.pid
```

Repeated termination drives the kubelet into `CrashLoopBackOff` with growing
restart backoff. The supervisor's pidfile is the undo token. Distinct from
`k8s.pod_kill` (one-shot) and `k8s.pod_liveness_fail` (probe-driven).

**Params.**

```yaml
params:
  restarts: 5       # integer, default 5, 1..50
  interval: 5s      # duration string, default 5s, 1s..5m
```

**Undo.** Reap the supervisor by pidfile (`kill`), then clear the pidfile.
Best-effort: if a container restart already reaped the supervisor, undo is an
idempotent no-op. Uses the same `K8sPodPressureExecutor` worker-reap path.

**Constraint (documented).** The primitive kills the *app process*; on a
single-container pod a restart also kills the supervisor, so the observable
effect is a bounded crash storm rather than an unbounded loop. That is the
intended drill (repeated application failure + backoff convergence).

**Gating.** `KUBERNETES_ENGINE`; reversible (worker reap).

---

### 3. `k8s.pod_pending` — high · lane `scheduler`

**Primitive.** Patch the owning workload's `podTemplate.spec` with an
unsatisfiable scheduling constraint selected by `reason`, so replacement Pods
are created but never bound (the scheduler publishes `FailedScheduling`):

| `reason` | injected constraint |
| --- | --- |
| `insufficient_cpu` | `resources.requests.cpu` unrealistically high |
| `insufficient_memory` | `resources.requests.memory` unrealistically high |
| `no_matching_node` | `nodeSelector` that matches no node |
| `taint` | tolerated? no — add `nodeAffinity` required term for an absent label |
| `affinity` | required pod anti-affinity that cannot be met |
| `resource_quota` | (see §7) oversized request exceeding quota |

Reuses `K8sWorkloadExecutor` (annotate snapshot → patch template).

**Params.**

```yaml
params:
  reason: insufficient_cpu    # enum, required
```

**Undo.** Restore the template snapshot; wait for the pending pod to schedule
(bounded) and clear the annotation.

**Gating.** `KUBERNETES_ENGINE`; reversible.

---

### 4. `k8s.node_network_partition` — critical · lane `node-network`

**Primitive.** Node-pinned privileged worker that `nsenter`s the host network
namespace and installs a `DROP` chain on cluster-directed traffic while leaving
the node powered on:

```sh
nsenter -t 1 -n iptables -I MH-PARTITION 1 -d <apiserver_cidr> -j DROP
nsenter -t 1 -n iptables -I MH-PARTITION 1 -p udp --dport 8472 -j DROP   # overlay
# direction: both | ingress | egress selects which side of the chain is added
```

Control-plane traffic drops, the node's heartbeats fail, EndpointSlices
converge toward removal, and workloads begin moving. Undo flushes the chain.

**Params.**

```yaml
params:
  direction: both    # enum both|ingress|egress, default both
```

**Undo.** `iptables -F MH-PARTITION && iptables -X MH-PARTITION` via host ns,
delete the worker, wait for `Ready` + endpoint reconvergence.

**Gating.** `NODE_CONTROL`; **CRITICAL** (refused without `--allow-critical`);
node family; reversible.

---

### 5. `k8s.deployment_scale_failure` — high · lane `workload`

**Primitive.** Patch the Deployment to declare `spec.replicas: <replicas>`
while simultaneously pinning a blocking scheduling constraint on a *subset* of
the desired pods (via `topologySpreadConstraints` with `whenUnsatisfiable:
DoNotSchedule` and a maxSkew that cannot be met). `availableReplicas` settles
below `replicas`, exercising desired-vs-available drift monitoring without
taking the workload fully down.

**Params.**

```yaml
params:
  replicas: 3       # integer, required, desired count to hold below
```

**Undo.** Restore `spec.replicas` and the template snapshot together; clear the
annotation. `K8sWorkloadExecutor`, kind `Deployment`.

**Gating.** `KUBERNETES_ENGINE`; reversible.

---

### 6. `k8s.statefulset_scale_failure` — high · lane `workload`

**Primitive.** Same shape as §5 against a StatefulSet; the blocking constraint
is applied so ordinal pods beyond the current ready count stay unbound, leaving
quorum-based systems short of desired replicas. Uses `podManagementPolicy:
OrderedReady` semantics so the failure is visible as stuck ordinals.

**Params.**

```yaml
params:
  replicas: 3       # integer, required
```

**Undo.** Restore replicas + template snapshot; clear annotation.
`K8sWorkloadExecutor`, kind `StatefulSet`.

**Gating.** `KUBERNETES_ENGINE`; reversible.

---

### 7. `k8s.resource_quota_exhaust` — high · lane `namespace`

**Primitive.** New `K8sQuotaExecutor(K8sSnapshotExecutor)` over
`ResourceQuota`. Read the namespace's `ResourceQuota`, snapshot
`spec.hard`, then lower the chosen resource's hard limit to
`max(current_usage, requested_amount)` so subsequent creates/admissions are
denied (`exceeded quota`). `amount` drives how much headroom is removed.

**Params.**

```yaml
params:
  resource: pods            # enum: pods|cpu|memory|requests.storage|count/<obj>, default pods
  amount: 5                 # integer, required, units of headroom to remove
```

**Undo.** Restore `spec.hard` from the snapshot; label/clear the annotation.
`ref_kinds` = `("ResourceQuota",)`.

**Gating.** `KUBERNETES_ENGINE`; reversible.

---

### 8. `k8s.persistent_volume_mount_failure` — high · lane `storage`

**Primitive.** Patch the workload pod template so the named volume no longer
mounts: rename the `volumeMounts[].mountPath` to a path shadowed by an
emptyDir, or repoint the volume to a non-existent PVC via an added `volumes`
entry that supersedes the real one. The container starts but the data path is
broken, exercising stateful-workload startup recovery.

**Params.**

```yaml
params:
  volume: data      # string, required, volumeMount name to break
```

**Undo.** Restore the template snapshot; clear annotation.
`K8sWorkloadExecutor`, kind resolved from the target.

**Gating.** `KUBERNETES_ENGINE`; reversible.

---

### 9. `k8s.persistent_volume_claim_pending` — high · lane `storage`

**Primitive.** New `K8sPvcExecutor(K8sSnapshotExecutor)` over
`PersistentVolumeClaim`. Snapshot `spec`, then repoint `storageClassName` to a
non-existent class (or add a `selector` matching no PV) so the PVC stays
`Pending` and the consuming workload stalls at startup.

**Params.**

```yaml
params: {}
```

**Undo.** Restore the PVC `spec` snapshot; clear annotation. `ref_kinds` =
`("PersistentVolumeClaim",)`.

**Gating.** `KUBERNETES_ENGINE`; reversible.

---

### 10. `k8s.kube_proxy_failure` — critical · lane `node`

**Primitive.** Node-pinned privileged worker that stops/masks `kube-proxy` on
the node (host `systemctl stop kube-proxy` via `nsenter`), so the node's
iptables/IPVS Service rules go stale. Existing Service ClusterIPs stop being
programmed on that node, exercising the Service → EndpointSlice →
node-proxy path.

**Params.**

```yaml
params: {}
```

**Undo.** Restart `kube-proxy` (`systemctl start kube-proxy`), delete the
worker, and wait for the node's Service rules to reconverge (bounded).

**Gating.** `NODE_CONTROL`; **CRITICAL** (refused without `--allow-critical`);
node family; reversible.

---

## Register & catalog deltas

`_K8S_EXECUTORS` additions:

```python
"k8s.node_not_ready": K8sNodeNotReadyExecutor,            # new (node worker)
"k8s.node_network_partition": K8sNodePartitionExecutor,   # new (node worker)
"k8s.kube_proxy_failure": K8sKubeProxyExecutor,           # new (node worker)
"k8s.pod_crash_loop": K8sCrashLoopExecutor,               # new (argv supervisor)
"k8s.pod_pending": K8sWorkloadExecutor,
"k8s.deployment_scale_failure": K8sWorkloadExecutor,
"k8s.statefulset_scale_failure": K8sWorkloadExecutor,
"k8s.persistent_volume_mount_failure": K8sWorkloadExecutor,
"k8s.resource_quota_exhaust": K8sQuotaExecutor,           # new (snapshot)
"k8s.persistent_volume_claim_pending": K8sPvcExecutor,    # new (snapshot)
```

`k8s_available_faults()` gains all ten; `K8S_MUTATION_FAULTS` /
`K8S_REVERSIBLE_FAULTS` gain the controller subset; `K8S_NODE_FAULTS` gains the
three node families.

---

## Test plan

Extend the fake-kubectl harness (`tests/unit/test_kplan6_runtime.py` pattern)
with state for `Node`, `ResourceQuota`, `PersistentVolumeClaim`, and the
node-worker workload objects.

- **Node families** — assert the worker is pinned (`nodeName`, `hostPID`,
  `hostNetwork`), that `can_apply` refuses with `k8s.unsupported` when
  `NODE_CONTROL` is absent, and that critical families refuse without
  `--allow-critical`.
- **Crash loop** — assert the supervisor argv contains `kill -KILL` and the
  interval, the pidfile is written, and undo reaps the pid.
- **Pending / scale-failure** — assert the injected template carries the
  `reason`-mapped constraint and that undo restores the exact pre-inject
  template from the annotation.
- **Quota / PVC** — snapshot round-trip: mutate → assert `Pending`/`exceeded`
  state → undo → assert the original `spec` is byte-identical.
- **Mount failure** — assert the named volume is broken and restored.
- **Ordering** — the full file must pass both standalone and in-suite (no
  cross-test mutation aliasing: fake `_do_patch` deep-copies stored objects).

## Acceptance criteria

- Ten new faults planned, gated, executed, and undone; `mayhem plan` compiles an
  example drill naming each without schema error.
- Node faults refuse cleanly without `NODE_CONTROL`; criticals refuse without
  `--allow-critical`.
- `kubectl get/delete/patch/apply/exec` all route through the canonical
  alias-normalised fake; all new undo paths restore byte-identical snapshots.
- `uv run pytest`, `ruff`, and `mypy` green; catalog and README/`features`
  surfaces list the ten ids; `-k` fault-kind assertion includes them.

## Deliberately out of scope (→ k8s-plan-2)

Autoscaler (HPA), disruption budgets (PDB/eviction), DNS/CoreDNS, image-pull
latency, termination delay, and preemption tuning.
