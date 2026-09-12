# k-plan-4 — Pod-level faults, multi-instance selection, reconciliation compensation

> **Phase 4 of 5**. Predecessors: k-plan-1/2/3 (executable container-level
> faults). Exit: `k8s.pod_kill`, `k8s.pod_evict`, `k8s.pod_oom` run against a
> live cluster, `selection.all|count|percentage|random` work, and
> compensation for irreversible pod faults is *reconciliation verification*.

---

## Goal

Move from "perturb inside a Pod" to "perturb the Pod itself" — the faults the
user most associates with Kubernetes chaos (kill/evict/OOM/partition), backed
by explicit multi-instance selection semantics and a compensation model that
does not pretend pod deletion has an inverse.

---

## Locked decisions (k-plan-1 interview)

- **[interview] Compensation** — irreversible pod faults (pod_kill, pod_evict,
  k-plan-5 node_drain) have **no undo op**; compensation = wait for controller
  replacement → wait Ready → verify Service endpoints.
- **[interview] Selection policy** — the full grammar (`all|count|percentage|
  random`) becomes implemented here, feeding `max_faults`, blast radius,
  conflict, and risk.
- **[interview] Fault scope** — pod-lifecycle category is this plan's live
  scope; node category remains k-plan-5.

---

## 4.1 Fault capabilities this plan makes live

Catalog (catalog.py:610-710) — these are already declared with the right node
kinds; this plan flips them from UNSUPPORTED to executable behind the driver:

| Fault | Node kind | Mechanism | Reversible? |
|-------|-----------|-----------|-------------|
| `k8s.pod_kill` | POD | delete Pod (grace period param) | No — reconciliation |
| `k8s.pod_evict` | POD | Eviction API (respects PDB/disruption budget) | No — reconciliation |
| `k8s.pod_oom` | POD | set OOM-killed state via triggering memory limit on the chosen container (param) | No — reconciliation |
| `k8s.pod_latency` | POD | netem-style latency into the pod network path | No — node-level mechanism (see 4.4 cage) |
| `k8s.pod_partition` | POD | network partition of the pod (labels/NetworkPolicy, or netns on node) | Yes (remove policy) |
| `k8s.network_policy` | POD/K8S_NODE | temporary deny NetworkPolicy | Yes (delete policy) |
| `k8s.pod_pressure` | POD | capacity stress within the container(s) (param-driven, subset of mem/cpu) | Yes |

**Scope gate for this plan:** `pod_kill`, `pod_evict`, `pod_oom` ship live.
`pod_partition`/`network_policy` ship as **compensation-complete** (they are
effectively reversible) when the node-level mechanism in 4.4 lands; if the
node-level mechanism is not ready, they remain capability-refused with a
"needs k-plan-5 node mechanism" message. `pod_latency` is **deferred to
k-plan-5** (needs netns on the node — see 4.4). `pod_pressure` is a thin
extension of the k-plan-3 container payload and ships now.

---

## 4.2 Multi-instance selection (`domain/target_selector.py`)

`mode: one` (k-plan-2) becomes one branch of a complete grammar:

```text
mode: one          # deterministic single pick (k-plan-2 contract)
mode: count        # N distinct eligible pods (count: int, 1..eligible); no drops
mode: percentage   # ceil(eligible * percentage/100) distinct pods; 0..100
mode: all          # every eligible pod
mode: random       # uniform draw per-round; seed from maniac/plan seed (deterministic replay)
```

All modes:
- Validate against **live** eligible set at impact-gate time (re-resolution,
  k-plan-3 pattern) — never against a stale plan-time pod list.
- Respect `config.max_faults` (a count/percentage/all mode exceeding
  `max_faults` is a plan error `selection.out_of_budget`, pointing at the
  config knob).
- Feed blast-radius/risk already in the planner: multi-pod selection raises the
  effective blast radius deterministically (same math as existing container
  fan-out, extended to pods).
- Conflict rules: a second step targeting overlapping pods within one round is
  refused (`conflict.overlap`) keeping the existing resource-conflict logic
  vocabulary.

Plan-time vs impact-time: `plan`/`validate` records the *expected* selection
snapshot; the impact gate re-runs and emits `resolved_drift` (k-plan-3) when
the concrete pod set moved.

---

## 4.3 Pod-lifecycle executors

New executors beside `K8sExecExecutor` (k-plan-3):

1. **K8sPodKillExecutor** — `delete pod` (grace_period param, catalog
   default 30). `state: injecting` only until deletion requested; no wait for
   termination (that is compensation).
2. **K8sPodEvictExecutor** — `create Eviction` (PDB-friendly; eviction
   rejection is a *server-refused* lease outcome → run note, not a crash).
3. **K8sPodOomExecutor** — triggers the OOM condition on the selected
   container (param: memory-usage spike honoring the pod's memory limit, via
   `kubectl exec` + existing mem payload, then `kill -9` semantics happen in
   kernel terms).
4. **K8sPodPressureExecutor** — pods gain the container-stress payloads
   (reuses k-plan-3 exec plumbing, applied per selected container).

Each executor writes the standard lease/observation/decision records; the
*kind* of the resolved target is `POD` and the evidence JSON (k-plan-3 §3.4)
gains `pod_action` describing the mutation (`delete`, `eviction`, `oom`).

---

## 4.4 Node-level mechanism cage (why latency/partition land here or in k-plan-5)

Pod-network perturbations (`pod_latency`, `pod_partition`, `network_policy`)
need one of:

- node-level: enter the pod's network namespace from the node (`nsenter`) —
  requires node access + `CAP_SYS_ADMIN` / hostPID/hostNetwork privileges;
- or control-plane: NetworkPolicy mutation (pure API, no node access).

**`network_policy` ships (reversible, cheap).** `pod_partition` ships only if
we take the NetworkPolicy route in the same plan; the netns route lands in
k-plan-5 with node faults. `pod_latency` waits for the netns/node route
(k-plan-5). The plan document for k-plan-5 references this cage so nobody
re-opens the decision silently.

If the operator has no ClusterRole permission for NetworkPolicy, the
adapter's capability matrix reports `policy: UNSUPPORTED` and the planner
refuses again — capability-supervised, exactly the docker pattern.

---

## 4.5 Reconciliation compensation (`controller/compensation.py`)

A `CompensationTemplate`-style split (the file already supports undo+verify;
see §1 and `_proc_pause_undo`/`_process_term_undo`) gains a k8s branch:

```text
CompensationTemplate(
    undo=NOOP,                       # pod delete has no inverse operation
    verify=[                          # reconciliation verification
        readiness of replacement pod,
        Service endpoints include a Ready pod,
         (param) run the authored observe window
    ]
)
```

Mechanics:

1. After `pod_kill`/`pod_evict`/`pod_oom` the round enters
   `compensating` lease state.
2. Wait for the owning controller (Deployment/StatefulSet/DaemonSet) to
   create a replacement: watch `Pod` events with the workload selector until
   a new pod (uid differs) reaches `Running`+`Ready`; timeout =
   `config.recovery_grace` (new config key, default 300s, overridable per
   fault like duration).
3. Verify Service endpoints include a Ready pod (only when the workload is
   behind a Service — skipped with a note otherwise).
4. Dispatch of `kubectl rollout restart` is **not** compensation — it is a
   separate authored fault surface (proposal §16 reference); no automatic
   rollout is triggered by compensation.
5. Timeout → lease `compensation_timeout`, janitor continues watching and
   resolves on readiness (existing janitor loop intakes these leases).

The config `recovery: false` semantics keep working: compensation is skipped
entirely; the drill ends with a post-mutation observation window so
self-healing is what is actually being tested.

---

## 4.6 Task breakdown (ordered)

1. Migration: `lease.resolved_target.pod_action`; `config.recovery_grace`;
   support in config schema + `config show`.
2. `mode: count|percentage|all|random` in target_selector.py + budget/
   blast-radius integration (`selection.out_of_budget`,
   `conflict.overlap`); fake-client tests for each mode and each refusal.
3. Pod executors (kill/evict/oom/pressure) + lease state wiring
   (`injecting → compensating → recovered`).
4. NetworkPolicy executor (pure-API; partition if same route) +
   policy capability flag on the adapter.
5. Reconciliation compensation template + event watcher + readiness/endpoint
   verify + timeout/failure states; janitor intake for compensation_timeout.
6. `pod_latency`/netns mechanism decision lock: write the verdict into
   k-plan-5's cage section (ship latency in k-plan-5; remove duplicate work
   updates here).
7. Live e2e (autoskip): pod_kill round → replacement Ready → endpoints
   healthy; eviction with a PDB honored; OOM; NetworkPolicy observed
   dropping traffic then cleared; `recovery: false` leaves the post-mutation
   window observable.
8. Unit tests (fake client): compensation state machine (happy / timeout /
   endpoint-missing), budget refusals, drift snapshots, policy-permission
   UNSUPPORTED refusal.
9. Docs: drill-spec.md k8s examples for count/percentage/all/random,
   compensation semantics table update, features.md M8 → "pod-level +
   reconciliation live", README table CLI flags that expose the new modes.

## 4.7 Acceptance criteria

- `k8s.pod_kill`, `k8s.pod_evict`, `k8s.pod_oom`, `k8s.network_policy`
  execute on a live cluster and each ends **reconciled** (replacement ready /
  policy removed) unless `recovery: false`.
- `selection.mode: count 2` on a 5-replica Deployment drops exactly 2 pods
  and `selection.mode: all` on a 10-replica Deployment with
  `config.max_faults: 1` is refused pre-execution.
- A busted PDB (eviction blocked forever) produces a server-refused lease +
  run note, never a hang.
- No regression: docker container.kill recovery still uses the docker undo op
  (untouched code path verified by existing suite).
- `uv run pytest`, `ruff`, `mypy` green; e2e autoskips without a cluster.

## 4.8 Out of scope

- Node-level faults (`node_drain`, `node_pressure`) + netns latency
  mechanism → k-plan-5 cage.
- Maniac/explore/coverage re-enable over k8s targets → k-plan-5.