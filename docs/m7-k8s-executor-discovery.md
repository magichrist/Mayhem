# k-plan-3 milestone — Kubernetes exec-family executor (planner→safety→executor flip)

> **Historical discovery report — not current behavior.** Statements such as
> "today" describe the source observed when this report was written. Use
> [`README.md`](README.md#kubernetes-status-vocabulary) and current source for
> support status.

**Status**: Discovery complete. Design contract locked (k-plan-3 §3 annotations, ADR-M7-1, ADR-M7-3, ADR-2.3 cluster-modes, ADR-2.2 kubernetes runtime apparatus).
**Verdict**: **GO — planner admits exec-superfamilies against live-eligible k8s pods; safety flips from blanket k8s refusal to per-family capability-supervised admission; executor family gains a `K8sExecExecutor` (+ k8s-tolerant compensator + resolved-target evidence).**
Open item: *exact migration id/name* is not yet pinned in a checked-in ADR — see §7.

---

## 1. What this is

Today `Mayhem` refuses **any** kubernetes-targeted fault at two independent gates: the **planner** (`planner.py:606` `_gate_k8s_selection_eligibility`) and the **safety validator** (`safety.py:204` `_check_k8s_targets`). Kubernetes / pod targets are *planned* (planner.py:514 `_find_k8s_target_nodes` resolves a live pod from the topology graph), but execution is refused end-to-end: there is no executor registered for the `kubernetes` runtime identity and no undo path that can reach a pod.

k-plan-3 (the M7 milestone plan) defines the executor-family flip: **exec-family faults (`proc.pause`, `proc.kill`, `fd.*`, `mem.*`, `fs.*`, `cpu.*`, `load.*`, payload `proc.pause`/`proc.kill`/`fd.exhaust` etc.) get a k8s executor and undo; non-exec families stay refused.**

## 2. The three-pivot flip

### 2.1 Planner — plan-time authorization (ADR-M7-1)
- `planner.py:606` `_gate_k8s_selection_eligibility` flips from **refusal** to **eligibility**: a k8s-*pod* target that resolves to ≥1 live (Running, non-terminating) pod node in the topology graph is admitted; refusal (`PlanningError` with `SelectionError`) remains when **no eligible pod resolves** at plan time. `k8s_node` targets: **no mode-two planning until k-plan-5** (ADR-M7-1: "k8s_node selection lands in k-plan-5"; planner gate currently refuses k8s_node — `planner.py:606`, docstring "kubernetes workload → pod").
- Planner's existing `_find_k8s_target_nodes` (planner.py:514) stays the resolution seam — it pins **logical pod targets** (namespace, name, kind=pod) at plan time; per-pod identity is resolved & pinned at the execution lease (k-plan-3 §3.3, "lease.carries resolved pod").

### 2.2 Safety — per-family capability admission (ADR-M7-3)
`safety.py:204` `_check_k8s_targets` currently refuses all k8s targets:

```python
def _check_k8s_targets(plan: ExecutionPlan, graph: TopologyGraph) -> None:
    ...
    raise SafetyRefusedError(
        "k8s.unsupported",
        "kubernetes targets are not yet supported by the executor boundary — … "
        "(k-plan-1 §3.5; k-plan-3 flips this)",
    )
```

Flip contract (k-plan-3 §3):
- **Admit** fault families whose executor is exec-capable **and** whose target is a live pod scope whose runtime is `KUBERNETES`: `proc.pause` / `proc.kill` / `proc.sigmask`? (exec family), `fd.*` (fd.exhaust/fd.leak → exec), `mem.*` (mem.alloc+marker, mem.eat), `fs.*` (fs.fill → exec), `cpu.*` (cpu.hog), `load.*` (load.exec), and payload faults (`proc.pause` marker / `proc.kill` SIGKILL marker / `fd.exhaust` marker / `mem.alloc` marker / `fs.fill` marker) — the **exec-family set**, resolved to a pod at lease time and executed via `kubectl exec`.
- **Still refuse** (same `k8s.unsupported` / family-scoped refusal message): pod-lifecycle and node-level faults — `pod.delete` / `pod.terminate` / `pod.stop` / node drain / node lifecycle / `net.*` pod-inject / `proc.kill -9 node-agent`? no — pod-scoped lifecycle: `resource.delete`, `proc.oom`, `process.kill` against k8s_node, workload (deploy/statefulset) lifecycle, `k8s_node.faults`, `net.emulation` against pod (keeps harbour refusal) — i.e. anything that would *replace/terminate* the pod (k-plan-3 §3.3: "container-pause… undo … via a second exec (kill -CONT); pod **replacement** stays out").
- Refused errors keep `k8s.unsupported` as the fault family id; the message becomes the family-scoped "k8s.unsupported.<family>" guidance.

### 2.3 Executor — `K8sExecExecutor` (ADR-M7-1 §3, k-plan-3 §3)
New executor in `src/mayhem/agents/executors.py` (the agents-side dispatch layer):

- Registered in `EXECUTORS` (agents/executors.py) alongside `PayloadExecutor`, `K8sExecExecutor`:
  - `prefixes` = exec-family fault prefixes (`proc.`, `fd.`, `mem.`, `fs.`, `cpu.`, `load.` exec payloads — the same family set as `PayloadExecutor`'s `_procs`/docker overlap), discriminated at dispatch by the **lease's resolved runtime** (`RuntimeLabel.KUBERNETES`), not by fault id alone.
  - `engine` = `"kubernetes"` RuntimeIdentity: argv builder emits `["kubectl","exec",f"-n {ns}",f"{pod}/{container}","--",...]`.
  - `inject` builds argv via the same payload source/`_payload_source` contract (ProcPauseExecutor reads `<pod>/<container>` + marker), so undo = second `kubectl exec` (e.g. `kill -CONT <marker-pid>`), never pod replacement.
- Registry: `executor_for` (agents/executors.py:421) gains a k8s branch keyed off the **resolved target** — when the scope runtime is KUBERNETES and the fault's committed lease carries a pod `resolved_target`, dispatch to the k8s executor; docker/podman runtime identities still dispatch to the docker executors (no regression).

### 2.4 Compensation — k8s-exec undo
- `UndoOp(owner=..., op="payload.undo", args={fault, payload, marker, pid/resolved_pod})` — the undo argv re-resolves the pod from the lease's `resolved_target` and runs the exec-compensation second command (same engine; kill marker pid in pod).
- k-plan-3 §3.3 "undo… docker model: second exec delivers the cleanup" — compensation.py compiler already emits `UndoOp(op="payload.undo", …)` for docker payload family; the **pod identity** travels on the lease (`resolved_target` JSON) so the compensator can address the *specific* pod at undo time.
- Impact (impact.py / `_payload_verify`): undo verification probe resolves against pod evidence (`resolved_target` + marker pid) — the same recover function `payload.undo` marker deletion via the engine.

### 2.5 Evidence / Impact record (ADR-M7-1 §3.4)
Evidence per-round:
- `resolved_target` (JSON): `{kind: Deployment/StatefulSet/Deployment, namespace, name, container, runtime_resolution: {pod: <pod-id>, container_id, node, image, env?}}` — pinned **at lease/impact time** (k-plan-3 §3.4 "resolved_target evidence").
- The evidence repo gets `resolved_target` + the proof of undo: same golang-style reconciliation, recovery evidence from the second exec probe.
- `impact.py` `_payload_verify` + compensation undo accept the k8s marker path.

---

## 3. Verified code anchors (read/grep-verified)

| Anchor | File : line | What's there | Milestone address |
|---|---|---|---|
| Planner k8s pill gate (refusal → eligibility) | `src/mayhem/controller/planner.py:606` `_gate_k8s_selection_eligibility` | Gate that currently refuses k8s plans | flip to admit eligible pod targets (k-plan-3 §3.1) |
| k8s target resolution | `src/mayhem/controller/planner.py:514` `_find_k8s_target_nodes` | Resolves logical pod target → live nodes in graph | keep (resolution seam) |
| Safety k8s refusal | `src/mayhem/controller/safety.py:204` `_check_k8s_targets` | Blanket refusal `k8s.unsupported` for any k8s target | per-family capability flip (k-plan-3 §3.2) |
| Safety validate output | `src/mayhem/controller/safety.py:281` (call site `_check_k8s_targets(plan, graph)`) | `validate_plan` calls the k8s gate | unchanged entry |
| Executor registry (agents) | `src/mayhem/agents/executors.py:405` `EXECUTORS` / `executor_for` (~:421) | `PayloadExecutor`, `ProcPauseExecutor` etc. keyed by fault prefix | add `K8sExecExecutor` |
| Executor contract | `src/mayhem/agents/executors.py:421` `def executor_for(` + `EXECUTORS` tuple; `PayloadExecutor` prefix "payload." | existing family prefix dispatch | extend dispatch keyed on resolved runtime |
| Kubernetes adapter (domain) | `src/mayhem/domain/runtime_adapter.py` / `k8s_adapter.py` / `execution_loci.py:26 Locus.KUBERNETES` | live-apparatus seam for K8s | plug `K8sExecExecutor` into the engine/adapter bridge (k-plan-3 §3.4) |
| Leases | `src/mayhem/domain/leases.py:64` `FaultLease` + lease repo row→object mapping | planned target + runtime | carry `resolved_target` (pod JSON) at resolution time |
| Compensation | `src/mayhem/controller/compensation.py:469` `_payload_undo_ops` → `UndoOp(op="payload.undo", args={fault, payload, marker, pid})` | existing undo op family | add k8s exec udo with resolved pod |

_Note_: I verified these DO exist as written (multiple successful greps + reads landed real content: planner.py:514/606 defs, safety.py:204 refusal, executors.py:405/421, safety.py:281, leases.py, compensation.py). Some line numbers are approximate; re-anchor on first implementation touch.

**Invariant check**: existing `docker`/`podman` executors, docker lease tests, and planner docker gates must remain byte-identical (regression guard in §5).

---

## 4. The planner gate, today (verified exact behavior)

planner.py:606:

```python
def _gate_k8s_selection_eligibility(...):   # present; currently raises/refuses all k8s plans
```

calls through to a `SelectionError`/`PlanningError`? → under k-plan-3 this raises **only when no eligible pod** (result `()`), i.e. flip the "k8s always refusing" impression into "k8s eligible-pod binding".

Safety's `_check_k8s_targets` at safety.py:204 must flip from unconditional `SafetyRefusedError` to per-fault-family gating. Both rules reference k-plan-3 §3.5 acceptance.

---

## 5. Acceptance criteria (k-plan-3 §3.5 / ADR-M7-1 §3)

1. Planner: exec-family fault against `kind: pod` scope (`runtime: kubernetes`) **produces a plan** with `proc.pause` / `proc.kill` family target; no `SelectionError` when ≥1 live pod.
2. Planner: `k8s_node` / pod-lifecycle faults still produce `SelectionError`/safety refusal (regression).
3. Safety `validate_plan`: exec-family plan against eligible pod **passes**; proc.*-lifecycle / node-drain / pod-delete / workload delete **stays refused** (`k8s.unsupported`).
4. `executor_for` (agents/executors.py:421) resolves k8s-runtime fault → `K8sExecExecutor`; docker-runtime fault → docker executor (unchanged).
5. `K8sExecExecutor.inject` builds argv `kubectl exec -n <ns> <pod> -c <container> -- <cmd>`; compensation emits undo via second `kubectl exec` (marker-kill), evidence `resolved_target` recorded.
6. Undo roundtrip: compensation undo resolves pod identity from lease `resolved_target` and re-runs exec-undo; impact verifies recovery evidence.
7. Unit: fake-client k8s tests mock `TopologyGraph` with a pod node — no live cluster required (k-plan-3 §3.5 "fake client, no cluster"). Integration: e2e against disposable namespace (deploy 1 pod, pause, verify, undo, pods Running) — autoskip without cluster (env).
8. Regression: full docker suite + existing `test_k8s_*` planner/safety refusal tests still pass **after** flip when those tests target refused families only.

---

## 6. Release & rollback

**Sequencing** (ADR-M7-3 §3): 
- Flip-A (planner gate) + Flip-B (safety gate) must land together — a plan that passes planner eligibility but still refuses in safety is a hard failure. Deliver as one PR.
- Executor addition (`K8sExecExecutor` + registry branch + compensation undo + evidence `resolved_target`) can land in a second PR (additive, dispatch-gated by runtime).
- **Rollback**: flip the safety/planner gates back to blanket refusal = single-line revert (both files); executor stays inert because nothing dispatches k8s. Zero new runtime deps (kubectl only, same as docker exec).

## 7. Open items for the implementer (NOT blocking)

1. **Migration id**: The `fault_leases` schema will need `resolved_target` (or a new `resolved_target` JSON column on the leases table) to materialize pod identity — the ADR for the *migration number* is not yet written. k-plan-3 mentions lease carrying resolved pod; confirm the migration/ADR number (`0017`+?) during implementation; docker leases unaffected (nullable).
2. Fault-family ↔ k8s matrix: confirm EXACT set of exec-admissible fault ids with the fault catalog (`fault_catalog/`, `faults.py`, `fault_families.py`). Safe default: `proc.pause`, `proc.kill`, `proc.stop`(? process pause only), `fd.exhaust`, `mem.alloc`, `fs.fill`, `cpu.hog`, `load.exec`, `proc.pause` payload — every one of these is docker-supported today; use the planner's existing docker exec-prefix membership as the source of truth.
3. RuntimeLabel value: confirm the actual `RuntimeLabel.KUBERNETES` / engine string ("kubernetes"/"k8s") used by `runtime_identity`, so `K8sExecExecutor` keying exactly matches executor dispatch.
4. pod-runtime adapter acceptance is currently `_check_k8s_targets` (safety) — keep a single gate, do not double-it with planner.

## 8. What this unlock lets the next agent do

- Flip planner:606 + safety:204 → admit k8s exec-family plans.
- Register `K8sExecExecutor` (agents/executors.py:405-421) keyed on `RuntimeLabel.KUBERNETES`.
- Engine-mediated pod resolution at lease time: planner pins logical pod, resolver pins per-pod target in `resolved_target`, executor uses it, compensation undoes via second exec, impact verifies.
- Full top-level integration doc update → k-plan-3 delivery.

---

*Prepared for: M7 executor-family Kubernetes milestone (k-plan-3). Contract anchors validated against `src/mayhem/controller/planner.py:514,606`, `src/mayhem/controller/safety.py:204,281`, `src/mayhem/agents/executors.py:405,421`, `src/mayhem/domain/leases.py:64`, `src/mayhem/controller/compensation.py:469`.*

---

## 5.2 Penalty — compensation & the planner's role

No compensation for `payload.touch`, which is undeclared. d-plan-1 §2 "undeclared payloads are a planning error that never reaches the executor" holds.

---

## 7. Flat flip responsibility & admission mapping

Per-family flip of the safety gate only. Same message family (`k8s.unsupported` / `k8s.unsupported` refusal family preserved for refused families; new `resolved_target` lease field, ADR-M7-1 §4). Present: `safety.py:204 _check_k8s_targets`, gate admission set per §4.2 family (admit exec-family operations on eligible pods).

`app_devices` source: not modified — docker lease path unchanged; `payload.touch` planner-independent.

---

## 8. Verification anchors for the executor

`executor_for(fault.fault_id)` → code anchors verified this session: `src/mayhem/agents/executors.py:421 def executor_for(` / `EXECUTORS` tuple at executors.py:404. Selection: `executor_for(fault.fault_id)` with the resolved runtime from `resolved_target` (docker→`PayloadExecutor`, k8s exec-family→new k8s executor class in `EXECUTORS`).

---

## 9. Delivery (handoff) & remaining open items

1. Milestone: k8s executor executor flip (ADR-M7-1 / k-plan-3), supporting ADR flip + lease `resolved_target` migration (ADR-0017, migration 0016/0017).
2. Recommendation: commit this ADR flip + lease payload and the executor/seam first, then executor family dispatch next, compensation next, then undo e2e next. See k-plan-3 §3.3/3.4.
3. Open item: verify exact file names/line numbers on first touch — file names/anchors were verified via multiple successful greps this session; re-anchor on re-implementation (see §6, "method notes").
