# Kubernetes exec-family executor — planner → safety → executor flip (design report)

> **Implemented design record with dated snapshots.** This ADR and the code
> examples inside it describe the design and rollout state recorded on
> 2026-09-12. For current Kubernetes support, use
> [`../README.md`](../README.md#kubernetes-status-vocabulary) and the executable
> source anchors listed there.

**Status:** Discovery complete · contract locked against k-plan-3 / ADR-M7-1
**Owner:** Mayhem controller exploration agent (M7 k8s milestone)
**Date:** 2026-09-12
**Verdict:** **GO (gated).** The change is real, bounded, and arc-splittable. Flip-list A (reroute) + B (executor) are each independently releasable; release only after the `k-plan-3 §3 / §2 (mode-one) e2e` acceptance run passes. Do **not** merge A and B together with the planner gate flip before the impact/compensation contract roundtrip (`_submit_compensation_lease` ⇄ `UndoOp(op="payload.undo")`) is pinned in an update to k-plan-3.

---

## 1. What this is

The **exec-family fault executors** (`proc.*`, `process.*`, `fd.*`, `mem.*`, `fs.*`, `cpu.hog`, `load.exec` payload faults) currently execute only against `docker` / `podman` container runtimes via `PayloadExecutor` / `ProcPauseExecutor`, which build argv as `docker/podman exec -d <container> -- <cmd>`. The Kubernetes runtime is **entirely refused** in two independent planner-side gates today. k-plan-3 (ADR-M7-1) defines the container-level execution milestone that turns this into a **capability-supervised admission** for the exec family against live pods.

## 2. Verified code anchors (read during this session)

| Concern | Anchor |
|---|---|
| Exec-family registry / `executor_for()` | `src/mayhem/agents/executors.py:421` (`def executor_for`), tuple `EXECUTORS` ~405, `PayloadExecutor` (~243-315) with `prefixes = (payload prefixes)` + proc pause executor |
| Planner k8s target resolution (mode-one: resolve pod at plan time) | `src/mayhem/controller/planner.py:514` `_find_k8s_target_nodes`, `~606` `_gate_k8s_selection_eligibility` (plan-eligibility gate, refuses empty eligibility) |
| Planner blanket refusal | `src/mayhem/controller/planner.py` — planner asks *capability* gate; policy refusal lives in safety (see rows below) |
| Safety gate — k8s refusal | `src/mayhem/controller/safety.py:204` `_check_k8s_targets`; invoked from `validate_plan` (`safety.py:281`) |
| Safety refusal family | `SafetyRefusedError("unsupported.k8s" / "k8s.unsupported")` — blanket refusal of any plan whose target scope/lease resolves to a pod or k8s node |
| Kubernetes runtime label | `src/mayhem/agents/executors.py` / domain — `RuntimeLabel.KUBERNETES`, `ResourceKind.POD` / `K8S_NODE`, `RuntimeLabel.KUBERNETES` values; planner plans pod depth, executor would use `kubernetes` engine |
| Compensation undo contract | `src/mayhem/controller/compensation.py` — `UndoOp(op="payload.undo", args={…payload, marker, pid})` + exec-family undo via engine (docker model); `FaultLease` resident in `src/mayhem/domain/leases.py` + `src/mayhem/domain/faults.py` (FaultFamily, FaultCategory `proc`→`process`) |
| Lease / resolved-target contract | `src/mayhem/domain/leases.py` — `FaultLease.resolved_target` (k-plan-3 task 1; nullable JSON recording the concrete resolved pod) proposed for migration 0017 |

## 3. Root cause of the current gap

1. **Planner refuses k8s target work at plan time** (`planner.py:606` eligibility gate) — "mode-one eligibility gate (k-plan-2 §2.5)" plus the safety gate at `safety.py:204`, which raises `SafetyRefusedError("k8s.unsupported", …)` for **any** plan whose fault targets a pod/k8s_node, regardless of family.
2. **The executor registry is fault_id-prefix-keyed**, so a `proc.*`/`fd.*` fault planned against a live pod can only ever resolve to the docker/podman `PayloadExecutor`; there is no executor that understands a `kubernetes`/`kubectl exec` runtime identity emitted by the planner at lease resolution.
3. **Undo is runtime-bound**: the payload family's `UndoOp(op="payload.undo", …)` path in compensation.py assumes the docker container/engine context the planner records in the lease today; it does not record the resolved *container identity inside a pod* (k-plan-3 §A "undo… survive" hold).

## 4. The contract (from k-plan-3 §2, §3 / ADR-M7-1)

### 4.1 Fault / executor gating flip (planner → capability)
- The planner's **mode-one eligibility gate** (`planner.py:606`) is retained for fault *identity* refusal: exec-family faults (`proc.pause`, `proc.kill`/`proc.stop`, `fd.*` (when exec-supported), `mem.*`/`fs.*`/`cpu.*`/`load.*` payload families against a live pod) are **admitted for planning** if — and only if — the scope's runtime is `KUBERNETES` **and** the target authority resolves to eligible pods. Non-exec, container-runtime-only families (`proc.oom`, `process.kill` via pod-lifecycle, watchdog, net.* that target pod lifecycle, etc.) stay refused by the **safety gate** (`safety.py:204`).
- The **safety gate flips** from blanket `k8s.unsupported` refusal to **per-family, capability-supervised admission**: a small admission gate evaluates the fault's `segment.family` — `proc`/`fd`/`mem`/`fs`/`cpu`(load.exec) — and admits only the exec-compatible subset of the catalog for pod targets. `k8s_node` targets were refused by safety until k-plan-5 delivered node-level faults (`k8s.node_drain` / `k8s.node_pressure`); k-plan-5 flips the node-kind gate to admission (`safety.py:204` admits node scopes, superseding the k-plan-3 §scope boundary).
- **Timing**: this is a *mode-one* flip per k-plan-3 §3: execution-side resolution lands the concrete pod identity at lease time (candidate-pod resolution, ADR-M7-1/ADR-M7); the planner/impact resolver records `resolved_target` on the lease rather than pinning a decorator pod at plan time (k-plan-3 §A "logical→physical" contract).

### 4.2 Lease / evidence contract
- `FaultLease.resolved_target: JSON | None` (migration 0017). Populated at **execution** by the resolver (`KubernetesRuntimeResolver`), containing pod identity: `{kind, namespace, name, container, runtime_id/ pod_uid, authority {...}}`.
- `resolved_target` is what the impact gate (`_C-phase` `impact.py`), compensation (`UndoOp`), and executor all read; it is **not** set at plan time (isolation from planner/planner gate; the planner *may* pre-resolve logical→nodes for mode-one eligibility, but the lease must record the *live* pod at exec boundary).
- Postcondition for every successful exec-family k8s fault: lease carries `resolved_target`; compensation carries an exec-family undo-op with the resolved pod/container; evidence (`resolved_target` + `ResolvedTarget`) is written before payload execution.

### 4.3 Executor contract
- New `K8sExecExecutor` (name to be finalized; also referenced as part of the `proc.*` family executor) registered in `executors.py` (`EXECUTORS` + `executor_for`), with:
  - `prefixes`/`support` reflecting execution via `kubectl exec -n <ns> <pod> -c <container> -- <cmd>` for the exec-family faults; same undo via kubectl exec (kill marker pid / compensation payload op).
  - Runtime identity: `RuntimeLabel.KUBERNETES`; argv construction mirrors docker (`kubectl exec` instead of `docker exec`), reusing the same payload scripts + marker-adding compensation pattern so undo remains marker-addressed (k-plan-3 "the same signal/cleanup… second kubectl exec").
  - Executor selection at the point where the planner/executor currently dispatches: key off **runtime label on the fault's target** (pod/container identity), not fault_id prefix alone — the discriminator is `scope.runtime == KUBERNETES` + kind ∈ {POD, K8S_NODE? no — POD only} at executor selection.
- `FaultExecutor.inject()` futures: the interface contract this executor implements must expose the resolved pod (lease `resolved_target`) so both `inject` and `undo` resolve the container from the pod identity, not from plan-time pod-name decoration.

### 4.4 Planner eligibility gate (detail)
- `planner.py:606` stays as the **"eligible pod must exist at plan time (mode-one)"** guard — so a plan that targets a pod in a scope where the planner can resolve **zero** eligible pods is refused (planner's `_gate_k8s_selection_eligibility` lifts the refusal *only* when `allow_unresolved` / the runtime is KUBERNETES and resolution is deferred to exec). Ensure the flip-list keeps this guard for *family* refusal independent of *runtime*.
- The **planner must not emit exec-family faults for a k8s workload whose hosts/leases never reach an executor**: so the flip is complete only when `validate_plan` (`safety.py:281`) no longer blanket-refuses and `executor_for` can yield the k8s executor.

## 5. Task breakdown (ordered — mirrors k-plan-3 script)

1. **Migration 0017**: `fault_leases.resolved_target` nullable JSON; backfill absent → `NULL`; forward/backward safe (existing docker leases unaffected).
2. **`KubernetesRuntimeResolver`** in domain (or `agents/`): read scope.graph → pod (candidate resolution at exec boundary), env/container-record; raises `SelectionError`/`SafetyRefusedError` on no eligible pod; records `resolved_target` on lease.
3. **Adapter flip**: `domain/` + `agents/` capability check for `proc.*/fd.*/mem.*/fs.*/cpu.*/load.*` against `kubernetes` engine — from refusal-gate to admission + engine supervision for exec family; non-exec families refused with `k8s.unsupported` (message unchanged-family).
4. **`K8sExecExecutor`**: argv `["kubectl","exec","-n",ns,"pod/name","-c",container,"--",cmd]`; payload marker handoff; undo via second kubectl exec (kill marker pid / compensation "payload.undo" family), resolved from lease `resolved_target`.
5. **Planner/safety flip**: planner `_gate_k8s_selection_eligibility` + safety `_check_k8s_targets` — admit exec-family, refuse `pod-lifecycle`/`proc.k8s.*` families; safety gate message stays `k8s.unsupported` for still-refused families.
6. **Impact/compensation**: `_C-phase` impact.py + compensation record `resolved_target` + pod-scoped undo; impact gate reads `resolved_target` (not plan-time target only).
7. **Tests**: unit (fake k8s client, no cluster) for resolver selection + pid-pod argv + undo roundtrip; execution-family executor dispatch; planner still refuses non-exec k8s families (regression); migration 0017 up/down.
8. **E2E (autoskip)**: `proc.pause` against a real *(temporary, namespaced)* deployment → probes verify; evidence JSON carries `resolved_target` with pod+uid+container; undo returns the pod to Running.
9. **Docs**: k-plan-3 ADR §3 status flip; fault-catalog k8s cap rows "unsupported"→"supported (exec family)"; README capability table; compensation §evidence example.

## 6. Impact / capability matrix

| Component | Current | After | Relaxation risk |
|---|---|---|---|
| `controller/safety.py:204` `_check_k8s_targets` | refuse ALL k8s | admit exec-family per capability; refuse lifecycle+node | **Low** — family-keyed, safety still refuses node/unsupported |
| `controller/planner.py:514`/`606` | refuse empty-eligibility | keep for `k8s_node`; add pod-eligible enrollment for exec family | Low, plan-time only; lease holds live pod |
| `agents/executors.py:421` (`executor_for`) + `EXECUTORS` | no k8s executor | `K8sExecExecutor` registered, selected by runtime label + exec family | **Low** — new executor, registry additive |
| `domain/faults.py` FaultCategory | `proc`→PROCESS family map already present | unchanged (exec compatibility by family) | None |
| `leases.py` `FaultLease` | no `resolved_target` | nullable JSON column + resolver | **Low** — additive, nullable, docker untouched |

## 7. Failure modes / rollback

- **F1 mismatch** — planner gate kept but no executor dispatch (`executor_for` returns None for new executor) → plan would pass safety but crash executor → **mitigate**: flip 2 (resolver) + flip 3 (registry) land in the same release as flip 5; release order A (lease+resolver, additive) then B (executor+planner flip, gated).
- **F2 undo loses pod identity** — undo op without `resolved_target` cannot re-exec → refused at compensation/lease validate; **contract**: executor undo must resolve from `resolved_target`, and `UndoOp` must carry resolved pod/container (ADR-M7-1 requirement, task 6).
- **F3 regression on docker** — docker leases must not pick up k8s executor; discriminator is runtime label on target, and docker fault targets carry no k8s runtime, so `executor_for` must not key on fault_id alone. Test: existing docker unit suite + a `test_docker_fault_still_uses_payload_executor`.
- **Rollback**: R1 = revert migration 0017 down (nullable, docker-unaffected); R2 = drop `K8sExecExecutor` + restore `safety.py:204` blanket refusal + planner gate. Each independently reversible; document both.

## 8. Verification & release gates

- Unit: 7 tasks all with fake-client k8s tests (`tests/unit/...k8s*`) — no cluster needed.
- Planner regression: `tests/unit` k8s planner tests still refuse `pod-lifecycle`/`watchdog`/`k8s_node` families (message `k8s.unsupported`) while exec-family pod plans now validate.
- `mayhem validate-plan / plan` smoke against a disposable namespace (deploy 2 replicas, `proc.pause`/`proc.pause`… kill one, probe, undo) — explicit, namespaced, low risk, revertible.
- **Acceptance**: run `k-plan-3 §3.5 acceptance checks` — e2e `proc.pause` on a real pod delivers resolved_target evidence + running-pod undo.

**Recommendation:** commit flip-list A (migration 0017 + resolver + lease contract) as one PR, flip-list B (executor + safety/planner gate + compensation) as a second PR, each with its own fake-client unit tests and the k-plan-3 e2e acceptance as the required end-to-end check. Both PRs are additive; neither touches the docker path. Do not merge either until `validate_plan` on a k8s exec-family plan no longer raises and `executor_for` resolves the k8s executor — assert this as a test in the first PR (`test_k8s_exec_*`) rather than left to e2e.
