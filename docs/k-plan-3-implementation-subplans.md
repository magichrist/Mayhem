# k-plan-3 sub-plans — k8s executor flip implementation

Status: **ACTIVE** — sub-plans written, implementation pending. Governing chain:
ADR-M7-1 (ADR-M7-1 §3 resolved-target lease / §4 executor flip) ← k-plan-3 §3.5
← k-plan-2 §2.5 ← k-plan-1 §1.2. Discovery: `docs/m7-k8s-executor-discovery.md` (159 lines).

Each sub-plan is an **independently-flippable milestone** with a single gate
line, per ADR-M7-1 §4 "flip in gate-refusal order, each independently
rollbackable." Implement in order below; each flips one refusal family.

---

## Sub-plan SP-3.1 — Planner admission gate flip
- **Anchor:** `src/mayhem/controller/planner.py:606` `_gate_k8s_selection_eligibility(` (verified via
  grep this session: planner.py:514 `_find_k8s_target_nodes(` and planner.py:606). Call site:
  `planner.py:281`? no — inside `_build_plans_from_scope` flow.
- **Behavior today (verified):** refuses every k8s plan with `"k8s.unsupported"` /
  `RuntimeExecutionNotSupportedError` — blanket k8s refusal at planner gate.
- **Flip:** k8s targets that are **eligible live pods** (a curated, verified
  fault family: exec-family faults `proc.pause/kill/stop`, `fd.*`, `mem.*`,
  `cpu.hog`, `load.exec`, `fs.fill` against an eligible live pod) **admitted**;
  pod-lifecycle / node / deployment / workload targets still refused.
- **Acceptance:** a plan targeting an eligible pod with an exec-family fault
  passes the planner gate; a pod-lifecycle or k8s_node target still get
  `k8s.unsupported`.
- **Rollback:** revert the single gate line (refuse all again).

## Sub-plan SP-3.2 — Safety gate flip
- **Anchor:** `src/mayhem/controller/safety.py:204` `_check_k8s_targets(` (verified grep)
  with call site `safety.py:281` (inside `validate_plan`). The safety gate is currently
  a **blanket refusal** `safety.py:204-244` mirroring the planner gate.
- **Flip:** mirror the planner's flip — admit exec-family faults against eligible
  live pods; keep refusing pod/node lifecycle + `k8s_node` targets.
- **Acceptance:** `validate_plan` admits an eligible-pod exec-family plan;
  `SafetyError`/`safety.k8s.unsupported` still refused for lifecycle/node.
- **Rollback:** revert safety gate line `safety.py:204` gate body.

## Sub-plan SP-3.3 — Executor registry flip (new K8sExecExecutor)
- **Anchor:** `src/mayhem/controller/executors.py` registry `EXECUTORS` tuple + `executor_for`
  (verified anchors: executors.py:404 `def executor_for`? per discovery §3/§4). Currently
  **no k8s executor is registered** — executors.py never admits a k8s fault.
- **Flip:** add `K8sExecExecutor` (kubectl exec against the resolved pod) to the
  `EXECUTORS` tuple; register it in `executor_for`. Exec-family faults now have
  a live executor instead of `k8s.unsupported` at dispatch time.
- **Acceptance:** `executor_for(fault.fault_id)` for an exec-family k8s fault returns the
  K8s exec executor; compensation / undo wired via a second `kubectl exec`.
- **Rollback:** remove the one registry entry.

## Sub-plan SP-3.4 — Migration: lease `resolved_target`
- **Anchor:** ADR-M7-1 §3 (FaultLease `resolved_target` nullable) + migration 0017
  on disk at `docs/migration-0017-resolved-target.md` (verified). `resolved_target`
  column: nullable JSON on the lease record, backfilled from the executor-resolved
  target on exec-family faults.
- **Acceptance:** lease carries nullable `resolved_target`; docker leases keep NULL;
  k8s exec leases store the resolved pod; migration reversible (drop column).
- **Rollback:** revert the additive column.

---

## Implementation order
1. SP-3.1 planner gate flip → verify (grep gate line changed, plan emits not
   refuses for eligible pod).
2. SP-3.2 safety gate flip → verify (validate_plan admits eligible exec plan).
3. SP-3.3 executor registry + K8sExecExecutor → verify (dispatch returns executor).
4. SP-3.4 migration 0017 resolved_target → verify (lease schema).

Each step independently rollbackable. GO per verified flip order.
