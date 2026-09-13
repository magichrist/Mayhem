# k-plan-3 sub-plans — implementable flip order (ADR-M7-1 track)

Status: **ACTIVE — sub-planning complete, ready to implement.**
Parent: `docs/k-plan-3.md` (k-plan-3) — milestone "flip the k8s executor selection
gates." Governing chain: ADR-M7-1 (ADR-M7-1 §3 flip design / §4 acceptance / §5
release-rollback) ← k-plan-3 §3 ← k-plan-2 §2.5 ← k-plan-1 §1.2. Discovery report:
`docs/m7-k8s-executor-discovery.md` (159 lines, read + grep-verified this session).
ADR flip record: `docs/adr-adr-m7-1-k8s-executor-flip.md` (executor-flip ADR,
on disk, verified).

Every sub-plan is an **independently rollbackable flip** with a single gate-line
anchor. Order below is the **verified flip order** (option (a) — re-anchored on
first touch). Each sub-plan flips one refusal gate line; each is reversible by
reverting that line. Implement in order: SP-3.1 → SP-3.2 → SP-3.3 → SP-3.4.

> Anchors were freshly re-grepped this session (broad fresh grep) and are treated
> as verified discovery baselines. **Re-grep on first touch** (per discovery §8):
> line numbers may drift if the working tree shifted since the grep.

## Sub-plan SP-3.1 — Planner gate flip
- **Anchor:** `src/mayhem/controller/planner.py:606` `def _gate_k8s_selection_eligibility(` — the planner's mode-one eligibility gate (verified grep: `planner.py:606`). Call site `planner.py:281`? — re-anchor via grep on first touch.
- **Flip:** refuse-family → admit-eligible. A k8s target **in the live topology** that
  resolves to at least one **eligible live pod** (Running, not terminating) passes
  planning; targets absent from the graph (logically pinned) pass through (executor
  resolves at exec time). Untracked/absent workloads and pod/nodepool lifecycle
  targets still planned=true but gated the same as today; only the *eligibility
  blanket-refusal* is opened.
- **Acceptance criteria:** planner admits an exec-family k8s fault against an
  eligible live pod; planner still refuses telnet/launch/tee exec-family faults
  on k8s executors until executor present (SP-3.3 ensures the executor exists).
  Planner still refuses pod/node lifecycle k8s faults.
- **Rollback:** revert the single gate flip at `planner.py:606` region.
- **ADR:** ADR-M7-1 §3 (flip #1); governed per ADR-M7-1.

## Sub-plan SP-3.2 — Safety gate flip
- **Anchor:** `src/mayhem/controller/safety.py:204` `def _check_k8s_targets(` (verified grep). Call site `safety.py:281` inside `validate_plan`.
- **Flip (mirror of SP-3.1):** safety gate refuses → admits exec-family k8s faults
  against eligible live pods; still refuses pod-lifecycle/node-lifecycle k8s
  targets with `k8s.unsupported`.
- **Acceptance criteria:** `validate_plan` passes an eligible exec-family k8s plan;
  refuses a k8s lifecycle plan with `k8s.unsupported` (unchanged behavior).
- **Rollback:** revert safety gate flip at `safety.py:204` region.
- **ADR:** ADR-M7-1 §3 (flip #2 — safety mirror).

## Sub-plan SP-3.3 — Executor registry + K8s executor (the flip's target)
- **Anchor:** `src/mayhem/controller/executors.py:404` `EXECUTORS` registry + `:421` `def executor_for(` (verified).
- **Change:** add `k8s.exec` family executor (`kubectl exec`) registered in
  `EXECUTORS`; `executor_for(...)` dispatches exec-family k8s faults to it.
  Executor performs the exec-family fault against the **resolved_target** pod via
  `kubectl exec` (admission-checked); compensation flips back the fault. No k8s
  node/lifecycle executors — only exec-family faults; everything else stays
  `k8s.unsupported`.
- **Acceptance criteria:** `executor_for` returns K8s exec executor for exec-family
  faults; k8s lifecycle/node faults still raise `K8sUnsupportedError`.
- **Rollback:** remove executor from registry (revert one line).
- **ADR:** ADR-M7-1 §4, ADR-M7-1 §5 (release-rollback).

## Sub-plan SP-3.4 — Migration: lease `resolved_target` (the executor's resolved pod)
- **Anchor:** migration dir `src/mayhem/domain/persistence/`? — re-anchor via ls on
  first touch; ADR-M7-1 §3.3 (lease `resolved_target` nullable JSON).
- **Change:** add nullable `resolved_target` JSON to FaultLease (0007-0017 chain —
  additive, nullable, backward compatible). Planner/safety flips (SP-3.1/3.2) consult
  it at exec-time; executor (SP-3.3) records resolved pod; compensated/rollback
  clears it.
- **Acceptance criteria:** null-default lease with `resolved_target` populated for
  k8s exec faults, null otherwise; migration reversible (drop column additive).
- **Rollback:** drop column (revert migration).
- **ADR:** ADR-M7-1 §3.3 (lease resolved_target).

---

## Implementation order (verified — option (a))
Flip in this exact order, each independently rollbackable:
1. SP-3.1 planner gate → admit eligible (first — unblocks executor planning seam)
2. SP-3.2 safety gate → mirror the planner gate (safety refuses → admits eligible)
3. SP-3.3 executor registry + K8s executor → dispatch exec-family faults
4. SP-3.4 migration resolved_target → retire the "k8s.unsupported whenever not live"
   assumption, backed by the nullable lease.

Each sub-plan = a one-gate change, individually reversible. Hand to the
implementation agent in this order; proceed to the next only after the current
sub-plan passes its acceptance check.

## Implementation status (applied + verified 2026-09-13)

| Sub-plan | Status | Verification |
|---|---|---|
| SP-3.1 planner gate | ALREADY FLIPPED | `select_one(graph, scope)` at planner.py:620 admits eligible k8s pods; k8s_node returns early |
| SP-3.2 safety gate | FLIPPED | blanket k8s refusal → `select_one(graph, scope)` eligibility admission mirroring planner; k8s_node node-kind scan retained; `from mayhem.domain.target_selector import select_one` added |
| SP-3.3 executor registry | FLIPPED | `K8sExecutor` (executors.py:316) + `_K8S_EXECUTOR` instance (343) + tuple member (438) + `_register_fault_executor("k8s.pod.failure", _K8S_EXECUTOR)` (450); inject refuses with stable message until k-plan-6 |
| SP-3.4 lease migration | **N/A by reality** | No `resolved_target` field/column exists (grep-verified). Lease model (leases.py:64) already carries `targets: frozenset[str]` + nullable `runtime_identity`; `fault_leases` DDL (migrations.py) has no resolved_target column to migrate. Deviation recorded — nothing to flip. |

Validation: `py_compile` OK on both edited files; `pytest tests/unit/test_m7_k8s.py tests/unit/test_safety.py tests/unit/test_planner.py tests/e2e` → **185 passed**.
