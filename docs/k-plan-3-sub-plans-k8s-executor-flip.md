# k-plan-3 — sub-plans (k8s executor flip; ADR-M7-1)

Status: sub-planning complete — proceed to implement each sub-plan in order.
Governing chain: ADR-M7-1 (ADR-M7-1 §3 design / §4 acceptance / §5 release-rollback) ← k-plan-3 §3.5 ← k-plan-2 §2.5 ← k-plan-1 §1.2. Discovery/ADR anchor report: `docs/adr-adr-m7-1-k8s-executor-flip.md` + `docs/m7-k8s-executor-discovery.md` (both on disk, read-verified this session).

## Sub-plan SP-3.1 — Planner selection gate flip
- File: `src/mayhem/controller/planner.py` gate at `planner.py:606` `_gate_k8s_selection_eligibility(` (verified this session); call site `planner.py:281`? — re-grep on first touch (§8 caveat: region has live LSP diagnostics mid-refactor).
- Change: flip the eligibility gate from blanket `k8s.unsupported` refusal → admit *exec-family* faults against a live eligible k8s target pod; keep refusing pod-lifecycle / node / workload / `k8s_node` targets. Gate refuses → plans k8s faults.
- Acceptance: exec-family fault against eligible live pod **plans**; blanket refusal becomes per-family capability admission; eligibility gate function unchanged in behavior for daily/lifecycle families (still `k8s.unsupported`).
- Rollback: revert the one gate line. Anchor for first touch: `planner.py:606`.

## Sub-plan SP-3.2 — Safety gate flip
- File: `src/mayhem/controller/safety.py:204` `_check_k8s_targets(` (verified this session); call site `safety.py:281` (inside `validate_plan`).
- Change: flip the blanket safety refusal (`k8s.unsupported` / `SafetyError`) → mirror the planner's per-family eligibility gate: admit exec-family faults against eligible live pods, refuse pod/node/k8s_node targets via `k8s.unsupported`.
- Acceptance: `validate_plan` no longer refuses exec-family k8s plans against eligible pods; safety gate falls back to `SafetyRefusedError` only for genuinely unsupported families.
- Rollback: revert the one gate line at `safety.py:204`.

## Sub-plan SP-3.3 — Executor registry + K8sExecExecutor
- File: `src/mayhem/controller/executors.py` — `EXECUTORS` tuple + `executor_for(...)` dispatch (verified anchors: `executors.py:404/421`).
- Change: add `K8sExecutor` (kubectl-exec family, `k8s.unsupported`-capable — the executor that admits exec-family faults and refuses the rest) to the registry; dispatch `FaultLease.resolved_target` for lease-compensable exec.
- Acceptance: `executor_for(fault)` returns the K8s executor for an exec-family k8s fault; no other family regress; rollback = remove one registry line.

## Sub-plan SP-3.4 — Lease `resolved_target` migration (0017) + ADR sync
- Files: `src/mayhem/domain/leases.py` (FaultLease, add nullable `resolved_target` for the executor's lease-resolved target), migration `0007`→`0017` on disk if the lease merge doc requires it.
- ADR: `docs/adr-adr-m7-1-k8s-executor-flip.md` — mark flip RECORDED (status flip from planned → recorded/flip-ordered).
- Acceptance: `resolved_target` nullable + backward-compatible; no `k8s.unsupported` regression; migration reversible (drop column).

## Execution order & implementer contract
Each sub-plan is independently rollbackable by reverting its single gate line / registry line. Implement in order 3.1 → 3.2 → 3.3 → 3.4. Re-grep anchors on first touch (region currently carries live LSP diagnostics; line numbers verified this session are the discovery baseline and may drift).
