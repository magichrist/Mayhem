# k-plan-4 sub-plans — implementation sequence

> **Implemented 2026-09-13.** Each sub-plan is independently testable. Follow
> the order — later plans depend on earlier anchors.

---

## Implementation status (applied + verified 2026-09-13)

| Sub-plan | Status | Verification |
|---|---|---|
| SP-4.1 selection grammar flip | **DONE** | `select_many` (target_selector.py) dispatches one/count/percentage/all/random with `_dispatch`; `select_one` = legacy single-pod view. Planner/SP-3.2 safety gates now call `select_many`; `_require_implemented_selection` + reserved-mode refusals deleted; `conflict.overlap` guard in `_plan_target_faults`; `selection.out_of_budget` enforced against `BlastRadiusBudget.max_concurrent_faults`. Node-kind target still reserved (k-plan-5). Tests: `tests/unit/test_selection_modes.py` (24 cases). |
| SP-4.2+ | PENDING | queue order preserved |

Validation: `pytest tests/unit` → **423 passed, 2 skipped**; `ruff check` clean on modified files; `mypy` clean on modified modules.

---



## SP-4.1 Selection grammar flip (driver-independent)

**Anchor sites (post-SP-4.1):**
- `target_selector.py` — `select_many` (multi-mode dispatch) + `_dispatch` +
  `_deterministic_key`; `select_one` = single-pod view over `select_many`
- `planner.py` — `_require_implemented_selection` deleted;
  `_gate_k8s_selection_eligibility` calls `select_many`;
  `_require_no_selection_conflict` (conflict.overlap) wired into
  `_plan_target_faults`; `RESERVED_SELECTION_MODES` import removed
- `safety.py` — `_check_k8s_targets` calls `select_many` (SP-3.2 flip)

**Flip target:** replace all reserved-mode refusals with real multi-mode
selection; enforce `selection.out_of_budget` and `conflict.overlap` errors.
**Status: DONE (see table above).**

**Error vocabulary (k-plan-4 §4.2):**
- `selection.count_exceeds_eligible` — requested count > eligible pods
- `selection.out_of_budget` — picked set exceeds `BlastRadiusBudget.max_concurrent_faults`
- `conflict.overlap` — two multi-instance fault steps on one target share a pod

**Key design note (reality adaptation):** k-plan-4 doc references
`config.max_faults`; no such field exists. Budget enforcement uses the real
knob: `BlastRadiusBudget.max_concurrent_faults` (experiments.py). The
`out_of_budget` error message points there. Deviation recorded in SP-4.7.

---

## SP-4.2 Config — `recovery_grace`

**Anchor:** `config.py:126 MayhemConfigBase` (currently no `recovery_grace`).

**Flip:** add `recovery_grace: float = Field(default=300.0, gt=0)` to
`MayhemConfigBase`. No migration needed (Pydantic value object, not a stored
column). Expose via `config show`.

**Scope gate:** This config key exists for SP-4.5 (compensation watcher).
SP-4.2 adds the knob; SP-4.5 consumes it.

---

## SP-4.3 Live cluster driver (biggest jump)

**Anchor:** `k8s_adapter.py:57 KubernetesAdapter` (stub; `is_available → False`)

**Flip:** real kubectl-based transport (no mandatory `kubernetes` pip dep —
the optional dep stays optional). `is_available()` checks for a reachable
kubeconfig context. `list_pods` runs `kubectl get pods ... -o json`.
Capability matrix flips to SUPPORTED for pod-lifecycle faults (kill/evict/oom)
+ policy (network_policy). Execution methods (`exec`, `signal`, etc.)
raise `NotImplementedError` until SP-4.4 wires the individual executors.

**Test:** real kubectl tests autoskip in CI (no cluster in CI); local
tests require live cluster + `kubeconfig` present.

---

## SP-4.4 Pod lifecycle executors + lease state wiring

**Anchor:** `executors.py:316 K8sExecutor` (current — refuses inject)

**Sub-flips:**
- `K8sPodKillExecutor` — `delete pod` (grace_period param)
- `K8sPodEvictExecutor` — Eviction API (PDB-aware; server-refused → run note)
- `K8sPodOomExecutor` — memory-usage spike via `kubectl exec` + kill -9
- `K8sPodPressureExecutor` — reuse k-plan-3 exec plumbing per selected container
- `K8sNetworkPolicyExecutor` — apply temp deny policy; undo = delete policy

**Lease states:** injecting → compensating → recovered; `pod_action` evidence
JSON (`delete`, `eviction`, `oom`, `policy_apply`).

---

## SP-4.5 Reconciliation compensation (k8s branch)

**Anchor:** `compensation.py` (k8s template + verify).

**Sub-flips:**
- `CompensationTemplate` k8s branch: `undo=NOOP`, verify=[readiness, endpoint]
- readiness watch: wait for replacement pod (uid differs) to hit
  Running+Ready within `config.recovery_grace` (SP-4.2)
- endpoint verify: only when workload is behind a Service
- timeout → `compensation_timeout` lease state; janitor loop continues watching
- `recovery: false` leaves post-mutation window observable (no compensation)

---

## SP-4.6 Docs + e2e autoskip + full test/ruff/mypy gate

- drill-spec.md k8s examples (count/percentage/all/random)
- compensation semantics table update
- features.md M8 → pod-level + reconciliation live
- e2e: pod_kill round → Ready replacement → endpoints healthy; autoskip
  without cluster; eviction with PDB honored

---

## SP-4.7 Deviation notes

| Doc reference | Reality | Record |
|---|---|---|
| `config.max_faults` (k-plan-4 §4.2) | No such field exists | Budget = `BlastRadiusBudget.max_concurrent_faults` (experiments.py); error points there |
| `lease.resolved_target.pod_action` (§4.6 task 1) | `resolved_target` field doesn't exist (plan-3 SP-4.7 N/A) | `pod_action` stored in evidence JSON on `ObservationRecord`; no lease migration |
| `max_faults` config show (§4.6 task 1) | Same as row 1 | `blast_radius.max_concurrent_faults` shown in config show |
