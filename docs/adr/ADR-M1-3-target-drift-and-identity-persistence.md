# ADR-M1-3: TARGET_DRIFT state contract and identity persistence

**Status:** Approved
**Date:** 2026-08-30
**Deciders:** Ali
**Relates to:** ADR-M1-1, ADR-0007, docs/milestones/milestone-1.md Phases 1.3–1.4

## Context

A container recreated mid-run changes `runtime_id` while the authored name stays
stable. Today neither the state machine nor the outcome taxonomy has a word for
"the plan targeted an identity that no longer exists" — such a step looks like a
plain failure. That conflation blocks M2 recovery and runtime adapters.

## Decision

### TARGET_DRIFT is a first-class outcome

A new outcome/state constant, **`TARGET_DRIFT`**, is declared now (M1) and *detected*
in M2:

> `TARGET_DRIFT` = "planned `RuntimeIdentity` no longer matches the live
> `RuntimeIdentity` at execution time".

Semantics — a drifted target is **mismatched, not failed**:

- `TARGET_DRIFT ≠ FAILED_TO_APPLY` — the latter is a capability/permission failure on
  a *present* target.
- `TARGET_DRIFT ≠ RESOURCE_CONFLICT` — the latter is ownership/lease contention on a
  *present* target.
- A drifted target was never the object the plan meant to touch, so it is excluded
  from "release cleanly" bookkeeping; recovery/re-run decisions key on the identity.

The constant belongs to the shared outcome vocabulary in `domain/` so that the
executor, planner, CLI exit mapping, and a future drift **publisher event** all name
the same thing. The publisher callback signature (`drift_event(run_id, step_id,
planned, live) -> None`) is declared in M1; no detection logic ships here.

### Identity is persisted on every record

Execution, registration, and recovery records carry the canonical identity key
(ADR-M1-1) instead of leaning on `container_name` as a foreign key:

- `step_runs.runtime_identity` (execution rows)
- `fault_leases.runtime_identity` (registration/lease rows)
- `observations.runtime_identity` (observed-event rows)
- `recovery_records` / `recovery_audit_log.runtime_identity` (recovery rows)
- `runs.runtime_identity` (reserved; NULL until a run is single-identity)

`targets_json` / `container_name` columns are retained unchanged during M1 so the
store is readable by every pre-M1 tool.

### Schema freeze point

Per Q9 (hybrid migrations): **in-place schema change is allowed through M1 only**.
Identity columns and the canonical key freeze at **M4**; after M4 the identity
columns are the only supported target key and no further alteration of the identity
shape is permitted without a new ADR.

## Migration / implications

- Migration `M0006_RUNTIME_IDENTITY` rebuilds `step_runs` (adding `runtime_identity`
  and admitting `target_drift` in the status CHECK) and adds nullable identity columns
  to `runs`, `fault_leases`, `observations`, and `recovery_records`.
- Store readers gain identity-based lookup; `container_name` remains a read alias.

## References

- ADR-M1-1, ADR-M1-2, ADR-M1-4; Phase 1.3/1.4 acceptance in milestone-1.md.