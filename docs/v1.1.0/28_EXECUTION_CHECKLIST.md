# Plan 28 — Production Experiment Execution Checklist

Status: **planning only.** Meta document: the operator spine for every
production run. Each item names its owning plan; an unchecked item
blocks execution, and a check without cited evidence is a defect in the
check, not a pass.

Before execution:
- [ ] experiment version pinned (16/22 pin rule)
- [ ] target set resolved (02 resolution, frozen in plan)
- [ ] environment identified (09 org model, 20 deployment)
- [ ] topology impact calculated (14 prediction sealed with plan)
- [ ] safety proof generated (30 proof output)
- [ ] required capabilities available (03 `can_apply` at the boundary)
- [ ] risk policy evaluated (07 decision with digests)
- [ ] damage budget available (07 hierarchical ledger)
- [ ] resource budget available (23 dimensions)
- [ ] cloud cost budget checked (06 estimate vs. 07 ceiling)
- [ ] preflight checks passed (10 preflight; warn-and-continue forbidden)
- [ ] stop conditions compiled (11 definitions pinned)
- [ ] compensation plan verified (planner refuses uncompensated faults)
- [ ] required approvals present (09 digest-bound approvals)
- [ ] secrets resolved via references only (29; plaintext fails validation)
- [ ] agent health verified (03 heartbeat plus capability report)
- [ ] plan digest frozen (canonical hash; any change restarts this list)

During execution:
- [ ] resource reservations active (07 locks)
- [ ] events emitted (08 live stream)
- [ ] observations stored (11 collector, best-effort plus bounded)
- [ ] stop conditions evaluated (11 evaluator → 10 enforcement)
- [ ] heartbeat maintained (03 fabric)
- [ ] leases/fencing enforced (03 single-owner rule)
- [ ] budget continuously checked (07 plus 23 dimensions)

After execution:
- [ ] compensation completed (undo contracts, never-raise discipline)
- [ ] residue scan completed (01 scan definition; dirty stays dirty)
- [ ] postflight checks passed (10 postflight report)
- [ ] SLO state evaluated (11 verdict inputs cited)
- [ ] verdict generated (graded verdict, no-effect first-class)
- [ ] raw evidence sealed (12 chain plus provenance edges)
- [ ] evidence signed (12 manifests; gate NOT APPLICABLE until 12 lands)
- [ ] report generated (20 report inputs, 34 rendering)
- [ ] coverage/regression data updated (22 cells plus comparisons)
- [ ] resource locks released (07 ledger closeout)

## STATUS — planning only, 0%
Checklist defined; items become enforceable as their owning plans land.
