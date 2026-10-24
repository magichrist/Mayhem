# Plan 28 — Production Experiment Execution Checklist

Status: **checklist live.** Meta document: the operator spine for every
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

## STATUS — checklist live; every item's owning plan has landed, and two items are now enforced by tests rather than by review

Every item's owning plan is in `docs/v1.1.0/` and each carries its own `## STATUS`
block, which is the authoritative per-item state. Items become enforceable as
their owning plans land — they have.

Two are enforced mechanically today, not by review:

- the plan-document honesty gates, `tests/unit/test_*_plan_docs.py` (eight
  suites) plus `tests/unit/test_plan_doc_status_blocks.py` over the whole
  directory;
- the evidence-boundary completeness guard,
  `tests/unit/test_evidence_boundary.py`, which compares `(module, function)`
  pairs in both directions so a new gated write path cannot drift out of the
  table.

Items still open are the live ones: the Kubernetes DaemonSet transport and the
live-cluster cells (`02_KUBERNETES_RUNTIME.md` Phases 4–5), and the enterprise
walkthrough's live-site clause (`20_ENTERPRISE_PRODUCT_HARDENING.md` Phase 4).
Each needs a cluster, an IdP or a human, not missing code.
