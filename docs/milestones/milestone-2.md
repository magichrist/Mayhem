# Milestone 2 — Execution Engine (P0 §4/§5, P1, deferred P0 process-identity/TARGET_DRIFT-detection)

> **Verdict basis:** `docs/answer2.md` §4, §5, §6, §7, §8, §9, §10, §11.
> **Decision locks (grill Q1, Q3, Q4, Q5, Q8, Q10, Q18):** one M2 with many phases; FaultGroup v1; plan non-null ExecutionContext; execution-time revalidation; escalation ladder (framework only); hybrid migrations (in-place until M4).

## 1. Goal

Turn a `PlannedFault` into a **verified, group-aware, cancellable, recoverable mutation** — and never mutate a live system on stale facts. This milestone delivers the execution engine: multi-fault groups with persistent identity, live re-resolution + `TARGET_DRIFT` detection, execution-time capability revalidation, a staged cancellation ladder (grace→term→kill), a mutation-boundary journal, and resource-conflict management. Container faults are fully supported end-to-end; process identity evidence (PID-reuse) is introduced here.

**Out of scope (now):** rootless/podman-specific behaviors, the three-locus ExecutionContext, NetworkPath model (→ M3); network/load fault *archetypes* (→ M6/M8).

## 2. ADR lock (freeze before code)

- **ADR-M2-1 — FaultGroup v1.**
  - `FaultGroup(faults: tuple[InjectFault,...] len≥1, mode: parallel|sequential|best_effort)`.
  - Every executed group carries a **persistent `execution_group_id`** + `group_path` and a `group_mode`; member faults share the group id.
  - `parallel` runs members concurrently; `sequential` runs them one-at-a-time in order; `best_effort` continues past member failures. All three report **partial-failure** as a first-class result (which members succeeded, which failed).
  - `atomic` (all-or-nothing with full compensation) is *demoted*: v1 attempts "all injected, compensations applied on any failure" rather than strong atomicity. Strong rollback-neutralisation is documented, not forced.
- **ADR-M2-2 — Persistent group identity.** `execution_group_id` + `parent_group_id` persisted; `parent_group_id` nullable (nesting is a schema-in-place field now, full nesting in M5 campaigns). Recovery/lease records attribute to groups.
- **ADR-M2-3 — Live inspection wins over stale journal.** At every injection/verification touchpoint, re-resolve the target's `RuntimeIdentity` and compare to planned. On mismatch → `TARGET_DRIFT`, safe-abort that fault. The journal is authoritative for *what was done*, never for *what the target currently is*.
- **ADR-M2-4 — Execution-time capability revalidation.** Before any mutation, re-check the tool/permission/locus capability bundle (using existing `CapabilityReport`/`ToolAvailability`). A capability present at plan time but gone at run time → `FAILED_TO_APPLY` (not a crash).
- **ADR-M2-5 — Non-null plan ExecutionContext.** `ExecutionContext` is **required on every `PlannedFault`** (validated against target-kinds). Authoring-level `execution` field on `InjectFault` stays optional (inference allowed); the **plan** is non-null. Single-locus enum retained; three-locus separation → M3.
- **ADR-M2-6 — Cancellation escalation (framework).** A cancellation token + per-fault deadline; escalation ladder `graceful → timeout → terminate → kill` bounded by a parent deadline; process-group aware (the current `subprocess.run(timeout→SIGKILL)` single-shot path is replaced with staged termination). Final `kill` is guaranteed and unconditional.
- **ADR-M2-7 — Mutation-boundary journal.** A durable journal of each mutation intent→attempt→evidence→registration. `OwnedResource` lifecycle used for resources created during execution. Journal append is the record of record.

## 3. Phases

### Phase 2.1 — FaultGroup data model + persistent group id

**Tasks**
- Add `FaultGroup` (v1 fields above) to `domain/experiments.py`; wire the executor (`controller/executor.py`) to run groups.
- Since the current planner drops `faults[0]` on multi-fault containers (bug), fix plan-time to emit **all** faults with group attribution.
- Add `execution_group_id`/`parent_group_id`/`group_mode`/`group_path` columns in `infra/store.py` (in-place per Q9).

**Acceptance criteria**
- A container spec with N faults plans N fault entries, all sharing a group id; `faults[0]`-only regression is gone (unit `test_planner.py`).
- `parallel`/`sequential`/`best_effort` modes execute per ADR; partial-failure reported as member-level results.
- Integration `test_store.py`: group fields round-trip.

### Phase 2.2 — Live re-resolution + TARGET_DRIFT detection

**Tasks**
- Add a live resolve step in the executor before each mutation: `resolve_container(name)` → current `RuntimeIdentity`; compare to planned.
- On mismatch → terminate that fault safely (no mutation), record `TARGET_DRIFT`, continue per group mode.
- Wire `TARGET_DRIFT` (declared in M1) into outcomes/CLI exit.

**Acceptance criteria**
- Simulated recreation (change container, keep name) → fault records `TARGET_DRIFT`, no mutation applied; tested in `test_executor.py` with a mocked provider.
- Other faults in a `best_effort`/`parallel` group still run; group partial-failure recorded.

### Phase 2.3 — Execution-time capability revalidation

**Tasks**
- Extend the executor touchpoint to re-run the capability bundle (`CapabilityReport`/`ToolAvailability`/privilege) immediately before mutation.
- Map to `FAILED_TO_APPLY` on drift (tool gone / permission lost / locus changed).

**Acceptance criteria**
- Unit `test_agent_capabilities.py`/`test_capability_registry.py`: a capability present in plan, removed at runtime → `FAILED_TO_APPLY`, no mutation.
- Reuses existing `CapabilityReport` — **no new `CapabilityRequirements` schema yet** (that is M3).

### Phase 2.4 — Process identity + PID-reuse evidence

**Tasks**
- Add `ProcessRuntimeIdentity(pid, proc_starttime, pid_namespace)`; supersede `_pid_arg` placeholder on `ProcessNode`.
- Executable/command-line/user captured as **verification evidence**, not identity.
- PID-reuse guard: before signalling a process, verify `proc_starttime` matches; mismatch → treat as drifted target.

**Acceptance criteria**
- Unit `test_resolve.py`/`test_topology.py`: `ProcessRuntimeIdentity` resolves; `starttime` mismatch invalidates a cached pid mapping.
- Kill/stop operations check starttime before acting (unit `test_faults.py`).

### Phase 2.5 — Cancellation escalation ladder (framework)

**Tasks**
- Replace `tool_runner.run_tool`'s single `SIGKILL`-on-timeout with staged: `graceful → timeout → terminate(sigterm) → kill(sigkill)`, process-group aware, bounded by a parent deadline.
- Introduce a `CancellationToken` carried through executor + tool path; compensation-on-kill hook.

**Acceptance criteria**
- Unit `test_tool_runner.py`: a run exceeding `grace` receives `SIGTERM` then, if still alive, `SIGKILL`; process-group children terminated; parent deadline respected.
- No tool-specific kill wiring yet (that's M3/M6) — the framework is generic.

### Phase 2.6 — Mutation-boundary journal + OwnedResource lifecycle

**Tasks**
- Build the journal (intent→attempt→evidence→registration) as a durable append; resources created during execution use `OwnedResource` lifecycle (RESERVED…ORPHANED states).
- Attribute journal entries to `execution_group_id`; lease/compensation per member fault.

**Acceptance criteria**
- Unit `test_observations.py`/`test_resources.py`/`test_recovery.py`: journal append order invariant (intent before attempt before evidence before registration); resource lifecycle transitions valid.
- `janitor`/`watchdog` consume the journal for cleanup (integration `test_agent_watchdog_e2e.py` green).

### Phase 2.7 — Resource-conflict manager

**Tasks**
- One-inflight-writer per resource identity (via `OwnedResource`); concurrent attempts to the same resource → `RESOURCE_CONFLICT` outcome (not a crash).
- Conflict attribution to groups; release on completion/cancellation.

**Acceptance criteria**
- Unit `test_resource_manager.py`: two concurrent faults over the same resource → second is `RESOURCE_CONFLICT`; first completes.
- `test_janitor.py`: released/ORPHANED resources reconciled.

### Phase 2.8 — e2e + backward-compat + regression

**Tasks**
- Run `pytest tests/unit tests/integration`; fix identity-equivalence assertions only.
- Run `tests/e2e` against a real local docker-compose target: a multi-fault parallel drill exercises live re-resolution, journal persistence, group attribution, cancellation (a long fault is cancelled by deadline).
- Verify existing single-fault `kind: drill` specs behave identically (non-breaking, Q2).

**Acceptance criteria**
- Unit + integration green; e2e green (or cleanly skipped when no docker).
- No Mypy/ruff regressions on touched modules.

## 4. Testing / DONE stance (Q18)

**Unit + e2e-where-live.** M2 touches **live mutation**, so it requires the e2e compose drill as a hard DONE gate, not optional. Every phase carries its unit acceptance test; the milestone DONE = all green + e2e exercise of: multi-fault group, TARGET_DRIFT (via controlled recreate), cancellation ladder, journal persistence, conflict.

## 5. Risks / open items

- **Atomicity:** v1 demotes `atomic` to compensate-on-failure; if you later need true all-or-nothing (financial/remote scenarios), revisit in M5/M8 — do not build strong rollback here.
- **Cancellation is framework-only:** killing a specific tool (tc rule, stress-ng) correctly is M3/M6 work; M2 guarantees the engine stops, not that tool side-effects are individually removed.
- **E2E requires docker:** local-only milestones are marked; CI without docker must skip e2e, never fail the suite.
- **In-place schema:** acknowledged churn until M4 freeze (Q9); keep the freeze date/commit marker visible.
