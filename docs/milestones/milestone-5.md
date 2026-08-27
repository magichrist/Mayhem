# Milestone 5 — Intelligence: Run/Outcome, Coverage, Campaigns & Autonomous Maniac (P4, §20–24)

> **Verdict basis:** `docs/answer2.md` §20 (ExperimentCandidate), §22 (distinct Run vs Outcome), §23 (coverage-as-objective), §24 (campaign semantics), §25 (Maniac), §26 (novelty) — and §10-seed from the original doc.
> **Decision locks (grill Q14, Q15, Q18):** build the **full autonomous Maniac** selection/optimization engine (Q14); executions gated by a per-campaign `mode` — `supervised` (human confirms each drill, default) or `autonomous` (auto-run within blast-radius + stop-condition + resource-conflict bounds, explicit opt-in) (Q15); **unit + e2e-where-live**.

## 1. Goal

Give Mayhem the ability to *reason about what to poke next*. This milestone builds the intelligence layer: a clean `Run` vs `Outcome` separation, `ExperimentCandidate` generation, coverage-as-objective accounting, campaign semantics, and the autonomous Maniac engine that picks experiments against recorded history — with execution behind a human gate by default.

**Out of scope (now):** full declarative `targets/operations` grammar (M4 was additive; step/tooling beyond the DSL is a later concern); network/load fault *implementation* (M6/M8); remote-k8s runtime.

## 2. ADR lock (freeze before code)

- **ADR-M5-1 — Run and Outcome are distinct.**
  - `Run`: *what was executed* — experiment spec, faults, groups, cancellation, journal refs, verdict, duration, tool evidence.
  - `Outcome`: *what happened* — observed post-run system state, checks passed/failed, metric deltas, residual effect, stability/recovery signal.
  - They persist separately and link by a run→outcome reference. A `Run` is never conflated with its `Outcome`.
- **ADR-M5-2 — ExperimentCandidate.**
  - `ExperimentCandidate(target, fault-kinds, params, execution-context, expected-effect, risk-band)`.
  - A candidate is a *proposal*, created by generation or Maniac, and passes through Safety → Feasibility → Resource-conflict gates before it is executable. (The M2 resource-conflict + M3 capability machinery gate a candidate, reusing the same checks.)
- **ADR-M5-3 — Coverage is the objective.**
  - Coverage is measured over the landscape of (target, fault-kind, execution-context, parameter-band). A recorded `Outcome` for a cell increments coverage. Maniac optimizes coverage + novelty while respecting risk bands and a novelty guard against repetition.
- **ADR-M5-4 — Campaign semantics.**
  - A campaign is a *goal + bounds*: a target set, a coverage target or stop condition, a blast-radius budget, a `mode` (`supervised` | `autonomous`), a time/deadline bound, and policy constraints (never exceed blast budget; respect resource conflicts; respect per-campaign risk ceiling).
  - A campaign produces many `Run`/`Outcome` pairs; it completes when the stop condition is reached, the budget is exhausted, or the deadline passes.
- **ADR-M5-5 — Human gate by default.**
  - `supervised` (default): Maniac selects + scores the next candidate, but the **drill does not execute until a human approves it**.
  - `autonomous`: Maniac executes selected drills directly, but **only within** the campaign's blast-radius + stop-condition + resource-conflict + risk-ceiling bounds. Autonomous is an explicit, safe-bound opt-in.
  - There is no unguarded mode that ignores these bounds.

## 3. Phases

### Phase 5.1 — Run/Outcome domain + persistence

**Tasks**
- Add `Run` and `Outcome` models; persist separately (M4-frozen schema + new migration M5-1).
- Link runs→outcomes; record the M4 `SuccessCriteria` verdict into `Outcome`.

**Acceptance criteria**
- Unit `test_campaigns.py`: a completed drill yields exactly one `Run` and one linked `Outcome`; fields round-trip; no conflation.
- Integration `test_store.py`: migration M5-1 applied; run/outcome queryable.

### Phase 5.2 — Coverage accounting

**Tasks**
- Define the coverage cell; a recorded `Outcome` marks its cell seen.
- Coverage record persists; query for covered/`UNKNOWN` cells.

**Acceptance criteria**
- Unit `test_campaigns.py`: coverage increments per distinct cell; re-running the same cell does not double-count; `UNKNOWN` cells are enumerable.

### Phase 5.3 — Candidate generation + gates

**Tasks**
- Seeded generator produces `ExperimentCandidate`s over the target/fault/context/param landscape.
- Route each candidate through Safety → Feasibility (M3 verdicts) → Resource-conflict (M2) gates; a candidate that fails a gate is rejected with a reason, not executed.

**Acceptance criteria**
- Unit `test_campaigns.py`/`test_safety.py`: generator output is valid; every executable candidate passed all three gates; rejected candidates carry a reason.

### Phase 5.4 — Campaign semantics + execution loop

**Tasks**
- Implement campaign lifecycle: init → iterate (generate/select → gate → run) → stop (coverage target / budget exhausted / deadline / stop-condition).
- Campaign attributes each `Run`; a campaign's `mode` gates execution.

**Acceptance criteria**
- Unit `test_campaigns.py`: a bounded campaign iterates and stops correctly on each stop-condition path; budget and deadline respected.
- `supervised` campaign never executes a drill without an approve signal (unit `test_campaigns.py` + CLI gate).

### Phase 5.5 — Maniac selection/optimization engine (autonomous core)

**Tasks**
- Maniac scores candidates against RecordedHistory: coverage gain, novelty, risk-band, expected-value.
- Selection loop: pick next candidate by objective; novelty guard breaks repetition; risk ceiling respected.
- The *selection* engine is fully real regardless of mode (Q14).

**Acceptance criteria**
- Unit (e.g., `test_maniac.py`): with a seeded history, Maniac selects a non-repeating, coverage-advancing, risk-bounded candidate; a history showing the top cells already covered shifts selection to `UNKNOWN` cells.
- Deterministic against a fixed history (seeded) — no flaky ordering.

### Phase 5.6 — Supervised ↔ autonomous execution gate

**Tasks**
- Wire the campaign `mode` into the execution path.
- `supervised`: emit a pending candidate + scored rationale to the CLI/interactive layer; execute only after approval; capture the approve/deny into the campaign log.
- `autonomous`: execute directly within bounds; add the protective checks (blast-radius, resource-conflict, deadline) as hard aborts.

**Acceptance criteria**
- Unit `test_campaigns.py`: `supervised` blocks until approval; denied candidates are skipped/recorded; `autonomous` executes within bounds; a violating candidate (over blast budget / resource conflict) is aborted with `RESOURCE_CONFLICT`/bound-abort, never executed out of bounds.

### Phase 5.7 — Report + experiment guidance (rich report)

**Tasks**
- Consume `Run`+`Outcome` into the rich report; present coverage heatmap, per-cell verdicts, supported-by evidence, candidate backlog ranked by Maniac score.
- Expose the untouched/`UNKNOWN` high-priority cells as the guided "what to run next" list.

**Acceptance criteria**
- Test the report builder against a populated history: coverage heatmap renders; the next-candidate list is non-empty and ranked; evidence links to specific runs.
- (Model-only judgment; string/report assertions in unit tests.)

### Phase 5.8 — e2e + regression

**Tasks**
- Full unit/integration suite + e2e: a small `supervised` campaign over a real compose target runs and records Run+Outcome; Maniac proposes a next candidate.
- No Mypy/ruff regressions.

**Acceptance criteria**
- Unit + integration green; e2e green (supervised campaign on local docker; autonomous exercised for the abort-bound paths with a short bounded campaign).

## 4. Testing / DONE stance (Q18)

**Unit + e2e-where-live.** M5 runs real drills via campaigns, so e2e is required for at least the supervised path. Maniac selection/coverage/gates are unit-testable against seeded histories (deterministic).

## 5. Risks / open items

- **Full autonomous Maniac is large:** the selection engine is the heavy lift; keep it decoupled from execution so `supervised` reuse is trivial and `autonomous` stays opt-in.
- **Coverage metric definition drift:** cells must be stable and well-defined (target/fault/context/param) or coverage is meaningless; freeze the cell definition in ADR-M5-3 before algorithms lean on it.
- **Determinism:** use seeded generation + seeded history so tests and reproducible selection hold; document the seed.
- **Autonomous safety is a hard guarantee:** the blast-radius/resource-conflict/deadline aborts must be uncatchable-safe (checked in the executor, not only the selection layer) — a runaway autonomous campaign is the worst failure this milestone could ship.
- **Maniac "learning" scope:** this milestone is a deterministic objective engine over recorded history (coverage+novelty+risk). If you later want ML-driven prediction, it slots in behind the `ExperimentCandidate` selection interface — do not couple now.
