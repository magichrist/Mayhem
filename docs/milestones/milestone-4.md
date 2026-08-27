# Milestone 4 — DSL: Additive Checks, SuccessCriteria, Observability, Duration Fix (P3, §17–19, §21)

> **Verdict basis:** `docs/answer2.md` §17 (new top-level structure as *compiled shorthand*), §18 (machine-evaluable success criteria), §19 (checks execution-locus), §21 (observability/metrics sources).
> **Decision locks (grill Q9, Q13, Q18):** **additive, non-breaking** (Q13); `containers:`+`execution:` stay the primary non-breaking path; add execution-locus-aware checks + machine-evaluable `SuccessCriteria`/assertions + observability/metrics sources as optional keys; **schema freeze + versioned migrations start here** (Q9); fix the `Duration`-string typing bug found during review.

## 1. Goal

Extend the drill DSL *without breaking anything* to support the observation/evaluation backbone that M5's autonomous Maniac depends on: execution-locus-aware **checks**, **machine-evaluable success criteria**, and **observability/metrics sources**, all optional and additive. Fix the real `Duration`-represents-`float`-but-specs-pass-`"3s"` type bug surfaced by the review. Freeze the execution/identity/ownership schema and introduce versioned migrations (Q9).

**Out of scope (now):** the full `targets/operations` grammar restructure (documented relationship only, post-GA option); no change to container-name-keyed DSL authoring.

## 2. ADR lock (freeze before code)

- **ADR-M4-1 — Additive DSL sections.** Introduce optional top-level `checks`, `success`, `observability` (and reserve `metrics`) keys alongside existing `containers:` + `execution:`. `containers:` remains the primary authoring path; any new relation to a future `targets/operations` grammar is documented as a convenience-target relationship, **not** a forced migration.
- **ADR-M4-2 — Execution-locus checks (≥ §19).** A check declares `execution` (where the check runs: host / container / service / process) and is evaluated *at that locus*, distinct from the fault target. No check silently assumes its target's locus.
- **ADR-M4-3 — Machine-evaluable SuccessCriteria (§18).** Success is an objective, machine-evaluable predicate over recorded observations — never a human eyeball. Assertions are typed (status, latency bound, metric threshold, count, boolean) and evaluated by the engine; a drill's success/failure verdict is derived from these.
- **ADR-M4-4 — Observability/metrics sources (§21).** Sources (container logs, inspect, external probe, metrics endpoint) are declared additively; observations are replayed/collected per source into the outcome record. Metrics sources are optional; polling cadence + timeout are bounded.
- **ADR-M4-5 — Schema freeze + versioned migrations (Q9).** The execution/identity/ownership schema introduced across M1–M3 is **frozen**; introduce versioned forward migrations (`infra/migrations.py` gains proper sequencing) from this milestone onward. In-place dev-DB drops end here.

## 3. Phases

### Phase 4.1 — Fix Duration string typing (pre-existing bug)

**Tasks**
- Resolve the `Duration` mis-typing: specs pass `"3s"`, `"30m"`, `"10s"`; the field type is `float`. Introduce a proper duration value type (e.g., `Duration` parsed from `"3s"`/`"30m"` → seconds) so `tests/unit/test_planner.py`, `test_drill_spec.py`, `test_faults.py` type-check and stay semantically identical.
- Keep YAML authoring identical (strings accepted); the model normalises to a numeric duration internally.

**Acceptance criteria**
- Mypy clean on `experiments.py`/`planner.py`/`tests/unit/test_planner.py` Duration paths (these are the exact diagnostics the review surfaced).
- Existing `"3s"`/`"5s"`/`"30m"` specs parse to the identical runtime behaviour (unit `test_drill_spec.py`).

### Phase 4.2 — Execution-locus checks

**Tasks**
- Add `CheckSpec` with explicit `execution` locus (host/container/service/process) + probe type (`http`, `tcp`, `process`, `metric`, `file`).
- The executor evaluates checks at their declared locus (uses M2/M3 locus machinery; single-locus inference = locus == fault target for backward compat).

**Acceptance criteria**
- Unit `test_drill_spec.py`/`test_executor.py`: a container-locus check probes inside the container; a host-locus check probes the host; a bare (unqualified) check infers the fault-target locus (pre-0.3.0 behaviour).
- `CheckExpectation`/`CheckProbe` wired into execution and recorded in the journal.

### Phase 4.3 — Machine-evaluable SuccessCriteria

**Tasks**
- Add `SuccessCriteria` as typed, machine-evaluable assertions (status/latency/threshold/count/boolean) over recorded observations.
- The engine computes the drill verdict (`succeeded`/`failed`) from criteria; verdict feeds the outcome record (consumed by M5).
- Wire into CLI/report so a drill's pass/fail is objective and reproducible.

**Acceptance criteria**
- Unit `test_planner.py`/`test_executor_drill.py`: a drill with a latency-bound criterion is judged by measured latency; a status-code criterion by the check status; missing observation → criterion evaluates false (not a crash).
- Verdict is deterministic and stored.

### Phase 4.4 — Observability/metrics sources

**Tasks**
- Add `observability` source config (container logs, inspect, external probe, metrics endpoint) with bounded cadence/timeout.
- Sources collect into the outcome record; sources are optional and additive.

**Acceptance criteria**
- Unit `test_observations.py`: each source type collects per its cadence/timeout; a misbehaving source fails gracefully (skip with a recorded note, non-fatal) and never blocks the drill past its bound.

### Phase 4.5 — Versioned migrations + schema freeze

**Tasks**
- Freeze the M1–M3 schema; build versioned migration scaffolding in `infra/migrations.py` with a sequence + up/down.
- Migration for the new `checks`/`success`/`observability`/`duration` fields added as version `N+1`.

**Acceptance criteria**
- `tests/unit/test_migrations.py` / `tests/integration/test_store.py`: a DB at the frozen schema migrates forward to the M4 schema; down-migration restores it.
- No in-place schema replacement beyond this milestone (enforced by policy + the migration scaffold).

### Phase 4.6 — Backward-compat + full regression

**Tasks**
- Verify all pre-existing `tests/unit` parse+run **unchanged** (Q2 non-breaking) — only Duration-typing assertions touched.
- Full suite + e2e against a local compose target using `containers:`-keyed drill with the new additive checks/success.

**Acceptance criteria**
- `pytest tests/unit tests/integration` green; e2e green against real compose with checks+success+evaluation running.
- No Mypy/ruff regressions (including the Duration fix).

## 4. Testing / DONE stance (Q18)

**Unit + e2e-where-live.** M4 adds evaluation/observation of **live drill results**, so e2e is required to prove checks+success verdicts end-to-end. Model-only portions (type parsing) need unit coverage.

## 5. Risks / open items

- **Additive ≠ canonical:** until a later decision, `targets/operations` remains a documented direction, not implemented — avoid half-adding it or you'll lose non-breaking status.
- **Duration fix must not change semantics:** the point is typing correctness, not changing how `"5s"` behaves. Guard with `test_drill_spec.py`.
- **Schema freeze is a commitment:** from M4, changes go through migrations; plan schema thrash to stop now (Q9 agreed).
- **Observability scope creep:** "metrics endpoint" sources could balloon; cap to the listed source types + bounded cadence this milestone (full collectors → M8).
