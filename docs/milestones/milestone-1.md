# Milestone 1 — Container Identity (P0 §1, §2-container-only)

> **Verdict basis:** `docs/answer2.md` P0 items 1–3, container half.
> **Decision locks (grill Q1, Q2, Q3, Q18):** container identity only; full backward compat; `TARGET_DRIFT` state defined here (ADR) but detected in M2; acceptance = unit + e2e-where-live.

## 1. Goal

Eliminate `container_name`-as-identity once and for all on the **container** path. Every persisted plan/execution/recovery record must carry a stable `RuntimeIdentity` (runtime + host_id + runtime_id), resolved from an authored `container_name`/`service` key, so that a container recreated mid-run is recognized as drifted — not silently treated as the same target. This is the foundation that M2's `TARGET_DRIFT` detection, M2's recovery, and every later runtime adapter depend on.

**Out of scope (now):** process identity (`ProcessRuntimeIdentity`/pid+starttime+pid_namespace), `TARGET_DRIFT` *detection*, the three-locus ExecutionContext, rootless podman behavior. These land in M2/M3.

## 2. ADR lock (freeze before code)

New ADR(s) replacing the informal `container_name` conventions:

- **ADR-M1-1 — RuntimeIdentity is the identity; container_name is a resolver key.**
  - `RuntimeIdentity(runtime: str, host_id: str|None, runtime_id: str)` is the equality key.
  - `container_name`/`service` live only in `RuntimeMetadata` and as *authoring* resolver keys — never identity equality.
- **ADR-M1-2 — RuntimeMetadata is descriptive, not identity.**
  - `RuntimeMetadata(project, service, name, labels, created_at, started_at)` — all mutable/descriptive; explicitly not part of equality.
  - Identity equality compares `runtime + host_id + runtime_id` only.
- **ADR-M1-3 — TARGET_DRIFT state contract (declared here, implemented M2).**
  - New outcome/state `TARGET_DRIFT` = "planned `RuntimeIdentity` no longer matches the live `RuntimeIdentity` at execution time".
  - Semantics: distinguish from `FAILED_TO_APPLY` (capability/permission failure) and `RESOURCE_CONFLICT` (ownership/lease contention); a drifted target is *not failed*, it is *mismatched*.
- **ADR-M1-4 — Backward compatibility.**
  - Authored YAML may key by `container_name`/`service` only; the **plan and all persisted records resolve to and carry `RuntimeIdentity`**.
  - Any existing `kind: drill` spec and the current un-mocked unit test suite must keep passing unchanged (except where a test asserted `container_name` in a *persisted/plan* record — those assertions are updated to `RuntimeIdentity`, preserving semantic equality).

## 3. Phases

### Phase 1.1 — Introduce `RuntimeIdentity` + `RuntimeMetadata` value objects

**Tasks**
- Add `RuntimeIdentity(runtime, host_id, runtime_id)` in `src/mayhem/domain/identity.py` with `__eq__`/`__hash__` on the three identity fields only; `resolve_key()` helper.
- Add `RuntimeMetadata(project, service, name, labels, created_at, started_at)`; `from_compose_labels()` and `from_inspect()` helpers.
- Wire into `topology/`: replace the ad-hoc `runtime_id`/`host_id`/`service_name`/`container_name` fields on `ContainerNode` with a `runtime_identity: RuntimeIdentity` + a `runtime_metadata: RuntimeMetadata|None`.
- Keep `ContainerNode.container_name` as a *resolver key* (non-null, still usable by DSL) but mark it deprecated-in-identity-context.

**Acceptance criteria**
- `RuntimeIdentity("docker","h1","c1") == RuntimeIdentity("docker","h1","c1")` and `!=` when any of runtime/host_id/runtime_id differ (name is irrelevant to equality).
- `RuntimeIdentity` hash-stable and usable as a dict/mapping key.
- `ContainerNode` carries `runtime_identity` everywhere `runtime_id`/`host_id` previously appeared; `container_name` remains present as a resolver key.

### Phase 1.2 — Resolve plan records to `RuntimeIdentity`

**Tasks**
- In `controller/planner.py` + `domain/experiments.py` `PlannedFault`/`PlannedStep`/`ExecutionPlan`: add `runtime_identity: RuntimeIdentity` (planned) next to `container_name`.
- `resolve.py` `resolve_container(name)` → returns `(RuntimeIdentity, RuntimeMetadata)`; planner stores identity on every fault/step.
- Ensure `containers-referencing` analysis (existing multi-target logic) resolves each name to its identity before planning.

**Acceptance criteria**
- `ExecutionPlan.steps[*].runtime_identity` is populated (non-null) for every container-targeted fault when a provider is available.
- Regression: `tests/unit/test_planner.py` container-name-based assertions pass with identity-equivalent mapping.

### Phase 1.3 — Persist identity in store + recovery records

**Tasks**
- In `infra/store.py`: execution/registration/recovery tables carry `runtime/` + `host_id` + `runtime_id` columns (or a canonical `runtime_identity` key) instead of relying on `container_name` as the foreign key.
- Recovery/lease records (`leases.py`, `recovery.py`, `janitor.py` touchpoints) index by `RuntimeIdentity`.
- Per Q9 (hybrid migrations): **in-place schema change allowed** this milestone; note the freeze point (M4) in the ADR.

**Acceptance criteria**
- A persisted execution row round-trips its `RuntimeIdentity` and is queryable by identity.
- `tests/unit/test_lease_repository.py`, `test_observations.py`, `test_recovery.py`: identity-based lookups pass.
- A `container_name` change in metadata does not change the persisted identity key.

### Phase 1.4 — `TARGET_DRIFT` state + outcome contract (declared only)

**Tasks**
- Add `TARGET_DRIFT` to the outcome/state enum and to the failure/outcome taxonomy in `domain/` (errors + planner + CLI exit mappings).
- Define the publisher/types signature for a future drift event (no detection logic here).
- Document that `TARGET_DRIFT ≠ FAILED_TO_APPLY ≠ RESOURCE_CONFLICT` in the ADR and in error-class docs.

**Acceptance criteria**
- `TARGET_DRIFT` is a first-class outcome constant; serializes into persisted outcome records.
- `tests/unit/test_domain_properties.py` covers the new enum value as a state (single possible next-states / invariant checks set per ADR).

### Phase 1.5 — Backward-compat verification + e2e smoke

**Tasks**
- Run the full `tests/unit/**` suite; fix only identity-equivalence test assertions (never DSL-meaning).
- Run `tests/integration/test_store.py` (store path with identity columns).
- Run `tests/e2e/test_cli_e2e.py` against a real local docker-compose target: author a drill by `container_name`, confirm it plans/executes and records against `RuntimeIdentity`.

**Acceptance criteria**
- `pytest tests/unit tests/integration` green.
- `pytest tests/e2e` green against a live local docker engine (or explicitly marked `@pytest.mark.e2e` and skipped cleanly when docker absent — never silently failing).
- No Mypy/ruff regressions on touched modules.

## 4. Testing / DONE stance (Q18)

Per the acceptance bar: **unit + e2e-where-live**. M1 touches no live mutation (it's identity plumbing), so the DONE bar is: all unit + integration tests green, no lint/Mypy regressions, and the e2e CLI smoke green against a local docker target where available.

## 5. Risks / open items

- **Drift window before M2:** until M2 adds live re-validation, a recreated container is *still not detected* at runtime — M1 only makes it detectable. This is accepted and gated to M2.
- **`node_pid` ambiguity:** process identity remains on the old `_pid_arg` path until M2; document that `ProcessRuntimeIdentity` supersedes it (do not build on `_pid_arg` new logic).
- **Scope guard:** do not let "clean up `ContainerNode`" balloon into reworking the DSL/topology graph — that is M4.
