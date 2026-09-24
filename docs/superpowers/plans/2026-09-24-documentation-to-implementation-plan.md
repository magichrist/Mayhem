# Mayhem Documentation-to-Implementation Plan

> **For agentic workers:** Execute this plan task-by-task in the current workspace. Do not run E2E tests or any external container/Kubernetes runtime.

**Goal:** Restore the repository’s current executable contracts, implement the current non-historical documentation requirements in verifiable slices, and make the checked-in documentation accurately describe the resulting behavior.

**Architecture:** Preserve the existing domain/controller/agent layering. Restore compatibility at the narrowest seam, keep target selection in the domain layer, and let the planner attach normalized target metadata to planned steps. Treat source code, catalog definitions, and unit tests as the executable authority; preserve historical documents but label them separately from current behavior.

**Tech Stack:** Python 3.12+, Pydantic v2, Typer, pytest, Ruff, YAML, existing Mayhem domain/controller/agent/infra modules.

## Global Constraints

- Do not run Minikube, `kubectl`, Podman, Docker, E2E tests, or external clusters.
- Verification commands are limited to `python3 -m pytest tests/unit/ -q` and `ruff check src/ tests/`.
- Do not commit changes unless explicitly requested by the user.
- Do not add inline code comments.
- Keep the domain layer free of I/O and upward imports.
- Unsupported external operations must use existing typed refusal/error paths and must never report false success.
- Compensation and undo behavior must remain idempotent and planner-owned.

---

## File Map

- `src/mayhem/domain/maniac.py`: container and Kubernetes-target maniac draw contracts.
- `src/mayhem/domain/experiments.py`: drill target validation and planned-step contracts.
- `src/mayhem/domain/target.py`: normalized logical target identity.
- `src/mayhem/domain/target_selector.py`: canonical target selection implementation.
- `src/mayhem/controller/target_selector.py`: compatibility re-export for existing controller callers/tests.
- `src/mayhem/controller/planner.py`: target-to-plan compilation and planned-step target metadata.
- `src/mayhem/domain/catalog.py`: fault definitions and parameter schemas.
- `src/mayhem/controller/k8s_runtime.py`: Kubernetes fault-family unions and runtime routing.
- `src/mayhem/agents/executors.py`: Kubernetes fault injection and undo seams.
- `src/mayhem/controller/safety.py`: capability and critical-risk refusal behavior.
- `docs/README.md`: documentation authority and status index.
- `docs/config.md`: current configuration reference.
- `docs/reference/cli.md`: current CLI and exit-code reference.
- `docs/reference/fault-catalog.md`: current catalog/fault-family reference.
- `docs/reference/k8s.md`: current Kubernetes capability and status reference.
- `README.md`, `Justfile`, `examples/k8s/README.md`: user-facing and executable documentation.
- `tests/unit/test_maniac.py`, `tests/unit/test_k8s_manifest.py`: existing regression contracts.
- `tests/unit/test_documentation_consistency.py`: documentation/source consistency checks.

---

## Task 1: Restore Maniac Draw Contracts

**Files:**
- Modify: `src/mayhem/domain/maniac.py:33-107`
- Test: `tests/unit/test_maniac.py`

**Interfaces:**
- `ManiacDraw` continues to expose `container`, `target`, `fault`, and `round`.
- `draw_maniac_rounds(spec, *, level, run_level, seed)` returns one draw per round and sets `target` to the same logical container key selected for the round.

- [ ] **Step 1: Add a regression assertion for target metadata**

Add to `test_level_1_takes_first_authored_fault_without_jitter`:

```python
assert draw.target == draw.container
```

- [ ] **Step 2: Run the focused test and confirm the current failure**

Run: `python3 -m pytest tests/unit/test_maniac.py -q`
Expected: failures caused by `ManiacDraw.__init__()` missing `target`.

- [ ] **Step 3: Populate the target field in the container draw**

Change the append in `draw_maniac_rounds` to:

```python
draws.append(ManiacDraw(container=target, target=target, fault=fault, round=round_no))
```

Keep `draw_maniac_target_rounds` using `ManiacTargetDraw(target=target, ...)`.

- [ ] **Step 4: Run focused and full unit tests**

Run: `python3 -m pytest tests/unit/test_maniac.py -q`
Expected: PASS.

Run: `python3 -m pytest tests/unit/ -q`
Expected: all unit tests pass after Tasks 1-4 complete.

---

## Task 2: Restore Target-Selector Compatibility

**Files:**
- Create: `src/mayhem/controller/target_selector.py`
- Modify: `src/mayhem/domain/target.py:86-113` if the current target model needs compatibility properties.
- Test: `tests/unit/test_k8s_manifest.py:169-283`

**Interfaces:**
- `mayhem.controller.target_selector.select_many` re-exports `mayhem.domain.target_selector.select_many` with the same signature and return type.
- `TargetScope` remains the canonical normalized target identity.

- [ ] **Step 1: Add a focused compatibility test**

Add a unit test that imports both module paths and asserts the public function is the same object:

```python
def test_controller_target_selector_is_compatibility_surface() -> None:
    from mayhem.controller.target_selector import select_many as controller_select_many
    from mayhem.domain.target_selector import select_many as domain_select_many

    assert controller_select_many is domain_select_many
```

- [ ] **Step 2: Create the compatibility module**

Create `src/mayhem/controller/target_selector.py` with explicit re-exports for the public selector functions used by controller callers:

```python
from mayhem.domain.target_selector import select_many, select_one

__all__ = ["select_many", "select_one"]
```

Do not duplicate selector logic.

- [ ] **Step 3: Run the focused target-selector tests**

Run: `python3 -m pytest tests/unit/test_k8s_manifest.py::TestBlueprintTransparency -q`
Expected: PASS for blueprint-only, live-pod, and terminating-only selection.

---

## Task 3: Restore Planned-Step Target Metadata

**Files:**
- Modify: `src/mayhem/domain/experiments.py:520-532`
- Modify: `src/mayhem/controller/planner.py:681-1180`
- Test: `tests/unit/test_k8s_manifest.py:402-465`

**Interfaces:**
- `PlannedStep.target: TargetRef | None` is the normalized logical target scope carried by a planned step.
- Every targeted fault step receives the same `TargetScope` that is stored in its `PlannedFault.target`.
- Container-authored steps may retain `None` unless the current planner contract explicitly has a container scope.

- [ ] **Step 1: Add the model field**

Add to `PlannedStep`:

```python
target: TargetRef | None = None
```

- [ ] **Step 2: Pass target metadata when constructing targeted planned steps**

Where the planner constructs a `PlannedStep` for a targeted fault, pass:

```python
target=planned_fault.target
```

Use the already constructed `PlannedFault` instance so the step and fault cannot diverge. Do not perform a second topology lookup.

- [ ] **Step 3: Preserve existing runtime identity and group metadata**

Keep all existing `runtime_identity`, `execution_group_id`, `group_mode`, and `group_path` assignments unchanged.

- [ ] **Step 4: Run the Kubernetes manifest unit tests**

Run: `python3 -m pytest tests/unit/test_k8s_manifest.py -q`
Expected: targeted planning tests pass; remaining failures identify only unrelated schema or Docker-locator issues.

---

## Task 4: Align Docker Target Validation with the Current DSL Contract

**Files:**
- Modify: `src/mayhem/domain/experiments.py:281-329`
- Test: `tests/unit/test_k8s_manifest.py:467-505`
- Test: `tests/unit/test_drill_spec.py`

**Interfaces:**
- Kubernetes targets require a `kubernetes:` locator.
- Docker targets may omit `docker:` when the logical target key is the container name; the planner then derives `TargetScope` from the key.
- Explicit Docker and Kubernetes locators may not be mixed.

- [ ] **Step 1: Add a minimal schema test**

Add a test that validates a Docker target with only `runtime: docker` and a fault, then asserts its normalized scope has the logical target key as `authority["container_name"]`.

- [ ] **Step 2: Update `DrillTarget._runtime_locator_matches`**

Implement the same rule in the model:

```python
if self.runtime == RuntimeLabel.KUBERNETES:
    if self.kubernetes is None:
        raise InvariantViolationError(
            "target.runtime_mismatch",
            "kubernetes runtime requires a `kubernetes:` locator block",
        )
    if self.docker is not None:
        raise InvariantViolationError(
            "target.mixed_locators",
            "a target may not carry both `docker:` and `kubernetes:` blocks",
        )
else:
    if self.kubernetes is not None:
        raise InvariantViolationError(
            "target.mixed_locators",
            f"target runtime {self.runtime.value} may not carry a `kubernetes:` block",
        )
```

- [ ] **Step 3: Update `DrillTarget.to_scope` for implicit Docker targets**

When `self.docker is None`, create the Docker scope from the logical target key. Keep explicit Docker locators authoritative.

- [ ] **Step 4: Run schema and Kubernetes manifest tests**

Run: `python3 -m pytest tests/unit/test_drill_spec.py tests/unit/test_k8s_manifest.py -q`
Expected: PASS.

---

## Task 5: Classify Documentation and Add the Authority Index

**Files:**
- Create: `docs/README.md`
- Modify: `README.md`
- Modify: `docs/grounding-log.md`
- Modify: `examples/k8s/README.md`
- Modify: `docs/adr/adr-m7-1-k8s-executor.md`
- Modify: `docs/adr-adr-m7-1-k8s-executor-flip.md`

**Interfaces:**
- Every documentation file is classified as one of: user guide, current reference, implemented design record, historical audit, forward-looking plan, or unsupported/catalog-only.
- The index links to every tracked Markdown document and identifies the executable source of truth for current behavior.

- [ ] **Step 1: Build the document inventory**

Use the tracked Markdown paths and classify each document according to its content and current source references. Record the classification in `docs/README.md`.

- [ ] **Step 2: Add explicit status sections**

For Kubernetes documents, distinguish manifest topology discovery, planner support, executor support, live resolution, legacy adapter availability, and catalog-only faults.

- [ ] **Step 3: Mark the grounding log as dated historical evidence**

Add a clear “Historical snapshot — not current behavior” label to `docs/grounding-log.md`; do not rewrite its dated claims.

- [ ] **Step 4: Add documentation consistency tests**

Create `tests/unit/test_documentation_consistency.py` with checks that:

```python
from pathlib import Path
import re

ROOT = Path(__file__).parents[2]
DOC_FILES = tuple(ROOT.glob("docs/**/*.md"))
SOURCE = tuple(ROOT.glob("src/**/*.py"))
```

The tests must verify that every relative Markdown link resolves to an existing tracked path, and that documented exit-code identifiers are a subset of `src/mayhem/cli/exit_codes.py` symbols.

- [ ] **Step 5: Run documentation consistency tests**

Run: `python3 -m pytest tests/unit/test_documentation_consistency.py -q`
Expected: PASS after links and status references are corrected.

---

## Task 6: Rewrite Current Configuration and CLI References

**Files:**
- Modify: `docs/config.md`
- Create: `docs/reference/cli.md`
- Modify: `README.md:199-375`
- Modify: `Justfile:47-60,67-150`
- Test: `tests/unit/test_documentation_consistency.py`

**Interfaces:**
- Configuration documentation must match `MayhemConfigBase`, `_ENV_ALLOWED`, `load_config`, and the actual CLI surface.
- `docs/reference/cli.md` must document commands and stable exit codes from source.

- [ ] **Step 1: Generate the configuration field inventory from source**

Document these current top-level fields: `apiVersion`, `policy`, `blast_radius`, `storage`, `toolkit`, `runtime`, `target`, `kubernetes`, `recovery_grace`, `log_level`, and `maniac`. Document only the three allowed environment variables: `MAYHEM_STORAGE_PATH`, `MAYHEM_ARTIFACTS_DIR`, and `MAYHEM_LOG_LEVEL`.

- [ ] **Step 2: Correct the Justfile paths and commands**

Change `_config` to `examples/testCase/mayhem.yaml` only if that file is intentionally used as a config; otherwise remove the stale config recipe. Remove `validate-process` or update it only if the CLI supports the same options. Update campaign creation to the current positional name syntax, require a run ID for recovery, and use the current janitor command name.

- [ ] **Step 3: Add CLI and exit-code documentation**

List commands from the actual Typer application and exit-code names from `src/mayhem/cli/exit_codes.py`. Do not document removed flags.

- [ ] **Step 4: Run the relevant unit tests**

Run: `python3 -m pytest tests/unit/test_command_inventory.py tests/unit/test_cli_contract.py tests/unit/test_documentation_consistency.py -q`
Expected: PASS.

---

## Task 7: Complete Current Kubernetes Target/Planner Contracts

**Files:**
- Modify: `src/mayhem/controller/planner.py:495-1180`
- Modify: `src/mayhem/controller/k8s_runtime.py`
- Modify: `src/mayhem/agents/k8s_resolve.py`
- Test: `tests/unit/test_k8s_manifest.py`, `tests/unit/test_k8s_selection.py`, `tests/unit/test_kplan3_resolver.py`

**Interfaces:**
- Manifest-only targets remain logically pinned and carry no pod UID.
- Live targets resolve deterministically to eligible Running pods.
- Planned fault target scope is preserved from authored target through execution-plan compilation.
- Kubernetes node targets follow the existing node-family refusal or support contract and do not silently fall back to pod selection.

- [ ] **Step 1: Add a regression test for target identity preservation**

Assert that a planned Kubernetes fault and its `PlannedStep` have equal `target.logical_id`, `runtime`, `kind`, `authority`, and `selection`.

- [ ] **Step 2: Fix targeted planning metadata at the construction seam**

Ensure all targeted `PlannedStep` constructions receive the already-created `PlannedFault.target`; do not re-run selection or use a different logical id.

- [ ] **Step 3: Keep manifest-only selection distinct from live selection**

Ensure blueprint pods are excluded from eligible picks and absent workloads return `None`; ensure a present workload with only terminating pods raises `SelectionError`.

- [ ] **Step 4: Run Kubernetes unit tests**

Run: `python3 -m pytest tests/unit/test_k8s_manifest.py tests/unit/test_k8s_selection.py tests/unit/test_kplan3_resolver.py -q`
Expected: PASS without running a cluster.

---

## Task 8: Implement or Refuse Current Kubernetes Plan Families

**Files:**
- Modify: `src/mayhem/domain/catalog.py`
- Modify: `src/mayhem/controller/k8s_runtime.py`
- Modify: `src/mayhem/agents/executors.py`
- Modify: `src/mayhem/agents/k8s_control.py`
- Modify: `src/mayhem/controller/safety.py`
- Test: `tests/unit/test_fault_catalog_all.py`, `tests/unit/test_kplan1_targets.py`, `tests/unit/test_kplan2_topology.py`, `tests/unit/test_kplan3_runtime.py`, `tests/unit/test_kplan5_runtime.py`, `tests/unit/test_kplan6_runtime.py`, `tests/unit/test_capability_safety.py`, `tests/unit/test_compensation.py`

**Interfaces:**
- Every catalog fault has a valid definition, applicable node kinds, risk level, required capabilities, parameter schema, and either an executor mapping or a documented deterministic refusal.
- Every mutable Kubernetes fault has a planner-owned compensation contract and an idempotent undo path.
- Critical faults remain refused unless the existing critical opt-in is present.

- [ ] **Step 1: Inventory all plan fault IDs against catalog and executor mappings**

For each ID in `docs/k8s-plan-1.md` and `docs/k8s-plan-2.md`, record one state: implemented, catalog-only, or unsupported. Do not infer implementation from prose alone.

- [ ] **Step 2: Implement one family at a time using existing seams**

For each family that has an existing executor seam, add catalog/schema validation, planner routing, safety checks, compensation nodes, and unit tests before moving to the next family. Use mocked `run_tool`, Kubernetes client boundaries, and resolution data in tests; do not call a cluster or container runtime.

- [ ] **Step 3: Implement deterministic refusals for unavailable or unsafe families**

For families that cannot be implemented safely without a capability, wire the existing stable refusal path and assert the reason in unit tests. Do not add a false-success no-op.

- [ ] **Step 4: Run the Kubernetes unit test set**

Run: `python3 -m pytest tests/unit/test_fault_catalog_all.py tests/unit/test_kplan1_targets.py tests/unit/test_kplan2_topology.py tests/unit/test_kplan3_runtime.py tests/unit/test_kplan5_runtime.py tests/unit/test_kplan6_runtime.py tests/unit/test_capability_safety.py tests/unit/test_compensation.py -q`
Expected: PASS.

---

## Task 9: Synchronize Remaining Documentation and Verify

**Files:**
- Modify: `docs/compensation.md`
- Modify: `docs/drill-spec.md`
- Modify: `docs/k8s-plan-1.md`
- Modify: `docs/k8s-plan-2.md`
- Modify: `README.md`
- Modify: `CHANGELOG.md` only if repository history requires regeneration without invoking unavailable tooling.
- Test: `tests/unit/test_documentation_consistency.py`

**Interfaces:**
- Documentation examples validate against the current Pydantic models.
- Compensation tables match executor and planner behavior.
- Kubernetes plan documents identify implemented, partial, and catalog-only entries.
- Changelog is either current for the repository history or explicitly labeled as not covering unreleased work.

- [ ] **Step 1: Validate all checked-in drill examples with existing unit coverage**

Run: `python3 -m pytest tests/unit/test_example_specs_yaml.py -q`
Expected: PASS.

- [ ] **Step 2: Correct stale counts, commands, and status claims**

Use source and test-derived values rather than old prose. Keep historical claims in historical documents but mark them as historical.

- [ ] **Step 3: Run the complete allowed verification set**

Run: `python3 -m pytest tests/unit/ -q`
Expected: all unit tests pass.

Run: `ruff check src/ tests/`
Expected: Ruff exits successfully.

- [ ] **Step 4: Report remaining unsupported forward-plan work without claiming completion**

List any catalog-only or capability-gated Kubernetes families that remain unavailable, with their stable refusal code and documentation path. Do not run forbidden runtime checks.
