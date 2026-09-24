# Mayhem Documentation-to-Implementation Design

## Scope

Implement the current, non-historical functionality described by the repository documentation in phases. Historical grounding logs, superseded Kubernetes plans, and forward-looking plans are preserved but are not treated as automatic production requirements without corroborating source contracts, catalog entries, or unit tests.

The implementation must not invoke Minikube, kubectl, Podman, Docker, E2E tests, or any other busy external runtime. Verification is limited to unit tests and Ruff.

## Current-state findings

The repository is in a partially completed Kubernetes target-selector and maniac-mode migration. Existing unit tests require contracts that the current source does not fully expose:

- `ManiacDraw` requires a `target` field, but the container draw does not populate it.
- Unit tests import the target selector through `mayhem.controller.target_selector`, while the current implementation lives in `mayhem.domain.target_selector`.
- `PlannedStep` lacks the target-scope field expected by current planning tests.
- `DrillTarget` runtime validation rejects Docker targets that omit an explicit `docker:` locator, while the current test contract expects Docker targets to be valid without that block.
- Current unit tests expose incomplete planning compatibility and are the first executable contract to repair.

The documentation also contains configuration, CLI, Kubernetes, and reference-document drift. Some Kubernetes faults from `k8s-plan-1` and `k8s-plan-2` already exist in the catalog or executor stack; others are only planning prose. Existing code and tests are the authority for implemented behavior.

## Architecture

Use a compatibility-preserving migration rather than a broad rewrite:

1. Restore the domain model and planner contracts required by current unit tests.
2. Keep the canonical selector implementation in the domain layer and expose a thin controller compatibility surface only if current callers require it.
3. Preserve the normalized `TargetScope`/`TargetRef` model as the planner-to-executor contract.
4. Populate planned-step target metadata at the same point that planned faults receive their logical target, avoiding duplicate target selection.
5. Keep Kubernetes manifest-only topology logically pinned and resolve live pods only when eligible live nodes exist.
6. Treat Docker target locators as optional only where the current DSL contract intentionally derives the container name from the logical target key; retain strict validation for Kubernetes locators.

## Delivery phases

### Phase 1: Restore current executable contracts

- Repair maniac draw construction and container/target metadata.
- Repair target-selector import compatibility.
- Restore planned-step target metadata.
- Align Docker target validation with the current DSL contract.
- Add focused regression tests only where current coverage is insufficient.
- Run the full unit suite and Ruff.

### Phase 2: Classify documentation

Create a documentation authority index with these classes:

- User guide
- Current reference
- Implemented design record
- Historical audit
- Forward-looking plan
- Unsupported/catalog-only

Mark Kubernetes execution, legacy adapter availability, and catalog-only fault families separately. Do not rewrite historical claims as current behavior.

### Phase 3: Implement current non-historical requirements

For each documented current requirement, create a vertical slice:

- catalog/schema definition
- planner acceptance
- safety/capability gate
- executor or deterministic refusal behavior
- compensation/undo contract
- unit tests with mocked external boundaries

Prioritize behavior that is already represented in current source or tests, then implement the remaining current requirements from the Kubernetes plans. Forward-looking operations requiring unavailable external runtimes must still have deterministic refusal or planning behavior and unit-level seam tests, but must not invoke those runtimes.

### Phase 4: Documentation truthfulness

- Rewrite `docs/config.md` from the current configuration models and loaders.
- Update README, Justfile, examples, and CLI documentation to the current interfaces.
- Add missing current reference documents or remove source references to absent files.
- Add a documentation index and status markers.
- Add unit-level documentation consistency checks for documented commands, exit codes, configuration keys, and example schemas.
- Keep historical documents clearly dated and separate from current references.

## Error handling and safety

All unsupported external operations must fail through existing typed domain/controller errors and stable refusal reasons. No implementation may silently claim success for catalog-only or unavailable operations. Compensation must remain idempotent and planner-owned.

## Verification

After each implementation slice:

- Run targeted unit tests for the changed contract.
- Run `python3 -m pytest tests/unit/ -q`.
- Run `ruff check src/ tests/`.
- Do not run E2E tests, Minikube, kubectl, Podman, Docker, or external clusters.

A phase is complete only when its unit contracts and Ruff checks pass, or when an explicitly documented unit-test failure remains isolated and reported.
