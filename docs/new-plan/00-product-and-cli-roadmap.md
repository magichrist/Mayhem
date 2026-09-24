# Plan 00 — Product and CLI Roadmap

## Builder brief

Create the canonical product/CLI direction document that every later implementation plan can reference. This plan does not add a command or change runtime behavior. It establishes vocabulary, workflow boundaries, migration rules, and measurable product outcomes so builder agents do not independently invent incompatible CLI patterns.

## Current context

The repository currently exposes 20 top-level commands, duplicate configuration and experiment surfaces, inconsistent JSON behavior, and separate lifecycle/discovery/coverage/recovery commands. The domain, controller, agent, topology, store, and fault catalog layers already contain substantial reusable behavior. The CLI is the weakest product boundary, not the entire system.

## Locked product decisions

- Primary experience is progressive: guided, precise, automatable, and expert-capable.
- The new command tree is workflow-oriented.
- Mutating commands plan first and require an explicit execution action.
- Human output is default; stable JSON is always available.
- Existing commands remain compatibility aliases during a migration window.
- Engine selection is explicit and first-class for Docker, Podman, and Kubernetes.
- Fault families require evidence contracts.
- Target profiles, not loose flags alone, represent environments.
- A provider extension API follows proven built-in slices.

## Phase 1 — Establish vocabulary and outcome metrics

### Work

- Add `docs/product/cli-product-direction.md` with the product promise, target personas, workflow map, and terminology.
- Define the canonical workflow names: `discover`, `prepare`, `experiment`, `run`, `inspect`, `recover`, and `extend`.
- Define the distinction between logical targets, resolved runtime objects, faults, leases, plans, runs, and evidence.
- Record measurable outcomes: time to first safe plan, percentage of commands with JSON schemas, percentage of faults with compensation coverage, and command migration adoption.

### Deliverables

- A product direction document with no implementation-dependent claims.
- A decision table mapping each current command to a new workflow owner, compatibility alias, or retirement reason.
- A terminology section that is reused by later plans.

### Verification

- Documentation link and consistency tests pass.
- A reviewer can map every current top-level command to exactly one future owner or explicit retirement decision.
- No new command names are introduced that conflict with the locked workflow list.

## Phase 2 — Build the migration and architecture contract

### Work

- Add a command architecture contract describing root context, engine selection, target selection, output selection, safety state, and database context.
- Define how legacy commands delegate to new handlers without changing exit codes or JSON keys.
- Define a stable error envelope with stable `code`, `message`, `details`, `remediation`, and `evidence_ref` fields while preserving existing human text.
- Define the version boundary for database and machine-output changes.

### Deliverables

- `docs/product/command-architecture.md`.
- Versioned compatibility rules for commands, flags, output, and store schemas.
- A deprecation policy with warnings, exit behavior, and removal criteria.

### Verification

- Unit tests pin legacy command behavior and exit codes.
- A new command skeleton can be added without importing controller implementation details into the CLI package.
- The architecture document contains no unresolved alternatives.

## Phase 3 — Publish the executable roadmap

### Work

- Add a roadmap manifest linking the twelve plans in this directory.
- Add dependency order and parallelization boundaries.
- Define review gates for compatibility, safety, evidence, and external runtime validation.
- Update `README.md` and `docs/reference/cli.md` with the migration notice, and keep the compatibility boundary explicit while the command tree is implemented.

### Deliverables

- `docs/new-plan/README.md` links every plan and records implementation status.
- `docs/product/cli-product-direction.md` is linked from the main documentation index.
- Builder agents can select the next plan without reading the entire repository.

### Verification

- `python3 -m pytest tests/unit/ -q` passes.
- `ruff check src/ tests/` is run and its result is recorded; no claim of green lint is made while baseline violations remain.
- Documentation consistency tests pass for all newly added links.
