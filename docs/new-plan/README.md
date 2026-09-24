# Mayhem CLI and Platform Plans

These plans turn the CLI brainstorm into an implementation sequence for builder agents. **Implementation status: Plans 00–11 are implemented in the current working tree; external Docker, Podman, Kubernetes, and live-cluster validation remains intentionally unrun.** The product direction is locked:

- Progressive CLI: guided defaults for newcomers, precise flags and stable JSON for automation, expert diagnostics for operators.
- Workflow-first command tree with compatibility aliases.
- Plan-first safety for every mutating operation.
- Docker, Podman, and Kubernetes are first-class engines.
- Human output by default, machine-readable output available everywhere.
- `init` and `doctor` provide guided onboarding.
- Faults require typed parameters, observable effects, safety metadata, compensation, and unit evidence.
- Target profiles make environment selection explicit.
- A stable provider API is introduced after the built-in vertical slices are proven.
- Existing exit codes, JSON fields, command aliases, and database schema remain script-safe during migration.

## Current product gaps

1. The current command tree is flat and mixes user workflows, resources, and engine concerns.
2. `config`/`cfg` and `experiment`/root lifecycle commands create avoidable duplication.
3. Mutation commands do not share one explicit plan/approval/evidence model.
4. Output modes, schemas, error rendering, and deprecation behavior are inconsistent.
5. There is no guided project onboarding or `doctor` workflow.
6. Target selection is mostly flags and auto-detection; environments are not first-class named profiles.
7. Kubernetes is present in source and unit tests but is not yet a first-class live operator experience.
8. The fault catalog is broad but lacks a systematic reliability matrix and evidence contract for every family.
9. Coverage, next, explore, campaigns, history, and reports are separate instead of one coherent operating loop.
10. There is no stable extension contract for engines, faults, checks, reporters, or policy backends.

## Plan order and dependencies

1. [00 — Product and CLI roadmap](00-product-and-cli-roadmap.md)
2. [01 — Workflow command architecture](01-workflow-command-architecture.md)
3. [02 — Guided onboarding and target profiles](02-guided-onboarding-and-target-profiles.md)
4. [03 — Plan-first execution and unified evidence](03-plan-first-execution-and-unified-evidence.md)
5. [04 — Output, errors, and script compatibility](04-output-errors-and-script-compatibility.md)
6. [05 — Configuration, policy, and environment safety](05-configuration-policy-and-environment-safety.md)
7. [06 — Docker/Podman reliability slice](06-docker-podman-reliability-slice.md)
8. [07 — First-class Kubernetes engine](07-first-class-kubernetes-engine.md)
9. [08 — Fault catalog reliability matrix](08-fault-catalog-reliability-matrix.md)
10. [09 — Campaigns, coverage, and explore loop](09-campaigns-coverage-and-explore-loop.md)
11. [10 — Diagnostics, recovery, and reporting](10-diagnostics-recovery-and-reporting.md)
12. [11 — Extension API and packaging](11-extension-api-and-packaging.md)

## Builder operating rules

- Every plan has exactly three phases. Do not merge phases or add hidden fourth phases.
- Every phase ends with tests, a review gate, and an observable artifact.
- Preserve existing unit-test contracts and run only unit tests and Ruff unless a later user-approved task explicitly authorizes external runtimes.
- Do not claim live Kubernetes or container behavior from mocked unit tests.
- Do not break existing exit codes, JSON keys, database migrations, or exact command aliases without a versioned migration plan.
- Prefer vertical slices over horizontal framework work: a user-visible workflow must work end to end before the next broad surface is added.
- Treat documentation, help text, machine-readable output, and tests as part of the feature, not follow-up work.
