# v0.9.0 Core Safety and Truth Implementation Plan

> **For agentic workers:** Execute these tasks in order. Each task ends in a working, tested increment and an atomic commit.

**Goal:** Make every v0.9.0 mutating run explicit, deterministic, typed, and evidence-producing.

**Architecture:** Add a resolved runtime context and execution-intent contract at the application-service boundary. Persist approval and capability truth, then pass the same context through planning, safety, execution, and evidence.

**Tech Stack:** Python 3.12+, Click/Typer, Pydantic, SQLite, pytest, import-linter, Hatchling.

## Global constraints

- Preserve the PyPI distribution name `mayhem-cli` and console command `mayhem`.
- Keep Docker, Podman, and Kubernetes as explicit runtime lanes.
- No live-cluster execution in default unit or integration tests.
- Missing capability, target type, policy, or compensation is a refusal before lease creation.
- Every mutating command must have an explicit intent.
- Evidence must be redacted before persistence.
- Do not claim `live_verified` without a dated conformance artifact.

---

## Task 1: Establish v0.9.0 truth baseline

**Status:** DONE — commits `45e5c93`, `916d378`; review approved.

**Files:**
- Modify: `README.md`
- Modify: `docs/reference/cli.md`
- Modify: `docs/reference/output-schema.md`
- Modify: `docs/reference/fault-catalog.md`
- Modify: `Justfile`
- Modify: `pyproject.toml`
- Test: `tests/unit/test_release_contract.py`

**Interfaces:**
- Produces: a checked command registry, version metadata, and documented install dependency contract.

- [x] Write a test that imports the active command registry and compares root/group names against the CLI reference command inventory.
- [x] Add a test that asserts the default runtime dependency list includes `kubernetes` and that docs contain no `mayhem[k8s]` install instruction.
- [x] Run `python -m pytest tests/unit/test_release_contract.py -q`; expect the new tests to fail against stale references.
- [x] Reconcile the command reference, README, Justfile recipes, provider version, fallback version, and changelog with `src/mayhem/cli/command_registry.py` and `pyproject.toml`.
- [x] Run `python -m pytest tests/unit/test_release_contract.py -q`; expect PASS.
- [x] Run `python -m build --sdist --wheel`; expect both artifacts.
- [x] Commit with `docs: establish v0.9.0 release truth baseline`.

## Task 2: Add resolved runtime context

**Status:** DONE — commits `5afd916`, `d370798`, `88aec04`, `a238ab4`; review approved.

**Files:**
- Create: `src/mayhem/domain/runtime_context.py`
- Modify: `src/mayhem/cli/lifecycle.py`
- Modify: `src/mayhem/cli/services.py`
- Modify: `src/mayhem/cli/topology.py`
- Modify: `src/mayhem/controller/executor.py`
- Modify: `src/mayhem/controller/preflight.py`
- Test: `tests/unit/test_runtime_context.py`

**Interfaces:**
- Produces: `RuntimeContext(engine, target_profile, namespace, context, runtime_version, provider_version, topology_fingerprint)`.
- Consumes: explicit target selection and engine selection once during application preflight.

- [x] Write tests proving an ambiguous engine is refused before planning and an explicit engine remains unchanged through preflight and execution.
- [x] Write tests proving namespace/context and topology fingerprint are preserved in the execution handoff.
- [x] Run the focused tests and expect missing context behavior to fail.
- [x] Implement the immutable context and replace raw engine re-resolution in lifecycle/services/topology paths.
- [x] Update executor and preflight signatures to accept the context without breaking existing simple command callers.
- [x] Run `python -m pytest tests/unit/test_runtime_context.py tests/unit/test_cli_lifecycle.py -q`; expect PASS.
- [x] Commit with `feat: resolve one runtime context per plan`.

## Task 3: Require explicit execution intent

**Status:** DONE — commits `261518d`, `cd4bd1b`, `2285352`, `26ac4c0`; static review approved; tests deferred to final verification.

**Files:**
- Create: `src/mayhem/domain/execution_intent.py`
- Modify: `src/mayhem/cli/lifecycle.py`
- Modify: `src/mayhem/cli/campaign.py`
- Modify: `src/mayhem/cli/dependency.py`
- Modify: `src/mayhem/cli/app.py`
- Modify: `docs/reference/cli.md`
- Test: `tests/unit/test_execution_intent.py`
- Test: `tests/unit/test_cli_execution_intent.py`

**Interfaces:**
- Produces: `ExecutionIntent(plan_hash, engine, target_identity, policy_id, blast_radius, actor, approved_at, expires_at, break_glass)`.
- Produces: stable refusal code `execution_intent_required` and `approval_expired`.

- [x] Write tests proving every mutating command refuses without an explicit intent and that preview commands never create a lease.
- [x] Write tests proving an intent bound to a different plan hash, target, engine, or expired timestamp is refused.
- [ ] Run the tests and expect existing implicit paths to fail.
- [x] Implement intent validation before lease acquisition and pass the intent into evidence.
- [x] Update campaign and dependency mutations to use the shared contract.
- [x] Update CLI help and JSON error envelopes.
- [ ] Run the focused tests and the full unit suite.
- [x] Commit with `feat: require explicit execution intent`.

## Task 4: Make target profiles first-class configuration

**Status:** DONE — commits `2accb0d`, `1b6e209`; targeted config/profile/diagnostic tests pass.

**Files:**
- Modify: `src/mayhem/config.py`
- Modify: `src/mayhem/domain/target_profiles.py`
- Modify: `src/mayhem/cli/services.py`
- Modify: `src/mayhem/cli/doctor.py`
- Modify: `src/mayhem/cli/diagnostics.py`
- Test: `tests/unit/test_target_profiles_config.py`
- Test: `tests/unit/test_config_target_profiles.py`

**Interfaces:**
- Consumes: top-level `targets` or `profiles` in `mayhem.yaml`.
- Produces: validated target profiles available to topology, preflight, policy, and machine-readable output.

- [x] Write tests for valid profiles, inheritance, duplicate names, invalid engines, credential keys, and multiple-profile selection.
- [x] Write a test proving a `mayhem.yaml` containing targets loads through `MayhemConfigBase` instead of being rejected as an unknown field.
- [x] Add the target-profile field/reference to config parsing while preserving profile selection semantics.
- [x] Make diagnostics and doctor report the selected profile and available engine explicitly.
- [x] Run the focused tests and existing config tests.
- [x] Commit with `feat: integrate target profiles into configuration`.

## Task 5: Add capability truth records

**Status:** DONE — commit `45bd1fd`; targeted capability/catalog/doctor tests pass.

**Files:**
- Create: `src/mayhem/domain/capability_status.py`
- Modify: `src/mayhem/infra/catalog_report.py`
- Modify: `src/mayhem/cli/doctor.py`
- Modify: `src/mayhem/cli/services.py`
- Modify: `src/mayhem/cli/toolkit.py`
- Test: `tests/unit/test_capability_truth.py`
- Test: `tests/unit/test_cli_doctor.py`

**Interfaces:**
- Produces: `CapabilityStatus(fault_id, engine, registered, available, target_supported, unit_verified, live_verified, compensation_complete, blocked_reason)`.
- Produces: `mayhem discover capabilities --explain` with text, JSON, and YAML output.

- [x] Write tests for catalog-only, unavailable runtime, missing target support, missing compensation, and unit-verified states.
- [x] Write CLI tests that require human-readable reasons and stable machine-readable fields.
- [x] Run focused tests and expect missing status dimensions to fail.
- [x] Implement the status record and derive it from catalog, provider, runtime, and conformance registries.
- [x] Expose the dashboard through doctor/discover/toolkit without changing existing fault IDs.
- [x] Run focused tests, catalog tests, and output-schema tests.
- [x] Commit with `feat: expose capability truth for every fault`.

## Task 6: Enforce typed executor admission

**Files:**
- Create: `src/mayhem/domain/admission.py`
- Modify: `src/mayhem/controller/executor.py`
- Modify: `src/mayhem/agents/executors.py`
- Modify: `src/mayhem/controller/k8s_runtime.py`
- Test: `tests/unit/test_executor_admission.py`
- Test: `tests/integration/test_fake_runtime_admission.py`

**Interfaces:**
- Produces: `AdmissionDecision(allowed, code, reason, required_target_types, required_capabilities)`.
- Refusal codes: `target.type_mismatch`, `target.unresolved`, `capability.missing`, `compensation.incomplete`.

- [ ] Write a matrix test for pod, node, container, service, workload, and unresolved target types.
- [ ] Write tests proving refusal occurs before lease creation and before subprocess/Kubernetes calls.
- [ ] Run the matrix and expect current late failures.
- [ ] Implement admission before lease acquisition and pass typed target information into executors.
- [ ] Replace late `AttributeError` paths with stable typed refusals.
- [ ] Run the matrix, lease lifecycle tests, and fake runtime integration tests.
- [ ] Commit with `fix: admit typed targets before mutation`.

## Task 7: Add replay capsules and approval artifacts

**Files:**
- Create: `src/mayhem/domain/replay.py`
- Create: `src/mayhem/infra/replay_repository.py`
- Modify: `src/mayhem/infra/store.py`
- Modify: `src/mayhem/infra/evidence.py`
- Modify: `src/mayhem/cli/lifecycle.py`
- Test: `tests/unit/test_replay_capsule.py`
- Test: `tests/integration/test_replay_roundtrip.py`

**Interfaces:**
- Produces: `ReplayCapsule(schema_version, spec, plan, policy, target, runtime, versions, seed, fingerprints, digests)`.
- Produces: `validate_replay_capsule(capsule, mode=validate|dry_run) -> ReplayValidation`.

- [ ] Write tests for deterministic capsule serialization, digest verification, stale fingerprint detection, and dry-run validation.
- [ ] Write a round-trip test that creates a capsule, reloads it from SQLite, and reproduces the plan identity without mutation.
- [ ] Run tests and expect missing persistence/model behavior to fail.
- [ ] Implement schema, SQLite migration, repository, and evidence linkage.
- [ ] Add CLI output for capsule export/validate through existing inspect/report surfaces.
- [ ] Run focused, integration, migration, and evidence tests.
- [ ] Commit with `feat: persist replayable run capsules`.

## Task 8: Centralize redaction and recovery evidence

**Files:**
- Create: `src/mayhem/domain/redaction.py`
- Modify: `src/mayhem/cli/errors.py`
- Modify: `src/mayhem/config.py`
- Modify: `src/mayhem/toolkit/tool_runner.py`
- Modify: `src/mayhem/infra/evidence.py`
- Modify: `src/mayhem/infra/store.py`
- Test: `tests/unit/test_redaction_boundary.py`
- Test: `tests/integration/test_evidence_degradation.py`

**Interfaces:**
- Produces: `redact(value) -> RedactionResult(value, removed_paths, rule_versions)`.
- Covers structured values, mappings, argv, URLs, environment, stdout, stderr, and traceback text.

- [ ] Write adversarial fixtures for password, token, secret, kubeconfig, registry credentials, URL credentials, and command-line secrets.
- [ ] Write a test proving redaction occurs before SQLite and artifact writes.
- [ ] Write a test proving evidence write failure yields `degraded` and preserves recovery data.
- [ ] Implement the typed policy and route existing error/config/tool/report paths through it.
- [ ] Add redaction metrics to the run evidence without recording raw secret values.
- [ ] Run redaction, evidence, CLI error, and integration tests.
- [ ] Commit with `feat: enforce one evidence redaction boundary`.

## Task 9: Repair release quality gates

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: `.github/workflows/release.yml`
- Modify: `pyproject.toml`
- Create: `tests/package/test_wheel_smoke.py`
- Create: `scripts/verify_release_artifacts.py`
- Modify: `docs/v0.9.0/08-release-readiness.md`

**Interfaces:**
- Produces: PR checks for unit, integration, package build, wheel install, schema validation, Ruff, mypy, and dependency/security scans.
- Produces: release artifact verification report.

- [ ] Write a packaging smoke test that installs the wheel into a clean temporary environment and runs `mayhem --help` and `mayhem discover capabilities --format json`.
- [ ] Write a workflow contract test for required job names and commands.
- [ ] Run the tests and expect missing CI/package checks to fail.
- [ ] Add the CI workflow, artifact verification script, schema checks, and immutable action references.
- [ ] Keep live conformance in a separate opt-in workflow/job.
- [ ] Run all gates locally where possible and record any environment-only exclusions.
- [ ] Commit with `ci: add v0.9.0 quality gates`.

## Task 10: Make no-backend actions honest

**Files:**
- Modify: `src/mayhem/controller/executor.py`
- Modify: `src/mayhem/domain/evidence.py`
- Modify: `src/mayhem/cli/lifecycle.py`
- Test: `tests/unit/test_action_outcome_contract.py`
- Test: `tests/unit/test_fault_catalog_exhaustive.py`

**Interfaces:**
- Produces action outcome states: `applied`, `verified`, `compensated`, `acknowledged_no_backend`, `refused`, `failed`.

- [ ] Write tests for `start_load`, `stop_load`, and `notify` showing they cannot report unqualified success without a backend.
- [ ] Write tests proving catalog-only and no-backend actions are visible in text and JSON output.
- [ ] Run the tests and expect the current acknowledgement behavior to fail.
- [ ] Implement the outcome state and map no-backend actions to an explicit degraded/acknowledged state.
- [ ] Update evidence and report rendering.
- [ ] Run focused catalog and run-state tests.
- [ ] Commit with `fix: make unsupported actions honest`.

## Checkpoint after core plan

- [ ] `python -m pytest tests/unit tests/integration -q` passes.
- [ ] `python -m build --sdist --wheel` passes.
- [ ] A clean wheel install passes CLI smoke tests.
- [ ] No mutating command executes without an intent.
- [ ] No target-type mismatch reaches lease creation.
- [ ] No known credential fixture reaches an artifact.
