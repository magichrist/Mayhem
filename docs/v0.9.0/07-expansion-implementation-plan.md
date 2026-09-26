# v0.9.0 Expansion Implementation Plan

> **For agentic workers:** Execute after the core safety/truth plan passes its checkpoint. Each task produces a tested vertical slice.

**Goal:** Add operator workflows that turn Mayhem from a safe executor into a resilience operating system for local rehearsals, campaigns, and evidence review.

**Architecture:** Build on `RuntimeContext`, `ExecutionIntent`, `CapabilityStatus`, replay capsules, and evidence bundles. New integrations are provider-neutral and read-only by default; any mutation remains inside the existing safety and lease boundaries.

**Tech Stack:** Existing Python/Click/SQLite stack; provider-neutral observation contracts; optional OpenTelemetry, Prometheus, and Loki adapters; no required hosted service.

## Global constraints

- Do not weaken explicit intent, typed admission, redaction, or compensation requirements.
- Recommendations and scenario generation produce plans only; they never mutate automatically.
- Live Kubernetes and remote-agent features remain opt-in and separately authorized.
- New output fields are additive and schema-versioned.
- Every new action has text, JSON, and YAML-compatible machine output where it is observable.

---

## Task 11: Build the capability truth dashboard

**Files:**
- Create: `src/mayhem/cli/capabilities.py`
- Modify: `src/mayhem/infra/catalog_report.py`
- Modify: `src/mayhem/cli/command_registry.py`
- Modify: `docs/reference/cli.md`
- Test: `tests/unit/test_capability_dashboard.py`

**Interfaces:**
- Produces: `CapabilityDashboard(engine, rows, generated_at, schema_version)`.
- Consumes: `CapabilityStatus` records from the core plan.

**Status:** DONE — the dashboard itself landed with core task 5 (commit `45bd1fd`); this pass added the `CapabilityDashboard` model, the engine/family/maturity/blocked filters, per-row remediation and source-of-truth text, and the test suite. The command lives in `src/mayhem/cli/toolkit.py` rather than a separate `capabilities.py`, because it shares the toolkit group with `discover faults`.

- [x] Write tests for Docker, Podman, Kubernetes, catalog-only, blocked, and unit-verified rows.
- [x] Write text/JSON/YAML output tests and filter tests by engine, fault family, maturity, and blocked reason.
- [x] Implement `discover capabilities` and `discover capabilities --explain`.
- [x] Include remediation text and source of truth for every blocked row.
- [x] Run dashboard, CLI, output-schema, and catalog tests.
- [x] Commit with `feat: add capability truth dashboard`.

## Task 12: Add the resilience coverage graph

**Files:**
- Create: `src/mayhem/domain/coverage_graph.py`
- Modify: `src/mayhem/infra/coverage_repository.py`
- Modify: `src/mayhem/cli/explore.py`
- Modify: `src/mayhem/cli/inspect.py`
- Test: `tests/unit/test_coverage_graph.py`
- Test: `tests/integration/test_coverage_delta.py`

**Interfaces:**
- Produces: `CoverageNode`, `CoverageEdge`, `CoverageDelta(before, after, added, removed, changed)`.
- Consumes: catalog definitions, target profiles, run evidence, and maturity status.

**Status:** DONE — `src/mayhem/domain/coverage_graph.py`, migration 19 (`coverage_graph`), `CoverageGraphRepository`, and the read-only `mayhem inspect graph` / `mayhem inspect coverage-diff` commands. The graph is an additive projection: `m5_coverage` is read, never written, so the existing five-state table keeps its semantics.

- [x] Write tests proving coverage is keyed by service, failure domain, target type, engine, maturity, and evidence status.
- [x] Write tests for baseline creation, successful run updates, blocked-run exclusion, and campaign-level delta aggregation.
- [x] Implement graph persistence and a read-only JSON/table view.
- [x] Add `inspect coverage` and `experiment coverage-diff` without changing existing coverage table semantics.
- [x] Run graph, campaign, inspect, and integration tests.
- [x] Commit with `feat: add resilience coverage graph`.

**Note:** the two read surfaces are `mayhem inspect graph` and `mayhem inspect coverage-diff BASELINE [--save]` rather than `inspect coverage` / `experiment coverage-diff`, because `inspect coverage` already exists as the five-state coverage table view and reusing the name would have changed its meaning.

## Task 13: Add provider-neutral observation contracts

**Files:**
- Create: `src/mayhem/domain/observations.py`
- Create: `src/mayhem/providers/observation.py`
- Modify: `src/mayhem/domain/evidence.py`
- Modify: `src/mayhem/cli/lifecycle.py`
- Test: `tests/unit/test_observation_contract.py`
- Test: `tests/integration/test_slo_success_criteria.py`

**Interfaces:**
- Produces: `ObservationProvider`, `ObservationQuery`, `ObservationResult`, `SloCriterion`.
- Supports HTTP/process checks first; Prometheus/Loki adapters consume the same contract later.

**Status:** DONE — `src/mayhem/domain/observations.py` (contracts), `src/mayhem/providers/observation.py` (HTTP/process/static providers), `ExecutionPlan.slo`, and `observation_provenance` / `slo_outcomes` on the evidence envelope. A missing observation fails its criterion rather than passing, and a crashing provider becomes an `error` result rather than a silent pass.

- [x] Write tests for latency threshold, error-budget threshold, recovery-time, saturation, and missing-observation behavior.
- [x] Write a fake provider that returns deterministic observations and a redacted result.
- [x] Add criterion types to the drill schema with explicit units, windows, and failure semantics.
- [x] Implement provider-neutral collection and persist observation provenance in evidence.
- [x] Run observation, evidence, lifecycle, and fake integration tests.
- [x] Commit with `feat: add provider-neutral SLO observations`.

**Note:** the default provider is a local static one, so a run records only measurements it actually took; the Prometheus and Loki adapters arrive with task 19 and stay opt-in.

## Task 14: Add scenario variables and conditional steps

**Files:**
- Create: `src/mayhem/domain/scenarios.py`
- Modify: `src/mayhem/domain/drill_spec.py`
- Modify: `src/mayhem/controller/planner.py`
- Modify: `src/mayhem/cli/experiment.py`
- Test: `tests/unit/test_scenario_compiler.py`
- Test: `tests/integration/test_scenario_plan_replay.py`

**Interfaces:**
- Produces: `ScenarioVariable`, `Condition`, `ConditionalStep`, `CompiledScenario`.
- Compiled plans contain resolved values and preserve the original scenario source for evidence.

**Status:** DONE — `src/mayhem/domain/scenarios.py` plus the plan-only `mayhem experiment compose` and `mayhem experiment check-scenario` commands. Compilation is pure: same variables and seed ⇒ same `digest`, and the compiled plan carries its own scenario source so a replay needs no extra inputs. Neither command can execute: `compose` never constructs a `RunEngine`, which the integration suite asserts structurally.

- [x] Write tests for variables, typed constraints, time windows, conditional branches, missing variables, and deterministic compilation.
- [x] Write a replay test proving the same variables and seed produce the same compiled plan.
- [x] Implement scenario parsing, validation, and compile-time resolution.
- [x] Add `experiment compose`/`experiment validate` plan-only flows; no direct execution from generated output.
- [x] Run scenario, planner, CLI, and integration tests.
- [x] Commit with `feat: compile variable-driven scenarios`.

**Note:** the scenario validator is `experiment check-scenario`, not `experiment validate`, because `experiment v` is a documented two-letter prefix for the existing drill `validate` command and a second `v…` child would make that prefix ambiguous.

## Task 15: Add campaign checkpoints and safe resume

**Files:**
- Create: `src/mayhem/domain/campaign_checkpoint.py`
- Modify: `src/mayhem/infra/campaign_engine.py`
- Modify: `src/mayhem/infra/store.py`
- Modify: `src/mayhem/cli/campaign.py`
- Test: `tests/unit/test_campaign_checkpoint.py`
- Test: `tests/integration/test_campaign_resume.py`

**Interfaces:**
- Produces: `CampaignCheckpoint(campaign_id, experiment_id, state, lease_id, attempt, fingerprint, resume_safe, updated_at)`.
- States: `pending`, `running`, `verified`, `compensating`, `compensated`, `retryable`, `blocked`, `completed`, `aborted`.

**Status:** DONE — `src/mayhem/domain/campaign_checkpoint.py` (nine-state vocabulary + deterministic `plan_resume`), migration 20 (`campaign_checkpoints`), `CampaignCheckpointRepository`, and three plan-only commands: `campaign checkpoint`, `campaign checkpoints`, `campaign resume-plan`. A verified experiment is skipped unless `--retry-verified` is passed; work in flight (`running`/`compensating`), a stale fingerprint, an exhausted retry budget, or a `resume_safe=false` checkpoint all make the plan report `safe: false` rather than proceeding.

- [x] Write tests for normal progression, controller loss, compensation in progress, retry budget exhaustion, and stale fingerprint.
- [x] Write a test proving resume never repeats a verified experiment without an explicit retry intent.
- [x] Implement checkpoint persistence and a deterministic resume planner.
- [x] Add `campaign resume --dry-run` and explicit `campaign resume --execute` behavior.
- [x] Run campaign, lease, recovery, and integration tests.
- [x] Commit with `feat: add resumable campaign checkpoints`.

**Note:** the resume surface is `campaign resume-plan` and it is *always* plan-only. The existing `campaign resume` already flips campaign status, and adding `--execute` there would have created a second approval model; a resume that actually runs experiments routes through the existing campaign execution path with its existing intent gate.

## Task 16: Add before/after residual impact

**Files:**
- Create: `src/mayhem/domain/residual_impact.py`
- Modify: `src/mayhem/infra/evidence.py`
- Modify: `src/mayhem/cli/inspect.py`
- Modify: `src/mayhem/cli/recover.py`
- Test: `tests/unit/test_residual_impact.py`
- Test: `tests/integration/test_recovery_proof.py`

**Interfaces:**
- Produces: `ImpactSnapshot`, `ResidualImpactAssessment(expected, observed, tolerated, violations)`.

**Status:** DONE — `src/mayhem/domain/residual_impact.py`, the `residual_impact` field on the evidence envelope (also rendered by `render_evidence_human`), and the read-only `mayhem inspect residual` command. An unavailable observation source reports `unavailable`, never `clean`, and a deviation is `tolerated` only when an `ImpactAcceptance` names a human and a reason — there is no silent tolerance.

- [x] Write tests for clean recovery, partial recovery, unexpected persistent change, unavailable observation source, and explicitly accepted residual impact.
- [x] Implement before/after snapshot comparison using existing topology and observation contracts.
- [x] Add residual impact to evidence, inspect, and recovery reports.
- [x] Require explicit acceptance metadata for any tolerated violation.
- [x] Run evidence, recovery, inspect, and integration tests.
- [x] Commit with `feat: verify residual impact after compensation`.

**Note:** `inspect residual` is read-only; the live run path records the assessment into the evidence envelope, and the command recomputes or replays it from recorded values rather than mutating state.

## Task 17: Add game-day mode

**Files:**
- Create: `src/mayhem/domain/game_day.py`
- Create: `src/mayhem/cli/game_day.py`
- Modify: `src/mayhem/cli/command_registry.py`
- Modify: `src/mayhem/cli/campaign.py`
- Modify: `docs/reference/cli.md`
- Test: `tests/unit/test_game_day.py`
- Test: `tests/integration/test_game_day_approval_flow.py`

**Interfaces:**
- Produces: `GameDaySession`, `ApprovalGate`, `FreezeWindow`, `OperatorAcknowledgement`.

- [ ] Write tests for missing approval, expired freeze window, critical-fault dual control, operator pause, and final evidence bundle creation.
- [ ] Implement session state persisted separately from campaign state.
- [ ] Add plan-only session creation and explicit execution start.
- [ ] Ensure all session operations reuse `ExecutionIntent`; do not create a second approval model.
- [ ] Run game-day, campaign, CLI, and integration tests.
- [ ] Commit with `feat: add controlled game-day sessions`.

## Task 18: Add provider sandbox and signed fault packs

**Files:**
- Create: `src/mayhem/providers/permissions.py`
- Create: `src/mayhem/providers/pack.py`
- Modify: `src/mayhem/providers/loader.py`
- Modify: `docs/provider-sdk.md`
- Test: `tests/unit/test_provider_permissions.py`
- Test: `tests/unit/test_fault_pack_validation.py`

**Interfaces:**
- Produces: `ProviderPermissionSet`, `ProviderManifest`, `FaultPack`, `pack_digest`.
- Default permission set: no target mutation, no subprocess, no network, no environment read.

- [ ] Write malicious-provider tests for filesystem access, network access, subprocess execution, environment capture, and implicit mutation requests.
- [ ] Write pack validation tests for schema version, signature/digest, compatibility, duplicate IDs, unsafe targets, and incomplete compensation.
- [ ] Implement opt-in loading with explicit permission grants and deterministic refusal messages.
- [ ] Add a signed/digest workflow that treats an unsigned pack as local development-only.
- [ ] Run provider, security, catalog, and CLI tests.
- [ ] Commit with `feat: sandbox providers and fault packs`.

## Task 19: Add observability connectors

**Files:**
- Create: `src/mayhem/observability/otel.py`
- Create: `src/mayhem/observability/prometheus.py`
- Create: `src/mayhem/observability/loki.py`
- Modify: `src/mayhem/domain/evidence.py`
- Modify: `docs/observability.md`
- Test: `tests/unit/test_observability_connectors.py`
- Test: `tests/integration/test_observability_run.py`

**Interfaces:**
- Produces: `SpanSink`, `MetricQuery`, `LogQuery`; all connectors are read-only except the local OpenTelemetry span sink.

- [ ] Write tests with fake HTTP servers for Prometheus query responses and Loki query responses.
- [ ] Write tests proving connector credentials are redacted and connector errors produce degraded evidence.
- [ ] Implement bounded timeouts, response-size limits, and redaction.
- [ ] Add OpenTelemetry spans for plan, approval, lease, mutation, verification, compensation, and evidence persistence.
- [ ] Run connector, evidence, redaction, and integration tests.
- [ ] Commit with `feat: add observability connectors`.

## Task 20: Add signed evidence bundle verifier

**Files:**
- Create: `src/mayhem/domain/evidence_bundle.py`
- Create: `src/mayhem/cli/verify_bundle.py`
- Modify: `src/mayhem/infra/evidence.py`
- Modify: `docs/reference/output-schema.md`
- Test: `tests/unit/test_evidence_bundle.py`
- Test: `tests/integration/test_bundle_verifier.py`

**Interfaces:**
- Produces: `EvidenceBundle`, `BundleManifest`, `verify_bundle(path) -> BundleVerification`.
- Verification checks schema, hashes, signature metadata, replay digest, and redaction marker.

- [ ] Write tests for valid bundles, changed payloads, changed order, missing artifacts, invalid signature metadata, and secret-bearing extras.
- [ ] Implement deterministic bundle serialization and hash chaining.
- [ ] Add a standalone verifier command that does not require a live runtime.
- [ ] Run bundle, evidence, redaction, packaging, and integration tests.
- [ ] Commit with `feat: add portable evidence bundle verification`.

## Expansion checkpoint

- [ ] All new commands are plan-only until explicitly executed.
- [ ] Every new output is schema-validated and covered in human/JSON/YAML modes.
- [ ] All new integrations have timeout, redaction, and degraded-state tests.
- [ ] Campaign resume and game-day flows pass controller-loss simulations.
- [ ] Provider sandbox tests reject undeclared mutation authority.
- [ ] No live Kubernetes or remote-agent code is enabled by default.
