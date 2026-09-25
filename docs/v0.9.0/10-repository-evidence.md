# v0.9.0 Repository Evidence Index

This file records the current-state evidence used by the v0.9.0 plans. It is a planning snapshot, not a live-runtime certification.

## Product and CLI

- Active command registration: `src/mayhem/cli/command_registry.py`
- Root CLI assembly and exception mapping: `src/mayhem/cli/app.py`
- Workflow groups: `src/mayhem/cli/workflows.py`
- CLI reference: `docs/reference/cli.md`
- Product direction: `docs/product/cli-product-direction.md`
- Command architecture: `docs/product/command-architecture.md`

## Core safety and execution

- Safety decisions and critical-fault controls: `src/mayhem/controller/safety.py`
- Run execution and lease lifecycle: `src/mayhem/controller/executor.py`
- Lease state model: `src/mayhem/domain/leases.py`
- Recovery and janitor behavior: `src/mayhem/controller/janitor.py`
- Tool invocation and captured output: `src/mayhem/toolkit/tool_runner.py`

## Runtime and Kubernetes

- Runtime descriptors and engine selection: `src/mayhem/domain/runtime_adapter.py`
- Kubernetes target resolution: `src/mayhem/agents/k8s_resolve.py`
- Kubernetes runtime registration and contracts: `src/mayhem/controller/k8s_runtime.py`
- Kubernetes discovery provider: `src/mayhem/topology/providers/kubernetes.py`
- Kubernetes executor families: `src/mayhem/agents/executors.py`
- Kubernetes status qualification: `docs/reference/fault-catalog.md`
- Kubernetes live-status caveats: `docs/k8s-plan-1.md` and `docs/k8s-plan-2.md`

## Evidence and persistence

- Evidence domain model: `src/mayhem/domain/evidence.py`
- Evidence assembly: `src/mayhem/infra/evidence.py`
- SQLite store: `src/mayhem/infra/store.py`
- Report artifacts: `src/mayhem/infra/report.py`
- Output schema: `docs/reference/output-schema.md`
- SQLite schema: `docs/reference/sqlite-schema.md`

## Catalog, coverage, and campaigns

- Fault catalog: `src/mayhem/domain/catalog.py`
- Fault definitions: `src/mayhem/domain/faults.py`
- Catalog report: `src/mayhem/infra/catalog_report.py`
- Campaign engine: `src/mayhem/infra/campaign_engine.py`
- Exploration flow: `src/mayhem/controller/explore_flow.py`
- CLI explore: `src/mayhem/cli/explore.py`
- Campaign CLI: `src/mayhem/cli/campaign.py`

## Provider and extension surface

- Provider loader: `src/mayhem/providers/loader.py`
- Built-in provider metadata: `src/mayhem/providers/builtin.py`
- Provider SDK reference: `docs/provider-sdk.md`
- Extension CLI: `src/mayhem/cli/extend.py`

## Existing planning baseline

- Product and CLI roadmap: `docs/new-plan/00-product-and-cli-roadmap.md`
- Workflow command architecture: `docs/new-plan/01-workflow-command-architecture.md`
- Plan-first execution and evidence: `docs/new-plan/03-plan-first-execution-and-unified-evidence.md`
- Configuration and policy: `docs/new-plan/05-configuration-policy-and-environment-safety.md`
- Docker/Podman reliability: `docs/new-plan/06-docker-podman-reliability-slice.md`
- Kubernetes engine: `docs/new-plan/07-first-class-kubernetes-engine.md`
- Fault catalog reliability: `docs/new-plan/08-fault-catalog-reliability-matrix.md`
- Campaigns, coverage, and explore: `docs/new-plan/09-campaigns-coverage-and-explore-loop.md`
- Diagnostics, recovery, and reporting: `docs/new-plan/10-diagnostics-recovery-and-reporting.md`
- Extension API and packaging: `docs/new-plan/11-extension-api-and-packaging.md`

## Existing tests used as evidence

- CLI contract: `tests/unit/test_cli_exit_codes.py`
- CLI error envelopes: `tests/unit/test_cli_errors.py`
- Active command matrix: `tests/unit/test_cli_exhaustive_matrix.py`
- Exhaustive catalog matrix: `tests/unit/test_fault_catalog_exhaustive.py`
- Runtime execution matrix: `tests/unit/test_runtime_execution_matrix.py`
- Topology providers: `tests/unit/test_topology_providers.py`
- In-process CLI E2E: `tests/e2e/test_cli_e2e.py`
- Agent watchdog integration: `tests/integration/test_agent_watchdog_e2e.py`

## Current release and quality surface

- Release workflow: `.github/workflows/release.yml`
- Project dependencies and pytest configuration: `pyproject.toml`
- Local automation: `Justfile`
- Current tag and release notes: `CHANGELOG.md`
- Package distribution: `mayhem-cli`
- Console command: `mayhem`
- Default Kubernetes dependency: `kubernetes>=31`

## Known planning caveats

- The repository has substantial unit and fake-runtime coverage, but unit tests do not certify live Kubernetes behavior.
- Runtime availability varies by machine; tests must select explicit runtimes when more than one engine is installed.
- Current import-linter contracts expose architecture debt; v0.9.0 reduces that debt through vertical-slice migrations rather than claiming it is already clean.
- Current release automation was repaired during the 0.8.x line; v0.9.0 adds PR-level quality gates and artifact verification rather than assuming tag-only testing is sufficient.
