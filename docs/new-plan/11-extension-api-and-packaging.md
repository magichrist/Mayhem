# Plan 11 — Extension API and Packaging

## Builder brief

Introduce a stable extension boundary only after the built-in engine and workflow slices are coherent. The goal is to let the project add engines, fault families, checks, reporters, and policy backends without allowing plugins to bypass planning, safety, leases, or evidence contracts.

## Extension contract

A provider may contribute:

- Engine discovery and runtime capabilities.
- Fault definitions and parameter schemas.
- Target locators and resolution evidence.
- Safety or capability predicates.
- Compensation primitives.
- Checks and observability sources.
- Report renderers.

A provider may not directly execute an uncompiled plan, bypass safety, fabricate compensation, or hide capability failures.

## Phase 1 — Define interfaces and compatibility versioning

### Work

- Add provider protocol modules under `src/mayhem/providers/`.
- Separate declaration from runtime implementation so the domain can validate providers without importing external code.
- Define capability descriptors, fault declarations, target locators, evidence records, and provider metadata.
- Add provider version compatibility and a stable registration format.
- Add a built-in provider registry that wraps current Docker, Podman, and Kubernetes implementations.

### Files

- `src/mayhem/providers/protocols.py`
- `src/mayhem/providers/registry.py`
- `src/mayhem/providers/builtin.py`
- `src/mayhem/domain/provider.py`
- `tests/unit/test_provider_registry.py`

### Verification

- Built-in providers register without behavior changes.
- Protocol tests reject incomplete or unsafe declarations.
- Domain modules remain free of provider I/O.

## Phase 2 — Add safe plugin loading and isolation

### Work

- Support entry-point or explicitly configured plugin loading.
- Validate plugin metadata before loading implementation code.
- Add permission declarations for network, filesystem, subprocess, and target access.
- Refuse plugins that request undeclared mutation permissions.
- Add a dry-run plugin inspection command.
- Keep plugin failures typed and isolated from built-in providers.

### Files

- `src/mayhem/providers/loader.py`
- `src/mayhem/cli/extend.py`
- `tests/unit/test_provider_loader.py`
- `tests/unit/test_cli_extend.py`

### Verification

- Malformed, incompatible, and over-permissioned providers are rejected.
- No plugin is loaded during ordinary built-in CLI commands unless explicitly configured.
- Unit tests never import or execute untrusted third-party code.

## Phase 3 — Publish SDK, examples, and governance

### Work

- Document provider authoring, versioning, testing, safety, compensation, and evidence requirements.
- Add a minimal example provider with no external runtime dependency.
- Add catalog validation and compatibility checks for external providers.
- Add deprecation and security response procedures.
- Add a compatibility matrix for the CLI, provider API, catalog schema, and evidence schema.

### Acceptance criteria

- A builder agent can add a test provider without modifying CLI internals.
- The platform remains safe by construction when a provider is absent, broken, or incompatible.
- Built-in functionality does not depend on plugin availability.

### Verification

- Run provider, CLI, safety, documentation, and full unit tests.
- Run Ruff only; no external runtime or E2E test is required.
