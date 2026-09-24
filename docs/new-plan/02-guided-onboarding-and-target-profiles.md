# Plan 02 — Guided Onboarding and Target Profiles

## Builder brief

Add a safe first-run experience and named environment selection. The CLI currently assumes the user already knows the config, compose file, engine, and topology shape. The onboarding layer must reduce that knowledge without hiding safety or automating mutation.

## Product model

A target profile is a named, validated environment definition containing engine, target locator, policy reference, and optional observability sources. It is not a secret store. It can point to environment variables or an external secret provider, but never embeds credentials.

## Phase 1 — Implement `mayhem init`

### Work

- Detect `docker-compose.yml`, `docker-compose.yaml`, `compose.yml`, `compose.yaml`, `mayhem.yaml`, and Kubernetes manifests.
- Detect whether Docker, Podman, or Kubernetes is explicitly configured without invoking the runtime.
- Generate a candidate profile and a safe starter drill without mutating the target.
- Prompt only for values that cannot be inferred; support `--non-interactive` and `--output`.
- Refuse to overwrite existing files unless `--force` is supplied.
- Print a next-step plan and the exact command needed to validate it.

### Files

- `src/mayhem/cli/init.py`
- `src/mayhem/cli/context.py`
- `src/mayhem/infra/project_detection.py`
- `tests/unit/test_cli_init.py`

### Verification

- Unit tests cover compose, manifest, existing config, noninteractive, overwrite refusal, and no-runtime detection.
- `init` never calls Docker, Podman, kubectl, or a cluster.

## Phase 2 — Implement `mayhem doctor`

### Work

- Validate config layering, spec parsing, target profile syntax, database migration state, and available host binaries.
- Separate checks into `config`, `database`, `engine`, `topology`, `capabilities`, and `permissions`.
- Support human, JSON, and quiet output.
- Return a typed diagnostic record with severity, remediation, and evidence references.
- Never claim a live runtime is healthy based on file presence alone.

### Files

- `src/mayhem/cli/doctor.py`
- `src/mayhem/infra/diagnostics.py`
- `tests/unit/test_cli_doctor.py`
- `tests/unit/test_diagnostics.py`

### Verification

- Tests prove missing optional runtimes are warnings, invalid configuration is an error, and database migration drift is actionable.
- JSON output is stable and machine-readable.

## Phase 3 — Add target profiles and explicit target context

### Work

- Add profile schema and loader with strict unknown-key rejection.
- Add `--target NAME` to discovery, planning, execution, coverage, and recovery commands.
- Show target profile, engine, namespace, and safety policy in preflight output.
- Require an explicit target for mutations when multiple profiles exist.
- Support profile inheritance only for safe defaults; prohibit inherited credentials and secret values.

### Acceptance criteria

- A new user can run `init`, `doctor`, and `validate` without knowing internal module structure.
- An operator can switch environments without reconstructing long flag combinations.
- Profile selection is visible in every machine-readable plan and run record.

### Verification

- Add tests for profile parsing, selection, ambiguity, environment isolation, and missing target refusal.
- Run full unit tests and Ruff only.
