# Plan 04 — Output, Errors, and Script Compatibility

## Builder brief

Create one output and error system for human users, CI systems, and future providers. The current CLI has mixed JSON, text, color, quiet flags, abbreviated commands, and command-local database options. This plan standardizes the contract while preserving existing scripts.

## Compatibility rules

- Existing numeric exit codes remain unchanged.
- Existing JSON keys remain present during the migration window; new fields are additive.
- A deprecation warning is emitted to stderr, never into machine stdout.
- Human output is default; JSON is opt-in; YAML is a documented extension point.
- Errors always expose a stable code and remediation path.

## Phase 1 — Define output envelopes and renderers

### Work

- Define `CommandResult` with status, data, warnings, errors, evidence refs, and renderer metadata.
- Implement table, key-value, tree, human summary, JSON, and YAML renderers.
- Define color and TTY detection; disable color for noninteractive output and `--no-color`.
- Make truncation, null, empty list, and large numeric values deterministic.

### Files

- `src/mayhem/cli/output.py`
- `src/mayhem/cli/renderers.py`
- `tests/unit/test_cli_output.py`
- `tests/unit/test_cli_renderers.py`

### Verification

- Snapshot tests cover every renderer and edge case.
- JSON output is valid, stable, and never polluted by human text.

## Phase 2 — Standardize errors, diagnostics, and deprecations

### Work

- Define `MayhemCliError` carrying code, message, details, remediation, and evidence reference.
- Map domain, safety, config, usage, tool, recovery, and ambiguous-command errors to existing exit codes.
- Add structured diagnostic codes for missing target, missing capability, stale plan, blocked topology, and unavailable engine.
- Add deprecation metadata to command registry and warnings.
- Ensure `--debug` adds a traceback without changing the stable error code or machine output.

### Files

- `src/mayhem/cli/errors.py`
- `src/mayhem/cli/app.py`
- `src/mayhem/cli/deprecation.py`
- `tests/unit/test_cli_errors.py`
- `tests/unit/test_cli_deprecations.py`

### Verification

- Tests assert every stable exit code for representative failures.
- Tests assert no secret values appear in error details or debug output.

## Phase 3 — Protect and migrate automation

### Work

- Add golden JSON fixtures for every public command.
- Add compatibility tests that invoke every legacy alias.
- Add a `--format` option with `text`, `json`, and `yaml` values while preserving existing `--json`.
- Add a migration report command showing aliases, deprecation age, replacement, and sample invocation.
- Publish a versioned output schema location and changelog policy.

### Acceptance criteria

- A CI script can switch to the new workflow commands without losing exit semantics.
- A human can use the same command interactively without parsing terminal formatting.

### Verification

- Run command inventory, CLI contract, output, error, and full unit tests.
- Run Ruff and separate existing baseline violations from new violations.
