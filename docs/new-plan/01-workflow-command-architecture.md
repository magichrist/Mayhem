# Plan 01 — Workflow Command Architecture

## Builder brief

Refactor the CLI presentation layer around user workflows without breaking the current command surface. The new tree should make common paths obvious while keeping the existing domain/controller/agent architecture unchanged.

## Target command shape

```text
mayhem discover
mayhem prepare
mayhem experiment
mayhem run
mayhem inspect
mayhem recover
mayhem extend
mayhem init
mayhem doctor
```

Each group owns a small set of subcommands. Exact legacy commands such as `topology`, `plan`, `validate`, `status`, `history`, `campaign`, `toolkit`, `coverage`, `next`, and `explore` remain aliases during the compatibility window.

## Phase 1 — Define command ownership and routing

### Work

- Add a command registry that declares command name, owner workflow, aliases, help group, mutation risk, and output contract.
- Replace ad hoc abbreviation discovery with a deterministic resolver that rejects ambiguous prefixes with the existing `AMBIGUOUS_COMMAND` exit code.
- Preserve exact command names and legacy aliases before adding abbreviations.
- Add command metadata for `--help` examples and deprecation state.

### Files

- `src/mayhem/cli/app.py`
- `src/mayhem/cli/command_registry.py`
- `src/mayhem/cli/errors.py` or the existing error boundary
- `tests/unit/test_command_inventory.py`
- `tests/unit/test_cli_contract.py`

### Verification

- Every current top-level command is covered by the registry.
- Exact legacy invocation returns the same exit code for success and representative failure.
- Ambiguous prefixes still return `ExitCode.AMBIGUOUS_COMMAND`.

## Phase 2 — Implement the new workflow groups

### Work

- Add `discover` with `topology`, `faults`, and `capabilities` views.
- Add `prepare` with `config`, `dependencies`, `plan`, and `check` views.
- Add `experiment` with `show`, `validate`, `synthesize`, and `diff` views.
- Add `inspect` with `runs`, `run`, `coverage`, `history`, and `leases` views.
- Add `recover` with `run`, `janitor`, and `status` views.
- Add `extend` as the future-facing home for catalog and provider operations; initially delegate to `toolkit` and `dependency`.
- Keep each group thin: parse input, resolve context, call existing service functions, render output.

### Verification

- New group handlers call the same service layer as legacy handlers.
- No controller/domain module imports Click or renders output.
- Each group has a focused unit test for success, usage error, and domain failure.

## Phase 3 — Roll out compatibility and migration UX

### Work

- Add deprecation warnings only when a legacy alias is used.
- Include the replacement command in warnings and `--help`.
- Add `mayhem commands` or `mayhem help-map` to show the old/new mapping.
- Add command-level examples for common workflows: discover, prepare, plan, execute, inspect, and recover.
- Update CLI documentation and generated help fixtures.

### Acceptance criteria

- New users can discover the recommended path from root help without reading source.
- Existing scripts continue to work during the migration window.
- The command tree can be changed in one registry location rather than across unrelated modules.

### Verification

- Run command inventory, CLI contract, documentation, and full unit tests.
- Run Ruff and record remaining baseline violations separately from new violations.
