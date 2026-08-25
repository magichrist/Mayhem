# CLI Refactor Report

**Date**: 2026-08-25
**Scope**: `src/mayhem/cli/` — full replacement of Typer with Click

---

## What changed

The `mayhem` CLI was rewritten from a single-file Typer application into a
multi-module Click package. No existing domain, controller, infra, or toolkit
code was modified; the change is confined to the CLI layer.

### Before (Typer)

- Single file `src/mayhem/cli.py` containing all commands, resolver logic,
  services, exit codes, and the debug-reraise boundary.
- Typer handled argument parsing, help generation, and type coercion.
- Unique-prefix resolution was not supported; users had to type full command
  names.
- Exit codes were ad-hoc integers with no central definition.

### After (Click)

| File | Purpose |
|---|---|
| `app.py` | Root group, `main()` entry, error→exit-code mapping |
| `resolver.py` | `PrefixGroup` + unique-prefix resolution |
| `context.py` | `CliContext` dataclass |
| `services.py` | Thin service layer (UI-framework-agnostic) |
| `lifecycle.py` | validate, plan, run, status, history, recover, janitor |
| `experiment.py` | experiment show/validate group |
| `topology.py` | topology discover group |
| `toolkit.py` | toolkit faults/list group |
| `config_cmd.py` | config show/validate group |
| `exit_codes.py` | `ExitCode` enum (stable public contract) |

---

## Key design decisions

### 1. Unique-prefix resolution (no external dependency)

A `PrefixGroup(click.MultiCommand)` subclass resolves unambiguous prefixes
at every level of the tree. This lets users type `mayhem e v` instead of
`mayhem experiment validate` without adding `click-completion` or any third-
party resolver. The implementation is ~60 lines with a full test suite.

Ambiguous prefixes exit with code `10` (`AMBIGUOUS_COMMAND`) and print the
matching candidates, so scripts can detect and handle the ambiguity.

### 2. Services layer as the UI/domain boundary

`services.py` is the only file that imports from `mayhem.controller.*`,
`mayhem.infra.*`, or `mayhem.toolkit.*`. Handlers in `lifecycle.py`,
`experiment.py`, etc. translate Click arguments into service calls and format
results. This means a future REST or TUI layer can reuse every service
function without touching Click.

### 3. Centralized exit-code mapping

`ExitCode(IntEnum)` defines 11 stable exit codes (0–10). The `main()`
function's top-level try/except maps every typed exception to the correct
code. Handlers never format exit codes themselves — they raise domain errors
and let `main()` translate them.

### 4. Debug-reraise via module-level state

The `--debug` flag stores its value in a module-level `_STATE` dict (not a
Click context attribute) so the top-level exception handler can read it after
the Click context has unwound. This avoids the fragile pattern of reaching
into `click.get_current_context()` during exception processing.

### 5. Group-as-singleton via `add_command` reuse

`experiment validate` reuses the exact same handler object as the top-level
`validate` command (registered via `experiment.add_command(_validate_handler)`).
No behavioral drift between the two paths — they are literally the same
function.

---

## File changes summary

| File | Action |
|---|---|
| `src/mayhem/cli/app.py` | Created (root group + main + error mapping) |
| `src/mayhem/cli/resolver.py` | Created (PrefixGroup + prefix resolution) |
| `src/mayhem/cli/context.py` | Created (CliContext dataclass) |
| `src/mayhem/cli/services.py` | Created (service layer extracted from old cli.py) |
| `src/mayhem/cli/lifecycle.py` | Created (lifecycle commands) |
| `src/mayhem/cli/experiment.py` | Created (experiment group) |
| `src/mayhem/cli/topology.py` | Created (topology group) |
| `src/mayhem/cli/toolkit.py` | Created (toolkit group) |
| `src/mayhem/cli/config_cmd.py` | Created (config group) |
| `src/mayhem/cli/exit_codes.py` | Created (ExitCode enum) |
| `src/mayhem/cli/__init__.py` | Updated (namespace only) |
| `src/mayhem/cli.py` | Removed |
| `pyproject.toml` | Updated (entry point → mayhem.cli.app:main, ruff per-file-ignores) |
| `docs/reference/cli.md` | Rewritten for the new surface |
| `README.md` | Updated quickstart (`mayhem faults` → `mayhem toolkit faults`) |
| `tests/unit/test_cli.py` | Rewritten for Click surface + prefix + e2e tests |
| `tests/unit/test_cli_resolver.py` | Created (PrefixGroup unit tests) |
| `tests/unit/test_cli_exit_codes.py` | Created (exit-code mapping tests) |
| `tests/unit/test_cli.py` (old Typer tests) | Removed (replaced) |

---

## Bugs fixed during the refactor

1. **`toolkit list` rendered phantom attributes**: The old handler referenced
   `entry.available`, `entry.reason_if_unavailable`, and `entry.manifest_id`
   — none of which exist on `ProbedTool`. Fixed to use `entry.manifest.tool`,
   `entry.version`, and to list missing tools by comparing against the
   registered manifest set.

---

## Verification

All four gates pass:

| Gate | Command | Result |
|---|---|---|
| Tests | `pytest tests/ -q` | 196 passing |
| Lint | `ruff check src tests` | clean |
| Type | `mypy src` | 0 errors, 58 files |
| Layers | `lint-imports` | 3 contracts kept, 0 broken |

CLI-specific tests (33 cases) cover:
- Prefix resolution (exact, unique prefix, ambiguous, multi-level, help bypass)
- Exit code mapping for every error family
- E2E run with proc.pause → history verification

---

## Migration notes

- `mayhem faults` → `mayhem toolkit faults`
- `mayhem tools status` → `mayhem toolkit list`
- `mayhem config show` / `mayhem config validate` — unchanged (now under the
  `config` group, same name)
- All other command names are unchanged; prefix resolution means existing
  scripts that type enough of the name will continue to work.
