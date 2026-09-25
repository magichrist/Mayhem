# Output schema and changelog policy

Versioned output schema location: `src/mayhem/schemas/output_v1.json`

Current schema version: `1.0`

## Envelope

Every machine-readable command emits a versioned envelope:

```json
{
  "status": "ok",
  "schema_version": "1.0",
  "data": {},
  "warnings": [],
  "errors": [],
  "evidence_refs": [],
  "meta": {
    "renderer": "json",
    "format": "json"
  }
}
```

## Compatibility rules

- Existing numeric exit codes remain unchanged.
- Existing JSON keys remain present during the migration window; new fields are additive only.
- A deprecation warning is emitted to stderr, never into machine stdout.
- Human output is default; JSON is opt-in via `--json` or `--format json`; YAML is a documented extension point via `--format yaml`.
- Errors always expose a stable code and remediation path.

## Changelog policy

- Schema version bumps only on breaking change; additive fields do not bump major.
- The release changelog lives at `CHANGELOG.md`; this file records the schema
  contract, not release notes.
- `CHANGELOG.md` is raw `git-cliff` output and is kept verbatim, low-signal
  entries included: it is an audit record of what was committed, not a curated
  announcement. Regenerate it with `just changelog`; read the curated per-release
  view with `just changelog-release`. Do not hand-edit the generated file — a
  hand-edit is lost on the next regeneration, and
  `tests/unit/test_release_contract.py` checks the git-cliff footer so that a
  hand-edited file fails the suite instead of passing unnoticed.
- Consumers should pin to `schema_version` and ignore unknown keys.
- Legacy root commands and aliases were removed from the active surface after
  `0.8.0`; `docs/reference/cli.md` carries the checked command inventory, and the
  v0.9.0 line opens no new deprecation window.

## v0.9.0 compatibility boundary

`schema_version` stays `1.0` for the whole v0.9.0 line. The frozen surfaces are:

| Surface | v0.9.0 boundary | Authority |
|---------|-----------------|-----------|
| Output envelope | additive fields only, `schema_version` pinned to `1.0` | `src/mayhem/schemas/output_v1.json` |
| Exit codes | unchanged identifiers and numeric values | `src/mayhem/cli/exit_codes.py` |
| Root commands | exactly the `Command inventory` table | `src/mayhem/cli/command_registry.py` |
| Fault IDs | unchanged; no fault is added or removed | `src/mayhem/domain/catalog.py` |
| Provider contract | `mayhem.provider-catalog/v1` | `src/mayhem/domain/provider.py` |
| SQLite migrations | additive; no destructive migration | `src/mayhem/infra/store.py` |

The output-envelope row and the command-inventory row are machine-checked by
`tests/unit/test_release_contract.py`; the exit-code identifiers and Markdown
links are checked by `tests/unit/test_documentation_consistency.py`. The fault
ID, provider-contract, and SQLite-migration rows are declared boundaries for
this release line, not yet machine-checked invariants.

## Rendering rules

- Color disabled when stdout is not a TTY or `--no-color` or `NO_COLOR` is set.
- Truncation at 1000 chars, deterministic suffix `… (truncated, total N chars)`.
- Null renders as `-` in human, `null` in JSON.
- Empty list renders as `(empty)` in human, `[]` in JSON.
- Large integers beyond 9007199254740991 render without loss; human view preserves exact decimal.
