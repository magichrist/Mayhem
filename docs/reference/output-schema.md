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
- Changelog lives at `docs/reference/cli.md` and this file.
- Consumers should pin to `schema_version` and ignore unknown keys.
- Deprecations advance: warn since `0.6.0`, removal target `0.8.0`.

## Rendering rules

- Color disabled when stdout is not a TTY or `--no-color` or `NO_COLOR` is set.
- Truncation at 1000 chars, deterministic suffix `… (truncated, total N chars)`.
- Null renders as `-` in human, `null` in JSON.
- Empty list renders as `(empty)` in human, `[]` in JSON.
- Large integers beyond 9007199254740991 render without loss; human view preserves exact decimal.
