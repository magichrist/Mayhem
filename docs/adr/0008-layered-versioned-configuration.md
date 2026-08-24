# 0008. Configuration: Layered, Versioned, Pydantic-Validated

- **Date:** 2026-08-23
- **Status:** Accepted

## Context

The spec demands configuration be a *major subsystem*: controller, agents, targets, topology,
toolkit, policies, blast radius, safety limits, observation, notifications, load generation,
fuzzing, scheduling, concurrency, production safeguards, and future K8s/plugin knobs. YAML is the
human-facing language. Misconfiguration here can destroy systems, so validation must be strict and
every run must record exactly what config produced it.

## Options considered

1. **Loose dict parsing (`yaml.safe_load` + getattr chains).** Rejected: typos become behavior;
   no audit trail.
2. **JSON Schema validation only.** Better, but two sources of truth (schema vs code) and weak
   typing downstream.
3. **Layered pydantic models with versioned documents and run-scoped snapshots.** Chosen.

## Decision

- Every YAML document carries `apiVersion: mayhem/v1`. Unknown versions rejected loudly; unknown
  keys rejected strictly (typo = error, not silence).
- **Layering order** (later wins): built-in defaults → `mayhem.yaml` (project root or `--config`)
  → profile overlays (`--profile staging` loads `mayhem.{profile}.yaml`) → `TGONDI_*` environment
  variables (limited allowlist: storage path, artifacts dir, log level) → CLI flags.
- Pydantic v2 models mirror the schema; cross-field rules (e.g., `risk_ceiling: critical` requires
  explicit acknowledgement flag) validated in a policy pass, not scattered checks.
- The **effective merged config is snapshotted into every run row** — reproducibility includes
  provenance of settings, not just seed.
- Secrets are never stored in config files; references only (env var names), redacted in snapshots.

Full annotated schema: [reference/configuration-schema.md](../reference/configuration-schema.md).

## Consequences

- **Positive:** fail-fast on bad config before touching any system; profiles enable dev/staging
  variants of the same project; snapshots make historical runs fully explainable.
- **Negative:** strictness can annoy early users (mitigated by `mayhem init` generating valid
  starter config and precise error paths like `policy.blast_radius.max_services_pct`);
  pydantic models must be kept in sync with docs (docs reference generated schema).
