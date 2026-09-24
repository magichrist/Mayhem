# Policy, Environment Safety, and Break-Glass

## Policy profiles

BUILTIN_PROFILES in `src/mayhem/domain/policy.py`: default, strict, permissive, staging, production.
Field mapping via conversion layer to `MayhemConfigBase` policy and blast_radius without renaming fields.
Selection via `--policy` flag or `MAYHEM_POLICY` env. Conflicting sources rejected: file policy vs --policy, env vs flag, cli_overrides vs --policy.

## Environment isolation

- Target-profile inheritance allowlist: engine, compose, namespace, context, policy, targets, observability, env_ref.
- Secrets forbidden in target profiles: password, secret, token, credentials, api_key, kubeconfig, registry_token, secret_value.
- Sanitization: `sanitize_for_logging` redacts those keys in config show, explain, and evidence.

## Environment fingerprint

`environment_fingerprint(host_names, compose_digest, profile, policy_id, target_profile)` SHA256 includes profile, policy, and target so a run cannot execute against a different target than planned.

## Break-glass overrides

- `--skip-gate` bypasses impact gate. Prominent warning printed: `!!! BREAK-GLASS WARNING !!!` and evidence field `break-glass: --skip-gate`.
- Automation must treat skip-gate runs as failure unless `MAYHEM_ALLOW_SKIP_GATE=1` or `MAYHEM_BREAK_GLASS=1` is set. In JSON automation mode the CLI exits non-zero.
- `--allow-critical` plus `policy.allow_critical` and `policy.critical_fault_acks` triple opt-in remains.
- Audit fields in evidence: `environment_fingerprint`, `target_identity`, `blast_radius`, `compensation_status`, `safety_decisions`, `remediation` containing break-glass marker.

## Dry-run

`--dry-run` evaluates policy without mutating: `dry_run_policy_evaluation` returns typed decisions.
