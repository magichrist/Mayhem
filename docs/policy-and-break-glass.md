# Policy, Environment Safety, and Break-Glass

## Policy profiles

BUILTIN_PROFILES in `src/mayhem/domain/policy.py`: default, strict, permissive, staging, production.
Field mapping via conversion layer to `MayhemConfigBase` policy and blast_radius without renaming fields.
Selection via `--policy` flag or `MAYHEM_POLICY` env. Conflicting sources rejected: file policy vs --policy, env vs flag, cli_overrides vs --policy.

## Environment isolation

- Target profiles are configuration: a top-level `targets:` block (or its `profiles:` alias) in `mayhem.yaml` is validated by `load_config` and merged per profile name across layers. The merged, overlay-aware result is what every consumer resolves (discovery, preflight, diagnostics). See [`config.md`](config.md).
- Target-profile inheritance allowlist: engine, compose, namespace, context, policy, targets, observability, env_ref. Inheritance is one level deep.
- Credential keys rejected inside a target profile: password, secret, token, credentials, api_key, apikey.
- Redacted when configuration is rendered — by `sanitize_for_logging` in config show, config explain, and evidence: password, secret, token, credentials, api_key, apikey, kubeconfig, registry_token, registry_tokens, secret_value, secrets.
- A target profile's `policy:` is declarative. It names a policy the run does not enforce; the enforced policy is the one `--policy`, `MAYHEM_POLICY`, or the `policy:` block resolves. `mayhem doctor` reports a profile whose declared name is not a built-in policy, and says nothing about a name that resolves.
- A drill document's own `targets:` block declares logical targets, not target profiles, and is never read as one.

## Environment fingerprint

`environment_fingerprint(host_names, compose_digest, profile, policy_id, target_profile)` SHA256 includes profile, policy, and target so a run cannot execute against a different target than planned.

## Break-glass overrides

- `--skip-gate` bypasses impact gate. Prominent warning printed: `!!! BREAK-GLASS WARNING !!!` and evidence field `break-glass: --skip-gate`.
- Automation must treat skip-gate runs as failure unless `MAYHEM_ALLOW_SKIP_GATE=1` or `MAYHEM_BREAK_GLASS=1` is set. In JSON automation mode the CLI exits non-zero.
- `--allow-critical` plus `policy.allow_critical` and `policy.critical_fault_acks` triple opt-in remains.
- Audit fields in evidence: `environment_fingerprint`, `target_identity`, `blast_radius`, `compensation_status`, `safety_decisions`, `remediation` containing break-glass marker.

## Dry-run

`--dry-run` evaluates policy without mutating: `dry_run_policy_evaluation` returns typed decisions.
