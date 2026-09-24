# Plan 05 — Configuration, Policy, and Environment Safety

## Builder brief

Turn configuration and safety policy into visible, reviewable CLI inputs. The current layered configuration is useful but opaque to users, and `--skip-gate`/`--allow-critical` are easy to misuse. This plan adds explicit policy profiles and explainable preflight decisions without changing the current model semantics unnecessarily.

## Phase 1 — Normalize configuration and policy surfaces

### Work

- Add a `PolicyProfile` model containing risk ceiling, allowed/denied faults, blast-radius limits, critical acknowledgements, and environment restrictions.
- Keep `MayhemConfigBase` as the compatibility model; add a conversion layer rather than renaming fields.
- Add `config explain` to show each effective field, source layer, and whether it is safe for mutation.
- Add `--policy` to select a named policy profile.
- Reject conflicting policy sources instead of silently choosing one.

### Files

- `src/mayhem/config.py`
- `src/mayhem/domain/policy.py`
- `src/mayhem/cli/config_cmd.py`
- `tests/unit/test_config.py`
- `tests/unit/test_cli_config.py`

### Verification

- Existing config fixtures continue to pass.
- Tests cover source precedence, policy conflicts, environment variables, and explanation output.
- No secret values are rendered by `config explain`.

## Phase 2 — Add safety explanations and policy gates

### Work

- Represent every safety decision as a typed decision record: rule id, input values, outcome, reason, remediation, and severity.
- Render refused faults with the exact policy rule and the change required to permit them.
- Require an explicit policy id in generated plans.
- Make `--skip-gate` produce a prominent warning, an evidence field, and a non-zero automation status unless an explicit override is supplied.
- Add dry-run policy evaluation for all mutating commands.

### Files

- `src/mayhem/controller/safety.py`
- `src/mayhem/domain/decisions.py`
- `src/mayhem/cli/preflight.py`
- `tests/unit/test_capability_safety.py`
- `tests/unit/test_policy_explain.py`

### Verification

- Tests assert policy explanations for risk ceiling, blast radius, critical opt-in, capability, and topology drift.
- A safety refusal never silently downgrades to a warning.

## Phase 3 — Add environment isolation and safe secret boundaries

### Work

- Add target-profile policy inheritance with explicit allowlists.
- Prevent credentials, kubeconfig contents, registry tokens, and secret values from entering logs, plans, and evidence.
- Add environment fingerprint fields to preflight and run evidence.
- Add `doctor` checks for profile identity, policy identity, and target mismatch.
- Document break-glass overrides and their audit fields.

### Acceptance criteria

- Users can understand why a fault was allowed or refused without reading source.
- A run cannot execute against a different target than the one described by its plan.
- Policy and secret behavior is covered by unit and documentation tests.

### Verification

- Run config, safety, CLI contract, documentation, and full unit tests.
- Run Ruff and record all remaining violations with changed-file attribution.
