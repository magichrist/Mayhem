# Plan 29 — Secrets Management

**Priority:** P0. Gap item 13.

## Objective
Give chaos experiments the credentials they inevitably need without ever writing a secret into a spec, a plan, a log, or an evidence bundle.

## Builds on
- `config.py` target profiles already refuse forbidden credential keys — this plan turns that refusal into a positive system: references that resolve late, not values that sit in YAML.
- `domain/redaction.py` plus the evidence redaction boundary stay the last line of defense; this plan moves the first line to resolution time so redaction is backup, not policy.
- The Chaos Toolkit precedent (secrets as a first-class experiment concept) is followed for ergonomics, not for trust semantics: Mayhem references resolve against named providers under policy, never from ambient environment.

## Providers
Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault,
Kubernetes Secrets, OIDC workload identity, scoped environment
injection as a development-only path with a loud marker.

## Reference shape
```yaml
credentialRef:
  provider: vault
  secret: prod/database
```

Never `username`/`password` literals in an experiment. A literal where
a reference is required fails spec validation with the field named.

## Phase 1 — Domain model: references, grants, classification
Add `domain/secrets.py`: `CredentialRef` (provider, path, version pin, purpose binding), `SecretGrant` (which principal may resolve which ref for which run scope), `DataClassification` (secret, sensitive, internal, public) applied to evidence fields. Pure types; "reference without a grant" and "literal where a reference is required" as pure validation predicates. Acceptance: validation tests pin every refusal with the offending field named.

## Phase 2 — Engine: late resolution with least privilege
Resolution happens at execution time inside the narrowest scope that needs the value (agent-side for injection credentials, controller-side for provider API calls), fetched under the run's identity with short-lived tokens (OIDC workload identity preferred; static tokens deprecated loudly). Resolved values live in process memory only, never touch the store, and are zeroed after use. Scope rule: a credential resolved for step N is unavailable to step N+1 unless separately granted. Acceptance: memory-lifetime tests; cross-step leakage tests refused.

## Phase 3 — Surface: reference authoring and grant administration
Reference syntax in drill specs with schema validation; grant administration in CLI/UI (who may resolve what, for which environments, with what expiry); development-only environment injection requiring an explicit per-run marker sealed into evidence. Acceptance: authoring a literal secret fails validation in tests; grants render with effective-permission explanations.

## Phase 4 — Safety and evidence integration
Secrets never enter evidence artifacts: classification rules plus redaction enforced at the envelope boundary, with a CI gate scanning test fixtures and example specs for literal secrets; cloud credentials flow through 06 IAM-role validation (roles preferred over stored keys everywhere a cloud allows); rotation events recorded without values. Acceptance: the evidence produced by a secrets-bearing run contains zero credential bytes (byte-scan test over sealed bundles).

## Phase 5 — Tests, regression guards, negative controls
Provider-adapter tests against fixtures (no live vault in unit tests); grant tests (wrong principal, wrong scope, expired grant — all refused); redaction tests (value planted upstream must not appear downstream in any artifact: store rows, bundles, reports, logs). Negative controls: a run configured with a literal secret refuses before planning; a revoked grant mid-run fences the step. Acceptance: full matrix green; fixture-secret scanner in CI.

## Phase 6 — Docs, honesty gates, rollout
Secrets configuration guide per provider, grant-model reference, rotation runbook, incident process for suspected exposure (revoke, rotate, tombstone the evidence note — never rewrite sealed history). Rollout: Kubernetes Secrets plus environment-injection discipline first, Vault second, cloud managers third, workload identity throughout. Acceptance: no doc shows a literal credential in any example (scanner-enforced).

## Dependencies
06 (cloud IAM roles), 09 (principals, grants as authorization data), 12 (classification plus redaction enforcement), 19 (credential custody, rotation).

## STATUS
- Phase 1 (domain model): DONE — `domain/secrets.py` landed `CredentialRef`, `SecretGrant`, `DataClassification`, the `grant_refusals`/`find_grant`/`reference_is_granted`/`validate_reference`/`require_reference` access decision, the literal-credential scanner (`find_literal_credentials`, `has_literal_credential`, `require_no_literal_credentials`), and classification ordering (`classification_rank`, `most_restrictive`, `must_not_persist`); 79 tests.
- Phase 2 (engine): DONE — `infra/secret_resolver.py` landed `SecretResolverPort`/`SecretProviderPort`/`GrantSourcePort` seams over injectable callables (no provider SDK), the real `EnvironmentSecretProvider` plus a filesystem fixture provider, `ResolvedSecret` with in-place zero-after-use and a non-picklable value, `ResolutionReceipt` (metadata, never a value), `SecretLeakGuard`/`require_clean_bundle` for the byte-scan over sealed bundles, and `SecretGrantRepository` on migration `M0022_SECRET_GRANTS`; 58 tests.
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 2 of 6 phases complete.

Known limitation: **no provider adapter but the environment one is real.** `infra/secret_resolver.py` adds no third-party dependency, so Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, Kubernetes Secrets, and OIDC exist as *seams*: `CallableSecretProvider(provider, fn)` takes whatever callable a deployment injects, and the resolver refuses a reference whose provider has no registered adapter rather than guessing. `EnvironmentSecretProvider` and `FilesystemFixtureProvider` are the two implementations that need no library. Also: `SecretLeakGuard.require_clean_envelope` / `require_clean_bundle` are provided as gates but are **not yet called from `infra/evidence.py` or `build_evidence`** — wiring them into the write path is Phase 4's job, so today a caller must invoke the guard explicitly. Finally, zeroing a `bytearray` is the strongest custody Python offers; any `str` or `bytes` copy taken inside `ResolvedSecret.use()` is the caller's to zero, and this module cannot reach it.
