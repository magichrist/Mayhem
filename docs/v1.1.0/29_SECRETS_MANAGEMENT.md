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
- Phase 3: not started — `scan_spec_for_literals`/`require_no_literal_spec` exist but have no production caller, there is no spec-schema wiring for `credentialRef`, and there is no CLI or UI grant administration. (Wave bookkeeping expected this phase to land alongside Phase 4; it has not, so the honest count below is 3, not 4.)
- Phase 4 (safety and evidence integration): DONE — the evidence boundary is now structural rather than conventional: four no-opt-out gates in `infra/secret_resolver.py` (`require_persistable_document`, `require_envelope_boundary`, `require_clean_artifact`, `require_clean_log_line`) are called by every write path itself — envelope construction, the store row, the evidence file, all four renderers, the sealed bundle, the grant row, and the log line — over a process-wide needle registry, with a byte-scan of a real sealed bundle produced through the real pipeline as the acceptance test; no new dependency, no new migration. **Correction, same phase:** the list of write paths above was incomplete — `infra/audit_stream.py` was not among them. An audit entry is persisted, exported and covered by the attestation and retention machinery, so it is evidence, and its free-form `AuditEntry.detail` dict was an ungated write: an integrator reproduced a resolved credential reaching `audit_entries` while a guard was active. `AuditStream.record` now calls `require_persistable_document` before the transaction opens — the same gate, no new rule — and is registered in `tests/unit/test_evidence_boundary.py`'s `BOUNDARY_CALL_SITES`, so deleting the gate fails statically. The phase count is unchanged. **Second correction, same phase:** the same reasoning binds three further persist paths, found by a sweep of `src/mayhem/` for modules writing a document, blob or free-form payload. (1) `infra/attestation_store.py` — an attestation row is persisted, exported and covered by the retention and audit machinery, so it is evidence; all three of that module's writers are now gated (`seal_run_evidence`, and both `AttestationRepository.save_chain` / `save_manifest`), on the placement `audit_stream` chose and after sealing rather than before, because the chain and the manifest are two transactions and only a gate ahead of the first leaves neither half written. (2) `infra/replay_repository.py` — a capsule carries the caller-authored `spec`/`plan` of the run an operator is asked to reproduce, so it is evidence. (3) `infra/coverage_repository.py` — a coverage observation carries the caller-authored `verdict` and `metadata` of what a run did, so it is evidence; the gate covers both the insert and the update branch, so a refusal leaves a previously recorded row untouched. Same gate, same two rules, no new rule, no opt-out parameter, no new dependency, no new migration. The completeness guard in `tests/unit/test_evidence_boundary.py` was also tightened: it compared *modules*, so with three gated writers in one module, deleting any one of their three `BOUNDARY_CALL_SITES` rows still passed. It now compares `(module, function)` pairs in both directions — an unregistered gate-calling function fails, and so does a row that no longer describes a gate-calling function. The phase count is unchanged.
- Phase 5: not started
- Phase 6: not started

Overall: 3 of 6 phases complete.

Is the guard unskippable now? **Yes, and the mechanism is worth stating precisely, because "enforcement" was the whole point.** Two rules apply at every write path, neither with an opt-out:

* **The grade rule is stateless.** `require_persistable_document` calls `FieldClassifications.require_persistable` on every document it is handed, unconditionally, before any early return. It needs no registry, no configuration and no run state, so there is nothing a caller can leave unset to switch it off — it holds on a run that resolved no credential at all. The envelope form is stated in the domain as `require_persistable_envelope`, so the rule lives with the type.
* **The byte rule is ambient.** A `SecretLeakGuard` registered by `guard_evidence_writes` is consulted by every artifact write in the process, including from threads the caller did not spawn on the guard's thread. The registry is a lock-guarded set rather than a `ContextVar` precisely because a leak gate should fail closed in a worker thread, not fall back to "no needles registered". The only optional part is the *registration*, and it is optional in the safe direction: no active guard means no resolved value exists to leak, because a value enters the process only through `SecretResolver.resolve`, which is what registers the needles.

Three properties make that total rather than aspirational. The gate is **not a parameter** — no write path takes a `guard=`, and a test asserts the four gate functions expose no `enabled`/`skip`/`guard` keyword, so "I remembered to gate it" is not the property holding the line. It is **not skippable by delegation** — the gate runs *before* the envelope is constructed, *before* the store transaction opens (a refusal leaves no row and no `evidence_envelopes` table, which is stronger than a rollback), and *before* a bundle's first byte reaches disk (the whole bundle is staged, gated, then written, so a refusal never leaves a half-written leak). And it **cannot be deleted silently** — `tests/unit/test_evidence_boundary.py` parses the owned modules and asserts each write entry point still calls its gates, so removing a call fails the suite statically even where behaviour is masked by a second gate further down; all call sites are mutation-tested and each deletion fails at least one test.

Known limitation: **no provider adapter but the environment one is real.** `infra/secret_resolver.py` adds no third-party dependency, so Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, Kubernetes Secrets, and OIDC exist as *seams*: `CallableSecretProvider(provider, fn)` takes whatever callable a deployment injects, and the resolver refuses a reference whose provider has no registered adapter rather than guessing. `EnvironmentSecretProvider` and `FilesystemFixtureProvider` are the two implementations that need no library. Also, the envelope grade vocabulary is a *name* list: a value written under a field name nobody graded is caught by the byte rule but not by the grade rule, which is why both exist and why neither is described as sufficient. The log boundary is a provided gate (`require_clean_log_line`) rather than an in-repo call site, because this build has no logging sink — `structlog` is named in the plan's dependency set but is imported nowhere under `src/`, so there is no log-emitting module for the gate to be wired into; the sink that is added must route through it. One limitation is now named rather than papered over: the static conformance table is hand-maintained, so it proves a *listed* write path still calls its gates but not that the list is complete — which is exactly how the audit-stream defect survived it. Half of that is now closed: a test fails when any module calls a boundary gate without a `BOUNDARY_CALL_SITES` row, so a new gated path cannot drift out of the table. The other half — a brand-new write path with *no* gate call — is not decidable from source text without an allowlist that would reproduce the same hand-maintained table under a second name, so it is left as a review obligation instead of a check that would pass while the hole stayed open. Finally, zeroing a `bytearray` is the strongest custody Python offers; any `str` or `bytes` copy taken inside `ResolvedSecret.use()` is the caller's to zero, and this module cannot reach it.
