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
- Phase 3 (surface: reference authoring and grant administration): PARTIAL — **the grant half is delivered; the reference-syntax half is not.** `mayhem secrets` (`cli/secrets_cmd.py`) is the administration surface Phase 3 asked for and Phase 4 recorded as absent: `grant` issues one grant (principal, pattern, environments, scopes, expiry — every bound required, because the domain refuses a grant with unbounded environments or no deadline), `revoke` withdraws by the `(principal, credential_pattern)` pair the resolver looks a grant up by and **refuses when it withdrew nothing**, `list` shows what each grant permits, and `explain` is the phase's acceptance criterion made operable: given a principal, a canonical key, an environment and a scope it names which grant answers and reports all five of its clauses (principal, pattern, environment, scope, unexpired), exiting non-zero when none does. 21 tests in `tests/unit/test_secret_grants_surface.py`, driven through the CLI because the exit codes are what a pipeline reads. **`require_no_literal_spec` has a production caller at last**: `_load_scenario` in `cli/experiment.py` — the point an authored scenario enters the process — refuses a document carrying a literal credential before it is compiled, naming the offending field path and never the value. Driving the surface through the real CLI proved the rendering (exit 4 with a remediation line) that `CliRunner` cannot see, which is why the test file asserts the domain's raise and the driver asserts the surface's. **What is NOT delivered, named rather than netted out:** *reference syntax in drill specs with schema validation* is still absent. `DrillSpec` has no `credentialRef` field, `load_scenario` compiles a document whose `env:` block is opaque, and this phase's literal gate catches a pasted credential without yet offering the declared alternative at the spec level — a reference is still only expressible where a caller constructs one (the resolver, the run path). The surface also has **no UI**: the phase says "CLI/UI" and plan 08's UI does not exist, so nothing was built to look like one. **No dependency changed and no crypto was added**; `--principal` remains a declared string with nothing authenticating it, which the `list` payload says in as many words.
- Phase 4 (safety and evidence integration): DONE — the evidence boundary is now structural rather than conventional: four no-opt-out gates in `infra/secret_resolver.py` (`require_persistable_document`, `require_envelope_boundary`, `require_clean_artifact`, `require_clean_log_line`) are called by every write path itself — envelope construction, the store row, the evidence file, all four renderers, the sealed bundle, the grant row, and the log line — over a process-wide needle registry, with a byte-scan of a real sealed bundle produced through the real pipeline as the acceptance test; no new dependency, no new migration. **Correction, same phase:** the list of write paths above was incomplete — `infra/audit_stream.py` was not among them. An audit entry is persisted, exported and covered by the attestation and retention machinery, so it is evidence, and its free-form `AuditEntry.detail` dict was an ungated write: an integrator reproduced a resolved credential reaching `audit_entries` while a guard was active. `AuditStream.record` now calls `require_persistable_document` before the transaction opens — the same gate, no new rule — and is registered in `tests/unit/test_evidence_boundary.py`'s `BOUNDARY_CALL_SITES`, so deleting the gate fails statically. The phase count is unchanged. **Second correction, same phase:** the same reasoning binds three further persist paths, found by a sweep of `src/mayhem/` for modules writing a document, blob or free-form payload. (1) `infra/attestation_store.py` — an attestation row is persisted, exported and covered by the retention and audit machinery, so it is evidence; all three of that module's writers are now gated (`seal_run_evidence`, and both `AttestationRepository.save_chain` / `save_manifest`), on the placement `audit_stream` chose and after sealing rather than before, because the chain and the manifest are two transactions and only a gate ahead of the first leaves neither half written. (2) `infra/replay_repository.py` — a capsule carries the caller-authored `spec`/`plan` of the run an operator is asked to reproduce, so it is evidence. (3) `infra/coverage_repository.py` — a coverage observation carries the caller-authored `verdict` and `metadata` of what a run did, so it is evidence; the gate covers both the insert and the update branch, so a refusal leaves a previously recorded row untouched. Same gate, same two rules, no new rule, no opt-out parameter, no new dependency, no new migration. The completeness guard in `tests/unit/test_evidence_boundary.py` was also tightened: it compared *modules*, so with three gated writers in one module, deleting any one of their three `BOUNDARY_CALL_SITES` rows still passed. It now compares `(module, function)` pairs in both directions — an unregistered gate-calling function fails, and so does a row that no longer describes a gate-calling function. The phase count is unchanged.
- Phase 5 (tests and negative controls): DONE — with one honest correction. The phase's *named* list was already covered before this phase: provider adapters are tested in `test_secret_resolver.py` (36 tests, `test_every_adapter_satisfies_the_provider_port`, no live vault anywhere), the grant refusals in `test_secrets.py` (79) and again across the resolver's ten-case `TestGrantMatrix` — wrong principal, wrong environment, pattern mismatch, expired grant, scope not granted, no grants at all — and both required negative controls exist by name: `test_a_literal_password_in_a_spec_refuses_before_execution` and `test_revoked_grant_fences_the_next_step_mid_run`. What did not exist was the phase's *acceptance criterion*, "fixture-secret scanner in CI", so that is what landed: `tests/unit/test_secret_fixture_scan.py` (12 tests) walks every YAML/JSON document under `examples/` and every fenced YAML/JSON example under `docs/`, with no allowlist, and reports through the domain's own `find_literal_credentials` so "what counts as a literal" has one answer. The scanner is in CI because `release.yml` runs `uv run pytest tests/unit`, and a test asserts that job still exists so the scanner cannot be silently disarmed. Its negative controls plant literals in `tmp_path` and prove each stage bites: the walk, the fenced-example extraction, and a `---`-separated Kubernetes manifest, which a single-document YAML loader would have skipped entirely. **Defect found and fixed while writing it:** the walk immediately reported `$.services.db.environment.POSTGRES_PASSWORD` in both `examples/testCase/docker-compose.yml` and its committed generated artifact — a literal credential in a published example, which is precisely what this plan forbids. The fix removed the credential rather than exempting the file: the db port is `expose`d and never published to the host, so the drill needs no authentication at all and now uses `POSTGRES_HOST_AUTH_METHOD: trust`. Ambient environment interpolation was considered and rejected, because `is_reference_value` deliberately does not accept it — this plan resolves against named providers under policy, *never* from ambient environment — so `${POSTGRES_PASSWORD:-x}` would still be a literal, and exempting it would have taught the scanner to call an env read a reference.
- Phase 6 (guides and rollout): DONE — five sections appended below. **Secrets configuration guide**, per provider, and honest about the shape of what exists: seven providers are named and **one ships an adapter** (`EnvironmentSecretProvider`, development-only and refused without the per-run marker); the other six are `CallableSecretProvider` seams, so the guide documents `register_provider` rather than printing a config block that does not run. **Grant-model reference**, the six dimensions of a `SecretGrant` as a table — who, what shape, where, how wide, until when, when issued — with the reason each is non-optional, all five grant refusal codes, and the note that every failing dimension is reported rather than the first. **Rotation runbook**, five ordered steps whose first is *pin the version* and whose third is *re-grant rather than widen*, because editing a grant in place would rewrite the history the receipts exist to preserve. **Incident process for suspected exposure**, ordered revoke → rotate → tombstone, and explicit that appending a tombstone is correct while editing or deleting the original audit row is not. **Rollout order**, the plan's Kubernetes-then-Vault-then-cloud-mansgers sequence with the reason environment injection leads *as the thing to discipline* rather than as the thing to adopt. Enforced, not just asserted: `tests/unit/test_secret_plan_docs.py` parses this file, cross-checks `Overall:` against the `DONE` lines, requires the five headings, verifies **every `secret.*` code quoted in backticks exists in the source** — a checker that immediately caught five invented codes while this section was being written — refuses the over-claims this plan is most likely to make, and proves each of its own checkers bites against a mutated copy.

Overall: 5 of 6 phases complete (Phases 1, 2, 4, 5, and 6), unchanged by this pass — **Phase 3 remains PARTIAL and is still not counted.** The grant-administration surface and the literal-credential gate's first production caller both landed, but the phase also names reference syntax in drill specs with schema validation and a UI, and neither exists: `DrillSpec` carries no `credentialRef`, and plan 08's UI is not written anywhere. Counting the phase on the half that landed would be the same kind of arithmetic this repository's ledgers exist to refuse.

Is the guard unskippable now? **Yes, and the mechanism is worth stating precisely, because "enforcement" was the whole point.** Two rules apply at every write path, neither with an opt-out:

* **The grade rule is stateless.** `require_persistable_document` calls `FieldClassifications.require_persistable` on every document it is handed, unconditionally, before any early return. It needs no registry, no configuration and no run state, so there is nothing a caller can leave unset to switch it off — it holds on a run that resolved no credential at all. The envelope form is stated in the domain as `require_persistable_envelope`, so the rule lives with the type.
* **The byte rule is ambient.** A `SecretLeakGuard` registered by `guard_evidence_writes` is consulted by every artifact write in the process, including from threads the caller did not spawn on the guard's thread. The registry is a lock-guarded set rather than a `ContextVar` precisely because a leak gate should fail closed in a worker thread, not fall back to "no needles registered". The only optional part is the *registration*, and it is optional in the safe direction: no active guard means no resolved value exists to leak, because a value enters the process only through `SecretResolver.resolve`, which is what registers the needles.

Three properties make that total rather than aspirational. The gate is **not a parameter** — no write path takes a `guard=`, and a test asserts the four gate functions expose no `enabled`/`skip`/`guard` keyword, so "I remembered to gate it" is not the property holding the line. It is **not skippable by delegation** — the gate runs *before* the envelope is constructed, *before* the store transaction opens (a refusal leaves no row and no `evidence_envelopes` table, which is stronger than a rollback), and *before* a bundle's first byte reaches disk (the whole bundle is staged, gated, then written, so a refusal never leaves a half-written leak). And it **cannot be deleted silently** — `tests/unit/test_evidence_boundary.py` parses the owned modules and asserts each write entry point still calls its gates, so removing a call fails the suite statically even where behaviour is masked by a second gate further down; all call sites are mutation-tested and each deletion fails at least one test.

Known limitation: **no provider adapter but the environment one is real.** `infra/secret_resolver.py` adds no third-party dependency, so Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, Kubernetes Secrets, and OIDC exist as *seams*: `CallableSecretProvider(provider, fn)` takes whatever callable a deployment injects, and the resolver refuses a reference whose provider has no registered adapter rather than guessing. `EnvironmentSecretProvider` and `FilesystemFixtureProvider` are the two implementations that need no library. Also, the envelope grade vocabulary is a *name* list: a value written under a field name nobody graded is caught by the byte rule but not by the grade rule, which is why both exist and why neither is described as sufficient. The log boundary is a provided gate (`require_clean_log_line`) rather than an in-repo call site, because this build has no logging sink — `structlog` is named in the plan's dependency set but is imported nowhere under `src/`, so there is no log-emitting module for the gate to be wired into; the sink that is added must route through it. One limitation is now named rather than papered over: the static conformance table is hand-maintained, so it proves a *listed* write path still calls its gates but not that the list is complete — which is exactly how the audit-stream defect survived it. Half of that is now closed: a test fails when any module calls a boundary gate without a `BOUNDARY_CALL_SITES` row, so a new gated path cannot drift out of the table. The other half — a brand-new write path with *no* gate call — is not decidable from source text without an allowlist that would reproduce the same hand-maintained table under a second name, so it is left as a review obligation instead of a check that would pass while the hole stayed open. Finally, zeroing a `bytearray` is the strongest custody Python offers; any `str` or `bytes` copy taken inside `ResolvedSecret.use()` is the caller's to zero, and this module cannot reach it.

## Secrets configuration guide

Seven providers are named in the plan and **one of them ships an adapter**: the
rest are seams, and the honest way to configure one is to say so rather than to
print a config block that does not run. `SecretResolver.resolve` refuses a
reference whose provider has no registered adapter with
`secret.provider_unavailable` instead of guessing, so a missing adapter is a
refusal at the first resolution, not a silent fallback.

* **`environment` — real, and development-only.**
  `EnvironmentSecretProvider(environ)` reads a named variable and is the one
  adapter that needs no library. It is refused with
  `secret.development_only_provider_not_permitted` unless the resolver was built
  with `allow_development_only=True`, which is the "explicit per-run marker"
  Phase 3 asks for. Two rules it enforces on its own: a variable name shaped like
  a path is refused (an environment provider that would read `PROD/DB` as a name
  is a provider guessing), and an empty value is refused rather than resolved to
  an empty string.
* **`vault`, `aws_secrets_manager`, `gcp_secret_manager`, `azure_key_vault`,
  `kubernetes`, `oidc` — seams.** Register each with
  `resolver.register_provider(SecretProvider.VAULT, CallableSecretProvider(
  SecretProvider.VAULT, my_fetch))`, where `my_fetch` takes a `ProviderRequest`
  and returns bytes. `CallableSecretProvider` adds no policy; it is the injection
  point that keeps a provider SDK out of this repository.
* **`FilesystemFixtureProvider(root)`** is the fixture adapter unit tests use:
  it serves `<root>/<secret>`, optionally at a pinned `version`, and reports the
  default provider as `vault` so a fixture test exercises the real code path
  rather than a special one.

**The window is short on purpose.** Every `ProviderRequest` carries
`expires_at = issued_at + credential_ttl_seconds` (default 900, one OIDC token
lifetime), and if the clock reads past that window after `fetch` returns, the
value is refused with `secret.provider_credential_expired`. A provider that
hangs does not get to hand back a credential nobody can revoke any more.

## Grant-model reference

A `SecretGrant` is a whole permission and answers six questions. A reference that
no grant answers is invalid, not merely undocumented.

| Dimension | Field | Shape | Why it exists |
|---|---|---|---|
| Who | `principal` | exact string | The identity the permission is issued to. |
| What | `credential_pattern` | glob over `canonical_key`, e.g. `vault:prod/*` | Narrow is better; a bare `*` is legal and grants the whole provider namespace. |
| Where | `environments` | non-empty globs, e.g. `prod-*` | Required and non-empty: an unbounded environment scope is a grant with no boundary, so the type refuses to express one. |
| How wide | `scopes` | globs over `step:inject-db` / `run:r-1`; empty means any scope within the covered environments | This is the cross-step rule: a value resolved for step N is not available to step N+1 unless separately granted. |
| Until when | `expires_at` | timestamp | Required. A grant with no end date would be a standing permission. |
| When issued | `issued_at` | timestamp | Evidence, and the anchor a rotation runbook reasons from. |

**Every failing dimension is reported, not just the first**, so "why was this
refused?" gets the whole answer rather than the first thing that happened to be
checked. `grant_refusals(grant, reference, ...)` returns the codes
`secret.grant_principal_mismatch`, `secret.grant_pattern_mismatch`,
`secret.grant_environment_out_of_scope`, `secret.grant_scope_not_granted`,
`secret.grant_expired`; with no grant at all the decision is
`secret.reference_without_grant`, and `require_reference` raises with the field
name attached. The resolver adds three more on top of the grant decision:
`secret.development_only_provider_not_permitted`,
`secret.provider_unavailable` and `secret.resolver_scope_handoff` — the last for
a step-scoped reference asked for while a *different* step executes, which is the
engine half of the cross-step rule.

**Revocation is a delete, not a flag.** `SecretGrantRepository.revoke` removes the
matching rows, and `StoredGrantSource` re-reads on every resolution precisely so
nothing is cached between the revoke and the next step. The prior
`ResolutionReceipt`s stay: they are the standing evidence that the permission
existed, and a receipt carries metadata only — provider, canonical key, purpose,
scope token, principal, environment, grant pattern, timestamps — never a value.

**Four more codes an operator can be handed, and what each one means.** These do
not come from the grant decision, so they are worth stating separately because
they are the ones that arrive *after* authorization succeeded:

* `secret.literal_where_reference_required` — a spec or document carried a
  credential value where a `credentialRef` was required. Fix the authoring; there
  is no way to resolve this at runtime.
* `secret.resolved_value_already_spent` — the value was used once and its buffer
  was zeroed, and something asked for it again. Each resolution produces one
  single-use value; reuse means either two grants where one was intended, or one
  `use()` block spanning two steps.
* `secret.credential_bytes_in_artifact` — a resolved value's bytes were found in
  an artifact a write path was about to persist. This is the byte rule firing,
  and it fires *before* the write rather than after, so the store row, the bundle
  and the report are all absent rather than rolled back.
* `secret.secret_classified_field_present` — a document carried a field graded
  `secret` where persistence is forbidden. This is the grade rule firing, and it
  is stateless: it holds on a run that resolved no credential at all.

## Rotation runbook

1. **Pin the version if the run must reproduce.** `CredentialRef.version` takes
   an exact version, so a drill authored against a rotated secret still resolves
   the version it was written for. Without it, the reference follows the provider's
   current version, which is the right default for a live drill and the wrong one
   for a replay.
2. **Rotate at the provider, not in mayhem.** Mayhem holds no secret to rotate; it
   holds a reference, a grant, and receipts. Rotation is the provider's event, and
   what mayhem records is `issued_at` on the new grant.
3. **Re-grant rather than widen.** A rotated secret usually needs a *new* grant
   for the same narrow pattern. Editing a grant in place would rewrite the
   permission's history, which is the thing the receipts exist to preserve.
4. **Expired grants are not a rotation failure.** `secret.grant_expired` is the
   correct refusal for a grant that outlived its window; issue the successor
   grant before the old one lapses if the drill is mid-campaign.
5. **A revoked grant fences the next step mid-run** — the property
   `tests/unit/test_secret_resolver.py::TestRevocationFence` pins, and the reason
   `StoredGrantSource` caches nothing.

## Incident process for suspected exposure

Ordered, because the order is the part that gets skipped under pressure.

1. **Revoke first, before rotating.** A rotation alone leaves the exposed
   credential valid until the provider's cache lapses; `revoke` removes the grant
   row, and with it the resolver's authority to fetch anything.
2. **Rotate at the provider.** Then re-issue a narrow grant under
   `issued_at` = the rotation time, so the receipts on either side of the event
   are distinguishable.
3. **Tombstone the evidence note — never rewrite sealed history.** An
   `AuditEntry` is persisted, exported, and covered by the attestation and
   retention machinery. Appending a tombstone that names the incident is correct;
   editing or deleting the original row is not, and the byte gate is deliberately
   unable to authorise it.
4. **Confirm nothing carries the bytes.** The boundary gates
   (`require_persistable_document`, `require_envelope_boundary`,
   `require_clean_artifact`, `require_clean_log_line`) and the ambient
   `SecretLeakGuard` are the evidence that the value did not reach a store row, a
   bundle, a report or a log line. `tests/unit/test_secret_fixture_scan.py` is the
   separate check that no *example* or documented YAML ships one.
5. **Expect the forensic limit.** Zeroing a `bytearray` is the strongest custody
   Python offers. Any `str` or `bytes` copy taken inside `ResolvedSecret.use()` is
   the caller's to zero, and this module cannot reach it — so step 4 is evidence
   about mayhem's own write paths, not a claim about the host.

## Rollout order

Kubernetes Secrets and environment-injection discipline first, Vault second,
cloud managers third, workload identity throughout — the plan's order, kept
because it runs from "no adapter at all" to "no static token anywhere", and each
step is worth more than the one before it. Environment injection leads the
sequence *as the thing to discipline* rather than as the thing to adopt: it is
the development-only provider, and shipping it first means shipping its marker and
its refusal with it.
