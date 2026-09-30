# Plan 18 — Verified Fault Marketplace

**Priority:** P2. Gap items 33, 73, 76.

## Objective
Create a trusted ecosystem for reusable experiments, providers, and templates — where the trust labels are enforced by machinery, not marketing.

## Builds on
- `providers/pack.py` assurance (SHA-256 integrity enforced; signatures NOT verified — the two axes never collapsed into one "verified" flag) is the minimum bar for anything listed.
- The 01 certification states plus provider-version pinning decide what "verified" means per artifact; the marketplace displays those states, never invents its own.
- Honesty note, repeated deliberately: nothing here authenticates authorship until the signing lane exists. "Verified community" means certification evidence exists and the digest matches — not that an author is trusted.

## Artifact classes
Official, verified community, organization-private, unverified,
deprecated. An unverified artifact can never display a certified state;
a deprecated artifact cannot back new approvals.

## Required metadata
Publisher, version, digest, permissions, supported runtimes,
certification status, dependencies, license, changelog.

## Marketplace workflows
Search, install, update, pin version, revoke, trust publisher, inspect
permissions, validate compatibility.

## Phase 1 — Domain model: artifact and trust types
Add `domain/marketplace.py`: `Artifact` (class, version, digest, publisher declaration), `TrustLabel` with promotion rules as pure predicates over 01 records (e.g. verified-community requires a current certification record plus digest match — nothing less, nothing else), `Revocation` (scope, propagation deadline). Pure types. Acceptance: label-promotion tests where every path to "verified" requires the record; no shortcut compiles.

## Phase 2 — Engine: registry, pinning, revocation
Marketplace registry resolves pins (exact version plus digest), validates compatibility against the local matrix cell, and propagates revocations to the dispatch path (03 refuses revoked providers after the propagation deadline, with the refusal naming the revocation). Supply-chain records (gap 76: publisher, digest, SBOM, dependencies, permissions, verification state, release history) stored per artifact version. Acceptance: install-then-revoke drills; a revoked provider cannot execute post-deadline in tests.

## Phase 3 — Surface: search, inspect, install
Search and inspect flows showing permissions pre-install (17 display reused), compatibility verdicts, and certification states; organization-private registries federated with the same protocol. Experiment templates and scenario packs (gap 33 Mayhem Hub content) distributed as versioned artifacts with the same labels. Acceptance: install flows golden-tested; permission display accuracy tests.

## Phase 4 — Safety and evidence integration
Installed artifacts execute only through normal admission with pinned versions in evidence; template-instantiated experiments compile through the standard planner (a template is authoring convenience, never a gate bypass). Acceptance: an experiment instantiated from a template is indistinguishable downstream from an authored one.

## Phase 5 — Tests, regression guards, negative controls
Label-promotion tests, revocation-propagation tests, digest-mismatch tests, private-registry federation tests. Negative controls: a tampered artifact (digest mismatch) refused at install; an artifact claiming verified status without a record refused at listing. Acceptance: full matrix green.

## Phase 6 — Docs, honesty gates, rollout
Publisher guide, trust-label semantics doc (the most important page: what each label does and does not mean), revocation runbook. Rollout: organization-private registries first, official catalog second, community third. Acceptance: the overclaim scan (no "signed/verified/trusted" without same-breath qualification) extended to marketplace pages.

## Dependencies
01 (certification records), 03 (dispatch refusal), 12 (artifact evidence), 17 (provider declarations, SBOM).

## STATUS — planning only, 0%
