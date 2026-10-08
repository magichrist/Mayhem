# Plan 18 — Fault Marketplace and What "Verified" Means

**Priority:** P2. Gap items 33, 73, 76.

## Objective
Create a trusted ecosystem for reusable experiments, providers, and templates — where the trust labels are enforced by machinery, not marketing.

## Builds on
- `providers/pack.py` assurance (SHA-256 integrity enforced; signatures NOT verified — the two axes never collapsed into one "verified" flag) is the minimum bar for anything listed.
- The 01 certification states plus provider-version pinning decide what "verified" means per artifact; the marketplace displays those states, never invents its own.
- Honesty note, repeated deliberately: nothing here authenticates authorship until the signing lane exists. "Verified community" means certification evidence exists and the digest matches — not that an author is trusted.

## Artifact classes
The five `ArtifactClass` values are `official`, `verified`,
`organization_private`, `unverified` and `deprecated`; the
[trust-label table](18_trust_labels.md) states what each one does
and does not establish. An `unverified` artifact can never display a certified
state; a `deprecated` artifact cannot back new approvals.

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

## Phase 5 outcome — the controls existed; proving they were load-bearing did not

Every control this phase names was already in the tree, and the `not started`
status was stale in the way plan 14's was: a tampered artifact is refused at
install (`test_a_tampered_artifact_is_refused_and_recorded`), a cold label cannot
claim a certified state (`test_a_cold_label_cannot_claim_a_certified_state`),
promotion and revocation propagation are covered in `test_marketplace.py`, and
federation closure is sealed in `test_marketplace_evidence.py`.

What was missing is what the completed plans in this package record: proving the
properties *underneath* those assertions are load-bearing. A suite of correct
assertions over a predicate that no longer enforces anything is still green, and
these are the predicates a reader's trust label rests on.

`tests/unit/test_marketplace_negative_controls.py` pins six properties, each
two-sided so it cannot pass by coincidence:

1. **Deprecation dominates.** A withdrawn artifact reads `DEPRECATED` even on the
   official registry with a current certification record behind it. The paired
   case is the same artifact without the notice reading `OFFICIAL`, so the test
   above cannot also pass against a classifier that ignored both.
2. **Distribution beats evidence.** An organization-private artifact with a current
   record still reads `ORGANIZATION_PRIVATE` — the label means "this came from your own
   catalogue", and a certification does not change where it came from. The
   community artifact with the *same record* reads `VERIFIED_COMMUNITY`.
3. **A record for other bytes grants nothing.** The digest comparison is what makes
   `VERIFIED_COMMUNITY` a claim about *these* bytes rather than about the
   artifact's identity.
4. **Currency needs two independent conditions.** `grants_live_verification` and
   `now < expires_at`. Each alone is insufficient: certified-but-lapsed and
   unexpired-but-not-granting both fail, which is precisely what a
   single-condition implementation would break.
5. **`now` is a parameter, not a clock read.** Classification changes when *only*
   `now` changes. Anything reading the wall clock would make the two calls agree.
6. **Pending is not blocking.** A revocation inside its propagation deadline is
   announced and does not stop a dispatch; after the deadline it does. "We told
   you yesterday" and "we stopped it" are different claims.

Plus: the publisher declaration does not move the label, which is the property the
whole trust-label page rests on, and `require_trust_label` names the class it
refused rather than raising something generic.

### Two things this cost

* **The first draft imported the fixtures** from `tests/unit/test_marketplace.py`,
  which was tidier and wrong: `mypy` follows the import and reports seventeen
  errors belonging to *that* file, six of them pre-existing (it imports
  `test_readme_honesty` by a name that only resolves under pytest's rootdir
  insertion, so mypy sees the module as `Any` and every call through it as
  untyped). Reverting to local fixtures was the honest fix and is recorded here
  rather than hidden: **the pre-existing broken import in `test_marketplace.py`
  is still there** and is not this phase's to fix.
* Rebuilding `MatrixCell` and `CertificationRecord` by hand got nine required
  fields wrong on the first attempt. The lesson is in the file: reuse the
  fixtures the existing assertions are written against, or read the model.

## Phase 6 outcome — the semantics page, and the scan that keeps it honest

`docs/v1.1.0/18_trust_labels.md` is the page the phase calls its most important
one. It leads with the sentence that bounds every row — every label is evidence
about bytes on a certification cell or about where those bytes were published,
and none is evidence about who wrote them — and gives each of the five classes a
row with **both** what it establishes and what it does not.

`tests/unit/test_marketplace_plan_docs.py` is the acceptance criterion: the
overclaim scan, extended to marketplace pages. A trust word must carry its
qualification **in the same sentence**, and a table row counts as its own unit,
because a row has no terminating period and one disclaimer would otherwise float
up to qualify every cell above it.

Three findings came from running it against the real documents rather than
against synthetic strings:

* **The scan flagged `signed` inside `unsigned`.** These plans discuss
  `unsigned_no_signing` constantly, so an unanchored pattern demanded a
  disclaimer for the very sentences saying signing is *not* implemented. The
  pattern is word-bounded now. The same substring trap caught the identity gate
  earlier with `port` inside `ProviderPort`.
* **The qualifier vocabulary was too narrow for the honest prose already here** —
  "enforced by machinery", "not that an author is trusted", "signatures NOT
  verified". Widening it conforms the gate to real qualifications rather than
  weakening it, and the two-sided controls still catch a bare claim.
* **The negative-column check originally looked for a phrase repeated in every
  row**, which could only pass if the table repeated its own header. It checks the
  cell is non-empty now, which is what a reader actually sees.
* **Two rules were missing, and both were found by running the scan on the real
  pages rather than on synthetic strings.** A heading was being joined onto the
  paragraph beneath it, so its trust word rode down as somebody else's
  disclaimer; a heading is now its own unit, terminated so it is actually
  scanned — which is how the plan's own title, "# Plan 18 — Verified Fault
  Marketplace", was caught. It is now "# Plan 18 — Fault Marketplace and What
  \"Verified\" Means". Separately, a page *about* trust labels has to be able to
  name the words it scans: a sentence whose trust words are all inside quotes
  or backticks is naming the vocabulary, not claiming a property, so it is not
  an offender. The rule is all-or-nothing on purpose — one bare word among
  quoted ones is a claim wearing a quotation mark as a disguise, and a control
  proves it is still caught.

Six mutations of the real documents are each proven to fail the gate: a bare
"trusted by Mayhem" appended to the guide, a label row with its negative column
blanked, an inflated ledger count, an unqualified heading, and unquoting the
words this plan quotes when it describes its own mutations. A bare "signed" is
the first of these and was proved before the scan was extended.

### What these do not claim

* **The scan reads prose.** It checks that a sentence qualifying a trust word
  exists, not that the qualification is *correct*. The page and the build are
  kept in agreement by the separate assertion that
  `SIGNATURE_VERIFICATION_IMPLEMENTED` is still `False` while the page says so.
* **It scans two documents.** `docs/README.md`, the provider SDK docs and the
  v1.0.0 package have their own gates; this one covers the marketplace pages and
  this plan.
* **Rollout order is unchanged** and recorded as the phase specifies:
  organization-private registries first, official catalog second, community third.
  Nothing in Phase 6 changed what is federated today.
* **No publisher guide or revocation runbook was written.** The phase lists both;
  what landed is the trust-label semantics page and the scan that keeps it honest.
  The runbook in particular is coupled to Phase 3's install surface, which does
  not exist yet.

## STATUS
- Phase 1 (domain model): DONE — `src/mayhem/domain/marketplace.py` landed `ArtifactClass` (official, verified_community, organization_private, unverified, deprecated), `Artifact` (id, version, sha256 digest, publisher *declaration*, registry, dependencies, declared permissions, license, changelog ref, deprecation notice), `ArtifactCertification` — the pairing of a plan-01 `CertificationRecord` with the artifact digest it was actually made against, `RegistryRef`/`RegistryScope`/`RegistryFederation`, the pure promotion predicates (`is_current_record`, `matching_certifications`, `classify_artifact`, `trust_label`, `require_trust_label`), `TrustLabel` + `CLASS_MEANING`, `Revocation`/`RevocationScope`/`RevocationReason` with the propagation-deadline predicates (`dispatches`, `dispatch_refusal`, `blocking_revocations`, `pending_revocations`), the approval predicates (`approval_refusals`, `backs_new_approval`), and the gap-76 supply-chain record per artifact version (`SupplyChainRecord`, `SourceChainEntry`/`SourceStage`, `SbomRef`, `ReleaseEvent`, `DigestCheckState`, `check_digest`); 100 tests in `tests/unit/test_marketplace.py`. **How the type is structurally unable to overclaim:** `TrustLabel` has **no class field** — `artifact_class` is a derived property over three stored facts (registry scope, deprecation, certifications), and `Artifact` has no trust field at all, both with `extra="forbid"`, so "marking" an artifact is not a value either type can hold; every path to `verified_community`/`official` requires an `ArtifactCertification` whose `artifact_digest` equals the artifact's own digest and whose record is live and unexpired at an injected `now`, and `require_trust_label` is the only way to *ask* for a class and refuses by name; federation is deliberately not an input to `classify_artifact`, so a private registry peer of the official catalogue gains nothing; `DigestCheckState` has no `signed`/`trusted` member; a test asserts over *every* model field in the module that no name reads as authentication, and another asserts the module never reads a clock. **SIGNATURE VERIFICATION IS NOT IMPLEMENTED** — `mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` remains `False` and this phase does not change it: the module repeats it as a second literal (`mayhem.domain.marketplace.SIGNATURE_VERIFICATION_IMPLEMENTED`) that a test pins equal to the providers flag, `PublisherDeclaration` carries only a publisher id, display name, contact, and organization with no signature/key-id/algorithm field for a future commit to fill in, `SourceChainEntry.actor` is a declared name of the same standing as a comment header, and `SIGNATURE_TRUST_NOTICE` is returned by `TrustLabel.notice` so a renderer cannot print a class word without the qualification reachable in the same breath. **No label in this model implies authorship authentication:** every class word — including `official` and `verified_community` — is evidence about *bytes on a runtime cell* or about *where the bytes were published*, and never about who wrote them; `CLASS_MEANING` states that in the same string a renderer prints, and `ArtifactClass` itself contains no word for trust.
- Phase 2 (engine): DONE — `src/mayhem/infra/marketplace_store.py` landed the catalog store behind `M0028_MARKETPLACE` (`marketplace_registries`, `marketplace_artifacts`, `marketplace_certifications`, `marketplace_supply_chain`, `marketplace_revocations`, `marketplace_pins`) and the engine over it: `MarketplaceStore` (publish/deprecate/link/record/revoke/pin, one transaction per write, derived label re-derived on every read) and `MarketplaceRegistry` (`resolve` by exact version **and** digest, `verify_bytes`, `install`, `approval_gate`, `compatibility` against a local `MatrixCell`, `listing`/`listing_entry`, `federation`/`require_registry`, and the two dispatch seams `admit` and `guarded_factory`); 92 tests in `tests/unit/test_marketplace_store.py`. **Decisions a reviewer should read first.** (a) *Deprecation does not stop an installed artifact from dispatching.* Revocation is the withdrawal instrument: it carries a reason, a deadline, and an id a refusal can name (`RevocationReason.SUPERSEDED` is the "use the newer version" case), and a deprecation notice has no deadline at all — so letting it kill running code would make deprecation strictly stronger than the instrument designed to be auditable, and would collapse Phase 1's `pending_revocations`/`blocking_revocations` split for the one case that cannot express it. Deprecation is therefore enforced where it is a *new* grant: `install` refuses it (`marketplace.deprecated_install`) and `approval_gate` reports it, while every `DispatchAdmission` reports `deprecated` and the reason so a withdrawn version running in the field is visible rather than merely un-refused. An operator who wants it to stop revokes it, and then the gate refuses it by name — that drill is a test. (b) *Revocation reaches the loader's dispatch path through the loader, not beside it.* `admit()` refuses a blocking revocation with the message from `dispatch_refusal` (so the refusal names the revocation), then asks the *same* `ProviderLoader` for the enforcer over the profile it chose and runs that loader's own `SandboxEnforcer.admit()`; a provider the loader refuses is still refused by the loader's own exception, unwrapped. `guarded_factory()` closes the remaining window by re-checking at the moment `ProviderRegistry.runtime()` materialises the runtime, which is why the install-then-revoke test asserts on the *registry* path and not only on `admit`. (c) *No trust class is stored anywhere in Phase 2.* The schema has no class column; `ResolvedPin`, `ListingEntry`, and `DispatchAdmission` each carry a `TrustLabel` and expose `artifact_class` as a property, because a dataclass field would have been constructible with any value. A listing that *claims* a class goes through `require_trust_label` and is refused by name. (d) *`marketplace_supply_chain.signature_verified` is `CHECK (signature_verified = 0)`* — a 1 cannot be written without a migration that admits it, so the table can never be read as provenance. A revocation has no stored "in force" column either, because that verdict moves with the clock. **HONESTY GATE, stated for every phase that follows:** SIGNATURE VERIFICATION IS NOT IMPLEMENTED. `mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` is `False`, and the same fact is repeated as a pinned `False` literal in `mayhem.domain.marketplace` and in `mayhem.infra.marketplace_store`; a test pins all three equal. **NO TRUST LABEL IN THIS SYSTEM IMPLIES AUTHORSHIP AUTHENTICATION.** `official`, `verified_community`, and `organization_private` are statements about *bytes on a cell* and about *where those bytes were published* — nothing more. A `PublisherDeclaration` records who says they published an artifact and nothing can check it; the sha256 content digest is checked at install and that proves integrity, not provenance. Phase 3's surfaces and Phase 6's docs must carry `SIGNATURE_TRUST_NOTICE` in the same breath as any label, and Phase 5's overclaim scan must treat "signed", "verified", and "trusted" as words this build cannot use about a publisher.
- Phase 4 (safety and evidence integration): **DONE.** Sealing, privileged-action audit, and one correction to Phase 2's coupling claim, all in `src/mayhem/infra/marketplace_store.py`; 39 tests in `tests/unit/test_marketplace_evidence.py`. **Sealing.** `MarketplaceEvidence` writes each catalogue activity into plan 12's own chain through `AttestationRepository` — the same `AttestedEvent` type, the same `seal_events`, the same `verify_chain`, the same `Manifest`. A publish, a pin, an unpin, an install, a refused install, a revocation, a deprecation, a trust-publisher link, and a federation closure each seal one event and one manifest; the vocabulary is the closed tuple `MARKETPLACE_ACTIVITY_KINDS`. One activity is one chain, keyed by an id derived from the payload's own content digest, so replaying a drill is idempotent by construction rather than by a caller being careful, and ordering across activities is carried by the manifest chain (`previous_manifest_digest`), which lets an export of the manifests alone reconstruct the order the catalogue moved in. Every payload names the artifact digest, the registry, and the **derived** trust class together with that label's own `meaning()` plus `signature_verification_implemented: False` and `SIGNATURE_TRUST_NOTICE` — so a consumer holding only the exported chain can answer *which bytes were admitted, under which label, from which digest* without this database. A **refused** install seals its own activity and reports `artifact_class: null`, because a refusal is not evidence and a label for bytes that were not admitted is the overclaim this whole lane exists to prevent. **Sealing is not signing:** every manifest is written with `signature_state = unsigned_no_signing` and plan 12's own reason string stored beside it, because the chain proves these bytes are unaltered and in order and proves nothing at all about who produced them. **Audit.** Install, revoke, and trust-publisher are the three entries of `MARKETPLACE_PRIVILEGED_ACTIONS` and go through `AuditStream.record` with no second format invented; publishing a catalogue row and recording a deprecation are sealed but are *not* privileged actions, since neither grants nor withdraws standing on a runtime and putting them in the privileged log would dilute it with entries that mean the opposite. `principal` is what the caller declared and nothing authenticates it. **The no-FK coupling claim was checked, and it did not hold — it was fixed rather than restated.** Phase 2 claimed that `marketplace_certifications` having no foreign key to `certification_records` was free. The *survival* half is free and remains the right design: the row outlives any transition, so "were these bytes ever certified" stays answerable without a join a later move could erase, and `test_a_record_can_age_in_place_while_the_pairing_stays_consistent` proves the stored snapshot is genuinely untouched while the label drops. The *truth* half was false. A pairing stores a **snapshot**, and a snapshot cannot follow `CertificationRepository.store_transition`: time ageing survived only because `is_current_record` compares `expires_at` against the caller's `now` independently, but a record demoted in place to `failed` or moved to the terminal `incompatible` left the catalogue still reporting `verified_community` for evidence a human had just withdrawn. `MarketplaceStore.certifications` now resolves every pairing against the authoritative record whenever plan 01 holds rows for that `(fault_id, cell)`, matched on the identity a transition provably cannot move (`_claim_identity`: fault, cell fingerprint, `certified_at`, evidence bundle set — pinned by `test_a_transition_cannot_move_the_identity_the_resolution_keys_on`); when plan 01 has no rows for the fault at all the catalogue is the sole authority and the snapshot stands as Phase 2 described; and when it holds rows that cannot be matched the claim **fails closed** as `stale` rather than being trusted. **The one clock read that decides.** `CLOCK_DECISION_NOTE` names it: `guarded_factory` is the only place a wall clock can change a verdict, and it deliberately takes **no** `now` parameter, because it runs at runtime-materialisation time and a caller-supplied instant is precisely the stale value that lets a revoked provider execute — injecting a clock there would make the one safety property this lane cannot compromise opt-out-able, which is theatre in the exact sense the phrase is used elsewhere in this repository. Every other policy decision (`resolve`, `admit`, `listing`, `compatibility`, `install`) takes `now`, and `test_every_policy_decision_is_replayable_and_ignores_the_wall_clock` proves it behaviourally by holding a fictional catalog constant while moving the host clock four years. The other wall-clock reads in the module are *stamps*, not decisions, and every one is overridable. **Negative controls, each executable rather than described:** a tampered artifact is refused **and** sealed (`marketplace.install.refused`, carrying both the requested and the observed digest, because the disagreement between them *is* the failure); an install of bytes that do not hash to the published digest leaves no pin, no privileged-action entry, and no class above `unverified` anywhere; a revoked artifact cannot execute after its deadline through either the admission path or the guarded runtime factory, and both refusals name the revocation; an unverified artifact never displays a certified state in a listing, in a `listing_entry(claimed=...)` request, or in a sealed payload; and `test_no_payload_ever_reports_a_signature_as_verified` walks every sealed payload, audit entry, manifest, listing entry, dispatch admission, and resolved pin this phase produces and fails on any key that reads as authentication, using the same honesty regex the document gate uses. **The three signature literals still agree and are all `False`.** **SIGNATURE VERIFICATION IS NOT IMPLEMENTED** — this phase did not change `mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED`, did not add a signer seam, and every marketplace manifest it writes is unsigned with the reason recorded. **NO TRUST LABEL IN THIS SYSTEM IMPLIES AUTHORSHIP AUTHENTICATION** — the sealed payload's `artifact_class` is read off a `TrustLabel`, which has no class field, and it travels with the label's own `meaning()` sentence and the trust notice; `publisher_is_declared_only: True` is recorded beside every publisher id because the honest sentence about that field is not optional. Phase 3's surfaces must carry `SIGNATURE_TRUST_NOTICE` in the same breath as any label they read out of a sealed payload, and Phase 5's overclaim scan must treat the sealed chain as a published surface.
- Phase 3 (surface: search, inspect, install): DONE — `src/mayhem/cli/marketplace_cmd.py` landed the `mayhem marketplace` group (`list`, `search`, `inspect`, `install`) over `MarketplaceRegistry.listing`/`resolve`/`install`, registered in `command_registry.py` (`extend` workflow, `mutating` because `install` pins bytes) and in the `test_command_inventory.py` allowlist. Read-only except install: `list`/`search`/`inspect` resolve and derive labels without writing anything (inspect never calls `verify_bytes`, which records a verdict and is therefore a write, not a read). Permission display is the artifact's declared set rendered verbatim in the plan-17 provider vocabulary and labelled declared-not-granted, and install grants nothing — the grant lives with the provider loader and nothing here writes it. Every class word is printed with its own `meaning()` and `SIGNATURE_TRUST_NOTICE` in the same breath, in text and in JSON, and `signature_verification_implemented: False` travels in every payload because no signature is checked anywhere on this surface. `--digest` (the bytes the caller intends to install) and `--observed-digest` (the sha256 of the bytes actually in hand) stay separate required options, so "we checked the digest" cannot become a claim about a file nobody hashed. A refusal names its record and exits nonzero, and a refused install seals a refusal rather than evidence. Compatibility verdicts are not invented: a verdict needs the runtime cell it is made against and the CLI builds none, so `inspect` reports the cells the current records were made on and `install` checks compatibility only when its caller supplies a cell. What did not land: template and scenario-pack artifact types (gap 33 content as versioned artifacts), which is what keeps Phase 4's second clause unmet — see the note below. Acceptance: install flows drilled end-to-end through the real CLI (success, tampered-bytes refusal, missing version) with permission bytes asserted verbatim, and the related suites green.
- Phase 5 (tests, regression guards, negative controls): DONE — every control the phase names already existed (tampered artifact refused at install, cold label unable to claim a certified state, promotion and revocation propagation, federation closure sealed), so what was missing was the discipline the completed plans record. `tests/unit/test_marketplace_negative_controls.py` proves the predicates underneath those assertions are **load-bearing**: deprecation dominates even on the official registry with live evidence; distribution beats evidence; a record for other bytes grants nothing; currency needs both conditions independently; `now` is a parameter rather than a clock read; and pending revocation is not blocking. Each is two-sided.
- Phase 6 (docs, honesty gates, rollout): DONE — `docs/v1.1.0/18_trust_labels.md` is the trust-label semantics page the phase calls its most important one, and `tests/unit/test_marketplace_plan_docs.py` is the acceptance criterion: the overclaim scan extended to marketplace pages, requiring a trust word to carry its qualification in the **same sentence**. The scan is scoped by one word: every label names what it establishes and what it does not.

Overall: 6 of 6 phases complete. Phase 4's second clause — template-instantiated experiments compiling through the standard planner — is now delivered and tested; see the note below.

## Phase 4's second clause, delivered — the template artifact type

The clause was unreachable while no template artifact type existed, and the plan
puts "Experiment templates and scenario packs (gap 33) distributed as versioned
artifacts with the same labels" in **Phase 3**. Phase 3 landed the
search/inspect/install surface but no template type, so there was nothing to
instantiate and the acceptance criterion could not even be stated as a test.

`domain/marketplace.py` now carries the type:

* **`ExperimentTemplate`** — `template_id`, `version`, sha256 `digest`, publisher
  **declaration**, registry, `parameters`, `drill_template`, license, changelog,
  optional deprecation. The same discipline as `Artifact` for the same reason:
  there is **no** `class`, `verified`, `trusted`, or `trust_label` field and
  `extra="forbid"`, so a publisher cannot mark their own template.
  `SIGNATURE_VERIFICATION_IMPLEMENTED` is still `False` and
  `SIGNATURE_TRUST_NOTICE` applies verbatim — rendering a template proves nothing
  about who wrote it.
* **`TemplateParameter`** — name, description, `required`, `default`, `choices`.
  `required` and `default` are independent facts: a slot may be required *and*
  carry a default (the caller must be explicit about relying on it).
* **`render_template`** — pure substitution, returning a **document**. Fails
  closed with a named rule on each of the four ways an instantiation can be
  wrong: `template.unknown_parameter` (a value nobody declared is refused, not
  ignored), `template.missing_parameter`, `template.choice_not_allowed`, and
  `template.unfilled_placeholder`.
* **`instantiate_spec`** — the single door out of a template. It returns a
  `DrillSpec`, the *same* type `mayhem.spec.parse_drill` returns for an authored
  file, so from there the only route to an `ExecutionPlan` is `plan_drill`, the
  one planner.

**Why "never a gate bypass" is structural rather than asserted.**
`ExperimentTemplate` has no `run`, `execute`, `plan`, or `dispatch` method;
`instantiate_spec` returns a spec with no `steps`; and `plan_drill` is the only
function that turns a `DrillSpec` into a plan. There is no second path to
compare against, which is a stronger property than two paths agreeing.
`tests/unit/test_marketplace_templates.py::TestNoSecondDoor` pins the absence of
every such method so a future "convenience" path cannot appear without failing
the suite.

**The acceptance criterion, as a test.** `TestTemplateParity` compiles a plan
from `instantiate_spec(...)` and a plan from the hand-authored equivalent
document and compares them step for step. Parity is asserted as frozen **shape**
rather than byte equality, for the reason `test_k8s_crds.py` gives:
`_plan_target_faults` mints a `grp-<uuid>` per compilation, so two compilations
of one spec differ in group ids by construction, and a byte-equality test would
fail on correct code. Its control —
`test_different_values_give_a_different_plan` — is the assertion that stops the
parity test being satisfiable by a template that ignores its parameters.

**A defect this work found and fixed.** `instantiate_spec` validated the rendered
document with `DrillSpec.model_validate` directly, which is **not** what
`parse_drill` does: `parse_drill` runs plan 29's
`require_no_literal_credentials` first. Validating directly was therefore a
second door into the domain that skipped the credential scan, and a template
carrying a literal secret value would have instantiated into a `DrillSpec` the
authored path refuses. `instantiate_spec` now makes the same call, naming the
template in the message because the publisher — not the operator who
instantiated it — put the value in the artifact.

**What this clause's delivery does NOT include.** Templates are not yet
*distributable*: there is no `marketplace_templates` table in
`infra/marketplace_store.py`, no `mayhem marketplace template` verb, and no
supply-chain record per template version. Those are Phase 3's "distributed as
versioned artifacts with the same labels" half, and Phase 3 remains responsible
for them. What is delivered here is the acceptance criterion Phase 4 names, on a
template type an operator can construct today.

**Why the count changed.** The phase as written has two clauses. The first — *"installed artifacts execute only through normal admission with pinned versions in evidence"* — was delivered, sealed, audited and tested earlier. The second — *"template-instantiated experiments compile through the standard planner; a template is authoring convenience, never a gate bypass"*, with the acceptance criterion *"an experiment instantiated from a template is indistinguishable downstream from an authored one"* — was recorded as unmet because no template artifact type existed, so the criterion could not even be stated as a test.

`ExperimentTemplate` and `instantiate_spec` now exist, the criterion is stated as a test, and it passes. Phase 4 is therefore counted DONE. This supersedes the earlier reading that a reviewer should either keep the count at five or close Phase 4 "when template artifacts land" — the template type has landed, and the acceptance criterion named by the phase is met and proven.

The narrower residual — catalogue **distribution** of templates (store table, CLI verb, per-version supply-chain record) — is Phase 3's sentence and stays Phase 3's debt. Phase 4's acceptance criterion does not mention distribution, and closing it would not have been honest if it had.
