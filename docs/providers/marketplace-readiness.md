# Marketplace readiness checklist

What a provider extension must have satisfied before plan 18 may list it. This
page **feeds** plan 18; it does not replace plan 18's own trust-label semantics
(`mayhem.domain.marketplace.TrustLabel` and `CLASS_MEANING`), and every label
there is a statement about bytes on a runtime cell or about where those bytes
were published — never about who wrote them.

> **No label a provider can obtain implies authorship authentication.**
> `mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` is `False` and
> `mayhem.domain.marketplace.SIGNATURE_VERIFICATION_IMPLEMENTED` mirrors it. A
> publisher id in a declaration is a declared name of the same standing as a
> comment header, and the sha256 content digest plan 18 checks at install proves
> integrity, not provenance.

## How to read the boxes

A box is `[x]` when mayhem's own code enforces it today, and `[ ]` when it does
not. Nothing here is aspirational: an unchecked box is a finding, and the finding
is written down rather than left for a reader to discover.

## 1. The declaration

- [x] Provider id is a lowercase dotted identifier; version is semantic
      versioning.
- [x] Every fault hangs off a declared capability and declared target locators.
- [x] No part of the declaration requests a permission the provider did not
      declare.
- [x] Every mutating fault requires `target:mutate` and declares a compensation
      path; every read-only fault requires no action permissions.
- [x] Every fault has a declared parameter grammar with defaults for optional
      parameters, checked against the declared fault defaults at load.
- [x] An evidence schema is published and every declared fault maps to it.
- [x] Compatibility bounds are declared and satisfied, including the release
      window. The engine axis is reported as `not_declared` / `unverified` /
      `matched` / `mismatched` — "we did not look" is a value, not a missing axis.
- [x] The provider id does not shadow a built-in.

## 2. Loading

- [x] The SHA-256 content digest is checked against the declared digest.
- [x] No path traversal in the artifact path.
- [x] No shadowing of a built-in provider or fault id.
- [x] Compensation is present for anything mutating.
- [x] The runtime's advertised capabilities, fault ids and permissions are
      checked against the declaration **before** it reaches the registry, so a
      mismatch is a refusal rather than a revocation.
- [x] Every refusal carries a named code and is sealed as well as raised.

## 3. Sandboxing — read this before checking any box here

- [ ] A seccomp filter is applied. **Not implemented in this build.**
- [ ] An AppArmor profile is written. **Not implemented in this build.**
- [ ] An SELinux label is applied. **Not implemented in this build.**
- [ ] A container is created for the provider. **Not implemented in this build.**
- [x] The profile a declaration *would* earn is computed from its permissions,
      and every mechanism it needs is named with state `declared_not_applied`.
- [x] Six of the seven tiers are refused by default; only `declaration_only` is
      admitted.
- [x] The refusal code (`provider_sandbox_mechanism_unapplied`) names the
      mechanisms that are missing.
- [x] An operator can load the provider unconfined, but only by passing two
      separately named flags, and the unconfined admission seals as
      `ACKNOWLEDGED_NO_BACKEND`.

**Consequence for plan 18.** A provider that declares any permission cannot be
loaded in a default configuration. Listing it without saying so would be a
misrepresentation of what a default install does.

## 4. Evidence and accountability

- [x] Provider activity — load, admission, sandbox decision, permission denial,
      provider-initiated action — is sealed into plan 12's existing attested
      chain, with the evidence schema resolved from the provider's own declared
      mapping.
- [x] Every activity carries an `ActionOutcome` from the same closed vocabulary a
      native action uses.
- [x] Registration and permission changes are recorded in the audit stream with
      the old grant as well as the new one.
- [x] The ledger is opt-in (`ProviderLoader(store=...)`) because a loader cannot
      invent a database, and with no store every inspection carries
      `evidence["sealed"] = False` plus a notice.
- [ ] Every manifest is authenticated. **Not implemented: every manifest is
      written unsigned**, with plan 12's reason stored beside it. Sealing proves
      ordering and integrity of the bytes; it proves nothing about authorship.
- [x] `AuditStream` records a principal as a declared claim, and its payload says
      so.

## 5. Safety participation

- [x] Cumulative damage accounting exists for a provider action and charges
      through the same `DamageLedger` a native action uses.
- [x] A quota breach refuses with the ledger's own `damage_quota.*` rule ids, so
      a provider breach compiles into an existing proof line.
- [x] A provider fault's damage weight is reported with its provenance
      (`catalog` or `unresolved_conservative`); today it is always the latter,
      because a third-party fault id is not in mayhem's catalog.
- [x] A mutating provider action takes a real `FaultLease` under the native state
      machine and the native invariants.
- [x] A mutating action without write-ahead undo ops is refused by name.
- [ ] The charge is made by the run path. **Not wired:** nothing in
      `controller/cell_runner.py` or `controller/safety.py` calls the
      participation module today.
- [ ] The lease is persisted by the executor. **Not wired:** the lease is
      constructed but no store writes it.
- [ ] A provider fault can be certified on a matrix cell. **Blocked twice over:**
      `MatrixCell` has no `provider_version` field, and `CertificationRecord`
      refuses a provider fault id. Both are plan-01 changes and both are stated as
      `change_required` by `mayhem.providers.participation.certification_blockers`.

## 6. SDK-built artifacts

- [x] The Python SDK is shipped and authors `mayhem.provider-declaration/v1`
      documents.
- [ ] A Rust crate is shipped. **`RUST_SDK_SHIPPED` is `False`**; what ships is
      the field map, the reader, and the conformance suite.
- [ ] A Go package is shipped. **`GO_SDK_SHIPPED` is `False`**; same.
- [x] `AuthoredArtifact` has **no field that could carry a signature**, so an
      artifact cannot be the thing that makes a reader believe a check happened.
- [x] `ArtifactAuthenticity` has one member and refuses to become two.
- [x] The three front-ends produce byte-identical canonical documents and equal
      loaded registrations.
- [x] Every artifact carries `SDK_UNVERIFIED_NOTICE` and a report of the signature
      flag, so a renderer cannot print one without the qualification available.

## 7. What listing an artifact may and may not say

Plan 18's rules, restated here because a provider author reads this page:

- **May** say the artifact's digest matches, that a certification record exists
  for it on a named cell, and where it was published.
- **May** say the publisher *declared* an identity. Always with the word
  "declared" attached — `publisher_is_declared_only` is recorded beside every
  publisher id for exactly this reason.
- **May not** say, in any label, class or summary, that a signature was checked,
  that the publisher is authenticated, or that the artifact is trusted. None of
  those is true and none may be implied: `SIGNATURE_VERIFICATION_IMPLEMENTED` is
  `False`, so a signature check is not merely absent, it is unperformed. The word
  "trusted" applied to a publisher is the specific overclaim this plan has
  refused in every phase so far.
- **May not** imply that a sandbox profile is enforced isolation. See section 3.

## See also

- [security-model.md](security-model.md) — the full model behind sections 3 to 5.
- [README.md](README.md) — what the SDK confers and what it does not.