# Trust labels: what each one means

This is the page plan 18 Phase 6 calls the most important one, because a trust
label is the single thing a reader of the marketplace is most likely to
over-read. Everything below is derived from `src/mayhem/domain/marketplace.py`
and pinned by `tests/unit/test_marketplace_plan_docs.py`.

## The one sentence

Every label in this system is evidence about **bytes on a certification cell** or
about **where those bytes were published**. No label is evidence about **who
wrote them**.

That is not a caveat bolted onto the design; it is what the design can know.
`mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` is `False` and
`mayhem.domain.marketplace.SIGNATURE_VERIFICATION_IMPLEMENTED` is `False`: there
is no public key, no algorithm, and no trust store in this build. So the sha256
content digest is checked, and a matching digest proves **integrity** — that the
bytes are the bytes the record was made about — and proves nothing about
**provenance**, which is a claim about an author.

## The five classes

`ArtifactClass` is in ascending order of assertion. `DEPRECATED` is terminal: it
overrides every other class and cannot back a new approval.

| Label | What it establishes | What it does **not** establish |
|-------|--------------------|-------------------------------|
| `unverified` | The artifact is listed. No certification record, so no certified state may be displayed. | Anything about the publisher. This is the floor, not a judgement. |
| `organization_private` | Distribution on an organization-private registry. A **distribution** fact. | Verification of anything. The publisher is still only declared. |
| `verified_community` | A **current** certification record exists **for this exact artifact digest**. | The author's identity, reputation, or honesty. |
| `official` | Distribution on the official Mayhem registry (`mayhem.official`) **and** the same certification evidence. | A signature. It is an editorial fact plus evidence. |
| `deprecated` | Withdrawn from new use. | — it overrides the rest. |

`verified_community` is the label most likely to be misread, so it is worth
being exact: it means a record exists, it is current, and it is for these bytes.
A record for a different digest promotes nothing — `classify_artifact` and
`trust_label` compare the observed digest, not the artifact's identity.

## The two notices, and why they are constants

`TrustLabel.notice` returns `SIGNATURE_TRUST_NOTICE`, so a renderer cannot print
a label without the qualification sitting structurally next to it. The narrower
`PUBLISHER_DECLARATION_NOTICE` is what a UI shows beside a `publisher: acme` field.

Both are module constants rather than strings written at each call site,
precisely so that a renderer which reads the label has the caveat within reach
of the same import. If you are adding a rendering path, read
`label.notice` — do not retype the caveat.

## Promotions are pure, and `now` is a parameter

`classify_artifact`, `trust_label` and `require_trust_label` read only their
arguments. There is no clock read inside any of them: `now` is a parameter. That
is what makes a promotion decision replayable, and it is why a test can prove a
refusal or a TTL boundary without waiting for it.

`require_trust_label` is the only way to *ask* for a class. It raises
`TrustLabelError` naming the requirement that was missing. There is no shortcut
that returns a class the records do not justify — the shortcut does not exist,
it just has a refusal message.

## Revocation is a fact with a deadline

A `Revocation` names a scope (one artifact version, one publisher, or one
registry), a reason, and the instant by which the refusal must be in force.

Before that instant the revocation is **announced but not yet enforceable**.
`pending_revocations` reports those separately from `blocking_revocations`,
because "we told you yesterday" and "we stopped it" are different claims and a UI
that renders both as "revoked" has told a reader something untrue.

`dispatches` is the pure predicate the dispatch path calls, and
`dispatch_refusal` names the revocation in its message, so a refusal is
traceable to the record that caused it.

## Federation grants no standing

`federated_registries` computes a `RegistryFederation` closure, and sealing one
grants no standing of its own — a federated registry is a place artifacts were
published, not an endorsement of them. Sealing an **empty** federation is
refused rather than attesting to nothing.

## Reading the page honestly

Four claims this document deliberately does not make, because none of them is
true of this build. Each is written as a negative so that a reader who takes
one line on its own still gets the caveat with it:

- An artifact is **not** signed, and nothing here can say it is signed *by its
  publisher*.
- A `verified_community` artifact is **not** thereby safe, trustworthy, or
  endorsed; the label is evidence, not a judgement.
- A publisher field is **not** authenticated; it records a declaration and
  nothing can check it.
- `official` **does not** mean Mayhem vouches for the code; it is an editorial
  fact plus certification evidence.

What it does say, and what the gate enforces: every label names what it
establishes and what it does not, and every rendering of one carries the notice.