# Attestation format and signature reference

This document is the wire format for plan 12: the attestation chain, the
manifest, and the signature over it. It is written for a reader who has the
bundle bytes and wants to check them without running mayhem at all — that
reader is the reason the format is specified here rather than only in code.

Nothing in this document is aspirational. Every field described exists in
`mayhem.domain.attestation` and `mayhem.infra.evidence_signing` today, and every
algorithm named as *not* implemented is genuinely refused by name rather than
substituted.

## What a signature in this build does and does not prove

Read this before anything else.

**Proves.** The bytes covered by the signature are unaltered since signing, and
were produced by someone holding the HMAC key whose fingerprint is named in the
signature.

**Does not prove.** *Who* produced them. The implemented scheme is HMAC-SHA256,
which is symmetric: verification requires the same secret used to sign. A
verifier that can check the signature can also *mint* one. So a passing verdict
means "unaltered, and produced by a key holder" — never "signed by Alice". Every
verdict this codebase emits carries that caveat in its `warnings`, and
`public_key_verification_available` is `false` on every passing verdict. A tool
that treats `verified: true` as authorship has misread the output.

That is why the verdict carries **two** booleans, asked separately:

| Field | Question | Meaning of `true` |
|---|---|---|
| `verified` | Do these bytes match the signature? | The bytes are unaltered and were produced by the holder of the named key. |
| `trusted` | Does this deployment vouch for that key? | A trust root in *this* store lists the signature's fingerprint. |

They are independent, and the interesting cases are the disagreements:

- `verified=true, trusted=true` — the ordinary case.
- `verified=true, trusted=false` — the bytes check out, but under a key this
  deployment does not currently vouch for. This is the **rotated-key** case: the
  evidence is sound and was signed by a key that has since been retired. An
  auditor should read it as "validly signed under a since-revoked key", not as a
  failure.
- `verified=false` — the bytes do not match, or no key material was available to
  check them. This is the only case that means "do not rely on this".

`bundle signatures` exits non-zero only when `verified` is false. A rotated key
is a fact to report, not a verification failure.

## Canonicalization

Signed bytes are canonical JSON. Canonicalization is part of the signature, not
a convenience: two encodings of the same logical manifest must produce the same
digest, or an auditor re-serializing the bundle would get a different answer
than the signer.

`mayhem.domain.attestation.canonical_json` applies, in order:

1. **NFC normalization** of all string keys and values, so a bundle re-encoded
   from decomposed Unicode hashes identically.
2. **Key sorting**, recursively.
3. **Refusal of non-finite floats.** `NaN` and `±inf` raise instead of being
   stringified. `allow_nan=False` discipline is retained deliberately: a JSON
   encoder that silently emits `NaN` produces bytes that no conformant parser
   will read back to the same value, which would make the digest unverifiable
   by anyone but the signer.
4. **Refusal of non-JSON-native types.** Anything not a dict, list, str, int,
   float, bool, or `None` raises rather than being coerced with `str()`. A
   coerced object hashes as its repr, which is not a property anyone can verify.

The same discipline as `allow_nan=False`: refuse at the boundary, because a
signature over bytes only the signer can reproduce is not evidence.

## The hash chain

Each event commits to its predecessor:

```
digest(event_n) = sha256(canonical_json(event_n without digest, digest))
link(event_n)   = digest(event_{n-1})   # genesis is 64 zeros
chain_root      = digest(event_last)
```

`chain_root` is the single value that commits to every event. `verify_chain`
walks the links and recomputes each digest, so any reordering, insertion,
removal, or byte change is caught and named against the event that broke it.

Reordering is detected even when the events are otherwise identical, because a
reordered chain has a different `link` at the point of the swap.

## The manifest

The manifest is the object that gets signed. It commits to the run's evidence:

| Field | Commits to |
|---|---|
| `manifest_id`, `run_id` | which run |
| `chain_root` | every event, transitively |
| `event_count` | how many |
| `retention_class` | how long it must be kept |
| `provenance` | the fact→observation→probe→step→fault→target→experiment→verdict path |

A manifest is self-verifying against the events it references, but it is *not*
a substitute for them: verifying the manifest proves the chain was intact when
the manifest was built, and the signature proves the manifest has not changed
since. Both are needed, and neither implies the other.

## The signature

A signature is issued over the manifest. The signed payload binds four things at
once, so none of them can be swapped independently:

```
signing_bytes(manifest, trust_root_id, algorithm, key_fingerprint)
  = canonical_json({
        "artifact": manifest,
        "trust_root_id": trust_root_id,
        "algorithm": algorithm,
        "key_fingerprint": key_fingerprint,
    })
```

Consequences worth stating explicitly:

- **Re-pointing a signature at another trust root breaks it.** The trust root id
  is inside the signed bytes, not merely alongside them.
- **Swapping the manifest breaks it**, and is caught by a digest check before any
  HMAC is computed — so the failure names *what* happened rather than reporting a
  bare mismatch.
- **Algorithm and key fingerprint are inside the signature.** A signature cannot
  be re-labelled as a different algorithm or a different key.

Key identity is a **fingerprint**, `sha256(secret)` hex, not the secret. It
identifies which key signed without publishing it.

> **Fingerprints are not publishable.** For a symmetric scheme the fingerprint is
> `sha256` *of the secret itself*, so it is an offline dictionary-attack target.
> It is never logged, never written into a bundle, and never printed. It lives
> only in trust-root files and signature records, both inside the plan 29 secret
> boundary. If you have a fingerprint in hand, treat it as key-adjacent material.

## Trust roots

A `TrustRoot` is a named set of key fingerprints plus the algorithm it vouches
for. Two rules:

- A root **must have an id**. An unnamed root would let any key holder claim the
  evidence was signed under the deployment's trust.
- A root that vouches for Ed25519 **cannot** accept an HMAC signature. Without
  this check a root would silently accept a weaker algorithm than the one it was
  created to vouch for.

In this build the deployment trust store is **derived from the keys that actually
exist on disk** rather than hand-written, so it cannot drift from the deployment.
A root vouching for a key the deployment does not hold is exactly the "trust
nobody verified anybody" state this plan exists to make impossible.

## Key rotation and the archive

Rotation replaces a key's bytes under the **same key id**, changing the
fingerprint, and **archives** the retired generation to
`<key-dir>/archive/<key-id>.<fingerprint>.key`.

Archiving rather than truncating is a deliberate design decision, and it is the
one place where the obvious implementation is wrong. A rotation that overwrote
the bytes in place would leave an operator with no safe move at all: rotate, and
every historical signature becomes permanently unverifiable; or don't rotate, and
a leaked key stays live forever. Archiving makes revocation and preservation the
same action.

The archived material is **not** trusted by default:

- `active_key_ids()` and the derived trust store cover live keys only, so a
  retired key can never produce anything new, even though its bytes are still
  readable on disk.
- Archived generations are addressed **by fingerprint**. A key id rotated several
  times resolves a specific generation or raises — never "the most recent one",
  because checking a signature against the wrong generation is worse than
  reporting it unverifiable.
- An unknown fingerprint **raises**. A caller that asked for a specific
  generation must be told it is absent, not handed a near match.

Archived key files are held at `0600` and refused on read if any group/other
permission bit is set, exactly like live keys — a retired key is still a secret.

## Algorithms

| Algorithm | Status |
|---|---|
| HMAC-SHA256 | Implemented. The only one. |
| Ed25519 | Declared, **refused by name**. |
| X.509 / KMS | Declared, **refused by name**. |

Requesting an unimplemented algorithm raises `SigningNotImplementedError` naming
the algorithm. No fallback signer is substituted, because silently downgrading a
requested algorithm would hand the caller a signature the intended verifier
cannot check — a downgrade that fails open, in the one place that must not.

KMS/HSM and Sigstore/Cosign custody are not implemented. That is a gap in the
deployment's threat model, not something this format papers over: with a local
file key, "the deployment signed this" and "an operator with filesystem access
signed this" are not distinguishable.

## Retention

`RetentionClass` on the manifest carries how long the evidence must be kept. The
retention engine (`mayhem.infra.retention`) moves records hot → cold → archive →
deleted, with two rules that override the clock:

- **A legal hold outranks expiry.** Expired-but-held evidence survives; it is not
  listed as due.
- **Deletion requires dual control** — two distinct named approvers, never the
  same one twice — and writes a tombstone attestation in the same transaction as
  the deletion, so the record of the deletion cannot itself vanish with the data.

## Checking evidence without mayhem

See `docs/verification-without-mayhem.md` for a from-scratch procedure using only
`python3` and the standard library.