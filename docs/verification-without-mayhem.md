# Verifying evidence without mayhem

The point of cryptographic evidence is that someone who does not trust mayhem
can still check it. This document is a complete procedure using **only Python
and the standard library** — no mayhem install, no database, no network, no
trusted third party.

If the procedure below cannot check a bundle, the bundle is not independently
verifiable, and that is a property of the bundle rather than of your setup.

## What you need

- The bundle directory (or the manifest JSON and its events).
- The signature JSON.
- The signing key file.
- A trust root: the set of key fingerprints this deployment vouches for.

## The honest limit, before you start

With the scheme this build implements (HMAC-SHA256), checking a signature
requires the **same secret** used to sign it. So the party verifying is in the
same position as the party signing: they can check the bytes, and they could also
have forged them.

What this procedure therefore proves: **the bytes are unaltered since signing,
and match the key you hold.** What it cannot prove: *who* signed them. That limit
is inherent to a symmetric scheme, and no amount of care in this script changes
it. A public-key scheme would allow third-party verification without the secret;
that is not implemented, and `public_key` is `false` in every signature this build
produces.

Trust in *whose* key it is comes from your trust root, not from the signature.

## Step 1 — Re-derive the canonical bytes

The signature is over a canonical JSON encoding of the manifest plus the
signature's own identifying fields. Canonicalization must match mayhem's exactly,
or the digest differs for reasons that have nothing to do with tampering.

Rules: NFC-normalize every string, sort keys recursively, refuse `NaN`/`inf`,
refuse non-JSON-native types.

```python
import hashlib, hmac, json, unicodedata
from pathlib import Path


def canonical(obj):
    """Replicate mayhem.domain.attestation.canonical_json."""
    if isinstance(obj, dict):
        return {k: canonical(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [canonical(v) for v in obj]
    if isinstance(obj, str):
        return unicodedata.normalize("NFC", obj)
    if isinstance(obj, float):
        # Refused, not stringified: a value no conformant parser reads back
        # identically would make the digest unverifiable by anyone but the signer.
        if obj != obj or obj in (float("inf"), float("-inf")):
            raise ValueError(f"non-finite float in signed bytes: {obj!r}")
        return obj
    if isinstance(obj, (bool, int, str)) or obj is None:
        return obj
    raise TypeError(f"non-JSON-native type in signed bytes: {type(obj).__name__}")


def digest_of(obj):
    encoded = json.dumps(
        canonical(obj),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
```

## Step 2 — Re-derive what was signed

The signature covers a **domain-separated envelope**, not the manifest directly.
Reconstructing exactly that structure is what makes re-pointing a signature at
another trust root, key, or algorithm detectable.

```python
import base64

DOMAIN = b"mayhem-evidence-signature-v1\x00"  # exact prefix, trailing NUL included


def signing_bytes(manifest, signature):
    body = enc(manifest)  # canonical manifest bytes
    envelope = {
        "_domain": DOMAIN[:-1].decode(),  # prefix without the NUL
        "body": base64.b64encode(body).hex(),
        "trust_root_id": signature["trust_root_id"],
        "algorithm": signature["algorithm"],
        "key_fingerprint": signature["key_fingerprint"],
    }
    return DOMAIN + enc(envelope)
```

Two details that are easy to get wrong and produce a digest mismatch that looks
like tampering but is not:

- The `_domain` value in the envelope is the prefix with the **trailing NUL
  stripped**; the prefix bytes, NUL included, are prepended to the canonical
  envelope. Getting this backwards yields a plausible-looking but wrong payload.
- The body is **hex-encoded base64**, i.e. base64 then hex, not either alone.

## Step 3 — Check the signature

```python
manifest = json.loads(Path("manifest.json").read_text())
signature = json.loads(Path("signature.json").read_text())

payload = signing_bytes(manifest, signature)

# The recorded digest must match what we just derived. This catches a swapped
# manifest before any HMAC work, and names *what* went wrong.
derived = hashlib.sha256(payload).hexdigest()
assert derived == signature["signed_digest"], (
    f"manifest does not match what was signed "
    f"(recorded {signature['signed_digest'][:16]}…, derived {derived[:16]}…)"
)

secret = Path("release.key").read_bytes()  # the 32 raw bytes, not hex
expected = hmac.new(secret, payload, hashlib.sha256).digest()

if not hmac.compare_digest(expected, base64.b64decode(signature["signature"])):
    raise SystemExit("SIGNATURE DOES NOT VERIFY — treat this evidence as altered")
print("bytes verified against key", signature["key_id"])
```

If that prints, the bytes are unaltered since signing and were produced by a
holder of that key.

## Step 4 — Check the key is one you trust

Verification passing means nothing about which key signed. That is the trust
root's job:

```python
fingerprint = hashlib.sha256(secret).hexdigest()
assert fingerprint == signature["key_fingerprint"], (
    "the key you hold is not the key that made this signature"
)

TRUSTED = {"mayhem-local": {"<a fingerprint you were told to expect>"}}
trusted = fingerprint in TRUSTED.get(signature["trust_root_id"], set())
print("trusted:", trusted)
```

`trusted: false` with a successful verification is a normal, meaningful state:
the evidence is sound and was signed under a key you no longer vouch for —
typically one that has since been rotated out. Only `verified: false` means "do
not rely on this".

Report both. A single combined boolean destroys the distinction between "these
bytes were altered" and "these bytes were signed by a key you do not trust",
and those demand completely different responses.

## Step 5 — Re-derive the hash chain

The manifest commits to every event transitively. Events chain as:

```
digest(event) = sha256(canonical(event without "digest", then with "digest" set))
link(event)   = digest(previous event)   # genesis = "0" * 64
```

```python
ZERO = "0" * 64
previous = ZERO
for index, event in enumerate(events):
    # Each event commits to its predecessor in a *separate* structure so the
    # chain link is not confused with the event's own content digest.
    link = content_digest(
        {
            "previous": previous,
            "event_id": event["event_id"],
            "digest": event["digest"],
        }
    )
    if event["chain_link"] != link:
        raise SystemExit(
            f"chain broken at event {index} ({event['event_id']}): "
            f"chain_link does not match its predecessor"
        )
    # The event's own digest covers its declared content.
    recomputed = content_digest(event)
    assert recomputed == event["digest"], f"event {event['event_id']} digest mismatch"
    previous = link

assert previous == manifest["chain_root"], (
    "chain root does not match the manifest; the manifest does not commit to these events"
)
```

Reordering is caught because a reordered chain has a different `link` at the swap
point — even when the events are otherwise byte-identical.

## Negative controls

Trust these procedures only after confirming they can **fail**. A verifier that
always passes is worse than none, because it manufactures confidence.

- Change one byte of the manifest → Step 3 must fail on the digest mismatch.
- Change one byte of an event → Step 5 must fail naming that event.
- Swap two events → Step 5 must fail on the link check.
- Use a different key file → Step 4 must fail on the fingerprint comparison.
- Verify a signature against a trust root that omits the fingerprint →
  verification succeeds and `trusted` is `false`.

## What this cannot check

- **Identity.** HMAC is symmetric; see the limit above.
- **That the events describe what actually happened.** The chain proves the
  evidence is internally consistent and unaltered since sealing, not that the
  recorded observations are true. mayhem's probe layer is what makes the
  observations meaningful; this script only proves nobody edited them afterwards.
- **Retention.** Legal holds and tombstones are enforced by the retention engine
  and recorded as evidence; this script does not evaluate policy.