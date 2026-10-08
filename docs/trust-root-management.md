# Trust-root management

How to create, use, rotate, and retire the keys and trust roots that decide what
mayhem treats as deployment-signed evidence.

The honesty gate this document exists to satisfy: **every signing claim must name
the key holder and the trust root.** "Signed" alone is not a claim you are
allowed to make. See `docs/attestation-format.md` first for what a signature in
this build does and does not prove — the short version is that HMAC-SHA256 is
symmetric, so verification proves a key holder produced the bytes, never that a
particular person or organization did.

## The model in one paragraph

A **key** is 32 bytes in a file at `<key-dir>/<key-id>.key`, mode `0600`. A
**trust root** is a named set of key fingerprints, plus the algorithm it vouches
for. A **signature** names one key id, one fingerprint, and one trust root. The
deployment's trust store is *derived from the keys on disk* rather than
hand-written, so it cannot claim to trust a key the deployment does not have.

## Where keys live

Default: `~/.mayhem/keys/`, or `--key-dir` on any key-bearing command. The
directory is created `0700`; every key file is created `0600`.

Permissions are checked **on read as well as on write**. A key file that was
world-readable when created but `chmod`ed later, or copied in with loose
permissions, is refused at load time:

```
key file /path/keys/alpha.key is mode 0644; owner-only (0600) is required
or any local user can mint evidence that verifies as deployment-signed
```

This is a refusal, not a warning. The permission bit is the entire boundary
between "the deployment signed this" and "any user on this host signed this", so
a permissive mode is treated as a compromised key.

Archived (rotated-out) generations live in `<key-dir>/archive/` and are held to
the same `0600` rule. A retired key is still a secret.

## Day-to-day

Create a key:

```bash
mayhem bundle keygen release
```

Sign a sealed manifest. `--trust-root` is **required**, not defaulted:

```bash
mayhem bundle sign RUN_ID:manifest --key release --trust-root mayhem-local
```

It is required on purpose. A signing command that picked a trust root for you
would let a deployment inherit whichever root the tool happened to choose, and
the trust root is the part of a signature that says *whose* authority is being
claimed. Making it mandatory forces the operator to name that authority.

Check a signature:

```bash
mayhem bundle signatures RUN_ID:manifest
```

Note there is no `--trust-root` flag on verification. The command reads the trust
root id out of the **signature itself** and builds a trust store for that root
from this deployment's own keys. That is deliberate: a verifier that accepted a
caller-supplied trust root could be pointed at a root chosen to produce a
`trusted=true`, which would make the flag a way to manufacture a verdict rather
than check one. The trust root is part of what the signature commits to, so it is
read, not asserted.

Exit code is **0 when `verified` is true**, including when `trusted` is false. A
rotated key is reported, not rejected, because the bytes genuinely still check
out and an auditor needs to see that. Only `verified=false` — bytes that do not
match, or no key material available to check them — exits non-zero.

List keys without exposing anything:

```bash
mayhem bundle keys --key-dir ./keys
```

Key ids only. No fingerprints, no secrets — see "Fingerprints are not
publishable" below.

`keygen` refuses to overwrite an existing key without `--rotate`, because
`create_key` truncates in place and a silent overwrite would invalidate every
signature ever made with that key, with no record that it happened.

## Rotation

```bash
mayhem bundle keygen release --rotate
```

This replaces the bytes under the same key id, changing the fingerprint, and
**archives** the retired generation to `archive/<key-id>.<fingerprint>.key`.

Rotation is the only supported way to retire a key, and it is deliberately not
destructive. The obvious implementation — write new bytes over the old file —
would leave no safe move available: rotate and every historical signature becomes
permanently unverifiable, or don't rotate and a leaked key stays live forever.
Archiving makes revocation and preservation one action.

After rotation:

- New signatures use the new fingerprint. Old ones keep their recorded
  fingerprint.
- The derived forward trust store vouches for the **new** fingerprint only.
- A signature naming the retired fingerprint reports `verified=true,
  trusted=false` — sound evidence, signed under a since-revoked key.
- To audit that old evidence, reconstruct a trust root over the archived
  generation explicitly. This is deliberate: it is never implicit.

```python
from mayhem.infra.evidence_signing import (
    LocalKeyStore,
    TrustRoot,
    KeyStoreBackedVerifier,
)

keys = LocalKeyStore("./keys")
archived = keys.load_archived_key("release", "<fingerprint from the signature>")
root = TrustRoot("mayhem-local-2025").with_key(archived)
verdict = KeyStoreBackedVerifier(keys, (root,)).verify_signature(signature, manifest)
```

A new trust root id (`mayhem-local-2025`) is the recommended form when auditing
across a rotation, so the historical scope is legible in the evidence itself
rather than implied.

Resolving an archived key by **fingerprint**, not recency, is a safety property:
a key id rotated several times must resolve a specific generation or raise, never
silently the most recent one.

## Revoking a key you no longer trust

Rotation changes the fingerprint, which is what causes old signatures to report
`trusted=false`. There is no separate "revoke" verb, and that is intentional:
revocation is expressed as the forward trust store no longer vouching for the
old fingerprint. If you need to *accept* an old key again — for instance an audit
under dispute — you must construct a trust root that vouches for it, which leaves
a reviewable record of who decided that.

One honest limitation: with HMAC and a local file key, you cannot distinguish
"the deployment signed this" from "someone with filesystem access to
`~/.mayhem/keys` signed this". Revocation stops the deployment from *vouching*
for the key; it does not and cannot prove the old key was not used to sign
something after you stopped trusting it. This is the practical argument for the
KMS/HSM tier in the rollout, which is not implemented.

## Trust roots across deployments

The default root id is `mayhem-local`, meaning "the keys this deployment holds".
To accept evidence from another deployment, that deployment's root must be
present in your store. Because the local trust store is *derived* from local
keys, this means importing the other deployment's key material and giving it a
distinct key id — and, in this build, only via the filesystem, since there is no
KMS or Sigstore path yet.

Before accepting a third party's evidence, note what you are accepting: their
symmetric key means they can mint evidence that verifies against their own root,
and your verification of it proves nothing about their identity. It proves the
bytes are unaltered and match a key you hold. Attribute it accordingly.

## Fingerprints are not publishable

For a symmetric scheme the fingerprint is `sha256` **of the secret**. It is
therefore an offline dictionary-attack target: publishing it lets an attacker
test candidate secrets against it.

Consequences, applied throughout the codebase and worth preserving in any tooling
you build on top:

- Never logged.
- Never written into a bundle or an evidence row.
- Never printed by any command.
- Confined to trust-root files and signature records, both inside the plan 29
  secret boundary.

If you find a fingerprint in a log, a bundle, or a ticket, rotate that key.

## Adding an algorithm later

`EvidenceSigner` is a Protocol, so a KMS or HSM signer satisfies it without
`HmacLocalKeySigner` knowing it exists. Two requirements when one is added:

1. It must implement `key_id`, `trust_root_id`, and `algorithm` as **read-only
   properties**. They name the context a signature is made under; a setter would
   let a caller rewrite the identity of key material already on disk.
2. It must refuse rather than fall back. `PUBLIC_KEY_ALGORITHMS_IMPLEMENTED` is
   `False` today, and every passing verdict records
   `public_key_verification_available: false`. Adding a real asymmetric signer
   means flipping that flag and removing the symmetric caveat from warnings —
   which is a claim change and must be a deliberate, visible edit, never a
   side effect of adding a signer.

Until then, no verdict from this build may claim third-party verification is
available.