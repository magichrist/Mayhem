# Plan 12 — Cryptographic Evidence and Audit

**Priority:** P0. Gap items 12, 57, 98, 99, 100, 101.

## Objective
Turn Mayhem evidence into independently verifiable attestations suitable for audits, incident reviews, and compliance workflows — and fold in time synchronization (98), the provenance graph (99), retention (57), and external storage (101).

## Builds on — and honesty first
- `domain/evidence.py` (`EvidenceEnvelope`, redaction boundary), `domain/evidence_bundle.py`, `domain/replay.py` capsules, and `infra/evidence_bundle_io.py` stay the bundle substrate. Signing is NEW capability: nothing in this build authenticates authorship — pack signatures are NOT verified and evidence is currently integrity-chained, not signed. This plan closes that gap for evidence; pack provenance stays exactly as honestly-limited until its own lane exists.
- OTel span names (never attributes) reaching evidence stays the privacy rule; 29 extends redaction to secrets.

## Evidence model
```text
canonical event
 -> digest
 -> hash chain / Merkle structure
 -> signed manifest
 -> certificate/identity
 -> immutable storage
```

## Requirements
Canonical JSON serialization, SHA-256 integrity, signed manifests,
Sigstore/Cosign support, KMS/HSM integration, key rotation, trust
roots, signer identity, offline verification, WORM/object-lock
storage, retention policies.

## Privacy
Secrets must never enter evidence. Support redaction and data-classification rules.

## Phase 1 — Domain model: attestations, provenance, time
Add `domain/attestation.py`: `AttestedEvent` (canonical JSON bytes, SHA-256, chain link, monotonic-plus-wall-clock timestamps with uncertainty bounds for gap 98), `ProvenanceEdge` (fact → observation → probe → step → fault → target → experiment → verdict for gap 99), `Manifest` (event roots, signer identity, trust root ref, retention class for gap 57). Pure types; canonicalization byte-tested. Acceptance: reordered-but-equal JSON canonicalizes identically; clock-uncertainty arithmetic tested.

## Phase 2 — Engine: sealing, signing, retention, external storage
Seal bundles at run close (hash-chained, `allow_nan=False` discipline retained); sign manifests via local keys first, then KMS/HSM, then Sigstore/Cosign; retention engine enforces per-class policies (hot → cold → archive → legal-hold-aware delete) with WORM/object-lock backends; external immutable storage (S3/MinIO/GCS/Azure Blob/OCI/Git) holds sealed bundles so evidence survives control-plane deletion (gap 101). Acceptance: tamper with any covered byte → verification fails naming the event.

## Phase 3 — Surface: bundle extension, not a new group
Per program decision, signing/attestation/export extend the existing `bundle` group (`bundle build/show/verify` plus new signing and export operations) rather than minting a parallel `evidence` command tree. Acceptance: the command-inventory contract (registry → README → docs) updated atomically; old bundle commands keep working.

## Phase 4 — Safety and evidence integration
Approval and policy artifacts sealed into the chain (09/07 digests as chain inputs); audit log itself an attested event stream (append-only, WORM-backed); retention deletions require dual control and leave a tombstone attestation. Acceptance: the 24 release-gate evidence section (bundle generation, offline verification, signature verification, tamper test) passes.

## Phase 5 — Tests, regression guards, negative controls
Canonicalization vectors, chain-verification tests, tamper tests per event class, key-rotation tests (old signatures verify under archived trust roots, new events use new keys), retention tests (expired-but-held evidence survives; held-then-released deletes with tombstone). Negative controls: verification without the control plane (air-gapped fixture); a bundle with a swapped event rejected. Acceptance: all green; offline verification proven by a test with no store access.

## Phase 6 — Docs, honesty gates, rollout
Attestation format spec, trust-root management guide, retention-policy reference, verification-without-Mayhem guide. Rollout: local-key signing first, KMS/HSM second, Sigstore third; retention last with conservative defaults. Acceptance: every signing claim names the key holder and trust root — "signed" without "by whom, trusted how" fails review.

## Dependencies
07 (sealed decisions), 09 (sealed approvals), 29 (redaction rules), 08 (object-store wiring), 19 (key custody, SBOM of signing path).

## STATUS — planning only, 0%
