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

This plan's own audit stream is inside that boundary, not beside it. An audit
entry is persisted, exported, and covered by the attestation and retention
machinery, so `infra/audit_stream.py` calls the same no-opt-out gate every other
write path calls (`require_persistable_document` from plan 29), before the
transaction opens. See the Phase 4 correction below for what was true before.

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

## STATUS
- Phase 1 (domain model): DONE — `domain/attestation.py` landed `AttestedEvent` with hash-chain links (`seal_events`, `chain_root`, `verify_chain`), `AttestedTimestamp` with uncertainty arithmetic (`accumulated_uncertainty`, `wall_clock_offset`, `monotonic_span_ns`), the `ProvenanceEdge`/`ProvenancePath` ladder, and `Manifest` with `build_manifest`/`verify_manifest`; canonicalization NFC-normalizes and refuses NaN/inf and any non-JSON-native value rather than stringifying it; 79 tests.
- Phase 2 (engine): DONE — sealing at run close (`infra/attestation_store.py`: `seal_run_evidence` derives `evidence.recorded` + `run.closed` events that *reference* the envelope by digest, seals the chain, builds the manifest, and persists both behind migration M0023 `attestation_retention` with a down path; re-verification goes through the Phase 1 verifier, never a re-implemented check) plus `infra/retention.py` (`RetentionEngine`: hot → cold → archive → deleted, per-class expiry, legal hold that outranks the clock, deletion refused without two distinct named approvers, tombstones written in the same transaction as the deletion); 48 tests.
- **SIGNING IS STILL NOT IMPLEMENTED.** Phase 2 built the sealing and retention engine only. No key material, no signature bytes, no KMS/HSM custody, no Sigstore/Cosign, no `mayhem bundle sign` — those remain later phases (rollout order in Phase 6: local keys → KMS/HSM → Sigstore).
- Phase 3: not started
- Phase 4 (safety and evidence integration): DONE — `infra/attestation_store.py` gained `RunAuthorization` (the `PolicyDecision` and `ApprovalState` that authorized a run, referenced by `decision_digest()`/`rule_digest`/`policy_digest`/`facts_digest` and a canonical `approval_state_digest()`) and `chain_completeness`, so a run's chain carries the `policy.decided` + `approval.evaluated` events and a mutating run that carries neither verifies as **incomplete**, never as clean; `infra/audit_stream.py` makes the audit log an attested event stream — `AttestedEvent` entries over the same `canonical_event_json`/`seal_events`/`verify_chain` (a second table, never a second format), behind migration M0029 `audit_stream` with `BEFORE UPDATE`/`BEFORE DELETE` triggers that refuse, plus a recorded head so a truncated stream is detectable; `infra/retention.py` now records every state change, and a dual-control deletion leaves an audit entry in a table the deletion does not touch. 58 new tests (`tests/unit/test_audit_stream.py` 51, `tests/unit/test_attestation_store.py` +7).
- Phase 4 correction (audit stream inside the evidence boundary): DONE — `AuditStream.record` was an ungated evidence write path. `AuditEntry.detail` is a free-form dict, so a resolved credential could be persisted into `audit_entries` while a plan 29 `SecretLeakGuard` was active; an integrator reproduced it. It now calls plan 29's existing `require_persistable_document` before the transaction opens, so a refusal leaves neither an entry row nor a head update. Same gate, same two rules, no audit-specific rule and no `guard=` parameter; the call site is registered in `tests/unit/test_evidence_boundary.py`'s `BOUNDARY_CALL_SITES` so deleting the gate fails statically. This is a correction inside Phase 4's existing scope, not new scope: the phase count is unchanged and no phase was advanced.
- Phase 5: not started
- Phase 6: not started

Overall: 3 of 6 phases complete (Phases 1, 2, and 4).

**SIGNATURE VERIFICATION IS STILL NOT IMPLEMENTED.** Phase 4 added *integrity* and *completeness*; it added no *authorship*. Attestation and integrity are implemented — a chain is hash-chained, re-verifiable offline, and tamper-detecting. Authorship authentication is **not** implemented: no key material, no signature bytes, no KMS/HSM custody, no Sigstore/Cosign, no signature verification anywhere. Every manifest is written with `signature_state = unsigned_no_signing` and a stored reason; `Manifest.signed` is true only when a signer is *named*, never when a signature is *verified*; `AuditStream.signed` is `False` by construction. An audit entry's `principal` column is a claim recorded by the writer, not an authenticated identity. **No document, CLI output, report, or attestation payload may state or imply that a signature was verified, that authorship was established, or that a named signer vouched for anything.** Phases 2, 4, and 6 all carry this gate; Phase 6 (local keys → KMS/HSM → Sigstore, retention last) is where it closes.

Known limitations:
- **No signing is implemented.** `Manifest` carries `signer_identity` and `trust_root_ref` as the Phase 6 honesty gate only: `Manifest.signed` is true when a signer is *named*, and `_check_signer_honesty` turns "signed without a trust root" (or the reverse) into an error and "unsigned" into a warning — never into verified authorship. No key material, no signature bytes, no verification. `verify_manifest` verifies *integrity*, not *authorship*, and says so in the warning it emits. Phase 2 makes that concrete rather than theoretical: `seal_run_evidence` **refuses** an `AttestationSigner` with `SigningNotImplementedError` instead of naming a signer it cannot honour, and every stored manifest row records `signature_state = unsigned_no_signing` together with the reason. Integrity is verified; authorship is not claimed anywhere.
- **No external immutable storage is implemented.** `RetentionBackend` is a seam with no production implementation. Archive and delete therefore fail closed with `RetentionBackendUnavailableError` when no backend is configured — the Phase 2 default. Deletion additionally refuses unless the external copy exists first, so the ladder cannot skip ahead and destroy the only copy (gap 101 remains open until a WORM/object-lock backend lands).
- **The audit stream is append-only and integrity-chained, not WORM-backed and not signed.** The M0029 triggers make `UPDATE`/`DELETE` on `audit_entries` impossible even for a direct SQL writer, and the recorded head makes a truncation *detectable*; the shared `signature_state` reason covers this stream too, so nothing here claims WORM durability or authenticated authorship. The plan's Phase 4 wording says "WORM-backed": the WORM half is **not** delivered, and is blocked on the `RetentionBackend` gap above. What is delivered is enforcement (triggers) plus detection (head/root/count), which is strictly weaker than object-lock and is documented as such rather than described as WORM.
- **Sealing is not yet called by the run close.** `seal_run_evidence` is the run-close seam, but `controller/executor.py` is unchanged. Phase 4 investigated and confirmed this is not an oversight: the executor never builds an `EvidenceEnvelope` (the type does not appear in that file), so sealing inside `_close_run` would require a *second* envelope producer — the duplication this plan exists to remove. The exact call site a later lane must use is `src/mayhem/cli/lifecycle.py`, in `_write_evidence_after_run`, immediately after the `write_evidence(store, envelope)` call (line 1076 as of Phase 4) and before `write_evidence_file`. The single call for it is `infra/audit_stream.seal_run_evidence_at_run_close`, whose docstring carries the same call site inline. Until that plumbing lands, passing no `authorization` seals a **complete-looking but INCOMPLETE** chain for every mutating run — which is the honest state, and what `chain_completeness` exists to report.
- **The authorization artifacts are not yet plumbed from the admission gates.** `RunAuthorization` accepts a `PolicyDecision` and an `ApprovalState`, but nothing in the tree yet supplies them: `controller/policy_gate.evaluate_gate` and `controller/approval_gate.verify_approvals` compute them inside `controller/safety.validate_plan` and discard the results after recording a `SafetyDecision`. Until a later lane carries them to the run close, real mutating runs will verify as incomplete. That is the designed fail-closed behaviour, not a silent pass.
- **This module is not a second bundle producer.** It names `mayhem.domain.evidence_bundle.build_bundle` in prose only, to say the two chain identically. Bundles remain built by that one function. Phase 2's `infra/attestation_store.py` does not even name it: its events reference the evidence envelope by digest, and the portable bundle stays the one container the one existing producer builds.


