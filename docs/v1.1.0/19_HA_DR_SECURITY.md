# Plan 19 — High Availability, Disaster Recovery, and Security Hardening

**Priority:** P0/P1. Gap items 30, 38, 40.

## Objective
Survive controller death, restore from backups, and harden the supply chain — with agent communication authenticated end to end (gap 30).

## Builds on
- `domain/leases.py` plus the agent watchdog (safety without the controller) and `controller/janitor.py` (orphan reconciliation) are the crash-safety core; 03 fencing tokens extend them across controller instances.
- 08 replication (SQLite plus WAL archive, snapshot ship, fenced standby promotion) is the HA storage story — this plan consumes it and adds restore drills plus evidence replication.
- `toolkit/tool_runner.py` (sole spawner, argv/env digests, redaction) stays the execution chokepoint agents inherit.

## HA
Multiple controllers, leader election, durable PostgreSQL? No —
durable replicated SQLite per the 08 decision, queue/broker for
dispatch, agent reconnection, fencing, idempotent retries.

## DR
Database backups, point-in-time recovery, evidence replication,
object-storage backups, restore drills, documented RPO/RTO.

## Security
mTLS, certificate rotation, command signatures, nonce/replay
protection, SBOM, SLSA provenance, Cosign/Sigstore, dependency
scanning, secret scanning, vulnerability disclosure process, secure
update mechanism. Honesty note: release-artifact signing and SLSA
provenance are NEW capability built here; until each ships, no doc may
claim it.

## Agent security (gap 30)
Controller issues signed commands; agents verify signature, nonce,
plan hash, and authorization before executing, then return signed
results. Short-lived agent credentials with rotation and revocation;
certificate pinning; replay protection via the 03 nonce envelope.

## Phase 1 — Domain model: identity, fencing, backup types
Add `domain/agent_identity.py` (agent identity, credential lifetime, rotation state) and `domain/backup.py` (snapshot descriptors, RPO/RTO objectives as data, restore plans). Pure types; fencing-token monotonicity and nonce-uniqueness as pure predicates. Acceptance: token-ordering tests; a stale token authorizing an action is unrepresentable.

## Phase 2 — Engine: mTLS fabric, leader election, restore
Mutual TLS on all controller-agent links with rotation and revocation propagation; leader election over the replicated store with fencing so only the leader dispatches; backup engine (scheduled snapshots, WAL archives, evidence replication to object storage per 12) plus restore drills that actually restore into an isolated cell and verify. Acceptance: leader-kill drills; restore drills that prove RPO/RTO rather than asserting them.

## Phase 3 — Surface: cluster operations and update channel
Cluster membership views, credential rotation operations, backup/restore commands, secure update mechanism for agents and controllers (signed update manifests verified before apply). Acceptance: rotation and update flows tested end to end with fixture certificate authorities.

## Phase 4 — Safety and evidence integration
Every dispatch authenticated and fenced; every failover and restore sealed into evidence; SBOM plus SLSA provenance generated per release and verified at install. Acceptance: the 24 release-gate platform section (upgrade, rollback where supported, controller/agent restart, restore, partition test) passes.

## Phase 5 — Tests, regression guards, negative controls
mTLS conformance (expired/revoked/wrong-role certificates refused), replay tests (captured command re-injected → refused), partition tests (split-brain cannot produce two dispatchers), restore tests, supply-chain tests (SBOM completeness, provenance verification, secret-scan gates). Negative controls: an agent trusting a non-pinned certificate fails closed; a backup that never completed a restore drill is marked untrusted. Acceptance: full matrix green.

## Phase 6 — Docs, honesty gates, rollout
Cluster operations guide, certificate management runbook, backup/restore guide with tested RPO/RTO, vulnerability disclosure policy, supply-chain posture doc. Rollout: mTLS first, leader election second, backups third, supply-chain signing last (each gated on the previous). Acceptance: no doc claims an HA or security property without naming the test that proves it.

## Dependencies
03 (fencing, nonces), 08 (replicated store), 12 (evidence replication, sealed operations), 24 (release-gate enforcement).

## STATUS
- Phase 1 (domain model): DONE — `domain/agent_identity.py` landed `AgentIdentity` (agent id, controller id, principal + `EnvironmentScope` from plan 09, credential lifetime, derived rotation window, identity version), `AgentCredential` (required `expires_at`, so an eternal credential is unrepresentable; `RotationState.CURRENT`/`SUPERSEDED`; revocation that survives rotation), `CredentialGrant` — the only thing a caller may hold to authenticate an agent, whose own validator re-runs the refusal predicates, so a revoked or expired identity cannot be wrapped in a grant by any construction path — `credential_refusals`/`authorize_credential` enumerating all seven `CredentialRefusal` reasons in a canonical order (the pattern `approval.py` set), `Revocation`, `AgentIdentityRegistry` for revocation propagation (frozen; every change bumps a version a grant names, so staleness is detectable), `CertificateRef`/`TrustAnchorRef`/`check_certificate_pinning` as **data with no verification claim** (`trust_state` is validated to exactly `unverified_plan19_phase1`, and an agent with no configured anchor fails closed), plus fencing as pure predicates over plan 03's existing `FencingToken` — **no second fence type**: `fence_permits_dispatch` (plan 03's `is_at_least`, unchanged) and the plan-19 addition `fence_transfers_ownership` (strictly newer, via `is_after`), `assert_fence_authorises` raising `agent_fence_not_authorised`, and `fence_chain_is_monotonic`; `domain/backup.py` landed `SnapshotDescriptor` (with **no** `restored`/`verified` field at all), `RestorePlan`/`RestoreCheckSpec`/`RestoreCheckResult` (a `passed=True` with no recorded observation is refused), `RestoreVerification` whose `status` is *derived* (`RestoreOutcome.VERIFIED` only when every required check ran and passed **and** data loss was measured — there is no `SUCCESS` member, and `claim_success()` raises `restore_unverified`), `RecoveryObjective` (targets only, `is_measured` is always `False`), `Measurement` whose evidence is a **required** field, `ObjectiveComparison`/`ObjectiveReport`, and `compare_against_objective` returning `None` when no verified drill exists — so a stated RPO with no restore evidence can never be reported as an achieved RPO; `infra/agent_identity_store.py` persists both behind migration `M0025 agent_identity_backups` (five tables, all with down paths, no key material, no achieved-RPO column, revocation ledger consulted on every authorization); 130 tests.
- **mTLS AND SIGNATURE VERIFICATION ARE NOT IMPLEMENTED.** Phase 1 is types and pure predicates only. There is no handshake, no session, no key material, no CA implementation, and no check that a `FabricCommand`'s `signature` is good against its `signing_key_id` — that verification is Phase 2. `CertificateRef` is a *record of references somebody wrote down*, `check_certificate_pinning` is a fingerprint comparison (a configuration check, not authentication), and `CertificateRef.chain_verified` is `False` by construction. `FABRIC_UNDERSIGNED` is raised nowhere, exactly as plan 03 left it: the envelope makes an unsigned command unrepresentable, so only a wire-decoding path could ever see it, and there is none yet. Likewise there is **no backup engine, no scheduler, no WAL archiving, no object-storage replication, and no restore runner** — this phase stores descriptors and restore *records* that something else produces. Every backup, restore, and objective in the database is a **statement**; nothing has been demonstrated.
- Phase 2: not started
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 1 of 6 phases complete.

Known limitations:
- **No mTLS, no signature verification, no real certificate validation** (Phase 2). Nothing here authenticates a peer. An agent with no trust anchor configured gets `PinReason.NO_ANCHORS`, which is a *refusal* — fail-closed on configuration — but a pinned fingerprint match still proves only that the configuration lines up, never that the bytes are genuine.
- **Revocation propagation is detectable, not enforced across processes.** A `CredentialGrant` carries the identity it cleared against, so a registry that has advanced makes it stale (`grant_is_current`), and a fresh authorization through the advanced registry is refused. A caller that cached a grant and never re-checks keeps it; `require_still_usable(grant, now=…)` is the use-time re-check and it is the caller's job until Phase 2 supplies a wire. This is stated rather than papered over: a pure layer cannot revoke an object somebody already holds.
- **A registry cannot reach a peer holding an older one.** `AgentIdentityRegistry` is frozen, so a revocation produces a new registry with a higher `version`. `infra/agent_identity_store.py` closes the local half by consulting the append-only revocation ledger on every authorization (a row that landed without its identity update still refuses), but pushing a revocation to a live controller is Phase 2's job.
- **Rotation grace defaults to zero and is a per-credential field.** `rotate_before` and `rotation_grace` live on the credential rather than in one policy object, so two agents can carry different discipline. A policy-level rotation schedule is Phase 3's "credential rotation operations".
- **`FencingToken.outranks` reads backwards and is not used here.** In plan 03 it is `other.is_at_least(self)`, i.e. `a.outranks(b)` means *b is at least as new as a* — the **older** side. Plan 19's `fence_transfers_ownership` therefore uses `is_after` (strictly newer) and says so in its docstring. Plan 03's method is left exactly as written because it is not this lane's file; a reviewer should confirm that reading against `fabric.py` before anyone "simplifies" this.
- **No RPO/RTO has ever been measured, and the schema makes that visible.** `recovery_objectives` has no achieved columns at all, and `backup_restore_verifications.data_loss_seconds` stays `NULL` for a restore that never measured one — an unmeasured drill is `outcome = 'incomplete'`, never a zero that reads like a good result. `BackupRepository.objective_report` returns `demonstrated=False` until a verified drill exists.
