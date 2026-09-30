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

## STATUS — planning only, 0%
