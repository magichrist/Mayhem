# Plan 06 — Cloud Fault Providers

**Priority:** P1. Gap items 6, 69.

## Objective
Provide provider-neutral cloud failure primitives while supporting cloud-native capabilities through adapters.

## Builds on
- `providers/` permission model (default posture nothing; capabilities declared and visible pre-execution).
- `domain/quota.py` damage pricing and blast-radius dependents closure — cloud actions price real `FaultDefinition`s, never estimates alone.
- Evidence envelope and redaction (cloud identifiers and account data classified; secrets never enter evidence per 29).

## Providers
AWS, GCP, Azure.

## Core resource classes
VM/instance, network, load balancer, object storage, block storage,
managed database, queues, functions, managed Kubernetes.

## Provider abstraction
```text
CloudProvider
  discover()
  capabilities()
  preview()
  execute()
  compensate()
  verify()
```

## Safety
Provider IAM role validation, resource allowlists,
account/project/subscription boundaries, region/AZ restrictions, cost
estimation (gap 69: expected incremental cost shown before execution,
cost ceiling enforced), stop conditions, automatic rollback where
supported.

## Phase 1 — Domain model: cloud vocabulary
Add `domain/cloud.py`: `CloudTarget` (provider, resource class, selector, resolved resource identity), `CloudAction` (stop, reboot, isolate, impair, failover), `CostEstimate` (expected range plus ceiling), all pure. Selectors resolve to exact resource identities; unresolved selectors are a plan-time refusal. Acceptance: resolution tests pin exact-identity semantics — no prefix/wildcard execution.

## Phase 2 — Engine: adapters behind the provider contract
Implement AWS/GCP/Azure adapters behind the abstraction; each action implements execute/compensate/verify or declares itself irreversible (irreversible actions require elevated approval per 09 and never run under implicit execution). Acceptance: every adapter action demonstrates compensate→verify on a sandbox account before catalog exposure.

## Phase 3 — Surface: provider commands and permission analysis
`mayhem cloud` command group (single inventory entry each, README/Justfile updated per the release contract), provider permission analyzer (`can this role perform this action?` answered pre-run), cost estimator output. Acceptance: IAM-insufficient plans refused with the missing permission named.

## Phase 4 — Safety and evidence integration
Cloud actions enter blast-radius and damage-quota accounting (region/AZ blast rules in 07); cloud action logs correlated with Mayhem evidence (timestamped, monotonic-clock-annotated per the 12 time-sync rule). Acceptance: an action exceeding the cost ceiling refuses before mutation.

## Phase 5 — Tests, regression guards, negative controls
Adapter conformance against recorded API fixtures (no live cloud in unit tests); refusal tests for unresolved targets, insufficient IAM, exceeded ceilings. Negative control: revoked credentials mid-run trigger fencing/recovery, never silent continuation. Acceptance: suite green without cloud credentials; live cells via 01 only where sandbox accounts exist.

## Phase 6 — Docs, honesty gates, rollout
Provider capability matrices marked per adapter honesty (what the cloud API actually supports vs. what Mayhem wraps); rollout one provider and one resource class at a time. Acceptance: no doc implies rollback where the cloud offers none.

## Deliverables
AWS provider, GCP provider, Azure provider, cost estimator, provider
permission analyzer, cloud audit integration.

## Dependencies
03 (fabric distribution), 07 (region/AZ policy, cost ceilings), 09 (elevated approvals), 12 (correlated evidence), 29 (cloud credentials).

## STATUS — planning only, 0%
