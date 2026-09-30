# Plan 09 — Identity, RBAC, Teams, and Approvals

**Priority:** P0. Gap items 8, 11.

## Objective
Give Mayhem enterprise identity and an approval workflow where an approval is a cryptographic statement about an exact plan — invalid the moment anything changes.

## Builds on
- `domain/execution_intent.py` (explicit `--execute` semantics, plan-hash binding) becomes the approval primitive's core: approval = (plan digest, policy digest, approver identity, expiry, ticket refs).
- `controller/plan_diff.py` canonical hashing (`canonical_json`, `diff_plans`) is how "the plan changed" is detected — no parallel digest scheme.
- `config.py` target profiles and `providers/permissions.py` default-deny posture extend into environment-scoped roles.

## Identity
Local auth, OIDC/OAuth, MFA, service accounts, API keys, short-lived
tokens, token rotation and revocation, optional SAML, optional SCIM.
Workload identity for agents (see 19 for mTLS identities).

## Organization model
```text
Organization
 -> Project
 -> Environment
 -> Team
 -> User / Service Account
```

## RBAC
Roles separate: view, design, plan, approve, execute, emergency-stop,
administer, evidence-admin. Environment-scoped permissions with
team boundaries (RBAC plus environment boundaries; ABAC attributes
arrive as a later extension, not a second system).

## Approval model
Single/multi approval, manager and SRE approval paths, approval
expiration, approval bound to plan digest, invalidation on plan change,
change-ticket requirement (Jira/ServiceNow/Linear refs via 16),
emergency override with mandatory post-hoc review.

## Phase 1 — Domain model: identity and approval types
Add `domain/identity.py` extensions (principal, team membership, environment scope, role grants) and `domain/approval.py` (`Approval` with plan digest, policy digest, approver, expiry, ticket refs, override flag; `ApprovalState`). Pure types; "modified plan invalidates approval" as a pure predicate over digests. Acceptance: approval-validity matrix tests covering every invalidation trigger.

## Phase 2 — Engine: authentication and authorization enforcement
Authenticate every API/CLI session; authorize every mutation against role plus environment scope before it reaches the engine — the engine keeps its own intent gate as defense in depth, never as the only check. Approval service mints, verifies, expires, and revokes approvals; emergency override executes but seals the override identity and reason into evidence for review. Acceptance: privilege-escalation tests (approve-then-modify-plan, cross-environment replay, expired-approval reuse) all refused.

## Phase 3 — Surface: login, teams, approval flows
Login and token flows, team/environment administration, approval request/grant/expire UX in CLI and UI (08), ticket linking. Acceptance: the full enterprise walkthrough step (authenticate → policy → approve → execute) runs end to end in tests with faked identity providers.

## Phase 4 — Safety and evidence integration
Approvals recorded into the sealed evidence chain (12); every privileged action emits an audit event with principal, action, target, and decision digests; a user can never approve a modified plan with an old approval (digest comparison at execution, not just at grant). Acceptance: audit-trail completeness test — a run without a matching approval record is unrepresentable.

## Phase 5 — Tests, regression guards, negative controls
Approval-binding tests (the v1.0.0 execution-intent suite extended), RBAC matrix tests per role × environment × action, token lifecycle tests (rotation, revocation propagation, short-lived expiry). Negative controls: revoked approver, forked plan digest, replayed approval token. Acceptance: all green; revocation propagation time bounded and tested.

## Phase 6 — Docs, honesty gates, rollout
Identity configuration guide, RBAC role reference, approval policy examples. Rollout: local auth first, OIDC second, SAML/SCIM last; single approval before multi-approval. Acceptance: no doc implies SSO guarantees the deployment does not configure.

## Dependencies
08 (API/CLI surfaces), 12 (sealed audit trail), 16 (ticket linking), 19 (agent identities, mTLS).

## STATUS
- Phase 1 (domain model): DONE — `Principal`/`TeamMembership`/`EnvironmentScope`/`Role`/`RoleGrant` in `domain/identity.py`, plus `domain/approval.py` (`Approval`, `ApprovalState`, `InvalidationReason`) and the pure `evaluate_approvals` predicate that enumerates every invalidation trigger
- Phase 2: not started
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 1 of 6 phases complete.
