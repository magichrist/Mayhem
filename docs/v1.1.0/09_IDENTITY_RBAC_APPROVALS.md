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
- Phase 2 (engine): DONE — `controller/approval_gate.py` (`ApprovalGateInputs`, `verify_approvals`, `ApprovalLedger`, sealed `evidence()`) wired into `controller/safety.validate_plan` behind the additive `SafetyContext.approval_gate`; executor role + environment scope authorized before any approval counts, separation of duties switchable by policy, and an emergency override that executes while sealing principal and reason into the evidence record
- Phase 3 (surface: authentication and authorization service): DONE — `infra/identity_store.py` (migration `M0031_IDENTITY`, reversible; principals, PBKDF2-only local credentials, memberships, role grants, sessions, scoped API keys, and an append-only revocation log whose triggers refuse UPDATE/DELETE) and `controller/auth_service.py`. Local auth is implemented for real (PBKDF2-HMAC-SHA256, per-credential salt, constant-time compare) with **no new dependency**; OIDC/OAuth/SAML/SCIM are `IdentityProviderPort` seams plus `CallableIdentityProvider`/`StaticIdentityProvider`, exercised by an end-to-end walkthrough (authenticate → policy → approve → execute) against a faked IdP. Tokens issue, rotate, revoke, and expire, with `IssuedToken`/`IssuedApiKey` redacting their own secret in `__repr__`; API keys are short-lived (900s default), scoped at issue, revocable, and never readable out of the store (schema `CHECK`s make a plaintext credential unrepresentable). The service **supplies** principals, grants, memberships, and consumed ids to `approval_gate` via `gate_inputs()` and defines no second role or approval model — `effective_roles`/`has_role`/`Approval.bind` still decide. Revocation propagation is bounded at `REVOCATION_PROPAGATION_BOUND_S` (5s) on an injected monotonic clock, and cached decisions are additionally capped by the subject's own expiry so an expired credential is never served from cache
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 3 of 6 phases complete.

### Phase 3 — what this phase does *not* claim

- **No UI or CLI surface.** The plan's Phase 3 heading says "login, teams, approval
  flows ... in CLI and UI (08)". What landed here is the service those surfaces
  call; no `mayhem login` command and no screen exists yet, and nothing in
  `src/mayhem/cli/` was touched. Phase 6 owns the rollout surfaces.
- **No MFA, password reset, refresh tokens, OAuth client registration, SAML
  metadata, or SCIM sync state.** Their formats belong to provider libraries this
  project does not depend on, and the migration deliberately has no column where
  an unverified assertion could be parked.
- **No policy on who may call which service method.** `AuthService` has no
  `ADMINISTER`-gated admin operations; authorization exists for *acting on a
  target*, and administration of the identity store itself is Phase 6's
  question.
- **Approval levels (`sre`, `service_owner`) are still unbound to roles/teams.**
  Phase 2's `quorum_from_requirements` enforces their *count* only; Phase 3
  supplies grants so a level-bearing quorum can eventually be attributed, but
  nothing here maps a level to a required team.
- **The API-key scope is a narrowing on top of RBAC, not a replacement for it.**
  A scoped key can only ever reach where its scopes reach; it confers nothing on
  its own.
