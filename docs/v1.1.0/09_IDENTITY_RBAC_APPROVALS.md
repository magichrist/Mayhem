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
- Phase 4 (safety and evidence integration): DONE — `controller/approval_evidence.py` re-evaluates the approvals **at seal time** against the digests the chain is about to commit to, delegating to `domain.approval.evaluate_approvals` rather than adding a second notion of validity, so the plan's "a user can never approve a modified plan with an old approval" is enforced at the boundary and not only at grant; `build_authorization` produces plan 12's `RunAuthorization` and `seal_approval_decision` hands it to plan 12's own sealer, minting no event type, digest, manifest, or sealer of its own. Six new audit kinds (`audit.approval.granted`, `audit.approval.revoked`, `audit.approval.override_exercised`, `audit.role.granted`, `audit.role.revoked`, `audit.principal.disabled`) are declared in `infra/audit_stream.py` — the table that owns that vocabulary — and `require_approval_records` makes the plan's acceptance criterion enforceable: **a run whose approvals authorized it but whose approval records are absent from the audit stream cannot be sealed**, matched by approval digest so an entry naming the right people but the wrong record does not satisfy it. Both refusals run before the store is touched, so a refusal leaves no chain, no manifest, and no audit row
- Phase 5 (tests, regression guards, negative controls): DONE — `tests/unit/test_rbac_matrix.py` (776 lines, 21 test functions, 78 cases) proves the **matrix** rather than the pieces: role x environment x action over the whole surface. Every axis is *derived* — the action axis is `api_service.ROUTES` crossed with the `Role` enum, the environment axis is real `EnvironmentScope` values — so a new route or a ninth role is covered by construction instead of by remembering to add a row. Verified by mutation: adding a `Role.DESIGN` route makes the suite fail until somebody names the layer that enforces it. Covers the approval-binding extension of the v1.0.0 execution-intent suite (the intent's `plan_hash` and the approval's `plan_digest` bind the same plan, and all three digest producers agree), the no-hierarchy property over the whole enum, the environment axis including the project-narrowing an environment-name matrix would miss, the store-backed `AuthService` agreeing with the pure predicate in every cell, and every `InvalidationReason` provoked by a real construction and *named* by the refusal. Negative controls: a revoked approver, a forked plan digest, a replayed approval token, and an approver whose grant is absent — each asserted through the real gate, not by reading a field. `test_auth_service.py` already bounded revocation propagation at `REVOCATION_PROPAGATION_BOUND_S` on an injected clock and this suite re-asserts that bound rather than duplicating it
- Phase 6 (docs, honesty gates, rollout): DONE — `docs/v1.1.0/09_identity_guide.md` (identity configuration, the eight-role reference with its scope table, approval policy examples, and the audit-record vocabulary), `tests/unit/test_approval_plan_docs.py` as the honesty gate over both documents, and the rollout order below. The guide leads with a capability table in which every federated or unattended identity feature is marked **port** or **nothing**, because the phase's acceptance criterion is that no doc implies SSO guarantees the deployment does not configure

Overall: 6 of 6 phases complete.

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

### Phase 4 — what this phase does *not* claim

- **No signature, and no claim of one.** Nothing here mints signature bytes: no
  key material, KMS/HSM custody, or Sigstore integration exists, so every
  artifact this phase produces is integrity-chained and *named*. A reader must
  treat "these bytes were unaltered and in order" as established and "these
  bytes were written by this person" as **a claim by the writer, not a proven
  fact**. An `approval_digest` pins a record's *content*; it is not an
  authorship proof, and `tests/unit/test_approval_evidence.py` asserts those two
  facts separately so the distinction cannot quietly rot.
- **Nothing in the run-close path calls it yet.** `seal_approval_decision` is
  the seam a caller reaches with a store, an envelope, and a gate result in
  hand. Neither `controller/executor.py` nor `cli/lifecycle.py` calls it, for
  the reason plan 12's own `seal_run_evidence_at_run_close` is not called from
  the executor: the envelope is assembled after the run and the gate result is a
  `SafetyContext` local. This is the documented seam, not a silent omission.
- **The completeness check needs an audit stream.** `seal_approval_decision`
  takes `audit: AuditStream | None`, and the "a run without a matching approval
  record is unrepresentable" guarantee holds only when a stream is supplied.
  Passing `None` seals without it. The parameter is additive for the same
  reason plan 12's authorization argument is: a run's evidence must survive even
  when the evidence about how it was authorized is missing — an
  incomplete-but-honest chain is worth more than no chain.
- **`grants` and `memberships` must be handed to the re-derivation.** They
  default to empty, and `domain.approval.approval_reasons` refuses an approval
  whose approver holds no `APPROVE` grant in scope — so forgetting them is
  default-deny rather than an accidental pass. The caller must therefore supply
  the authority the gate used, which is a real burden and a real property: it is
  what makes an approver whose grant was withdrawn between admission and close
  caught here rather than at the gate.
- **The environment scope is a parameter, not re-derived.** The gate result
  records its environment as a *rendered* string. Parsing that back into a scope
  would be a second, looser notion of what an environment is, so the scope is
  demanded from the caller and a missing one is refused.
- **Approval *levels* remain unbound to roles or teams.** Phase 2's gap is
  unchanged: `quorum_from_requirements` enforces the *count* of named levels and
  `ApprovalGateResult.unbound_levels` reports which groups it could not bind.
  Sealing a run does not close that gap — an evidence record naming an
  outstanding level is a record of the gap, not a resolution of it.
- **No post-hoc review workflow.** An override's principal and reason are sealed
  into the chain and recorded in the audit stream, and a run executed under one
  is never mistakable for an ordinary approval. *Reviewing* it is still a human
  process with no artifact behind it; this phase records the obligation, it does
  not discharge it.

### Phase 5 — what this suite does *not* claim

- **It is a matrix over the surfaces that exist, not a proof about a
  deployment.** The action axis is `api_service.ROUTES`: an action nobody
  routed is not in the matrix, and a role enforced only at a layer with no
  route (`approve`, `execute`, `design`) is a *finding*, recorded in
  `ROLES_WITHOUT_A_ROUTE` with the layer that enforces it — not a covered cell.
- **`ADMINISTER` is a real gap, and this suite names it rather than routing
  around it.** `AuthService` has no `ADMINISTER`-checked administration of the
  identity store itself, so `UNENFORCED_ROLES == ("administer",)` is asserted.
  Adding a role to the enum without saying where it is enforced fails the
  suite, which is the intended pressure.
- **The project axis is exercised at two scopes only.** `platform` and
  `payments` under `production` are enough to catch the asymmetry that matters
  (a project-narrowed grant reaches the bare environment but not a sibling
  project); they are not a tenancy model, and no claim is made about
  hierarchical organizations.
- **No hierarchy is asserted for `effective_roles`, not for the surfaces.** A
  role a route never demands confers nothing *through that route*; whether some
  other surface treats it as a superset is outside what this file checks.
- **The store-backed comparison covers `EXECUTE` in five scopes**, not all
  eight roles in every scope. The point is that the service and the pure
  predicate cannot disagree, and a disagreement on any one cell is the failure
  mode; the pure matrix above is what covers the full product.
- **Revocation-propagation *timing* is not re-measured here.** It is bounded and
  tested in `test_auth_service.py` against an injected monotonic clock. This
  suite asserts the bound's existence through that suite, not a second timing
  measurement, because two measurements of the same bound would be one number
  and one number is not evidence.
- **The unused-import guard is self-referential by necessity** and its first
  draft exempted its own docstring twice before being simplified; a guard that
  needs to exempt itself is usually the wrong guard, and this one was kept only
  because it is cheap and caught a real unused import during development.

---

## Identity configuration

Full reference in `docs/v1.1.0/09_identity_guide.md`. The short version:

| Capability | Status |
| --- | --- |
| Local passwords, sessions, API keys, role grants, teams | implemented and tested |
| Approvals, revocation, expiry, emergency override | implemented and tested |
| Sealed approval records in the attested chain | implemented and tested |
| OIDC / OAuth | `IdentityProviderPort` only, exercised against a faked IdP |
| SAML, SCIM, MFA, password reset, refresh tokens | nothing |
| CLI or UI surface for login, teams, approval flows | nothing |
| Signatures on approvals or audit entries | nothing |

## RBAC role reference

Eight closed roles, environment-scoped, with **no hierarchy**: `ADMINISTER` does
not imply `EXECUTE`, and no value means "everything". `effective_roles` unions
direct and team grants and never ranks them. The scope is the boundary, and
`EnvironmentScope.covers` is asymmetric on purpose — a `production` grant does
not reach `staging`, and a `platform/production` grant reaches `production` but
not `payments/production`, which is the case a matrix written in terms of
environment names misses.

**`ADMINISTER` is a real gap and is annotated as one.** Nothing enforces it;
`tests/unit/test_rbac_matrix.py` asserts `UNENFORCED_ROLES == ("administer",)`, so
the gap cannot quietly become a claim.

## Approval policy examples

Four configurations, as the gate reads them. Each is a claim about what the
system *does*, not what a deployment should do.

**Single approval, the default.** One approver holding `approve` in the acted-on
environment; quorum 1. The plan the gate compares is the plan that runs, so an
approval stops matching the moment the plan changes.

**Multi approval.** `required_approvals=2` raises the quorum to two *distinct*
principals — `evaluate_approvals` counts `set(approver.principal_id)`, so the same
person approving twice is one signature. Two approvals from two people with the
same name are one signature too, which is why the count is over principal ids and
not over display names.

**Separation of duties.** A switch, not a hard rule. On means the executor may not
be among the approvers; off means the roles stay separate but their holders may
coincide. Either answer is enforced and the gate never derives the switch itself.

**Emergency override.** Executes, and pays for it by being unrepresentable as an
ordinary approval: its own decision rule, its own audit kind, and a digest that
changes when it is minted as one.

## Rollout

The order the plan names, and where each step actually stands:

| Step | Status |
| --- | --- |
| local auth first | done — PBKDF2, no new dependency |
| OIDC second | port only; no client, no JWKS fetch, no network call |
| single approval before multi-approval | both implemented; multi-approval's *levels* are unbound to teams |
| SAML / SCIM last | nothing |

**The first three tiers have no schedule.** Nothing in this repository schedules
an identity rollout, and no SSO deployment has ever been configured, so any
timeline attached to this table would be a date this project cannot keep.

## Phase 6 — what this phase does not claim

- **No SSO guarantee of any kind.** The guide says "port" or "nothing" for every
  federated feature and never "supported". A deployment integrating
  `IdentityProviderPort` is building something Mayhem does not have.
- **No schedule.** The rollout order is a preference, not a plan with dates.
- **No deployment guidance for MFA, which does not exist.** A guide that omitted
  the row would be the more dangerous choice, so the row is present and empty.
- **The role reference is not an authorization policy.** It says what each role
  *is*; which roles a given team holds is configuration this system does not
  decide.
