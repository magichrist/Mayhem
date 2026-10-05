# Plan 09 — identity, RBAC and approvals guide

Companion to `docs/v1.1.0/09_IDENTITY_RBAC_APPROVALS.md`. Everything here is
generated from the code that enforces it: the roles are
`mayhem.domain.identity.Role`, the approval binding is
`mayhem.domain.approval.Approval`, and the audit actions are
`mayhem.infra.audit_stream.KIND_*`. If a statement here disagrees with the code,
the code is right and this page is stale.

---

## 1. The rule everything else serves

**A principal holds nothing it was not granted, in one environment, and an
approval authorizes exactly one plan under exactly one policy and one proof.**

Two halves, and neither has a default:

- **RBAC** answers *may this person act here?* — one of eight roles, in one
  `EnvironmentScope`, unioned across direct and team grants. No hierarchy:
  `ADMINISTER` does not imply `EXECUTE`, and there is no wildcard role value.
- **Approval** answers *did a named person agree to this exact thing?* — four
  digests: plan, policy, proof, and an environment that covers the one being
  acted on. An approval that disagrees with any of them is not a lesser
  approval; it is not an approval of this run.

Both are enforced by pure predicates in `domain/identity.py` and
`domain/approval.py`, reached from admission by
`controller/approval_gate.py` and re-checked at seal time by
`controller/approval_evidence.py`.

## 2. What is implemented, and what is only a port

This is the first section because the honest answer is not the one an identity
guide usually gives. **Nothing here configures your SSO.**

| Capability | Status |
| --- | --- |
| Local passwords | **Implemented and tested.** PBKDF2-HMAC-SHA256, per-credential salt, constant-time compare, injected work factor. **No new dependency** — PBKDF2 is in the standard library. |
| Session tokens | **Implemented and tested.** Short-lived, revocable, rotated, with a bounded propagation delay (`REVOCATION_PROPAGATION_BOUND_S`). |
| API keys | **Implemented and tested.** Scoped at issue, short-lived (900 s default), hashed at rest, never readable out of the store. |
| Role grants and team membership | **Implemented and tested.** Environment-scoped, windowed, revocable. |
| Approval minting, verification, revocation, expiry | **Implemented and tested.** |
| Emergency override | **Implemented and tested.** Executes, and seals the principal and reason into the evidence and the audit stream. |
| Sealed approval records | **Implemented and tested.** `RunAuthorization` in plan 12's attested chain. |
| OIDC / OAuth | **`IdentityProviderPort` only.** A two-method protocol plus `CallableIdentityProvider` and `StaticIdentityProvider`, exercised against a *faked* IdP. **No OIDC client, no token validation, no JWKS fetch, no network call of any kind.** |
| SAML | **Nothing.** No metadata parsing, no assertion validation, no signature check. |
| SCIM | **Nothing.** No provisioning, no deprovisioning, no sync state. |
| MFA / TOTP / WebAuthn | **Nothing.** No second factor is required, offered, or verified anywhere. |
| Password reset, refresh tokens, OAuth client registration | **Nothing.** |
| CLI or UI surface for login, teams, or approval flows | **Nothing.** No `mayhem login`, no screen, no command. Phase 3 of the plan is the *service* those surfaces would call. |
| Signatures on approvals or audit entries | **Nothing.** No key material, no KMS/HSM custody, no Sigstore. Every artifact is integrity-chained and *named*; an entry's `principal` is a recorded claim by the writer, **not an authenticated identity**. |

The rule this page follows: if a thing was not executed against a real
identity provider, this page says "port" or "nothing", never "supported".

### Why local auth got built first

PBKDF2 is in the standard library, so local auth needed no new dependency and no
network. That is the whole reason it exists, and it is also its limit: it proves
the *model* — principals, grants, sessions, revocation propagation — rather than
federation. A deployment that wants SSO is integrating `IdentityProviderPort`;
it is not turning something on.

## 3. The eight roles

| Role | Grants |
| --- | --- |
| `view` | Read. |
| `design` | Author a design; gates publishing a policy bundle in `domain/policy_authoring.py`. |
| `plan` | Compile a plan. `POST /api/v1/plans`. |
| `approve` | Grant an approval. Never implied by holding anything else. |
| `execute` | Run a plan. Never implied by `approve`, and never implies it. |
| `emergency_stop` | Place a stop. |
| `administer` | Administer. **Nothing enforces this yet** — see §7. |
| `evidence_admin` | Evidence-shaped reads. A legitimate read role, deliberately distinct from `view`. |

`Role` is a `StrEnum`; the set is closed. **No value means "everything".** A
wildcard would make the authorization matrix vacuous, and
`tests/unit/test_rbac_matrix.py` asserts the absence.

### Roles are scoped, and the scope is the boundary

A grant says *this role, in this scope*. `EnvironmentScope` covers the
environments it reaches, and `covers()` is asymmetric on purpose:

| Grant in | Acting in | Reaches? |
| --- | --- | --- |
| `production` | `staging` | no |
| `*` (org-wide) | anything | yes |
| `platform/production` | `production` | yes |
| `platform/production` | `payments/production` | **no** |

The last row is the one a matrix written in terms of environment names misses:
both scopes are called "production". Narrowing by project is real, and it is
tested in `test_a_grant_reaches_exactly_the_scopes_that_cover_the_action`.

### No hierarchy, deliberately

`effective_roles` unions grants; it never ranks them. Holding `administer`
confers nothing beyond itself. The separated roles exist so a policy can require
two people, and a hierarchy would dissolve exactly that.

## 4. Approvals

### What an approval binds

`Approval.bind` takes the plan digest **from the proof**, so an approval over a
plan its proof was not compiled from is unrepresentable from the constructor. An
approval binds:

- `plan_digest`, `policy_digest`, `proof_digest` — three sha256 digests;
- an `EnvironmentScope` that must **cover** the environment being acted on;
- an approver, a window, and optionally change-ticket refs.

`Approval.speaks_for` is the four comparisons and nothing else, so "does this
still name what is about to run?" is one readable predicate.

### The rules, and which layer enforces each

| Rule | Enforced at |
| --- | --- |
| The executor holds `execute` **in the environment being acted on** | admission, before approvals are read at all |
| The proof presented declares `PASS` and still evaluates to `PASS` for this plan | admission |
| The approvals cover this exact `(plan, policy, proof, environment)` tuple | admission |
| The executor is not among the approvers, when separation of duties is on | admission; a switch, not a hard rule |
| The approver held `approve` in scope **at mint time** | minting, by `AuthService` |
| The approver still holds it **at seal time** | sealing, by `require_approval_records` via the re-derivation |
| An approval is not revoked / not expired / not replayed | both, from the same `evaluate_approvals` |
| An override carries a reason | minting *and* evaluation |
| Every approval that authorized the run is in the audit stream | sealing, **before the store is touched** |

Two different moments, deliberately. Minting-time checks stop an unauthorized
approval from existing; seal-time checks stop an approval that has since been
revoked, expired, or replayed from being the run's authority. The same
`evaluate_approvals` answers both, so the two moments cannot disagree about what
an approval means.

### Approval *levels* are not bound to teams

Policy decisions can name levels (`sre`, `service_owner`). The gate enforces their
**count** — one signature per level — and reports the ones it could not bind in
`ApprovalGateResult.unbound_levels`, which travels into the sealed evidence. So an
allowed run's record says "authorized on N signatures; which group gave them is not
recorded". That is the honest reading, and **nothing in the evidence resolves it.**
Binding a level to a required team is unmapped work.

### Emergency overrides

An override executes the plan and is never mistakable for an ordinary approval:

- its reason is mandatory at mint and travels in the record;
- the gate gives it its own decision rule (`approval.override`), a warning
  severity, and the principal and reason in the text;
- it gets its own audit kind, and the run cannot be sealed without that entry;
- the approval's own digest changes when it is minted as an override, so it
  cannot be presented as an ordinary approval.

**It executes anyway.** That is the point of a break-glass path, and it is also
the risk. Post-hoc *review* is still a human process with no artifact behind it;
what this system provides is the record a reviewer would read.

## 5. Audit records

Six actions, all cross-run facts about people, all in the append-only
`AuditStream`, all declared in `infra/audit_stream.py` — the module that owns
that vocabulary:

| Kind | Records |
| --- | --- |
| `audit.approval.granted` | an approval was granted; carries the digests it binds |
| `audit.approval.revoked` | an approval was revoked, naming the revoker |
| `audit.approval.override_exercised` | a principal *exercised* an override on a named run |
| `audit.role.granted` | a role was granted, naming what and where |
| `audit.role.revoked` | a role grant was withdrawn |
| `audit.principal.disabled` | a principal was disabled, with a mandatory reason |

Granting an override and exercising one are two different entries on purpose: the
question "who pressed the button" is only answerable if the *use* is its own
record.

Three of the six assert a *transition*. An entry claiming a revocation that did
not happen, an override exercise that was not an override, or a principal
disabled who is not disabled is **refused** — in an append-only log there is no
later entry to contradict it.

The stream is verified offline by `verify_audit_chain`, which detects an entry
that was altered, reordered, or removed, naming the entry. It detects *that*, not
*who*: with no signature, a writer that can insert can insert a different chain.

## 6. Reading a run's approval evidence

```
seal_approval_decision(
    store, envelope,
    result=gate_result,          # the same object admission reached
    policy_decision=...,         # plan 07's decision, which the sealer requires
    approvals=(...),             # the records, as they read NOW
    environment=scope,           # the scope, not a parsed string
    grants=...,                  # the authority behind those approvals
    now=...,                     # the sealing instant, not a clock read
    audit=audit_stream,
)
```

Two refusals run before the store is touched, so a refusal leaves no chain, no
manifest, and no audit row:

1. the binding does not re-derive at this instant → `approval.not_reproducible`;
2. the approvals are not on record for this run → the seal is refused.

A caller that passes `audit=None` gets neither. The parameter is additive for the
same reason plan 12's authorization argument is: a run's evidence must survive
even when the evidence about how it was authorized is missing, because an
incomplete-but-honest chain is worth more than no chain.

## 7. What this guide does not claim

- **It does not describe a deployment.** No `mayhem login`, no SSO
  configuration, no screen. The service exists; the surface does not.
- **`administer` is a real gap.** Nothing enforces it. It is listed in §3 with
  that annotation and asserted as a gap by `tests/unit/test_rbac_matrix.py`
  (`UNENFORCED_ROLES == ("administer",)`), so it cannot quietly become a claim.
- **No artifact here is signed.** Integrity is established; authorship is not.
  An `approval_digest` pins a record's content and says nothing about who wrote
  it — the two facts are asserted separately in
  `tests/unit/test_approval_evidence.py` precisely so they do not blur.
- **Approval levels remain unbound to teams** (§4). An evidence record naming an
  outstanding level records the gap; it does not close it.
- **Revocation propagation is bounded and tested, not instantaneous.** The bound
  is `REVOCATION_PROPAGATION_BOUND_S` (5 s) on an *injected* clock. A credential
  revoked on one connection is honoured on another within that bound, and the
  claim is about the bound, not about zero.
- **Nothing here has been run against a real identity provider**, so nothing here
  can tell you how your provider will behave. The walkthrough runs against a faked
  IdP by design, because a test that needed the network would be a test that could
  not be trusted.