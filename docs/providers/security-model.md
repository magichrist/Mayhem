# The provider security model

What a provider extension can reach, what mayhem actually confines, and — the
part most pages get wrong — what it does not.

> **mayhem verifies no signature over a provider artifact in this build.**
> `mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` is `False`, and no
> page in this directory may call an artifact trusted, verified or signed.

## The four statements that hold everything else up

1. **Extensions are untrusted by default, and enforced that way.** The declared
   permission set is compared against a caller-supplied grant that defaults to
   *nothing* (`DEFAULT_DECLARED_PERMISSIONS`). A declaration that asks for any
   permission loads only when someone supplied that permission explicitly.
2. **No confinement mechanism exists in this build.** No seccomp filter, no
   AppArmor profile, no SELinux label, no container isolation. `mayhem` computes
   which of those a declaration would need, labels them
   `declared_not_applied`, and refuses six of the seven profile tiers. Only
   `declaration_only` is admitted.
3. **A declared permission is a decision, not a mechanism.** A `SandboxProfile`
   is a stated intent. Capability drops, filesystem rules and egress rules are
   all evaluated as policy and none of them touches the kernel, the filesystem or
   the network.
4. **Sealing proves ordering, not authorship.** Provider activity is sealed into
   plan 12's existing attested chain. Every manifest is written unsigned, with
   plan 12's reason recorded beside it, and `infra/audit_stream` records a
   principal as a *claim* rather than as an authenticated identity.

## The permission vocabulary

| Permission | What granting it means |
|---|---|
| `target:read` | reads the mayhem target through mayhem's own API |
| `target:mutate` | changes the target — which is why a compensating fault must exist |
| `filesystem:read` | reads paths outside the target |
| `filesystem:write` | writes paths outside the target |
| `subprocess` | spawns processes on this host |
| `network` | reaches the network from this host |

`target:read` is the one people underestimate. A provider that can read a target
can exfiltrate what it reads, and the read is what an operator is being asked to
permit. The gap-74 display lists it under `cannot_do` like any other until it is
both granted and approved.

## The sandbox tiers

`SANDBOX_TIERS` names seven profiles, selected as the most specific tier a
declaration's permissions satisfy:

| Tier | Required permissions | Admitted in this build |
|---|---|---|
| `declaration_only` | none | **yes** |
| `target.read` | `target:read` | no |
| `target.mutate` | `target:read`, `target:mutate` | no |
| `filesystem.read` | `target:read`, `filesystem:read` | no |
| `filesystem.write` | `…read`, `filesystem:write` | no |
| `subprocess` | `target:read`, `subprocess` | no |
| `network.egress` | `target:read`, `network` | no |

The six refusals are not a policy preference. They are the honest answer to "you
asked for a mechanism and this build has none": the refusal code is
`provider_sandbox_mechanism_unapplied` and it names the mechanisms that would
have been required.

### The opt-out, and what it costs

`ProviderLoader(require_sandbox_enforcement=False)` — or `--allow-unsandboxed`
on `mayhem providers load` and `mayhem providers inspect` — admits the profile.

It is deliberately *loud* rather than convenient:

- **Explicit only.** No inference, no auto-downgrade, no "it looks harmless"
  heuristic.
- **Two flags, not one.** `--allow-unsandboxed` gives up a mechanism;
  `--allow-permission` grants a permission. Neither implies the other.
- **Not silent.** The unconfined admission seals as `ACKNOWLEDGED_NO_BACKEND`
  with the profile's unapplied mechanism list, so "we ran it unconfined" is in
  the evidence chain.
- **Not free.** It does not make the provider safe, does not grant the declared
  permission, and confines nothing. It removes that one refusal.

## Blast accounting and the damage quota

A provider action participates in cumulative damage accounting through the *same*
ledger a native action uses: `mayhem.providers.participation.charge_provider_blast`
calls `DamageLedger.charge`. There is one implementation of the arithmetic, so a
provider step and a native step cannot disagree about what a run costs, and a
breach refuses with the ledger's own `damage_quota.*` rule ids rather than a
provider-flavoured one.

One honest caveat, reported on every charge: a provider fault id is not in
mayhem's fault catalog, so `damage_weight` prices it at
`UNRESOLVED_FAULT_WEIGHT` — the top rung of both ladders. That is fail-safe (an
unpriced fault can never be the cheap one) but it is *unresolved*, so
`BlastCharge.weight_source` reports `unresolved_conservative` instead of letting
a reader assume a catalog price was found.

What is not wired yet: nothing in the run path calls this module today. The
charge has to be made from the controller, which another lane owns.

## Leases

A mutating provider action takes a real `FaultLease` and lives under the same
invariants as a native one: no `ACTIVE` without write-ahead undo ops, no
`RELEASING` without verify probes, and `assert_all_recovered` as the
run-completion invariant. There is deliberately no `ProviderLease` type that
could be more permissive.

The refusal that matters is `provider.lease_undo_absent`. A `FaultDeclaration`
can say `reversible=True` — a compensation path exists — and has **no field for
the operations that perform it**. Those arrive from the provider's runtime at
lease time. A mutating action with no undo ops is refused rather than admitted,
because a mutation without write-ahead undo is the defect ADR-0005 exists to
prevent, and a provider must not be the one actor allowed to skip it.

## Certification, and the pin that cannot be set

The plan requires provider faults to enter the plan-01 certification pipeline with
their provider version pinned in the matrix cell. **That does not work today, and
mayhem says so rather than papering over it.** `mayhem.providers.participation.certification_blockers`
*calls* plan 01's own code and reports both blockers it finds:

1. `MatrixCell` is `extra="forbid"` with no `provider_version` field, so a
   provider version cannot be frozen into the cell's identity and therefore cannot
   invalidate a certification when the provider moves.
2. `CertificationRecord` refuses a provider fault id outright, because `fault_id`
   is validated against `FaultCategory` prefixes and a third-party provider does
   not get one.

`ensure_certification_pin` refuses on both counts. Each blocker carries a
`change_required` string naming the exact file and field, because a plan-01 change
belongs to plan 01.

## What a provider still has to pass

- **Declaration gates**, in a fixed order, each with a named code: compatibility
  bounds → declared permissions → declaration graph → parameter defaults →
  evidence coverage → id shadowing → sandbox profile.
- **A behaviour check before registration.** A runtime advertising a capability,
  fault or permission it never declared is refused while it is still a local
  variable, so there is no window in which a mismatched runtime was reachable.
- **Approval before install.** The gap-74 display is never approved on
  construction, and `approve_permission_display` is the only thing that grants.

## See also

- [README.md](README.md) — the SDK's index and what it confers.
- [marketplace-readiness.md](marketplace-readiness.md) — what plan 18 checks.