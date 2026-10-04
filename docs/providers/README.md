# Provider extensions and the extension SDK

This directory documents plan 17: how a provider extension is declared, loaded,
held accountable, and — the part worth reading first — **what mayhem cannot
establish about one**.

## Read this first

> **mayhem verifies no signature over a provider artifact in this build.**
> `mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` is `False`, and
> nothing in the SDK changes it. An SDK-built declaration is a *claim of
> authorship by whoever ran the SDK*. Nothing in this system can tell you that
> claim is true.

Two further facts sit next to that one, and every page here carries at least one
of them:

- **No confinement mechanism exists in this build.** No seccomp filter, no
  AppArmor profile, no SELinux label, no container is created anywhere. Mayhem
  computes which of those a declaration *would* need and refuses the six of seven
  profile tiers that need one; the seventh (`declaration_only`) is admitted.
- **Sealing is not signing.** Every evidence chain mayhem writes is written
  *unsigned*, with plan 12's reason stored beside it. A sealed record proves the
  bytes are unaltered and in order. It proves nothing about who produced them.

## What the SDK does, and does not, confer

Building a declaration through the SDK confers exactly three things:

1. the declaration validates against the `mayhem.provider-declaration/v1` grammar;
2. the canonical form is byte-stable and safe to hash;
3. the author-supplied provider id and version are carried through unaltered, so
   an operator can see and compare them.

It confers **none** of the following, and no page here may imply otherwise:

- that the provider's code is safe, correct, or free of malice;
- that the provider id, version or homepage identifies a real party;
- that the artifact was not modified between publication and installation;
- that the provider will keep working after its author stops maintaining it.

That list is a constant — `SDK_CONFERRED` and `SDK_NOT_CONFERRED` in
`mayhem.providers.sdk` — rather than a paragraph, so a documentation page and the
code cannot drift apart.

## Pages

Each page below carries the signature caveat in its first paragraph and the
sandbox caveat where it discusses permissions. A page that cannot carry both
without saying something false about itself should not exist.

| Page | What it covers |
|---|---|
| [sdk-python.md](sdk-python.md) | Authoring a declaration with the Python SDK, and what it does not check for you |
| [sdk-rust.md](sdk-rust.md) | The Rust wire contract, and the honest reason no `.crate` ships here |
| [sdk-go.md](sdk-go.md) | The Go wire contract, and the honest reason no Go package ships here |
| [security-model.md](security-model.md) | What a provider can reach, what mayhem confines, and what it does not |
| [marketplace-readiness.md](marketplace-readiness.md) | The checklist a provider must pass before plan 18 may list it |

## One protocol, two documents

The 37 "Mayhem-compatible provider" protocol is the declaration schema plus the
plan-03 fabric command envelope. `MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL` in
`mayhem.providers.loader` names the schema half and
`MAYHEM_COMPATIBLE_PROVIDER_PROTOCOL_DOCUMENTS` names both documents, so "one
protocol, two documents" is a value in the code rather than a slogan in a plan.

## The refusal you will hit first

Since the Phase 2 and Phase 4 decisions, `require_sandbox_enforcement` defaults
to `True`. With no confinement mechanism in this build, **a provider that
declares any permission at all does not load by default.** The refusal names the
mechanisms that are missing, and the escape hatch is two explicit flags:

- `--allow-unsandboxed` gives up the *mechanism*. It does not grant the
  permission, does not make the provider safe, and confines nothing. It removes
  that one refusal and only that refusal.
- `--allow-permission` grants a *permission*. It is still required.

An admission made under the first flag is recorded in the evidence chain as
`ACKNOWLEDGED_NO_BACKEND`, so "we ran it unconfined" is a recorded fact rather
than an absence nobody chose.