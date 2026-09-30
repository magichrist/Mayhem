# Plan 4 — the fault pack, finished or deleted

**Finding: mayhem had a fault-pack format with a `signature` field, no way to use it, and no signature verification behind that field.**

> **CORRECTED 2026-09-29 during implementation.** This plan originally
> described the format as *signed* and the loader as verifying a signature. Both
> were false. `providers/pack.py` declared `signature: str` and `signer: str`
> with **no key material, no algorithm identifier, and no trust store**; the
> old `_check_signature` only refused an empty signature. The literal
> `"signature": "sig-abc"` verified exactly as well as a real one. The loader
> that now exists enforces **integrity** (SHA-256 over the pack bytes) and
> reports **`signature NOT VERIFIED`** on every pack, naming the signer as a
> *claim*. Shipping "signed fault packs" in 1.0 release material would have
> been the exact overselling this plan set out to prevent.

## What exists

`src/mayhem/providers/pack.py` defines:

```python
FaultPack:  schema_version, manifest, faults, signature, signer,
            declared_digest, development_only
PackFault:  id, target, risk, reversible, compensation,
            observable_effect, permissions
```

`tests/unit/test_fault_pack_validation.py` validates it. The security model is
real and well-chosen: a declared digest, a signature, a named signer, and a
`development_only` escape hatch.

**Nothing outside `src/mayhem/providers/` references it.** A repository-wide
grep for `FaultPack`, `load_pack`, `discover_pack` returns no consumer. There is
no CLI surface, no planner integration, no executor registration path, no
`mayhem pack install`. The format is defined, validated, and unreachable.

## Why it matters for 1.0

Every competitor has an extensibility story, and mayhem should have one too:

| | Extensibility mechanism | Signed? |
| --- | --- | --- |
| Chaos Mesh | closed CRD set — fork the repo | n/a |
| Litmus | **BYOC** + Go/Python/Ansible SDKs | no |
| AWS FIS | **arbitrary SSM documents** as fault actions | via IAM |
| mayhem | `FaultPack` — **exists, unused** | **yes, designed in** |

mayhem is the only one of the four whose design includes a signature and a
digest from the start. That is a genuinely better answer to "should I trust
this third-party fault definition?" than anything else in the market.

**Shipping a 1.0 that advertises signed third-party fault packs and cannot verify
signatures (let alone load
one is worse than shipping no packs at all.** A user who reads about the format
in the release notes and finds no `mayhem pack` command concludes the project
oversells. This is a decision, not a task.

## Recommendation: finish it

The format and its security model are already right. What is missing is the
path from "a signed file on disk" to "a fault in a plan". That is a moderate
amount of work, and it is the single largest *new capability* available to 1.0
without new fault mechanisms.

### Scope

**1. Loading.** `mayhem pack add <path|url>` → verify `declared_digest` →
verify `signature` against a configured signer trust store → validate schema →
record in a local pack registry. A pack whose signature does not verify is
**refused**, with the signer named.

**2. Trust.** Explicit, and boring:

- no implicit trust of a local path — today a pack is trusted only because its
  bytes match a declared digest; authorship is an unverified claim until real
  signature verification exists. A pack is trusted because it is signed by a
  key in `mayhem pack trust add`, not because it is on the local filesystem
- `development_only: true` packs are loadable with an explicit flag and are
  **refused in any run that is not `--dry-run`**, with the refusal printed. This
  is the same posture as the `dependency install` approval contract and it
  should read the same way
- the signer is recorded in every run's evidence bundle, so a verdict can be
  traced to the pack that produced the fault

**3. Planning.** A pack fault participates in the normal pipeline: it must
resolve in `definition_for()`-equivalent lookup, be gated by the impact layer,
and carry a compensation contract. A `PackFault` that declares no usable
`compensation` is **refused at plan time**, exactly as an in-tree fault with no
template is today (`plan_uncompensated_fault`).

That last point is the crux: a pack must not be a way to bypass the safety
contract. If the pack's `reversible: false` and no reconciliation path, the
existing `Reversibility` handling applies unchanged.

**4. Execution.** The pack declares a command; mayhem runs it under the same
rules as any in-tree fault: engine-relative, marker-addressed, undo required,
`can_apply()` honoured. The `permissions` field in `PackFault` should feed the
existing capability layer rather than being advisory.

### Sequencing

| Step | Deliverable | Note |
| --- | --- | --- |
| 1 | `mayhem pack validate <path>` — verify + report, no installation | standalone, useful immediately, zero risk |
| 2 | `mayhem pack add` + trust store + registry | |
| 3 | pack faults in `definition_for()` lookup and the impact gate | the five-registry contract applies to packs too |
| 4 | pack faults plannable and executable, compensation enforced | |
| 5 | signer in the evidence bundle | closes the audit loop |
| 6 | `mayhem pack list` showing every pack fault and its signer | |

**Step 1 alone is worth shipping in 1.0** even if nothing else lands. A
`validate` command that tells you whether a third-party fault pack is
trustworthy is a complete, coherent feature, and it makes the format real
without promising the loader.

### The alternative

Delete `pack.py` and `test_fault_pack_validation.py`, and say nothing about
third-party packs in 1.0. That is defensible: 67 working container-lane faults
need no extension mechanism.

It is worse than finishing it, but it is not much worse, and it is honest. The
thing to avoid is the current state: a signed format with a test suite and no
way to use it, sitting in a release that is otherwise making careful claims.

## A note on `permissions`

`PackFault.permissions` exists and is not consumed. Whatever happens with the
rest of this plan, that field should either feed the capability layer or be
removed. An unenforced permission declaration in a *signed* format is worse than
an unenforced one in an ad-hoc script, because the signature tells the reader it
was considered.

---

## STATUS — SHIPPED, as **integrity-checked**, not signed.

`mayhem pack validate|load|list` exists. The loader enforces a **real SHA-256
digest over the pack bytes** and refuses a mismatch naming both digests.

**It cannot verify a signature, and says so on every path.**
`SIGNATURE_VERIFICATION_IMPLEMENTED = False` is a module constant and a test
asserts it is still `False`, so implementing real crypto later fails the suite
loudly instead of the caveat being quietly dropped. `mayhem pack validate`
prints `signature NOT VERIFIED (pack claims signer 'acme')`, and every pack
fault's `refusal_reason` names the signer as a *claim*. There is no
`--insecure` flag — there is nothing to skip.

Assurance is a two-axis split that cannot collapse into one boolean:
`digest_verified` (integrity, real) and `signature_verified` (provenance,
honestly `False` in this build).

### Also closed

- A pack redeclaring or **shadowing** a built-in fault id or provider id is refused.
- **Path traversal** in a pack-supplied target or homepage is refused. The
  pre-existing guard only blocked targets *starting* with `/`, so
  `../../etc/passwd` and `~/root/.ssh` sailed through. That was a live hole.
- A pack declaring faults it does not define, or defining ones it does not
  declare, is refused.
- 20+ refusal paths, each with a message that says what to do.

### Known limit, reported not hidden

A loaded pack fault is an ordinary `FaultDefinition` with `catalog_only=True`
and a populated refusal reason, run through the same `validate_catalog()` that
gates built-ins. It is **not** in `definition_for()`'s static `_BY_ID` (that
would require editing `domain/catalog.py`, outside the lane), so a pack fault
is loadable and inspectable but not yet resolvable by the planner.

### Breaking change

`mayhem p` no longer resolves. `pack` made the prefix ambiguous with
`prepare`; the resolver refuses to guess, which is the safer behaviour, so
`mayhem p` now exits `ambiguous_command` and names both. Use `mayhem pre` or
spell it out. Recorded in the changelog and locked by a test.
