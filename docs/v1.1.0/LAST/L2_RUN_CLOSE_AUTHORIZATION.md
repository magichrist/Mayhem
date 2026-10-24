# L2 — carry the policy decision and approval state to the run close

## What is open

`docs/v1.1.0/12_CRYPTOGRAPHIC_EVIDENCE.md` Phase 6 records two gaps. Both are
real and both are confirmed by grep:

**Gap 1 — run-close sealing is unwired.** Plan 12 §Phase 4 names the exact call
site: `src/mayhem/cli/lifecycle.py`, in `_write_evidence_after_run`, immediately
after `write_evidence(store, envelope)` and before `write_evidence_file`.

The seal exists. `seal_run_evidence_at_run_close` is at
`src/mayhem/infra/audit_stream.py:736`. `seal_policy_decision` — which builds the
`RunAuthorization` and calls it — is at
`src/mayhem/controller/policy_evidence.py:404`. It is called from
`policy_evidence.py:447` (itself), and `seal_approval_decision` calls it from
`approval_evidence.py:513`. **`src/mayhem/cli/` contains no reference to either
module.** The run-close path never seals.

Consequence, stated by the plan and true today: *passing no `authorization` seals a
complete-looking but INCOMPLETE chain for every mutating run.* `chain_completeness`
reports this correctly; the chain is wrong.

**Gap 2 — the authorization's inputs are computed then discarded.**
`controller/safety.py:999` builds `policy_result` via `evaluate_gate`, hands it to
`_apply_policy_result`, reads `result.required_approvals`, and drops it. Lines
1010–1013 do the same with `verify_approvals(...)` through `_apply_approval_result`.
Both objects leave `validate_plan` as local variables. Nothing downstream carries
them to the close.

So the seal cannot be wired without a carrier, and the carrier does not exist.
Both halves are in this plan.

---

## Phase 1 — the carrier

Two dataclass fields. Additive, `None`-defaulted, no behaviour change.

### 1a. `src/mayhem/controller/safety.py` — `SafetyContext`

`SafetyContext` is a `@dataclass` at line 89. **`policy_gate` must remain the last
field**: `tests/unit/test_policy_gate.py` asserts exactly that, and the existing
comments at lines 113–116 and 127–131 record the constraint deliberately. New
fields therefore go **immediately before** `policy_gate`.

```python
    # L2: the gate verdicts themselves, carried so a later caller can bind a
    # decision to evidence rather than re-running the gate and hoping the inputs
    # still agree. ``None`` — the default — means this context never ran the
    # gate, and every path below is behind the existing ``is not None`` test, so
    # admission is byte-for-byte what it was before these fields existed.
    #
    # These are *results*, not decisions: a run that is refused never reaches
    # anywhere that reads them, because ``validate_plan`` raises. What survives is
    # an allowed run, and only an allowed run has an authorization to seal.
    policy_gate_result: PolicyGateResult | None = None
    approval_state: ApprovalState | None = None
```

Add the imports. `PolicyGateResult` is already imported in this module (it is the
annotation on `_apply_policy_result` at line 1045). `ApprovalState` is not —
add it to the `mayhem.domain.approval` import at the top, **alphabetically**, and
expect the file's import sorter to complain if it is not.

### 1b. Record them where they are produced

`_apply_policy_result` (line 1045) and `_apply_approval_result` (line 1095) each
already receive the result. Set the field as the **first** statement, before any
recording loop, so the value is on the context even if a later statement raises:

```python
def _apply_policy_result(result: PolicyGateResult, ctx: SafetyContext) -> None:
    """…existing docstring unchanged…

    L2: the result is now retained on ``ctx`` so the run-close path can bind it
    to evidence. Recording is unchanged — a decision nobody reads at run close is
    still a decision worth recording here.
    """
    ctx.policy_gate_result = result
    for approval in result.required_approvals:
        …
```

and the same one line at the top of `_apply_approval_result` (line 1092). Its
argument is an `ApprovalGateResult`, and the `ApprovalState` is `result.state`
— a field on the frozen dataclass at `controller/approval_gate.py:271`:

```python
    ctx.approval_state = result.state
```

**Two things that fall out of reading `ApprovalGateResult` first.** Its fields
include `plan_digest` (line 274), `proof_digest` (line 276) and `policy_digest`
(line 275). So:

* the approval gate already knows the plan digest it was decided against. Phase 2
  should read `plan_digest` from `result.state`'s sibling fields rather than from
  `envelope.plan_hash` — or, better, keep reading `envelope.plan_hash` as Phase 2
  says and add a Phase 3 test that the two **agree**, so a disagreement between
  "the plan the approval was decided against" and "the plan the evidence
  describes" is caught rather than papered over. That test is worth more than
  either source alone;
* `proof_digest` is available here too, which narrows Phase 2's `proof_digest`
  gap — see 2b.

### 1c. `src/mayhem/domain/preflight.py` — `Preflight`

`Preflight` is `@dataclass(frozen=True, slots=True)` at line 35. Add two
`None`-defaulted fields after `runtime_context` (line 64):

```python
    # L2: the admission verdicts, carried to the run close so plan 12's sealer
    # has a real ``PolicyGateResult`` and ``ApprovalState`` to bind rather than
    # none. ``None`` — the default — is the case for every deployment that
    # configures no policy gate, and it seals nothing.
    #
    # Deliberately *absent* from ``to_dict``: that dict is the CLI's ``--json``
    # rendering, and a ``PolicyGateResult`` carries lock verdicts, pending budget
    # charges and compatibility outcomes — far more than a render needs and some
    # of it belongs in the sealed chain rather than in a stdout projection. The
    # run-close path reads the attribute, not the dict, which is the same
    # ``getattr`` idiom ``cli/lifecycle.py`` already uses throughout
    # ``_write_evidence_after_run``. Leaving ``to_dict`` alone is what keeps this
    # change from moving a single byte of existing JSON output.
    policy_gate_result: PolicyGateResult | None = None
    approval_state: ApprovalState | None = None
```

Add `PolicyGateResult` and `ApprovalState` under the existing `if TYPE_CHECKING:`
block so the frozen-slots dataclass annotation stays a string at runtime.

### 1d. `src/mayhem/controller/preflight.py` — the single construction site

There is exactly one `Preflight(` construction in the tree, at line 449. Inside
`build_preflight`, `validate_plan(plan, graph, safety)` is called at line 343, so
by the time control reaches line 449 a configured `safety` context is already
carrying both verdicts.

Add two keyword arguments at the construction, reading the same `safety` local:

```python
policy_gate_result = (getattr(safety, "policy_gate_result", None),)
approval_state = (getattr(safety, "approval_state", None),)
```

`getattr` rather than direct attribute access is deliberate: `safety` is typed
`SafetyContext | None` and is `None` on the paths that never ran a gate. A direct
access would raise on exactly the path this must leave alone.

### Golden guard, before anything else

Add to `tests/unit/test_preflight.py`:

```python
def test_a_preflight_with_no_gate_carries_no_verdicts_and_dumps_identically():
    """The L2 fields are additive all the way down: absent means absent, and the
    `--json` rendering does not move."""
    from mayhem.domain.preflight import Preflight

    before = {f for f in Preflight.__dataclass_fields__}
    pf = Preflight(
        resolved_target="t",
        config_snapshot_id="c",
        topology_snapshot_id="g",
        environment_fingerprint="f",
        plan=object(),
        safety_decisions=("d",),
    )
    assert pf.policy_gate_result is None
    assert pf.approval_state is None
    dumped = pf.to_dict()
    assert "policy_gate_result" not in dumped
    assert "approval_state" not in dumped
    # Every key that existed before L2 is still there.
    for key in ("plan_hash", "plan_id", "safety_decisions", "blast_radius"):
        assert key in dumped
    assert len(dumped) == len(before) - 2
```

Run this **before** the edit to confirm the `len` arithmetic, then again after.

### Acceptance

* `uv run pytest -n 3 tests/unit/test_policy_gate.py tests/unit/test_preflight.py`
  green — in particular the `policy_gate`-is-last assertion.
* A run with no policy gate produces a byte-identical `Preflight.to_dict()` and
  an identical evidence envelope.

---

## Phase 2 — the wiring

### 2a. `src/mayhem/cli/lifecycle.py`

Three edits, all inside `_write_evidence_after_run`.

**Add the parameter.** Beside `secret_development_marker`, which is the same
shape of seam:

```python
secret_development_marker: Mapping[str, Any] | None = (None,)
proof_digest: str = ("",)
```

**Seal, immediately after `write_evidence` and before `write_evidence_file`.**
`write_evidence(store, envelope)` is at line 1116 today; insert between line 1126
(the end of its `except`) and line 1127 (`if evidence_dir:`).

```python
# L2: bind the policy decision and the approval state to this run's
# evidence chain, so a mutating run stops sealing an INCOMPLETE chain.
#
# Placement is load-bearing and is plan 12's: the envelope row must exist
# before the chain references its digest, and the artifact must be written
# from the envelope as it was admitted. Both `PolicyGateResult` and
# `ApprovalState` ride in on `preflight`, carried by the admission pass
# that produced them — the gate is never re-run here, so the decision
# sealed is the decision that was enforced.
#
# `plan_digest` is read off the envelope rather than off `preflight` on
# purpose: ``RunAuthorization`` compares it against the envelope's own
# ``plan_hash`` at seal time, so taking it from the envelope is what makes
# a disagreement impossible rather than merely unlikely.
#
# Three outcomes, and all three are non-raising, matching the sibling
# secret-marker seal 40 lines above: no gate configured seals nothing;
# a configured gate that denies has already refused the run before this
# function is reached; a configured gate that allows seals. A seal failure
# degrades to a remediation note, because losing the whole envelope
# because an *additional* record failed is the wrong trade — the
# chain_completeness check still reports the truth.
try:
    from mayhem.controller.policy_evidence import seal_policy_decision

    _policy_result = getattr(preflight, "policy_gate_result", None)
    _approval_state = getattr(preflight, "approval_state", None)
    if _policy_result is not None and _approval_state is not None:
        seal_policy_decision(
            store,
            _policy_result,
            envelope,
            approval_state=_approval_state,
            plan_digest=envelope.plan_hash,
            run_status=str(getattr(result, "status", "") or ""),
            verdict=verdict,
            proof_digest=proof_digest,
        )
except Exception as exc:
    envelope = envelope.model_copy(
        update={
            "remediation": (
                *envelope.remediation,
                f"policy authorization not sealed into the evidence chain: {type(exc).__name__}",
            ),
        }
    )
```

Three details that are not stylistic:

* **Both** must be present. `build_authorization` requires a `PolicyGateResult`
  *and* an `ApprovalState`; a policy gate with no approval gate leaves the second
  `None`, and there is nothing to authorize against. That case seals nothing, which
  is the honest state, and Phase 3 records it as a remaining gap rather than
  inventing a default `ApprovalState`.
* **`verdict` is the local** already computed at line 961 and threaded through the
  function. Do not re-derive it.
* **`envelope.plan_hash`, not `preflight.plan_hash`.** See the comment.

### 2b. `proof_digest` — a better source than the parameter suggests

`ApprovalGateResult` already carries `proof_digest` (`approval_gate.py:276`),
carried from the approval gate's own evaluation. So Phase 1's third field is
worth adding, and it is nearly free:

```python
    approval_result: ApprovalGateResult | None = None
```

set alongside `ctx.approval_state = result.state`, and carried on `Preflight` the
same way. Then here:

```python
proof_digest = (str(getattr(_approval_result, "proof_digest", "") or ""),)
```

falling back to the `proof_digest=""` parameter for a caller that has a state but
no result.

**Why the extra field is worth it.** Without it, a run whose safety proof was
VOID — the refusal plan 30 exists to make visible — seals its run-close chain
with an empty proof digest, and nothing in that chain distinguishes it from a run
that never needed a proof. With it, `build_authorization` receives the digest the
approval gate actually decided against, and "no proof was required" stays
distinguishable from "a proof was required and it was not a PASS".

Its default remains `""`, which is honest for a deployment with no approval gate.

If `ApprovalGateResult.proof_digest` turns out to be empty on every real path,
drop this sub-item and keep the parameter — **do not synthesise a digest.** Record
the outcome either way in the Phase 3 ledger.

### 2c. What is deliberately not changed

* `controller/executor.py` is not touched. Plan 12 established that the executor
  never builds an `EvidenceEnvelope`, so sealing there would require a second
  envelope producer — the duplication the plan exists to remove.
* No second sealer is added. This calls plan 12's one.
* The `try/except` shape is copied from the secret-marker seal, not invented.

### Acceptance

* `uv run pytest -n 3 tests/unit/test_evidence_boundary.py` green — deleting the
  new call fails it statically once registered (see 2d).
* A run with a configured, allowing policy gate produces a chain whose
  `chain_completeness` is `COMPLETE`, not `INCOMPLETE`.
* A run with no policy gate is byte-identical to one from before this change.

### 2d. Register the call site

`tests/unit/test_evidence_boundary.py` maintains `BOUNDARY_CALL_SITES` as
`(module, function)` pairs, asserted in **both** directions — an unregistered
gate-calling function fails, and so does a row that no longer describes one.
`seal_policy_decision` builds and persists an authorization, which is evidence, so
it belongs in the table:

```python
(("mayhem.controller.policy_evidence", "seal_policy_decision"),)
```

Confirm the exact tuple form the existing rows use before adding — read the file,
do not assume this shape. `seal_approval_decision` may also need a row; if it is
absent today, that is a pre-existing gap this plan should close rather than
leave, and Phase 3 records it either way.

---

## Phase 3 — the proof

### 3a. `tests/unit/test_run_close_authorization.py` — new

At minimum:

| Test | What it pins |
| ---- | ------------ |
| `test_a_run_with_no_policy_gate_seals_nothing` | default path unchanged; chain stays INCOMPLETE and says why |
| `test_an_allowed_gate_seals_a_complete_chain` | the whole point — the chain completeness flips |
| `test_the_sealed_decision_is_the_one_that_was_enforced` | the gate ran once; the sealed `PolicyGateResult` is the same object `validate_plan` produced, not a re-run |
| `test_a_plan_digest_mismatch_is_refused` | `plan_digest` read off the envelope; a preflight/plan disagreement cannot slip through |
| `test_the_envelope_digest_and_the_approval_gate_digest_agree` | the two independent sources of the plan digest — `envelope.plan_hash` and `ApprovalGateResult.plan_digest` — name the same plan. This is the test that makes Phase 2's choice of source safe rather than merely convenient |
| `test_a_seal_failure_degrades_to_a_note_and_keeps_the_envelope` | the `except` path: envelope survives, `evidence_status` untouched, note present |
| `test_a_denied_policy_never_reaches_the_close` | a refusal is evidence but not an authorization; `build_authorization` refuses it |
| `test_a_policy_gate_with_no_approval_gate_seals_nothing` | the both-must-be-present rule |

### 3b. Negative controls

Three, and the third is the one that matters:

1. **Break a collaborator, not `src/`.** Wrap the real `seal_policy_decision` in a
   collaborator that returns a `SealedRun` with an empty chain and assert the
   completeness check still reports `INCOMPLETE`. This shows the property is the
   check's, not the caller's.
2. **Make `build_authorization`'s own refusals load-bearing.** Plant a result whose
   `plan_digest` disagrees with the envelope and assert the typed
   `PolicyAuthorizationRefusedError` propagates into the note — proving the refusal
   is reached in the real path and not merely present in the module.
3. **Prove the seal cannot be skipped silently.** Delete the `seal_policy_decision`
   call from `lifecycle.py` and assert (a) a completeness assertion fails and (b)
   `test_evidence_boundary.py`'s `BOUNDARY_CALL_SITES` check fails naming the
   function. If only (a) fires, the static guard is not actually registered and
   Phase 2's 2d is incomplete.

### 3c. `tests/unit/test_last_l2_plan_docs.py` — the honesty gate over this file

Same shape as `test_proof_plan_docs.py`:

* `- Phase 1 (the carrier): DONE — `SafetyContext.gate_verdicts` plus the two
  typed accessors, `Preflight.policy_verdict` / `approval_verdict`, the two
  retention lines, the single `Preflight(...)` construction site, and the golden
  `to_dict` guard.
- Phase 2 (the wiring): DONE — one call site in `_write_evidence_after_run`,
  `proof_digest` threaded from the approval result, and the delegation assertion
  that replaced the `BOUNDARY_CALL_SITES` row the checker refused.
- Phase 3 (the proof): DONE — `tests/unit/test_run_close_authorization.py` (16,
  no skips) and `tests/unit/test_last_l2_plan_docs.py` (14).

Overall: 3 of 3 phases complete (Phases 1, 2, and 3).` equals the `DONE` count here.
* The `file:line` citations above resolve — `audit_stream.py:736`,
  `policy_evidence.py:404` and `:257`, `safety.py:999` and `:1045`, `preflight.py:343`,
  `lifecycle.py:1116` all still say what this document claims.
* This document does not claim the chain is COMPLETE today. It does not.
* This document states that a deployment with **no** policy gate configured still
  seals nothing, so L2 does not make the default path better — it makes the
  configured path honest. Overstating this is the most likely rot.
* `build_authorization`'s four refusal reasons are quoted against the source, and
  every invented code fails.

### 3d. Recorded gaps, not hidden ones

Write these into this document's ledger when Phase 2 lands:

* **A policy gate configured without an approval gate still seals nothing.** Both
  inputs are required. Closing it means deciding what an unconfigured approval
  gate authorizes — a policy question, not a plumbing one.
* **`proof_digest` comes from the approval gate, not from plan 30's seal.** If
  Phase 2b lands it is populated; if `ApprovalGateResult.proof_digest` is empty on
  every real path it is not, and it stays empty rather than being synthesised. A
  run-close chain with no proof digest does not claim a proof was verified.
* **`seal_run_evidence_at_run_close` is not fail-closed at this call site.** A seal
  failure degrades to a note by design, matching its sibling. `chain_completeness`
  is what reports the truth, and nothing blocks a release on it yet — that is L3's
  job.

### Rollout

Phase 1 is inert and safe to land alone. Phase 2 changes what a run writes, so it
lands with Phase 3a in the same commit. Nothing is behind a flag: the behaviour is
gated by whether a policy gate is configured at all, which is already the
deployment's decision.

### What this does not claim

It does not make evidence *verifiable to a third party*. Plan 30 is explicit that
`SIGNATURE_VERIFICATION_IMPLEMENTED` is `False`, so a seal demonstrates integrity
and never authorship. It does not implement KMS/HSM custody or Sigstore. And it
changes nothing for a deployment that has configured no policy gate — which is
every deployment in this repository today.

---

## STATUS — 3 of 3 phases complete

- Phase 1: DONE — `SafetyContext.gate_verdicts`, `Preflight.policy_verdict` and
  `Preflight.approval_verdict`, the two retention lines in
  `_apply_policy_result` / `_apply_approval_result`, the two accessors, and the
  golden `to_dict` guard in `test_preflight.py`.
- Phase 2: DONE — the seal call in `_write_evidence_after_run`, placed after
  `write_evidence` and before `write_evidence_file`; `proof_digest` threaded from
  the approval result; the delegation assertion in `test_evidence_boundary.py`.
- Phase 3: DONE — `tests/unit/test_run_close_authorization.py` (16 tests) and
  `tests/unit/test_last_l2_plan_docs.py` (14 tests). No skips.

No new dependency, no new migration, and `controller/executor.py` is untouched —
plan 12's reasoning for that stands and this plan did not revisit it.

**The state this changed.** A mutating run with a configured, allowing policy
gate and an approval gate now seals a COMPLETE chain where it previously sealed an
INCOMPLETE one. That is the entire claim, and it holds only for a deployment that
configures both gates — which is no deployment in this repository. **For every
other run the envelope is byte-identical to one from before this wiring**, asserted
by comparing two closes of the same run with the carrier absent and present-but-
`None`.

## Deviations, recorded rather than hidden

**1. `SafetyContext` is frozen, so the two optional fields could not work.**
Phase 1 as written added `policy_gate_result` and `approval_result` as
`None`-defaulted fields. `SafetyContext` is `@dataclass(frozen=True)`
(`controller/safety.py:88`), so `ctx.field = result` raises `FrozenInstanceError` —
31 tests failed on the first run. Unfreezing it would change the hashability and
the construction contract every caller relies on, so the shipped shape is **one
mutable mapping**, `gate_verdicts`, read through two typed accessors
(`policy_verdict`, `approval_verdict`). That is the idiom the class already uses:
`record()` appends to `decisions` and `warnings` on a frozen dataclass.

The accessors are `isinstance`-checked, so a misspelled key is a miss rather than
a wrong-shaped object reaching the sealer — pinned by
`test_the_accessors_ignore_a_misspelled_key_rather_than_returning_it`.

**2. The carrier holds the `ApprovalGateResult`, not the `ApprovalState`.** Phase
1b originally planned to store `result.state`. Reading `ApprovalGateResult` first
(`controller/approval_gate.py:263`) showed it already carries `plan_digest`,
`policy_digest` and `proof_digest` — so the whole result is stored and
`proof_digest` is threaded from it (2b). The first version of the test passed a
bare `ApprovalState` and the run close degraded with `AttributeError:
'ApprovalState' object has no attribute 'state'`; that is the degradation working,
and it is why the call site was left strict rather than taught to accept either
shape.

**3. `PolicyGateResult` carries no `plan_digest`, so the plan's
"two independent digests must agree" test could not exist as written.** Phase 1b
proposed comparing the envelope's `plan_hash` against the approval gate's
`plan_digest`. The comparison that actually exists is `RunAuthorization`'s, of
`plan_digest` against `envelope.plan_hash` at seal time. What is shipped is
`test_a_plan_digest_the_envelope_does_not_carry_is_refused`, which plants a
mismatched digest and asserts `AuthorizationMismatchError` — the negative control
the original test was reaching for.

**4. `BOUNDARY_CALL_SITES` gained no row, and the two-directional check refused
the one that was tried.** A row for `seal_run_evidence_at_run_close` was added and
the conformance check refused it: *"a row that no longer describes a gate-calling
function"*. That function has no gate call of its own — it delegates to
`seal_run_evidence`, which is in the table. The row was deleted and the property
is now asserted positively by
`test_the_run_close_seam_reaches_the_gated_sealer_by_delegation`, which reads the
delegation out of the source. "It is gated somewhere underneath" is not something
a caller can check by reading the table, so asserting it from the table would have
been a claim rather than a check.

## Recorded gaps, unchanged

- **A policy gate configured without an approval gate still seals nothing.** Both
  inputs are required. Closing it means deciding what an unconfigured approval
  gate authorizes — a policy question, not a plumbing one.
- **`proof_digest` is populated only when an approval gate ran.** A run with no
  approval gate seals with an empty proof digest, which claims no proof was
  verified. That is honest, not a fallback.
- **The seal is not fail-closed at this call site.** A failure degrades to a note,
  matching its sibling. `chain_completeness` is what reports the truth, and
  nothing blocks a release on it yet — that is L3's job.

## What this does not claim

It does not make evidence verifiable to a third party.
`SIGNATURE_VERIFICATION_IMPLEMENTED` is `False`, so a seal demonstrates integrity
and never authorship. It does not implement KMS/HSM custody or Sigstore. And it
changes nothing for a deployment that has configured no policy gate — which is
every deployment in this repository today.