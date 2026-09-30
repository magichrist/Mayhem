# Plan 1 — earn the maturity claim

**Problem:** 128 executable faults, **0** `verified-live`, **0** `stable`. The
maturity model defines three rungs above `verified-unit` and nothing climbs them.

**Why it is first:** a chaos tool's only currency is trust in its fault
catalogue. `verified-unit` means "the compensation contract and parameter
grammar are tested in isolation" — which is a real guarantee, but it is a
guarantee about *our code*, not about the fault *working*. Every other
competitor's catalogue has been run against live infrastructure by its users for
years. Ours has never been run by us, once, systematically.

## Current state

`MaturityLevel` (`domain/faults.py:130-134`): `EXPERIMENTAL` →
`VERIFIED_UNIT` → `VERIFIED_LIVE` → `STABLE`.

`_define()` (`catalog.py:193-195`) auto-promotes any non-`catalog_only` fault
straight to `VERIFIED_UNIT` and stamps `verification_date = 2026-09-24`. So
`VERIFIED_UNIT` currently carries **no information at all** — it is a constant
applied to everything. `MATURITY_PROMOTION_CRITERIA`
(`infra/catalog_report.py:20-41`) defines what the top two rungs require, but
nothing implements a promotion path.

Enforced today by `test_fault_catalog_exhaustive.py::TestMaturityMetadata`:
`(maturity is EXPERIMENTAL) == catalog_only` and
`verification_date is None` iff `EXPERIMENTAL`. So the invariant to preserve is
that **only** `catalog_only` may be `EXPERIMENTAL`.

## The proposal: a live-verification harness

A repeatable command that runs a selected fault set against a real stack and
records the outcome per fault id, promoting what passes.

### Shape

```
mayhem verify-live                      # run the standard matrix
mayhem verify-live --fault net.latency  # one fault
mayhem verify-live --engine podman --engine docker
mayhem verify-live --record             # write evidence, promote on pass
```

Default is **read-only**: it runs and reports. Promotion requires `--record`,
because it writes to the catalogue. That mirrors the existing intent contract
(`require_explicit_approval`) and the `mayhem dependency install` precedent —
`--execute` / `--yes`, never implicit.

### What it must do per fault

1. **Start the fixture stack** — the existing `examples/testCase` compose file
   is the natural default; add a dedicated chaos-oriented fixture that includes a
   service with known-steady latency, so latency-based faults have something
   measurable.
2. **Capture a baseline** — for each declared steady-state probe, N samples
   before injection. This is the data that `verified-live` is really asserting:
   that the fault perturbs a *known* signal, not merely that it runs.
3. **Inject** via the normal `plan_drill` → executor path. No special path. If
   the fault cannot be planned, it fails.
4. **Observe during** — sample the probes at the fault's duration.
5. **Undo and verify** — the existing `compensated()` contract plus
   `verify_probes`. A fault whose undo does not restore the baseline is a
   **failure**, not a partial pass.
6. **Assert residue** — the container must be observably clean afterwards. This
   is lifted verbatim from Litmus's GA criterion: *"leaves no chaos residue…
   regardless of success."* mayhem can check it precisely: the probe must return
   to within tolerance of the captured baseline after undo.
7. **Record** — a signed evidence bundle via the existing `mayhem bundle`
   machinery, keyed by fault id, engine, and mayhem version.

### Promotion rules

| Rung | Requires |
| --- | --- |
| `VERIFIED_LIVE` | passed on **both** Docker and Podman, with a recorded evidence bundle, and undo restored the baseline within tolerance |
| `STABLE` | `VERIFIED_LIVE` **and** every supported engine/platform combination verified **and** a documented deprecation + rollback policy |

The second row is deliberately copied from the existing
`MATURITY_PROMOTION_CRITERIA` text. The plan is to make that text executable,
not to replace it.

### Storage

Do **not** rewrite `CATALOG` in place. Add a `verified_live.json` (or a table)
recording `{fault_id, engines, evidence_bundle_hash, verified_at, mayhem_version}`
and derive the rung at import. Rationale: `CATALOG` is a hand-written tuple
validated at import time; a generated tier that rewrites source is a merge
hazard and makes `git blame` useless on the catalogue. Deriving at read time
keeps `definition_for()` a single source of truth while letting the tier be
evidence-backed.

### Sequencing

| Step | Deliverable | Risk |
| --- | --- | --- |
| 1 | `mayhem verify-live --dry-run` reporting only; no promotion | none |
| 2 | A steady-state fixture with measurable latency + error-rate signals | low |
| 3 | Evidence recording, no promotion | low |
| 4 | Derived `VERIFIED_LIVE` tier + `mayhem discover faults --live` | medium — will expose faults that do not work |
| 5 | `STABLE` tier | deferred to 1.1 |

**Step 4 is the one that will hurt, and that is the point.** Expect a
meaningful fraction of the 67 container-lane faults to fail live verification —
the payload faults in particular have never been executed against anything. The
honest outcome is a lower headline number and a catalogue that is finally true.
Ship that, not a number that isn't.

## Open questions

- Does live verification belong in CI, or only on a deliberate local run? CI
  would need a container-engine fixture on every runner; the answer is probably
  "a separate job, opt-in, non-blocking at first."
- Should a fault that is *unverifiable* (e.g. requires a specific image, or a
  rootless engine nuance) be demoted, or marked `verified-live (partial)`? A
  third state is probably needed; two states will produce pressure to lie.
- The 62 existing lint errors mean the advisory quality gate cannot currently
  be a promotion prerequisite. Fix that first, or the gate means nothing. →
  [06](06-debt-and-quality.md)

---

## STATUS — SHIPPED as a harness. **0 faults promoted, by design.**

`infra/promotion.py` (new) evaluates the criteria table against **recorded
evidence**, and `evaluate_maturity(definition, probe, store)` is the only
function that can produce a `MaturityLevel` from a decision. There is no
`set_maturity`, no `verified=True` flag, and no `record()` shortcut.

**No code path can set `VERIFIED_LIVE` without a real run.** A `LiveRunRecord`
is unrepresentable without an undo, tz-aware timestamps, a sha256 bundle, and
observations that would themselves be rejected if fabricated — an `injected`
observation with `passed=True` whose signal never moved raises
*"a fault that does not move the signal is not evidence that the fault works."*

**The honest outcome: 0 of 141 faults are `verified-live`.** Not a failure of
the harness — a missing verification *program*. A promotion is a claim about
real systems, so `mayhem run` on a real target, recorded, is what moves the
number. The catalog report now derives maturity, shows `live_evidence_records`,
and carries a `maturity_disclaimer` stating that `verified-unit` is "a claim
about mayhem's own parameter, refusal, and compensation code — not about the
fault working."

`MaturityLevel` is now documented per rung: what each claims and what it does
not. `FaultDefinition.maturity` is carried as the *declaration*; reports show
the derived level beside it, so a stale badge stays visible.
