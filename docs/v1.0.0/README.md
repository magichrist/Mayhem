# v1.0.0 — release plans

Originally planning only. **Implementation has since begun** — see
[Implementation status](#implementation-status) below. **Nothing is committed.**

Research date **2026-09-28**.

## The one-line thesis

> **Stop adding fault ids and start making the verdict mean something.**

The market analysis found that the two CNCF projects and AWS FIS all reduce a
chaos experiment to a boolean — probe passed, probe failed, alarm state. Not one
of them can express *"latency rose 18%, inside the 20% band"*, because none of
them has a tolerance field in any CRD. mayhem has a verification probe on every
single fault, a write-ahead undo contract, and a hash-chained evidence bundle,
and does not yet compare any of it against a baseline.

That is the gap 1.0.0 should close.

## Read in this order

| | Document | What it decides |
| --- | --- | --- |
| 00 | [market landscape](00-market-landscape.md) | what Chaos Mesh, Litmus and AWS FIS actually do, sourced — and **which research failed** |
| 01 | [positioning](01-positioning.md) | where mayhem wins, where it loses honestly, what is in and out of scope |
| 02 | [earn maturity](02-earn-maturity.md) | the live-verification harness — 128 executable faults, **0** `verified-live` |
| 03 | [steady state](03-steady-state-hypothesis.md) | **the 1.0 feature** — baseline, tolerance bands, before/during/after, a graded verdict |
| 04 | [dry run and quota](04-dry-run-and-quota.md) | the preview that is the real gate, plus a cumulative damage quota |
| 05 | [fault packs](05-fault-packs.md) | a fault-pack format with a `signature` field and no key behind it — integrity now enforced, signatures honestly reported as unverified |
| 06 | [debt and quality](06-debt-and-quality.md) | 62 lint errors, an unenforced config field, a shell-injection surface, an undo contract that isn't kept |
| 07 | [release gates](07-release-gates.md) | the binary checklist, the non-goals, and what must be re-researched |

## The three things

1. **Earn the maturity claim.** `VERIFIED_LIVE` and `STABLE` exist in the enum
   and in `MATURITY_PROMOTION_CRITERIA`, and **nothing has ever been promoted
   to either**. `VERIFIED_UNIT` is currently a constant applied to all 128
   executable faults, so it carries no information. A 1.0 that cannot demonstrate
   its catalogue works against a live runtime is making a claim it has not
   earned.

2. **Make the verdict mean something.** Baseline capture, per-metric tolerance
   bands, and explicit `assert_unchanged` / `assert_degraded` / `assert_recovered`
   phases. Two new verdicts matter most: **`no-effect`** (the fault did nothing —
   a real and under-reported failure mode neither competitor can detect) and
   **`not-recovered`** (residue after undo).

3. **Make it safe to press the button.** The preflight `blast_radius` line is a
   *looser re-derivation* than the gate that actually refuses — it omits
   `dependents_closure` and never surfaces `max_concurrent_faults`, the limit
   that refused the example drill. Fix that, then show the operator the actual
   argv per target before they approve.

## Findings that were not in the brief

Three things worth flagging because they change what 1.0 should be:

- **mayhem had a fault-pack format with a `signature` field, no loader, and no key material behind that field.**
  `providers/pack.py` defines `FaultPack` with a `signature`, a `declared_digest`
  and a `development_only` flag, and `test_fault_pack_validation.py` validates
  it — but nothing outside that module references it. No CLI, no planner
  integration. It is the only *signed* extensibility design in the four-tool
  comparison, and it is currently unreachable. → plan 5
- **`ToolExecutor.undo` does not honour the contract its own module docstring
  states.** "Undo must be idempotent and must never raise" — two executors
  comply, this one doesn't. → plan 6
- **The version is tag-derived, not a `pyproject.toml` key.** The release
  checklist I first drafted said to bump `version`; there is no such key.
  `hatch-vcs` derives it from the tag, the convention is a **bare** `1.0.0` with
  no `v` prefix even though the branch is `v1.0.0`, and the only thing that
  needs editing is `fallback-version`, still `0.9.0.dev0`. → plan 7

## Honest limits of this research

**Gremlin, Steadybit, Harness and Azure Chaos Studio were not retrieved.** Search
returned marketing copy with no page content and 5 of 7 search engines were
erroring; the Azure documentation URLs 404'd. Three of the four strongest
commercial products in this category are therefore unexamined, and two of them
compete for the same buyer.

The competitive analysis rests on Chaos Mesh, Litmus and AWS FIS, which were read
from CRD schemas, the fault trees, and the live AWS actions reference. Those
claims are cited to file paths and URLs. Re-running the missing research is a
release gate in [07](07-release-gates.md) — **do not ship a positioning claim
that rests on research that did not complete.**

## Constraints observed

- Only files under `docs/v1.0.0/` were created or modified.
- No source, test, or configuration file was touched.
- Nothing was committed. Branch is `v1.0.0`; working tree state is unchanged
  apart from this directory.

---

## Implementation status

**Everything below is uncommitted.** `ruff check src/`: **62 → 1**. Suite:
**15565 passed, 4 skipped, 11 xfailed, 0 failed**. 41 files changed
(+907/-430) plus 5 new test files.

### Shipped

| Item | Plan | Result |
| --- | --- | --- |
| `ToolExecutor.undo` honours its documented never-raise contract | [05](06-debt-and-quality.md) §5 | matches the pattern of the two compliant executors; lease degrades to DIRTY instead of crashing |
| Shell-injection guards | [05](06-debt-and-quality.md) §4 | **6 sites, not the 1 reported** — 2 quoted, 4 validated-and-refused; wire behaviour unchanged |
| Preflight = the real blast-radius gate | [04](04-dry-run-and-quota.md) | drift closed: preflight said 33.3% where the gate said 100.0%; all 5 limits now render |
| `config.max_faults` deprecated loudly | [05](06-debt-and-quality.md) §3 | warns on **key presence**, so the default `1` is not silently exempt |
| 62 lint errors | [05](06-debt-and-quality.md) §1 | 62 → 1, zero unjustified `noqa`, differential-tested for observational equivalence |
| import-linter runnable | [05](06-debt-and-quality.md) §2 | the documented `python3 -m lint_imports` invocation **can never work**; correct form recorded |
| v1 version bump | [07](07-release-gates.md) | `fallback-version` + `PROVIDER_VERSION` + `RELEASE_LINE` moved in lockstep |

### Found during implementation — not in the original plans

| | Finding | Severity |
| --- | --- | --- |
| [`06` §7a](06-debt-and-quality.md) | `forbidden_fault_pairs` is **silently inert** for plans > 2 faults — `safety.py:231` builds a `frozenset` of all faults so far, not the pair | **HIGH** |
| [`06` §7b](06-debt-and-quality.md) | `docs/reference/cli.md` does not exist and its parity test is **dead code** inside an uncalled generator, referencing undefined names. Red at HEAD; nothing runs ruff on `tests/` | MED |
| [`06` §7c](06-debt-and-quality.md) | `ToolExecutor.inject` has the same unguarded `run_tool` as the undo defect it just fixed | MED |
| [`06` §2](06-debt-and-quality.md) | **2 of 3 import-linter contracts are BROKEN** — 7 violations across 6 sites (`domain` → `toolkit`/`pathlib`/`subprocess`; `infra` → `agents`/`controller`) | MED |
| [`06` §3](06-debt-and-quality.md) | `README.md:378` still claims `max_faults` caps concurrent faults; `cli/init.py` scaffolds it into every new project | MED |

### Final state — all plans implemented

| Plan | State |
| --- | --- |
| [02 earn maturity](02-earn-maturity.md) | **DONE as a harness. 0 promoted, by design** — `evaluate_maturity` cannot yield `VERIFIED_LIVE` without recorded evidence from a real run |
| [03 steady state](03-steady-state-hypothesis.md) | **DONE, all six steps.** The headline feature. 201 tests |
| [04 dry run and quota](04-dry-run-and-quota.md) | **DONE.** A1 preview-is-the-gate + Part B cumulative damage quota |
| [05 fault packs](05-fault-packs.md) | **DONE as integrity-checked.** SHA-256 enforced; signatures honestly `NOT VERIFIED` |
| [06 debt and quality](06-debt-and-quality.md) | **DONE**, plus §6's audit in [08](08-withdrawal-audit.md) and six findings found during implementation |
| [07 release gates](07-release-gates.md) | **19 ticked, 11 open** — every Quality, Safety and Honesty gate closed |

**Gates, all green:**

| | |
| --- | --- |
| `ruff check src/` | **0** (was 62) |
| `mypy --strict src` | **1** (was 284 — never run) |
| `import-linter` | **3 kept, 0 broken** (was 1 kept, 2 broken) |
| full suite incl. `e2e` | **15968 passed, 0 failed** |

### What is still genuinely undone

Three things, named rather than ticked:

1. **0 of 141 faults are `verified-live`.** The harness exists and refuses to
   promote without real recorded evidence from a live run. Promoting requires
   running drills against real systems — no amount of code substitutes.
2. **The `STABLE` tier is unreachable.** Its criteria require a documented
   deprecation path, and 140 of 141 entries have `deprecation_path = None`. A
   policy decision, not an implementation gap.
3. **Catalogue-digest attestation** was cut. No 1.0 claim depended on it.

### The four defects implementation found

Not in any plan; all found by doing the work.

| | Defect | Severity |
| --- | --- | --- |
| `06` §7d | `mayhem bundle` advertised "**Build** and verify" with no `build`; the README recipe produced a file the verifier rejected. The headline differentiator had no producer | **HIGH** |
| `06` §7e | `executor.py` skipped the admission guard for a node target and reported `ok=True, status='ok'` — a **fail-open** on a pod fault | **HIGH** |
| `06` §7a | `forbidden_fault_pairs` was **silently inert** for plans of 3+ faults (compared a `frozenset` of all faults so far against pairs). Now load-bearing — and plans that ran in 0.9.x will be refused | **HIGH** |
| `03` | `within_relative` was **sign-blind**: `+100 → -100` graded `recovered / as-hypothesised` while `delta_pct` correctly said −200% | **HIGH** |

Plus: the steady-state evaluator was **fully built and never ran** (the spec
lookup returned `None` on every real run), and `mypy` surfaced 9 unreachable
lines in `compensation.py` duplicating the live undo function.

### How to read the honesty claims

`README.md` and `CHANGELOG.md` now carry the things a 1.0 usually hides: no
kernel/BPF injection, 0 `verified-live`, the real `catalog_only` count (13, not
the 9 previously stated), and five breaking changes. Fault packs are described
as integrity-checked, never signed. The `bundle` verifier reports
`unsigned: integrity is verified, authorship is not`.

### Known and deliberately unowned

Every remaining debt is named and sized in
[`06` §Sequencing](06-debt-and-quality.md). The two that gate plan 2's
promotion criteria: **lint is not enforced** (no workflow runs it) and **the
architecture contracts are red**. A `verified-live` gate is not worth much while
static analysis and import boundaries are both unverified.
