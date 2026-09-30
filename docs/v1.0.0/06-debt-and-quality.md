> ## STATUS — items 1-4, 6, 7 SHIPPED (uncommitted)
>
> Implemented across 6 parallel lanes. `ruff check src/`: **62 -> 1**.
> Suite: **15565 passed, 4 skipped, 11 xfailed, 0 failed**. Nothing committed.
> See the per-item "SHIPPED" notes below and `README.md` for the full ledger.

# Plan 5 — debt and quality gates

A 1.0 that ships with a red quality gate is telling its users the gate is
advisory. Every item here was found while preparing this release; none is
speculative.

## 1. `ruff check src/` is red — 62 errors  →  **SHIPPED: 62 → 1**

```
$ python3 -m ruff check --output-format=concise src/   # before
Found 62 errors.
$ python3 -m ruff check --output-format=concise src/   # after
src/mayhem/config.py:358:5: PLR0915 Too many statements (63 > 50)
Found 1 error.
```

**DONE.** 41 files changed, +907/-430. Zero `# noqa` added in the second
sweep; 4 in the first, each justified in the lane report. Behaviour was proven
observationally equivalent by differential testing against verbatim pre-refactor
copies (2492 `scenarios` cases, 108 `pack` cases incl. refusal-message ordering,
21 `verify_bundle` cases, 156 pairwise import-order cycle checks) — not merely
by the suite passing.

**REMAINING: 1 error.** `config.py:358 PLR0915` is unowned and deliberately
left. Also note **`ruff check tests/` is not enforced anywhere** (CI is
deleted) and is red at HEAD — see finding 8.

**NOT DONE (deliberately): making lint blocking.** No CI workflow runs lint
(`conformance.yml` / `release.yml` neither do). This item fixed the debt; the
*enforcement* is a separate decision and is still open.

These have been consistently treated as non-blocking, and `ci.yml` — which is
where the `ruff-fatal` job lived — was deleted. The current workflow set is
`conformance.yml` and `release.yml`; **neither runs lint**.

This is the highest-leverage item in the document. A `verified-live` promotion
gate (plan 2) is meaningless if the repository's own static analysis does not
pass. Fix the 62, then make lint blocking, then let the promotion gate depend
on it.

Note the ordering consequence: **plan 2 depends on this.** Do not build a
promotion criterion on a gate that is already failing.

## 2. `import-linter` cannot be run locally  →  **SHIPPED (with a real finding)**

```
$ python3 -m lint_imports
/Users/.../bin/python3: No module named lint_imports
```

**DONE — and the diagnosis was wrong in the brief.** Three separate causes:

1. The dependency was **never missing**: `import-linter>=2.1` is in
   `[dependency-groups] dev` and pinned in `uv.lock`. The failure was that
   `python3` resolves to conda base, not the project `.venv` (which has it).
2. **The documented invocation can never work**, installed or not —
   import-linter ships no `__main__`. `python3 -m lint_imports` is wrong
   independent of install state. Only the `lint-imports` console script works.
   `pyproject.toml` now carries the correct invocation in a comment.
3. No test shelled out to import-linter, so it was never *collected* as a
   failure — a silent gap, not a red gate.

`tests/unit/test_import_contracts.py` now pins all of it: 9 tests, incl. a skip
path that names the missing package instead of failing false-red.

**THE ACTUAL FINDING — 2 of 3 contracts are BROKEN** (`.venv/bin/lint-imports`,
216 files / 1420 dependencies):

```
Contracts: 1 kept, 2 broken.
  BROKEN  Domain layer has zero IO and no upward imports
    mayhem.domain -> mayhem.toolkit, pathlib, subprocess   (3 sites)
  BROKEN  Layered architecture: domain <- infra/toolkit/agents <- controller
    mayhem.infra -> mayhem.agents, mayhem.controller      (2 sites)
  KEPT    Agents never import controller modules
```

7 distinct violations across 6 import sites. **Not fixed** — restructuring
imports is an architectural change, not a lint fix. Pinned in the test's
`KNOWN_BROKEN_CONTRACTS` so a *new* violation fails and a *fixed* one fails
asking for a baseline update: a green gate that still catches drift both ways.

`include_external_packages = true` is what makes the stdlib entries
(`pathlib`, `subprocess`) reachable and the contract bite at all — without it
that half passes silently.

`pyproject.toml` declares three architecture contracts:

1. Domain layer has zero IO and no upward imports
2. Layered architecture: `domain <- infra/toolkit/agents <- controller`
3. Agents never import controller modules

These are exactly the invariants that keep a 51k-line codebase comprehensible,
and **none of them can be verified on a developer machine.** They are presumably
checked in CI — but CI is what was just deleted.

First question to answer: is `lint-imports` in a dependency group that CI
installs and a dev machine does not? If so, add it to the default dev setup. If
it is only in an extras group, the contracts have been unenforced for some time
and 1.0 should either fix or delete them. An architecture contract that
nobody runs is a comment.

## 3. `config.max_faults` is declared and never read  →  **SHIPPED (deprecated)**

**Decision taken: the "Deprecate it" option.** Warned loudly at spec-parse
time; the field stays parseable; behaviour is unchanged. Making it real was
rejected because it would silently start *refusing* existing drills mid-release
— a breaking change wearing a bugfix costume.

`MaxFaultsNotEnforced(Warning)` in `domain/experiments.py` fires from a
`model_validator(mode="before")`, naming the field, the value, and the real
control:

> `config.max_faults=1 is deprecated and is NOT enforced: no scheduler,
> planner, or executor reads it, so it caps nothing. The enforced
> concurrent-fault budget is blast_radius.max_concurrent_faults (the safety
> gate in mayhem.controller.safety) — set it under `blast_radius:` and drop
> `max_faults` to silence this warning.`

**Keyed on key-presence, not value — and this is the whole point.** `max_faults`
*is* `1` by default, and `1` is exactly what `mayhem init` scaffolds and what
`README.md` / `examples/testCase` ship. Keying on "differs from default" would
have silenced the single case the deprecation exists to catch. Omitted → silent;
authored → loud, whatever the value.

A custom `Warning` subclass, not `DeprecationWarning`: Python hides the latter
outside `__main__`, and the person who needs to see this is the one running
`mayhem run`. The repo's one existing runtime deprecation
(`SpecFileUsedAsConfig`) uses the same idiom, so this matches.

**FOLLOW-UP NOT DONE (both are lies still on disk):**
- `README.md:378` still says *"Concurrency budget. `max_faults` caps
  simultaneously-injected faults"* — the single most misleading sentence in the
  repo, and now contradicted by code.
- `cli/init.py:64` scaffolds `max_faults: 1` into every new project, so
  `mayhem init` now produces a spec that warns on first run. Defensible as a
  migration nudge; it is a product decision, not a lint fix.

```yaml
config:
  max_faults: 1      # in examples/testCase/mayhem.yaml
```

`grep -rn "max_faults" src/` finds the field definition
(`domain/experiments.py:181`), three docstrings, and a CLI template. **Nothing
reads it.** The executable limit is
`blast_radius.max_concurrent_faults` (`domain/experiments.py:60`, default 3),
enforced at `safety.py:205-217` as a running prefix count of fault steps.

The documentation was corrected at 0.9.1 to describe the code. That was the
right call in the moment, but for 1.0 the question is whether the code or the
name is wrong.

Options:

- **Make it real.** Project `max_faults` onto the blast-radius budget the way
  `risk_ceiling` already is. Cheapest, and makes the field mean what it says.
  Risk: existing drills with `max_faults: 1` and many faults would start
  refusing. That is arguably correct — they are currently running wider than
  they declared.
- **Deprecate it.** Emit a warning, refuse a spec that sets it, remove it in
  2.0.
- **Leave it.** Not acceptable for 1.0: a documented field that does nothing is
  a lie in the schema.

Recommendation: **deprecate.** The name is wrong for what it would do —
`max_faults` reads as "how many faults in this drill", but the budget is about
concurrent blast width, and those are different questions. Renaming in place
would break every existing spec. Warn loudly, remove in 2.0.

## 4. `fs.read_only` interpolates `path` unquoted  →  **SHIPPED — 6 sites, not 1**

The reported defect was real, and **understated by 5x**. Every `_param` reaching
an `sh -c` body was audited by AST, not by eye:

| Site | Param | Treatment |
| --- | --- | --- |
| `_fs_read_only_undo` | `path` | `shlex.quote` |
| `_dns_nxdomain_undo` | `domain` | `shlex.quote` |
| `_process_crash_loop_undo` | `interval` | validate grammar |
| `_process_restart_delay_undo` | `delay` | validate grammar |
| `_dep_flap_undo` | `protocol` | validate charset |
| `_dep_block_undo` | `protocol` | validate charset |

**Quote vs validate is a real distinction, not a style preference.** `path` and
`domain` are genuinely one-shell-word values, so quoting preserves meaning. The
four numeric/closed-grammar params (`sleep` durations, IP protocol names) get
*validated and refused* — quoting them would turn a spec error into a command
that runs and quietly does the wrong thing. Follows the existing `_net_device`
and `_RATE_RE` discipline in the same file.

Confirmed **not** vulnerable, deliberately untouched: `fill_path` and
`conn_exhaust` pass values only via a quoted `{!r}` Python repr; `_file_revert_undo`'s
`target` is a registry literal; `net_load`'s `script_content` is *intentionally*
arbitrary user script; all `_iparam` ports are `int`-coerced.

Wire behaviour is unchanged: `shlex.quote("/")` returns `/`, so the exact-argv
assertions in `test_compensation.py` and the runtime matrix still pass.
`tests/unit/test_shell_quoting.py` includes a regression guard proving the
common case is byte-identical.

**Not a rathole, but note:** the layer above still interpolates a *validated but
shell-built* command. `shlex.quote` closes injection; it does not make the
builder correct. Plan 4's `sh -c` removal is what removes the class.

```python
# controller/compensation.py:_fs_read_only_undo
path = str(_param(fault, "path", "/"))
inject = ["sh", "-c", f"mount -o remount,ro {path}"]
```

`path` comes from a drill spec and reaches an `sh -c` command line with no
quoting. A path containing `;` or `$(...)` is executed inside the target
container. Found during the 0.9.1 fault work; `fs.corrupt` was written with
`shlex.quote` from the start, and the existing fault was deliberately **not**
changed inside a fault-addition commit.

For 1.0 this must be fixed. Beyond that specific call, the general rule should
be: **any user-supplied value that reaches a shell string is `shlex.quote`d**,
and a test enforces it. This is a one-line fix plus a guard, and it should not
wait for a release.

## 5. `ToolExecutor.undo` can raise  →  **SHIPPED**

Matched the established `try/except ToolError` pattern used by the two compliant
executors; no new pattern, no new import. Returns a truthful
`StepOutcome(ok=False, detail=f"undo tool failed: {exc}")` so the engine marks
the lease DIRTY instead of crashing.

**NEW, ADJACENT, NOT FIXED:** `ToolExecutor.inject` (line ~3830) has the
*identical* unguarded `run_tool`. The documented contract is scoped to undo, so
this was left alone rather than widening the change mid-lane — but it is the
same crash surface one call earlier, and it should be decided deliberately
rather than by omission.

The module docstring (`agents/executors.py:1-6`) states the contract: *"Undo
must be idempotent and must never raise: if undo fails, the executor reports
DIRTY and the controller escalates; it does not retry blindly."*

`PayloadExecutor.undo` and `ProcPauseExecutor._signal` honour it. `ToolExecutor.undo`
(`executors.py:3837`) does not — it calls `run_tool` without the
`ToolError` guard the other two have. A missing binary during undo raises out of
the executor instead of degrading to DIRTY.

The engine probably still handles it, but the contract is documented and not
kept, which is worse than not documenting it.

## 6. `withdrawal` audit — the one asset with no plan  →  **DONE: see [08-withdrawal-audit.md](08-withdrawal-audit.md)**

mayhem's genuine differentiator is the evidence bundle: hash-chained, signed,
replayable, exportable. Nothing in the market does this. But **nothing in
1.0.0 as planned extends it.**

Candidates, in order of value:

- record the **pack signer** (plan 4 step 5) — closes the audit loop for
  third-party faults
- record the **steady-state verdict and per-signal detail** (plan 1 step 4) —
  makes the bundle evidence rather than just a receipt
- record the **impact-gate cross-check** (plan 1 step 5) — "the gate said inert
  and the measurement agreed" is a strong claim
- **v1.0 attestation**: the bundle states the mayhem version, the fault
  catalogue digest, and the verified-live status of every fault that ran

The last one is the compounding move. A bundle that says *"produced by mayhem
1.0.0, catalogue digest abc123, all 4 faults verified-live"* is an artifact an
auditor or an SRE can act on six months later. It is the natural payoff of
plans 1 and 2, and it costs one signature over data that already exists.

## Sequencing

| # | Item | State | Blocks | Effort |
| --- | --- | --- | --- | --- |
| 1 | Fix the 62 lint errors | **DONE (62 → 1)** | plan 2 | S |
| 1b | Make lint blocking again | **NOT DONE** — no workflow runs lint | plan 2 | S |
| 2 | Restore `import-linter` locally, or delete the contracts | **DONE + 2 contracts BROKEN** | — | S |
| 2b | Fix the 7 import-contract violations | **NOT DONE** — architectural | plan 2 | L |
| 3 | Deprecate `config.max_faults` loudly | **DONE** | — | M |
| 3b | Fix the `README.md:378` lie; reconsider `cli/init.py` scaffold | **NOT DONE** | — | S |
| 4 | `shlex.quote` + enforcement test | **DONE (6 sites)** | — | S |
| 5 | `ToolExecutor.undo` honours the contract | **DONE** | — | S |
| 5b | `ToolExecutor.inject` — same unguarded `run_tool` | **NOT DONE** | — | S |
| 6 | Steady-state verdict into the evidence bundle | not started | plan 1 | M |
| 7 | v1.0 catalogue-digest attestation | not started | plan 1 | S |

Items 1–5 are now **shipped**. Every remaining row is a known, named, unowned
debt — not a surprise. Items 1b and 2b are the two that gate plan 2's promotion
criteria, because a `verified-live` gate is meaningless while static analysis is
red and architecture is unverified.

---

## 7. NEW — found during implementation, not in the original plan

### 7a. `forbidden_fault_pairs` is near-dead enforcement  (**HIGH**)

`controller/safety.py:231`:

```python
pair = frozenset((*fault_ids_so_far, new_fault_id)) if fault_ids_so_far else None
```

`fault_ids_so_far` is *every fault so far in the plan*, not the pair
`(previous, new)`. On a 3-fault plan the gate tests `{'a','b','c'}` against
`forbidden_fault_pairs`, which will essentially never match. The rule works for
2-fault plans and is **silently inert for longer ones**. A user who configures
a forbidden pair and writes a 3-step drill believes they are protected and are
not.

Found by Lane C while making preflight call the real gate. **Not fixed** — it
changes enforcement behaviour, and was correctly outside that lane's boundary.

### 7b. `docs/reference/cli.md` does not exist; its parity test is dead code  (**MED**)

`tests/unit/test_release_contract.py:234` `_iter_doc_invocations` is a
**generator with zero callers**, and the CLI doc-parity assertion is stranded
*inside* it, referencing `documented` and `active` — names never defined in that
scope. Consequences:

1. There is currently **no test** that `docs/reference/cli.md` matches
   `COMMAND_SPECS`.
2. The doc it guards **does not exist**.
3. ruff reports `F821 Undefined name` × 7 in that file — **red at HEAD**, and
   nothing runs `ruff` on `tests/`, so it has stayed invisible.

This is the same drift class that let the preflight/gate mismatch survive until
this release, and it is a hole in the guarantee the rest of this plan leans on.
**Not fixed here** — writing a 100-command reference doc is a separate body of
work, and the dead code reads as deliberate parked WIP. Flagged, not deleted.

### 7c. `ToolExecutor.inject` shares the undo defect  (**MED**)

See item 5b. Same unguarded `run_tool`, one call earlier.

### 7d. `mayhem bundle` advertised a producer it did not have  (**HIGH — FIXED**)

Found by the `withdrawal` audit, which is itself in `08-withdrawal-audit.md`.

`mayhem bundle --help` said **"Build and verify portable evidence bundles"** and
offered only `show` and `verify`. `build_bundle` had **zero production
callers** — every call site was in `tests/`. mayhem shipped a working verifier
for bundles it could not produce, and named the missing producer in its own
help text. Evidence bundles are the feature the market comparison claims as
the differentiator.

The README recipe was broken too: `inspect replay export --out bundle/`
produces a **JSON file** and `bundle verify` wants a **directory** — reproduced
live, exit 1.

**FIXED.** `mayhem bundle build RUN_ID --out DIR` now exists, built on inputs
that were already there (`load_evidence`, `ReplayRepository.load`,
`build_bundle`). Round-trip verified: build → `bundle valid: true`. The README
recipe now works verbatim. The audit's two guard tests were **inverted** as
their own docstrings instructed, so removing `build` again requires narrowing
the help string in the same change.

`verify` reports `unsigned: integrity is verified, authorship is not` — the same
integrity-versus-provenance split the fault-pack loader follows.

### 7e. Executor fail-open: a node target reported as a successful pod fault  (**HIGH — FIXED**)

`controller/executor.py:~1140` did `target = outcome.pod_or_none()` and
`continue`d on `None`. `pod_or_none()` returns `None` for a **node**
resolution, so a node target skipped the admission guard entirely and the step
then reported `ok=True, status='ok', detail='no pods mutated'`. The guard was
unreachable for precisely the case it was written to catch.

Now admits against the untyped resolution, so `admit_resolved_target` refuses
`target.type_mismatch` and the pod-only accessors are reached only after
admission passes. The sibling site at `:893` was checked: it **fails closed**
(raises → `resolution_failed`).

### 7f. `mypy --strict` had never been run: 284 errors  (**FIXED → 1**)

No CI ran it, and the CI workflow was deliberately deleted, so the backlog was
invisible. 284 → **1**, and the 111 that remained after a first pass turned out
to be ~20 root causes, not 111 problems. Six accounted for 42 errors between
them, and two were genuine **type-domain defects** — an annotation that said
something the code had been doing all along.

Two real bugs surfaced as a side effect:
- `compensation.py:2770` — **9 unreachable lines** after a `return`,
  byte-identical to `_net_congestion_undo`. A future edit to the live function
  would have silently not taken effect. Removed.
- `cli/lifecycle.py:1427` — a provably-dead `else` branch, left and pinned.

`tests/unit/test_mypy_baseline.py` ratchets the count **by file and error
code**, asserting a *non-increasing* total and **no new `(file, code)` pair** —
so the backlog cannot grow, and the single remaining error is trustworthy. It
deliberately does not demand zero: a test that demands zero gets deleted.

### 7g. Import-linter: 2 of 3 contracts broken  (**FIXED → 3 kept, 0 broken**)

`domain` was doing IO. Fixed by moving the *facts* down and keeping the *rules*
up: `toolkit.hashing` (four pure functions, no IO — a domain concept filed one
layer too high) moved to `domain/hashing.py`; path IO moved to `infra/*_io.py`;
`runtime_adapter`'s selection rule **stayed in the domain** as `select_engine`
with only host probing moved to `infra`; `catalog_report` moved wholesale to
`controller/`, the only layer permitted to see all three registries it needs.

**No contract was weakened.** All three bodies are byte-identical to before, and
`include_external_packages = true` is retained — it is what makes the stdlib
entries bite.
