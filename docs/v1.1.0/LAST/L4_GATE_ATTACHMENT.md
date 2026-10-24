# L4 — the gate/budget binding: wired, reachable, and untested

## Correction to the earlier reading

An initial pass reported "`attach_preflight_gate` / `attach_resource_budget` have
zero production attach points." **That was wrong, and the correction is the
finding.** The call sites exist:

* `src/mayhem/cli/lifecycle.py:1493` — `gate = run_gate()`
* `src/mayhem/cli/lifecycle.py:2024` — `gate = run_gate()`
* `src/mayhem/cli/lifecycle.py:1625–1626`, `1731–1732`, `1888–1889`, `2164–2165` —
  `build_run_engine(..., gate=gate, budget_guard=run_budget_guard(run_id))`

`run_gate()` is `src/mayhem/cli/app.py:182`; `run_budget_guard()` is
`app.py:213`. Both read one environment variable each —
`MAYHEM_GATE_WITNESSES` and `MAYHEM_BUDGET_GUARD` (`cli/execution.py:112` and
`:119`) — resolve an import spec, and pass the result down to `build_run_engine`,
which attaches it (`cli/services.py:632–639`).

So plan 10's ledger line — *"No production call site attaches a gate, exactly as
`attach_resource_budget` has none today"* — is **stale**. It describes a state the
code left behind. That sentence is itself an L1-class defect and Phase 3 below
corrects it.

## What is actually open

Three things, all about the last mile between the binding and a user:

### A. The binding machinery has **zero** test coverage

```
$ grep -rln "GATE_WITNESSES\|BUDGET_GUARD\|_load_binding\|gate_from_spec\|run_gate" tests/
(no output)
```

`gate_from_spec`, `budget_guard_from_spec`, `_resolve_gate`, `_load_binding`,
`run_gate`, `run_budget_guard` — the entire path by which any production run
becomes gated or budgeted — is exercised by **no test in the repository**. Not
weakly covered; not referenced at all.

This matters more than a coverage percentage. The design block at
`cli/execution.py:75–105` makes three load-bearing promises:

1. *"A binding that cannot be loaded is refused loudly … rather than degraded into
   'no gate', because an operator who asked for gating and silently got none has
   been told the safe thing is on when it is off."*
2. *"An empty binding is no gate, not a refusing one"* — `PreflightPorts()` with
   nothing bound resolves to `None` via `gate_for_ports`.
3. *"Binding … can only add"* — no spelling gets past what a binding installed.

None of the three is pinned by a test. A regression that turned promise 1 into a
silent `return None` would be invisible to the entire suite, and that regression
is the difference between "mayhem told me it was gated" and "mayhem was not".

### B. Neither environment variable is documented anywhere

```
$ grep -rln "MAYHEM_GATE_WITNESSES" docs/
(no output)
```

`MAYHEM_GATE_WITNESSES` and `MAYHEM_BUDGET_GUARD` appear in five source files and
zero documents. `docs/config.md` is declared the authoritative summary of
`src/mayhem/config.py`; neither variable is read by `config.py`, so they are
correctly outside it — but there is no other document, no `mayhem doctor` line,
and no CLI help text that names them. `cli/execution.py`'s own comment block is
the entire user-facing description, and it is a comment.

### C. No shipped witness provider exists

`MAYHEM_GATE_WITNESSES` takes `module:attribute`. Nothing under `src/mayhem/`
provides one. A deployment that wants gating must author its own module exporting
a `PreflightGate`, a `PreflightPorts`, a mapping of witness name to witness, or a
zero-arg factory — with no worked example anywhere in the repository to copy.

This is defensible by design (*"mayhem binds none of the five witnesses, because
it owns no incident manager, deployment feed, backup system or replication
peer"* — `cli/app.py:194–196`) and this plan does not change that. But a
configuration surface with no example and no test is a surface nobody will
configure, which makes the correctly-designed wiring inert in practice.

---

## Phase 1 — pin the binding machinery

New file: `tests/unit/test_binding_spec.py`. No source change in this phase.

The module already documents its own accepted shapes in `_resolve_gate`'s
docstring. These tests make that documentation load-bearing.

### 1a. The accepted shapes

For each of the four shapes `_resolve_gate` accepts, assert the resolved gate:

| Spec resolves to | Expected |
| --- | --- |
| a `PreflightGate` | returned **verbatim** — assert identity (`is`), not equality, because the docstring promises a configured gate is never rebuilt |
| a `PreflightPorts` with all five bound | a `PreflightGate` |
| a `dict` of witness name → witness | a `PreflightGate`, built by `_ports_from_mapping` |
| a zero-arg callable returning any of the above | the same result as returning it directly |

### 1b. The unconfigured state, which must **not** become a refusing gate

* `PreflightPorts()` with nothing bound → `run_gate` yields `None`, and
  `build_run_engine` attaches nothing. This is promise 2.
* A factory returning an empty `PreflightPorts` → also `None`. The docstring calls
  this out specifically ("a factory is not a wider door than the value it
  names"); assert it.
* An env var that is unset, or set to whitespace → `None`.

### 1c. The refusals — promise 1, the important half

Every one of these must raise `InvariantViolationError`, **not** return `None`:

| Case | Rule id asserted |
| --- | --- |
| spec with no `:` | `gate_binding_*` (read `_binding_error` for the exact spelling) |
| importable module, missing attribute | ditto |
| unimportable module | ditto |
| factory that raises | `gate_binding_call` |
| factory returning `object()` | `gate_binding_shape` |
| attribute holding `object()` | `gate_binding_shape` |
| `MAYHEM_BUDGET_GUARD` factory that raises | the budget equivalent |
| `MAYHEM_BUDGET_GUARD` factory that ignores `run_id` and takes none | `TypeError` surfaces as the binding refusal, not a `TypeError` to the operator |

The last row is the one most likely to be wrong. Write it to assert the *actual*
behaviour after reading `_load_binding`; if the current code lets a bare
`TypeError` escape, that is a defect this test should surface and Phase 2 fixes.

### 1d. `run_budget_guard` receives this run's id

Assert the factory is called with the `run_id` passed in, and that a guard scoped
to run A is not reused for run B. `ResourceScope.RUN` resolves its scope key from
that id, so this is the property that makes a per-run budget a per-run budget.

### 1e. An end-to-end test through the environment

The one that would have caught the original stale claim:

```python
def test_a_bound_gate_reaches_the_engine_through_the_environment(monkeypatch, tmp_path):
    """MAYHEM_GATE_WITNESSES set → build_run_engine attaches a gate.

    This is the only seam at which the binding is reachable from a user, so it is
    the only place the promise "binding can only add" can be checked end to end.
    """
    monkeypatch.setenv("MAYHEM_GATE_WITNESSES", "tests.unit.binding_fixtures:five_ports")
    engine = build_run_engine(store, plan, runtime=None)
    assert engine.preflight_gate is not None
```

Add `tests/unit/binding_fixtures.py` exporting `five_ports` (a fully bound
`PreflightPorts`) and `budget_guard` (a factory taking `run_id`). Without this
fixture module there is no way to write any of the tests above without
monkeypatching `importlib`, which tests the mock rather than the loader.

### Acceptance

`uv run pytest -n 3 tests/unit/test_binding_spec.py` — green, and the refusals in
1c genuinely bite.

---

## Phase 2 — make the surface reachable

### 2a. Ship one witness provider

New file: `src/mayhem/cli/witnesses.py`. **Not** a real deployment binding — a
documented, importable starting point that resolves and refuses honestly.

```python
"""Shipped witness providers for ``MAYHEM_GATE_WITNESSES`` and
``MAYHEM_BUDGET_GUARD``.

A binding is an import spec, and until now the repository shipped nothing for one
to name: a deployment wanting gating had to author a module from the type
definitions alone, with no worked example. This module is that example, and it is
deliberately made of **unreachable** witnesses rather than permissive ones.

Every port below answers ``UNAVAILABLE``. That is not a stub pretending to work —
it is the honest answer from a process that owns no incident manager, deployment
feed, backup system or replication peer — and it makes the gate *refuse*, which is
the behaviour an operator should see when the systems cannot be consulted. A
provider that answered ``HEALTHY`` would be the bug this whole plan is about.

To use it::

    MAYHEM_GATE_WITNESSES=mayhem.cli.witnesses:unavailable_ports

and then bind each witness to something real in your own module, importing
:func:`unavailable_ports` as the starting shape. To use the budget side::

    MAYHEM_BUDGET_GUARD=your.module:budget_for_run
"""
```

Exports:

* `unavailable_ports() -> PreflightPorts` — all five ports bound to witnesses that
  report `UNAVAILABLE` with a detail naming the system, so a refusal says *which*
  system could not be consulted (`PORT_SUBJECTS` already exists for this).
* `empty_ports() -> PreflightPorts` — nothing bound, i.e. the unconfigured state,
  so the documented "empty binding is no gate" path is reachable from a spec too.
* `noop_budget_guard(run_id: str) -> RunBudgetGuard | None` — returns `None`,
  documented as "a binding that resolves to `None`", so the budget side's
  unconfigured path is exercisable.

Register the module in the CLI inventory test
(`tests/unit/test_cli_exhaustive_matrix.py`) if that test enumerates `src/mayhem/cli/`
modules — read it first; it may enumerate commands rather than modules, in which
case nothing is needed.

### 2b. Name the variables in the surfaces a user reads

Three additive edits, no behaviour change:

* **`mayhem doctor`** — one line per variable: set / unset, and for a set one, the
  spec it names and whether it resolves. Read `cli/doctor_cmd.py` for the existing
  line shape and match it. Do not have doctor *resolve* an unset variable into a
  gate and then drop it; report the binding state, not the resolved object.
* **`docs/config.md`** — a new section, "Bindings outside `mayhem.yaml`", naming
  both variables, the spec grammar, the four accepted shapes, the three promises
  from `cli/execution.py:75–105` in prose, and a pointer to
  `mayhem.cli.witnesses`. Note explicitly that `config.md` documents
  `src/mayhem/config.py` and these two are read at the CLI edge by
  `mayhem.cli.app`, which is why they are here and not in the YAML reference.
* **`docs/v1.1.0/10_EMERGENCY_STOP_PREFLIGHT.md` and `23_PERFORMANCE_SCALE.md`** —
  Phase 3 below, because editing a STATUS block without the test that guards it
  repeats L1.

### 2c. The `TypeError` escape, if 1c found one

If the last row of 1c shows a bare `TypeError` escaping `budget_guard_from_spec`,
fix it inside `_load_binding` so every binding failure is an
`InvariantViolationError`. That is the whole point of the design block: *every*
unusable binding refuses loudly and identically. One path raising `TypeError` is a
hole in "an operator who asked for gating and silently got none" — they get a
stack trace instead, which is louder but not *actionable*.

### Acceptance

* `uv run pytest -n 3 tests/unit/test_binding_spec.py tests/unit/test_cli_doctor.py`
  green.
* `MAYHEM_GATE_WITNESSES=mayhem.cli.witnesses:unavailable_ports mayhem doctor`
  names the binding, the spec and the resolution.
* `MAYHEM_GATE_WITNESSES=mayhem.cli.witnesses:empty_ports` attaches nothing and a
  run is byte-identical.

---

## Phase 3 — correct the two stale ledgers, and guard them

### 3a. Fix the false sentence

`docs/v1.1.0/10_EMERGENCY_STOP_PREFLIGHT.md` line 288 currently reads:

> `build_run_engine` is the bind point, and it is not yet configured. …
> **No production call site attaches a gate** … The lane that owns the run path
> (`cli/lifecycle.py`, not this plan's) decides when to attach one; the attach
> point is ready and tested.

The lane that owns the run path **has** decided: `cli/lifecycle.py` calls
`run_gate()` at lines 1493 and 2024 and passes the result to `build_run_engine` at
four sites. Replace with the correction, in the same voice plan 19 Phase 3 used
when it found its own stale "not registered" claim:

```markdown
   **Correction, this entry was stale.** It previously read *"No production call
   site attaches a gate."* That is no longer true: `cli/lifecycle.py` calls
   `run_gate()` (lines 1493 and 2024) and passes the result to `build_run_engine`
   (lines 1625, 1731, 1888, 2164), which attaches it through
   `attach_preflight_gate`. `MAYHEM_GATE_WITNESSES` is the bind.

   **What is still true** is narrower and is what actually matters: the variable
   is unset in every environment this repository ships, because mayhem owns none
   of the five witness systems. So every production run is correctly ungated —
   not because nothing is wired, but because no deployment has bound a witness.
   The binding machinery had no test at all until
   `tests/unit/test_binding_spec.py`, and no shipped provider until
   `mayhem.cli.witnesses`.
```

Apply the same treatment to `23_PERFORMANCE_SCALE.md`'s claim that
`attach_resource_budget` "has none today".

### 3b. Guard the correction

Extend `tests/unit/test_last_l4_plan_docs.py` (new, same shape as the other three
`test_last_*` files):

* `Overall: 3 of 3 phases complete` equals the `DONE` count here.
* Every `file:line` citation resolves — including the four `lifecycle.py` attach
  sites, which is the check that stops this document becoming the next stale one.
* A source-parsing assertion over `cli/lifecycle.py` that
  `build_run_engine(` is called with `gate=` and `budget_guard=` at least once
  each. **This is the check that makes 3a's correction self-enforcing**: if a
  future lane removes the attach, this document's claim and the plan-10 ledger
  both become false again and the suite says so.
* Both `MAYHEM_GATE_WITNESSES` and `MAYHEM_BUDGET_GUARD` appear in `docs/` —
  asserted by scanning the docs tree, because a binding nobody can read about is
  the Phase 2 defect returning.
* This document does not claim mayhem ships working incident-manager or backup
  witnesses. It ships *unreachable* ones, on purpose.

### 3c. Recorded gaps

* **`witnesses.py` answers `UNAVAILABLE` for all five ports, forever.** It is a
  template, not a deployment. A real binding is the deployment's work.
* **Attaching `unavailable_ports` refuses every run.** That is intended, and it is
  why `empty_ports` exists — but it means the useful first step for an operator is
  the *empty* one, and this document should say so rather than implying the
  refusing one is a starting configuration.
* **`budget:available` is judged `FAIL` naming what it lacked** when a gate is
  attached, so a deployment that binds all five witnesses still gets a refusal
  until it also declares a narrower catalogue. Documented at
  `cli/execution.py:96–105`; not fixed here.
* **This does not make any run gated.** It makes gating reachable, documented and
  tested. The distinction is the entire difference between this plan and a plan
  that claimed a capability it did not ship.

### What this does not claim

It does not bind a witness to a real system, does not implement an incident
manager or a backup probe, and does not change a single run's behaviour by
default. Nothing here is on by default; `MAYHEM_GATE_WITNESSES` unset is still
`None`, and the ungated path is still byte-identical.

---

## STATUS — 3 of 3 phases complete

- Phase 1: DONE — `tests/unit/test_binding_spec.py` (26 tests) and
  `tests/unit/binding_fixtures.py`, with real implementations of all five port
  Protocols rather than `object()` stand-ins.
- Phase 2: DONE — `src/mayhem/cli/witnesses.py`, the two doctor lines in
  `src/mayhem/cli/doctor.py`, and the `docs/config.md` section "Bindings outside
  `mayhem.yaml`".
- Phase 3: DONE — the plan-10 ledger correction, the four `build_run_engine` to
  `engine_for` docstring renames, and `tests/unit/test_last_l4_plan_docs.py`.

Overall: 3 of 3 phases complete (Phases 1, 2, and 3).

## The correction, restated because it is the whole point of this document

This plan was written on a false premise. It opened by claiming
`attach_preflight_gate` and `attach_resource_budget` had no production call
sites. **The call sites exist.** `cli/lifecycle.py` calls `run_gate()` (lines
1493 and 2024) and `run_budget_guard()` and passes both to `engine_for` (lines
1625, 1731, 1888, 2164). The plan-10 ledger that made the same claim is now
corrected in place, and `tests/unit/test_last_l4_plan_docs.py` asserts that the
sentence "No production call site attaches a gate" may appear in plan 10 only on
a line that also says "previously read" — so the retraction cannot be quietly
un-retracted.

What was genuinely open, and what this plan closed:

| | before | after |
| --- | --- | --- |
| test coverage of the binding machinery | **zero** | 26 tests |
| documents naming either variable | **zero** | `docs/config.md`, doctor |
| a spec an operator could point at | none | `mayhem.cli.witnesses` |

## Deviations, recorded rather than hidden

**1. The factory is `engine_for`, not `build_run_engine`.** The plan named a
function that does not exist. The real name is `engine_for`
(`cli/services.py:553`); `build_run_engine` survived in four docstrings across
`cli/execution.py` and `controller/executor.py`, which have now been renamed.
That is the same defect class as the four stale STATUS blocks L1 closed, found
in source rather than in prose.

**2. The zero-arg-factory case is not a defect.** Phase 2c anticipated that a
zero-arg factory on the budget path would escape as a bare `TypeError`, since
`budget_guard_from_spec` calls the factory *with* `run_id`. It does not: the call
is inside `except Exception`, so it is wrapped as an
`InvariantViolationError` with rule `budget_binding_call` and the `TypeError`
chained as `__cause__`. The behaviour is now pinned by
`test_a_zero_arg_budget_factory_is_refused_not_leaked_as_a_type_error` rather
than fixed. **The plan's hypothesis was wrong and the code was right.**

**3. `unavailable_ports` witnesses raise rather than return.** Returning
`healthy=False` would produce a `FAIL` — "reached, and the answer was no" — which
would *certify* that an incident is open. Returning `None` reads as an adapter
bug. Raising takes the gate's error branch, which appends `mayhem cannot see
{system}` from `PORT_SUBJECTS` plus the environment that went unprobed. That
last fragment is the additive part: the gate's own detail never says which
target it failed to ask about.

## Recorded gaps, unchanged

- **`witnesses.py` answers UNAVAILABLE for all five ports, forever.** It is a
  template, not a deployment. A real binding is the deployment's work.
- **Attaching `unavailable_ports` refuses every run.** That is intended, and it
  is why `empty_ports` exists — but it means the useful first step is the *empty*
  one.
- **A bound gate still judges `plan:admitted`, `agent:availability`,
  `agent:capability`, `policy:available` and `budget:available` as `FAIL`**
  naming what they lacked, so binding all five witnesses still gets a refusal
  until a narrower catalogue is declared. Documented at `cli/execution.py:96-105`;
  not fixed here.
- **Doctor stops at the import seam.** Full resolution *calls* what it loads, and
  a doctor line must be safe to run, so doctor reports "does it resolve" without
  invoking a factory. The failures it therefore cannot see (a factory that
  raises, a wrong shape) are still refused loudly by the run path before any
  store is touched.

## What this does not claim

It does not bind a witness to a real system, does not implement an incident
manager or a backup probe, and does not change a single run's behaviour by
default. Nothing here is on by default: `MAYHEM_GATE_WITNESSES` unset is still
`None`, and the ungated path is still byte-identical. The distinction between
*reachable, documented and tested* and *gated* is the entire difference between
this plan and a plan that claimed a capability it did not ship.