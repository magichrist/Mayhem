# L3 — give `release_gate()` its first production caller

## What was open

At the time this plan was written, `release_gate` was implemented, documented,
and had **no caller anywhere in `src/`**:

```
$ grep -rn "release_gate(" src/ --exclude-dir=__pycache__ | grep -v "def \|test"
(no output)
```

**That is now closed.** `mayhem ci check --release-gate` calls it. The problem
statements below are kept as written, because they are what the phases were
planned against; the current state is in the STATUS block at the end.

It lives at `src/mayhem/controller/check_gate.py:1696` and takes
`suites: Sequence[ResilienceSuite]` and
`open_findings: Sequence[RegressionFinding]` — the exact two feeds plan 22
Phase 4 built to hand it. Plan 22 Phase 4 records the gap itself:

> "no CLI or dashboard consumes `open_findings` yet — `release_gate` is the wired
> consumer and has no production caller until plan 16's CI runners invoke it"

Meanwhile `--release-gate` **already exists** on `mayhem ci workflow`
(`src/mayhem/cli/ci_cmd.py:238`). It renders the string `" --release-gate"`
into generated GitHub/GitLab YAML (`ci_surface.py:461`, `:568`). So a pipeline
generated today is told to ask for a gate that nothing answers.

Two sub-gaps block the obvious fix, and neither is "call a function":

**A. There is no rehydration path for stored findings.**
`ComparisonService.record_finding` persists `json.dumps(finding.to_dict())` into
the `regression_findings.finding_json` column (`coverage_service.py:1244`).
`ComparisonService.findings()` returns `tuple[dict[str, Any], ...]` — raw dicts.
`RegressionFinding` (`domain/comparison.py:698`) has `open()` and no
`from_dict()`. `release_gate` needs `RegressionFinding` objects. Reading findings
back out of the store is therefore **not implemented today**, and it is not a
one-liner: the object graph is `RegressionFinding → DeltaReport → RunPin × 2`.

**B. There is no suite runner, so `--release-gate` alone always blocks.**
`release_gate`'s own docstring: *"a required suite with no result at all blocks —
a suite that did not run is not a suite that passed."* `required_suites_for(kind)`
returns a non-empty tuple for every `ChangeKind`. With no suite input, every
release gate blocks on every required suite. That is correct, fail-closed
behaviour — and it means the flag is useless without an input channel.

Neither gap is a reason to skip this. Both are stated below with the honest
resolution: the inputs arrive as explicit, human-supplied JSON files, and the
gate's blocking-on-no-input behaviour becomes the documented default.

---

## Phase 1 — rehydrate findings, and a suite parser

### 1a. `src/mayhem/domain/comparison.py` — `RegressionFinding.from_dict`

New classmethod on `RegressionFinding`, beside the existing `open()`:

```python
    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RegressionFinding:
        """Rebuild a persisted finding, or refuse.

        The inverse of :meth:`to_dict`, and it must be exact: the store wrote
        ``finding.to_dict()`` and a reader that reconstructs a *different*
        object than the one that was recorded has invented a finding. Every
        refusal below names the field that would have been guessed.

        * a missing or non-mapping ``report`` — refused, because a finding whose
          delta report is absent has no regression behind it and
          ``__post_init__`` would refuse it anyway;
        * a report whose ``outcome`` is not ``REGRESSED`` — refused here with
          its own rule id rather than relying on ``__post_init__``, so the
          message says *the stored row* claimed something impossible;
        * a pin missing ``run_id``, ``release``, ``experiment`` or
          ``evidence_digest`` — refused by name, because a pin with a blank
          digest is a run nobody sealed.

        This is the third member of a set the module already has:
        ``RunPin``, ``DeltaReport`` and ``RunReport`` all round-trip through
        ``to_dict``. Do not introduce a second serialization convention for this
        one type.
        """

        raw_report = payload.get("report")
        if not isinstance(raw_report, Mapping):
            raise InvariantViolationError(
                "comparison.finding_unreadable",
                f"stored finding {payload.get('finding_id')!r} carries no delta "
                f"report: a finding cannot be read back as a regression the "
                f"store did not record",
            )
        outcome_raw = raw_report.get("outcome")
        try:
            outcome = ComparisonOutcome(outcome_raw)
        except ValueError as exc:
            raise InvariantViolationError(
                "comparison.finding_unreadable",
                f"stored finding {payload.get('finding_id')!r} names outcome "
                f"{outcome_raw!r}, which is not one of "
                f"{[o.value for o in ComparisonOutcome]}",
            ) from exc
        if outcome is not ComparisonOutcome.REGRESSED:
            raise InvariantViolationError(
                "comparison.finding_without_regression",
                f"stored finding {payload.get('finding_id')!r} was recorded from "
                f"an {outcome.value} comparison: refusing to rebuild a "
                f"regression the row does not describe",
            )
        return cls(
            finding_id=_require_str(payload, "finding_id", "comparison.finding_unreadable"),
            report=DeltaReport.from_dict(raw_report),
            summary=_require_str(payload, "summary", "comparison.finding_unexplained"),
        )
```

Requirements on this implementation, each of which Phase 3 tests:

* `regressed_metrics` is derived from `report`, not read from the payload. If
  `to_dict()` stores it separately, `__post_init__` must agree with the
  rehydrated value — read `DeltaReport.to_dict()` and the `RegressionFinding`
  property before writing this and make them one answer.
* A module-level `_require_str(payload, key, rule)` helper, or reuse an existing
  one if the module has it. Check first; do not add a second.

### 1b. `DeltaReport.from_dict` and `RunPin.from_dict`

Same shape, same refusal discipline. `RunPin.from_dict` must refuse a blank
`evidence_digest` — that is the field whose absence would make a comparison
uncitable.

### 1c. `ComparisonService.finding_objects()` — the read side

New method on `ComparisonService`, beside `findings()`:

```python
    def finding_objects(self) -> tuple[RegressionFinding, ...]:
        """Every stored finding, rebuilt as the objects the gate consumes.

        Unlike :meth:`findings`, which returns rows verbatim for display, this
        reconstructs the domain object and therefore **refuses** a row that
        cannot be rebuilt. That asymmetry is the point: a corrupt row should
        still be readable by a human inspecting the table, and must not be
        silently dropped from a release decision — it must stop the release.
        """
        return tuple(
            RegressionFinding.from_dict(row["finding_json"])
            if isinstance(row.get("finding_json"), Mapping)
            else json.loads(str(row["finding_json"]))
            for row in self._store.query(
                "SELECT finding_json FROM regression_findings ORDER BY opened_at"
            )
        )
```

Read the real `findings()` implementation before copying its query and its row
shape — match it exactly rather than writing a second one.

### 1d. `src/mayhem/cli/ci_cmd.py` — the two input parsers

Two module-level helpers, placed near `_read_json` (which already exists at
`ci_cmd.py:~300`):

```python
def _suites_from_paths(paths: tuple[str, ...]) -> tuple[ResilienceSuite, ...]:
    """Suites, from JSON files the pipeline already produced.

    There is no suite runner in this build, so the gate's suite input is a file
    the caller hands it. An empty ``paths`` is **not** "no suites owed" — it is
    every required suite missing, which is exactly what ``release_gate`` blocks
    on, and the surface says so rather than papering over it.
    """
    suites: list[ResilienceSuite] = []
    for path in paths:
        raw = _read_json(path, f"resilience suite result {path!r}")
        if not isinstance(raw, list):
            raise MayhemCliError(
                code="invalid_input",
                message=f"{path} is not a list of suite results",
                details={"path": path, "type": type(raw).__name__},
                remediation="each --suite file holds a JSON array of "
                "{name, outcome, evidence_refs, run, detail} objects",
            )
        for item in raw:
            suites.append(_suite_from_mapping(item, path))
    return tuple(suites)
```

`_suite_from_mapping` builds a `ResilienceSuite` and lets
`ResilienceSuite.__post_init__` do the refusing — it already refuses a `PASS`
with no evidence refs, a `PASS` citing no run, and an `UNKNOWN` with no detail.
**Do not re-implement those three refusals at the CLI edge.** Their whole value
is that they cannot be bypassed by a caller building the object directly.

`ResilienceSuite.run` is a `RunPin | None`, so the parser needs
`RunPin.from_dict` from 1b anyway — one reason 1b is not optional.

### Acceptance

* `uv run pytest -n 3 tests/unit/test_comparison.py tests/unit/test_coverage_service.py`
  green — including the 48 fixture-pair cases, which must not move.
* `finding_objects()` round-trips every finding `open_finding` created in those
  fixtures, field for field.

---

## Phase 2 — call the gate from `mayhem ci check`

### 2a. New options on `check_cmd`

`check_cmd` is at `src/mayhem/cli/ci_cmd.py:468`. Add four, all `default=False`
or `()` so the existing invocation is byte-identical:

```python
@click.option(
    "--release-gate/--no-release-gate",
    default=False,
    help="Also decide whether this change may open a release. Off by default: "
    "the gate blocks on any required suite it was not given.",
)
@click.option(
    "--subject",
    default="",
    metavar="TEXT",
    help="The deployment, dependency, or infrastructure change the release gate "
    "is deciding about. Required with --release-gate.",
)
@click.option(
    "--suite",
    "suite_paths",
    multiple=True,
    metavar="PATH",
    help="A JSON file of resilience suite results. Repeatable. No file means "
    "every required suite is missing, which blocks.",
)
@click.option(
    "--finding",
    "finding_paths",
    multiple=True,
    metavar="PATH",
    help="A JSON file of regression findings to feed the gate. Repeatable.",
)
```

Then thread them into the signature. `test_cli_exhaustive_matrix.py` enumerates
the reachable surface leaf by leaf — it will need updating, and that is the
check working.

### 2b. The call

Insert after the existing proof rendering and **before** the final
`ctx.exit(...)` at line 553. The current tail is:

```python
    if report.blocking or not report.proven:
        ctx.exit(int(ExitCode.SAFETY_REFUSAL))
```

Replace with:

```python
blocked = bool(report.blocking) or not report.proven
if release_gate:
    blocked = (
        _apply_release_gate(
            ctx,
            change=change,
            verdict=verdict,
            blocked_already=blocked,
            subject=subject,
            suite_paths=suite_paths,
            finding_paths=finding_paths,
        )
        or blocked
    )
if blocked:
    ctx.exit(int(ExitCode.SAFETY_REFUSAL))
```

`blocked or= ` ordering is deliberate: a passing check suite cannot rescue a
blocked release gate, because they are different questions.

### 2c. `_apply_release_gate`

One new helper in `ci_cmd.py`:

```python
def _apply_release_gate(
    ctx: click.Context,
    *,
    change: Any,
    verdict: Any,
    blocked_already: bool,
    subject: str,
    suite_paths: tuple[str, ...],
    finding_paths: tuple[str, ...],
) -> bool:
    """Run the release gate, print its decision, return whether it blocked.

    Three refusals, each fail-closed:

    * no ``--subject`` — ``ReleaseGateRequest`` refuses an empty subject itself
      (``RULE_BLOCK_WITHOUT_REASON``); let it, and report its message rather
      than pre-empting it with a different one.
    * a ``verdict`` of ``None`` — the pipeline half already blocked and cited no
      run, so there is no candidate release for the gate to reason about. Print
      that and return ``True``. This is the documented case, not an error.
    * a suite or finding file that will not parse — ``_read_json`` raises
      ``MayhemCliError``; surface it through the same ``_fail``/``_refuse``
      handlers ``check_cmd`` already uses, and return ``True``.
    """
```

Inside it:

* Build `ReleaseGateRequest(change=change, kind=…, subject=subject)`. **`kind` is
  the one thing `ReleaseGateRequest` needs that `check_cmd` does not have** —
  `ChangeLink` has no `kind` field. Add `--change-kind`, a
  `click.Choice([k.value for k in ChangeKind])`, defaulting to
  `ChangeKind.DEPLOYMENT.value`, and note in its help that it decides *which
  suites are owed* (`required_suites_for`). Defaulting to DEPLOYMENT means the
  common case works and the wrong guess blocks rather than passes — a suite owed
  that was not supplied blocks either way.
* `suites = _suites_from_paths(suite_paths)`.
* `findings = tuple(RegressionFinding.from_dict(item) for path in finding_paths
  for item in _read_json(path, ...))`. Feed the gate the objects, never the
  dicts.
* `decision = release_gate(verdict, request, suites=suites, open_findings=findings)`.
* Print `decision.allow`, the reasons, and `evidence_refs`, using the same
  `style.info` treatment as the existing summary lines.
* `return not decision.allow`.

### 2d. Leave `workflow_cmd` alone

`--release-gate` on `workflow_cmd` is correct as written: it renders a flag into
generated YAML. This plan makes that flag answer to something. Do not change the
generator — `tests/unit/test_ci_surface.py` (54 tests) pins its bytes, and the
byte-for-byte determinism claim in its docstring is a product property.

The one thing worth adding is a doc note in `docs/v1.1.0/16_ci_cookbook.md`:
`--release-gate` in a workflow now corresponds to `mayhem ci check
--release-gate`, and the latter needs `--subject` and a suite file.

### Acceptance

* `uv run pytest -n 3 tests/unit/test_ci_surface_cli.py tests/unit/test_cli_exhaustive_matrix.py`
  green.
* `mayhem ci check --release-gate` with no suites exits non-zero and says a
  required suite did not run.
* `mayhem ci check` with no flags is byte-identical to before.

---

## Phase 3 — the proof

### 3a. `tests/unit/test_release_gate_cli.py` — new

| Test | What it pins |
| ---- | ------------ |
| `test_release_gate_off_is_the_default_and_changes_nothing` | the additive claim |
| `test_no_suites_blocks_on_every_required_suite` | gap B is fail-closed, not bypassed |
| `test_a_passing_suite_with_no_evidence_ref_is_refused_at_parse` | `ResilienceSuite.__post_init__` reached through the real parser |
| `test_an_unreachable_control_plane_differs_from_a_reachable_one` | the `UNKNOWN` distinction the `ResilienceSuite` docstring insists on survives parsing |
| `test_a_regression_finding_on_this_candidate_blocks` | the plan 22 feed, end to end from a JSON file |
| `test_a_finding_on_another_experiment_does_not_block` | the gate blocks what the evidence names, nothing else |
| `test_a_verdict_of_none_reports_the_pipeline_block` | gap A's documented case |
| `test_a_missing_subject_is_refused_with_the_gates_own_rule` | `RULE_BLOCK_WITHOUT_REASON`, not a CLI invention |
| `test_a_finding_file_that_will_not_parse_blocks` | malformed input never becomes "no findings" |

### 3b. Negative controls

1. **A store round trip through the real service.** Write a finding with
   `open_finding` against a migrated test store, read it back with
   `finding_objects()`, and assert every field survives. Then mutate the stored
   JSON's `outcome` to `IMPROVED` and assert `from_dict` refuses rather than
   rebuilding — this is the control that makes the rehydration trustworthy, and
   it is the reason the refusal exists.
2. **Delete the CLI call.** Remove the `release_gate(...)` invocation and assert
   both: the CLI test fails, and a source-parsing assertion over `ci_cmd.py`
   fails naming `check_cmd`. There is no store boundary to catch this one, so the
   static check is the guard.
3. **Break `required_suites_for`, not `src/mayhem`.** Pass a `kind` whose
   required suites are empty and assert the gate still blocks on the pipeline
   half. Shows the gate is not leaning on the suite table for its verdict.

### 3c. `tests/unit/test_last_l3_plan_docs.py` — the honesty gate

* `Overall: 3 of 3 phases complete` equals the `DONE` count here.
* Every `file:line` citation resolves.
* This document states plainly that **there is still no suite runner**, so
  `--release-gate` in any generated workflow will block until someone supplies
  suite files. That sentence is the most likely thing to rot and it must be
  asserted.
* This document states that `release_gate` still has no caller **other than**
  `mayhem ci check`, so the claim "the release gate is enforced" is refused.
* `RegressionFinding.from_dict`'s refusal rule ids are cross-checked against the
  source; an invented id fails.

### 3d. Recorded gaps

* ~~**No suite runner.** Suites arrive as files. Nothing in this repository
  produces them.~~ **Closed.** `mayhem ci suite --db PATH --run RUN_ID --kind K`
  produces the file `--suite` reads, grading each owed suite from that run's
  recorded coverage. See the "Recorded gaps" block in the STATUS section for what
  it still cannot do.
* **`release_gate` is not a required CI check.** Nothing enforces that a pipeline
  passes `--release-gate`; the flag is opt-in at the workflow level and off by
  default at the check level.
* **A finding has no close state.** "Open" means every stored finding. Every
  finding ever opened therefore blocks its candidate release forever. That is
  plan 22's recorded limitation and this plan inherits it; fixing it is a
  `RegressionFinding` lifecycle change, not a gate change.
* **L2 does not close here.** The gate reads a `PipelineVerdict` from the check
  report, not a chain completeness from L2. Wiring release decisions to
  `chain_completeness` is not done and is not claimed.

### What this does not claim

It does not make the gate suite green for a production-class release — that needs
`certified_faults > 0` and a soak, per plan 24. It does not implement a suite
runner, and a workflow generated with `--release-gate` today blocks. It does not
publish a commit status: `publish_commit_status` remains deliberately unbound.

---

## STATUS — 3 of 3 phases complete

- Phase 1: DONE — `from_dict` on `MetricDelta`, `RunPin`, `DeltaReport` and
  `RegressionFinding` (each beside its own `to_dict`), and
  `ComparisonService.finding_objects()`, which reuses `findings()`'s query
  rather than writing a second one.
- Phase 2: DONE — five options on `check_cmd`, `_suites_from_paths`,
  `_apply_release_gate`, and the new tail that lets a passing check suite never
  rescue a blocked gate. `workflow_cmd` was not touched: it renders a flag into
  generated YAML, and its bytes are pinned by 54 tests.
- Phase 3: DONE — `tests/unit/test_release_gate_cli.py` (13 tests, driven
  through the real `CliRunner`) and `tests/unit/test_last_l3_plan_docs.py`.

Overall: 3 of 3 phases complete (Phases 1, 2, and 3).

## The limitation that mattered most — now closed, and conditional

~~**`check_cmd` never supplies a `cited_run`.** `CheckInputs` is built without one,
so `blocking_reasons` always appends *"no run is cited, and a run that cannot be
cited cannot back a release-gate decision"* — and `release_gate`'s only allow
path requires an empty reason list. **The gate invoked from this surface can
therefore only ever block; it cannot allow.**~~

**Closed after this plan landed.** `mayhem ci check` now accepts `--run PATH`,
naming a JSON file holding one `RunPin`, and threads it into **both**
`CheckInputs` branches. With a cited run whose pin vector agrees with the change
link's own pins, `blocking_reasons` no longer carries the "no run is cited"
reason and the gate can allow.

Two decisions in that option are worth keeping:

* **The pin comes from a file, not the store.** This command claims to be
  read-only with respect to the store and to any control plane, and a cited run
  is a claim about sealed evidence that the operator, not this process, vouches
  for.
* **A malformed file refuses; it never degrades to "no run cited."** Silently
  falling back would turn a typo into a gate that blocks for a reason the
  operator is not looking at.

**What remains true.** Without `--run` — which is the default — the gate still
can only block, and a finding still has no close state, so "open" means every
stored finding. `--run` lifts the first limitation; it does not make the flag
safe to leave on.

The allow *branch* itself is proven at the fixture level in
`tests/unit/test_ci_pipeline_gates.py`, where a genuinely passing verdict and a
passing suite reach `opens_release == True`. Driving a full allow through the CLI
needs a plan and topology that pass every one of the seven checks, which is a
fixture `tests/unit/test_release_gate_cli.py` deliberately does not fake — so
that file asserts what is true of *its* fixture (the reason disappears) and does
not claim a gate opened when its own plan failed three checks.

## Deviations, recorded rather than hidden

**1. Two of the plan's three Phase 1 sub-gaps were not where it said.**
`RunPin.from_dict` and `MetricDelta.from_dict` were not in the plan; they are
required because `ResilienceSuite.run` is a `RunPin` and `DeltaReport.deltas` is
a tuple of `MetricDelta`, so rehydrating a finding means rehydrating all three.
**2. `from_dict` cannot be a strict inverse of `to_dict`.** Each `to_dict` emits
*derived* keys that are not constructor arguments — `graded`, `label`, `scored`,
`cited_runs`, `regressed_metrics`. They are dropped and **recomputed**, never
read: `from_dict(t.to_dict()) == t` holds, but a tampered derived key does not
survive the round trip. `RunPin` needed this most — `extra="forbid"` would have
rejected its own serialization.
**3. Only the store boundary translates errors.** `RegressionFinding.from_dict`
maps construction failures to `comparison.finding_unreadable`; the three inner
`from_dict` methods raise raw `KeyError`/`ValueError`/pydantic `ValidationError`,
because inventing rule ids for them was out of scope.
**4. `finding_objects` refuses rather than skips.** A row that cannot be rebuilt
must stop the release, not vanish from it — a dropped row is a pass over a store
the gate could not read. `findings()` deliberately keeps returning the raw row,
because a human inspecting the table *should* see it.

## Recorded gaps, unchanged

- **No suite runner.** Suites arrive as JSON files. Nothing in this repository
  produces them, so `--release-gate` with no `--suite` blocks on every required
  suite. That is correct and it is also why the flag is off by default.
- **`release_gate` is not a required CI check.** The flag is opt-in at the
  workflow level and off at the check level.
- **A finding has no close state.** "Open" means every stored finding, so every
  finding ever opened blocks its candidate release forever. Inherited from plan
  22; fixing it is a `RegressionFinding` lifecycle change, not a gate change.
- **L2 does not close here.** The gate reads a `PipelineVerdict` from the check
  report, not a chain completeness from L2, so wiring release decisions to
  `chain_completeness` is still not done.

## What this does not claim

It does not make the gate suite green for a production-class release — that needs
`certified_faults > 0` and a soak, per plan 24. It does not implement a suite
runner. It does not publish a commit status: `publish_commit_status` remains
deliberately unbound. And `SIGNATURE_VERIFICATION_IMPLEMENTED` is `False`, so no
release decision here rests on a signature anyone has verified.