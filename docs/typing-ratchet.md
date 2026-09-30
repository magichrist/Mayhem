# Typing ratchet — mypy error budget and the root causes behind it

`mypy --strict` on `src/`. The budget is enforced by
`tests/unit/test_mypy_baseline.py`, which pins the remaining errors **by file
and by error code** and asserts a non-increasing total.

## Why a ratchet and not a zero-gate

A test that demands zero gets deleted rather than fixed: the pressure it
creates is to silence the checker rather than fix the code, and the deletion
is invisible in review. A ratchet makes *growth* loud and *shrinkage* free. It
does not claim the backlog is acceptable — it claims the backlog is not
growing, and that every remaining error is a named, reviewed decision rather
than drift.

`# type: ignore` is deliberately not pinned separately. mypy already reports
`unused-ignore` when a suppression stops being needed, so a stale ignore
surfaces as a new error and trips the ratchet on its own.

## Current budget

**1 error** (from **111** at the start of the typing lanes).

| File | Code | Count | Why it stays |
| --- | --- | --- | --- |
| `src/mayhem/cli/lifecycle.py:1427` | `unreachable` | 1 | A `rows[0][0]` fallback in a `sqlite3.Row` ternary. `Store.query` is annotated `list[sqlite3.Row]` and `Store.__init__` sets `row_factory = sqlite3.Row` unconditionally, so `hasattr(row, "__getitem__")` is always true and the `else` is provably dead. Kept: the guard is a deliberate "dict rows *or* tuple rows" accommodation, and deleting a defensive branch in a CLI plan-loading path is a worse trade than one pinned error. Dead code, not a defect. |

## Root causes, and what each one cost

The 111 errors were not 111 problems. These are the causes that actually
generated the noise, largest first.

| # | Root cause | Errors | Fix |
| --- | --- | --- | --- |
| 1 | `*args: object, **kwargs: object` on a Click subclass (`PrefixGroup.__init__`) forwarded to `click.Group.__init__` | 9 | `Any`. `object` was a lie: Click's constructor is keyword-open, and the annotation claimed to check it. Also removed the then-stale `type: ignore[arg-type]` on the caller. |
| 2 | `_preflight_for_run(...) -> object` erased a real `Preflight` dataclass, spraying `attr-defined` at every consumer | 5 | Return the concrete `Preflight`. |
| 3 | `_write_evidence_after_run(store: object)` and `_slo_from_plan(...) -> tuple[object, ...]` erased two boundaries | 7 | Real types (`Store`; `tuple[ObservationQuery, ...]`, `tuple[SloCriterion, ...]`). |
| 4 | pydantic's mypy plugin ignores `populate_by_name`, so every `Field(alias=...)` field reports "Unexpected keyword argument" for its own snake_case name | 7 | 4 targeted `# type: ignore[call-arg]` (one per *line*, covering all errors on it) in `providers/builtin.py`. Proven with a minimal repro. The alternative — dropping `alias=` for `serialization_alias=` — would stop camelCase provider manifests from validating, which is a breaking change to a plugin API. |
| 5 | `RuntimeAdapter` declared no `__init__`, so `cls(engine)` in the adapter registry did not type-check (one call site carried a pre-existing ignore, its twin did not) | 2 | Declared the constructor contract on the ABC, matching what all three concrete adapters already implemented. Removed the pre-existing ignore. |
| 6 | `rank()` was typed `CoverageCell`-only, but `rank_resilience_cells` legitimately passes `ResilienceCell`s through it and `RankedCell.cell` already declared the union | 7 | Made `RankedCell` and `rank` generic over the cell type (`RankedCell[CellT]`, `rank[CellT: CoverageCell | ResilienceCell]`), and widened the four scoring helpers. `rank_resilience_cells` now honestly returns `RankedCell[ResilienceCell]`, which is what `SQLiteCoverageRepository.next_cells` was already relying on. |
| 7 | `observations: tuple[dict[str, object], ...]` asserted more than was known about `getattr(result, "observability")`, making the `isinstance(item, dict)` / `else` normalisation provably dead | 1 | Bind the raw sequence as `tuple[object, ...]` and normalise into the typed one. The branch is live again. |
| 8 | `IPvAnyAddress(ip_str)` — calling a `TYPE_CHECKING` union alias as a constructor | 3 | `ipaddress.ip_address`. Verified behaviour-identical on every valid input (v4, v6, scoped v6); only the *exception class* on malformed input changes, from pydantic's `PydanticCustomError` to stdlib `AddressValueError` (a `ValueError`). |
| 9 | `RecoveryAuditLog` used an un-imported `Store` (papered over with a `# noqa: F821`, which mypy does not honour) and `self._store.write()` on a `Store \| None` | 5 | Import `Store` under `TYPE_CHECKING` (**removed** the noqa, strengthening ruff) and pass the non-`None` store into `_ensure_table` / `_load` instead of re-reading the optional attribute. |
| 10 | `DrillSpec.containers: dict \| None` and `DrillSpec.evidence_schema` aliases flowing into unguarded uses | 2 | `maniac.py`: `(spec.containers or {})` — a `None` now lands on the same `ManiacError` as an empty pool instead of `AttributeError`. `lifecycle.py`: `len(containers or {})`. |
| 11 | `domain/cancellation.py::_LADDER` annotated `tuple[CancellationLevel, ...]` but populated with raw `str` | 2 | Corrected the annotation to `tuple[str, ...]`. The runtime was already right (`.upper()` on a `str`); the annotation was the bug. |
| 12 | Bare `dict` / `list` / `tuple` generics under `--strict` | 9 | Parameterised. |
| 13 | Missing parameter/return annotations on CLI helpers | 9 | Annotated with the types the bodies already use. |
| 14 | `ExploreDryRun` and `ExploreRun` results both bound to `result`; `provider` bound to two different provider classes | 6 | Distinct local names. |
| 15 | `json.loads` typed `Any` flowing out of functions promising a concrete type | 4 | `cast` at three `agents/k8s_control.py` JSON boundaries, an `isinstance` narrow in `plan_diff.py`, `bool()` on a comparison in `report.py`. |
| 16 | `lambda runtime=runtime: runtime` — a default-argument closure mypy cannot infer | 2 | `_factory_for(runtime)`: a closure over a *parameter*, which is bind-by-value exactly like the default-arg trick, and inferable. |
| 17 | Stale `type: ignore` comments left behind by earlier fixes | 8 | Deleted. |
| 18 | Untyped parameters on duck-typed CLI callbacks (`approve_fn: object`, `assessment`, `store`, `outcome`) | 5 | Annotated to the documented contract — in `explore_flow.py` the annotation had contradicted its own docstring (`Callable[[ExperimentCandidate], bool]`). |
| 19 | `implementation={...}` dicts passed where an `ImplementationReference` model is declared | 2 | Construct the model. Identical validation, stricter types. |
| 20 | `kubernetes` (36.0.3) ships no `py.typed` | 1 | 1 targeted `# type: ignore[import-untyped]`, the legitimate case. The whole import sits inside `except Exception`, so an absent or wrong-version SDK degrades to a failed `StepOutcome`, never a silent success. |

## The `unreachable` findings

`unreachable` is the error code most likely to be a real defect, so every
instance was investigated individually. All 13:

| Location | Verdict |
| --- | --- |
| `controller/compensation.py:2770` | **Real defect — dead code, not a behaviour bug.** A 9-line block after `return`, byte-identical to `_net_congestion_undo`. `net.congestion` is fully wired at the dispatch table, so nothing was lost — but a future edit to the live congestion undo could be made in the dead copy and silently not take effect. **Removed.** |
| `agents/executors.py:508` | Not a bug. `UndoOp.args` is `dict[str, str]`, so `isinstance(params, dict)` in `_lease_fault_params` is provably dead. Guard kept (zero runtime cost, correct if the arg bag ever widens) by widening the local to `object`. |
| `cli/render.py:91` (x2) | Not a bug. `isinstance(value, str)` after `not isinstance(value, (int, float))` — a `str` is never an `int`/`float`, so the conjunct is dead. Removed. |
| `cli/next_cmd.py` (x2), `cli/coverage_cmd.py` (x2), `cli/explore.py` (x3) | Not bugs. All 7 were a bare `return` after `ctx.exit(...)`. `click.Context.exit` is annotated `NoReturn` and unconditionally raises `Exit`. **Removed.** |
| `cli/lifecycle.py:1427` | Not a bug. See the budget table above. Left in place. |

Found outside mypy, by an AST sweep for statements following an
unconditional `return`/`raise`: `domain/experiments.py:501` is a second
dead `raise` after a `raise` on line 500, the same copy-paste drift. Both
paths raise, so it is harmless, but it is the same class of defect and worth
a look.

## Deliberate deviations

- **`# type: ignore[call-arg]` x4** — `providers/builtin.py`, one per line
  covering 7 errors. pydantic's mypy plugin ignores `populate_by_name` (repro
  in the fix commit). The code is correct at runtime.
- **`# type: ignore[import-untyped]` x1** — `agents/executors.py`, the
  `kubernetes` SDK, which ships no `py.typed`.
- **1 error left unpinned-as-zero** — the `lifecycle.py` dead branch above.

Total `type: ignore` added in this lane: **5**, all with an inline reason,
none wider than the single error code they name.
