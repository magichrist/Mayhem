# ADR-M4-1: Additive, non-breaking DSL sections + typed Duration
**Status:** Approved
**Date:** 2026-09-02
**Deciders:** Ali
**Relates to:** ADR-M3-3 (ExecutionContext), ADR-M4-5 (schema freeze), ADR-0019
## Context
M5's autonomous Maniac needs an observation/evaluation backbone: execution-locus
checks, machine-evaluable success criteria, and observability/metrics sources.
The drill DSL must grow to carry them, but the Q13 lock is that the existing
`containers:` + `execution:` grammar is the primary authoring path and must not
break. Separately, the review surfaced a real Duration bug: fields were typed
`float` while specs (and class defaults) pass `"3s"`/`"30m"` strings, so mypy
flagged the Duration paths as incompatible.
## Decision
- **Additive sections only.** Introduce optional top-level `checks`, `success`,
  and `observability` (reserve `metrics`) alongside `containers:` + `execution:`.
  `containers:` remains primary; a future `targets/operations` grammar is a
  documented convenience-target relationship, never a forced migration.
- **Typed `Duration` as `float | str`.** `Duration = Annotated[float | str, ...]`
  with a `BeforeValidator` that parses DSL strings (`"30s"`/`"5m"`/`"1h"`) to
  seconds and a `PlainSerializer` that emits seconds strings. The declared type
  is the union because Pydantic v2 returns an *un-passed class default* without
  running the validator — `DrillConfig().timeout == "30m"` (string) is asserted
  behaviour — so a string default must be type-valid. Explicitly supplied values
  are coerced to `float` at validation time, so arithmetic consumers that
  `float(...)` their duration still see floats.
- **Runtime behaviour unchanged.** YAML authoring stays string-friendly; specs
  parse identically; existing `test_drill_spec` assertions are untouched.
## Consequences
Mypy is clean on `experiments.py`/`planner.py`/`common.py`/`load_strategy.py`
Duration paths with no behavioural change to existing specs. New check/success/
observability sections are additive and versioned via ADR-M4-5.
