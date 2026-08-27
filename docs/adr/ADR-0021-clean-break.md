# ADR-0021: Clean Break from Step-Based Spec

**Status:** Approved
**Date:** 2026-08-26
**Deciders:** Ali

## Context

The existing `kind: deterministic` format with `inject_fault:` steps and target selectors (`kind: process, expr: "name=download-1"`) is being replaced by `kind: drill` (ADR-0019). The old format has fundamental issues:

1. **Fragile selectors**: `name=download-1` relies on process names which can change
2. **Stale PIDs**: target resolution happens at plan time, but PIDs change by execution time
3. **Two file system**: requires separate config and spec files
4. **Complex step types**: `inject_fault`, `wait`, `check`, `start_load`, `stop_load`, `notify`, `parallel`, `batch` — most unused in practice
5. **Dead code**: many step types have no real executor implementation

Maintaining both formats doubles the test surface and creates confusion about which format to use.

## Decision

Remove `kind: deterministic` and `kind: random` entirely. `kind: drill` is the only supported spec kind. This is a clean, immediate break — no deprecation period.

### What is Removed

| Component | Location | Reason |
|-----------|----------|--------|
| `DeterministicExperiment` | `domain/experiments.py` | Replaced by `DrillSpec` |
| `RandomExperiment` | `domain/experiments.py` | No equivalent in drill model |
| `ExperimentKind` enum | `domain/experiments.py` | Single kind: `drill` |
| `Step` model | `domain/experiments.py` | Replaced by `ExecutionStep` |
| `StepAction` union | `domain/experiments.py` | Actions embedded in `ExecutionStep` |
| `InjectFault` model | `domain/experiments.py` | Replaced by `DrillFault` |
| `StartLoad`, `StopLoad`, `Notify` | `domain/experiments.py` | Not supported in v1 drill |
| `Parallel` model | `domain/experiments.py` | Replaced by `ExecutionStep.parallel` |
| `plan_deterministic()` | `controller/planner.py` | Replaced by `plan_drill()` |
| `plan_random()` | `controller/planner.py` | No random drills in v1 |
| `_plan_action()` | `controller/planner.py` | Old action dispatch |
| `_resolve_targets()` | `controller/planner.py` | Old selector resolution |
| `_resolve_target()` | `controller/planner.py` | Old expression parser |
| `parse_selector()` | `domain/topology.py` | Old selector expressions |
| `_normalize()` | `spec.py` | Old step shorthand expansion |
| `_ACTION_KEYS` | `spec.py` | Old action registry |
| `load_spec()` / `parse_spec()` | `spec.py` | Old spec loading path |
| `--process`, `--service`, `--host` | `cli/lifecycle.py` | Drill specs are compose-native |

### What is Kept

| Component | Reason |
|-----------|--------|
| `ExecutionPlan` | Same plan shape — drill compiles to it |
| `PlannedStep`, `PlannedFault`, `ResolvedTarget` | Same intermediate representation |
| `LeaseClient` | Fault lifecycle unchanged |
| Compensation templates | Undo/verify unchanged (receives live PID) |
| Event journal | Same event model |
| `SafetyContext` | Plan validation unchanged |
| `ProcPauseExecutor` | Same injection mechanism (receives live PID) |
| `ToolExecutor` | Same tool dispatch |
| `NoopExecutor` | Same no-op path |
| All toolkit scripts | Same fault implementations |

### CLI Changes

The `--process`, `--service`, and `--host` options are removed from the root CLI group. Drill specs are compose-native — the topology comes from the compose file, not from CLI flags. The `--compose` option remains as the sole topology source.

```bash
# Old (removed):
mayhem run full-fault.yml --process download-1=1234 --compose docker-compose.yml

# New:
mayhem run mayhem.yaml --compose docker-compose.yml
```

## Consequences

- **Simpler spec parser**: one code path, not two
- **Simpler planner**: no selector resolution, just validate container names exist
- **Smaller test surface**: old format tests removed
- **Clear mental model**: one format, one way to author drills
- **No migration path**: old specs must be rewritten — but they were broken anyway
- **Temporary breakage**: tests referencing old models will fail until updated (Phase 8)
