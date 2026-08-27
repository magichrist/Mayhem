# Plan: Drill Spec DSL + Container-Name PID Resolution

> Status: Approved
> Date: 2026-08-26
> ADRs: ADR-0019, ADR-0020, ADR-0021

## Summary

Three coupled architectural changes to Mayhem:

1. **Unified Drill Spec DSL** (`kind: drill`) — single YAML replacing both `mayhem.yml` config and step-based fault specs
2. **Container-name-first resolution** — PIDs and IPs resolved at execution time via `container_name`, not at topology discovery
3. **Clean break** — old `kind: deterministic`/`kind: random` formats removed

## Target Drill Spec Format

```yaml
kind: drill
name: full-fault-drill
hypothesis: "Stack recovers from every implemented fault"

config:
  risk_ceiling: critical
  max_faults: 1
  timeout: 30m
  log_level: INFO

containers:
  testcase-api:
    faults:
      - fault: proc.pause
        duration: 10s
        on_failure: abort_and_recover

  testcase-download-1:
    faults:
      - fault: proc.pause
        duration: 10s

  testcase-redis:
    faults:
      - fault: node.service_stop
        duration: 15s

  testcase-lb:
    faults:
      - fault: net.partition
        duration: 5s
        targets:
          - testcase-api
          - testcase-download-1

execution:
  - parallel: [testcase-api, testcase-download-1]
  - wait: 5s
  - check:
      - http: http://testcase-api:8080/
        expect: { status: 200 }
  - sequential: [testcase-redis]
  - wait: 3s
  - check:
      - http: http://testcase-api:8080/
        expect: { status: 200 }
```

## Design Rules

- `containers:` keys ARE the `container_name:` values from docker-compose.yml — identity anchor
- `faults:` list runs sequentially within each container
- `execution:` controls cross-container ordering: `parallel`, `sequential`, `wait`, `check`
- `config:` replaces the separate `mayhem.yml` for drill contexts
- `check:` targets resolved by container name → IP at check time
- PID is never older than the injection syscall — resolved in `_execute_fault()` immediately before injection
- Container names are mandatory — every service in docker-compose.yml must have `name:`

---

## Phase 1: Domain Models — New Spec Types

### Goal
Define all Pydantic models for the drill spec DSL and update the topology model.

### Files to Create/Modify

#### `src/mayhem/domain/experiments.py`
- **ADD** new models at the bottom of the file:

```python
class DrillConfig(BaseModel):
    model_config = ConfigDict(frozen=True)
    risk_ceiling: RiskLevel = RiskLevel.HIGH
    max_faults: int = Field(default=1, ge=0)
    timeout: Duration = "30m"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"


class DrillFault(BaseModel):
    model_config = ConfigDict(frozen=True)
    fault: str  # fault id: "proc.pause", "net.partition", etc.
    duration: Duration = "10s"
    on_failure: OnFailure = OnFailure.ABORT_AND_RECOVER
    targets: tuple[str, ...] = ()  # for network faults: container names to partition
    # fault-specific extra params stored via model_config extra="allow"


class DrillContainer(BaseModel):
    model_config = ConfigDict(frozen=True)
    faults: tuple[DrillFault, ...] = ()


class CheckExpectation(BaseModel):
    model_config = ConfigDict(frozen=True)
    status: int | None = None


class CheckProbe(BaseModel):
    model_config = ConfigDict(frozen=True)
    http: str | None = None
    expect: CheckExpectation = CheckExpectation()


class ExecutionStep(BaseModel):
    model_config = ConfigDict(frozen=True)
    parallel: tuple[str, ...] | None = None
    sequential: tuple[str, ...] | None = None
    wait: Duration | None = None
    check: tuple[CheckProbe, ...] | None = None


class DrillSpec(BaseModel):
    model_config = ConfigDict(frozen=True)
    kind: Literal["drill"]
    name: str
    hypothesis: str = ""
    config: DrillConfig = DrillConfig()
    containers: dict[str, DrillContainer]  # key = container_name
    execution: tuple[ExecutionStep, ...]
```

- **REMOVE** (or keep as dead code for reference): nothing yet — cleanup in Phase 8

#### `src/mayhem/domain/topology.py`
- **MODIFY** `ProcessNode` (line 74):
  - Change `pid: int` → `pid: int | None = None`
  - Add `container_name: str | None = None`
- **MODIFY** `ContainerNode` (line 54):
  - Add `container_name: str | None = None`

#### `src/mayhem/spec.py`
- **ADD** new function `load_drill(path)` and `parse_drill(data)`:

```python
def load_drill(path: str | Path) -> DrillSpec:
    """Load a drill spec from YAML."""
    raw_path = Path(path)
    if not raw_path.is_file():
        raise FileNotFoundError(f"spec file not found: {raw_path}")
    try:
        data = yaml.safe_load(raw_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SchemaValidationError("drill", f"invalid YAML: {exc}") from None
    return parse_drill(data)


def parse_drill(data: Any) -> DrillSpec:
    if not isinstance(data, dict):
        raise SchemaValidationError("drill", "top level must be a mapping")
    if data.get("kind") != "drill":
        raise SchemaValidationError("drill", f"expected kind: drill, got: {data.get('kind')}")
    try:
        return DrillSpec.model_validate(data)
    except ValidationError as exc:
        raise SchemaValidationError("drill", str(exc)) from None
```

- **MODIFY** `parse_spec()` — keep for now but add deprecation warning for `kind: deterministic`/`kind: random`

### Tests to Create/Modify

#### `tests/unit/test_drill_spec.py` (NEW)
- Test `parse_drill()` with valid spec → returns `DrillSpec`
- Test missing required fields → `SchemaValidationError`
- Test `kind: drill` required
- Test `containers` must be non-empty dict
- Test `execution` must be non-empty tuple
- Test `DrillFault` defaults (duration=10s, on_failure=abort_and_recover)
- Test `DrillConfig` defaults (risk_ceiling=HIGH, timeout=30m)
- Test frozen models (immutable after creation)

#### `tests/unit/test_topology.py` (MODIFY)
- Test `ProcessNode` with `pid=None` and `container_name` set
- Test `ContainerNode` with `container_name` set

### Verification
```bash
python -m pytest tests/unit/test_drill_spec.py -v
python -m pytest tests/unit/test_topology.py -v
```

---

## Phase 2: Container Name Enforcement

### Goal
Every container in the topology graph must have a `container_name`. Docker-compose.yml must use explicit `name:` fields. Topology discovery validates this.

### Files to Create/Modify

#### `src/mayhem/topology/providers/docker_runtime.py`
- **MODIFY** `_inspect_container()` or equivalent discovery method:
  - When constructing `ContainerNode`: extract the container name from `docker inspect` output (`.Name` field, which returns `/container-name`, strip the leading `/`)
  - Set `container_name=clean_name` on `ContainerNode`
  - When constructing `ProcessNode`: set `container_name` from the parent container's name

- **MODIFY** discovery to store the container name from inspect:

```python
# In the container loop:
raw_name = inspect_data.get("Name", "")  # "/testcase-api"
container_name = raw_name.lstrip("/")  # "testcase-api"

node = ContainerNode(
    ...,
    container_name=container_name,
)
```

- When creating `ProcessNode` for the main process:
```python
ProcessNode(
    ...,
    container_name=container_name,
    pid=None,  # deferred — resolved at execution time
)
```

#### `src/mayhem/topology/providers/compose.py`
- **MODIFY** `_parse_services()` or equivalent:
  - Extract the `name:` field from each service definition
  - Store it on `ServiceNode` or use it as the canonical name
  - Compose services with `name: testcase-api` → the container should match `container_name=testcase-api`

#### `src/mayhem/topology/service.py`
- **MODIFY** `TopologyService.discover()` (line 26):
  - After merging fragments, validate that every `ContainerNode` has a non-empty `container_name`
  - If missing, add to `errors` list with a clear message:

```python
for node in nodes.values():
    if isinstance(node, ContainerNode) and not node.container_name:
        errors.append(
            f"container {node.id} (service={node.service_name}) has no container_name — "
            "add 'name:' to docker-compose.yml"
        )
```

#### `examples/testCase/docker-compose.yml`
- **MODIFY** — add `name:` to every service:

```yaml
services:
  api:
    name: testcase-api
    # ... rest unchanged

  web:
    name: testcase-web
    # ...

  download-1:
    name: testcase-download-1
    # ...

  download-2:
    name: testcase-download-2
    # ...

  lb:
    name: testcase-lb
    # ...

  redis:
    name: testcase-redis
    # ...

  postgres:
    name: testcase-postgres
    # ...

  init:
    name: testcase-init
    # ...
```

### Tests to Create/Modify

#### `tests/unit/test_topology_providers.py` (MODIFY)
- Test `ContainerNode` includes `container_name` from inspect output
- Test `ProcessNode` includes `container_name` from parent container
- Test missing `container_name` in compose produces error in `TopologyService.discover()`

#### `tests/unit/test_topology.py` (MODIFY)
- Test graph with all containers having `container_name` → no errors
- Test graph with one container missing `container_name` → error in drift/errors

### Verification
```bash
python -m pytest tests/unit/test_topology_providers.py -v
python -m pytest tests/unit/test_topology.py -v
```

---

## Phase 3: PID/IP Resolution Module

### Goal
New module that resolves PID and IP from container names at execution time. Single `inspect` call per container.

### Files to Create

#### `src/mayhem/topology/resolve.py` (NEW)

```python
"""Container resolution — get current PID and IP from container names.

Called at execution time, not discovery time. PID is never older than
the injection syscall.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class ContainerInfo:
    pid: int
    ip_address: str
    state: str  # "running", "exited", etc.


def _inspect(engine: str, container_name: str, fmt: str) -> str:
    """Run engine inspect with a format string."""
    cmd = [engine, "inspect", "--format", fmt, container_name]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        raise RuntimeError(f"{engine} inspect failed for {container_name}: {result.stderr.strip()}")
    return result.stdout.strip()


def resolve_pid(container_name: str, engine: str | None = None) -> int:
    """Get the current host PID for a named container."""
    engine = engine or _detect_engine()
    out = _inspect(engine, container_name, "{{.State.Pid}}")
    pid = int(out)
    if pid <= 0:
        raise RuntimeError(f"container {container_name} has no running process (pid={pid})")
    return pid


def resolve_ip(container_name: str, engine: str | None = None) -> str:
    """Get the current IP address for a named container."""
    engine = engine or _detect_engine()
    fmt = "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
    ip = _inspect(engine, container_name, fmt)
    if not ip:
        raise RuntimeError(f"container {container_name} has no IP address")
    return ip


def resolve_container(container_name: str, engine: str | None = None) -> ContainerInfo:
    """Resolve PID + IP + state in a single inspect call."""
    engine = engine or _detect_engine()
    fmt_pid = "{{.State.Pid}}"
    fmt_ip = "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
    fmt_state = "{{.State.Status}}"
    pid = int(_inspect(engine, container_name, fmt_pid))
    ip = _inspect(engine, container_name, fmt_ip)
    state = _inspect(engine, container_name, fmt_state)
    return ContainerInfo(pid=pid, ip_address=ip, state=state)


def _detect_engine() -> str:
    """Return 'podman' or 'docker', preferring podman."""
    for engine in ("podman", "docker"):
        if shutil.which(engine):
            return engine
    raise RuntimeError("neither podman nor docker found in PATH")
```

### Files to Modify

#### `src/mayhem/controller/executor.py`
- **MODIFY** `RunEngine.__init__()`:
  - Add `engine: str | None = None` parameter (podman/docker)
  - Store as `self._engine`

- **MODIFY** `_execute_fault()` (line 232):
  - Before calling the fault executor, resolve PID/IP for each target:

```python
from mayhem.topology.resolve import resolve_container


def _execute_fault(self, plan, step):
    # ... existing setup ...

    # Resolve fresh PID/IP for each target container
    for target in fault.targets:
        for node_id in target.node_ids:
            node = self._get_node(node_id)
            if isinstance(node, ProcessNode) and node.container_name:
                try:
                    info = resolve_container(node.container_name, self._engine)
                    # Update the node's PID — fresh, just-in-time
                    # (we work on a mutable copy or pass resolved info)
                except RuntimeError as exc:
                    return StepReport(step.id, False, f"PID resolution failed: {exc}"), []
```

- **IMPORTANT**: Since topology nodes are frozen Pydantic models, we cannot mutate `node.pid`. Instead, pass the resolved PID directly to the executor. Modify the executor interface:

```python
# In _execute_fault(), build a ResolvedTarget with fresh PID:
@dataclass
class LiveTarget:
    node_id: str
    pid: int  # fresh, just resolved
    ip_address: str  # fresh, just resolved
    container_name: str
```

- Build `LiveTarget` list from resolved containers, pass to fault executor

#### `src/mayhem/agents/executors.py`
- **MODIFY** `ProcPauseExecutor.inject()` signature:
  - Instead of reading `target.pid` from `TopologyNode`, receive a `LiveTarget` with resolved PID
  - `os_kill(target.pid, signal.SIGSTOP)` → `os_kill(live_target.pid, signal.SIGSTOP)`

- **MODIFY** `ProcPauseExecutor.undo()`:
  - Same: receive live PID from the lease record (undo_argv already stores it)

#### `src/mayhem/controller/compensation.py`
- **MODIFY** `_proc_pause_undo()` and `_proc_pause_verify()`:
  - These currently read `proc.pid` from frozen topology node
  - Change to: receive the PID as a parameter (already stored in the undo op args)

### Tests to Create

#### `tests/unit/test_resolve.py` (NEW)
- Mock `subprocess.run` for `podman inspect` calls
- Test `resolve_pid()` returns correct PID
- Test `resolve_ip()` returns correct IP
- Test `resolve_container()` returns `ContainerInfo`
- Test container not found → `RuntimeError`
- Test container stopped → `RuntimeError` (pid <= 0)
- Test engine detection (podman preferred over docker)
- Test timeout handling

### Verification
```bash
python -m pytest tests/unit/test_resolve.py -v
```

---

## Phase 4: Planner Rewrite

### Goal
Replace step-based planner with drill-aware planner. Compile `DrillSpec` into `ExecutionPlan` steps.

### Files to Create/Modify

#### `src/mayhem/controller/planner.py`
- **ADD** new function `plan_drill()`:

```python
def plan_drill(
    run_id: str,
    spec: DrillSpec,
    graph: TopologyGraph,
    *,
    config_snapshot_id: str,
    topology_snapshot_id: str,
    environment_fingerprint: str,
    engine: str = "podman",
) -> ExecutionPlan:
    """Compile a DrillSpec into an ExecutionPlan."""
    steps: list[PlannedStep] = []
    seq = 0

    # Validate: every container name in spec must exist in graph
    _validate_container_names(spec, graph)

    for block in spec.execution:
        if block.parallel:
            # One step per container — executor will run them concurrently
            for container_name in block.parallel:
                step = _plan_container_faults(
                    run_id,
                    seq,
                    container_name,
                    spec.containers[container_name],
                    graph,
                    engine,
                )
                steps.append(step)
                seq += 1

        elif block.sequential:
            for container_name in block.sequential:
                step = _plan_container_faults(
                    run_id,
                    seq,
                    container_name,
                    spec.containers[container_name],
                    graph,
                    engine,
                )
                steps.append(step)
                seq += 1

        elif block.wait is not None:
            steps.append(
                PlannedStep(
                    id=f"wait-{seq:04d}",
                    seq=seq,
                    raw_action=StepActionWait(type="wait", duration=block.wait),
                    fault=None,
                )
            )
            seq += 1

        elif block.check:
            for i, probe in enumerate(block.check):
                steps.append(
                    PlannedStep(
                        id=f"check-{seq:04d}-{i}",
                        seq=seq,
                        raw_action=StepActionCheck(
                            type="check", url=probe.http, expect=probe.expect
                        ),
                        fault=None,
                    )
                )
                seq += 1

    # Build plan
    ended_iso = utc_now().isoformat()
    return ExecutionPlan(
        run_id=run_id,
        kind=ExperimentKind.DRILL,
        spec_snapshot=json.dumps(spec.model_dump(mode="json"), sort_keys=True),
        config_snapshot_id=config_snapshot_id,
        topology_snapshot_id=topology_snapshot_id,
        environment_fingerprint=environment_fingerprint,
        steps=tuple(steps),
        created_at=ended_iso,
    )


def _validate_container_names(spec: DrillSpec, graph: TopologyGraph) -> None:
    """Every container name in the spec must exist in the topology."""
    graph_names = {
        node.container_name
        for node in graph.nodes.values()
        if isinstance(node, ContainerNode) and node.container_name
    }
    for container_name in spec.containers:
        if container_name not in graph_names:
            raise PlanningError(
                f"container '{container_name}' in spec not found in topology — "
                f"available: {sorted(graph_names)}"
            )
    # Also validate execution block references
    for block in spec.execution:
        for name in (block.parallel or ()) + (block.sequential or ()):
            if name not in spec.containers:
                raise PlanningError(
                    f"execution references container '{name}' not defined in containers:"
                )


def _plan_container_faults(
    run_id: str,
    seq: int,
    container_name: str,
    container: DrillContainer,
    graph: TopologyGraph,
    engine: str,
) -> PlannedStep:
    """Create a PlannedStep for a container's fault list."""
    # Build a PlannedFault per DrillFault
    faults = []
    for drill_fault in container.faults:
        # Resolve the container node from graph
        target_node = _find_container_node(graph, container_name)
        # Build PlannedFault with compensation
        planned = PlannedFault(
            fault_id=drill_fault.fault,
            duration=drill_fault.duration,
            targets=(
                ResolvedTarget(
                    selector=TargetSelector(kind="container", expr=container_name),
                    node_ids=frozenset([target_node.id]),
                ),
            ),
            undo_ops=...,  # from compensation template
            verify_probes=...,  # from compensation template
            inject_argv=...,  # built by executor, not planner
            engine=engine,
        )
        faults.append(planned)

    return PlannedStep(
        id=f"{container_name}-{seq:04d}",
        seq=seq,
        raw_action=...,
        fault=faults[0] if len(faults) == 1 else None,  # or merge
    )
```

- **REMOVE** (keep for reference until Phase 8):
  - `plan_deterministic()` — can be deleted or marked deprecated
  - `plan_random()` — same
  - `_plan_action()` — old action dispatch
  - `_resolve_targets()` — old selector resolution

#### `src/mayhem/domain/experiments.py`
- **MODIFY** `ExecutionPlan`:
  - Add `kind: ExperimentKind` field with value for drill
  - Or reuse existing: the plan shape stays the same, just the compilation path changes

### Tests to Create/Modify

#### `tests/unit/test_planner.py` (REWRITE)
- Test `plan_drill()` with valid spec → returns `ExecutionPlan`
- Test missing container name in spec → `PlanningError`
- Test execution block references undefined container → `PlanningError`
- Test `parallel` block → multiple steps with sequential seq numbers
- Test `sequential` block → steps in order
- Test `wait` block → wait step with correct duration
- Test `check` block → check steps with URL and expectation
- Test empty execution → empty plan (or error)

### Verification
```bash
python -m pytest tests/unit/test_planner.py -v
```

---

## Phase 5: Executor Rewrite

### Goal
Executor handles drill execution model: parallel container faults, wait, check. Resolves PIDs just before injection.

### Files to Modify

#### `src/mayhem/controller/executor.py`
- **MODIFY** `RunEngine.__init__()`:
  - Add `engine: str | None = None` parameter
  - Store as `self._engine`

- **MODIFY** `execute()` method:
  - The iteration over `plan.steps` stays the same
  - But steps now may have `parallel` flag from the planner
  - For parallel steps: collect all steps with same `seq`, run concurrently

- **MODIFY** `_execute_fault()`:
  - Before calling fault executor, resolve PID/IP:

```python
def _execute_fault(self, plan, step):
    fault = step.fault
    # Resolve live PID for each target
    live_targets = []
    for target in fault.targets:
        for node_id in target.node_ids:
            node = self._get_node(node_id)
            if isinstance(node, ProcessNode) and node.container_name:
                info = resolve_container(node.container_name, self._engine)
                live_targets.append(
                    LiveTarget(
                        node_id=node_id,
                        pid=info.pid,
                        ip_address=info.ip_address,
                        container_name=node.container_name,
                    )
                )
            elif isinstance(node, ProcessNode) and node.pid is not None:
                # Fallback: use pre-resolved PID (non-compose mode)
                live_targets.append(
                    LiveTarget(
                        node_id=node_id,
                        pid=node.pid,
                        ip_address="",
                        container_name=node.container_name or "",
                    )
                )

    # Pass live_targets to executor
    executor = executor_for(fault.fault_id)
    report = executor.inject(fault, live_targets, ...)
    # ...
```

- **ADD** parallel execution support:
```python
def _execute_parallel(self, plan, steps):
    """Run multiple fault steps concurrently using threads."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    with ThreadPoolExecutor(max_workers=len(steps)) as pool:
        futures = {pool.submit(self._run_step, plan, step): step for step in steps}
        reports = []
        for future in as_completed(futures):
            report, dirty = future.result()
            reports.append(report)
            # ...
```

### Tests to Modify

#### `tests/unit/test_executor.py` (MODIFY)
- Test `_execute_fault()` resolves PID before injection
- Test PID resolution failure → step fails cleanly
- Test parallel execution of multiple container faults
- Test wait step sleeps correctly
- Test check step verifies HTTP endpoint

### Verification
```bash
python -m pytest tests/unit/test_executor.py -v
```

---

## Phase 6: CLI Updates

### Goal
CLI commands (`validate`, `plan`, `run`) use the new drill spec format.

### Files to Modify

#### `src/mayhem/cli/lifecycle.py`
- **MODIFY** `validate` command:
  - Load drill spec via `load_drill()`
  - Build graph from compose
  - Validate container names exist in graph
  - Print validation result

- **MODIFY** `plan` command:
  - Load drill spec via `load_drill()`
  - Build graph from compose
  - Call `plan_drill()` to compile
  - Print execution plan as JSON

- **MODIFY** `run` command:
  - Load drill spec via `load_drill()`
  - Build graph from compose
  - Call `plan_drill()` to compile
  - Create `RunEngine` with `engine=engine`
  - Execute and print result

- **SIMPLIFY** topology options:
  - Remove `--process`, `--service`, `--host` options
  - Keep only `--compose` (drill specs are compose-native)
  - If `--compose` not given, auto-detect in cwd

#### `src/mayhem/cli/services.py`
- **MODIFY** `prepare()`:
  - Simplified: only compose-based topology
  - Remove `--process`, `--service`, `--host` handling

- **MODIFY** `plan_from_spec()`:
  - Call `plan_drill()` instead of `plan_deterministic()`
  - Pass `engine` parameter

- **MODIFY** `engine_for()`:
  - Pass `engine` string to `RunEngine`

#### `src/mayhem/cli/app.py`
- **MODIFY** global options:
  - Remove `--process`, `--service`, `--host` from root group if present
  - Keep `--db`, `--config`, `--profile`, `--allow-critical`, `--podman`

### Tests to Modify

#### `tests/e2e/test_cli_e2e.py` (REWRITE)
- Test full drill workflow:
  1. `mayhem validate drill.yml --compose docker-compose.yml` → success
  2. `mayhem plan drill.yml --compose docker-compose.yml` → prints plan JSON
  3. `mayhem run drill.yml --compose docker-compose.yml` → executes and prints result
- Test validation failure: missing container name → clear error
- Test plan failure: container not in topology → clear error

### Verification
```bash
python -m pytest tests/e2e/test_cli_e2e.py -v
```

---

## Phase 7: Example + Documentation

### Goal
Working example, ADRs documented, DSL reference written.

### Files to Create

#### `examples/testCase/drill.yml` (NEW)
Complete drill spec for the testCase compose stack — uses the target format from the top of this document.

#### `docs/adr/ADR-0019-unified-drill-spec.md` (NEW)
- Context: two-file system is confusing
- Decision: single `kind: drill` YAML
- Consequences: simpler authoring, single source of truth

#### `docs/adr/ADR-0020-container-name-pid-resolution.md` (NEW)
- Context: PIDs stale after container restart
- Decision: resolve at execution time via container name
- Consequences: fault injection always uses fresh PIDs

#### `docs/adr/ADR-0021-clean-break.md` (NEW)
- Context: old format broken and confusing
- Decision: remove `kind: deterministic`/`kind: random`
- Consequences: clean slate, simpler codebase

#### `docs/drill-spec.md` (NEW)
DSL reference:
- All fields with types and defaults
- Container name requirements
- Execution block semantics (parallel, sequential, wait, check)
- Fault catalog (proc.pause, net.partition, node.service_stop, etc.)
- Three complete examples (basic, full, network-partition)

### Files to Modify

#### Justfile
- **MODIFY** `run` recipe:
  ```makefile
  run: setup
      @echo "=== run ==="
      mayhem --db {{ _db }} run examples/testCase/drill.yml --compose examples/testCase/docker-compose.yml
      @echo "✓ run"
  ```

- **MODIFY** `full` recipe to use `drill.yml` instead of `full-fault.yml`

### Verification
```bash
just full
```

---

## Phase 8: Test Cleanup

### Goal
Remove dead code, old models, old test fixtures.

### Files to Remove
- `examples/testCase/full-fault.yml` (old spec — replaced by `drill.yml`)
- `examples/testCase/mayhem.yml` (old config — embedded in drill spec)

### Files to Modify
- `src/mayhem/domain/experiments.py`:
  - Remove `DeterministicExperiment`, `RandomExperiment` models
  - Remove `ExperimentKind` enum (or rename to just `DRILL`)
  - Remove `Step`, `StepAction`, `InjectFault`, etc. (old step types)
- `src/mayhem/controller/planner.py`:
  - Remove `plan_deterministic()`, `plan_random()`
  - Remove `_plan_action()`, `_resolve_targets()`, `_resolve_target()`
- `src/mayhem/spec.py`:
  - Remove `parse_spec()` old path (or keep as deprecated)
  - Remove `_normalize()` step shorthand expansion
  - Remove `_ACTION_KEYS` dict

### Tests to Clean
- Remove tests that reference `DeterministicExperiment`, `RandomExperiment`
- Remove tests that use old spec format fixtures
- Update `tests/unit/test_config.py` if config interface changed

### Verification
```bash
python -m pytest tests/ -v
just e2e
```

---

## Dependency Graph

```
Phase 1 (domain models)
  └─→ Phase 2 (container names)
       └─→ Phase 3 (resolve module)
            └─→ Phase 4 (planner)
                 └─→ Phase 5 (executor)
                      └─→ Phase 6 (CLI)
                           └─→ Phase 7 (docs + examples)
                                └─→ Phase 8 (cleanup)
```

Each phase must be complete and tests passing before the next begins.

## Verification After Each Phase

```bash
# After every phase:
python -m pytest tests/ -v

# After Phase 7:
just full

# Final:
just e2e
```
