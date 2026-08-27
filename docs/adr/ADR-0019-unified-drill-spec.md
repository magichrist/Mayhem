# ADR-0019: Unified Drill Spec Format

**Status:** Approved
**Date:** 2026-08-26
**Deciders:** Ali

## Context

Users must maintain two separate files to run chaos drills:
- `mayhem.yml` — config (risk ceiling, log level, profiles, rules)
- `full-fault.yml` — spec (steps, faults, constraints, target selectors)

The target selector syntax (`kind: process, expr: "name=download-1"`) is fragile — PIDs change, selectors break, and there's no explicit link between a compose container and the faults targeting it. The two-file system creates confusion about which file controls what, and keeping them synchronized is error-prone.

## Decision

A single `kind: drill` YAML file that embeds config, declares per-container faults, and specifies cross-container execution ordering.

### Target Format

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

### Key Rules

- `containers:` keys ARE the `container_name:` values from docker-compose.yml — this is the identity anchor
- `faults:` list runs sequentially within each container
- `execution:` controls cross-container ordering: `parallel`, `sequential`, `wait`, `check`
- `config:` replaces the separate `mayhem.yml` for drill contexts
- `check:` targets are resolved by container name → IP at check time
- Container names are mandatory — every service in docker-compose.yml must have `name:`

### Why Not Alternatives

| Alternative | Why Rejected |
|-------------|-------------|
| Two files (status quo) | Confusing, error-prone synchronization |
| Single file with `tests:` blocks | Over-nested, hard to read |
| Single file with `target:` declarations | Extra indirection — container name IS the target |

## Consequences

- **Single source of truth**: one file to author, version, and review
- **Zero ambiguity**: container name is the stable identity — no PID fragility
- **Explicit execution ordering**: visible at a glance how faults play out across containers
- **Config embedded**: no separate config file needed for drill contexts
- **Simpler parser**: one code path, not two
- **Breaking change**: old `kind: deterministic` format removed (see ADR-0021)
