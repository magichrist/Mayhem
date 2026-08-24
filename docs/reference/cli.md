# CLI Reference

Single entrypoint `mayhem` (Typer). Every command honors `--config`, `--dry-run` where meaningful,
and prints structured output (`--json` flag on read commands).

---

## Lifecycle

```bash
mayhem init                          # scaffold .mayhem/mayhem.yaml + sample experiment;
                                     # safe defaults: dry-run-first, empty allowlist
mayhem validate [EXPERIMENT]         # compile plan; run all safety gates G1–G2
mayhem run EXPERIMENT.yaml           # execute; streams journal to stdout
mayhem run --fault net.latency --target service:api \
           --params '{"delay":"200ms"}' --duration 30s   # manual single fault (dev)
mayhem watch RUN_ID                  # tail an active run
```

Common `run` flags: `--seed N`, `--dry-run` (compile+validate+print plan only),
`--allow-critical` (required for critical faults), `--yes` (skip approval prompts when policy
allows).

## Agents

```bash
mayhem agents install --host user@bm-1 [--host …]   # bootstrap over SSH (venv, systemd unit)
mayhem agents status                 # table: host, roles, state, capabilities summary
mayhem agents probe --host bm-1      # refresh CapabilityReport
```

## Topology

```bash
mayhem topology show [--format graph|table|json]    # merged TopologyGraph
mayhem topology drift                # blueprint vs live diff
mayhem topology targets 'service:api'   # resolve a selector, show what it matches
```

## Recovery & ops

```bash
mayhem recover [--dry-run]           # sweep non-terminal leases (janitor escape hatch)
mayhem abort RUN_ID                  # write ABORT signal (equivalent of SIGUSR1)
mayhem db prune --older-than 90d
```

## Maniac

```bash
mayhem maniac generate               # produce a RandomExperiment plan (no execution)
mayhem maniac explain RUN_ID         # candidates, scores, weights, RNG state — why this fault?
mayhem maniac run                    # generate → gate → execute (respects approval policy)
```

## Introspection

```bash
mayhem faults list [--category net] [--risk medium]
mayhem faults describe net.partition  # schema, backends, caps, risk ladder position
mayhem tools status                  # per-host tool availability matrix
mayhem config show | validate | migrate
mayhem runs list | mayhem runs show RUN_ID [--timeline] [--evaluations]
mayhem dev coverage-matrix           # regenerate docs/fault-catalog/matrix.md
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | runtime failure (fault/step error) |
| 2 | validation/safety refusal |
| 3 | recovery incomplete (`dirty`) |
| 130 | interrupted (SIGINT) — after graceful recovery |

All refusals print the failing gate ([safety.md](../architecture/safety.md) §2) and the exact rule
that refused.
