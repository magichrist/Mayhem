# Safety Architecture

Full design record: [ADR-0012](../adr/0012-safety-model-environment-identity-and-risk-gates.md).
Principle: destructive power requires deliberate configuration at multiple layers, enforced
mechanically between planner and executor — never by convention.

---

## 1. Scope charter

Mayhem tests **authorized systems**. It contains no scanning, exploitation, or credential
primitives:

| In scope | Out of scope (forever) |
|---|---|
| Fault injection on owned infra | Vulnerability scanning |
| Schema-aware API fuzzing of owned services (Schemathesis) | Exploitation / payload work |
| Controlled load generation & saturation of owned endpoints | Attacking third parties |
| Dependency resilience testing (DB, queues) | Credential attacks |

Saturation experiments are load-generation faults governed by the risk ladder — the vocabulary is
resilience engineering, and the tool refuses targets outside configured environments.

## 2. Gate stack

Every fault invocation passes **five** mechanical gates; failing any one refuses with a typed,
logged reason (`safety.refused`):

```
G1 config policy      → allowlists/denylists, risk ceiling, env class rules
G2 plan validation    → compile-time: schema, budgets fit, capability availability, critical flags
G3 pre-exec assertion → resolved targets re-checked against live topology seconds before injection
G4 runtime enforcement→ scheduler caps concurrency; watchdog TTLs; abort matrix armed
G5 post-exec verify   → recovery verification probes must pass before release
```

Precedence: denylist beats allowlist beats selector beats default.

## 3. Environment identity

```text
fingerprint = SHA256( sorted(host set) + compose_file_digest + environment.name + environment.class )
```

- Stamped into every run row; mismatch at any phase ⇒ refuse.
- `environment.class` drives defaults: `production` ⇒ dry-run-first mandatory, `critical` risk hard
  -forbidden unless explicitly overridden in config *and* CLI.

## 4. Risk ladder enforcement points

| Level | Requirements |
|---|---|
| `low` | policy allowlist |
| `medium` | policy allowlist |
| `high` | explicit per-fault or category opt-in in policy |
| `critical` | policy opt-in **+** CLI `--allow-critical` on the command; `node.reboot` additionally requires it to be un-forbidden |

The ladder is checked at G2; a plan containing an unauthorized level fails compilation — Maniac
plans included ([ADR-0009](../adr/0009-maniac-deterministic-weighted-stochastic-planner.md) §6).

## 5. Blast-radius budgets

Computed from the live `TopologyGraph`, not guessed:

```yaml
blast_radius:
  max_services_pct: 50        # of services in graph
  max_hosts: 2
  max_concurrent_faults: 3
  max_duration_per_fault: 300s
  forbidden_pairs: [[storage.fill, db.conn_exhaust]]
```

The scheduler enforces `max_concurrent_faults` as a semaphore; candidate filtering uses the rest.
Dependency-aware scoring penalizes targeting nodes whose failure cascades beyond budget
(upstream dependents counted via DEPENDS_ON closure).

## 6. Abort matrix

| Trigger | Semantics |
|---|---|
| SIGINT | graceful: finish current step → recover all active leases → summarize |
| SIGUSR1 | immediate: cancel tasks → recover all → summarize |
| ABORT file `.mayhem/ABORT` | same as SIGUSR1; works for scheduled/headless runs |
| Steady-state breach (pre) | run skipped or aborted per check policy |
| Violation (during) | default `abort_and_recover` |

Recovery-on-abort uses the standard lease pipeline ([recovery.md](recovery.md)) — aborts never
bypass undo.

## 7. Audit log

Append-only `audit_log`: every privileged action recorded **before** execution —

```jsonc
{"ts": "...", "run": "r-…", "lease": "l-a1f3", "actor": "controller",
 "argv_digest": "…", "argv": ["iptables", "-A", "TGP-l-a1f3", …],
 "env_digest": "…", "host": "bm-1", "gate_chain": "G1✓ G2✓ G3✓"}
```

Env captures are redacted at capture time ([observation.md](observation.md) §7). The audit log is
never rewritten; corrections are appended.

## 8. Defaults that fail safe

- No config = no fault execution (empty allowlist refuses everything).
- Dry-run-first default for every new experiment target combination.
- Unknown fault id, unknown node kind, unknown env class ⇒ refuse (no wildcard fallbacks).
- Agent refusals propagate as refusals upstream — agents never auto-elevate privileges.
