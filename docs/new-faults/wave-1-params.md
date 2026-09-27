# Wave 1 — retire 31 ids by widening existing params

**Adds 0 fault ids. Retires 31 requests.** Every change is a `params_schema`
entry plus a compensation builder branch. This is the highest
effort-to-capability ratio in the plan, and it should land first.

## Why this wave exists

Every fault in the catalog already carries typed, bounded params with defaults
(`ParamSpec`, `domain/faults.py:147-156`). The compensation builders are pure
functions of `(PlannedFault, nodes)` — they branch on
`fault.fault_id` and then read params. So the *correct* way to express "jitter",
"a backward clock jump", "an ingress block", or "a lock contention error" is a
param, not a new id. The repo has already done this deliberately twice:

- `net.latency` declares `jitter_ms` and appends it to the netem argv as a second
  token (`compensation.py:702-712`).
- `mem.exhaust` declares `mode: str = "allocate"` and raises
  `InvariantViolationError("fault_mode", "only 'allocate' exists")` for any other
  value (`compensation.py:216-220`) — the extension point was reserved on
  purpose.

Wave 1 completes that pattern for the rest.

## 1.1 The live bug: `db.query_error.error` is inert

`_db_query_error_undo` (`compensation.py:1744-1770`) reads only `probability`
and `port` and emits a netfilter REJECT on 3306. The declared
`error: str = "deadlock"` param is never read.

This is a real defect, not just a missed feature: the catalog advertises a
knob (`http.error_injection`-style fault selection is visible in
`mayhem discover faults`) that silently does nothing.

**Fix.** Branch on `error` in the compensation builder, mapping SQLSTATE
classes to distinct wire behaviour:

| `error` value | mechanism | undo |
| --- | --- | --- |
| `deadlock` (default, unchanged) | netfilter REJECT `tcp-reset` on 3306 | delete rule |
| `lock_timeout` | same, but hold the connection open for `timeout_ms` then reject — the client sees a timeout, not a reset | delete rule |
| `serialization_failure` | `tc netem delay` scoped to 3306 by `timeout_ms`, so the transaction fails client-side | `tc qdisc del` |
| `pool_exhaust` | alias of `db.connection_exhaust` payload | marker kill |

Add `timeout_ms: int = 5000 [100, 120000]` to the schema. This answers
`db.lock_contention`, `db.deadlock`, and `db.transaction_abort` with no new ids
and turns an advertised-but-dead param into working functionality.

## 1.2 Fix the `db.slow_query` / `db.query_timeout` contradiction

`db.slow_query` declares `seconds: duration` and ships
`_netfilter_undo("3306")` = `iptables -I OUTPUT -p tcp --dport 3306 -j DROP`
(`compensation.py:2244-2247`, builder at `:1154-1180`). A DROP is a
**blackhole**: the caller's query blocks until its own client-side timeout. That
is `db.query_timeout`, not a slow query.

**Fix.** Add `mode: "latency" \| "timeout"` (default `latency`, so the existing
name becomes true):

- `latency` → `tc qdisc add dev eth0 root netem delay <seconds>`, filtered to
  the 3306 flow with the ifb/mirred path already used by `_direction()`
  (`compensation.py:733-786`). Undo: `tc qdisc del`.
- `timeout` → today's DROP. Undo: delete rule.

Verification differs per mode: `mode=latency` verifies with
`! tc qdisc show dev eth0 | grep -q netem`; `mode=timeout` verifies with
`! iptables -S OUTPUT | grep -q -- '--dport 3306'`.

## 1.3 Param additions, by carrier

Every row is: add params to the `params_schema` entry in `catalog.py`, branch
in the corresponding compensation builder, and add one case to the argv/verify
matrix tests.

| carrier | new params | retires |
| --- | --- | --- |
| `fs.fill` | `path: str = "/tmp"` | `fs.temp_exhaust`, `fs.log_fill` |
| `fd.exhaust` | `mode: "exhaust" \| "leak" = "exhaust"` | `process.fd_leak` |
| `mem.exhaust` | activate the reserved `mode` (`allocate` \| `reclaim` \| `freeze`) | `mem.reclaim_pressure` |
| `fs.io_stress` | `op: "read" \| "write" \| "both" = "both"` | `fs.read_delay` |
| `db.query_error` | wire `error` + add `timeout_ms` | `db.lock_contention`, `db.deadlock`, `db.transaction_abort` |
| `db.slow_query` | `mode: "latency" \| "timeout"` | `db.query_timeout` |
| `db.connection_exhaust` | `port` default is already 3306; add `label: str = "db"` | `db.pool_exhaust`, `dependency.connection_pool_exhaust` |
| `net.latency` | already has `jitter_ms` — document it | `net.jitter` |
| `net.packet_loss` | `direction` already implemented — document it | `net.egress_block`, `net.ingress_block` |
| `clock.skew` | `offset_ms` already signed — document it | `clock.jump_forward`, `clock.jump_backward` |
| `http.error_injection` | `status` already unbounded — document it | `http.status_4xx`, `dependency.bad_status`, `dependency.auth_failure` |

`db.connection_exhaust` deserves a note: the payload is already
protocol-agnostic (`socket.create_connection((host, port), timeout=10)` × N,
held open, marker-addressed). It is byte-for-byte the primitive
`dependency.connection_pool_exhaust` asks for; only the default port and the
namespace differ. Adding a `label` param is cosmetic — the real work here is
deciding whether a `dependency.`-namespaced alias is worth it, and this plan
says no.

## 1.4 Verification matrix changes

New param branches change argv, so these tests need new cases:

- `tests/unit/test_container_fault_matrix.py` — `seeds_for()`
  (`:69-84`) must seed the new enums; add per-mode cases.
- `tests/unit/test_runtime_execution_matrix.py` — the `PAYLOAD_FAULTS` /
  `TOOL_FAULTS` buckets are **derived from `executor_for()`** (`:125-137`), so
  param branches are swept in automatically; add explicit argv assertions for
  the new modes.
- `tests/unit/test_impact_gate.py` — no change needed; no new fault ids, so
  `test_every_catalog_fault_is_classified_by_the_gate` (`:465-480`) is
  unaffected.
- New: a test that `db.query_error{error=deadlock}` and
  `db.query_error{error=serialization_failure}` produce **different** argv.
  This is the regression guard for the inert-param bug.

## 1.5 Docs

- `docs/fault-catalog/reliability-matrix.md` — the family table (`:30-39`)
  should gain rows for the now-documented param axes, so
  `clock.jump_forward` and `net.ingress_block` are discoverable as
  `clock.skew{offset_ms<0}` and `net.packet_loss{direction:ingress,...}`.
  Note this file also contains a dead pointer to
  `docs/reference/fault-catalog.md`, which does not exist.
- `docs/drill-spec.md` — document the new params alongside existing ones.
