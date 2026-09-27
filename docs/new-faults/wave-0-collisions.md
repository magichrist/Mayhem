# Wave 0 — collision decisions

No fault ids are added here. These are the questions that must be answered
before wave 1, because the answer changes what wave 1 and 2 build.

## 0.1 The 31 near-duplicates, grouped by the decision they need

Full per-id evidence is in the table at the bottom. Grouped:

### Group A — "this already exists, do not add an id" (10 ids)

The mechanism is implemented and reachable **today** with a param that is
already declared. Adding an id would be a second name for the same argv.

| requested | already covered by | evidence |
| --- | --- | --- |
| `net.jitter` | `net.latency{jitter_ms}` | `jitter_ms: int = 0` declared, no bounds, appended as netem token 2 (`compensation.py:702-712`) |
| `clock.jump_forward` | `clock.skew{offset_ms > 0}` | `offset_ms` is **required and signed**; implemented as a step, not a rate (`compensation.py:2100-2143`) |
| `clock.jump_backward` | `clock.skew{offset_ms < 0}` | same; undo restores the exact prior epoch |
| `net.egress_block` | `net.packet_loss{percent:100, direction:egress}` | `_direction()` + full egress/ingress/both path (`compensation.py:733-786`) |
| `net.ingress_block` | `net.packet_loss{percent:100, direction:ingress}` | same, ifb/mirred ingress |
| `http.status_4xx` | `http.error_injection{status:4xx}` | `status: int = 500` with **no min/max**; contrast `app.response_5xx` whose status is clamped `[500,599]` |
| `dependency.bad_status` | `http.error_injection{status}` | `http.error_injection` already targets `external_dependency` |
| `dependency.auth_failure` | `http.error_injection{status:401\|403}` | unbounded status; `canned()` clamps only at `>= 100` |
| `http.connection_close` | `net.connection_reset` | `iptables -I OUTPUT -p tcp --dport <port> -j REJECT --reject-with tcp-reset` (`compensation.py:1018-1030`) |
| `process.restart_loop` | `process.crash_loop` | argv is literally `engine stop C; engine start C; sleep <interval>` × `restarts` (`compensation.py:1966-1991`) |

**Decision:** retire all ten. Optionally add an alias-resolution note in
`docs/fault-catalog/reliability-matrix.md` so a user searching for
`clock.jump_forward` is pointed at `clock.skew`.

### Group B — "a param exists but is inert; wire it" (4 ids) — **includes a live bug**

| requested | carrier | the problem |
| --- | --- | --- |
| `db.lock_contention` | `db.query_error{error}` | `error: str = "deadlock"` is **declared and never read** |
| `db.deadlock` | `db.query_error{error}` | the declared default is literally `'deadlock'` |
| `db.transaction_abort` | `db.query_error{error}` | same |
| `mem.reclaim_pressure` | `mem.exhaust{mode}` | `mode: str = "allocate"` is **declared and explicitly rejected for any other value** — `InvariantViolationError("fault_mode", "only 'allocate' exists")` (`compensation.py:216-220`) |

`_db_query_error_undo` (`compensation.py:1744-1770`) reads only `probability`
and `port` and emits a netfilter REJECT. So `db.lock_contention` and
`db.deadlock` would compile to the **same TCP RST to 3306** — they are
distinct in the database and indistinguishable here.

**Decision:** wire the params. The repo already reserved `mode` as the
extension point on `mem.exhaust`; use the same pattern on `db.query_error`.
This is the highest-value item in the whole plan because it converts three
requests into working functionality with no new ids.

Also fix the naming contradiction found while checking `db.slow_query`:
`db.slow_query` promises *latency* but its compensation is
`_netfilter_undo("3306")` = `iptables … -j DROP` — a **blackhole**, not a
delay. `db.query_timeout` and `db.slow_query` are currently the same fault
under two contradictory names. A real slow query is `tc netem delay`, and that
argv builder already exists for `dependency.timeout`.

### Group C — "add one param, retire the id" (8 ids)

| requested | carrier | param to add |
| --- | --- | --- |
| `fs.temp_exhaust` | `fs.fill` | `path: str = "/tmp"` — the payload hardcodes `os.statvfs('/tmp')` (`compensation.py:285-310`) |
| `fs.log_fill` | `fs.fill{path:/var/log}` | same param |
| `process.fd_leak` | `fd.exhaust` | `mode: "exhaust" \| "leak"` — the existing loop just needs to open a fresh fd per iteration and drop the `.count` artifact (`compensation.py:409-424`) |
| `db.pool_exhaust` | `db.connection_exhaust` | none needed; same socket-holding payload (`compensation.py:1784-1830`) |
| `dependency.connection_pool_exhaust` | `db.connection_exhaust` | the payload is protocol-agnostic; only the default port differs |
| `fs.write_error` | `fs.read_only` | none; `mount -o remount,ro` already makes every write fail with EROFS, with a `touch` write-probe as undo (`compensation.py:1919-1965`) |
| `fs.read_delay` | `fs.io_stress` | `fs.io_stress` already has `read_mb_s` **and** `write_mb_s`; add `op: read \| write \| both` rather than a new id |
| `clock.ntp_unavailable` | `dependency.block{protocol:udp, port:123}` | the generic "silence a protocol endpoint" fault; `dns.timeout` is the existing precedent using the same builder |

### Group D — "genuinely new, but the lane has no OOM primitive" (3 ids)

`process.oom_kill`, `mem.oom_kill`, and the OOM half of `fs.mount_unavailable`
have no container-lane implementation. `k8s.pod_oom` is the **only** real OOM
implementation in the repo, and it is k8s-only (`K8sPodOomExecutor`,
`executors.py:610-668`).

`mem.exhaust` deliberately refuses to do it: its payload caps the allocation
goal at `memory.max * 95 // 100` "so the run can never OOM-kill the whole
container" (`compensation.py:225-234`).

**Decision:** do not lift that cap silently. An OOM kill is irreversible from
inside the container (the process is gone), so it belongs to
`Reversibility.RECONCILED` and needs a real recovery story. Treat in wave 3.

### Group E — "approximations only; be honest about it" (4 ids)

| requested | nearest existing | why it is only an approximation |
| --- | --- | --- |
| `app.panic` | `process.kill` / `process.crash_loop` | a panic's external signature *is* "process aborts abnormally, supervisor restarts it" — but mayhem cannot cause the panic without an app hook |
| `app.deadlock` | `container.pause` | a true lock cycle is not injectable; the cgroup freezer is the only implementable approximation, and it also freezes execution |
| `fs.mount_unavailable` | `k8s.persistent_volume_detach` | k8s lane only; the container lane has `remount` but no `umount` |
| `http.response_corrupt`, `dependency.response_corrupt` | `dependency.malformed_response` | that fault's params are literally `body: str = "not-json"` + `content_type` — but it is **`catalog_only`**, refused with *"no protocol-aware response proxy is registered"*. Any "covered" claim here is a claim about a refused entry. |

**Decision:** do not add ids. If the proxy work in wave 2 lands,
`dependency.malformed_response` becomes executable and these two requests are
answered by un-refusing it — which is strictly better than two new ids.

## 0.2 The 21 invalid prefixes — reject the prefix, reuse the namespace

`_PREFIX_TO_CATEGORY` (`domain/faults.py:54-76`) has 21 prefixes. `mq`, `obs`,
`cluster`, `config`, `secret`, `cert`, `auth` are **not among them**, and
`FaultCategory.from_fault_id` raises `SchemaValidationError` before the model
is even built. Adding a prefix is not one line: `_FAILURE_DOMAIN_BY_CATEGORY`
(`catalog.py:56`), `_EFFECT_BY_CATEGORY` (`:115`) and
`_VERIFICATION_BY_CATEGORY` (`:95`) are **total maps keyed by category**, so a
new `FaultCategory` without entries in all three is a `KeyError` at import.
`tests/unit/test_fault_catalog_exhaustive.py:784-785` also asserts
`{d.category for d in CATALOG} == frozenset(FaultCategory)` — a new category
with no fault fails, and a fault with no category fails.

Recommendation, per group:

| requested prefix | count | recommendation |
| --- | --- | --- |
| `cluster.` | 5 | **Reject the prefix.** These are consensus primitives with no mechanism here. The k8s lane already has the closest twins: `k8s.node_network_partition(direction=both)` for split brain, `k8s.workload_stall` for stale state, `k8s.replica_reduce` for replication lag, `k8s.pod_kill` on the leader for leader loss. |
| `config.`, `secret.` | 2 | **Reject the prefix.** `k8s.configmap_corrupt` and `k8s.secret_unavailable` are real `kubectl`-backed object mutations with tested snapshot undo. |
| `cert.`, `secret.expired` | 2 | **Reject the prefix; use `tls.`** `tls.certificate_expired` truncates the CA bundle and restores the file (`compensation.py:2220-2250`); revocation is the same trust-store concern. |
| `auth.` | 1 | **Reject the prefix; use `http.error_injection{status:401\|403}`.** The mechanism exists; only the id prefix is wrong. |
| `mq.` | 7 | Substrate required — wave 4. |
| `obs.` | 4 | Substrate required — wave 4. See the reframing note there; the honest version of this is interesting. |

## 0.3 Full evidence table

| requested_id | bucket | existing_id | evidence |
| --- | --- | --- | --- |
| process.oom_kill | D | `k8s.pod_oom` | only real OOM impl is k8s-only; `mem.exhaust` caps at 95% deliberately |
| process.fd_leak | C | `fd.exhaust` | same loop without the `.count` artifact |
| process.thread_exhaust | **NEW** | – | no existing thread fault; `k8s.node_pid_pressure` is node-scoped PID, not in-process threads |
| process.child_exhaust | **NEW** | – | no `setrlimit`/`RLIMIT_NPROC` anywhere; fork payload is available |
| process.restart_loop | A | `process.crash_loop` | identical argv loop |
| cpu.steal | no-primitive | – | needs hypervisor/KVM control |
| cpu.interrupt_storm | no-primitive | – | needs IRQ/softirq (`/proc/interrupts`, RPS) |
| mem.fragment | no-primitive | – | needs allocator control; `mem.freeze` allocates-and-holds, does not fragment |
| mem.reclaim_pressure | B | `mem.exhaust{mode}` | `mode` declared, all non-`allocate` values rejected |
| mem.oom_kill | D | `k8s.pod_oom` | as `process.oom_kill` |
| fs.read_delay | C | `fs.io_stress` | already has `read_mb_s`/`write_mb_s` |
| fs.read_error | no-primitive | – | needs `dm-error`/`dm-flakey`/FUSE; all absent |
| fs.write_error | C | `fs.read_only` | EROFS on write; undo has a `touch` write-probe |
| fs.corrupt | **NEW** | – | payload substrate available; no fs-layer corruption fault exists |
| fs.temp_exhaust | C | `fs.fill` | payload hardcodes `statvfs('/tmp')` |
| fs.log_fill | C | `fs.fill{path}` | same, different directory |
| fs.mount_unavailable | D/E | `k8s.persistent_volume_detach` | k8s-only; container lane has `remount`, no `umount` |
| net.interface_down | **NEW** | – | `ip link` is already used in-container under NET_ADMIN (`compensation.py:735-749`) |
| net.mtu_mismatch | **NEW** | – | same `ip link` lane |
| net.packet_corrupt | A | `net.corrupt` | identical `tc netem corrupt <p>%` argv and `percent` param |
| net.tcp_half_open | **NEW** | – | netfilter builder exists but is not parameterized for `--tcp-flags` |
| net.conn_exhaust | **NEW** | – | `db.connection_exhaust` holds sockets to one host:port; nothing exhausts local ephemeral ports or the accept queue |
| net.jitter | A | `net.latency{jitter_ms}` | already wired |
| net.egress_block | A | `net.packet_loss{direction:egress}` | `net.partition` is literally `netem loss 100%` |
| net.ingress_block | A | `net.packet_loss{direction:ingress}` | ifb/mirred ingress path implemented |
| http.status_4xx | A | `http.error_injection{status}` | unbounded status |
| http.response_truncate | **NEW** | – | `_HttpEffect` has only `delay_ms`, `status`, `rate`; `canned()` always writes a complete response |
| http.response_corrupt | E | `dependency.malformed_response` | catalog-only, refused |
| http.header_inject | **NEW** | – | `canned()` writes a fixed 4-line response; `fuzz.protocol_abuse` only attacks requests |
| http.stream_stall | **NEW** | – | all existing delays are pre-relay; nothing stalls mid-stream |
| http.connection_close | A | `net.connection_reset` | netfilter REJECT tcp-reset |
| app.exception | no-primitive | – | no in-process hook; no ptrace/gdb/`/proc/pid/mem` |
| app.panic | E | `process.kill` | approximation only |
| app.deadlock | E | `container.pause` | approximation only |
| db.lock_contention | B | `db.query_error{error}` | `error` param is inert |
| db.deadlock | B | `db.query_error{error}` | default value is `'deadlock'` |
| db.replication_lag | **NEW** | – | nothing is replication-aware; `k8s.replica_reduce` scales a k8s workload, not a DB replica |
| db.replica_unavailable | **NEW** | – | no id removes a DB replica |
| db.transaction_abort | B | `db.query_error{error}` | same inert param |
| db.query_timeout | B | `db.slow_query` | `db.slow_query` currently ships a DROP, not a delay — same fault, contradictory name |
| db.pool_exhaust | C | `db.connection_exhaust` | identical payload |
| mq.* (7) | prefix | – | no broker client, no `pika`/`kafka-python`/`confluent-kafka` |
| dependency.bad_status | A | `http.error_injection` | unbounded `status` |
| dependency.response_truncate | **NEW** | – | same proxy gap as `http.response_truncate` |
| dependency.response_corrupt | E | `dependency.malformed_response` | catalog-only |
| dependency.auth_failure | A | `http.error_injection{status:401}` | unbounded status |
| dependency.circuit_open | **NEW** | – | no short-circuit mode; `forward(c)` always dials upstream |
| dependency.connection_pool_exhaust | C | `db.connection_exhaust` | protocol-agnostic payload |
| clock.jump_forward | A | `clock.skew{offset_ms>0}` | signed, stepped |
| clock.jump_backward | A | `clock.skew{offset_ms<0}` | same |
| clock.freeze | no-primitive | – | no libfaketime / time namespace; `container.pause` also freezes execution |
| clock.ntp_unavailable | C | `dependency.block{udp,123}` | generic protocol-silencing fault |
| cluster.* (5) | prefix | – | no Raft/etcd/consensus client |
| obs.* (4) | prefix | – | mayhem observes; it never perturbs a telemetry path |
| config.invalid | prefix | `k8s.configmap_corrupt` | prefix invalid; k8s twin exists |
| config.missing | prefix | `k8s.secret_unavailable` | prefix invalid; k8s twin exists |
| secret.expired | prefix | `tls.certificate_expired` | prefix invalid; use `tls.` |
| cert.revoked | prefix | `tls.handshake_failure` | prefix invalid; use `tls.` |
| auth.denied | A | `http.error_injection{status:401}` | prefix invalid; mechanism exists |
