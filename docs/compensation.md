# Compensation: fault execution, undo, and lifecycle verification

The active CLI exposes compensation through `mayhem run --execute`, `mayhem
inspect run`, `mayhem inspect history`, and `mayhem recover`. Legacy root
commands are not part of the active surface.

Every fault in the catalog resolves to exactly one **compensation template**
(`controller.compensation.template_for`). A template pairs:

- an **undo builder** that, given the `PlannedFault` and the resolved topology
  nodes, returns zero-or-more `UndoOp`s — the exact operations that remove the
  injected failure; and
- a **verify builder** that returns zero-or-more `VerifyProbe`s — the checks
  that run after undo to prove the fault is gone.

The invariant enforced across the controller is: **the inject path, the undo
path, and the verify probe are generated from the same plan-level parameters
and address the same marker artifacts**, so what an operator plans is precisely
what gets removed and what gets verified.
This document records the lifecycle for the fault families wired in the
controller and the marker conventions. Compensation evidence is persisted in
run evidence and exposed through the active inspect commands.

Any new fault must ship all three legs (inject, undo, verify) or it cannot
enter the catalog's compensatable set.

## Executor routing

`executor_for(fault_id)` selects the agent that executes the undo op:

| prefix | executor      | rationale                                                      |
|--------|---------------|----------------------------------------------------------------|
| `mem`  | Payload       | marker-pid payloads run in-container; undo kills the marker pid |
| `load` | Payload       | same marker model                                               |
| `cpu`  | Tool          | `cpu.throttle` uses the container engine (`update --cpus`); `cpu.saturate` stays parallel payload |
| all others | Tool     | tc / iptables / http proxy / engine ops, addressed via tool argv |

## Marker files

Payload-based faults (mem/fs/fd/load/fuzz) write `/tmp/mayhem.<fault>.<node>.pid`
containing the payload pid; undo SIGKILLs it and removes the marker files.
Proxy-based faults (http latency/error, dependency rate-limit) additionally
write `<marker>.pid`, `<marker>.port`, `<marker>.src`, so the same artifacts
drive undo, recovery, and verification.

## Template table (wired in `_TEMPLATES`)

| fault id | undo strategy | verify strategy |
|---|---|---|
| `proc.pause` | `signal.cont` on the live pid | `ps -p <pid>` — process must be present |
| `process.stop` | no-op (pid is gone) | process probe, `expect_present=false` — pid must be gone |
| `process.kill` | no-op (pid is gone) | process probe, `expect_present=false` — pid must be gone |
| `net.packet_loss` | `tc qdisc del` (netem loss) | tc chain absent |
| `net.bandwidth` | `tc qdisc del` (tbf) | tc chain absent |
| `net.partition` | `tc qdisc add dev eth0 root netem loss 100%`; undo deletes the root qdisc | tc chain absent |
| `net.load` | host k6 SIGKILL + `rm` of marker script/pid | host exec: marker script and k6 pidfile absent |
| `http.latency` | in-container proxy kill + nat REDIRECT delete + marker removal | pidfile + port marker + nat rule absent |
| `http.error_injection` | `probability < 1.0`: iptables REJECT rule delete; `probability >= 1.0`: proxy tear-down | rule absent / pidfile absent |
| `http.upstream_timeout` | proxy kill + nat REDIRECT delete + marker removal | pidfile + rule absent |
| `app.response_5xx` | same as `http.error_injection` (delegates to it) | same as `http.error_injection` |
| `mem.exhaust` | payload SIGKILL (marker pid) + `rm` of marker | marker pidfile absent |
| `mem.leak` | payload SIGKILL (marker pid) + `rm` of marker | marker pidfile absent |
| `cpu.saturate` | payload SIGKILL (marker pid) + `rm` of marker | marker pidfile absent |
| `cpu.throttle` | engine `update --cpus` restore (cap lifted to unlimited) | engine exec `true` (no container check) |
| `fs.fill` | payload SIGKILL (marker pid) + `rm` of all `marker.*` siblings | marker pidfile absent |
| `fs.inode_exhaust` | payload SIGKILL (marker pid) + `rm` of all `marker.*` siblings | marker pidfile absent |
| `fs.io_stress` | payload SIGKILL (marker pid) + `rm` of all `marker.*` siblings | marker pidfile absent |
| `fs.quota` | payload SIGKILL (marker pid) + `rm` of all `marker.*` siblings | marker pidfile absent |
| `fs.write_delay` | payload SIGKILL (marker pid) + `rm` of all `marker.*` siblings | marker pidfile absent |
| `fd.exhaust` | payload SIGKILL (marker pid) | marker pidfile absent |
| `process.thread_exhaust` | payload SIGKILL (marker pid) | marker pidfile absent |
| `process.child_exhaust` | payload SIGKILL (marker pid) | marker pidfile absent |
| `net.conn_exhaust` | payload SIGKILL (marker pid) + `rm` of marker + `.src` | marker pid + `.src` absent |
| `load.spike` | payload SIGKILL (marker pid) | marker pidfile absent |
| `fuzz.protocol_abuse` | payload SIGKILL (marker pid) | marker pidfile absent |
| `db.connection_exhaust` | payload SIGKILL (marker pid) + `rm` of marker + `.src` | marker pid + `.src` absent |
| `db.query_error` | iptables REJECT/DROP delete (mode-dependent) or pulsing rule removal | iptables rule absent / pulse pid + rule absent |
| `db.slow_query` | tc port netem delay delete or iptables DROP delete | tc chain absent / iptables rule absent |
| `dns.resolve_delay` | `/etc/resolv.conf` restore from backup marker | backup marker absent |
| `dns.nxdomain` | `/etc/hosts` restore from backup marker (appends `<address> <domain>`, restores original on undo) | backup marker absent |
| `dns.timeout` | pulsing iptables DROP rule removal (udp/53) | pulse pidfile absent + iptables rule absent |
| `dns.servfail` | pulsing iptables REJECT rule removal (udp/53) | pulse pidfile absent + iptables rule absent |
| `tls.certificate_expired` | `/etc/ssl/certs/ca-certificates.crt` restore from backup | backup marker absent |
| `tls.handshake_failure` | iptables REJECT rule delete (tcp-reset, port 443) | iptables rule absent |
| `clock.skew` | `date` restore from epoch marker | marker file absent |
| `dependency.block` | iptables DROP rule delete | iptables rule absent |
| `dependency.timeout` | `tc qdisc del` (netem delay) | tc chain absent |
| `dependency.flap` | pulsing iptables DROP rule removal | pulse pidfile absent + iptables rule absent |
| `dependency.rate_limit` | proxy kill + nat REDIRECT delete + marker removal | pidfile + rule absent |
| `dependency.connection_refuse` | iptables REJECT rule delete (icmp-port-unreachable) | iptables rule absent |
| `net.connection_reset` | iptables REJECT rule delete (tcp-reset) | iptables rule absent |
| `net.connection_refuse` | iptables REJECT rule delete (icmp-port-unreachable) | iptables rule absent |
| `net.reorder` | `tc qdisc del` (netem reorder) | tc chain absent |
| `net.duplicate` | `tc qdisc del` (netem duplicate) | tc chain absent |
| `net.interface_down` | `ip link set dev <device> up` + prove `state UP` | `ip link show` reports `state UP` |
| `net.mtu_mismatch` | MTU restored from marker file + marker removed | MTU marker absent |
| `net.tcp_half_open` | iptables rule delete (SYN/ACK DROP) | iptables rule absent |
| `fs.read_only` | `mount -o remount,rw` + write-probe touch/rm | write-probe succeeds (touch + rm marker) |
| `fs.corrupt` | original file restored from `<path>.mayhem-orig` backup | backup marker absent |
| `process.crash_loop` | engine `start` (restores container to running) | engine exec `true` (no container check) |
| `process.restart_delay` | engine `start` | engine exec `true` (no container check) |
| `container.kill` | engine `start` | engine exec `true` (no container check) |
| `container.restart` | engine `start` | engine exec `true` (no container check) |
| `container.pause` | engine `unpause` | engine exec `true` (no container check) |
| `node.service_stop` | engine `start` | engine exec `true` (no container check) |

## Routing overrides keep argv-pair faults off the payload track

`cpu.throttle` must be routed to the Tool executor (engine `update --cpus` on
the container), never to the payload track: the payload track assumes the
marker pid is killable, which a reserve-share throttle does not provide. The
same applies to `fs.read_only` (remounts the container filesystem in place —
there is no burner payload to kill) and `process.crash_loop` (drives a
container-engine stop/start cadence, which the SIGSTOP/SIGTERM/SIGKILL
proc-pause executor cannot express). The routing overrides live in
`agents/executors.py` and are covered by `test_executor_drill` and the e2e
lease round-trip.

## `http.error_injection` dual personality at plan time

`http.error_injection` is parameterized by `probability`. At plan time the
template picks one of two implementations:

- `probability < 1.0` (default is `0.0`) → legacy iptables `REJECT` with
  `tcp-reset` on `OUTPUT` (synchronous, no proxy); undo deletes the rule.
- `probability >= 1.0` → in-container python proxy + `nat OUTPUT REDIRECT`;
  undo kills the proxy pid, deletes the rule, removes markers.

Both branches share verify logic appropriate to their strategy so the wrong
strategy can never pass verification.

## Lifecycle

The verify leg runs the commands that recovery also relies on: pidfile absence,
iptables rule absence, tc chain absence, marker sibling absence, and engine
state restore. This "same-artifacts, same-parameters" contract is what makes
verification check the full lifecycle rather than a partial teardown.

## Database faults (phase D — integration level)

`db.query_error` (and `db.slow_query`) currently resolve to a connectivity
shell: they drop or reject on the target port. The plan leaves query-level
injection at the database/integration level (the `error`/`slow`-mode semantic
in `_db_query_error_undo` is stubbed for that phase), so these two entries stay
documented as connectivity-level until chunk D wires a query-aware shim.