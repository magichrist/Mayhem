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

| fault id                   | undo strategy                                        | verify strategy                    |
|----------------------------|------------------------------------------------------|------------------------------------|
| `net.packet_loss`          | `tc qdisc del` leaving the target intact             | tc chain absent                    |
| `net.bandwidth`            | `tc qdisc del`                                       | tc chain absent                    |
| `net.partition`            | container engine network disconnect                  | connectivity restored              |
| `net.load`                 | host k6 SIGKILL + `rm` of marker script/pid         | host markers absent                |
| `http.latency`             | proxy kill + nat REDIRECT delete + marker removal    | pidfile absent + rule absent       |
| `http.error_injection`     | probability <100: iptables REJECT rule delete; else proxy tear-down | rule absent / pidfile absent |
| `mem.exhaust`              | payload SIGKILL (marker pid)                         | pidfile absent                     |
| `mem.leak`                 | payload SIGKILL (marker pid)                         | pidfile absent                     |
| `cpu.saturate`             | payload SIGKILL (marker pid)                         | pidfile absent                     |
| `cpu.throttle`             | engine `update --cpus` restore                       | engine state restored              |
| `fs.fill`                  | payload SIGKILL + `rm` of all marker siblings        | pidfile + siblings absent          |
| `fs.inode_exhaust`         | payload SIGKILL + `rm` of all marker siblings        | pidfile + siblings absent          |
| `fs.io_stress`             | payload SIGKILL + `rm` of all marker siblings        | pidfile + siblings absent          |
| `fd.exhaust`               | payload SIGKILL (marker pid)                         | pidfile absent                     |
| `db.connection_exhaust`    | proxy kill + REDIRECT delete (native proxy to host)  | pidfile absent + rule absent       |
| `db.query_error`           | `iptables` REJECT delete (connectivity shell today)  | rule absent                        |
| `db.slow_query`            | `iptables` DROP delete (connectivity shell today)    | rule absent                        |
| `dns.timeout`              | pulsing rule removal (marker-suffixed)               | iptables rule absent               |
| `dns.servfail`             | pulsing REJECT removal                              | iptables rule absent               |
| `dns.nxdomain`             | resolv.conf restore (file revert)                    | file restored                      |
| `tls.certificate_expired`  | ca-certificates file revert                          | file restored                      |
| `tls.handshake_failure`    | REJECT rule delete                                   | rule absent                        |
| `clock.skew`               | engine clock restore                                 | engine state restored              |
| `dependency.block`         | iptables DROP delete                                 | rule absent                        |
| `dependency.timeout`       | tc netem delay delete                                | tc chain absent                    |
| `dependency.flap`          | pulsing REJECT rule removal (marker-suffixed)        | iptables rule absent               |
| `dependency.rate_limit`    | proxy kill + REDIRECT delete + marker removal        | pidfile absent + rule absent       |
| `dependency.connection_refuse` | iptables REJECT delete (`icmp-port-unreachable`) | rule absent                         |
| `net.connection_reset`        | iptables REJECT delete (`tcp-reset`)              | rule absent                         |
| `net.connection_refuse`       | iptables REJECT delete (`icmp-port-unreachable`)  | rule absent                         |
| `net.reorder`                 | `tc qdisc del` (netem reorder)                    | tc chain absent                     |
| `net.duplicate`               | `tc qdisc del` (netem duplicate)                  | tc chain absent                     |
| `fs.read_only`                | `mount -o remount,rw` restore                     | write-probe succeeds                |
| `process.crash_loop`          | engine `start` restore                            | engine state restored               |

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
template picks one of two implementations on the same marker conventions:

- `probability < 100` → legacy iptables `REJECT` on `OUTPUT` (synchronous,
  no proxy); undo deletes the rule.
- `probability == 100` (default) → in-container python proxy + `nat OUTPUT
  REDIRECT`; undo kills the proxy pid, deletes the rule, removes markers.

Both branches share the same verify helper, which mirrors the selection so the
wrong strategy can never pass verification.

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