# Fault Taxonomy

Tgondi's arsenal, organized by domain. Coverage claims are **measurable, not asserted**: the
generated matrix in `docs/fault-catalog/` (fault class × target context × backend × privilege
level) counts as "covered" only where a test injects *and* recovers the fault
([spec resolution R6](../README.md)). Maturity targets: ~30 faults at MVP (v0.1), ~100+ by v1.0.

Risk ladder: `low < medium < high < critical` — `critical` requires policy opt-in + CLI flag
([ADR-0012](../adr/0012-safety-model-environment-identity-and-risk-gates.md)).

---

## Process (`proc.*`) — role: process

| Fault | Effect | Risk | Reversible |
|---|---|---|---|
| `proc.kill` | SIGKILL/SIGTERM target process(es) | low | ✅ (restart strategy) |
| `proc.pause` / `proc.resume` | SIGSTOP/SIGCONT | low–med | ✅ |
| `proc.restart_loop` | kill + supervised restart cycling | med | ✅ (stop loop) |
| `proc.spawn_storm` | fork-bomb-shaped bounded spawn pressure | high | ✅ (self-expiring) |
| `proc.fd_exhaust` | raise FD consumption to `prlimit` ceiling | med | ✅ |

## CPU (`cpu.*`) — role: cpu

| Fault | Effect | Risk | Reversible |
|---|---|---|---|
| `cpu.saturate` | burn all cores | med | ✅ self-expiring |
| `cpu.burst` | periodic duty-cycle spikes | med | ✅ |
| `cpu.pin_core` | pin target process to contended core(s) | med | ✅ |
| `cpu.cgroup_throttle` | cgroup v2 `cpu.max` quota squeeze | med | ✅ |

## Memory (`mem.*`) — role: memory

| Fault | Effect | Risk | Reversible |
|---|---|---|---|
| `mem.exhaust` | drive host/container memory to limit | high | ✅ self-expiring |
| `mem.pressure_gradual` | ramp RSS over time | med | ✅ |
| `mem.swap_thrash` | force swap churn | high | ✅ |
| `mem.oom_bait` | allocation pattern tuned to trigger OOM killer on target | **high** | ✅ |

## Storage (`fs.*`, `io.*`) — role: storage

| Fault | Effect | Risk | Reversible |
|---|---|---|---|
| `fs.fill` | fallocate/dd fill to threshold % | high | ✅ (delete filler) |
| `fs.inode_exhaust` | create many small files | high | ✅ |
| `io.saturate` | sustained I/O pressure | med | ✅ |
| `io.delay` | inject I/O latency via device mapper/cgroup io.latency where available | high | ✅ |

## Network (`net.*`, `dns.*`) — role: network · backends per [ADR-0010](../adr/0010-network-fault-tiered-backends.md)

| Fault | Effect | Risk | Reversible |
|---|---|---|---|
| `net.latency` | delay ± jitter | med | ✅ (qdisc removal) |
| `net.loss` / `net.corruption` | drop/damage packets by rate | med | ✅ |
| `net.bandwidth` | rate cap | med | ✅ |
| `net.partition` | iptables/nft DROP/REJECT between endpoints | high | ✅ (chain removal) |
| `net.reset` / `net.refuse` | RST injection / reject with ICMP | med | ✅ |
| `dns.fail` / `dns.delay` | resolver blackhole/slowness via local override | med | ✅ |
| `net.port_block` | block specific port(s) | med | ✅ |
| `net.asymmetric` | one-direction impairment | high | ✅ |

## Containers (`container.*`) — role: container (3 attack levels: engine-level, netns-level, exec-level)

| Fault | Effect | Risk | Reversible |
|---|---|---|---|
| `container.kill` / `pause` / `restart` | engine ops on container | med | ✅ |
| `container.fs_fill` | fill inside container layer/volume | high | ✅ |
| `container.net_fault` | network faults applied to container netns | high | ✅ |
| `container.exec_inject` | run native faults on in-container processes/filesystem | high | ✅ |

## Nodes / hosts (`node.*`) — role: node

| Fault | Effect | Risk | Reversible |
|---|---|---|---|
| `node.service_stop` | stop systemd unit | med | ✅ |
| `node.isolate` | cut node from network | high | ✅ |
| `node.resource_exhaust` | host-wide cpu/mem/fs combos | high | ✅ |
| `node.reboot` / `node.shutdown` | controlled restart/power-off | **critical** | ⚠️ partial (default forbidden) |

## HTTP / API (`http.*`) — role: http-api

| Fault | Effect | Risk | Reversible |
|---|---|---|---|
| `http.error_injection` | 5xx ratio via proxy toxics | med | ✅ |
| `http.malformed_response` | truncated/corrupt payloads | med | ✅ |
| `http.conn_kill` | mid-response connection termination | med | ✅ |
| `http.api_abuse_run` | schemathesis-driven malformed/edge-case request bursts | med | ✅ |

## Databases / dependencies (`db.*`) — role: database

| Fault | Effect | Risk | Reversible |
|---|---|---|---|
| `db.unavailable` | stop/restart dependency | high | ✅ |
| `db.conn_exhaust` | hold connections to pool exhaustion | high | ✅ |
| `db.kill_backends` | terminate PG backends | med | ✅ |
| `db.lock_contention` | manufactured lock queues | med | ✅ |
| `db.slow_query` | pg_sleep-style latency injection | med | ✅ |
| `db.partition_app` | app↔DB partition only | high | ✅ |

## Load & abuse (`load.*`, `fuzz.*`) — roles: load, fuzz

| Fault | Effect | Risk | Reversible |
|---|---|---|---|
| `load.spike` / `load.sustained` / `load.soak` | k6 profiles | med | ✅ stop generator |
| `load.overload` | beyond-capacity saturation (**controlled DoS-class**, policy-gated) | high | ✅ |
| `load.conn_exhaust` | raw-socket backlog/conntrack exhaustion | high | ✅ |
| `fuzz.protocol_abuse` | malformed traffic streams | med | ✅ |

---

## Definition metadata contract

Every `FaultDefinition` carries exactly what safety/planning consumes:

```yaml
id: net.latency
category: network
risk: medium
reversible: true
required_caps: [net_admin]          # or capability alternatives resolved via fallback groups
applicable_node_kinds: [ContainerNode, HostNode]
max_duration: 300s
backends: [tc-netem, toxiproxy-latency, userspace-shim]
safe_env_classes: [dev, staging]     # production requires explicit policy override
params_schema: {delay: duration, jitter: duration?, loss: percent?}
```

Coverage-matrix generation and the test-gated definition of "covered" are specified in
[testing-strategy.md](testing-strategy.md) §7.
