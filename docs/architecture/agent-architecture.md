# Agent Architecture

Agents are per-host worker processes (`tgondi-agent`) that execute fault capabilities. They are
**not network services**: no listening ports anywhere ([ADR-0003](../adr/0003-controller-agent-communication-jsonrpc-over-stdio-and-ssh.md)).
All connections belong to the controller.

---

## 1. Runtime base

Every role subclasses one `AgentRuntime` — roles differ only in registered capability handlers:

```
spawn (controller-owned)
  → handshake          # version, protocol rev, roles, CapabilityReport
  → READY ⇄ task.execute / task.cancel / lease.extend
       │ heartbeat every 5s (health.ping if idle)
       │ lease-watchdog thread (independent of channel health)
       → drain-on-idle → exit (idle_ttl)
```

Runtime responsibilities (never duplicated in roles):

| Concern | Behavior |
|---|---|
| Task loop | Sequential per role by default; `concurrency` per role configurable |
| Timeouts | Wall-clock deadline per task; cancellation ⇒ compensate inline before returning |
| Watchdog | Expires leases past TTL, runs undo steps locally; survives controller death |
| Heartbeat | Controller marks agent dead after 3 missed beats; leases go `orphaned` for janitor |
| Capability probe | Executed once at handshake: root?, CAP_NET_ADMIN/SYS_ADMIN, cgroup v2, kernel, tool versions |
| Refusal policy | Tasks exceeding declared capabilities are **refused** — never auto-elevated |
| Subprocess discipline | argv lists, env scrub + digest, output caps, `start_new_session=True`, process-group kill on cancel |
| Event stream | `event.emit` notifications upward; agents never write storage directly |

## 2. Protocol

JSON-RPC 2.0, newline-delimited JSON frames over the channel (stdio locally, SSH exec remotely).

| Method / notification | Direction | Purpose |
|---|---|---|
| `handshake` | C→A→resp | version/protocol/roles exchange |
| `capabilities.query` | C→A | fresh CapabilityReport (cache-busting) |
| `task.execute {fault_id, params, targets, lease_id, deadline}` | C→A | run lifecycle hooks |
| `task.cancel {task_id}` | C→A | cooperative cancel + inline compensation |
| `lease.extend {lease_id, ttl}` | C→A | extend watchdog TTL on long observations |
| `health.ping` | both | liveness |
| `event.emit`, `log.emit` | A→C notifications | streamed evidence/logs |

Framing is deliberately dumb (ndjson) so debugging is `cat`/`grep`; a length-prefixed variant can
be added behind the same transport interface if binary payloads ever matter.

## 3. Transports

| Transport | Mechanism | Notes |
|---|---|---|
| `local_stdio` | controller spawns `tgondi-agent serve --roles …` as child process | default host = controller itself |
| `ssh_exec` | persistent `ssh -o ControlMaster=auto <host> -- tgondi-agent serve` via asyncio subprocess wrapping OpenSSH client | reuses users' key management; ControlMaster multiplexes channels per host |

Reconnect: exponential backoff; in-flight faults survive channel loss via the watchdog TTL
([ADR-0005](../adr/0005-recovery-model-lease-journal-janitor.md)).

**Bootstrap** (`tgondi agents install --host user@h`): verify Python ≥ 3.12 over SSH → create
dedicated venv `/opt/tgondi/venv` → install the `tgondi` wheel → optional systemd template unit
(`tgondi-agent.service`) for root-mode agents → print fingerprint for allowlist confirmation.
Privilege modes: `root_via_systemd` (preferred for net/cgroup work) or pinned `sudo_patterns`
(regex-allowlisted commands only).

## 4. Roles (~12)

MVP ships ✅ rows; others land without architectural change ([roadmap](../roadmap.md)).

| Role | Purpose | Key tools | MVP |
|---|---|---|---|
| `process` | kill/pause/resume/restart/crash-loop/spawn-storm; fd exhaustion | pkill, kill, prlimit, nsenter | ✅ |
| `cpu` | saturation, burst, per-core pin, cgroup throttle | stress-ng, cgroup v2 `cpu.max` | ✅ |
| `memory` | exhaustion, gradual pressure, swap thrash, per-process RSS | stress-ng `--vm`, cgroup `memory.max` | ✅ |
| `storage` | fs fill, inode exhaustion, I/O saturation/delay | fallocate, dd, stress-ng fallocate variants | ✅ |
| `network` | latency/jitter/loss/corruption/bandwidth, partition, DNS fail/delay, port block, resets | tc netem, iptables/nft, nsenter into container netns | ✅ |
| `container` | container kill/pause/restart; exec faults *inside* containers; in-container fs/net pressure; host↔container boundary attacks from either side | docker/podman CLI wrappers | ✅ |
| `load` | k6/Locust orchestration; raw-socket connection exhaustion (policy-gated) | k6 (MVP), locust | ✅ k6 |
| `http-api` | proxy-level latency/error injection, malformed responses, API abuse runs | toxiproxy HTTP toxics, schemathesis | v0.x |
| `database` | PG backend termination, lock contention, conn exhaustion, slow queries, dependency restart | psql/pg_isready, container exec | v0.x |
| `node` | service stop/start, sysctl, clock skew, controlled reboot (**critical**) | systemctl, shutdown | v0.x |
| `fuzz` | malformed protocol traffic, request corruption streams | custom generators, schemathesis | v0.x |
| `validation` | reusable steady-state probes, recovery verification helpers | curl/httpie, pg_isready | ✅ light |

### Three levels of container attack (spec requirement)

1. **Container-level:** engine/pause/kill/fs-fill *of* the container.
2. **Network-level:** resolve container IP/netns → apply netns-targeted network faults from the
   host side (requires host NET_ADMIN) or inside the container (requires container NET_ADMIN).
3. **Inside-out:** `exec` into the container → run native fault tools against its processes/filesystem.

The `container` and `network` roles cooperate; backend selection follows
[ADR-0010](../adr/0010-network-fault-tiered-backends.md).

## 5. Inputs / outputs / failure handling

- **Input:** typed `Task(fault_id, params, targets, lease_id, deadline)` — params already validated
  against the fault's pydantic schema by the controller.
- **Output:** `TaskResult(status ∈ {completed, refused, failed}, evidence_refs[], timings)` +
  streamed events during execution.
- **Failure matrix:**

| Failure | Handling |
|---|---|
| Task deadline exceeded | cancel → compensate → report `failed(compensated)` |
| Tool missing | refuse with capability diff (controller filters future candidates) |
| Inject succeeded, recover failed | retry undo ×N → mark lease `dirty` → loud event |
| Agent SIGKILLed | channel EOF → controller orphans leases → janitor reconciles |
| Silent channel loss | watchdog TTL expiry self-compensates locally |
| Crash mid-injection | write-ahead undo exists pre-injection → janitor path |

## 6. Security boundaries

Agents execute only tasks signed by their controller session; they never open inbound ports;
privileged commands run under the agent's OS identity (systemd unit or pinned sudo); all privileged
argv is audit-logged by the controller *before* dispatch ([ADR-0012](../adr/0012-safety-model-environment-identity-and-risk-gates.md)).
