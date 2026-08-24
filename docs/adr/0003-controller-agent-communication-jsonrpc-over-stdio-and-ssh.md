# 0003. Controller↔Agent Communication: ndjson JSON-RPC over stdio, SSH exec for Remote Hosts

- **Date:** 2026-08-23
- **Status:** Accepted
- **Related:** [ADR-0005](0005-recovery-model-lease-journal-janitor.md) (crash semantics),
  [ADR-0012](0012-safety-model-environment-identity-and-risk-gates.md)

## Context

The controller coordinates fault execution across **multiple hosts from day one** (local Linux host
plus remote bare-metal machines over SSH), while the spec forbids "50 microservices". Agents run
privileged operations; the communication channel must therefore be authenticated, encrypted,
firewall-friendly, debuggable, and survivable when either side crashes mid-fault.

## Options considered

| Option | Assessment |
|---|---|
| In-process function calls (threads) | No isolation; an agent crash takes down the controller; cannot cross hosts. Rejected. |
| Agents dial home (reverse HTTP/WebSocket to controller listener) | Requires inbound ports + PKI + reachability from every target network; heavy security surface. Rejected for MVP. |
| gRPC | Strong typing + streaming, but codegen toolchain, protobuf dependency weight, harder human debugging of raw frames. Rejected for MVP. |
| Message broker (NATS/Redis) | New always-on infrastructure component for a framework whose selling point is "point it at your stack". Rejected. |
| **Controller-initiated sessions: newline-delimited JSON-RPC 2.0 over stdio; local = spawned child process, remote = persistent `ssh … mayhem-agent serve` exec channel** | Zero inbound ports anywhere; OS-authenticated transport (SSH keys); crash isolation between processes; frames readable in a terminal. Chosen. |

## Decision

1. **Protocol:** JSON-RPC 2.0, one JSON object per line (ndjson framing). Methods:
   `handshake`, `capabilities.query`, `task.execute`, `task.cancel`, `task.status`,
   `lease.extend`, `health.ping`; notifications: `event.emit`, `log.emit`.
   Every message carries `run_id`/`agent_id` context for correlation.
2. **Transports** behind one interface:
   - `LocalStdioTransport`: controller spawns `mayhem-agent serve --roles …` as a child process.
   - `SSHTransport`: persistent `ssh -o ControlMaster=auto -o ControlPersist=600 <host> --
     mayhem-agent serve`; stdout/stderr pipes carry protocol/log streams respectively.
     Uses the **system OpenSSH client** driven via `asyncio.create_subprocess_exec` — no asyncssh
     dependency; host-key management stays with the user's known configuration.
3. **Agents never listen on sockets.** All connections are controller-initiated.
4. **Reconnect:** exponential backoff with jitter; channel loss does NOT cancel in-flight faults —
   leases survive independently ([ADR-0005](0005-recovery-model-lease-journal-janitor.md)); on
   reconnect the controller re-synchronizes lease/task state via `capabilities.query` + task status.
5. **Remote bootstrap:** `mayhem agents install --host user@h` verifies Python ≥ 3.12, creates
   `/opt/mayhem/venv`, installs the wheel, optionally writes a systemd template unit
   (`mayhem-agent.service`) for root-mode agents; otherwise pinned sudo patterns apply
   ([ADR-0012](0012-safety-model-environment-identity-and-risk-gates.md)).

## Consequences

- **Positive:** trivially debuggable (`ssh host mayhem-agent serve | jq`); no firewall changes on
  targets; process boundary gives fault/crash isolation; same wire format local and remote.
- **Negative / accepted trade-offs:** SSH channel drops are part of normal operation and every
  consumer must handle them (mitigated by lease independence); bandwidth-inefficient vs binary
  protocols (irrelevant at our message rates); a future high-scale remote mode may add a
  dial-home WebSocket transport implementing the same `Transport` interface — no core change.
