# ADR-M3-5: Remote execution — interface only, no transport
**Status:** Approved
**Date:** 2026-09-02
**Deciders:** Ali
**Relates to:** ADR-M3-1, ADR-M3-2, ADR-M3-6, ADR-0020
## Context
A future milestone may want to run faults against remote hosts and clusters
(SSH'd boxes, wireguard-connected agents, managed fleets). Remote execution carries
a distinct capability surface: a control-plane ⇄ agent transport, a capability
handshake, remote target resolution, remote tool execution, cancellation, and
teardown. None of this exists in the current single-engine topology; introducing
it speculatively would add an SSH transport nobody uses yet.
## Decision
Define the **remote execution seam as an interface only** — `RemoteAgentInterface`
— and ADR the contract now, but implement **no transport** in this milestone:
- `connect()`, `capability_handshake(reqs) → VerdictResult`, `target_resolution(id)`,
  `tool_run(cmd, timeout_s) → str`, `cancel(run_id)`, `teardown()`.
- A concrete `RemoteAgentAdapter` placeholder is provided so the planner can
  **statically refuse** any plan whose execution context is remote: `evaluate()`
  returns `UNSUPPORTED` for `remote_execution` and `transport`. Because it is
  `runtime_checkable`, future transports can be substituted as long as they satisfy
  the protocol.
- A remote target in a spec fails planning with a clear `UNSUPPORTED` message rather
  than failing unpredictably mid-run (Q11).
## Consequences
- Remote plans are refused deterministically at plan time until a transport exists.
- The contract is stable and testable independent of any transport.
- No SSH/agent credential handling, host key management, or network egress code ships
  prematurely.
