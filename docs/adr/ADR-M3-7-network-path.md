# ADR-M3-7: NetworkPath is first-class
**Status:** Approved
**Date:** 2026-09-02
**Deciders:** Ali
**Relates to:** ADR-0019, ADR-0020, ADR-M1-1, ADR-M3-2
## Context
Network faults (partition, blackhole, latency) were expressed as "these container
names" — a list of targets with no connectivity relation. That cannot express *a
link*: src → dst, through which interface, on which namespace, over which protocol
and ports. And without an ownership key, the resource ledger (ADR-0019) cannot
correlate a planned network fault with the tracked resource it mutates across runs
and engine choices.
## Decision
Promote `NetworkPath` to a first-class, fault-targetable model:
```
NetworkPath(src_node_id, dst_node_id, network, namespace, interface,
            protocol, ports, direction)
```
- A network fault targets a **path**, not a bare set of container names.
- Path detail is additive and optional on the existing model: `namespace`,
  `interface`, `protocol` (default `tcp`), `ports`, `direction` (default `both`),
  all with safe defaults so pre-existing paths keep working.
- Every network operation carries an **ownership/identity fingerprint**
  (`compute_network_fingerprint`) — a stable 16-hex digest of
  `src:dst:namespace:protocol:fault_type` — so it is attributable, journaled, and
  recoverable (ADR-M1 attribution + ADR-0019 ledger).
- `TrackedResource` gains a `fingerprint` field and `NETWORK_FAULT` becomes a
  resource type, tying a planned network mutation to a recoverable, journaled
  resource.
## Consequences
- Network faults are attributable and recoverable via the fingerprint.
- The path is the unit of targeting, so the planner can reason about direction,
  ports, and namespace rather than a flat name list.
- `DrillFault.network_path` is an optional, non-breaking target pointer.
