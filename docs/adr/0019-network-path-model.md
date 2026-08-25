# 0019. Network Path Model

- **Date:** 2026-08-25
- **Status:** Accepted
- **Related:** [ADR-0006](0006-topology-model.md) (topology model), [ADR-0014](0014-execution-context-model.md) (execution context)

## Context

Network faults (latency, partition, DNS delay) are specified against node pairs, but the planner has no model of *how* traffic flows between nodes — which segments it crosses, what intermediaries exist (load balancers, firewalls, service meshes), and what the expected latency is. Without this, the planner cannot determine whether a network fault on a specific path is realistic or which intermediary nodes could be targeted.

## Decision

Three new value objects in `domain.topology`:

**`NetworkSegment`** — a named network zone (subnet, VLAN, namespace):
- `id`, `name`, `cidr` (optional), `node_ids` (members)

**`NetworkPath`** — a directed connection between two nodes:
- `src_node_id`, `dst_node_id`
- `hop_count`, `expected_latency_ms`
- `intermediaries` — node IDs of LBs, firewalls, service meshes along the path
- `segments` — segment IDs this path crosses
- `bidirectional` — whether the path is symmetric

**`NetworkTopology`** — collection of segments and paths:
- `paths_for_node(node_id)` — all paths touching a node
- `segment_for_node(node_id)` — which segment a node belongs to
- `find_path(src, dst)` — directional path lookup
- `cross_segment_paths()` — paths crossing segment boundaries (high fault surface)

All three are Pydantic `BaseModel` with `frozen=True`, fully JSON-serializable.

## Consequences

- The planner can now reason about network faults at the path level, not just node pairs.
- Cross-segment paths are flagged as higher risk for partition faults.
- Intermediary nodes (LBs, firewalls) become targetable for more precise fault injection.
- The model is purely declarative — no runtime network probing in v0.2.0.
- Backward compatible: existing specs that don't declare network topology are unaffected.
