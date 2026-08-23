# 0004. Toolkit Arsenal: Capability Registry with Declarative Manifests and Fallback Chains

- **Date:** 2026-08-23
- **Status:** Accepted
- **Related:** [ADR-0010](0010-network-fault-tiered-backends.md),
  [ADR-0011](0011-toolkit-as-extension-point-no-plugin-system.md)

## Context

Fault implementations must invoke real machinery: `tc`, `iptables/nft`, `stress-ng`, `fallocate`,
`prlimit`, `docker`, `podman`, `k6`, `toxiproxy`, `schemathesis`, … If agents hardcode these tools:

- heterogeneous hosts break loudly instead of degrading gracefully,
- swapping backends (e.g., netem → toxiproxy) requires touching fault code,
- capability probing, version detection, and safety metadata get reinvented per agent.

## Options considered

1. **Hardcode tools inside agents.** Rejected: couples faults to binaries; kills portability.
2. **Wrap everything behind heavyweight Python libraries.** Rejected: most Linux fault primitives
   have no maintained library; shelling out is the honest interface anyway.
3. **Plugin ecosystem as extension point.** Rejected as primary mechanism
   ([ADR-0011](0011-toolkit-as-extension-point-no-plugin-system.md)).
4. **Capability-oriented registry: declarative manifests + uniform executor + fallback groups.** Chosen.

## Decision

### Capability IDs

Every executable skill has a stable ID `<domain>.<action>`: `proc.kill`, `proc.pause`,
`cpu.pressure`, `mem.pressure`, `fs.fill`, `fs.inodes`, `net.latency`, `net.partition`,
`dns.fail`, `container.kill`, `container.pause`, `container.exec`, `load.generate`,
`http.inject_error`, `db.exhaust_conn`, …

### Manifests

Tools are declared as data (YAML in `toolkit/manifests/`, loaded into typed models):

```yaml
tool: stress-ng
provides: [cpu.burn, memory.pressure, io.stress]
probe: {cmd: [stress-ng, --version], version_regex: 'version\s+(?P<v>[\d.]+)'}
privilege: unprivileged          # none | sudo_patterns | root
risk: medium                     # low|medium|high|critical
fallback_groups:
  cpu.pressure: primary          # primary | fallback_n
```

Fault definitions declare required capabilities; the registry resolves
`registry.resolve("cpu.pressure", host)` → ranked candidate tools filtered by the host's cached
capability probe (binary present? version ok? privileges sufficient?) → adapter executes.

### Executor guarantees (non-optional, per call)

argv lists only (never shell strings) · scrubbed env + digest logged · pinned cwd · output size
caps · wall-clock deadline · `start_new_session=True` + `killpg` on cancellation · audit line
written **before** exec · result envelope captured to the artifact store:

```python
@dataclass(frozen=True)
class ToolResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    parsed: dict | None
    artifact_ref: str
```

### Fallback groups

Capabilities map to ordered backend lists, e.g. `net.latency`:
`tc-netem (primary) → toxiproxy-latency (fallback_1) → userspace shim (last resort)`. Selection is
automatic via probing, overridable per-config. Discovery runs at agent handshake and caches
versions into the `CapabilityReport`; refresh is explicit, never implicit mid-run.

## Consequences

- **Positive:** hosts without `tc` still support latency faults via toxiproxy; new tools integrate
  by adding a manifest + adapter, not editing agents; uniform evidence capture for every external
  invocation; safety metadata lives beside tool knowledge.
- **Negative:** indirection cost when debugging ("which backend ran?") — mitigated because every
  resolution decision is recorded in observations and the journal.
