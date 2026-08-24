# Toolkit Arsenal

The Toolkit is the abstraction layer between agents and the tools that actually break things
([ADR-0004](../adr/0004-toolkit-capability-registry.md)). Agents invoke **capabilities**, never raw
binaries.

```
Agent role handler → Toolkit API (resolve capability) → Tool adapter → native / external tool
```

---

## 1. Capability model

- Capability IDs: `<domain>.<action>` (see [domain-model](domain-model.md) §Agents).
- A tool *provides* capabilities; a capability may be provided by several tools forming a
  **fallback group** with priority order.
- Resolution: `toolkit.resolve(capability_id, host)` returns the best available provider given that
  host's `CapabilityReport` (probed at handshake, cacheable, refreshable via `capabilities.query`).

Example — one fault, three backends:

```text
net.latency →  tc-netem (needs NET_ADMIN)  →  toxiproxy-latency (unprivileged)  →  userspace shim
```

## 2. Tool manifests

Declarative YAML shipped in-tree (`src/mayhem/toolkit/manifests/*.yaml`); adding a tool = adding a
manifest + adapter ([ADR-0011](../adr/0011-toolkit-as-extension-point-no-plugin-system.md)).

```yaml
tool: stress-ng
provides: [cpu.pressure, mem.pressure, io.stress]
probe:
  cmd: [stress-ng, --version]
  version_regex: 'version\s+(?P<v>[\d.]+)'
privilege: unprivileged        # none | net_admin | sys_admin | root
risk: medium                   # low | medium | high | critical
fallback_groups:
  cpu.pressure: primary        # or: {group: cpu.pressure, rank: 1}
cleanup_ownership: managed     # toolkit owns child lifecycle (stress processes)
```

## 3. Adapter contract

```python
class ToolAdapter(Protocol):
    async def probe(self) -> ProbeResult: ...  # presence + version parse
    async def execute(self, call: ToolCall) -> ToolResult: ...  # uniform envelope


@dataclass(frozen=True)
class ToolResult:
    exit_code: int
    stdout: str
    stderr: str  # size-capped; truncation flagged explicitly
    duration_ms: int
    parsed: dict | None  # adapter-specific structured extraction
    artifact_ref: str  # full output stored in artifact store
```

## 4. Executor guarantees (every invocation, non-optional)

1. argv lists only — never shell strings (injection-proof by construction).
2. Environment scrubbed to an explicit allowlist; digest of effective env logged.
3. cwd pinned; wall-clock deadline enforced.
4. Output caps (default 1 MiB/stream) with explicit truncation markers.
5. `start_new_session=True`; cancellation kills the process group.
6. Audit line written **before** exec: timestamp, lease id, argv, env digest.
7. Full stdout/stderr persisted to artifact store keyed by `ToolRun.id`.
8. Managed children (e.g., toxiproxy-server, k6) tracked for janitor reaping.

## 5. Discovery & caching

| Aspect | Behavior |
|---|---|
| When | Once per agent handshake; refreshed on demand |
| Where cached | Controller-side per `(host, tool)`; agents also self-cache probe results |
| Failure mode | Missing tool ⇒ capability unavailable ⇒ faults depending on it drop out of candidate sets (they do not error) |
| Overrides | Config can pin binaries/versions (`toolkit.overrides.k6.binary`) |

## 6. Bundled adapters (initial)

**Native:** `tc`, `iptables`, `nft`, `ip`, `nsenter`, `pkill/kill`, `prlimit`, `fallocate`, `dd`,
`docker`, `podman`, `systemctl`, `ssh`, `ss`, coreutils.
**External:** `k6`, `locust`, `toxiproxy-cli/-server`, `schemathesis`, `fio`, `stress-ng`.

External daemons started by the toolkit (toxiproxy-server) are owned children: recorded leases,
janitor-reapable, never orphaned.

## 7. Adding a new tool — checklist

1. Manifest with accurate `privilege`, `risk`, `probe.version_regex`.
2. Adapter implementing `probe`/`execute`; map its CLI quirks into `parsed`.
3. Contract tests against a fake binary in `tests/fixtures/bin`
   ([testing-strategy](testing-strategy.md)).
4. If it starts daemons: register cleanup ownership + janitor reap path.
5. Update fallback groups of affected capabilities.
