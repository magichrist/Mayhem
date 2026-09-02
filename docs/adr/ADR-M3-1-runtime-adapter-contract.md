# ADR-M3-1: RuntimeAdapter contract — normalize the container runtime
**Status:** Approved
**Date:** 2026-09-02
**Deciders:** Ali
**Relates to:** ADR-0013, ADR-0019, ADR-0020, ADR-0021, ADR-M3-2, ADR-M3-5, ADR-M3-6
## Context
The pre-refactor `ContainerRuntimeProvider` was a single parameterized class that
answered for `"docker"` and `"podman"` through the same code path. That works for a
demo but collapses two genuinely different runtimes into one object, hides
per-engine capability differences (rootless podman, port/netns support), and leaves
no seam for future targets (remote agents, Kubernetes). Engines were addressed by a
string label only, because ADR-0013 forbids introducing "runtime types".
## Decision
Normalize `ContainerRuntimeProvider` into a single `RuntimeAdapter` **abstract
contract** (ABC), with Docker and Podman as concrete implementations:
- `id()` → stable adapter identifier (`"docker" | "podman"`), exposed as a property
  to stay structurally compatible with the `TopologyProvider` protocol.
- `is_available()` → whether the engine binary is reachable on this host.
- `inspect(id) → (RuntimeIdentity, RuntimeMetadata)` (ADR-M1).
- `ps()`, `exec`, `pid`, `signal`, `netns`, `filter_by_compose`, `filter_by_names`,
  `discover()`.
- `capabilities() → AdapterCapabilities` — a static, pure-lookup snapshot
  (ADR-M3-2) that `evaluate()` consumes with no subprocess calls.

The old single class is **refactored**, not preserved as a god-object. Remote and
Kubernetes are `RuntimeAdapter`-compatible stubs returning UNSUPPORTED (ADR-M3-5,
ADR-M3-6).
## Consequences
- Distinct, tested docker and podman behaviors live in their own adapters.
- Future targets plug in by satisfying the ABC (or the `RemoteAgentInterface`
  protocol) without touching the engine code.
- `RuntimeAdapter.id` doubles as the engine label consumed by `_STATE["engine"]`,
  preserving ADR-0013's "label only, no runtime types" rule.
