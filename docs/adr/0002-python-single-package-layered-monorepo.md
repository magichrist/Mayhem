# 0002. Python Single-Package Layered Monorepo

- **Date:** 2026-08-23
- **Status:** Accepted
- **Related:** [ADR-0011](0011-toolkit-as-extension-point-no-plugin-system.md) (extension points),
  [ADR-0013](0013-kubernetes-readiness-via-provider-seams.md)

## Context

Mayhem spans a controller, agent runtime, toolkit adapters, domain logic, persistence, and a CLI.
We must choose how the codebase is packaged and what internal layering prevents rot. Constraints:

- Entire initial framework is **Python ≥ 3.12**; no Rust/Go in core (external binaries are invoked
  through the Toolkit, not reimplemented).
- Must remain understandable to one expert engineer end-to-end; no premature multi-package split.
- Must still prevent the classic failure mode: domain logic importing Docker SDKs, agents reaching
  into controller state, CLI bypassing services.

## Options considered

1. **Multi-package workspace** (`mayhem-core`, `mayhem-agents`, `mayhem-toolkit`, …). Rejected for
   MVP: version-sync overhead, publishing complexity, and boundaries not yet stable enough to be
   encoded as package seams.
2. **Single flat package, conventions only.** Rejected: import rules would be aspirational, not
   enforced; entropy wins within months.
3. **Single distribution, src-layout, enforced internal layers.** Chosen.

## Decision

One installable distribution `mayhem` from a src-layout repository:

```
src/mayhem/{domain,config,topology,toolkit,protocol,agents,controller,maniac,
            faults,recovery,observation,safety,persistence,reporting,api,cli}
```

Layering rules, enforced in CI with **import-linter** (fail the build, not lint-warned):

1. `domain` imports nothing from higher layers; zero IO in `domain`.
2. `controller`, `maniac`, `recovery`, `safety` may import `domain/config/topology/toolkit/persistence`
   but never `agents.roles` internals or `cli`.
3. **Container-runtime imports (`docker`/`podman`) appear only in**
   `topology/providers/*` **and** container-execution adapters under `agents/roles/container` /
   `faults/container`. This is the seam that keeps Kubernetes pluggable ([ADR-0013](0013-kubernetes-readiness-via-provider-seams.md)).
4. `cli` is thin over `api` service interfaces; no business logic in commands.
5. The agent process entrypoint is the same wheel: console script `mayhem-agent` (alias of
   `mayhem agent serve`) — one artifact to ship locally and remotely.

Core runtime dependencies kept deliberately small: `pydantic` (v2), `typer`, `structlog`,
`pyyaml`. SSH uses the system OpenSSH client via subprocess (see [ADR-0003](0003-controller-agent-communication-jsonrpc-over-stdio-and-ssh.md));
no gRPC, no async framework beyond stdlib asyncio, no database ORM.

## Consequences

- **Positive:** single-artifact deployment (wheel → local venv, remote bootstrap via SSH); enforced
  boundaries keep the K8s/provider seam honest; dependency surface tiny and auditable.
- **Negative:** splitting into packages later requires un-flattening imports (mechanical, low risk);
  import-linter config is itself a contract to maintain.
