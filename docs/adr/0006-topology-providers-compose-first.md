# 0006. Topology: Provider-Based Discovery with Compose as First-Class Blueprint

- **Date:** 2026-08-23
- **Status:** Accepted
- **Related:** [ADR-0013](0013-kubernetes-readiness-via-provider-seams.md)

## Context

Fault selection needs to *understand the system*: services, containers, hosts, networks, ports,
dependencies, health checks. The primary declaration source is `docker-compose.yaml`, but Compose
files drift from runtime reality (scaled replicas, restarted containers with new IPs, manually
added sidecars), and future targets (Kubernetes, VMs) must plug into the same model without
rewriting the core ([ADR-0002](0002-python-single-package-layered-monorepo.md)).

## Options considered

1. **Parse Compose only; trust it as truth.** Rejected: blind fault targeting against drifted
   reality is dangerous and produces garbage observations.
2. **Docker daemon/socket introspection only.** Rejected: ignores declared intent (dependencies,
   healthchecks) and breaks Podman rootless parity.
3. **Provider pipeline merged into one `TopologyGraph`: Compose = blueprint, Docker/Podman/host =
   live truth, diff = drift report.** Chosen.

## Decision

- Domain defines a **sealed node union**: `HostNode | ContainerNode | ServiceNode | ProcessNode |
  ExternalDependencyNode` and typed edges: `RUNS_ON`, `DEPENDS_ON`, `CONNECTS_VIA`, `EXPOSES`.
- Providers implement `async discover() -> PartialGraph`:
  - **ComposeFileProvider** — parses services/networks/volumes/ports/healthcheck/depends_on
    (including `condition: service_healthy` → dependency weight); interpolates `.env`.
  - **DockerRuntimeProvider / PodmanRuntimeProvider** — CLI-based (`ps --format json`, `inspect`);
    Compose labels bind containers ↔ services; captures live IPs/networks/state. CLI wrappers (not
    SDKs) so Docker and Podman share one code path.
  - **HostProcessProvider** — self processes by pattern, listening sockets via `ss`, systemd units
    where permitted.
- Merge rules: blueprint nodes matched to live nodes by service label/name; unmatched live nodes
  surface in a **drift report** (missing service, changed image, extra container, IP change).
- **External dependencies** are inferred heuristically from service env vars (`DATABASE_URL`,
  `REDIS_URL`, outbound URLs) and flagged for the database/HTTP agents — never silently targeted;
  they enter allowlists explicitly.
- Kubernetes later contributes a `K8sTopologyProvider` + node-scoped agent execution — same
  interfaces, no core edits.

Full design: [architecture/topology-discovery.md](../architecture/topology-discovery.md).

## Consequences

- **Positive:** fault targeting grounded in verified reality; drift becomes visible instead of
  silently poisoning experiments; new platforms = new providers.
- **Negative / accepted trade-offs:** two sources can disagree awkwardly (drift report resolves);
  heuristic external-dependency detection can miss unusual config (operators can declare
  dependencies explicitly in config).
