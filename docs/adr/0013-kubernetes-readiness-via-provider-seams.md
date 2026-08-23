# 0013. Kubernetes Readiness via Provider Seams, Not Speculative Abstractions

- **Date:** 2026-08-23
- **Status:** Accepted
- **Related:** [ADR-0002](0002-python-single-package-layered-monorepo.md) (import rules),
  [ADR-0006](0006-topology-providers-compose-first.md)

## Context

Kubernetes, cloud infrastructure, VMs, and remote Linux fleets are future targets. The spec forbids
coupling everything to Kubernetes — but also demands K8s be designed into the abstractions without
becoming an MVP dependency or forcing a rewrite later.

## Options considered

1. **Build a universal "runtime" abstraction now covering Compose/Docker/Podman/K8s.** Rejected:
   speculative generality; K8s semantics (pods, nodes, controllers, RBAC) don't compress cleanly
   into Compose-shaped concepts, and the wrong abstraction ossifies.
2. **Ignore K8s entirely until later.** Rejected: risks Docker-flavored types leaking into domain
   logic, making K8s a rewrite.
3. **Shape interfaces by what any execution context needs (host + namespace + privileges +
   capabilities), enforce isolation via import rules, add K8s later as new providers only.** Chosen.

## Decision

- Domain speaks only of `HostNode | ContainerNode | ServiceNode | ProcessNode |
  ExternalDependencyNode`, `TargetRef` selectors, and `CapabilityReport`s — never of "docker" or
  "compose".
- Import-linter rule ([ADR-0002](0002-python-single-package-layered-monorepo.md)): container-runtime
  imports exist only inside `topology/providers/*` and container adapters. CI enforces it.
- K8s enablement plan (post-v1.0): `K8sTopologyProvider` (services/pods/nodes → graph),
  agent delivery as DaemonSet or ephemeral Job per node, faults executed node-scoped through the
  existing toolkit. Expected core changes: none beyond registering providers/transports; verified
  continuously by keeping the import rules green.

## Consequences

- **Positive:** MVP stays lean while the seam is mechanically protected; K8s work becomes additive.
- **Negative / accepted trade-offs:** some K8s-native opportunities (operators, CRDs) wait until
  after v1.0; if K8s semantics demand richer graph nodes, the sealed union gains a variant — a
  compatible extension, not a break.
