# Topology Discovery

How Tgondi learns the shape of the system it is about to break
([ADR-0006](../adr/0006-topology-providers-compose-first.md)).

---

## 1. Model

One merged `TopologyGraph` per environment snapshot:

```text
nginx (ServiceNode)
  └─RUNS_ON→ nginx-<abc> (ContainerNode @10.0.0.4:80)   ─┐
fastapi (ServiceNode)                                     │ CONNECTS_VIA net "backend"
  ├─DEPENDS_ON(weight=healthy)→ postgres                  │
  ├─DEPENDS_ON→ redis                                     │
  └─EXPOSES 8000/tcp                                      │
postgres-<def> (ContainerNode) ─RUNS_ON→ HostNode bm-1    ┘
ExternalDependency(api.acme.com, kind=http, inferred_from env OUTBOUND_API)
```

Node kinds and edges are the sealed union defined in [domain-model](domain-model.md).

## 2. Providers

| Provider | Source | Extracts |
|---|---|---|
| `ComposeFileProvider` | docker-compose.yaml + .env | services, images, networks, volumes, ports, healthchecks, depends_on (incl. `condition: service_healthy` → weighted edge), commands, env |
| `DockerRuntimeProvider` | `docker ps --format json`, `inspect` | live containers, state, IPs, networks, Compose label bindings (`com.docker.compose.service`) |
| `PodmanRuntimeProvider` | same via podman CLI | identical mapping — one code path behind a CLI adapter ([ADR-0015-equivalent choice: CLI over SDK]) |
| `HostProcessProvider` | `ps`, `ss -tlnp`, systemctl where permitted | self processes by pattern, listening sockets, units |

Providers implement `async discover() -> PartialGraph`; the Topology service merges them.

## 3. Merge & drift

Blueprint (compose) ↔ live (runtime) matched by service label/name:

| Drift case | Handling |
|---|---|
| Service declared, no live container | drift warning; targets for it are unresolvable this run |
| Live container without blueprint | drift info; excluded from targeting unless allowlisted |
| Image/state/IP changed vs expectation | recorded in discovery report; IP changes re-resolve `CONNECTS_VIA` edges |

Discovery output = graph + drift report; both attach to the run snapshot so later analysis sees
what the controller actually knew.

## 4. External dependency inference

Heuristic pass over service env vars (`DATABASE_URL`, `REDIS_URL`, `*_URL`, outbound hosts parsed
from app config when trivially available) creates `ExternalDependencyNode`s marked `inferred`.
They are never targetable until explicitly added to an allowlist — inference informs planning,
authorization remains explicit ([ADR-0012](../adr/0012-safety-model-environment-identity-and-risk-gates.md)).
Operators can declare dependencies manually to supplement heuristics.

## 5. Runtime refresh semantics

Graph snapshots at plan validation; long experiments may refresh on step boundaries
(`targets.refresh: true`); fault pre-execution assertion re-checks resolved targets against live
state before injecting (drift between plan and execution ⇒ refuse that step).

## 6. Kubernetes preview (future phase)

`K8sTopologyProvider` maps Deployments/Services/Pods → `ServiceNode`/`ContainerNode`;
node-scoped agents run as DaemonSets or ephemeral Jobs. Because container-runtime types exist only
inside providers/adapters (import rule, [ADR-0002/0013](../adr/0013-kubernetes-readiness-via-provider-seams.md)),
no core changes are anticipated.
