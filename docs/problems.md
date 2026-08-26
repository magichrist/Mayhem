# Task: Audit and Fix Mayhem Topology Discovery — Current Runtime Graph Is Incorrect

Perform a focused architectural and implementation audit of **Mayhem's topology discovery system**.

Do not redesign the whole project and do not add new fault types yet.

The current problem is that the Compose/runtime topology is being modeled incorrectly, which prevents Mayhem from correctly targeting containers, processes, networking, and runtime-level faults.

## Current reproduction

Running:

```bash
mayhem topology discover --compose docker-compose.yml
```

currently produces approximately:

```json
{
  "graph": {
    "nodes": [
      {"id": "svc-download-1", "name": "download-1", "kind": "service"},
      {"id": "svc-download-2", "name": "download-2", "kind": "service"},
      {"id": "svc-lb", "name": "lb", "kind": "service"},
      {"id": "svc-db", "name": "db", "kind": "service"},
      {"id": "h-podman-local", "name": "podman", "kind": "host"}
    ],
    "edges": [
      {"src": "svc-lb", "dst": "svc-lb", "kind": "exposes"},
      {"src": "svc-lb", "dst": "svc-download-1", "kind": "depends_on"},
      {"src": "svc-lb", "dst": "svc-download-2", "kind": "depends_on"}
    ]
  },
  "drift": {
    "missing_services": [
      "db",
      "download-1",
      "download-2",
      "lb"
    ]
  }
}
```

The Compose file contains:

```text
download-1
download-2
lb
db
```

and the runtime is Podman/Docker.

A fault such as:

```text
proc.pause
```

currently fails against:

```text
svc-download-1
kind=service
```

because the topology has no process node.

---

# 1. Primary Problem

Determine why the runtime provider is not reconciling the Compose blueprint with the actual running containers.

The expected architecture is:

```text
Compose blueprint
       +
Docker/Podman runtime
       ↓
Reconciled topology
```

but the current behavior is effectively:

```text
Compose blueprint
       ↓
service nodes

Runtime
       ↓
host node

No meaningful reconciliation
```

Find the exact cause in the implementation.

Inspect:

```text
src/mayhem/topology/
src/mayhem/topology/providers/
src/mayhem/domain/topology.py
```

and all related tests and ADRs.

Do not assume the problem is only Podman. Verify Docker and Podman behavior separately.

---

# 2. Runtime Container Discovery

The topology must discover actual runtime containers belonging to the Compose project.

The current graph contains zero `container` nodes.

Determine why.

The provider must reliably correlate:

```text
Compose service
      ↕
Compose project/service metadata
      ↕
runtime container
```

Do not rely only on container names.

Use stable runtime metadata such as Compose labels where available.

The audit must verify:

* Compose project detection
* service-name matching
* container ID
* container name
* runtime
* state
* image
* labels
* networks
* IP addresses
* ports
* host relationship

---

# 3. Drift Detection Is Incorrect

Current output reports every Compose service as missing:

```text
db
download-1
download-2
lb
```

even when the corresponding runtime containers should exist.

Determine why reconciliation produces this result.

Fix drift semantics so it distinguishes at least:

```text
matched
missing
unexpected runtime container
changed
unhealthy/unavailable
unrecognized
```

The drift report should contain enough information to diagnose mismatches.

---

# 4. Container Nodes Must Exist

For the running Compose stack, the resulting graph should contain both logical services and runtime containers.

At minimum:

```text
service: download-1
container: <runtime-id>

service: download-2
container: <runtime-id>

service: lb
container: <runtime-id>

service: db
container: <runtime-id>

host: podman/docker/local
```

with relationships such as:

```text
container → service
container → host
```

Do not remove service nodes simply because container nodes are added.

The logical Compose layer and runtime layer represent different things.

---

# 5. Process Discovery Is Missing

The current topology cannot target:

```text
proc.pause
proc.kill
proc.cpu
```

because there are no process nodes.

Determine what is currently intended by the domain's `ProcessNode` and implement the missing runtime discovery needed to populate it.

At minimum, process nodes should be capable of representing:

```text
PID
PPID
command
executable
user
container_id
host identity
container PID where available
host PID where available
```

The architecture should connect:

```text
host
  ↓
container
  ↓
process
```

where runtime permissions and platform semantics allow it.

Do not fake process nodes from service definitions.

---

# 6. Container → Process Relationship

Container-level and process-level faults must remain distinct.

The topology must support:

```text
service
   ↓
container
   ↓
process
```

so:

```text
container.pause
```

can target a container while:

```text
proc.pause
```

can target a process.

The planner must be able to validate these distinctions.

---

# 7. Network Topology Is Too Weak

The current graph contains almost no meaningful runtime networking information.

A production-capable topology model needs to represent, where discoverable:

```text
network
network namespace
interface
IP address
container
host
port
protocol
```

and relationships such as:

```text
container → network
container → IP
container → host
service → container
container → listens_on port
```

This is necessary for future capabilities such as:

```text
container → container network faults
container → host faults
service → dependency faults
source → destination network impairment
```

Do not solve this by adding arbitrary fields to existing nodes without considering the domain model.

Determine whether a separate network/address/endpoint abstraction is required.

---

# 8. Port Modeling Is Incorrect

The current Compose discovery reports:

```json
"exposed_ports": [8080]
```

for `lb`.

But the Compose mapping is:

```text
host:8080
container:80
```

These are different concepts.

Audit the port model and determine whether it needs explicit:

```text
host address
host port
container port
protocol
```

and possibly a dedicated port-binding/endpoint abstraction.

The topology must distinguish:

```text
container port
exposed port
published host port
```

---

# 9. The `lb → lb exposes` Edge Is Suspicious

The current graph contains:

```text
svc-lb → svc-lb
kind=exposes
```

Determine exactly why this self-edge is generated.

It should not be created unless the domain explicitly defines a valid semantic meaning for it.

A host/container port publication should not automatically become a self-edge between identical service nodes.

Correct the topology semantics rather than merely filtering the edge from output.

---

# 10. Dependency Graph Is Too Dependent on Compose `depends_on`

Current edges include:

```text
lb → download-1
lb → download-2
```

but there is no PostgreSQL relationship.

Determine what `depends_on` currently means in Mayhem.

It must be clearly distinguished from:

```text
runtime dependency
network connectivity
startup ordering
application dependency
```

Compose `depends_on` is not automatically the same thing as an application's runtime dependency graph.

Preserve the Compose dependency information, but do not mislabel it as a discovered runtime dependency.

Design clear edge semantics for future:

```text
depends_on
connects_to
routes_to
runs_on
contained_in
attached_to
exposes
listens_on
```

Only add relationships that can be justified by actual evidence.

---

# 11. Stable Identity

Audit whether topology and recovery currently rely too heavily on mutable names or IP addresses.

For runtime resources, prefer stable identities such as:

```text
container ID
host identity
process identity
network namespace identity
interface identity
```

Names and IPs may change after restart.

Recovery must still be able to identify the original resource.

---

# 12. Docker and Podman Parity

The implementation must work conceptually for:

```text
Docker
Podman rootful
Podman rootless where possible
```

Audit runtime-specific assumptions.

Do not duplicate the entire topology implementation for each runtime.

Use a common runtime-provider abstraction with runtime-specific adapters.

Document behavior that genuinely differs between Docker and Podman.

---

# 13. Host vs Container vs Process Execution Context

Topology discovery must provide enough information for the planner to distinguish:

```text
host fault
container fault
process fault
container-internal fault
network-namespace fault
```

For example:

```text
mem.pressure
```

should be able to mean:

```text
host memory pressure
container memory pressure
process memory pressure
```

depending on the target and execution context.

Do not solve this by weakening `FaultDefinition.required_targets`.

The topology must provide the correct nodes.

---

# 14. Runtime Discovery Failure Handling

Audit what happens if:

```text
runtime unavailable
runtime CLI missing
permission denied
container stopped
container disappears during discovery
invalid Compose project
Podman socket unavailable
Docker daemon unavailable
```

Discovery should return structured errors rather than silently producing an incomplete graph that looks valid.

A partial graph must clearly indicate that discovery was incomplete.

---

# 15. Test the Actual Environment

Use the supplied Compose test environment.

Verify with both:

```bash
mayhem topology discover --compose docker-compose.yml
```

and:

```bash
mayhem --podman topology discover --compose docker-compose.yml
```

when the corresponding stack is running.

Also inspect the runtime directly:

```bash
podman ps
podman inspect <container>
```

or Docker equivalents.

Use the runtime's actual labels, IDs, networks, IPs, ports, and process information to validate Mayhem's discovery.

Do not make assumptions based only on the Compose YAML.

---

# 16. Required Final Topology

For the test Compose environment, the final topology should be capable of representing at least:

```text
Host
├── Container: download-1
│   └── Process: python
├── Container: download-2
│   └── Process: python
├── Container: lb
│   └── Process: nginx
└── Container: db
    └── Process: postgres
```

plus:

```text
Compose services
Networks
IP addresses
Ports
Host/container relationships
Container/process relationships
```

Exact process-discovery depth may depend on runtime permissions, but failures must be explicit rather than silently returning only service nodes.

---

# 17. Do Not Fix This by Hacking Target Matching

Do NOT make:

```text
proc.pause
```

accept:

```text
kind=service
```

just because process discovery is missing.

Do NOT make:

```text
container.kill
```

operate on logical service IDs without resolving the actual runtime container.

The topology must become more accurate so the existing fault-target validation remains meaningful.

---

# 18. Testing Requirements

Add integration tests covering:

### Compose

* service discovery
* service ↔ container correlation
* project filtering
* container IDs
* labels
* networks
* IPs
* ports
* process discovery

### Docker

* runtime discovery
* matching
* container metadata

### Podman

* same coverage
* rootless behavior where practical

### Drift

* missing container
* extra container
* renamed/recreated container
* changed image
* changed IP
* stopped container

### Process

* process node creation
* container → process relationship
* PID changes after restart

### Network

* network membership
* IPs
* interfaces
* published ports

### Failure

* daemon unavailable
* permission denied
* malformed runtime data
* partial discovery

---

# 19. Required Output Before Implementation

First provide an audit with:

```text
1. Exact root causes
2. Incorrect assumptions in current implementation
3. Domain-model problems
4. Runtime-provider problems
5. Reconciliation/drift problems
6. Network-model problems
7. Process-discovery problems
8. Docker/Podman problems
9. Recovery implications
10. Tests currently missing
```

For each problem include:

```text
file/module
current behavior
why it is wrong
impact
recommended correction
```

Then provide:

```text
11. Minimal architectural changes
12. Files to modify
13. New files only where genuinely necessary
14. Migration/compatibility concerns
15. Implementation order
```

Do not implement unrelated features.

Do not expand the fault catalog until this topology problem is resolved.

The success criterion is:

> **Mayhem must be able to build a truthful, reconciled runtime topology from Docker Compose + Docker/Podman, including service, container, host, process, network, IP, and port relationships where discoverable, while preserving clear distinctions between logical and runtime resources.**
