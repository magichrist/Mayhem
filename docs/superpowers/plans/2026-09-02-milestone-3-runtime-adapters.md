# Milestone 3 Implementation Plan

**Scope:** docs/milestones/milestone-3.md (Phases 3.1-3.7)
**Date:** 2026-09-02

---

## File map

### New files

- src/mayhem/domain/runtime_adapter.py - RuntimeAdapter ABC, RuntimeCapability, CapabilityVerdict, AdapterCapabilities
- src/mayhem/topology/providers/docker_adapter.py - DockerAdapter(RuntimeAdapter)
- src/mayhem/topology/providers/podman_adapter.py - PodmanAdapter(RuntimeAdapter)
- src/mayhem/topology/providers/adapter_registry.py - best_effort() factory
- src/mayhem/domain/execution_loci.py - ThreeLocusContext, Locus, backward-compat
- src/mayhem/domain/remote_agent_interface.py - RemoteAgentInterface ABC (interface-only)
- src/mayhem/domain/k8s_adapter.py - KubernetesAdapterInterface ABC (interface-only)
- tests/unit/test_runtime_adapter.py - Adapter contract tests + FakeAdapter
- tests/unit/test_capability_matrix.py - Verdict matrix evaluation
- tests/unit/test_three_locus.py - Three-locus parsing, backward compat
- tests/unit/test_network_path_model.py - NetworkPath round-trip, fingerprint
- docs/adr/ADR-M3-1 through ADR-M3-8 - 8 ADRs

### Modified files

- src/mayhem/domain/topology.py - NetworkPath: add namespace, interface, protocol, ports, direction, fingerprint
- src/mayhem/domain/experiments.py - DrillFault: add optional network_path
- src/mayhem/domain/resources.py - Add NETWORK_FAULT; add fingerprint to TrackedResource
- src/mayhem/domain/execution_context.py - Add to_three_locus() bridge
- src/mayhem/cli/topology.py - Replace ContainerRuntimeProvider with adapter_registry
- src/mayhem/cli/services.py - Replace ContainerRuntimeProvider with adapter_registry
- src/mayhem/controller/executor.py - Accept RuntimeAdapter, delegate exec/signals
- src/mayhem/topology/service.py - Accept adapters via TopologyProvider
- src/mayhem/topology/providers/docker_runtime.py - Deprecated alias at bottom
- src/mayhem/infra/migrations.py - Migration M0010 for network path

---

## Phase 3.1 - RuntimeAdapter interface

### 3.1.1 Domain ABC: src/mayhem/domain/runtime_adapter.py

RuntimeCapability(StrEnum): EXEC, PID, SIGNAL, NETNS, RESOURCE_LIMITS, INSPECT, COMPOSE_FILTER
CapabilityVerdict(StrEnum): SUPPORTED, ALTERNATIVE, UNSUPPORTED, UNKNOWN
AdapterCapabilities(BaseModel, frozen=True): engine, rootless, supported, alternatives, version. Method verdict(cap) -> CapabilityVerdict
RuntimeAdapter(ABC): id(), is_available(), capabilities(), ps(), inspect(), exec(), pid(), signal(), netns(), filter_by_compose(), filter_by_names(), discover()

### 3.1.2 DockerAdapter: src/mayhem/topology/providers/docker_adapter.py

Extract from ContainerRuntimeProvider. Keep module-level helpers (_inspect_pid, _ps, _labels, etc.) unchanged. DockerAdapter calls them with engine="docker". All capabilities SUPPORTED. exec() uses subprocess.run(["docker", "exec", ...]). signal() uses subprocess.run(["docker", "kill", "-s", ...]). netns() resolves PID -> /proc/{pid}/ns/net. discover() preserves existing PartialGraph logic.

### 3.1.3 PodmanAdapter: src/mayhem/topology/providers/podman_adapter.py

Same structure. Rootless detection via podman info -> host.security.rootless. Rootless: EXEC=SUPPORTED, PID=SUPPORTED, SIGNAL=SUPPORTED, NETNS=ALTERNATIVE, RESOURCE_LIMITS=UNSUPPORTED. Rootful: all SUPPORTED.

### 3.1.4 Adapter registry: src/mayhem/topology/providers/adapter_registry.py

register(name, cls) adds to _REGISTRY. best_effort(engine) returns adapter for requested engine or first available (docker preferred). Auto-registers DockerAdapter and PodmanAdapter.

### 3.1.5 Migrate CLI callers

cli/topology.py (lines 33, 44, 69): Replace ContainerRuntimeProvider.best_effort(engine) with adapter_registry.best_effort(engine).
cli/services.py (lines 62, 68): Same migration.

### 3.1.6 TopologyService integration

DockerAdapter/PodmanAdapter implement TopologyProvider duck-type (id, is_available, discover). topology/service.py discovers them through the same list[TopologyProvider] interface.

### 3.1.7 Deprecated alias

At bottom of docker_runtime.py: ContainerRuntimeProvider = DockerAdapter  # type: ignore[misc]

### 3.1.8 Tests: tests/unit/test_runtime_adapter.py

- FakeAdapter(RuntimeAdapter) stub satisfies ABC
- FakeAdapter.capabilities() returns valid AdapterCapabilities
- best_effort("docker") returns DockerAdapter
- best_effort(None) prefers docker
- best_effort("unknown") returns None
- RuntimeAdapter ABC cannot be instantiated directly

---

## Phase 3.2 - CapabilityRequirements + verdict matrix

### 3.2.1 CapabilityRequirements (in runtime_adapter.py)

dataclass with: platforms, runtimes, target_kinds, privileges, namespaces, tools, kernel_features, permissions (all frozenset)

### 3.2.2 VerdictResult (in runtime_adapter.py)

BaseModel with: requirements, verdicts dict, blocking bool. Method refuse_with_message() returns human-readable refusal.

### 3.2.3 RuntimeAdapter.evaluate()

Maps CapabilityRequirements to verdict checks. UNSUPPORTED -> blocking=True.

### 3.2.4 Planner integration in safety.py

validate_plan() accepts optional adapter. Builds CapabilityRequirements from plan, calls adapter.evaluate(). If blocking -> PlanRefusedError. ALTERNATIVE -> warning.

### 3.2.5 Tests: tests/unit/test_capability_matrix.py

Docker rootful: all SUPPORTED. Podman rootless: NETNS=ALTERNATIVE, RESOURCE_LIMITS=UNSUPPORTED. Blocking/non-blocking evaluation. Refusal message generation.

---

## Phase 3.3 - Three-locus ExecutionContext

### 3.3.1 src/mayhem/domain/execution_loci.py

Locus dataclass: target, agent, tool. ThreeLocusContext: target_locus, agent_locus, tool_locus, plan_context. from_single() classmethod for backward compat.

### 3.3.2 Bridge in PlannedFault

Add execution_loci dict | None = None. Planner populates from resolved targets. Executor uses it when present, falls back to execution_context.

### 3.3.3 Backward compat

Pre-0.3.0 specs -> planner calls ThreeLocusContext.from_single(). Existing ExecutionContextSpec stays.

### 3.3.4 Tests: tests/unit/test_three_locus.py

from_single produces identical loci. PlannedFault with/without loci. Backward compat inference.

---

## Phase 3.4 - Rootless / remote / k8s capability matrix

### 3.4.1 Podman rootless rows

EXEC=SUPPORTED, PID=SUPPORTED, SIGNAL=SUPPORTED, NETNS=ALTERNATIVE, RESOURCE_LIMITS=UNSUPPORTED, INSPECT=SUPPORTED, COMPOSE_FILTER=SUPPORTED

### 3.4.2 Remote target UNSUPPORTED

RemoteAgentInterface returns UNSUPPORTED for all. Planner refuses with clear message.

### 3.4.3 Kubernetes UNSUPPORTED

KubernetesAdapterInterface returns UNSUPPORTED. Planner refuses with clear message.

---

## Phase 3.5 - Remote-agent + k8s interface ADRs (no code)

### 3.5.1 ADR-M3-5: RemoteAgentInterface contract

connect, capability_handshake, target_resolution, tool_run, cancel, teardown. No SSH transport.

### 3.5.2 ADR-M3-6: Kubernetes adapter interface

Satisfies RuntimeAdapter ABC. All UNSUPPORTED until M7.

### 3.5.3 Stub files

remote_agent_interface.py: ABC with docstring. k8s_adapter.py: ABC stub.

---

## Phase 3.6 - NetworkPath model + fingerprints

### 3.6.1 Extend NetworkPath in domain/topology.py

Add: namespace (str|None), interface (str|None), protocol (str="tcp"), ports (tuple[int,...]=()), direction (str="both"), fingerprint (str="")

### 3.6.2 compute_network_fingerprint()

hashlib.sha256(f"{src}:{dst}:{namespace}:{protocol}:{fault_type}").hexdigest()[:16]

### 3.6.3 Network resource type + fingerprint

resources.py: NETWORK_FAULT = "network_fault" in ResourceType. TrackedResource gets fingerprint: str = "".

### 3.6.4 DrillFault.network_path

Add network_path: str | None = None to DrillFault. Additive, non-breaking.

### 3.6.5 Tests: tests/unit/test_network_path_model.py

NetworkPath round-trip with new fields. Fingerprint stability. DrillFault backward compat.

---

## Phase 3.7 - Migration freeze prep + e2e

### 3.7.1 Migration M0010_NETWORK_PATH

Add plan_steps columns: network_path TEXT, path_namespace TEXT, path_interface TEXT. Add TrackedResource column: fingerprint TEXT.

### 3.7.2 Run full unit + integration suite

All unit + integration green. No mypy/ruff regressions.

### 3.7.3 E2E

Docker-compose drill exercises DockerAdapter end-to-end incl. capability verdict + network-path fingerprint. Podman path gated on podman availability.

### 3.7.4 ADR-M3-7 and ADR-M3-8

Write NetworkPath + fingerprint ADR. Write fault registry ADR (per-adapter targeting, precedence).

### 3.7.5 No regressions

Verify: mypy clean, ruff clean, all 490+ tests pass.
