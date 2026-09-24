"""Seed fault catalog — curated FaultDefinitions matching the taxonomy doc.

This is the planner's source of truth for what is injectable, at what risk,
on which node kinds, with which params. Backends gate actual tooling; a
definition without an executable compensation template will be refused at
plan time (see controller.compensation).
"""

from __future__ import annotations

from datetime import date
from typing import Any

from mayhem.domain.capabilities import Capability
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.faults import (
    EngineLane,
    FailureDomain,
    FaultCategory,
    FaultDefinition,
    MaturityLevel,
    ParamSpec,
    ParamType,
    Reversibility,
    TargetKind,
    VerificationMethod,
)
from mayhem.domain.risks import RiskLevel
from mayhem.domain.topology import NodeKind

_S = ParamSpec(name="seconds", type=ParamType.DURATION)
_CONTAINER_SERVICE_KINDS = frozenset(
    {NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.EXTERNAL_DEPENDENCY}
)
_CONTAINER_SERVICE_TARGETS = frozenset(
    {TargetKind.SERVICE, TargetKind.CONTAINER, TargetKind.EXTERNAL_DEPENDENCY}
)

RELIABILITY_MATRIX: tuple[str, ...] = (
    "proc.pause",
    "process.stop",
    "cpu.saturate",
    "mem.exhaust",
    "net.latency",
    "net.packet_loss",
    "fs.fill",
    "net.load",
    "process.kill",
)


def _pct(minimum: float, maximum: float) -> ParamSpec:
    return ParamSpec(name="percent", type=ParamType.PERCENT, minimum=minimum, maximum=maximum)


_FAILURE_DOMAIN_BY_CATEGORY: dict[FaultCategory, FailureDomain] = {
    FaultCategory.PROCESS: FailureDomain.PROCESS,
    FaultCategory.CPU: FailureDomain.CPU,
    FaultCategory.MEMORY: FailureDomain.MEMORY,
    FaultCategory.STORAGE: FailureDomain.STORAGE,
    FaultCategory.NETWORK: FailureDomain.NETWORK,
    FaultCategory.CONTAINER: FailureDomain.PROCESS,
    FaultCategory.NODE: FailureDomain.PLATFORM,
    FaultCategory.HTTP_API: FailureDomain.APPLICATION,
    FaultCategory.DATABASE: FailureDomain.DEPENDENCY,
    FaultCategory.LOAD: FailureDomain.APPLICATION,
    FaultCategory.FUZZ: FailureDomain.APPLICATION,
    FaultCategory.DNS: FailureDomain.DEPENDENCY,
    FaultCategory.TLS: FailureDomain.DEPENDENCY,
    FaultCategory.CLOCK: FailureDomain.PLATFORM,
    FaultCategory.FD: FailureDomain.PROCESS,
    FaultCategory.DEPENDENCY: FailureDomain.DEPENDENCY,
    FaultCategory.K8S: FailureDomain.PLATFORM,
}

_TARGET_PRIORITY: tuple[NodeKind, ...] = (
    NodeKind.EXTERNAL_DEPENDENCY,
    NodeKind.POD,
    NodeKind.K8S_NODE,
    NodeKind.PROCESS,
    NodeKind.SERVICE,
    NodeKind.CONTAINER,
    NodeKind.HOST,
)
_TARGET_KIND_BY_NODE = {
    NodeKind.EXTERNAL_DEPENDENCY: TargetKind.EXTERNAL_DEPENDENCY,
    NodeKind.POD: TargetKind.POD,
    NodeKind.K8S_NODE: TargetKind.NODE,
    NodeKind.PROCESS: TargetKind.PROCESS,
    NodeKind.SERVICE: TargetKind.SERVICE,
    NodeKind.CONTAINER: TargetKind.CONTAINER,
    NodeKind.HOST: TargetKind.PROCESS,
}

_VERIFICATION_BY_CATEGORY: dict[FaultCategory, VerificationMethod] = {
    FaultCategory.PROCESS: VerificationMethod.PROCESS_SIGNAL,
    FaultCategory.CPU: VerificationMethod.RESOURCE_METRIC,
    FaultCategory.MEMORY: VerificationMethod.RESOURCE_METRIC,
    FaultCategory.STORAGE: VerificationMethod.STORAGE_ACCESS,
    FaultCategory.NETWORK: VerificationMethod.NETWORK_PATH,
    FaultCategory.CONTAINER: VerificationMethod.PROCESS_EXIT,
    FaultCategory.NODE: VerificationMethod.PROCESS_EXIT,
    FaultCategory.HTTP_API: VerificationMethod.HTTP_RESPONSE,
    FaultCategory.DATABASE: VerificationMethod.DEPENDENCY_RESPONSE,
    FaultCategory.LOAD: VerificationMethod.HTTP_RESPONSE,
    FaultCategory.FUZZ: VerificationMethod.HTTP_RESPONSE,
    FaultCategory.DNS: VerificationMethod.DNS_RESOLUTION,
    FaultCategory.TLS: VerificationMethod.DEPENDENCY_RESPONSE,
    FaultCategory.CLOCK: VerificationMethod.PLATFORM_STATE,
    FaultCategory.FD: VerificationMethod.RESOURCE_METRIC,
    FaultCategory.DEPENDENCY: VerificationMethod.DEPENDENCY_RESPONSE,
    FaultCategory.K8S: VerificationMethod.KUBERNETES_OBJECT,
}

_EFFECT_BY_CATEGORY: dict[FaultCategory, str] = {
    FaultCategory.PROCESS: "process execution state changes",
    FaultCategory.CPU: "target CPU utilization rises or is throttled",
    FaultCategory.MEMORY: "target memory pressure rises",
    FaultCategory.STORAGE: "target storage availability or access latency changes",
    FaultCategory.NETWORK: "target network path timing, delivery, or capacity changes",
    FaultCategory.CONTAINER: "container lifecycle state changes",
    FaultCategory.NODE: "host service lifecycle changes",
    FaultCategory.HTTP_API: "HTTP response behavior changes",
    FaultCategory.DATABASE: "database dependency behavior changes",
    FaultCategory.LOAD: "request load increases",
    FaultCategory.FUZZ: "request parsing and validation work increases",
    FaultCategory.DNS: "name resolution fails or slows",
    FaultCategory.TLS: "TLS trust or handshake behavior changes",
    FaultCategory.CLOCK: "target clock offset changes",
    FaultCategory.FD: "file descriptor availability decreases",
    FaultCategory.DEPENDENCY: "upstream dependency behavior changes",
    FaultCategory.K8S: "Kubernetes object or workload state changes",
}

_RECONCILED_FAULTS = frozenset(
    {
        "process.stop",
        "process.kill",
        "process.crash_loop",
        "process.restart_delay",
        "k8s.pod_kill",
        "k8s.pod_evict",
        "k8s.pod_oom",
        "k8s.pod_delete_uncontrolled",
        "k8s.pod_restart_churn",
        "k8s.sidecar_termination",
    }
)
_VERIFICATION_DATE = date(2026, 9, 24)


def _target_kind(definition: FaultDefinition) -> TargetKind:
    for node_kind in _TARGET_PRIORITY:
        if node_kind in definition.applicable_node_kinds:
            return _TARGET_KIND_BY_NODE[node_kind]
    raise ValueError(f"fault {definition.id!r} has no target kind")


def _derived_target_kinds(definition: FaultDefinition) -> frozenset[TargetKind]:
    kinds = {
        _TARGET_KIND_BY_NODE[node_kind]
        for node_kind in definition.applicable_node_kinds
        if node_kind in _TARGET_KIND_BY_NODE
    }
    return frozenset(kinds or {_target_kind(definition)})


def _engine_lanes(definition: FaultDefinition) -> frozenset[EngineLane]:
    lanes: set[EngineLane] = set()
    if definition.category is FaultCategory.K8S:
        lanes.add(EngineLane.KUBERNETES)
    if NodeKind.POD in definition.applicable_node_kinds:
        lanes.add(EngineLane.KUBERNETES)
    if Capability.DOCKER_ENGINE in definition.required_caps:
        lanes.update({EngineLane.DOCKER, EngineLane.PODMAN})
    if definition.applicable_node_kinds & {
        NodeKind.CONTAINER,
        NodeKind.PROCESS,
        NodeKind.SERVICE,
        NodeKind.HOST,
    }:
        lanes.update({EngineLane.DOCKER, EngineLane.PODMAN, EngineLane.HOST})
    if NodeKind.EXTERNAL_DEPENDENCY in definition.applicable_node_kinds:
        lanes.add(EngineLane.MULTI_ENGINE)
    return frozenset(lanes or {EngineLane.MULTI_ENGINE})


def _define(**values: Any) -> FaultDefinition:
    definition = FaultDefinition.model_validate(values)
    catalog_only = definition.catalog_only
    maturity = definition.maturity
    verification_date = definition.verification_date
    if maturity is MaturityLevel.EXPERIMENTAL and not catalog_only:
        maturity = MaturityLevel.VERIFIED_UNIT
        verification_date = _VERIFICATION_DATE
    reversibility = definition.reversibility
    target_kind = definition.target_kind or _target_kind(definition)
    target_kinds = definition.target_kinds or _derived_target_kinds(definition)
    if reversibility is None:
        if definition.id in _RECONCILED_FAULTS:
            reversibility = Reversibility.RECONCILED
        elif definition.reversible:
            reversibility = Reversibility.REVERSIBLE
        else:
            reversibility = Reversibility.IRREVERSIBLE
    deprecation_path = definition.deprecation_path
    replacement = definition.replacement_fault_id
    if definition.id == "k8s.image_pull_slow":
        deprecation_path = (
            "Keep catalog-only until a registry-pacing runtime exists; deprecate before removal "
            "with a release note and an explicit refusal migration."
        )
    if definition.id == "k8s.nvidia_smi_error":
        deprecation_path = (
            "Retire on clusters without NVIDIA device-plugin support after users migrate to the "
            "documented node-state families."
        )
    compensation_evidence = definition.compensation_evidence or (
        ("undo operation", "verification probe")
        if reversibility is Reversibility.REVERSIBLE
        else ("reconciliation result", "recovery result")
    )
    return definition.model_copy(
        update={
            "failure_domain": definition.failure_domain
            or _FAILURE_DOMAIN_BY_CATEGORY[definition.category],
            "target_kind": target_kind,
            "target_kinds": target_kinds,
            "engine_lanes": definition.engine_lanes or _engine_lanes(definition),
            "observable_effect": definition.observable_effect
            or _EFFECT_BY_CATEGORY[definition.category],
            "compensation_evidence": compensation_evidence,
            "verification_method": definition.verification_method
            or _VERIFICATION_BY_CATEGORY[definition.category],
            "reversibility": reversibility,
            "maturity": maturity,
            "verification_date": verification_date,
            "deprecation_path": deprecation_path,
            "replacement_fault_id": replacement,
        }
    )


CATALOG: tuple[FaultDefinition, ...] = (
    _define(
        id="proc.pause",
        category=FaultCategory.PROCESS,
        risk=RiskLevel.LOW,
        required_caps=frozenset({Capability.PROCESS_CONTROL}),
        applicable_node_kinds=frozenset({NodeKind.PROCESS, NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=600.0,
        params_schema=(),
    ),
    _define(
        id="process.stop",
        category=FaultCategory.PROCESS,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.PROCESS_CONTROL}),
        applicable_node_kinds=frozenset({NodeKind.PROCESS, NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=300.0,
        params_schema=(),
    ),
    _define(
        id="process.kill",
        category=FaultCategory.PROCESS,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.PROCESS_CONTROL}),
        applicable_node_kinds=frozenset({NodeKind.PROCESS, NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=60.0,
        params_schema=(),
    ),
    _define(
        id="process.crash_loop",
        category=FaultCategory.PROCESS,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.DOCKER_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=120.0,
        params_schema=(
            ParamSpec(name="restarts", type=ParamType.INTEGER, minimum=1, maximum=1000, default=10),
            ParamSpec(name="interval", type=ParamType.STRING, default="2s"),
        ),
    ),
    _define(
        id="process.startup_delay",
        category=FaultCategory.PROCESS,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.PROCESS_CONTROL}),
        applicable_node_kinds=frozenset(
            {NodeKind.PROCESS, NodeKind.SERVICE, NodeKind.CONTAINER}
        ),
        max_duration_s=300.0,
        params_schema=(ParamSpec(name="seconds", type=ParamType.DURATION, default="10s"),),
        observable_effect="target readiness is delayed after process startup",
        verification_method=VerificationMethod.PROCESS_EXIT,
        catalog_only=True,
        refusal_reason=(
            "catalog.unsupported: startup gating requires an application-aware readiness hook; "
            "use process.crash_loop for lifecycle recovery"
        ),
    ),
    _define(
        id="cpu.saturate",
        category=FaultCategory.CPU,
        risk=RiskLevel.MEDIUM,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.HOST, NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(_pct(minimum=1.0, maximum=100.0),),
    ),
    _define(
        id="cpu.throttle",
        category=FaultCategory.CPU,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.DOCKER_ENGINE}),
        # A reserve-share throttle needs the container engine cgroup knobs
        # (``update --cpus``), so it cannot address a bare HOST process.
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(_pct(minimum=1.0, maximum=100.0),),
    ),
    _define(
        id="mem.exhaust",
        category=FaultCategory.MEMORY,
        risk=RiskLevel.HIGH,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.POD}),
        max_duration_s=120.0,
        params_schema=(
            _pct(minimum=1.0, maximum=99.0),
            ParamSpec(name="amount", type=ParamType.BYTES),
            # ``allocate`` (default) commits anonymous memory. A slow, sustained
            # leak is a distinct fault (mem.leak); this fault only ever allocates,
            # so any other mode is refused at plan time.
            ParamSpec(name="mode", type=ParamType.STRING, default="allocate"),
        ),
    ),
    _define(
        id="mem.leak",
        category=FaultCategory.MEMORY,
        risk=RiskLevel.HIGH,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="rate_mb", type=ParamType.INTEGER, default=8, minimum=1, maximum=512),
        ),
    ),
    _define(
        id="fs.fill",
        category=FaultCategory.STORAGE,
        risk=RiskLevel.MEDIUM,
        reversible=True,
        applicable_node_kinds=frozenset(
            {NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.HOST, NodeKind.POD}
        ),
        max_duration_s=300.0,
        params_schema=(_pct(minimum=1.0, maximum=99.0),),
    ),
    _define(
        id="fs.inode_exhaust",
        category=FaultCategory.STORAGE,
        risk=RiskLevel.MEDIUM,
        reversible=True,
        applicable_node_kinds=frozenset(
            {NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.HOST, NodeKind.POD}
        ),
        max_duration_s=300.0,
        # Consumes free inodes (zero-byte marker files) instead of capacity;
        # undo removes the marker files, so the filesystem is fully restored.
        params_schema=(_pct(minimum=1.0, maximum=99.0),),
    ),
    _define(
        id="fs.io_stress",
        category=FaultCategory.STORAGE,
        risk=RiskLevel.MEDIUM,
        reversible=True,
        applicable_node_kinds=frozenset(
            {NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.HOST, NodeKind.POD}
        ),
        max_duration_s=120.0,
        params_schema=(
            _S,
            ParamSpec(name="workers", type=ParamType.INTEGER, default=1, minimum=1, maximum=8),
            ParamSpec(
                name="io_bytes",
                type=ParamType.BYTES,
                default=64 * 1024 * 1024,
                minimum=1024 * 1024,
                maximum=1024**3,
            ),
            # Spec-compliant throughput twins: when either is set the payload
            # drives sustained read+write I/O at the given MiB/s per worker
            # instead of the io_bytes churn loop.
            ParamSpec(name="read_mb_s", type=ParamType.INTEGER, minimum=1, maximum=512),
            ParamSpec(name="write_mb_s", type=ParamType.INTEGER, minimum=1, maximum=512),
            ParamSpec(name="block_size", type=ParamType.STRING, default="64k"),
        ),
    ),
    _define(
        id="fs.read_only",
        category=FaultCategory.STORAGE,
        risk=RiskLevel.HIGH,
        reversible=True,
        required_caps=frozenset({Capability.FS_CONTROL}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.HOST}),
        max_duration_s=120.0,
        params_schema=(ParamSpec(name="path", type=ParamType.STRING, default="/"),),
    ),
    _define(
        id="fs.permission_failure",
        category=FaultCategory.STORAGE,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.FS_CONTROL}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.HOST}),
        max_duration_s=120.0,
        params_schema=(
            ParamSpec(name="path", type=ParamType.STRING, default="/tmp"),
            ParamSpec(name="mode", type=ParamType.STRING, default="0000"),
        ),
        observable_effect="target storage operations fail with permission denied",
        verification_method=VerificationMethod.STORAGE_ACCESS,
        catalog_only=True,
        refusal_reason=(
            "catalog.unsupported: no permission-preserving executor is registered; "
            "choose fs.read_only or fs.io_stress"
        ),
    ),
    _define(
        id="net.latency",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.MEDIUM,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            _S,
            ParamSpec(name="jitter_ms", type=ParamType.INTEGER, default=0),
            ParamSpec(name="direction", type=ParamType.STRING, default="egress"),
        ),
    ),
    _define(
        id="net.packet_loss",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.MEDIUM,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            _pct(minimum=1.0, maximum=100.0),
            ParamSpec(name="direction", type=ParamType.STRING, default="egress"),
        ),
    ),
    _define(
        id="net.bandwidth",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="rate", type=ParamType.STRING, required=True),
            ParamSpec(name="burst", type=ParamType.STRING, default="10k"),
            ParamSpec(name="direction", type=ParamType.STRING, default="egress"),
        ),
    ),
    _define(
        id="net.partition",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.POD}),
        max_duration_s=120.0,
        params_schema=(),
    ),
    _define(
        id="net.load",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.MEDIUM,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=600.0,
        params_schema=(
            ParamSpec(name="users", type=ParamType.INTEGER, minimum=1.0),
            # ``url``: target for the generated load script. Defaults to the
            # target container's own network address (live IP + first TCP
            # serving port); ``http://localhost/`` only when no address is
            # known at plan time.
            ParamSpec(name="url", type=ParamType.STRING, default=None),
            # ``script``: path on the drill host to a k6 ``script.js`` run by
            # the host k6 against the target; when set it replaces the built-in
            # inline script instead of ``url``.
            ParamSpec(name="script", type=ParamType.STRING, default=None),
        ),
    ),
    _define(
        id="net.connection_reset",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="port", type=ParamType.INTEGER, required=True, minimum=1, maximum=65535),
            ParamSpec(name="protocol", type=ParamType.STRING, default="tcp"),
        ),
    ),
    _define(
        id="net.connection_refuse",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="port", type=ParamType.INTEGER, required=True, minimum=1, maximum=65535),
            ParamSpec(name="protocol", type=ParamType.STRING, default="tcp"),
        ),
    ),
    _define(
        id="net.reorder",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            _pct(minimum=1.0, maximum=100.0),
            ParamSpec(name="delay_ms", type=ParamType.INTEGER, default=50),
            ParamSpec(name="direction", type=ParamType.STRING, default="egress"),
        ),
    ),
    _define(
        id="net.duplicate",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            _pct(minimum=1.0, maximum=100.0),
            ParamSpec(name="direction", type=ParamType.STRING, default="egress"),
        ),
    ),
    _define(
        id="node.service_stop",
        category=FaultCategory.NODE,
        risk=RiskLevel.HIGH,
        applicable_node_kinds=frozenset({NodeKind.SERVICE}),
        max_duration_s=120.0,
        params_schema=(),
    ),
    _define(
        id="http.error_injection",
        category=FaultCategory.HTTP_API,
        risk=RiskLevel.MEDIUM,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.EXTERNAL_DEPENDENCY}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="status", type=ParamType.INTEGER, default=500),
            ParamSpec(
                name="probability",
                type=ParamType.PERCENT,
                minimum=0.0,
                maximum=100.0,
                default=0.0,
            ),
            ParamSpec(
                name="port",
                type=ParamType.INTEGER,
                minimum=1,
                maximum=65535,
                default=80,
            ),
        ),
    ),
    _define(
        id="http.latency",
        category=FaultCategory.HTTP_API,
        risk=RiskLevel.MEDIUM,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.EXTERNAL_DEPENDENCY}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="delay_ms", type=ParamType.INTEGER, minimum=1, maximum=30000),
            ParamSpec(
                name="probability",
                type=ParamType.PERCENT,
                minimum=1.0,
                maximum=100.0,
                default=100.0,
            ),
            ParamSpec(
                name="port",
                type=ParamType.INTEGER,
                minimum=1,
                maximum=65535,
                default=80,
            ),
        ),
    ),
    _define(
        id="db.slow_query",
        category=FaultCategory.DATABASE,
        risk=RiskLevel.MEDIUM,
        applicable_node_kinds=frozenset({NodeKind.EXTERNAL_DEPENDENCY, NodeKind.SERVICE}),
        max_duration_s=300.0,
        params_schema=(_S,),
    ),
    _define(
        id="db.connection_exhaust",
        category=FaultCategory.DATABASE,
        risk=RiskLevel.HIGH,
        applicable_node_kinds=frozenset(
            {NodeKind.EXTERNAL_DEPENDENCY, NodeKind.SERVICE, NodeKind.CONTAINER}
        ),
        max_duration_s=120.0,
        params_schema=(
            ParamSpec(
                name="connections", type=ParamType.INTEGER, required=True, minimum=1, maximum=256
            ),
            ParamSpec(name="host", type=ParamType.STRING, required=True),
            ParamSpec(
                name="port",
                type=ParamType.INTEGER,
                minimum=1,
                maximum=65535,
                default=3306,
            ),
        ),
    ),
    _define(
        id="db.query_error",
        category=FaultCategory.DATABASE,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset(
            {NodeKind.EXTERNAL_DEPENDENCY, NodeKind.SERVICE, NodeKind.CONTAINER}
        ),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(
                name="probability",
                type=ParamType.PERCENT,
                minimum=1.0,
                maximum=100.0,
                default=100.0,
            ),
            ParamSpec(name="error", type=ParamType.STRING, default="deadlock"),
            ParamSpec(
                name="port",
                type=ParamType.INTEGER,
                minimum=1,
                maximum=65535,
                default=3306,
            ),
        ),
    ),
    _define(
        id="load.spike",
        category=FaultCategory.LOAD,
        risk=RiskLevel.LOW,
        applicable_node_kinds=frozenset({NodeKind.SERVICE}),
        max_duration_s=900.0,
        params_schema=(
            ParamSpec(name="rps", type=ParamType.INTEGER, minimum=1.0),
            _S,
        ),
    ),
    _define(
        id="fuzz.protocol_abuse",
        category=FaultCategory.FUZZ,
        risk=RiskLevel.HIGH,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.EXTERNAL_DEPENDENCY}),
        max_duration_s=180.0,
        params_schema=(),
    ),
    _define(
        id="dns.resolve_delay",
        category=FaultCategory.DNS,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.HOST}),
        max_duration_s=300.0,
        params_schema=(_S,),
    ),
    _define(
        id="dns.timeout",
        category=FaultCategory.DNS,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.HOST}),
        max_duration_s=120.0,
        params_schema=(),
    ),
    _define(
        id="dns.servfail",
        category=FaultCategory.DNS,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.HOST}),
        max_duration_s=120.0,
        params_schema=(),
    ),
    _define(
        id="dns.nxdomain",
        category=FaultCategory.DNS,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.HOST}),
        max_duration_s=300.0,
        params_schema=(ParamSpec(name="domain", type=ParamType.STRING),),
    ),
    _define(
        id="tls.certificate_expired",
        category=FaultCategory.TLS,
        risk=RiskLevel.HIGH,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.EXTERNAL_DEPENDENCY}),
        max_duration_s=120.0,
        params_schema=(),
    ),
    _define(
        id="tls.handshake_failure",
        category=FaultCategory.TLS,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset(
            {NodeKind.SERVICE, NodeKind.EXTERNAL_DEPENDENCY, NodeKind.CONTAINER}
        ),
        max_duration_s=120.0,
        params_schema=(
            ParamSpec(
                name="port",
                type=ParamType.INTEGER,
                minimum=1,
                maximum=65535,
                default=443,
            ),
        ),
    ),
    _define(
        id="container.kill",
        category=FaultCategory.CONTAINER,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.DOCKER_ENGINE}),
        # A compose service is a SERVICE-kind node backed by a container whose
        # container.kill restarts, so accept SERVICE like sibling faults.
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=60.0,
        params_schema=(ParamSpec(name="signal", type=ParamType.STRING, default="SIGKILL"),),
    ),
    _define(
        id="container.restart",
        category=FaultCategory.CONTAINER,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.DOCKER_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=60.0,
        params_schema=(),
    ),
    _define(
        id="container.pause",
        category=FaultCategory.CONTAINER,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.DOCKER_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=300.0,
        params_schema=(),
    ),
    _define(
        id="clock.skew",
        category=FaultCategory.CLOCK,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.HOST, NodeKind.CONTAINER, NodeKind.SERVICE}),
        max_duration_s=300.0,
        params_schema=(ParamSpec(name="offset_ms", type=ParamType.INTEGER, required=True),),
    ),
    _define(
        id="dependency.block",
        category=FaultCategory.DEPENDENCY,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset(
            {NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.EXTERNAL_DEPENDENCY}
        ),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="port", type=ParamType.INTEGER, required=True, minimum=1, maximum=65535),
            ParamSpec(name="protocol", type=ParamType.STRING, default="tcp"),
        ),
    ),
    _define(
        id="dependency.timeout",
        category=FaultCategory.DEPENDENCY,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset(
            {NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.EXTERNAL_DEPENDENCY}
        ),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="port", type=ParamType.INTEGER, required=True, minimum=1, maximum=65535),
            ParamSpec(
                name="delay_ms",
                type=ParamType.INTEGER,
                required=True,
                minimum=1,
                maximum=30000,
            ),
            ParamSpec(name="protocol", type=ParamType.STRING, default="tcp"),
        ),
    ),
    _define(
        id="dependency.flap",
        category=FaultCategory.DEPENDENCY,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset(
            {NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.EXTERNAL_DEPENDENCY}
        ),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="port", type=ParamType.INTEGER, required=True, minimum=1, maximum=65535),
            ParamSpec(name="interval", type=ParamType.DURATION, default=10.0),
            ParamSpec(name="failure_probability", type=ParamType.PERCENT, default=50.0),
            ParamSpec(name="protocol", type=ParamType.STRING, default="tcp"),
        ),
    ),
    _define(
        id="dependency.rate_limit",
        category=FaultCategory.DEPENDENCY,
        risk=RiskLevel.MEDIUM,
        applicable_node_kinds=frozenset(
            {NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.EXTERNAL_DEPENDENCY}
        ),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(
                name="rate",
                type=ParamType.INTEGER,
                required=True,
                minimum=1,
                maximum=1000,
            ),
            ParamSpec(name="burst", type=ParamType.INTEGER, default=200, minimum=1, maximum=1000),
            ParamSpec(name="code", type=ParamType.INTEGER, default=429),
            ParamSpec(
                name="port",
                type=ParamType.INTEGER,
                minimum=1,
                maximum=65535,
                default=80,
            ),
        ),
    ),
    _define(
        id="dependency.connection_refuse",
        category=FaultCategory.DEPENDENCY,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset(
            {NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.EXTERNAL_DEPENDENCY}
        ),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="port", type=ParamType.INTEGER, required=True, minimum=1, maximum=65535),
            ParamSpec(name="protocol", type=ParamType.STRING, default="tcp"),
        ),
    ),
    _define(
        id="dependency.malformed_response",
        category=FaultCategory.DEPENDENCY,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset(
            {NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.EXTERNAL_DEPENDENCY}
        ),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="port", type=ParamType.INTEGER, required=True, minimum=1, maximum=65535),
            ParamSpec(name="body", type=ParamType.STRING, default="not-json"),
            ParamSpec(name="content_type", type=ParamType.STRING, default="application/json"),
        ),
        observable_effect="upstream response parsing fails on malformed payload",
        verification_method=VerificationMethod.DEPENDENCY_RESPONSE,
        catalog_only=True,
        refusal_reason=(
            "catalog.unsupported: no protocol-aware response proxy is registered; "
            "use http.error_injection for deterministic status failures"
        ),
    ),
    _define(
        id="fd.exhaust",
        category=FaultCategory.FD,
        risk=RiskLevel.HIGH,
        applicable_node_kinds=frozenset(
            {NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.HOST, NodeKind.POD}
        ),
        max_duration_s=120.0,
        params_schema=(ParamSpec(name="limit", type=ParamType.INTEGER, default=64),),
    ),
    # ── Kubernetes archetypes (ADR-M7-3, ADR-M7-4) ──────────────────────────
    # All k8s archetypes are AVAILABLE when the live cluster driver is present;
    # the executor register is the source of truth for executability.  Families
    # without a kubectl primitive (image_pull_slow) remain catalog-only and
    # refuse at can_apply time with a stable unsupported reason.
    #
    # Capacity-stress sub-category (ADR-M7-3)
    _define(
        id="k8s.node_pressure",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.K8S_NODE}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="resource", type=ParamType.STRING, default="cpu"),
            ParamSpec(name="target_percent", type=ParamType.PERCENT, minimum=1, maximum=100),
        ),
    ),
    _define(
        id="k8s.pod_oom",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=120.0,
        params_schema=(ParamSpec(name="memory_limit", type=ParamType.STRING, default="64Mi"),),
    ),
    _define(
        id="k8s.pod_pressure",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="resource", type=ParamType.STRING, default="cpu"),
            ParamSpec(name="target_percent", type=ParamType.PERCENT, minimum=1, maximum=100),
        ),
    ),
    # Network sub-category (ADR-M7-3)
    _define(
        id="k8s.network_policy",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD, NodeKind.K8S_NODE}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="policy_name", type=ParamType.STRING),
            ParamSpec(name="direction", type=ParamType.STRING, default="ingress"),
        ),
    ),
    _define(
        id="k8s.pod_latency",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            _S,
            ParamSpec(name="jitter_ms", type=ParamType.FLOAT, minimum=0, maximum=5000),
        ),
    ),
    _define(
        id="k8s.pod_partition",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(_S,),
    ),
    # Preemption sub-category (ADR-M7-3)
    _define(
        id="k8s.pod_evict",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=120.0,
        params_schema=(),
    ),
    _define(
        id="k8s.pod_kill",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=60.0,
        params_schema=(),
    ),
    _define(
        id="k8s.node_drain",
        category=FaultCategory.K8S,
        risk=RiskLevel.CRITICAL,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.K8S_NODE}),
        max_duration_s=600.0,
        params_schema=(ParamSpec(name="grace_period", type=ParamType.INTEGER, default=30),),
    ),
    # ── k-plan-6: next-20 families (docs/k8s-new.md) ────────────────────────
    # Probe sub-family — patch the owning workload's readiness/liveness/startup
    # probe to a failing command; undo restores the original probe object.
    _define(
        id="k8s.pod_readiness_fail",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="failure_command", type=ParamType.STRING, default="/bin/false"),
        ),
    ),
    _define(
        id="k8s.pod_liveness_fail",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="failure_command", type=ParamType.STRING, default="/bin/false"),
        ),
    ),
    _define(
        id="k8s.pod_startup_fail",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="failure_command", type=ParamType.STRING, default="/bin/false"),
        ),
    ),
    # Scheduler sub-family — workload-level template patch (nodeSelector /
    # schedulerName) that prevents new pods from becoming ready or scheduled.
    _define(
        id="k8s.pod_unschedulable",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(),
    ),
    _define(
        id="k8s.schedule_delay",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(
                name="scheduler_name", type=ParamType.STRING, default="mayhem-scheduler-nope"
            ),
        ),
    ),
    # Registry sub-family — image reference patch (image_pull_slow is
    # catalog-only; kubectl alone cannot shape pull latency).
    _define(
        id="k8s.image_pull_failure",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(
                name="image", type=ParamType.STRING, default="mayhem.invalid/pull-fail:latest"
            ),
        ),
    ),
    # Registry pacing — CATALOG ONLY: no kubectl primitive delivers slow
    # image pulls; the executor refuses at can_apply time with a stable
    # ``k8s.unsupported`` reason.  Planner can reason about the archetype
    # but the driver never registers it.
    _define(
        id="k8s.image_pull_slow",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(
                name="image", type=ParamType.STRING, default="mayhem.invalid/pull-slow:latest"
            ),
            ParamSpec(name="delay_s", type=ParamType.INTEGER, default=30, minimum=1, maximum=600),
        ),
        catalog_only=True,
        refusal_reason=(
            "k8s.unsupported: no registry-pacing runtime is registered; "
            "use k8s.image_pull_failure for deterministic pull failure"
        ),
    ),
    # Workload sub-family — mutations delivered via kubectl patch/scale on
    # the owning Deployment/StatefulSet.
    _define(
        id="k8s.replica_reduce",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(ParamSpec(name="replicas", type=ParamType.INTEGER, default=1, minimum=0),),
    ),
    _define(
        id="k8s.rollout_pause",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(),
    ),
    _define(
        id="k8s.rollout_failure",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(
                name="image", type=ParamType.STRING, default="mayhem.invalid/rollout-fail:latest"
            ),
        ),
    ),
    # Pod-delete sub-family — uncontrolled deletion (no graceful shutdown).
    _define(
        id="k8s.pod_delete_uncontrolled",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=120.0,
        params_schema=(),
    ),
    # Service sub-family — Service object-level mutation (selector / port).
    _define(
        id="k8s.service_no_endpoints",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="selector_key", type=ParamType.STRING, default="mayhem.no-endpoints"),
            ParamSpec(name="selector_value", type=ParamType.STRING, default="true"),
        ),
    ),
    _define(
        id="k8s.service_endpoint_flap",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="cycles", type=ParamType.INTEGER, default=3, minimum=1, maximum=20),
            ParamSpec(name="interval_s", type=ParamType.INTEGER, default=5, minimum=1, maximum=120),
        ),
    ),
    _define(
        id="k8s.service_port_mismatch",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="target_port", type=ParamType.INTEGER, default=0, minimum=0),
        ),
    ),
    # Config sub-family — ConfigMap data corruption / Secret deletion.
    _define(
        id="k8s.configmap_corrupt",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="configmap", type=ParamType.STRING),
            ParamSpec(name="prefix", type=ParamType.STRING, default="mayhem-corrupted-"),
        ),
    ),
    _define(
        id="k8s.secret_unavailable",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="synthetic", type=ParamType.STRING, default="true"),
            ParamSpec(name="name", type=ParamType.STRING),
        ),
    ),
    # Storage sub-family — in-pod persistent volume stress / permission change
    # or workload volume-source swap.
    _define(
        id="k8s.persistent_volume_delay",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=600.0,
        params_schema=(ParamSpec(name="volume_path", type=ParamType.STRING),),
    ),
    _define(
        id="k8s.persistent_volume_error",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=600.0,
        params_schema=(ParamSpec(name="volume_path", type=ParamType.STRING),),
    ),
    _define(
        id="k8s.persistent_volume_detach",
        category=FaultCategory.K8S,
        risk=RiskLevel.CRITICAL,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(),
    ),
    _define(
        id="k8s.node_not_ready",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.K8S_NODE}),
        max_duration_s=300.0,
        params_schema=(ParamSpec(name="duration", type=ParamType.DURATION, default="30s"),),
    ),
    _define(
        id="k8s.pod_crash_loop",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="restarts", type=ParamType.INTEGER, default=5, minimum=1, maximum=50),
            ParamSpec(name="interval", type=ParamType.DURATION, default="5s"),
        ),
    ),
    _define(
        id="k8s.pod_pending",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(
                name="reason",
                type=ParamType.STRING,
                required=True,
            ),
        ),
    ),
    _define(
        id="k8s.node_network_partition",
        category=FaultCategory.K8S,
        risk=RiskLevel.CRITICAL,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.K8S_NODE}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="direction", type=ParamType.STRING, default="both"),
        ),
    ),
    _define(
        id="k8s.deployment_scale_failure",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="replicas", type=ParamType.INTEGER, required=True, minimum=1),
        ),
    ),
    _define(
        id="k8s.statefulset_scale_failure",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="replicas", type=ParamType.INTEGER, required=True, minimum=1),
        ),
    ),
    _define(
        id="k8s.resource_quota_exhaust",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="resource", type=ParamType.STRING, default="pods"),
            ParamSpec(name="amount", type=ParamType.INTEGER, required=True, minimum=0),
        ),
    ),
    _define(
        id="k8s.persistent_volume_mount_failure",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(ParamSpec(name="volume", type=ParamType.STRING, required=True),),
    ),
    _define(
        id="k8s.persistent_volume_claim_pending",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(),
    ),
    _define(
        id="k8s.kube_proxy_failure",
        category=FaultCategory.K8S,
        risk=RiskLevel.CRITICAL,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.K8S_NODE}),
        max_duration_s=300.0,
        params_schema=(),
    ),
    _define(
        id="k8s.pod_image_pull_delay",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.K8S_NODE}),
        max_duration_s=300.0,
        params_schema=(ParamSpec(name="seconds", type=ParamType.DURATION, default="30s"),),
    ),
    _define(
        id="k8s.container_termination_delay",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(ParamSpec(name="seconds", type=ParamType.DURATION, default="20s"),),
    ),
    _define(
        id="k8s.preemption_failure",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(),
    ),
    _define(
        id="k8s.pdb_violation",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="unavailable", type=ParamType.INTEGER, required=True, minimum=0),
        ),
    ),
    _define(
        id="k8s.eviction_block",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(),
    ),
    _define(
        id="k8s.dns_failure",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="domain", type=ParamType.STRING, required=True),
            ParamSpec(name="mode", type=ParamType.STRING, default="servfail"),
        ),
    ),
    _define(
        id="k8s.dns_delay",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(
                name="delay_ms", type=ParamType.INTEGER, default=500, minimum=1, maximum=30000
            ),
        ),
    ),
    _define(
        id="k8s.service_dns_mismatch",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="domain", type=ParamType.STRING, required=True),
            ParamSpec(name="address", type=ParamType.STRING, required=True),
        ),
    ),
    _define(
        id="k8s.hpa_scale_delay",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=3600.0,
        params_schema=(ParamSpec(name="seconds", type=ParamType.DURATION, default="60s"),),
    ),
    _define(
        id="k8s.hpa_scale_failure",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(ParamSpec(name="direction", type=ParamType.STRING, default="up"),),
    ),
    # Node sub-family — cordon (subset of drain without eviction).
    _define(
        id="k8s.node_cordon",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.K8S_NODE}),
        max_duration_s=300.0,
        params_schema=(),
    ),
    # Node-killer sub-family (k-plan-6 §24) — NODE_CONTROL-gated mutations:
    # the executors refuse at can_apply time when the capability is absent, so
    # none of these rides the KUBERNETES_ENGINE unsupported gate.
    _define(
        id="k8s.taint_evict",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.K8S_NODE}),
        max_duration_s=120.0,
        params_schema=(
            ParamSpec(name="key", type=ParamType.STRING, default="mayhem.io/taint-evict"),
            ParamSpec(name="value", type=ParamType.STRING, default="mayhem"),
            ParamSpec(name="effect", type=ParamType.STRING, default="NoExecute"),
        ),
    ),
    _define(
        id="k8s.nvidia_smi_error",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.K8S_NODE}),
        max_duration_s=120.0,
        params_schema=(
            ParamSpec(name="interval", type=ParamType.INTEGER, minimum=1, maximum=60, default=1),
        ),
    ),
    _define(
        id="k8s.crash_loop",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.K8S_NODE}),
        max_duration_s=120.0,
        params_schema=(
            ParamSpec(name="restarts", type=ParamType.INTEGER, minimum=1, maximum=1000, default=10),
        ),
    ),
    _define(
        id="cpu.burst",
        category=FaultCategory.CPU,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.DOCKER_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.CONTAINER, NodeKind.PROCESS}),
        target_kind=TargetKind.CONTAINER,
        target_kinds=frozenset({TargetKind.CONTAINER, TargetKind.PROCESS}),
        max_duration_s=300.0,
        params_schema=(_pct(minimum=1.0, maximum=100.0),),
    ),
    _define(
        id="mem.freeze",
        category=FaultCategory.MEMORY,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.DOCKER_ENGINE, Capability.CGROUP_CONTROL}),
        applicable_node_kinds=frozenset({NodeKind.CONTAINER, NodeKind.PROCESS}),
        target_kind=TargetKind.CONTAINER,
        target_kinds=frozenset({TargetKind.CONTAINER, TargetKind.PROCESS}),
        max_duration_s=120.0,
        params_schema=(
            _pct(minimum=1.0, maximum=99.0),
            ParamSpec(name="hold_s", type=ParamType.DURATION, default="30s"),
        ),
    ),
    _define(
        id="mem.swap_pressure",
        category=FaultCategory.MEMORY,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.DOCKER_ENGINE, Capability.CGROUP_CONTROL}),
        applicable_node_kinds=frozenset({NodeKind.CONTAINER, NodeKind.PROCESS}),
        target_kind=TargetKind.CONTAINER,
        target_kinds=frozenset({TargetKind.CONTAINER, TargetKind.PROCESS}),
        max_duration_s=120.0,
        params_schema=(
            _pct(minimum=1.0, maximum=99.0),
            ParamSpec(name="swap_mb", type=ParamType.INTEGER, default=64, minimum=1, maximum=4096),
        ),
    ),
    _define(
        id="fs.quota",
        category=FaultCategory.STORAGE,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.DOCKER_ENGINE, Capability.FS_CONTROL}),
        applicable_node_kinds=frozenset({NodeKind.CONTAINER, NodeKind.PROCESS}),
        target_kind=TargetKind.CONTAINER,
        target_kinds=frozenset({TargetKind.CONTAINER, TargetKind.PROCESS}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="quota_mb", type=ParamType.INTEGER, default=64, minimum=1, maximum=4096),
        ),
    ),
    _define(
        id="fs.write_delay",
        category=FaultCategory.STORAGE,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.DOCKER_ENGINE, Capability.FS_CONTROL}),
        applicable_node_kinds=frozenset({NodeKind.CONTAINER, NodeKind.PROCESS}),
        target_kind=TargetKind.CONTAINER,
        target_kinds=frozenset({TargetKind.CONTAINER, TargetKind.PROCESS}),
        max_duration_s=120.0,
        params_schema=(
            ParamSpec(
                name="delay_ms", type=ParamType.INTEGER, default=100, minimum=1, maximum=30000
            ),
        ),
    ),
    _define(
        id="net.corrupt",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.DOCKER_ENGINE, Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.CONTAINER, NodeKind.PROCESS, NodeKind.SERVICE}),
        target_kind=TargetKind.SERVICE,
        target_kinds=frozenset({TargetKind.CONTAINER, TargetKind.PROCESS, TargetKind.SERVICE}),
        max_duration_s=120.0,
        params_schema=(
            ParamSpec(
                name="percent",
                type=ParamType.PERCENT,
                default=1.0,
                minimum=0.0,
                maximum=100.0,
            ),
        ),
    ),
    _define(
        id="net.congestion",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.DOCKER_ENGINE, Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.CONTAINER, NodeKind.PROCESS, NodeKind.SERVICE}),
        target_kind=TargetKind.SERVICE,
        target_kinds=frozenset({TargetKind.CONTAINER, TargetKind.PROCESS, TargetKind.SERVICE}),
        max_duration_s=120.0,
        params_schema=(
            ParamSpec(
                name="rate_kbps", type=ParamType.INTEGER, default=128, minimum=1, maximum=1000000
            ),
        ),
    ),
    _define(
        id="process.restart_delay",
        category=FaultCategory.PROCESS,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.DOCKER_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.CONTAINER, NodeKind.PROCESS}),
        target_kind=TargetKind.PROCESS,
        target_kinds=frozenset({TargetKind.CONTAINER, TargetKind.PROCESS}),
        max_duration_s=120.0,
        params_schema=(
            ParamSpec(name="restarts", type=ParamType.INTEGER, default=3, minimum=1, maximum=20),
            ParamSpec(name="delay", type=ParamType.DURATION, default="5s"),
        ),
    ),
    _define(
        id="http.upstream_timeout",
        category=FaultCategory.HTTP_API,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=_CONTAINER_SERVICE_KINDS,
        target_kind=TargetKind.SERVICE,
        target_kinds=_CONTAINER_SERVICE_TARGETS,
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="upstream", type=ParamType.STRING, required=True, min_length=1),
            ParamSpec(
                name="timeout_ms", type=ParamType.INTEGER, default=1000, minimum=1, maximum=30000
            ),
            ParamSpec(name="port", type=ParamType.INTEGER, default=80, minimum=1, maximum=65535),
        ),
    ),
    _define(
        id="app.response_5xx",
        category=FaultCategory.HTTP_API,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=_CONTAINER_SERVICE_KINDS,
        target_kind=TargetKind.SERVICE,
        target_kinds=_CONTAINER_SERVICE_TARGETS,
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="status", type=ParamType.INTEGER, default=503, minimum=500, maximum=599),
            ParamSpec(
                name="probability",
                type=ParamType.PERCENT,
                default=100.0,
                minimum=1.0,
                maximum=100.0,
            ),
            ParamSpec(name="port", type=ParamType.INTEGER, default=80, minimum=1, maximum=65535),
        ),
    ),
    _define(
        id="k8s.pod_restart_churn",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        target_kind=TargetKind.POD,
        target_kinds=frozenset({TargetKind.POD}),
        max_duration_s=120.0,
        params_schema=(
            ParamSpec(name="restarts", type=ParamType.INTEGER, default=3, minimum=1, maximum=20),
            ParamSpec(name="interval", type=ParamType.DURATION, default="5s"),
        ),
    ),
    _define(
        id="k8s.sidecar_termination",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        target_kind=TargetKind.POD,
        target_kinds=frozenset({TargetKind.POD}),
        max_duration_s=120.0,
        params_schema=(
            ParamSpec(name="container", type=ParamType.STRING, default="sidecar", min_length=1),
        ),
    ),
    _define(
        id="k8s.workload_stall",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        target_kind=TargetKind.WORKLOAD,
        target_kinds=frozenset({TargetKind.WORKLOAD, TargetKind.POD}),
        max_duration_s=300.0,
        params_schema=(ParamSpec(name="stall_s", type=ParamType.DURATION, default="30s"),),
    ),
    _define(
        id="k8s.service_5xx",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        target_kind=TargetKind.SERVICE,
        target_kinds=frozenset({TargetKind.SERVICE, TargetKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="status", type=ParamType.INTEGER, default=503, minimum=500, maximum=599),
            ParamSpec(
                name="probability",
                type=ParamType.PERCENT,
                default=100.0,
                minimum=1.0,
                maximum=100.0,
            ),
        ),
    ),
    _define(
        id="k8s.dns_timeout",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        target_kind=TargetKind.SERVICE,
        target_kinds=frozenset({TargetKind.SERVICE, TargetKind.POD}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="domain", type=ParamType.STRING, required=True, min_length=1),
            ParamSpec(
                name="timeout_ms", type=ParamType.INTEGER, default=500, minimum=1, maximum=30000
            ),
        ),
    ),
    _define(
        id="k8s.node_disk_pressure",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.K8S_NODE}),
        target_kind=TargetKind.NODE,
        target_kinds=frozenset({TargetKind.NODE}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(
                name="target_percent", type=ParamType.INTEGER, default=80, minimum=1, maximum=100
            ),
        ),
    ),
    _define(
        id="k8s.node_memory_pressure",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.K8S_NODE}),
        target_kind=TargetKind.NODE,
        target_kinds=frozenset({TargetKind.NODE}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(
                name="target_percent", type=ParamType.INTEGER, default=80, minimum=1, maximum=100
            ),
        ),
    ),
    _define(
        id="k8s.node_pid_pressure",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.K8S_NODE}),
        target_kind=TargetKind.NODE,
        target_kinds=frozenset({TargetKind.NODE}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(
                name="target_percent", type=ParamType.INTEGER, default=80, minimum=1, maximum=100
            ),
        ),
    ),
    _define(
        id="k8s.hpa_oscillation",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        target_kind=TargetKind.HPA,
        target_kinds=frozenset({TargetKind.WORKLOAD, TargetKind.HPA}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(
                name="min_replicas", type=ParamType.INTEGER, default=1, minimum=0, maximum=100
            ),
            ParamSpec(
                name="max_replicas", type=ParamType.INTEGER, default=3, minimum=1, maximum=100
            ),
            ParamSpec(name="window_s", type=ParamType.INTEGER, default=30, minimum=1, maximum=300),
        ),
    ),
    _define(
        id="k8s.pdb_over_eviction",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        target_kind=TargetKind.PDB,
        target_kinds=frozenset({TargetKind.WORKLOAD, TargetKind.POD, TargetKind.PDB}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(
                name="unavailable", type=ParamType.INTEGER, default=0, minimum=0, maximum=100
            ),
        ),
    ),
)

def validate_catalog(definitions: tuple[FaultDefinition, ...]) -> None:
    seen: set[str] = set()
    for definition in definitions:
        if definition.id in seen:
            raise SchemaValidationError("catalog", f"duplicate fault id {definition.id!r}")
        seen.add(definition.id)
        if definition.failure_domain is None:
            raise SchemaValidationError("catalog", f"{definition.id}: failure_domain is required")
        if definition.target_kind is None:
            raise SchemaValidationError("catalog", f"{definition.id}: target_kind is required")
        if not definition.target_kinds:
            raise SchemaValidationError("catalog", f"{definition.id}: target_kinds is required")
        if not definition.engine_lanes:
            raise SchemaValidationError("catalog", f"{definition.id}: engine_lanes is required")
        if not definition.observable_effect.strip() or not definition.compensation_evidence:
            field = (
                "observable_effect"
                if not definition.observable_effect.strip()
                else "compensation_evidence"
            )
            raise SchemaValidationError("catalog", f"{definition.id}: {field} is required")
        if definition.verification_method is None:
            raise SchemaValidationError(
                "catalog", f"{definition.id}: verification_method is required"
            )
        if definition.reversibility is None:
            raise SchemaValidationError(
                "catalog", f"{definition.id}: reversibility is required"
            )
        if definition.maturity is not MaturityLevel.EXPERIMENTAL and (
            definition.verification_date is None
        ):
            raise SchemaValidationError(
                "catalog",
                f"{definition.id}: verification_date is required for {definition.maturity.value}",
            )
        if definition.catalog_only and not (definition.refusal_reason or "").strip():
            raise SchemaValidationError(
                "catalog", f"{definition.id}: catalog-only entry requires refusal_reason"
            )
        if not definition.catalog_only and definition.refusal_reason:
            raise SchemaValidationError(
                "catalog", f"{definition.id}: executable entry cannot carry refusal_reason"
            )


validate_catalog(CATALOG)
_BY_ID: dict[str, FaultDefinition] = {d.id: d for d in CATALOG}


def definition_for(fault_id: str) -> FaultDefinition:
    """Catalog lookup; unknown ids are planning errors, not KeyErrors."""
    try:
        return _BY_ID[fault_id]
    except KeyError:
        known = ", ".join(sorted(_BY_ID))
        msg = f"fault {fault_id!r} not in catalog (known: {known})"
        raise LookupError(msg) from None


def all_definitions() -> tuple[FaultDefinition, ...]:
    return CATALOG
