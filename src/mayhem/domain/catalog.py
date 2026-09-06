"""Seed fault catalog — curated FaultDefinitions matching the taxonomy doc.

This is the planner's source of truth for what is injectable, at what risk,
on which node kinds, with which params. Backends gate actual tooling; a
definition without an executable compensation template will be refused at
plan time (see controller.compensation).
"""

from __future__ import annotations

from mayhem.domain.capabilities import Capability
from mayhem.domain.faults import FaultCategory, FaultDefinition, ParamSpec, ParamType
from mayhem.domain.risks import RiskLevel
from mayhem.domain.topology import NodeKind

_S = ParamSpec(name="seconds", type=ParamType.DURATION)


def _pct(minimum: float, maximum: float) -> ParamSpec:
    return ParamSpec(name="percent", type=ParamType.PERCENT, minimum=minimum, maximum=maximum)


CATALOG: tuple[FaultDefinition, ...] = (
    FaultDefinition(
        id="proc.pause",
        category=FaultCategory.PROCESS,
        risk=RiskLevel.LOW,
        required_caps=frozenset({Capability.PROCESS_CONTROL}),
        applicable_node_kinds=frozenset({NodeKind.PROCESS, NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=600.0,
        params_schema=(),
    ),
    FaultDefinition(
        id="process.stop",
        category=FaultCategory.PROCESS,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.PROCESS_CONTROL}),
        applicable_node_kinds=frozenset({NodeKind.PROCESS, NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=300.0,
        params_schema=(),
    ),
    FaultDefinition(
        id="process.kill",
        category=FaultCategory.PROCESS,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.PROCESS_CONTROL}),
        applicable_node_kinds=frozenset({NodeKind.PROCESS, NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=60.0,
        params_schema=(),
    ),
    FaultDefinition(
        id="cpu.saturate",
        category=FaultCategory.CPU,
        risk=RiskLevel.MEDIUM,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.HOST}),
        max_duration_s=300.0,
        params_schema=(_pct(minimum=1.0, maximum=100.0),),
    ),
    FaultDefinition(
        id="cpu.throttle",
        category=FaultCategory.CPU,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.DOCKER_ENGINE}),
        # A reserve-share throttle needs the container engine cgroup knobs
        # (``update --cpus``), so it cannot address a bare HOST process.
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=300.0,
        params_schema=(_pct(minimum=1.0, maximum=100.0),),
    ),
    FaultDefinition(
        id="mem.exhaust",
        category=FaultCategory.MEMORY,
        risk=RiskLevel.HIGH,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
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
    FaultDefinition(
        id="mem.leak",
        category=FaultCategory.MEMORY,
        risk=RiskLevel.HIGH,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="rate_mb", type=ParamType.INTEGER, default=8, minimum=1, maximum=512),
        ),
    ),
    FaultDefinition(
        id="fs.fill",
        category=FaultCategory.STORAGE,
        risk=RiskLevel.MEDIUM,
        reversible=True,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.HOST}),
        max_duration_s=300.0,
        params_schema=(_pct(minimum=1.0, maximum=99.0),),
    ),
    FaultDefinition(
        id="fs.inode_exhaust",
        category=FaultCategory.STORAGE,
        risk=RiskLevel.MEDIUM,
        reversible=True,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.HOST}),
        max_duration_s=300.0,
        # Consumes free inodes (zero-byte marker files) instead of capacity;
        # undo removes the marker files, so the filesystem is fully restored.
        params_schema=(_pct(minimum=1.0, maximum=99.0),),
    ),
    FaultDefinition(
        id="fs.io_stress",
        category=FaultCategory.STORAGE,
        risk=RiskLevel.MEDIUM,
        reversible=True,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.HOST}),
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
    FaultDefinition(
        id="net.latency",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=300.0,
        params_schema=(
            _S,
            ParamSpec(name="jitter_ms", type=ParamType.INTEGER, default=0),
            ParamSpec(name="direction", type=ParamType.STRING, default="egress"),
        ),
    ),
    FaultDefinition(
        id="net.packet_loss",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=300.0,
        params_schema=(
            _pct(minimum=1.0, maximum=100.0),
            ParamSpec(name="direction", type=ParamType.STRING, default="egress"),
        ),
    ),
    FaultDefinition(
        id="net.bandwidth",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="rate", type=ParamType.STRING, required=True),
            ParamSpec(name="burst", type=ParamType.STRING, default="10k"),
            ParamSpec(name="direction", type=ParamType.STRING, default="egress"),
        ),
    ),
    FaultDefinition(
        id="net.partition",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=120.0,
        params_schema=(),
    ),
    FaultDefinition(
        id="net.load",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.MEDIUM,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=600.0,
        params_schema=(
            ParamSpec(name="users", type=ParamType.INTEGER, minimum=1.0),
            ParamSpec(name="url", type=ParamType.STRING, default="http://localhost/"),
            # ``script``: path on the drill host to a k6 ``script.js``. When set,
            # it is copied into the target container and run instead of the
            # built-in inline script.
            ParamSpec(name="script", type=ParamType.STRING, default=None),
        ),
    ),
    FaultDefinition(
        id="node.service_stop",
        category=FaultCategory.NODE,
        risk=RiskLevel.HIGH,
        applicable_node_kinds=frozenset({NodeKind.SERVICE}),
        max_duration_s=120.0,
        params_schema=(),
    ),
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
        id="db.slow_query",
        category=FaultCategory.DATABASE,
        risk=RiskLevel.MEDIUM,
        applicable_node_kinds=frozenset({NodeKind.EXTERNAL_DEPENDENCY, NodeKind.SERVICE}),
        max_duration_s=300.0,
        params_schema=(_S,),
    ),
    FaultDefinition(
        id="db.connection_exhaust",
        category=FaultCategory.DATABASE,
        risk=RiskLevel.HIGH,
        applicable_node_kinds=frozenset(
            {NodeKind.EXTERNAL_DEPENDENCY, NodeKind.SERVICE, NodeKind.CONTAINER}
        ),
        max_duration_s=120.0,
        params_schema=(
            ParamSpec(name="connections", type=ParamType.INTEGER, required=True, minimum=1, maximum=256),
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
    FaultDefinition(
        id="db.query_error",
        category=FaultCategory.DATABASE,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset(
            {NodeKind.EXTERNAL_DEPENDENCY, NodeKind.SERVICE, NodeKind.CONTAINER}
        ),
        max_duration_s=300.0,
        params_schema=(
            ParamSpec(name="probability", type=ParamType.PERCENT, minimum=1.0, maximum=100.0, default=100.0),
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
    FaultDefinition(
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
    FaultDefinition(
        id="fuzz.protocol_abuse",
        category=FaultCategory.FUZZ,
        risk=RiskLevel.HIGH,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.EXTERNAL_DEPENDENCY}),
        max_duration_s=180.0,
        params_schema=(),
    ),
    FaultDefinition(
        id="dns.resolve_delay",
        category=FaultCategory.DNS,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.HOST}),
        max_duration_s=300.0,
        params_schema=(_S,),
    ),
    FaultDefinition(
        id="dns.timeout",
        category=FaultCategory.DNS,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.HOST}),
        max_duration_s=120.0,
        params_schema=(),
    ),
    FaultDefinition(
        id="dns.servfail",
        category=FaultCategory.DNS,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.HOST}),
        max_duration_s=120.0,
        params_schema=(),
    ),
    FaultDefinition(
        id="dns.nxdomain",
        category=FaultCategory.DNS,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.HOST}),
        max_duration_s=300.0,
        params_schema=(ParamSpec(name="domain", type=ParamType.STRING),),
    ),
    FaultDefinition(
        id="tls.certificate_expired",
        category=FaultCategory.TLS,
        risk=RiskLevel.HIGH,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.EXTERNAL_DEPENDENCY}),
        max_duration_s=120.0,
        params_schema=(),
    ),
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
        id="container.restart",
        category=FaultCategory.CONTAINER,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.DOCKER_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=60.0,
        params_schema=(),
    ),
    FaultDefinition(
        id="container.pause",
        category=FaultCategory.CONTAINER,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.DOCKER_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=300.0,
        params_schema=(),
    ),
    FaultDefinition(
        id="clock.skew",
        category=FaultCategory.CLOCK,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.HOST, NodeKind.CONTAINER, NodeKind.SERVICE}),
        max_duration_s=300.0,
        params_schema=(ParamSpec(name="offset_ms", type=ParamType.INTEGER, required=True),),
    ),
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
        id="fd.exhaust",
        category=FaultCategory.FD,
        risk=RiskLevel.HIGH,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.HOST}),
        max_duration_s=120.0,
        params_schema=(ParamSpec(name="limit", type=ParamType.INTEGER, default=64),),
    ),
    # ── Kubernetes archetypes (ADR-M7-3, ADR-M7-4) ──────────────────────────
    # All k8s archetypes are UNSUPPORTED (no live cluster driver); they exist so
    # the planner + capability matrix can reason about k8s targets without
    # executing.  Fingerprints reuse M2/M3 patterns for future k8s drivers.
    #
    # Capacity-stress sub-category (ADR-M7-3)
    FaultDefinition(
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
    FaultDefinition(
        id="k8s.pod_oom",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=120.0,
        params_schema=(ParamSpec(name="memory_limit", type=ParamType.STRING, default="64Mi"),),
    ),
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
        id="k8s.pod_partition",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(_S,),
    ),
    # Preemption sub-category (ADR-M7-3)
    FaultDefinition(
        id="k8s.pod_evict",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=120.0,
        params_schema=(),
    ),
    FaultDefinition(
        id="k8s.pod_kill",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=60.0,
        params_schema=(),
    ),
    FaultDefinition(
        id="k8s.node_drain",
        category=FaultCategory.K8S,
        risk=RiskLevel.CRITICAL,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.K8S_NODE}),
        max_duration_s=600.0,
        params_schema=(ParamSpec(name="grace_period", type=ParamType.INTEGER, default=30),),
    ),
)

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
