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
    FaultDefinition(
        id="cpu.saturate",
        category=FaultCategory.CPU,
        risk=RiskLevel.MEDIUM,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.HOST, NodeKind.POD}),
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
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(_pct(minimum=1.0, maximum=100.0),),
    ),
    FaultDefinition(
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
    FaultDefinition(
        id="mem.leak",
        category=FaultCategory.MEMORY,
        risk=RiskLevel.HIGH,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.POD}),
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
        applicable_node_kinds=frozenset(
            {NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.HOST, NodeKind.POD}
        ),
        max_duration_s=300.0,
        params_schema=(_pct(minimum=1.0, maximum=99.0),),
    ),
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
        id="fs.read_only",
        category=FaultCategory.STORAGE,
        risk=RiskLevel.HIGH,
        reversible=True,
        required_caps=frozenset({Capability.FS_CONTROL}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.HOST}),
        max_duration_s=120.0,
        params_schema=(ParamSpec(name="path", type=ParamType.STRING, default="/"),),
    ),
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
        id="net.partition",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.POD}),
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
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
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
    # ── k-plan-6: next-20 families (docs/k8s-new.md) ────────────────────────
    # Probe sub-family — patch the owning workload's readiness/liveness/startup
    # probe to a failing command; undo restores the original probe object.
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
        id="k8s.pod_unschedulable",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(),
    ),
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
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
    ),
    # Workload sub-family — mutations delivered via kubectl patch/scale on
    # the owning Deployment/StatefulSet.
    FaultDefinition(
        id="k8s.replica_reduce",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(ParamSpec(name="replicas", type=ParamType.INTEGER, default=1, minimum=0),),
    ),
    FaultDefinition(
        id="k8s.rollout_pause",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(),
    ),
    FaultDefinition(
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
    FaultDefinition(
        id="k8s.pod_delete_uncontrolled",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=120.0,
        params_schema=(),
    ),
    # Service sub-family — Service object-level mutation (selector / port).
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
        id="k8s.persistent_volume_delay",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=600.0,
        params_schema=(ParamSpec(name="volume_path", type=ParamType.STRING),),
    ),
    FaultDefinition(
        id="k8s.persistent_volume_error",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=600.0,
        params_schema=(ParamSpec(name="volume_path", type=ParamType.STRING),),
    ),
    FaultDefinition(
        id="k8s.persistent_volume_detach",
        category=FaultCategory.K8S,
        risk=RiskLevel.CRITICAL,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(),
    ),
    # HPA sub-family (k-plan-2 §14–§15) — HorizontalPodAutoscaler mutation.
    FaultDefinition(
        id="k8s.hpa_scale_delay",
        category=FaultCategory.K8S,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=3600.0,
        params_schema=(ParamSpec(name="seconds", type=ParamType.DURATION, default="60s"),),
    ),
    FaultDefinition(
        id="k8s.hpa_scale_failure",
        category=FaultCategory.K8S,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.KUBERNETES_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.POD}),
        max_duration_s=300.0,
        params_schema=(ParamSpec(name="direction", type=ParamType.STRING, default="up"),),
    ),
    # Node sub-family — cordon (subset of drain without eviction).
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
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
    FaultDefinition(
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
