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
        id="cpu.saturate",
        category=FaultCategory.CPU,
        risk=RiskLevel.MEDIUM,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.HOST}),
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
        id="net.latency",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER}),
        max_duration_s=300.0,
        params_schema=(
            _S,
            ParamSpec(name="jitter_ms", type=ParamType.INTEGER, default=0),
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
        id="container.kill",
        category=FaultCategory.CONTAINER,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.DOCKER_ENGINE}),
        applicable_node_kinds=frozenset({NodeKind.CONTAINER}),
        max_duration_s=60.0,
        params_schema=(ParamSpec(name="signal", type=ParamType.STRING, default="SIGKILL"),),
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
        params_schema=(ParamSpec(name="status", type=ParamType.INTEGER, default=500),),
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
        id="clock.skew",
        category=FaultCategory.CLOCK,
        risk=RiskLevel.HIGH,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.HOST, NodeKind.CONTAINER}),
        max_duration_s=300.0,
        params_schema=(ParamSpec(name="offset_ms", type=ParamType.INTEGER, required=True),),
    ),
    FaultDefinition(
        id="fd.exhaust",
        category=FaultCategory.FD,
        risk=RiskLevel.HIGH,
        applicable_node_kinds=frozenset({NodeKind.SERVICE, NodeKind.CONTAINER, NodeKind.HOST}),
        max_duration_s=120.0,
        params_schema=(ParamSpec(name="limit", type=ParamType.INTEGER, default=64),),
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
