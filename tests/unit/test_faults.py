"""Fault definition and param validation."""

import pytest

from mayhem.domain.capabilities import Capability
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.faults import FaultCategory, FaultDefinition, ParamSpec, ParamType
from mayhem.domain.risks import RiskLevel
from mayhem.domain.topology import NodeKind


def _latency() -> FaultDefinition:
    return FaultDefinition(
        id="net.latency",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.CONTAINER, NodeKind.PROCESS}),
        params_schema=(
            ParamSpec(
                name="delay_ms",
                type=ParamType.INTEGER,
                required=True,
                minimum=1,
                maximum=10_000,
            ),
            ParamSpec(name="jitter_ms", type=ParamType.INTEGER, default=0),
            ParamSpec(name="duration_s", type=ParamType.DURATION, default=30),
        ),
    )


class TestFaultDefinition:
    def test_category_prefix_must_match_id(self) -> None:
        with pytest.raises(SchemaValidationError):
            FaultDefinition(id="cpu.burn", category=FaultCategory.MEMORY, risk=RiskLevel.LOW)

    def test_unknown_prefix_refused(self) -> None:
        with pytest.raises(SchemaValidationError):
            FaultCategory.from_fault_id("quantum.collapse")

    def test_param_normalization(self) -> None:
        normalized = _latency().validate_params({"delay_ms": 100, "jitter_ms": "5"})
        assert normalized == {"delay_ms": 100, "jitter_ms": 5, "duration_s": 30.0}

    def test_missing_required_param(self) -> None:
        with pytest.raises(SchemaValidationError, match="missing required"):
            _latency().validate_params({"jitter_ms": 1})

    def test_unknown_param(self) -> None:
        with pytest.raises(SchemaValidationError, match="unknown parameter"):
            _latency().validate_params({"delay_ms": 1, "warp_factor": 9})

    def test_bounds_enforced(self) -> None:
        with pytest.raises(SchemaValidationError, match="above maximum"):
            _latency().validate_params({"delay_ms": 999_999})

    def test_percent_bounds(self) -> None:
        spec = FaultDefinition(
            id="mem.pressure",
            category=FaultCategory.MEMORY,
            risk=RiskLevel.HIGH,
            params_schema=(ParamSpec(name="pct", type=ParamType.PERCENT),),
        )
        assert spec.validate_params({"pct": 50}) == {"pct": 50.0}
        with pytest.raises(SchemaValidationError, match="outside"):
            spec.validate_params({"pct": 150})

    def test_bytes_param_dsl(self) -> None:
        spec = FaultDefinition(
            id="mem.exhaust",
            category=FaultCategory.MEMORY,
            risk=RiskLevel.HIGH,
            params_schema=(ParamSpec(name="amount", type=ParamType.BYTES),),
        )
        assert spec.validate_params({"amount": "256M"}) == {"amount": 256 * 1024 * 1024}
        assert spec.validate_params({"amount": "1.5G"}) == {"amount": 1.5 * 2**30}
        with pytest.raises(SchemaValidationError, match="got 'a lot'"):
            spec.validate_params({"amount": "a lot"})

    def test_new_fault_categories(self) -> None:
        from mayhem.domain.catalog import CATALOG

        ids = {f.id for f in CATALOG}
        assert "dns.resolve_delay" in ids
        assert "dns.nxdomain" in ids
        assert "tls.certificate_expired" in ids
        assert "clock.skew" in ids
        assert "fd.exhaust" in ids
        assert "container.restart" in ids
        assert "container.pause" in ids
        assert "dependency.block" in ids
        assert "dependency.timeout" in ids

    def test_new_fault_category_mapping(self) -> None:
        assert FaultCategory.from_fault_id("dns.resolve_delay") == FaultCategory.DNS
        assert FaultCategory.from_fault_id("tls.certificate_expired") == FaultCategory.TLS
        assert FaultCategory.from_fault_id("clock.skew") == FaultCategory.CLOCK
        assert FaultCategory.from_fault_id("fd.exhaust") == FaultCategory.FD
        assert FaultCategory.from_fault_id("container.restart") == FaultCategory.CONTAINER
        assert FaultCategory.from_fault_id("container.pause") == FaultCategory.CONTAINER
        assert FaultCategory.from_fault_id("dependency.block") == FaultCategory.DEPENDENCY
        assert FaultCategory.from_fault_id("dependency.timeout") == FaultCategory.DEPENDENCY
