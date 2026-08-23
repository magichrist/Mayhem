"""Fault definition and param validation."""

import pytest

from tgondi.domain.capabilities import Capability
from tgondi.domain.errors import SchemaValidationError
from tgondi.domain.faults import FaultCategory, FaultDefinition, ParamSpec, ParamType
from tgondi.domain.risks import RiskLevel
from tgondi.domain.topology import NodeKind


def _latency() -> FaultDefinition:
    return FaultDefinition(
        id="net.latency",
        category=FaultCategory.NETWORK,
        risk=RiskLevel.MEDIUM,
        required_caps=frozenset({Capability.NET_ADMIN}),
        applicable_node_kinds=frozenset({NodeKind.CONTAINER, NodeKind.PROCESS}),
        params_schema=(
            ParamSpec(
                name="delay_ms", type=ParamType.INTEGER, required=True, minimum=1, maximum=10_000
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
