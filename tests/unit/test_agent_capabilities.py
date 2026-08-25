"""Tests for agent capability constraints (ADR-0017)."""

import pytest

from mayhem.agents.capabilities import (
    AgentCapabilities,
    AgentIdentity,
    CapabilityKind,
)
from mayhem.domain.errors import InvariantViolationError


class TestCapabilityKind:
    def test_all_values(self) -> None:
        assert set(CapabilityKind) == {
            CapabilityKind.FAULT_INJECT,
            CapabilityKind.FAULT_UNDO,
            CapabilityKind.PROBE_RUN,
            CapabilityKind.RESOURCE_ACCESS,
            CapabilityKind.NETWORK_ACCESS,
            CapabilityKind.SHELL_EXEC,
        }


class TestAgentCapabilities:
    def test_empty_capabilities_nothing_allowed(self) -> None:
        caps = AgentCapabilities()
        assert caps.can_inject("net.latency") is False
        assert caps.can_undo("net.latency") is False
        assert caps.can_access_resource("tc_rule") is False
        assert caps.can_use_network() is False
        assert caps.can_exec_shell() is False

    def test_inject_with_specific_fault(self) -> None:
        caps = AgentCapabilities(
            capabilities=(CapabilityKind.FAULT_INJECT,),
            allowed_faults=("net.latency",),
        )
        assert caps.can_inject("net.latency") is True
        assert caps.can_inject("net.partition") is False

    def test_inject_with_prefix_match(self) -> None:
        caps = AgentCapabilities(
            capabilities=(CapabilityKind.FAULT_INJECT,),
            allowed_faults=("net.",),
        )
        assert caps.can_inject("net.latency") is True
        assert caps.can_inject("net.partition") is True
        assert caps.can_inject("cpu.stress") is False

    def test_inject_empty_allowlist_allows_all(self) -> None:
        caps = AgentCapabilities(
            capabilities=(CapabilityKind.FAULT_INJECT,),
            allowed_faults=(),
        )
        assert caps.can_inject("net.latency") is True
        assert caps.can_inject("any.fault") is True

    def test_undo_requires_capability(self) -> None:
        caps = AgentCapabilities(
            capabilities=(CapabilityKind.FAULT_INJECT,),
            allowed_faults=("net.latency",),
        )
        assert caps.can_undo("net.latency") is False  # no FAULT_UNDO capability

    def test_undo_with_capability(self) -> None:
        caps = AgentCapabilities(
            capabilities=(CapabilityKind.FAULT_INJECT, CapabilityKind.FAULT_UNDO),
            allowed_faults=("net.latency",),
        )
        assert caps.can_undo("net.latency") is True

    def test_resource_access(self) -> None:
        caps = AgentCapabilities(
            capabilities=(CapabilityKind.RESOURCE_ACCESS,),
            allowed_resources=("tc_rule",),
        )
        assert caps.can_access_resource("tc_rule") is True
        assert caps.can_access_resource("iptables_rule") is False

    def test_resource_empty_allowlist(self) -> None:
        caps = AgentCapabilities(
            capabilities=(CapabilityKind.RESOURCE_ACCESS,),
            allowed_resources=(),
        )
        assert caps.can_access_resource("anything") is True

    def test_network_and_shell(self) -> None:
        caps = AgentCapabilities(
            capabilities=(CapabilityKind.NETWORK_ACCESS, CapabilityKind.SHELL_EXEC),
        )
        assert caps.can_use_network() is True
        assert caps.can_exec_shell() is True

    def test_frozen(self) -> None:
        caps = AgentCapabilities()
        with pytest.raises(Exception):
            caps.capabilities = (CapabilityKind.FAULT_INJECT,)  # type: ignore[misc]


class TestAgentIdentity:
    def test_validate_fault_dispatch_ok(self) -> None:
        identity = AgentIdentity(
            agent_id="agent-1",
            capabilities=AgentCapabilities(
                capabilities=(CapabilityKind.FAULT_INJECT,),
                allowed_faults=("net.latency",),
            ),
        )
        identity.validate_fault_dispatch("net.latency")

    def test_validate_fault_dispatch_denied(self) -> None:
        identity = AgentIdentity(
            agent_id="agent-1",
            capabilities=AgentCapabilities(
                capabilities=(CapabilityKind.FAULT_INJECT,),
                allowed_faults=("net.latency",),
            ),
        )
        with pytest.raises(InvariantViolationError, match="agent.capability.denied"):
            identity.validate_fault_dispatch("cpu.stress")

    def test_validate_undo_denied(self) -> None:
        identity = AgentIdentity(
            agent_id="agent-1",
            capabilities=AgentCapabilities(
                capabilities=(CapabilityKind.FAULT_INJECT,),
            ),
        )
        with pytest.raises(InvariantViolationError, match="agent.capability.denied"):
            identity.validate_fault_dispatch("net.latency", is_undo=True)

    def test_validate_undo_ok(self) -> None:
        identity = AgentIdentity(
            agent_id="agent-1",
            capabilities=AgentCapabilities(
                capabilities=(CapabilityKind.FAULT_INJECT, CapabilityKind.FAULT_UNDO),
            ),
        )
        identity.validate_fault_dispatch("net.latency", is_undo=True)
