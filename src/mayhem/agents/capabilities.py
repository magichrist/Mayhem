"""Agent capability constraints and security model (ADR-0017).

Every agent declares what it can do via ``AgentCapabilities``. The controller
enforces these at task dispatch time — an agent cannot inject a fault it
hasn't declared capability for, and cannot touch resources outside its scope.

This is the *compile-time* agent security boundary. Runtime isolation
(sandboxing, process-level containment) is a separate concern.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class CapabilityKind(StrEnum):
    """What an agent is allowed to do."""

    FAULT_INJECT = "fault_inject"  # inject a specific fault type
    FAULT_UNDO = "fault_undo"  # undo/clean up a fault type
    PROBE_RUN = "probe_run"  # execute observation probes
    RESOURCE_ACCESS = "resource_access"  # touch tracked resources
    NETWORK_ACCESS = "network_access"  # make outbound network calls
    SHELL_EXEC = "shell_exec"  # execute shell commands on hosts


class AgentCapabilities(BaseModel):
    """The set of capabilities an agent declares at registration time.

    The controller validates task dispatch against these capabilities.
    Unknown capabilities are ignored (fail-closed for unrecognized kinds).
    """

    model_config = ConfigDict(frozen=True)

    allowed_faults: tuple[str, ...] = ()
    allowed_resources: tuple[str, ...] = ()
    capabilities: tuple[CapabilityKind, ...] = ()

    def can_inject(self, fault_id: str) -> bool:
        """Can this agent inject the given fault type?"""
        if CapabilityKind.FAULT_INJECT not in self.capabilities:
            return False
        if not self.allowed_faults:
            return True  # empty allowlist = all faults allowed
        return fault_id in self.allowed_faults or any(
            fault_id.startswith(prefix) for prefix in self.allowed_faults
        )

    def can_undo(self, fault_id: str) -> bool:
        """Can this agent undo the given fault type?"""
        if CapabilityKind.FAULT_UNDO not in self.capabilities:
            return False
        if not self.allowed_faults:
            return True
        return fault_id in self.allowed_faults or any(
            fault_id.startswith(prefix) for prefix in self.allowed_faults
        )

    def can_access_resource(self, resource_type: str) -> bool:
        """Can this agent touch the given resource type?"""
        if CapabilityKind.RESOURCE_ACCESS not in self.capabilities:
            return False
        if not self.allowed_resources:
            return True
        return resource_type in self.allowed_resources

    def can_use_network(self) -> bool:
        return CapabilityKind.NETWORK_ACCESS in self.capabilities

    def can_exec_shell(self) -> bool:
        return CapabilityKind.SHELL_EXEC in self.capabilities


class AgentIdentity(BaseModel):
    """Immutable identity for an agent, set at registration."""

    model_config = ConfigDict(frozen=True)

    agent_id: str
    hostname: str = ""
    pid: int | None = None
    started_at: str = ""
    capabilities: AgentCapabilities = Field(default_factory=AgentCapabilities)

    def validate_fault_dispatch(self, fault_id: str, *, is_undo: bool = False) -> None:
        """Raise if this agent cannot handle the given fault.

        Uses a domain-level error rather than a generic exception so callers
        can catch it uniformly.
        """
        from mayhem.domain.errors import InvariantViolationError  # noqa: PLC0415

        action = "undo" if is_undo else "inject"
        if is_undo and not self.capabilities.can_undo(fault_id):
            raise InvariantViolationError(
                "agent.capability.denied",
                f"agent '{self.agent_id}' not authorized to {action} '{fault_id}'",
            )
        if not is_undo and not self.capabilities.can_inject(fault_id):
            raise InvariantViolationError(
                "agent.capability.denied",
                f"agent '{self.agent_id}' not authorized to {action} '{fault_id}'",
            )
