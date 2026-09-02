"""Remote-agent interface contract (ADR-M3-5).

Defines the seam a remote execution transport must satisfy.  **No transport is
implemented in this milestone** — a remote target in a spec fails planning with
``UNSUPPORTED`` until a future milestone implements a transport (Q11).

The methods below describe the *capability handshake* and *tool run* lifecycle.
Because no SSH/agent transport exists yet, ``capabilities()`` returns all
verdicts as ``UNSUPPORTED`` so the planner can refuse remote plans with a clear
message rather than fail unpredictably mid-run.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from mayhem.domain.runtime_adapter import (
    CapabilityRequirements,
    CapabilityVerdict,
    VerdictResult,
)


@runtime_checkable
class RemoteAgentInterface(Protocol):
    """Contract for a remote execution agent (ADR-M3-5).

    Implementations provide a transport (SSH, WireGuard, managed agent, ...).
    This milestone ships the interface only.
    """

    def connect(self) -> None: ...

    def capability_handshake(self, reqs: CapabilityRequirements) -> VerdictResult: ...

    def target_resolution(self, target_id: str) -> str: ...

    def tool_run(self, command: list[str], *, timeout_s: float) -> str: ...

    def cancel(self, run_id: str) -> None: ...

    def teardown(self) -> None: ...


class RemoteAgentAdapter:
    """Placeholder adapter so the planner can statically refuse remote plans.

    ``evaluate`` returns UNSUPPORTED for every requirement, which is what the
    planner uses to reject remote execution with a clear message.
    """

    def __init__(self, remote_id: str = "remote") -> None:
        self._remote_id = remote_id

    @property
    def id(self) -> str:
        return self._remote_id

    def evaluate(self, reqs: CapabilityRequirements) -> VerdictResult:
        blocking = True
        verdicts = {
            "remote_execution": CapabilityVerdict.UNSUPPORTED.value,
            "transport": CapabilityVerdict.UNSUPPORTED.value,
        }
        return VerdictResult(
            engine=self._remote_id,
            requirements=reqs,
            verdicts=verdicts,
            blocking=blocking,
        )
