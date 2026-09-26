from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class CapabilityStatus:
    fault_id: str
    engine: str
    registered: bool
    available: bool
    target_supported: bool
    unit_verified: bool
    live_verified: bool
    compensation_complete: bool
    blocked_reason: str = ""

    @property
    def supported(self) -> bool:
        return (
            self.registered
            and self.available
            and self.target_supported
            and self.compensation_complete
        )

    def to_dict(self) -> dict[str, object]:
        return {**asdict(self), "supported": self.supported}
