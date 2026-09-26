from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from typing import Any

DASHBOARD_SCHEMA_VERSION = "1.0"


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
    family: str = ""
    maturity: str = ""
    source_of_truth: str = ""
    remediation: str = ""

    @property
    def supported(self) -> bool:
        return (
            self.registered
            and self.available
            and self.target_supported
            and self.compensation_complete
        )

    @property
    def maturity_band(self) -> str:
        """Coarse maturity label used for filtering (``unit``/``live``/``stable``)."""
        return self.maturity or "unknown"

    def to_dict(self) -> dict[str, object]:
        return {
            **asdict(self),
            "supported": self.supported,
            "maturity_band": self.maturity_band,
        }


@dataclass(frozen=True, slots=True)
class CapabilityDashboard:
    """Read-only view of every fault/engine capability pair (ADR-M2-2)."""

    engine: str | None
    rows: tuple[CapabilityStatus, ...]
    generated_at: str
    schema_version: str = DASHBOARD_SCHEMA_VERSION
    filters: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "engine": self.engine,
            "generated_at": self.generated_at,
            "filters": list(self.filters),
            "summary": self.summary(),
            "capabilities": [row.to_dict() for row in self.rows],
        }

    def summary(self) -> dict[str, int]:
        return {
            "total": len(self.rows),
            "supported": sum(1 for row in self.rows if row.supported),
            "blocked": sum(1 for row in self.rows if row.blocked_reason),
            "unit_verified": sum(1 for row in self.rows if row.unit_verified),
            "live_verified": sum(1 for row in self.rows if row.live_verified),
        }

    def find(self, fault_id: str) -> tuple[CapabilityStatus, ...]:
        return tuple(row for row in self.rows if row.fault_id == fault_id)

    def filtered(
        self,
        *,
        engine: str | None = None,
        family: str | None = None,
        maturity: str | None = None,
        blocked: bool | None = None,
    ) -> CapabilityDashboard:
        rows: Iterable[CapabilityStatus] = self.rows
        if engine:
            rows = [row for row in rows if row.engine == engine.lower()]
        if family:
            wanted = family.lower()
            rows = [row for row in rows if row.fault_id.split(".", 1)[0].lower() == wanted]
        if maturity:
            wanted = maturity.lower()
            rows = [row for row in rows if row.maturity_band.lower() == wanted]
        if blocked is True:
            rows = [row for row in rows if row.blocked_reason]
        elif blocked is False:
            rows = [row for row in rows if not row.blocked_reason]
        applied = tuple(
            name
            for name, value in (
                ("engine", engine),
                ("family", family),
                ("maturity", maturity),
                ("blocked", blocked),
            )
            if value not in (None, "")
        )
        return CapabilityDashboard(
            engine=engine.lower() if engine else self.engine,
            rows=tuple(rows),
            generated_at=self.generated_at,
            schema_version=self.schema_version,
            filters=applied,
        )
