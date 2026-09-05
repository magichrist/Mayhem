"""Governing-decision registry — ADR decision IDs + decided-on timestamps.

Every outcome record carries the decision refs that produced it, so a replay
can attribute a verdict, its criteria, and its observations to the approved
decisions that defined them (ADR-M4-1/4-3/4-4/4-5). The ID is the ADR's own
name and the timestamp is the date it was approved — captured here once and
persisted on the run row by the executor.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class DecisionRef(BaseModel):
    """A single governing decision: ADR id + approval timestamp."""

    model_config = ConfigDict(frozen=True)

    decision_id: str
    decided_on: str  # ISO date the decision was approved
    title: str = ""

    def summary(self) -> str:
        """One-line human description: ``ADR-M4-3 2026-09-05 (title)``."""
        return f"{self.decision_id} {self.decided_on} ({self.title})"


DECISION_M4_1_ADDITIVE_DSL = DecisionRef(
    decision_id="ADR-M4-1",
    decided_on="2026-09-02",
    title="Additive, non-breaking DSL sections + typed Duration",
)

DECISION_M4_3_SUCCESS_CRITERIA = DecisionRef(
    decision_id="ADR-M4-3",
    decided_on="2026-09-05",
    title="Machine-evaluable success criteria + run verdict",
)

DECISION_M4_4_OBSERVABILITY = DecisionRef(
    decision_id="ADR-M4-4",
    decided_on="2026-09-05",
    title="Declarative observability/metrics sources",
)

DECISION_M4_5_SCHEMA_FREEZE = DecisionRef(
    decision_id="ADR-M4-5",
    decided_on="2026-09-02",
    title="Schema freeze + versioned migrations with up/down",
)
