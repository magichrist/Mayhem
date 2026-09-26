"""Before/after residual impact assessment (v0.9.0 expansion task 16).

A run can compensate every fault and still leave the system changed. This module
compares a *before* snapshot with an *after* snapshot and reports what did not
come back. The rule that matters: a violation is only "tolerated" when a human
accepted it explicitly — there is no silent tolerance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

RESIDUAL_SCHEMA_VERSION = "1.0"

CLEAN = "clean"
PARTIAL = "partial"
VIOLATION = "violation"
TOLERATED = "tolerated"
UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class ImpactSnapshot:
    """A point-in-time set of measured values."""

    label: str = ""
    values: dict[str, float] = field(default_factory=dict)
    available: bool = True
    source: str = ""
    detail: str = ""

    @classmethod
    def unavailable(cls, label: str, reason: str) -> ImpactSnapshot:
        return cls(label=label, available=False, detail=reason)

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "values": dict(self.values),
            "available": self.available,
            "source": self.source,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class ImpactAcceptance:
    """Explicit human acceptance of one residual deviation."""

    signal: str
    accepted_by: str
    reason: str
    accepted_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal": self.signal,
            "accepted_by": self.accepted_by,
            "reason": self.reason,
            "accepted_at": self.accepted_at,
        }


@dataclass(frozen=True, slots=True)
class ResidualViolation:
    signal: str
    expected: float
    observed: float
    delta: float
    tolerated: bool = False
    acceptance: ImpactAcceptance | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal": self.signal,
            "expected": self.expected,
            "observed": self.observed,
            "delta": self.delta,
            "tolerated": self.tolerated,
            "acceptance": self.acceptance.to_dict() if self.acceptance else None,
        }


@dataclass(frozen=True, slots=True)
class ResidualImpactAssessment:
    """The verdict: did the system return to where it started?"""

    status: str
    before: ImpactSnapshot
    after: ImpactSnapshot
    violations: tuple[ResidualViolation, ...] = ()
    signals_compared: int = 0
    schema_version: str = RESIDUAL_SCHEMA_VERSION

    @property
    def clean(self) -> bool:
        return self.status == CLEAN

    @property
    def untolerated(self) -> tuple[ResidualViolation, ...]:
        return tuple(violation for violation in self.violations if not violation.tolerated)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "clean": self.clean,
            "signals_compared": self.signals_compared,
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "violations": [violation.to_dict() for violation in self.violations],
            "untolerated_count": len(self.untolerated),
        }


def assess_residual_impact(
    before: ImpactSnapshot,
    after: ImpactSnapshot,
    *,
    tolerance: float = 0.0,
    acceptances: tuple[ImpactAcceptance, ...] = (),
) -> ResidualImpactAssessment:
    """Compare two snapshots and classify the result.

    An unavailable observation source is reported as ``unavailable`` — never as
    ``clean``, because "we could not look" is not "nothing changed".
    """
    if not before.available or not after.available:
        return ResidualImpactAssessment(
            status=UNAVAILABLE,
            before=before,
            after=after,
            violations=(),
            signals_compared=0,
        )

    accepted = {acceptance.signal: acceptance for acceptance in acceptances}
    signals = sorted(set(before.values) & set(after.values))
    violations: list[ResidualViolation] = []
    for signal in signals:
        expected = before.values[signal]
        observed = after.values[signal]
        delta = observed - expected
        if abs(delta) <= tolerance:
            continue
        acceptance = accepted.get(signal)
        violations.append(
            ResidualViolation(
                signal=signal,
                expected=expected,
                observed=observed,
                delta=delta,
                tolerated=acceptance is not None,
                acceptance=acceptance,
            )
        )

    untolerated = [violation for violation in violations if not violation.tolerated]
    if not violations:
        status = CLEAN
    elif not untolerated:
        status = TOLERATED
    elif len(untolerated) == len(violations):
        status = VIOLATION
    else:
        status = PARTIAL

    return ResidualImpactAssessment(
        status=status,
        before=before,
        after=after,
        violations=tuple(violations),
        signals_compared=len(signals),
    )
