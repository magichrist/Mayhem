"""Seeded, bounded candidate generator (ADR-M5-2, M5 Phase 5.3).

Produces ``ExperimentCandidate`` proposals over the
(target, fault_kind, execution_context, parameter_band) landscape. Generation
is deterministic for a fixed seed, and honors a per-band risk ceiling so no
candidate above the campaign's risk tolerance is ever proposed.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

from mayhem.domain.candidates import ExperimentCandidate
from mayhem.domain.risks import RiskLevel

# Risk of a fault_kind, keyed by fault id prefix (mirrors safety projection).
_DEFAULT_FAULT_RISK: dict[str, RiskLevel] = {
    "net": RiskLevel.MEDIUM,
    "cpu": RiskLevel.MEDIUM,
    "mem": RiskLevel.MEDIUM,
    "fs": RiskLevel.HIGH,
    "disk": RiskLevel.HIGH,
    "storage": RiskLevel.HIGH,
    "process": RiskLevel.LOW,
    "container": RiskLevel.LOW,
    "node": RiskLevel.CRITICAL,
    "http_api": RiskLevel.LOW,
    "database": RiskLevel.HIGH,
    "load": RiskLevel.MEDIUM,
    "fuzz": RiskLevel.HIGH,
    "dns": RiskLevel.LOW,
    "tls": RiskLevel.LOW,
    "clock": RiskLevel.MEDIUM,
    "fd": RiskLevel.MEDIUM,
}


def _risk_of_fault(fault_kind: str) -> RiskLevel:
    prefix = fault_kind.split(".", 1)[0]
    return _DEFAULT_FAULT_RISK.get(prefix, RiskLevel.MEDIUM)


@dataclass
class CandidateLandscape:
    """The space the generator draws from, plus the allowed risk ceiling."""

    targets: tuple[str, ...] = ()
    fault_kinds: tuple[str, ...] = ()
    execution_contexts: tuple[str, ...] = ("container",)
    parameter_bands: tuple[str, ...] = ("default",)
    risk_ceiling: RiskLevel = RiskLevel.HIGH


@dataclass
class SeededCandidateGenerator:
    """Deterministic generator; the same seed yields the same candidates."""

    landscape: CandidateLandscape
    seed: int = 0
    rng: random.Random | None = None

    def __post_init__(self) -> None:
        if self.rng is None:
            self.rng = random.Random(self.seed)

    def _in_ceiling(self, risk: RiskLevel) -> bool:
        return _risk_rank(risk) <= _risk_rank(self.landscape.risk_ceiling)

    def generate(self, *, limit: int | None = None) -> tuple[ExperimentCandidate, ...]:
        """Yield candidates until the landscape is exhausted or ``limit`` reached.

        Candidates above the risk ceiling are skipped, never emitted.
        """
        out: list[ExperimentCandidate] = []
        for target in self.landscape.targets:
            for fault_kind in self.landscape.fault_kinds:
                risk = _risk_of_fault(fault_kind)
                if not self._in_ceiling(risk):
                    continue
                for ctx in self.landscape.execution_contexts:
                    for band in self.landscape.parameter_bands:
                        params: dict[str, Any] = {"band": band}
                        candidate = ExperimentCandidate(
                            target=target,
                            fault_kinds=(fault_kind,),
                            params=params,
                            execution_context=ctx,
                            expected_effect=f"{fault_kind} on {target} in {band}",
                            risk_band=risk,
                            seed_hint=self.seed,
                        )
                        out.append(candidate)
                        if limit is not None and len(out) >= limit:
                            return tuple(out)
        # Deterministic shuffle so selection order isn't trivially the
        # landscape enumeration order — still fully reproducible from seed.
        rng = self.rng if self.rng is not None else random.Random(self.seed)
        rng.shuffle(out)
        return tuple(out)


def _risk_rank(level: RiskLevel) -> int:
    return {
        RiskLevel.LOW: 0,
        RiskLevel.MEDIUM: 1,
        RiskLevel.HIGH: 2,
        RiskLevel.CRITICAL: 3,
    }[level]
