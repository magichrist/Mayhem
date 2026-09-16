"""Maniac mode — random fault injection (ADR-M5-1).

``mayhem maniac`` compiles a drill spec exactly like ``mayhem run``, then
replaces the authored execution with a random draw: ``run_level`` rounds, each
picking a random container (from the spec's own ``containers`` map) and a
random fault. The spec keeps providing the container pool, the fault catalog
entries, the success criteria and the observability sources, so the machine
verdict and evidence are produced exactly as in a deterministic run.

The ``level`` dial (1-5) scales how far each round strays from the spec's
authored intent (see the table below). Drawing is reproducible when ``seed``
is set.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.domain.catalog import definition_for
from mayhem.domain.common import parse_duration
from mayhem.domain.errors import SchemaValidationError

if TYPE_CHECKING:
    from mayhem.domain.experiments import DrillFault, DrillSpec


class ManiacError(Exception):
    """Raised when maniac mode cannot be compiled."""


@dataclass(frozen=True)
class ManiacDraw:
    """One maniac round: a fault to inject on a container."""

    container: str  # target container name (matches the topology)
    target: str  # logical target key (same as container for compose maniac)
    fault: DrillFault  # duration may be jittered (levels 4-5)
    round: int  # 1-based injection round


@dataclass(frozen=True)
class ManiacTargetDraw:
    """One maniac round against a kubernetes logical target (k-plan-3 SP-3.6).

    ``target`` is the ``targets:`` key (the logical id the planner pins);
    ``fault`` may be sourced from any target at ``level >= 3`` (cross-locus).
    """

    target: str  # logical target id (matches the topology pin)
    fault: DrillFault
    round: int  # 1-based injection round


def _jitter_duration(fault: DrillFault, pct: float, rng: random.Random) -> DrillFault:
    """Jitter ``fault.duration`` by ``±pct``, clamped to the catalog cap / 1 s."""
    raw = (
        parse_duration(fault.duration) if isinstance(fault.duration, str) else float(fault.duration)
    )
    jittered = raw * (1.0 + rng.uniform(-pct, pct))
    try:
        cap = definition_for(fault.fault).max_duration_s
        jittered = min(jittered, cap)
    except (SchemaValidationError, LookupError):
        pass  # the planner surfaces unknown-fault errors with authority
    return fault.model_copy(update={"duration": round(max(jittered, 1.0), 3)})


def draw_maniac_rounds(
    spec: DrillSpec,
    *,
    level: int,
    run_level: int,
    seed: int | None = None,
) -> tuple[ManiacDraw, ...]:
    """Draw ``run_level`` random (container, fault) rounds from ``spec``.

    Only containers that actually author faults are in the pool; cross-locus
    draws (``level >= 3``) may apply any spec-wide fault to any pool container.
    Durations are jittered at ``level >= 4`` (ADR-M5-1 §semantics).
    """
    pool = {name: container for name, container in spec.containers.items() if container.faults}
    if not pool:
        raise ManiacError(
            "maniac mode needs at least one container with faults — "
            "none of the spec's containers define any"
        )
    rng = random.Random(seed)
    names = sorted(pool)
    all_faults = tuple(f for c in pool.values() for f in c.faults)
    jitter_pct = 0.20 if level >= 5 else (0.10 if level == 4 else 0.0)

    draws: list[ManiacDraw] = []
    for round_no in range(1, run_level + 1):
        target = rng.choice(names)
        if level >= 3:
            # Cross-locus: any spec-wide fault may land on any pool container.
            fault = rng.choice(all_faults)
        elif level == 2:
            fault = rng.choice(pool[target].faults)
        else:
            fault = pool[target].faults[0]
        if jitter_pct > 0:
            fault = _jitter_duration(fault, jitter_pct, rng)
        draws.append(ManiacDraw(container=target, fault=fault, round=round_no))
    return tuple(draws)


def draw_maniac_target_rounds(
    spec: DrillSpec,
    *,
    level: int,
    run_level: int,
    seed: int | None = None,
) -> tuple[ManiacTargetDraw, ...]:
    """Draw ``run_level`` random (target, fault) rounds from a ``targets:`` spec.

    Kubernetes maniac mode (k-plan-3 SP-3.6) draws against the spec's
    ``targets:`` map: each target authors >= 1 fault (schema invariant), so
    any target in the pool is drawable.  Cross-locus draws (``level >= 3``)
    may apply any spec-wide fault to any pool target; durations are jittered
    at ``level >= 4`` like the container path (ADR-M5-1 §semantics).
    """
    if not spec.targets:
        raise ManiacError(
            "maniac target rounds need a `targets:` map with at least one target"
        )
    rng = random.Random(seed)
    names = sorted(spec.targets)
    all_faults = tuple(f for t in spec.targets.values() for f in t.faults)
    jitter_pct = 0.20 if level >= 5 else (0.10 if level == 4 else 0.0)

    draws: list[ManiacTargetDraw] = []
    for round_no in range(1, run_level + 1):
        target = rng.choice(names)
        if level >= 3:
            fault = rng.choice(all_faults)
        elif level == 2:
            fault = rng.choice(spec.targets[target].faults)
        else:
            fault = spec.targets[target].faults[0]
        if jitter_pct > 0:
            fault = _jitter_duration(fault, jitter_pct, rng)
        draws.append(ManiacTargetDraw(target=target, fault=fault, round=round_no))
    return tuple(draws)
