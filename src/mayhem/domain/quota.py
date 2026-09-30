"""Cumulative damage accounting — the quota Part B of the dry-run plan adds.

`controller.safety.check_blast_radius` enforces five limits, and every one of
them is evaluated **per fault step**: `max_services_pct`, `max_hosts`,
`max_concurrent_faults`, `max_duration_per_fault_s`, `forbidden_fault_pairs`.
A step that stays under all five is, by construction, small. A *plan* of
twenty such steps is not small, and nothing in the gate sees the sum.

So this module is the missing half: a pure damage ledger that charges every
step against a per-target budget and refuses the step that would take the
total over. It performs no IO — the ledger is created by the caller, charged
per step, and read back by the same process — so it is testable on its own
without a store, a graph, or a runtime.

## Where a fault's damage comes from

Not from a parallel cost table. Every weight is read out of the *existing*
`FaultDefinition` the rest of the system already prices the fault by:

- ``risk`` — the authored ladder (`domain/risks.py`). A paused process and a
  500ms latency injection both cost the target time; a node drain costs it the
  node. Only from ``HIGH`` up does a second of impairment cost more than a
  second.
- ``reversibility`` — whether the damage is undone with the fault. An
  ``IRREVERSIBLE`` fault leaves residue, so the same injected second is worth
  more against a rolling budget.
- the **blast width** is not a weight at all: it comes from the
  ``dependents_closure`` set ``check_blast_radius`` already computes for the
  per-step service percentage. Every node in that set is impaired, so every
  node in it accrues. A wide step therefore charges many ledgers at once
  without a single magic multiplier, and the per-step ``max_services_pct``
  and the cumulative budget stay derived from the *same* closure — they cannot
  disagree about what a fault touched.
- ``duration_s`` — the plan's own step duration, already capped per step by
  ``max_duration_per_fault_s``.

A fault id the catalog cannot resolve is priced at the top of the ladder on
purpose: an unpriced fault must never be cheaper than a priced one. (The
asymmetry with ``safety._risk_of``, which floors an unknown fault at ``LOW``,
is deliberate — that one is admission, where over-pricing refuses valid plans,
and this one is damage, where under-pricing allows them.)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from mayhem.domain.catalog import definition_for
from mayhem.domain.faults import FaultDefinition, Reversibility
from mayhem.domain.risks import RiskLevel

if TYPE_CHECKING:
    from collections.abc import Iterable


# Seconds of impairment cost this many damage-seconds. LOW and MEDIUM are both
# 1.0 on purpose: a 300s latency injection and a 300s process pause each cost
# the target 300s of impairment, and inflating one of them would make the
# budget disagree with `max_duration_per_fault_s`, which treats them alike.
RISK_DAMAGE_WEIGHT: dict[RiskLevel, float] = {
    RiskLevel.LOW: 1.0,
    RiskLevel.MEDIUM: 1.0,
    RiskLevel.HIGH: 2.0,
    RiskLevel.CRITICAL: 4.0,
}

# Damage that is not undone with the fault counts more than damage that is.
REVERSIBILITY_DAMAGE_WEIGHT: dict[Reversibility, float] = {
    Reversibility.REVERSIBLE: 1.0,
    Reversibility.RECONCILED: 1.25,
    Reversibility.IRREVERSIBLE: 2.0,
}

# The price of a fault the catalog cannot resolve: the most expensive rung of
# both ladders. Fail-safe — an unknown fault can never be the cheap one.
UNRESOLVED_FAULT_WEIGHT: float = (
    RISK_DAMAGE_WEIGHT[RiskLevel.CRITICAL] * REVERSIBILITY_DAMAGE_WEIGHT[Reversibility.IRREVERSIBLE]
)

RULE_BUDGET = "damage_quota.budget"
RULE_PER_FAULT_CEILING = "damage_quota.per_fault_ceiling"

# 4h of damage per target. Generous enough to never fire on a normal drill
# (a 300s MEDIUM/REVERSIBLE fault at the default duration costs 300, so this
# is ~48 of them) and tight enough to catch a `campaign` run for a week.
DEFAULT_BUDGET_S: float = 4 * 3600.0

# 1h for a *single* fault on a *single* target. Above the worst catalog fault
# at the default `max_duration_per_fault_s` (300s x CRITICAL x IRREVERSIBLE =
# 2400), so it is a backstop against one authored step eating the window, not
# a limit normal use meets.
DEFAULT_PER_FAULT_CEILING_S: float = 3600.0

# 7 days. Authored and reported, but not enforced here: a rolling window needs
# the persisted run history, and this module is pure by construction. See the
# wiring note in domain/quota.py's consumers.
DEFAULT_WINDOW_S: float = 7 * 24 * 3600.0


class DamageQuota(BaseModel):
    """The authored cumulative damage budget.

    The intended spec home is ``blast_radius.damage_quota`` next to the five
    per-step limits, i.e. a field on
    ``domain.experiments.BlastRadiusBudget``. That model is not owned by the
    lane that built this one, so the field was wired during integration: it is
    carried on ``BlastRadiusBudget.damage_quota`` and enforced by
    ``check_blast_radius``. The defaults below are what the safety context
    carries when a drill does not author its own.
    """

    model_config = ConfigDict(frozen=True)

    budget_s: float = Field(default=DEFAULT_BUDGET_S, gt=0.0)
    per_fault_ceiling_s: float = Field(default=DEFAULT_PER_FAULT_CEILING_S, gt=0.0)
    window_s: float = Field(default=DEFAULT_WINDOW_S, gt=0.0)

    def unrestricted(self) -> DamageQuota:
        """A clone with every cap lifted, for probing a step's *numbers*.

        ``preflight`` needs the damage a refused step *would* charge, and the
        same trick it already uses for the five per-step limits: the numbers
        do not depend on the budget, only the comparisons do.
        """
        return self.model_copy(
            update={
                "budget_s": float("inf"),
                "per_fault_ceiling_s": float("inf"),
                "window_s": float("inf"),
            }
        )


def damage_weight_for(definition: FaultDefinition) -> float:
    """Damage-seconds per injected second, straight off the catalog record."""
    reversibility = definition.reversibility or Reversibility.REVERSIBLE
    return RISK_DAMAGE_WEIGHT[definition.risk] * REVERSIBILITY_DAMAGE_WEIGHT[reversibility]


def damage_weight(fault_id: str) -> float:
    """Damage-seconds per injected second for ``fault_id``, from the catalog.

    Falls back to :data:`UNRESOLVED_FAULT_WEIGHT` rather than raising: the
    planner is the component that rejects an unknown fault id, and a safety
    gate that crashed on one would be a gate that stops gating.
    """
    try:
        return damage_weight_for(definition_for(fault_id))
    except Exception:
        return UNRESOLVED_FAULT_WEIGHT


def is_catalog_fault(fault_id: str) -> bool:
    """True when the catalog prices ``fault_id``.

    Exists so the tests can assert the weight really was read from catalog
    data — a local lookup table could satisfy every other assertion in the
    suite while disagreeing with the fault definitions the rest of the system
    prices by, and nothing else would notice.
    """
    try:
        definition_for(fault_id)
    except Exception:
        return False
    return True


@dataclass(frozen=True)
class QuotaCharge:
    """The result of charging one step against the ledger.

    ``rule_id`` is empty when the step is within budget. The refusal is
    deterministic: the same ledger and the same step always produce the same
    reason, the same node, and the same numbers.
    """

    fault_id: str
    step_index: int
    weight: float
    per_node_s: float
    step_damage_s: float
    total_s: float
    worst_node: str
    worst_node_s: float
    limit_s: float
    rule_id: str = ""
    reason: str = ""
    remediation: str = ""

    @property
    def exceeded(self) -> bool:
        return bool(self.rule_id)

    def inputs(self) -> dict[str, object]:
        """The machine-readable half of the refusal, for ``SafetyDecision``."""
        return {
            "fault_id": self.fault_id,
            "step_index": self.step_index,
            "node_id": self.worst_node,
            "accumulated_damage_s": round(self.worst_node_s, 3),
            "budget_s": self.limit_s,
            "step_damage_s": round(self.step_damage_s, 3),
            "plan_total_damage_s": round(self.total_s, 3),
            "weight": self.weight,
        }


@dataclass
class DamageLedger:
    """Per-target accumulated damage for one plan.

    Keyed by node, because the budget is per target: a target that is impaired
    forty times is in trouble whether the forty faults were wide or narrow.
    ``by_node_fault`` keeps the ``(node_id, fault_id)`` breakdown the quota
    proposal asks for, so a refusal can say which fault did the damage and not
    only which step tripped the limit.
    """

    _by_node: dict[str, float] = field(default_factory=dict)
    _by_node_fault: dict[tuple[str, str], float] = field(default_factory=dict)
    _total_s: float = 0.0
    _steps: int = 0

    @property
    def total_s(self) -> float:
        """Plan-wide accumulated damage: the sum over every node charged."""
        return self._total_s

    @property
    def steps(self) -> int:
        return self._steps

    @property
    def worst_node(self) -> str:
        return self._worst()[0]

    @property
    def worst_node_s(self) -> float:
        return self._worst()[1]

    def damage_for(self, node_id: str) -> float:
        return self._by_node.get(node_id, 0.0)

    def by_node(self) -> dict[str, float]:
        return dict(sorted(self._by_node.items()))

    def by_node_fault(self) -> dict[tuple[str, str], float]:
        return dict(sorted(self._by_node_fault.items()))

    def _worst(self) -> tuple[str, float]:
        """The most-damaged target; ties break on node id so it is stable."""
        if not self._by_node:
            return "", 0.0
        top = max(self._by_node.values())
        node = min(n for n, v in self._by_node.items() if v == top)
        return node, top

    def charge(
        self,
        *,
        fault_id: str,
        duration_s: float,
        node_ids: Iterable[str],
        quota: DamageQuota,
    ) -> QuotaCharge:
        """Charge one step, then judge it against ``quota``.

        Charges first and judges second, so the ledger is a record of what the
        plan *does*, not a record of what it was allowed to do. Mutates the
        ledger; every other operation is a read.
        """
        nodes = tuple(sorted(set(node_ids)))
        weight = damage_weight(fault_id)
        per_node = float(duration_s) * weight
        step_index = self._steps
        for node_id in nodes:
            self._by_node[node_id] = self._by_node.get(node_id, 0.0) + per_node
            key = (node_id, fault_id)
            self._by_node_fault[key] = self._by_node_fault.get(key, 0.0) + per_node
        self._total_s += per_node * len(nodes)
        self._steps += 1

        step_damage = per_node * len(nodes)
        worst_node, worst_node_s = self._worst()

        if per_node > quota.per_fault_ceiling_s:
            return QuotaCharge(
                fault_id=fault_id,
                step_index=step_index,
                weight=weight,
                per_node_s=per_node,
                step_damage_s=step_damage,
                total_s=self._total_s,
                worst_node=worst_node,
                worst_node_s=worst_node_s,
                limit_s=quota.per_fault_ceiling_s,
                rule_id=RULE_PER_FAULT_CEILING,
                reason=(
                    f"damage quota: step {step_index} ({fault_id}) charges "
                    f"{per_node:.0f} damage-seconds to {worst_node} in a single fault "
                    f"> per-fault ceiling {quota.per_fault_ceiling_s:.0f} "
                    f"[{RULE_PER_FAULT_CEILING}]"
                ),
                remediation=(
                    "shorten the fault, choose a lower-risk or reversible fault, or raise "
                    f"damage_quota.per_fault_ceiling_s (currently "
                    f"{quota.per_fault_ceiling_s:.0f})"
                ),
            )

        if worst_node_s > quota.budget_s:
            return QuotaCharge(
                fault_id=fault_id,
                step_index=step_index,
                weight=weight,
                per_node_s=per_node,
                step_damage_s=step_damage,
                total_s=self._total_s,
                worst_node=worst_node,
                worst_node_s=worst_node_s,
                limit_s=quota.budget_s,
                rule_id=RULE_BUDGET,
                reason=(
                    f"damage quota: step {step_index} ({fault_id}) brings {worst_node} to "
                    f"{worst_node_s:.0f} cumulative damage-seconds "
                    f"> budget {quota.budget_s:.0f} [{RULE_BUDGET}]"
                ),
                remediation=(
                    "split the plan across more runs, shorten the faults, target fewer nodes, "
                    f"or raise damage_quota.budget_s (currently {quota.budget_s:.0f})"
                ),
            )

        return QuotaCharge(
            fault_id=fault_id,
            step_index=step_index,
            weight=weight,
            per_node_s=per_node,
            step_damage_s=step_damage,
            total_s=self._total_s,
            worst_node=worst_node,
            worst_node_s=worst_node_s,
            limit_s=quota.budget_s,
        )
