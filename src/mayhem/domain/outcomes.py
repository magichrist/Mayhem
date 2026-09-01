"""Shared outcome/state taxonomy (ADR-M1-3 Phase 1.4).

The outcome vocabulary is a single source of truth that the executor,
planner, CLI exit mapping, recovery state machine, and a future drift
*publisher event* all name the same way.

The three constants are deliberately siblings with sharply distinct
semantics:

* :data:`TARGET_DRIFT` — the plan targeted an identity that no longer exists.
  The planned ``RuntimeIdentity`` does not match the live one. A drifted
  target is *mismatched*, never failed.
* :data:`FAILED_TO_APPLY` — a capability/permission/mutation failure on a
  *present* target.
* :data:`RESOURCE_CONFLICT` — ownership/lease contention on a *present*
  target.

``TARGET_DRIFT`` is declared here (M1) but *detected* in M2. This module
ships no detection logic; it only fixes the shared vocabulary.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from mayhem.domain.identity import RuntimeIdentity


class StepOutcome(StrEnum):
    """Lead outcome for a single step at execution time (ADR-M1-3).

    Values are exactly the ``step_runs.status`` vocabulary admitted by the
    persisted schema (migration M0006): ``completed``, ``failed``,
    ``skipped``, ``cancelled``, ``bypassed``, and ``target_drift``.
    :attr:`TARGET_DRIFT` is a first-class persisted step state — it is *not* a
    failure of injection, not a dirty state, and not ownership contention; it
    means the object the plan intended to touch is no longer the object
    present.
    """

    COMPLETED = "completed"
    FAILED = "failed"
    TARGET_DRIFT = "target_drift"


class TargetOutcome(StrEnum):
    """Why a particular fault never reached its target (failure taxonomy).

    These classify the *reason* a step did not apply to its target. They
    refine the raw ``failed`` step outcome, and are the vocabulary used to
    distinguish drift from capability failures from contention:

    * :attr:`FAILED_TO_APPLY` — capability/permission/mutation failure on a
      *present* target.
    * :attr:`RESOURCE_CONFLICT` — ownership/lease contention on a *present*
      target.
    * :attr:`TARGET_DRIFT` — the planned identity no longer matches the live
      identity; the target was *mismatched, not failed*.
    """

    FAILED_TO_APPLY = "failed_to_apply"
    RESOURCE_CONFLICT = "resource_conflict"
    TARGET_DRIFT = "target_drift"


@dataclass(frozen=True)
class DriftEvent:
    """Payload of a future drift publisher event (declared M1, fired M2).

    No detection logic ships here; this dataclass is the contract consumed by
    a publisher callback so recovery, reporting, and the CLI all agree on the
    shape of a drift notification.
    """

    run_id: str
    step_id: str
    planned: RuntimeIdentity
    live: RuntimeIdentity


class DriftPublisher(Protocol):
    """Callback signature for the drift event publisher (ADR-M1-3).

    A conforming publisher accepts a :class:`DriftEvent` and returns
    ``None``. The controller may use this to emit an observation, persist a
    recovery hint, or notify an external surface — enforcement is wired in M2.
    """

    def __call__(self, event: DriftEvent) -> None: ...
