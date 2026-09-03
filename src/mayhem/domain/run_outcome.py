"""Run and Outcome domain models (ADR-M5-1).

A ``RunRecord`` is *what was executed* — the experiment spec, faults, groups,
cancellation, journal refs, verdict, duration, and tool evidence.

An ``Outcome`` is *what happened* — observed post-run system state, checks
passed/failed, metric deltas, residual effect, and stability/recovery signal.

They persist separately and link by a ``run_id → outcome`` reference.
A ``RunRecord`` is never conflated with its ``Outcome``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class RunVerdict(StrEnum):
    """Top-level verdict for a completed run."""

    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    ABORTED = "aborted"
    BYPASSED = "bypassed"


class RunStatus(StrEnum):
    """Lifecycle status of a run."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


@dataclass(frozen=True)
class RunRecord:
    """What was executed in a single drill run.

    Persisted separately from its ``Outcome`` and linked by ``run_id``.
    """

    run_id: str
    experiment_name: str
    spec_json: str
    plan_json: str
    seed: int | None = None
    status: RunStatus = RunStatus.PENDING
    environment_fingerprint: str = ""
    config_snapshot_id: str = ""
    started_at: str = ""
    ended_at: str = ""
    description: str = ""
    verdict: RunVerdict = RunVerdict.PASS
    tags: tuple[str, ...] = ()
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def wall_seconds(self) -> float:
        """Duration in seconds (requires both timestamps set)."""
        if not self.started_at or not self.ended_at:
            return 0.0
        try:
            start = datetime.fromisoformat(self.started_at)
            end = datetime.fromisoformat(self.ended_at)
            return max(0.0, (end - start).total_seconds())
        except ValueError:
            return 0.0

    def summary_md(self) -> str:
        """Markdown summary of the run."""
        lines = [
            f"# Run {self.run_id}",
            "",
            f"**experiment**: {self.experiment_name}",
            f"**status**: {self.status.value}",
            f"**verdict**: {self.verdict.value}",
        ]
        if self.started_at:
            lines.append(f"**started**: {self.started_at}")
        if self.ended_at:
            lines.append(f"**ended**: {self.ended_at}")
        if self.seed is not None:
            lines.append(f"**seed**: {self.seed}")
        if self.tags:
            lines.append(f"**tags**: {', '.join(self.tags)}")
        if self.description:
            lines.append("")
            lines.append(self.description)
        return "\n".join(lines)


@dataclass(frozen=True)
class Outcome:
    """What happened after a run — observed post-run system state.

    Persisted separately from the ``RunRecord`` and linked by ``run_id``.
    """

    run_id: str
    body_json: str = "{}"
    body_hash: str = ""
    checks_passed: int = 0
    checks_failed: int = 0
    metric_deltas: dict[str, float] = field(default_factory=dict)
    residual_effect: str = ""
    stability_signal: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def all_checks_passed(self) -> bool:
        """True when there were checks and every one passed."""
        return self.checks_passed > 0 and self.checks_failed == 0

    @property
    def total_checks(self) -> int:
        return self.checks_passed + self.checks_failed

    def summary_md(self) -> str:
        """Markdown summary of the outcome."""
        total = self.total_checks
        if total == 0:
            status_str = "no checks"
        elif self.all_checks_passed:
            status_str = f"all {total} checks passed"
        else:
            status_str = f"{self.checks_failed}/{total} checks failed"
        lines = [
            f"# Outcome for Run {self.run_id}",
            "",
            f"**checks**: {status_str}",
        ]
        if self.metric_deltas:
            lines.append("**metric deltas**:")
            for name, delta in self.metric_deltas.items():
                lines.append(f"  - {name}: {delta:+.4f}")
        if self.residual_effect:
            lines.append(f"**residual**: {self.residual_effect}")
        if self.stability_signal:
            lines.append(f"**stability**: {self.stability_signal}")
        return "\n".join(lines)
