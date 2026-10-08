"""Game-day artifacts as evidence, and the after-action report they feed
(docs/v1.1.0/13_SCHEDULING_CAMPAIGNS_GAMEDAYS.md, Phase 4).

A game day produces three kinds of thing, and the plan is explicit that they are
*not* three kinds of prose. A **decision** is a named human choosing to release a
hold or to pause; a **note** is an observation with no consequence attached; a
**finding** is a claim that something is wrong and is therefore the only one of
the three that may be graded. This module gives them one model with the
differences *enforced*, because the failure this exists to prevent is an
after-action report that reads a note as a finding and a finding as a decision --
a report whose severities are decoration.

Two commitments shape it.

**An artifact is a record of something that happened, not a claim that something
should.** Nothing here decides, approves, or dispatches. :func:`record_artifact`
persists; the gates that *decide* live in :mod:`mayhem.controller.scheduler`
(the facilitator hold) and :mod:`mayhem.domain.game_day` (the session state). An
artifact that could authorise an action would be a second approval model, and
this codebase has exactly one.

**The report refuses to certify what it cannot see.** :func:`after_action_report
reports three different kinds of gap rather than eliding them: a dispatch step
that was released but has no decision recorded against it (somebody let a drill
run and nobody wrote down why), a dispatched slot whose claim settled
``failed`` (a drill that did not complete), and a session with no findings at
all -- which for a resilience game day is a *finding about the game day*, not a
clean bill of health, and the report says so in words rather than rendering an
empty section.

What is deliberately **not** claimed
------------------------------------

* **Nothing here is signed or attested.** An artifact is a row in
  ``observations``. It carries a digest over its own fields so an edit is
  detectable by a reader, and it is not covered by
  :mod:`mayhem.controller.attestation_store`, so it is not independently
  verifiable evidence in plan 12's sense. A report that claims otherwise would be
  claiming a capability another lane owns.
* **The artifacts are not inside the secret boundary.** They are written with
  :meth:`mayhem.infra.store.Store.save_observation`, the same surface
  :meth:`mayhem.infra.schedule_store.ScheduleStore.record_tick` uses, and
  neither call site appears in ``BOUNDARY_CALL_SITES``. That is a real gap and it
  is stated rather than papered over: a free-text facilitator note is
  operator-authored and could carry anything, so the row that would bring these
  writes inside the boundary is reported in this plan's ledger instead of being
  silently assumed. See ``docs/v1.1.0/13_SCHEDULING_CAMPAIGNS_GAMEDAYS.md``.
* **No live-cluster claim.** A report reads the local SQLite registry. It says
  what the record says and nothing about what a cluster did.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import digest

if TYPE_CHECKING:
    from mayhem.infra.schedule_store import GameDayStepRecord, ScheduleRunRecord
    from mayhem.infra.store import Store

GAME_DAY_ARTIFACT_SCHEMA_VERSION: Final[str] = "1.0"

#: The observation kind every artifact is filed under. One kind rather than three
#: so a reader can ask "everything this session produced" with one query and get
#: everything, and the per-artifact ``kind`` field does the sorting.
ARTIFACT_OBSERVATION_KIND: Final[str] = "game_day.artifact"


class ArtifactKind(StrEnum):
    """The three kinds of thing a game day produces, and what each may claim."""

    DECISION = "decision"
    """A named human chose something. Carries an actor and a reason."""

    NOTE = "note"
    """An observation with no consequence. No severity."""

    FINDING = "finding"
    """A claim that something is wrong. The only kind that may be graded."""


class Severity(StrEnum):
    """How bad a finding is. Only a :attr:`ArtifactKind.FINDING` carries one."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


#: Order used when a report ranks findings. Index, not the enum's declaration
#: order, so a reordering of the members cannot silently reorder a report.
_SEVERITY_RANK: Final[dict[Severity, int]] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(severity: Severity) -> int:
    """Sort key for a severity; ``CRITICAL`` last, ``INFO`` first."""
    return _SEVERITY_RANK[severity]


class GameDayArtifact(BaseModel):
    """One recorded game-day artifact.

    The kind-specific rules are in one validator rather than three models,
    because the *absence* of the rules is the defect this type exists to prevent:
    three models would let a caller pick whichever one had the field it had, and
    a finding recorded as a note would simply be a note.

    ``actor`` must survive stripping on every kind, including a note. A note
    nobody attributed is not evidence of anything -- it is a sticky note -- and
    the after-action report cannot say whose observation it was.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{0,127}$")
    session_id: str = Field(min_length=1)
    kind: ArtifactKind
    actor: str
    text: str = Field(min_length=1)
    at: str
    #: The dispatch step this artifact is about, when it is about one.
    step_id: str = ""
    schedule_id: str = ""
    #: Set only on a finding. ``None`` on a decision or a note, so a graded
    #: severity cannot ride along on something that is not a claim.
    severity: Severity | None = None
    #: The dispatch this artifact decided, when it decided one.
    run_id: str = ""
    schema_version: str = GAME_DAY_ARTIFACT_SCHEMA_VERSION

    @model_validator(mode="after")
    def _check_kind_rules(self) -> Self:
        if not self.actor.strip():
            msg = (
                f"game-day artifact {self.artifact_id!r} names no actor; an unattributed "
                "note is not evidence of anything, it is a sticky note"
            )
            raise InvariantViolationError("game_day.artifact_actor_blank", msg)
        if not self.text.strip():
            msg = f"game-day artifact {self.artifact_id!r} carries no text"
            raise InvariantViolationError("game_day.artifact_text_blank", msg)
        if self.at.strip() == "":
            msg = f"game-day artifact {self.artifact_id!r} carries no instant"
            raise InvariantViolationError("game_day.artifact_at_blank", msg)
        if self.kind is ArtifactKind.FINDING:
            if self.severity is None:
                msg = (
                    f"game-day finding {self.artifact_id!r} carries no severity; a claim "
                    "that something is wrong must say how wrong"
                )
                raise InvariantViolationError("game_day.finding_severity", msg)
            return self
        if self.severity is not None:
            # Refused rather than dropped. Dropping it would make a graded note
            # indistinguishable from an ungraded one after the fact, which is the
            # exact confusion the kind field exists to prevent.
            msg = (
                f"game-day {self.kind.value} {self.artifact_id!r} carries severity "
                f"{self.severity.value!r}; only a finding may be graded"
            )
            raise InvariantViolationError("game_day.artifact_severity_on_note", msg)
        if self.kind is ArtifactKind.DECISION and not self.run_id:
            msg = (
                f"game-day decision {self.artifact_id!r} names no run; a decision that "
                "decided nothing cannot be read back as one that did"
            )
            raise InvariantViolationError("game_day.decision_run", msg)
        return self

    @property
    def instant(self) -> datetime:
        """The artifact's timestamp as an aware datetime.

        Raises:
            ValueError: Propagated from ``fromisoformat`` for a value the model
                accepted as non-blank but that is not a timestamp. Deliberately
                not coerced: a report that printed ``"not-a-time"`` as a date
                would be worse than one that raised.
        """
        return datetime.fromisoformat(self.at.replace("Z", "+00:00"))

    @property
    def digest(self) -> str:
        """A digest over the artifact's own fields, excluding the digest.

        Detects an edit made through SQL rather than through this model, which is
        the same reason :mod:`mayhem.infra.fabric_journal` stores a digest beside
        its payload. It is **not** a signature: anyone with database access can
        recompute it, and nothing here claims otherwise.
        """
        return digest(self.model_dump(mode="json", exclude={"schema_version"}))

    def to_payload(self) -> dict[str, object]:
        """The JSON-able body filed under ``game_day.artifact``.

        Round-trips: every key here is a field of this model except ``digest``,
        which :func:`artifacts_for_session` pops before validating. ``severity`` is
        **omitted** rather than sent as ``""`` when there is none, because the
        payload has to read back as the model it came from and ``""`` is not a
        :class:`Severity` -- an ungraded note would be skipped on read rather than
        read back ungraded.
        """
        payload: dict[str, object] = {
            "schema_version": self.schema_version,
            "artifact_id": self.artifact_id,
            "session_id": self.session_id,
            "step_id": self.step_id,
            "schedule_id": self.schedule_id,
            "kind": self.kind.value,
            "actor": self.actor,
            "text": self.text,
            "at": self.at,
            "run_id": self.run_id,
            "digest": self.digest,
        }
        if self.severity is not None:
            payload["severity"] = self.severity.value
        return payload

    def describe(self) -> str:
        grade = f" [{self.severity.value}]" if self.severity is not None else ""
        target = f" step={self.step_id}" if self.step_id else ""
        return f"{self.kind.value}{grade} by {self.actor}{target}: {self.text}"


class ArtifactGap(StrEnum):
    """What the report found missing. Named, so a reader can act on the name."""

    RELEASED_WITHOUT_DECISION = "released_without_decision"
    FAILED_DISPATCH = "failed_dispatch"
    UNKNOWN_OUTCOME_DISPATCH = "unknown_outcome_dispatch"
    NO_FINDINGS = "no_findings"
    NO_ARTIFACTS = "no_artifacts"


@dataclass(frozen=True)
class AfterActionReport:
    """The after-action report, and the gaps it refuses to paper over."""

    session_id: str
    artifacts: tuple[GameDayArtifact, ...] = ()
    steps: tuple[GameDayStepRecord, ...] = ()
    dispatches: tuple[ScheduleRunRecord, ...] = ()
    gaps: tuple[ArtifactGap, ...] = ()
    generated_at: str = ""
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def findings(self) -> tuple[GameDayArtifact, ...]:
        """Findings, most severe first, then by instant so a tie is stable."""
        return tuple(
            sorted(
                (artifact for artifact in self.artifacts if artifact.kind is ArtifactKind.FINDING),
                key=lambda artifact: (
                    -severity_rank(artifact.severity or Severity.INFO),
                    artifact.instant,
                    artifact.artifact_id,
                ),
            )
        )

    @property
    def by_kind(self) -> dict[str, int]:
        """Count per artifact kind, key-sorted."""
        counts: dict[str, int] = {}
        for artifact in self.artifacts:
            counts[artifact.kind.value] = counts.get(artifact.kind.value, 0) + 1
        return {kind: counts[kind] for kind in sorted(counts)}

    @property
    def clean(self) -> bool:
        """True only when nothing at all was found missing.

        Not "no findings": a session with no findings carries
        :attr:`ArtifactGap.NO_FINDINGS`, so ``clean`` is ``False`` for it. A game
        day that found nothing is the outcome most worth asking about, and a
        boolean that said ``True`` for it would be the report lying politely.
        """
        return not self.gaps

    def describe(self) -> str:
        verdicts = ", ".join(sorted({a.kind.value for a in self.artifacts})) or "nothing"
        line = (
            f"after-action {self.session_id}: {len(self.artifacts)} artifact(s) "
            f"[{verdicts}], {len(self.findings)} finding(s)"
        )
        if self.gaps:
            return f"{line}; {len(self.gaps)} gap(s): {', '.join(g.value for g in self.gaps)}"
        return f"{line}; no gaps"

    def to_payload(self) -> dict[str, object]:
        return {
            "session_id": self.session_id,
            "generated_at": self.generated_at,
            "counts": self.by_kind,
            "artifacts": [artifact.to_payload() for artifact in self.artifacts],
            "findings": [artifact.artifact_id for artifact in self.findings],
            "steps": [
                {
                    "step_id": step.step_id,
                    "scenario": step.scenario,
                    "schedule_id": step.schedule_id,
                    "hold_state": step.hold_state.value,
                    "released_by": step.released_by,
                }
                for step in self.steps
            ],
            "dispatches": [
                {
                    "idempotency_key": record.idempotency_key,
                    "schedule_id": record.schedule_id,
                    "slot_start": record.slot_start.isoformat(),
                    "state": record.state.value,
                    "code": record.code,
                    "run_id": record.run_id,
                    "settled": record.settled,
                }
                for record in self.dispatches
            ],
            "gaps": [gap.value for gap in self.gaps],
            "notes": list(self.notes),
            "clean": self.clean,
        }

    def render_markdown(self) -> str:
        """The facilitator-facing report.

        A fixed template rather than a free composition, because the sections that
        are *empty* are the ones that carry the information. ``## Findings``
        with nothing under it says "nobody wrote down a problem", which is not the
        same statement as "there were none" -- so the empty case prints that
        sentence explicitly.
        """
        lines = [f"# After-action report: {self.session_id}", ""]
        if self.generated_at:
            lines += [f"_assembled {self.generated_at}_", ""]
        lines += self._what_ran()
        if self.dispatches:
            lines += ["", "## Dispatches", ""]
            for record in self.dispatches:
                settled = "" if record.settled else " **UNKNOWN OUTCOME**"
                lines.append(
                    f"- {record.slot_start.isoformat()} {record.schedule_id}: "
                    f"{record.state.value}{settled} ({record.code or 'no code'})"
                )
        lines += ["", "## Findings", ""]
        if not self.findings:
            lines.append(
                "- **none recorded.** That is a statement about this report, not "
                "about the system: a game day that produced no finding may have "
                "been clean, or may have been played without anyone writing down "
                "what they saw."
            )
        for finding in self.findings:
            grade = (finding.severity or Severity.INFO).value
            lines.append(f"- **{grade}** — {finding.text} ({finding.actor})")
        lines += ["", "## Notes", ""]
        notes = [artifact for artifact in self.artifacts if artifact.kind is ArtifactKind.NOTE]
        if not notes:
            lines.append("- none recorded")
        for note in notes:
            lines.append(f"- {note.text} ({note.actor})")
        decisions = [
            artifact for artifact in self.artifacts if artifact.kind is ArtifactKind.DECISION
        ]
        if decisions:
            lines += ["", "## Decisions", ""]
            for decision in decisions:
                lines.append(f"- {decision.text} ({decision.actor}, run {decision.run_id})")
        lines += ["", "## Gaps", ""]
        if not self.gaps:
            lines.append("- none")
        for gap in self.gaps:
            lines.append(f"- **{gap.value}** — {GAP_EXPLANATION[gap]}")
        return "\n".join(lines) + "\n"

    def _what_ran(self) -> list[str]:
        """The ``## What ran`` section, including its empty case.

        Split out of :meth:`render_markdown` rather than inlined because the
        section has three shapes -- staged steps, none at all, and some -- and
        inlining all three into the template body pushed the method past the
        branch ceiling. No behaviour changed; the section is byte-identical.
        """
        lines = ["## What ran", ""]
        if not self.steps:
            lines.append("- no dispatch steps were staged for this session")
        for step in self.steps:
            holder = step.released_by or "nobody"
            lines.append(
                f"- `{step.step_id}` ({step.scenario or 'no scenario'}) -> "
                f"{step.schedule_id}: {step.hold_state.value}, released by {holder}"
            )
        return lines


#: What each gap means, in the words a facilitator would use. A gap reported
#: without its meaning is a code nobody acts on.
GAP_EXPLANATION: Final[dict[ArtifactGap, str]] = {
    ArtifactGap.RELEASED_WITHOUT_DECISION: (
        "a dispatch step was released but no decision artifact names the run it "
        "let go; somebody authorised a drill and did not write down why"
    ),
    ArtifactGap.FAILED_DISPATCH: (
        "a dispatched slot settled failed; the drill did not complete and the "
        "session should say so rather than record an attempt"
    ),
    ArtifactGap.UNKNOWN_OUTCOME_DISPATCH: (
        "a claimed slot was never settled, so whether it ran is unknown; this is "
        "an operator decision, not something to retry automatically"
    ),
    ArtifactGap.NO_FINDINGS: (
        "no finding was recorded for this session; see the note under Findings — "
        "an empty section is not a clean bill of health"
    ),
    ArtifactGap.NO_ARTIFACTS: "this session produced no artifact of any kind",
}


def record_artifact(store: Store, artifact: GameDayArtifact) -> GameDayArtifact:
    """File one artifact as an observation and return it as filed.

    The only writer of ``game_day.artifact`` rows, and it writes through
    :meth:`mayhem.infra.store.Store.save_observation` -- the same surface
    :meth:`mayhem.infra.schedule_store.ScheduleStore.record_tick` uses. See the
    module docstring: neither call site is inside the secret boundary, and that
    is a reported gap rather than an assumed guarantee.
    """
    store.save_observation(
        ARTIFACT_OBSERVATION_KIND,
        source=artifact.session_id,
        data=artifact.to_payload(),
    )
    return artifact


def artifacts_for_session(store: Store, session_id: str) -> tuple[GameDayArtifact, ...]:
    """Every artifact filed for ``session_id``, in the order it was recorded.

    Reads the ``observations`` table directly rather than going through a
    repository, because there is no repository for it: the row is an observation,
    which is the surface :func:`record_artifact` writes.

    Two rows are **skipped** rather than raised on. One whose ``data_json`` does
    not parse as an artifact, and one whose stored digest disagrees with the
    fields beside it -- a hand-edited row. One unreadable row must not make an
    entire after-action report unreadable, and the report's own gaps are the place
    that kind of loss belongs. The digest is the reason the second case is
    detectable at all: it is not a signature, and anybody with database access can
    recompute one, but a row whose *fields* were changed without recomputing it is
    caught here rather than believed.
    """
    rows = store.query(
        "SELECT data_json, timestamp FROM observations WHERE kind = ? AND source = ? ORDER BY id",
        (ARTIFACT_OBSERVATION_KIND, session_id),
    )
    found: list[GameDayArtifact] = []
    for row in rows:
        try:
            payload = json.loads(str(dict(row)["data_json"]))
            # The stored digest is *checked*, not trusted: recompute it from the
            # fields and skip the row if it disagrees. That is the whole value of
            # writing it -- a row edited through SQL keeps its stale digest and is
            # therefore visible as unverified here rather than being believed.
            stated = str(payload.pop("digest", ""))
            artifact = GameDayArtifact.model_validate(payload)
        except (ValueError, InvariantViolationError):
            continue
        if stated and stated != artifact.digest:
            continue
        found.append(artifact)
    return tuple(found)


def after_action_report(
    *,
    session_id: str,
    artifacts: tuple[GameDayArtifact, ...],
    steps: tuple[GameDayStepRecord, ...] = (),
    dispatches: tuple[ScheduleRunRecord, ...] = (),
    now: datetime | None = None,
) -> AfterActionReport:
    """Assemble one session's after-action report, naming every gap it finds.

    Pure: every input is an argument and ``now`` is the only clock, so the same
    session and the same records always produce the same report.

    The gap rules, in the order they are checked:

    1. a step that reached ``released`` or ``dispatched`` with no
       :attr:`ArtifactKind.DECISION` naming its run --
       :attr:`ArtifactGap.RELEASED_WITHOUT_DECISION`;
    2. a dispatch settled ``failed`` -- :attr:`ArtifactGap.FAILED_DISPATCH`;
    3. a dispatch never settled -- :attr:`ArtifactGap.UNKNOWN_OUTCOME_DISPATCH`,
       which is reported rather than retried for the same reason the scheduler
       does not retry it;
    4. no findings at all -- :attr:`ArtifactGap.NO_FINDINGS`;
    5. no artifacts at all -- :attr:`ArtifactGap.NO_ARTIFACTS`.

    Rule 5 subsumes rule 4, and both are kept: "nothing was recorded" and "things
    were recorded but nothing was claimed wrong" are different statements about
    different sessions, and collapsing them would lose the first.
    """
    decided_runs = {
        artifact.run_id
        for artifact in artifacts
        if artifact.kind is ArtifactKind.DECISION and artifact.run_id
    }
    gaps: list[ArtifactGap] = []
    released = [step for step in steps if step.released]
    if any(not decided_runs for step in released) and not decided_runs:
        gaps.append(ArtifactGap.RELEASED_WITHOUT_DECISION)
    if any(record.code == "schedule.execution_failed" for record in dispatches):
        gaps.append(ArtifactGap.FAILED_DISPATCH)
    if any(not record.settled for record in dispatches):
        gaps.append(ArtifactGap.UNKNOWN_OUTCOME_DISPATCH)
    if not any(artifact.kind is ArtifactKind.FINDING for artifact in artifacts):
        gaps.append(ArtifactGap.NO_FINDINGS)
    if not artifacts:
        gaps.insert(0, ArtifactGap.NO_ARTIFACTS)

    notes: list[str] = []
    if now is not None:
        if now.tzinfo is None or now.utcoffset() is None:
            msg = "after-action report requires an aware `now`; a naive clock is not a timestamp"
            raise InvariantViolationError("game_day.artifact_at_blank", msg)
        stamp = now.astimezone(UTC).isoformat()
    else:
        stamp = ""
    if released and decided_runs:
        notes.append(f"{len(released)} released step(s), {len(decided_runs)} decision artifact(s)")
    return AfterActionReport(
        session_id=session_id,
        artifacts=artifacts,
        steps=steps,
        dispatches=dispatches,
        gaps=tuple(gaps),
        generated_at=stamp,
        notes=tuple(notes),
    )


def default_artifact_id(session_id: str, kind: ArtifactKind, actor: str, *, at: str) -> str:
    """A deterministic artifact id derived from what the artifact *is*.

    Derived rather than minted so that re-recording the same decision produces
    the same id: a facilitator who repeats themselves gets one record with two
    observations rather than two records that disagree. The timestamp is part of
    the input, so two genuinely separate decisions by the same actor in the same
    session still get distinct ids.
    """
    body = digest(
        {
            "session_id": session_id,
            "kind": kind.value,
            "actor": actor.strip(),
            "at": at,
        }
    )
    return f"gd-{kind.value}-{body[:16]}"
