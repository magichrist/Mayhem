"""Probe observations as evidence: citable, redacted, and sealed with the run
(docs/v1.1.0/11_OBSERVABILITY_PROBES_STOP_CONDITIONS.md, Phase 4).

:mod:`mayhem.controller.probe_service` produces readings and
:mod:`mayhem.controller.probe_collector` sweeps them through the lifecycle. None
of that is yet evidence. This module is the three things the plan's Phase 4 asks
for, and it is all pure — no IO, no clock, no upward import:

1. **Readings become envelope rows with their provenance, and redaction applied
   before the row exists.** :func:`envelope_observations` is the only place a
   reading turns into a document. It emits **one row per attempt, available or
   not**, because the alternative — emitting only the available ones — renders a
   probe that answered nothing as a probe that was never asked, and those are
   different facts. A ``None`` value serialises as ``null``; it is never ``0.0``
   and never ``inf``/``nan``, because this payload ends up in a hash-chained
   artifact a reader must be able to interpret.
2. **A verdict's citations must be findable in evidence.**
   :func:`assert_citations_verified` is the plan's Phase 4 acceptance criterion
   as a function: a firing whose cited samples cannot be matched to recorded
   evidence **fails verification**, naming every citation it could not find. The
   match is by :func:`fingerprint_for`, a digest over the semantic content of a
   reading — not by object identity, because evidence crosses a process boundary
   and a replay must re-derive it.
3. **Condition definitions and probe versions are sealed with the run.**
   :class:`SealedConditionSet` holds the conditions *and* the probe pins, hashed
   together, and :meth:`SealedConditionSet.assert_unchanged` refuses a set whose
   conditions or pins have been edited after sealing. A stop whose definition
   moved between firing and review is a stop nobody can reproduce.

The synthetic-transaction rule
------------------------------

A synthetic probe that checked "every step returned HTTP 200" would be a probe
that certifies the absence of transport errors and calls it business
correctness. :func:`synthetic_outcome` grades a synthetic transaction against
**business assertions** — a field that must hold, an order that must be
respected, an error marker that must be absent — and treats the status code as one
assertion among several rather than as the verdict.

And the third outcome is the point. ``UNDETERMINED`` exists because a step whose
observation never arrived is not a passing step; :func:`synthetic_outcome` returns
it, and :attr:`SyntheticVerdict.supports_verdict` is ``False``. A transaction
where mayhem watched three of four steps is **not** a correct transaction, and
this module will not let it be reported as one.

Why the reading arrives as a :class:`ReadingView`
------------------------------------------------

The domain cannot import :class:`~mayhem.controller.probe_service.ProbeReading` —
the controller layer is above it, and ``mayhem.domain`` importing upward is the
thing the layering contract forbids. So this module declares :class:`ReadingView`,
the read-only surface it needs, and
:func:`mayhem.controller.probe_service.reading_view` is what projects a live
reading onto it. The alternative — ``getattr`` chains against ``object`` — would
have made a field rename in the controller a runtime ``AttributeError`` in
evidence, which is the worst possible time to find out.

What is deliberately not claimed
--------------------------------

Nothing here reads a live cluster, a vendor API or a real transaction. Every
function takes recorded data. In particular **no signature verification is claimed
anywhere in this module or its callers**: a probe reading is evidence that mayhem
asked and got a number back, and it is not evidence that the number is
authentic. ``verified-live`` is 0 and stays 0.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from math import isfinite
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import digest
from mayhem.domain.probes import ProbePin
from mayhem.domain.redaction import redact, redact_text
from mayhem.domain.stop_conditions import Condition, ConditionResult, Sample

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from mayhem.domain.stop_conditions import Firing

__all__ = [
    "BUSINESS_ASSERTIONS",
    "BusinessAssertion",
    "CitationVerification",
    "Fingerprint",
    "ProbeEvidenceRecord",
    "ReadingView",
    "SealedConditionSet",
    "SyntheticOutcome",
    "SyntheticStepResult",
    "SyntheticVerdict",
    "assert_citations_verified",
    "envelope_observations",
    "fingerprint_for",
    "synthetic_outcome",
    "synthetic_verdict",
    "verify_citations",
]


#: A 64-character lowercase hex digest, or nothing. Same shape and same reason as
#: :data:`mayhem.domain.probes.ProbeFingerprint`: a fingerprint column that could
#: hold prose is not a fingerprint column.
Fingerprint = str


@dataclass(frozen=True, slots=True)
class ReadingView:
    """The read-only surface of one collection attempt, as the domain needs it.

    Produced by :func:`mayhem.controller.probe_service.reading_view`. Every field
    is a plain string or number, deliberately: this is the boundary where the
    controller's enum-flavoured reading becomes the JSON-safe document that ends
    up in an envelope, and doing the conversion here means the spellings of
    ``availability`` and ``stage`` are stated once.

    ``observation`` is flattened into ``value``/``unit``/``provenance`` rather
    than carried, because an *unavailable* attempt has no observation and the row
    must still exist. The three fields are empty strings when there was none,
    which is what distinguishes "no measurement" from "a measurement of the empty
    string".
    """

    probe_id: str
    family: str
    stage: str
    availability: str
    at_epoch_s: float
    value: float | None
    unit: str
    provenance: str
    evidence_ref: str
    note: str = ""

    def __post_init__(self) -> None:
        if not self.probe_id.strip():
            raise InvariantViolationError(
                "probes.reading_field_blank",
                "a reading view carries a blank probe id: evidence that cannot be "
                "named cannot be cited, and a citation that cannot be named cannot be "
                "verified",
            )
        if not isfinite(self.at_epoch_s):
            raise InvariantViolationError(
                "probes.reading_time_not_finite",
                f"reading view for {self.probe_id!r} carries a non-finite recording "
                f"time ({self.at_epoch_s!r}): a row that cannot be placed on a timeline "
                "cannot have its citation matched against one",
            )
        if self.value is not None and not isfinite(self.value):
            raise InvariantViolationError(
                "probes.reading_value_not_finite",
                f"reading view for {self.probe_id!r} carries {self.value!r}: evidence "
                "rows are hash-chained and a reader must be able to interpret every "
                "number in one, so a non-finite measurement is refused rather than "
                "serialised",
            )


@dataclass(frozen=True, slots=True)
class ProbeEvidenceRecord:
    """One collection attempt as evidence: what was asked, and what came back.

    ``availability`` is carried as its own field rather than inferred from
    ``value``. The inference is tempting and wrong: an available reading of
    ``0.0`` and an unavailable reading both look like "no number" to a naive
    reader, and collapsing them is how "mayhem did not look" becomes "mayhem
    looked and found nothing". Both fields are present, always.
    """

    probe_id: str
    family: str
    stage: str
    availability: str
    at_epoch_s: float
    value: float | None
    unit: str
    provenance: str
    evidence_ref: str
    fingerprint: Fingerprint = ""
    note: str = ""

    @property
    def available(self) -> bool:
        return self.availability == "available"

    @classmethod
    def of(cls, view: ReadingView) -> ProbeEvidenceRecord:
        """Build a record from a :class:`ReadingView`, redacting the note first.

        ``note`` is redacted **before** it is stored, so a refusal message that
        happened to quote a secret cannot reach an envelope. A value planted under
        an ungraded field name is caught on the way out by
        :func:`~mayhem.infra.secret_resolver.require_persistable_document`; this is
        the structural first half, and it needs no run state, so it holds on a run
        that resolved nothing.
        """
        clean_note, _hits = redact_text(view.note)
        return cls(
            probe_id=view.probe_id,
            family=view.family,
            stage=view.stage,
            availability=view.availability,
            at_epoch_s=view.at_epoch_s,
            value=view.value,
            unit=view.unit,
            provenance=view.provenance,
            evidence_ref=view.evidence_ref,
            fingerprint=fingerprint_for_record(view),
            note=clean_note,
        )

    def to_dict(self) -> dict[str, object]:
        """The envelope row. JSON-safe by construction.

        ``value`` is ``None`` for an unavailable reading and serialises as
        ``null``. It is never rendered as ``0.0`` and never as ``inf``/``nan``.
        """
        return {
            "probe_id": self.probe_id,
            "family": self.family,
            "stage": self.stage,
            "availability": self.availability,
            "at_epoch_s": self.at_epoch_s,
            "value": self.value,
            "unit": self.unit,
            "provenance": self.provenance,
            "evidence_ref": self.evidence_ref,
            "fingerprint": self.fingerprint,
            "note": self.note,
        }


def _fingerprint_payload(
    *,
    probe_id: str,
    availability: str,
    at_epoch_s: float,
    value: float | None,
    unit: str,
    provenance: str,
    evidence_ref: str,
) -> dict[str, object]:
    """The one payload a fingerprint is computed over.

    **The lifecycle stage and the family are deliberately not in it.** A
    :class:`~mayhem.domain.stop_conditions.Sample` carries its metric, value,
    unit, provenance, source and recording time — not the stage it was taken in,
    because the stage is a property of the sweep, not of the reading. Hashing the
    stage here would make every citation unmatched against evidence recorded by a
    sweep that walked a different stage list, which would look exactly like
    fabricated evidence. The two fields are still *in the row*; they are just not
    part of a reading's identity.
    """
    return {
        "probe_id": probe_id,
        "availability": availability,
        "at_epoch_s": at_epoch_s,
        "value": value,
        "unit": unit,
        "provenance": provenance,
        "evidence_ref": evidence_ref,
    }


def fingerprint_for_record(view: ReadingView) -> Fingerprint:
    """The digest an evidence row is findable under."""
    return digest(
        _fingerprint_payload(
            probe_id=view.probe_id,
            availability=view.availability,
            at_epoch_s=view.at_epoch_s,
            value=view.value,
            unit=view.unit,
            provenance=view.provenance,
            evidence_ref=view.evidence_ref,
        )
    )


def fingerprint_for(sample: Sample) -> Fingerprint:
    """The digest a cited :class:`Sample` must be findable under.

    Computed from the *sample* side, so a replay holding only the recorded stream
    can re-derive the fingerprint without holding the reading object. It uses the
    same :func:`_fingerprint_payload` the record side does — one payload, two
    directions, so the two cannot drift into never matching.
    """
    return digest(
        _fingerprint_payload(
            probe_id=sample.metric,
            availability="available",
            at_epoch_s=sample.at_epoch_s,
            value=sample.value,
            unit=sample.observation.unit,
            provenance=sample.observation.provenance,
            evidence_ref=sample.observation.source,
        )
    )


def envelope_observations(readings: Iterable[ReadingView]) -> tuple[dict[str, object], ...]:
    """The envelope rows these readings become. Redaction applied, gaps kept.

    Every attempt produces a row. An ``unavailable`` attempt produces a row with
    ``availability: "unavailable"``, ``value: null`` and its reason — because the
    difference between "the run watched this and it was fine" and "the run could
    not watch this" is exactly what an evidence reviewer needs, and it is erased by
    a filter that keeps only the rows with numbers in them.

    :func:`~mayhem.domain.redaction.redact` is applied to each finished row, so a
    secret planted under *any* field name — not only one graded ``secret`` — is
    scrubbed on the way in. The write boundary applies its own byte-level guard
    afterwards; this is the first of the two halves and the one that needs no run
    state.
    """
    rows: list[dict[str, object]] = []
    for view in readings:
        record = ProbeEvidenceRecord.of(view)
        cleaned = redact(record.to_dict()).value
        rows.append(cleaned)
    return tuple(rows)


# =============================================================================
# Citations: a verdict must be findable in the evidence
# =============================================================================


@dataclass(frozen=True, slots=True)
class CitationVerification:
    """The result of checking a verdict's citations against recorded evidence."""

    condition_name: str
    verified: tuple[Fingerprint, ...]
    missing: tuple[str, ...]
    evidence_fingerprints: tuple[Fingerprint, ...]

    @property
    def ok(self) -> bool:
        return not self.missing

    def describe(self) -> str:
        if self.ok:
            return (
                f"condition {self.condition_name!r} cites {len(self.verified)} sample(s), "
                "all found in the recorded evidence"
            )
        return (
            f"condition {self.condition_name!r} cites {len(self.missing)} sample(s) that "
            f"are not in the recorded evidence ({', '.join(self.missing)}): a stop whose "
            "cited observations cannot be found cannot be reviewed, replayed or defended"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "condition": self.condition_name,
            "ok": self.ok,
            "verified": list(self.verified),
            "missing": list(self.missing),
            "evidence_fingerprints": list(self.evidence_fingerprints),
            "summary": self.describe(),
        }


def verify_citations(
    result: ConditionResult | Firing,
    records: Sequence[ProbeEvidenceRecord],
    *,
    require_all_available: bool = True,
) -> CitationVerification:
    """Check every cited sample against ``records``.

    Returns a :class:`CitationVerification` rather than raising, so a caller
    verifying a whole report can collect every failure instead of stopping at the
    first. :func:`assert_citations_verified` is the raising form.

    ``require_all_available`` is on by default and is the "no probe data may
    support a passing verdict" rule stated at this layer: a citation that matches
    an **unavailable** record is not a match. An unavailable record has no value
    and no metric-time pair, so matching one would mean matching on emptiness —
    which every sample would match, and which would make this function a
    tautology.
    """
    samples = tuple(result.samples)
    condition_name = result.condition_name
    matchable = {
        record.fingerprint: record
        for record in records
        if record.fingerprint and (record.available or not require_all_available)
    }
    verified: list[Fingerprint] = []
    missing: list[str] = []
    for sample in samples:
        fingerprint = fingerprint_for(sample)
        if fingerprint in matchable:
            verified.append(fingerprint)
        else:
            missing.append(_citation_label(sample))
    return CitationVerification(
        condition_name=condition_name,
        verified=tuple(verified),
        missing=tuple(missing),
        evidence_fingerprints=tuple(
            sorted({record.fingerprint for record in records if record.fingerprint})
        ),
    )


def assert_citations_verified(
    result: ConditionResult | Firing,
    records: Sequence[ProbeEvidenceRecord],
    *,
    require_all_available: bool = True,
) -> CitationVerification:
    """:func:`verify_citations`, refusing when a citation is not in the evidence.

    Raises:
        InvariantViolationError: With ``probes.verdict_cites_unrecorded_observation``
            and every unmatched citation named. This is the plan's Phase 4
            acceptance criterion: *a verdict whose cited observations cannot be
            found in evidence fails verification*.
    """
    verification = verify_citations(
        result, records, require_all_available=require_all_available
    )
    if not verification.ok:
        raise InvariantViolationError(
            "probes.verdict_cites_unrecorded_observation",
            verification.describe(),
        )
    return verification


def _citation_label(sample: Sample) -> str:
    """How a missing citation is named: enough to find it, not enough to fake it."""
    value = "null" if sample.value is None else repr(sample.value)
    return f"{sample.metric}@{sample.at_epoch_s:g}={value} (source {sample.source!r})"


# =============================================================================
# Sealing: the conditions and the pins, hashed together with the run
# =============================================================================


class SealedConditionSet(BaseModel):
    """The stop conditions a run was judged by, and the probe versions it read.

    Sealed rather than merely recorded, because a condition definition that can
    change after the fact makes every firing unreproducible: the reviewer's
    condition and the run's condition are different objects with the same name.
    :meth:`assert_unchanged` refuses that, and :attr:`sealed_digest` is the value
    an envelope or a run row carries.

    The digest covers **both** the conditions and the pins on purpose. A condition
    tree that is unchanged while the probe definition it reads is edited in place
    is the drift :mod:`mayhem.domain.probes` exists to catch, and it is caught here
    at the boundary that is actually asked: did the thing that read differ from
    the thing that was pinned?
    """

    model_config = ConfigDict(frozen=True)

    run_id: str = Field(min_length=1)
    conditions: tuple[Condition, ...] = ()
    pins: tuple[ProbePin, ...] = ()
    sealed_digest: str = ""

    def seal(self) -> SealedConditionSet:
        """This set with :attr:`sealed_digest` computed. Idempotent."""
        return SealedConditionSet(
            run_id=self.run_id,
            conditions=self.conditions,
            pins=self.pins,
            sealed_digest=self.compute_digest(),
        )

    def compute_digest(self) -> str:
        """The digest over conditions and pins together. Pure, never reads state."""
        return digest(
            {
                "run_id": self.run_id,
                "conditions": [
                    condition.model_dump(mode="json") for condition in self.conditions
                ],
                "pins": [pin.model_dump(mode="json") for pin in self.pins],
            }
        )

    def assert_unchanged(self) -> None:
        """Refuse a sealed set whose content has moved since it was sealed.

        Raises:
            InvariantViolationError: With ``probes.sealed_conditions_unsealed`` when
                no digest was recorded, or ``probes.sealed_conditions_drifted`` when
                the recomputed one differs. Both digests are named in the message so a
                reader can see *that* they differ rather than being told they do.
        """
        if not self.sealed_digest:
            raise InvariantViolationError(
                "probes.sealed_conditions_unsealed",
                f"the condition set for run {self.run_id!r} carries no sealed digest: an "
                "unsealed set cannot be checked for drift, so it is refused rather than "
                "assumed intact",
            )
        current = self.compute_digest()
        if current != self.sealed_digest:
            raise InvariantViolationError(
                "probes.sealed_conditions_drifted",
                f"the condition set for run {self.run_id!r} was sealed as "
                f"{self.sealed_digest[:12]}… and now computes {current[:12]}…: a "
                "condition definition or a probe pin changed after the run was sealed, "
                "so every firing made under the old definition is no longer "
                "reproducible from this artifact",
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "conditions": [condition.model_dump(mode="json") for condition in self.conditions],
            "pins": [pin.model_dump(mode="json") for pin in self.pins],
            "sealed_digest": self.sealed_digest or self.compute_digest(),
        }


# =============================================================================
# Synthetic transactions: business correctness, not status codes
# =============================================================================


class BusinessAssertion(StrEnum):
    """What a synthetic transaction's step is judged *on*.

    ``STATUS_OK`` is here, and it is here deliberately alongside three others
    rather than alone. A checkout flow can return 200 at every step and still have
    charged a card without creating an order; the transport succeeded and the
    business did not. A synthetic probe whose verdict is "all the calls worked" is
    measuring the network, not the transaction, so a step's verdict is the
    conjunction of its assertions and the status code is one of them.
    """

    STATUS_OK = "status-ok"
    FIELD_EQUALS = "field-equals"
    ORDER_RESPECTED = "order-respected"
    NO_ERROR_SIGNAL = "no-error-signal"


#: Every assertion a step may be judged on. A step naming an assertion outside this
#: set is refused rather than silently ungradable — an assertion nobody can check
#: is the "business correctness" that is really just a comment.
BUSINESS_ASSERTIONS: frozenset[BusinessAssertion] = frozenset(BusinessAssertion)


class SyntheticOutcome(StrEnum):
    """What a synthetic transaction's recorded steps establish.

    Three outcomes, and the third is the one that keeps the module honest:
    ``UNDETERMINED`` means at least one step's answer never arrived. It is not
    ``CORRECT``, and it is not ``INCORRECT`` — a step mayhem did not observe is
    neither a business success nor a business failure.
    """

    CORRECT = "correct"
    INCORRECT = "incorrect"
    UNDETERMINED = "undetermined"


@dataclass(frozen=True, slots=True)
class SyntheticStepResult:
    """One step's outcome, per business assertion.

    ``ok is None`` is the assertion's own answer to *I cannot say* — the step ran
    but the field it needed was not readable, or the step never ran. It is a
    distinct value from ``False`` for the same reason
    :data:`~mayhem.controller.probe_service.ProbeAvailability.UNAVAILABLE` is
    distinct from a failing reading: they are different findings and a report that
    merged them would say "the check passed" about a check that never ran.
    """

    step: str
    assertion: BusinessAssertion
    ok: bool | None
    at_epoch_s: float = 0.0
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.step.strip():
            raise InvariantViolationError(
                "probes.synthetic_step_unnamed",
                "a synthetic step result carries a blank step name: an assertion nobody "
                "can locate is an assertion nobody can check",
            )
        if self.assertion not in BUSINESS_ASSERTIONS:
            raise InvariantViolationError(
                "probes.synthetic_assertion_unknown",
                f"synthetic step {self.step!r} claims assertion {self.assertion!r}, which "
                "is not one of "
                f"{sorted(a.value for a in BUSINESS_ASSERTIONS)}: an assertion outside "
                "the vocabulary cannot be graded, and an ungradable assertion graded as "
                "true is exactly the synthetic probe that certifies nothing",
            )
        if not isfinite(self.at_epoch_s):
            raise InvariantViolationError(
                "probes.synthetic_step_time_not_finite",
                f"synthetic step {self.step!r} carries a non-finite recording time "
                f"({self.at_epoch_s!r}): a step that cannot be placed on a timeline "
                "cannot have its order respected",
            )

    @property
    def determined(self) -> bool:
        return self.ok is not None

    def to_dict(self) -> dict[str, object]:
        return {
            "step": self.step,
            "assertion": self.assertion.value,
            "ok": self.ok,
            "at_epoch_s": self.at_epoch_s,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class SyntheticVerdict:
    """The graded transaction: its outcome, and what it may be used for.

    ``supports_verdict`` is ``False`` for ``UNDETERMINED`` and that is the whole
    reason the third outcome exists. A run may report *what it saw of the
    transaction* and must not report *the transaction was correct*.
    :attr:`asserts_correctness` is the narrower question, and it is ``True`` only
    for ``CORRECT``.
    """

    outcome: SyntheticOutcome
    steps: tuple[SyntheticStepResult, ...]

    @property
    def supports_verdict(self) -> bool:
        """May this transaction's correctness be asserted either way?

        ``False`` only when the transaction is undetermined. An ``INCORRECT``
        transaction *does* support a verdict — the negative one.
        """
        return self.outcome is not SyntheticOutcome.UNDETERMINED

    @property
    def asserts_correctness(self) -> bool:
        """May this be reported as a correct transaction?"""
        return self.outcome is SyntheticOutcome.CORRECT

    @property
    def undetermined_steps(self) -> tuple[str, ...]:
        return tuple(
            f"{step.step}:{step.assertion.value}" for step in self.steps if not step.determined
        )

    @property
    def failed_steps(self) -> tuple[str, ...]:
        return tuple(
            f"{step.step}:{step.assertion.value}" for step in self.steps if step.ok is False
        )

    def describe(self) -> str:
        if self.outcome is SyntheticOutcome.CORRECT:
            return f"correct: {len(self.steps)} business assertion(s) held"
        if self.outcome is SyntheticOutcome.UNDETERMINED:
            names = ", ".join(self.undetermined_steps) or "(an unnamed assertion)"
            return (
                f"undetermined: mayhem could not observe {names}, so this transaction is "
                "neither proven correct nor proven broken — a business check mayhem did "
                "not complete is not a business check that passed"
            )
        names = ", ".join(self.failed_steps) or "(a failed assertion)"
        return f"incorrect: {names} failed, against {len(self.steps)} recorded assertion(s)"

    def to_dict(self) -> dict[str, object]:
        return {
            "outcome": self.outcome.value,
            "supports_verdict": self.supports_verdict,
            "asserts_correctness": self.asserts_correctness,
            "failed_steps": list(self.failed_steps),
            "undetermined_steps": list(self.undetermined_steps),
            "steps": [step.to_dict() for step in self.steps],
            "summary": self.describe(),
        }


def synthetic_outcome(steps: Sequence[SyntheticStepResult]) -> SyntheticVerdict:
    """Grade recorded synthetic-step results for business correctness.

    **A refused emptiness, because a vacuous pass is the failure.** Zero steps is
    not a correct transaction; it is no transaction at all, and
    ``probes.synthetic_transaction_vacuous`` names it — the same rule the preflight
    gate applies to a gate that evaluated no checks.

    The order matters and is the point of the function: an undetermined step yields
    ``UNDETERMINED`` even when other steps failed, because "we also saw a failure"
    is not a reason to assert we saw everything. A caller that wants the failures
    anyway has :attr:`SyntheticVerdict.failed_steps`.
    """
    if not steps:
        raise InvariantViolationError(
            "probes.synthetic_transaction_vacuous",
            "a synthetic transaction was graded with zero recorded steps: nothing was "
            "asked and nothing was observed, and a check that evaluated nothing is "
            "refused rather than passed — the same rule the preflight gate applies to a "
            "vacuous gate",
        )
    frozen = tuple(steps)
    if any(not step.determined for step in frozen):
        return SyntheticVerdict(outcome=SyntheticOutcome.UNDETERMINED, steps=frozen)
    if any(step.ok is False for step in frozen):
        return SyntheticVerdict(outcome=SyntheticOutcome.INCORRECT, steps=frozen)
    return SyntheticVerdict(outcome=SyntheticOutcome.CORRECT, steps=frozen)


def synthetic_verdict(steps: Sequence[SyntheticStepResult]) -> dict[str, object]:
    """:func:`synthetic_outcome`, rendered as an envelope row."""
    return synthetic_outcome(steps).to_dict()
