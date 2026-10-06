"""Synthetic customer journeys: business metrics as resilience criteria (plan 22).

A journey here is an **authored program**, not a run. It is the thing a probe
executes, the thing a plan pins, and the thing a finding cites — so it carries
an explicit ``version`` and a content ``digest``, and two runs of the same
program are comparable while an edited program is a different program. That
distinction is the whole reason this lives in the domain rather than in a YAML
file nobody versions: a comparison across a re-pinned journey is not a
regression, it is a different measurement, and only an explicit version can
tell those two apart.

The capability this module exists to express is plan 22's gap 51: **business
metrics are resilience criteria**. A synthetic journey that walks signup →
login → cart → checkout → payment → order is only useful if each step says what
"working" meant — success, latency, error rate, or business correctness — and
says it in terms somebody who owns the KPI can be held to. So the assertions
are first-class, named, and citable: every assertion has a ``criterion_id``
that is unique across the program, a metric in its own unit, and exactly one
basis to be judged against.

Three invariants are enforced at construction, not checked later:

* **A step that asserts nothing cannot be written.** A step with an empty
  assertion list is a step whose result is a green tick no matter what
  happened. The journey would then read "checkout journey passed" having
  checked only that a socket closed. The refusal names the step.
* **An assertion is judged against one basis, never two.** ``threshold`` (a
  band someone typed) and ``baseline`` + ``tolerance_pct`` (a band relative to
  what the tool itself measured) answer different questions. Setting both would
  have to pick a winner, and whichever lost would be the assertion the author
  believed they had written. Setting neither accepts every measurement. Both
  are refused, and so is a non-finite bound: ``nan`` captured nothing, and a
  ``nan`` bound silently passes everything.
* **A business-correctness assertion must say the business thing.** A
  ``business_correctness`` assertion without a description is a category label
  with no claim in it; the description is the sentence a payments owner can
  read and disagree with.

**Authoring a journey proves nothing.** :func:`authored_cells` projects a
program onto the existing :class:`~mayhem.domain.coverage.CoverageCell` key
and returns every cell in :data:`~mayhem.domain.coverage.CellState.UNKNOWN`.
The program version and step name are carried in the cell's parameter band, so
re-pinning a journey lands on a *different* cell and the old cell keeps its own
evidence instead of being overwritten by an unrelated one. Catalog presence is
not coverage: nothing here can move a cell out of ``unknown``, and only
executed evidence (plan 22 phase 2 owns the accounting) ever will.
"""

from __future__ import annotations

from enum import StrEnum
from math import isfinite
from typing import Annotated, Final

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from mayhem.domain.capabilities import Identifier
from mayhem.domain.coverage import CellState, CoverageCell, ResilienceCell
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import digest as canonical_digest

__all__ = [
    "BUSINESS_CORRECTNESS",
    "CANONICAL_CHECKOUT_LADDER",
    "ERROR_RATE",
    "JOURNEY_SCHEMA_VERSION",
    "LATENCY",
    "PLAN_BUSINESS_METRICS",
    "SUCCESS",
    "AssertionBasis",
    "AssertionComparator",
    "AssertionKind",
    "JourneyDigest",
    "JourneyPin",
    "JourneyProgram",
    "JourneyStage",
    "JourneyStep",
    "StepAssertion",
    "authored_cells",
]

JOURNEY_SCHEMA_VERSION: Final[str] = "1.0"

#: SHA-256 hex. Same shape as ``mayhem.domain.fabric.PlanDigest``; written out
#: here because a journey citation and a plan digest are different claims and
#: neither should be inferred from the other's field.
JourneyDigest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class JourneyStage(StrEnum):
    """The six business steps of the synthetic customer journey.

    A stage is the *business* step, not the request: ``cart`` means "the
    shopper's basket is readable and writable", whether that took one HTTP call
    or five. The vocabulary is closed deliberately. Widening it would make every
    stored citation ambiguous about what it measured, and a program that grows a
    ``refund`` stage is a new program with its own version, not a wider
    vocabulary the old citations quietly inherit.
    """

    SIGNUP = "signup"
    LOGIN = "login"
    CART = "cart"
    CHECKOUT = "checkout"
    PAYMENT = "payment"
    ORDER = "order"


CANONICAL_CHECKOUT_LADDER: Final[tuple[JourneyStage, ...]] = (
    JourneyStage.SIGNUP,
    JourneyStage.LOGIN,
    JourneyStage.CART,
    JourneyStage.CHECKOUT,
    JourneyStage.PAYMENT,
    JourneyStage.ORDER,
)
"""The plan 22 reference journey: signup → login → cart → checkout → payment → order.

A program need not follow it (a sign-up-only journey is a legitimate program);
:attr:`JourneyProgram.covers_checkout_ladder` says whether one does.
"""


class AssertionKind(StrEnum):
    """What a step asserts about itself.

    ``SUCCESS`` — the step completed at all. Necessary, never sufficient on its
    own: a checkout that returns 200 after eleven seconds passed ``success``.

    ``LATENCY`` — how long the step took, in its own unit.

    ``ERROR_RATE`` — the share of attempts that failed, as a fraction.

    ``BUSINESS_CORRECTNESS`` — the KPI moved the way the business expects. This
    is the one that makes a journey worth running: it is the only kind whose
    failure means money, and it is the kind every other tool in this repo
    cannot express. It must carry a description, because the description *is*
    the claim.
    """

    SUCCESS = "success"
    LATENCY = "latency"
    ERROR_RATE = "error_rate"
    BUSINESS_CORRECTNESS = "business_correctness"


#: The three kinds that stand in for the enum's own spelling, re-exported so a
#: caller writing a table of them does not have to reach for the enum twice.
SUCCESS: Final[str] = AssertionKind.SUCCESS.value
LATENCY: Final[str] = AssertionKind.LATENCY.value
ERROR_RATE: Final[str] = AssertionKind.ERROR_RATE.value
BUSINESS_CORRECTNESS: Final[str] = AssertionKind.BUSINESS_CORRECTNESS.value


PLAN_BUSINESS_METRICS: Final[frozenset[str]] = frozenset(
    {
        "checkout_success_rate",
        "orders_per_minute",
        "payment_success_rate",
        "queue_lag",
    }
)
"""The business KPIs plan 22 names as first-class SLO metrics.

Listing them is not a whitelist: a program may assert any metric it can measure
and justify. The set exists so a report can say which of the plan's four
canonical KPIs a journey actually exercises, and so the obvious typo
(``order_per_minute``) has something to be compared against.
"""


class AssertionComparator(StrEnum):
    """How an observed value is compared against a bound."""

    LT = "lt"
    LTE = "lte"
    GT = "gt"
    GTE = "gte"
    EQ = "eq"


class AssertionBasis(StrEnum):
    """Which of the two judgement bases an assertion is written against.

    ``THRESHOLD`` — the authored absolute bound. ``BASELINE_TOLERANCE`` — a
    captured baseline plus a percentage allowance. Mutually exclusive by
    construction; see :class:`StepAssertion`.
    """

    THRESHOLD = "threshold"
    BASELINE_TOLERANCE = "baseline_tolerance"


class StepAssertion(BaseModel):
    """One first-class, citable criterion attached to one journey step.

    The assertion is the unit a finding quotes, a report tabulates, and a
    reviewer disputes. It names itself (``criterion_id``, unique across the
    whole program), says what it measures (``metric`` in ``unit``), how it is
    compared (``comparator``), and against which single basis.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    criterion_id: Identifier
    kind: AssertionKind
    metric: Identifier
    comparator: AssertionComparator = AssertionComparator.LTE
    unit: str = Field(default="ms", min_length=1, max_length=32)
    threshold: float | None = None
    baseline: float | None = None
    tolerance_pct: float | None = Field(default=None, ge=0.0)
    description: str = ""

    # -- the single-basis invariant ----------------------------------------

    @model_validator(mode="after")
    def _one_basis_only(self) -> StepAssertion:
        """``threshold`` and ``baseline``+``tolerance_pct`` are exclusive.

        A merged bound would have to pick a winner, and the loser would be the
        assertion the author believed they had written — the same failure
        ``mayhem.domain.steady_state`` refuses for a signal's ``expect`` /
        ``tolerance`` pair. Declaring neither is refused too: an assertion
        with no bound accepts every measurement, which is a no-op wearing an
        assertion's name.
        """
        has_threshold = self.threshold is not None
        has_baseline = self.baseline is not None and self.tolerance_pct is not None
        if has_threshold and (self.baseline is not None or self.tolerance_pct is not None):
            raise InvariantViolationError(
                "journey.assertion_mixes_bases",
                f"assertion {self.criterion_id!r} sets both a threshold and a "
                "baseline/tolerance: judge an assertion against an authored "
                "threshold or against a captured baseline, never both — one of "
                "them would be silently ignored",
            )
        if self.baseline is not None and self.tolerance_pct is None:
            raise InvariantViolationError(
                "journey.baseline_without_tolerance",
                f"assertion {self.criterion_id!r} sets a baseline without a "
                "tolerance_pct: a baseline with no allowance is not a bound",
            )
        if self.tolerance_pct is not None and self.baseline is None:
            raise InvariantViolationError(
                "journey.tolerance_without_baseline",
                f"assertion {self.criterion_id!r} sets a tolerance_pct without a "
                "baseline: a percentage of nothing is not a bound",
            )
        if not has_threshold and not has_baseline:
            raise InvariantViolationError(
                "journey.assertion_declares_no_bound",
                f"assertion {self.criterion_id!r} declares neither a threshold nor a "
                "baseline/tolerance: it would accept every measurement, which is a "
                "no-op wearing an assertion's name",
            )
        return self

    @field_validator("threshold", "baseline", "tolerance_pct")
    @classmethod
    def _finite_bound(cls, value: float | None) -> float | None:
        """Refuse ``nan``/``inf`` bounds instead of letting them judge.

        ``nan`` compares false against every operator, so a ``nan`` threshold
        fails everything and an ``inf`` one passes everything; both are
        arithmetic accidents dressed as bounds, and neither survives a trip
        through a hash-chained evidence bundle.
        """
        if value is not None and not isfinite(value):
            raise InvariantViolationError(
                "journey.assertion_bound_not_finite",
                "an assertion bound must be a finite measurement; nan and inf are "
                "arithmetic accidents, not bounds",
            )
        return value

    @model_validator(mode="after")
    def _business_assertion_states_the_claim(self) -> StepAssertion:
        """``business_correctness`` must say the business thing in words.

        The description is the claim a payments owner can disagree with. A
        business-correctness assertion without one is a category label that
        reports a failure nobody can act on.
        """
        if self.kind is AssertionKind.BUSINESS_CORRECTNESS and not self.description.strip():
            raise InvariantViolationError(
                "journey.business_assertion_undescribed",
                f"assertion {self.criterion_id!r} is business_correctness with no "
                "description: the business claim is the assertion, and an empty one "
                "reports a failure nobody can act on",
            )
        return self

    # -- derived facts ------------------------------------------------------

    @property
    def basis(self) -> AssertionBasis:
        """Which single basis this assertion is judged against."""
        return (
            AssertionBasis.THRESHOLD
            if self.threshold is not None
            else AssertionBasis.BASELINE_TOLERANCE
        )

    @property
    def cites_plan_metric(self) -> bool:
        """True when ``metric`` is one of plan 22's four canonical business KPIs."""
        return self.metric in PLAN_BUSINESS_METRICS

    def to_dict(self) -> dict[str, object]:
        """A *report* payload: the fields plus the derived facts a table needs.

        Not re-loadable — :meth:`model_dump` is the serialization that round
        trips. The extra keys are here so a report or evidence bundle can render
        an assertion's basis and KPI membership without re-deriving them.
        """
        payload = self.model_dump(mode="json")
        payload["basis"] = self.basis.value
        payload["cites_plan_metric"] = self.cites_plan_metric
        return payload


class JourneyStep(BaseModel):
    """One business step of a journey, with the criteria that judge it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: Identifier
    stage: JourneyStage
    service: Identifier
    assertions: tuple[StepAssertion, ...]
    probe_class: str = Field(default="synthetic.journey", min_length=1, max_length=64)
    depends_on: tuple[Identifier, ...] = ()
    description: str = ""

    @model_validator(mode="after")
    def _asserts_something(self) -> JourneyStep:
        """A step with no assertions is refused.

        This is the negative control the plan asks for. A step that asserts
        nothing produces a result no matter what the system did, so the
        journey would report "checkout passed" having checked only that a
        socket closed — and a passing journey is exactly the artefact somebody
        later cites as evidence the flow is healthy.
        """
        if not self.assertions:
            raise InvariantViolationError(
                "journey.step_asserts_nothing",
                f"step {self.name!r} declares no assertions: a step that asserts "
                "nothing passes whatever the system does, and a passing journey is "
                "what a reviewer cites as evidence the flow is healthy",
            )
        return self

    @model_validator(mode="after")
    def _criterion_ids_unique(self) -> JourneyStep:
        seen: set[str] = set()
        for assertion in self.assertions:
            if assertion.criterion_id in seen:
                raise InvariantViolationError(
                    "journey.duplicate_criterion_id",
                    f"step {self.name!r} declares criterion {assertion.criterion_id!r} "
                    "twice: a criterion id addresses exactly one assertion, and a "
                    "duplicate makes it unciteable",
                )
            seen.add(assertion.criterion_id)
        return self

    @field_validator("depends_on")
    @classmethod
    def _no_self_dependency(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise InvariantViolationError(
                "journey.duplicate_dependency",
                f"depends_on lists a step more than once: {value!r}",
            )
        return value

    def to_dict(self) -> dict[str, object]:
        """A *report* payload with the assertions expanded — see :meth:`StepAssertion.to_dict`."""
        payload = self.model_dump(mode="json")
        payload["stage"] = self.stage.value
        payload["assertions"] = [assertion.to_dict() for assertion in self.assertions]
        return payload


class JourneyPin(BaseModel):
    """The citable identity of a journey program: name, version, content digest.

    A comparison or a finding that cites a journey cites this, so "which
    program, at which version" is never a question a reader has to guess at.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=64)
    digest: JourneyDigest

    @property
    def label(self) -> str:
        """``name@version#digest[:12]`` — short enough for a report line."""
        return f"{self.name}@{self.version}#{self.digest[:12]}"

    @property
    def identity(self) -> str:
        """``name@version#digest`` — the whole pin, every digest byte.

        :attr:`label` is for a report line, where twelve hex characters are
        enough to recognise a program. A *pin* is not a report line: a change
        link that records which journey program version its run carried stores
        this string, so two programs sharing a name and a version but differing
        in bytes can never read as the same pin.
        """
        return f"{self.name}@{self.version}#{self.digest}"

    def to_dict(self) -> dict[str, object]:
        payload = self.model_dump(mode="json")
        payload["label"] = self.label
        return payload


class JourneyProgram(BaseModel):
    """A versioned multi-step synthetic customer journey.

    Frozen, and pinned twice over: an author-managed ``version`` that says
    *which revision of the program this is*, and a content ``digest`` that says
    *whether the bytes are the same*. The two are not redundant — the version
    is what a human bumped, the digest is what proves the bump happened and
    that nobody edited a program without bumping it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = JOURNEY_SCHEMA_VERSION
    name: Identifier
    version: str = Field(min_length=1, max_length=64)
    steps: tuple[JourneyStep, ...]
    title: str = ""
    description: str = ""

    # -- schema -------------------------------------------------------------

    @field_validator("schema_version")
    @classmethod
    def _known_schema(cls, value: str) -> str:
        if value != JOURNEY_SCHEMA_VERSION:
            raise InvariantViolationError(
                "journey.unsupported_schema",
                f"unsupported journey schema {value!r}: this build reads "
                f"{JOURNEY_SCHEMA_VERSION!r} only",
            )
        return value

    @model_validator(mode="after")
    def _has_steps(self) -> JourneyProgram:
        if not self.steps:
            raise InvariantViolationError(
                "journey.program_has_no_steps",
                f"journey {self.name!r} declares no steps: an empty program would "
                "report success having walked nowhere",
            )
        return self

    @model_validator(mode="after")
    def _step_names_unique(self) -> JourneyProgram:
        seen: set[str] = set()
        for step in self.steps:
            if step.name in seen:
                raise InvariantViolationError(
                    "journey.duplicate_step",
                    f"journey {self.name!r} declares step {step.name!r} twice: a step "
                    "name addresses exactly one step",
                )
            seen.add(step.name)
        return self

    @model_validator(mode="after")
    def _criterion_ids_unique(self) -> JourneyProgram:
        """Criterion ids are unique across the whole program, not just per step.

        The id is the citation handle a finding and a report both quote, so it
        has to mean one thing in the program. Per-step uniqueness would permit
        ``latency`` to name two different assertions, and then a citation could
        not be resolved.
        """
        seen: dict[str, str] = {}
        for step in self.steps:
            for assertion in step.assertions:
                if assertion.criterion_id in seen:
                    raise InvariantViolationError(
                        "journey.duplicate_criterion_id",
                        f"criterion {assertion.criterion_id!r} is declared on both "
                        f"step {seen[assertion.criterion_id]!r} and step {step.name!r}: "
                        "criterion ids are the program's citation handles and must "
                        "resolve to one assertion",
                    )
                seen[assertion.criterion_id] = step.name
        return self

    @model_validator(mode="after")
    def _dependencies_are_earlier_steps(self) -> JourneyProgram:
        """A step may only depend on a step declared before it.

        A forward or dangling ``depends_on`` is a typo, and a typo that resolves
        to a silent no-op is the worst failure a journey program can have: the
        step runs with no input from the step it claimed to need and the report
        shows a clean run.
        """
        declared: set[str] = set()
        for step in self.steps:
            for dependency in step.depends_on:
                if dependency not in declared:
                    where = (
                        "declared later"
                        if any(other.name == dependency for other in self.steps)
                        else "not declared anywhere in this program"
                    )
                    raise InvariantViolationError(
                        "journey.unresolved_dependency",
                        f"step {step.name!r} depends on {dependency!r}, which is "
                        f"{where}: a dependency resolves only against a step "
                        "authored before it",
                    )
            declared.add(step.name)
        return self

    # -- identity -----------------------------------------------------------

    def digest(self) -> str:
        """Content digest over the whole program, canonically encoded.

        Uses the system's one canonical hasher so a journey digest means the
        same thing as every other digest in mayhem. The digest is taken over
        the full dump *including* ``version``: a program whose assertions
        changed under the same version is a different program as far as any
        comparison is concerned, and its digest has to say so.
        """
        return canonical_digest(self.model_dump(mode="json"))

    @property
    def pin(self) -> JourneyPin:
        """The citable identity of this program."""
        return JourneyPin(name=self.name, version=self.version, digest=self.digest())

    # -- derived facts ------------------------------------------------------

    @property
    def covers_checkout_ladder(self) -> bool:
        """True when every canonical stage is present, in ladder order.

        Order is part of the claim: a program carrying all six stages out of
        order is not the reference journey, and reporting it as one would make
        ``order`` look like something that happened before ``signup``.
        """
        stages = tuple(step.stage for step in self.steps)
        return stages == CANONICAL_CHECKOUT_LADDER

    @property
    def business_metrics(self) -> tuple[str, ...]:
        """Every business-correctness metric this program asserts, sorted."""
        return tuple(
            sorted(
                {
                    assertion.metric
                    for step in self.steps
                    for assertion in step.assertions
                    if assertion.kind is AssertionKind.BUSINESS_CORRECTNESS
                }
            )
        )

    @property
    def criterion_ids(self) -> tuple[str, ...]:
        """Every criterion the program asserts, in step order — its citation index."""
        return tuple(assertion.criterion_id for step in self.steps for assertion in step.assertions)

    @property
    def cells(self) -> tuple[CoverageCell, ...]:
        """The coverage cells this program *claims* to exercise.

        The cell key is the existing one from :mod:`mayhem.domain.coverage` —
        target, fault kind, execution context, parameter band — with the journey
        dimensions carried in the band and the context rather than by forking the
        store: ``target`` is the service under test, ``fault_kind`` is the probe
        class, ``execution_context`` names the journey, and the band pins
        ``<version>#<step>``.

        The version belongs in the key because a re-pinned journey is a
        *different cell*: the evidence gathered under v1 must stay addressable
        and citable after v2 lands, not be overwritten by an unrelated run's
        evidence wearing the same key.
        """
        return tuple(
            CoverageCell(
                target=step.service,
                fault_kind=step.probe_class,
                execution_context=f"journey:{self.name}",
                parameter_band=f"{self.version}#{step.name}",
            )
            for step in self.steps
        )

    def to_dict(self) -> dict[str, object]:
        """A *report* payload: the program, its pin, and what it claims to cover.

        Carries the citation facts a run record needs — the pin, the digest, the
        ladder claim, the asserted criterion index — so a stored run can say
        which program at which version produced it. :meth:`model_dump` is the
        serialization that round trips back into a program.
        """
        payload = self.model_dump(mode="json")
        payload["steps"] = [step.to_dict() for step in self.steps]
        payload["pin"] = self.pin.to_dict()
        payload["digest"] = self.digest()
        payload["covers_checkout_ladder"] = self.covers_checkout_ladder
        payload["criterion_ids"] = list(self.criterion_ids)
        payload["business_metrics"] = list(self.business_metrics)
        return payload


def authored_cells(program: JourneyProgram) -> tuple[ResilienceCell, ...]:
    """Project a journey program onto coverage cells, all of them ``unknown``.

    This is the honest reading of "we have written a checkout journey": the
    service x fault x context x band cells exist and are *untested*. Catalog
    presence
    is not coverage, so every cell starts in :data:`CellState.UNKNOWN` and
    nothing in this module can move one. Only executed evidence does that, and
    the accounting for it is plan 22 phase 2's job.
    """
    return tuple(
        ResilienceCell.from_coverage_cell(cell, state=CellState.UNKNOWN) for cell in program.cells
    )
