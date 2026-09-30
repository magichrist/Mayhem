"""Evidence-backed fault-maturity promotion (plan ``02-earn-maturity``).

Why this module exists
----------------------
``MaturityLevel`` defines four rungs, but only the bottom two were ever
reachable. ``catalog._define()`` promoted every non-``catalog_only`` fault
straight to ``VERIFIED_UNIT``, which made the level a *constant applied to
everything*: a badge that looked like a claim and carried no information.

This module makes the level mean something. Two things follow:

1. ``VERIFIED_UNIT`` is no longer trusted because the catalog says so. It is
   *derived* from facts that can be recomputed at read time and can fail —
   catalog completeness, an executable parameter grammar, a deterministic
   refusal path, a registered compensation contract, recorded unit coverage,
   and a recorded verification date. See :class:`CatalogProbe`.
2. ``VERIFIED_LIVE`` and ``STABLE`` are reachable **only** through a recorded
   :class:`LiveRunRecord`. There is no flag, no constructor argument, and no
   code path in this module that sets either rung without a record that
   survives ``LiveRunRecord``'s own validation and carries every observation
   the criteria name. An empty evidence store yields zero live-verified
   faults — never a "presumed live" default.

The top two rungs differ by repetition and coverage, not by severity:

* ``VERIFIED_LIVE`` — passing runs on the *required* container engines
  (``docker`` and ``podman``), each with a complete observation set: an
  injected effect, an undo that ran, and a probe that confirmed the
  pre-injection baseline was restored within tolerance.
* ``STABLE`` — strictly more: the *entire declared engine-lane matrix* has
  passing evidence, the same verification is repeated on distinct days, and a
  deprecation + rollback policy is recorded on the catalog entry. A single
  successful run on a subset of engines is not ``STABLE``, by construction.

Refusal is the default. Every refusal names the criterion, the observed value,
and the value that would have been required.

The engine reads no registry, no clock of its own, and no filesystem. It is a
pure function of ``(definition, probe, store)``; the report layer supplies the
registry facts. That is what makes the derived level falsifiable rather than
decorative.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from typing import TYPE_CHECKING, Any, Final

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mayhem.domain.catalog import definition_for
from mayhem.domain.common import utc_now
from mayhem.domain.faults import (
    EngineLane,
    FaultCategory,
    FaultDefinition,
    MaturityLevel,
    ParamSpec,
    ParamType,
)
from mayhem.domain.risks import RiskLevel

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = [
    "BUNDLE_HASH_RE",
    "CUMULATIVE_CRITERIA",
    "LIVE_STAGES",
    "MATURITY_MEANING",
    "MATURITY_PROMOTION_CRITERIA",
    "MIN_LIVE_OBSERVATION_DAYS",
    "REQUIRED_BUNDLE_DIGESTS",
    "REQUIRED_LIVE_ENGINES",
    "RUNG_CRITERIA",
    "SCHEMA_REFUSES_DETERMINISTICALLY",
    "BundleRef",
    "BundleStore",
    "CatalogProbe",
    "Criterion",
    "CriterionOutcome",
    "EvidenceStore",
    "LiveRunRecord",
    "Observation",
    "PromotionDecision",
    "build_probe",
    "criterion_text",
    "evaluate_maturity",
    "probe_params_grammar",
    "promotion_status",
]


#: Engines that a ``verified-live`` promotion must cover. Narrower than "any
#: engine that happened to be installed", so the rung is a statement about a
#: real matrix rather than about one developer's laptop.
REQUIRED_LIVE_ENGINES: Final[tuple[EngineLane, ...]] = (EngineLane.DOCKER, EngineLane.PODMAN)

#: SHA-256 hex of the evidence bundle a record points at. A record whose digest
#: does not look like one cannot be referring to a bundle.
BUNDLE_HASH_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")

#: Minimum distinct days on which a *repeated* passing verification must be
#: observed. Maturity is about surviving time, not about one lucky afternoon.
MIN_LIVE_OBSERVATION_DAYS: Final[int] = 2

#: Content digests a bundle must carry for the evidence to be usable. Each maps
#: onto a claim the criteria make, so a bundle that omits one is a bundle that
#: does not support the claim.
REQUIRED_BUNDLE_DIGESTS: Final[tuple[str, ...]] = (
    "params",
    "target",
    "observed_effect",
    "undo",
    "residue",
)

#: The three stages a run has to show. A single ``ok`` boolean cannot express
#: this distinction, which is exactly why ``verified-live`` used to be
#: unearnable.
LIVE_STAGES: Final[tuple[str, ...]] = ("injected", "undo", "residue")


# ── criteria ────────────────────────────────────────────────────────────────


class Criterion(StrEnum):
    """Stable machine names for every executable promotion criterion.

    The names are identifiers, not prose: a refusal or a report renders the
    name so it can be grepped, asserted on, and diffed across runs. The
    human-readable text lives in :data:`MATURITY_PROMOTION_CRITERIA` — the same
    table the report has always shown — and each name appears verbatim inside
    one of those strings, so the two cannot drift into two different claims.
    """

    CATALOG_METADATA_COMPLETE = "catalog metadata is complete"
    PLANNER_VALIDATES_PARAMS = "planner validates parameters and target applicability"
    EXECUTION_REFUSES_DETERMINISTICALLY = (
        "the execution path refuses unsupported use deterministically"
    )
    UNIT_TEST_COVERAGE = (
        "deterministic unit tests cover the parameters, refusal, and compensation contract"
    )
    VERIFICATION_DATE_RECORDED = "a verification date is recorded in the catalog"
    LIVE_RUNTIME_COMPLETED = "a supported live runtime completed injection and recovery"
    EVIDENCE_RECORDED = "the observation and recovery evidence is recorded"
    ENGINE_MATRIX_VERIFIED = "the supported engine and platform matrix is verified"
    REPEATED_ACROSS_DAYS = (
        f"repeated verification on at least {MIN_LIVE_OBSERVATION_DAYS} distinct days"
    )
    DEPRECATION_POLICY_DOCUMENTED = "the deprecation and rollback policy is documented"


#: Criteria consulted when checking a rung, in report order. "all <lower>
#: criteria pass" is enforced structurally: a rung is only reached once every
#: lower rung has been reached.
RUNG_CRITERIA: Final[dict[MaturityLevel, tuple[Criterion, ...]]] = {
    MaturityLevel.EXPERIMENTAL: (
        Criterion.CATALOG_METADATA_COMPLETE,
        Criterion.PLANNER_VALIDATES_PARAMS,
        Criterion.EXECUTION_REFUSES_DETERMINISTICALLY,
    ),
    MaturityLevel.VERIFIED_UNIT: (
        Criterion.UNIT_TEST_COVERAGE,
        Criterion.VERIFICATION_DATE_RECORDED,
    ),
    MaturityLevel.VERIFIED_LIVE: (
        Criterion.LIVE_RUNTIME_COMPLETED,
        Criterion.EVIDENCE_RECORDED,
    ),
    MaturityLevel.STABLE: (
        Criterion.ENGINE_MATRIX_VERIFIED,
        Criterion.REPEATED_ACROSS_DAYS,
        Criterion.DEPRECATION_POLICY_DOCUMENTED,
    ),
}


def _cumulative_criteria() -> dict[MaturityLevel, tuple[Criterion, ...]]:
    """Every criterion up to and including a rung, in climb order."""
    ladder = (
        MaturityLevel.EXPERIMENTAL,
        MaturityLevel.VERIFIED_UNIT,
        MaturityLevel.VERIFIED_LIVE,
        MaturityLevel.STABLE,
    )
    cumulative: dict[MaturityLevel, tuple[Criterion, ...]] = {}
    running: tuple[Criterion, ...] = ()
    for level in ladder:
        running = (*running, *RUNG_CRITERIA[level])
        cumulative[level] = running
    return cumulative


#: Cumulative criteria per rung, so a promotion is a strict climb rather than a
#: per-rung checkbox.
CUMULATIVE_CRITERIA: Final[dict[MaturityLevel, tuple[Criterion, ...]]] = _cumulative_criteria()

#: The documented criteria table. First entry of each rung is the
#: "all <lower> criteria pass" umbrella, exactly as before — this is the text
#: the report renders, now with an executable name attached to every line.
MATURITY_PROMOTION_CRITERIA: Final[dict[MaturityLevel, tuple[str, ...]]] = {
    MaturityLevel.EXPERIMENTAL: (
        Criterion.CATALOG_METADATA_COMPLETE.value,
        Criterion.PLANNER_VALIDATES_PARAMS.value,
        Criterion.EXECUTION_REFUSES_DETERMINISTICALLY.value,
    ),
    MaturityLevel.VERIFIED_UNIT: (
        "all experimental criteria pass",
        Criterion.UNIT_TEST_COVERAGE.value,
        Criterion.VERIFICATION_DATE_RECORDED.value,
    ),
    MaturityLevel.VERIFIED_LIVE: (
        "all verified-unit criteria pass",
        Criterion.LIVE_RUNTIME_COMPLETED.value,
        Criterion.EVIDENCE_RECORDED.value,
    ),
    MaturityLevel.STABLE: (
        "all verified-live criteria pass",
        Criterion.ENGINE_MATRIX_VERIFIED.value,
        Criterion.REPEATED_ACROSS_DAYS.value,
        Criterion.DEPRECATION_POLICY_DOCUMENTED.value,
    ),
}

#: What a rung asserts, and what it does not. Rendered into reports so a reader
#: never has to guess how much a badge is worth.
MATURITY_MEANING: Final[dict[MaturityLevel, str]] = {
    MaturityLevel.EXPERIMENTAL: (
        "not unit-verified: the catalog entry does not satisfy the verified-unit "
        "criteria recomputed at read time"
    ),
    MaturityLevel.VERIFIED_UNIT: (
        "verified in isolation only: the parameter grammar, the refusal path, and the "
        "compensation contract check out in-process. This is a claim about our code, not "
        "about the fault working against a real system."
    ),
    MaturityLevel.VERIFIED_LIVE: (
        "injected into a running stack on the required engines with a recorded evidence "
        "bundle; the declared effect was observed and the undo restored the pre-injection "
        "baseline within tolerance"
    ),
    MaturityLevel.STABLE: (
        "verified-live across the whole declared engine-lane matrix, repeated across "
        "distinct days, with a documented deprecation and rollback policy"
    ),
}


def criterion_text(name: Criterion) -> str:
    """Human-readable text for a criterion, from the canonical table."""
    for texts in MATURITY_PROMOTION_CRITERIA.values():
        if name.value in texts:
            return name.value
    return name.value


# ── evidence records ────────────────────────────────────────────────────────


def _digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(encoded.encode()).hexdigest()


class BundleRef(BaseModel):
    """Pointer to a recorded evidence bundle, plus the digests that bind it.

    A bundle hash alone proves nothing on its own — anyone can write a hash into
    a file. The record therefore also carries digests of the *contents* the
    criteria depend on (:data:`REQUIRED_BUNDLE_DIGESTS`). A bundle that omits
    one of them cannot be used as promotion evidence, and the engine says which
    one is missing.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    bundle_hash: str = Field(min_length=64, max_length=64)
    mayhem_version: str = Field(min_length=1, max_length=64)
    bundle_path: str = Field(min_length=1)
    digests: dict[str, str] = Field(default_factory=dict)

    @field_validator("bundle_hash")
    @classmethod
    def _is_sha256(cls, value: str) -> str:
        if BUNDLE_HASH_RE.match(value) is None:
            raise ValueError("bundle_hash must be 64 lowercase hex characters (sha256)")
        return value

    @model_validator(mode="after")
    def _digests_are_digests(self) -> BundleRef:
        for name, digest in self.digests.items():
            if BUNDLE_HASH_RE.match(digest) is None:
                raise ValueError(f"digest for {name!r} must be 64 lowercase hex characters")
        return self

    def missing_digests(self) -> tuple[str, ...]:
        return tuple(name for name in REQUIRED_BUNDLE_DIGESTS if name not in self.digests)


class Observation(BaseModel):
    """One recorded measurement from a live run.

    ``stage`` separates the three things a run has to show: the fault actually
    changed the declared signal (``injected``), undo actually ran (``undo``),
    and the post-undo probe actually returned to the baseline (``residue``).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    stage: str = Field(pattern=r"^(injected|undo|residue)$")
    probe: str = Field(min_length=1)
    baseline: float
    observed: float
    tolerance: float = Field(ge=0.0)
    passed: bool

    @property
    def drift(self) -> float:
        return abs(self.observed - self.baseline)

    @model_validator(mode="after")
    def _pass_is_derivable_from_the_numbers(self) -> Observation:
        """A recorded ``passed`` must follow from the recorded numbers.

        Without this, ``passed`` is a self-asserted claim: a caller could record
        ``observed == baseline`` with ``passed=True`` for the ``injected`` stage
        and the engine would have to take it on faith. Recomputing here makes an
        inconsistent observation unrepresentable rather than merely discouraged.
        """
        drift = self.drift
        if self.stage == "injected":
            if self.passed and drift <= self.tolerance:
                raise ValueError(
                    f"injected-stage observation of {self.probe!r} moved the signal by {drift}, "
                    f"within tolerance {self.tolerance}: a fault that does not move the signal "
                    "is not evidence that the fault works"
                )
            if not self.passed and drift > self.tolerance:
                raise ValueError(
                    f"injected-stage observation of {self.probe!r} reports passed=False but the "
                    f"signal moved by {drift}, above tolerance {self.tolerance}"
                )
            return self
        if self.passed and drift > self.tolerance:
            raise ValueError(
                f"{self.stage}-stage observation of {self.probe!r} reports passed=True but the "
                f"signal is {drift} from baseline, above tolerance {self.tolerance}: undo did "
                "not restore the baseline"
            )
        if not self.passed and drift <= self.tolerance:
            raise ValueError(
                f"{self.stage}-stage observation of {self.probe!r} reports passed=False but the "
                f"signal is {drift} from baseline, within tolerance {self.tolerance}"
            )
        return self


class LiveRunRecord(BaseModel):
    """Everything one real run must record before a rung can move.

    A record is only constructible from a run that produced all of it: an
    observed effect, a completed undo, a residue check, a bundle, an engine, and
    timezone-aware timestamps. The model validator is the gate; there is no
    ``verified`` field a caller can set to skip it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    fault_id: str = Field(min_length=3)
    engine: str = Field(min_length=1)
    platform: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    params: dict[str, object] = Field(default_factory=dict)
    target: str = Field(min_length=1)
    observed_effect: str = Field(min_length=1)
    undo_performed: bool
    undo_description: str = Field(min_length=1)
    started_at: datetime
    finished_at: datetime
    bundle: BundleRef
    observations: tuple[Observation, ...] = Field(min_length=1)

    @field_validator("fault_id")
    @classmethod
    def _plausible_fault_id(cls, value: str) -> str:
        if re.match(r"^[a-z][a-z0-9_]*\.[a-z0-9_.]+$", value) is None:
            raise ValueError("fault_id must look like '<family>.<kind>'")
        FaultCategory.from_fault_id(value)  # raises on an unknown family prefix
        return value

    @model_validator(mode="after")
    def _run_is_coherent(self) -> LiveRunRecord:
        if self.started_at.tzinfo is None or self.finished_at.tzinfo is None:
            raise ValueError("started_at and finished_at must be timezone-aware")
        if self.finished_at < self.started_at:
            raise ValueError("finished_at precedes started_at")
        if not self.undo_performed:
            raise ValueError(
                f"run {self.run_id!r} records no undo for {self.fault_id!r}: a fault that was not "
                "compensated leaves chaos residue and is not evidence for any rung above "
                "verified-unit"
            )
        return self

    # -- criterion helpers. Each is computed from the record's own contents so a
    # -- report can quote what was seen rather than a bare verdict.

    def stages_observed(self) -> frozenset[str]:
        return frozenset(observation.stage for observation in self.observations)

    def stage_passed(self, stage: str) -> bool:
        return any(
            observation.stage == stage and observation.passed for observation in self.observations
        )

    def max_recovery_drift(self) -> float:
        """Largest distance from baseline across undo and residue samples."""
        drifts = [
            observation.drift
            for observation in self.observations
            if observation.stage in {"undo", "residue"}
        ]
        return max(drifts, default=0.0)

    def passes(self) -> bool:
        """A passing run: every stage observed, every observation passed."""
        return self.stages_observed() == frozenset(LIVE_STAGES) and all(
            observation.passed for observation in self.observations
        )

    def kind_fingerprint(self) -> str:
        """Content digest of everything a rung claim depends on.

        Two records with the same fingerprint are the *same evidence*, so a
        repeated verification cannot be manufactured by recording one run twice.
        """
        return _digest(
            {
                "fault_id": self.fault_id,
                "params": dict(sorted(self.params.items(), key=lambda item: item[0])),
                "target": self.target,
                "observed_effect": self.observed_effect,
                "undo": self.undo_description,
                "observations": [
                    {
                        "stage": observation.stage,
                        "probe": observation.probe,
                        "baseline": observation.baseline,
                        "observed": observation.observed,
                        "tolerance": observation.tolerance,
                        "passed": observation.passed,
                    }
                    for observation in self.observations
                ],
            }
        )

    def kind_key(self) -> tuple[str, str, str, str]:
        return (self.fault_id, self.engine, self.platform, self.kind_fingerprint())

    def observation_day(self) -> str:
        """Local calendar day the run finished, per the report's own convention."""
        return self.finished_at.astimezone().date().isoformat()


# ── the in-process facts that make ``verified-unit`` mean something ─────────


class CatalogProbe(BaseModel):
    """Facts about the catalog and the registries, recomputed at read time.

    This is the substitute for the old blanket promotion. Every field is an
    observation the engine checks, so a fault that stops being executable, or
    loses its compensation contract, or gains an un-validatable parameter, or
    loses its recorded unit coverage, drops out of ``verified-unit`` instead of
    silently keeping a badge it no longer earns.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    definition: FaultDefinition
    metadata_complete: bool
    executor_registered: bool
    compensation_registered: bool
    params_grammar_ok: bool
    refusal_deterministic: bool
    unit_evidence: tuple[str, ...] = ()

    @property
    def fault_id(self) -> str:
        return self.definition.id

    @property
    def declared_effect(self) -> str:
        return self.definition.observable_effect


def probe_params_grammar(definition: FaultDefinition) -> bool:
    """Recompute the parameter grammar against the definition it ships with.

    Each declared default is validated in isolation — the spec under test is
    copied into an otherwise-parameterless entry, so a *required* parameter with
    no default is not mistaken for a broken grammar (it is the caller's job to
    supply one) while a default the spec itself would refuse is caught here
    rather than at plan time.
    """
    for spec in definition.params_schema:
        if spec.default is None:
            continue
        isolated = spec.model_copy(update={"required": False})
        entry = definition.model_copy(update={"params_schema": (isolated,)})
        try:
            entry.validate_params({str(isolated.name): isolated.default})
        except Exception:  # any rejection at all is a grammar failure
            return False
    return True


def probe_refusal_deterministic() -> bool:
    """Recompute the deterministic-refusal criterion by observing a refusal.

    A fault's parameters must be rejected deterministically when they are
    wrong, otherwise the planner's refusal is advisory. This is settled by
    actually running the refusal against a known-bad parameter and a known-bad
    type, not by reading a claim that it will refuse. It is evaluated once, at
    import, because the answer is a property of the schema rather than of any
    one fault.
    """
    probe = FaultDefinition(
        id="proc.pause",
        category=FaultCategory.PROCESS,
        risk=RiskLevel.LOW,
        catalog_only=True,
        params_schema=(ParamSpec(name="percent", type=ParamType.PERCENT, maximum=100.0),),
    )
    refusals: tuple[dict[str, object], ...] = (
        {"unknown_parameter": 1},
        {"percent": "not-a-number"},
        {"percent": 1000.0},
    )
    for bad in refusals:
        try:
            probe.validate_params(bad)
        except Exception:  # any rejection at all is a deterministic refusal
            continue
        return False
    return True


#: Evaluated once: the schema either refuses deterministically or it does not.
SCHEMA_REFUSES_DETERMINISTICALLY: Final[bool] = probe_refusal_deterministic()


def build_probe(
    definition: FaultDefinition,
    *,
    executor_registered: Callable[[str], bool],
    compensation_registered: Callable[[str], bool],
    unit_evidence: tuple[str, ...] = (),
) -> CatalogProbe:
    """Assemble a :class:`CatalogProbe` from registry lookups.

    The two registry predicates are required rather than defaulted: this module
    performs no lookups of its own, so the promotion engine's verdict depends
    only on facts a caller passes in and can be exercised end to end without a
    cluster.
    """
    return CatalogProbe(
        definition=definition,
        metadata_complete=bool(
            definition.observable_effect
            and definition.verification_method is not None
            and definition.reversibility is not None
            and definition.compensation_evidence
            and definition.engine_lanes
            and definition.target_kinds
        ),
        executor_registered=bool(executor_registered(definition.id)),
        compensation_registered=bool(compensation_registered(definition.id)),
        params_grammar_ok=probe_params_grammar(definition),
        # A catalog-only entry that does not say why it refuses is not refusing
        # deterministically; it is just undocumented.
        refusal_deterministic=SCHEMA_REFUSES_DETERMINISTICALLY
        and (not definition.catalog_only or bool(definition.refusal_reason)),
        unit_evidence=tuple(unit_evidence),
    )


# ── decisions ───────────────────────────────────────────────────────────────


class CriterionOutcome(BaseModel):
    """One computed criterion, carrying the values that produced it."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    text: str
    met: bool
    observed: str
    required: str
    detail: str = ""

    def reason(self) -> str:
        """One line naming the criterion, the observation, and the bar."""
        suffix = f" ({self.detail})" if self.detail else ""
        return (
            f"criterion {self.name} not met: observed {self.observed}; "
            f"required {self.required}{suffix}"
        )


class PromotionDecision(BaseModel):
    """The evaluated answer: the earned rung, and every criterion behind it.

    ``maturity`` is derived. It is never copied from the catalog's declared
    field, and it is never allowed past the rung the evidence supports.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    fault_id: str
    declared: MaturityLevel
    maturity: MaturityLevel
    meaning: str
    outcomes: tuple[CriterionOutcome, ...]
    refusals: tuple[str, ...]
    live_record_count: int = 0
    distinct_observation_days: int = 0
    required_engines: tuple[str, ...] = ()
    recorded_engines: tuple[str, ...] = ()

    @property
    def eligible(self) -> bool:
        """True only when nothing blocks this rung. Always the default is False."""
        return not self.refusals

    @property
    def at_least_unit_verified(self) -> bool:
        return self.maturity in {
            MaturityLevel.VERIFIED_UNIT,
            MaturityLevel.VERIFIED_LIVE,
            MaturityLevel.STABLE,
        }

    @property
    def live_verified(self) -> bool:
        return self.maturity in {MaturityLevel.VERIFIED_LIVE, MaturityLevel.STABLE}

    def to_dict(self) -> dict[str, object]:
        return {
            "fault_id": self.fault_id,
            "declared_maturity": self.declared.value,
            "maturity": self.maturity.value,
            "meaning": self.meaning,
            "eligible": self.eligible,
            "unit_verified": self.at_least_unit_verified,
            "live_verified": self.live_verified,
            "live_record_count": self.live_record_count,
            "distinct_observation_days": self.distinct_observation_days,
            "required_engines": list(self.required_engines),
            "recorded_engines": list(self.recorded_engines),
            "refusals": list(self.refusals),
            "criteria": [outcome.model_dump(mode="json") for outcome in self.outcomes],
        }


# ── stores ──────────────────────────────────────────────────────────────────


class EvidenceStore:
    """Append-only collection of :class:`LiveRunRecord`.

    Empty by default, and the default everywhere. Nothing seeds it, so a
    ``verified-live`` count in any report is zero until a run has actually been
    executed and recorded.
    """

    __slots__ = ("_records",)

    def __init__(self, records: tuple[LiveRunRecord, ...] = ()) -> None:
        self._records: tuple[LiveRunRecord, ...] = tuple(records)

    def __len__(self) -> int:
        return len(self._records)

    def __bool__(self) -> bool:
        return bool(self._records)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(records={len(self._records)})"

    @property
    def records(self) -> tuple[LiveRunRecord, ...]:
        return self._records

    def record(self, entry: LiveRunRecord) -> EvidenceStore:
        """Return a new store with ``entry`` appended. The store is immutable."""
        return type(self)((*self._records, entry))

    def for_fault(self, fault_id: str) -> tuple[LiveRunRecord, ...]:
        return tuple(record for record in self._records if record.fault_id == fault_id)

    def fault_ids(self) -> frozenset[str]:
        return frozenset(record.fault_id for record in self._records)


@dataclass(frozen=True, slots=True)
class BundleStore(EvidenceStore):
    """Marker subclass: the on-disk live-verification evidence bundle store.

    The record's ``observed_effect``, ``undo_description``, and the numeric
    observations are exactly the fields a hostile or careless recorder would
    most want to overstate, so their digests must be present in the bundle for
    the record to count as evidence. That is checked per record in
    :func:`evaluate_maturity`, not here, so the refusal can name the run.
    """


# ── criterion evaluation ────────────────────────────────────────────────────


def _effective_engine_lanes(probe: CatalogProbe) -> frozenset[EngineLane]:
    """Engine lanes a live run can actually target for this fault.

    The ``multi-engine`` sentinel is not a lane you can run on; it is how the
    catalog says "engine-agnostic, decide at plan time". Requiring evidence for
    it would make the top rung unreachable for a well-formed entry.
    """
    return frozenset(
        lane for lane in probe.definition.engine_lanes if lane is not EngineLane.MULTI_ENGINE
    )


def _lane_of(engine: str) -> EngineLane | None:
    try:
        return EngineLane(engine)
    except ValueError:
        return None


def _passing_records(
    records: tuple[LiveRunRecord, ...], probe: CatalogProbe
) -> list[LiveRunRecord]:
    """Records that pass *and* agree with the catalog entry they claim to prove.

    A run that observed a different effect, on an engine the fault does not
    declare, with parameters the fault does not accept, is not evidence about
    this fault. The check needs the definition, so it lives here rather than in
    the record's own validator.
    """
    lanes = _effective_engine_lanes(probe)
    accepted = {str(spec.name) for spec in probe.definition.params_schema}
    passing: list[LiveRunRecord] = []
    for record in records:
        if not record.passes():
            continue
        if record.observed_effect.strip() != probe.declared_effect.strip():
            continue
        lane = _lane_of(record.engine)
        if lane is None or lane not in lanes:
            continue
        if not set(record.params).issubset(accepted):
            continue
        passing.append(record)
    return passing


def _observed_bool(flag: bool, subject: str) -> str:
    return f"{subject}" if flag else f"not {subject}"


def _unit_outcomes(probe: CatalogProbe) -> dict[Criterion, CriterionOutcome]:
    definition = probe.definition
    return {
        Criterion.CATALOG_METADATA_COMPLETE: CriterionOutcome(
            name=Criterion.CATALOG_METADATA_COMPLETE.value,
            text=criterion_text(Criterion.CATALOG_METADATA_COMPLETE),
            met=probe.metadata_complete,
            observed=_observed_bool(
                probe.metadata_complete,
                "catalog metadata (effect, verification method, reversibility, compensation "
                "evidence, engine lanes, target kinds) is complete",
            ),
            required="catalog metadata is complete",
        ),
        Criterion.PLANNER_VALIDATES_PARAMS: CriterionOutcome(
            name=Criterion.PLANNER_VALIDATES_PARAMS.value,
            text=criterion_text(Criterion.PLANNER_VALIDATES_PARAMS),
            met=probe.params_grammar_ok,
            observed=_observed_bool(
                probe.params_grammar_ok,
                f"the parameter grammar of {definition.id} validates its declared schema",
            ),
            required="planner validates parameters and target applicability",
        ),
        Criterion.EXECUTION_REFUSES_DETERMINISTICALLY: CriterionOutcome(
            name=Criterion.EXECUTION_REFUSES_DETERMINISTICALLY.value,
            text=criterion_text(Criterion.EXECUTION_REFUSES_DETERMINISTICALLY),
            met=probe.refusal_deterministic,
            observed=_observed_bool(
                probe.refusal_deterministic,
                f"{definition.id} refuses unsupported use deterministically",
            ),
            required="the execution path refuses unsupported use deterministically",
        ),
        Criterion.UNIT_TEST_COVERAGE: CriterionOutcome(
            name=Criterion.UNIT_TEST_COVERAGE.value,
            text=criterion_text(Criterion.UNIT_TEST_COVERAGE),
            # The criteria name the parameters, the refusal, and the *compensation
            # contract* — not the executor. A fault with an undo template and a
            # covered grammar is unit-verified even if no executor is registered
            # yet, and the dashboard's separate ``registered`` dimension already
            # says so.
            met=bool(probe.unit_evidence) and probe.compensation_registered,
            observed=(
                f"unit-verified for {', '.join(probe.unit_evidence)}; compensation contract "
                f"{'registered' if probe.compensation_registered else 'not registered'}"
                if probe.unit_evidence
                else (
                    "no unit-verification evidence recorded for this fault; compensation contract "
                    f"{'registered' if probe.compensation_registered else 'not registered'}"
                )
            ),
            required=(
                "deterministic unit tests cover the parameters, refusal, and compensation contract"
            ),
        ),
        Criterion.VERIFICATION_DATE_RECORDED: CriterionOutcome(
            name=Criterion.VERIFICATION_DATE_RECORDED.value,
            text=criterion_text(Criterion.VERIFICATION_DATE_RECORDED),
            met=definition.verification_date is not None,
            observed=(
                f"verification_date={definition.verification_date.isoformat()}"
                if definition.verification_date is not None
                else "verification_date=None"
            ),
            required="a verification date is recorded in the catalog",
        ),
    }


def _live_outcomes(
    probe: CatalogProbe,
    passing: list[LiveRunRecord],
    *,
    by_engine: dict[str, list[LiveRunRecord]],
    repeated_days: int,
    repetition_dates: list[str],
    required_engines: tuple[str, ...],
    recorded_engines: tuple[str, ...],
) -> dict[Criterion, CriterionOutcome]:
    bundle_problems: list[str] = []
    for record in passing:
        for name in record.bundle.missing_digests():
            bundle_problems.append(f"run {record.run_id!r} has no {name} digest in its bundle")

    missing_required = [engine for engine in required_engines if engine not in by_engine]
    lanes = _effective_engine_lanes(probe)
    matrix = lanes or frozenset(REQUIRED_LIVE_ENGINES)
    missing_matrix = sorted(lane.value for lane in matrix if lane.value not in by_engine)
    deprecation = (probe.definition.deprecation_path or "").strip()

    return {
        Criterion.LIVE_RUNTIME_COMPLETED: CriterionOutcome(
            name=Criterion.LIVE_RUNTIME_COMPLETED.value,
            text=criterion_text(Criterion.LIVE_RUNTIME_COMPLETED),
            met=bool(by_engine) and not missing_required,
            observed=(
                f"no passing run recorded for {', '.join(missing_required)}; passing engines: "
                f"{', '.join(recorded_engines) or 'none'}"
                if missing_required
                else f"passing runs recorded on {', '.join(recorded_engines)}"
            ),
            required=(
                "a supported live runtime completed injection and recovery on "
                f"{', '.join(required_engines)}"
            ),
        ),
        Criterion.EVIDENCE_RECORDED: CriterionOutcome(
            name=Criterion.EVIDENCE_RECORDED.value,
            text=criterion_text(Criterion.EVIDENCE_RECORDED),
            met=bool(passing) and not bundle_problems,
            observed=(
                "; ".join(bundle_problems)
                if bundle_problems
                else (
                    f"{len(passing)} passing run(s), each with an evidence bundle carrying "
                    f"digests for {', '.join(REQUIRED_BUNDLE_DIGESTS)}"
                    if passing
                    else "no recorded evidence bundle for this fault"
                )
            ),
            required="the observation and recovery evidence is recorded",
        ),
        Criterion.ENGINE_MATRIX_VERIFIED: CriterionOutcome(
            name=Criterion.ENGINE_MATRIX_VERIFIED.value,
            text=criterion_text(Criterion.ENGINE_MATRIX_VERIFIED),
            met=bool(by_engine) and not missing_matrix,
            observed=(
                f"engine matrix incomplete: no passing run for {', '.join(missing_matrix)}; "
                f"recorded engines {', '.join(recorded_engines) or 'none'}"
                if missing_matrix
                else f"every declared engine lane verified: {', '.join(recorded_engines)}"
            ),
            required=(
                "the supported engine and platform matrix is verified on "
                f"{', '.join(sorted(lane.value for lane in matrix))}"
            ),
        ),
        Criterion.REPEATED_ACROSS_DAYS: CriterionOutcome(
            name=Criterion.REPEATED_ACROSS_DAYS.value,
            text=criterion_text(Criterion.REPEATED_ACROSS_DAYS),
            met=repeated_days >= MIN_LIVE_OBSERVATION_DAYS,
            observed=(
                f"{repeated_days} distinct day(s) with repeated evidence"
                + (f" ({', '.join(repetition_dates)})" if repetition_dates else "")
            ),
            required=(
                f"repeated verification on at least {MIN_LIVE_OBSERVATION_DAYS} distinct days"
            ),
        ),
        Criterion.DEPRECATION_POLICY_DOCUMENTED: CriterionOutcome(
            name=Criterion.DEPRECATION_POLICY_DOCUMENTED.value,
            text=criterion_text(Criterion.DEPRECATION_POLICY_DOCUMENTED),
            met=bool(deprecation),
            observed=(
                f"deprecation_path={deprecation!r}" if deprecation else "deprecation_path=None"
            ),
            required="the deprecation and rollback policy is documented",
        ),
    }


_LADDER: Final[tuple[MaturityLevel, ...]] = (
    MaturityLevel.VERIFIED_UNIT,
    MaturityLevel.VERIFIED_LIVE,
    MaturityLevel.STABLE,
)


def evaluate_maturity(
    definition: FaultDefinition,
    *,
    probe: CatalogProbe,
    store: EvidenceStore | None = None,
) -> PromotionDecision:
    """Evaluate the promotion criteria for ``definition`` and return a decision.

    This is the only function in the codebase that decides a fault's reported
    maturity. It is a pure function of its arguments: no clock, no filesystem,
    no ambient registry, and no default that grants a rung. Feed it an empty
    store and every fault stops at whatever its own facts earn.
    """
    records = (store if store is not None else EvidenceStore()).for_fault(definition.id)
    outcomes = _unit_outcomes(probe)

    passing = _passing_records(records, probe)
    by_engine: dict[str, list[LiveRunRecord]] = {}
    for entry in passing:
        by_engine.setdefault(entry.engine, []).append(entry)

    required_engines = tuple(lane.value for lane in REQUIRED_LIVE_ENGINES)
    recorded_engines = tuple(sorted(by_engine))

    # A run's observation day is its local calendar day, matching the report's
    # existing "generated on" convention. A run stamped later than the
    # evaluation (clock skew, a fixture recording a planned window) is folded
    # onto the evaluation day rather than counted as future evidence.
    today = utc_now().date().isoformat()

    def _day_of(entry: LiveRunRecord) -> str:
        day = entry.observation_day()
        return day if day < today else today

    fingerprint_counts: dict[tuple[str, str, str, str], int] = {}
    for entry in passing:
        fingerprint_counts[entry.kind_key()] = fingerprint_counts.get(entry.kind_key(), 0) + 1
    repeated = [entry for entry in passing if fingerprint_counts[entry.kind_key()] > 1]
    repetition_dates = sorted({_day_of(entry) for entry in repeated})

    outcomes.update(
        _live_outcomes(
            probe,
            passing,
            by_engine=by_engine,
            repeated_days=len(repetition_dates),
            repetition_dates=repetition_dates,
            required_engines=required_engines,
            recorded_engines=recorded_engines,
        )
    )

    maturity = MaturityLevel.EXPERIMENTAL
    evaluated: list[CriterionOutcome] = []
    refusals: list[str] = []
    blocked = False
    for level in _LADDER:
        unmet = [
            outcomes[criterion]
            for criterion in CUMULATIVE_CRITERIA[level]
            if not outcomes[criterion].met
        ]
        if unmet:
            evaluated.extend(unmet)
            refusals.extend(outcome.reason() for outcome in unmet)
            blocked = True
            break
        maturity = level
    if not blocked:
        evaluated.extend(
            outcomes[criterion] for criterion in CUMULATIVE_CRITERIA[MaturityLevel.STABLE]
        )

    return PromotionDecision(
        fault_id=definition.id,
        declared=definition.maturity,
        maturity=maturity,
        meaning=MATURITY_MEANING[maturity],
        outcomes=tuple(evaluated),
        refusals=tuple(refusals),
        live_record_count=len(passing),
        distinct_observation_days=len(repetition_dates),
        required_engines=required_engines,
        recorded_engines=recorded_engines,
    )


def promotion_status(
    fault_id: str,
    *,
    probe: CatalogProbe,
    store: EvidenceStore | None = None,
) -> PromotionDecision:
    """Evaluate a catalog fault by id, resolving its definition."""
    return evaluate_maturity(definition_for(fault_id), probe=probe, store=store)
