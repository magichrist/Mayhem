"""Probe definitions: *what a probe is about*, declared as data.

Plan 11 lists eighteen probe families — HTTP/HTTPS, TCP/UDP, DNS, gRPC, SQL,
Redis, Kafka/RabbitMQ/NATS, process, file, command, Prometheus metrics,
OpenTelemetry, logs, traces, Kubernetes state, and a synthetic business
transaction — and then, in one sentence, says what a probe definition is:
*"new families as data: endpoints, queries, sampling cadence, lifecycle
membership."* That is the whole job. Eighteen families is eighteen endpoint
strings and eighteen query strings; it is not eighteen classes, and building
eighteen classes is how a probe catalogue turns into a second probe hierarchy
that drifts from the first one.

**This module extends the probe vocabulary that already exists. It does not
replace it.** The runtime probe is still the closed
:data:`mayhem.domain.checks.Probe` union, the post-recovery assertion is still
:mod:`mayhem.domain.leases`' ``VerifyProbe``, the phases are still
:mod:`mayhem.domain.steady_state`'s ``Phase``, the reading is still
:mod:`mayhem.domain.observations`' ``ObservationResult``, the collector that
will satisfy a definition is still one of
:mod:`mayhem.domain.observability`'s four source kinds, and the comparison a
reading will be graded by is still
:mod:`mayhem.domain.stop_conditions`' ``Threshold``/``ToleranceKind``. A
:class:`ProbeDefinition` names those things and holds the data; where a family
has no member in the closed probe union — UDP, DNS, gRPC, SQL, Redis, the
message brokers, OpenTelemetry, traces, Kubernetes state, the synthetic
transaction — the definition says so by carrying *no* ``carrier`` and saying
why, rather than smuggling a SQL statement into an ``ExecProbe`` and calling
it a family.

Four commitments run through the code below.

**A probe is a locator plus a cadence, or it is nothing.** Every family
declares which of ``endpoint`` / ``query`` / ``command`` / ``path`` / ``target``
/ ``steps`` is the thing that makes it *that* probe, and a definition missing
its own locator is refused. The tempting alternative — accept an empty
definition and let the collector complain at run time — produces the failure
this whole plan exists to remove: a probe that resolves to nothing reports
calm.

**Lifecycle membership is stated, and noise is budgeted before it is
discovered.** A probe names the stages of the plan's six-stage lifecycle it
belongs to — ``pre-baseline``, ``warm-up``, ``during-fault``, ``continuous``,
``after-recovery``, ``final-verification`` — and each stage anchors to the
``Phase`` (``pre`` / ``during`` / ``post``) the verdict core already grades in,
so a lifecycle stage cannot introduce a fourth spelling. The two settling
stages are the interesting ones: claiming ``warm-up`` **requires** declaring a
``warmup`` budget, and claiming ``after-recovery`` **requires** declaring a
``cooldown``. A budget with no stage, or a stage with no budget, is refused —
either one alone is a setting that either does nothing or discovers its noise
in the middle of a verdict, which is the failure the plan calls out by name.
:meth:`ProbeDefinition.graded_stages` then says which stages may support a
verdict, so "excluded because it is still settling" is a fact about the
definition rather than a judgement the collector has to make silently.

**Definitions are versioned and pinnable, and drift is detected two ways.**
:meth:`ProbeDefinition.fingerprint` is a canonical digest of the definition's
*semantic* fields (prose excluded: a reworded description does not make a probe
behave differently, and pinning it would churn every pin in every plan for a
docstring). A :class:`ProbePlan` holds :class:`ProbePin` values — id, version,
fingerprint — and :meth:`ProbePlan.bind` refuses a plan whose pins do not match
the catalogue: an unknown id, a version that moved, and the case a version
number alone cannot catch, a definition edited in place while still claiming
the version it always claimed.

**Units are declared, and a reading in the wrong unit is refused rather than
converted.** :meth:`ProbeDefinition.check_reading` compares units by identity
(normalised for case and surrounding whitespace, and nothing else): a probe
declared in ``ms`` that receives ``0.25 s`` is a unit error, and a tool that
quietly converted it would be comparing 250 against 0.25 and calling the
result a measurement.

The categorical tolerance is **still absent, deliberately**. ``ToleranceKind``
in :mod:`mayhem.domain.stop_conditions` carries four mechanisms and no
``categorical``, and Phase 1 deferred it for a reason that still holds: there
is no categorical value on
:class:`~mayhem.domain.observations.ObservationResult` to compare —
``value`` is ``float | None`` and nothing carries a label. Adding a categorical
value to that dataclass is the only honest way to add the tolerance, and it is
a change to a contract every observation provider already satisfies, so it is
not this phase's to make unilaterally. Rather than leave that as a comment,
:class:`ProbeValueKind` makes the gap enforceable: a definition may *declare*
that it wants a categorical reading, and construction refuses it with
``probes.categorical_unsupported`` naming the missing field. The refusal is
lifted in the same commit that adds a label to ``ObservationResult``, and
``tests/unit/test_probes.py`` asserts that precondition still holds, so the
day the field appears the test goes red and points at the refusal. This is
recorded in the STATUS ledger of
``docs/v1.1.0/11_OBSERVABILITY_PROBES_STOP_CONDITIONS.md``.

Nothing here performs IO, reads a clock, or judges a value. A definition is
input; the engine (Phase 2) is what runs it.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import TYPE_CHECKING, Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from mayhem.domain.capabilities import Identifier
from mayhem.domain.checks import Probe, ProbeType
from mayhem.domain.common import Duration
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import digest
from mayhem.domain.leases import VerifyProbe
from mayhem.domain.observability import ObservabilitySourceKind
from mayhem.domain.steady_state import Phase
from mayhem.domain.stop_conditions import ToleranceKind

if TYPE_CHECKING:
    from mayhem.domain.observations import ObservationResult

__all__ = [
    "CATEGORICAL_REFUSAL_CODE",
    "LOCATOR_FIELDS",
    "SUPPORTED_TOLERANCE_KINDS",
    "LifecycleStage",
    "ProbeCatalog",
    "ProbeDefinition",
    "ProbeFamily",
    "ProbeFingerprint",
    "ProbePin",
    "ProbePlan",
    "ProbeValueKind",
    "ProbeVersion",
    "graded_stages",
    "stage_phase",
]

#: The error code raised for a probe that asks for a categorical reading.
#: Named so the ledger, the tests and any future collector can agree on the
#: refusal without matching on message text.
CATEGORICAL_REFUSAL_CODE = "probes.categorical_unsupported"

#: Every comparison mechanism a probe reading may eventually be graded with.
#: Re-exported from :mod:`mayhem.domain.stop_conditions` rather than restated:
#: probes do not own tolerances, they only inherit the ones that exist. Note
#: what is *not* here — ``categorical`` — and see the module docstring.
SUPPORTED_TOLERANCE_KINDS: frozenset[ToleranceKind] = frozenset(ToleranceKind)

#: ``major.minor`` with an optional patch, the same shape
#: :mod:`mayhem.domain.provider` requires of an evidence-schema version. A
#: probe definition that cannot say which version it is cannot be pinned, and
#: an unpinned definition is a plan that reads one way on Monday and another on
#: Tuesday.
ProbeVersion = Annotated[str, StringConstraints(pattern=r"^\d+\.\d+(?:\.\d+)?$")]

#: A canonical digest of a definition's semantic fields — see
#: :meth:`ProbeDefinition.fingerprint`.
ProbeFingerprint = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


# -- vocabulary ---------------------------------------------------------------------


class ProbeFamily(StrEnum):
    """The eighteen families plan 11 lists, spelled out one by one.

    ``HTTP`` covers HTTPS: the scheme is part of the endpoint, and splitting
    them would produce two families with identical semantics and a
    ``tls`` flag that can only disagree with the URL it is meant to describe.
    ``TCP`` and ``UDP`` are separate because they genuinely differ — a UDP
    "connect" is a datagram with no handshake, so a probe that reports on one
    is not reporting on the other.
    """

    HTTP = "http"
    TCP = "tcp"
    UDP = "udp"
    DNS = "dns"
    GRPC = "grpc"
    SQL = "sql"
    REDIS = "redis"
    KAFKA = "kafka"
    RABBITMQ = "rabbitmq"
    NATS = "nats"
    PROCESS = "process"
    FILE = "file"
    COMMAND = "command"
    PROMETHEUS = "prometheus"
    OPENTELEMETRY = "opentelemetry"
    LOGS = "logs"
    TRACES = "traces"
    KUBERNETES = "kubernetes"
    SYNTHETIC = "synthetic"


class LifecycleStage(StrEnum):
    """The six stages of a probe's life, in the order a run walks them.

    These are the plan's own stage names, kept verbatim so an authored
    ``stages:`` list reads like the plan it comes from. What each stage *means*
    for evidence is the difference between observing and grading:

    ==========================  ========  ===================================
    stage                       phase     readings may support a verdict
    ==========================  ========  ===================================
    ``pre-baseline``            ``pre``   yes — they are the baseline
    ``warm-up``                 ``pre``   no — the budgeted settling window
    ``during-fault``            ``during``  yes
    ``continuous``              ``during``  yes, and spans pre and post too
    ``after-recovery``          ``post``  no — the budgeted settling window
    ``final-verification``      ``post``  yes — the proof the fault is gone
    ==========================  ========  ===================================

    ``warm-up`` and ``after-recovery`` are the two stages that exist so noise
    is *budgeted*: a probe in them is running, it is being recorded, and it may
    not yet say anything. Both require a declared duration on the definition
    (:attr:`ProbeDefinition.warmup`, :attr:`ProbeDefinition.cooldown`).
    """

    PRE_BASELINE = "pre-baseline"
    WARM_UP = "warm-up"
    DURING_FAULT = "during-fault"
    CONTINUOUS = "continuous"
    AFTER_RECOVERY = "after-recovery"
    FINAL_VERIFICATION = "final-verification"


class ProbeValueKind(StrEnum):
    """The shape of the reading a probe expects back.

    ``NUMERIC`` is every reading :class:`ObservationResult` can carry today
    (``value: float | None``). ``CATEGORICAL`` exists so the absence is
    *refusable* rather than merely documented: an author who wants a categorical
    probe can say so, and is told the observation contract has nowhere to put
    the value. See the module docstring — lifting this refusal is the same
    commit that adds a label to ``ObservationResult``.
    """

    NUMERIC = "numeric"
    CATEGORICAL = "categorical"


#: Stage → the phase that grades it. Every stage anchors to exactly one of the
#: three phases the verdict core defines; the values are the
#: ``steady_state_evaluations.phase`` spellings, so a stage cannot smuggle in a
#: fourth one.
_STAGE_PHASE: dict[LifecycleStage, Phase] = {
    LifecycleStage.PRE_BASELINE: Phase.PRE,
    LifecycleStage.WARM_UP: Phase.PRE,
    LifecycleStage.DURING_FAULT: Phase.DURING,
    LifecycleStage.CONTINUOUS: Phase.DURING,
    LifecycleStage.AFTER_RECOVERY: Phase.POST,
    LifecycleStage.FINAL_VERIFICATION: Phase.POST,
}

_PHASE_ORDER: tuple[Phase, ...] = (Phase.PRE, Phase.DURING, Phase.POST)

#: Stages whose readings repeat. A probe in one of these declares a cadence
#: above zero, because one reading where the plan asked for a stream is a
#: sample, not a series — and grading a trend off a single sample is how a
#: single spike is reported as a plateau.
_REPEATING_STAGES: frozenset[LifecycleStage] = frozenset(
    {
        LifecycleStage.WARM_UP,
        LifecycleStage.DURING_FAULT,
        LifecycleStage.CONTINUOUS,
        LifecycleStage.AFTER_RECOVERY,
    }
)

#: Stages whose readings are recorded but may not be graded, because they are
#: the budgeted settling windows.
_SETTLING_STAGES: tuple[LifecycleStage, ...] = (
    LifecycleStage.WARM_UP,
    LifecycleStage.AFTER_RECOVERY,
)

#: Every locator field a definition may carry. A probe is located by one of
#: these and by nothing else.
LOCATOR_FIELDS: tuple[str, ...] = (
    "endpoint",
    "query",
    "command",
    "path",
    "target",
    "steps",
)

#: The field that makes a definition *that* family. A probe that connects to
#: something is located by its address; a probe that asks something is located
#: by the question. Reachability is ``TCP``'s job, so a family listed here as
#: question-shaped will not accept a bare address as a substitute.
_REQUIRED_LOCATOR: dict[ProbeFamily, tuple[str, ...]] = {
    ProbeFamily.HTTP: ("endpoint",),
    ProbeFamily.TCP: ("endpoint",),
    ProbeFamily.UDP: ("endpoint",),
    ProbeFamily.DNS: ("query",),
    ProbeFamily.GRPC: ("endpoint",),
    ProbeFamily.SQL: ("query",),
    ProbeFamily.REDIS: ("query",),
    ProbeFamily.KAFKA: ("query",),
    ProbeFamily.RABBITMQ: ("query",),
    ProbeFamily.NATS: ("query",),
    ProbeFamily.PROCESS: ("target",),
    ProbeFamily.FILE: ("path",),
    ProbeFamily.COMMAND: ("command",),
    ProbeFamily.PROMETHEUS: ("query",),
    ProbeFamily.OPENTELEMETRY: ("query",),
    ProbeFamily.LOGS: ("query",),
    ProbeFamily.TRACES: ("query",),
    ProbeFamily.KUBERNETES: ("target", "query"),
    ProbeFamily.SYNTHETIC: ("steps",),
}

#: The member of the closed :data:`~mayhem.domain.checks.Probe` union a family
#: binds to, where one exists. A family absent from this table has no member in
#: that union, and a definition that claims one anyway is refused rather than
#: having its payload forced into a probe kind that does not mean it.
_CARRIER_TYPE: dict[ProbeFamily, ProbeType] = {
    ProbeFamily.HTTP: ProbeType.HTTP,
    ProbeFamily.TCP: ProbeType.TCP,
    ProbeFamily.PROCESS: ProbeType.PROCESS,
    ProbeFamily.FILE: ProbeType.FILE,
    ProbeFamily.COMMAND: ProbeType.EXEC,
    ProbeFamily.PROMETHEUS: ProbeType.METRIC,
}

#: The existing collector that will satisfy a definition, where one exists.
#: Absent means Phase 2 has not added that source kind yet — stated rather than
#: guessed, so a definition never claims a collection path that does not exist.
_SOURCE_KIND: dict[ProbeFamily, ObservabilitySourceKind] = {
    **dict.fromkeys(_CARRIER_TYPE, ObservabilitySourceKind.PROBE),
    ProbeFamily.PROMETHEUS: ObservabilitySourceKind.METRICS,
    ProbeFamily.LOGS: ObservabilitySourceKind.LOGS,
}

#: Which of a carrier's fields must agree with which of the definition's, for
#: the families where that comparison needs no parsing. ``(carrier_field,
#: locator_field)`` pairs; see
#: :meth:`ProbeDefinition._carrier_agrees_with_its_locators`.
_CARRIER_LOCATOR: dict[ProbeFamily, tuple[tuple[str, str], ...]] = {
    ProbeFamily.HTTP: (("url", "endpoint"),),
    ProbeFamily.FILE: (("path", "path"),),
    ProbeFamily.COMMAND: (("cmd", "command"),),
    ProbeFamily.PROCESS: (("name", "target"),),
    ProbeFamily.PROMETHEUS: (("endpoint", "endpoint"), ("query", "query")),
}

_HTTP_ENDPOINT = re.compile(r"^https?://[^\s]+$")


def stage_phase(stage: LifecycleStage) -> Phase:
    """The phase that grades readings taken in ``stage``."""
    return _STAGE_PHASE[stage]


def graded_stages(definition: ProbeDefinition) -> tuple[LifecycleStage, ...]:
    """The stages of ``definition`` whose readings may support a verdict.

    The module-level twin of :meth:`ProbeDefinition.graded_stages`, for callers
    holding a definition they are not ready to trust as well-formed (a plan
    being validated stage by stage, say).
    """
    excluded = set(_SETTLING_STAGES)
    return tuple(stage for stage in definition.stages if stage not in excluded)


# -- the definition -----------------------------------------------------------------


class ProbeDefinition(BaseModel):
    """One probe, as data: where it points, what it asks, how often, when.

    The catalogue entry for a probe family. It is *not* a probe: it names the
    :data:`~mayhem.domain.checks.Probe` that will carry it, the ``VerifyProbe``
    that will prove the fault is gone, the phase its readings belong to, and
    the unit its readings must be in. Reading it performs nothing.

    Every field is either the thing being probed (``endpoint``, ``query``,
    ``command``, ``path``, ``target``, ``steps``) or a control on the
    observation schedule (``cadence``, ``window``, ``warmup``, ``cooldown``,
    ``stages``). Locators are strings and tuples, not nested models: a probe
    definition is a thing an author writes in YAML, and a family-specific
    sub-model per family is the hierarchy this module exists to avoid.
    """

    model_config = ConfigDict(frozen=True)

    # -- identity ----------------------------------------------------------------
    id: Identifier
    family: ProbeFamily
    version: ProbeVersion
    unit: str = Field(min_length=1)
    description: str = ""

    # -- locators ----------------------------------------------------------------
    endpoint: str = ""
    query: str = ""
    command: tuple[str, ...] = ()
    path: str = ""
    target: str = ""
    steps: tuple[str, ...] = ()

    # -- the vocabulary this definition extends --------------------------------
    value_kind: ProbeValueKind = ProbeValueKind.NUMERIC
    carrier: Probe | None = None
    verify: VerifyProbe | None = None
    source_kind: ObservabilitySourceKind | None = None

    # -- schedule ----------------------------------------------------------------
    cadence: Duration = 5.0
    window: Duration = 10.0
    stages: tuple[LifecycleStage, ...] = ()
    warmup: Duration = 0.0
    cooldown: Duration = 0.0

    @model_validator(mode="after")
    def _unit_is_a_unit(self) -> ProbeDefinition:
        if not self.unit.strip():
            raise InvariantViolationError(
                "probes.probe_unit_blank",
                f"probe {self.id!r} declares a blank unit: a unit is what makes a "
                "reading comparable, and whitespace cannot be compared with",
            )
        return self

    @model_validator(mode="after")
    def _locator_is_declared(self) -> ProbeDefinition:
        """A family is defined by its locator; without one it is a name."""
        required = _REQUIRED_LOCATOR[self.family]
        if not any(_present(self, field) for field in required):
            expected = " or ".join(f"{field!r}" for field in required)
            raise InvariantViolationError(
                "probes.probe_without_locator",
                f"probe {self.id!r} is a {self.family.value} probe and declares no "
                f"{expected}: a {self.family.value} probe is defined by the thing it "
                f"{'asks' if required[0] == 'query' else 'is pointed at'}, and with "
                "neither an endpoint nor a query it resolves to nothing — a probe that "
                "resolves to nothing is indistinguishable from a system that is fine",
            )
        return self

    @model_validator(mode="after")
    def _http_endpoint_is_absolute(self) -> ProbeDefinition:
        if self.family is not ProbeFamily.HTTP or not self.endpoint.strip():
            return self
        if not _HTTP_ENDPOINT.match(self.endpoint.strip()):
            raise InvariantViolationError(
                "probes.http_endpoint_not_absolute",
                f"probe {self.id!r} is an http probe with endpoint "
                f"{self.endpoint!r}: an http probe needs an absolute http:// or "
                "https:// URL, and a relative path here would resolve against "
                "whatever base the collector happened to assume",
            )
        return self

    @model_validator(mode="after")
    def _carrier_matches_family(self) -> ProbeDefinition:
        """The carrier must be a probe of this family, or there must be none."""
        expected = _CARRIER_TYPE.get(self.family)
        if self.carrier is None:
            return self
        if expected is None:
            raise InvariantViolationError(
                "probes.probe_carrier_unsupported",
                f"probe {self.id!r} is a {self.family.value} probe and names a "
                f"{self.carrier.type.value} carrier, but no member of the closed Probe "
                "union means a "
                f"{self.family.value} probe: carrying it in a probe kind that does not "
                f"describe it is a second probe hierarchy wearing a {self.family.value} "
                "label. Declare the endpoint and query as data and let Phase 2 bind a "
                "collector",
            )
        if self.carrier.type is not expected:
            raise InvariantViolationError(
                "probes.probe_carrier_mismatch",
                f"probe {self.id!r} is a {self.family.value} probe carrying a "
                f"{self.carrier.type.value} probe: a {self.family.value} definition is "
                f"carried by a {expected.value} probe, and the two disagreeing means "
                "one of them is wrong about what this probe is",
            )
        return self

    @model_validator(mode="after")
    def _source_kind_matches_family(self) -> ProbeDefinition:
        expected = _SOURCE_KIND.get(self.family)
        if self.source_kind is None:
            return self
        if expected is None:
            raise InvariantViolationError(
                "probes.probe_source_kind_unsupported",
                f"probe {self.id!r} is a {self.family.value} probe and names the "
                f"{self.source_kind.value!r} source kind, but no existing source kind "
                "collects a "
                f"{self.family.value} probe: naming one means the definition was "
                "checked against a collection path that does not exist. Leave it unset "
                "until the engine adds the kind",
            )
        if self.source_kind is not expected:
            raise InvariantViolationError(
                "probes.probe_source_kind_mismatch",
                f"probe {self.id!r} is a {self.family.value} probe and names the "
                f"{self.source_kind.value!r} source kind, but a {self.family.value} "
                f"probe is collected by the {expected.value!r} source: declaring a "
                "collection path the family does not use means the definition was "
                "checked against nothing",
            )
        return self

    @model_validator(mode="after")
    def _carrier_agrees_with_its_locators(self) -> ProbeDefinition:
        """A definition and its carrier must describe the same probe.

        Only the carriers whose locator is a single comparable string are
        cross-checked. A contradiction is refused (both sides stated something
        and they differ); an omission is not, because a definition may leave a
        locator for the collector to fill in. ``TCP`` is deliberately absent:
        its endpoint is an address the carrier carries as ``host`` + ``port``,
        and this module will not invent a parsing rule for one to compare
        against.
        """
        if self.carrier is None:
            return self
        for carrier_field, locator_field in _CARRIER_LOCATOR.get(self.family, ()):
            carried = _as_text(getattr(self.carrier, carrier_field))
            declared = _as_text(getattr(self, locator_field))
            if carried and declared and carried != declared:
                raise InvariantViolationError(
                    "probes.probe_carrier_locator_conflict",
                    f"probe {self.id!r} declares {locator_field}={declared!r} but its "
                    f"carrier points at {carried!r}: the definition and the carrier "
                    "describe two different probes under one id, and which of them the "
                    "collector honours would be a coin flip",
                )
        return self

    @model_validator(mode="after")
    def _value_kind_is_supported(self) -> ProbeDefinition:
        """Refuse a categorical probe while observations cannot carry one."""
        if self.value_kind is ProbeValueKind.NUMERIC:
            return self
        raise InvariantViolationError(
            CATEGORICAL_REFUSAL_CODE,
            f"probe {self.id!r} asks for a categorical reading, but "
            "ObservationResult.value is float | None and carries no label, enum or "
            "string to compare: there is nothing for a categorical tolerance to "
            "compare. ToleranceKind has no categorical mechanism for the same reason. "
            "Until the observation contract carries a non-numeric value, a categorical "
            "probe can only be recorded as data — adding the tolerance without the "
            "value would make it pass or fail on nothing",
        )

    @model_validator(mode="after")
    def _declares_lifecycle(self) -> ProbeDefinition:
        if not self.stages:
            raise InvariantViolationError(
                "probes.probe_without_stage",
                f"probe {self.id!r} declares no lifecycle stage: a probe that is not "
                "scheduled anywhere runs whenever the collector happens to reach it, "
                "and a baseline captured mid-fault is a baseline of the perturbation",
            )
        seen: set[LifecycleStage] = set()
        for stage in self.stages:
            if stage in seen:
                raise InvariantViolationError(
                    "probes.probe_duplicate_stage",
                    f"probe {self.id!r} declares stage {stage.value!r} twice: a probe "
                    "is either in a stage or not, and listing it twice reads as a "
                    "second membership nobody can honour",
                )
            seen.add(stage)
        return self

    @model_validator(mode="after")
    def _continuous_spans_the_run(self) -> ProbeDefinition:
        """``continuous`` means every window, so it must say so at both ends.

        A probe that only claims ``continuous`` has unclaimed readings at both
        ends of the run — it is a probe during the fault and nothing before or
        after, which is what ``during-fault`` is for. Saying ``continuous``
        while declaring one stage is how a probe gets a name that promises
        coverage it does not have.
        """
        if LifecycleStage.CONTINUOUS not in self.stages:
            return self
        missing = [
            stage.value
            for stage in (LifecycleStage.PRE_BASELINE, LifecycleStage.FINAL_VERIFICATION)
            if stage not in self.stages
        ]
        if missing:
            raise InvariantViolationError(
                "probes.probe_continuous_not_spanning",
                f"probe {self.id!r} claims the continuous stage but does not declare "
                f"{' and '.join(missing)}: continuous means the whole run, and a probe "
                "that only watches the fault window is a during-fault probe. Either "
                "declare the stages it spans, or drop continuous",
            )
        return self

    @model_validator(mode="after")
    def _noise_is_budgeted(self) -> ProbeDefinition:
        """A settling stage and its budget are the same declaration.

        Both directions are refused. A stage with no budget is a settling
        window of unknown length, which is discovered mid-verdict. A budget
        with no stage is a number that never affects a reading, which is worse,
        because the author believes it did.
        """
        warmup_s, cooldown_s = float(self.warmup), float(self.cooldown)
        pairs = (
            (LifecycleStage.WARM_UP, warmup_s, "warmup"),
            (LifecycleStage.AFTER_RECOVERY, cooldown_s, "cooldown"),
        )
        for stage, budget, field in pairs:
            member = stage in self.stages
            if member and budget <= 0.0:
                raise InvariantViolationError(
                    "probes.probe_noise_budget_missing",
                    f"probe {self.id!r} is in the {stage.value} stage but declares no "
                    f"{field}: that stage exists to budget settling time. Without a "
                    "budget, noise is discovered in the middle of a verdict rather "
                    f"than declared up front, which is the whole point of {stage.value}",
                )
            if budget > 0.0 and not member:
                raise InvariantViolationError(
                    "probes.probe_noise_budget_unclaimed",
                    f"probe {self.id!r} declares {field}={budget:g}s but is not in the "
                    f"{stage.value} stage: the budget is spent on a stage this probe is "
                    "not in, so it reads as a control and does nothing. Add the stage, "
                    "or drop the budget",
                )
        return self

    @model_validator(mode="after")
    def _cadence_matches_stages(self) -> ProbeDefinition:
        """A repeating stage needs a stream; a one-shot stage needs one reading."""
        cadence_s = float(self.cadence)
        if cadence_s > 0.0:
            return self
        repeating = [stage.value for stage in self.stages if stage in _REPEATING_STAGES]
        if repeating:
            raise InvariantViolationError(
                "probes.probe_cadence_conflicts_with_stages",
                f"probe {self.id!r} declares a cadence of 0 (collect once) but is in "
                f"the repeating stage(s) {', '.join(repeating)}: one reading where the "
                "plan asked for a series is a sample, and a trend graded off a single "
                "sample is a spike reported as a plateau. Give it a cadence, or move it "
                "to a one-shot stage",
            )
        return self

    # -- introspection -----------------------------------------------------------

    @property
    def phases(self) -> tuple[Phase, ...]:
        """Every phase this probe's readings belong to, in phase order.

        Derived, never declared: a probe that stated its own phase could
        disagree with its stages, and there would then be no way to tell which
        one the verdict core should believe.
        """
        anchored = {stage_phase(stage) for stage in self.stages}
        return tuple(phase for phase in _PHASE_ORDER if phase in anchored)

    def stages_in_phase(self, phase: Phase) -> tuple[LifecycleStage, ...]:
        """The stages of this probe that grade in ``phase``."""
        return tuple(stage for stage in self.stages if stage_phase(stage) is phase)

    @property
    def excluded_stages(self) -> tuple[LifecycleStage, ...]:
        """The declared stages whose readings are recorded but not graded."""
        return tuple(stage for stage in _SETTLING_STAGES if stage in self.stages)

    @property
    def graded_stages(self) -> tuple[LifecycleStage, ...]:
        """The declared stages whose readings may support a verdict."""
        excluded = set(self.excluded_stages)
        return tuple(stage for stage in self.stages if stage not in excluded)

    @property
    def planned_samples(self) -> int:
        """How many readings ``window`` buys at ``cadence``.

        Informational, and deliberately not a policy:
        :class:`~mayhem.domain.steady_state.CaptureSpec` owns how many samples a
        baseline needs, and it reports an under-sampled one as insufficient
        rather than grading it. A pre-baseline probe that plans one sample
        therefore gets told so by the verdict core — it does not get a second
        opinion from here.
        """
        window_s, cadence_s = float(self.window), float(self.cadence)
        if cadence_s <= 0.0:
            return 1
        return max(1, int(window_s // cadence_s))

    @property
    def carrier_type(self) -> ProbeType | None:
        """The closed-union member this family is carried by, if it has one."""
        return _CARRIER_TYPE.get(self.family)

    @property
    def expected_source_kind(self) -> ObservabilitySourceKind | None:
        """The existing collector that satisfies this family, if one does."""
        return _SOURCE_KIND.get(self.family)

    @property
    def locator(self) -> str:
        """The locator this family is defined by, rendered for a message.

        The family's own required locator first — for a DNS probe that is the
        name it resolves, not the resolver it asks — then any other locator it
        happens to carry, in :data:`LOCATOR_FIELDS` order. For messages and
        diagnostics, not for grading: a definition may be located by more than
        one thing, and only the family knows which one is the point.
        """
        ordered = _REQUIRED_LOCATOR[self.family] + tuple(
            field for field in LOCATOR_FIELDS if field not in _REQUIRED_LOCATOR[self.family]
        )
        for field in ordered:
            if not _present(self, field):
                continue
            value = getattr(self, field)
            return " ".join(value) if isinstance(value, tuple) else value
        return ""  # pragma: no cover - _locator_is_declared refuses this first

    @property
    def fingerprint(self) -> ProbeFingerprint:
        """A canonical digest of everything about this probe except its prose.

        What is excluded is :attr:`description` and nothing else. A pin answers
        *"would this probe behave the same way?"*, and a reworded description
        does not change a single reading — including it would make every doc
        edit churn every plan that pins this probe, and the honest response to
        that churn would be to stop pinning.
        """
        payload = self.model_dump(mode="json", exclude={"description"})
        return digest(payload)

    # -- readings ----------------------------------------------------------------

    def unit_matches(self, reading: ObservationResult) -> bool:
        """Is this reading in the unit this probe declared?

        Identity, compared case-insensitively and whitespace-trimmed, and
        nothing else. No conversion: a probe declared in ``ms`` handed ``0.25``
        with a unit of ``s`` is a unit error, and converting it silently would
        mean the tool decided on the author's behalf that two different
        quantities were the same one.
        """
        return reading.unit.strip().casefold() == self.unit.strip().casefold()

    def check_reading(self, reading: ObservationResult) -> None:
        """Refuse a reading whose unit is not the one this probe declared.

        The collection-time twin of a threshold's unit: comparing 250 against
        0.25 produces a confident number about nothing, which is the exact
        failure this plan exists to prevent.
        """
        if self.unit_matches(reading):
            return
        raise InvariantViolationError(
            "probes.probe_reading_unit_mismatch",
            f"probe {self.id!r} declares unit {self.unit!r} but reading "
            f"{reading.metric!r} arrived in {reading.unit!r}: a reading in another "
            "unit is not a measurement of this probe. Convert it where the value is "
            "produced, or declare the unit the source really emits — never both",
        )


def _present(definition: ProbeDefinition, field: str) -> bool:
    """Does this locator carry anything? Whitespace is not anything."""
    value = getattr(definition, field)
    if isinstance(value, str):
        return bool(value.strip())
    return bool(value)


def _as_text(value: object) -> str:
    """Render a locator for comparison: trimmed text, or argv joined by spaces."""
    if isinstance(value, (tuple, list)):
        return " ".join(str(part) for part in value)
    return str(value).strip()


# -- pinning into a plan ------------------------------------------------------------


class ProbePin(BaseModel):
    """A plan's claim about one probe: which one, which version, which bytes.

    The version alone is not a pin, and this is the reason for the third field:
    a definition edited in place keeps its version, so a version-only pin would
    happily verify a plan against a probe that now asks a different question.
    The :attr:`fingerprint` is what catches that, and it is required — a pin
    that could be satisfied by a version string alone is not a pin.
    """

    model_config = ConfigDict(frozen=True)

    id: Identifier
    version: ProbeVersion
    fingerprint: ProbeFingerprint

    @classmethod
    def of(cls, definition: ProbeDefinition) -> ProbePin:
        """Pin a definition exactly as it is now."""
        return cls(
            id=definition.id,
            version=definition.version,
            fingerprint=definition.fingerprint,
        )

    @property
    def describe(self) -> str:
        return f"{self.id}@{self.version}"


class ProbePlan(BaseModel):
    """The probes a run is authorised to use, each pinned to one version.

    This is the "pinnable into a plan" half of the versioning commitment, and it
    holds pins rather than definitions on purpose: a plan that embedded the
    definitions would be unable to notice that the catalogue moved underneath
    it, which is the entire failure mode pinning exists to catch.
    """

    model_config = ConfigDict(frozen=True)

    pins: tuple[ProbePin, ...] = ()

    @model_validator(mode="after")
    def _authorises_something(self) -> ProbePlan:
        if not self.pins:
            raise InvariantViolationError(
                "probes.empty_plan",
                "a probe plan pins no probes: it would authorise no observation and "
                "read as a plan that watched the whole system and found nothing wrong",
            )
        seen: set[str] = set()
        for pin in self.pins:
            if pin.id in seen:
                raise InvariantViolationError(
                    "probes.duplicate_pin",
                    f"probe plan pins {pin.describe!r} more than once: a plan authorises "
                    "each probe at one version, and two pins for one probe means two "
                    "different intentions nobody can tell apart",
                )
            seen.add(pin.id)
        return self

    def pin_for(self, probe_id: str) -> ProbePin | None:
        """The pin for ``probe_id``, or ``None`` when the plan does not authorise it."""
        for pin in self.pins:
            if pin.id == probe_id:
                return pin
        return None

    def bind(self, catalogue: ProbeCatalog) -> tuple[ProbeDefinition, ...]:
        """Resolve every pin against ``catalogue``, in pin order. Refuses on drift.

        Three refusals, and the third is the one a version number cannot do:

        ``probes.unpinned_probe``
            the plan names a probe the catalogue does not have. A plan that
            cannot resolve a probe would run without it, and the report would
            never mention the probe that was missing.
        ``probes.probe_version_drift``
            the catalogue's version has moved since the plan was written. The
            definition is different, and the plan was authorised against
            something else.
        ``probes.probe_definition_drift``
            the version matches and the bytes do not: the definition was edited
            without a version bump. This is the drift a version-only pin
            reports as healthy, and it is why :class:`ProbePin` requires a
            fingerprint.
        """
        return tuple(catalogue.resolve(pin) for pin in self.pins)

    def assert_resolvable(self, catalogue: ProbeCatalog) -> None:
        """Refuse drift now, before a run starts.

        The authoring-time twin of :meth:`bind`; it performs the same checks and
        reports nothing, for preflight and for validation that wants the
        assertion rather than the definitions.
        """
        self.bind(catalogue)

    def covers(self, definition: ProbeDefinition) -> bool:
        """Does this plan authorise ``definition``, at the version it pins?"""
        pin = self.pin_for(definition.id)
        return pin is not None and pin.version == definition.version


class ProbeCatalog(BaseModel):
    """Every probe definition a run may use, one per id."""

    model_config = ConfigDict(frozen=True)

    definitions: tuple[ProbeDefinition, ...] = ()

    @model_validator(mode="after")
    def _catalogue_holds_something(self) -> ProbeCatalog:
        if not self.definitions:
            raise InvariantViolationError(
                "probes.empty_catalogue",
                "a probe catalogue holds no definitions: every plan would then be "
                "unresolvable, and a run that authorised no probe is a run that "
                "watched nothing",
            )
        seen: set[str] = set()
        for definition in self.definitions:
            if definition.id in seen:
                raise InvariantViolationError(
                    "probes.duplicate_probe_id",
                    f"catalogue holds two definitions for probe {definition.id!r}: one "
                    "probe id must address exactly one definition, or a plan pinning "
                    "that id could not say which of them it meant",
                )
            seen.add(definition.id)
        return self

    def get(self, probe_id: str) -> ProbeDefinition:
        """The definition for ``probe_id``. Refuses rather than returning ``None``.

        ``None`` for a missing probe is the same trap as a stop condition whose
        metric resolves to nothing: the caller treats absence as "no problem
        here" and says so in a report.
        """
        definition = self._lookup(probe_id)
        if definition is not None:
            return definition
        raise InvariantViolationError(
            "probes.unknown_probe",
            f"no probe definition for id {probe_id!r} in a catalogue of "
            f"{[definition.id for definition in self.definitions]}: an unresolvable "
            "probe is a probe that never runs",
        )

    def _lookup(self, probe_id: str) -> ProbeDefinition | None:
        for definition in self.definitions:
            if definition.id == probe_id:
                return definition
        return None

    def resolve(self, pin: ProbePin) -> ProbeDefinition:
        """Resolve one pin, refusing drift in either direction.

        See :meth:`ProbePlan.bind` for why there are three refusals rather than
        one.
        """
        definition = self._lookup(pin.id)
        if definition is None:
            raise InvariantViolationError(
                "probes.unpinned_probe",
                f"probe plan pins {pin.describe!r}, which this catalogue does not "
                f"define (it holds {[each.id for each in self.definitions]}): a plan "
                "that cannot resolve a probe would run without it, and the report "
                "would never mention the probe that was missing",
            )
        if definition.version != pin.version:
            raise InvariantViolationError(
                "probes.probe_version_drift",
                f"probe {pin.id!r} is pinned at {pin.version} but the catalogue "
                f"defines {definition.version}: the run was authorised against a "
                "different probe than the one that exists now",
            )
        if definition.fingerprint != pin.fingerprint:
            raise InvariantViolationError(
                "probes.probe_definition_drift",
                f"probe {pin.id!r} still claims version {pin.version} but its definition "
                f"has changed (pinned {pin.fingerprint[:12]}…, catalogue "
                f"{definition.fingerprint[:12]}…): a probe edited without a version "
                "bump verifies against a plan that never approved it. Bump the "
                "version, or re-pin deliberately",
            )
        return definition

    def select(
        self,
        *,
        family: ProbeFamily | None = None,
        stage: LifecycleStage | None = None,
        phase: Phase | None = None,
    ) -> tuple[ProbeDefinition, ...]:
        """Definitions matching every filter given, in catalogue order."""
        return tuple(
            definition
            for definition in self.definitions
            if (family is None or definition.family is family)
            and (stage is None or stage in definition.stages)
            and (phase is None or phase in definition.phases)
        )

    def pins(self) -> tuple[ProbePin, ...]:
        """Pin every definition, in catalogue order."""
        return tuple(ProbePin.of(definition) for definition in self.definitions)

    def plan(self) -> ProbePlan:
        """A plan authorising exactly this catalogue, at the versions it holds."""
        return ProbePlan(pins=self.pins())


ProbeDefinition.model_rebuild()
ProbePin.model_rebuild()
ProbePlan.model_rebuild()
ProbeCatalog.model_rebuild()
