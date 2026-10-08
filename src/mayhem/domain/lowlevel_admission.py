"""The admission gate for plan 04's low-level primitives — Phase 4.

What this module decides, and what it does not
----------------------------------------------
Plan 04's Phase 2 could not implement a single mechanism, so the fault catalog
refuses eighteen primitives. That leaves a real question with no good answer in
any other file: **when mayhem is asked to inject one anyway, what does it do?**

The answers this module makes available are: refuse it, and say why. It never
substitutes a weaker mechanism, never downgrades a magnitude, and never returns
a "close enough" report. Those are not policies applied here — they are
*unrepresentable*. :class:`LowLevelRequest` has no field for a fallback, and
:class:`AdmissionReport` has no field for one either, for the same reason
:class:`~mayhem.domain.lowlevel.MissingMechanism` has no ``substitute``: a type
that can hold a substitute is a type that will eventually hold one.

The split this module exists to hold
------------------------------------
* the **decision** — is this request admissible on this substrate, for this
  engine, at this magnitude, alongside these other primitives — is pure, total,
  and testable without a kernel;
* the **mechanism** — attaching an eBPF program, mounting a FUSE shim, loading a
  JVM agent — is behind :class:`MechanismPort`, and **no port is bound in this
  build**.

An unbound port, a port that raises, a port that answers ``None``, and a port
that answers in the wrong shape are all ``UNAVAILABLE``, and ``UNAVAILABLE``
refuses. That is the same rule
:mod:`mayhem.controller.preflight_gate` applies, for the same reason: *mayhem
cannot see an eBPF loader, so it cannot certify that one attached.* The absence
of the ability to ask is not an answer, and a gate that answers anyway is worse
than no gate.

Deliberately absent, and why
----------------------------

* **No impact-gate ``REQUIREMENTS`` row.** The plan asks for one per primitive,
  and Phase 2 already recorded why none was added: a row would gate a fault that
  has no tooling to probe, and every bin these descriptors demand
  (``bpftool``, ``jcmd``, ``dmsetup``, ``fusermount3``, ``mount``) is absent
  from ``agents/impact.py``'s ``_PROBE_BINS`` — so the row would be an INERT
  gate that reads as a passing one. :func:`requirements_rows_needed` answers the
  question as data instead of as a row, and ``tests/unit/test_lowlevel_admission.py``
  pins the reason it currently returns nothing.
* **No collision-graph registration.** :func:`collision_edges` *derives* the
  edges plan 07's graph needs from the descriptors' own
  :meth:`~mayhem.domain.lowlevel.LowLevelPrimitive.incompatible_ids`, and this
  lane does not write into ``domain/policy.py``'s bundle. What integration has to
  do is said in the plan's Phase 4 STATUS line, not guessed at here.
* **No evidence write.** Nothing here persists, so there is no
  ``BOUNDARY_CALL_SITES`` row owed: the gate produces a value, and a caller that
  writes it is a caller that owns the write path.
* **No ``kubernetes`` support, for every family.** All four mechanisms are
  *in-image* injections: they need binaries in the image and capabilities inside
  the container. mayhem's Kubernetes adapter writes neither ``cap_add`` nor a
  host ``debugfs`` mount into a pod spec, so a kernel attach that works under
  Podman cannot be attempted under Kubernetes, and the gate says so rather than
  trying. :data:`SUPPORTED_ENGINES` is the whole of that claim, in one constant.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.lowlevel import (
    CURRENT_SUBSTRATE,
    PRIMITIVES,
    AttachSpecification,
    GapReason,
    LowLevelPrimitive,
    SubstrateSurface,
    resolve_params,
    specification_for,
)
from mayhem.domain.lowlevel_report import PrimitiveDisposition, explain_primitive
from mayhem.domain.policy import (
    CompatibilityEdge,
    CompatibilityVerdict,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

__all__ = [
    "ALL_CHECKS",
    "CHECK_COLLISION_PAIRS",
    "CHECK_DURATION",
    "CHECK_ENGINE",
    "CHECK_PARAMETERS",
    "CHECK_PRIMITIVE_KNOWN",
    "CHECK_SUBSTRATE",
    "MIN_OBSERVABLE_FRACTION",
    "SUPPORTED_ENGINES",
    "AdmissionReport",
    "LowLevelCheck",
    "LowLevelRefusedError",
    "LowLevelRequest",
    "LowLevelStatus",
    "MechanismObservation",
    "MechanismPort",
    "ResidueObservation",
    "ResiduePass",
    "ResidueProbe",
    "ResidueScan",
    "admit",
    "collision_edges",
    "declared_unbound_ports",
    "disposition_of",
    "evaluate",
    "inert_demands",
    "mechanism_ref",
    "primitive_ref",
    "refuses_gate",
    "refusing_names",
    "request_ref",
    "requirements_rows_needed",
    "residue_scan",
    "scan_after_recovery",
    "unprobeable_demands",
]


# =============================================================================
# Statuses, and the one predicate that decides them
# =============================================================================


class LowLevelStatus(StrEnum):
    """What one admission check concluded. Three members and no more.

    ``UNAVAILABLE`` is not a soft ``REFUSED``. A refused check is "mayhem looked
    and the answer was no"; an unavailable one is "mayhem had no way to look".
    Both block, and the difference is what an operator triaging at 3am needs:
    one is an environment finding, the other is a wiring finding.
    """

    PASS = "pass"
    REFUSED = "refused"
    UNAVAILABLE = "unavailable"


def refuses_gate(status: LowLevelStatus) -> bool:
    """True for every status that blocks. Total over :class:`LowLevelStatus`.

    Written ``is not PASS`` so that a status this build does not recognise
    refuses rather than passes by omission — the same asymmetry
    :func:`mayhem.controller.preflight_gate.refuses_gate` states for the same
    reason.
    """
    return status is not LowLevelStatus.PASS


#: The engines a low-level injection can be attempted on.
#:
#: Docker and Podman, and nothing else. Every mechanism plan 04 describes is
#: in-image: it needs a binary inside the image (``bpftool``, ``jcmd``,
#: ``dmsetup``) and a capability inside the container (``SYS_ADMIN``, ``SYS_TIME``).
#: mayhem's Kubernetes adapter sets neither on a pod spec, so "attempt it under
#: Kubernetes anyway" would be a *different fault* with a different blast radius
#: — an agent running with the pod's own privileges rather than a container
#: root. The gate refuses the combination by name instead of trying it and
#: reporting the difference later.
SUPPORTED_ENGINES: Final[frozenset[str]] = frozenset({"docker", "podman"})


# =============================================================================
# The mechanism port: the privileged half, unbound in this build
# =============================================================================


class MechanismObservationError(InvariantViolationError):
    """A mechanism port answered in a shape the gate cannot read.

    An :class:`~mayhem.domain.errors.InvariantViolationError` so it carries a
    ``rule`` a test can assert. It is *not* raised by the gate: the gate turns a
    wrong-shaped answer into ``UNAVAILABLE`` and records it, so one misbehaving
    port cannot abort an admission pass. It exists so a port implementation has
    something to raise when it is about to return the wrong shape.
    """


@dataclass(frozen=True, slots=True)
class MechanismObservation:
    """One mechanism answer, in the only shape a port is allowed to answer in.

    ``available`` and ``applied`` are separate because "the loader is present"
    and "the loader is attached to this target right now" are different facts,
    and a single boolean would have to mean one of them in every call site.
    ``evidence_ref`` is required on **every** observation including the negative
    ones: an ``UNAVAILABLE`` still has to say what mayhem tried to reach, or the
    refusal names no witness.
    """

    available: bool
    applied: bool
    evidence_ref: str
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.evidence_ref.strip():
            msg = "a mechanism observation must cite something, even when it reports nothing"
            raise MechanismObservationError("lowlevel.mechanism_evidence_required", msg)
        if self.applied and not self.available:
            msg = (
                "a mechanism cannot be applied while reporting itself unavailable: the "
                "two facts come from the same answer"
            )
            raise MechanismObservationError("lowlevel.mechanism_applied_without_available", msg)

    def to_dict(self) -> dict[str, object]:
        return {
            "available": self.available,
            "applied": self.applied,
            "evidence_ref": self.evidence_ref,
            "detail": self.detail,
        }


@runtime_checkable
class MechanismPort(Protocol):
    """The privileged operations, behind one port.

    Four methods because a mechanism has four moments, and the gate asks about
    each one separately so that a failure at *probe* time is never confused with a
    failure at *undo* time — the difference between "mayhem cannot load a program"
    and "mayhem loaded one and cannot detach it".

    **No implementation of this protocol exists in this repository, and the gate
    treats ``None`` as ``UNAVAILABLE`` rather than as "nothing to do".**
    """

    def probe(self, primitive: LowLevelPrimitive) -> MechanismObservation:
        """Can this host attach the primitive's mechanism at all?"""

    def attach(self, specification: AttachSpecification) -> MechanismObservation:
        """Attach it, and report whether it is attached."""

    def detach(self, specification: AttachSpecification) -> MechanismObservation:
        """Remove it. The undo, asked about separately from the injection."""

    def residue(self, specification: AttachSpecification) -> MechanismObservation:
        """Look at the descriptor's residue checks and report what was seen."""


#: The ports the gate reads, named. Every field defaults to ``None``, and ``None``
#: means ``UNAVAILABLE``. There is intentionally no "no ports configured, assume
#: available" default: that default *is* the bug this module exists to prevent.
@dataclass(frozen=True, slots=True)
class MechanismPorts:
    """The mechanism seam. Unbound by default, and unbound means refusing."""

    mechanism: MechanismPort | None = None

    def bound(self) -> tuple[str, ...]:
        """Which ports are actually bound, in declaration order."""
        return ("mechanism",) if self.mechanism is not None else ()


def declared_unbound_ports() -> tuple[str, ...]:
    """The port names this build leaves unbound, in one place.

    A surface can print it, so "nothing is attached" is a statement mayhem makes
    rather than one a reader has to infer from an absence.
    """
    return ("mechanism",)


# =============================================================================
# The request
# =============================================================================


@dataclass(frozen=True, slots=True)
class LowLevelRequest:
    """One request to inject one low-level primitive.

    There is no ``fallback_to``, no ``if_unavailable``, and no ``force``. Each of
    those would be a place for a weaker mechanism to be substituted for the one
    that was asked for, and the plan's rule is that a refusal names the missing
    mechanism rather than offering a stand-in.

    ``active_primitives`` is the *already-running* set for this drill, which is
    what makes the incompatibility check meaningful: two primitives that could
    not be attributed independently cannot both be live, and only the set tells
    the gate that.
    """

    primitive_id: str
    engine: str
    duration_s: float
    params: Mapping[str, object] = field(default_factory=dict)
    active_primitives: tuple[str, ...] = ()
    request_id: str = ""

    def __post_init__(self) -> None:
        if not self.primitive_id.strip():
            msg = "a low-level request must name the primitive it asks for"
            raise InvariantViolationError("lowlevel.request_primitive_blank", msg)
        if not self.engine.strip():
            msg = "a low-level request must name the engine it would run on"
            raise InvariantViolationError("lowlevel.request_engine_blank", msg)
        if self.duration_s <= 0.0:
            msg = f"duration_s must be positive; got {self.duration_s!r}"
            raise InvariantViolationError("lowlevel.request_duration_not_positive", msg)


# =============================================================================
# Checks and the report
# =============================================================================


@dataclass(frozen=True, slots=True)
class LowLevelCheck:
    """One check, its verdict, and the witness behind it.

    A non-blank ``evidence_ref`` is required on every status, for
    :mod:`mayhem.controller.preflight_gate`'s reason: the refusal is what an
    operator acts on at 3am *and* what an auditor re-reads a week later, so it
    has to say what was looked at.
    """

    name: str
    status: LowLevelStatus
    detail: str
    evidence_ref: str

    def __post_init__(self) -> None:
        for field_name in ("name", "detail", "evidence_ref"):
            if not getattr(self, field_name).strip():
                msg = f"a low-level check's {field_name} must be non-blank"
                raise InvariantViolationError("lowlevel.check_field_not_blank", msg)

    @property
    def refuses(self) -> bool:
        """Whether this check, on its own, blocks the request."""
        return refuses_gate(self.status)

    def describe(self) -> str:
        return f"{self.name}={self.status.value} ({self.evidence_ref})"


@dataclass(frozen=True, slots=True)
class AdmissionReport:
    """The gate's verdict, and every check it reached to form one.

    :attr:`applied_primitive` is ``None`` on every report this build produces,
    and that is the whole claim: no mechanism is bound, so the gate cannot reach
    the check that would set it. There is deliberately no field for "a weaker
    mechanism was used instead", so the failure mode of a future maintainer
    reaching for one is a type error rather than a silent downgrade.
    """

    request: LowLevelRequest
    checks: tuple[LowLevelCheck, ...]
    applied_primitive: str | None = None
    specification: AttachSpecification | None = None

    def __post_init__(self) -> None:
        names = [check.name for check in self.checks]
        if len(set(names)) != len(names):
            repeated = sorted({name for name in names if names.count(name) > 1})
            msg = f"the gate repeats a check: {repeated}"
            raise InvariantViolationError("lowlevel.duplicate_check", msg)

    @property
    def refusing_checks(self) -> tuple[LowLevelCheck, ...]:
        """Every check that blocks, in report order."""
        return tuple(check for check in self.checks if check.refuses)

    @property
    def refused_checks(self) -> tuple[LowLevelCheck, ...]:
        """Only those that were reached and answered ``REFUSED``."""
        return tuple(check for check in self.checks if check.status is LowLevelStatus.REFUSED)

    @property
    def unavailable_checks(self) -> tuple[LowLevelCheck, ...]:
        """Only those with no witness at all."""
        return tuple(check for check in self.checks if check.status is LowLevelStatus.UNAVAILABLE)

    @property
    def vacuous(self) -> bool:
        """True when the gate evaluated nothing.

        And a vacuous report never grants: a gate with an empty catalogue would
        otherwise report "every check passed" about zero checks, which in a log
        reads exactly like a gate that verified everything.
        """
        return not self.checks

    @property
    def granted(self) -> bool:
        """Whether the injection may proceed: something ran, and nothing refuses."""
        return not self.vacuous and not self.refusing_checks

    @property
    def applied(self) -> bool:
        """Whether a mechanism is actually attached.

        Distinct from :attr:`granted` on purpose, and a report may not be granted
        without being applied: a gate that admits an injection nothing attached
        is the exact silent-fallback the plan forbids. One refusal short of that
        is a port that reports ``applied=True`` — mayhem cannot verify a port's
        honesty, only its shape, and the port's own ``evidence_ref`` is what the
        report cites.
        """
        return self.applied_primitive is not None

    def check(self, name: str) -> LowLevelCheck | None:
        for candidate in self.checks:
            if candidate.name == name:
                return candidate
        return None

    @property
    def refusal_reason(self) -> str:
        """One line naming every refusal, in the order the gate reached them."""
        if self.vacuous:
            return (
                f"low-level admission for {self.request.primitive_id!r} evaluated no checks: "
                "a gate that checked nothing cannot admit an injection"
            )
        if not self.refusing_checks:
            return (
                f"low-level admission for {self.request.primitive_id!r} granted: all "
                f"{len(self.checks)} checks passed"
            )
        blocking = "; ".join(f"{c.name}={c.status.value}: {c.detail}" for c in self.refusing_checks)
        return (
            f"low-level admission for {self.request.primitive_id!r} refused "
            f"{len(self.refusing_checks)} of {len(self.checks)} checks: {blocking}"
        )

    def describe(self) -> str:
        return self.refusal_reason

    def to_payload(self) -> dict[str, object]:
        """The machine-readable half, in the shape a refusal would be sealed in."""
        return {
            "request_id": self.request.request_id,
            "primitive_id": self.request.primitive_id,
            "engine": self.request.engine,
            "duration_s": self.request.duration_s,
            "params": dict(self.request.params),
            "active_primitives": list(self.request.active_primitives),
            "granted": self.granted,
            "applied": self.applied,
            "applied_primitive": self.applied_primitive,
            "vacuous": self.vacuous,
            "refusal_reason": self.refusal_reason,
            "specification": (
                self.specification.fingerprint() if self.specification is not None else None
            ),
            "checks": [
                {
                    "name": check.name,
                    "status": check.status.value,
                    "detail": check.detail,
                    "evidence_ref": check.evidence_ref,
                }
                for check in self.checks
            ],
            "unbound_ports": list(declared_unbound_ports()),
        }


class LowLevelRefusedError(InvariantViolationError):
    """An admission that refuses, carrying the report that refused it.

    Subclasses :class:`~mayhem.domain.errors.InvariantViolationError` so a
    refusal is caught by the same ``except`` that catches the other gates', and
    carries ``rule`` ``lowlevel.admission_refused``.
    """

    def __init__(self, report: AdmissionReport) -> None:
        super().__init__("lowlevel.admission_refused", report.refusal_reason)
        self.report = report

    @property
    def refusing_checks(self) -> tuple[LowLevelCheck, ...]:
        return self.report.refusing_checks


#: Evidence-reference vocabulary. Same shape as
#: :mod:`mayhem.controller.preflight_gate`'s, kept here so a low-level refusal is
#: citable without borrowing a prefix that means something else.
def request_ref(request_id: str) -> str:
    """Evidence reference for the request itself."""
    return f"lowlevel.request/{request_id or 'unidentified'}"


def primitive_ref(primitive_id: str) -> str:
    """Evidence reference for a primitive's descriptor."""
    return f"lowlevel.primitive/{primitive_id}"


def mechanism_ref(name: str) -> str:
    """Evidence reference for a port that produced no answer.

    The weakest reference in the vocabulary and it says so: the evidence of
    unavailability *is* the silence. Non-blank and stable, which is exactly what
    a ``PASS`` would have needed and could not have had.
    """
    return f"lowlevel.port/{name}"


# =============================================================================
# Check catalogue
# =============================================================================

CHECK_PRIMITIVE_KNOWN: Final[str] = "primitive:known"
CHECK_SUBSTRATE: Final[str] = "primitive:substrate"
CHECK_ENGINE: Final[str] = "engine:supported"
CHECK_DURATION: Final[str] = "admission:duration"
CHECK_PARAMETERS: Final[str] = "admission:parameters"
CHECK_COLLISION_PAIRS: Final[str] = "collision:pairs"
CHECK_MECHANISM_PROBE: Final[str] = "mechanism:probe"
CHECK_MECHANISM_APPLY: Final[str] = "mechanism:apply"

ALL_CHECKS: Final[tuple[str, ...]] = (
    CHECK_PRIMITIVE_KNOWN,
    CHECK_SUBSTRATE,
    CHECK_ENGINE,
    CHECK_DURATION,
    CHECK_PARAMETERS,
    CHECK_COLLISION_PAIRS,
    CHECK_MECHANISM_PROBE,
    CHECK_MECHANISM_APPLY,
)


def _pass(name: str, detail: str, evidence_ref: str) -> LowLevelCheck:
    return LowLevelCheck(
        name=name, status=LowLevelStatus.PASS, detail=detail, evidence_ref=evidence_ref
    )


def _refuse(name: str, detail: str, evidence_ref: str) -> LowLevelCheck:
    return LowLevelCheck(
        name=name, status=LowLevelStatus.REFUSED, detail=detail, evidence_ref=evidence_ref
    )


def _unavailable(name: str, detail: str, evidence_ref: str) -> LowLevelCheck:
    return LowLevelCheck(
        name=name, status=LowLevelStatus.UNAVAILABLE, detail=detail, evidence_ref=evidence_ref
    )


# =============================================================================
# The real checks
# =============================================================================


def check_primitive_known(
    request: LowLevelRequest, *, surface: SubstrateSurface = CURRENT_SUBSTRATE
) -> LowLevelCheck:
    """Is the id a declared primitive, and what does it say about itself?

    An unknown id is a ``REFUSED`` and not a crash: the gate is asked about
    primitives, and "there is no such primitive" is an answer. The detail carries
    the explanation Phase 3 built, because a caller that typed a wrong id wants
    to be told what the right ones are.
    """
    primitive = PRIMITIVES.get(request.primitive_id)
    if primitive is None:
        return _refuse(
            CHECK_PRIMITIVE_KNOWN,
            f"no low-level primitive is declared with id {request.primitive_id!r}; "
            f"{len(PRIMITIVES)} are declared",
            primitive_ref(request.primitive_id),
        )
    del surface  # the substrate is the next check's question
    # Phase 3 owns the disposition, so it is read rather than re-derived — but it is
    # read defensively. A primitive that both tables fail to decide makes
    # ``explain_primitive`` raise by design, and a *gate* must turn that into a
    # finding rather than propagate it: nothing a caller can hand in makes
    # ``evaluate`` raise.
    try:
        disposition = explain_primitive(primitive.id).disposition.value
    except InvariantViolationError as exc:
        return _refuse(
            CHECK_PRIMITIVE_KNOWN,
            f"{primitive.id} is declared but nothing has decided what happens to it: {exc}",
            primitive_ref(primitive.id),
        )
    return _pass(
        CHECK_PRIMITIVE_KNOWN,
        f"{primitive.id} is a declared {primitive.family.value} primitive; {disposition}",
        primitive_ref(primitive.id),
    )


def check_substrate(
    request: LowLevelRequest, *, surface: SubstrateSurface = CURRENT_SUBSTRATE
) -> LowLevelCheck:
    """Can this substrate inject the primitive at all?

    The refusal names the mechanism, because a refusal that names nothing gives
    an operator nothing to file. The unmet demands are listed too, so a reader
    learns *which* impact-gate trap is in play — an unprobed bin, an undefined
    cap bit, a bin that can never be installed — rather than only that something
    is missing.
    """
    primitive = PRIMITIVES.get(request.primitive_id)
    if primitive is None:
        return _unavailable(
            CHECK_SUBSTRATE,
            f"cannot ask about the substrate for undeclared primitive {request.primitive_id!r}",
            primitive_ref(request.primitive_id),
        )
    verdict = primitive.substrate_verdict(surface)
    if verdict.injectable:
        return _pass(
            CHECK_SUBSTRATE,
            f"every demand {primitive.id} declares is satisfiable on this substrate",
            primitive_ref(primitive.id),
        )
    gaps = verdict.gaps
    missing = primitive.missing
    mechanism = missing.mechanism if missing is not None else "an unnamed mechanism"
    detail = (
        f"{primitive.id} cannot be injected on this substrate: {mechanism} is missing; "
        f"{len(gaps)} unmet demand(s), first is {gaps[0].demand} ({gaps[0].reason.value})"
    )
    if missing is not None and missing.unachievable_substrate:
        detail += (
            "; and the host does not offer the operation at all, so no mechanism work closes this"
        )
    return _refuse(CHECK_SUBSTRATE, detail, primitive_ref(primitive.id))


def check_engine(request: LowLevelRequest) -> LowLevelCheck:
    """Is the engine one a low-level injection can be attempted on?

    Two refusals, deliberately distinguished in the detail. An engine mayhem does
    not have at all (``containerd``) is a different finding from an engine it has
    but whose adapter cannot carry an in-image mechanism (``kubernetes``), and the
    reason is a product fact about the adapter, not about the primitive.
    """
    engine = request.engine.strip().lower()
    if engine in SUPPORTED_ENGINES:
        return _pass(
            CHECK_ENGINE,
            f"{engine} can carry an in-image injection: binaries and capabilities are "
            "mayhem's to set",
            request_ref(request.request_id),
        )
    known_but_unsupported = {"kubernetes"}
    if engine in known_but_unsupported:
        return _refuse(
            CHECK_ENGINE,
            f"{engine} is not a lane mayhem attaches low-level mechanisms on: every "
            "mechanism plan 04 describes is in-image, and the Kubernetes adapter sets "
            "neither cap_add nor a host debugfs mount on a pod spec, so an attempt "
            "there would run as an agent with the pod's own privileges rather than "
            "as a container root",
            request_ref(request.request_id),
        )
    return _refuse(
        CHECK_ENGINE,
        f"engine {request.engine!r} is not one mayhem knows; supported lanes are "
        + ", ".join(sorted(SUPPORTED_ENGINES)),
        request_ref(request.request_id),
    )


def check_duration(
    request: LowLevelRequest, *, surface: SubstrateSurface = CURRENT_SUBSTRATE
) -> LowLevelCheck:
    """Is the requested window inside the descriptor's maximum safe duration?

    The plan's safety requirement — "maximum safe duration" — enforced here and
    nowhere else for primitives. A descriptor's own bound is the number used
    rather than a gate-wide constant, because a 60-second window is safe for one
    primitive and reckless for another, and a single ceiling would be either too
    strict for the first or too lax for the second.

    The ratio also matters: a request for 1% of a primitive's window injects a
    fault too small to observe, which is the inert-parameter defect wearing a
    duration. :data:`MIN_OBSERVABLE_FRACTION` is the floor.
    """
    del surface
    primitive = PRIMITIVES.get(request.primitive_id)
    if primitive is None:
        return _unavailable(
            CHECK_DURATION,
            f"cannot bound the duration of undeclared primitive {request.primitive_id!r}",
            primitive_ref(request.primitive_id),
        )
    ceiling = primitive.max_safe_duration_s
    if request.duration_s > ceiling:
        return _refuse(
            CHECK_DURATION,
            f"{request.duration_s:g}s exceeds {primitive.id}'s maximum safe duration of "
            f"{ceiling:g}s; a fault that outlasts its own recovery window cannot be undone "
            "in the time the plan allows for undoing it",
            primitive_ref(primitive.id),
        )
    floor = ceiling * MIN_OBSERVABLE_FRACTION
    if request.duration_s < floor:
        return _refuse(
            CHECK_DURATION,
            f"{request.duration_s:g}s is below {primitive.id}'s minimum observable window "
            f"of {floor:g}s ({MIN_OBSERVABLE_FRACTION:.0%} of its {ceiling:g}s maximum): a "
            "window this short perturbs nothing an observer or a residue check can see",
            primitive_ref(primitive.id),
        )
    return _pass(
        CHECK_DURATION,
        f"{request.duration_s:g}s is within {primitive.id}'s window [{floor:g}s, {ceiling:g}s]",
        primitive_ref(primitive.id),
    )


#: The fraction of a primitive's maximum window below which an injection is not
#: observable. Not zero: a fault whose whole recovery takes less than a second
#: can be shorter than the sampling interval of the thing meant to detect it,
#: which makes the fault indistinguishable from the environment.
MIN_OBSERVABLE_FRACTION: Final[float] = 0.05


def check_parameters(
    request: LowLevelRequest, *, surface: SubstrateSurface = CURRENT_SUBSTRATE
) -> LowLevelCheck:
    """Does the request fit the descriptor's parameter grammar?

    Delegated to :func:`mayhem.domain.lowlevel.resolve_params` rather than
    re-checked, so the grammar has exactly one implementation. The refusal is the
    grammar's own message, which prints the whole vocabulary — a caller with a
    wrong magnitude learns the accepted range in the same breath.
    """
    del surface
    primitive = PRIMITIVES.get(request.primitive_id)
    if primitive is None:
        return _unavailable(
            CHECK_PARAMETERS,
            f"cannot check the parameters of undeclared primitive {request.primitive_id!r}",
            primitive_ref(request.primitive_id),
        )
    try:
        resolved = resolve_params(primitive, request.params)
    except InvariantViolationError as exc:
        return _refuse(CHECK_PARAMETERS, str(exc), primitive_ref(primitive.id))
    return _pass(
        CHECK_PARAMETERS,
        f"{len(resolved)} parameter(s) accepted by {primitive.id}'s grammar: "
        + ", ".join(f"{param.name}={value}" for param, value in resolved),
        primitive_ref(primitive.id),
    )


def check_collision_pairs(request: LowLevelRequest) -> LowLevelCheck:
    """Can this run alongside what is already live?

    Reads the descriptor's own :meth:`~mayhem.domain.lowlevel.
    LowLevelPrimitive.incompatible_ids`, which is symmetric by construction, so a
    pair declared on either side blocks from either side. The refusal names both
    ends of the pair and the reason — an observation that could not be
    attributed is not a weaker observation, it is no observation.
    """
    primitive = PRIMITIVES.get(request.primitive_id)
    if primitive is None:
        return _unavailable(
            CHECK_COLLISION_PAIRS,
            f"cannot check collisions for undeclared primitive {request.primitive_id!r}",
            primitive_ref(request.primitive_id),
        )
    unknown = sorted(set(request.active_primitives) - set(PRIMITIVES))
    if unknown:
        return _refuse(
            CHECK_COLLISION_PAIRS,
            f"the active set names primitive(s) mayhem does not declare: {unknown}; an "
            "unresolvable active set means no collision can be ruled out",
            primitive_ref(request.primitive_id),
        )
    clashes = sorted(set(primitive.incompatible_ids()) & set(request.active_primitives))
    if clashes:
        return _refuse(
            CHECK_COLLISION_PAIRS,
            f"{primitive.id} cannot run alongside {', '.join(clashes)}: the two perturb "
            "the same observable, so neither effect could be attributed to its own cause",
            primitive_ref(primitive.id),
        )
    active = tuple(sorted(request.active_primitives))
    if active:
        return _pass(
            CHECK_COLLISION_PAIRS,
            f"{primitive.id} declares no collision with the {len(active)} active primitive(s)",
            primitive_ref(primitive.id),
        )
    return _pass(
        CHECK_COLLISION_PAIRS,
        f"{primitive.id} declares no collision and nothing else is active",
        primitive_ref(primitive.id),
    )


# =============================================================================
# Port checks
# =============================================================================


def _call_mechanism(
    ports: MechanismPorts,
    method: str,
    primitive: LowLevelPrimitive,
    specification: AttachSpecification | None,
) -> tuple[MechanismObservation | None, BaseException | None]:
    """Call one port method, normalised into an observation and an error.

    ``(None, None)`` means "there is no usable answer": an unbound port, a port
    that does not implement the method, a port that answered ``None``, and a port
    that answered an object of the wrong type. ``(None, exc)`` means the port
    raised. Both are the same *finding* — mayhem has no witness, and the absence
    of the ability to ask is not an answer — but the raised case carries the
    exception type into the detail, because "the loader crashed" and "there is no
    loader" are different problems that happen to have the same verdict.

    The exception is not re-raised: one misbehaving port must not abort an
    admission pass, and re-raising would turn an environment finding into a crash.
    """
    port = ports.mechanism
    if port is None:
        return None, None
    bound = getattr(port, method, None)
    if not callable(bound):
        return None, None
    argument = specification if specification is not None else primitive
    try:
        answer = bound(argument)
    except Exception as exc:
        return None, exc
    if not isinstance(answer, MechanismObservation):
        return None, None
    return answer, None


def check_mechanism_probe(
    request: LowLevelRequest,
    ports: MechanismPorts,
    *,
    surface: SubstrateSurface = CURRENT_SUBSTRATE,
) -> LowLevelCheck:
    """Can this host attach the mechanism at all?

    With no port bound — which is every invocation in this build — this is
    ``UNAVAILABLE`` and it refuses. The refusal says *which* system mayhem could
    not consult, so an operator reads "mayhem cannot load an eBPF program" rather
    than "something failed".
    """
    del surface
    primitive = PRIMITIVES.get(request.primitive_id)
    if primitive is None:
        return _unavailable(
            CHECK_MECHANISM_PROBE,
            f"cannot probe for undeclared primitive {request.primitive_id!r}",
            mechanism_ref("mechanism"),
        )
    observation, error = _call_mechanism(ports, "probe", primitive, None)
    if error is not None:
        return _unavailable(
            CHECK_MECHANISM_PROBE,
            f"the mechanism port raised {type(error).__name__} while probing "
            f"{primitive.id}; mayhem has no witness of what the host would support",
            mechanism_ref("mechanism"),
        )
    if observation is None:
        return _unavailable(
            CHECK_MECHANISM_PROBE,
            "no mechanism port answered the probe: mayhem ships no eBPF loader, FUSE shim, "
            f"device-mapper target or JVM agent, so it cannot ask whether {primitive.id}'s "
            "mechanism could be attached here",
            mechanism_ref("mechanism"),
        )
    if not observation.available:
        return _refuse(
            CHECK_MECHANISM_PROBE,
            f"the host reports no mechanism for {primitive.id}: {observation.detail}",
            observation.evidence_ref,
        )
    return _pass(
        CHECK_MECHANISM_PROBE,
        f"the host reports a mechanism for {primitive.id}: {observation.detail}",
        observation.evidence_ref,
    )


def check_mechanism_apply(
    request: LowLevelRequest,
    ports: MechanismPorts,
    specification: AttachSpecification | None,
) -> LowLevelCheck:
    """Is the mechanism **attached** right now?

    Separate from the probe because the two facts come apart in the field: a host
    with a loader still fails to attach, and an attach that succeeds still has to
    be undone. One boolean for both would report "available" as "attached", which
    is how a run records an injection that never happened.

    This check is only reached when every real check has passed. A refused
    substrate means there is nothing to attach, so the gate stops rather than
    asking a port to attach an attachment it cannot describe.
    """
    primitive = PRIMITIVES.get(request.primitive_id)
    if primitive is None:
        return _unavailable(
            CHECK_MECHANISM_APPLY,
            f"cannot attach for undeclared primitive {request.primitive_id!r}",
            mechanism_ref("mechanism"),
        )
    if specification is None:
        return _unavailable(
            CHECK_MECHANISM_APPLY,
            f"no attachment was described for {primitive.id}, so there is nothing to "
            "attach; mayhem will not attach an unspecified perturbation",
            primitive_ref(primitive.id),
        )
    observation, error = _call_mechanism(ports, "attach", primitive, specification)
    if error is not None:
        return _unavailable(
            CHECK_MECHANISM_APPLY,
            f"the mechanism port raised {type(error).__name__} while attaching "
            f"{primitive.id}; mayhem cannot tell whether anything is attached, and an "
            "unwitnessed attach is treated as no attach",
            mechanism_ref("mechanism"),
        )
    if observation is None:
        return _unavailable(
            CHECK_MECHANISM_APPLY,
            "no mechanism port is bound, so no low-level perturbation has been attached; "
            "mayhem decides and refuses, and the operating system has not been touched",
            mechanism_ref("mechanism"),
        )
    if not observation.applied:
        return _refuse(
            CHECK_MECHANISM_APPLY,
            f"the mechanism reports {primitive.id} was not attached: {observation.detail}",
            observation.evidence_ref,
        )
    return _pass(
        CHECK_MECHANISM_APPLY,
        f"the mechanism reports {primitive.id} is attached: {observation.detail}",
        observation.evidence_ref,
    )


# =============================================================================
# The gate
# =============================================================================


def evaluate(
    request: LowLevelRequest,
    ports: MechanismPorts | None = None,
    *,
    surface: SubstrateSurface = CURRENT_SUBSTRATE,
    checks: Sequence[str] = ALL_CHECKS,
) -> AdmissionReport:
    """Run the selected checks and report what was found. Never refuses.

    ``ports=None`` means *no port is bound*, not "skip the port checks": the port
    checks still run and report ``UNAVAILABLE``. Making ``None`` mean "skip" would
    let a caller obtain a granting report by omitting an argument, which is the
    one thing this gate must not be.

    A check that is not in the catalogue is refused at the call rather than
    silently ignored — a gate that quietly drops an unknown check is a gate
    reporting on fewer things than its caller believes.
    """
    unknown = sorted(set(checks) - set(ALL_CHECKS))
    if unknown:
        msg = f"unknown low-level check(s): {unknown}; the catalogue is {list(ALL_CHECKS)}"
        raise InvariantViolationError("lowlevel.unknown_check", msg)
    bound_ports = ports if ports is not None else MechanismPorts()
    ordered = tuple(checks)

    results: list[LowLevelCheck] = []
    for name in ordered:
        if name == CHECK_PRIMITIVE_KNOWN:
            results.append(check_primitive_known(request, surface=surface))
        elif name == CHECK_SUBSTRATE:
            results.append(check_substrate(request, surface=surface))
        elif name == CHECK_ENGINE:
            results.append(check_engine(request))
        elif name == CHECK_DURATION:
            results.append(check_duration(request, surface=surface))
        elif name == CHECK_PARAMETERS:
            results.append(check_parameters(request, surface=surface))
        elif name == CHECK_COLLISION_PAIRS:
            results.append(check_collision_pairs(request))
        elif name == CHECK_MECHANISM_PROBE:
            results.append(check_mechanism_probe(request, bound_ports, surface=surface))
        else:
            results.append(check_mechanism_apply(request, bound_ports, _specification_for(request)))

    specification = _specification_for(request)
    refusing = any(result.refuses for result in results)
    apply_check = next((result for result in results if result.name == CHECK_MECHANISM_APPLY), None)
    # ``applied_primitive`` names what *this gate* left attached, so it is only set
    # when nothing refused. A report that refuses on any check and still names an
    # applied primitive would be the exact shape the plan forbids: a run that
    # recorded an injection it also refused.
    applied = (
        request.primitive_id
        if not refusing and apply_check is not None and apply_check.status is LowLevelStatus.PASS
        else None
    )
    return AdmissionReport(
        request=request,
        checks=tuple(results),
        applied_primitive=applied,
        specification=specification,
    )


def _specification_for(request: LowLevelRequest) -> AttachSpecification | None:
    """The attachment this request describes, or ``None`` when it cannot.

    Pure: it reads the descriptor and resolves the grammar, and it never asks a
    port anything. ``None`` for a request whose primitive is undeclared or whose
    parameters do not fit the grammar — and it is ``None`` rather than a
    best-effort value, because a partially-described attachment is the shape a
    mechanism would act on.
    """
    primitive = PRIMITIVES.get(request.primitive_id)
    if primitive is None:
        return None
    try:
        return specification_for(primitive, request.params)
    except InvariantViolationError:
        return None


def admit(
    request: LowLevelRequest,
    ports: MechanismPorts | None = None,
    *,
    surface: SubstrateSurface = CURRENT_SUBSTRATE,
) -> AdmissionReport:
    """Admit the request or refuse it.

    Raises:
        LowLevelRefusedError: When any check refuses, or when the gate evaluated
            nothing at all. Never returns a report that does not grant.
    """
    report = evaluate(request, ports, surface=surface)
    if not report.granted:
        raise LowLevelRefusedError(report)
    return report


def refusing_names(
    request: LowLevelRequest,
    ports: MechanismPorts | None = None,
    *,
    surface: SubstrateSurface = CURRENT_SUBSTRATE,
) -> tuple[str, ...]:
    """Which checks would refuse, without raising.

    A preview for a surface that renders the checklist before deciding. The
    return type is a tuple of names and :func:`admit` is the only thing that
    grants, so it cannot be mistaken for a decision.
    """
    return tuple(check.name for check in evaluate(request, ports, surface=surface).refusing_checks)


# =============================================================================
# The residue scan: what to look at after the undo
# =============================================================================


@dataclass(frozen=True, slots=True)
class ResidueObservation:
    """One look at the world after the undo, against one declared facet.

    ``facet`` must be one the descriptor declares. An observation for a facet
    nobody declared is not extra assurance — it is a check the plan never
    promised, so :func:`residue_scan` refuses to treat it as coverage.
    """

    facet: str
    probe: str
    clean: bool
    detail: str = ""

    def __post_init__(self) -> None:
        for name in ("facet", "probe"):
            if not getattr(self, name).strip():
                msg = f"a residue observation's {name} must be non-blank"
                raise InvariantViolationError("lowlevel.residue_field_not_blank", msg)


@dataclass(frozen=True, slots=True)
class ResidueScan:
    """The scan's verdict, and what it looked at.

    ``clean`` is the conjunction of two things, and the second is the one that is
    usually forgotten:

    * every observation that was taken came back clean; **and**
    * every facet the descriptor declares was actually looked at.

    A scan that skipped a declared facet reports ``complete=False`` and cannot be
    clean, however clean the observations it did take were. That is the whole
    point of the type: "we looked and found nothing" and "we looked at one of the
    two things" must not read alike in a recovery record.
    """

    primitive_id: str
    declared_facets: tuple[str, ...]
    observations: tuple[ResidueObservation, ...]
    complete: bool
    undeclared_facets: tuple[str, ...] = ()

    @property
    def open_obligations(self) -> tuple[ResidueObservation, ...]:
        """Every observation that came back dirty, in scan order."""
        return tuple(observation for observation in self.observations if not observation.clean)

    @property
    def clean(self) -> bool:
        """Clean means nothing dirty *and* nothing skipped."""
        return self.complete and not self.open_obligations

    def describe(self) -> str:
        if not self.complete:
            skipped = sorted(
                set(self.declared_facets) - {observation.facet for observation in self.observations}
            )
            return (
                f"residue scan for {self.primitive_id} is incomplete: it looked at "
                f"{len(self.observations)} of {len(self.declared_facets)} declared facet(s), "
                f"missing {skipped}"
            )
        if self.open_obligations:
            return (
                f"residue scan for {self.primitive_id} found {len(self.open_obligations)} "
                f"open obligation(s): "
                + ", ".join(f"{o.facet} {o.probe}" for o in self.open_obligations)
            )
        return (
            f"residue scan for {self.primitive_id} is clean: all "
            f"{len(self.declared_facets)} declared facet(s) looked at and nothing remained"
        )


def residue_scan(primitive_id: str, observations: Sequence[ResidueObservation]) -> ResidueScan:
    """Compare what was observed against what the descriptor declares.

    Pure and total over a declared primitive. An undeclared primitive is a
    ``REFUSED`` rather than an empty scan: an empty scan of a primitive that does
    not exist is a clean report about nothing.
    """
    primitive = PRIMITIVES.get(primitive_id)
    if primitive is None:
        raise InvariantViolationError(
            "lowlevel.unknown_primitive",
            f"cannot scan residue for undeclared primitive {primitive_id!r}",
        )
    declared = tuple(sorted({check.facet.value for check in primitive.residue_checks}))
    seen = {observation.facet for observation in observations}
    undeclared = tuple(sorted(seen - set(declared)))
    complete = seen >= set(declared)
    return ResidueScan(
        primitive_id=primitive_id,
        declared_facets=declared,
        observations=tuple(observations),
        complete=complete,
        undeclared_facets=undeclared,
    )


@dataclass(frozen=True, slots=True)
class ResiduePass:
    """One pass of the recovery scan: what it looked at and what it found.

    Attributes:
        index: The pass number, 1-based.
        scan: The scan that pass produced.
        looked_at: The facets this pass actually observed, in order.
    """

    index: int
    scan: ResidueScan
    looked_at: tuple[str, ...]


def scan_after_recovery(
    primitive_id: str,
    observe: Callable[[ResidueProbe], ResidueObservation],
    *,
    max_passes: int = 3,
) -> tuple[tuple[ResiduePass, ...], ResidueScan]:
    """Run the residue checks after a recovery, until clean or out of passes.

    A **recovery auto-scan**, not a single look. An undo can be asynchronous — a
    detached kprobe entry disappears once the module unloads, a device-mapper
    target once the table is flushed — so a first observation taken immediately
    after the undo is a finding about *when it was taken*, not about the world.
    Re-running the whole declared set is the only way to tell the difference, and
    the loop is bounded so an undo that never lands cannot spin.

    Fail-closed on exhaustion: if the scan is still not clean after ``max_passes``
    this **raises** rather than returning the last scan. A caller that caught the
    exception still has the passes, and a caller that ignored it has not been
    handed a clean bill of health — which is the failure this mirrors from
    :func:`mayhem.controller.preflight_gate.obligation_verdict`, where an absent
    report is ``False``.

    The observer is a **port**, for the same reason :class:`MechanismPort` is:
    looking at ``/sys/kernel/debug/tracing/kprobe_events`` is a privileged read,
    and this build cannot do it. The negative control in
    ``tests/unit/test_lowlevel_wire.py`` drives the whole loop with a fake and
    shows the loop refusing to declare clean when a facet is skipped.

    Raises:
        InvariantViolationError: With rule ``lowlevel.residue_not_clean`` if the
            scan is not clean after ``max_passes``.
    """
    if max_passes < 1:
        msg = f"max_passes must be at least 1; got {max_passes}"
        raise InvariantViolationError("lowlevel.residue_pass_budget_invalid", msg)
    primitive = PRIMITIVES.get(primitive_id)
    if primitive is None:
        msg = f"cannot scan residue for undeclared primitive {primitive_id!r}"
        raise InvariantViolationError("lowlevel.unknown_primitive", msg)

    passes: list[ResiduePass] = []
    scan = ResidueScan(
        primitive_id=primitive_id,
        declared_facets=tuple(sorted({c.facet.value for c in primitive.residue_checks})),
        observations=(),
        complete=False,
    )
    for index in range(1, max_passes + 1):
        observations = tuple(
            observe(
                ResidueProbe(
                    facet=check.facet.value, probe=check.probe, expectation=check.expectation
                )
            )
            for check in primitive.residue_checks
        )
        scan = residue_scan(primitive_id, observations)
        passes.append(
            ResiduePass(index=index, scan=scan, looked_at=tuple(o.facet for o in observations))
        )
        if scan.clean:
            return tuple(passes), scan
    raise InvariantViolationError(
        "lowlevel.residue_not_clean",
        f"residue scan for {primitive_id!r} was still not clean after {max_passes} pass(es): "
        + "; ".join(pass_.scan.describe() for pass_ in passes),
    )


@dataclass(frozen=True, slots=True)
class ResidueProbe:
    """One residue check, as the observer is handed it.

    Carries the **expectation**, not just the probe, because the observer's whole
    job is to answer "is this what a clean undo looks like?" — a probe with no
    stated expectation can only be answered with a shrug. :attr:`evidence_ref`
    makes the answer citable, on the same rule as every other observation mayhem
    records.
    """

    facet: str
    probe: str
    expectation: str
    evidence_ref: str = ""

    def to_observation(self, *, clean: bool, detail: str = "") -> ResidueObservation:
        """The observation this probe produced, citing itself by default.

        The default ``evidence_ref`` is the probe itself: an observation that
        cannot say what was looked at is not a residue check, and defaulting the
        reference to the declared probe is exactly as strong as the claim the
        descriptor makes.
        """
        return ResidueObservation(
            facet=self.facet,
            probe=self.probe,
            clean=clean,
            detail=detail,
        )


# =============================================================================
# What plan 07's collision graph needs
# =============================================================================


def collision_edges() -> tuple[CompatibilityEdge, ...]:
    """Every incompatible pair among the declared primitives, as graph edges.

    Derived from the descriptors, so a pair declared on one side appears on both
    and an asymmetric authoring mistake is impossible — the same property
    :meth:`~mayhem.domain.lowlevel.LowLevelPrimitive.incompatible_ids` exists for,
    reached here through plan 07's own :class:`~mayhem.domain.policy.
    CompatibilityEdge` type so the graph reads these like any other edge.

    **This function is not registered anywhere.** ``domain/policy.py``'s bundles
    are outside this lane's ownership, so what integration has to do is stated in
    the plan's Phase 4 STATUS line rather than done here. That is recorded as an
    integration dependency, not as a completed step.
    """
    edges: set[frozenset[str]] = set()
    for primitive in PRIMITIVES.values():
        for other_id in primitive.incompatible_ids():
            pair = frozenset({primitive.id, other_id})
            if len(pair) == 2:
                edges.add(pair)
    reason = (
        "the two perturb the same observable, so neither effect could be attributed "
        "to its own cause while both are live"
    )
    return tuple(
        CompatibilityEdge(
            left_fault=min(pair),
            right_fault=max(pair),
            verdict=CompatibilityVerdict.CONFLICTING,
            reason=reason,
        )
        for pair in sorted(edges, key=sorted)
    )


# =============================================================================
# The impact-gate row, answered as data
# =============================================================================


#: Gap reasons that make a ``REQUIREMENTS`` row **inert** rather than gating.
#:
#: The plan's Phase 4 trap, named. A row exists so the impact gate probes for a
#: binary, evaluates a capability bit, or checks a tool's presence. If the bin is
#: in no ``_PROBE_BINS`` row the gate never probes it; if the cap name is in no
#: ``_CAP_BITS`` row ``has_cap`` answers False unconditionally; if the bin has no
#: ``_PM_PACKAGES`` row it can never be installed; and if no manifest declares the
#: capability it cannot be checked at all. In all four cases the row reads like a
#: gate that ran and cleared, which is the failure this set exists to prevent.
INERT_GAP_REASONS: Final[frozenset[GapReason]] = frozenset(
    {
        GapReason.BIN_NOT_PROBED,
        GapReason.CAP_BIT_UNDEFINED,
        GapReason.BIN_NOT_INSTALLABLE,
        GapReason.TOOL_NOT_MANIFESTED,
    }
)


def requirements_rows_needed(*, surface: SubstrateSurface = CURRENT_SUBSTRATE) -> tuple[str, ...]:
    """Which blocked primitives would earn an impact-gate ``REQUIREMENTS`` row.

    Today: **none of them**, and that empty answer is the decision the plan's
    Phase 4 asks for rather than an omission. A row is worth publishing when the
    gate could actually evaluate the primitive's demand — every unmet demand is an
    ordinary "not installed on this target" that a probe would settle. A primitive
    whose demand includes one of :data:`INERT_GAP_REASONS` would get a row that
    reports the fault INERT forever, which is a gate that reads as a pass.

    So the predicate is: blocked, **and** every unmet demand is one the gate could
    evaluate. Every one of the eighteen blocked primitives trips at least one of
    the four traps, so the answer is empty, and
    :func:`inert_demands` says which trap each one trips.

    The predicate cannot read ``agents/impact.py``'s real tables — ``mayhem.domain``
    may not import ``mayhem.agents`` under the layered import contract — so it
    restates the documented traps through :class:`SubstrateSurface`, and
    ``tests/unit/test_lowlevel_admission.py`` re-checks the restatement against the
    real ``_PROBE_BINS``, ``_CAP_BITS`` and ``_PM_PACKAGES`` on every run. Returning
    ids rather than raising keeps this from becoming a second opinion the impact
    gate might disagree with: it is a *report*, and the report's text is the
    decision.
    """
    return tuple(
        sorted(
            primitive_id
            for primitive_id, primitive in PRIMITIVES.items()
            if not primitive.substrate_verdict(surface)
            and not inert_demands(primitive_id, surface=surface)
        )
    )


def inert_demands(
    primitive_id: str, *, surface: SubstrateSurface = CURRENT_SUBSTRATE
) -> tuple[str, ...]:
    """Which of this primitive's unmet demands a requirements row could not gate.

    Empty means a row *would* gate the demand — the unmet part is ordinary, and a
    probe would settle it. Non-empty means the row would be decoration.
    """
    primitive = PRIMITIVES.get(primitive_id)
    if primitive is None:
        return ()
    return tuple(
        sorted(
            {
                f"{gap.demand} ({gap.reason.value})"
                for gap in primitive.substrate_gaps(surface)
                if gap.reason in INERT_GAP_REASONS
            }
        )
    )


def unprobeable_demands(*, surface: SubstrateSurface = CURRENT_SUBSTRATE) -> tuple[str, ...]:
    """Every bin any **blocked** primitive demands, sorted.

    Restricted to blocked primitives deliberately: the four injectable ones demand
    ``python``, ``sh`` and ``date``, which *are* in ``_PROBE_BINS``, and counting
    them here would hide which demands the gate could never probe. What is left is
    the interesting half — ``bpftool``, ``dmsetup``, ``faketime``, ``fusermount3``,
    ``jcmd``, ``mount`` are all absent from ``_PROBE_BINS``, and the suite re-checks
    that against the real table on every run. Exposed beside
    :func:`requirements_rows_needed` so the reason it returns nothing is checkable
    rather than asserted.
    """
    return tuple(
        sorted(
            {
                binary
                for primitive in PRIMITIVES.values()
                if not primitive.substrate_verdict(surface)
                for binary in primitive.probe_bins
            }
        )
    )


def disposition_of(primitive_id: str) -> PrimitiveDisposition:
    """The Phase-3 disposition of a primitive, for a caller that needs it here.

    A thin re-export rather than a second derivation: which primitives are
    refusals is Phase 3's to decide, and this module must not hold an opinion of
    its own that could disagree with the surface.
    """
    return explain_primitive(primitive_id).disposition
