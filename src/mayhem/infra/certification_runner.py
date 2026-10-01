"""The certification runner: one fault, one disposable cell, one honest claim.

What this module is for
-----------------------
Plan 01 Phase 2. :mod:`mayhem.domain.certification` (Phase 1) made the *rules*
of a live claim pure; this module is the machine that has to earn one. It
provisions a disposable environment, compiles a drill, executes it through the
**normal** run path, residue-scans the cell, cross-checks the evidence bundle
against what the run actually did, and only then mints a
:class:`~mayhem.domain.certification.CertificationRecord`.

Why the seams are protocols
--------------------------
Every external dependency is injected — the provisioner, the drill compiler, the
evidence capturer, the clock, the record sink. Nothing here imports
``mayhem.controller``, shells out, or touches a database, and a test asserts
the absence of the controller import by AST so it cannot rot. That is not an
aesthetic preference:

* The **unit** suite drives the whole pipeline with fakes and no live runtime.
  A certification claim is expensive to make and free to fake; a test that
  needed a container to prove a refusal would not be a test.
* The **live** path is bound to ``RunEngine.execute`` at the CLI seam
  (:mod:`mayhem.cli.certify`), and nowhere else. There is no second executor,
  no direct executor call, and no "fast path" for certification: the only thing
  this module can do is hand a compiled plan to whatever object the cell
  exposes, and the CLI's cell exposes ``RunEngine.execute``. A certification
  therefore travels the same approval, lease, compensation, and observability
  path a normal run does, which is the only way "it worked on a live runtime"
  can mean what it says.

What makes a claim falsifiable
------------------------------
The runner never accepts a claim about the run; it recomputes it. For each of
:data:`~mayhem.domain.certification.REQUIRED_EVIDENCE_DIGESTS` it derives a
digest from the run's own facts — the parameters the plan actually carried, the
target it resolved, the step report that claims the effect, the recovery probe
numbers, the residue scan — via :func:`expected_evidence_digests`, and then
requires the captured :class:`~mayhem.domain.certification.EvidenceBundleRef` to
carry *the same digests*. A bundle is a claim; the run is the evidence; when
they disagree the attempt is refused and the mismatch is named. Fabricated
evidence is therefore not "detected" — it is arithmetically unable to match.

Refusals are recorded, not raised
---------------------------------
A certification attempt that cannot be certified still produces a record. A
catalog-only fault, a reversible fault whose probe never came back to baseline,
a residue scan that was skipped or found something, a bundle that is missing a
digest: each is written down as a ``pending`` record carrying the reason and an
``outcome`` naming the refusal class. Nothing about that record grants live
verification — that is the property that matters, and it is what
:func:`mayhem.domain.certification.certified_engines` reads.

Two refusals are settled without a cell at all, because a cell cannot change
their answer: a declared engine lane the cell does not provide, and a
catalog-only fault. The second is the plan's negative verification: a
catalog-only entry must still refuse, and the attempt records that refusal
rather than reporting a pass. Refusing it *before* provisioning is deliberate —
there is no executor to run, so burning a runtime to rediscover the catalog's
own answer would be theatre. The refusal is still persisted, so it is visible.

Regression demotion
-------------------
Re-running a fault on a cell that already holds a live claim is a regression
test. If the re-run shows the fault did *not* recover — the probe stayed away
from baseline, or the run left dirty leases — the existing claim is demoted with
:func:`~mayhem.domain.certification.mark_failed` in place, and the demotion is
recorded three ways: as the stored record's reason, as a :class:`DemotionEvent`
on the returned attempt, and as a ``demotion`` digest in the new attempt's
evidence, so the demotion travels *in* the bundle rather than beside it. The
demotion is written **before** the new attempt is appended, so a reader can
never see a new record next to a still-certified old one.

Re-certification is a new row
-----------------------------
A lapsed claim is terminal by design, so re-certifying after expiry appends a
new record rather than transitioning the old one. The runner never promotes by
transition: it constructs a fresh ``pending`` record and hands it to
:func:`~mayhem.domain.certification.certify`, or hands it back un-certified with
a reason. The store (a per-fault sequence) and the domain agree on that by
construction.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from typing import TYPE_CHECKING, Any, Protocol

from mayhem.domain.catalog import definition_for
from mayhem.domain.certification import (
    DEFAULT_CERTIFICATION_TTL,
    REQUIRED_EVIDENCE_DIGESTS,
    Arch,
    CellPrivilege,
    CertificationRecord,
    CertificationState,
    EvidenceBundleRef,
    MatrixCell,
    certify,
    mark_failed,
)
from mayhem.domain.errors import DomainError
from mayhem.domain.faults import EngineLane, FaultDefinition, Reversibility

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence
    from datetime import datetime, timedelta

    from mayhem.domain.capabilities import Capability
    from mayhem.domain.evidence import ActionOutcome
    from mayhem.domain.experiments import ExecutionPlan
    from mayhem.domain.run_outcome import RunVerdict
    from mayhem.infra.certification_repository import StoredCertification

__all__ = [
    "DEMOTION_DIGEST",
    "RESIDUE_KINDS",
    "AttemptOutcome",
    "CellProvisioner",
    "CellRequest",
    "CertificationAttempt",
    "CertificationError",
    "CertificationRequest",
    "CertificationSink",
    "CertifiedRun",
    "CertifiedStep",
    "DemotionEvent",
    "DisposableCell",
    "EvidenceCapturer",
    "RecoveryEvidence",
    "RecurrenceVerdict",
    "RefusalClass",
    "ResidueFinding",
    "ResidueScan",
    "certify_fault",
    "evidence_digest",
    "expected_evidence_digests",
    "planned_target_identity",
    "requires_recovery_verification",
]


#: The residue classes the plan names. A cell that cannot observe one of these
#: has not residue-scanned, and :attr:`ResidueScan.performed` is how that is said
#: rather than implied by an empty finding list.
RESIDUE_KINDS: tuple[str, ...] = (
    "tc_rule",
    "iptables_entry",
    "marker_process",
    "marker_file",
    "cgroup_override",
)

#: The digest name that carries a regression demotion, so the demotion is inside
#: the bundle rather than in a field a bundle can lose.
DEMOTION_DIGEST = "demotion"


class CertificationError(DomainError):
    """The certification attempt could not be run at all.

    Distinct from a *refusal*, which is a result. Raised for a request the
    runner cannot interpret — an unknown fault id, parameters the catalog
    refuses. A refusal means the attempt ran and the answer was no.
    """


class RefusalClass(StrEnum):
    """Why an attempt did not produce a live claim.

    Machine-readable so CI can assert on the *class* of refusal without parsing
    prose, and so a reader can tell a missing capability apart from a recovered
    baseline that drifted.
    """

    REFUSED = "refused"
    UNKNOWN_FAULT = "refused:unknown_fault"
    INVALID_PARAMS = "refused:invalid_params"
    ENGINE_LANE = "refused:engine_lane"
    CATALOG_ONLY = "refused:catalog_only"
    RUN_FAILED = "refused:run_failed"
    EFFECT_NOT_OBSERVED = "refused:effect_not_observed"
    RECOVERY_UNVERIFIED = "refused:recovery_unverified"
    RESIDUE = "refused:residue"
    NO_EVIDENCE = "refused:no_evidence"
    EVIDENCE_MISMATCH = "refused:evidence_mismatch"


class AttemptOutcome(StrEnum):
    """The one-word verdict an attempt carries into the record's ``outcome``."""

    CERTIFIED = "certified"
    REFUSED = "refused"


class RecurrenceVerdict(StrEnum):
    """What the cell observed about the fault's *recovery*.

    The dimension a certification exists to protect. ``REGRESSED`` means the cell
    contradicted the claim already on file, and it is the only trigger for
    automatic demotion.
    """

    RECOVERED = "recovered"
    REGRESSED = "regressed"
    NOT_APPLICABLE = "not_applicable"


# ── request and result shapes ───────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class CellRequest:
    """The cell an attempt asks for, before anything is provisioned.

    Every dimension of :class:`~mayhem.domain.certification.MatrixCell` is here
    because every one of them can invalidate an existing claim later. A
    provisioner that cannot honour a dimension must refuse, not substitute a
    value: a certification on a cell nobody can name is a claim about "a machine
    somewhere".
    """

    engine: EngineLane
    engine_version: str = "unknown"
    os_distro: str = "unknown"
    kernel_version: str = "unknown"
    arch: Arch = Arch.AMD64
    privilege: CellPrivilege = CellPrivilege.ROOTLESS
    capabilities: frozenset[Capability] = frozenset()

    def as_matrix_cell(self) -> MatrixCell:
        return MatrixCell(
            engine=self.engine,
            engine_version=self.engine_version,
            os_distro=self.os_distro,
            kernel_version=self.kernel_version,
            arch=self.arch,
            privilege=self.privilege,
            capabilities=self.capabilities,
        )


@dataclass(frozen=True, slots=True)
class CertificationRequest:
    """One fault on one cell, with the parameters and target to use."""

    fault_id: str
    cell: CellRequest
    params: Mapping[str, object] = field(default_factory=dict)
    target: str = ""
    duration_s: float = 5.0
    seed: int | None = None
    ttl: timedelta = DEFAULT_CERTIFICATION_TTL
    injector_version: str = ""
    mayhem_version: str = "0.0.0"


@dataclass(frozen=True, slots=True)
class ResidueFinding:
    """One thing the cell still had after the run that it should not have had."""

    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
class ResidueScan:
    """The result of looking for residue — including *not having looked*.

    ``performed=False`` is the important case. An empty ``findings`` tuple from a
    scan that never ran is indistinguishable from a clean cell to any consumer
    that forgets to check, so "I did not look" is its own value here and a
    certification resting on it is refused.
    """

    performed: bool
    findings: tuple[ResidueFinding, ...] = ()
    note: str = ""

    @property
    def clean(self) -> bool:
        return self.performed and not self.findings

    def rendered(self) -> str:
        if not self.performed:
            return f"residue scan not performed{': ' + self.note if self.note else ''}"
        if not self.findings:
            return "residue scan clean"
        return "residue: " + "; ".join(f"{f.kind}({f.detail})" for f in self.findings)


@dataclass(frozen=True, slots=True)
class RecoveryEvidence:
    """Did the undo run, and did the probe come back to where it started?

    Mandatory for a reversible fault. ``undo_ran`` and ``within_tolerance`` are
    kept separate because a fault that was undone and then drifted back is a
    different, worse fact than one that was never undone, and the record has to
    be able to say which.
    """

    probe: str
    baseline: float
    observed: float
    tolerance: float
    undo_ran: bool

    @property
    def drift(self) -> float:
        return abs(self.observed - self.baseline)

    @property
    def within_tolerance(self) -> bool:
        return self.undo_ran and self.drift <= self.tolerance

    def rendered(self) -> str:
        return (
            f"{self.probe}: undo_ran={self.undo_ran} baseline={self.baseline} "
            f"observed={self.observed} tolerance={self.tolerance} drift={self.drift}"
        )


@dataclass(frozen=True, slots=True)
class DemotionEvent:
    """A live claim withdrawn because the cell contradicted it.

    Carries the previous claim's sequence so the event names the row it demoted
    rather than just the fault — the difference between "this fault is no longer
    certified" and "this specific claim was withdrawn, at this time, because the
    probe stayed at X".
    """

    fault_id: str
    cell_label: str
    previous_sequence: int
    previous_state: str
    new_state: str
    at: datetime
    reason: str

    def rendered(self) -> str:
        return (
            f"demoted {self.fault_id}@sequence {self.previous_sequence} on {self.cell_label}: "
            f"{self.previous_state} -> {self.new_state}; {self.reason}"
        )

    def payload(self) -> dict[str, str]:
        return {
            "fault_id": self.fault_id,
            "cell_label": self.cell_label,
            "previous_sequence": str(self.previous_sequence),
            "previous_state": self.previous_state,
            "new_state": self.new_state,
            "at": self.at.isoformat(),
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class CertificationAttempt:
    """What one attempt did, what it concluded, and what it wrote.

    ``record`` is always present: an attempt that was refused still leaves a
    record behind, because "we tried on this cell and it did not certify" is a
    fact worth keeping. ``refusals`` names each reason in the order it was found,
    so a reader does not have to guess which of several problems was fatal.
    """

    fault_id: str
    cell: MatrixCell
    run_id: str
    outcome: AttemptOutcome
    record: CertificationRecord
    run_status: str
    verdict: str
    residue: ResidueScan
    recovery: RecoveryEvidence | None
    recurrence: RecurrenceVerdict
    refusals: tuple[str, ...] = ()
    demotions: tuple[DemotionEvent, ...] = ()
    demoted: tuple[StoredCertification, ...] = ()

    @property
    def certified(self) -> bool:
        return self.record.grants_live_verification

    def summary(self) -> str:
        lines = [
            f"{self.record.label}: {self.outcome.value} "
            f"(run {self.run_id or 'n/a'}, status {self.run_status}, "
            f"verdict {self.verdict or 'undecided'})",
            f"  {self.residue.rendered()}",
        ]
        if self.recovery is not None:
            lines.append(f"  {self.recovery.rendered()}")
        lines.extend(f"  {demotion.rendered()}" for demotion in self.demotions)
        lines.extend(f"  {reason}" for reason in self.refusals)
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fault_id": self.fault_id,
            "cell": self.cell.label,
            "cell_fingerprint": self.cell.fingerprint,
            "engine": self.cell.engine.value,
            "run_id": self.run_id,
            "outcome": self.outcome.value,
            "certified": self.certified,
            "state": self.record.state.value,
            "record": self.record.model_dump(mode="json"),
            "run_status": self.run_status,
            "verdict": self.verdict,
            "recurrence": self.recurrence.value,
            "residue": {
                "performed": self.residue.performed,
                "clean": self.residue.clean,
                "findings": [
                    {"kind": finding.kind, "detail": finding.detail}
                    for finding in self.residue.findings
                ],
            },
            "recovery": (
                None
                if self.recovery is None
                else {
                    "probe": self.recovery.probe,
                    "undo_ran": self.recovery.undo_ran,
                    "baseline": self.recovery.baseline,
                    "observed": self.recovery.observed,
                    "tolerance": self.recovery.tolerance,
                    "drift": self.recovery.drift,
                    "within_tolerance": self.recovery.within_tolerance,
                }
            ),
            "refusals": list(self.refusals),
            "demotions": [
                {
                    "fault_id": demotion.fault_id,
                    "cell_label": demotion.cell_label,
                    "previous_sequence": demotion.previous_sequence,
                    "previous_state": demotion.previous_state,
                    "new_state": demotion.new_state,
                    "reason": demotion.reason,
                }
                for demotion in self.demotions
            ],
        }


# ── injected seams ──────────────────────────────────────────────────────────


class CertifiedStep(Protocol):
    """One step report, as the promotion engine already models it."""

    @property
    def step_id(self) -> str: ...

    @property
    def ok(self) -> bool: ...

    @property
    def detail(self) -> str: ...

    @property
    def status(self) -> str: ...

    @property
    def outcome(self) -> ActionOutcome: ...


class CertifiedRun(Protocol):
    """The subset of ``RunResult`` a certification reads.

    Structural, not a redefinition: the real
    :class:`mayhem.controller.executor.RunResult` and its
    :class:`~mayhem.controller.executor.StepReport` satisfy these, and so does a
    test double. Naming the shape here rather than importing the classes is what
    keeps ``infra`` from importing ``controller`` — the layering contract
    forbids it, and a runner that quietly reached around it would be exactly the
    "side channel" the plan forbids.
    """

    @property
    def run_id(self) -> str: ...

    @property
    def status(self) -> str: ...

    @property
    def steps(self) -> tuple[CertifiedStep, ...]: ...

    @property
    def dirty_leases(self) -> tuple[str, ...]: ...

    @property
    def verdict(self) -> RunVerdict | None: ...


class DisposableCell(Protocol):
    """A provisioned, throwaway runtime the attempt runs against.

    ``execute`` is the seam that must be the normal run path. The CLI binds it
    to :meth:`mayhem.controller.executor.RunEngine.execute`; nothing else in this
    repository implements it.
    """

    @property
    def cell(self) -> MatrixCell: ...

    @property
    def injector_version(self) -> str: ...

    def execute(self, plan: ExecutionPlan) -> CertifiedRun: ...

    def recovery_evidence(self, run: CertifiedRun) -> RecoveryEvidence | None: ...

    def residue_scan(self) -> ResidueScan: ...

    def dispose(self) -> None: ...


class CellProvisioner(Protocol):
    """Builds a :class:`DisposableCell`, or refuses."""

    def provision(self, request: CertificationRequest) -> DisposableCell: ...


class EvidenceCapturer(Protocol):
    """Returns the sealed bundle produced by the run, or ``None``.

    ``None`` is a legitimate answer: a run that produced no bundle has produced
    no evidence, and the runner refuses rather than minting a record that cites
    nothing. A capturer that cannot observe a required digest must return a
    bundle that lacks it rather than invent one.

    ``demotions`` is supplied so a bundle can *record* a regression demotion
    rather than merely being adjacent to one: the demotion is hashed into the
    bundle's digests (see :data:`DEMOTION_DIGEST`), which is the only way the
    plan's "the demotion event in evidence" is literal rather than a promise.
    """

    def capture(
        self,
        run: CertifiedRun,
        *,
        request: CertificationRequest,
        cell: MatrixCell,
        plan: ExecutionPlan,
        residue: ResidueScan,
        recovery: RecoveryEvidence | None,
        demotions: tuple[DemotionEvent, ...] = (),
    ) -> EvidenceBundleRef | None: ...


class CertificationSink(Protocol):
    """The record store, as the runner needs it.

    :class:`mayhem.infra.certification_repository.CertificationRepository`
    satisfies this structurally; the tests supply an in-memory fake. The
    asymmetry between :meth:`append` and :meth:`store_transition` is the domain's
    asymmetry: a new claim is appended, an existing one is transitioned in place.
    """

    def append(
        self,
        record: CertificationRecord,
        *,
        run_id: str = "",
        now: datetime | None = None,
    ) -> StoredCertification: ...

    def store_transition(
        self,
        stored: StoredCertification,
        record: CertificationRecord,
        *,
        now: datetime | None = None,
    ) -> StoredCertification: ...

    def latest_on_cell(self, fault_id: str, cell: MatrixCell) -> StoredCertification | None: ...


# ── evidence digests ────────────────────────────────────────────────────────


def evidence_digest(name: str, payload: object) -> str:
    """Canonical sha256 of one evidence claim.

    The name is inside the hashed bytes, so a digest for ``undo`` can never be
    presented as a digest for ``residue``: swapping two claims around does not
    produce two valid digests, it produces two invalid ones.
    """
    encoded = json.dumps(
        {"name": name, "payload": payload},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return sha256(encoded.encode()).hexdigest()


def expected_evidence_digests(
    *,
    params: Mapping[str, object],
    target: str,
    observed_effect: str,
    recovery: RecoveryEvidence | None,
    residue: ResidueScan,
    demotions: Sequence[DemotionEvent] = (),
    compensated: bool = True,
) -> dict[str, str]:
    """The digests a bundle must carry to support *this* run's claims.

    Each key is one claim
    :data:`~mayhem.domain.certification.REQUIRED_EVIDENCE_DIGESTS` makes, and each
    payload is derived from the run's own facts rather than from anything the
    capturer supplied. A capturer that hashes the same artifacts lands on the
    same values; one that does not is describing a different run, and
    :func:`certify_fault` refuses.

    The ``undo`` digest exists for irreversible faults too. Their undo is
    reconciliation rather than reversal, so the claim is "the run left no
    unrecovered lease behind" — and that is what gets hashed. A bundle cannot
    escape the obligation to say something about recovery by being irreversible.
    """
    digests = {
        "params": evidence_digest("params", dict(sorted(params.items()))),
        "target": evidence_digest("target", target),
        "observed_effect": evidence_digest("observed_effect", observed_effect),
        "undo": evidence_digest(
            "undo",
            {
                "recovery": (
                    None
                    if recovery is None
                    else {
                        "probe": recovery.probe,
                        "undo_ran": recovery.undo_ran,
                        "baseline": recovery.baseline,
                        "observed": recovery.observed,
                        "tolerance": recovery.tolerance,
                    }
                ),
                "compensated": compensated,
            },
        ),
        "residue": evidence_digest(
            "residue",
            {
                "performed": residue.performed,
                "findings": sorted((f.kind, f.detail) for f in residue.findings),
            },
        ),
    }
    if demotions:
        digests[DEMOTION_DIGEST] = evidence_digest(
            DEMOTION_DIGEST, [demotion.payload() for demotion in demotions]
        )
    return digests


# ── policy helpers ──────────────────────────────────────────────────────────


def requires_recovery_verification(definition: FaultDefinition) -> bool:
    """Must a certification of ``definition`` carry recovery evidence?

    Yes unless the catalog says the fault cannot be reversed. ``reversible`` is
    the coarse boolean the rest of the harness uses; ``reversibility`` is the
    typed answer and wins when present, so a fault declared ``irreversible`` is
    not asked for a baseline it can never have, while a fault that merely
    forgot to declare anything is still asked.
    """
    if definition.reversibility is Reversibility.IRREVERSIBLE:
        return False
    return bool(definition.reversible)


def effective_lanes(definition: FaultDefinition) -> frozenset[EngineLane]:
    """Lanes the fault can run on, with the ``multi-engine`` sentinel removed.

    ``multi-engine`` is not a lane you can execute on; it is how the catalog says
    "engine-agnostic, decide at plan time", so requiring a cell on it would make
    the check unanswerable.
    """
    return frozenset(
        lane for lane in definition.engine_lanes if lane is not EngineLane.MULTI_ENGINE
    )


# ── the runner ──────────────────────────────────────────────────────────────


def certify_fault(
    request: CertificationRequest,
    *,
    provisioner: CellProvisioner,
    compile_plan: Callable[[CertificationRequest], ExecutionPlan],
    capture: EvidenceCapturer,
    sink: CertificationSink,
    now: datetime,
) -> CertificationAttempt:
    """Run one fault on one cell and record what the cell said about it.

    The attempt always produces a record. It is certified only when every check
    below passed; otherwise the pending record is stored with the refusal
    written into it, and the returned :class:`CertificationAttempt` names why.

    The order of the checks is the order a reader should care about, and each is
    a question the cell can actually answer:

    1. **Does this fault exist, and do these parameters validate?** Refused
       before anything is provisioned; there is nothing to learn from a cell
       about a fault that is not in the catalog.
    2. **Can this cell run this fault at all?** A declared engine lane the cell
       does not provide is a refusal, not a failed run.
    3. **Compile once, execute through the normal path.** ``RunEngine.execute``,
       bound by the caller. No bypass exists.
    4. **Residue scan.** Mandatory after every run; a scan that was not performed
       is a refusal, because "I did not look" is not "I found nothing".
    5. **Recovery verification** for a reversible fault, plus the absence of
       dirty leases for every fault.
    6. **Evidence cross-check.** The bundle's digests must equal the digests
       derived from the run's own facts.
    7. **Regression demotion**, when the cell already held a live claim and this
       run contradicts it.

    The cell is disposed in a ``finally``, so a run that raises cannot leak a
    disposable environment. A provisioner that raises propagates: provisioning
    is not a refusal, it is the infrastructure failing to answer.

    Args:
        request: The fault, the cell, the parameters, the target.
        provisioner: Builds the disposable cell.
        compile_plan: Compiles the request into a frozen plan. Injected so the
            planner stays the single implementation — this module never plans,
            and the plan is compiled exactly once so the run and the digests
            describe the same drill.
        capture: Returns the sealed evidence bundle for the run.
        sink: Where records are written and where a prior claim is looked up.
        now: The certification instant. Explicit, so expiry policy is testable
            instead of waited for.

    Returns:
        The attempt, including the stored record and any demotions.

    Raises:
        CertificationError: If the request itself cannot be interpreted.
    """
    definition = _definition_for(request.fault_id)
    _validated_params(definition, request)

    early = _refuse_without_a_cell(definition, request, now=now)
    if early is not None:
        sink.append(early.record, run_id="", now=now)
        return early

    plan = compile_plan(request)
    cell = provisioner.provision(request)
    try:
        matrix_cell = cell.cell
        injector_version = cell.injector_version
        step_id, target, planned_params = _plan_facts(plan, definition.id)
        run = cell.execute(plan)
        report = _report_for(run, step_id)
        residue = cell.residue_scan()
        recovery = cell.recovery_evidence(run)
    finally:
        cell.dispose()

    observed_effect = _observed_effect(definition, report)
    verdict = "" if run.verdict is None else run.verdict.value
    recurrence = _recurrence(definition, run, recovery)

    demotions, demoted = _demote_regressions(
        definition, sink, matrix_cell=matrix_cell, recurrence=recurrence, now=now
    )

    refusals = _evaluate(
        definition,
        run=run,
        report=report,
        residue=residue,
        recovery=recovery,
    )

    bundle: EvidenceBundleRef | None = None
    # A bundle is captured for a clean attempt *and* for one that demoted a
    # previous claim. The second case is the only way the plan's "the demotion
    # event in evidence" can be literal: the demoted record's own row carries
    # the reason, but a reason string is a claim about the demotion while a
    # sealed bundle is evidence of it. A plain refusal captures nothing — there
    # is no claim to support and no demotion to document.
    if not refusals or demotions:
        captured = capture.capture(
            run,
            request=request,
            cell=matrix_cell,
            plan=plan,
            residue=residue,
            recovery=recovery,
            demotions=demotions,
        )
        if captured is None:
            if not refusals:
                refusals.append(
                    f"{RefusalClass.NO_EVIDENCE}: the run produced no evidence bundle, so there "
                    "is nothing for a certification to cite"
                )
        else:
            problems = _evidence_refusals(
                captured,
                expected=expected_evidence_digests(
                    params=planned_params,
                    target=target or request.target,
                    observed_effect=observed_effect,
                    recovery=recovery,
                    residue=residue,
                    demotions=demotions,
                    compensated=not run.dirty_leases,
                ),
            )
            refusals.extend(problems)
            # A bundle that failed verification is not evidence of this run, so it
            # is dropped rather than attached to the refused record. Keeping it
            # would leave a hash on a record that no longer claims anything.
            bundle = None if problems else captured

    record = _mint(
        definition=definition,
        cell=matrix_cell,
        request=request,
        injector_version=injector_version,
        run=run,
        residue=residue,
        recovery=recovery,
        bundle=bundle,
        refusals=refusals,
        now=now,
    )
    sink.append(record, run_id=run.run_id, now=now)
    return CertificationAttempt(
        fault_id=definition.id,
        cell=matrix_cell,
        run_id=run.run_id,
        outcome=AttemptOutcome.CERTIFIED if not refusals else AttemptOutcome.REFUSED,
        record=record,
        run_status=run.status,
        verdict=verdict,
        residue=residue,
        recovery=recovery,
        recurrence=recurrence,
        refusals=tuple(refusals),
        demotions=demotions,
        demoted=demoted,
    )


def _definition_for(fault_id: str) -> FaultDefinition:
    try:
        return definition_for(fault_id)
    except LookupError as exc:
        raise CertificationError(f"{RefusalClass.UNKNOWN_FAULT}: {exc}") from None


def _validated_params(
    definition: FaultDefinition, request: CertificationRequest
) -> dict[str, object]:
    try:
        return definition.validate_params(dict(request.params))
    except Exception as exc:
        raise CertificationError(
            f"{RefusalClass.INVALID_PARAMS}: {definition.id} refused "
            f"{dict(request.params)!r}: {exc}"
        ) from None


def _pending_record(
    definition: FaultDefinition,
    cell: MatrixCell,
    request: CertificationRequest,
    *,
    at: datetime,
    injector_version: str = "",
) -> CertificationRecord:
    """The un-certified record an attempt starts from and may end at.

    A fresh record every attempt, because a lapsed or failed claim is terminal:
    re-running a fault mints the *next* record in the store's per-fault sequence
    rather than reviving the previous one.
    """
    return CertificationRecord(
        fault_id=definition.id,
        cell=cell,
        injector_version=injector_version or request.injector_version or request.mayhem_version,
        expires_at=at + request.ttl,
        state=CertificationState.PENDING,
    )


def _refuse_without_a_cell(
    definition: FaultDefinition,
    request: CertificationRequest,
    *,
    now: datetime,
) -> CertificationAttempt | None:
    """Refusals a cell cannot change: a missing engine lane, or catalog-only.

    Returns ``None`` when the attempt should proceed to provision a cell.
    """
    cell = request.cell.as_matrix_cell()
    lanes = effective_lanes(definition)
    if lanes and cell.engine not in lanes:
        return _refused_attempt(
            definition,
            cell,
            request,
            refusal=(
                f"{RefusalClass.ENGINE_LANE}: {definition.id} declares lanes "
                f"{', '.join(sorted(lane.value for lane in lanes))} and this cell is "
                f"{cell.engine.value}"
            ),
            now=now,
        )
    if definition.catalog_only:
        return _refused_attempt(
            definition,
            cell,
            request,
            refusal=(
                f"{RefusalClass.CATALOG_ONLY}: {definition.id} is catalog-only and refuses to "
                f"execute on any cell — including this one: "
                f"{definition.refusal_reason or 'no refusal reason recorded'}"
            ),
            now=now,
        )
    return None


def _refused_attempt(
    definition: FaultDefinition,
    cell: MatrixCell,
    request: CertificationRequest,
    *,
    refusal: str,
    now: datetime,
) -> CertificationAttempt:
    """An attempt that never ran, recorded as the refusal it is.

    The record stays ``pending`` with the class in ``outcome`` and the sentence
    in ``reason``. ``pending`` is the honest state — nothing was certified — and
    it grants no live verification, which is the property the promotion gate and
    the CLI both read.
    """
    pending = _pending_record(definition, cell, request, at=now)
    record = pending.model_copy(
        update={"outcome": RefusalClass.REFUSED.value, "reason": refusal}
    )
    return CertificationAttempt(
        fault_id=definition.id,
        cell=cell,
        run_id="",
        outcome=AttemptOutcome.REFUSED,
        record=record,
        run_status="not-executed",
        verdict="",
        residue=ResidueScan(performed=False, note="nothing was executed on this cell"),
        recovery=None,
        recurrence=RecurrenceVerdict.NOT_APPLICABLE,
        refusals=(refusal,),
    )


def planned_target_identity(target: object) -> str:
    """The stable, human-meaningful identity of a planned fault's target.

    ``TargetScope``'s own ``__str__`` is a pydantic repr, which would make the
    ``target`` evidence digest a hash of a serialisation detail rather than of
    the thing that was perturbed. ``<runtime>/<logical_id>`` is what a reader
    would recognise and what both the live cell (from the stored plan) and the
    runner (from the in-memory plan) can compute identically.
    """
    runtime = getattr(target, "runtime", None)
    logical_id = getattr(target, "logical_id", "")
    if runtime is None or not logical_id:
        return str(target)
    return f"{getattr(runtime, 'value', runtime)}/{logical_id}"


def _plan_facts(plan: ExecutionPlan, fault_id: str) -> tuple[str, str, dict[str, object]]:
    """``(step_id, target, params)`` for the plan step that injects ``fault_id``.

    Read off the plan rather than guessed from a step report's prose: the run
    engine reports each step under the id the planner gave it, so matching on the
    plan is exact where string-matching a detail would be a guess.
    """
    for step in plan.steps:
        fault = step.fault
        if fault is None or fault.fault_id != fault_id:
            continue
        target = planned_target_identity(fault.target) if fault.target is not None else ""
        if not target and fault.targets:
            target = ",".join(
                sorted(",".join(sorted(entry.node_ids)) for entry in fault.targets)
            )
        return step.id, target, dict(fault.params)
    return "", "", {}


def _report_for(run: CertifiedRun, step_id: str) -> CertifiedStep | None:
    if not step_id:
        return None
    for report in run.steps:
        if report.step_id == step_id:
            return report
    return None


def _observed_effect(definition: FaultDefinition, report: CertifiedStep | None) -> str:
    """The effect the cell reported, bound to the effect the catalog declares.

    Both halves are hashed: a report that says something, and the claim it is
    held to. A step that reported success without naming anything cannot be cited
    as evidence for the declared effect.
    """
    detail = "" if report is None else report.detail
    return f"{definition.observable_effect}|observed={detail}"


def _recurrence(
    definition: FaultDefinition,
    run: CertifiedRun,
    recovery: RecoveryEvidence | None,
) -> RecurrenceVerdict:
    """What the cell said about *recovery* specifically.

    Narrow on purpose. A run that failed for an unrelated reason is not a
    recovery regression, and demoting a live claim because the drill's HTTP probe
    timed out would fire the demotion path for reasons that have nothing to do
    with whether the fault can be undone.
    """
    if run.dirty_leases:
        return RecurrenceVerdict.REGRESSED
    if not requires_recovery_verification(definition):
        return RecurrenceVerdict.NOT_APPLICABLE
    if recovery is None or not recovery.within_tolerance:
        return RecurrenceVerdict.REGRESSED
    return RecurrenceVerdict.RECOVERED


def _demote_regressions(
    definition: FaultDefinition,
    sink: CertificationSink,
    *,
    matrix_cell: MatrixCell,
    recurrence: RecurrenceVerdict,
    now: datetime,
) -> tuple[tuple[DemotionEvent, ...], tuple[StoredCertification, ...]]:
    """Withdraw a live claim this run has contradicted.

    A catalog-only fault never demotes. It never ran, so it has said nothing
    about the cell, and a refusal to execute is not evidence that a previously
    working fault stopped working. (Those attempts are settled before a cell is
    provisioned at all, so this guard is belt and braces.)
    """
    if definition.catalog_only or recurrence is not RecurrenceVerdict.REGRESSED:
        return (), ()
    stored = sink.latest_on_cell(definition.id, matrix_cell)
    if stored is None or not stored.record.grants_live_verification:
        return (), ()
    reason = (
        f"re-run of {definition.id} on {matrix_cell.label} did not reproduce the certified "
        "recovery, so the claim is withdrawn rather than kept"
    )
    demoted = mark_failed(stored.record, reason=reason)
    written = sink.store_transition(stored, demoted, now=now)
    event = DemotionEvent(
        fault_id=definition.id,
        cell_label=matrix_cell.label,
        previous_sequence=stored.sequence,
        previous_state=stored.record.state.value,
        new_state=demoted.state.value,
        at=now,
        reason=reason,
    )
    return (event,), (written,)


def _evaluate(
    definition: FaultDefinition,
    *,
    run: CertifiedRun,
    report: CertifiedStep | None,
    residue: ResidueScan,
    recovery: RecoveryEvidence | None,
) -> list[str]:
    """Every reason this attempt cannot be certified, in the order found.

    All of them are collected rather than short-circuiting on the first: a run
    that left residue *and* failed recovery is a different remediation from one
    that only failed recovery, and a reader shown only the first refusal cannot
    tell which problem to fix.
    """
    refusals: list[str] = []
    if run.status != "completed":
        refusals.append(
            f"{RefusalClass.RUN_FAILED}: the run finished {run.status!r}, so no fault was "
            "certified on this cell"
        )
    elif report is None:
        refusals.append(
            f"{RefusalClass.EFFECT_NOT_OBSERVED}: the run reported no step for "
            f"{definition.id}, so the declared effect was never observed"
        )
    elif not report.ok:
        refusals.append(
            f"{RefusalClass.EFFECT_NOT_OBSERVED}: the step for {definition.id} reported "
            f"{report.status} / {report.outcome.value} ({report.detail}), so the declared "
            "effect was not observed"
        )
    if run.dirty_leases:
        refusals.append(
            f"{RefusalClass.RECOVERY_UNVERIFIED}: the run left {len(run.dirty_leases)} "
            f"unrecovered lease(s) ({', '.join(run.dirty_leases)}); nothing is certified on a "
            "cell that is still perturbed"
        )
    if requires_recovery_verification(definition):
        if recovery is None:
            refusals.append(
                f"{RefusalClass.RECOVERY_UNVERIFIED}: {definition.id} is reversible and the "
                "cell reported no recovery evidence, so there is no proof that the undo ran "
                "and the probe returned to baseline"
            )
        elif not recovery.within_tolerance:
            refusals.append(
                f"{RefusalClass.RECOVERY_UNVERIFIED}: recovery did not restore the baseline — "
                f"{recovery.rendered()}"
            )
    if not residue.performed:
        refusals.append(
            f"{RefusalClass.RESIDUE}: the residue scan was not performed, and 'not checked' is "
            "not 'clean'"
        )
    elif residue.findings:
        refusals.append(f"{RefusalClass.RESIDUE}: {residue.rendered()}")
    return refusals


def _evidence_refusals(bundle: EvidenceBundleRef, *, expected: dict[str, str]) -> list[str]:
    """Refuse a bundle that does not support the claims it is cited for.

    Two independent failures, both reported:

    * **incomplete** — a required digest is absent, so the bundle says nothing
      about that claim at all;
    * **mismatched** — a digest is present and does not equal the one the run's
      own facts produce, so the bundle is describing something other than this
      run. This is the fabrication check: a plausible-looking hash of anything
      cannot equal the hash of what happened.
    """
    refusals: list[str] = []
    # ``required`` includes the demotion digest when a regression happened: an
    # attempt that withdrew a claim has to say so inside the bundle, not only in
    # a field the bundle cannot lose.
    required = tuple(REQUIRED_EVIDENCE_DIGESTS)
    if DEMOTION_DIGEST in expected:
        required = (*required, DEMOTION_DIGEST)
    missing = tuple(name for name in required if name not in bundle.digests)
    if missing:
        refusals.append(
            f"{RefusalClass.EVIDENCE_MISMATCH}: the evidence bundle has no "
            f"{', '.join(missing)} digest, so it cannot support the claim it is cited for"
        )
    for name in required:
        claimed = bundle.digests.get(name)
        if claimed is None:
            continue
        if claimed != expected.get(name):
            refusals.append(
                f"{RefusalClass.EVIDENCE_MISMATCH}: the bundle's {name} digest {claimed[:12]}… "
                f"does not match what this run did ({str(expected.get(name))[:12]}…); the "
                "bundle is not evidence for this run"
            )
    return refusals


def _mint(
    *,
    definition: FaultDefinition,
    cell: MatrixCell,
    request: CertificationRequest,
    injector_version: str,
    run: CertifiedRun,
    residue: ResidueScan,
    recovery: RecoveryEvidence | None,
    bundle: EvidenceBundleRef | None,
    refusals: Sequence[str],
    now: datetime,
) -> CertificationRecord:
    """The record this attempt leaves behind, certified or not.

    On success, :func:`mayhem.domain.certification.certify` performs the
    transition and re-validated the record, so anything construction would have
    refused cannot be produced here either. On failure the pending record keeps
    the class in ``outcome`` and the refusals in ``reason``; it grants no live
    verification, which is the property every reader depends on.

    A *refused* record may still carry an evidence bundle, and that is not a
    contradiction: ``pending`` means "nothing is certified", not "nothing was
    observed". The bundle on a refused record is the record of the attempt — in
    practice a regression demotion, whose event is what the bundle documents. The
    record is rebuilt through :meth:`CertificationRecord.model_validate` rather
    than patched with ``model_copy``, so the same invariants that refused an
    impossible record at construction are re-checked here.
    """
    del residue, recovery
    pending = _pending_record(
        definition, cell, request, at=now, injector_version=injector_version
    )
    if refusals or bundle is None:
        reason = "; ".join(refusals) or f"{RefusalClass.NO_EVIDENCE}: no evidence bundle"
        changes: dict[str, object] = {
            "outcome": RefusalClass.REFUSED.value,
            "reason": reason,
        }
        if bundle is not None:
            changes["evidence"] = (bundle,)
        return CertificationRecord.model_validate({**pending.model_dump(), **changes})
    verdict = "undecided" if run.verdict is None else run.verdict.value
    outcome = (
        f"run {run.run_id} completed with verdict {verdict}; the declared effect was observed, "
        "the recovery probe returned to baseline within tolerance, and the residue scan was clean"
    )
    return certify(
        pending,
        at=now,
        expires_at=now + request.ttl,
        evidence=(bundle,),
        outcome=outcome,
        injector_version=pending.injector_version,
    )
