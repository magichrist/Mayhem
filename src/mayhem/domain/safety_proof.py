"""Formal experiment safety proof — the frozen plan as a checkable safety case
(docs/v1.1.0/30_SAFETY_PROOF.md, Phase 1: proof as a type).

Phase 1 is types and pure predicates only. A :class:`SafetyProof` is a value
object: the digest of the plan it was built from, one :class:`Obligation` per
check carrying the gate output behind it, and an overall verdict. Nothing here
runs a gate, reads a lease, or touches a socket — the proof is *compiled* from
gate outputs elsewhere (Phase 2) and *discharged* by residue scans (Phase 4).
What lives here is the honesty rule the plan is named for, enforced by the type
rather than left to convention:

* a PASS line without a cited gate digest is malformed, not passing — an
  :class:`Obligation` claiming ``pass`` refuses to be constructed without one
  (:mod:`mayhem.domain.hashing` is the project's only digest producer, so a
  citation is a 64-char sha256 hex string and nothing looser);
* the declared verdict must equal the verdict recomputed from the obligations
  and the required-obligation catalogue — a hand-written ``verdict=PASS`` is
  refused at construction, exactly as a lease cannot become ``ACTIVE`` without
  write-ahead undo ops;
* validity is a pure predicate over an *externally supplied* frozen-plan digest
  (:meth:`SafetyProof.is_valid`), because a proof cannot know what the plan
  looks like now. A superseded plan therefore yields ``VOID`` — never an old
  ``PASS`` — and :meth:`SafetyProof.voided` returns the copy that says so.

Residue obligations (gap 65) are obligations too, narrowed to one fault: after
the run, each fault must be *clean* on the six predicates the residue scan
knows how to check. :class:`ResidueObligation` asserts that full predicate set
by construction, so a "residue check" that forgot ``no_leases_held`` cannot be
written, and :meth:`ResidueObligation.discharge` is the pure, testable
transition from "asserted" to "discharged or visibly not".

Determinism: every model is frozen, every collection is a tuple, and
``model_dump(mode="json")`` is byte-stable for a given instance, so
:meth:`SafetyProof.proof_digest` is a real identity — the value an approval
binds to in Phase 4.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import canonical_json, sha256_hex

# A citation is a sha256 hex digest and nothing looser: ``hashing.sha256_hex`` is
# the project's single definition of "same input", so a gate output that cannot
# be named by one of these did not actually run.
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def _require_digest(value: str, rule: str, subject: str) -> str:
    if not _SHA256_HEX.fullmatch(value):
        msg = f"{subject} must be a lowercase sha256 hex digest, got {value!r}"
        raise InvariantViolationError(rule, msg)
    return value


class ObligationStatus(StrEnum):
    """Result of one check, as the gate that ran it reported it."""

    PASS = "pass"
    FAIL = "fail"
    VOID = "void"  # asserted but not established (stale, unscanned, unresolved)


class ProofVerdict(StrEnum):
    """Overall proof result. ``VOID`` is the fail-closed third state."""

    PASS = "PASS"
    FAIL = "FAIL"
    VOID = "VOID"


class ObligationName(StrEnum):
    """The checks the admission pipeline owes every plan (doc's output shape).

    These nine lines are the proof's fixed spine: a proof that does not carry
    all of them has not been shown to satisfy the plan, it has been shown to
    satisfy *part* of it — which is ``VOID``, not ``PASS``.
    """

    MAX_CONCURRENT_FAULTS = "max_concurrent_faults"
    MAX_DURATION = "max_duration"
    DAMAGE_BUDGET = "damage_budget"
    TARGET_POLICY = "target_policy"
    CAPABILITY_REQUIREMENTS = "capability_requirements"
    COMPENSATION = "compensation"
    RECOVERY_PATH = "recovery_path"
    STOP_CONDITIONS = "stop_conditions"
    REQUIRED_APPROVALS = "required_approvals"


REQUIRED_OBLIGATIONS: frozenset[str] = frozenset(name.value for name in ObligationName)
"""Catalogue of obligations a ``PASS``-shaped proof must contain.

A residue obligation is *additional* to this set, never a substitute: residue
proves the run left nothing behind, the nine above prove it was allowed to
start.
"""


class ResiduePredicate(StrEnum):
    """The ways a fault can leave residue behind (gap 65).

    Each names an *expected-clean* condition, not a cleanup action: the residue
    scan observes, these predicates assert absence.
    """

    NO_TC_RULES = "no_tc_rules"
    NO_IPTABLES_ENTRIES = "no_iptables_entries"
    NO_MARKER_PROCESSES = "no_marker_processes"
    NO_FILES = "no_files"
    NO_CGROUP_OVERRIDES = "no_cgroup_overrides"
    NO_LEASES_HELD = "no_leases_held"


RESIDUE_PREDICATES: frozenset[str] = frozenset(p.value for p in ResiduePredicate)
RESIDUE_PREDICATE_ORDER: tuple[ResiduePredicate, ...] = tuple(ResiduePredicate)
"""Canonical predicate order — the order a residue line renders in."""


def residue_obligation_name(fault_id: str) -> str:
    """Canonical line name for ``fault_id``'s residue obligation."""
    return f"residue:{fault_id}"


class Obligation(BaseModel):
    """One check the plan had to satisfy, and the gate output behind it.

    ``gate_digest`` and ``evidence_ref`` are what make a line checkable. They
    are mandatory for a ``pass`` line and best-effort for the rest, mirroring
    the plan's rule that a PASS with an uncited line is malformed, not passing.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    status: ObligationStatus
    gate_digest: str = ""
    evidence_ref: str = ""
    evaluated_at: datetime = Field(default_factory=utc_now)
    detail: str = ""

    @field_validator("name")
    @classmethod
    def _name_not_blank(cls, value: str) -> str:
        if not value.strip() or value != value.strip():
            msg = f"obligation name must be a non-blank trimmed string, got {value!r}"
            raise InvariantViolationError("obligation_name_not_blank", msg)
        return value

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        if self.status is ObligationStatus.PASS:
            # The forged-PASS guard: a claim of having passed with nothing behind
            # it is not a weak claim, it is a malformed one.
            _require_digest(self.gate_digest, "pass_requires_cited_gate_digest", self.name)
            if not self.evidence_ref.strip():
                msg = f"obligation {self.name!r} is pass without an evidence reference"
                raise InvariantViolationError("pass_requires_citation", msg)
        return self

    @property
    def is_pass(self) -> bool:
        return self.status is ObligationStatus.PASS


class ResidueScan(BaseModel):
    """What one fault's residue scan observed. Pure input to ``discharge``.

    ``scanned=False`` is a real, load-bearing value: a residue obligation that
    was never checked is not clean, it is unchecked, and the run may not close
    on an unchecked line.
    """

    model_config = ConfigDict(frozen=True)

    fault_id: str
    scanned: bool = False
    dirty_predicates: tuple[ResiduePredicate, ...] = ()
    gate_digest: str = ""
    evidence_ref: str = ""
    observed_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        if len(set(self.dirty_predicates)) != len(self.dirty_predicates):
            msg = f"residue scan for {self.fault_id!r} lists a duplicate predicate"
            raise InvariantViolationError("residue_scan_no_duplicates", msg)
        if self.scanned and self.dirty_predicates and not self.gate_digest.strip():
            msg = f"residue scan for {self.fault_id!r} found residue but cites no gate output"
            raise InvariantViolationError("residue_finding_requires_citation", msg)
        return self


class ResidueObligation(Obligation):
    """One fault's expected-clean assertion, discharged line by line post-run.

    Subclasses :class:`Obligation` because it *is* one — a proof line with the
    fault it covers and the predicates that must hold. Construction insists on
    the full predicate set, so no residue obligation can be weaker than the six
    conditions the residue scan knows how to observe.
    """

    # Overridden as defaulted: the line name is *derived* from the fault, so
    # asking a caller to type it would be asking them to spell a function's
    # output. The before-validator fills it; the after-validator below refuses
    # anything but the canonical spelling.
    name: str = ""
    fault_id: str
    predicates: tuple[ResiduePredicate, ...] = RESIDUE_PREDICATE_ORDER

    @model_validator(mode="before")
    @classmethod
    def _default_name(cls, data: Any) -> Any:
        if isinstance(data, dict) and not str(data.get("name", "")).strip():
            fault_id = data.get("fault_id")
            if isinstance(fault_id, str) and fault_id.strip():
                data = {**data, "name": residue_obligation_name(fault_id)}
        return data

    @model_validator(mode="after")
    def _check_residue_invariants(self) -> Self:
        # Distinct name from ``Obligation._check_invariants`` on purpose:
        # pydantic indexes decorators by attribute name down the MRO, so
        # reusing the name would *replace* the base citation check rather than
        # add to it — a discharged line could then carry an empty digest.
        stated = {p.value for p in self.predicates}
        if stated != RESIDUE_PREDICATES:
            missing = ", ".join(sorted(RESIDUE_PREDICATES - stated))
            extra = ", ".join(sorted(stated - RESIDUE_PREDICATES))
            msg = (
                f"residue obligation for {self.fault_id!r} must assert exactly "
                f"{sorted(RESIDUE_PREDICATES)}; missing=[{missing}] unknown=[{extra}]"
            )
            raise InvariantViolationError("residue_predicates_incomplete", msg)
        if self.name != residue_obligation_name(self.fault_id):
            msg = (
                f"residue obligation name {self.name!r} is not the canonical line name "
                f"{residue_obligation_name(self.fault_id)!r}"
            )
            raise InvariantViolationError("residue_name_not_canonical", msg)
        return self

    @property
    def discharged(self) -> bool:
        return self.status is not ObligationStatus.VOID

    def discharge(self, scan: ResidueScan) -> ResidueObligation:
        """Return this obligation advanced by what ``scan`` observed.

        Three outcomes, and none of them is "assume clean":

        * residue found on any asserted predicate -> ``VOID``, naming the
          predicates. A voided line dirties its run.
        * the scan never ran -> ``FAIL``. Unchecked is not clean, and a run may
          not close on a line nobody looked at.
        * predicates observed clean -> ``PASS``, citing the scan's own digest.

        Raises:
            InvariantViolationError: If ``scan`` is for a different fault.
        """
        if scan.fault_id != self.fault_id:
            msg = (
                f"residue scan for {scan.fault_id!r} cannot discharge the obligation "
                f"for {self.fault_id!r}"
            )
            raise InvariantViolationError("residue_scan_fault_mismatch", msg)
        if not scan.scanned:
            return _discharge(
                self,
                status=ObligationStatus.FAIL,
                gate_digest=scan.gate_digest,
                evidence_ref=scan.evidence_ref,
                evaluated_at=scan.observed_at,
                detail=f"residue scan did not run for fault {self.fault_id!r}",
            )
        dirty = tuple(p for p in scan.dirty_predicates if p in self.predicates)
        if dirty:
            return _discharge(
                self,
                status=ObligationStatus.VOID,
                gate_digest=scan.gate_digest,
                evidence_ref=scan.evidence_ref,
                evaluated_at=scan.observed_at,
                detail=f"residue found: {', '.join(p.value for p in dirty)}",
            )
        return _discharge(
            self,
            status=ObligationStatus.PASS,
            gate_digest=scan.gate_digest,
            evidence_ref=scan.evidence_ref,
            evaluated_at=scan.observed_at,
            detail="residue scan clean on all asserted predicates",
        )


def _discharge(
    base: ResidueObligation,
    *,
    status: ObligationStatus,
    gate_digest: str,
    evidence_ref: str,
    evaluated_at: datetime,
    detail: str,
) -> ResidueObligation:
    """Rebuild ``base`` with a new status, re-running every validator.

    ``model_copy`` would skip validation, so the update travels as data and is
    re-validated by the target class — a discharged line that violates a
    citation rule cannot be forged by discharging it. The ``PASS`` branch is
    where that bites: discharging with a scan that cites no digest raises
    rather than minting an uncited pass line.
    """
    return ResidueObligation.model_validate(
        {
            **base.model_dump(),
            "status": status,
            "gate_digest": gate_digest,
            "evidence_ref": evidence_ref,
            "evaluated_at": evaluated_at,
            "detail": detail,
        }
    )


class SafetyProof(BaseModel):
    """A frozen plan's safety case: obligations, citations, and a verdict.

    The verdict is stored rather than derived so the proof is a serializable
    artifact (Phase 3 renders it, Phase 4 seals it) — and a model validator
    re-derives it on every construction, so the stored value can never be
    *stronger* than the evidence beside it. A caller that writes
    ``verdict=ProofVerdict.PASS`` over a failing obligation is refused, not
    believed; declaring ``VOID`` over passing lines is allowed (and is what
    :meth:`voided` does), because voiding a proof is always the safe direction.
    """

    model_config = ConfigDict(frozen=True)

    plan_digest: str
    # The union (not bare ``Obligation``) is what keeps a residue line typed
    # through an artifact round trip: a serialized ``ResidueObligation``
    # re-validates as a ``ResidueObligation``, so its fault and predicates
    # cannot decay away on the way to storage.
    obligations: tuple[Obligation | ResidueObligation, ...] = ()
    verdict: ProofVerdict = ProofVerdict.VOID
    void_reason: str = ""
    generated_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _check_invariants(self) -> Self:
        _require_digest(self.plan_digest, "plan_digest_not_canonical", "SafetyProof")
        names = [o.name for o in self.obligations]
        if len(set(names)) != len(names):
            repeated = sorted({n for n in names if names.count(n) > 1})
            msg = f"proof repeats an obligation name: {repeated}"
            raise InvariantViolationError("obligation_names_unique", msg)
        if self.verdict is not ProofVerdict.VOID and self.void_reason:
            msg = f"proof is {self.verdict.value} yet carries a void_reason"
            raise InvariantViolationError("void_reason_only_when_void", msg)
        if self.verdict is ProofVerdict.VOID and not self.void_reason:
            msg = "void proof does not say what voided it"
            raise InvariantViolationError("void_proof_requires_reason", msg)
        # VOID is the weakest verdict, so declaring it is always allowed — a
        # proof may be voided for a reason its own lines cannot show (a
        # superseded plan, say). Declaring PASS or FAIL is not: that claim
        # must be the one the obligations actually support.
        implied = self.recompute_verdict()
        if self.verdict is not ProofVerdict.VOID and self.verdict is not implied:
            msg = (
                f"proof declares {self.verdict.value} but its obligations only support "
                f"{implied.value}"
            )
            raise InvariantViolationError("verdict_must_match_obligations", msg)
        return self

    # -- catalogue ------------------------------------------------------------------
    def missing_obligations(self) -> tuple[str, ...]:
        """Required lines this proof does not carry, in catalogue order."""
        stated = {o.name for o in self.obligations}
        return tuple(name.value for name in ObligationName if name.value not in stated)

    def obligation(self, name: str) -> Obligation | None:
        for candidate in self.obligations:
            if candidate.name == name:
                return candidate
        return None

    @property
    def residue_obligations(self) -> tuple[ResidueObligation, ...]:
        return tuple(o for o in self.obligations if isinstance(o, ResidueObligation))

    # -- pure predicates ------------------------------------------------------------
    def recompute_verdict(self) -> ProofVerdict:
        """Verdict implied by the obligations alone, ignoring plan freshness.

        Precedence is ``VOID`` > ``FAIL`` > ``PASS``: a single unproven line
        (``void``) makes the whole proof unproven, because a proof that cannot
        vouch for all of its lines vouches for none of them. Absent required
        lines void rather than fail — "not checked" is not "checked and
        negative", and only the second is a finding about the plan.
        """
        if any(o.status is ObligationStatus.VOID for o in self.obligations):
            return ProofVerdict.VOID
        if any(o.status is ObligationStatus.FAIL for o in self.obligations):
            return ProofVerdict.FAIL
        if not self.obligations or self.missing_obligations():
            return ProofVerdict.VOID
        return ProofVerdict.PASS

    def void_reasons(self, plan_digest: str) -> tuple[str, ...]:
        """Every reason this proof cannot speak for ``plan_digest``, in order."""
        reasons: list[str] = []
        if self.plan_digest != plan_digest:
            reasons.append(
                f"plan superseded: proof is for {self.plan_digest}, frozen plan is {plan_digest}"
            )
        missing = self.missing_obligations()
        if missing:
            reasons.append(f"required obligations absent: {', '.join(missing)}")
        if not self.obligations:
            reasons.append("proof carries no obligations")
        return tuple(reasons)

    def evaluate(self, plan_digest: str) -> ProofVerdict:
        """Verdict for ``plan_digest``: freshness first, then the obligations.

        A superseded plan is ``VOID`` even when its lines all passed — those
        lines describe a plan that no longer exists, so the proof must not be
        read as a PASS of the one that does.
        """
        if self.void_reasons(plan_digest):
            return ProofVerdict.VOID
        return self.recompute_verdict()

    def is_valid(self, plan_digest: str) -> bool:
        """True only when every obligation passes *and* the plan still matches."""
        return self.evaluate(plan_digest) is ProofVerdict.PASS

    def voided(self, plan_digest: str) -> SafetyProof:
        """Return a copy that is explicitly ``VOID`` for ``plan_digest``.

        The copy is re-validated, not patched: a stale proof becomes an
        artifact that says "void, and here is why" rather than a stale PASS
        some later reader might trust.
        """
        reasons = self.void_reasons(plan_digest)
        if not reasons:
            return self
        return self.__class__.model_validate(
            {
                **self.model_dump(),
                # Obligations are passed as instances, not dumped dicts, so
                # subclass fields (a residue obligation's fault and predicates)
                # survive the round trip.
                "obligations": self.obligations,
                "verdict": ProofVerdict.VOID,
                "void_reason": "; ".join(reasons),
            }
        )

    @property
    def proof_digest(self) -> str:
        """Canonical digest of the whole proof, verdict included.

        The verdict is inside the digest on purpose: an approval bound to this
        digest in Phase 4 cannot be honoured by a later ``VOID`` rendering of
        the same obligations.
        """
        return sha256_hex(canonical_json(self.model_dump(mode="json")))

    def canonical_json(self) -> str:
        """Deterministic JSON form — what ``proof_digest`` is taken over."""
        return canonical_json(self.model_dump(mode="json"))
