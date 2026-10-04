"""Plan 30 Phase 5 — negative controls for the safety proof.

`test_safety_proof.py` (45), `test_proof_compiler.py` (87) and
`test_proof_sealing.py` (35) assert what a proof *is*. This file asserts that the
proof's three load-bearing properties decide their outcomes rather than merely
coexisting with them — each test is two-sided, so a property that stopped working
would have to start returning the opposite answer to pass.

* **The plan digest is what voids a proof.** A proof built against one digest
  evaluates ``PASS`` against that digest and ``VOID`` against another, while its
  own lines keep passing. That asymmetry is the whole point of ``VOID``: FAIL
  would claim the current plan is unsafe, and VOID says the evidence describes a
  plan that no longer exists. If ``VOID`` were a constant, or were driven by the
  lines rather than the digest, a superseded plan would be reported as a safety
  verdict.
* **A PASS line must cite a gate.** The same line with a real gate digest and a
  real evidence reference is accepted; the same line carrying a fabricated
  citation is refused at construction. One-sided this would be a badge a caller
  could type into existence.
* **Found residue voids the line; a clean scan leaves it passing.** Asserted as a
  pair on the same proof, because the interesting failure is a scan that reports
  *clean* while residue exists — which only a two-sided test can distinguish from
  a scan that simply never looked.
"""

from __future__ import annotations

import pytest
from tests.unit.test_safety_proof import (
    GATE_ADMISSION,
    MOMENT,
    PLAN_A,
    PLAN_B,
    full_obligations,
    passing,
    proof_of,
    residue_for,
    scan_of,
)

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.safety_proof import (
    ObligationStatus,
    ProofVerdict,
    ResiduePredicate,
    SafetyProof,
)


def _proof_with(line: object, *, verdict: ProofVerdict) -> SafetyProof:
    payload: dict[str, object] = {}
    if verdict is ProofVerdict.VOID:
        payload["void_reason"] = "a residue line is void"
    return SafetyProof(
        plan_digest=PLAN_A,
        obligations=(*full_obligations(), line),  # type: ignore[arg-type]
        verdict=verdict,
        generated_at=MOMENT,
        **payload,  # type: ignore[arg-type]
    )


# ── the digest voids; the lines do not ───────────────────────────────────────


def test_the_plan_digest_alone_decides_void_versus_pass() -> None:
    """One proof, two digests, opposite verdicts, unchanged lines.

    Asserting the digest-mismatch half and the matching-digest half in the same
    test is what makes this a control rather than a restatement: a
    ``evaluate`` that returned ``VOID`` for everything would satisfy the first
    assertion and fail the second.
    """
    proof = proof_of(PLAN_A)

    assert proof.evaluate(PLAN_A) is ProofVerdict.PASS
    assert proof.evaluate(PLAN_B) is ProofVerdict.VOID
    # The lines are untouched by the mismatch — which is why VOID exists as a
    # third answer rather than FAIL.
    assert proof.recompute_verdict() is ProofVerdict.PASS
    assert proof.missing_obligations() == ()


def test_a_voided_proof_names_what_voided_it() -> None:
    """A reader must be able to tell *why* the proof does not apply."""
    reasons = proof_of(PLAN_A).void_reasons(PLAN_B)

    assert len(reasons) == 1
    assert "plan superseded" in reasons[0]


# ── a PASS line must cite a gate ────────────────────────────────────────────


def test_a_pass_line_is_accepted_only_when_it_cites_a_real_gate_output() -> None:
    """The accepting half and the refusing half of the same rule.

    Fabricating a citation is the failure this exists to stop: a proof is a
    record that *checks ran*, so a PASS whose citation is invented is a badge
    with no gate behind it.
    """
    accepted = passing("admission")

    assert accepted.status is ObligationStatus.PASS
    assert accepted.gate_digest == GATE_ADMISSION
    assert accepted.evidence_ref.strip()

    with pytest.raises(InvariantViolationError):
        passing("admission", digest="")


def test_a_missing_obligation_is_reported_rather_than_tolerated() -> None:
    """A proof that skipped a line says which one — and cannot be authored as a PASS.

    The gap is what the compiler reports, and the refusal is what stops anyone
    from declaring the omission away: a proof over an incomplete obligation set
    does not validate as ``PASS``, because the model compares the declared
    verdict against the lines rather than taking the caller's word.
    """
    proof = proof_of(PLAN_A)
    incomplete = tuple(proof.obligations[:-1])

    dropped = SafetyProof(
        plan_digest=PLAN_A,
        obligations=incomplete,
        verdict=ProofVerdict.VOID,
        void_reason="an obligation was never evaluated",
        generated_at=proof.generated_at,
    )

    assert proof.missing_obligations() == ()
    assert dropped.missing_obligations() != ()
    assert dropped.is_valid(PLAN_A) is False

    with pytest.raises(InvariantViolationError, match="verdict_must_match_obligations"):
        SafetyProof(
            plan_digest=PLAN_A,
            obligations=incomplete,
            verdict=ProofVerdict.PASS,
            generated_at=proof.generated_at,
        )


# ── residue discharges line by line ─────────────────────────────────────────


def test_found_residue_voids_the_line_where_a_clean_scan_leaves_it_passing() -> None:
    """Both outcomes on the same fault, so a scan that never looked cannot pass.

    The tempting defect is a residue scan reporting ``scanned=True`` with an empty
    ``dirty_predicates`` without having compared anything. Asserting only the clean
    case would accept it; asserting the dirty case alongside is what makes the pair
    meaningful. Both lines are built from the *same* obligation and the *same*
    obligation name, so only the scan differs.
    """
    clean_line = residue_for().discharge(scan_of())
    dirty_line = residue_for().discharge(scan_of(dirty=(ResiduePredicate.NO_FILES,)))

    assert clean_line.status is ObligationStatus.PASS
    assert clean_line.discharged is True
    assert dirty_line.status is ObligationStatus.VOID
    assert dirty_line.discharged is False

    clean_proof = _proof_with(clean_line, verdict=ProofVerdict.PASS)
    dirty_proof = _proof_with(dirty_line, verdict=ProofVerdict.VOID)

    assert clean_proof.is_valid(PLAN_A) is True
    assert dirty_proof.is_valid(PLAN_A) is False


def test_a_verdict_that_contradicts_its_lines_is_refused_at_construction() -> None:
    """The proof cannot be *authored* into a PASS its own lines do not support.

    Worth its own test because it is what makes the pair above trustworthy: if a
    caller could declare ``PASS`` over a VOID residue line, the model would be
    decorative and the two-sided assertion would prove nothing.
    """
    void_line = residue_for().discharge(scan_of(dirty=(ResiduePredicate.NO_FILES,)))

    with pytest.raises(InvariantViolationError, match="verdict_must_match_obligations"):
        _proof_with(void_line, verdict=ProofVerdict.PASS)
