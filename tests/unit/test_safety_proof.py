"""Safety proof as a type — validity, residue discharge, and the negative
controls that keep the proof honest (docs/v1.1.0/30_SAFETY_PROOF.md, Phase 1).

The proof's whole reason to exist is that it can be *checked*, so the tests
below check it three ways: the happy path (a fully-cited, complete proof is
valid), the degradation path (missing lines, stale plan digests, unscanned
residue), and the negative controls — a hand-written ``PASS`` with nothing
behind it, and a proof carried across a plan change. Both negative controls
must fail closed. A safety proof that can be forged is worse than no safety
proof, because it is trusted.

Timestamps and digests are fixed rather than defaulted so every assertion here
is about the *rules*, not about the clock.
"""

from __future__ import annotations

import ast
import inspect
from datetime import UTC, datetime

import pytest

from mayhem.domain import safety_proof
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.safety_proof import (
    REQUIRED_OBLIGATIONS,
    RESIDUE_PREDICATES,
    Obligation,
    ObligationName,
    ObligationStatus,
    ProofVerdict,
    ResidueObligation,
    ResiduePredicate,
    ResidueScan,
    SafetyProof,
    residue_obligation_name,
)

# Two distinct well-formed plan digests: "the plan this proof was built from"
# and "the plan that is frozen right now".
PLAN_A = "a" * 64
PLAN_B = "c" * 64
# A citation is a sha256 of some gate's output — the same 64-hex shape, a
# different gate, so "cited by the wrong gate" is expressible in a test.
GATE_ADMISSION = "b" * 64
GATE_RESIDUE_SCAN = "d" * 64

MOMENT = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)


def passing(name: str, *, digest: str = GATE_ADMISSION) -> Obligation:
    """A properly cited passing line — the only shape a PASS may take."""
    return Obligation(
        name=name,
        status=ObligationStatus.PASS,
        gate_digest=digest,
        evidence_ref=f"gate-output/{name}",
        evaluated_at=MOMENT,
    )


def full_obligations() -> tuple[Obligation, ...]:
    """Every line the catalogue requires, each citing a gate output."""
    return tuple(passing(name.value) for name in ObligationName)


def proof_of(plan_digest: str = PLAN_A, **kwargs: object) -> SafetyProof:
    return SafetyProof(
        plan_digest=plan_digest,
        obligations=full_obligations(),
        verdict=ProofVerdict.PASS,
        generated_at=MOMENT,
        **kwargs,  # type: ignore[arg-type]
    )


def residue_for(fault_id: str = "net.latency") -> ResidueObligation:
    """An undischarged residue obligation: asserted, cited, not yet discharged."""
    return ResidueObligation(
        fault_id=fault_id,
        status=ObligationStatus.PASS,
        gate_digest=GATE_ADMISSION,
        evidence_ref=f"plan/{fault_id}",
        evaluated_at=MOMENT,
    )


def scan_of(
    fault_id: str = "net.latency",
    *,
    scanned: bool = True,
    dirty: tuple[ResiduePredicate, ...] = (),
    digest: str = GATE_RESIDUE_SCAN,
    evidence: str = "residue-scan/net.latency",
) -> ResidueScan:
    return ResidueScan(
        fault_id=fault_id,
        scanned=scanned,
        dirty_predicates=dirty,
        gate_digest=digest,
        evidence_ref=evidence,
        observed_at=MOMENT,
    )


# -- validity ---------------------------------------------------------------


def test_complete_cited_proof_is_valid() -> None:
    proof = proof_of(PLAN_A)

    assert proof.is_valid(PLAN_A) is True
    assert proof.evaluate(PLAN_A) is ProofVerdict.PASS
    assert proof.missing_obligations() == ()
    assert proof.recompute_verdict() is ProofVerdict.PASS
    assert {o.name for o in proof.obligations} == REQUIRED_OBLIGATIONS


def test_digest_mismatch_voids_rather_than_failing() -> None:
    """A superseded plan voids the proof; it does not fail it, and never passes.

    The distinction matters to a reader: FAIL says "the plan is unsafe", which
    is a claim about the *current* plan. VOID says "this evidence describes a
    plan that no longer exists" — the honest answer when the plan moved.
    """
    proof = proof_of(PLAN_A)

    assert proof.evaluate(PLAN_B) is ProofVerdict.VOID
    assert proof.is_valid(PLAN_B) is False
    assert proof.recompute_verdict() is ProofVerdict.PASS  # the lines still pass
    reasons = proof.void_reasons(PLAN_B)
    assert len(reasons) == 1
    assert "plan superseded" in reasons[0]


def test_missing_obligation_cannot_be_forged_into_a_pass() -> None:
    """Dropping a required line voids the proof; claiming PASS anyway raises."""
    incomplete = tuple(
        o for o in full_obligations() if o.name != ObligationName.RECOVERY_PATH.value
    )

    with pytest.raises(InvariantViolationError, match="only support VOID"):
        SafetyProof(
            plan_digest=PLAN_A,
            obligations=incomplete,
            verdict=ProofVerdict.PASS,
            generated_at=MOMENT,
        )

    honest = SafetyProof(
        plan_digest=PLAN_A,
        obligations=incomplete,
        verdict=ProofVerdict.VOID,
        void_reason="required obligations absent: recovery_path",
        generated_at=MOMENT,
    )
    assert honest.missing_obligations() == (ObligationName.RECOVERY_PATH.value,)
    assert honest.is_valid(PLAN_A) is False


def test_proof_with_no_obligations_is_not_vacuously_valid() -> None:
    """An empty proof proves nothing; all-pass must not read as all-of-nothing."""
    empty = SafetyProof(
        plan_digest=PLAN_A,
        obligations=(),
        verdict=ProofVerdict.VOID,
        void_reason="proof carries no obligations",
        generated_at=MOMENT,
    )

    assert empty.is_valid(PLAN_A) is False
    assert empty.recompute_verdict() is ProofVerdict.VOID
    assert "proof carries no obligations" in empty.void_reasons(PLAN_A)


def test_failing_obligation_fails_the_proof() -> None:
    obligations = (
        *(
            passing(o.name)
            for o in full_obligations()
            if o.name != ObligationName.DAMAGE_BUDGET.value
        ),
        Obligation(
            name=ObligationName.DAMAGE_BUDGET.value,
            status=ObligationStatus.FAIL,
            gate_digest=GATE_ADMISSION,
            evidence_ref="gate-output/damage-budget",
            evaluated_at=MOMENT,
            detail="plan would exceed the cumulative damage budget",
        ),
    )
    proof = SafetyProof(
        plan_digest=PLAN_A,
        obligations=obligations,
        verdict=ProofVerdict.FAIL,
        generated_at=MOMENT,
    )

    assert proof.evaluate(PLAN_A) is ProofVerdict.FAIL
    assert proof.is_valid(PLAN_A) is False
    assert proof.void_reasons(PLAN_A) == ()


def test_void_obligation_outranks_a_passing_line() -> None:
    """One unproven line makes the whole proof unproven — VOID beats PASS."""
    obligations = (
        passing(ObligationName.STOP_CONDITIONS.value),
        Obligation(
            name=ObligationName.TARGET_POLICY.value,
            status=ObligationStatus.VOID,
            evidence_ref="gate-output/target-policy",
            evaluated_at=MOMENT,
            detail="policy gate never returned",
        ),
    )
    proof = SafetyProof(
        plan_digest=PLAN_A,
        obligations=obligations,
        verdict=ProofVerdict.VOID,
        void_reason="target_policy unproven",
        generated_at=MOMENT,
    )

    assert proof.recompute_verdict() is ProofVerdict.VOID
    assert proof.is_valid(PLAN_A) is False


def test_voided_returns_a_revalidated_copy() -> None:
    """The stale rendering keeps its lines, gains a reason, and is not the old PASS."""
    proof = proof_of(PLAN_A)

    voided = proof.voided(PLAN_B)

    assert voided.verdict is ProofVerdict.VOID
    assert "plan superseded" in voided.void_reason
    assert {o.name for o in voided.obligations} == REQUIRED_OBLIGATIONS
    assert voided.is_valid(PLAN_B) is False
    # A fresh proof is untouched: voiding is a copy, not a mutation.
    assert proof.is_valid(PLAN_A) is True
    assert proof.verdict is ProofVerdict.PASS
    # Voiding a proof that is already current is the identity.
    assert proof.voided(PLAN_A) is proof


def test_repeated_obligation_name_is_refused() -> None:
    with pytest.raises(InvariantViolationError, match="repeats an obligation name"):
        SafetyProof(
            plan_digest=PLAN_A,
            obligations=(*full_obligations(), passing(ObligationName.COMPENSATION.value)),
            verdict=ProofVerdict.PASS,
            generated_at=MOMENT,
        )


def test_void_proof_must_say_what_voided_it() -> None:
    with pytest.raises(InvariantViolationError, match="does not say what voided it"):
        SafetyProof(
            plan_digest=PLAN_A,
            obligations=full_obligations(),
            verdict=ProofVerdict.VOID,
            generated_at=MOMENT,
        )


def test_non_void_proof_may_not_carry_a_void_reason() -> None:
    with pytest.raises(InvariantViolationError, match="carries a void_reason"):
        SafetyProof(
            plan_digest=PLAN_A,
            obligations=full_obligations(),
            verdict=ProofVerdict.PASS,
            void_reason="left over from an earlier render",
            generated_at=MOMENT,
        )


def test_plan_digest_must_be_canonical() -> None:
    with pytest.raises(InvariantViolationError, match="sha256 hex digest"):
        SafetyProof(
            plan_digest="not-a-digest",
            obligations=full_obligations(),
            verdict=ProofVerdict.PASS,
            generated_at=MOMENT,
        )


# -- determinism ------------------------------------------------------------


def test_proof_digest_is_stable_and_covers_the_verdict() -> None:
    first = proof_of(PLAN_A)
    second = proof_of(PLAN_A)

    assert first.proof_digest == second.proof_digest
    assert first.canonical_json() == second.canonical_json()
    # The verdict is inside the digest, so an approval bound to a PASS digest
    # cannot be honoured by a later VOID rendering of the same lines.
    assert first.proof_digest != first.voided(PLAN_B).proof_digest
    assert len(first.proof_digest) == 64


def test_proof_round_trips_through_json() -> None:
    proof = SafetyProof(
        plan_digest=PLAN_A,
        obligations=(*full_obligations(), residue_for()),
        verdict=ProofVerdict.PASS,
        generated_at=MOMENT,
    )
    assert proof.missing_obligations() == ()

    restored = SafetyProof.model_validate(proof.model_dump(mode="json"))

    assert restored.proof_digest == proof.proof_digest
    # Subclass structure survives the artifact round trip, so a residue line
    # does not decay into a bare Obligation on its way to storage.
    assert len(restored.residue_obligations) == 1
    assert restored.residue_obligations[0].fault_id == "net.latency"


# -- residue obligations ----------------------------------------------------


def test_residue_obligation_asserts_every_predicate() -> None:
    obligation = residue_for()

    assert obligation.name == residue_obligation_name("net.latency") == "residue:net.latency"
    assert {p.value for p in obligation.predicates} == RESIDUE_PREDICATES
    assert len(obligation.predicates) == 6
    assert obligation.discharged is True  # nothing found; not yet checked


def test_residue_obligation_refuses_a_weaker_predicate_set() -> None:
    """A 'residue check' that forgot no_leases_held is not a residue check."""
    with pytest.raises(InvariantViolationError, match="residue_predicates_incomplete"):
        ResidueObligation(
            fault_id="net.latency",
            status=ObligationStatus.PASS,
            gate_digest=GATE_ADMISSION,
            evidence_ref="plan/net.latency",
            predicates=(
                ResiduePredicate.NO_TC_RULES,
                ResiduePredicate.NO_IPTABLES_ENTRIES,
                ResiduePredicate.NO_MARKER_PROCESSES,
                ResiduePredicate.NO_FILES,
                ResiduePredicate.NO_CGROUP_OVERRIDES,
            ),
        )


def test_residue_obligation_refuses_a_non_canonical_name() -> None:
    with pytest.raises(InvariantViolationError, match="residue_name_not_canonical"):
        ResidueObligation(
            name="residue",
            fault_id="net.latency",
            status=ObligationStatus.PASS,
            gate_digest=GATE_ADMISSION,
            evidence_ref="plan/net.latency",
        )


def test_clean_scan_discharges_to_pass() -> None:
    discharged = residue_for().discharge(scan_of())

    assert discharged.status is ObligationStatus.PASS
    assert discharged.is_pass is True
    assert discharged.discharged is True
    assert discharged.gate_digest == GATE_RESIDUE_SCAN
    assert discharged.evidence_ref == "residue-scan/net.latency"
    assert discharged.detail == "residue scan clean on all asserted predicates"
    # Discharge is a copy: the original obligation is unchanged.
    assert residue_for().status is ObligationStatus.PASS


@pytest.mark.parametrize(
    ("predicate", "expected_in_detail"),
    [
        (ResiduePredicate.NO_TC_RULES, "no_tc_rules"),
        (ResiduePredicate.NO_IPTABLES_ENTRIES, "no_iptables_entries"),
        (ResiduePredicate.NO_MARKER_PROCESSES, "no_marker_processes"),
        (ResiduePredicate.NO_FILES, "no_files"),
        (ResiduePredicate.NO_CGROUP_OVERRIDES, "no_cgroup_overrides"),
        (ResiduePredicate.NO_LEASES_HELD, "no_leases_held"),
    ],
)
def test_found_residue_voids_the_line(
    predicate: ResiduePredicate, expected_in_detail: str
) -> None:
    """Found residue voids the corresponding line — it does not merely fail it."""
    discharged = residue_for().discharge(scan_of(dirty=(predicate,)))

    assert discharged.status is ObligationStatus.VOID
    assert discharged.discharged is False
    assert expected_in_detail in discharged.detail
    assert discharged.gate_digest == GATE_RESIDUE_SCAN


def test_multiple_found_predicates_are_all_named() -> None:
    discharged = residue_for().discharge(
        scan_of(dirty=(ResiduePredicate.NO_FILES, ResiduePredicate.NO_LEASES_HELD))
    )

    assert discharged.status is ObligationStatus.VOID
    assert "no_files" in discharged.detail
    assert "no_leases_held" in discharged.detail


def test_unscanned_fault_fails_rather_than_assuming_clean() -> None:
    discharged = residue_for().discharge(scan_of(scanned=False, digest="", evidence=""))

    assert discharged.status is ObligationStatus.FAIL
    assert discharged.discharged is True
    assert "did not run" in discharged.detail


def test_scan_for_another_fault_cannot_discharge_this_one() -> None:
    with pytest.raises(InvariantViolationError, match="residue_scan_fault_mismatch"):
        residue_for("net.latency").discharge(scan_of("cpu.starve"))


def test_residue_finding_cannot_be_uncited() -> None:
    """A scan that reports residue but names no gate output is not evidence."""
    with pytest.raises(InvariantViolationError, match="cites no gate output"):
        ResidueScan(
            fault_id="net.latency",
            scanned=True,
            dirty_predicates=(ResiduePredicate.NO_FILES,),
            evidence_ref="residue-scan/net.latency",
            observed_at=MOMENT,
        )


def test_discharge_cannot_mint_an_uncited_pass_line() -> None:
    """The citation rule survives the discharge transition, not just construction."""
    obligation = residue_for()

    with pytest.raises(InvariantViolationError, match="sha256 hex digest"):
        obligation.discharge(scan_of(digest="", evidence=""))


def test_residue_obligation_inherits_the_base_citation_check() -> None:
    """Regression guard: the subclass's own validator must not shadow the base.

    Pydantic indexes model validators by attribute name down the MRO, so a
    ``ResidueObligation`` validator also called ``_check_invariants`` would
    *replace* the base citation check rather than add to it — and an uncited
    ``pass`` on a residue line would then be constructible.
    """
    with pytest.raises(InvariantViolationError, match="pass_requires_cited_gate_digest"):
        ResidueObligation(fault_id="net.latency", status=ObligationStatus.PASS)

    with pytest.raises(InvariantViolationError, match="pass_requires_citation"):
        ResidueObligation(
            fault_id="net.latency",
            status=ObligationStatus.PASS,
            gate_digest=GATE_ADMISSION,
            evidence_ref="",
        )


def test_voided_residue_line_voids_the_whole_proof() -> None:
    """A dirty fault cannot close its run clean: the proof is VOID, not PASS."""
    discharged = residue_for().discharge(scan_of(dirty=(ResiduePredicate.NO_TC_RULES,)))
    proof = SafetyProof(
        plan_digest=PLAN_A,
        obligations=(*full_obligations(), discharged),
        verdict=ProofVerdict.VOID,
        void_reason="residue found: no_tc_rules",
        generated_at=MOMENT,
    )

    assert proof.evaluate(PLAN_A) is ProofVerdict.VOID
    assert proof.is_valid(PLAN_A) is False
    assert proof.residue_obligations[0].status is ObligationStatus.VOID


def test_clean_residue_line_leaves_the_proof_passing() -> None:
    discharged = residue_for().discharge(scan_of())
    proof = SafetyProof(
        plan_digest=PLAN_A,
        obligations=(*full_obligations(), discharged),
        verdict=ProofVerdict.PASS,
        generated_at=MOMENT,
    )

    assert proof.is_valid(PLAN_A) is True
    assert proof.missing_obligations() == ()  # residue lines are additional, never required


# -- negative controls ------------------------------------------------------


def test_forged_pass_line_without_gate_output_is_refused() -> None:
    """A hand-written 'pass' with nothing behind it is malformed, not passing."""
    with pytest.raises(InvariantViolationError, match="pass_requires_cited_gate_digest"):
        Obligation(name="damage_budget", status=ObligationStatus.PASS)


def test_forged_pass_line_with_blank_evidence_is_refused() -> None:
    with pytest.raises(InvariantViolationError, match="pass_requires_citation"):
        Obligation(
            name="damage_budget",
            status=ObligationStatus.PASS,
            gate_digest=GATE_ADMISSION,
            evidence_ref="   ",
        )


@pytest.mark.parametrize("bogus", ["deadbeef", "not-a-digest", "A" * 64, "a" * 63])
def test_forged_pass_line_with_a_non_canonical_citation_is_refused(bogus: str) -> None:
    with pytest.raises(InvariantViolationError, match="sha256 hex digest"):
        Obligation(
            name="damage_budget",
            status=ObligationStatus.PASS,
            gate_digest=bogus,
            evidence_ref="gate-output/damage-budget",
        )


def test_forged_pass_proof_over_a_failing_line_is_refused() -> None:
    """The strongest forgery: real citations on some lines, none on the failure."""
    obligations = (
        passing(ObligationName.MAX_DURATION.value),
        Obligation(
            name=ObligationName.CAPABILITY_REQUIREMENTS.value,
            status=ObligationStatus.FAIL,
            evidence_ref="gate-output/capability-requirements",
            evaluated_at=MOMENT,
        ),
    )
    with pytest.raises(InvariantViolationError, match="only support FAIL"):
        SafetyProof(
            plan_digest=PLAN_A,
            obligations=obligations,
            verdict=ProofVerdict.PASS,
            generated_at=MOMENT,
        )


@pytest.mark.parametrize(
    "stale_digest",
    [
        "0" * 64,
        "1" * 64,
        PLAN_B,
        "f" * 64,
        "9" * 63 + "0",
    ],
)
def test_stale_digest_proof_is_never_pass(stale_digest: str) -> None:
    """One canonical-hash mutation anywhere in the plan is enough to void it."""
    proof = proof_of(PLAN_A)

    assert proof.is_valid(stale_digest) is False
    assert proof.evaluate(stale_digest) is ProofVerdict.VOID
    assert proof.voided(stale_digest).verdict is ProofVerdict.VOID
    assert proof.voided(stale_digest).is_valid(stale_digest) is False


def test_digest_change_voids_a_residue_carrying_proof_too() -> None:
    proof = SafetyProof(
        plan_digest=PLAN_A,
        obligations=(*full_obligations(), residue_for()),
        verdict=ProofVerdict.PASS,
        generated_at=MOMENT,
    )

    voided = proof.voided(PLAN_B)

    assert voided.verdict is ProofVerdict.VOID
    assert voided.is_valid(PLAN_B) is False
    # The residue line is still there, still typed, still not a PASS.
    assert voided.residue_obligations[0].fault_id == "net.latency"
    assert voided.residue_obligations[0].status is ObligationStatus.PASS


# -- domain law -------------------------------------------------------------


def test_module_imports_nothing_above_the_domain() -> None:
    """This file is the proof; it may not import the machinery that runs gates.

    The same ban import-linter enforces repo-wide is asserted here for this one
    module so the proof's own type cannot quietly grow a dependency on IO, a
    subprocess, or an upper layer.
    """
    forbidden = {
        "asyncio",
        "os",
        "socket",
        "sqlite3",
        "subprocess",
        "pathlib",
        "mayhem.agents",
        "mayhem.controller",
        "mayhem.infra",
        "mayhem.toolkit",
    }
    tree = ast.parse(inspect.getsource(safety_proof))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module)
    roots = {name.split(".")[0] for name in imported}

    assert roots & forbidden == set()
    assert not {name for name in imported if name.startswith("mayhem.")} - {
        "mayhem.domain.common",
        "mayhem.domain.errors",
        "mayhem.domain.hashing",
    }
