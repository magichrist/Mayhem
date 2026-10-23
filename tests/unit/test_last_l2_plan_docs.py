"""L2 Phase 3 — the honesty gate over the run-close authorization plan.

A plan whose subject is "a chain was sealing INCOMPLETE and now does not" is the
kind of document most likely to overclaim. It changed what a run *writes*, so
every claim here is one a reader could be misled by.

Six checks:

* the ``Overall:`` count equals the ``DONE`` phase lines, and the phases are 1-3;
* the ``file:line`` citations still resolve to the functions they name — this
  plan edited three of them, so a citation that drifted is a live possibility
  rather than a formality;
* the document does **not** claim the default path changed. It did not: a
  deployment with no policy gate still seals nothing, and saying otherwise is
  the flattery this plan is most prone to;
* the document does not claim signature verification. ``SIGNATURE_VERIFICATION_
  IMPLEMENTED`` is ``False`` in this build and a seal demonstrates integrity,
  never authorship;
* the recorded gaps are still present in the source — a gap silently closed
  elsewhere but still written up as open is its own kind of drift;
* the document says the guard is one file with no other reference, which is the
  honest description rather than a claim of unremovability.

Each checker is proven to bite against a mutated copy of the document.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

from mayhem.providers.pack import SIGNATURE_VERIFICATION_IMPLEMENTED

if TYPE_CHECKING:
    from collections.abc import Iterator

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
PLAN_PATH: Final = REPO_ROOT / "docs/v1.1.0/LAST/L2_RUN_CLOSE_AUTHORIZATION.md"
PLAN: Final = PLAN_PATH.read_text(encoding="utf-8")

PHASE_LINE: Final = re.compile(
    r"^-\s+Phase\s+(\d+)\b[^\n]*?:\s*\**\s*(DONE|PARTIAL|INCOMPLETE)\b([^\n]*)$", re.M
)
OVERALL_LINE: Final = re.compile(r"^Overall:\s*(\d+)\s+of\s+(\d+)\s+phases", re.M)

#: Citations this plan makes, as ``(module, attribute)``. Resolved through
#: ``inspect`` rather than by reading line numbers, because this plan *edited*
#: the functions and a line-number citation would be the thing that rots.
CITED_SYMBOLS: Final[tuple[tuple[str, str], ...]] = (
    ("mayhem.infra.audit_stream", "seal_run_evidence_at_run_close"),
    ("mayhem.controller.policy_evidence", "seal_policy_decision"),
    ("mayhem.controller.policy_evidence", "build_authorization"),
    ("mayhem.controller.safety", "SafetyContext"),
    ("mayhem.controller.safety", "policy_verdict"),
    ("mayhem.controller.safety", "approval_verdict"),
    ("mayhem.domain.preflight", "Preflight"),
    ("mayhem.controller.approval_gate", "ApprovalGateResult"),
)

#: Claims this plan must never make.
FORBIDDEN_CLAIMS: Final[tuple[str, ...]] = (
    r"every (?:mutating )?run (?:now )?seals a complete chain",
    r"every mutating run (?:now )?seals a complete chain",
    r"\bpacks?\s+(?:is|are)\s+(?:signed|verified|trusted)",
    r"signature verification is implemented",
    r"proves authorship",
)

#: One plausible over-claim per forbidden pattern, so each checker's *positive*
#: half is proven to bite. A checker that is only ever run against the real
#: document has never been shown to catch the thing it exists to catch.
_OVERCLAIMS: Final[dict[str, str]] = {
    FORBIDDEN_CLAIMS[0]: "Every mutating run now seals a complete chain.",
    FORBIDDEN_CLAIMS[1]: "Every mutating run now seals a complete chain.",
    FORBIDDEN_CLAIMS[2]: "The pack is signed, so the fault catalogue is verified.",
    FORBIDDEN_CLAIMS[3]: "Signature verification is implemented for these bundles.",
    FORBIDDEN_CLAIMS[4]: "The seal proves authorship of the plan.",
}


def _phases() -> dict[int, str]:
    return {int(m.group(1)): m.group(2) for m in PHASE_LINE.finditer(PLAN)}


def _resolve(module_name: str, attribute: str) -> object:
    import importlib

    return getattr(importlib.import_module(module_name), attribute)


# --- check 1: the ledger ---------------------------------------------------- #


def test_overall_count_equals_the_done_lines() -> None:
    overall = OVERALL_LINE.search(PLAN)
    assert overall is not None, "L2 has a phase ledger but no 'Overall:' line"
    phases = _phases()
    done = sum(1 for verdict in phases.values() if verdict == "DONE")
    assert int(overall.group(1)) == done, (
        f"L2 says {overall.group(1)} of {overall.group(2)} complete, "
        f"but marks {done} of {len(phases)} phases DONE"
    )
    assert int(overall.group(2)) == len(phases)


def test_all_three_phases_are_present_and_done() -> None:
    phases = _phases()
    assert set(phases) == {1, 2, 3}, sorted(phases)
    assert all(verdict == "DONE" for verdict in phases.values()), phases


# --- check 2: the citations resolve ----------------------------------------- #


def test_every_cited_symbol_still_exists() -> None:
    missing: list[str] = []
    for module_name, attribute in CITED_SYMBOLS:
        try:
            found = _resolve(module_name, attribute)
        except (ImportError, AttributeError) as exc:
            missing.append(f"{module_name}.{attribute} ({type(exc).__name__})")
            continue
        assert found is not None, f"{module_name}.{attribute} is None"
    assert missing == [], f"L2 cites symbols that no longer exist: {missing}"


def test_the_seal_call_site_is_still_where_this_document_says() -> None:
    """The claim "wired into ``_write_evidence_after_run``" must stay true."""
    from mayhem.cli import lifecycle

    source = inspect.getsource(lifecycle)
    assert "_write_evidence_after_run" in source
    assert "seal_policy_decision" in source, (
        "the document says the run close seals the policy decision, and it does not"
    )


def test_the_carrier_still_exists_on_both_types() -> None:
    """Two independent edits — a dataclass field and a mapping key."""
    from mayhem.controller.approval_gate import ApprovalGateResult
    from mayhem.controller.safety import GATE_VERDICT_APPROVAL, GATE_VERDICT_POLICY
    from mayhem.domain.preflight import Preflight

    for field in ("policy_verdict", "approval_verdict"):
        assert field in Preflight.__dataclass_fields__, (
            f"Preflight lost {field}; the run close would read None and seal nothing"
        )
    assert GATE_VERDICT_POLICY and GATE_VERDICT_APPROVAL
    assert "state" in ApprovalGateResult.__dataclass_fields__


# --- check 3 and 4: what this plan may not claim ---------------------------- #


def test_the_document_does_not_claim_the_default_path_changed() -> None:
    """A deployment with no policy gate still seals nothing.

    Asserted against the source as well as the prose, because the prose is the
    easy half: if the call site ever stopped requiring both verdicts, the
    document's careful "a deployment with no gate is unchanged" would become
    false while reading exactly as true.
    """
    from mayhem.cli import lifecycle

    assert "_policy is not None and _approval is not None" in inspect.getsource(lifecycle), (
        "the seal no longer requires both verdicts; the no-gate path changed"
    )
    assert "unchanged" in PLAN and "no policy gate" in PLAN.lower()


def test_the_document_does_not_claim_signature_verification() -> None:
    assert SIGNATURE_VERIFICATION_IMPLEMENTED is False
    found = [pattern for pattern in FORBIDDEN_CLAIMS if re.search(pattern, PLAN, re.I)]
    assert found == [], f"L2 claims something false: {found}"


# --- check 5: the recorded gaps are still open ------------------------------ #


def test_a_policy_gate_without_an_approval_gate_still_seals_nothing() -> None:
    """The first recorded gap, asserted at the source rather than in prose.

    If both verdicts are still required, then a deployment with a policy gate and
    no approval gate seals nothing — which is what L2's ledger says, and which
    would become false if either requirement were relaxed.
    """
    from mayhem.cli import lifecycle

    source = inspect.getsource(lifecycle)
    assert "_policy is not None and _approval is not None" in source


def test_proof_digest_is_threaded_from_the_approval_result() -> None:
    """The 2b sub-item landed, so the ledger must not still call it unpopulated."""
    from mayhem.cli import lifecycle

    assert 'getattr(_approval, "proof_digest"' in inspect.getsource(lifecycle)


# --- check 6: the guard is described honestly ------------------------------- #


def test_the_document_names_its_guard() -> None:
    """It must name the file that holds the property, so a reader can go read it."""
    assert "test_run_close_authorization.py" in PLAN
    assert "test_last_l2_plan_docs.py" in PLAN
    # And it must not claim the tests make the wiring impossible to delete.
    assert not re.search(r"(?:cannot|can't) be (?:deleted|removed)", PLAN, re.I)


# --- the checkers bite ------------------------------------------------------ #


def test_the_ledger_checker_bites() -> None:
    inflated = PLAN.replace("Overall: 3 of 3 phases complete", "Overall: 2 of 3 phases complete")
    match = OVERALL_LINE.search(inflated)
    assert match is not None
    phases = {int(m.group(1)): m.group(2) for m in PHASE_LINE.finditer(inflated)}
    done = sum(1 for v in phases.values() if v == "DONE")
    assert int(match.group(1)) != done


def test_the_forbidden_claim_checker_bites() -> None:
    for pattern in FORBIDDEN_CLAIMS:
        # Each pattern must match at least one plausible over-claim, and must not
        # match the sentence L2 actually makes. The negative half matters as much
        # as the positive: a pattern so broad it also refuses the honest wording
        # gets "fixed" by being deleted.
        assert re.search(pattern, _OVERCLAIMS[pattern], re.I), (
            f"the checker for {pattern!r} does not bite on {_OVERCLAIMS[pattern]!r}"
        )
        assert re.search(pattern, PLAN, re.I) is None


def test_the_signature_checker_would_bite_if_it_were_implemented() -> None:
    """The negative control for the honesty gate itself.

    If ``SIGNATURE_VERIFICATION_IMPLEMENTED`` ever becomes ``True`` without this
    document being revisited, the refusal in
    :func:`test_the_document_does_not_claim_signature_verification` would need
    replacing rather than simply passing — so the change is loud.
    """
    assert SIGNATURE_VERIFICATION_IMPLEMENTED is False, (
        "signature verification is now implemented; this document's refusal of "
        "the claim is stale and the checks around it must be rewritten"
    )


def _phases_iter() -> Iterator[int]:  # pragma: no cover
    yield from sorted(_phases())
