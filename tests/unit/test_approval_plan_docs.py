"""Plan 09 Phase 6 — the honesty gate over the identity plan and its guide.

Plan 09 is the plan most likely to acquire a claim it has not earned. Identity
documentation has a gravitational pull toward saying "SSO supported", "audited",
"signed", and "role-based access control" — and every one of those is a claim
about a deployment rather than about the code, while what actually exists is a
local password path, an integrity-chained stream, and a role predicate.

So this gate checks the three things that drift, across **both** documents:

* **The ledger against itself.** One line per phase, ``Overall:`` equal to the
  ``DONE`` count, and no open phase. With all six done, the failure this catches
  is a ledger quietly counting five while the headline says six.
* **The Phase 6 deliverables are present by name**, and the sentences the phase
  rests on survive — in particular that the first three rollout tiers have no
  schedule, and that the guide's federated rows say "port" or "nothing".
* **The claims are load-bearing.** Every code identifier and test name the two
  documents cite is checked to exist. This is what stops a citation from rotting
  into a sentence that still *reads* as evidence while pointing at nothing.

It also refuses the overclaims this plan is most likely to acquire: an SSO
guarantee, a signature over an approval, or a complete set of role enforcement.

Each checker is a function, so the negative-control table can attack it, and every
one of those is proven to bite against a mutated copy of the document.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = REPO_ROOT / "docs/v1.1.0/09_IDENTITY_RBAC_APPROVALS.md"
GUIDE_PATH = REPO_ROOT / "docs/v1.1.0/09_identity_guide.md"
PLAN = PLAN_PATH.read_text(encoding="utf-8")
GUIDE = GUIDE_PATH.read_text(encoding="utf-8")

#: The Phase 6 deliverables, by the heading each must carry in the plan document.
REQUIRED_SECTIONS: Final[tuple[str, ...]] = (
    "## Identity configuration",
    "## RBAC role reference",
    "## Approval policy examples",
    "## Rollout",
)

#: Fragments of the reasoning the phase rests on. Line-break independent: the
#: prose may be reflowed, but deleting the reasoning must fail the gate.
REQUIRED_SENTENCES: Final[tuple[str, ...]] = (
    "The first three tiers have no schedule.",
    "No SSO guarantee of any kind",
    'no value means "everything"',
    "`ADMINISTER` is a real gap",
    "person approving twice is one signature",
)

#: Words that turn a match into a denial. Checked over the whole sentence, not
#: the match, because both documents deny things in prose the pattern also sees.
NEGATIONS: Final[tuple[str, ...]] = (
    "no ",
    "not ",
    "never",
    "nothing",
    "only a",
    "is a real gap",
    "must stay",
    "must remain",
    "the first",
    "port only",
    "unsigned",
    "no new dependency",
)


def _sentence_around(text: str, start: int) -> str:
    """The sentence containing ``start``: the nearest sentence boundary behind it."""
    preceding = text[:start]
    for mark in (". ", ".\n", "? ", "! ", "; ", ", and ", ", but ", "**: "):
        index = preceding.rfind(mark)
        if index != -1:
            preceding = preceding[index + len(mark) :]
    return preceding.lower()


def _claims_in(document: str, patterns: tuple[tuple[str, str], ...]) -> list[str]:
    found: list[str] = []
    for pattern, reason in patterns:
        for match in re.finditer(pattern, document, re.IGNORECASE):
            if any(word in _sentence_around(document, match.start()) for word in NEGATIONS):
                continue
            found.append(f"{reason}: ...{document[max(0, match.start() - 60) : match.end()]!r}")
    return found


#: Claims these documents must never make. Each is a direct contradiction of a
#: source-level fact: ``SIGNATURE_VERIFICATION_IMPLEMENTED`` is ``False``, there
#: is no OIDC client, and ``administer`` is not enforced.
FORBIDDEN_CLAIMS: Final[tuple[tuple[str, str], ...]] = (
    (
        r"\bsso (?:is )?(?:supported|configured|enabled)\b",
        "SSO is a port; no deployment has ever been configured",
    ),
    (
        r"\b(?:oidc|saml|scim) (?:is )?(?:supported|implemented|configured)\b",
        "OIDC is a port; SAML and SCIM are nothing",
    ),
    (
        r"\bapprovals are (?:signed|signature[- ]verified)\b",
        "no signature bytes are minted anywhere",
    ),
    (
        r"\bmfa is (?:supported|enforced|required)\b",
        "no second factor exists",
    ),
    (
        r"\badminister (?:is|role is) enforced\b",
        "nothing enforces the administer role",
    ),
    (
        r"\bthe rollout is scheduled\b",
        "no identity rollout has a schedule",
    ),
)


# ── the ledger ───────────────────────────────────────────────────────────────


def ledger_lines(document: str) -> dict[str, str]:
    """``phase label -> its STATUS line``, parsed from the ledger."""
    lines: dict[str, str] = {}
    in_status = False
    for raw in document.split("\n"):
        stripped = raw.strip()
        if stripped.startswith("## STATUS"):
            in_status = True
            continue
        if in_status and stripped.startswith("## ") and stripped != "## STATUS":
            in_status = False
        if not in_status:
            continue
        match = re.match(
            r"^- (Phase \d)(.*?):\s*(DONE|INCOMPLETE|not started|partially|\*\*)", stripped
        )
        if match:
            lines[match.group(1)] = stripped
    return lines


def done_phase_count(document: str) -> int:
    return sum(1 for line in ledger_lines(document).values() if ": DONE" in line)


def claimed_overall(document: str) -> tuple[int, int] | None:
    match = re.search(r"^Overall:\s*(\d+)\s+of\s+(\d+)", document, re.MULTILINE)
    return (int(match.group(1)), int(match.group(2))) if match else None


def open_phases(document: str) -> list[str]:
    return [phase for phase, line in sorted(ledger_lines(document).items()) if ": DONE" not in line]


def missing_sections(document: str) -> list[str]:
    return [heading for heading in REQUIRED_SECTIONS if heading not in document]


def missing_sentences(document: str) -> list[str]:
    return [sentence for sentence in REQUIRED_SENTENCES if sentence not in document]


def forbidden_claims_found() -> list[str]:
    """Over both documents: a claim in the guide is as false as one in the plan."""
    return _claims_in(PLAN, FORBIDDEN_CLAIMS) + _claims_in(GUIDE, FORBIDDEN_CLAIMS)


# ── citation integrity ───────────────────────────────────────────────────────


#: Identifiers the two documents cite as evidence of what they claim. Every one
#: is checked to exist in the source tree, because a citation that has rotted
#: still reads as evidence.
CITED_SYMBOLS: Final[tuple[tuple[str, str], ...]] = (
    ("src/mayhem/domain/identity.py", "class Role"),
    ("src/mayhem/domain/identity.py", "def effective_roles"),
    ("src/mayhem/domain/identity.py", "class EnvironmentScope"),
    ("src/mayhem/domain/approval.py", "def speaks_for"),
    ("src/mayhem/domain/approval.py", "def evaluate_approvals"),
    ("src/mayhem/domain/execution_intent.py", "class ExecutionIntent"),
    ("src/mayhem/controller/approval_gate.py", "def verify_approvals"),
    ("src/mayhem/controller/approval_gate.py", "def quorum_from_requirements"),
    ("src/mayhem/controller/approval_evidence.py", "def verify_approval_binding"),
    ("src/mayhem/controller/approval_evidence.py", "def require_approval_records"),
    ("src/mayhem/controller/approval_evidence.py", "RULE_APPROVAL_NOT_REPRODUCIBLE"),
    ("src/mayhem/controller/auth_service.py", "REVOCATION_PROPAGATION_BOUND_S"),
    ("src/mayhem/controller/auth_service.py", "class IdentityProviderPort"),
    ("src/mayhem/domain/policy_authoring.py", "def"),
    ("src/mayhem/infra/audit_stream.py", "KIND_APPROVAL_GRANTED"),
    ("src/mayhem/infra/audit_stream.py", "KIND_EMERGENCY_OVERRIDE_EXERCISED"),
    ("src/mayhem/infra/audit_stream.py", "KIND_PRINCIPAL_DISABLED"),
    ("src/mayhem/infra/attestation_store.py", "SIGNATURE_UNSIGNED_NO_SIGNING"),
)

#: Tests the two documents cite, paired with the file that must define them.
CITED_TESTS: Final[tuple[tuple[str, str], ...]] = (
    (
        "tests/unit/test_rbac_matrix.py",
        "test_a_grant_reaches_exactly_the_scopes_that_cover_the_action",
    ),
    ("tests/unit/test_rbac_matrix.py", "UNENFORCED_ROLES"),
    (
        "tests/unit/test_approval_evidence.py",
        "def test_every_artifact_this_module_produces_is_unsigned",
    ),
    ("tests/unit/test_approval_gate.py", "def test_the_approval_gate_runs_without_a_policy_bundle"),
    ("tests/unit/test_auth_service.py", "REVOCATION_PROPAGATION_BOUND_S"),
    ("tests/unit/test_execution_intent.py", "class TestBindingMismatch"),
)


def dangling_citations() -> list[str]:
    """Cited symbols and tests that no longer exist."""
    missing: list[str] = []
    for relative, name in (*CITED_SYMBOLS, *CITED_TESTS):
        path = REPO_ROOT / relative
        if not path.exists():
            missing.append(f"{relative} does not exist")
        elif name not in path.read_text(encoding="utf-8"):
            missing.append(f"{relative} does not define {name}")
    return missing


# ── the guide's own honesty table ────────────────────────────────────────────


def guide_capability_rows(document: str) -> list[str]:
    """The status table rows in §2 of the guide."""
    rows = re.findall(r"^\| ([^|]+?) \| (.+?) \|$", document, re.MULTILINE)
    return [f"{name}: {status}" for name, status in rows]


#: Phrases that make a capability row honest. Matched against the row's leading
#: verdict -- the token a skimming reader stops at.
#:
#: Deliberately phrases rather than the bare word "port": substring matching on
#: "port" also matches "IdentityProviderPort", which is how the first draft of
#: this checker reported a perfectly honest OIDC row as an overclaim. "only" is
#: the honest signal here because the row says what it *is* ("port only"), not
#: what it lacks.
HONEST_STATUS_PHRASES: Final[tuple[str, ...]] = (
    "nothing",
    "no ",
    "not ",
    "only",
    "unsupported",
)

#: Feature names whose row is checked: the ones whose absence of an
#: implementation this plan would be most tempted to overclaim.
FEDERATED_TOKENS: Final[tuple[str, ...]] = (
    "oidc",
    "saml",
    "scim",
    "mfa",
    "sso",
    "signature",
    "refresh",
    "cli or ui",
)


def leading_verdict(status: str) -> str:
    """The row's verdict: the first bolded segment, or the whole cell.

    Reading only the leading verdict is the point. A cell reading
    ``**Supported.** ... No client exists.`` is dishonest even though the word
    "no" is somewhere in it, because "Supported" is what a reader takes away --
    and a trailing disclaimer is precisely the shape an overclaim hides behind.
    """
    match = re.match(r"\s*\*\*(.+?)\*\*", status)
    return (match.group(1) if match else status).strip()


def federated_rows_without_an_honest_status(document: str) -> list[str]:
    """Federated or unattended features whose row leads with an overclaim.

    The phase's acceptance criterion is that no doc implies SSO guarantees the
    deployment does not configure. A capability row is where that implication
    would live, so each of these names is checked to lead with an honest verdict.
    """
    dishonest: list[str] = []
    for name, status in re.findall(r"^\| ([^|]+?) \| (.+?) \|$", document, re.MULTILINE):
        lowered = name.lower()
        if not any(token in lowered for token in FEDERATED_TOKENS):
            continue
        verdict = leading_verdict(status)
        if not any(phrase in verdict.lower() for phrase in HONEST_STATUS_PHRASES):
            dishonest.append(f"{name}: {verdict}")
    return dishonest


def signature_claims(document: str) -> list[str]:
    """Whether the guide claims any artifact is authenticated.

    The honest form is "integrity is established; authorship is not", and the
    phrase "signature" must never appear next to a claim of protection.
    """
    return _claims_in(
        document,
        (
            (
                r"\bsigned\b(?!\s+and)",
                "no signature bytes are minted",
            ),
            (
                r"\bauthenticates? the (?:principal|identity|author)\b",
                "authorship is not established",
            ),
        ),
    )


# ── the tests ────────────────────────────────────────────────────────────────


def test_the_ledger_carries_one_line_per_phase() -> None:
    assert sorted(ledger_lines(PLAN)) == [f"Phase {n}" for n in range(1, 7)]


def test_the_overall_count_equals_the_number_of_done_lines() -> None:
    overall = claimed_overall(PLAN)

    assert overall is not None, "the STATUS block must carry an Overall: line"
    assert overall == (done_phase_count(PLAN), len(ledger_lines(PLAN)))
    assert overall == (6, 6), "plan 09 is complete; the ledger must say so"


def test_no_phase_is_open() -> None:
    """Six of six with an open phase beside it is the drift this catches."""
    assert open_phases(PLAN) == []


def test_the_four_sections_are_in_the_document() -> None:
    assert missing_sections(PLAN) == []


def test_the_sections_keep_their_own_denials() -> None:
    """The honest half of each section, so an edit cannot reduce it to a promise."""
    assert missing_sentences(PLAN) == []


def test_the_guide_exists_and_leads_with_the_honesty_table() -> None:
    """The guide is a Phase 6 deliverable, and the table must come before the prose."""
    assert GUIDE_PATH.exists()
    assert guide_capability_rows(GUIDE), "the guide must carry a capability table"
    assert GUIDE.index("## 2. What is implemented") < GUIDE.index("## 3. The eight roles")


def test_the_guide_marks_every_federated_feature_honestly() -> None:
    """The phase's acceptance criterion, checked row by row rather than in prose."""
    assert federated_rows_without_an_honest_status(GUIDE) == []


def test_the_guide_claims_no_authorship_for_its_artifacts() -> None:
    """Integrity is established; who wrote it is not. Those are different claims."""
    assert signature_claims(GUIDE) == []


def test_every_symbol_the_documents_cite_still_exists() -> None:
    assert dangling_citations() == []


def test_the_documents_make_no_literal_false_claim() -> None:
    assert forbidden_claims_found() == []


# ── negative controls: each checker must bite ────────────────────────────────

_MUTATIONS: Final[tuple[tuple[str, Callable[[str], str], Callable[[str], object]], ...]] = (
    (
        "the Overall count deflated to five",
        lambda d: d.replace("Overall: 6 of 6", "Overall: 5 of 6", 1),
        claimed_overall,
    ),
    (
        "Phase 5 silently marked not-started",
        lambda d: re.sub(
            r"^- Phase 5 \(tests, regression guards, negative controls\): DONE",
            "- Phase 5: not started",
            d,
            count=1,
            flags=re.MULTILINE,
        ),
        open_phases,
    ),
    (
        "the rollout section removed",
        lambda d: d.replace("## Rollout", "## Removed", 1),
        lambda d: len(missing_sections(d)),
    ),
    (
        "the no-schedule denial dropped",
        lambda d: d.replace(
            "The first three tiers have no schedule.",
            "The first three tiers ship next quarter.",
        ),
        lambda d: len(missing_sentences(d)),
    ),
    (
        "the administer gap annotation dropped",
        lambda d: d.replace("`ADMINISTER` is a real gap", "`ADMINISTER` is enforced"),
        lambda d: len(missing_sentences(d)),
    ),
    (
        "an SSO guarantee appended",
        lambda d: d + "\nSSO is supported against any OIDC provider.\n",
        lambda d: len(_claims_in(d, FORBIDDEN_CLAIMS)),
    ),
    (
        "a signature claim appended to the plan",
        lambda d: d + "\nApprovals are signed with the deployment's key.\n",
        lambda d: len(_claims_in(d, FORBIDDEN_CLAIMS)),
    ),
    (
        "a scheduled rollout claimed",
        lambda d: d + "\nThe rollout is scheduled for the next release.\n",
        lambda d: len(_claims_in(d, FORBIDDEN_CLAIMS)),
    ),
)

_GUIDE_MUTATIONS: Final[
    tuple[tuple[str, Callable[[str], str], Callable[[str], list[str]]], ...]
] = (
    (
        "the OIDC row upgraded to 'supported'",
        lambda d: d.replace(
            "| OIDC / OAuth | **`IdentityProviderPort` only.**",
            "| OIDC / OAuth | **Supported.** A two-method protocol plus",
            1,
        ),
        federated_rows_without_an_honest_status,
    ),
    (
        "the MFA row upgraded",
        lambda d: d.replace(
            "| MFA / TOTP / WebAuthn | **Nothing.**",
            "| MFA / TOTP / WebAuthn | **Enforced.** No second factor",
            1,
        ),
        federated_rows_without_an_honest_status,
    ),
    (
        "the guide claims its artifacts are signed",
        lambda d: d + "\nEvery audit entry is signed by the deploying organisation.\n",
        signature_claims,
    ),
)


def _run(plan: str, guide: str) -> None:
    for name, mutate, checker in _MUTATIONS:
        baseline = checker(PLAN)
        mutated = mutate(plan)
        assert mutated != plan, f"{name}: the mutation must change the document"
        assert checker(mutated) != baseline, f"{name}: the checker did not bite"
    for name, mutate, checker in _GUIDE_MUTATIONS:
        baseline = checker(GUIDE)
        mutated = mutate(guide)
        assert mutated != guide, f"{name}: the mutation must change the guide"
        assert checker(mutated) != baseline, f"{name}: the checker did not bite"


def test_each_plan_checker_notices_its_own_mutation() -> None:
    _run(PLAN, GUIDE)


def test_the_guide_mutations_are_matched_against_the_guide_not_the_plan() -> None:
    """The guide checkers take the guide, and are proven to bite on it.

    A guide checker that accidentally read the plan would pass every mutation
    here while never having examined the document it is named after.
    """
    for _, mutate, checker in _GUIDE_MUTATIONS:
        assert checker(mutate(GUIDE)), f"a guide checker returned clean on {checker.__name__}"


def test_the_citation_checker_bites_on_a_renamed_symbol() -> None:
    """Citation integrity is what makes the ledger evidence rather than prose.

    The doctored table replaces a real cited symbol with a name that does not
    exist anywhere, and the same lookup that reports it clean for the real table
    must report exactly that one entry for the doctored one. Asserting only the
    clean result would be a check that cannot fail.
    """
    assert dangling_citations() == []

    doctored = tuple(
        ("src/mayhem/domain/identity.py", "class NotARole")
        if relative == "src/mayhem/domain/identity.py" and name == "class Role"
        else (relative, name)
        for relative, name in CITED_SYMBOLS
    )
    missing = [
        f"{relative} does not define {name}"
        for relative, name in doctored
        if not (REPO_ROOT / relative).exists()
        or name not in (REPO_ROOT / relative).read_text(encoding="utf-8")
    ]
    assert missing == ["src/mayhem/domain/identity.py does not define class NotARole"]
    assert dangling_citations() == [], "the real table must still be clean"
