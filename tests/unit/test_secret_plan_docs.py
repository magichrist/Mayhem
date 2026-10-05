"""Plan 29 Phase 6 — the honesty gate over the secrets-management document.

This gate exists because of something that happened while the document was being
written: the first draft of the configuration guide quoted five refusal codes
that looked right and did not exist. `secret.principal_mismatch` is not a code in
this codebase; `secret.grant_principal_mismatch` is. Nothing in a Markdown file
can catch that, and a runbook that tells an operator to go looking for a refusal
code the code never emits is worse than no runbook.

So the load-bearing checker here is :func:`unquoted_codes`: **every** ``secret.*``
code in backticks must be a real constant in `mayhem.domain.secrets` or
`mayhem.infra.secret_resolver`. Prose that names a symbol is a claim about the
source, and this plan can check it, so it does.

The rest follows the shape of the other doc gates in this repository:

* the ledger carries one line per phase and ``Overall:`` equals the ``DONE`` count;
* the five Phase 6 sections are present by name;
* the section that says one adapter exists must not also claim the seams are
  implemented, and the incident process must keep its "never rewrite sealed
  history" clause — the two sentences a future edit is most likely to soften;
* four literal over-claims are absent, and the document's own *denials* must not
  match them.

Each checker is proven to bite against a mutated copy of the document.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

from mayhem.domain import secrets as domain_secrets
from mayhem.infra import secret_resolver as infra_secrets

if TYPE_CHECKING:
    from collections.abc import Callable

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = REPO_ROOT / "docs/v1.1.0/29_SECRETS_MANAGEMENT.md"
PLAN = PLAN_PATH.read_text(encoding="utf-8")

#: The Phase 6 deliverables, by the heading each one must carry.
REQUIRED_SECTIONS: Final[tuple[str, ...]] = (
    "## Secrets configuration guide",
    "## Grant-model reference",
    "## Rotation runbook",
    "## Incident process for suspected exposure",
    "## Rollout order",
)

#: Claims this plan must never make. Narrow and literal by design. The document's
#: own denials — "one of them ships an adapter", "seams", "never rewrite sealed
#: history" — must not match these.
FORBIDDEN_CLAIMS: Final[tuple[tuple[str, str], ...]] = (
    (
        r"\bvault adapter is implemented\b",
        "six of the seven providers are CallableSecretProvider seams",
    ),
    (
        r"\bno (?:secret|credential) (?:ever|can) (?:reach|persist)",
        "the boundary covers mayhem's own write paths, not the host",
    ),
    (
        r"\brevoke(?:d|s)? (?:the )?(?:row|entry|record)(?:,| and)? (?:delete|remov)",
        "the incident process appends a tombstone; it never deletes history",
    ),
    (
        r"\bsealed (?:history|evidence) (?:can|may) be (?:edited|rewritten|deleted)\b",
        "an audit entry is evidence; tombstone it, never rewrite it",
    ),
)


def _real_refusal_codes() -> set[str]:
    """Every refusal code the two modules actually define."""
    return {
        getattr(module, name)
        for module in (domain_secrets, infra_secrets)
        for name in dir(module)
        if name.startswith("REFUSAL_")
    }


# ── the checkers, as functions, so the negative controls can attack them ──────


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
        # ``PARTIAL`` is a state word like DONE and not started, so it needs its
        # own alternative: ``partially`` would not match it. Phase 3 is recorded
        # that way because the grant-administration half landed and the
        # reference-syntax half did not, and a line the parser cannot read is a
        # line nothing can be checked against.
        match = re.match(
            r"^- (Phase \d)(.*?):\s*(DONE|PARTIAL|INCOMPLETE|not started|partially)", stripped
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


def forbidden_claims_found(document: str) -> list[str]:
    return [
        reason
        for pattern, reason in FORBIDDEN_CLAIMS
        if re.search(pattern, document, re.IGNORECASE)
    ]


def unquoted_codes(document: str) -> list[str]:
    """``secret.*`` codes in the document that no module defines.

    The check that justifies this file's existence: five of the codes the first
    draft of the configuration guide quoted were invented, and only a comparison
    against the source finds that class of mistake.
    """
    real = _real_refusal_codes()
    quoted = set(re.findall(r"`(secret\.[a-z_]+)`", document))
    return sorted(quoted - real)


def uncited_codes(document: str) -> list[str]:
    """Real refusal codes the guide never mentions.

    The reverse direction: a code an operator can be handed at runtime but which
    the runbook does not explain is a dead end in an incident.
    """
    return sorted(code for code in _real_refusal_codes() if code not in document)


def _demote_the_first_done_phase(document: str) -> str:
    """Flip the first ``DONE`` ledger line to ``not started``.

    Derived from the document rather than a hardcoded label, because a label
    copied into a test is a second place for the ledger to be wrong — and this
    mutation would then silently stop mutating anything.
    """
    for raw in document.split("\n"):
        if raw.startswith("- Phase ") and ": DONE" in raw:
            return document.replace(": DONE", ": not started", 1)
    raise AssertionError("the document has no DONE ledger line to demote")


# ── the ledger ───────────────────────────────────────────────────────────────


def test_the_ledger_carries_one_line_per_phase() -> None:
    assert sorted(ledger_lines(PLAN)) == [f"Phase {n}" for n in range(1, 7)]


def test_the_overall_count_equals_the_number_of_done_lines() -> None:
    overall = claimed_overall(PLAN)

    assert overall is not None, "the STATUS block must carry an Overall: line"
    assert overall == (done_phase_count(PLAN), len(ledger_lines(PLAN)))


def test_exactly_one_phase_is_open_and_it_is_phase_three() -> None:
    assert open_phases(PLAN) == ["Phase 3"]


# ── the Phase 6 deliverables ─────────────────────────────────────────────────


def test_the_four_guides_and_the_rollout_order_are_in_the_document() -> None:
    assert missing_sections(PLAN) == []


def test_every_refusal_code_the_document_quotes_is_real() -> None:
    assert unquoted_codes(PLAN) == []


def test_the_guides_explain_every_refusal_code_an_operator_can_be_handed() -> None:
    assert uncited_codes(PLAN) == []


# ── the claims the document must not make ─────────────────────────────────────


def test_the_document_makes_no_literal_false_claim() -> None:
    assert forbidden_claims_found(PLAN) == []


def test_the_configuration_guide_does_not_claim_the_seams_are_implemented() -> None:
    """The phase's own honesty risk: one real adapter, six notional ones."""
    assert forbidden_claims_found(PLAN) == []


def test_the_incident_process_keeps_the_no_rewrite_clause() -> None:
    assert "Tombstone the evidence note — never rewrite sealed history" in PLAN


def test_the_scanner_the_ledger_claims_is_the_one_that_runs() -> None:
    """The ledger names the scanner; assert the file exists and is a unit test.

    A ledger line citing a test that was renamed or deleted is the same class of
    lie as an invented refusal code, and it is checkable.
    """
    scanner = REPO_ROOT / "tests/unit/test_secret_fixture_scan.py"

    assert scanner.exists(), "the ledger cites a scanner that does not exist"
    assert "def test_no_example_file_carries_a_literal_credential" in scanner.read_text(
        encoding="utf-8"
    )


# ── negative controls: each checker must bite ────────────────────────────────

_MUTATIONS: Final[tuple[tuple[str, Callable[[str], str], Callable[[str], object]], ...]] = (
    (
        "a done phase demoted",
        _demote_the_first_done_phase,
        done_phase_count,
    ),
    (
        "the Overall count inflated",
        lambda d: d.replace("Overall: 5 of 6", "Overall: 6 of 6", 1),
        claimed_overall,
    ),
    (
        "the rotation runbook removed",
        lambda d: d.replace("## Rotation runbook", "## Removed", 1),
        lambda d: len(missing_sections(d)),
    ),
    (
        "an invented refusal code quoted",
        lambda d: d.replace(
            "`secret.provider_unavailable`",
            "`secret.provider_not_registered`",
            1,
        ),
        lambda d: len(unquoted_codes(d)),
    ),
    (
        "a real refusal code dropped from the guides",
        lambda d: d.replace("`secret.reference_without_grant`", "`secret.no_grant`", 1),
        lambda d: len(unquoted_codes(d)) + len(uncited_codes(d)),
    ),
    (
        "the guide claiming the vault adapter is implemented",
        lambda d: d + "\nThe Vault adapter is implemented and ready for use.\n",
        lambda d: len(forbidden_claims_found(d)),
    ),
    (
        "the incident process licensing a history rewrite",
        lambda d: d + "\nSealed evidence can be edited once an incident closes.\n",
        lambda d: len(forbidden_claims_found(d)),
    ),
    (
        "the no-rewrite clause softened",
        lambda d: d.replace(
            "never rewrite sealed history",
            "amend the note if the incident closes",
        ),
        lambda d: int("never rewrite sealed history" not in d),
    ),
    (
        "a PARTIAL phase quietly promoted to DONE",
        lambda d: re.sub(
            r"^(- Phase 3[^\n]*?): PARTIAL",
            r"- \1: DONE",
            d,
            count=1,
            flags=re.MULTILINE,
        ),
        open_phases,
    ),
)


def _run_negative_controls() -> None:
    for name, mutate, checker in _MUTATIONS:
        baseline = checker(PLAN)
        mutated = mutate(PLAN)
        assert mutated != PLAN, f"{name}: the mutation must change the document"
        assert checker(mutated) != baseline, f"{name}: the checker did not bite"


def test_each_checker_notices_its_own_mutation() -> None:
    _run_negative_controls()
