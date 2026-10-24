"""L3 Phase 3 — the honesty gate over the release-gate-caller plan.

L3's subject is "give ``release_gate()`` its first production caller", so this
document is most likely to overclaim in exactly one direction: that the gate is
now enforced, runnable, and able to say yes. It landed a caller, not the
machinery around it. The checks below pin the difference:

* the ``Overall:`` count equals the ``DONE`` phase lines, and the phases are 1-3;
* every symbol the document cites resolves through ``importlib``/``getattr`` —
  classmethods and ``__post_init__`` included, because the document cites
  members, not just modules;
* ``release_gate`` really is reachable from ``check_cmd``, and the document no
  longer claims it has no caller;
* the document claims no capability the build lacks: no sentence asserts the
  gate can allow without naming its ``--run`` condition, there is no suite
  runner, and ``--release-gate`` is opt-in rather than a required CI check;
* the known limitation is stated in its conditional shape: without ``--run``
  the gate invoked from this surface can only ever block, with it a cited run
  lifts the "no run is cited" reason — asserted against the source as well as
  the prose, because this is the claim a reader would most want to be true;
* ``ResilienceSuite.__post_init__`` still owns the three refusals and the CLI
  still does not re-implement them;
* the recorded gaps are still open: no suite runner produces suite files, and a
  finding has no close state;
* ``SIGNATURE_VERIFICATION_IMPLEMENTED`` is ``False`` and the document does not
  claim signature verification.

Each checker is proven to bite against a fabricated over-claim or a synthetic
ledger rather than only ever running against the real document.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from typing import Final

from mayhem.providers.pack import SIGNATURE_VERIFICATION_IMPLEMENTED

REPO_ROOT: Final = Path(__file__).resolve().parents[2]
PLAN_PATH: Final = REPO_ROOT / "docs/v1.1.0/LAST/L3_RELEASE_GATE_CALLER.md"
PLAN: Final = PLAN_PATH.read_text(encoding="utf-8")

PHASE_LINE: Final = re.compile(
    r"^-\s+Phase\s+(\d+)\b[^\n]*?:\s*\**\s*(DONE|PARTIAL|INCOMPLETE)\b([^\n]*)$", re.M
)
OVERALL_LINE: Final = re.compile(r"^Overall:\s*(\d+)\s+of\s+(\d+)\s+phases", re.M)

#: The document's own unqualified present-tense claim that the gate is uncalled.
#: Scoped to that sentence: plan 22's quoted "no production caller" is a
#: citation of another document, and "no caller **other than** `mayhem ci
#: check`" is the honest present claim — the rot to catch is "has ... no caller
#: anywhere in src/" now that ``mayhem ci check`` calls the gate.
PRESENT_NO_CALLER: Final = re.compile(r"has\s+\**\s*no caller anywhere in", re.I)

#: What a suite runner would look like in ``src/``. Nothing may define one while
#: the document records "no suite runner" as an open gap.
SUITE_RUNNER_DEF: Final = re.compile(r"\bdef\s+(?:run_suites?|suite_runner)\b|\bsuite_runner\b")

#: Citations this plan makes, as ``(module, attribute)`` — dotted for members.
#: Resolved through ``inspect``-style ``getattr`` rather than line numbers,
#: because this plan *added* every one of them and a line citation would rot.
CITED_SYMBOLS: Final[tuple[tuple[str, str], ...]] = (
    ("mayhem.controller.check_gate", "release_gate"),
    ("mayhem.controller.check_gate", "ReleaseGateRequest"),
    ("mayhem.controller.check_gate", "ResilienceSuite"),
    ("mayhem.controller.check_gate", "ResilienceSuite.__post_init__"),
    ("mayhem.controller.check_gate", "ChangeKind"),
    ("mayhem.controller.check_gate", "required_suites_for"),
    ("mayhem.domain.comparison", "RegressionFinding"),
    ("mayhem.domain.comparison", "RegressionFinding.from_dict"),
    ("mayhem.domain.comparison", "DeltaReport.from_dict"),
    ("mayhem.domain.comparison", "RunPin.from_dict"),
    ("mayhem.infra.coverage_service", "ComparisonService"),
    ("mayhem.infra.coverage_service", "ComparisonService.finding_objects"),
    ("mayhem.cli.ci_cmd", "_suites_from_paths"),
    ("mayhem.cli.ci_cmd", "_apply_release_gate"),
)

#: Claims this plan must never make. All three are FALSE in this build;
#: the last two keep L2's signature refusal alive in a document that does not
#: discuss signatures at all — until it does, incorrectly.
FORBIDDEN_CLAIMS: Final[tuple[str, ...]] = (
    r"there (?:is|now is)\s+(?:a\s+)?suite runner",
    r"--release-gate (?:is|becomes|will be)\s+(?:now\s+)?(?:a\s+)?(?:required|mandatory)",
    r"signature verification is implemented",
    r"proves authorship",
)

#: The allow-claim this plan may never make *unqualified*. When the first
#: version of this checker was written, the limitation was absolute —
#: ``check_cmd`` supplied no ``cited_run``, so "the gate can allow" was false
#: without qualification and a bare regex refused every occurrence. The
#: limitation is now conditional: ``--run PATH`` lets a cited run lift the
#: "no run is cited" reason, and the gate then *can* allow. So the rot this
#: checker must still catch is the unqualified claim — an allow-assertion whose
#: sentence never names the condition that makes it true. Handled as sentence
#: logic rather than one regex, because the honest sentence and the over-claim
#: share every keyword.
ALLOW_WORDING: Final = re.compile(r"\b(?:the )?gate (?:can|may|could|will) allow", re.I)
ALLOW_CONDITION: Final = re.compile(r"--run\b|cited(?:_run)?\s+run|\bpin\b", re.I)

#: The refusal-of-signature subset, for the dedicated L2-pattern check.
SIGNATURE_CLAIMS: Final[tuple[str, ...]] = (FORBIDDEN_CLAIMS[2], FORBIDDEN_CLAIMS[3])

#: One plausible over-claim per forbidden pattern, so each checker's *positive*
#: half is proven to bite. A checker that is only ever run against the real
#: document has never been shown to catch the thing it exists to catch.
_OVERCLAIMS: Final[dict[str, str]] = {
    FORBIDDEN_CLAIMS[0]: "There is a suite runner in this build now.",
    FORBIDDEN_CLAIMS[1]: "--release-gate is a required CI check on every pipeline.",
    FORBIDDEN_CLAIMS[2]: "Signature verification is implemented for this release.",
    FORBIDDEN_CLAIMS[3]: "The seal proves authorship of the run.",
}

#: The unqualified over-claim for the allow-claim checker above, kept beside the
#: structurally identical honest sentence so the checker must reject one and
#: accept the other.
ALLOW_OVERCLAIM: Final = "The gate can allow a release once every suite passes."
ALLOW_HONEST: Final = "With a cited run (--run PATH), the gate can allow."


def _phases() -> dict[int, str]:
    return {int(m.group(1)): m.group(2) for m in PHASE_LINE.finditer(PLAN)}


def _resolve(module_name: str, attribute: str) -> object:
    import importlib

    target: object = importlib.import_module(module_name)
    for part in attribute.split("."):
        target = getattr(target, part)
    return target


def _states_cited_run_limitation(text: str) -> bool:
    """The full limitation: the omitted field, the reason, and the consequence."""
    return (
        "cited_run" in text
        and "no run is cited" in text
        and re.search(r"never allow|can(?:not)? allow|only(?:\s+ever)?\s+block", text, re.I)
        is not None
    )


def _unqualified_allow_claims(text: str) -> list[str]:
    """Sentences asserting the gate can allow without naming their condition.

    An allow-assertion is honest only where its sentence names ``--run``/the
    cited run that lifts the "no run is cited" reason. Markdown emphasis is
    stripped before the condition check so backticked flags count.
    """
    unqualified = []
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        if not ALLOW_WORDING.search(sentence):
            continue
        bare = re.sub(r"[`*_~]", "", sentence)
        if not ALLOW_CONDITION.search(bare):
            unqualified.append(sentence.strip())
    return unqualified


# --- check 1: the ledger ---------------------------------------------------- #


def test_overall_count_equals_the_done_lines() -> None:
    overall = OVERALL_LINE.search(PLAN)
    assert overall is not None, "L3 has a phase ledger but no 'Overall:' line"
    phases = _phases()
    done = sum(1 for verdict in phases.values() if verdict == "DONE")
    assert int(overall.group(1)) == done, (
        f"L3 says {overall.group(1)} of {overall.group(2)} complete, "
        f"but marks {done} of {len(phases)} phases DONE"
    )
    assert int(overall.group(2)) == len(phases)


def test_all_three_phases_are_present_and_done() -> None:
    phases = _phases()
    assert set(phases) == {1, 2, 3}, sorted(phases)
    assert all(verdict == "DONE" for verdict in phases.values()), phases


# --- check 2: the cited symbols resolve ------------------------------------- #


def test_every_cited_symbol_still_exists() -> None:
    missing: list[str] = []
    for module_name, attribute in CITED_SYMBOLS:
        try:
            found = _resolve(module_name, attribute)
        except (ImportError, AttributeError) as exc:
            missing.append(f"{module_name}.{attribute} ({type(exc).__name__})")
            continue
        assert found is not None, f"{module_name}.{attribute} is None"
    assert missing == [], f"L3 cites symbols that no longer exist: {missing}"


def test_every_cited_symbol_is_named_by_the_document() -> None:
    """The list above is only honest if the document actually cites each name."""
    for module_name, attribute in CITED_SYMBOLS:
        name = attribute.rsplit(".", 1)[-1]
        assert name in PLAN, f"{module_name}.{attribute} is not cited by the document"


# --- check 3: release_gate has a caller ------------------------------------- #


def test_release_gate_is_reachable_from_check_cmd() -> None:
    """The claim this plan exists for, proven through the source chain.

    ``check_cmd`` is wrapped by click, so its body is sliced out of the module
    source rather than read off the ``click.Command`` object — ``getsource``
    on the wrapper would hand back click's own class.
    """
    from mayhem.cli import ci_cmd

    source = inspect.getsource(ci_cmd)
    assert "release_gate(verdict" in source, "no call site of release_gate( in ci_cmd.py"
    start = source.index("def check_cmd(")
    end = source.index("\ndef ", start + 1)
    body = source[start:end]
    assert "if release_gate:" in body, "check_cmd no longer takes the --release-gate option"
    assert "_apply_release_gate(" in body, "check_cmd does not reach the release gate"
    helper = inspect.getsource(ci_cmd._apply_release_gate)
    assert "release_gate(verdict, request," in helper, "_apply_release_gate stopped calling it"
    # And the document's present-tense claim names its one caller.
    assert "no caller **other than**" in PLAN, (
        "the document no longer states that mayhem ci check is the gate's caller"
    )


def test_the_document_no_longer_claims_release_gate_has_no_caller() -> None:
    """The claim that made this plan necessary is the one that must be gone.

    ``mayhem ci check`` now calls the gate, so "no caller anywhere in `src/`"
    reads as a present fact and is false. Plan 22's quoted "no production
    caller" is a citation of another document and is left alone.
    """
    assert PRESENT_NO_CALLER.search(PLAN) is None, (
        "L3 still claims release_gate has no caller in src/, but mayhem ci check calls it"
    )


# --- check 4: what this plan may not claim ---------------------------------- #


def test_the_document_claims_no_capability_it_lacks() -> None:
    found = [pattern for pattern in FORBIDDEN_CLAIMS if re.search(pattern, PLAN, re.I)]
    assert found == [], f"L3 over-claims something false: {found}"
    unqualified = _unqualified_allow_claims(PLAN)
    assert unqualified == [], (
        f"L3 claims the gate can allow without naming its --run condition: {unqualified}"
    )
    assert "not a required CI check" in PLAN, (
        "the document no longer records that --release-gate is opt-in"
    )


def test_the_document_does_not_claim_signature_verification() -> None:
    assert SIGNATURE_VERIFICATION_IMPLEMENTED is False
    found = [pattern for pattern in SIGNATURE_CLAIMS if re.search(pattern, PLAN, re.I)]
    assert found == [], f"L3 claims signature verification it does not have: {found}"


# --- check 5: the cited_run limitation -------------------------------------- #


def test_the_cited_run_limitation_is_opt_in_not_absolute() -> None:
    """The source half of the block-only limitation, after ``--run`` landed.

    ``ci_cmd`` *does* now name ``cited_run`` — ``--run PATH`` threads it into
    both ``CheckInputs`` branches. The limitation this file pinned was therefore
    **conditional**, not absolute: without the flag the gate can only block, with
    it the gate can allow. This guard now pins the three properties that
    conditional claim rests on, and it is the shape of the assertion that
    survives the next change:

    * the pin is opt-in and defaults to nothing — ``CheckInputs.cited_run``
      still defaults to ``None``, so a default invocation cannot start citing a
      run nobody named;
    * ``ci_cmd`` reads the pin through exactly one helper, so there is one place
      a run enters the check;
    * ``blocking_reasons`` still refuses an uncited run — that sentence is the
      domain's, and it did not change.
    """
    from mayhem.cli import ci_cmd
    from mayhem.controller import check_gate
    from mayhem.domain import pipeline

    assert check_gate.CheckInputs.__dataclass_fields__["cited_run"].default is None, (
        "CheckInputs now cites a run by default; the opt-in claim is stale"
    )
    source = inspect.getsource(ci_cmd)
    assert "_run_pin_from_path(ctx, run_path)" in source, (
        "ci_cmd no longer reads the run pin through the one helper this guard names"
    )
    assert "cited_run=cited_run" in source, "the pin is not threaded into CheckInputs"
    reasons_source = inspect.getsource(pipeline.blocking_reasons)
    assert "no run is cited" in reasons_source
    assert "if verdict.cited_run is None:" in reasons_source, (
        "blocking_reasons no longer refuses an uncited run; the limitation this "
        "document records is no longer true"
    )
    gate_source = inspect.getsource(check_gate.release_gate)
    assert "pipeline_reasons = blocking_reasons(" in gate_source
    assert "if not ordered:" in gate_source, (
        "release_gate no longer gates its allow path on an empty reason list"
    )


def test_the_document_states_the_cited_run_limitation() -> None:
    """The most load-bearing sentence in the document, in its conditional shape.

    A reader must know how the gate invoked from ``mayhem ci check`` behaves on
    both sides of ``--run``: without the flag ``blocking_reasons`` always
    contains "no run is cited", so the gate can only ever block; with a cited
    run that reason is lifted and the gate can allow.
    """
    assert _states_cited_run_limitation(PLAN), (
        "the document never states that check_cmd supplies no cited_run, so the "
        "gate from this surface can only block and never allow"
    )


# --- check 6: the three refusals stay in __post_init__ ---------------------- #


def test_the_three_suite_refusals_stay_in___post_init__() -> None:
    from mayhem.cli import ci_cmd
    from mayhem.controller import check_gate

    rule_ids = (
        "release_gate.suite_without_evidence",
        "release_gate.suite_without_run",
        "release_gate.unknown_suite_unexplained",
    )
    constants = (
        "RULE_SUITE_WITHOUT_EVIDENCE",
        "RULE_SUITE_WITHOUT_RUN",
        "RULE_SUITE_UNKNOWN_UNEXPLAINED",
    )
    source = inspect.getsource(check_gate)
    for rule_id in rule_ids:
        assert f'"{rule_id}"' in source, f"{rule_id} left check_gate.py"
    assert check_gate.RULE_SUITE_WITHOUT_EVIDENCE == "release_gate.suite_without_evidence"
    assert check_gate.RULE_SUITE_WITHOUT_RUN == "release_gate.suite_without_run"
    assert check_gate.RULE_SUITE_UNKNOWN_UNEXPLAINED == "release_gate.unknown_suite_unexplained"
    post_init = inspect.getsource(check_gate.ResilienceSuite.__post_init__)
    for constant in constants:
        assert constant in post_init, f"ResilienceSuite.__post_init__ no longer owns {constant}"
    cli_source = inspect.getsource(ci_cmd)
    for rule_id in rule_ids:
        assert rule_id not in cli_source, "the CLI re-implements a domain refusal"
    # And the document still says both halves.
    assert "ResilienceSuite.__post_init__" in PLAN
    assert "Do not re-implement those three refusals at the CLI edge" in PLAN


# --- check 7: the recorded gaps are still open ------------------------------ #


def test_there_is_still_no_suite_runner() -> None:
    """Gap 1, asserted at the source rather than in the prose.

    A new ``ResilienceSuite`` consumer or a runner definition would silently
    close the gap while the document still writes it up as open — that drift is
    exactly what this check exists to catch.
    """
    src_files = sorted((REPO_ROOT / "src").rglob("*.py"))
    texts = {path: path.read_text(encoding="utf-8") for path in src_files}
    consumers = {
        path.relative_to(REPO_ROOT).as_posix()
        for path, text in texts.items()
        if "ResilienceSuite" in text
    }
    assert consumers == {
        "src/mayhem/controller/check_gate.py",
        "src/mayhem/cli/ci_cmd.py",
    }, f"a new ResilienceSuite consumer appeared, so a suite runner may exist: {consumers}"
    runners = [
        path.relative_to(REPO_ROOT).as_posix()
        for path, text in texts.items()
        if SUITE_RUNNER_DEF.search(text)
    ]
    assert runners == [], f"src/ now defines a suite runner: {runners}"
    # The document still records the gap.
    assert "No suite runner" in PLAN
    assert re.search(r"Nothing in this repository\s+produces them", PLAN), (
        "the document no longer records that nothing produces suite files"
    )


def test_a_finding_still_has_no_close_state() -> None:
    from mayhem.domain.comparison import RegressionFinding

    fields = set(RegressionFinding.__dataclass_fields__)
    assert fields == {"finding_id", "report", "summary"}, (
        "RegressionFinding gained a field; if it is a close state, the recorded "
        "gap closed and the document must be rewritten rather than this check"
    )
    assert not hasattr(RegressionFinding, "close")
    assert "A finding has no close state" in PLAN


# --- check 8: signature verification ---------------------------------------- #


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


# --- the checkers bite ------------------------------------------------------- #


def test_the_ledger_checker_bites() -> None:
    fake = (
        "- Phase 1 — rehydrate: **DONE**\n"
        "- Phase 2 — call the gate: **DONE**\n"
        "- Phase 3 — the proof: **DONE**\n"
        "Overall: 3 of 3 phases complete\n"
    )
    inflated = fake.replace("Overall: 3 of 3 phases complete", "Overall: 2 of 3 phases complete")
    match = OVERALL_LINE.search(inflated)
    assert match is not None
    phases = {int(m.group(1)): m.group(2) for m in PHASE_LINE.finditer(inflated)}
    done = sum(1 for v in phases.values() if v == "DONE")
    assert int(match.group(1)) != done, "ledger checker did not bite"


def test_the_forbidden_claim_checker_bites() -> None:
    for pattern in FORBIDDEN_CLAIMS:
        # Each pattern must match at least one plausible over-claim, and must not
        # match the sentence L3 actually makes. The negative half matters as much
        # as the positive: a pattern so broad it also refuses the honest wording
        # gets "fixed" by being deleted.
        assert re.search(pattern, _OVERCLAIMS[pattern], re.I), (
            f"the checker for {pattern!r} does not bite on {_OVERCLAIMS[pattern]!r}"
        )
        assert re.search(pattern, PLAN, re.I) is None
    # The allow-claim checker bites on an unqualified over-claim whose sentence
    # shares every keyword with the honest conditional sentence — which is
    # exactly why it is sentence logic and not one bare regex.
    assert _unqualified_allow_claims(ALLOW_OVERCLAIM) == [ALLOW_OVERCLAIM], (
        "the allow-claim checker did not bite on the unqualified over-claim"
    )
    assert _unqualified_allow_claims(ALLOW_HONEST) == [], (
        "the allow-claim checker refuses the honest conditional sentence"
    )


def test_the_no_caller_checker_bites() -> None:
    landing = "release_gate is implemented, documented, and has **no caller anywhere in `src/`**"
    assert PRESENT_NO_CALLER.search(landing) is not None, "the checker did not bite"
    past = "release_gate had no caller anywhere in src/ back then"
    assert PRESENT_NO_CALLER.search(past) is None, "the checker flags honest history"
    qualified = "release_gate still has no caller **other than** `mayhem ci check`"
    assert PRESENT_NO_CALLER.search(qualified) is None, "the checker flags the honest claim"


def test_the_cited_run_checker_bites() -> None:
    honest = (
        "`check_cmd` never supplies a `cited_run`, so `blocking_reasons` always "
        'contains "no run is cited": the gate can only ever block, never allow.'
    )
    assert _states_cited_run_limitation(honest), "the checker did not bite"
    assert not _states_cited_run_limitation(
        "the gate decides whether the change may open a release"
    ), "the checker accepts a document that never mentions the limitation"


def test_the_suite_runner_checker_bites() -> None:
    assert SUITE_RUNNER_DEF.search("def run_suite(results):") is not None, (
        "the runner checker did not bite"
    )
    assert SUITE_RUNNER_DEF.search("suite_runner = build(results)") is not None
    assert SUITE_RUNNER_DEF.search("def _suites_from_paths(paths):") is None, (
        "the runner checker flags the file parser"
    )
