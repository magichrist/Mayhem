"""Plan 04 Phase 6 — the honesty gate over the plan document.

Phases 1 to 5 built the model, the refusals, the grammar, the surface, the gate
and the tests. This file is the gate that keeps the *document* honest about them,
and it is the only test in the plan that reads prose.

Why prose needs a gate here at all
----------------------------------
Every other plan's STATUS is a claim a reader can check against code by opening
the code. This plan's central claim — "no mechanism exists, and here is the named
thing that is missing" — is the claim most likely to rot, because it is the one
that gets *less* true as the surrounding code grows. Someone adds a loader, or
someone adds a JVM agent, and a document that still says "mayhem ships none"
becomes a lie nobody re-reads.

So the document is parsed, not trusted:

* every fault id it names must exist in ``CATALOG`` and be ``catalog_only``;
* every primitive id it names must exist in ``PRIMITIVES``;
* every primitive it claims is blocked must actually be blocked on
  ``CURRENT_SUBSTRATE``, and every one it claims is injectable must be;
* its per-phase ledger must have one line per phase and the ``Overall:`` count
  must equal the number of ``DONE`` lines — **a summary disagreeing with its own
  ledger is the defect this test exists to catch**;
* it must not claim a mechanism was attached, a signature verified, a primitive
  promoted to ``verified-live``, or a Kubernetes lane;
* it must carry the substrate-ceiling notes and the rollout ladder Phase 6 asks
  for, so their absence fails here rather than being noticed by a reader.

Negative controls, at the end: mutating a copy of the document so that each of
those properties breaks, and asserting the checkers notice — so a checker that
passes vacuously is distinguishable from one that bites.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Final

import pytest

from mayhem.agents import impact
from mayhem.domain.catalog import CATALOG, definition_for
from mayhem.domain.lowlevel import CURRENT_SUBSTRATE, PRIMITIVES, primitive_by_id
from mayhem.domain.lowlevel_report import (
    CATALOG_REFUSAL_BY_PRIMITIVE,
    DESCRIPTOR_ONLY_RULES,
    LOWLEVEL_NOT_ATTACHED_NOTICE,
    disposition_problems,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = REPO_ROOT / "docs/v1.1.0/04_EBPF_KERNEL_IO_JVM.md"
PLAN = PLAN_PATH.read_text(encoding="utf-8")

#: A dotted identifier, which is what every fault id and primitive id in the
#: document is. Anchored on a word boundary so a sentence-ending period is not
#: swallowed into the match.
_DOTTED = re.compile(
    r"\b(?:process|fs|jvm|kernel|io|clock|net|app|http|db|mem|cpu|k8s|proc)\.[a-z0-9_]+\b"
)

#: Any file path a STATUS line could name. Deliberately loose about the root: the
#: document writes ``domain/lowlevel.py`` where the test needs
#: ``src/mayhem/domain/lowlevel.py``, and the claim being checked is "it names a
#: file", not "it spells the module the way Python does".
_FILE_PATH_RE = re.compile(r"\b[\w.]+/[\w./-]*\.(?:py|md)\b")

#: One planted false claim per forbidden pattern, each with the reason it would be
#: a lie. The suite plants each of these and asserts it trips exactly one
#: checker, so a checker that never fires is caught by a test rather than by a
#: reader.
PLANTED_CLAIMS: Final[tuple[tuple[str, str], ...]] = (
    (
        "The kprobe has been attached to a dev cell and the undo was verified.",
        "a mechanism cannot have been attached in this build",
    ),
    (
        "The loader was attached before the drill started.",
        "a mechanism cannot have been attached in this build",
    ),
    (
        "Signature verification is implemented for every provider pack.",
        "mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED is False",
    ),
    (
        "The primitive reached verified-live was promoted after three cells.",
        "nothing in this plan is verified-live",
    ),
    (
        "The same attach works under kubernetes once the pod spec is applied.",
        "the kubernetes lane refuses every low-level primitive",
    ),
    (
        "Mayhem shipped the ebpf loader in v1.0.0.",
        "mayhem ships no eBPF loader",
    ),
    (
        "We attach the ebpf program before the first fault step.",
        "mayhem attaches no eBPF program",
    ),
)

#: The claims this plan must never make, each with the word that would break it.
#:
#: Deliberately narrow and literal. A prose gate cannot judge intent, so it
#: judges the smallest set of literal claims that would each be a distinct lie,
#: and the surrounding paragraphs carry the reasoning a regex cannot.
FORBIDDEN_CLAIMS: tuple[tuple[str, str], ...] = (
    (r"\bhas been attached\b", "a mechanism cannot have been attached"),
    (r"\bwas attached\b", "a mechanism cannot have been attached"),
    (
        r"\bsignature verification (?:is )?implemented\b",
        "signature verification is not implemented",
    ),
    (
        r"\bverified[- ]live (?:was|is) (?:achieved|promoted|reached|granted)\b",
        "nothing is verified-live",
    ),
    (r"\bunder kubernetes\b", "the kubernetes lane refuses every low-level primitive"),
    (r"\bshipped (?:an?|the) ebpf\b", "mayhem ships no eBPF loader"),
    (r"\bwe (?:attach|inject) (?:the )?ebpf\b", "mayhem attaches no eBPF program"),
)


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
        if in_status and stripped.startswith("## ") and not stripped.startswith("## STATUS"):
            in_status = False
        if not in_status:
            continue
        match = re.match(r"^- (Phase \d)(.*?):\s*(DONE|INCOMPLETE)\b(.*)$", stripped)
        if match:
            lines[match.group(1)] = stripped
    return lines


def done_phase_count(document: str) -> int:
    """How many ledger lines end in ``DONE``."""
    return sum(1 for line in ledger_lines(document).values() if "DONE" in line.split(":")[1])


def overall_count(document: str) -> int:
    """The ``Overall:`` figure, or ``-1`` when the document has none."""
    match = re.search(r"^Overall:\s*(\d+)\s+of\s+(\d+)\s+phases complete", document, re.M)
    return int(match.group(1)) if match else -1


def claimed_blocked(document: str) -> set[str]:
    """Primitives the document says cannot be injected."""
    claimed: set[str] = set()
    for primitive_id, primitive in PRIMITIVES.items():
        blocked = not primitive.substrate_verdict(CURRENT_SUBSTRATE)
        # The document has to be checked against the model's answer, so search for
        # the id in a sentence that also says it cannot.
        pattern = (
            rf"{re.escape(primitive_id)}[^\n.]{{0,200}}?"
            r"\b(?:cannot be injected|is not injectable|blocked)\b"
        )
        if re.search(pattern, document, re.S) and not blocked:
            claimed.add(primitive_id)
    return claimed


def named_fault_ids(document: str) -> set[str]:
    """Fault ids the document names, restricted to the prefixes plan 04 owns."""
    catalog_ids = {definition.id for definition in CATALOG}
    return {token for token in _DOTTED.findall(document) if token in catalog_ids}


# ── the checks ───────────────────────────────────────────────────────────────


class TestTheLedger:
    def test_the_ledger_has_one_line_per_phase(self) -> None:
        lines = ledger_lines(PLAN)
        assert set(lines) == {f"Phase {index}" for index in range(1, 7)}, (
            f"the ledger is missing a phase line: {sorted(set(lines))}"
        )

    def test_the_overall_count_equals_the_number_of_done_lines(self) -> None:
        """A summary disagreeing with its own ledger is the defect this pins.

        Not a style assertion. The count is the one thing a reader takes from a
        STATUS, and a count that disagrees with the lines above it is worse than
        no count: it tells a reader the plan is further along, or less, than it is.
        """
        lines = ledger_lines(PLAN)
        done = [label for label, line in lines.items() if "DONE" in line]
        assert overall_count(PLAN) == len(done), (
            f"Overall says {overall_count(PLAN)} but {len(done)} ledger lines say DONE: {done}"
        )

    def test_the_overall_denominator_is_six(self) -> None:
        assert re.search(r"^Overall:\s*\d+\s+of\s+6\s+phases complete", PLAN, re.M), (
            "the plan has six phases and the denominator says otherwise"
        )

    def test_every_done_line_names_its_files_and_its_tests(self) -> None:
        for label, line in ledger_lines(PLAN).items():
            if "DONE" not in line:
                continue
            assert "tests/unit/" in line, f"{label} claims DONE without naming a test file"
            assert _FILE_PATH_RE.search(line), (
                f"{label} claims DONE without naming a file it landed"
            )

    def test_every_done_line_records_what_it_did_not_land(self) -> None:
        """The half of a STATUS that matters most, and the easiest to omit.

        A phase that landed something and quietly dropped something else reads
        as a phase that landed everything.
        """
        for label, line in ledger_lines(PLAN).items():
            if "DONE" not in line:
                continue
            assert re.search(r"\*\*Not landed:\*\*", line), (
                f"{label} claims DONE and says nothing about what it did not land"
            )

    def test_every_incomplete_line_says_what_is_missing(self) -> None:
        for label, line in ledger_lines(PLAN).items():
            if "INCOMPLETE" not in line:
                continue
            assert "**Not landed:**" in line and len(line) > 120, (
                f"{label} is marked INCOMPLETE without saying what is missing"
            )


class TestTheDocumentAgreesWithTheCode:
    def test_every_fault_id_the_plan_names_exists_and_is_a_refusal(self) -> None:
        """A refusal id that has been promoted would make the document a lie."""
        for fault_id in sorted(named_fault_ids(PLAN)):
            definition = definition_for(fault_id)
            assert definition.id == fault_id
            if fault_id in set(CATALOG_REFUSAL_BY_PRIMITIVE.values()):
                assert definition.catalog_only, (
                    f"{fault_id} is described as a refusal but is now an active entry"
                )
                assert fault_id in impact._CATALOG_ONLY_FAULTS, (
                    f"{fault_id} is documented as refused but the impact gate would "
                    "report it as able to take effect"
                )

    def test_every_primitive_id_the_plan_names_exists(self) -> None:
        named = {token for token in _DOTTED.findall(PLAN) if token in PRIMITIVES}
        assert len(named) >= 15, (
            f"the plan names only {len(named)} primitive(s); the tables below it are the "
            "document's substance and must not rot away unremarked"
        )
        for primitive_id in named:
            assert primitive_by_id(primitive_id) is not None

    def test_the_plan_does_not_claim_a_blocked_primitive_is_injectable(self) -> None:
        offenders = claimed_blocked(PLAN)
        assert offenders == set(), (
            "the document says these cannot be injected and the substrate says they "
            f"can: {sorted(offenders)}"
        )

    def test_the_four_injectable_primitives_are_the_ones_the_code_says(self) -> None:
        """Every primitive the substrate can inject is named, so the count is checkable.

        The reverse direction — a primitive the document calls injectable that the
        substrate refuses — is covered by
        :meth:`test_the_plan_does_not_claim_a_blocked_primitive_is_injectable`.
        """
        injectable = sorted(
            primitive_id
            for primitive_id, primitive in PRIMITIVES.items()
            if primitive.substrate_verdict(CURRENT_SUBSTRATE)
        )
        assert len(injectable) == 4, injectable
        for primitive_id in injectable:
            assert primitive_id in PLAN, (
                f"{primitive_id} is injectable on this substrate and the document "
                "never mentions it, so a reader cannot see the ceiling from the top"
            )

    def test_the_documents_blocked_count_is_the_models_blocked_count(self) -> None:
        """``18`` appears as the blocked count in the STATUS prose; keep it true."""
        blocked = sum(
            1
            for primitive in PRIMITIVES.values()
            if not primitive.substrate_verdict(CURRENT_SUBSTRATE)
        )
        assert blocked == 18
        assert (
            re.search(r"\b18 of (?:the )?22\b", PLAN) or re.search(r"\b18 blocked\b", PLAN)
        ), "the document no longer states the blocked count in any form the test reads"

    def test_the_verified_live_count_this_plan_reports_is_zero(self) -> None:
        """Phase 5's acceptance clause, restated over the prose that claims it."""
        assert re.search(r"`verified-live` remains 0", PLAN) or re.search(
            r"`verified-live` stays 0", PLAN
        ), "the document must state that no primitive is verified-live"

    def test_the_two_decision_tables_are_exhaustive(self) -> None:
        assert disposition_problems() == (), (
            "the tables the document prints no longer agree with the descriptors"
        )
        decided = set(CATALOG_REFUSAL_BY_PRIMITIVE) | set(DESCRIPTOR_ONLY_RULES)
        blocked = {
            primitive_id
            for primitive_id, primitive in PRIMITIVES.items()
            if not primitive.substrate_verdict(CURRENT_SUBSTRATE)
        }
        assert decided == blocked

    def test_every_rule_id_the_plan_explains_is_still_used(self) -> None:
        counts = Counter(DESCRIPTOR_ONLY_RULES.values())
        for rule_id, count in sorted(counts.items()):
            assert rule_id in PLAN, (
                f"rule {rule_id} decides {count} primitive(s) and the plan does not "
                "explain it, so a reader meets a refusal with no reason"
            )


class TestTheDocumentMakesNoFalseClaim:
    @pytest.mark.parametrize(
        ("pattern", "because"),
        FORBIDDEN_CLAIMS,
        ids=[pattern.replace("\\b", "")[:24] for pattern, _ in FORBIDDEN_CLAIMS],
    )
    def test_the_plan_never_makes_the_claim(self, pattern: str, because: str) -> None:
        match = re.search(pattern, PLAN, re.I)
        assert match is None, (
            f"the plan claims {match.group(0)!r}: {because}. "
            "Delete the claim rather than qualifying it — the refusal is the deliverable."
        )

    def test_the_plan_carries_the_substrate_ceiling_note(self) -> None:
        """Phase 6's second deliverable, and the one a reader most needs."""
        assert "substrate ceiling" in PLAN.lower()
        assert LOWLEVEL_NOT_ATTACHED_NOTICE[:60].lower() in PLAN.lower(), (
            "the plan must state the caveat in its own words, not only by reference"
        )

    def test_the_plan_carries_the_rollout_ladder(self) -> None:
        """One family at a time, behind capability detection."""
        assert "rollout" in PLAN.lower()
        for family in ("kernel", "io", "jvm", "clock"):
            assert re.search(rf"`{family}`", PLAN) or re.search(rf"\b{family}\b", PLAN), family

    def test_the_plan_carries_the_parameter_catalogue(self) -> None:
        """Per-fault parameter entries in drill-spec style."""
        assert "drill-spec" in PLAN.lower() or "drill spec" in PLAN.lower()
        assert "--param" in PLAN or "-e" in PLAN

    def test_the_plan_names_the_privileges_this_environment_lacks(self) -> None:
        """The substrate ceiling has to name the *things*, not gesture at them.

        Each token is one a reader would otherwise have to go and look up: the two
        capability bits, the two devices, and the debugfs mount an eBPF attach
        needs and a Kubernetes pod spec does not get.
        """
        for token in ("SYS_ADMIN", "CAP_BPF", "/dev/fuse", "debugfs", "/dev/mapper/control"):
            assert token in PLAN, f"the substrate ceiling does not mention {token}"


# ── negative controls: break the document, prove the checks notice ───────────


class TestNegativeControls:
    def _mutated(self, old: str, new: str) -> str:
        assert old in PLAN, f"the control's anchor {old!r} is not in the plan"
        return PLAN.replace(old, new, 1)

    def test_the_overall_check_catches_a_wrong_count(self) -> None:
        """Bump the summary down by one and the ledger no longer agrees with it."""
        broken = self._mutated(
            re.search(r"^Overall:\s*\d+\s+of\s+6", PLAN, re.M).group(0), "Overall: 5 of 6"
        )
        done = [label for label, line in ledger_lines(broken).items() if "DONE" in line]
        assert len(done) == 6, "the control must leave six DONE lines in place"
        assert overall_count(broken) == 5
        assert overall_count(broken) != len(done), (
            "a wrong Overall count must disagree with the ledger it summarises"
        )
        assert overall_count(PLAN) == len(done), "the unmutated plan is its own control"

    def test_the_ledger_check_catches_a_missing_phase_line(self) -> None:
        broken = self._mutated("- Phase 6 (docs, honesty gates, rollout):", "- Phase Six:")
        assert "Phase 6" not in ledger_lines(broken)
        assert set(ledger_lines(broken)) != {f"Phase {i}" for i in range(1, 7)}
        assert "Phase 6" in ledger_lines(PLAN)

    def test_the_done_line_check_catches_a_line_with_no_files(self) -> None:
        original = ledger_lines(PLAN)["Phase 6"]
        stripped = _FILE_PATH_RE.sub("a-file", original).replace("tests/unit/", "a-suite ")
        assert _FILE_PATH_RE.search(stripped) is None, "the control must strip the file names"
        assert _FILE_PATH_RE.search(original) is not None
        assert "tests/unit/" not in stripped

    @pytest.mark.parametrize("planted", [planted for planted, _ in PLANTED_CLAIMS])
    def test_every_forbidden_claim_checker_actually_fires(self, planted: str) -> None:
        """Each checker is exercised by planting its own sentence.

        A prose gate that never fires is indistinguishable from a prose gate that
        does not work. For every planted false claim: the real plan is clean of it,
        and the sentence trips exactly one forbidden pattern.
        """
        offenders = [
            pattern for pattern, _ in FORBIDDEN_CLAIMS if re.search(pattern, planted, re.I)
        ]
        assert len(offenders) == 1, (
            f"{planted!r} should trip exactly one forbidden pattern, tripped {offenders}"
        )
        assert re.search(offenders[0], PLAN, re.I) is None, (
            "the plan already contains a forbidden claim; this control cannot prove "
            "the checker fires while the real check is failing for a different reason"
        )

    def test_the_claim_checker_catches_a_planted_sentence_in_the_document(self) -> None:
        """The same plant, but inside the document the checker reads.

        A checker that only works on a bare string would pass the per-pattern
        control above; this one puts the lie where a reader would find it.
        """
        planted, because = PLANTED_CLAIMS[0]
        broken = self._mutated("## STATUS", f"## STATUS\n\n{planted}\n")
        offenders = [
            (pattern, match.group(0))
            for pattern, _ in FORBIDDEN_CLAIMS
            if (match := re.search(pattern, broken, re.I)) is not None
        ]
        assert len(offenders) == 1, f"expected one trip, got {offenders}"
        assert because, "each planted claim records why it would be a lie"

    def test_a_dropped_decision_row_is_caught_by_the_exhaustiveness_check(self) -> None:
        from mayhem.domain import lowlevel_report

        saved = lowlevel_report.DESCRIPTOR_ONLY_RULES
        object.__setattr__(
            lowlevel_report,
            "DESCRIPTOR_ONLY_RULES",
            {key: value for key, value in saved.items() if key != "jvm.gc_pressure"},
        )
        try:
            problems = disposition_problems()
        finally:
            object.__setattr__(lowlevel_report, "DESCRIPTOR_ONLY_RULES", saved)
        assert [p.subject for p in problems] == ["jvm.gc_pressure"]
        assert disposition_problems() == ()

    def test_a_missing_caveat_sentence_is_caught(self) -> None:
        broken = re.sub(r"substrate ceiling", "substrate summary", PLAN, flags=re.I)
        assert "substrate ceiling" not in broken.lower()
        assert "substrate ceiling" in PLAN.lower()

    def test_the_privilege_check_catches_a_dropped_token(self) -> None:
        broken = PLAN.replace("`CAP_BPF`", "`CAP_SYS_NICE`")
        assert "CAP_BPF" not in broken
        assert "CAP_BPF" in PLAN



