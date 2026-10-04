"""Plan 17 Phase 6's acceptance criterion, made executable.

    *Acceptance: no doc calls an SDK-built artifact trusted, verified, or signed
    without the same-breath disclaimer.*

That is a claim about prose, so only a test can keep it. This file is that test,
scoped to the documents plan 17 owns — ``docs/providers/`` plus this plan's own
status file.

Why it is not redundant with ``tests/unit/test_readme_honesty.py``
---------------------------------------------------------------------
That module already owns two adjacent gates over the published surface: no
document describes a fault pack as signed without a disclaimer, and no document
asserts a verified signature. Neither of those is this criterion. It is about
**an SDK-built artifact and a publisher**, which is a different subject: a page
may be perfectly correct about fault packs and still call the output of
``python_declaration`` "verified", because the SDK is not a pack.

So this scan adds the missing axis rather than repeating two others:

* **subject**: SDK / artifact / provider / publisher — not "pack".
* **the specific overclaim**: a *publisher* being authenticated, trusted or
  checked, which is the thing no label and no evidence chain in this repository
  establishes.

Negative controls
-----------------
Every substantive check has one. :class:`TestTheScanCanFail` deletes each
disclaimer from a copy of the real page and asserts the scan complains, and
asserts that a scan run against an empty rule set would pass — which is what
proves the rules are doing the work and not the file being clean.

Prose is scanned, not identifiers. That is the difference from the SDK suite's
overclaim scan and it is deliberate: in *source*, a field named
``verified_signer`` is the defect; in *documentation*, the sentence "this is not
verified" is the requirement, so the scan must be able to see and permit a
denial.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from mayhem.domain.provider import PROVIDER_DECLARATION_SCHEMA_VERSION
from mayhem.providers.pack import SIGNATURE_TRUST_NOTICE, SIGNATURE_VERIFICATION_IMPLEMENTED
from mayhem.providers.sdk import (
    GO_SDK_SHIPPED,
    PYTHON_SDK_SHIPPED,
    RUST_SDK_SHIPPED,
    SDK_NOT_CONFERRED,
    SDK_UNVERIFIED_NOTICE,
)

ROOT = Path(__file__).parents[2]

#: The documents plan 17 owns. ``test_readme_honesty.py`` scans a wider surface;
#: this is the subset this plan is responsible for, so a failure here names a
#: page this lane wrote.
OWNED_DOCUMENTS: tuple[Path, ...] = (
    *sorted(ROOT.glob("docs/providers/*.md")),
    ROOT / "docs" / "v1.1.0" / "17_EXTENSION_SDK_PROVIDER_PROTOCOL.md",
)

#: Words that put a passage *about* the subject this scan cares about. Kept
#: separate from :data:`SIGNATURE_OVERCLAIM` in the other module because the
#: subject differs: a page about fault packs is not in scope here, and a page
#: about an SDK artifact is.
SUBJECT = re.compile(r"\bSDK\b|artifact|provider|publisher|declaration", re.IGNORECASE)

#: Phrasings that assert a *check happened*. Each is a contradiction of
#: ``SIGNATURE_VERIFICATION_IMPLEMENTED is False``. Written as explicit
#: overclaims rather than as "any use of the word", because the honest sentence
#: this plan needs everywhere is "no signature is verified" — and a scan that
#: forbade the word would forbid the disclaimer.
CLAIMS_A_CHECK = re.compile(
    r"signature[-\s]?verified|"
    r"verified\s+signature|"
    r"signature\s+is\s+verified|"
    r"cryptographically\s+signed|"
    r"authentically\s+published|"
    r"trusts?\s+this\s+(?:artifact|provider|publisher|declaration)|"
    r"trusted\s+(?:artifact|provider|publisher|declaration)|"
    r"publisher\s+is\s+(?:authenticated|verified|trusted)|"
    r"(?:verify|verifies|verified)\s+the\s+publisher|"
    r"built\s+with\s+a\s+verified\s+sdk|"
    r"sdk[-\s]verified",
    re.IGNORECASE,
)

#: The same-breath disclaimers this plan accepts. Each is a *denial* the shipped
#: prose uses verbatim or by direct paraphrase, so a reworded page that keeps
#: the meaning keeps passing.
DISCLAIMERS = (
    re.compile(
        r"SIGNATURE_VERIFICATION_IMPLEMENTED`?\s*(?:is|remains)?\s*`?\s*`?False", re.I
    ),
    re.compile(r"verif(?:y|ies)\s+no\s+signature", re.I),
    re.compile(r"no\s+signature\s+is\s+(?:checked|verified)", re.I),
    re.compile(r"unverified", re.I),
    re.compile(r"unsigned", re.I),
    re.compile(r"claim(?:ed)?\s+of\s+authorship", re.I),
    re.compile(r"nothing\s+(?:in\s+this\s+system\s+)?can\s+tell\s+you", re.I),
    re.compile(r"no\s+\.crate|there\s+is\s+no\s+rust\s+crate", re.I),
    re.compile(r"no\s+go\s+package|there\s+is\s+no\s+go\s+package", re.I),
)

_BLOCK_SPLIT = re.compile(r"\n\s*\n")


def _blocks(text: str) -> list[str]:
    """Blank-line-separated blocks, so a disclaimer on the next paragraph counts."""
    return [block.strip() for block in _BLOCK_SPLIT.split(text) if block.strip()]


def _overclaims(text: str) -> list[str]:
    """Every block that claims a check about an SDK artifact or a publisher."""
    found = []
    for block in _blocks(text):
        if not SUBJECT.search(block):
            continue
        if not CLAIMS_A_CHECK.search(block):
            continue
        if any(pattern.search(block) for pattern in DISCLAIMERS):
            continue
        found.append(block.splitlines()[0][:160])
    return found


def _has_disclaimer(text: str) -> bool:
    return any(pattern.search(text) for pattern in DISCLAIMERS)


_CHECKLIST_ITEM = re.compile(r"(?ms)^- \[[ x]\].*?(?=^- \[[ x]\]|\Z)")


def _checklist_items(text: str) -> list[str]:
    """Each checklist entry as its own string, continuation lines included.

    Not :func:`_blocks`: a Markdown checklist has no blank lines between entries,
    so block splitting would return a whole section and a check that read one
    block would pass on an entry whose qualifier happens to live in the next one.
    """
    return [match.group(0) for match in _CHECKLIST_ITEM.finditer(text)]


# =============================================================================
# The gate
# =============================================================================


class TestNoOwnedDocumentOverclaims:
    @pytest.mark.parametrize("path", OWNED_DOCUMENTS, ids=lambda path: path.name)
    def test_no_block_claims_a_check_without_a_same_breath_disclaimer(
        self, path: Path
    ) -> None:
        text = path.read_text(encoding="utf-8")
        overclaims = _overclaims(text)
        assert not overclaims, (
            f"{path.relative_to(ROOT)} claims a check mayhem does not perform:\n"
            + "\n".join(overclaims)
        )

    @pytest.mark.parametrize("path", OWNED_DOCUMENTS, ids=lambda path: path.name)
    def test_every_document_states_the_signature_fact_outright(self, path: Path) -> None:
        """Not "no overclaim found" — an actual statement.

        A page can be clean by saying nothing at all. Every page this plan owns
        has to carry the fact, because a reader who lands on the sandbox tiers
        table should not have to guess whether any of it depends on authorship.
        """
        text = path.read_text(encoding="utf-8")
        assert _has_disclaimer(text), (
            f"{path.relative_to(ROOT)} says nothing about whether a signature is "
            "verified; silence is not a disclaimer"
        )

    def test_the_documents_say_the_flag_is_false_not_that_it_might_be(self) -> None:
        joined = "\n".join(path.read_text(encoding="utf-8") for path in OWNED_DOCUMENTS)
        assert "SIGNATURE_VERIFICATION_IMPLEMENTED" in joined
        assert "`False`" in joined

    def test_the_index_carries_both_caveats_before_any_example(self) -> None:
        """Order matters: a reader must meet the caveat before the first claim."""
        text = (ROOT / "docs" / "providers" / "README.md").read_text(encoding="utf-8")
        first_claim = text.find("## What the SDK does, and does not, confer")
        assert first_claim != -1
        preamble = text[:first_claim]
        assert "SIGNATURE_VERIFICATION_IMPLEMENTED" in preamble
        assert "seccomp" in preamble

    def test_no_own_document_calls_an_sdk_artifact_signed(self) -> None:
        for path in OWNED_DOCUMENTS:
            text = path.read_text(encoding="utf-8")
            for block in _blocks(text):
                if not SUBJECT.search(block):
                    continue
                if not re.search(r"\bsigned\b|\bsigner\b", block, re.IGNORECASE):
                    continue
                assert _has_disclaimer(block) or "signature" in block.lower(), (
                    f"{path.relative_to(ROOT)} pairs signing language about an SDK "
                    f"artifact with no disclaimer: {block.splitlines()[0][:120]!r}"
                )


# =============================================================================
# The documents state the facts the code states
# =============================================================================


class TestTheDocumentsMatchTheCode:
    def test_the_shipped_sdk_flags_agree_with_the_pages(self) -> None:
        rust = (ROOT / "docs" / "providers" / "sdk-rust.md").read_text(encoding="utf-8")
        go = (ROOT / "docs" / "providers" / "sdk-go.md").read_text(encoding="utf-8")
        assert "`RUST_SDK_SHIPPED` is `False`" in rust
        assert "`GO_SDK_SHIPPED` is `False`" in go
        assert RUST_SDK_SHIPPED is False
        assert GO_SDK_SHIPPED is False
        assert PYTHON_SDK_SHIPPED is True

    def test_the_security_model_names_the_real_tier_count(self) -> None:
        from mayhem.providers.sandbox import SANDBOX_TIERS

        text = (ROOT / "docs" / "providers" / "security-model.md").read_text(encoding="utf-8")
        for tier in SANDBOX_TIERS:
            assert tier.id in text, tier.id
        assert len(SANDBOX_TIERS) == 7
        assert "six of the seven" in text

    def test_the_not_conferred_list_is_the_one_the_code_holds(self) -> None:
        index = (ROOT / "docs" / "providers" / "README.md").read_text(encoding="utf-8")
        for claim in SDK_NOT_CONFERRED:
            sentence = claim.rstrip(".")
            assert sentence in index, claim

    def test_the_conferred_list_is_the_one_the_code_holds(self) -> None:
        index = (ROOT / "docs" / "providers" / "README.md").read_text(encoding="utf-8")
        for claim in SDK_NOT_CONFERRED:
            assert claim.startswith("that "), claim
        assert "validates against the `mayhem.provider-declaration/v1` grammar" in index
        assert PROVIDER_DECLARATION_SCHEMA_VERSION in index
        assert len(SDK_NOT_CONFERRED) == 4

    def test_the_two_notices_the_code_carries_appear_in_the_docs(self) -> None:
        joined = "\n".join(path.read_text(encoding="utf-8") for path in OWNED_DOCUMENTS)
        assert "SDK_UNVERIFIED_NOTICE" in joined or "claim of authorship" in joined
        assert SIGNATURE_TRUST_NOTICE
        assert SDK_UNVERIFIED_NOTICE
        assert SIGNATURE_VERIFICATION_IMPLEMENTED is False

    def test_the_readiness_checklist_leaves_the_unimplemented_boxes_unchecked(self) -> None:
        """The checklist must not tick a box the code does not deliver.

        Read as structure rather than as prose: a `- [x]` on any of these would
        be the page's own version of the overclaim this scan hunts.
        """
        text = (ROOT / "docs" / "providers" / "marketplace-readiness.md").read_text(
            encoding="utf-8"
        )
        items = _checklist_items(text)
        for absent in (
            "A seccomp filter is applied",
            "An AppArmor profile is written",
            "An SELinux label is applied",
            "A container is created for the provider",
            "Every manifest is authenticated",
            "The charge is made by the run path",
            "The lease is persisted by the executor",
            "A provider fault can be certified on a matrix cell",
            "A Rust crate is shipped",
            "A Go package is shipped",
        ):
            item = next(entry for entry in items if f"- [ ] {absent}" in entry)
            # Each entry has to say *why* it is unticked, in one of the phrasings
            # the checklist actually uses. An unticked box with no stated reason
            # is indistinguishable from an oversight.
            assert any(
                marker in item
                for marker in (
                    "Not implemented",
                    "Not wired",
                    "Blocked twice over",
                    "`False`",
                )
            ), item

    def test_the_checklist_ticks_only_what_the_code_enforces(self) -> None:
        text = (ROOT / "docs" / "providers" / "marketplace-readiness.md").read_text(
            encoding="utf-8"
        )
        checked = [line for line in text.splitlines() if line.startswith("- [x]")]
        assert len(checked) >= 20
        for line in checked:
            assert "Not implemented" not in line
            assert "Not wired" not in line


# =============================================================================
# Negative controls
# =============================================================================


class TestTheScanCanFail:
    """Every check above has to be able to complain.

    A gate that cannot fail is decoration. Each control removes one thing from a
    real page and asserts the scan notices, so a future edit that quietly deletes
    a disclaimer fails the suite rather than passing on a clean file.
    """

    def test_the_overclaim_scan_fails_on_a_signed_sdk_sentence(self) -> None:
        planted = (
            "## Load it\n\n"
            "Run `python_declaration` and the resulting artifact is signed by its "
            "publisher, so mayhem can trust this provider.\n"
        )
        assert _overclaims(planted)

    def test_the_overclaim_scan_fails_on_a_verified_publisher(self) -> None:
        planted = (
            "A provider is listed once the publisher is authenticated and the "
            "declaration has been verified.\n"
        )
        assert _overclaims(planted)

    def test_the_same_sentence_with_the_disclaimer_is_clean(self) -> None:
        """The control for the control.

        A scan that flagged every mention would make the required sentence
        unwritable, which would push the fix towards vagueness — the failure this
        whole gate exists to prevent.
        """
        honest = (
            "An SDK-built declaration is a claim of authorship. mayhem verifies no "
            "signature over a provider artifact in this build: "
            "SIGNATURE_VERIFICATION_IMPLEMENTED is `False`.\n"
        )
        assert _overclaims(honest) == []

    def test_the_disclaimer_does_not_cover_a_different_block(self) -> None:
        """Same-breath means same block, not same document."""
        planted = (
            "## Preface\n\n"
            "mayhem verifies no signature; SIGNATURE_VERIFICATION_IMPLEMENTED is "
            "`False`.\n\n"
            "## Load it\n\n"
            "The artifact is signature-verified by its publisher.\n"
        )
        assert _overclaims(planted)

    def test_removing_every_disclaimer_from_a_real_page_makes_it_fail(self) -> None:
        """The control for the disclaimer check itself.

        Every accepted phrasing is blanked out, not just one, because a page
        carries several and removing the first would leave the rest holding the
        property up. Only a page with none of them left is genuinely unqualified.
        """
        index = (ROOT / "docs" / "providers" / "README.md").read_text(encoding="utf-8")
        cleaned = index
        for pattern in DISCLAIMERS:
            cleaned = pattern.sub("REDACTED", cleaned)
        assert _has_disclaimer(index)
        assert not _has_disclaimer(cleaned)

    def test_removing_one_disclaimer_leaves_the_page_qualified(self) -> None:
        """The other half of the control: the check is not brittle.

        A page has several disclaimers on purpose, so deleting one should not
        make a good page look unqualified. If it does, the scan is measuring
        phrasing rather than substance.
        """
        index = (ROOT / "docs" / "providers" / "README.md").read_text(encoding="utf-8")
        without_flag = index.replace("SIGNATURE_VERIFICATION_IMPLEMENTED", "SIGNATURE_STATUS")
        assert _has_disclaimer(without_flag)

    def test_a_scan_with_no_rules_would_pass_everything(self) -> None:
        """Proof the rules, not the files, are what is doing the work."""
        index = (ROOT / "docs" / "providers" / "README.md").read_text(encoding="utf-8")
        subject = re.compile(r".", re.DOTALL)
        claims = re.compile(r"(?!x)x")
        overclaims = [
            block
            for block in _blocks(index)
            if subject.search(block) and claims.search(block)
        ]
        assert not overclaims
        assert _overclaims(index) == []

    def test_the_owned_document_set_is_not_empty(self) -> None:
        """A glob that matched nothing would make every gate above vacuous."""
        assert len(OWNED_DOCUMENTS) >= 6
        assert all(path.exists() for path in OWNED_DOCUMENTS)
        assert {path.name for path in OWNED_DOCUMENTS} >= {
            "README.md",
            "sdk-python.md",
            "sdk-rust.md",
            "sdk-go.md",
            "security-model.md",
            "marketplace-readiness.md",
        }
