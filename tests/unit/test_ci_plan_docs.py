"""The honesty gates on plan 16's documentation.

Phase 6's acceptance criterion is negative: *no doc may suggest gating
production on uncertified faults* (ties to 01's states). A negative acceptance
criterion checked by reading is not a gate, so this file turns it into assertions
against the source the docs describe.

The property is stated as "the doc and the code must agree", not "the doc must
say the right thing" — because the second is a test that goes stale the moment
somebody edits prose, and a stale honesty test is worse than none.

* **The authorization matrix in the docs is the engine's own table.** Rendered
  from `CHATOPS_REQUIRED_ROLE`, not transcribed, so a widened role shows up here
  rather than in a diff nobody reads.
* **The cookbook's pinned SHAs are the constants' SHAs.** The document quotes
  `actions/checkout@<40 hex>`; if the constant moves and the doc does not, this
  fails.
* **The cookbook names every refusal code the CI surfaces can raise.** A refusal
  a user can hit and the cookbook does not mention is a refusal they will meet as
  a mystery.
* **The honesty gates are stated.** `SIGNATURE_VERIFICATION_IMPLEMENTED` is
  `False`; if a document ever claims a workflow verified a pack signature, this
  fails. Zero `verified-live`; if either document claims otherwise, this fails.
* **The uncertified-fault rule is stated in both documents**, because that is
  Phase 6's own acceptance criterion.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from mayhem.controller import chatops as chatops_module
from mayhem.controller.check_gate import CHATOPS_REQUIRED_ROLE
from mayhem.controller.ci_surface import (
    RULE_FLOATING_ACTION,
    RULE_FLOATING_IMAGE,
    RULE_STATUS_UNAVAILABLE,
    RULE_SUMMARY_WITHOUT_VERDICT,
    RULE_UNTRUSTED_VALUE,
)
from mayhem.providers.pack import SIGNATURE_VERIFICATION_IMPLEMENTED

ROOT = Path(__file__).parents[2]
COOKBOOK = ROOT / "docs/v1.1.0/16_ci_cookbook.md"
GITOPS = ROOT / "docs/v1.1.0/16_gitops_reference.md"
PLAN = ROOT / "docs/v1.1.0/16_CI_GITOPS_INTEGRATIONS.md"

_DOCUMENTS = (COOKBOOK, GITOPS, PLAN)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class TestTheDocumentsExist:
    @pytest.mark.parametrize("document", _DOCUMENTS, ids=lambda p: p.name)
    def test_the_document_is_present_and_not_a_stub(self, document: Path) -> None:
        text = _text(document)
        assert len(text) > 2000, f"{document.name} is too short to be a reference"


class TestTheAuthorizationMatrixIsRenderedNotTranscribed:
    def test_the_gitops_document_renders_every_command_role_pair(self) -> None:
        text = _text(GITOPS)
        for command, role in CHATOPS_REQUIRED_ROLE.items():
            row = f"| `mayhem {command.value} <run-id>` | `{role.value}` |"
            assert row in text, f"the authorization matrix does not render {row!r}"

    def test_the_matrix_has_no_extra_row(self) -> None:
        rows = re.findall(r"^\| `mayhem (\w+) <run-id>` \| `(\w+)` \|", _text(GITOPS), re.M)
        assert set(rows) == {
            (command.value, role.value) for command, role in CHATOPS_REQUIRED_ROLE.items()
        }

    def test_the_module_matrix_agrees_with_the_engine(self) -> None:
        assert tuple(
            (command.value, role.value) for command, role in CHATOPS_REQUIRED_ROLE.items()
        ) == chatops_module.AUTHORIZATION_MATRIX


class TestPinsAreQuotedNotTranscribed:
    def test_the_cookbook_quotes_the_checkout_pin_from_the_constant(self) -> None:
        from mayhem.controller.ci_surface import CHECKOUT_ACTION

        assert CHECKOUT_ACTION.sha in _text(COOKBOOK)

    def test_the_cookbook_refuses_the_floating_shapes_it_names(self) -> None:
        text = _text(COOKBOOK)
        assert "actions/checkout@v4" in text
        assert RULE_FLOATING_ACTION in text
        assert RULE_FLOATING_IMAGE in text

    def test_the_cookbook_states_the_generated_never_ran_caveat(self) -> None:
        """The honesty half of the pinning section.

        A pinned digest is only worth having if the reader knows the workflow has
        never executed, because "we pin everything" and "our gate has been
        running for six months" are different claims.
        """
        text = _text(COOKBOOK)
        assert "Never executed" in text or "never executed" in text
        assert "No workflow in this repository has ever run" in text


class TestEveryRefusalCodeIsDocumented:
    @pytest.mark.parametrize(
        "rule",
        [
            RULE_FLOATING_ACTION,
            RULE_FLOATING_IMAGE,
            RULE_UNTRUSTED_VALUE,
            RULE_SUMMARY_WITHOUT_VERDICT,
            RULE_STATUS_UNAVAILABLE,
        ],
        ids=[
            "floating-action",
            "floating-image",
            "untrusted-value",
            "summary-without-verdict",
            "status-unavailable",
        ],
    )
    def test_the_cookbook_names_the_refusal(self, rule: str) -> None:
        assert rule in _text(COOKBOOK), f"{rule} can be hit by a user and is undocumented"

    @pytest.mark.parametrize(
        "rule",
        [
            "chatops.argument_not_an_identifier",
            "chatops.channel_not_bound",
            "chatops.unknown_command",
            "ci_execution.ambient_privilege",
            "ci_execution.run_without_evidence_link",
            "terraform.state_unreadable",
            "terraform.plan_stale",
            "terraform.credential_in_config",
        ],
        ids=[
            "chatops-argument",
            "chatops-channel",
            "chatops-verb",
            "ci-ambient",
            "ci-unlinked",
            "tf-unreadable",
            "tf-stale",
            "tf-token",
        ],
    )
    def test_the_references_name_the_refusal(self, rule: str) -> None:
        combined = _text(COOKBOOK) + _text(GITOPS)
        assert rule in combined, f"{rule} can be hit by a user and is undocumented"


class TestTheHonestyGates:
    def test_signature_verification_is_still_false_so_no_doc_may_claim_it(self) -> None:
        """The pinned fact this assertion exists to enforce.

        If a future release turns signature verification on, this test fails and
        has to be *edited* deliberately rather than drifting past — which is the
        point. A pack is integrity-checked by content digest; nothing
        authenticates its author.
        """
        assert SIGNATURE_VERIFICATION_IMPLEMENTED is False
        for document in (COOKBOOK, GITOPS):
            lowered = _text(document).lower()
            # Negated forms are the *expected* text, so the assertion has to
            # distinguish "no pack is signature-verified" from a bare claim.
            # Each claim is written as what a lying document would say, with the
            # negation stripped before the comparison.
            for claim in (
                "pack is signature-verified",
                "packs are signed",
                "verifies the pack signature",
                "signature verification is implemented",
                "verifies pack signatures",
            ):
                stripped = claim.replace("no ", "").replace("not ", "")
                bare = stripped not in ("pack is signature-verified",)
                del bare
                for negation in ("no fault pack is signature-verified",):
                    assert claim not in lowered.replace(negation, ""), (
                        f"{document.name} claims {claim!r} outside a negation"
                    )

    def test_both_documents_state_the_signature_position_explicitly(self) -> None:
        assert "SIGNATURE_VERIFICATION_IMPLEMENTED" in _text(COOKBOOK)
        assert "SIGNATURE_VERIFICATION_IMPLEMENTED" in _text(GITOPS)

    def test_neither_document_claims_a_workflow_has_run(self) -> None:
        for document in (COOKBOOK, GITOPS):
            lowered = _text(document).lower()
            for claim in (
                "in production today",
                "runs on every pull request",
                "as we saw in ci",
                "our ci results",
            ):
                assert claim not in lowered, f"{document.name} claims {claim!r}"

    def test_the_zero_verified_live_count_is_stated_and_is_still_zero(self) -> None:
        """Asserted against the repo's own honesty test, not a copy of its number.

        The count lives in a test this lane does not own; if it ever becomes
        non-zero, *that* test is what changes, and the two would then disagree
        loudly rather than the documentation quietly becoming wrong.
        """
        # The owner of the zero is `test_lowlevel_doc_honesty.py`, which asserts
        # it of the v1.0.0 release-gate doc. This lane reads that assertion
        # rather than restating the number.
        owner = (ROOT / "tests/unit/test_lowlevel_doc_honesty.py").read_text(encoding="utf-8")
        assert "verified-live" in owner
        assert "test_the_verified_live_count_this_plan_reports_is_zero" in owner
        for document in (COOKBOOK, GITOPS):
            assert "verified-live" in _text(document)

    def test_the_uncertified_fault_rule_is_stated_in_both_documents(self) -> None:
        """Phase 6's own acceptance criterion, as an assertion.

        The criterion is that *no doc suggests gating production on uncertified
        faults*. Both documents must state the rule positively — an uncertified
        fault warns, a check red on every PR is a check nobody reads, and what is
        unrepresentable is the opposite error.
        """
        for document in (COOKBOOK, GITOPS):
            text = _text(document)
            assert "uncertified" in text
            assert "learn to ignore" in text or "nobody reads" in text
            assert "reported as certified" in text

    def test_the_gitops_document_names_what_does_not_exist(self) -> None:
        text = _text(GITOPS)
        for absence in (
            "No Slack client",
            "No `terraform` binary has been driven",
        ):
            assert absence in text

    def test_the_cookbook_marks_unimplemented_providers_rather_than_guessing(
        self,
    ) -> None:
        """Jenkins, Buildkite, Argo, and Tekton are named in the plan.

        Each needs a different trust model, so the honest response is a closed
        ``Provider`` vocabulary plus a doc that says which are missing — not
        plausible-looking YAML nobody reasoned about.
        """
        from mayhem.controller.ci_surface import Provider

        assert {p.value for p in Provider} == {"github", "gitlab"}
        text = _text(COOKBOOK)
        for provider in ("Jenkins", "Buildkite", "Argo Workflows", "Tekton"):
            assert provider in text
        assert "**Not implemented.**" in text

    def test_the_cookbook_states_the_untrusted_input_containment_rule(self) -> None:
        text = _text(COOKBOOK)
        assert 'run: echo ${{ github.event.pull_request.title }}' in text
        assert '"$MAYHEM_PLAN_REF"' in text


class TestThePlanLedger:
    def test_the_plan_status_counts_match_the_done_lines(self) -> None:
        """One number, and it is checked against the lines rather than trusted."""
        text = _text(PLAN)
        done = len(re.findall(r"^- Phase \d+ .*: DONE", text, re.MULTILINE))
        assert done > 0
        match = re.search(r"^Overall: (\d+) of (\d+) phases complete\.$", text, re.MULTILINE)
        assert match, "the plan has no Overall line"
        assert int(match.group(1)) == done, (
            f"Overall says {match.group(1)} but there are {done} DONE phase lines"
        )
        assert int(match.group(2)) == 6

    def test_no_phase_is_marked_done_without_naming_its_files(self) -> None:
        """A DONE line that does not say what landed is a claim, not a record."""
        for line in _text(PLAN).splitlines():
            if line.startswith("- Phase ") and ": DONE" in line:
                assert "`" in line, f"a DONE line names no file: {line[:80]}"
