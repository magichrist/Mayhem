"""Plan 20 Phase 6 — the enterprise guides say only what the code can prove.

Each checker reads `docs/v1.1.0/20_ENTERPRISE_GUIDES.md` and fails the suite
(not the review) when the document drifts from the implementation: a
compliance or certification claim without qualification, a live proof named
as done, a refusal code nothing raises, or a rollout order that stops naming
local-plus-sandbox first. Every checker is also run against a mutated copy
to prove it bites.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DOC = Path(__file__).resolve().parents[2] / "docs" / "v1.1.0" / "20_ENTERPRISE_GUIDES.md"
SRC = Path(__file__).resolve().parents[2] / "src" / "mayhem"

BANNED_UNQUALIFIED = (
    "is compliant with",
    "certified compliant",
    "certifies compliance",
    "attests compliance",
    "guarantees compliance",
    "demonstrated on a live cluster",
    "demonstrated against a live identity provider",
    "proven against a live container runtime",
)


def _text() -> str:
    return DOC.read_text(encoding="utf-8")


def _code_vocabulary() -> set[str]:
    vocab: set[str] = set()
    for name in (
        "domain/deployment.py",
        "domain/failure_modes.py",
        "controller/sandbox_service.py",
        "controller/support_bundle.py",
        "controller/upgrade_channels.py",
        "controller/compliance_map.py",
        "controller/enterprise_walkthrough.py",
        "infra/network_policy.py",
    ):
        text = (SRC / name).read_text()
        vocab.update(re.findall(r"[\"']([a-z_]+\.[a-z_.]+)", text))
        vocab.update(re.findall(r"\b([a-z_]+(?:\.template_must_[a-z_]+|\.flag_drift))\b", text))
    # Rule ids built by f-string prefix rather than quoted whole: the evidence
    # and flag-drift refusals format their rule inline.
    vocab.update(
        {
            "evidence.non_production_mode",
            "evidence.flag_drift",
            "evidence.no_run_id",
            "deployment_model.air_gapped_without_policy",
        }
    )
    return vocab


def check_no_unqualified_claims(text: str) -> None:
    for claim in BANNED_UNQUALIFIED:
        assert claim not in text.lower(), (
            f"the guide over-claims with {claim!r}: no doc may claim compliance, "
            "certification, or a live proof without qualification"
        )
    assert "never a certification" in text or "not a finding" in text, (
        "the guide must state plainly that templates and maps are not attestations"
    )
    assert "must perform their own assessment" in text, (
        "the guide must name the customer's remaining obligation"
    )


def check_live_proofs_named_as_open(text: str) -> None:
    for item in ("live IdP", "human approver", "live container runtime", "live cluster"):
        assert item in text, f"the guide must name {item!r} as a live proof still owed, not as done"


def check_codes_exist(text: str, vocab: set[str]) -> None:
    quoted = set(re.findall(r"`([a-z_]+\.[a-z_.]+)`", text))
    unknown = sorted(code for code in quoted if code not in vocab)
    assert not unknown, (
        f"the guide quotes refusal codes nothing raises: {unknown}; "
        "a refusal code nothing can raise is a spelling, not a contract"
    )
    assert quoted, "the guide quotes no refusal codes at all; this probe is broken"


def check_rollout_order(text: str) -> None:
    section = text.split("## Rollout order")[1].split("## Honesty gates", maxsplit=1)[0]
    assert "Local plus sandbox first" in section
    assert "self-hosted second" in section
    assert "SaaS and air-gapped last" in section.lower() or "air-gapped last" in section


class TestPhase6GuidesHonesty:
    def test_no_unqualified_claims(self) -> None:
        check_no_unqualified_claims(_text())

    def test_live_proofs_named_as_open(self) -> None:
        check_live_proofs_named_as_open(_text())

    def test_codes_exist(self) -> None:
        check_codes_exist(_text(), _code_vocabulary())

    def test_rollout_order(self) -> None:
        check_rollout_order(_text())


class TestCheckersBite:
    """Each checker fails on a doc that breaks its rule — otherwise decoration."""

    def test_claims_bite(self) -> None:
        with pytest.raises(AssertionError):
            check_no_unqualified_claims(_text() + "\nThis setup is compliant with SOC 2.\n")

    def test_live_bites(self) -> None:
        with pytest.raises(AssertionError):
            check_live_proofs_named_as_open(_text().replace("live IdP", "the IdP"))

    def test_codes_bite(self) -> None:
        with pytest.raises(AssertionError):
            check_codes_exist(_text() + "\n`enterprise.nonexistent_thing`\n", _code_vocabulary())

    def test_rollout_bites(self) -> None:
        with pytest.raises(AssertionError):
            check_rollout_order(_text().replace("Local plus sandbox first", "SaaS first"))
