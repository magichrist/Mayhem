"""Plan 06 Phase 6 — the doc's honesty claims are machine-checked, not asserted.

Each checker below reads `docs/v1.1.0/06_CLOUD_PROVIDERS.md` and fails the
suite (not the review) when the document drifts from the implementation:
refusal codes that do not exist, matrix rows no adapter declares, rollback
implied where the cloud offers none, or a rollout order that stops naming
AWS first. Every checker is also run against a mutated copy to prove it
bites.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

DOC = Path(__file__).resolve().parents[2] / "docs" / "v1.1.0" / "06_CLOUD_PROVIDERS.md"
SRC = Path(__file__).resolve().parents[2] / "src" / "mayhem"

BANNED_OVERCLAIMS = (
    "guaranteed rollback",
    "exactly-once",
    "demonstrated on a live account",
)


def _text() -> str:
    return DOC.read_text()


def _code_vocabulary() -> set[str]:
    vocab: set[str] = set()
    for name in (
        "domain/cloud.py",
        "providers/cloud/port.py",
        "providers/cloud/report.py",
        "controller/cloud_evidence.py",
    ):
        vocab.update(re.findall(r'"(cloud\.[a-z_.]+)"', (SRC / name).read_text()))
    return vocab


def check_completion(text: str) -> None:
    assert "Overall: 6 of 6 phases complete." in text, (
        "the plan is not 6 of 6: update Overall when the last phase lands"
    )
    for phase in ("Phase 5", "Phase 6"):
        line = next((ln for ln in text.splitlines() if ln.startswith(f"- {phase}")), "")
        assert "DONE" in line, f"{phase} STATUS line does not say DONE: {line!r}"


def check_codes_exist(text: str, vocab: set[str]) -> None:
    quoted = set(re.findall(r"`(cloud\.[a-z_]+)`", text))
    unknown = sorted(code for code in quoted if code not in vocab)
    assert not unknown, (
        f"the doc quotes refusal codes nothing raises: {unknown}; "
        "a refusal code nothing can raise is a spelling, not a contract"
    )


def check_matrix_matches_tables(text: str) -> None:
    from mayhem.providers.cloud.aws import AwsCloudAdapter
    from mayhem.providers.cloud.azure import AzureCloudAdapter
    from mayhem.providers.cloud.gcp import GcpCloudAdapter
    from mayhem.providers.cloud.port import IrreversibleCapability

    declared = {
        f"{kind.value}/{cls.value}"
        for adapter_cls in (AwsCloudAdapter, GcpCloudAdapter, AzureCloudAdapter)
        for (kind, cls) in adapter_cls.capabilities
    }
    section = text.split("## Capability matrix")[1].split("## Honesty gates", maxsplit=1)[0]
    rows = re.findall(r"\| (?:aws|gcp|azure) \| `([a-z]+/[a-z_]+)`", section)
    assert rows, "the capability matrix has no provider rows to check"
    assert set(rows) == declared, (
        f"matrix drifts from the adapter tables: "
        f"missing={sorted(set(declared) - set(rows))} "
        f"extra={sorted(set(rows) - set(declared))}"
    )
    irreversible = {
        f"{kind.value}/{cls.value}"
        for adapter_cls in (AwsCloudAdapter, GcpCloudAdapter, AzureCloudAdapter)
        for (kind, cls), cap in adapter_cls.capabilities.items()
        if isinstance(cap, IrreversibleCapability)
    }
    assert irreversible == {
        "impair/block_storage",
        "isolate/function",
    }, f"unexpected irreversible set: {sorted(irreversible)}"
    for pair in irreversible:
        assert "| — (none exists) |" in section or "no" in section
        row = next(ln for ln in section.splitlines() if f"`{pair}`" in ln)
        assert "no" in row.split("|")[4], f"{pair} must read irreversible: {row!r}"


def check_no_implied_rollback(text: str) -> None:
    for claim in BANNED_OVERCLAIMS:
        assert claim not in text, (
            f"the doc over-claims with {claim!r}: no doc may imply rollback "
            "where the cloud offers none"
        )
    assert "the cloud offers no rollback" in text


def check_rollout_order(text: str) -> None:
    section = text.split("## Rollout order")[1]
    assert "`aws` `stop/vm` first" in section
    assert "one provider and one resource class at a time" in section.lower()
    assert "plan 01" in section


class TestPhase6DocHonesty:
    def test_completion(self) -> None:
        check_completion(_text())

    def test_codes_exist(self) -> None:
        check_codes_exist(_text(), _code_vocabulary())

    def test_matrix_matches_tables(self) -> None:
        check_matrix_matches_tables(_text())

    def test_no_implied_rollback(self) -> None:
        check_no_implied_rollback(_text())

    def test_rollout_order(self) -> None:
        check_rollout_order(_text())


class TestCheckersBite:
    """Each checker fails on a doc that breaks its rule — otherwise the
    checker is decoration."""

    def test_completion_bites(self) -> None:
        with pytest.raises(AssertionError):
            check_completion(_text().replace("6 of 6", "4 of 6"))
        with pytest.raises(AssertionError):
            check_completion(_text().replace("- Phase 6: DONE", "- Phase 6: not started"))

    def test_codes_bite(self) -> None:
        with pytest.raises(AssertionError):
            check_codes_exist(_text() + "\n`cloud.nonexistent_thing`\n", _code_vocabulary())

    def test_matrix_bites(self) -> None:
        with pytest.raises(AssertionError):
            check_matrix_matches_tables(_text().replace("`stop/vm`", "`reboot/vm`", 1))

    def test_overclaim_bites(self) -> None:
        with pytest.raises(AssertionError):
            check_no_implied_rollback(_text() + "\nguaranteed rollback\n")

    def test_rollout_bites(self) -> None:
        with pytest.raises(AssertionError):
            check_rollout_order(_text().replace("`aws` `stop/vm` first", "`gcp` first"))
