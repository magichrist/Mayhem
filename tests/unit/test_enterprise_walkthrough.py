"""Plan 20 Phase 4 — ``mayhem enterprise`` surface plus the walkthrough harness.

Two properties, each defended by tests that use fakes, never live infra:

1. **The walkthrough runs with injected seams.** ``enterprise walkthrough``
   provisions through a recording fake (no subprocess, no docker), runs the
   demo path with the sandbox's own ceilings, verifies the run, and builds a
   redacted support bundle. Harness-runnable steps are proven; live-only
   steps (an IdP, a human approver, a container runtime, a cluster) are
   reported as open items rather than proven.
2. **The compliance map cites sealed evidence only.** ``enterprise
   compliance-map`` maps sealed digests onto a template's evidence kinds and
   refuses unsealed digests. The output is a mapping, never a certification.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.exit_codes import ExitCode
from mayhem.controller.compliance_map import build_compliance_map, map_statement
from mayhem.controller.enterprise_walkthrough import STEP_NAMES, run_walkthrough
from mayhem.controller.sandbox_service import CommandOutcome, SandboxRunner
from mayhem.domain.deployment import DeploymentModel, NetworkPolicy
from mayhem.domain.failure_modes import COMPLIANCE_TEMPLATES
from mayhem.infra.network_policy import NetworkPolicyGuard

if TYPE_CHECKING:
    from collections.abc import Sequence


class FakeRunner(SandboxRunner):
    """A recording fake: answers from the blueprint, touches no runtime."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str]) -> CommandOutcome:
        from mayhem.controller.sandbox_service import blueprint_services

        recorded = tuple(argv)
        self.calls.append(recorded)
        action = recorded[recorded.index("-f") + 2]
        if action == "ps":
            return CommandOutcome(
                argv=recorded, returncode=0, stdout="\n".join(blueprint_services())
            )
        return CommandOutcome(argv=recorded, returncode=0, stdout="")


def test_walkthrough_harness_proves_the_runnable_steps(tmp_path: Path) -> None:
    report = run_walkthrough(
        FakeRunner(),
        tmp_path,
        policy=NetworkPolicy(),
        model=DeploymentModel.LOCAL,
    )
    assert [step.name for step in report.steps] == list(STEP_NAMES)
    assert report.harness_ok is True
    assert report.complete is False  # live items remain: IdP, human, runtime, cluster
    assert any("identity provider" in item.lower() for item in report.live_open_items)
    assert any("human approval" in item.lower() for item in report.live_open_items)
    proven = {step.name for step in report.steps if step.proven}
    assert {"deploy", "policy", "execute", "verify", "export"} <= proven


def test_walkthrough_names_its_live_open_items(tmp_path: Path) -> None:
    report = run_walkthrough(FakeRunner(), tmp_path)
    assert len(report.live_open_items) == 4
    blob = "\n".join(report.live_open_items)
    assert "plan 09" in blob
    assert "container runtime" in blob
    assert "Helm" in blob


def test_walkthrough_under_an_air_gap_refuses_before_any_command(tmp_path: Path) -> None:
    runner = FakeRunner()
    report = run_walkthrough(
        runner,
        tmp_path,
        policy=NetworkPolicy(air_gapped=True),
        model=DeploymentModel.LOCAL,
    )
    assert report.harness_ok is False
    assert runner.calls == []


def test_walkthrough_export_carries_the_sealed_mode_banner(tmp_path: Path) -> None:
    report = run_walkthrough(FakeRunner(), tmp_path)
    export = next(step for step in report.steps if step.name == "export")
    assert export.proven is True
    assert "dropped=" in export.detail


def test_guard_used_by_the_walkthrough_is_ready() -> None:
    guard = NetworkPolicyGuard.build(NetworkPolicy(), model=DeploymentModel.LOCAL)
    assert guard.ready is True
    assert guard.readiness_refusal() == ""


def _run(*args: str):  # type: ignore[no-untyped-def]
    return CliRunner().invoke(app, list(args), catch_exceptions=False)


def test_enterprise_walkthrough_help_parses() -> None:
    result = _run("enterprise", "walkthrough", "--help")
    assert result.exit_code == 0
    assert "Usage:" in result.output


def test_enterprise_compliance_map_help_parses() -> None:
    result = _run("enterprise", "compliance-map", "--help")
    assert result.exit_code == 0
    assert "Usage:" in result.output


def test_enterprise_compliance_map_refuses_an_unsealed_digest() -> None:
    result = _run(
        "enterprise",
        "compliance-map",
        "--evidence",
        "sealed evidence bundle digest for each run=not-a-digest",
    )
    assert result.exit_code == int(ExitCode.SAFETY_REFUSAL)
    assert "compliance.digest_unsealed" in result.output


def test_enterprise_compliance_map_maps_a_sealed_digest() -> None:
    digest = "c" * 64
    result = _run(
        "enterprise",
        "compliance-map",
        "--evidence",
        f"sealed evidence bundle digest for each run={digest}",
        "--json",
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["evidence_complete"] is False
    assert payload["supplied"][0]["digest"] == digest
    assert "not a finding" in payload["statement"]


def test_compliance_map_statement_never_asserts_conformance() -> None:
    from mayhem.controller.compliance_map import ComplianceEvidence

    control = COMPLIANCE_TEMPLATES[0]
    mapped = build_compliance_map(
        control,
        [
            ComplianceEvidence(evidence_kind=kind, evidence_digest="d" * 64)
            for kind in control.required_evidence
        ],
    )
    assert mapped.evidence_complete is True
    statement = map_statement(mapped)
    assert "not a finding" in statement
    assert "an attestation of conformance" in statement
    assert "must perform their own assessment" in statement
    assert "compliant" not in statement.lower().replace("compliance", "").replace(
        "non-compliant", ""
    )
