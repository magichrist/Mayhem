from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE = ROOT / ".github" / "workflows" / "release.yml"


def _workflow(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def test_ci_workflow_declares_required_jobs() -> None:
    workflow = _workflow(CI)
    jobs = workflow["jobs"]
    assert {
        "unit",
        "integration",
        "e2e",
        "schema",
        "ruff-fatal",
        "package-build",
        "wheel-smoke",
        "verify-artifacts",
    } <= set(jobs)
    assert jobs["ruff-fatal"]["steps"][-1]["run"].startswith("uv run ruff check --select")
    assert jobs["advisory"]["continue-on-error"] is True


def test_ci_workflow_does_not_gate_broken_architecture_contract() -> None:
    text = CI.read_text()
    assert "lint-imports" in text
    assert "continue-on-error: true" in text
    conformance = yaml.safe_load((ROOT / ".github" / "workflows" / "conformance.yml").read_text())
    assert "workflow_dispatch" in conformance[True]
    assert "push" not in conformance[True]


def test_release_workflow_keeps_publishing_permissions() -> None:
    workflow = _workflow(RELEASE)
    assert workflow["permissions"]["id-token"] == "write"
    assert "build-and-publish" in workflow["jobs"]
