"""Contract for the release workflow.

The CI workflow was removed deliberately, so its contract test went with it.
This file keeps the one assertion that still has a subject: the publishing
workflow that actually ships the package. `conformance.yml` is covered by
`test_release_contract.py`.
"""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
RELEASE = ROOT / ".github" / "workflows" / "release.yml"


def _workflow(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def test_release_workflow_keeps_publishing_permissions() -> None:
    workflow = _workflow(RELEASE)
    assert workflow["permissions"]["id-token"] == "write"
    assert "build-and-publish" in workflow["jobs"]
