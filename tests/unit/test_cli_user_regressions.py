from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

from click.testing import CliRunner

from mayhem.cli.app import app
from mayhem.cli.lifecycle import _resolve_spec_pair


def test_validate_finds_drill_spec_beside_compose_file(tmp_path: Path) -> None:
    compose = tmp_path / "docker-compose.mayhem.yml"
    spec = tmp_path / "mayhem.yaml"
    compose.write_text("services: {}\n")
    spec.write_text("kind: drill\n")

    resolved, config = _resolve_spec_pair(None, None, str(compose))

    assert resolved == str(spec)
    assert config is None


def test_janitor_execute_has_short_alias() -> None:
    result = CliRunner().invoke(app, ["janitor", "--help"])

    assert result.exit_code == 0
    assert "-e, --execute" in result.output


def test_status_projects_dead_running_controller_as_stale() -> None:
    from mayhem.cli.lifecycle import _project_run_liveness

    projected = _project_run_liveness(
        {"id": "run-1", "status": "running", "controller_pid": 99999999}
    )

    assert projected["liveness_status"] == "stale"
    assert projected["controller_alive"] is False


def test_status_projects_running_without_controller_as_stale() -> None:
    from mayhem.cli.lifecycle import _project_run_liveness

    projected = _project_run_liveness({"id": "run-2", "status": "running", "controller_pid": None})

    assert projected["liveness_status"] == "stale"
    assert projected["controller_alive"] is None


def test_discover_faults_explain_uses_short_option() -> None:
    result = CliRunner().invoke(app, ["discover", "faults", "-e", "proc.pause"])

    assert result.exit_code == 0
    assert json.loads(result.output)["id"] == "proc.pause"
    assert "fault" not in app.commands["discover"].commands
