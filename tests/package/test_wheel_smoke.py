from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


pytestmark = pytest.mark.package


def _wheel() -> Path:
    candidates = sorted((Path(__file__).resolve().parents[2] / "dist").glob("mayhem_cli-*.whl"))
    if not candidates:
        pytest.skip("wheel artifact is not present")
    return candidates[0]


@pytest.mark.skipif(os.environ.get("MAYHEM_PACKAGE_SMOKE") != "1", reason="package smoke opt-in")
def test_wheel_cli_smoke(tmp_path: Path) -> None:
    wheel = _wheel()
    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    python = venv / "bin" / "python"
    subprocess.run([str(python), "-m", "pip", "install", "--quiet", str(wheel)], check=True)
    env = {**os.environ, "PATH": f"{venv / 'bin'}:{os.environ['PATH']}", "HOME": str(tmp_path)}
    help_result = subprocess.run(
        [str(venv / "bin" / "mayhem"), "--help"], capture_output=True, text=True, env=env, cwd=tmp_path
    )
    assert help_result.returncode == 0, help_result.stderr
    capability_result = subprocess.run(
        [str(venv / "bin" / "mayhem"), "discover", "capabilities", "--json"],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
    )
    assert capability_result.returncode == 0, capability_result.stderr
    payload = json.loads(capability_result.stdout)
    assert payload["schema_version"] == "1.0"
    assert payload["capabilities"]
