from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from mayhem.cli.topology import discover


def _fake_which_both(name: str) -> str | None:
    if name in ("docker", "podman"):
        return f"/usr/bin/{name}"
    return None


def _fake_which_docker(name: str) -> str | None:
    return "/usr/bin/docker" if name == "docker" else None


def test_engine_ambiguity_refusal_via_fake_seam(tmp_path) -> None:
    runner = CliRunner()
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  api:\n    image: nginx\n")
    with patch("shutil.which", side_effect=_fake_which_both):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "v1"
            mock_run.return_value.stderr = ""
            result = runner.invoke(discover, ["--compose", str(compose)])
            assert result.exit_code != 0
            assert (
                "multiple engines available" in result.output.lower()
                or "pass --runtime" in result.output.lower()
            )


def test_engine_explicit_override_resolves(tmp_path) -> None:
    runner = CliRunner()
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  api:\n    image: nginx\n")
    fake_ps_output = json.dumps(
        [
            {
                "ID": "abc123",
                "Names": "test",
                "Image": "nginx",
                "State": "running",
                "Labels": (
                    "com.docker.compose.project=test,com.docker.compose.service=api"
                ),
            }
        ]
    )
    with patch("shutil.which", side_effect=_fake_which_both):
        with patch("subprocess.run") as mock_run:
            def side_effect(cmd, **kwargs):
                m = MagicMock()
                if "--version" in cmd:
                    m.stdout = "Docker version 24"
                    m.stderr = ""
                    m.returncode = 0
                    return m
                if "ps" in cmd:
                    m.stdout = fake_ps_output
                    m.stderr = ""
                    m.returncode = 0
                    return m
                if "inspect" in cmd:
                    m.stdout = "api|2024-01-01|2024-01-01\n"
                    m.stderr = ""
                    m.returncode = 0
                    return m
                if "network" in cmd:
                    m.stdout = "{}"
                    m.stderr = ""
                    m.returncode = 0
                    return m
                m.stdout = ""
                m.stderr = ""
                m.returncode = 0
                return m
            mock_run.side_effect = side_effect
            result = runner.invoke(discover, ["--compose", str(compose), "--runtime", "docker"])
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert data["engine"] == "docker"
            assert "topology_fingerprint" in data or "graph" in data


def test_normalized_topology_shape_both_engines(tmp_path) -> None:
    from mayhem.topology.providers.docker_adapter import DockerAdapter
    from mayhem.topology.providers.podman_adapter import PodmanAdapter

    row = {
        "ID": "abc123456789",
        "Names": "myctr",
        "Image": "nginx",
        "State": "running",
        "Labels": "com.docker.compose.project=test,com.docker.compose.service=api",
        "Networks": [],
    }
    ps_json = json.dumps([row])
    inspect_meta = "myctr|2024-01-01T00:00:00Z|2024-01-01T00:00:00Z"
    pid_out = "1234"

    def fake_run_docker(cmd, **kwargs):
        m = MagicMock()
        if "ps" in cmd:
            m.stdout = ps_json
        elif "--format" in cmd and "{{.State.Pid}}" in " ".join(cmd):
            m.stdout = pid_out
        elif "--format" in cmd and "{{.Name}}" in " ".join(cmd):
            m.stdout = inspect_meta
        elif "network" in cmd:
            m.stdout = "{}"
        else:
            m.stdout = ""
        m.stderr = ""
        m.returncode = 0
        return m

    with patch("shutil.which", return_value="/usr/bin/docker"):
        with patch("subprocess.run", side_effect=fake_run_docker):
            with patch(
                "mayhem.topology.providers.podman_adapter._detect_rootless",
                return_value=False,
            ):
                docker = DockerAdapter("docker")
                podman = PodmanAdapter("podman")
                docker_graph = docker.discover()
                podman_graph = podman.discover()
                docker_kinds = sorted(n.kind.value for n in docker_graph.nodes)
                podman_kinds = sorted(n.kind.value for n in podman_graph.nodes)
                assert docker_kinds == podman_kinds
                assert any(k == "container" for k in docker_kinds)
                assert any(k == "process" for k in docker_kinds)
                docker_ids = sorted(n.id for n in docker_graph.nodes if n.kind.value == "container")
                podman_ids = sorted(n.id for n in podman_graph.nodes if n.kind.value == "container")
                assert docker_ids == podman_ids
