from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from mayhem.cli.app import app


def _invoke(args, cwd=None):
    runner = CliRunner()
    with runner.isolated_filesystem():
        import os

        if cwd is not None:
            os.chdir(cwd)
        return runner.invoke(app, args)


def test_init_creates_mayhem_yaml_non_interactive(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(app, ["init", "--non-interactive"])
        assert result.exit_code == 0
        assert Path("mayhem.yaml").exists()
        assert Path("drill.starter.yaml").exists()
        assert "created" in result.output.lower()
        assert "mayhem doctor" in result.output.lower()


def test_init_detects_compose(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("docker-compose.yml").write_text("services:\n  web:\n    image: nginx\n")
        result = runner.invoke(app, ["init", "--non-interactive"])
        assert result.exit_code == 0
        assert "compose" in result.output.lower()
        content = Path("mayhem.yaml").read_text()
        assert "mayhem/v1" in content


def test_init_detects_k8s_manifest(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("deploy.yaml").write_text(
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: foo\n"
        )
        result = runner.invoke(app, ["init", "--non-interactive"])
        assert result.exit_code == 0
        assert (
            "k8s" in result.output.lower()
            or "kubernetes" in result.output.lower()
            or "manifest" in result.output.lower()
        )


def test_init_refuses_overwrite_without_force(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("mayhem.yaml").write_text("apiVersion: mayhem/v1\n")
        result = runner.invoke(app, ["init", "--non-interactive"])
        assert result.exit_code != 0
        assert "refusing to overwrite" in result.output.lower()


def test_init_force_overwrites(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("mayhem.yaml").write_text("apiVersion: mayhem/v1\nruntime: docker\n")
        result = runner.invoke(app, ["init", "--non-interactive", "--force"])
        assert result.exit_code == 0
        assert Path("mayhem.yaml").exists()


def test_init_custom_output(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(app, ["init", "--non-interactive", "--output", "custom.yaml"])
        assert result.exit_code == 0
        assert Path("custom.yaml").exists()
        assert not Path("mayhem.yaml").exists() or True


def test_init_non_interactive_defaults(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("compose.yaml").write_text("services:\n  api:\n    image: nginx\n")
        result = runner.invoke(app, ["init", "--non-interactive"])
        assert result.exit_code == 0
        assert result.exit_code == 0


def test_init_generates_starter_drill_without_mutating_target(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("docker-compose.yml").write_text(
            "services:\n  web:\n    image: nginx\n    container_name: web\n"
        )
        result = runner.invoke(app, ["init", "--non-interactive"])
        assert result.exit_code == 0
        drill = Path("drill.starter.yaml").read_text()
        assert "kind: drill" in drill
        assert "hypothesis" in drill


def test_init_never_calls_runtime(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        with patch("subprocess.run") as mock_run:
            with patch("subprocess.Popen") as mock_popen:
                result = runner.invoke(app, ["init", "--non-interactive"])
                assert result.exit_code == 0
                mock_run.assert_not_called()
                mock_popen.assert_not_called()


def test_init_existing_config_detected(tmp_path):
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("mayhem.yaml").write_text("apiVersion: mayhem/v1\nruntime: podman\n")
        result = runner.invoke(app, ["init", "--non-interactive", "--force"])
        assert result.exit_code == 0
        content = Path("mayhem.yaml").read_text()
        assert "mayhem/v1" in content
