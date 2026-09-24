from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from click.testing import CliRunner

from mayhem.cli.app import main
from mayhem.cli.extend import providers

if TYPE_CHECKING:
    from pathlib import Path


def metadata(provider_id: str = "test.provider") -> dict[str, Any]:
    return {
        "apiVersion": "mayhem.provider/v1",
        "providerId": provider_id,
        "name": "Test Provider",
        "version": "1.0.0",
        "description": "A test provider.",
        "permissions": [],
        "capabilities": [
            {"id": "target.discovery", "summary": "Resolve test targets."}
        ],
        "targetLocators": [
            {
                "id": "test.target",
                "kind": "test_object",
                "selectorSchema": {"name": "string"},
                "requiredPermissions": [],
            }
        ],
        "evidenceSchema": {
            "name": "test-evidence",
            "version": "1.0",
            "fields": ("target",),
        },
    }


def write_catalog(path: Path, target: str) -> None:
    path.write_text(
        json.dumps(
            {
                "apiVersion": "mayhem.provider-catalog/v1",
                "providers": [
                    {
                        "metadata": metadata(),
                        "implementation": {
                            "kind": "import",
                            "target": target,
                            "factory": False,
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def test_provider_inspection_is_dry_run(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog, "tests.missing_provider:Missing")
    runner = CliRunner()

    result = runner.invoke(
        providers,
        ["inspect", "--catalog", str(catalog), "--json"],
        standalone_mode=False,
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["loaded"] == []
    assert payload["providers"][0]["status"] == "ready"


def test_provider_load_rejects_undeclared_mutation_permission(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog, "tests.unit.test_cli_extend:TestRuntime")
    payload = json.loads(catalog.read_text(encoding="utf-8"))
    payload["providers"][0]["metadata"]["permissions"] = ["target:mutate"]
    catalog.write_text(json.dumps(payload), encoding="utf-8")
    runner = CliRunner()

    result = runner.invoke(
        providers,
        [
            "load",
            "--catalog",
            str(catalog),
            "--allow-permission",
            "target:read",
            "--json",
        ],
        standalone_mode=False,
    )

    assert result.exit_code != 0
    assert "target:mutate" in result.output


def test_provider_load_accepts_declared_permission(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog, "tests.unit.test_cli_extend:TestRuntime")
    payload = json.loads(catalog.read_text(encoding="utf-8"))
    payload["providers"][0]["metadata"]["permissions"] = ["target:read"]
    catalog.write_text(json.dumps(payload), encoding="utf-8")
    runner = CliRunner()

    result = runner.invoke(
        providers,
        [
            "load",
            "--catalog",
            str(catalog),
            "--allow-permission",
            "target:read",
            "--json",
        ],
        standalone_mode=False,
    )

    assert result.exit_code == 0
    assert json.loads(result.output)["loaded"] == ["test.provider"]


def test_provider_help_is_available() -> None:
    result = CliRunner().invoke(providers, ["--help"], standalone_mode=False)

    assert result.exit_code == 0
    assert "inspect" in result.output
    assert "load" in result.output


def test_ordinary_builtin_command_does_not_load_plugins(
    monkeypatch: Any, capsys: Any
) -> None:
    from mayhem.providers import loader

    def fail_import(_: str) -> object:
        raise AssertionError("plugin import attempted")

    monkeypatch.setattr(loader, "import_module", fail_import)

    assert main(["commands", "show"]) == 0
    assert "commands" in capsys.readouterr().out


class TestRuntime:
    pass
