from __future__ import annotations

import json
import re
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
        "capabilities": [{"id": "target.discovery", "summary": "Resolve test targets."}],
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


def _permission_catalog(tmp_path: Path, permission: str) -> Path:
    """A catalog whose single provider *declares* ``permission``.

    Declaring one is what makes the sandbox refusal reachable at all: every
    non-empty declared permission set carries at least one
    ``DECLARED_NOT_APPLIED`` mechanism, so a catalog declaring nothing is admitted
    by both the old and the current default and cannot tell them apart.
    """
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog, "tests.unit.test_cli_extend:TestRuntime")
    payload = json.loads(catalog.read_text(encoding="utf-8"))
    payload["providers"][0]["metadata"]["permissions"] = [permission]
    catalog.write_text(json.dumps(payload), encoding="utf-8")
    return catalog


def test_provider_load_accepts_declared_permission(tmp_path: Path) -> None:
    """The opt-out exists, so a permission-declaring provider is loadable at all.

    ``--allow-unsandboxed`` is stated here as a precondition rather than assumed,
    because without it this provider is refused on
    ``provider_sandbox_mechanism_unapplied`` — which is the correct behaviour and
    is what
    :func:`test_a_permission_declaring_provider_is_refused_without_the_opt_out`
    pins. This test is the half that says the refusal has an escape hatch, so it
    would be testing nothing at all without the flag in the argument list.

    Both flags are required and they are not interchangeable: ``--allow-permission``
    grants the declared permission, ``--allow-unsandboxed`` gives up the
    mechanism. Neither implies the other.
    """
    catalog = _permission_catalog(tmp_path, "target:read")
    runner = CliRunner()

    result = runner.invoke(
        providers,
        [
            "load",
            "--catalog",
            str(catalog),
            "--allow-permission",
            "target:read",
            "--allow-unsandboxed",
            "--json",
        ],
        standalone_mode=False,
    )

    assert result.exit_code == 0
    assert json.loads(result.output)["loaded"] == ["test.provider"]


def test_a_permission_declaring_provider_is_refused_without_the_opt_out(tmp_path: Path) -> None:
    """The negative control, and the more important half of the pair.

    Adding an opt-out to a fail-closed default is only safe if the default still
    holds, and "still holds" is a claim that has to be tested on every edit rather
    than inferred from the flag default. This invokes the *same* catalog as
    :func:`test_provider_load_accepts_declared_permission` — same provider, same
    declared permission, same granted permission — and differs in exactly one
    thing: the opt-out is absent. So the only variable is the flag, and the
    refusal that appears cannot be attributed to anything else.

    The refusal names the code rather than a message fragment, because the message
    is prose and the code is the contract. ``provider_sandbox_mechanism_unapplied``
    is what an operator greps for in a pipeline, so it is what this pins.
    """
    catalog = _permission_catalog(tmp_path, "target:read")
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
    assert "provider_sandbox_mechanism_unapplied" in result.output, result.output
    # No report at all, rather than a report listing the provider as unloaded.
    # ``--json`` asks for machine-readable output; emitting a well-formed
    # ``{"loaded": [...]}`` document on the refusal path would give a pipeline
    # something to parse and then quietly treat as a partial success.
    assert not result.output.strip().startswith("{"), result.output


def test_the_opt_out_does_not_grant_the_declared_permission(tmp_path: Path) -> None:
    """``--allow-unsandboxed`` removes one refusal, not all of them.

    The permission check and the sandbox check are separate, and the escape hatch
    is for the second. A provider declaring ``target:mutate`` is still refused
    when ``target:mutate`` was never granted, even with the flag set — otherwise
    "unsandboxed" would quietly become "unpermissioned" too, and the flag's help
    text would be a lie about its own reach.
    """
    catalog = _permission_catalog(tmp_path, "target:mutate")
    runner = CliRunner()

    result = runner.invoke(
        providers,
        [
            "load",
            "--catalog",
            str(catalog),
            "--allow-permission",
            "target:read",
            "--allow-unsandboxed",
            "--json",
        ],
        standalone_mode=False,
    )

    assert result.exit_code != 0
    assert "target:mutate" in result.output, result.output
    assert "provider_sandbox_mechanism_unapplied" not in result.output, result.output


def test_the_opt_out_states_plainly_that_it_disables_sandbox_enforcement() -> None:
    """The help has to say what the flag costs, in the help itself.

    An opt-out whose help text reads "allow unsandboxed providers" and stops there
    is a flag nobody informed will type, because the reader cannot tell from it
    whether mayhem confines the provider some other way or not at all. This pins
    the two halves of that answer — that enforcement is *disabled*, and that this
    build has no confinement mechanism to fall back to — on both verbs, since
    ``inspect`` and ``load`` share the option and a reader who checks one should
    not find the other silent about it.
    """
    for verb in ("inspect", "load"):
        result = CliRunner().invoke(providers, [verb, "--help"], standalone_mode=False)
        assert result.exit_code == 0
        help_text = re.sub(r"\s+", " ", result.output)
        assert "--allow-unsandboxed" in help_text, help_text
        assert "DISABLED" in help_text, help_text
        assert "provider_sandbox_mechanism_unapplied" in help_text, help_text
        assert "seccomp" in help_text, help_text


def test_provider_help_is_available() -> None:
    result = CliRunner().invoke(providers, ["--help"], standalone_mode=False)

    assert result.exit_code == 0
    assert "inspect" in result.output
    assert "load" in result.output


def test_ordinary_builtin_command_does_not_load_plugins(monkeypatch: Any, capsys: Any) -> None:
    from mayhem.providers import loader

    def fail_import(_: str) -> object:
        raise AssertionError("plugin import attempted")

    monkeypatch.setattr(loader, "import_module", fail_import)

    assert main(["commands", "show"]) == 0
    assert "commands" in capsys.readouterr().out


class TestRuntime:
    pass
