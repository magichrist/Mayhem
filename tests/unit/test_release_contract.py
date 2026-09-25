"""v0.9.0 release truth baseline.

Phase 0 of the v0.9.0 roadmap turns the release documentation into a checked
artifact instead of prose that can drift. Every assertion here compares a
checked-in document or automation file against the executable source of truth:

* the CLI reference inventory against
  :data:`mayhem.cli.command_registry.COMMAND_SPECS`;
* the Justfile recipes against the live Click command tree;
* the README command table against the same registry;
* the Kubernetes fault-catalog snapshot against
  :data:`mayhem.domain.catalog.CATALOG` and the runtime dispatch register;
* the output-schema reference against the emitted envelope version;
* packaging metadata in ``pyproject.toml`` (distribution name, console command,
  default runtime dependencies, version fallback) and the release line.

Nothing here reaches a runtime: the CLI tree is walked in-process and the
catalog is a pure domain module.
"""

from __future__ import annotations

import re
import shlex
import tomllib
from pathlib import Path

import click

from mayhem.cli.app import app
from mayhem.cli.command_registry import COMMAND_SPECS
from mayhem.cli.output import OUTPUT_SCHEMA_VERSION
from mayhem.controller.k8s_runtime import k8s_available_faults
from mayhem.domain.catalog import CATALOG
from mayhem.providers.builtin import create_builtin_registry

ROOT = Path(__file__).parents[2]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
RELEASE_LINE = "0.9.0"

K8S_CATALOG = {d.id: d for d in CATALOG if d.id.startswith("k8s.")}
K8S_EXECUTABLE = k8s_available_faults()


# --- helpers ---------------------------------------------------------------


def _section(text: str, heading: str) -> str:
    """Return the body of a level-2 Markdown section."""
    pattern = re.compile(
        rf"^## {re.escape(heading)}\s*$(?P<body>.*?)(?=^## |\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(text)
    assert match is not None, f"section not found: {heading}"
    return match.group("body")


def _requirement_names(requirements: list[str]) -> set[str]:
    names = set()
    for requirement in requirements:
        name = re.split(r"[<>=!~\[; ]", requirement, maxsplit=1)[0]
        if name:
            names.add(name.lower())
    return names


def _resolve(token: str, names: set[str]) -> str | None:
    """Resolve a command token by exact match or unique prefix."""
    if token in names:
        return token
    matches = sorted(name for name in names if name.startswith(token))
    return matches[0] if len(matches) == 1 else None


# --- command inventory -----------------------------------------------------


def test_cli_reference_inventory_matches_command_registry() -> None:
    body = _section(
        (ROOT / "docs/reference/cli.md").read_text(encoding="utf-8"),
        "Command inventory",
    )
    row = re.compile(
        r"^\|\s*`(?P<name>[a-z][a-z-]*)`\s*\|\s*`(?P<workflow>[a-z]+)`\s*"
        r"\|\s*(?P<group>[a-z]+)\s*\|\s*(?P<mutating>yes|no)\s*\|$",
        re.MULTILINE,
    )
    documented = {
        (m["name"], m["workflow"], m["group"], m["mutating"] == "yes") for m in row.finditer(body)
    }
    executable = {
        (spec.name, spec.workflow, spec.help_group, spec.mutating) for spec in COMMAND_SPECS
    }
    assert documented == executable, (
        "docs/reference/cli.md command inventory drifted from the command registry. "
        f"missing={sorted(executable - documented)} extra={sorted(documented - executable)}"
    )


def test_cli_reference_documents_every_active_command() -> None:
    text = (ROOT / "docs/reference/cli.md").read_text(encoding="utf-8")
    documented = set(re.findall(r"mayhem[\s`]+([a-z][a-z-]*)", text))
    active = {spec.name for spec in COMMAND_SPECS}
    assert active <= documented, sorted(active - documented)


def test_readme_command_table_matches_command_registry() -> None:
    body = _section((ROOT / "README.md").read_text(encoding="utf-8"), "CLI surface")
    documented = set(re.findall(r"mayhem[\s`]+([a-z][a-z-]*)", body))
    active = {spec.name for spec in COMMAND_SPECS}
    assert documented == active, (
        "README command table drifted from the command registry. "
        f"missing={sorted(active - documented)} extra={sorted(documented - active)}"
    )


def test_justfile_recipes_resolve_against_the_cli_tree() -> None:
    """Every `mayhem` invocation in the Justfile must resolve on the active surface."""
    global_value_options = {"--db", "--config", "--profile", "--policy", "--target", "--format"}
    global_flags = {
        "--dry-run",
        "--allow-critical",
        "--skip-gate",
        "--podman",
        "-p",
        "--kubernetes",
        "-k",
        "--debug",
        "-d",
        "--no-color",
    }
    text = (ROOT / "Justfile").read_text(encoding="utf-8")
    # Collapse `{{ _var }}` substitutions so they tokenize as a single word.
    text = re.sub(r"\{\{[^}]*\}\}", "_TEMPLATE_", text)

    unresolved: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if "mayhem" not in line:
            continue
        try:
            tokens = shlex.split(line, comments=True)
        except ValueError:  # pragma: no cover - malformed shell line
            continue
        if "mayhem" not in tokens:
            continue
        args = tokens[tokens.index("mayhem") + 1 :]
        index = 0
        while index < len(args):
            token = args[index]
            if token in global_value_options:
                index += 2
                continue
            if token in global_flags:
                index += 1
                continue
            break
        invocation = "mayhem " + " ".join(args[index:])
        # Walk the live Click tree, allowing the unique prefixes the CLI supports.
        node: click.Command | None = app
        for token in args[index:]:
            assert node is not None
            if not isinstance(node, click.Group):
                break
            resolved = _resolve(token, set(node.commands))
            if resolved is None:
                unresolved.append(f"Justfile:{lineno}: {invocation} (at `{token}`)")
                break
            node = node.commands[resolved]
        else:
            assert node is not None
    assert not unresolved, "Justfile recipes reference the removed CLI surface:\n" + "\n".join(
        unresolved
    )


# --- packaging and install contract ----------------------------------------


def test_distribution_name_and_console_command_are_stable() -> None:
    project = PYPROJECT["project"]
    assert project["name"] == "mayhem-cli"
    assert project["scripts"]["mayhem"] == "mayhem.cli.app:main"


def test_default_runtime_dependencies_include_kubernetes() -> None:
    dependencies = _requirement_names(PYPROJECT["project"]["dependencies"])
    assert "kubernetes" in dependencies, sorted(dependencies)
    extras = PYPROJECT["project"].get("optional-dependencies", {})
    assert "k8s" not in extras, f"the k8s extra was removed; found extras: {sorted(extras)}"


def test_docs_contain_no_k8s_extra_install_instruction() -> None:
    install_verb = re.compile(r"\b(?:pip3?|uv|pipx|conda)\s+(?:install|add)\b")
    extras_reference = re.compile(r"mayhem(?:-cli)?\s*\[[a-z0-9,._-]+\]")
    offenders: list[str] = []
    documents = [ROOT / "README.md", *sorted(ROOT.glob("docs/**/*.md"))]
    for document in documents:
        for lineno, line in enumerate(document.read_text(encoding="utf-8").splitlines(), 1):
            if install_verb.search(line) and extras_reference.search(line):
                rel = document.relative_to(ROOT)
                offenders.append(f"{rel}:{lineno}: {line.strip()}")
    assert not offenders, (
        "kubernetes ships as a default dependency; do not document an install extra:\n"
        + "\n".join(offenders)
    )


def test_readme_install_instruction_uses_the_distribution_name() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    install_lines = [
        line
        for line in text.splitlines()
        if re.search(r"\b(?:pip3?|uv|pipx)\s+(?:install|add)\b", line)
    ]
    assert install_lines, "README documents no install instruction"
    for line in install_lines:
        assert "mayhem-cli" in line, line.strip()
        assert "mayhem[" not in line, line.strip()


# --- version metadata ------------------------------------------------------


def test_version_fallback_matches_the_release_line() -> None:
    hatch_version = PYPROJECT["tool"]["hatch"]["version"]
    assert hatch_version["source"] == "vcs"
    assert hatch_version["fallback-version"] == f"{RELEASE_LINE}.dev0"


def test_builtin_provider_version_matches_the_release_line() -> None:
    versions = {
        registration.metadata.provider_id: registration.metadata.version
        for registration in create_builtin_registry().registrations()
    }
    assert versions, "no built-in provider registrations found"
    stale = {pid: v for pid, v in versions.items() if v != RELEASE_LINE}
    assert not stale, f"built-in provider versions behind the release line: {stale}"


def test_changelog_tracks_the_unreleased_release_line() -> None:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert text.startswith("# Changelog")
    body = _section(text, "[unreleased]")
    assert re.search(r"^- \S", body, re.MULTILINE), "unreleased changelog section is empty"


# --- reference snapshots ---------------------------------------------------


def test_fault_catalog_snapshot_matches_executable_registers() -> None:
    text = (ROOT / "docs/reference/fault-catalog.md").read_text(encoding="utf-8")
    row = re.compile(
        r"^\|\s*`(?P<id>k8s\.[a-z0-9_]+)`\s*\|\s*(?P<risk>[a-z]+)\s*\|"
        r"\s*(?P<status>[^|]+?)\s*\|$",
        re.MULTILINE,
    )
    documented = {m["id"]: m["status"] for m in row.finditer(text)}
    assert documented.keys() == K8S_CATALOG.keys(), (
        "docs/reference/fault-catalog.md drifted from the catalog. "
        f"missing={sorted(K8S_CATALOG.keys() - documented.keys())} "
        f"extra={sorted(documented.keys() - K8S_CATALOG.keys())}"
    )
    drifted = {
        fault_id: status
        for fault_id, status in documented.items()
        if status.split(",")[0].strip()
        != ("catalog-only" if fault_id not in K8S_EXECUTABLE else "executable")
    }
    assert not drifted, f"fault status drifted from the dispatch register: {drifted}"


def test_output_schema_version_is_documented() -> None:
    text = (ROOT / "docs/reference/output-schema.md").read_text(encoding="utf-8")
    match = re.search(r"^Current schema version:\s*`?([0-9]+\.[0-9]+)`?\s*$", text, re.MULTILINE)
    assert match is not None, "docs/reference/output-schema.md declares no schema version"
    assert match.group(1) == OUTPUT_SCHEMA_VERSION
    schema_path = ROOT / "src/mayhem/schemas/output_v1.json"
    assert f"`{schema_path.relative_to(ROOT)}`" in text
    import json

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["properties"]["schema_version"]["const"] == OUTPUT_SCHEMA_VERSION
    assert schema["version"] == OUTPUT_SCHEMA_VERSION
