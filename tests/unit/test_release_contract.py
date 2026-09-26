"""v0.9.0 release truth baseline.

Phase 0 of the v0.9.0 roadmap turns the release documentation into a checked
artifact instead of prose that can drift. Every assertion here compares a
checked-in document or automation file against the executable source of truth:

* the CLI reference inventory against
  :data:`mayhem.cli.command_registry.COMMAND_SPECS`;
* the README command table against the same registry;
* every ``mayhem …`` command reference in the current documents against the live
  Click command tree, so a retired root command cannot survive in prose;
* the Justfile recipes against the same Click tree, options included;
* the Kubernetes fault-catalog snapshot against
  :data:`mayhem.domain.catalog.CATALOG` and the runtime dispatch register;
* the output-schema reference against the emitted envelope version;
* the changelog's structural integrity and release-history floor;
* packaging metadata in ``pyproject.toml`` (distribution name, console command,
  default runtime dependencies, version fallback) and the release line.

Nothing here reaches a runtime: the CLI tree is walked in-process and the
catalog is a pure domain module.

Supported validation boundary
-----------------------------
``_resolve_invocation`` walks argv down the Click tree using the option
definitions the command itself declares, so option arity is never duplicated
here. It validates:

* every command token, by exact name or by the unique prefix the CLI supports;
* every option token, against the options declared on the node that consumes it
  (a parent group cannot take an option that belongs to a sub-command, and a
  sub-command cannot take a global option that was declared on the root);
* the *minimum* number of positional arguments a leaf command requires.

It deliberately does **not** validate:

* anything after a shell operator (``|``, ``&&``, ``;``, ``>``, …) — that is the
  shell's argv, not the CLI's;
* option *values* (a value that happens to look like a flag is not diagnosed);
* the exact number of positional arguments supplied to a command, because
  variadic arguments (``recover execute RUN_IDS…``) make an upper bound
  ambiguous;
* ``--help``/eager-option behaviour, or whether an option is legal in the
  position it appears in.
"""

from __future__ import annotations

import json
import re
import shlex
import tomllib
from pathlib import Path
from typing import TYPE_CHECKING

import click

from mayhem.cli.app import app
from mayhem.cli.command_registry import COMMAND_SPECS
from mayhem.cli.output import OUTPUT_SCHEMA_VERSION
from mayhem.controller.k8s_runtime import k8s_available_faults
from mayhem.domain.catalog import CATALOG
from mayhem.providers.builtin import create_builtin_registry

if TYPE_CHECKING:
    from collections.abc import Iterator

ROOT = Path(__file__).parents[2]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
RELEASE_LINE = "0.9.0"

#: Oldest released version the checked-in changelog must still describe. Bump
#: this floor when a release is tagged so a regeneration that silently drops
#: published history fails the suite.
CHANGELOG_HISTORY_FLOOR = (0, 8, 0)

K8S_CATALOG = {d.id: d for d in CATALOG if d.id.startswith("k8s.")}
K8S_EXECUTABLE = k8s_available_faults()

#: Documents that make current-surface claims, and therefore must not invoke a
#: command that no longer exists. The classification comes from
#: ``docs/README.md``: user guide, current references, current product/architecture
#: contracts, and the executable design rules. Dated audits and discovery
#: reports (``k8s-*.md``, ``m7-*.md``), ADRs, and forward
#: plans (``new-plan/``, ``superpowers/``) are excluded on purpose:
#: they record what was true when written, and rewriting them would falsify that
#: record.
CURRENT_DOCS: tuple[str, ...] = (
    "README.md",
    "docs/architecture/*.md",
    "docs/compensation.md",
    "docs/config.md",
    "docs/drill-spec.md",
    "docs/fault-catalog/*.md",
    "docs/policy-and-break-glass.md",
    "docs/product/*.md",
    "docs/provider-sdk.md",
    "docs/reference/*.md",
    "examples/*/README.md",
)

#: Tokens that end a `mayhem …` invocation: the rest of the line is shell.
SHELL_OPERATORS = frozenset({"|", "||", "&&", ";", ">", ">>", "<", "2>", "&"})
SHELL_OPERATOR_PREFIXES = ("|", ">", "<", "&", ";")

#: A fenced block or an inline code span. Fenced blocks are matched too, because
#: a ``` fence is itself a run of backticks.
CODE_SPAN_RE = re.compile(r"`+[^`]+`+", re.DOTALL)
#: Leading fence language, e.g. the `bash` of ```bash.
FENCE_LANGUAGE_RE = re.compile(r"^[A-Za-z0-9_+-]+$")
CHANGELOG_SECTION_RE = re.compile(
    r"^## \[?(?P<label>[^\]\s]+)\]?(?: - (?P<date>\d{4}-\d{2}-\d{2}))?\s*$", re.MULTILINE
)


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


def _option_arity(command: click.Command, token: str) -> int | None:
    """Return how many argv entries the option consumes, or None if unknown.

    The arity is read from the Click parameter itself, so the CLI's option
    definitions stay the single source of truth.
    """
    for param in command.params:
        if not isinstance(param, click.Option):
            continue
        if token in param.opts or token in param.secondary_opts:
            return 0 if param.is_flag else max(int(param.nargs), 1)
    return None


def _is_shell_operator(token: str) -> bool:
    return token in SHELL_OPERATORS or token.startswith(SHELL_OPERATOR_PREFIXES)


def _required_argument_count(command: click.Command) -> int:
    """Minimum positional arguments the command needs (variadic counts as one)."""
    arguments = [p for p in command.params if isinstance(p, click.Argument)]
    return sum(1 for p in arguments if p.required)


def _validate_leaf(command: click.Command, tokens: list[str]) -> list[str]:
    """Validate the options and minimum arity of a resolved leaf command."""
    problems: list[str] = []
    positional = 0
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if _is_shell_operator(token):
            break
        if token.startswith("-") and token != "-":
            arity = _option_arity(command, token)
            if arity is None:
                problems.append(f"unknown option `{token}` for `mayhem {command.name}`")
                index += 1
                continue
            index += 1 + arity
            continue
        positional += 1
        index += 1
    required = _required_argument_count(command)
    if positional < required:
        problems.append(f"`mayhem {command.name}` needs {required} argument(s), {positional} given")
    return problems


def _resolve_invocation(tokens: list[str]) -> list[str]:
    """Walk argv down the live Click tree, returning any contract violations.

    ``tokens`` is the argv that follows the word ``mayhem``. The walk stops at
    the first shell operator, because the remainder of the line is the shell's
    argv rather than the CLI's.
    """
    problems: list[str] = []
    node: click.Command = app
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if _is_shell_operator(token):
            return problems
        arity = _option_arity(node, token)
        if arity is not None:
            index += 1 + arity
            continue
        if isinstance(node, click.Group):
            resolved = _resolve(token, set(node.commands))
            if resolved is None:
                kind = "option" if token.startswith("-") else "command"
                return [f"no {kind} `{token}` under `mayhem {node.name}`"]
            node = node.commands[resolved]
            index += 1
            continue
        return _validate_leaf(node, tokens[index:])
    return problems


def _current_doc_paths() -> list[Path]:
    """Expand :data:`CURRENT_DOCS`; the globs are part of the checked contract."""
    paths: list[Path] = []
    for pattern in CURRENT_DOCS:
        matches = sorted(ROOT.glob(pattern))
        assert matches, f"current-doc pattern matches nothing: {pattern}"
        paths.extend(matches)
    return paths


def _iter_doc_invocations(text: str) -> Iterator[tuple[int, list[str]]]:
    """Yield ``(line, argv)`` for every `mayhem …` reference in a document.

    Only fenced code blocks and inline/fenced code spans are considered, and
    inside them only segments that *begin* with the word ``mayhem``. Prose such
    as "mayhem resolves live pods" is therefore never read as a command.
    """
    for match in CODE_SPAN_RE.finditer(text):
        lineno = text.count("\n", 0, match.start()) + 1
        body = match.group(0).strip("`~")
        lines = body.splitlines()
        # Drop a leading fence language such as `bash`.
        if lines and FENCE_LANGUAGE_RE.match(lines[0].strip()) and len(lines) > 1:
            lines = lines[1:]
        for line in lines:
            for segment in re.split(r"\|\||&&|\||;", line):
                try:
                    words = shlex.split(segment.strip(), comments=True)
                except ValueError:  # pragma: no cover - unbalanced quoting
                    continue
                if words and words[0] == "mayhem":
                    yield lineno, words[1:]


# --- command inventory -----------------------------------------------------


    executable = {
        (spec.name, spec.workflow, spec.help_group, spec.mutating) for spec in COMMAND_SPECS
    }
    assert documented == executable, (
        "docs/reference/cli.md command inventory drifted from the command registry. "
        f"missing={sorted(executable - documented)} extra={sorted(documented - executable)}"
    )


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
    """Every `mayhem` invocation in the Justfile must resolve on the active surface.

    Command paths, option names, and required argument counts are all checked;
    see the module docstring for the exact validation boundary.
    """
    text = (ROOT / "Justfile").read_text(encoding="utf-8")
    # Collapse `{{ _var }}` substitutions so they tokenize as a single word.
    text = re.sub(r"\{\{[^}]*\}\}", "_TEMPLATE_", text)

    problems: list[str] = []
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
        problems.extend(
            f"Justfile:{lineno}: mayhem {' '.join(args)}\n    {problem}"
            for problem in _resolve_invocation(args)
        )
    assert not problems, "Justfile recipes drifted from the active CLI surface:\n" + "\n".join(
        problems
    )


def _first_command_token(tokens: list[str]) -> str | None:
    """Return the first argv entry that was meant to be a command, or None.

    Options and their values are skipped, sub-commands are descended into, and
    the walk stops at a leaf command — its remaining tokens are arguments, not
    command names. A token is only reported when it was offered to a group and
    that group had no such command.
    """
    node: click.Command = app
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if _is_shell_operator(token):
            return None
        arity = _option_arity(node, token)
        if arity is not None:
            index += 1 + arity
            continue
        if not isinstance(node, click.Group):
            return None
        resolved = _resolve(token, set(node.commands))
        if resolved is None:
            return token
        node = node.commands[resolved]
        index += 1
    return None


#: A command name in a document is a bare lowercase word. Anything else — a
#: metavariable (`RUN_ID`, `<id>`), a synopsis placeholder (`[ROOT OPTION]...`),
#: or an ellipsis — is a usage sketch, not an invocable command, so the
#: retired-root-command contract does not apply to it.
COMMAND_NAME_RE = re.compile(r"^[a-z][a-z-]*$")

#: Liveness floor for the document extractor, so that a broken extractor cannot
#: make the retired-root-command contract vacuously true.
MIN_SCANNED_INVOCATIONS = 20


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


def _changelog_sections(text: str) -> list[tuple[str, str | None, str]]:
    """Parse ``(label, date, body)`` for every ``## `` section of the changelog."""
    sections: list[tuple[str, str | None, str]] = []
    matches = list(CHANGELOG_SECTION_RE.finditer(text))
    for position, match in enumerate(matches):
        end = matches[position + 1].start() if position + 1 < len(matches) else len(text)
        sections.append((match.group(1), match.group(2), text[match.end() : end]))
    return sections


def test_changelog_is_structurally_valid_and_keeps_release_history() -> None:
    """Validate the changelog without depending on the unreleased/tagged state.

    A tag-time release run legitimately has no ``[unreleased]`` bullets (or no
    ``[unreleased]`` section at all), so the contract is structural: the
    generated header is intact, every section is well formed, released versions
    descend, published history is never lost, and no published release is empty.
    """
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert text.startswith("# Changelog"), "the generated changelog header is missing"
    assert text.rstrip().endswith("<!-- generated by git-cliff -->"), (
        "CHANGELOG.md is no longer the git-cliff output; regenerate it with `just changelog`"
    )

    sections = _changelog_sections(text)
    assert sections, "CHANGELOG.md has no version sections"

    released: list[tuple[int, ...]] = []
    for label, date, body in sections:
        if label == "unreleased":
            # The unreleased section is the only one allowed to be empty: a
            # release run with no commits since the last tag renders it blank.
            continue
        assert date is not None, f"released section `{label}` has no release date"
        version = tuple(int(part) for part in label.split("."))
        assert len(version) == 3, f"unexpected version heading: {label}"
        assert re.search(r"^- \S", body, re.MULTILINE), (
            f"published release {label} has no entries — history was truncated"
        )
        released.append(version)

    assert released, "CHANGELOG.md describes no released version"
    descending = sorted(released, reverse=True)
    assert released == descending, (
        "released sections are not in descending order: "
        f"{['.'.join(map(str, v)) for v in released]}"
    )
    assert released[0] >= CHANGELOG_HISTORY_FLOOR, (
        f"newest documented release {'.'.join(map(str, released[0]))} is behind the "
        f"history floor {'.'.join(map(str, CHANGELOG_HISTORY_FLOOR))}; "
        "regenerating the changelog dropped published history"
    )
    assert len(set(released)) == len(released), "a released version appears twice"
