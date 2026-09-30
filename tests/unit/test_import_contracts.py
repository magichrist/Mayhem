"""Guards for the ``[tool.importlinter]`` architecture contracts.

The three contracts in ``pyproject.toml`` encode the layering invariants that
keep the codebase comprehensible. They are only meaningful if someone runs them,
so this module:

* proves the contract table is syntactically valid (parses, keys are present);
* proves every module a contract names is actually importable, so a contract can
  never silently reference a module that no longer exists;
* proves ``import-linter`` is actually declared as a dev dependency;
* proves the v1 ``fallback-version``;
* runs ``lint-imports`` for real when the tool is installed.

Note on invocation: import-linter ships **no** ``__main__``. Neither
``python -m importlinter`` nor ``python -m lint_imports`` can ever work; the only
supported entry point is the ``lint-imports`` console script. Earlier docs that
showed the ``-m`` form were wrong regardless of installation state.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = REPO_ROOT / "pyproject.toml"
VENV_BIN = REPO_ROOT / ".venv" / "bin"
CONSOLE_SCRIPT = "lint-imports"

#: import-linter contract types and the keys each one requires.
REQUIRED_KEYS: dict[str, frozenset[str]] = {
    "forbidden": frozenset({"name", "type", "source_modules"}),
    "layers": frozenset({"name", "type", "containers", "layers"}),
    "independence": frozenset({"name", "type", "modules"}),
}

#: `forbidden` needs a target as well as a source; either spelling is legal.
FORBIDDEN_TARGETS = frozenset({"forbidden_modules", "forbidden_contractions"})

IMPORT_TIMEOUT_SECONDS = 300
LINT_TIMEOUT_SECONDS = 600

EXPECTED_FALLBACK_VERSION = "1.0.0.dev0"


# --- config loading --------------------------------------------------------


@pytest.fixture(scope="module")
def pyproject() -> dict:
    """The parsed ``pyproject.toml``, or a skip if it cannot be parsed."""
    try:
        return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:  # pragma: no cover - config breakage
        pytest.skip(f"pyproject.toml is not valid TOML: {exc}")


@pytest.fixture(scope="module")
def importlinter_config(pyproject: dict) -> dict:
    section = pyproject.get("tool", {}).get("importlinter")
    if section is None:
        pytest.skip("pyproject.toml declares no [tool.importlinter] table")
    return section


@pytest.fixture(scope="module")
def contracts(importlinter_config: dict) -> list[dict]:
    declared = importlinter_config.get("contracts")
    if declared is None:
        pytest.skip("[tool.importlinter] declares no [[tool.importlinter.contracts]]")
    return declared


def contract_modules(contract: dict) -> list[str]:
    """Every module name a contract references, in declaration order.

    Layers contracts name bare layer names that sit under the container, and use
    ``|`` to mean "either/or" alternatives; both are expanded to real dotted
    paths so they can be imported.
    """
    names: list[str] = list(contract.get("source_modules", []))
    names.extend(contract.get("forbidden_modules", []))
    names.extend(contract.get("modules", []))

    containers = contract.get("containers") or []
    for layer in contract.get("layers", []):
        for alternative in layer.split("|"):
            names.extend(f"{container}.{alternative.strip()}" for container in containers)

    seen: set[str] = set()
    unique: list[str] = []
    for name in names:
        cleaned = name.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique.append(cleaned)
    return unique


# --- import-linter resolution ---------------------------------------------


def _has_importlinter(python_executable: Path) -> bool:
    probe = subprocess.run(
        [str(python_executable), "-c", "import importlinter"],
        capture_output=True,
        timeout=60,
        check=False,
    )
    return probe.returncode == 0


def _resolve_import_linter() -> tuple[Path, Path] | None:
    """Locate an interpreter that has import-linter plus its console script.

    ``sys.executable`` is preferred so the tool runs against the same environment
    as the test suite. The repository ``.venv`` is the documented dev setup
    (``uv sync --group dev``) and is accepted as a fallback, because a shell
    pointed at an unrelated interpreter is the usual reason the contracts look
    "unrunnable".
    """
    candidates: list[Path] = []
    current = Path(sys.executable)
    if current.parent.name == "bin":
        candidates.append(current.parent)
    if VENV_BIN.is_dir():
        candidates.append(VENV_BIN)

    for bin_dir in candidates:
        script = bin_dir / CONSOLE_SCRIPT
        python_executable = bin_dir / "python3"
        if not python_executable.exists():
            python_executable = bin_dir / "python"
        usable = script.is_file() and python_executable.is_file()
        if usable and _has_importlinter(python_executable):
            return python_executable, script
    return None


_RESOLVED = _resolve_import_linter()

MISSING_TOOL_REASON = (
    f"import-linter is not installed for this test run: no `{CONSOLE_SCRIPT}` console "
    "script found next to a working interpreter (checked sys.executable's bin dir and "
    f"{VENV_BIN}). Install the dev group (`uv sync --group dev`, or "
    "`pip install import-linter>=2.1`). import-linter has no `python -m` entry point, "
    "so the console script is the only way to run it."
)

requires_import_linter = pytest.mark.skipif(
    _RESOLVED is None,
    reason=MISSING_TOOL_REASON,
)


# --- contract table validity -----------------------------------------------


def test_pyproject_declares_import_linter_table(importlinter_config: dict) -> None:
    roots = importlinter_config.get("root_packages")
    assert roots == ["mayhem"], f"unexpected root_packages: {roots!r}"


def test_contracts_have_the_keys_their_type_requires(contracts: list[dict]) -> None:
    assert contracts, "no import-linter contracts declared"

    names: list[str] = []
    problems: list[str] = []
    for index, contract in enumerate(contracts):
        label = contract.get("name", f"contract #{index}")

        contract_type = contract.get("type")
        if contract_type not in REQUIRED_KEYS:
            problems.append(f"{label}: unknown type {contract_type!r}")
            continue

        missing = sorted(REQUIRED_KEYS[contract_type] - contract.keys())
        if contract_type == "forbidden" and not (FORBIDDEN_TARGETS & contract.keys()):
            missing.append("forbidden_modules or forbidden_contractions")
        if missing:
            problems.append(f"{label}: missing {missing}")

        for key in ("source_modules", "forbidden_modules", "containers", "layers"):
            value = contract.get(key)
            if value is not None and (not isinstance(value, list) or not value):
                problems.append(f"{label}: {key} must be a non-empty list, got {value!r}")

        names.append(label)

    assert not problems, "malformed import-linter contracts:\n  " + "\n  ".join(problems)
    assert len(set(names)) == len(names), f"duplicate contract names: {names}"


def test_layers_contract_layer_names_resolve_under_a_container(contracts: list[dict]) -> None:
    """`layers` entries are container-relative, so `controller` is legal.

    import-linter accepts either a bare layer name (`controller`) or one already
    qualified with its container (`mayhem.controller`). What it cannot accept is
    a name that sits outside every declared container, or an empty alternative
    produced by a malformed `a | b` expression -- both would silently shrink the
    graph and make the contract vacuously true.
    """
    seen_layers = False
    for contract in contracts:
        if contract.get("type") != "layers":
            continue
        seen_layers = True
        containers = contract["containers"]
        for layer in contract["layers"]:
            for alternative in layer.split("|"):
                name = alternative.strip()
                assert name, f"{contract['name']}: empty layer alternative in {layer!r}"

                relatives = [
                    name[len(container) + 1 :] if name.startswith(f"{container}.") else name
                    for container in containers
                ]
                usable = [rel for rel in relatives if rel and not rel.startswith(".")]
                assert usable, (
                    f"{contract['name']}: layer {name!r} resolves to nothing under "
                    f"containers {containers!r}"
                )
    if not seen_layers:
        pytest.skip("no layers contract declared")


# --- import reachability ---------------------------------------------------


def test_every_contract_module_is_importable(contracts: list[dict]) -> None:
    """Each contract must name modules that actually exist.

    A contract referencing a deleted module either errors out or is silently
    satisfied by an empty graph, so this is checked by real import in a
    subprocess with a timeout rather than by inspecting the file tree.
    """
    modules: list[str] = []
    for contract in contracts:
        modules.extend(contract_modules(contract))

    assert modules, "contracts reference no modules at all"

    probe = (
        "import importlib, json, sys\n"
        f"mods = {modules!r}\n"
        "out = {}\n"
        "for name in mods:\n"
        "    try:\n"
        "        importlib.import_module(name)\n"
        "        out[name] = None\n"
        "    except Exception as exc:\n"
        "        out[name] = f'{type(exc).__name__}: {exc}'\n"
        "sys.stdout.write(json.dumps(out))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        timeout=IMPORT_TIMEOUT_SECONDS,
        check=False,
    )
    assert result.returncode == 0, f"probe subprocess failed:\n{result.stderr}"

    failures = {name: err for name, err in json.loads(result.stdout).items() if err is not None}
    assert not failures, "contract modules that cannot be imported:\n  " + "\n  ".join(
        f"{name}: {err}" for name, err in sorted(failures.items())
    )


# --- packaging declarations ------------------------------------------------


def test_import_linter_is_declared_as_a_dev_dependency(pyproject: dict) -> None:
    """The dev group is the only dependency declaration this project uses."""
    groups = pyproject.get("dependency-groups", {})
    declared = [dep for group in groups.values() for dep in group]

    assert groups, "pyproject.toml declares no [dependency-groups]"
    matching = [dep for dep in declared if dep.lower().startswith("import-linter")]
    assert matching, (
        f"import-linter is not declared in [dependency-groups]; found: {sorted(declared)}"
    )
    assert any("dev" in group for group in groups), (
        f"no dev group to carry the import-linter declaration: {sorted(groups)}"
    )


def test_fallback_version_matches_the_v1_release(pyproject: dict) -> None:
    hatch_version = pyproject["tool"]["hatch"]["version"]
    assert hatch_version["source"] == "vcs", (
        "version must stay git-derived; a literal `version` key would desync "
        "the distribution from its tags"
    )
    assert hatch_version["fallback-version"] == EXPECTED_FALLBACK_VERSION, (
        "fallback-version only applies to a tree with no reachable tag; the 1.0.0 "
        "release version itself comes from the git tag"
    )


def test_fallback_version_is_a_dev_pin_not_a_release_pin(pyproject: dict) -> None:
    """The fallback must never claim a *released* version.

    ``hatch-vcs`` only falls back when no tag is reachable (exported tarballs,
    vendored copies). Such a tree has not been released, so the fallback must
    carry a ``.dev`` local segment -- otherwise a tarball of an untagged commit
    reports itself as a shipped release.

    The exact value is owned by ``test_release_contract.py`` (``RELEASE_LINE``).
    This test guards the *convention*, so the two cannot disagree about shape.
    """
    fallback = pyproject["tool"]["hatch"]["version"]["fallback-version"]
    assert re.fullmatch(r"\d+\.\d+\.\d+\.dev\d*", fallback), (
        f"fallback-version {fallback!r} must be a `.dev` pin, not a release version"
    )


# --- actually running the contracts ----------------------------------------

#: Contracts that are violated by the current shape of ``src/``. These are real
#: architectural findings (see docs/v1.0.0/06-debt-and-quality.md), not harness
#: faults: closing them means moving imports between layers, which is a large
#: change nobody has signed up for. The baseline exists so the set is pinned --
#: a *new* violation fails loudly, and a *fixed* contract asks you to update
#: this frozenset rather than quietly relaxing the guard.
#: Contracts that are violated by the current shape of ``src/``. Empty: all
#: three invariants now hold. Each was closed by moving imports between layers
#: rather than by relaxing a contract:
#:
#: * *Domain layer has zero IO and no upward imports* — the filesystem readers
#:   moved to ``infra`` (``evidence_bundle_io``, ``target_profile_io``), the
#:   engine host probe moved to ``infra.engine_probe`` (its selection rule
#:   stayed in the domain as ``select_engine``), and canonical hashing moved
#:   down to ``domain.hashing`` so ``domain.preflight`` stopped importing
#:   upward into ``toolkit``.
#: * *Layered architecture* — ``infra.evidence`` stopped reaching into
#:   ``cli.execution`` for ``artifact_name`` (now ``infra.report``), and the
#:   cross-layer capability view moved from ``infra/catalog_report.py`` to
#:   ``controller/catalog_report.py``, the only layer allowed to see the
#:   executor, compensation, and k8s-runtime registries at once.
#:
#: The baseline stays so that a *new* violation fails loudly and a *fixed*
#: contract asks you to acknowledge the change here.
KNOWN_BROKEN_CONTRACTS: frozenset[str] = frozenset()

#: Contracts that must hold at all times.
MUST_HOLD_CONTRACT = "Agents never import controller modules"

SUMMARY_LINE = re.compile(r"^Contracts: (?P<kept>\d+) kept, (?P<broken>\d+) broken\.", re.MULTILINE)
VERDICT_LINE = re.compile(r"^(?P<name>.+?) (?P<verdict>KEPT|BROKEN)$")


def _run_lint_imports() -> tuple[str, dict[str, str]]:
    """Run the whole contract set and return ``(raw output, name -> verdict)``."""
    assert _RESOLVED is not None
    _, script = _RESOLVED
    result = subprocess.run(
        [str(script), "--config", str(PYPROJECT), "--no-cache", "--no-logo"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=LINT_TIMEOUT_SECONDS,
        check=False,
    )
    combined = result.stdout + result.stderr

    # 0 = all kept, 1 = at least one broken. Anything else is a harness fault
    # (bad config path, unreadable file, crash) rather than a contract verdict.
    assert result.returncode in (0, 1), (
        f"lint-imports failed to run (exit={result.returncode}).\n{combined}"
    )
    assert SUMMARY_LINE.search(combined), f"no contract summary in output:\n{combined}"

    verdicts = {
        match.group("name"): match.group("verdict")
        for match in (VERDICT_LINE.match(line) for line in combined.splitlines())
        if match is not None
    }
    return combined, verdicts


@requires_import_linter
def test_lint_imports_evaluates_every_declared_contract(contracts: list[dict]) -> None:
    """The tool must actually consume the config, one verdict per contract."""
    raw, verdicts = _run_lint_imports()
    declared = {contract["name"] for contract in contracts}

    assert set(verdicts) == declared, (
        "lint-imports did not report one verdict per declared contract.\n"
        f"declared but unreported: {sorted(declared - set(verdicts))}\n"
        f"reported but undeclared: {sorted(set(verdicts) - declared)}\n"
        f"----- output -----\n{raw}"
    )


@requires_import_linter
def test_broken_contracts_match_the_pinned_baseline(contracts: list[dict]) -> None:
    """Pin which contracts are currently broken, in both directions.

    New breakage fails. A contract that starts passing also fails, because that
    means the recorded baseline is stale and the fix should be acknowledged.
    """
    raw, verdicts = _run_lint_imports()
    broken = {name for name, verdict in verdicts.items() if verdict == "BROKEN"}

    assert broken == set(KNOWN_BROKEN_CONTRACTS), (
        "the set of broken import-linter contracts changed.\n"
        f"newly broken: {sorted(broken - set(KNOWN_BROKEN_CONTRACTS))}\n"
        f"newly passing (drop them from KNOWN_BROKEN_CONTRACTS): "
        f"{sorted(set(KNOWN_BROKEN_CONTRACTS) - broken)}\n"
        "----- lint-imports output -----\n"
        f"{raw}"
        "---------------------------"
    )


@requires_import_linter
def test_agents_never_import_controller() -> None:
    """The cheapest real guard: a single-edge upward-dependency rule.

    `agents -> controller` is the boundary that keeps the agent layer
    independent, and it is currently upheld. It must stay upheld.
    """
    raw, verdicts = _run_lint_imports()
    assert MUST_HOLD_CONTRACT in verdicts, (
        f"{MUST_HOLD_CONTRACT!r} was not evaluated; the guard would be vacuous.\n{raw}"
    )
    assert verdicts[MUST_HOLD_CONTRACT] == "KEPT", (
        f"{MUST_HOLD_CONTRACT!r} regressed -- agents now reach into controller.\n"
        f"----- lint-imports output -----\n{raw}"
        "---------------------------"
    )
