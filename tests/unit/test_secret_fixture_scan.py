"""Plan 29 Phase 5 — the fixture-secret scanner, over the repository itself.

Phase 4's acceptance language is "a CI gate scanning test fixtures and example
specs for literal secrets", and Phase 6's is "no doc shows a literal credential
in any example (scanner-enforced)". Neither is discharged by having a function
that *could* scan: this suite walks the real tree and fails on what is there.

Two surfaces are covered, both at full strength — no allowlist, no skip list:

* every YAML/JSON document under ``examples/``;
* every YAML/JSON fenced example under ``docs/``, which is what makes Phase 6's
  "no doc shows a literal credential" a checked property rather than an intention.

``tests/`` is deliberately **not** walked, and the reason is worth stating rather
than hiding in a comment: the refusal tests must be able to plant a literal to
prove the scanner fires, so scanning them would require an exemption list, and
an exemption list is exactly the hand-maintained table whose blind spot let the
``audit_stream`` defect through in Phase 4. The scanner's own tests are the
negative controls, and they plant their literals in ``tmp_path``.

The scanner is the domain's, not a second opinion: every verdict comes from
:func:`mayhem.domain.secrets.find_literal_credentials`, so "what counts as a
literal credential" has one answer in this codebase. What this suite adds is the
walk, the multi-document parse, and the refusal to let an unreadable file pass
silently — a scanner that skips what it cannot parse is a scanner with a hole.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

import yaml

from mayhem.domain.secrets import find_literal_credentials

if TYPE_CHECKING:
    from collections.abc import Iterator

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLES_ROOT = REPO_ROOT / "examples"
DOCS_ROOT = REPO_ROOT / "docs"

#: Every file the scanner parses. Extensions only — never a name list, so a new
#: example or a new plan document is scanned the day it is added.
SCANNED_SUFFIXES: Final[tuple[str, ...]] = (".yaml", ".yml", ".json")

#: A fenced YAML or JSON example in a Markdown document.
FENCE: Final[re.Pattern[str]] = re.compile(
    r"^```(?:ya?ml|json)[ \t]*\n(.*?)^```",
    re.MULTILINE | re.DOTALL,
)

#: The ``apiVersion`` prefix that marks a document as a mayhem artifact. Used
#: only to report what was scanned, so a reader can tell a mayhem spec from a
#: compose file; the scan itself does not care which schema it is reading.
MAYHEM_API_PREFIX: Final[str] = "mayhem"


class UnreadableExampleError(AssertionError):
    """A scanned file the scanner could not parse.

    Raised rather than returned so it cannot be caught and ignored: the honest
    behaviour on a file we cannot read is to fail, not to skip.
    """


def _documents(text: str, source: str) -> list[object]:
    """Every YAML document in ``text``, including a multi-document stream.

    ``safe_load`` refuses a ``---``-separated stream, which is exactly the shape
    of a Kubernetes manifest, so a single-document loader would leave the most
    credential-bearing example format unscanned.
    """
    try:
        return [doc for doc in yaml.safe_load_all(text) if doc is not None]
    except yaml.YAMLError as error:
        raise UnreadableExampleError(
            f"{source}: cannot be parsed, so it cannot be scanned: {error}"
        ) from error


def _label(path: Path, root: Path) -> str:
    """``path`` as a repo-relative string, or its own name when it is elsewhere.

    The planted-literal controls run in ``tmp_path``, which is outside the repo,
    so the label falls back rather than raising — a scanner that crashes on a
    file outside its root is a scanner nobody can test.
    """
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def literal_hits(document: object, *, path: str = "$") -> tuple[str, ...]:
    return find_literal_credentials(document, path=path)


def scan_examples(root: Path = EXAMPLES_ROOT) -> dict[str, tuple[str, ...]]:
    """``relative path -> offending json paths`` for every example document."""
    hits: dict[str, tuple[str, ...]] = {}
    for path in sorted(root.rglob("*")):
        if path.suffix not in SCANNED_SUFFIXES or not path.is_file():
            continue
        label = _label(path, root)
        found: list[str] = []
        for index, document in enumerate(_documents(path.read_text(encoding="utf-8"), label)):
            found.extend(literal_hits(document, path=f"$[doc{index}]"))
        if found:
            hits[label] = tuple(found)
    return hits


def scan_doc_examples(root: Path = DOCS_ROOT) -> dict[str, tuple[str, ...]]:
    """``document -> offending json paths`` for every fenced YAML/JSON example."""
    hits: dict[str, tuple[str, ...]] = {}
    for path in sorted(root.rglob("*.md")):
        label = _label(path, root)
        found: list[str] = []
        for index, match in enumerate(FENCE.finditer(path.read_text(encoding="utf-8"))):
            source = f"{label}#fence{index}"
            for document in _documents(match.group(1), source):
                found.extend(literal_hits(document, path=f"$[fence{index}]"))
        if found:
            hits[label] = tuple(found)
    return hits


def scanned_example_files(root: Path = EXAMPLES_ROOT) -> Iterator[Path]:
    for path in sorted(root.rglob("*")):
        if path.suffix in SCANNED_SUFFIXES and path.is_file():
            yield path


# ── the walk ─────────────────────────────────────────────────────────────────


def test_no_example_file_carries_a_literal_credential() -> None:
    assert scan_examples() == {}


def test_no_documented_example_carries_a_literal_credential() -> None:
    """Phase 6's acceptance criterion, as a check rather than a promise."""
    assert scan_doc_examples() == {}


def test_the_scanner_is_wired_into_ci() -> None:
    """The gate has to actually run, or "in CI" is a claim about nothing.

    ``release.yml`` is the job that runs the unit suite, so this suite is in CI
    by being a unit test. Asserted from the workflow text rather than assumed, so
    renaming or deleting that job fails here instead of silently disarming both
    this scanner and the other 3,000-odd unit tests.
    """
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "uv run pytest tests/unit" in workflow, (
        "no job runs the unit suite, so a unit-test scanner is not in CI"
    )


# ── the walk is not vacuous ──────────────────────────────────────────────────


def _is_mayhem_artifact(document: object) -> bool:
    if not isinstance(document, dict):
        return False
    return str(document.get("apiVersion", "")).startswith(MAYHEM_API_PREFIX)


def test_the_example_walk_actually_parses_documents() -> None:
    """A scanner over an empty tree passes forever; assert it is looking at something."""
    files = list(scanned_example_files())

    assert files, "examples/ has no YAML or JSON to scan"
    assert len(files) >= 4, f"only {len(files)} example files found; is the walk still working?"
    specs = [
        path
        for path in files
        if any(
            _is_mayhem_artifact(doc)
            for doc in _documents(path.read_text(encoding="utf-8"), path.as_posix())
        )
    ]
    assert len(specs) >= 2, f"only {len(specs)} mayhem specs in examples/; the walk is blind"


def test_the_documentation_walk_actually_finds_fences() -> None:
    text = (DOCS_ROOT / "v1.1.0/29_SECRETS_MANAGEMENT.md").read_text(encoding="utf-8")

    assert FENCE.search(text), "the plan's own credentialRef example is not being read as a fence"


def test_a_multi_document_stream_is_scanned_in_full() -> None:
    """The Kubernetes manifest shape a single-document loader silently skips."""
    manifest = (
        "kind: ConfigMap\ndata:\n  token: abc123\n---\nkind: Secret\ndata:\n  password: hunter2\n"
    )

    documents = _documents(manifest, "planted.yaml")

    assert len(documents) == 2
    assert literal_hits(documents[0]) == ("$.data.token",)
    assert literal_hits(documents[1]) == ("$.data.password",)


def test_a_reference_shaped_example_is_not_a_literal() -> None:
    """The plan's own shape must survive the scanner, or the rule is unusable."""
    spec = {"steps": [{"credentialRef": {"provider": "vault", "secret": "prod/database"}}]}

    assert literal_hits(spec) == ()


# ── negative controls: each part of the scan must bite ───────────────────────


def test_the_scanner_catches_a_literal_planted_in_a_new_example(tmp_path: Path) -> None:
    (tmp_path / "drill.yaml").write_text(
        "steps:\n  - env:\n      password: hunter2\n",
        encoding="utf-8",
    )

    hits = scan_examples(tmp_path)

    assert hits == {"drill.yaml": ("$[doc0].steps[0].env.password",)}


def test_the_scanner_catches_a_literal_planted_in_a_documented_example(tmp_path: Path) -> None:
    (tmp_path / "guide.md").write_text(
        "# Guide\n\n```yaml\nsteps:\n  - env:\n      api_key: abc123\n```\n",
        encoding="utf-8",
    )

    assert scan_doc_examples(tmp_path) == {"guide.md": ("$[fence0].steps[0].env.api_key",)}


def test_an_unparseable_file_fails_rather_than_being_skipped(tmp_path: Path) -> None:
    """A scanner that cannot read a file must not report the file as clean."""
    (tmp_path / "broken.yaml").write_text("a:\n  - b\n c: [unclosed\n", encoding="utf-8")

    try:
        scan_examples(tmp_path)
    except UnreadableExampleError as error:
        assert "broken.yaml" in str(error)
    else:
        raise AssertionError("an unparseable example was skipped instead of failing")


def test_the_compose_example_no_longer_ships_a_password() -> None:
    """The concrete defect this scanner was written to find.

    Named rather than folded into the walk above, because a reader who wants to
    know what changed in ``examples/testCase/`` should not have to diff a test.
    """
    compose = (EXAMPLES_ROOT / "testCase/docker-compose.yml").read_text(encoding="utf-8")

    assert "POSTGRES_PASSWORD" not in compose
    assert "POSTGRES_HOST_AUTH_METHOD: trust" in compose


def test_both_committed_compose_files_agree() -> None:
    """The generated artifact is committed, so the two copies must not drift."""
    generated = (EXAMPLES_ROOT / "testCase/docker-compose.mayhem.yml").read_text(encoding="utf-8")

    assert "POSTGRES_PASSWORD" not in generated
    assert "POSTGRES_HOST_AUTH_METHOD: trust" in generated
    assert "mayhem_install()" in generated, "the generated file is the wrong artifact"
