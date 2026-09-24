from __future__ import annotations

import ast
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).parents[2]
DOC_FILES = tuple(
    sorted(
        {
            ROOT / "CHANGELOG.md",
            ROOT / "README.md",
            *ROOT.glob("docs/**/*.md"),
            *ROOT.glob("examples/**/*.md"),
        }
    )
)
_INLINE_LINK_RE = re.compile(r"!?\[[^\]]*\]\(\s*<?([^)\s>]+)>?(?:\s+['\"][^)]*['\"])?\s*\)")
_REFERENCE_LINK_RE = re.compile(r"^\s*\[[^\]]+\]:\s*<?([^\s>]+)>?", re.MULTILINE)
_EXIT_CODE_RE = re.compile(r"\bExitCode\.([A-Z][A-Z0-9_]*)\b")


def _markdown_targets(text: str) -> tuple[str, ...]:
    return tuple(_INLINE_LINK_RE.findall(text)) + tuple(_REFERENCE_LINK_RE.findall(text))


def _source_exit_codes() -> frozenset[str]:
    source = (ROOT / "src/mayhem/cli/exit_codes.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "ExitCode":
            return frozenset(
                item.targets[0].id
                for item in node.body
                if isinstance(item, ast.Assign)
                and isinstance(item.targets[0], ast.Name)
            )
    raise AssertionError("ExitCode class not found in src/mayhem/cli/exit_codes.py")


def test_relative_markdown_links_resolve() -> None:
    broken: list[str] = []
    for document in DOC_FILES:
        for target in _markdown_targets(document.read_text(encoding="utf-8")):
            parsed = urlsplit(target)
            if not parsed.path or parsed.scheme or parsed.netloc or target.startswith(("/", "#")):
                continue
            destination = (document.parent / unquote(parsed.path)).resolve()
            if not destination.exists():
                broken.append(f"{document.relative_to(ROOT)} -> {target}")
    assert not broken, "broken relative Markdown links:\n" + "\n".join(broken)


def test_documented_exit_code_identifiers_exist_in_source() -> None:
    reference = (ROOT / "docs/reference/cli.md").read_text(encoding="utf-8")
    documented = frozenset(_EXIT_CODE_RE.findall(reference))
    declared = _source_exit_codes()
    assert documented <= declared, sorted(documented - declared)
