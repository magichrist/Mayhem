"""Mypy error ratchet — the typing backlog may shrink, never grow.

This is a *ratchet*, not a gate demanding zero. A test that asserts zero gets
deleted rather than fixed, because the pressure it creates is to silence the
checker rather than to fix the code. What this does is make growth loud:
adding a new typing error, or reintroducing one that was already fixed, fails
the suite with the exact file and error code.

Two assertions, deliberately:

* **per (file, error code) pairs** — an error in a file that is currently
  clean for that code fails even if the *total* is unchanged. This is what
  stops the common trade of paying for a new error by leaving an old one.
* **a non-increasing total** — catches the net growth that pair-tracking alone
  would let through.

``# type: ignore`` is not separately pinned: mypy already reports
``unused-ignore`` when an ignore stops being needed, so a stale suppression
shows up here as a new error rather than disappearing silently.

Measured baseline: 1 error, from 111 at the start of the typing lanes.
See ``docs/typing-ratchet.md`` for the per-root-cause breakdown.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src"

#: ``path:line: error: message  [code]``
#:
#: ``--no-pretty`` is required, not cosmetic: in pretty mode mypy hard-wraps
#: long messages and pushes the trailing ``[code]`` onto a continuation line,
#: which silently drops the error from a per-line parse.
_ERROR_LINE = re.compile(r"^(?P<file>[^:]+):(?P<line>\d+): error: .*\[(?P<code>[a-z-]+)\]$")

#: The budget, as of the end of the H2 typing lane.
#:
#: Deliberately small. Each entry is a finding that was investigated and
#: consciously left in place; adding to this table is a review decision, not
#: a convenience. Raising a number without deleting the corresponding entry
#: fails :func:`test_baseline_table_is_ordered_and_complete`.
BASELINE: dict[tuple[str, str], int] = {
    # cli/lifecycle.py:1604 — a `rows[0][0]` fallback in a `sqlite3.Row`
    # ternary. `Store.query` is annotated `list[sqlite3.Row]` and
    # `Store.__init__` sets `row_factory = sqlite3.Row` unconditionally, so
    # `hasattr(row, "__getitem__")` is always true and the else is provably
    # dead. Left in place: the `isinstance`/`hasattr` guard is a deliberate
    # "support dict rows and tuple rows" accommodation, and deleting a
    # defensive branch in a CLI plan-loading path is a worse trade than one
    # pinned error. It is dead code, not a defect.
    ("src/mayhem/cli/lifecycle.py", "unreachable"): 1,
}

MAX_TOTAL = sum(BASELINE.values())


def _python() -> str:
    """The interpreter to run mypy under.

    Prefers the project venv. The ambient ``python3`` is miniconda, which
    lacks ``types-pyyaml`` and reports a spurious
    ``Library stubs not installed for "yaml"`` — a phantom that would show
    up here as a phantom regression.
    """
    venv = REPO_ROOT / ".venv" / "bin" / "python"
    return str(venv) if venv.exists() else sys.executable


def _run_mypy() -> str:
    """Run mypy over ``src/`` and return stdout+stderr."""
    result = subprocess.run(
        [_python(), "-m", "mypy", "--no-pretty", "src"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    combined = result.stdout + result.stderr
    if "No module named mypy" in combined:
        pytest.fail(
            "mypy is not importable under the interpreter this ratchet would use "
            f"({_python()}). Run `.venv/bin/python -m mypy src` to confirm."
        )
    if "Traceback (most recent call last)" in combined:
        pytest.fail(f"mypy failed to run:\n{combined}")
    return combined


def _current() -> dict[tuple[str, str], int]:
    counts: dict[tuple[str, str], int] = {}
    for raw in _run_mypy().splitlines():
        match = _ERROR_LINE.match(raw.strip())
        if match is None:
            continue
        key = (match.group("file"), match.group("code"))
        counts[key] = counts.get(key, 0) + 1
    return counts


def test_mypy_error_total_does_not_grow() -> None:
    """The headline ratchet: the error count may only go down."""
    current = _current()
    total = sum(current.values())
    offenders = sorted(
        (f"  {path} [{code}] x{n}" for (path, code), n in current.items()),
    )
    assert total <= MAX_TOTAL, (
        f"mypy error count grew from {MAX_TOTAL} to {total}.\n"
        f"Fix the new errors rather than raising BASELINE/MAX_TOTAL.\n"
        f"Current errors by file and code:\n" + "\n".join(offenders)
    )


def test_no_new_file_or_error_code_introduced() -> None:
    """No new (file, error code) pair may appear.

    This is the assertion the total alone cannot make. Paying for a new
    error by leaving an old one keeps the total flat; this fails anyway.
    """
    current = _current()
    new_pairs = sorted(set(current) - set(BASELINE))
    assert not new_pairs, (
        "New mypy error(s) in files that are currently clean for that code:\n"
        + "\n".join(f"  {path} [{code}]" for path, code in new_pairs)
    )


def test_baseline_entries_still_accurate() -> None:
    """Pinned pairs must not exceed their recorded count.

    A pair that disappears entirely (or shrinks) is *good* news and shows up
    here so the table can be tightened; it is reported, not failed, because a
    test that fails on improvement is a test that gets deleted.
    """
    current = _current()
    for (path, code), allowed in sorted(BASELINE.items()):
        found = current.get((path, code), 0)
        assert found <= allowed, (
            f"{path} now has {found} [{code}] errors, baseline allows {allowed}. "
            "Fix the regression rather than raising the baseline."
        )


def test_baseline_table_covers_everything_remaining() -> None:
    """BASELINE must be exactly the current error set.

    Keeps the table honest: a leftover entry (a fix that was never recorded)
    and a missing entry (a new error) both fail here. This is what makes
    MAX_TOTAL trustworthy as a single number.
    """
    current = _current()
    stale = sorted(set(BASELINE) - set(current))
    missing = sorted(set(current) - set(BASELINE))
    assert not stale, f"BASELINE has entries with no matching error: {stale}"
    assert not missing, f"BASELINE is missing current errors: {missing}"


def test_baseline_total_matches_table() -> None:
    """MAX_TOTAL is derived from the table, so the two cannot drift apart."""
    assert MAX_TOTAL == sum(BASELINE.values()) == len(BASELINE), (
        "MAX_TOTAL must equal the sum of BASELINE values"
    )
