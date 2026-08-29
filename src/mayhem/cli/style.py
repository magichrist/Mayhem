"""TTY-aware ANSI styling shared by every CLI command.

Wrapping user-facing lines through these helpers keeps log streams scannable:
green for success, cyan for informational, yellow for warnings and bypasses,
orange for failures and red-zone states. Color auto-cancels when the stream is
not a terminal (pipes, CI, test capture) or ``NO_COLOR`` is set, so rendered —
and captured — output stays plain.
"""

from __future__ import annotations

import os
import sys
from typing import IO

import click

# Orange ≈ ANSI 38;2;255;159;26 — click has no 16-color orange.
ORANGE: tuple[int, int, int] = (255, 159, 26)


def _stream(*, err: bool) -> IO[str]:
    return sys.stderr if err else sys.stdout


def _use_color(stream: IO[str]) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _style(
    text: str, fg: str | tuple[int, int, int], *, err: bool, bold: bool
) -> str:
    if not _use_color(_stream(err=err)):
        return text
    return click.style(text, fg=fg, bold=bold)


def green(text: str, *, err: bool = False, bold: bool = False) -> str:
    """Success and healthy-state marks."""
    return _style(text, "green", err=err, bold=bold)


def cyan(text: str, *, err: bool = False, bold: bool = False) -> str:
    """Informational lines, timestamps, and step identifiers."""
    return _style(text, "cyan", err=err, bold=bold)


def yellow(text: str, *, err: bool = False, bold: bool = False) -> str:
    """Warnings and bypassed (skip-with-reason) outcomes."""
    return _style(text, "yellow", err=err, bold=bold)


def orange(text: str, *, err: bool = False, bold: bool = False) -> str:
    """Failures and anything in the red zone."""
    return _style(text, ORANGE, err=err, bold=bold)


def ts(text: str, *, err: bool = False, bold: bool = False) -> str:
    """Timestamps and wall-clock — bright-cyan, visible on dark terminals."""
    return _style(text, "bright_cyan", err=err, bold=bold)


def ok(text: str, *, err: bool = False, bold: bool = True) -> str:
    """``[ok]`` marks and green confirmations."""
    return _style(text, "green", err=err, bold=bold)


def warn(text: str, *, err: bool = True, bold: bool = True) -> str:
    """``warning:`` prefix — yellow, bold."""
    return _style(text, "yellow", err=err, bold=bold)


def info(text: str, *, err: bool = False, bold: bool = False) -> str:
    """``info:`` prefix — cyan."""
    return _style(text, "cyan", err=err, bold=bold)


def danger(text: str, *, err: bool = True, bold: bool = True) -> str:
    """``error:`` / red-zone prefix — orange, bold."""
    return _style(text, ORANGE, err=err, bold=bold)


def state(text: str) -> str:
    """Color a run/step status value by what it means.

    Call on already-padded text (``state(f"{status:<10}")``) so the escape
    codes never disturb column alignment.
    """
    mapping = {
        "completed": green,
        "running": cyan,
        "pending": cyan,
        "created": cyan,
        "planning": cyan,
        "validated": cyan,
        "recovering": yellow,
        "skipped": yellow,
        "cancelled": yellow,
        "bypassed": yellow,
    }
    return mapping.get(text, orange)(text)
