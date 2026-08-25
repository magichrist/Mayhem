"""mayhem CLI package — Click-based, unique-prefix command resolution.

Public surface: ``app`` (the root group, for tests and embedding) and
``main`` (the console-script entry point with exit-code mapping).
"""

from __future__ import annotations

from mayhem.cli.app import app, main

__all__ = ["app", "main"]
