"""Tool execution with full evidence capture (tool-run contract).

Every external invocation goes through ``run_tool`` so the run record can
reconstruct: exact argv, environment digest, host, exit code, duration, and
(truncation-bounded) output. Nothing else in the codebase may spawn processes.
"""

from __future__ import annotations

import os
import platform
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tgondi.domain.errors import DomainError
from tgondi.toolkit.hashing import digest_mapping

DEFAULT_MAX_OUTPUT_BYTES = 1_048_576  # 1 MiB per stream


class ToolError(DomainError):
    """A tool invocation could not be executed at all."""


class ToolTimeoutError(ToolError):
    """The tool exceeded its time budget and was killed."""


@dataclass(frozen=True)
class ToolResult:
    argv: tuple[str, ...]
    argv_digest: str
    env_digest: str
    host: str
    cwd: str | None
    exit_code: int | None
    duration_ms: int
    stdout: str
    stderr: str
    truncated: bool

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0

    def to_row(self, *, invocation_ref: str | None = None) -> dict[str, Any]:
        """Shape matching the tool_runs table (stdout/stderr refs added by caller)."""
        return {
            "id": self.argv_digest,
            "invocation_ref": invocation_ref,
            "argv_digest": self.argv_digest,
            "argv_json": list(self.argv),
            "env_digest": self.env_digest,
            "host": self.host,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "truncated": int(self.truncated),
            "stdout_ref": None,
            "stderr_ref": None,
        }


def _truncate(data: bytes, limit: int) -> tuple[str, bool]:
    truncated = len(data) > limit
    text = data[:limit].decode("utf-8", errors="replace")
    if truncated:
        text += "\n...[TRUNCATED]"
    return text, truncated


def run_tool(
    argv: list[str] | tuple[str, ...],
    *,
    env: dict[str, str] | None = None,
    cwd: Path | str | None = None,
    timeout_s: float | None = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    stdin_data: str | None = None,
) -> ToolResult:
    """Run a tool synchronously; never raises for non-zero exit codes.

    Raises ToolError only when the process could not be started or timed out —
    those are harness failures, not tool failures, and callers must record them.
    """
    argv_tuple = tuple(argv)
    if not argv_tuple:
        raise ToolError("tool_runner", "refusing to execute empty argv")
    effective_env = dict(env) if env is not None else dict(os.environ)
    started = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603 — argv is controller-controlled
            argv_tuple,
            capture_output=True,
            text=False,
            env=effective_env,
            cwd=str(cwd) if cwd else None,
            timeout=timeout_s,
            input=stdin_data.encode("utf-8") if stdin_data is not None else b"",
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ToolTimeoutError(
            "tool_runner",
            f"{argv_tuple[0]} exceeded timeout of {timeout_s}s",
        ) from exc
    except OSError as exc:
        raise ToolError("tool_runner", f"failed to start {argv_tuple[0]}: {exc}") from exc
    duration_ms = int((time.monotonic() - started) * 1000)

    stdout_text, stdout_truncated = _truncate(completed.stdout or b"", max_output_bytes)
    stderr_text, stderr_truncated = _truncate(completed.stderr or b"", max_output_bytes)

    return ToolResult(
        argv=argv_tuple,
        argv_digest=digest_mapping({"argv": list(argv_tuple)}),
        env_digest=digest_mapping(effective_env),
        host=platform.node(),
        cwd=str(cwd) if cwd else None,
        exit_code=completed.returncode,
        duration_ms=duration_ms,
        stdout=stdout_text,
        stderr=stderr_text,
        truncated=stdout_truncated or stderr_truncated,
    )
