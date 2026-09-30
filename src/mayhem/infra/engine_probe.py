"""Host probing for container engines (ADR-M3-1).

Asking the host what is installed — is the binary on PATH, and what does its
``--version`` say — is IO, so it lives here in ``infra`` rather than in
``mayhem.domain.runtime_adapter``, which must keep zero IO (the domain layer
has zero IO and no upward imports contract).

The *selection rule* stays in the domain as
:func:`mayhem.domain.runtime_adapter.select_engine`: this module only gathers
the host facts and hands them over, so the rule remains testable without a
host.
"""

from __future__ import annotations

import shutil
import subprocess

from mayhem.domain.runtime_adapter import (
    EngineDescriptor,
    describe_engine,
    known_engines,
    select_engine,
)


def _probe_version(binary: str) -> str | None:
    """``<binary> --version``'s first line, or ``None`` if it will not say."""
    try:
        out = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        raw = (out.stdout or out.stderr or "").strip()
        return raw.splitlines()[0][:120] if raw else None
    except Exception:
        return None


def detect_available_engines() -> list[EngineDescriptor]:
    """Each known engine, with whether it is installed and what version it is."""
    result: list[EngineDescriptor] = []
    for name in known_engines():
        base = describe_engine(name)
        binary_available = shutil.which(base.binary) is not None
        version = _probe_version(base.binary) if binary_available else None
        result.append(
            base.model_copy(update={"binary_available": binary_available, "version": version})
        )
    return result


def resolve_engine_selection(explicit: str | None) -> EngineDescriptor:
    """Probe the host, then apply the domain's selection rule to the result."""
    return select_engine(explicit, detect_available_engines())
