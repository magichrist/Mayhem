"""End-to-end agent session: spawn ``mayhem-agent serve`` and speak ndjson JSON-RPC."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys

import pytest

CTX = {"run_id": "r-e2e", "agent_id": "controller-test"}


def _spawn() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [sys.executable, "-m", "mayhem.agent.cli", "serve", "--roles", "proc"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )


def _send(proc: subprocess.Popen[bytes], payload: dict | str) -> None:
    assert proc.stdin is not None
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    proc.stdin.write((raw + "\n").encode())
    proc.stdin.flush()


def _recv(proc: subprocess.Popen[bytes]) -> dict | None:
    assert proc.stdout is not None
    line = proc.stdout.readline()
    if not line:
        return None
    return json.loads(line)


def _ask(proc: subprocess.Popen[bytes], payload: dict | str) -> dict | None:
    _send(proc, payload)
    return _recv(proc)


@pytest.mark.skipif(not shutil.which("python3") and sys.platform == "win32",
                    reason="posix-only smoke")
def test_agent_serve_session_roundtrip() -> None:
    proc = _spawn()
    try:
        handshake = _ask(proc, {
            "jsonrpc": "2.0", "id": 1, "method": "handshake", "params": CTX,
        })
        assert handshake is not None and handshake["result"]["protocol"] == "mayhem/1"

        # notification → no frame on stdout; the next request must still answer id=2
        _send(proc, {"jsonrpc": "2.0", "method": "log.emit",
                     "params": {**CTX, "line": "noise"}})
        caps = _ask(proc, {"jsonrpc": "2.0", "id": 2,
                           "method": "capabilities.query", "params": CTX})
        assert caps is not None and caps["id"] == 2
        assert "proc" in caps["result"]["faults"]

        bad = _ask(proc, "{not-json-at-all")
        assert bad is not None
        assert bad["error"]["code"] == -32700

        unknown = _ask(proc, {"jsonrpc": "2.0", "id": 3, "method": "nope",
                              "params": CTX})
        assert unknown is not None
        assert unknown["error"]["code"] == -32601

        proc.stdin.close()
        assert proc.wait(timeout=10) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
