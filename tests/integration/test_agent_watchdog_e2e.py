"""E2E: ADR-0005 §3 — agent self-compensates a lease past TTL without the controller."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

CTX = {"run_id": "r-e2e", "agent_id": "a-e2e"}


def _send(proc: subprocess.Popen[bytes], payload: dict) -> None:
    assert proc.stdin is not None
    proc.stdin.write((json.dumps(payload) + "\n").encode())
    proc.stdin.flush()


def _recv(proc: subprocess.Popen[bytes]) -> dict | None:
    assert proc.stdout is not None
    line = proc.stdout.readline()
    return json.loads(line) if line else None


def _is_stopped(pid: int) -> bool:
    """True while the pid sits in SIGSTOP ('T' state). Works on darwin/linux."""
    try:
        out = subprocess.run(
            ["ps", "-o", "stat=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except subprocess.SubprocessError:
        return False
    return out.stdout.strip().startswith("T")


def test_watchdog_expires_lease_and_resumes_process() -> None:
    sleeper = subprocess.Popen(["sleep", "300"])
    try:
        proc = subprocess.Popen(
            [sys.executable, "-m", "mayhem.agent.cli", "serve", "--roles", "proc"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={**os.environ, "PYTHONPATH": "src"},
        )
        lease = {
            "id": "l-wd-1",
            "run_id": CTX["run_id"],
            "owner_agent": CTX["agent_id"],
            "fault_id": "proc.pause",
            "targets": [f"pid:{sleeper.pid}"],
            "ttl_seconds": 0.5,
            "undo_ops": [{"op": "process.resume", "args": {"pid": str(sleeper.pid)}}],
        }
        _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "handshake", "params": CTX})
        hello = _recv(proc)
        assert hello is not None and hello["id"] == 1

        _send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "task.execute",
                "params": {**CTX, "fault_id": "proc.pause", "lease": lease},
            },
        )
        resp = _recv(proc)
        assert resp is not None and resp["id"] == 2
        assert resp["result"]["ok"] is True
        assert _is_stopped(sleeper.pid), "inject should have SIGSTOPped the sleeper"

        # controller goes quiet; the watchdog must still compensate on its own.
        deadline = time.monotonic() + 6.0
        resumed = False
        while time.monotonic() < deadline:
            if not _is_stopped(sleeper.pid):
                resumed = True
                break
            time.sleep(0.1)
        assert resumed, "watchdog did not resume the paused process"

        _send(
            proc,
            {"jsonrpc": "2.0", "id": 3, "method": "task.status", "params": {**CTX}},
        )
        status = _recv(proc)
        assert status is not None and status["id"] == 3
        compensated = status["result"]["compensated"]
        assert compensated and compensated[0]["lease_id"] == "l-wd-1"
        assert compensated[0]["state"] == "expired"
    finally:
        if sleeper.poll() is None:
            sleeper.kill()
            sleeper.wait(timeout=5)
