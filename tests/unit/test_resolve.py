"""Tests for container resolution (PID/IP) at execution time (ADR-0020)."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from mayhem.topology.resolve import (
    ContainerInfo,
    _detect_engine,
    resolve_all,
    resolve_container,
    resolve_ip,
    resolve_pid,
    resolve_process_identity,
)


class _Raised(Exception):
    """Marker for a mocked subprocess returncode failure."""


def _mock_run(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return patch(
        "mayhem.topology.resolve.subprocess.run",
        return_value=subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=stderr
        ),
    )


class TestEngineDetection:
    @patch("shutil.which", side_effect=lambda name: f"/usr/bin/{name}")
    def test_prefers_podman(self, _mock_which) -> None:
        assert _detect_engine() == "podman"

    @patch("shutil.which", side_effect=lambda name: "/usr/bin/docker" if name == "docker" else None)
    def test_falls_back_to_docker(self, _mock_which) -> None:
        assert _detect_engine() == "docker"

    @patch("shutil.which", return_value=None)
    def test_no_engine_raises(self, _mock_which) -> None:
        with pytest.raises(RuntimeError, match="neither podman nor docker"):
            _detect_engine()


class TestResolvePid:
    def test_returns_pid(self) -> None:
        with (
            _mock_run(stdout="12345\n"),
            patch("mayhem.topology.resolve._detect_engine", return_value="podman"),
        ):
            assert resolve_pid("testcase-api") == 12345

    def test_returns_zero_pid_raises(self) -> None:
        with (
            _mock_run(stdout="0\n"),
            patch("mayhem.topology.resolve._detect_engine", return_value="podman"),
        ):
            with pytest.raises(RuntimeError, match="no running process"):
                resolve_pid("testcase-api")

    def test_negative_pid_raises(self) -> None:
        with (
            _mock_run(stdout="-1\n"),
            patch("mayhem.topology.resolve._detect_engine", return_value="podman"),
        ):
            with pytest.raises(RuntimeError, match="no running process"):
                resolve_pid("testcase-api")

    def test_container_not_found_raises(self) -> None:
        with (
            _mock_run(returncode=1, stderr="No such object: testcase-api\n"),
            patch("mayhem.topology.resolve._detect_engine", return_value="podman"),
        ):
            with pytest.raises(RuntimeError, match="inspect failed"):
                resolve_pid("testcase-api")

    def test_non_numeric_pid_raises(self) -> None:
        with (
            _mock_run(stdout="notanumber\n"),
            patch("mayhem.topology.resolve._detect_engine", return_value="podman"),
        ):
            with pytest.raises(RuntimeError, match="non-numeric"):
                resolve_pid("testcase-api")

    def test_timeout_raises(self) -> None:
        with (
            patch(
                "mayhem.topology.resolve.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="podman inspect", timeout=10),
            ),
            patch("mayhem.topology.resolve._detect_engine", return_value="podman"),
        ):
            with pytest.raises(RuntimeError, match="timed out"):
                resolve_pid("testcase-api")

    def test_explicit_engine_used(self) -> None:
        with _mock_run(stdout="42\n"):
            assert resolve_pid("testcase-api", engine="docker") == 42


class TestResolveIp:
    def test_returns_ip(self) -> None:
        with (
            _mock_run(stdout="172.18.0.3\n"),
            patch("mayhem.topology.resolve._detect_engine", return_value="podman"),
        ):
            assert resolve_ip("testcase-api") == "172.18.0.3"

    def test_empty_ip(self) -> None:
        with (
            _mock_run(stdout="\n"),
            patch("mayhem.topology.resolve._detect_engine", return_value="podman"),
        ):
            assert resolve_ip("testcase-api") == ""


class TestResolveProcessIdentity:
    def test_reads_boot_time_on_linux(self) -> None:
        # pid 42, comm "(python)", then fields 3..: state (R), ppid, pgrp,
        # session, tty, tpgid, flags, minflt, cminflt, majflt, cmajflt, utime,
        # stime, cutime, cstime, priority, nice, num_threads, itrealvalue,
        # starttime (field 22 -> index 19 after the ')' split) = 9001.
        stat = "42 (python) R 1 42 42 0 -1 4194304 0 0 0 0 10 3 0 0 20 0 1 0 9001 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"

        class _FakeStat:
            def read_text(self) -> str:
                return stat

        with (
            patch("mayhem.topology.resolve.sys.platform", "linux"),
            patch("mayhem.topology.resolve.Path", return_value=_FakeStat()),
        ):
            identity = resolve_process_identity(42, "h-local", "c-a")
        assert identity.pid == 42
        assert identity.boot_time == 9001
        assert identity.container_name == "c-a"
        assert identity.resolve_key() == "h-local|42|9001|c-a"

    def test_degrades_to_none_on_darwin(self) -> None:
        with patch("mayhem.topology.resolve.sys.platform", "darwin"):
            identity = resolve_process_identity(42, "h-local")
        assert identity.boot_time is None
        assert identity.pid == 42


class TestResolveContainer:
    def test_returns_container_info(self) -> None:
        calls: list[str] = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd[-1])
            fmt = cmd[cmd.index("--format") + 1]
            if fmt == "{{.State.Pid}}":
                out = "9876\n"
            elif ".IPAddress" in fmt:
                out = "172.18.0.3\n"
            else:
                out = "running\n"
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=out, stderr="")

        with (
            patch("mayhem.topology.resolve.subprocess.run", side_effect=fake_run),
            patch("mayhem.topology.resolve._detect_engine", return_value="podman"),
        ):
            info = resolve_container("testcase-api")
        assert isinstance(info, ContainerInfo)
        assert info.pid == 9876
        assert info.ip_address == "172.18.0.3"
        assert info.state == "running"


class TestResolveAll:
    def test_resolves_multiple_and_skips_failures(self) -> None:
        def fake_run(cmd, **kwargs):
            name = cmd[-1]
            fmt = cmd[cmd.index("--format") + 1]
            if name == "missing":
                return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="x")
            if fmt == "{{.State.Pid}}":
                out = "1111\n"
            elif ".IPAddress" in fmt:
                out = "172.18.0.2\n"
            else:
                out = "running\n"
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=out, stderr="")

        with (
            patch("mayhem.topology.resolve.subprocess.run", side_effect=fake_run),
            patch("mayhem.topology.resolve._detect_engine", return_value="podman"),
        ):
            out = resolve_all(("testcase-api", "missing"))
        assert "testcase-api" in out
        assert out["testcase-api"].pid == 1111
        assert "missing" not in out

    def test_empty_input(self) -> None:
        with patch("mayhem.topology.resolve._detect_engine", return_value="podman"):
            assert resolve_all(()) == {}


class TestSubstitutePids:
    def _undo(self, pid: str = "42") -> list:
        from mayhem.domain.leases import UndoOp

        return [UndoOp(op="signal.cont", args={"pid": pid})]

    def _verify(self, pid: str = "42") -> list:
        from mayhem.domain.leases import VerifyProbe

        return [
            VerifyProbe(
                probe="exec",
                args={"cmd": ["ps", "-p", pid], "timeout_s": "5"},
                expect_present=True,
            )
        ]

    def test_placeholder_replaced_with_live_pid(self) -> None:
        from mayhem.controller.executor import _LIVE_PID, _substitute_pids

        uo = self._undo(f"n-proc:{_LIVE_PID}")
        vp = self._verify(f"n-proc:{_LIVE_PID}")
        new_uo, new_vp = _substitute_pids(tuple(uo), tuple(vp), {"n-proc": 777})
        assert new_uo[0].args["pid"] == "777"
        assert new_vp[0].args["cmd"] == ["ps", "-p", "777"]
        assert new_vp[0].args["timeout_s"] == "5"

    def test_missing_live_pid_keeps_placeholder(self) -> None:
        from mayhem.controller.executor import _LIVE_PID, _substitute_pids

        uo = self._undo(f"n-proc:{_LIVE_PID}")
        new_uo, _ = _substitute_pids(tuple(uo), (), {})
        assert new_uo[0].args["pid"] == f"n-proc:{_LIVE_PID}"

    def test_plain_pid_untouched(self) -> None:
        from mayhem.controller.executor import _substitute_pids

        uo = self._undo("4242")
        new_uo, _ = _substitute_pids(tuple(uo), (), {"n-proc": 5})
        assert new_uo[0].args["pid"] == "4242"
