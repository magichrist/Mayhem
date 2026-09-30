"""The generated proxy, executed: real sockets, real bytes.

The other proxy test file checks the *shape* of the emitted program. This one
runs it. A program can satisfy every structural assertion and still be wrong --
`relay` had a two-argument signature while `forward` called it with three for
one whole revision, which compiled fine and would have raised `TypeError` inside
a container at fault-injection time. Nothing short of executing it catches that.

Every test binds loopback sockets and spawns the generated program as a
subprocess, then tears both down. No container, engine, or network is required.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from mayhem.controller.compensation import _http_proxy_source

TIMEOUT_S = 30


#: stop events keyed by server identity, so the fixture can halt its accept loop
_STOPS: dict[int, threading.Event] = {}


def _one_upstream(conn: socket.socket, gap: float):
    """Send a head, then a second body chunk after ``gap`` seconds, then close."""

    def run() -> None:
        try:
            conn.recv(65536)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\nAAA")
            time.sleep(gap)
            conn.sendall(b"BBB")
            time.sleep(0.5)
            conn.close()
        except OSError:
            pass

    return run


class _Proxy:
    """A running copy of the generated in-container proxy."""

    def __init__(self, **kwargs: object) -> None:
        self._portfile = Path(tempfile.mktemp(suffix=".port"))
        self._path = Path(tempfile.mktemp(suffix=".py"))
        self._path.write_text(
            _http_proxy_source(marker_port=str(self._portfile), **kwargs)  # type: ignore[arg-type]
        )
        self._proc = subprocess.Popen(
            [sys.executable, str(self._path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        for _ in range(200):
            if self._portfile.exists() and self._portfile.stat().st_size:
                break
            if self._proc.poll() is not None:  # pragma: no cover - defensive
                err = self._proc.stderr.read() if self._proc.stderr else b""
                pytest.fail(f"proxy died: {err.decode(errors='replace')[:400]}")
            time.sleep(0.05)
        self.port = int(self._portfile.read_text().strip())

    def request(self, payload: bytes = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") -> bytes:
        """Send one request and read the response, tolerating a lingering socket.

        The canned path advertises ``Connection: close`` but does not actually
        close the socket -- it drops the reference and lets the thread's
        refcount do it. That is pre-existing behaviour for the status and
        rate-limit modes, so this reads until the peer goes quiet rather than
        until EOF. A real HTTP client reads the head and moves on, which is what
        this models.
        """
        chunks: list[bytes] = []
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=TIMEOUT_S)
        try:
            sock.sendall(payload)
            sock.settimeout(TIMEOUT_S)
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                sock.settimeout(0.4)
        except TimeoutError:
            pass
        finally:
            sock.close()
        return b"".join(chunks)

    def close(self) -> None:
        self._proc.kill()
        self._proc.wait(timeout=5)
        for path in (self._path, self._portfile):
            if path.exists():
                path.unlink()


@pytest.fixture
def proxy_factory():
    made: list[_Proxy] = []

    def make(**kwargs: object) -> _Proxy:
        kwargs.setdefault("target", 9)
        kwargs.setdefault("prob", 100.0)
        proxy = _Proxy(**kwargs)
        made.append(proxy)
        return proxy

    yield make
    for proxy in made:
        proxy.close()


class TestCannedResponsesOnTheWire:
    def test_status_mode_is_byte_identical_to_before(self, proxy_factory) -> None:
        """The pre-existing mode must not have shifted by a single byte."""
        out = proxy_factory(status=503).request()
        assert out == b"HTTP/1.1 503 X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

    def test_truncate_declares_more_than_it_delivers(self, proxy_factory) -> None:
        out = proxy_factory(status=200, declared=4096, send_bytes=64).request()
        head, _, body = out.partition(b"\r\n\r\n")
        assert b"Content-Length: 4096" in head
        assert len(body) == 64
        assert set(body) == {ord("x")}

    def test_header_inject_places_headers_before_content_length(self, proxy_factory) -> None:
        out = proxy_factory(status=200, headers="X-Trace: abc\r\nX-Env: prod").request()
        head = out.partition(b"\r\n\r\n")[0]
        assert b"X-Trace: abc" in head
        assert b"X-Env: prod" in head
        # Content-Length must stay the final header or the head is malformed
        assert head.index(b"X-Env: prod") < head.index(b"Content-Length:")

    def test_circuit_open_serves_503_with_retry_after(self, proxy_factory) -> None:
        out = proxy_factory(status=503, headers="Retry-After: 45").request()
        head = out.partition(b"\r\n\r\n")[0]
        assert head.startswith(b"HTTP/1.1 503")
        assert b"Retry-After: 45" in head


class TestOperatorBodyOnTheWire:
    """``http.response_truncate{body: ...}`` — the operator's bytes, actually
    delivered, with a Content-Length that agrees with them.

    Everything about this axis is decided at plan time, which is exactly the
    "green tests, broken behaviour" shape: a Content-Length that is off by the
    difference between characters and bytes does not truncate, it hangs, and the
    request below times out rather than returning a wrong-but-plausible body.
    """

    def test_the_body_is_delivered_and_still_truncated(self, proxy_factory) -> None:
        body = b'{"items": [1, 2, 3], "partial": tr'
        out = proxy_factory(
            status=200, declared=len(body) + 4096, send_bytes=len(body), body=body
        ).request()
        head, _, delivered = out.partition(b"\r\n\r\n")
        assert f"Content-Length: {len(body) + 4096}".encode() in head
        assert delivered == body

    def test_a_binary_body_survives_intact(self, proxy_factory) -> None:
        """Every non-printable byte class, so an escaping bug in the literal
        would show up as changed bytes rather than as a compile error."""
        body = bytes(range(32)) + b"tail"
        out = proxy_factory(
            status=200, declared=len(body) + 64, send_bytes=len(body), body=body
        ).request()
        assert out.partition(b"\r\n\r\n")[2] == body

    def test_the_declared_length_is_exactly_the_body_length(self, proxy_factory) -> None:
        """A response that declares what it delivers is not a truncation, so the
        declared length has to be checked against the body the client receives."""
        body = b"12345"
        out = proxy_factory(
            status=200, declared=len(body), send_bytes=len(body), body=body
        ).request()
        head, _, delivered = out.partition(b"\r\n\r\n")
        assert int(head.split(b"Content-Length: ")[1].split(b"\r\n")[0]) == len(delivered)


class TestStreamStallOnTheWire:
    """Stall the client after the response head, prove the body is held back."""

    @staticmethod
    def _upstream(first_gap: float) -> tuple[socket.socket, int]:
        """Accept, send head+AAA now, then BBB after ``first_gap`` seconds."""
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        stop = threading.Event()

        def serve() -> None:
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                threading.Thread(target=_one_upstream(conn, first_gap), daemon=True).start()

        threading.Thread(target=serve, daemon=True).start()
        _STOPS[id(srv)] = stop
        return srv, srv.getsockname()[1]

    def test_body_waits_for_the_stall_window(self, proxy_factory) -> None:
        srv, upstream_port = self._upstream(first_gap=1.0)
        try:
            plain = proxy_factory(target=upstream_port)
            stalled = proxy_factory(target=upstream_port, stall_ms=8000)

            def timings(proxy: _Proxy) -> tuple[float, float]:
                sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=TIMEOUT_S)
                try:
                    sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                    sock.settimeout(TIMEOUT_S)
                    start = time.monotonic()
                    head = sock.recv(65536)
                    head_at = time.monotonic() - start
                    body = sock.recv(65536)
                    body_at = time.monotonic() - start
                finally:
                    sock.close()
                assert head.startswith(b"HTTP/1.1 200") and b"AAA" in head
                assert body == b"BBB"
                return head_at, body_at

            _plain_head, plain_body = timings(plain)
            stalled_head, stalled_body = timings(stalled)

            # the head must not be delayed: the stall starts after it
            assert stalled_head < 1.0, f"head was delayed by {stalled_head:.2f}s"
            assert plain_body < 2.0, f"baseline body should land near 1s, got {plain_body:.2f}s"
            # the body is gated on the stall completing, not on the upstream
            assert stalled_body > 7.0, f"body should wait for the 8s stall, got {stalled_body:.2f}s"
        finally:
            _STOPS.pop(id(srv), None).set()
            srv.close()
