"""Wave 2, substrate group 3: the five proxy-backed faults.

The in-container passthrough proxy is the only application-level mechanism in
the tree, and these tests pin the modes added to it. Two properties matter more
than the rest:

* **The pre-existing modes must be untouched.** Every new kwarg defaults to
  inert, so ``status``/``delay``/``rate`` still render a byte-identical program
  and a byte-identical response.
* **``headers`` is untrusted input that reaches an HTTP response.** It comes
  from a drill spec, and ``ParamSpec`` has no pattern or max_length to constrain
  it, so validation has to live in the compensation layer.
"""

from __future__ import annotations

import json

import pytest

from mayhem.controller.compensation import (
    _http_headers,
    _http_proxy_source,
    compensated,
)
from mayhem.domain.catalog import definition_for
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import PlannedFault
from mayhem.domain.identity import RuntimeIdentity
from mayhem.domain.topology import ContainerNode

_RUNTIME = RuntimeIdentity(runtime="podman", host_id="h1", runtime_id="api")
_NODE = ContainerNode(
    id="ctr.api",
    name="api",
    engine="podman",
    runtime_identity=_RUNTIME,
    container_name="testcase-api",
    state="running",
)

PROXY_FAULTS = (
    "http.response_truncate",
    "dependency.response_truncate",
    "http.header_inject",
    "http.stream_stall",
    "dependency.circuit_open",
)


def _fault(fault_id: str, params: dict[str, object]) -> PlannedFault:
    return PlannedFault(
        fault_id=fault_id,
        params=definition_for(fault_id).validate_params(params),
        duration=5.0,
        targets=(),
        undo_ops=(),
        verify_probes=(),
        runtime_identity=_RUNTIME,
    )


def _program(fault_id: str, params: dict[str, object]) -> str:
    """Render the proxy program this fault would install, and check it compiles."""
    written = compensated(_fault(fault_id, params), (_NODE,))
    script = json.loads(written.undo_ops[0].args["inject_argv"])[-1]
    body = script.split("<<'MAYHEM_PY_EOF'\n", 1)[1].rsplit("MAYHEM_PY_EOF", 1)[0]
    compile(body, f"<{fault_id}>", "exec")
    return body


class TestEmittedProgramIsAlwaysValid:
    @pytest.mark.parametrize(
        ("label", "kwargs"),
        [
            ("status (pre-existing)", {"status": 500}),
            ("delay (pre-existing)", {"delay_ms": 100}),
            ("rate (pre-existing)", {"rate": 10, "burst": 5, "code": 429}),
            ("truncate", {"status": 200, "declared": 4096, "send_bytes": 64}),
            ("header_inject", {"status": 200, "headers": "X-A: 1"}),
            ("stall", {"stall_ms": 5000}),
            (
                "all combined",
                {
                    "status": 200,
                    "declared": 100,
                    "send_bytes": 10,
                    "headers": "X-A: 1",
                    "stall_ms": 1000,
                    "delay_ms": 50,
                },
            ),
        ],
    )
    def test_renders_and_compiles(self, label: str, kwargs: dict[str, int | str]) -> None:
        source = _http_proxy_source(
            target=80,
            prob=100.0,
            marker_port="/tmp/m.port",
            **kwargs,  # type: ignore[arg-type]
        )
        compile(source, f"<{label}>", "exec")


class TestPreExistingModesAreUnchanged:
    """Every new kwarg defaults to inert, so old faults render identically."""

    def test_status_mode_still_declares_content_length_zero(self) -> None:
        source = _http_proxy_source(target=80, prob=100.0, marker_port="/tmp/m.port", status=500)
        assert "declared = 0" in source
        assert "send_bytes = 0" in source
        assert "extra = ''" in source
        assert "stall_s = 0.0" in source

    def test_status_mode_emits_no_extra_bytes_or_stall(self) -> None:
        source = _http_proxy_source(target=80, prob=100.0, marker_port="/tmp/m.port", status=500)
        assert "if send_bytes:" in source  # present but never taken
        assert "if stall and not stalled:" in source

    def test_relay_still_works_when_called_without_a_stall(self) -> None:
        """The third parameter defaults to 0, so the pre-existing two-arg call is intact."""
        source = _http_proxy_source(target=80, prob=100.0, marker_port="/tmp/m.port")
        assert "def relay(a, b, stall=0.0):" in source
        assert "threading.Thread(target=relay, args=(c, s), daemon=True)" in source


class TestTruncation:
    @pytest.mark.parametrize("fault_id", ("http.response_truncate", "dependency.response_truncate"))
    def test_declares_more_than_it_sends(self, fault_id: str) -> None:
        body = _program(fault_id, {"bytes": 64})
        assert "declared = 4096" in body  # 64 * 64
        assert "send_bytes = 64" in body
        assert "c.shutdown(socket.SHUT_WR)" in body

    def test_zero_bytes_is_a_bare_head(self) -> None:
        body = _program("http.response_truncate", {"bytes": 0})
        assert "send_bytes = 0" in body


class TestHeaderInjectValidation:
    """`headers` is untrusted and lands in an HTTP response."""

    def test_accepts_a_well_formed_pair(self) -> None:
        fault = _fault("http.header_inject", {"headers": "X-Trace: abc123"})
        assert _http_headers(fault) == "X-Trace: abc123"

    def test_accepts_multiple_pairs(self) -> None:
        """A single LF is the separator; the head is rebuilt with CRLF."""
        fault = _fault("http.header_inject", {"headers": "X-A: 1\nX-B: 2"})
        assert _http_headers(fault) == "X-A: 1\r\nX-B: 2"

    @pytest.mark.parametrize(
        "value",
        [
            "X-A: 1\r\nX-Admin: true",
            "\r\nX-Admin: true",
            "X-A: 1\rX-Admin: true",
        ],
    )
    def test_refuses_cr(self, value: str) -> None:
        """The injection defence: escaping does not stop this, only refusal does."""
        with pytest.raises(InvariantViolationError, match="must not contain CR"):
            _http_headers(_fault("http.header_inject", {"headers": value}))

    @pytest.mark.parametrize(
        "value",
        [
            # a bare LF followed by something that is not a header would split
            # the response, so the second line must itself parse as a header
            "X-A: 1\n\n<script>",
            "X-A: 1\nnot-a-header",
            "\nX-Admin: true",
        ],
    )
    def test_refuses_a_line_that_is_not_a_header(self, value: str) -> None:
        """Multi-header safety comes from requiring every line to be a header."""
        with pytest.raises(InvariantViolationError, match="Name: value"):
            _http_headers(_fault("http.header_inject", {"headers": value}))

    def test_refuses_non_ascii(self) -> None:
        """`UnicodeEncodeError` is not an `OSError` and would kill the proxy thread."""
        with pytest.raises(InvariantViolationError, match="must be ASCII"):
            _http_headers(_fault("http.header_inject", {"headers": "X-A: caf\u00e9"}))

    def test_empty_is_inert(self) -> None:
        assert _http_headers(_fault("http.header_inject", {"headers": ""})) is None

    def test_value_is_embedded_as_a_safe_python_literal(self) -> None:
        """A quote in the value must not break out of the generated literal."""
        body = _program("http.header_inject", {"headers": "X-A: it's fine"})
        emitted = [line for line in body.splitlines() if line.startswith("extra = ")][-1]
        assert emitted.startswith("extra = ") and "it" in emitted
        compile(emitted + "\n", "<extra>", "exec")

    def test_circuit_open_emits_retry_after(self) -> None:
        """Retry-After is what makes a 503 observably a breaker."""
        body = _program("dependency.circuit_open", {"retry_after_s": 45})
        assert "Retry-After: 45" in body
        assert "status = 503" in body

    def test_circuit_open_never_dials_upstream(self) -> None:
        body = _program("dependency.circuit_open", {})
        dispatch = body[body.index("def handle(c):") :]
        branch = dispatch[dispatch.index("if status:") :]
        # the branch serves the canned response and returns, so the trailing
        # forward(c) -- the only dialer -- is never reached
        assert "canned(c, status)" in branch
        assert branch.index("return") < branch.index("forward(c)")


class TestStreamStall:
    def test_stalls_only_the_client_bound_pump(self) -> None:
        """Stalling both directions would deadlock the relay's join()."""
        body = _program("http.stream_stall", {"stall_ms": 4000})
        client_to_upstream = "threading.Thread(target=relay, args=(c, s), daemon=True)"
        upstream_to_client = "threading.Thread(target=relay, args=(s, c, stall_s), daemon=True)"
        assert client_to_upstream in body
        assert upstream_to_client in body
        assert ", stall_s)" in body and body.count("stall_s)") == 1

    def test_stalls_after_the_first_chunk_not_every_chunk(self) -> None:
        body = _program("http.stream_stall", {"stall_ms": 1000})
        assert "if stall and not stalled:" in body
        assert "stalled = True" in body

    def test_schema_caps_the_stall_below_the_upstream_socket_timeout(self) -> None:
        """create_connection(..., timeout=30) would otherwise tear the pump down."""
        spec = next(
            p for p in definition_for("http.stream_stall").params_schema if p.name == "stall_ms"
        )
        assert spec.maximum == 30000


class TestProxyFaultContract:
    @pytest.mark.parametrize("fault_id", PROXY_FAULTS)
    def test_declares_python_and_iptables_and_net_admin(self, fault_id: str) -> None:
        """A proxy fault runs python3 AND installs a nat REDIRECT rule."""
        from mayhem.agents.impact import REQUIREMENTS

        requirement = REQUIREMENTS[fault_id]
        assert {"python", "iptables"} <= requirement.bins
        assert "NET_ADMIN" in requirement.caps

    @pytest.mark.parametrize("fault_id", PROXY_FAULTS)
    def test_has_both_compensation_contracts(self, fault_id: str) -> None:
        written = compensated(_fault(fault_id, {}), (_NODE,))
        assert written.undo_ops and written.verify_probes

    @pytest.mark.parametrize("fault_id", PROXY_FAULTS)
    def test_undo_leaves_no_redirect_rule(self, fault_id: str) -> None:
        written = compensated(_fault(fault_id, {}), (_NODE,))
        undo = json.loads(written.undo_ops[0].args["undo_argv"])[-1]
        assert "iptables -t nat -D OUTPUT" in undo
