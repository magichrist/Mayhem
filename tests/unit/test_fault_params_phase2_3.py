"""Plan 05 Phase 2/3: the two param extensions and the one live defect.

Phase 1 of ``docs/v1.1.0/05_APP_AND_DEPENDENCY_FAULTS.md`` audited 38 candidate
faults against the catalog and returned three verdicts that are parameter work
rather than new ids. This file pins all three:

* ``http.response_truncate`` gains a ``body`` axis (the "body replace/patch"
  ask), carrying a byte-safety validator of its own — see
  :func:`_http_body` for why ``_http_headers``' rules do not transfer.
* ``dns.nxdomain`` gains an ``address`` axis, and the id/behaviour mismatch the
  audit flagged is asserted here rather than left in prose.
* ``db.slow_query`` had **no** ``port`` param and hardcoded ``3306`` in three
  places, so the family could not be aimed at Postgres (5432) or SQL Server
  (1433). That is the same defect class wave 1 found in ``db.query_error.error``:
  a knob the surface promises and the mechanism ignores. The defect is the
  reason this file exists at all.

The wave-1 lesson — *a param that exists but does nothing* — is why every axis
here has a three-distinct-output guard. A fourth test file is a cheap way to buy
a green suite and keep shipping a lie.
"""

from __future__ import annotations

import inspect
import json

import pytest

from mayhem.controller import compensation
from mayhem.controller.compensation import (
    _dns_hosts_address,
    _http_body,
    _http_proxy_source,
    compensated,
)
from mayhem.domain.catalog import definition_for
from mayhem.domain.errors import InvariantViolationError, SchemaValidationError
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
_NODES = (_NODE,)

#: The generated source is delivered inside ``cat > src <<'MAYHEM_PY_EOF'`` so
#: that the container shell does not re-expand the python. A value that can emit
#: a line break can therefore close the heredoc and have the rest of the program
#: interpreted as shell. ``repr`` is what prevents it; this is the value that
#: would prove it if it did not.
_HEREDOC = "MAYHEM_PY_EOF"


def _fault(fault_id: str, params: dict[str, object]) -> PlannedFault:
    # Go through validate_params the way the planner does.
    return PlannedFault(
        fault_id=fault_id,
        params=definition_for(fault_id).validate_params(params),
        duration=5.0,
        targets=(),
        undo_ops=(),
        verify_probes=(),
        runtime_identity=_RUNTIME,
    )


def _argv(fault_id: str, params: dict[str, object]) -> tuple[list[str], list[str]]:
    written = compensated(_fault(fault_id, params), _NODES)
    assert written.undo_ops and written.verify_probes
    op = written.undo_ops[0]
    return json.loads(op.args["inject_argv"]), json.loads(op.args["undo_argv"])


def _program(fault_id: str, params: dict[str, object]) -> str:
    """The python the fault would install, extracted and compile-checked."""
    inject, _ = _argv(fault_id, params)
    script = inject[-1]
    body = script.split(f"<<'{_HEREDOC}'\n", 1)[1].rsplit(_HEREDOC, 1)[0]
    compile(body, f"<{fault_id}>", "exec")
    return body


def _shell_around(script: str) -> str:
    """The shell that wraps the program, with the heredoc payload elided.

    This is the part a spec-supplied value must not be able to reach: it is
    what the container actually parses, and it has to be identical whatever the
    body says.
    """
    before, _, rest = script.partition(f"<<'{_HEREDOC}'\n")
    _, _, after = rest.partition(f"\n{_HEREDOC}\n")
    return before + "\n<<PAYLOAD>>\n" + after


# ── 1. http.response_truncate: the body axis ──────────────────────────────

#: Three operator bodies, each structurally different, so a regression that
#: collapsed them onto one code path would show up as equal output.
BODY_VALUES = (
    '{"items": [1, 2, 3]}',
    "<html><body>upstream died</body></html>",
    "not-json-at-all: {oops",
)


class TestTruncateBodyAxisIsLive:
    """The regression guard for a param that could go inert."""

    def test_three_bodies_produce_three_distinct_argv(self) -> None:
        """If this fails, the axis is inert again."""
        argv_by_body = {
            body: " ".join(_argv("http.response_truncate", {"body": body})[0])
            for body in BODY_VALUES
        }
        assert len(set(argv_by_body.values())) == 3, argv_by_body

    def test_three_bodies_produce_three_distinct_sources(self) -> None:
        """The argv is a shell script; the distinctness must survive into the
        generated program, which is the thing that actually runs."""
        src_by_body = {
            body: _program("http.response_truncate", {"body": body}) for body in BODY_VALUES
        }
        assert len(set(src_by_body.values())) == 3

    @pytest.mark.parametrize("body", BODY_VALUES)
    def test_the_operators_bytes_are_embedded_verbatim(self, body: str) -> None:
        source = _program("http.response_truncate", {"body": body})
        assert f"body = {body.encode('ascii')!r}" in source

    def test_absent_body_leaves_the_pre_existing_rendering_untouched(self) -> None:
        """Every new mode defaults to inert, or the other tests stop meaning
        anything: the four shipped modes must render exactly as before."""
        program = _program("http.response_truncate", {"bytes": 64})
        assert "body = " not in program
        assert "sendall(b'x' * send_bytes)" in program
        assert "declared = 4096" in program
        assert "send_bytes = 64" in program
        assert "assert len(body)" not in program

    def test_empty_body_is_inert(self) -> None:
        assert _http_body(_fault("http.response_truncate", {})) is None

    def test_the_axis_is_a_declared_catalog_param(self) -> None:
        spec = next(
            p for p in definition_for("http.response_truncate").params_schema if p.name == "body"
        )
        assert spec.default is None, "an empty default would be an inert param in the CLI listing"
        assert spec.min_length == 1

    def test_only_http_response_truncate_declares_the_axis(self) -> None:
        """``dependency.response_truncate`` shares the builder but not the
        schema. The asymmetry is deliberate; this test is what keeps it a
        decision rather than an accident."""
        with pytest.raises(SchemaValidationError):
            definition_for("dependency.response_truncate").validate_params({"body": "{}"})


class TestTruncateBodyByteSafety:
    """Why this validator is not ``_http_headers`` with the name changed."""

    def test_content_length_always_exceeds_the_delivered_body(self) -> None:
        """Rule 1 — the failure a header-shaped validator cannot see. A
        ``Content-Length`` that disagrees with the wire does not truncate, it
        hangs, and the catalog would still be describing a truncation."""
        for body in BODY_VALUES:
            program = _program("http.response_truncate", {"body": body, "bytes": 8})
            # the initialiser is emitted first; the configured value is last
            declared = int(
                [x for x in program.splitlines() if x.startswith("declared = ")][-1].split("=")[1]
            )
            assert declared == len(body) + 8 * 64
            assert declared > len(body)

    def test_the_program_trips_if_the_body_length_ever_drifts(self) -> None:
        """The literal and the declaration come from one object; the assert is
        the tripwire for a future re-encoding edit."""
        program = _program("http.response_truncate", {"body": "abc"})
        assert "assert len(body) == 3" in program

    def test_refuses_non_ascii(self) -> None:
        """Rule 2 — ``len()`` of a str is characters, not bytes. A multi-byte
        body would over- or under-declare its own length."""
        with pytest.raises(InvariantViolationError, match="must be ASCII"):
            _http_body(_fault("http.response_truncate", {"body": "café"}))

    def test_refuses_an_oversized_body(self) -> None:
        """Rule 3 — the header path has no such cap. This value rides through
        the exec argv and a heredoc as well as the wire."""
        limit = compensation._HTTP_BODY_MAX_BYTES
        with pytest.raises(InvariantViolationError, match="the limit is"):
            _http_body(_fault("http.response_truncate", {"body": "x" * (limit + 1)}))
        assert _http_body(_fault("http.response_truncate", {"body": "x" * limit})) == b"x" * limit

    def test_refuses_a_body_that_would_not_truncate(self) -> None:
        """``bytes=0`` plus a body declares exactly what it delivers, so the
        fault would report injecting a truncation and not deliver one."""
        with pytest.raises(InvariantViolationError, match="bytes >= 1"):
            _argv("http.response_truncate", {"body": "{}", "bytes": 0})

    @pytest.mark.parametrize(
        "hostile",
        [
            "MAYHEM_PY_EOF",
            "'; touch /tmp/mayhem-pwned; echo '",
            "line1\nline2",
            "back\\slash and 'quote'",
            "\x00\x01\x02",
            "closing\r\nContent-Length: 0\r\n\r\n<html>",
        ],
    )
    def test_a_hostile_body_cannot_escape_the_generated_source(self, hostile: str) -> None:
        """Rule 4 — source and heredoc safety. ``repr`` of a ``bytes`` escapes
        quotes, backslashes, newlines and non-printables, so no byte of the value
        can start a line. Asserted, not assumed: the alternative is a drill
        spec that runs as shell inside the target container."""
        script = _argv("http.response_truncate", {"body": hostile})[0][-1]
        # the value must be confined to the heredoc: neither the shell that
        # writes the program nor the shell that runs it may differ from the
        # benign case by a single character.
        benign = _argv("http.response_truncate", {"body": "benign"})[0][-1]
        assert _shell_around(script) == _shell_around(benign)
        assert script.count(f"<<'{_HEREDOC}'\n") == 1
        assert script.count(f"\n{_HEREDOC}\n") == 1, "the heredoc delimiter was injected"
        # and the python half still compiles
        _program("http.response_truncate", {"body": hostile})

    def test_a_body_may_break_its_own_framing(self) -> None:
        """The validator polices bytes, not meaning. A body that splits a
        length-prefixed frame or a JSON document is the fault, not a bug —
        refusing that would leave only well-formed responses."""
        for hostile in ("a\r\nb", '{"a": 1, "b": ', "\x00\x01\x02", "MAYHEM_PY_EOF"):
            assert _http_body(_fault("http.response_truncate", {"body": hostile})) is not None


class TestTruncateBodyOnTheWire:
    def test_the_source_uses_the_body_instead_of_the_filler(self) -> None:
        source = _http_proxy_source(
            target=80,
            prob=100.0,
            marker_port="/tmp/m.port",
            status=200,
            declared=4106,
            send_bytes=10,
            body=b'{"a": 1}',
        )
        assert "c.sendall(body)" in source
        assert "elif send_bytes:" in source
        assert "assert len(body) == 8" in source
        compile(source, "<body>", "exec")


# ── 2. dns.nxdomain: the address axis, and the id/behaviour mismatch ───────


class TestDnsNxdomainAddressAxis:
    def test_default_is_loopback_and_argv_is_byte_identical(self) -> None:
        """The original hardcoded value, so every existing drill is unchanged."""
        inject, _ = _argv("dns.nxdomain", {"domain": "internal.example"})
        assert "127.0.0.1 internal.example" in inject[-1]
        explicit = _argv("dns.nxdomain", {"domain": "internal.example", "address": "127.0.0.1"})
        assert explicit == _argv("dns.nxdomain", {"domain": "internal.example"})

    def test_three_addresses_produce_three_distinct_argv(self) -> None:
        argv_by_address = {
            address: " ".join(_argv("dns.nxdomain", {"domain": "d.example", "address": address})[0])
            for address in ("127.0.0.1", "0.0.0.0", "10.0.0.7")
        }
        assert len(set(argv_by_address.values())) == 3, argv_by_address

    def test_a_wrong_answer_can_be_aimed_at_a_real_host(self) -> None:
        """The point of the axis: NXDOMAIN's substitute answer has to point
        somewhere, and where is the interesting part."""
        inject, _ = _argv("dns.nxdomain", {"domain": "api.internal", "address": "10.0.0.7"})
        assert "10.0.0.7 api.internal" in inject[-1]

    def test_accepts_ipv6(self) -> None:
        inject, _ = _argv("dns.nxdomain", {"domain": "api.internal", "address": "::1"})
        assert "::1 api.internal" in inject[-1]

    @pytest.mark.parametrize(
        "hostile",
        [
            # shlex.quote keeps the shell safe — a newline survives as data
            # inside one single-quoted word — but `echo` still writes both
            # lines, so this would append a second, attacker-chosen hosts entry.
            "127.0.0.1\n10.0.0.1 internal.evil",
            "127.0.0.1 internal.evil # comment",
            "not-an-ip",
            "127.0.0.1; touch /tmp/mayhem-pwned",
            "",
        ],
    )
    def test_refuses_anything_that_is_not_an_ip_literal(self, hostile: str) -> None:
        with pytest.raises((InvariantViolationError, SchemaValidationError)):
            _argv("dns.nxdomain", {"domain": "d.example", "address": hostile})

    def test_the_validator_normalises_rather_than_passes_through(self) -> None:
        """``0177.0.0.1`` is accepted by ``ipaddress`` and canonicalised, so
        the hosts file gets one spelling of the address rather than two."""
        assert _dns_hosts_address(_fault("dns.nxdomain", {"address": " 127.0.0.1 "})) == "127.0.0.1"

    def test_the_axis_is_a_declared_catalog_param(self) -> None:
        spec = next(p for p in definition_for("dns.nxdomain").params_schema if p.name == "address")
        assert spec.default == "127.0.0.1"


class TestDnsNxdomainRenameHonesty:
    """The id says NXDOMAIN; the mechanism writes a hosts-file answer.

    Pinned here because a test is harder to forget than a docstring: if a future
    change makes this fault actually return RCODE 3, this fails and the id, the
    docstring and the plan have to be updated together.
    """

    def test_the_mechanism_is_a_hosts_file_append_and_nothing_else(self) -> None:
        inject, undo = _argv("dns.nxdomain", {"domain": "api.internal"})
        assert "/etc/hosts" in inject[-1]
        # no resolver is involved: no iptables, no packet filter, no proxy
        for argv in (inject, undo):
            assert not any("iptables" in part or part == "tc" for part in argv)
        assert "mv -f" in undo[-1], "undo must restore the original hosts file"

    def test_the_compensation_verifies_the_hosts_file_is_back(self) -> None:
        written = compensated(_fault("dns.nxdomain", {"domain": "api.internal"}), _NODES)
        raw = written.verify_probes[0].args["cmd"]
        assert isinstance(raw, list)
        cmd = " ".join(str(part) for part in raw)
        assert "orig" in cmd

    def test_the_plan_document_records_the_mismatch(self) -> None:
        from pathlib import Path

        plan = Path(__file__).resolve().parents[2] / "docs/v1.1.0/05_APP_AND_DEPENDENCY_FAULTS.md"
        text = plan.read_text(encoding="utf-8")
        assert "hosts-file answer" in text, (
            "docs honesty: the NXDOMAIN/hosts-file mismatch must be stated"
        )


# ── 3. db.slow_query: the hardcoded-port defect ───────────────────────────


class TestDbSlowQueryPortIsLive:
    """The incident defect. Before this, `port` did not exist on the id at all
    and `3306` appeared as a literal three times in the builder."""

    def test_default_is_3306_and_argv_is_byte_identical(self) -> None:
        """No existing drill changes behaviour."""
        assert _argv("db.slow_query", {"mode": "timeout"}) == _argv(
            "db.slow_query", {"mode": "timeout", "port": 3306}
        )

    @pytest.mark.parametrize("mode", ["latency", "timeout"])
    def test_three_ports_produce_three_distinct_argv(self, mode: str) -> None:
        """If this fails, the port is a lie again."""
        argv_by_port = {
            port: " ".join(_argv("db.slow_query", {"mode": mode, "port": port})[0])
            for port in (3306, 5432, 1433)
        }
        assert len(set(argv_by_port.values())) == 3, argv_by_port

    def test_latency_mode_scopes_the_netem_filter_to_the_named_port(self) -> None:
        inject, undo = _argv("db.slow_query", {"mode": "latency", "port": 5432, "seconds": 2})
        body = " ".join(inject)
        assert "match ip dport 5432" in body
        assert "3306" not in body, "a stale default leaked into the netem filter"
        assert undo == ["@engine", "exec", "@cont", "sh", "-c", "tc qdisc del dev eth0 root"]

    def test_timeout_mode_drops_on_the_named_port(self) -> None:
        inject, undo = _argv("db.slow_query", {"mode": "timeout", "port": 1433})
        joined = " ".join(inject)
        assert "--dport 1433" in joined
        assert "DROP" in inject
        assert "3306" not in joined
        assert "--dport 1433" in " ".join(undo)

    @pytest.mark.parametrize("mode", ["latency", "timeout"])
    @pytest.mark.parametrize("port", [3306, 5432, 1433])
    def test_the_verify_probe_follows_the_port(self, mode: str, port: int) -> None:
        written = compensated(_fault("db.slow_query", {"mode": mode, "port": port}), _NODES)
        raw = written.verify_probes[0].args["cmd"]
        assert isinstance(raw, list)
        cmd = " ".join(str(part) for part in raw)
        if mode == "timeout":
            assert f"--dport {port}" in cmd
        else:
            # the netem qdisc probe is port-agnostic by construction: undo
            # deletes the whole root, so there is no per-port residue to check.
            assert "netem" in cmd

    def test_the_schema_mirrors_db_query_error(self) -> None:
        """The omission was a defect rather than a house style precisely
        because the sibling fault in the same family already had this param."""
        slow = {p.name: p for p in definition_for("db.slow_query").params_schema}
        error = {p.name: p for p in definition_for("db.query_error").params_schema}
        assert slow["port"].default == error["port"].default == 3306
        assert (slow["port"].minimum, slow["port"].maximum) == (
            error["port"].minimum,
            error["port"].maximum,
        )

    def test_out_of_range_ports_are_refused_by_the_schema(self) -> None:
        for bad in (0, 65536):
            with pytest.raises(SchemaValidationError):
                definition_for("db.slow_query").validate_params({"port": bad})

    def test_the_builder_no_longer_hardcodes_a_port(self) -> None:
        """A source-level guard. The defect was a *literal* used as the fault's
        port, so the regression to guard against is a literal reappearing — an
        argv-only test would still pass if someone reintroduced 3306 for a
        fourth code path. ``3306`` is allowed in exactly one place now: as the
        documented fallback handed to ``_param_netfilter``/``_iparam``, which is
        what makes the default 3306 rather than 0."""
        for fn in (compensation._db_slow_query_undo, compensation._db_slow_query_verify):
            source = inspect.getsource(fn)
            offenders = [
                line.strip()
                for line in source.splitlines()
                if "3306" in line
                and not line.strip().startswith(("return _param_netfilter", "port = _iparam"))
            ]
            assert offenders == [], f"{fn.__name__} hardcodes a port again: {offenders}"
            reads_the_param = (
                '_iparam(fault, "port", 3306)' in source
                or '_param_netfilter("port", "tcp", "DROP", [], 3306)' in source
                or '_param_netfilter_verify("port", 3306)' in source
            )
            assert reads_the_param, f"{fn.__name__} ignores the port param"

    def test_the_impact_requirement_still_matches_the_tooling(self) -> None:
        """No new id, so no REQUIREMENTS change — but the axis now reaches two
        different binaries depending on mode, and the gate must require both."""
        from mayhem.agents.impact import REQUIREMENTS

        assert {"tc", "iptables"} <= REQUIREMENTS["db.slow_query"].bins
