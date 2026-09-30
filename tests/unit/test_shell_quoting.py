"""Shell-injection regression guards for compensation command builders.

Every ``sh -c`` body in :mod:`mayhem.controller.compensation` is re-parsed by a
shell *inside the target container*, so a value taken from a drill spec and
interpolated raw into one of those bodies is remote code execution. These tests
pin the two disciplines that prevent it, matching the patterns already used by
``_fs_corrupt_undo`` and ``_net_device``:

* a value that must be **one shell word** (a path, a filename) is passed
  through :func:`shlex.quote`;
* a value that must be **a number or a grammar token** (a port, a duration, a
  device or protocol name) is **validated and refused**, never quoted — quoting
  a number would turn a spec error into a silently wrong command.

The common case must be untouched: ``shlex.quote`` is a no-op for an ordinary
path, so the argv for a normal spec stays byte-identical. Several tests below
assert that exact-argv property so a future "be safe by quoting everything"
change is caught.
"""

from __future__ import annotations

import json
import shlex

import pytest

from mayhem.controller.compensation import template_for
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import PlannedFault
from mayhem.domain.topology import ProcessNode, ServiceNode

# A path that, unquoted, ends the ``mount`` command and runs a second one.
INJECTION = "/; touch /tmp/mayhem-pwned; #"
# A domain that closes the single-quoted echo argument and appends a command.
DOMAIN_INJECTION = "evil.com'; touch /tmp/mayhem-pwned; echo '"


def _tool_fault(fault_id: str, **params: object) -> PlannedFault:
    return PlannedFault(fault_id=fault_id, targets=(), params=params or {}, duration=10.0)


def _nodes() -> tuple[ServiceNode, ProcessNode]:
    return (
        ServiceNode(id="svc-api", name="api", container_name="testcase-api"),
        ProcessNode(id="p-api", name="api", pid=4242, host_id="h1", container_name=None),
    )


def _build(fault_id: str, **params: object) -> tuple[list, list]:
    template = template_for(fault_id)
    assert template is not None, f"no compensation template for {fault_id}"
    ops, probes = template.build(_tool_fault(fault_id, **params), _nodes())
    return list(ops), list(probes)


def _shell_bodies(fault_id: str, **params: object) -> list[str]:
    """Every ``sh -c`` script reachable from a fault's undo ops and probes.

    The container-exec wrapper (``@engine exec @cont``) is stripped so the
    assertions below look only at what the shell will actually parse.
    """
    ops, probes = _build(fault_id, **params)
    argv_lists = [json.loads(op.args["inject_argv"]) for op in ops]
    argv_lists += [json.loads(op.args["undo_argv"]) for op in ops]
    argv_lists += [list(probe.args["cmd"]) for probe in probes]

    bodies: list[str] = []
    for argv in argv_lists:
        if "sh" in argv and "-c" in argv:
            bodies.append(argv[argv.index("-c") + 1])
    return bodies


# ── the primary defect: fs.read_only interpolated `path` raw ──────────────


def test_fs_read_only_malicious_path_is_quoted_into_one_token() -> None:
    """The reported defect: a ``;`` in ``path`` must not start a second command.

    Quoting means the whole hostile string survives as a single shell *word*:
    ``mount`` fails on it (which is correct — it is not a mount point) but
    nothing is executed.
    """
    bodies = _shell_bodies("fs.read_only", path=INJECTION)
    # The verify probe body carries only the marker, so assert on the bodies
    # that actually mention the path (the inject and the undo).
    bodies = [body for body in bodies if INJECTION in body]

    assert bodies, "fs.read_only must interpolate path into an sh -c body"
    for body in bodies:
        # The hostile path appears only inside a single-quoted token, so the
        # shell never sees the `;` as a command separator.
        assert f"'{INJECTION}'" in body, f"path was not quoted: {body!r}"
        outside = _strip_quoted(body)
        assert INJECTION not in outside, f"unquoted path reached the shell: {body!r}"
        assert ";" not in outside, f"unquoted `;` reached the shell: {body!r}"
        assert "mayhem-pwned" not in outside, f"injected command is live: {body!r}"


def test_fs_read_only_command_substitution_in_path_is_quoted() -> None:
    """``$(...)`` is the other half of the surface: it runs even with no ``;``."""
    bodies = _shell_bodies("fs.read_only", path="/$(touch /tmp/mayhem-pwned)")
    bodies = [body for body in bodies if "$(touch" in body]

    assert bodies, "fs.read_only must interpolate path into an sh -c body"
    for body in bodies:
        assert "'/$(touch /tmp/mayhem-pwned)'" in body, f"path was not quoted: {body!r}"
        outside = _strip_quoted(body)
        assert "$(touch" not in outside, f"command substitution reached the shell: {body!r}"


def test_fs_read_only_normal_path_argv_is_byte_identical() -> None:
    """Regression guard: the ordinary case must not gain quotes.

    ``shlex.quote`` only quotes when it must, so ``/`` and ``/var/log`` produce
    exactly the argv that shipped before the fix.
    """
    ops, _ = _build("fs.read_only", path="/")
    inject = json.loads(ops[0].args["inject_argv"])
    undo = json.loads(ops[0].args["undo_argv"])

    assert "mount -o remount,ro /" in inject
    assert any("mount -o remount,rw /" in part for part in undo)

    ops, _ = _build("fs.read_only", path="/var/log")
    inject = json.loads(ops[0].args["inject_argv"])
    assert "mount -o remount,ro /var/log" in inject
    # An absolute path with no metacharacters must not be wrapped in quotes.
    assert "'/var/log'" not in " ".join(inject)


# ── every builder that takes a user value into an sh -c body ──────────────

#: (fault_id, hostile params, benign params, the raw user value that must not
#: reach the shell). Each entry pairs a builder with the spec value that would
#: break out of an unquoted interpolation, plus the same builder driven with a
#: harmless value so the test can diff the emitted shell operators.
_USER_VALUE_BUILDERS = [
    ("fs.read_only", {"path": INJECTION}, {"path": "/benign"}, INJECTION),
    ("fs.corrupt", {"path": INJECTION}, {"path": "/benign"}, INJECTION),
    (
        "dns.nxdomain",
        {"domain": DOMAIN_INJECTION},
        {"domain": "benign.example.com"},
        DOMAIN_INJECTION,
    ),
    (
        "process.crash_loop",
        {"interval": "2s; touch /tmp/mayhem-pwned"},
        {"interval": "2s"},
        "2s; touch /tmp/mayhem-pwned",
    ),
    (
        "process.restart_delay",
        {"delay": "5s; touch /tmp/mayhem-pwned"},
        {"delay": "5s"},
        "5s; touch /tmp/mayhem-pwned",
    ),
    (
        "dependency.flap",
        {"protocol": "tcp; touch /tmp/mayhem-pwned"},
        {"protocol": "tcp"},
        "tcp; touch /tmp/mayhem-pwned",
    ),
    (
        "dependency.block",
        {"protocol": "tcp; touch /tmp/mayhem-pwned"},
        {"protocol": "tcp"},
        "tcp; touch /tmp/mayhem-pwned",
    ),
]


@pytest.mark.parametrize(
    ("fault_id", "params", "baseline_params", "raw"),
    _USER_VALUE_BUILDERS,
    ids=[case[0] for case in _USER_VALUE_BUILDERS],
)
def test_no_raw_user_value_reaches_shell_unquoted(
    fault_id: str, params: dict, baseline_params: dict, raw: str
) -> None:
    """Table-driven: no user param may land unquoted inside an ``sh -c`` body.

    A builder that *validates* its input refuses and raises, so it yields no
    body at all — which is the correct outcome and is why
    ``InvariantViolationError`` is allowed here. What must never happen is a
    body in which the user value became shell syntax.
    """
    try:
        bodies = _shell_bodies(fault_id, **params)
    except InvariantViolationError:
        return  # refused at plan time: the value never reaches a shell

    for index, body in enumerate(bodies):
        baseline = _shell_bodies(fault_id, **baseline_params)[index]

        # A correctly-quoted value survives as one intact token; an unquoted
        # one would be shredded into several words. Builders may legitimately
        # derive a *different* token from the value (fs.corrupt appends
        # `.mayhem-orig`), so only check tokens that start with the raw value.
        tokens = shlex.split(body)
        for token in tokens:
            if token.startswith(raw):
                assert token == raw or token.startswith(f"{raw}."), (
                    f"{fault_id}: user value was split across shell words: {token!r}"
                )

        # Differential check: the shell *operators* in the body must be exactly
        # the ones the builder emits for a benign value. A user value that
        # contributed its own `;`/`&&`/pipe would add operators here, which is
        # what turns data into a second command.
        operators = _shell_operators(tokens) - _shell_operators(shlex.split(baseline))
        assert not operators, (
            f"{fault_id}: user value introduced shell operators {sorted(operators)} in {body!r}"
        )

        # Nothing outside a quoted span may name the injected side effect.
        assert "mayhem-pwned" not in _strip_quoted(body), (
            f"{fault_id}: injected command is live in {body!r}"
        )


_SHELL_OPERATORS = {";", "&&", "||", "|", "&", ">", ">>", "<", "2>", "&>", ";;", "\n"}


def _shell_operators(tokens: list[str]) -> set[str]:
    return {token for token in tokens if token in _SHELL_OPERATORS}


def _strip_quoted(text: str) -> str:
    """Remove every quoted span (single or double), leaving bare shell text.

    Deleting the quoted regions rather than trying to un-escape them means a
    correctly-quoted hostile value disappears entirely, which is exactly the
    property under test: it is inert data, never shell syntax.
    """
    out: list[str] = []
    quote: str | None = None
    for char in text:
        if quote is None:
            if char in "'\"":
                quote = char
            else:
                out.append(char)
        elif char == quote:
            quote = None
    return "".join(out)


# ── numbers and grammar tokens are validated, not quoted ──────────────────


@pytest.mark.parametrize(
    ("fault_id", "params"),
    [
        ("process.crash_loop", {"interval": "2s; touch /tmp/mayhem-pwned"}),
        ("process.crash_loop", {"interval": "$(id)"}),
        ("process.crash_loop", {"interval": "2s && touch /tmp/mayhem-pwned"}),
        ("process.restart_delay", {"delay": "5s; rm -rf /"}),
        ("process.restart_delay", {"delay": "`id`"}),
        ("dependency.flap", {"protocol": "tcp; touch /tmp/mayhem-pwned"}),
        ("dependency.block", {"protocol": "tcp -j ACCEPT"}),
        ("net.mtu_mismatch", {"device": "eth0; touch /tmp/mayhem-pwned"}),
    ],
)
def test_out_of_grammar_params_are_refused_not_quoted(fault_id: str, params: dict) -> None:
    """A value outside its grammar is refused, rather than quoted and passed on.

    Quoting would turn a spec error into a command that runs and quietly does
    the wrong thing; refusing keeps the failure at plan time where the operator
    sees it.
    """
    with pytest.raises(InvariantViolationError):
        _build(fault_id, **params)


@pytest.mark.parametrize("value", ["2s", "5s", "30", "1.5s", "10m", "1h"])
def test_valid_sleep_durations_are_accepted_unchanged(value: str) -> None:
    """The duration grammar accepts real specs, and they pass through verbatim."""
    ops, _ = _build("process.crash_loop", restarts=2, interval=value)
    body = json.loads(ops[0].args["inject_argv"])[-1]
    assert f"sleep {value}" in body
    assert f"sleep '{value}'" not in body


@pytest.mark.parametrize("value", ["0", "1", "80", "65535"])
def test_valid_protocols_are_accepted_unchanged(value: str) -> None:
    """A legitimate protocol name still reaches the argv unquoted."""
    ops, _ = _build("dependency.block", port=3306, protocol=value)
    inject = json.loads(ops[0].args["inject_argv"])
    assert inject[inject.index("-p") + 1] == value


def test_net_mtu_rejects_out_of_range_numeric() -> None:
    """A numeric param is range-checked, never quoted, so a bad one is refused."""
    with pytest.raises(InvariantViolationError):
        _build("net.mtu_mismatch", device="eth0", mtu=99)
    with pytest.raises(InvariantViolationError):
        _build("net.mtu_mismatch", device="eth0", mtu=99999)
    # The in-range value is unaffected.
    ops, _ = _build("net.mtu_mismatch", device="eth0", mtu=1400)
    assert "mtu 1400" in json.loads(ops[0].args["inject_argv"])[-1]
