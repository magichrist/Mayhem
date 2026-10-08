"""Phase 2 — network-policy enforcement across every external call (gap 77).

Phase 1 (:mod:`mayhem.domain.deployment`) decided whether a host *may* be
reached and refused policies that contradict themselves, but it read no
environment, opened no socket, and loaded no CA file — the domain layer cannot.
This module is the other half: it takes the same
:class:`~mayhem.domain.deployment.NetworkPolicy` declaration and makes it bind,
so the plan's rule — *"every external call honors proxy/CA configuration or
fails closed with the cause named"* — is a property of a call path rather than a
sentence in a document.

Four things are enforced, and each of them has one honest enforcement point:

**Policy resolution is a pure function.** :func:`resolve_policy` takes a policy
(and optionally the deployment model) and returns a :class:`PolicyResolution`.
It touches no file, no socket, and no clock, so it is testable by construction
and the *only* thing that can turn a declaration into a usable configuration.
:func:`resolve_egress` is pure for the same reason, and it delegates the actual
reachability question to Phase 1's :func:`~mayhem.domain.deployment.egress_decision`
rather than reimplementing it — there is one allowlist matcher in this codebase,
not two.

**The air gap fails closed, loudly.** Every refusal carries a stable rule id
(``network_policy.air_gapped``, ``network_policy.allowlist_denied``,
``network_policy.proxy_not_allowed``, ``network_policy.ca_bundle_unreadable``,
``network_policy.unresolved``, ``network_policy.unparseable_url``) alongside the
human reason. A blocked call that cannot say why is a blocked call somebody
debugs by turning the policy off, so there is no path through this module that
returns a denial without a cause and a name.

**A proxy is a route, not a bypass.** When a policy declares a proxy for a
scheme, the call is answered by asking whether *the proxy itself* is reachable.
A proxy the allowlist does not name is refused
(``network_policy.proxy_not_allowed``) rather than quietly replaced with a
direct connection — a direct connection is exactly the egress the operator
installed the proxy to prevent.

**A declared CA is verified or the call is refused.** Phase 1 was explicit that
``custom_ca_bundle`` is a *reference*, not a read. :func:`resolve_ca_bundle`
performs that read through an injected reader and reports what it parsed;
:class:`NetworkPolicyGuard` then refuses every HTTPS call while a declared
bundle is unverified. Declaring a CA and not shipping it does not degrade to
"platform default" — it is a refusal, because silently losing a verification
step is worse than refusing the call.

The enforcement seam is :class:`NetworkPolicyGuard`, and it is the *only* holder
of an :class:`EgressTransport`. Two ways in:

* :meth:`NetworkPolicyGuard.fetch` for a call this codebase makes itself;
* :meth:`NetworkPolicyGuard.opener` for a call somebody else's helper makes —
  it returns an ``opener`` callable with the signature
  :func:`mayhem.observability.base.fetch_json` already accepts, so the
  existing connectors are guarded by passing one argument rather than by being
  rewritten.

One limit stated plainly rather than papered over: this guard governs the calls
*Mayhem* makes. Image pulls are performed by the container runtime, so the
sandbox provisioner resolves the policy for every registry host **before** it
issues the command that pulls (:mod:`mayhem.controller.sandbox_service` refuses
on a denied resolution). That is a pre-flight gate, not an interception of the
runtime's own socket traffic, and this module does not claim to be one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable
from urllib.parse import urlsplit

from mayhem.domain.deployment import (
    NetworkPolicy,
    air_gap_refusal,
    deployment_profile,
    egress_decision,
    network_policy_problems,
)
from mayhem.domain.errors import InvariantViolationError

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import Any

__all__ = [
    "RULE_AIR_GAPPED",
    "RULE_ALLOWLIST_DENIED",
    "RULE_CA_BUNDLE_UNREADABLE",
    "RULE_EGRESS_PERMITTED",
    "RULE_NO_TRANSPORT",
    "RULE_PROXY_NOT_ALLOWED",
    "RULE_PROXY_UNRESOLVED",
    "RULE_TRANSPORT_FAILED",
    "RULE_UNPARSEABLE_URL",
    "RULE_UNRESOLVED_POLICY",
    "CaResolution",
    "EgressAttempt",
    "EgressRefusedError",
    "EgressRequest",
    "EgressResolution",
    "EgressTransport",
    "GuardedResponse",
    "NetworkPolicyGuard",
    "PolicyResolution",
    "proxy_for",
    "resolve_ca_bundle",
    "resolve_egress",
    "resolve_egress_url",
    "resolve_policy",
]

#: Stable rule ids. Every refusal in this module starts with one, so a test and a
#: log line refer to the same fact and a rewording of the prose does not break
#: either.
RULE_UNRESOLVED_POLICY = "network_policy.unresolved"
RULE_AIR_GAPPED = "network_policy.air_gapped"
RULE_ALLOWLIST_DENIED = "network_policy.allowlist_denied"
RULE_EGRESS_PERMITTED = "network_policy.egress_permitted"
RULE_PROXY_NOT_ALLOWED = "network_policy.proxy_not_allowed"
RULE_PROXY_UNRESOLVED = "network_policy.proxy_unresolved"
RULE_CA_BUNDLE_UNREADABLE = "network_policy.ca_bundle_unreadable"
RULE_UNPARSEABLE_URL = "network_policy.unparseable_url"
RULE_NO_TRANSPORT = "network_policy.no_transport"
RULE_TRANSPORT_FAILED = "network_policy.transport_failed"

#: The scheme default, used only to report which route a call would take. The
#: port is deliberately *not* inferred for the allowlist check: Phase 1 defines
#: an entry carrying a port as matching any call to that host when the caller
#: stated no port, and inferring one here would quietly narrow that.
_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}


class EgressRefusedError(InvariantViolationError):
    """An external call was refused by policy. The cause is always named.

    A distinct type rather than a bare :class:`InvariantViolationError` because
    the two mean different things to whoever catches them: this one is an
    operational refusal an operator can act on (permit the host, declare the air
    gap, fix the bundle), and it is the exception an air-gapped install should
    see instead of a socket error three frames deeper.
    """

    def __init__(self, rule: str, message: str) -> None:
        super().__init__(rule, message)
        self.rule = rule
        self.decision = message


# -- policy resolution (pure) ----------------------------------------------------


@dataclass(frozen=True, slots=True)
class PolicyResolution:
    """Whether a declared policy may be enforced, and every reason it may not.

    ``problems`` is Phase 1's own ``network_policy_problems`` output plus the
    deployment-model cross-check (:func:`~mayhem.domain.deployment.air_gap_refusal`),
    carried unchanged rather than summarised, so a caller can render an operator
    all of them at once instead of one per run of the tool.

    ``requires_egress`` is the deployment profile's own answer and is ``None``
    when no model was supplied — an unknown deployment model is not the same as
    one that needs no egress.
    """

    policy: NetworkPolicy
    model: object | None
    resolved: bool
    problems: tuple[tuple[str, str], ...]
    requires_egress: bool | None

    @property
    def air_gapped(self) -> bool:
        return self.policy.air_gapped

    @property
    def rule_id(self) -> str:
        """The rule that refused the policy, or ``""`` when it resolved."""
        return self.problems[0][0] if self.problems else ""

    @property
    def reason(self) -> str:
        """The first refusal reason, or ``""`` when the policy resolved."""
        return self.problems[0][1] if self.problems else ""

    def refusal(self) -> str:
        """``"<rule_id>: <reason>"``, or ``""``."""
        if self.resolved:
            return ""
        return f"{self.rule_id}: {self.reason}"


def resolve_policy(policy: NetworkPolicy, *, model: object | None = None) -> PolicyResolution:
    """Decide whether ``policy`` may be enforced. Pure: no file, socket, or clock.

    Two refusals, both carried by name. Phase 1's own validation problems (an
    air gap declared alongside an allowlist, a bare ``*`` entry, a malformed
    entry, a proxy with no addressable scheme) and the cross-check between the
    deployment model and the policy's air-gap flag. The second is the one this
    module adds, because the two declarations are made by different people in
    different files and an install configured as air-gapped whose policy forgot
    to say so would pass every check that read only one of them.

    An unresolvable policy is not an error to raise from here — it is a decision
    that happens to be "no", so that every caller of this function fails closed
    by construction rather than by remembering to.
    """
    problems: list[tuple[str, str]] = list(network_policy_problems(policy))
    requires_egress: bool | None = None
    if model is not None:
        requires_egress = bool(deployment_profile(model).requires_egress)  # type: ignore[arg-type]
        mismatch = air_gap_refusal(model, policy)  # type: ignore[arg-type]
        if mismatch:
            rule, _, reason = mismatch.partition(": ")
            problems.append((rule or RULE_UNRESOLVED_POLICY, reason or mismatch))
    return PolicyResolution(
        policy=policy,
        model=model,
        resolved=not problems,
        problems=tuple(problems),
        requires_egress=requires_egress,
    )


# -- egress resolution (pure) -----------------------------------------------------


@dataclass(frozen=True, slots=True)
class EgressRequest:
    """A parsed destination: scheme, host, and the port only if the URL said so."""

    url: str
    scheme: str
    host: str
    port: int | None


@dataclass(frozen=True, slots=True)
class EgressResolution:
    """Whether one destination may be reached, and by what route.

    ``via_proxy`` is the proxy URL the call must go through when the policy
    declares one, and ``""`` for a direct call. It is carried on the *permit*
    rather than applied by the caller afterwards, so a guarded call cannot
    reach a transport by forgetting to route itself.

    ``rule_id`` is stable and the reason is a sentence naming the cause. The
    pair is the whole point of the type: ``allowed=False`` with no cause is the
    failure that gets debugged by disabling the policy.
    """

    host: str
    port: int | None
    allowed: bool
    rule_id: str
    reason: str
    via_proxy: str = ""
    scheme: str = ""

    @property
    def refused(self) -> bool:
        return not self.allowed

    def refusal(self) -> str:
        """``"<rule_id>: <reason>"`` when refused, ``""`` when permitted."""
        return "" if self.allowed else f"{self.rule_id}: {self.reason}"

    def describe(self) -> str:
        route = f" via {self.via_proxy}" if self.via_proxy else " directly"
        return f"[{self.rule_id}] {self.host}{route}: {self.reason}"


def parse_egress_request(url: str) -> EgressRequest | None:
    """Parse ``url`` into a destination, or ``None`` when it names none.

    ``None`` for a missing scheme, a non-HTTP scheme, or a missing host. A
    refusal for those is deliberate: Mayhem's own external calls are HTTP(S),
    and a URL this function cannot read is a URL no allowlist could be matched
    against, so permitting it would be permitting everything.
    """
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return None
    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        return None
    try:
        port: int | None = parts.port
    except ValueError:
        return None
    if port is None:
        port = None
    return EgressRequest(url=url, scheme=scheme, host=host, port=port)


def proxy_for(policy: NetworkPolicy, scheme: str) -> str:
    """The proxy ``policy`` declares for ``scheme``, or ``""`` for a direct call.

    Unknown schemes get ``""`` because a policy that names no route for a
    protocol has no route for it; the caller then answers a direct-permitted
    decision with an empty ``via_proxy``, which is the honest description of
    what will happen.
    """
    normalised = scheme.strip().lower()
    if normalised == "http":
        return policy.http_proxy
    if normalised == "https":
        return policy.https_proxy
    return ""


def _proxy_destination(proxy_url: str) -> tuple[str, int | None] | None:
    """``(host, port)`` for a proxy URL, or ``None`` when it names no host."""
    parts = urlsplit(proxy_url if "://" in proxy_url else f"http://{proxy_url}")
    host = (parts.hostname or "").strip().lower().rstrip(".")
    if not host:
        return None
    try:
        return host, parts.port
    except ValueError:
        return None


def _allow(policy: NetworkPolicy, host: str, port: int | None) -> EgressResolution:
    """The reachability answer, delegated to Phase 1's matcher.

    No proxy consideration, because this is the question "may this host be
    reached at all" and it is asked once per destination *and* once per proxy.
    Phase 1's :func:`~mayhem.domain.deployment.egress_decision` stays the single
    allowlist matcher in the codebase.
    """
    decision = egress_decision(policy, host, port=port)
    if decision.allowed:
        rule = RULE_EGRESS_PERMITTED
    elif policy.air_gapped:
        rule = RULE_AIR_GAPPED
    else:
        rule = RULE_ALLOWLIST_DENIED
    return EgressResolution(
        host=decision.host,
        port=port,
        allowed=decision.allowed,
        rule_id=rule,
        reason=decision.reason,
    )


def _refuse(
    host: str,
    port: int | None,
    rule_id: str,
    reason: str,
    scheme: str,
    *,
    allowed: bool = False,
    via_proxy: str = "",
) -> EgressResolution:
    """One refusal (or, with ``allowed``, one permit) in the shared shape.

    Every branch of :func:`resolve_egress` builds its answer here, so there is a
    single place where ``allowed``, the stable rule id, and the human reason are
    attached to each other and a future branch cannot answer with two of the three.
    """
    return EgressResolution(
        host=host,
        port=port,
        allowed=allowed,
        rule_id=rule_id,
        reason=reason,
        via_proxy=via_proxy,
        scheme=scheme,
    )


def _route_through_proxy(
    policy: NetworkPolicy,
    direct: EgressResolution,
    proxy: str,
    *,
    port: int | None,
    scheme: str,
) -> EgressResolution:
    """Answer a reachable destination that the policy routes through ``proxy``.

    A proxy that names no host, and a proxy the allowlist does not reach, both
    refuse. Neither degrades to a direct connection: that fallback is precisely
    the egress the operator installed the proxy to prevent, and a policy that
    cannot be honoured is a refusal rather than a preference.
    """
    destination = _proxy_destination(proxy)
    if destination is None:
        return _refuse(
            direct.host,
            port,
            RULE_PROXY_UNRESOLVED,
            f"the policy routes {scheme} through {proxy!r}, which names no proxy host, so the "
            "call has no sanctioned route; sending it directly would be an egress the operator "
            "installed a proxy to prevent",
            scheme,
        )
    proxy_host, proxy_port = destination
    proxy_check = _allow(policy, proxy_host, proxy_port)
    if proxy_check.refused:
        return _refuse(
            direct.host,
            port,
            RULE_PROXY_NOT_ALLOWED,
            f"the policy routes {scheme} through {proxy!r}, but the proxy itself {proxy_host} "
            f"is not reachable under this policy ({proxy_check.reason}). Falling back to a "
            "direct connection would be an egress the operator did not sanction, so the call "
            "is refused",
            scheme,
        )
    return _refuse(
        direct.host,
        port,
        RULE_EGRESS_PERMITTED,
        f"{direct.host} matches the outbound allowlist and is routed through the declared "
        f"{scheme} proxy {proxy!r}; {proxy_check.reason}",
        scheme,
        allowed=True,
        via_proxy=proxy,
    )


def resolve_egress(
    policy: NetworkPolicy,
    host: str,
    *,
    port: int | None = None,
    scheme: str = "https",
    model: object | None = None,
    resolution: PolicyResolution | None = None,
) -> EgressResolution:
    """Whether ``host`` may be reached under ``policy``, and by which route. Pure.

    Order is the substance of this function:

    1. an unresolvable policy refuses *everything* with the policy's own named
       cause, so a contradictory configuration cannot be partly enforced;
    2. an unnamed host refuses, because a destination nobody can name is one no
       allowlist can be matched against;
    3. reachability is asked first — an air-gapped or unlisted destination is
       refused whether it would have been routed through a proxy or not;
    4. only a reachable destination is then routed, and a declared proxy that is
       itself unreachable refuses the call rather than degrading it to a direct
       connection.

    ``resolution`` lets a caller resolve the policy once and reuse it, which is
    what :class:`NetworkPolicyGuard` does; ``model`` is only read when
    ``resolution`` is not supplied.
    """
    verdict = resolution if resolution is not None else resolve_policy(policy, model=model)
    target = host.strip().lower().rstrip(".")
    if not target:
        return _refuse(
            host,
            port,
            RULE_UNPARSEABLE_URL,
            "no host was named, so this call has no destination to check against the outbound "
            "allowlist; an unnamed destination is not a permitted one",
            scheme,
        )
    if not verdict.resolved:
        return _refuse(
            target,
            port,
            verdict.rule_id or RULE_UNRESOLVED_POLICY,
            "the declared network policy is inadmissible, so no egress is permitted: "
            f"{verdict.reason}. Fix the policy or remove the conflicting declaration; mayhem "
            "will not enforce half of it",
            scheme,
        )
    direct = _allow(policy, target, port)
    if direct.refused:
        return _refuse(direct.host, port, direct.rule_id, direct.reason, scheme)
    proxy = proxy_for(policy, scheme)
    if not proxy:
        return _refuse(
            direct.host, port, RULE_EGRESS_PERMITTED, direct.reason, scheme, allowed=True
        )
    return _route_through_proxy(policy, direct, proxy, port=port, scheme=scheme)


def resolve_egress_url(
    policy: NetworkPolicy,
    url: str,
    *,
    model: object | None = None,
    resolution: PolicyResolution | None = None,
) -> EgressResolution:
    """:func:`resolve_egress` for a URL, refusing a URL that names no destination."""
    parsed = parse_egress_request(url)
    if parsed is None:
        return EgressResolution(
            host=url,
            port=None,
            allowed=False,
            rule_id=RULE_UNPARSEABLE_URL,
            reason=(
                f"{url!r} is not an http(s) URL with a host, so this call cannot be matched "
                "against the outbound allowlist; mayhem's own external calls are http(s) and "
                "a destination it cannot read is one it cannot police"
            ),
        )
    return resolve_egress(
        policy,
        parsed.host,
        port=parsed.port,
        scheme=parsed.scheme,
        model=model,
        resolution=resolution,
    )


# -- custom CA (IO behind an injected reader) -------------------------------------


@dataclass(frozen=True, slots=True)
class CaResolution:
    """What happened when the declared CA bundle reference was resolved.

    ``declared`` is the reference as written and ``byte_count`` is what the
    reader actually returned — the two are reported side by side so a policy
    pointing at a bundle that resolves to nothing is visible rather than
    assumed. ``verified`` is ``True`` only for a reference that was read and
    parsed into a non-empty payload.
    """

    declared: str
    verified: bool
    byte_count: int
    rule_id: str
    reason: str

    @property
    def declared_and_unverified(self) -> bool:
        return bool(self.declared) and not self.verified

    @property
    def refusal(self) -> str:
        return "" if not self.declared_and_unverified else f"{self.rule_id}: {self.reason}"


def resolve_ca_bundle(
    policy: NetworkPolicy, reader: Callable[[str], bytes] | None = None
) -> CaResolution:
    """Resolve ``policy.custom_ca_bundle`` through ``reader``; fail closed if it fails.

    ``reader`` is injected because reading a file is IO and this module's other
    halves are pure; the unit suite supplies a mapping and the CLI will supply a
    path read. Four ways to end up unverified, all of which refuse: no bundle
    declared (which is not a failure and is reported as such), no reader
    supplied, the reader raised, or the payload was empty. "Declared but
    unreadable" never degrades to "platform default".
    """
    declared = policy.custom_ca_bundle.strip()
    if not declared:
        return CaResolution(
            declared="",
            verified=False,
            byte_count=0,
            rule_id="",
            reason=(
                "no custom CA bundle is declared, so TLS verification is the platform trust "
                "store and nothing is added to it"
            ),
        )
    if reader is None:
        return CaResolution(
            declared=declared,
            verified=False,
            byte_count=0,
            rule_id=RULE_CA_BUNDLE_UNREADABLE,
            reason=(
                f"the policy declares custom CA bundle {declared!r} but no bundle reader was "
                "supplied, so the bundle is unverified; a TLS client cannot add a CA it never "
                "parsed, and proceeding would mean trusting a declaration nobody checked"
            ),
        )
    try:
        payload = reader(declared)
    except Exception as exc:
        return CaResolution(
            declared=declared,
            verified=False,
            byte_count=0,
            rule_id=RULE_CA_BUNDLE_UNREADABLE,
            reason=(
                f"the declared custom CA bundle {declared!r} could not be read: "
                f"{type(exc).__name__}: {exc}. TLS verification would silently fall back to "
                "the platform trust store, so the call is refused instead"
            ),
        )
    if not payload or not payload.strip():
        return CaResolution(
            declared=declared,
            verified=False,
            byte_count=len(payload or b""),
            rule_id=RULE_CA_BUNDLE_UNREADABLE,
            reason=(
                f"the declared custom CA bundle {declared!r} parsed to an empty payload; an "
                "empty bundle trusts nothing and everything, so the call is refused"
            ),
        )
    return CaResolution(
        declared=declared,
        verified=True,
        byte_count=len(payload),
        rule_id="",
        reason=(
            f"custom CA bundle {declared!r} was resolved and parsed ({len(payload)} bytes); "
            "TLS verification uses it in addition to the platform trust store"
        ),
    )


# -- the enforcement seam ---------------------------------------------------------


@runtime_checkable
class EgressTransport(Protocol):
    """The only way a guarded call reaches the network.

    Deliberately narrow and deliberately not implemented here. A guard that
    owned its own HTTP client would be a second network stack; this protocol is
    the seam the real one is injected into, and it is why a guarded call cannot
    escape policy by accident — the transport is reachable from nowhere but the
    guard.
    """

    def fetch(self, request: EgressRequest, *, timeout_s: float) -> bytes: ...


@dataclass(frozen=True, slots=True)
class EgressAttempt:
    """One external call as policy saw it, permitted or refused.

    Refused attempts are recorded, not dropped. A ledger that only holds the
    calls that happened would be empty on exactly the air-gapped install whose
    log somebody needs.
    """

    url: str
    resolution: EgressResolution

    @property
    def host(self) -> str:
        return self.resolution.host

    @property
    def allowed(self) -> bool:
        return self.resolution.allowed


class GuardedResponse:
    """The minimal response surface ``fetch_json`` reads through a guarded opener.

    Wraps the bytes a transport returned so an existing connector can be guarded
    by passing one argument: :func:`mayhem.observability.base.fetch_json` takes an
    ``opener`` and calls ``response.read(max_bytes + 1)``, which is the whole
    contract this satisfies.
    """

    __slots__ = ("_body",)

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, size: int = -1) -> bytes:
        return self._body if size < 0 else self._body[:size]

    def close(self) -> None:
        """Present because the ``with`` block calls it. Holds nothing."""

    def __enter__(self) -> GuardedResponse:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


@dataclass(slots=True)
class NetworkPolicyGuard:
    """The single seam every external call passes through.

    Construct with :meth:`build`, which resolves the policy and the CA bundle
    once; the fields are then read-only in practice and the one thing that
    changes is :attr:`attempts`, the ledger. It mutates because a decision has to
    be recorded *before* the transport is allowed to run — a guard that could
    only append afterwards would have permitted the call first and explained it
    later.

    :attr:`ready` is the gate on every call. It is ``False`` when the policy
    could not be resolved **or** when the policy declares a CA bundle that was
    not verified, which is why "a policy that cannot resolve fails closed" and
    "a declared CA that was not supplied fails closed" are the same mechanism
    rather than two special cases.
    """

    policy: NetworkPolicy
    resolution: PolicyResolution
    transport: EgressTransport | None = None
    ca: CaResolution = field(
        default_factory=lambda: CaResolution(
            declared="",
            verified=False,
            byte_count=0,
            rule_id="",
            reason="no CA bundle was resolved",
        )
    )
    timeout_s: float = 5.0
    attempts: list[EgressAttempt] = field(default_factory=list)

    @classmethod
    def build(
        cls,
        policy: NetworkPolicy,
        *,
        model: object | None = None,
        transport: EgressTransport | None = None,
        ca_reader: Callable[[str], bytes] | None = None,
        timeout_s: float = 5.0,
    ) -> NetworkPolicyGuard:
        """Resolve the policy and the CA bundle once, then hold both."""
        return cls(
            policy=policy,
            resolution=resolve_policy(policy, model=model),
            transport=transport,
            ca=resolve_ca_bundle(policy, ca_reader),
            timeout_s=timeout_s,
        )

    @property
    def ready(self) -> bool:
        """True only when the policy resolved and every declared CA verified."""
        return self.resolution.resolved and not self.ca.declared_and_unverified

    @property
    def air_gapped(self) -> bool:
        return self.resolution.air_gapped

    def readiness_refusal(self) -> str:
        """Why no call may be attempted at all, or ``""`` when the guard is ready."""
        if not self.resolution.resolved:
            # The *policy's own* rule id, not a generic one: "your policy is
            # inadmissible" is the conclusion, and "air_gapped_with_allowlist" is
            # the cause an operator has to fix.
            rule = self.resolution.rule_id or RULE_UNRESOLVED_POLICY
            return (
                f"{rule}: the declared network policy is inadmissible, so no external call "
                f"is permitted: {self.resolution.reason}"
            )
        if self.ca.declared_and_unverified:
            return f"{self.ca.rule_id}: {self.ca.reason}"
        return ""

    def decide(self, url: str) -> EgressResolution:
        """Resolve ``url`` against this policy without attempting or recording it."""
        blocked = self.readiness_refusal()
        if blocked:
            return EgressResolution(
                host=url,
                port=None,
                allowed=False,
                rule_id=blocked.split(":", 1)[0],
                reason=blocked.split(": ", 1)[1] if ": " in blocked else blocked,
            )
        return resolve_egress_url(self.policy, url, resolution=self.resolution)

    def record(self, url: str) -> EgressResolution:
        """Resolve ``url``, append the attempt to the ledger, and return the decision.

        The decision is returned rather than raised so a caller that only wants
        to know (a provisioner refusing before it issues a command) does not have
        to catch an exception to continue.
        """
        decision = self.decide(url)
        self.attempts.append(EgressAttempt(url=url, resolution=decision))
        return decision

    def refusal_for(self, url: str) -> str:
        """``"<rule_id>: <reason>"`` when ``url`` may not be reached, else ``""``."""
        return self.decide(url).refusal()

    def fetch(self, url: str, *, timeout_s: float | None = None) -> bytes:
        """Make one guarded external call, refusing before the transport if denied.

        The order is the guarantee: resolve, record, then — only if the decision
        is a permit — hand the request to the transport. Under an air-gapped
        policy the transport is never reached, and the refusal names the air gap
        rather than surfacing as a socket error somewhere downstream.

        Raises:
            EgressRefusedError: The policy refused the call, or permitted it and
                no transport was supplied (which is a refusal too — a call that
                cannot be made is not a call that may be skipped), or the
                transport itself failed.
        """
        decision = self.record(url)
        if decision.refused:
            raise EgressRefusedError(decision.rule_id, decision.reason)
        request = parse_egress_request(url)
        if request is None:  # pragma: no cover - decide() already refused this
            raise EgressRefusedError(
                RULE_UNPARSEABLE_URL,
                f"{url!r} names no http(s) destination and cannot be fetched",
            )
        if self.transport is None:
            raise EgressRefusedError(
                RULE_NO_TRANSPORT,
                f"{request.host} is permitted by the declared policy, but this guard holds no "
                "transport, so the call cannot be made. A permitted call with nowhere to go "
                "is refused rather than silently dropped, because a caller waiting on a "
                "result must not be told it is fine",
            )
        effective_timeout = self.timeout_s if timeout_s is None else float(timeout_s)
        try:
            return self.transport.fetch(request, timeout_s=effective_timeout)
        except EgressRefusedError:
            raise
        except Exception as exc:
            raise EgressRefusedError(
                RULE_TRANSPORT_FAILED,
                f"{request.host} is permitted by the declared policy but the call failed: "
                f"{type(exc).__name__}: {exc}",
            ) from exc

    def opener(self) -> Callable[..., GuardedResponse]:
        """An ``opener`` callable shaped for :func:`mayhem.observability.base.fetch_json`.

        ``fetch_json(url, opener=guard.opener())`` is the whole integration for
        an existing connector: every request it makes is resolved by this guard
        first, so a connector in an air-gapped install fails with a named cause
        instead of reaching the network.
        """

        def _open(request: Any, *, timeout: float | None = None, **_kwargs: Any) -> GuardedResponse:
            url = getattr(request, "full_url", request)
            return GuardedResponse(self.fetch(str(url), timeout_s=timeout))

        return _open

    def hosts(self) -> tuple[str, ...]:
        """Every host this guard was asked about, permitted or refused, in order."""
        return tuple(attempt.host for attempt in self.attempts)

    def describe(self) -> str:
        """One screen: the policy verdict, the CA verdict, and the attempt count."""
        policy_line = (
            "policy resolved"
            if self.resolution.resolved
            else f"policy REFUSED ({self.resolution.rule_id})"
        )
        ca_line = self.ca.reason
        return (
            f"network policy: {policy_line} [{self.policy.http_proxy or 'no proxy'}] "
            f"air_gapped={self.policy.air_gapped} "
            f"allowlist_enforced={self.policy.allowlist_enforced} "
            f"entries={sorted(self.policy.outbound_allowlist) or 'none'}\n"
            f"custom CA: {ca_line}\n"
            f"external calls resolved: {len(self.attempts)} "
            f"(permitted {sum(1 for a in self.attempts if a.allowed)}, "
            f"refused {sum(1 for a in self.attempts if not a.allowed)})"
        )
