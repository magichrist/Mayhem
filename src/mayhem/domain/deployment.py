"""Deployment models, enterprise network policy, and the execution-mode marker
(docs/v1.1.0/20_ENTERPRISE_PRODUCT_HARDENING.md, Phase 1).

This module is **pure types and pure refusals**. It reads no environment, opens
no socket, loads no CA file, and starts no process. Everything here is data a
caller assembles and a validator either accepts or refuses by name, which is
what keeps it inside the "domain layer has zero IO and no upward imports"
contract. Enforcement — actually proxying a call, actually detaching a mutation
backend — is Phase 2's job; this file only decides whether a declared shape is
*admissible*, and says which rule refused it when it is not.

Four things are modelled, and each of them exists to stop a specific class of
misreport:

**Deployment models** (:class:`DeploymentModel`, :data:`DEPLOYMENT_PROFILES`)
— the four supported shapes from the plan (local CLI, self-hosted Kubernetes,
managed/SaaS, air-gapped enterprise). The profile is data rather than a
``if model == ...`` chain so a report can render "this evidence came from an
air-gapped bundle" from one lookup.

**Network policy** (:class:`NetworkPolicy`) — the gap-77 vocabulary as data:
HTTP/HTTPS proxy, custom CA bundle, private registry, private Git, air-gapped
mode, outbound allowlist. The plan's rule is *"every external call honors
proxy/CA configuration or fails closed with the cause named"*, so
:func:`egress_decision` is total: every host gets an :class:`EgressDecision`
carrying a human reason, and the air-gapped answer is ``denied`` with the reason
naming the air gap rather than an exception somewhere downstream. Two
contradictions are refused outright, and both are refused at *construction
time of the answer*, not at call time: an air-gapped policy that also carries an
outbound allowlist (:func:`validate_network_policy` rule
``network_policy.air_gapped_with_allowlist``) is a configuration that says both
"there is no egress" and "here is the list of hosts I will reach", and a bare
``*`` allowlist entry (``network_policy.wildcard_allowlist``) is not a policy at
all.

**Execution mode** (:class:`ExecutionMode`, :class:`ModeMarker`) — the
load-bearing one. The plan requires that *"a training run can never become a
production run by flag drift"*, and the only way to make that structural rather
than a convention is to make the marker **derived, never supplied**. A
:class:`ModeMarker` is only ever built by :func:`sealed_mode_marker`, which
computes the banner text and the ``mutates`` flag *from the mode*. There is no
constructor argument that can say ``mutates=True`` for a training run, and no
field a caller can edit afterwards (the dataclass is frozen). A :class:`ModeClaim`
— the object the evidence path carries — therefore cannot report a mode other
than the one it was sealed with, and :func:`production_presentation_refusal` is
the single answer to "may this be shown as a production result?", naming the
banner that would have had to be forged. A later feature flag cannot reclassify
sealed evidence: :func:`flag_drift_refusal` compares the *requested* mode against
the marker's sealed mode and refuses on any difference, which is the flag-drift
path the plan names.

Simulation, training, and safe-demo are all :attr:`ExecutionMode.is_demo`, and
all three are the plan-14 simulate path wearing different labels: they share
``mutates=False``, they share the ``— no mutation performed`` banner shape, and
none of them can produce a claim that passes
:func:`production_presentation_refusal`.

**Feature flags** (:class:`FeatureFlag`, :data:`FEATURE_FLAGS`) — a named
registry rather than free strings, because an untyped flag is where "enable
demo mode" quietly becomes "enable demo mode *in production*". Two fields are
refused at validation time and both are refusals against drift specifically:
``affects_execution_mode`` and ``affects_evidence_presentation`` may not be
``True`` (``feature_flag.evidence_presentation``). A flag that can change how
evidence is presented, or what mode a run is, is not a feature — it is a
backdoor around the marker, so this registry refuses to describe one.

Nothing in this module may assert a compliance claim. The compliance
vocabulary lives in :mod:`mayhem.domain.failure_modes` next to the evidence
mappings it draws from, and it carries the same rule: a template may describe
what evidence it asks for, never that the evidence was found.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.hashing import digest

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = [
    "ALLOWED_PROXY_SCHEMES",
    "ALLOWED_REGISTRY_SCHEMES",
    "ALLOWED_REPOSITORY_SCHEMES",
    "DEMO_MODES",
    "NO_MUTATION_PHRASE",
    "SANDBOX_COMPONENTS",
    "SANDBOX_DEPLOYMENT_MODEL",
    "DeploymentModel",
    "DeploymentProfile",
    "EgressDecision",
    "ExecutionMode",
    "FeatureFlag",
    "FlagRefusal",
    "FlagResolution",
    "ModeClaim",
    "ModeMarker",
    "NetworkPolicy",
    "air_gap_refusal",
    "default_flags_for",
    "deployment_profile",
    "egress_decision",
    "feature_flag",
    "feature_flags_for",
    "flag_drift_refusal",
    "is_valid_network_policy",
    "network_policy_problems",
    "production_presentation_refusal",
    "require_valid_network_policy",
    "resolve_flags",
    "sealed_mode_marker",
    "validate_feature_flag",
    "validate_network_policy",
]

# --- deployment models --------------------------------------------------------


class DeploymentModel(StrEnum):
    """The four supported deployment shapes (plan 20 §"Deployment models")."""

    LOCAL = "local"
    SELF_HOSTED_KUBERNETES = "self_hosted_kubernetes"
    MANAGED_SAAS = "managed_saas"
    AIR_GAPPED = "air_gapped"


@dataclass(frozen=True, slots=True)
class DeploymentProfile:
    """What one deployment model implies, as data.

    ``requires_egress`` is the field Phase 2 keys network enforcement off: an
    air-gapped install answers ``False`` and a policy that claims otherwise is
    refused by :func:`air_gap_refusal`. ``mutates_by_default`` says whether a
    run in this model may touch a real system without the caller opting in,
    which is ``False`` for the local profile only because the sandbox
    (:data:`SANDBOX_COMPONENTS`) is the local model; the sandbox is not a
    policy-free zone, it is a local model whose targets are Mayhem's own
    throwaway processes.
    """

    model: DeploymentModel
    summary: str
    requires_cluster: bool
    requires_egress: bool
    supports_live_evidence: bool
    offline_bundle_exchange: bool


DEPLOYMENT_PROFILES: Final[dict[DeploymentModel, DeploymentProfile]] = {
    DeploymentModel.LOCAL: DeploymentProfile(
        model=DeploymentModel.LOCAL,
        summary="Local CLI on an operator workstation or laptop",
        requires_cluster=False,
        requires_egress=True,
        supports_live_evidence=True,
        offline_bundle_exchange=False,
    ),
    DeploymentModel.SELF_HOSTED_KUBERNETES: DeploymentProfile(
        model=DeploymentModel.SELF_HOSTED_KUBERNETES,
        summary="Customer-operated Kubernetes cluster, installed by Helm",
        requires_cluster=True,
        requires_egress=True,
        supports_live_evidence=True,
        offline_bundle_exchange=False,
    ),
    DeploymentModel.MANAGED_SAAS: DeploymentProfile(
        model=DeploymentModel.MANAGED_SAAS,
        summary="Mayhem-operated multi-tenant service",
        requires_cluster=True,
        requires_egress=True,
        supports_live_evidence=True,
        offline_bundle_exchange=False,
    ),
    DeploymentModel.AIR_GAPPED: DeploymentProfile(
        model=DeploymentModel.AIR_GAPPED,
        summary="Disconnected enterprise site; bundles move in and out by hand",
        requires_cluster=False,
        requires_egress=False,
        supports_live_evidence=True,
        offline_bundle_exchange=True,
    ),
}


def deployment_profile(model: DeploymentModel) -> DeploymentProfile:
    """The descriptor for ``model``.

    Raises:
        KeyError: If a model is not one of the four supported shapes. Every
            member of :class:`DeploymentModel` has a profile, so this is a
            guard against the table drifting from the enum rather than a path a
            caller can normally reach.
    """
    return DEPLOYMENT_PROFILES[model]


# --- sandbox vocabulary -------------------------------------------------------


class SandboxComponent(StrEnum):
    """The built-in sandbox services (plan 20 §"Sandbox and demo", gap 70).

    The sandbox exists so a first run and a game-day rehearsal have something
    safe to break. It is a *local* deployment model whose targets are these
    components, which is why nothing here widens what a real run may touch.
    """

    FRONTEND = "frontend"
    API = "api"
    DATABASE = "database"
    CACHE = "cache"
    QUEUE = "queue"
    OBSERVABILITY = "observability"


SANDBOX_COMPONENTS: Final[tuple[SandboxComponent, ...]] = (
    SandboxComponent.FRONTEND,
    SandboxComponent.API,
    SandboxComponent.DATABASE,
    SandboxComponent.CACHE,
    SandboxComponent.QUEUE,
    SandboxComponent.OBSERVABILITY,
)

#: The sandbox is provisioned into the local model; it is never a remote target.
SANDBOX_DEPLOYMENT_MODEL: Final[DeploymentModel] = DeploymentModel.LOCAL


# --- network policy -----------------------------------------------------------

ALLOWED_PROXY_SCHEMES: Final[tuple[str, ...]] = ("http://", "https://")
ALLOWED_REGISTRY_SCHEMES: Final[tuple[str, ...]] = ("http://", "https://")
ALLOWED_REPOSITORY_SCHEMES: Final[tuple[str, ...]] = ("ssh://", "https://", "http://", "git@")


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    """The enterprise network vocabulary (gap 77) as data. Not enforcement.

    Every field is a *declaration* the operator made; none of them has been
    proven here. :attr:`custom_ca_bundle` in particular is a reference to a
    bundle, not a read of one — the domain layer cannot open a file, and a
    policy that claimed to have validated a CA it never parsed would be exactly
    the kind of unearned claim this module exists to prevent. Phase 2 resolves
    the reference and fails closed with the cause named if it cannot.

    ``allowlist_enforced`` distinguishes "no allowlist configured" from "an
    empty allowlist that permits nothing". They are different configurations and
    the second one is a valid way to run an install that must not phone home.
    """

    http_proxy: str = ""
    https_proxy: str = ""
    custom_ca_bundle: str = ""
    private_registry: str = ""
    private_git: str = ""
    air_gapped: bool = False
    outbound_allowlist: frozenset[str] = frozenset()
    allowlist_enforced: bool = False

    @property
    def air_gap_declared(self) -> bool:
        """True when the policy refuses egress by declaration."""
        return self.air_gapped


@dataclass(frozen=True, slots=True)
class EgressDecision:
    """Whether one host may be reached, and why. Never a bare ``bool``.

    A denied egress has to name its cause: "blocked" with no reason is the
    failure mode that gets debugged by disabling the policy.
    """

    host: str
    allowed: bool
    reason: str

    @property
    def denied(self) -> bool:
        return not self.allowed


def _is_wildcard_entry(entry: str) -> bool:
    """True for an allowlist entry that permits every host."""
    return entry.strip() in {"*", "*:*", "*/*"}


def _entry_is_malformed(entry: str) -> bool:
    """True for an allowlist entry that is not a host, ``host:port``, or ``*.suffix``.

    An entry is a DNS name or an IPv4 literal, optionally with ``:port``. An
    IPv6 literal is **not** accepted: more than one colon is refused rather than
    parsed, because a bracketed address this parser cannot match would sit in a
    customer's allowlist looking enforced while matching nothing.
    """
    candidate = entry.strip()
    host, _ = _split_entry(candidate)
    return (
        not candidate
        or candidate != entry
        or any(char.isspace() for char in candidate)
        or "://" in candidate
        or "/" in candidate
        or candidate.count("*") > 1
        or (candidate.startswith("*") and not candidate.startswith("*."))
        or candidate.count(":") > 1
        or not host
        or host == "*"
        or any(character in host for character in "@/\\")
    )


def _split_entry(entry: str) -> tuple[str, int | None]:
    """Split an allowlist entry into ``(host, port)``; port is ``None`` when absent.

    ``rpartition`` on a colon is not enough, because a malformed entry must not
    be silently reinterpreted: only a trailing all-digit field counts as a port.
    """
    candidate = entry.strip().lower()
    if candidate.count(":") == 1:
        host, _, port = candidate.partition(":")
        if port.isdigit() and port:
            return host, int(port)
    return candidate, None


def validate_network_policy(policy: NetworkPolicy) -> str:
    """Why ``policy`` is inadmissible, or ``""`` when it is fine.

    A single named reason, because every caller of this is a person-facing
    surface (a config error message, a doctor check, a test failure) and a
    policy refusal without a cause is a support ticket nobody can close. Rule
    ids are stable so a test and a log line can refer to the same thing:

    ``network_policy.air_gapped_with_allowlist``
        Air-gapped mode with a non-empty outbound allowlist. The two
        declarations contradict each other, and the contradiction is resolved
        by refusing rather than by picking a winner, because picking a winner
        would silently make an air-gapped install reachable.
    ``network_policy.wildcard_allowlist``
        A bare ``*`` entry. An allowlist that permits every host is not a
        policy; it is the absence of one wearing a policy's syntax.
    ``network_policy.malformed_allowlist_entry``
        An entry that is not a host, ``host:port``, or a leftmost-label
        wildcard such as ``*.corp.example``.
    ``network_policy.proxy_scheme``
        A proxy URL that is not ``http://`` or ``https://``.
    ``network_policy.registry_scheme``
        A private registry that is neither an allowed URL scheme nor a bare
        ``host[:port]``.
    ``network_policy.repository_scheme``
        A private Git remote that is not a URL or an ``git@host:path`` form.
    ``network_policy.ca_bundle``
        A CA bundle reference that is only whitespace.

    Every problem is collected by :func:`network_policy_problems` and this
    function reports the first, so a doctor check can show an operator
    everything that is wrong with one config file instead of one problem per
    run of the tool.
    """
    problems = network_policy_problems(policy)
    if not problems:
        return ""
    rule, reason = problems[0]
    return f"{rule}: {reason}"


def network_policy_problems(policy: NetworkPolicy) -> tuple[tuple[str, str], ...]:
    """Every ``(rule_id, reason)`` that makes ``policy`` inadmissible.

    Ordered by the rule the validator checks, so the first entry is what
    :func:`validate_network_policy` reports. All of them are reported here
    because an enterprise config file usually has more than one wrong line, and
    an operator who fixes them one run at a time is an operator who will stop
    after the third.
    """
    problems: list[tuple[str, str]] = []
    if policy.air_gapped and policy.outbound_allowlist:
        problems.append((
            "network_policy.air_gapped_with_allowlist",
            f"air_gapped=True declares that there is no egress, but outbound_allowlist names "
            f"{len(policy.outbound_allowlist)} reachable host(s) "
            f"{sorted(policy.outbound_allowlist)}; an air-gapped install either has egress or "
            "has an allowlist, and which one it is must be declared",
        ))
    for entry in sorted(policy.outbound_allowlist):
        if _is_wildcard_entry(entry):
            problems.append((
                "network_policy.wildcard_allowlist",
                f"allowlist entry {entry!r} permits every host, which is an absent policy "
                "rather than a policy; name the hosts, or set allowlist_enforced with an "
                "empty allowlist to permit none",
            ))
            continue
        if _entry_is_malformed(entry):
            problems.append((
                "network_policy.malformed_allowlist_entry",
                f"allowlist entry {entry!r} is not a host, a host:port, or a leftmost-label "
                "wildcard such as '*.corp.example'",
            ))
    for name, value in (("http_proxy", policy.http_proxy), ("https_proxy", policy.https_proxy)):
        if value and not value.startswith(ALLOWED_PROXY_SCHEMES):
            schemes = " or ".join(ALLOWED_PROXY_SCHEMES)
            problems.append((
                "network_policy.proxy_scheme",
                f"{name}={value!r} must start with {schemes}; a proxy that cannot be addressed "
                "is not a proxy, and a request sent without it would be a direct egress the "
                "operator did not sanction",
            ))
    if policy.private_registry and not _registry_is_wellformed(policy.private_registry):
        schemes = " or ".join(ALLOWED_REGISTRY_SCHEMES)
        problems.append((
            "network_policy.registry_scheme",
            f"private_registry={policy.private_registry!r} must be a {schemes} URL or a bare "
            "host[:port]",
        ))
    if policy.private_git and not _repository_is_wellformed(policy.private_git):
        schemes = " or ".join(ALLOWED_REPOSITORY_SCHEMES)
        problems.append((
            "network_policy.repository_scheme",
            f"private_git={policy.private_git!r} must start with {schemes} (git@host:path is "
            "accepted for scp-style remotes)",
        ))
    if policy.custom_ca_bundle and not policy.custom_ca_bundle.strip():
        problems.append((
            "network_policy.ca_bundle",
            "custom_ca_bundle is present but blank; a blank CA reference would leave TLS "
            "verification exactly as it was, so the declaration has to be removed rather "
            "than left empty",
        ))
    return tuple(problems)


def _registry_is_wellformed(value: str) -> bool:
    if value.startswith(ALLOWED_REGISTRY_SCHEMES):
        return "//" in value
    return not _entry_is_malformed(value)


def _repository_is_wellformed(value: str) -> bool:
    if value.startswith(ALLOWED_REPOSITORY_SCHEMES):
        return "//" in value or value.startswith("git@")
    return False


def require_valid_network_policy(policy: NetworkPolicy) -> None:
    """Raise :class:`InvariantViolationError` when :func:`validate_network_policy` refuses.

    For callers that treat an inadmissible policy as a programming error rather
    than a user input error.
    """
    reason = validate_network_policy(policy)
    if reason:
        raise InvariantViolationError(reason.split(":", 1)[0], reason.split(": ", 1)[1])


def is_valid_network_policy(policy: NetworkPolicy) -> bool:
    """True when the policy may be used as declared."""
    return not validate_network_policy(policy)


def egress_decision(policy: NetworkPolicy, host: str, *, port: int | None = None) -> EgressDecision:
    """Whether ``host`` (optionally ``port``) may be reached under ``policy``.

    Total and pure: every host gets an answer with a reason, and nothing is
    raised on a caller's behalf. The air-gapped answer is ``denied`` and says
    so, because an air-gapped install that raises a socket error three layers
    up is an install whose support burden is somebody else's problem.

    An allowlist entry may be a bare host or ``host:port``. An entry carrying a
    port matches any call to that host when the caller did not state a port, and
    only the stated port when it did — so ``db.internal:5432`` is not a licence
    to reach ``db.internal`` on 22.
    """
    target = host.strip().lower().rstrip(".")
    if not target:
        return EgressDecision(host=host, allowed=False, reason="no host was named")
    if policy.air_gapped:
        return EgressDecision(
            host=target,
            allowed=False,
            reason=(
                f"{target} refused: this install is air-gapped, so no outbound call is "
                "permitted. Exchange bundles out of band rather than opening egress"
            ),
        )
    if not policy.allowlist_enforced:
        return EgressDecision(
            host=target,
            allowed=True,
            reason=(
                f"{target} permitted: no outbound allowlist is enforced by this policy, so "
                "egress is unrestricted — this is a configuration fact, not a clearance"
            ),
        )
    for entry in sorted(policy.outbound_allowlist):
        if not _entry_matches(entry, target, port):
            continue
        return EgressDecision(
            host=target,
            allowed=True,
            reason=f"{target} matches allowlist entry {entry!r}",
        )
    return EgressDecision(
        host=target,
        allowed=False,
        reason=(
            f"{target} refused: the outbound allowlist is enforced and names no matching "
            f"entry (allowed: {sorted(policy.outbound_allowlist) or 'nothing'})"
        ),
    )


def _entry_matches(entry: str, host: str, port: int | None) -> bool:
    entry_host, entry_port = _split_entry(entry)
    if entry_port is not None and port is not None and entry_port != port:
        return False
    if entry_host.startswith("*."):
        suffix = entry_host[1:]
        return host.endswith(suffix) and host.count(".") == entry_host.count(".")
    return entry_host == host


def air_gap_refusal(model: DeploymentModel, policy: NetworkPolicy) -> str:
    """Why ``model`` and ``policy`` disagree about egress, or ``""``.

    The air-gapped deployment model and the air-gapped policy flag are separate
    declarations made by different people in different files, which is exactly
    why they are cross-checked rather than trusted: an install configured as
    air-gapped whose policy says ``air_gapped=False`` would pass every check
    that looked at only one of them and would then reach the internet.
    """
    if model is DeploymentModel.AIR_GAPPED and not policy.air_gapped:
        return (
            "deployment_model.air_gapped_without_policy: the install is configured as the "
            "air-gapped deployment model but its network policy does not set air_gapped=True, "
            "so every egress check would permit traffic; declare the air gap in the policy"
        )
    if model is not DeploymentModel.AIR_GAPPED and policy.air_gapped:
        return (
            f"deployment_model.egress_policy_under_{model.value}: the network policy declares "
            "an air gap but the install is configured as the "
            f"{model.value} deployment model, which requires egress; one of the two "
            "declarations is wrong and mayhem will not guess which"
        )
    return ""


# --- execution mode -----------------------------------------------------------


class ExecutionMode(StrEnum):
    """How a run was authorised, and therefore what its evidence may claim.

    ``PRODUCTION`` is the only member whose runs may mutate a real system, and
    the only one whose evidence may be presented as a production result. The
    other three are the plan-14 simulate path under different names: they run
    the full UX with the mutation backend detached, so they share
    ``mutates=False`` and the same ``— no mutation performed`` banner shape.

    The distinction is carried in the type rather than in a log line because
    the failure it prevents is not a bad log line — it is a sealed evidence
    bundle with no field saying how it was produced.
    """

    PRODUCTION = "production"
    SIMULATION = "simulation"
    TRAINING = "training"
    SAFE_DEMO = "safe_demo"

    @property
    def mutates(self) -> bool:
        """True only for a run that may change the system under test.

        Derived from the member, never stored: there is no field a caller can
        set to ``True`` on a training run.
        """
        return self is ExecutionMode.PRODUCTION

    @property
    def is_production(self) -> bool:
        return self is ExecutionMode.PRODUCTION

    @property
    def is_demo(self) -> bool:
        """True for the non-mutating modes — simulation, training, safe demo."""
        return self is not ExecutionMode.PRODUCTION

    @property
    def marker(self) -> str:
        """The banner sealed into evidence produced in this mode.

        The three non-production members share the phrase "no mutation
        performed" deliberately: a reader who sees it cannot misread it as a
        weaker claim about a real run, because it is a claim that no run
        happened against the system at all.
        """
        return _MODE_MARKERS[self]


_MODE_MARKERS: Final[dict[ExecutionMode, str]] = {
    ExecutionMode.PRODUCTION: "PRODUCTION",
    ExecutionMode.SIMULATION: "SIMULATION — no mutation performed",
    ExecutionMode.TRAINING: "TRAINING — no mutation performed",
    ExecutionMode.SAFE_DEMO: "SAFE DEMO — no mutation performed",
}

#: Every mode a demonstration, rehearsal, or training exercise may use.
DEMO_MODES: Final[frozenset[ExecutionMode]] = frozenset(
    mode for mode in ExecutionMode if mode.is_demo
)

#: The phrase every non-production marker carries. Phase 2 writes it into the
#: evidence banner; the verifier reads it back through the sealed marker.
NO_MUTATION_PHRASE: Final[str] = "no mutation performed"


@dataclass(frozen=True, slots=True)
class ModeMarker:
    """A sealed, derived record of the mode a run executed in.

    Construct only through :func:`sealed_mode_marker`. Every field is derived
    from ``mode``: the banner is looked up, ``mutates`` is the member's own
    property, and the dataclass is frozen. There is therefore no value of this
    class that says "training" and "mutates", which is the property the plan's
    "a training run can never become a production run by flag drift" requires.
    """

    mode: ExecutionMode
    marker: str
    mutates: bool
    basis: str = ""

    @property
    def digest(self) -> str:
        """Content digest of the marker, for sealing alongside an evidence bundle.

        Over the marker's own fields only. It deliberately does **not** hash the
        run: the marker says how a run was authorised, and two runs authorised
        the same way must produce the same marker, or the marker becomes a
        per-run id that proves nothing.
        """
        return digest({"mode": self.mode.value, "marker": self.marker, "basis": self.basis})

    @property
    def may_back_production_evidence(self) -> bool:
        """True only for a production marker.

        Read by the verifier, not by the renderer: a surface that is deciding
        whether to *show* something as a production result asks this, so the
        answer cannot be a formatting decision.
        """
        return self.mutates and self.mode.is_production


def sealed_mode_marker(mode: ExecutionMode, *, basis: str = "") -> ModeMarker:
    """Seal the marker for ``mode``, with the provenance that justifies it.

    ``basis`` is the sentence a reader needs to know *why* the run was in this
    mode ("plan 14 simulate path", "game-day rehearsal"). It is recorded, not
    validated: an operator's reason is not a policy question, and refusing an
    honest reason would only teach people to leave the field blank.
    """
    return ModeMarker(mode=mode, marker=mode.marker, mutates=mode.mutates, basis=basis)


@dataclass(frozen=True, slots=True)
class ModeClaim:
    """What the evidence path carries: a run, its sealed mode, where it ran.

    The claim does not store a mode. It stores the :class:`ModeMarker`, which
    does — so ``claim.marker.mode`` is the only answer to "what mode was this",
    and there is no second field that could disagree with it. ``active_flags`` is
    recorded for the audit trail, not for classification: see
    :func:`flag_drift_refusal` for why a flag cannot reclassify the run.
    """

    run_id: str
    marker: ModeMarker
    deployment_model: DeploymentModel
    plan_identity: str = ""
    active_flags: frozenset[str] = frozenset()

    @property
    def mode(self) -> ExecutionMode:
        """The sealed mode. Read-only by construction."""
        return self.marker.mode

    @property
    def mutates(self) -> bool:
        return self.marker.mutates


def production_presentation_refusal(claim: ModeClaim) -> str:
    """Why ``claim`` may not be presented as a production result, or ``""``.

    This is the negative control the plan asks for, stated as a function rather
    than a convention: a training run's evidence cannot be shown as a
    production result, and the refusal names the marker that would have had to
    be forged. The answer is never ``""`` for a non-production marker, no
    matter how healthy the run's own numbers are — a clean simulation of a
    system that passed is a fact about the simulation.
    """
    if not claim.run_id.strip():
        return "evidence.no_run_id: the claim names no run, so it cannot be attributed"
    if claim.marker.may_back_production_evidence:
        return ""
    return (
        f"evidence.non_production_mode: run {claim.run_id!r} executed in "
        f"{claim.marker.mode.value!r} mode, sealed as {claim.marker.marker!r}, so it may not "
        "be presented as a production result. The result describes a "
        f"{claim.marker.mode.value} run in which no mutation was performed; presenting it as a "
        "production result would claim a system impact that was never applied"
    )


def flag_drift_refusal(claim: ModeClaim, requested: ExecutionMode) -> str:
    """Why ``requested`` may not be substituted for the claim's sealed mode, or ``""``.

    The flag-drift guard. A run is classified by the mode it executed in, and
    that mode is sealed into its evidence at write time. Toggling a feature flag
    afterwards changes the *next* run's mode; it cannot rewrite this run's, and
    asking for the rewrite is refused by name.
    """
    if requested is claim.marker.mode:
        return ""
    return (
        f"evidence.flag_drift: run {claim.run_id!r} was sealed in {claim.marker.mode.value!r} "
        f"mode and cannot be reclassified as {requested.value!r} by a later flag or "
        f"configuration change; active flags at seal time were {sorted(claim.active_flags)}. "
        "Re-run under the requested mode to obtain evidence in it"
    )


# --- feature flags ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FeatureFlag:
    """One named, validated capability switch.

    The two ``affects_*`` fields exist to be refused. A flag that can change
    what mode a run is, or how its evidence is presented, is a way around
    :func:`sealed_mode_marker`, and this registry will not describe one. A flag
    that is safe in every deployment model and safe in a production run says so
    with ``production_safe``; a demo-only flag says ``False`` and is then
    refused when a production run tries to enable it.
    """

    key: str
    summary: str
    default_enabled: bool
    allowed_deployment_models: frozenset[DeploymentModel]
    production_safe: bool = True
    affects_execution_mode: bool = False
    affects_evidence_presentation: bool = False
    owner: str = ""
    removal_plan: str = ""


_ALL_MODELS: Final[frozenset[DeploymentModel]] = frozenset(DeploymentModel)
_DEMO_MODELS: Final[frozenset[DeploymentModel]] = frozenset(
    {DeploymentModel.LOCAL, DeploymentModel.SELF_HOSTED_KUBERNETES}
)

#: The flags this release defines. Keys are stable identifiers, not prose: a
#: flag whose key changes is a flag whose audit trail ends.
FEATURE_FLAGS: Final[tuple[FeatureFlag, ...]] = (
    FeatureFlag(
        key="sandbox.provisioning",
        summary="Allow `mayhem sandbox` to provision the built-in local test environment",
        default_enabled=True,
        allowed_deployment_models=frozenset({DeploymentModel.LOCAL}),
        owner="runtime",
    ),
    FeatureFlag(
        key="demo.mode",
        summary="Allow a safe-demo run that exercises the full UX with mutation detached",
        default_enabled=True,
        allowed_deployment_models=_DEMO_MODELS,
        production_safe=False,
        owner="runtime",
    ),
    FeatureFlag(
        key="offline.bundle_import",
        summary="Allow evidence bundles to be imported from an out-of-band medium",
        default_enabled=True,
        allowed_deployment_models=frozenset({DeploymentModel.AIR_GAPPED}),
        owner="evidence",
    ),
    FeatureFlag(
        key="offline.bundle_export",
        summary="Allow sealed evidence bundles to be exported for out-of-band transfer",
        default_enabled=True,
        allowed_deployment_models=frozenset({DeploymentModel.AIR_GAPPED}),
        owner="evidence",
    ),
    FeatureFlag(
        key="network.allowlist_enforced",
        summary="Refuse egress to any host not named in the outbound allowlist",
        default_enabled=False,
        allowed_deployment_models=_ALL_MODELS,
        owner="runtime",
    ),
    FeatureFlag(
        key="support.diagnostics_bundle",
        summary="Allow generation of a redacted support bundle",
        default_enabled=True,
        allowed_deployment_models=frozenset({DeploymentModel.MANAGED_SAAS}),
        owner="support",
    ),
    FeatureFlag(
        key="reporting.compliance_templates",
        summary="Render compliance templates as evidence requests, never as attestations",
        default_enabled=True,
        allowed_deployment_models=frozenset({DeploymentModel.MANAGED_SAAS}),
        owner="reporting",
    ),
)

_FLAGS_BY_KEY: Final[dict[str, FeatureFlag]] = {flag.key: flag for flag in FEATURE_FLAGS}


def validate_feature_flag(flag: FeatureFlag) -> str:
    """Why ``flag`` is inadmissible, or ``""``.

    Rule ids: ``feature_flag.key`` (missing or malformed key),
    ``feature_flag.summary`` (no human description — an undescribed flag is
    discovered by reading code), ``feature_flag.execution_mode`` (a flag that
    can change which mode a run executes in),
    ``feature_flag.evidence_presentation`` (a flag that can change how evidence
    is presented — the drift path the plan names), ``feature_flag.deployment_model``
    (no deployment model permits it, so enabling it can never succeed), and
    ``feature_flag.removal_plan`` (a temporary flag with no end state).
    """
    if not flag.key or not flag.key.strip():
        return "feature_flag.key: a feature flag needs a key, and a blank one cannot be requested"
    if any(character.isspace() for character in flag.key):
        return f"feature_flag.key: {flag.key!r} contains whitespace; use a dotted key"
    if not flag.summary.strip():
        return (
            f"feature_flag.key: {flag.key!r} has no summary; an undescribed flag is a "
            "behaviour nobody can review, and 'it was in the list' is not a reason to keep it"
        )
    return next(
        (
            f"{rule}: {reason}"
            for rule, reason in (
                (
                    "feature_flag.deployment_model",
                    f"{flag.key!r} is allowed in no deployment model, so enabling it can never "
                    "succeed; delete the flag instead of shipping it inert",
                ),
                (
                    "feature_flag.execution_mode",
                    f"{flag.key!r} is declared to affect execution mode. The mode a run "
                    "executes in is sealed into its evidence at write time and is not a runtime "
                    "switch; a flag that changes it would let a training run become a production "
                    "run by configuration",
                ),
                (
                    "feature_flag.evidence_presentation",
                    f"{flag.key!r} is declared to affect how evidence is presented. A surface "
                    "that can be switched into presenting a non-production run as a production "
                    "result is not a feature, it is the exact failure the execution-mode marker "
                    "exists to prevent",
                ),
            )
            if (
                not flag.allowed_deployment_models
                if rule == "feature_flag.deployment_model"
                else flag.affects_execution_mode
                if rule == "feature_flag.execution_mode"
                else flag.affects_evidence_presentation
            )
        ),
        "",
    )


def feature_flag(key: str) -> FeatureFlag:
    """Look a flag up by key; unknown keys are planning errors, not KeyErrors.

    Mirrors :func:`mayhem.domain.catalog.definition_for` so an unknown flag
    fails the way an unknown fault fails.
    """
    try:
        return _FLAGS_BY_KEY[key]
    except KeyError:
        known = ", ".join(sorted(_FLAGS_BY_KEY))
        msg = f"feature flag {key!r} is not defined (known: {known})"
        raise LookupError(msg) from None


def feature_flags_for(model: DeploymentModel) -> tuple[FeatureFlag, ...]:
    """Every flag that may be enabled under ``model``, in declaration order."""
    return tuple(flag for flag in FEATURE_FLAGS if model in flag.allowed_deployment_models)


@dataclass(frozen=True, slots=True)
class FlagRefusal:
    """One flag that was requested and not granted, with the rule that refused it."""

    key: str
    rule: str
    reason: str


@dataclass(frozen=True, slots=True)
class FlagResolution:
    """The flags actually in force, and the requests that were refused.

    A refusal is recorded rather than raised: a configuration file asking for
    five flags where one is inadmissible should not take the whole install down
    before it has told the operator which line was wrong. The granted set is
    what the runtime may use, and it is the *only* set — an ungranted flag is
    not "probably fine".
    """

    model: DeploymentModel
    mode: ExecutionMode
    enabled: frozenset[str]
    refusals: tuple[FlagRefusal, ...] = ()

    @property
    def granted(self) -> frozenset[str]:
        return self.enabled

    def refusal_for(self, key: str) -> str:
        """The reason ``key`` was refused, or ``""`` if it was granted."""
        for refusal in self.refusals:
            if refusal.key == key:
                return refusal.reason
        return ""


def resolve_flags(
    requested: Iterable[str], *, model: DeploymentModel, mode: ExecutionMode
) -> FlagResolution:
    """Resolve ``requested`` against ``model`` and ``mode``, refusing what cannot hold.

    Three refusals, in this order:

    ``flag.unknown``
        The key names no flag in :data:`FEATURE_FLAGS`.
    ``flag.deployment_model``
        The flag is not permitted in this deployment model — a sandbox flag on a
        managed install, an offline-bundle flag on a laptop with a network.
    ``flag.production_unsafe``
        The flag is permitted in this model but is not production-safe and the
        caller asked for it in a production run. This is the flag-drift path
        refused at resolution time as well as at definition time: the flag
        exists, the model permits it, and it is still wrong here.
    """
    enabled: set[str] = set()
    refusals: list[FlagRefusal] = []
    for key in sorted(set(requested)):
        try:
            flag = feature_flag(key)
        except LookupError as exc:
            refusals.append(FlagRefusal(key=key, rule="flag.unknown", reason=str(exc)))
            continue
        if model not in flag.allowed_deployment_models:
            permitted = ", ".join(sorted(m.value for m in flag.allowed_deployment_models))
            refusals.append(
                FlagRefusal(
                    key=key,
                    rule="flag.deployment_model",
                    reason=(
                        f"flag {key!r} is permitted in {permitted} but this install is "
                        f"{model.value}; the flag is not enabled"
                    ),
                )
            )
            continue
        if mode.is_production and not flag.production_safe:
            refusals.append(
                FlagRefusal(
                    key=key,
                    rule="flag.production_unsafe",
                    reason=(
                        f"flag {key!r} is not production-safe and a {mode.value} run was "
                        "requested; demo-only capability does not exist in a production run"
                    ),
                )
            )
            continue
        enabled.add(key)
    return FlagResolution(
        model=model, mode=mode, enabled=frozenset(enabled), refusals=tuple(refusals)
    )


def default_flags_for(model: DeploymentModel, mode: ExecutionMode) -> FlagResolution:
    """Resolve the flags that default to enabled under ``model`` and ``mode``."""
    return resolve_flags(
        (flag.key for flag in feature_flags_for(model) if flag.default_enabled),
        model=model,
        mode=mode,
    )
