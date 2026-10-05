"""Policy vocabulary: profiles, target profiles, and the v1.1.0 policy engine types.

Two things live here, and they are different layers of the same idea.

**Profiles** (:class:`PolicyProfile` and the built-in table) are the *target
profiles* the CLI already selects with ``--profile``: a named, flat set of
admission facts that :mod:`mayhem.controller.safety` reads. They are unchanged
by this module's second half and remain the migration surface the v1.1.0 policy
plan calls "the current config-policy block, which stays valid".

**The policy vocabulary** (:class:`PolicyRule` … :class:`CompatibilityEdge`) is
plan 07 Phase 1: the *domain types* a policy engine needs before any engine
exists. Everything in that half is a frozen value object plus pure functions
over it. There is no store, no clock read, no IO — ``evaluate_bundle`` takes the
"now" it compares expiry against as an argument precisely so that a decision is
a function of (bundle, facts, now) and nothing else. That is what makes the
Phase 4 requirement ("replaying a decision from evidence reproduces it
bit-for-bit") reachable: there is no ambient state for a replay to disagree
about.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from mayhem.domain.common import utc_now
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import BlastRadiusBudget
from mayhem.domain.hashing import digest
from mayhem.domain.risks import RiskLevel
from mayhem.domain.secrets import SECRET_FIELD_KEYS

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Mapping, Sequence


class PolicyProfile(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
    risk_ceiling: RiskLevel | None = None
    allowed_faults: frozenset[str] | None = None
    denied_faults: frozenset[str] = Field(default_factory=frozenset)
    blast_radius: BlastRadiusBudget = Field(default_factory=BlastRadiusBudget)
    critical_fault_acks: frozenset[str] = Field(default_factory=frozenset)
    allow_critical: bool = False
    allowed_environments: frozenset[str] | None = None
    denied_environments: frozenset[str] = Field(default_factory=frozenset)
    allowed_targets: frozenset[str] | None = None
    description: str = ""


def profile_to_policy_cfg(profile: PolicyProfile) -> dict[str, Any]:
    return {
        "risk_ceiling": profile.risk_ceiling,
        "allow_faults": profile.allowed_faults,
        "deny_faults": profile.denied_faults,
        "allow_critical": profile.allow_critical,
        "critical_fault_acks": profile.critical_fault_acks,
    }


def profile_to_blast_budget(profile: PolicyProfile) -> BlastRadiusBudget:
    return profile.blast_radius


BUILTIN_PROFILES: dict[str, PolicyProfile] = {
    "default": PolicyProfile(name="default", description="permissive default"),
    "strict": PolicyProfile(
        name="strict",
        risk_ceiling=RiskLevel.MEDIUM,
        blast_radius=BlastRadiusBudget(
            max_services_pct=25.0,
            max_hosts=1,
            max_concurrent_faults=1,
            max_duration_per_fault_s=60.0,
        ),
        description="strict production guardrail",
    ),
    "permissive": PolicyProfile(
        name="permissive",
        risk_ceiling=None,
        blast_radius=BlastRadiusBudget(
            max_services_pct=100.0,
            max_hosts=10,
            max_concurrent_faults=10,
            max_duration_per_fault_s=600.0,
        ),
        description="permissive lab profile",
    ),
    "staging": PolicyProfile(
        name="staging",
        risk_ceiling=RiskLevel.HIGH,
        blast_radius=BlastRadiusBudget(max_services_pct=50.0, max_hosts=2, max_concurrent_faults=3),
        allowed_environments=frozenset({"staging", "dev"}),
        description="staging environment profile",
    ),
    "production": PolicyProfile(
        name="production",
        risk_ceiling=RiskLevel.MEDIUM,
        blast_radius=BlastRadiusBudget(max_services_pct=25.0, max_hosts=1, max_concurrent_faults=1),
        denied_environments=frozenset({"dev"}),
        allowed_environments=frozenset({"production"}),
        description="production environment profile",
    ),
}


def get_profile(name: str) -> PolicyProfile | None:
    return BUILTIN_PROFILES.get(name)


def list_profiles() -> list[PolicyProfile]:
    return list(BUILTIN_PROFILES.values())


def is_environment_allowed(profile: PolicyProfile, env: str | None) -> bool:
    if env is None:
        return True
    if profile.denied_environments and env in profile.denied_environments:
        return False
    return not (
        profile.allowed_environments is not None and env not in profile.allowed_environments
    )


def contains_secret_key(data: dict[str, Any]) -> str | None:
    for key, value in data.items():
        if key.lower() in SECRET_FIELD_KEYS:
            return key
        if isinstance(value, dict):
            found = contains_secret_key(value)
            if found is not None:
                return found
    return None


def sanitize_for_logging(data: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in data.items():
        if key.lower() in SECRET_FIELD_KEYS:
            sanitized[key] = "***REDACTED***"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_for_logging(value)
        elif isinstance(value, list):
            sanitized[key] = [sanitize_for_logging(v) if isinstance(v, dict) else v for v in value]
        else:
            sanitized[key] = value
    return sanitized


# =============================================================================
# Policy-as-code vocabulary (plan 07, Phase 1 — domain model)
#
# Everything below is a frozen value type or a pure function over frozen value
# types. There is deliberately no engine here: Phase 2 wires evaluation into
# ``controller.safety.validate_plan``. What Phase 1 owes the rest of the system
# is a vocabulary that is *shaped like the decision* — dimension, predicate,
# effect, version, digest — so that a denial recorded today can still be
# explained, replayed, and bound to an approval later.
# =============================================================================


class PolicyDimension(StrEnum):
    """The facts a policy may speak to.

    One member per dimension in plan 07 §"Policy dimensions". The set is a
    vocabulary, not a licence: a gate that does not read a dimension cannot
    enforce it, and Phase 6's honesty gate ("no doc describes a policy
    dimension the evaluator does not enforce") is what keeps the two in step.
    """

    ENVIRONMENT = "environment"
    TEAM = "team"
    FAULT_FAMILY = "fault_family"
    RISK = "risk"
    TARGET = "target"
    CAPABILITY = "capability"
    SCHEDULE = "schedule"
    MAINTENANCE_WINDOW = "maintenance_window"
    DAMAGE_BUDGET = "damage_budget"
    CLOUD_COST = "cloud_cost"
    APPROVAL_LEVEL = "approval_level"
    CONCURRENCY = "concurrency"
    DEPLOYMENT_STATE = "deployment_state"
    INCIDENT_STATE = "incident_state"


class PolicyEffect(StrEnum):
    """What a rule does when it matches: admit or refuse.

    The serialized values are the same ``"allow"``/``"deny"`` pair
    ``SafetyDecision.outcome`` already uses, so a policy refusal and a safety
    refusal read identically in a log line.
    """

    ALLOW = "allow"
    DENY = "deny"


class PolicyOperator(StrEnum):
    """How a predicate reads the observed values of its dimension.

    ``NOT_IN`` and the absence operators are separated on purpose. ``NOT_IN``
    is a statement about values that *were* observed, so an unobserved
    dimension never satisfies it — otherwise a facts set that simply forgot to
    record a dimension would satisfy every deny-shaped "not in" rule and a
    policy would refuse work for the wrong reason. ``PRESENT`` / ``ABSENT`` are
    the operators that talk about observability itself.
    """

    IN = "in"  # any observed value is one of values
    NOT_IN = "not_in"  # observed values exist and none of them is in values
    ALL_IN = "all_in"  # observed values exist and every one is in values
    EXACT = "exact"  # the observed set equals the value set
    AT_LEAST = "at_least"  # max observed number >= values[0]
    AT_MOST = "at_most"  # max observed number <= values[0]
    PRESENT = "present"  # the dimension was observed at all
    ABSENT = "absent"  # the dimension was not observed


NUMERIC_OPERATORS: frozenset[PolicyOperator] = frozenset(
    {PolicyOperator.AT_LEAST, PolicyOperator.AT_MOST}
)
_PRESENCE_OPERATORS: frozenset[PolicyOperator] = frozenset(
    {PolicyOperator.PRESENT, PolicyOperator.ABSENT}
)


class PolicyFacts(BaseModel):
    """The observed facts a decision is made *from* — the entire input side.

    One entry per dimension, holding every value observed for it (a plan can
    carry several targets, several capabilities, several faults). A dimension
    with no entry is *unobserved*, which is different from observed-empty and
    is treated differently by :class:`PolicyPredicate`.
    """

    model_config = ConfigDict(frozen=True)

    values: dict[PolicyDimension, tuple[str, ...]] = Field(default_factory=dict)

    def observed(self, dimension: PolicyDimension) -> frozenset[str] | None:
        """The values recorded for ``dimension``, or ``None`` when unobserved.

        ``None`` (unobserved) is distinct from ``frozenset()`` (observed, but
        nothing to report): only the former makes ``NOT_IN`` fail to match.
        """
        recorded = self.values.get(dimension)
        if recorded is None:
            return None
        return frozenset(recorded)

    def with_values(self, dimension: PolicyDimension, *values: str) -> PolicyFacts:
        """A copy with ``dimension``'s value set replaced by ``values``."""
        merged = dict(self.values)
        merged[dimension] = tuple(values)
        return self.model_copy(update={"values": merged})

    def facts_digest(self) -> str:
        """Content digest of the facts, for pinning a decision to its inputs."""
        return digest(
            {
                dimension.value: sorted(vals)
                for dimension, vals in sorted(self.values.items(), key=lambda item: item[0].value)
            }
        )


class PolicyPredicate(BaseModel):
    """A test over one dimension's observed values.

    Deliberately dimension-free: the rule names the dimension, the predicate
    says what to do with it. That split keeps a predicate reusable across the
    rules that share one comparison, and it means a rule's ``dimension`` field
    is never ambiguous.
    """

    model_config = ConfigDict(frozen=True)

    operator: PolicyOperator
    values: tuple[str, ...] = ()

    @model_validator(mode="after")
    def _check_values(self) -> PolicyPredicate:
        needs_values = self.operator not in _PRESENCE_OPERATORS
        if needs_values and not self.values:
            msg = f"operator {self.operator.value!r} requires at least one value"
            raise InvariantViolationError("policy.predicate_values", msg)
        if self.operator in NUMERIC_OPERATORS and (
            len(self.values) != 1 or not _is_numeric(self.values[0])
        ):
            msg = (
                f"operator {self.operator.value!r} requires exactly one numeric "
                f"threshold, got {list(self.values)!r}"
            )
            raise InvariantViolationError("policy.predicate_values", msg)
        return self

    def matches(self, observed: frozenset[str] | None) -> bool:
        """Evaluate against one dimension's observed values.

        Unobserved (``None``) and observed-empty (``frozenset()``) are the same
        thing to every operator except the presence pair, because a rule has
        nothing to compare when the facts say nothing. The numeric operators
        likewise do not match a value that is not a number: concurrency,
        damage budget, and cloud cost are authored as numbers-as-text by the
        facts builder, and a categorical value leaking into a numeric
        comparison is an authoring mistake, not a reason to invent a verdict.
        """
        operator = self.operator
        if operator is PolicyOperator.PRESENT:
            return observed is not None
        if operator is PolicyOperator.ABSENT:
            return observed is None
        if observed is None or not observed:
            return False
        return _SET_OPERATORS[operator](observed, frozenset(self.values))

    def describe(self) -> str:
        """Human-readable form, for explanations and authored docs."""
        if self.operator in _PRESENCE_OPERATORS:
            return f"{self.operator.value}()"
        return f"{self.operator.value}({', '.join(self.values)})"

    def requirement(self) -> str:
        """What has to hold for this predicate to *match*, in one sentence.

        The companion to :meth:`describe`, and what makes a denial explainable
        rather than merely reported: "observed ``critical``" tells a reader what
        the gate saw, and this tells them what it wanted instead. Together they
        are the promotion-refusal shape — what happened, and what would have
        happened otherwise — with no second evaluation and no authoring step in
        between, because both halves are read off the same predicate object that
        made the decision.

        Deliberately phrased over *observed values* and never over the rule's own
        ``values`` alone: ``not_in(sre, service_owner)`` matching means "no
        observed level is one of these", not "the observed levels are none of
        these and there were none at all" — an unobserved dimension never matches
        at all (see :meth:`matches`), so the sentence must not imply it could.
        """
        values = ", ".join(self.values)
        if self.operator is PolicyOperator.IN:
            return f"at least one observed value is in ({values})"
        if self.operator is PolicyOperator.NOT_IN:
            return f"observed values exist and none of them is in ({values})"
        if self.operator is PolicyOperator.ALL_IN:
            return f"every observed value is in ({values})"
        if self.operator is PolicyOperator.EXACT:
            return f"the observed values are exactly ({values})"
        if self.operator is PolicyOperator.AT_LEAST:
            return f"the largest observed number is at least {values}"
        if self.operator is PolicyOperator.AT_MOST:
            return f"the largest observed number is at most {values}"
        if self.operator is PolicyOperator.PRESENT:
            return "the dimension was observed at all"
        return "the dimension was not observed"


def _is_numeric(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True


def _worst_number(observed: frozenset[str]) -> float | None:
    """The largest observed value, ignoring non-numeric entries."""
    numbers = [float(v) for v in sorted(observed) if _is_numeric(v)]
    return numbers[-1] if numbers else None


def _at_least(observed: frozenset[str], threshold: frozenset[str]) -> bool:
    worst = _worst_number(observed)
    return worst is not None and worst >= float(next(iter(threshold)))


def _at_most(observed: frozenset[str], threshold: frozenset[str]) -> bool:
    worst = _worst_number(observed)
    return worst is not None and worst <= float(next(iter(threshold)))


_SET_OPERATORS: dict[PolicyOperator, Callable[[frozenset[str], frozenset[str]], bool]] = {
    PolicyOperator.IN: lambda observed, values: bool(observed & values),
    PolicyOperator.NOT_IN: lambda observed, values: not (observed & values),
    PolicyOperator.ALL_IN: lambda observed, values: observed <= values,
    PolicyOperator.EXACT: lambda observed, values: observed == values,
    PolicyOperator.AT_LEAST: _at_least,
    PolicyOperator.AT_MOST: _at_most,
}
"""The comparison table. ``threshold`` arrives as a one-element set because the
validator has already established that a numeric operator carries exactly one
numeric value."""


class PolicyRule(BaseModel):
    """One deny/allow statement: which dimension, which test, which effect."""

    model_config = ConfigDict(frozen=True)

    rule_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{0,127}$")
    dimension: PolicyDimension
    predicate: PolicyPredicate
    effect: PolicyEffect
    # Higher wins when two rules both match. Default 0 so ordering between
    # unannotated rules is the stable ``rule_id`` tiebreak, never dict order.
    precedence: int = 0
    reason: str = ""
    remediation: str = ""

    def matches(self, facts: PolicyFacts) -> bool:
        return self.predicate.matches(facts.observed(self.dimension))

    def precedence_key(self) -> tuple[int, str, str]:
        """Total, content-derived sort key — see :func:`resolve_precedence`."""
        return (-self.precedence, self.dimension.value, self.rule_id)

    def rule_digest(self) -> str:
        return digest(self.model_dump(mode="json"))

    def explain(self, facts: PolicyFacts) -> str:
        """One line naming the rule, its test, and what it saw."""
        observed = facts.observed(self.dimension)
        seen = "<unobserved>" if observed is None else ", ".join(sorted(observed))
        return (
            f"{self.rule_id} [{self.dimension.value} {self.predicate.describe()}] "
            f"-> {self.effect.value}; observed {seen}"
        )

    def explain_detail(self, facts: PolicyFacts) -> str:
        """:meth:`explain` plus *why* the effect fired — what it wanted instead.

        The two halves together are what plan 07 Phase 3 asks an ``explain`` to
        show: the rule, the observed values, and the values that would have
        passed. Both come off this one rule and the same ``facts`` the decision
        was made from, so an explanation cannot disagree with the verdict it is
        explaining.
        """
        fired = "refused" if self.effect is PolicyEffect.DENY else "permitted"
        return f"{self.explain(facts)}; {fired} because {self.predicate.requirement()}"


class PolicyBundle(BaseModel):
    """A versioned, digest-addressed set of rules plus its inheritance edges.

    ``parents`` names other bundles this one extends; the child wins on any
    ``rule_id`` both declare (see :func:`inherited_rules`). ``content_digest``
    is the pin: once set, the bundle refuses to exist in a form whose content
    has drifted from that digest, so an approval, an evidence record, and a
    later replay can all name the same bundle by value.

    ``compatibility_edges`` is plan 07 gap 66's collision graph, and it lives
    *here* rather than only on the gate inputs for one reason: an approval binds
    a policy digest, so putting the graph inside the bundle is what makes an
    approval on this plan cover the pairs this bundle declares. A graph supplied
    as a side-channel is not covered by any digest anybody signs, which would
    leave the one thing that decides whether two faults may run together outside
    the thing an auditor can check. Adding an edge therefore changes the bundle's
    content digest, exactly like adding a rule does.
    """

    model_config = ConfigDict(frozen=True)

    bundle_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    version: int = Field(ge=1)
    rules: tuple[PolicyRule, ...] = ()
    compatibility_edges: tuple[CompatibilityEdge, ...] = ()
    parents: tuple[str, ...] = ()
    # Fail closed: a facts set no rule speaks to is refused, not waved through.
    default_effect: PolicyEffect = PolicyEffect.DENY
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = None
    content_digest: str | None = None
    description: str = ""

    @model_validator(mode="after")
    def _check_pin(self) -> PolicyBundle:
        if self.content_digest is not None and self.content_digest != self.compute_digest():
            msg = (
                f"policy bundle {self.bundle_id} v{self.version} carries digest "
                f"{self.content_digest} but its content hashes to {self.compute_digest()}"
            )
            raise InvariantViolationError("policy.bundle_digest_mismatch", msg)
        if self.expires_at is not None and self.expires_at <= self.created_at:
            msg = (
                f"policy bundle {self.bundle_id} v{self.version} expires "
                f"({self.expires_at.isoformat()}) at or before it was created "
                f"({self.created_at.isoformat()})"
            )
            raise InvariantViolationError("policy.bundle_window", msg)
        return self

    # -- digest ---------------------------------------------------------------
    def compute_digest(self) -> str:
        """Canonical digest of the bundle's content, excluding the pin itself."""
        payload = {
            key: value
            for key, value in self.model_dump(mode="json").items()
            if key != "content_digest"
        }
        return digest(payload)

    def is_pinned(self) -> bool:
        return self.content_digest is not None

    def pin(self) -> PolicyBundle:
        """A copy carrying ``content_digest`` set to its own content digest."""
        return self.model_copy(update={"content_digest": self.compute_digest()})

    def verify_pin(self) -> bool:
        """True when a pinned bundle still matches its pin (unpinned: True).

        Raises:
            InvariantViolationError: If a pinned bundle's content has drifted.
        """
        if self.content_digest is None:
            return True
        if self.content_digest != self.compute_digest():
            msg = f"policy bundle {self.bundle_id} v{self.version} no longer matches its pin"
            raise InvariantViolationError("policy.bundle_digest_mismatch", msg)
        return True

    # -- lifecycle ------------------------------------------------------------
    def is_expired(self, now: datetime) -> bool:
        """True at and after ``expires_at``; a bundle with no expiry never is."""
        return self.expires_at is not None and now >= self.expires_at

    def authorizes(self, now: datetime) -> bool:
        """The one question the negative control asks of an expired version."""
        return not self.is_expired(now)

    def describe(self) -> str:
        window = "never" if self.expires_at is None else self.expires_at.isoformat()
        return f"{self.bundle_id} v{self.version} (expires {window})"

    def graph(self) -> tuple[CompatibilityEdge, ...]:
        """The collision graph this bundle declares.

        Named rather than read as ``compatibility_edges`` at every call site
        because the field is the *data* and this is the question a gate asks of
        it. Empty for a bundle that declares no pairs, which is not the same as
        a bundle that forbids nothing: an undeclared pair is permitted by
        :func:`evaluate_compatibility` precisely so the graph stays additive to
        :attr:`~mayhem.domain.experiments.BlastRadiusBudget.forbidden_fault_pairs`.
        """
        return self.compatibility_edges

    def describes_pair(self, left_fault: str, right_fault: str) -> bool:
        """Whether *this* bundle, not a side-channel, declares the pair."""
        return frozenset({left_fault, right_fault}) in {
            edge.pair() for edge in self.compatibility_edges
        }


def inherited_rules(
    bundle: PolicyBundle,
    index: Mapping[str, PolicyBundle],
    *,
    _stack: tuple[str, ...] = (),
) -> tuple[PolicyRule, ...]:
    """``bundle``'s rules with every ancestor's folded in.

    Depth-first in the authored ``parents`` order; a rule from a nearer bundle
    replaces one with the same ``rule_id`` from a further one, which is what
    makes "the child overrides the parent" a fact about the function and not a
    convention about who calls it. A parent that cannot be resolved, or a cycle,
    raises rather than silently dropping a policy layer.
    """
    if bundle.bundle_id in _stack:
        chain = " -> ".join((*_stack, bundle.bundle_id))
        msg = f"policy bundle inheritance cycle: {chain}"
        raise InvariantViolationError("policy.bundle_cycle", msg)
    resolved: dict[str, PolicyRule] = {}
    for parent_id in bundle.parents:
        parent = index.get(parent_id)
        if parent is None:
            msg = f"policy bundle {bundle.bundle_id!r} inherits from unknown {parent_id!r}"
            raise InvariantViolationError("policy.bundle_parent_missing", msg)
        for rule in inherited_rules(parent, index, _stack=(*_stack, bundle.bundle_id)):
            resolved[rule.rule_id] = rule
    for rule in bundle.rules:
        resolved[rule.rule_id] = rule
    return tuple(resolved.values())


def resolve_precedence(rules: Iterable[PolicyRule]) -> tuple[PolicyRule, ...]:
    """Sort rules by precedence, then dimension, then rule id.

    Every component of :meth:`PolicyRule.precedence_key` is authored content, so
    the order is identical for the same rules however the caller collected them
    (a ``set``, a dict's values, a list in any order).
    """
    return tuple(sorted(rules, key=PolicyRule.precedence_key))


def effective_rules(
    bundle: PolicyBundle, index: Mapping[str, PolicyBundle] | None = None
) -> tuple[PolicyRule, ...]:
    """The bundle's resolved, precedence-ordered rule set."""
    return resolve_precedence(inherited_rules(bundle, index or {}))


class PolicyDecision(BaseModel):
    """The verdict: allow or deny, why, and the exact inputs that produced it.

    ``rule_digest`` pins the rule set and ``policy_digest`` the bundle it came
    from, so an evidence record can name both and a replay can refuse to claim
    a decision that was actually reached under different inputs.
    """

    model_config = ConfigDict(frozen=True)

    outcome: Literal["allow", "deny"]
    reasons: tuple[str, ...] = ()
    matched_rules: tuple[str, ...] = ()
    bundle_id: str = ""
    bundle_version: int = 0
    rule_digest: str = ""
    policy_digest: str = ""
    facts_digest: str = ""

    @property
    def allowed(self) -> bool:
        return self.outcome == "allow"

    @property
    def denied(self) -> bool:
        return self.outcome == "deny"

    def decision_digest(self) -> str:
        """Canonical digest of the decision — the replay comparison key."""
        return digest(self.model_dump(mode="json"))

    def inputs(self) -> dict[str, Any]:
        """The machine-readable half, matching ``SafetyDecision.inputs``."""
        return {
            "outcome": self.outcome,
            "bundle": self.describe(),
            "matched_rules": list(self.matched_rules),
            "rule_digest": self.rule_digest,
            "policy_digest": self.policy_digest,
            "facts_digest": self.facts_digest,
        }

    def describe(self) -> str:
        return f"{self.bundle_id} v{self.bundle_version}"


def evaluate_rules(
    rules: Iterable[PolicyRule],
    facts: PolicyFacts,
    *,
    bundle_id: str = "",
    bundle_version: int = 0,
    default_effect: PolicyEffect = PolicyEffect.DENY,
    policy_digest: str | None = None,
) -> PolicyDecision:
    """Evaluate an already-resolved rule set against ``facts``.

    Deny overrides allow: any matching deny decides the outcome on its own, and
    allow rules can only *also* speak when nothing refused. That asymmetry is
    the reason an expired or mis-pinned policy fails closed — there is no
    combination of allow rules that outranks a refusal.

    ``policy_digest`` is the digest the decision will be recorded under. A
    caller holding a bundle passes :meth:`PolicyBundle.compute_digest`, so one
    digest identifies one policy across every decision it produced; a caller
    with a bare rule set (no bundle to point at) gets a digest derived from the
    rule set itself instead.
    """
    ordered = resolve_precedence(rules)
    denies: list[PolicyRule] = []
    allows: list[PolicyRule] = []
    for rule in ordered:
        if not rule.matches(facts):
            continue
        (denies if rule.effect is PolicyEffect.DENY else allows).append(rule)

    rule_digest = digest([rule.model_dump(mode="json") for rule in ordered])
    policy_ref = policy_digest or digest(
        {
            "bundle_id": bundle_id,
            "bundle_version": bundle_version,
            "default_effect": default_effect.value,
            "rule_digest": rule_digest,
        }
    )

    def _reason(rule: PolicyRule) -> str:
        body = rule.reason or rule.explain(facts)
        return f"{body} [{rule.rule_id}]"

    if denies:
        return PolicyDecision(
            outcome="deny",
            reasons=tuple(_reason(rule) for rule in denies),
            matched_rules=tuple(rule.rule_id for rule in denies),
            bundle_id=bundle_id,
            bundle_version=bundle_version,
            rule_digest=rule_digest,
            policy_digest=policy_ref,
            facts_digest=facts.facts_digest(),
        )

    if default_effect is PolicyEffect.DENY and not allows:
        return PolicyDecision(
            outcome="deny",
            reasons=(
                f"no rule in {bundle_id or 'the policy set'} v{bundle_version} "
                f"permits these facts; policy defaults to deny [policy.default_deny]",
            ),
            bundle_id=bundle_id,
            bundle_version=bundle_version,
            rule_digest=rule_digest,
            policy_digest=policy_ref,
            facts_digest=facts.facts_digest(),
        )

    return PolicyDecision(
        outcome="allow",
        reasons=tuple(_reason(rule) for rule in allows),
        matched_rules=tuple(rule.rule_id for rule in allows),
        bundle_id=bundle_id,
        bundle_version=bundle_version,
        rule_digest=rule_digest,
        policy_digest=policy_ref,
        facts_digest=facts.facts_digest(),
    )


def evaluate_bundle(
    bundle: PolicyBundle,
    facts: PolicyFacts,
    *,
    now: datetime,
    index: Mapping[str, PolicyBundle] | None = None,
) -> PolicyDecision:
    """Evaluate ``bundle`` against ``facts`` as of ``now``.

    ``now`` is a required argument rather than a default ``utc_now()`` call:
    expiry is the one thing in this decision that depends on the clock, and a
    clock the caller did not pass is exactly the ambient behavior Phase 2's
    acceptance forbids. An expired bundle refuses *before* its rules are read,
    which is the negative control for "an expired policy version cannot
    authorize a run".
    """
    rules = effective_rules(bundle, index)
    if not bundle.authorizes(now):
        return PolicyDecision(
            outcome="deny",
            reasons=(
                f"policy bundle {bundle.describe()} expired at "
                f"{bundle.expires_at.isoformat() if bundle.expires_at else '?'}; "
                "an expired policy version cannot authorize a run "
                "[policy.bundle_expired]",
            ),
            bundle_id=bundle.bundle_id,
            bundle_version=bundle.version,
            rule_digest=digest([rule.model_dump(mode="json") for rule in rules]),
            policy_digest=bundle.compute_digest(),
            facts_digest=facts.facts_digest(),
        )
    return evaluate_rules(
        rules,
        facts,
        bundle_id=bundle.bundle_id,
        bundle_version=bundle.version,
        default_effect=bundle.default_effect,
        policy_digest=bundle.compute_digest(),
    )


# -- hierarchical damage budgets (gap 67) --------------------------------------


class BudgetScope(StrEnum):
    """The five levels a damage budget is spent against, widest first."""

    TEAM = "team"
    ENVIRONMENT = "environment"
    SERVICE = "service"
    EXPERIMENT = "experiment"
    FAULT = "fault"


BUDGET_SCOPE_ORDER: dict[BudgetScope, int] = {
    BudgetScope.TEAM: 0,
    BudgetScope.ENVIRONMENT: 1,
    BudgetScope.SERVICE: 2,
    BudgetScope.EXPERIMENT: 3,
    BudgetScope.FAULT: 4,
}
"""Width of the hierarchy, so a child knows which level must contain it."""

_NEXT_SCOPE: dict[BudgetScope, BudgetScope | None] = {
    BudgetScope.TEAM: BudgetScope.ENVIRONMENT,
    BudgetScope.ENVIRONMENT: BudgetScope.SERVICE,
    BudgetScope.SERVICE: BudgetScope.EXPERIMENT,
    BudgetScope.EXPERIMENT: BudgetScope.FAULT,
    BudgetScope.FAULT: None,
}

#: Rounding applied to accumulated damage so a replay cannot drift on the last
#: binary digit of a repeated addition. Six places is far below any budget a
#: human authors and far above the noise floor of the float arithmetic itself.
DAMAGE_PRECISION: int = 6


class BudgetCharge(BaseModel):
    """The arithmetic of one ``post`` at one level of the hierarchy."""

    model_config = ConfigDict(frozen=True)

    scope: BudgetScope
    key: str
    amount_s: float
    before_s: float
    after_s: float
    limit_s: float | None = None

    @property
    def unbounded(self) -> bool:
        return self.limit_s is None

    @property
    def headroom_s(self) -> float | None:
        """Budget left after the charge; negative once exhausted."""
        return (
            None if self.limit_s is None else round(self.limit_s - self.after_s, DAMAGE_PRECISION)
        )

    @property
    def exceeded(self) -> bool:
        return self.limit_s is not None and self.after_s > self.limit_s


class BudgetNode(BaseModel):
    """One node of the team → environment → service → experiment → fault tree.

    Immutable: ``charge``/``post_charge`` return a new tree rather than
    mutating, so a caller can evaluate a candidate charge against a real ledger
    without spending it. That is the same probe-then-commit shape
    ``check_blast_radius`` uses with ``DamageQuota.unrestricted()``.
    """

    model_config = ConfigDict(frozen=True)

    scope: BudgetScope
    key: str
    limit_s: float | None = None
    spent_s: float = 0.0
    children: tuple[BudgetNode, ...] = ()

    @model_validator(mode="after")
    def _check_node(self) -> BudgetNode:
        if not self.key:
            msg = f"budget node at scope {self.scope.value!r} has an empty key"
            raise InvariantViolationError("budget.empty_key", msg)
        if self.limit_s is not None and self.limit_s < 0.0:
            msg = f"budget node {self.key!r} has a negative limit {self.limit_s}"
            # Damage-qualified, and deliberately NOT ``budget.negative_limit``:
            # that id belongs to :data:`mayhem.domain.budgets.RULE_NEGATIVE_LIMIT`,
            # which is the *resource* budget's refusal over cpu-seconds and
            # request counts. These two ledgers are not the same ledger —
            # :class:`mayhem.domain.budgets.ResourceScope` says so at length —
            # and the two refusals do not even share a threshold: a zero limit is
            # a typo for a resource budget (``<= 0.0``) and a legal
            # "no ceiling at this scope" here (``< 0.0``). One id for both would
            # make an evidence record naming it ambiguous about which budget was
            # authored badly. Do not de-duplicate these back together.
            raise InvariantViolationError("budget.damage_negative_limit", msg)
        if self.spent_s < 0.0:
            msg = f"budget node {self.key!r} has negative spend {self.spent_s}"
            raise InvariantViolationError("budget.negative_spend", msg)
        seen: set[str] = set()
        expected = _NEXT_SCOPE[self.scope]
        for child in self.children:
            if child.key in seen:
                msg = (
                    f"budget node {self.key!r} has two {child.scope.value} "
                    f"children named {child.key!r}"
                )
                raise InvariantViolationError("budget.duplicate_child", msg)
            if child.scope is not expected:
                msg = (
                    f"budget node {self.key!r} ({self.scope.value}) cannot hold "
                    f"{child.scope.value!r} child {child.key!r}; expected {expected}"
                )
                raise InvariantViolationError("budget.scope_order", msg)
            seen.add(child.key)
        return self

    # -- reads ----------------------------------------------------------------
    @property
    def unbounded(self) -> bool:
        return self.limit_s is None

    @property
    def headroom_s(self) -> float | None:
        return (
            None if self.limit_s is None else round(self.limit_s - self.spent_s, DAMAGE_PRECISION)
        )

    @property
    def exhausted(self) -> bool:
        """This node alone, ignoring its subtree."""
        return self.limit_s is not None and self.spent_s > self.limit_s

    def is_exhausted(self) -> bool:
        """This node or anything beneath it has gone over its limit."""
        return self.exhausted or any(child.is_exhausted() for child in self.children)

    def child(self, scope: BudgetScope, key: str) -> BudgetNode | None:
        if scope is not _NEXT_SCOPE[self.scope]:
            return None
        for candidate in self.children:
            if candidate.scope is scope and candidate.key == key:
                return candidate
        return None

    def find(self, scope: BudgetScope, key: str) -> BudgetNode | None:
        """Depth-first search for a node anywhere in this subtree."""
        if self.scope is scope and self.key == key:
            return self
        for candidate in self.children:
            found = candidate.find(scope, key)
            if found is not None:
                return found
        return None

    def path(self, keys: Sequence[str]) -> tuple[BudgetNode, ...]:
        """Resolve ``keys`` (team → … → fault) to the nodes they name.

        The keys are matched *against* the tree, not assumed to line up with
        it: ``keys[0]`` is this node, ``keys[1]`` is this node's child, and a
        key that does not name an existing child ends the walk. A hierarchy
        whose levels were not filled in exactly therefore fails loudly instead
        of charging a node the caller did not name.

        Raises:
            InvariantViolationError: If the path does not exist in this tree.
        """
        node: BudgetNode | None = self
        resolved: list[BudgetNode] = []
        for index in range(len(keys)):
            if node is None:
                break
            if index and BUDGET_SCOPE_ORDER[node.scope] != index:
                msg = (
                    f"budget path {list(keys)!r} reaches scope {node.scope.value!r} "
                    f"at depth {index}"
                )
                raise InvariantViolationError("budget.path_order", msg)
            resolved.append(node)
            if index + 1 == len(keys):
                node = None
                continue
            downward = _NEXT_SCOPE[node.scope]
            node = node.child(downward, keys[index + 1]) if downward is not None else None
        if node is not None or len(resolved) != len(keys):
            msg = f"budget path {list(keys)!r} does not exist under {self.key!r}"
            raise InvariantViolationError("budget.path_missing", msg)
        return tuple(resolved)

    # -- writes (all return new trees) ---------------------------------------
    def with_child(self, child: BudgetNode) -> BudgetNode:
        """A copy of this node with ``child`` attached; duplicates are rejected."""
        if child.scope is not _NEXT_SCOPE[self.scope]:
            msg = (
                f"budget node {self.key!r} ({self.scope.value}) cannot hold "
                f"{child.scope.value!r} child {child.key!r}"
            )
            raise InvariantViolationError("budget.scope_order", msg)
        if self.child(child.scope, child.key) is not None:
            msg = f"budget node {self.key!r} already holds {child.scope.value} {child.key!r}"
            raise InvariantViolationError("budget.duplicate_child", msg)
        return self.model_copy(update={"children": (*self.children, child)})

    def charge(self, amount_s: float) -> tuple[BudgetNode, BudgetCharge]:
        """Spend ``amount_s`` at this node only. Returns the new node."""
        after = round(self.spent_s + amount_s, DAMAGE_PRECISION)
        charge = BudgetCharge(
            scope=self.scope,
            key=self.key,
            amount_s=amount_s,
            before_s=self.spent_s,
            after_s=after,
            limit_s=self.limit_s,
        )
        return self.model_copy(update={"spent_s": after}), charge

    def post_charge(
        self, path: Sequence[str], amount_s: float
    ) -> tuple[BudgetNode, tuple[BudgetCharge, ...]]:
        """Spend ``amount_s`` at ``path`` and at every ancestor above it.

        ``path`` names the leaf outward-in order (team, environment, service,
        experiment, fault) and must already exist: an unresolvable path raises
        rather than inventing an unbounded node, because silently creating one
        would turn a typo'd team name into damage charged to nobody.

        The returned charges run widest-first, so the caller reads the reason a
        plan was refused in the order the refusal is about.
        """
        if amount_s < 0.0:
            msg = f"cannot post a negative charge ({amount_s}) to budget {list(path)!r}"
            raise InvariantViolationError("budget.negative_charge", msg)
        nodes = self.path(path)
        charges: list[BudgetCharge] = []
        updated = list(nodes)
        for position in range(len(updated) - 1, -1, -1):
            node, charge = updated[position].charge(amount_s)
            updated[position] = node
            charges.append(charge)
        rebuilt = updated[-1]
        for position in range(len(updated) - 2, -1, -1):
            parent = updated[position]
            target = nodes[position + 1]
            children = list(parent.children)
            for offset, child in enumerate(children):
                if child.scope is target.scope and child.key == target.key:
                    children[offset] = rebuilt
                    break
            else:  # pragma: no cover - path() guarantees the child is present
                msg = f"budget path {list(path)!r} lost {target.key!r} below {parent.key!r}"
                raise InvariantViolationError("budget.path_broken", msg)
            rebuilt = parent.model_copy(update={"children": tuple(children)})
        charges.reverse()
        return rebuilt, tuple(charges)


# -- the persisted damage ledger (gap 67's commit side) ---------------------------


class BudgetLedgerEntry(BaseModel):
    """One charge as it exists on the *persisted* ledger.

    A :class:`BudgetNode` is a value. It can be built, charged, and compared, and
    then it is gone with the process that built it, which is the whole difference
    between a probe and a budget: :meth:`BudgetNode.post_charge` answers "what
    would this plan spend", and only a sum of these answers "what has this team
    already spent, across every run so far".

    This is that record, and it is the record that makes the hierarchy a budget
    over **time**. It is an append-only charge rather than a running total on
    purpose — see the ledger port in :mod:`mayhem.controller.policy_gate` — so a
    stored total can never disagree with the charges that produced it, and a
    reader can always show the arithmetic instead of a number nobody can account
    for.

    ``charged_at`` is the *gate's* clock (``PolicyGateInputs.now``), not the
    writer's. A charge is a fact about the decision that posted it, so recording
    the decision's own clock is what lets a replay of that decision reproduce
    when the charge landed without reading a wall clock the gate was forbidden to
    touch.
    """

    model_config = ConfigDict(frozen=True)

    scope: BudgetScope
    key: str
    amount_s: float
    run_id: str = ""
    charged_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _check_entry(self) -> BudgetLedgerEntry:
        # The same two refusals ``BudgetNode`` makes, for the same reasons: an
        # entry with no key names no budget, and a negative amount would be a
        # refund nobody agreed to give. A zero amount is legal — a zero-duration
        # fault is damage of no seconds, and recording it is still a fact.
        if not self.key:
            msg = f"budget ledger entry at scope {self.scope.value!r} has an empty key"
            raise InvariantViolationError("budget.empty_key", msg)
        if self.amount_s < 0.0:
            msg = f"budget ledger entry for {self.key!r} has a negative amount {self.amount_s}"
            raise InvariantViolationError("budget.negative_charge", msg)
        return self

    @classmethod
    def from_charge(
        cls, charge: BudgetCharge, *, run_id: str, charged_at: datetime
    ) -> BudgetLedgerEntry:
        """The ledger entry for one :meth:`BudgetNode.charge` result.

        Reads ``amount_s`` off the charge rather than re-deriving it from the
        plan, so what is persisted is exactly the arithmetic the gate judged.
        """
        return cls(
            scope=charge.scope,
            key=charge.key,
            amount_s=charge.amount_s,
            run_id=run_id,
            charged_at=charged_at,
        )

    def describe(self) -> str:
        return f"{self.scope.value}/{self.key} += {self.amount_s:g}s (run {self.run_id or '?'})"


def fold_spend(tree: BudgetNode, entries: Iterable[BudgetLedgerEntry]) -> BudgetNode:
    """``tree`` with every posted charge for each node folded into its ``spent_s``.

    Pure, and the whole of what "persisted across runs" means. A caller mounts
    the *authored* hierarchy — shape and authored limits, never spend, because a
    spent value is a fact about the past rather than a thing a config file can
    state — and this returns the same tree carrying the history. Two runs against
    one authored hierarchy therefore see different headroom without either run
    having mutated the object the author wrote.

    Rounded at :data:`DAMAGE_PRECISION` for the same reason ``charge`` rounds:
    a sum of many entries must not drift on a last binary digit that a replay
    would then disagree about.

    **An entry naming a node ``tree`` does not hold is not an error.** It belongs
    to some other branch of the hierarchy — another team, another environment —
    and this function answers about ``tree`` alone. A charge that cannot be
    attributed to *any* budget is refused when it is posted
    (:meth:`BudgetNode.path`), where refusing still means something, not here,
    where the damage is already on the ledger and nothing could be recovered.
    """
    totals: dict[tuple[BudgetScope, str], float] = {}
    for entry in entries:
        key = (entry.scope, entry.key)
        totals[key] = totals.get(key, 0.0) + entry.amount_s

    def _fold(node: BudgetNode) -> BudgetNode:
        posted = totals.get((node.scope, node.key), 0.0)
        children = tuple(_fold(child) for child in node.children)
        updates: dict[str, Any] = {}
        if posted:
            updates["spent_s"] = round(node.spent_s + posted, DAMAGE_PRECISION)
        if children != node.children:
            updates["children"] = children
        return node.model_copy(update=updates) if updates else node

    return _fold(tree)


# -- environment locking (gap 86) ----------------------------------------------


class ResourceLock(BaseModel):
    """An experiment-scoped reservation on one resource.

    ``owner_run_id`` is what a refusal names — "queued behind run abc, held by
    experiment x" — and ``expires_at`` is what makes the lock safe to abandon:
    a lock nobody released stops blocking the moment it expires, so a dead run
    cannot fence a resource forever.
    """

    model_config = ConfigDict(frozen=True)

    lock_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._:-]{0,127}$")
    resource: str = Field(min_length=1)
    experiment_id: str = Field(min_length=1)
    owner_run_id: str = Field(min_length=1)
    acquired_at: datetime
    expires_at: datetime
    reason: str = ""
    metadata: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check_window(self) -> ResourceLock:
        if self.expires_at <= self.acquired_at:
            msg = (
                f"resource lock {self.lock_id!r} expires ({self.expires_at.isoformat()}) "
                f"at or before it was acquired ({self.acquired_at.isoformat()})"
            )
            raise InvariantViolationError("lock.window", msg)
        return self

    def is_expired(self, now: datetime) -> bool:
        """True at and after ``expires_at``."""
        return now >= self.expires_at

    def is_live(self, now: datetime) -> bool:
        return not self.is_expired(now)

    def covers(self, resource: str) -> bool:
        return self.resource == resource

    def is_owned_by(self, experiment_id: str) -> bool:
        """True when this lock is the given experiment's own reservation."""
        return self.experiment_id == experiment_id

    def describe(self) -> str:
        return (
            f"lock {self.lock_id} held by {self.owner_run_id} "
            f"(experiment {self.experiment_id}) on {self.resource} "
            f"until {self.expires_at.isoformat()}"
        )


class LockVerdict(BaseModel):
    """The outcome of asking for a lock that may already be held."""

    model_config = ConfigDict(frozen=True)

    granted: bool
    resource: str
    requested_by: str
    blockers: tuple[str, ...] = ()
    holder_experiment_id: str = ""
    holder_run_id: str = ""
    holder_expires_at: datetime | None = None
    reason: str = ""

    def queued_behind(self) -> str:
        """The run to name in a refusal, empty when nothing blocks."""
        return self.holder_run_id


def lock_conflicts(existing: ResourceLock, requested: ResourceLock) -> bool:
    """True when ``existing`` stands between ``requested`` and its resource.

    Same resource, overlapping windows, and not the requesting experiment's own
    lock. Re-entrancy is the last clause on purpose: an experiment that already
    holds ``db-primary`` must be able to take it again for a second step
    without queueing behind itself.
    """
    if not existing.covers(requested.resource):
        return False
    if existing.is_owned_by(requested.experiment_id):
        return False
    return (
        existing.expires_at > requested.acquired_at and requested.expires_at > existing.acquired_at
    )


def blocking_locks(
    locks: Iterable[ResourceLock], requested: ResourceLock, *, now: datetime
) -> tuple[ResourceLock, ...]:
    """Live locks standing between ``requested`` and its resource, id-sorted.

    Expired locks are dropped before the conflict test, which is what makes a
    lock held by a dead run fence nothing once its window closes.
    """
    blocking = [lock for lock in locks if lock.is_live(now) and lock_conflicts(lock, requested)]
    return tuple(sorted(blocking, key=lambda lock: lock.lock_id))


def acquire_lock(
    locks: Iterable[ResourceLock], requested: ResourceLock, *, now: datetime
) -> LockVerdict:
    """Decide whether ``requested`` may be granted, naming the owner if not."""
    blockers = blocking_locks(locks, requested, now=now)
    if not blockers:
        return LockVerdict(
            granted=True,
            resource=requested.resource,
            requested_by=requested.owner_run_id,
            reason=f"{requested.resource} is free; lock {requested.lock_id} may be granted",
        )
    first = blockers[0]
    return LockVerdict(
        granted=False,
        resource=requested.resource,
        requested_by=requested.owner_run_id,
        blockers=tuple(lock.lock_id for lock in blockers),
        holder_experiment_id=first.experiment_id,
        holder_run_id=first.owner_run_id,
        holder_expires_at=first.expires_at,
        reason=(
            f"{requested.resource} is reserved by {first.owner_run_id} "
            f"(experiment {first.experiment_id}, lock {first.lock_id}) until "
            f"{first.expires_at.isoformat()}; queue behind it or pick another target"
        ),
    )


# -- fault-pair compatibility graph (gap 66) -----------------------------------


class CompatibilityVerdict(StrEnum):
    """What the collision graph knows about a pair of faults."""

    PERMITTED = "permitted"
    CONFLICTING = "conflicting"
    CONDITIONALLY_SAFE = "conditionally_safe"


class CompatibilityCondition(BaseModel):
    """One fact that must hold for a conditionally-safe pair to be safe."""

    model_config = ConfigDict(frozen=True)

    dimension: PolicyDimension
    values: tuple[str, ...]

    @model_validator(mode="after")
    def _check_values(self) -> CompatibilityCondition:
        if not self.values:
            msg = f"compatibility condition on {self.dimension.value!r} names no values"
            raise InvariantViolationError("compat.empty_condition", msg)
        return self

    def holds(self, facts: PolicyFacts) -> bool:
        observed = facts.observed(self.dimension)
        return observed is not None and bool(observed & set(self.values))

    def describe(self) -> str:
        return f"{self.dimension.value} in ({', '.join(self.values)})"


class CompatibilityEdge(BaseModel):
    """One directed-by-construction but order-insensitive entry of the graph.

    A pair is unordered: ``{a, b}`` is the same pair whichever step runs first,
    which is the same reading ``_first_forbidden_pair`` in
    ``controller.safety`` uses, and the reason the graph cannot be consulted in
    one order and missed in the other.
    """

    model_config = ConfigDict(frozen=True)

    left_fault: str = Field(min_length=1)
    right_fault: str = Field(min_length=1)
    verdict: CompatibilityVerdict
    reason: str = ""
    conditions: tuple[CompatibilityCondition, ...] = ()

    @model_validator(mode="after")
    def _check_edge(self) -> CompatibilityEdge:
        if self.left_fault == self.right_fault:
            msg = f"compatibility edge pairs {self.left_fault!r} with itself"
            raise InvariantViolationError("compat.self_pair", msg)
        if self.verdict is CompatibilityVerdict.CONFLICTING and not self.reason:
            msg = (
                f"compatibility edge {{{self.left_fault}, {self.right_fault}}} is "
                "conflicting but carries no reason"
            )
            raise InvariantViolationError("compat.reason_required", msg)
        if self.verdict is CompatibilityVerdict.CONDITIONALLY_SAFE and not self.conditions:
            msg = (
                f"compatibility edge {{{self.left_fault}, {self.right_fault}}} is "
                "conditionally safe but names no conditions"
            )
            raise InvariantViolationError("compat.conditions_required", msg)
        return self

    def pair(self) -> frozenset[str]:
        return frozenset({self.left_fault, self.right_fault})

    def describe(self) -> str:
        pair = ", ".join(sorted(self.pair()))
        detail = self.reason or ", ".join(c.describe() for c in self.conditions)
        return f"{{{pair}}}: {self.verdict.value} ({detail})"


class CompatibilityOutcome(BaseModel):
    """The graph's answer for one pair, after conditions were applied."""

    model_config = ConfigDict(frozen=True)

    verdict: CompatibilityVerdict
    left_fault: str
    right_fault: str
    declared: bool = False
    reason: str = ""
    unsatisfied: tuple[str, ...] = ()

    @property
    def safe(self) -> bool:
        """True when the pair may run together."""
        return self.verdict is not CompatibilityVerdict.CONFLICTING

    @property
    def conditional(self) -> bool:
        return self.verdict is CompatibilityVerdict.CONDITIONALLY_SAFE

    def describe(self) -> str:
        pair = ", ".join(sorted((self.left_fault, self.right_fault)))
        suffix = f" unmet: {', '.join(self.unsatisfied)}" if self.unsatisfied else ""
        return f"{{{pair}}}: {self.verdict.value} ({self.reason}){suffix}"


def compatibility_edge(
    edges: Iterable[CompatibilityEdge], left_fault: str, right_fault: str
) -> CompatibilityEdge | None:
    """The edge for this unordered pair, or ``None`` when none is declared.

    Order-insensitive by construction: the lookup builds the same
    ``frozenset`` the edges are keyed by, so declaring ``{a, b}`` and asking
    about ``{b, a}`` cannot disagree.
    """
    pair = frozenset({left_fault, right_fault})
    for edge in sorted(edges, key=lambda e: (e.left_fault, e.right_fault)):
        if edge.pair() == pair:
            return edge
    return None


def evaluate_compatibility(
    edges: Iterable[CompatibilityEdge],
    left_fault: str,
    right_fault: str,
    facts: PolicyFacts,
) -> CompatibilityOutcome:
    """Consult the graph for one pair.

    An undeclared pair is permitted. That default is deliberate and additive:
    the authoritative refusal for a forbidden pair remains
    ``BlastRadiusBudget.forbidden_fault_pairs``, enforced per ``{earlier, new}``
    pair in ``controller.safety``. This graph can only add conflicts and
    conditions on top of that, so it cannot quietly turn a passing plan into a
    failing one, and it cannot be the *only* thing standing between a plan and
    an incompatible pair.
    """
    edge = compatibility_edge(edges, left_fault, right_fault)
    if edge is None:
        return CompatibilityOutcome(
            verdict=CompatibilityVerdict.PERMITTED,
            left_fault=left_fault,
            right_fault=right_fault,
            reason="no collision edge declared for this pair",
        )
    if edge.verdict is CompatibilityVerdict.PERMITTED:
        return CompatibilityOutcome(
            verdict=CompatibilityVerdict.PERMITTED,
            left_fault=left_fault,
            right_fault=right_fault,
            declared=True,
            reason=edge.reason or "edge declares the pair compatible",
        )
    if edge.verdict is CompatibilityVerdict.CONFLICTING:
        return CompatibilityOutcome(
            verdict=CompatibilityVerdict.CONFLICTING,
            left_fault=left_fault,
            right_fault=right_fault,
            declared=True,
            reason=edge.reason,
        )
    unmet = tuple(
        condition.dimension.value for condition in edge.conditions if not condition.holds(facts)
    )
    if unmet:
        return CompatibilityOutcome(
            verdict=CompatibilityVerdict.CONFLICTING,
            left_fault=left_fault,
            right_fault=right_fault,
            declared=True,
            reason=edge.reason or "conditionally-safe edge whose conditions did not hold",
            unsatisfied=unmet,
        )
    return CompatibilityOutcome(
        verdict=CompatibilityVerdict.CONDITIONALLY_SAFE,
        left_fault=left_fault,
        right_fault=right_fault,
        declared=True,
        reason=edge.reason or f"all {len(edge.conditions)} condition(s) hold for this pair",
    )
