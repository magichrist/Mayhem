"""Provider-neutral cloud vocabulary (v1.1.0 plan 06, Phase 1).

The *words* of a cloud fault, stated once and independent of any provider SDK.
Phase 2 puts the AWS/GCP/Azure adapters behind these words; nothing in this
module knows a cloud API exists, and nothing here performs IO. What it does
decide is the set of claims that must be *structurally* true before any
adapter is allowed to act, because every one of them is a claim a reviewer
would otherwise have to re-derive by reading adapter code:

1. **A selector resolves to an exact resource identity, or it is refused.**
   :class:`CloudSelector` has no prefix form and no wildcard form — there is
   no field in which to write one, and a value containing a glob metacharacter
   is refused at construction (:data:`CLOUD_SELECTOR_WILDCARD`;
   :func:`ensure_selector_is_specific` raises that same judgement as a typed
   :class:`CloudRefused`, since a pydantic validator can only raise
   :class:`ValueError`). A target that
   has not been resolved is not a :class:`CloudTarget` at all; it is a
   :class:`CloudTargetIntent`, and :func:`resolve_cloud_target` turns an intent
   into a target by requiring *exactly one* matching identity. Zero matches is
   a plan-time refusal (:data:`CLOUD_TARGET_UNRESOLVED`); two or more is
   :data:`CLOUD_TARGET_AMBIGUOUS`, because "run the action on everything this
   matches" is a different plan with a different blast radius, and the
   difference is exactly what a plan-time refusal exists to force somebody to
   write down.

2. **No identity is a target without a provider.** ``provider``,
   ``resource_class``, ``account``, ``region`` and ``resource_id`` are all
   required fields with no defaults, on both :class:`CloudResourceIdentity` and
   :class:`CloudTarget`. There is no construction path that yields a
   provider-less cloud target, and the account/project/subscription boundary
   travels with the identity rather than being an ambient setting.

3. **Irreversibility is a type, not a flag.** The cloud cannot always roll
   back what it did, and an action that cannot be rolled back must be
   distinguishable *before* execution by anything that gates execution — not by
   reading a docstring. :class:`ReversibleCloudAction` and
   :class:`IrreversibleCloudAction` are separate models over a shared
   :class:`CloudAction` base, so :func:`requires_elevated_approval` is an
   ``isinstance`` check rather than a field comparison, and an irreversible
   action additionally cannot be constructed without saying why in
   ``rationale``. Reversibility reuses :class:`mayhem.domain.faults.Reversibility`
   — the same three-rung vocabulary the damage quota prices faults with — so
   "irreversible" means one thing in the whole system.

4. **Every cloud action declares the permission it needs.** ``required_permissions``
   uses :class:`mayhem.domain.provider.ProviderPermission`, the vocabulary the
   provider sandbox already gates on, and a mutating action that does not ask
   for ``target:mutate`` cannot be built
   (:func:`ensure_action_declares_permissions` raises that as a typed refusal,
   for the same validator reason as the selector codes above).
   :func:`check_role_can_perform` answers
   "can this role perform this action?" purely, and a refusal names the exact
   missing permission rather than a boolean.

5. **A cost estimate extends the existing resource-budget vocabulary instead of
   inventing a second money type.** :class:`CostEstimate` is a
   :class:`mayhem.domain.budgets.ResourceEstimate` narrowed to
   ``cloud_spend``: it inherits the mandatory ``basis``, the finiteness and
   non-negativity rules, the replay-stable :data:`~mayhem.domain.budgets.RESOURCE_PRECISION`
   rounding, and the ``currency_micros`` unit that ``compare_estimate`` already
   knows how to read. A cost estimate whose ceiling sits below its own high
   bound is incoherent and is refused
   (:data:`RULE_COST_CEILING_BELOW_HIGH`); :func:`check_cost_ceiling` is the
   pre-mutation hook Phase 4 wires to the admission gate.

**What this module deliberately does not do.** It holds no credentials, names
no account, and grants nothing. The default posture is *nothing* — exactly the
posture ``mayhem.providers.permissions.DEFAULT_PERMISSION_SET`` states, and
like that constant (:data:`DEFAULT_CLOUD_ROLE_GRANTS`) it is a second literal
that agrees with the first rather than an import of it, because the domain may
not depend on the loader layer.

Every function here is pure. There is no clock, no store, no network, and no
import of ``mayhem.toolkit``/``agents``/``controller``/``infra``, ``asyncio``,
``socket``, ``subprocess``, ``sqlite3``, ``pathlib`` or ``os`` per the
"Domain layer has zero IO and no upward imports" contract.
"""

from __future__ import annotations

from enum import StrEnum
from math import isfinite
from typing import TYPE_CHECKING, Final

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mayhem.domain.budgets import RESOURCE_PRECISION, ResourceDimension, ResourceEstimate
from mayhem.domain.errors import DomainError, InvariantViolationError
from mayhem.domain.faults import Reversibility
from mayhem.domain.provider import ProviderPermission
from mayhem.domain.risks import RiskLevel

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

__all__ = [
    "CLOUD_ACTION_PERMISSION_UNDECLARED",
    "CLOUD_AMBIGUOUS_RESOLUTION",
    "CLOUD_COST_CEILING_EXCEEDED",
    "CLOUD_PERMISSION_DENIED",
    "CLOUD_ROLE_PROVIDER_MISMATCH",
    "CLOUD_SELECTOR_EMPTY",
    "CLOUD_SELECTOR_WILDCARD",
    "CLOUD_TARGET_UNRESOLVED",
    "DEFAULT_CLOUD_ROLE_GRANTS",
    "RULE_COST_CEILING_BELOW_HIGH",
    "RULE_COST_ESTIMATE_ORDER",
    "CloudAction",
    "CloudActionKind",
    "CloudPermissionDecision",
    "CloudProviderRef",
    "CloudResourceClass",
    "CloudResourceIdentity",
    "CloudRoleRef",
    "CloudSelector",
    "CloudSelectorDecision",
    "CloudSelectorKind",
    "CloudSpec",
    "CloudTarget",
    "CloudTargetIntent",
    "CostCeilingDecision",
    "CostEstimate",
    "IrreversibleCloudAction",
    "Reversibility",
    "ReversibleCloudAction",
    "check_action_declares_permissions",
    "check_cost_ceiling",
    "check_role_can_perform",
    "check_selector_is_specific",
    "ensure_action_declares_permissions",
    "ensure_cost_ceiling",
    "ensure_role_can_perform",
    "ensure_selector_is_specific",
    "requires_elevated_approval",
    "resolve_cloud_target",
]


# --- refusal codes ------------------------------------------------------------
#
# Part of the module's error contract: an adapter, a CLI renderer or an
# evidence record may branch on these, so they are named here rather than
# spelled at each raise site.

CLOUD_SELECTOR_WILDCARD = "cloud.selector_wildcard"
CLOUD_SELECTOR_EMPTY = "cloud.selector_empty"
CLOUD_TARGET_UNRESOLVED = "cloud.target_unresolved"
CLOUD_AMBIGUOUS_RESOLUTION = "cloud.ambiguous_resolution"
CLOUD_PERMISSION_DENIED = "cloud.permission_denied"
CLOUD_ROLE_PROVIDER_MISMATCH = "cloud.role_provider_mismatch"
CLOUD_ACTION_PERMISSION_UNDECLARED = "cloud.action_permission_undeclared"
CLOUD_COST_CEILING_EXCEEDED = "cloud.cost_ceiling_exceeded"

#: Stable rule ids for the two cost invariants, in the ``<module>.<rule>`` shape
#: :mod:`mayhem.domain.budgets` already uses for its evidence records.
RULE_COST_ESTIMATE_ORDER = "cloud.cost_estimate_order"
RULE_COST_CEILING_BELOW_HIGH = "cloud.cost_ceiling_below_high"

_SELECTOR_REMEDIATION = (
    "a cloud selector must name exact resource identifiers or exact tags; "
    "prefix and wildcard matching are not available on this vocabulary"
)

_RESOLUTION_REMEDIATION = (
    "narrow the selector until it matches exactly one resource identity, or "
    "author one intent per resource; a selector that matches many is a "
    "different plan and must be written out as one"
)

#: A selector is a set of *exact* strings. These characters are the whole
#: vocabulary of "and everything that looks like this", and none of them may
#: appear in an identifier, a tag, an account or a region.
_WILDCARD_CHARS: Final[frozenset[str]] = frozenset({"*", "?", "%", "[", "]"})

#: Identifiers follow the same shape as a provider declaration's dotted id
#: (``domain/provider.py``): lowercase, dotted, no whitespace. Reusing the
#: convention is what lets a cloud action id and a provider fault id sit in the
#: same evidence record without a second naming rule.
_IDENTIFIER_CHARS: Final[frozenset[str]] = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_-.")

_MAX_NAMED_CANDIDATES: Final[int] = 8
"""How many candidate ids an ambiguity refusal names before truncating.

A selector that matches four hundred instances must not turn a plan-time
refusal into a four-hundred-line error message; the count is reported either
way, and the ids are the evidence a reader needs for the common case.
"""


class CloudRefused(DomainError):  # noqa: N818 — public API, not a stdlib error
    """A cloud plan was refused before it could act.

    Attributes:
        code: One of the module's ``CLOUD_*`` refusal codes.
        details: Stable, secret-free context (ids, counts, permission names).
        remediation: Human-readable next step.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: dict[str, object] | None = None,
        remediation: str = "",
    ) -> None:
        self.code = code
        self.details: dict[str, object] = dict(details or {})
        self.remediation = remediation
        super().__init__(message)


# --- providers ----------------------------------------------------------------


class CloudProvider(StrEnum):
    """The clouds this vocabulary names by default.

    ``CUSTOM`` is not a placeholder for an unimplemented adapter: it is the
    escape hatch for a provider-neutral plan that is authored before any
    adapter exists, and it *requires* a ``custom_id`` so a custom provider is
    still an identified provider rather than an anonymous one.
    """

    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    CUSTOM = "custom"


def _require_plain_identifier(value: str, *, subject: str) -> str:
    """Refuse blank, wildcard-bearing or oddly-shaped identifiers."""
    if not value or not value.strip():
        raise ValueError(f"{subject} must not be empty")
    if _WILDCARD_CHARS & set(value):
        raise ValueError(f"{subject} must not contain a wildcard character, got {value!r}")
    return value


class CloudProviderRef(BaseModel):
    """A cloud, named.

    ``provider`` has no default, so there is no construction path that yields a
    target without a provider. The three named clouds take no ``custom_id``:
    allowing ``aws`` plus a name is a second place for a provider's identity to
    drift, and the whole point of this record is that the provider is one fact.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: CloudProvider
    custom_id: str | None = None

    @model_validator(mode="after")
    def _validate_custom(self) -> CloudProviderRef:
        if self.provider is CloudProvider.CUSTOM:
            if self.custom_id is None:
                raise ValueError("a custom cloud provider must name a custom_id")
            _require_plain_identifier(self.custom_id, subject="cloud provider custom_id")
        elif self.custom_id is not None:
            raise ValueError(
                f"provider {self.provider.value!r} must not carry a custom_id; "
                "the provider name is the identity"
            )
        return self

    @property
    def key(self) -> str:
        """The provider's identity as one comparable string."""
        return self.custom_id if self.custom_id is not None else self.provider.value

    def describe(self) -> str:
        return self.key


# --- resource classes ---------------------------------------------------------


class CloudResourceClass(StrEnum):
    """The nine resource classes a cloud action may name.

    A closed vocabulary, matching the plan's core resource classes. An adapter
    that supports none of these has nothing to expose yet, and adding a member
    here is a claim that a provider-neutral action exists for that class.
    """

    VM = "vm"
    NETWORK = "network"
    LOAD_BALANCER = "load_balancer"
    OBJECT_STORAGE = "object_storage"
    BLOCK_STORAGE = "block_storage"
    MANAGED_DATABASE = "managed_database"
    QUEUE = "queue"
    FUNCTION = "function"
    MANAGED_KUBERNETES = "managed_kubernetes"


# --- selectors and identities -------------------------------------------------


class CloudSelectorKind(StrEnum):
    """The two exact-match shapes a selector may take.

    There is deliberately no third. A "prefix" or "pattern" kind is the feature
    this vocabulary refuses to have, and leaving the door open for one later
    would make every current refusal a temporary inconvenience.
    """

    IDENTIFIER = "identifier"
    TAG = "tag"


class CloudSelector(BaseModel):
    """An exact-match selector for one resource class inside one account/region.

    The load-bearing property: **this type has no prefix or wildcard form.**
    A glob metacharacter in any field is refused at construction
    (:data:`CLOUD_SELECTOR_WILDCARD`), and a selector that constrains nothing at
    all is refused (:data:`CLOUD_SELECTOR_EMPTY`) because it would match
    everything and "everything" is never what a plan meant.

    The account/region pair is part of the selector rather than an ambient
    setting, so a selector minted for one subscription cannot quietly resolve
    inside another.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    resource_class: CloudResourceClass
    kind: CloudSelectorKind = CloudSelectorKind.IDENTIFIER
    account: str
    region: str
    identifiers: tuple[str, ...] = ()
    tags: frozenset[str] = frozenset()

    @field_validator("account", "region")
    @classmethod
    def _check_boundary(cls, value: str) -> str:
        return _require_plain_identifier(value, subject="cloud selector boundary")

    @field_validator("identifiers")
    @classmethod
    def _check_identifiers(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            _require_plain_identifier(value, subject="cloud selector identifier")
        if len(set(values)) != len(values):
            raise ValueError("cloud selector identifiers must be unique")
        return values

    @field_validator("tags")
    @classmethod
    def _check_tags(cls, values: frozenset[str]) -> frozenset[str]:
        for value in values:
            _require_plain_identifier(value, subject="cloud selector tag")
        return values

    @model_validator(mode="after")
    def _check_exactness(self) -> CloudSelector:
        # The same two judgements :func:`check_selector_is_specific` makes, so
        # the code and the decision function cannot drift. Raised as ValueError
        # because pydantic is what is calling; the code appears in the message
        # so a caller reading the refusal can still branch on it.
        specificity = check_selector_is_specific(identifiers=self.identifiers, tags=self.tags)
        if not specificity.allowed:
            raise ValueError(f"[{specificity.code}] {specificity.reason}")
        if self.kind is CloudSelectorKind.IDENTIFIER:
            if self.tags:
                raise ValueError("an identifier selector must not carry tags")
        elif self.identifiers:
            raise ValueError("a tag selector must not carry identifiers")
        return self

    def matches(self, identity: CloudResourceIdentity) -> bool:
        """True when *identity* is exactly what this selector names.

        Exact on every axis: the resource class, the account, the region, and
        then either full-string identifier equality or tag-set containment. No
        axis is a prefix test, which is what makes "resolved" mean "this one
        resource" rather than "something shaped like it".
        """
        if identity.resource_class is not self.resource_class:
            return False
        if identity.account != self.account or identity.region != self.region:
            return False
        if self.kind is CloudSelectorKind.IDENTIFIER:
            return identity.resource_id in self.identifiers
        return self.tags <= identity.tags

    def describe(self) -> str:
        criteria = (
            f"identifiers={list(self.identifiers)}"
            if self.kind is CloudSelectorKind.IDENTIFIER
            else f"tags={sorted(self.tags)}"
        )
        return f"{self.resource_class.value} in {self.account}/{self.region} where {criteria}"


class CloudSelectorDecision(BaseModel):
    """Whether a selector is specific enough to act on, judged purely.

    Exists because :data:`CLOUD_SELECTOR_EMPTY` and
    :data:`CLOUD_SELECTOR_WILDCARD` are raised by *constructors*, and a
    constructor raises :class:`ValueError` — which pydantic re-wraps, so no
    adapter or CLI ever saw a :class:`CloudRefused` carrying either code. A
    refusal code nothing can raise is a spelling, not a contract.

    These two decision functions close that gap: they take the *raw* fields a
    caller is about to build a selector from, so the same judgement is available
    with a typed refusal, a remediation string, and structured details. They do
    not weaken the constructor — an empty or wildcard selector is still
    unbuildable — they give the boundary a way to say the same thing in the
    vocabulary the rest of the module refuses in.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    allowed: bool
    code: str = ""
    reason: str = ""
    offending: tuple[str, ...] = ()

    @property
    def denied(self) -> bool:
        return not self.allowed


def check_selector_is_specific(
    *,
    identifiers: Sequence[str] = (),
    tags: Iterable[str] = (),
) -> CloudSelectorDecision:
    """Answer, purely, whether these selector fields name a bounded set.

    Two refusals, in the order a reader would want them:

    * a wildcard or glob character in any member is
      :data:`CLOUD_SELECTOR_WILDCARD` — checked first, because a wildcard in an
      otherwise-empty selector would otherwise be reported as merely empty and
      the real mistake would be hidden; and
    * naming nothing at all is :data:`CLOUD_SELECTOR_EMPTY`, because a selector
      that constrains nothing matches everything, and "everything" is never what
      a plan meant.
    """
    named = tuple(identifiers) + tuple(tags)
    wildcarded = tuple(sorted({value for value in named if _WILDCARD_CHARS & set(value)}))
    if wildcarded:
        return CloudSelectorDecision(
            allowed=False,
            code=CLOUD_SELECTOR_WILDCARD,
            offending=wildcarded,
            reason=(
                f"selector member(s) {', '.join(repr(v) for v in wildcarded)} contain a "
                "wildcard character; a cloud selector is exact-match only"
            ),
        )
    if not named:
        return CloudSelectorDecision(
            allowed=False,
            code=CLOUD_SELECTOR_EMPTY,
            reason=(
                "a cloud selector must name at least one identifier or tag; a selector "
                "that constrains nothing matches every resource in the account/region"
            ),
        )
    return CloudSelectorDecision(
        allowed=True,
        reason=f"selector names {len(named)} member(s)",
    )


def ensure_selector_is_specific(
    *,
    identifiers: Sequence[str] = (),
    tags: Iterable[str] = (),
) -> CloudSelectorDecision:
    """Raise :class:`CloudRefused` unless these selector fields are specific.

    The refusal names what *would* have passed, per this module's convention:
    the offending members for a wildcard, and the requirement for an empty one.
    """
    decision = check_selector_is_specific(identifiers=identifiers, tags=tags)
    if decision.allowed:
        return decision
    raise CloudRefused(
        decision.code,
        decision.reason,
        details={"offending": list(decision.offending)},
        remediation=_SELECTOR_REMEDIATION,
    )


def check_action_declares_permissions(
    action_id: str,
    required_permissions: Iterable[ProviderPermission],
) -> CloudSelectorDecision:
    """Answer, purely, whether an action declares what it needs to act.

    The decision-function counterpart to :meth:`CloudAction._check_permissions`,
    for the same reason as :func:`check_selector_is_specific`: the validator
    raises :class:`ValueError`, so :data:`CLOUD_ACTION_PERMISSION_UNDECLARED` was
    a code no caller could ever receive.
    """
    declared = frozenset(required_permissions)
    if not declared:
        return CloudSelectorDecision(
            allowed=False,
            code=CLOUD_ACTION_PERMISSION_UNDECLARED,
            reason=(
                f"cloud action {action_id!r} declares no required_permissions; every cloud "
                "action acts on a resource and must say what it needs"
            ),
        )
    if ProviderPermission.TARGET_MUTATE not in declared:
        named = ", ".join(sorted(p.value for p in declared))
        return CloudSelectorDecision(
            allowed=False,
            code=CLOUD_ACTION_PERMISSION_UNDECLARED,
            offending=(ProviderPermission.TARGET_MUTATE.value,),
            reason=(
                f"cloud action {action_id!r} declares {named} but every cloud action "
                f"mutates a resource and must declare "
                f"{ProviderPermission.TARGET_MUTATE.value}"
            ),
        )
    return CloudSelectorDecision(
        allowed=True,
        reason=(f"action {action_id!r} declares {', '.join(sorted(p.value for p in declared))}"),
    )


def ensure_action_declares_permissions(
    action_id: str,
    required_permissions: Iterable[ProviderPermission],
) -> CloudSelectorDecision:
    """Raise :class:`CloudRefused` unless an action declares what it needs."""
    decision = check_action_declares_permissions(action_id, required_permissions)
    if decision.allowed:
        return decision
    raise CloudRefused(
        decision.code,
        decision.reason,
        details={
            "action_id": action_id,
            "declared": sorted(p.value for p in required_permissions),
            "missing": list(decision.offending),
        },
        remediation=(
            f"declare {ProviderPermission.TARGET_MUTATE.value} in required_permissions; "
            "every cloud action mutates the resource it names"
        ),
    )


class CloudResourceIdentity(BaseModel):
    """One exact cloud resource.

    Every field is required with no default, so an identity cannot exist
    without a provider, a class, an account boundary, a region, and the
    provider-native id. ``resource_id`` is the provider's own identifier,
    carried verbatim: this vocabulary never rewrites a cloud id into a
    Mayhem-shaped one, because a rewritten id is one nobody can check against
    the console.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: CloudProviderRef
    resource_class: CloudResourceClass
    account: str
    region: str
    resource_id: str
    tags: frozenset[str] = frozenset()

    @field_validator("account", "region", "resource_id")
    @classmethod
    def _check_identifier(cls, value: str) -> str:
        return _require_plain_identifier(value, subject="cloud resource identity")

    @field_validator("tags")
    @classmethod
    def _check_tags(cls, values: frozenset[str]) -> frozenset[str]:
        for value in values:
            _require_plain_identifier(value, subject="cloud resource tag")
        return values

    @property
    def canonical_id(self) -> str:
        """The identity as one string, for logs and refusal details.

        ``provider:account:region:class/resource_id``. Provider-native ids
        contain ``/`` and ``:`` in practice, so this is a display and
        correlation key, never a re-parsable address.
        """
        return (
            f"{self.provider.key}:{self.account}:{self.region}:"
            f"{self.resource_class.value}/{self.resource_id}"
        )

    def describe(self) -> str:
        return self.canonical_id


class CloudTargetIntent(BaseModel):
    """A selector that has *not* been resolved yet.

    Not a target. It is the thing a plan is written with before anyone has
    looked at the account, and it is deliberately a different type so that a
    selector can never be handed to an adapter as though it were a resource.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: CloudProviderRef
    selector: CloudSelector


class CloudTarget(BaseModel):
    """A resolved cloud resource: a selector plus the exact identity it named.

    The validator re-checks the pair rather than trusting the caller: the
    identity must belong to the declared provider, must be the declared
    resource class, and must actually be selected by the selector. So a
    ``CloudTarget`` cannot be hand-assembled to point somewhere the selector
    did not authorise, which is the whole failure mode this type exists to
    make impossible.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: CloudProviderRef
    resource_class: CloudResourceClass
    selector: CloudSelector
    identity: CloudResourceIdentity

    @model_validator(mode="after")
    def _check_resolution(self) -> CloudTarget:
        if self.selector.resource_class is not self.resource_class:
            raise ValueError(
                f"target resource class {self.resource_class.value!r} disagrees with its "
                f"selector's {self.selector.resource_class.value!r}"
            )
        if self.identity.provider != self.provider:
            raise ValueError(
                f"target names provider {self.provider.key!r} but its identity names "
                f"{self.identity.provider.key!r}"
            )
        if self.identity.resource_class is not self.resource_class:
            raise ValueError(
                f"target resource class {self.resource_class.value!r} disagrees with its "
                f"identity's {self.identity.resource_class.value!r}"
            )
        if not self.selector.matches(self.identity):
            raise ValueError(
                f"target identity {self.identity.canonical_id!r} is not selected by "
                f"selector {self.selector.describe()!r}"
            )
        return self

    def describe(self) -> str:
        return f"{self.resource_class.value} {self.identity.canonical_id}"


# --- actions ------------------------------------------------------------------


class CloudActionKind(StrEnum):
    """The provider-neutral failure primitives.

    What happens to a resource, never *how* a provider spells it. An adapter
    that cannot implement one of these reports it unsupported rather than
    substituting a near-miss.
    """

    STOP = "stop"
    REBOOT = "reboot"
    ISOLATE = "isolate"
    IMPAIR = "impair"
    FAILOVER = "failover"


class CloudAction(BaseModel):
    """Shared shape of every cloud action, reversible or not.

    ``required_permissions`` is mandatory (no default) and is expressed in
    :class:`~mayhem.domain.provider.ProviderPermission` — the same vocabulary
    the provider sandbox gates on, so "what would this need?" is answered in
    one language across local providers and cloud. Every cloud action mutates
    a resource, so ``target:mutate`` is required of all of them; the validator
    makes an action that fails to ask for it unbuildable
    (:data:`CLOUD_ACTION_PERMISSION_UNDECLARED`).

    ``action_id`` follows the same lowercase dotted convention as a provider
    declaration's ids, so a cloud action and a provider fault can be named in
    one evidence record.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    action_id: str
    kind: CloudActionKind
    target: CloudTarget
    summary: str = Field(min_length=1, max_length=500)
    risk: RiskLevel = RiskLevel.MEDIUM
    reversibility: Reversibility
    duration_s: float | None = None
    required_permissions: frozenset[ProviderPermission]

    @field_validator("action_id")
    @classmethod
    def _check_action_id(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("cloud action_id must not be empty")
        if not set(value) <= _IDENTIFIER_CHARS:
            raise ValueError(
                f"cloud action_id must be a lowercase dotted identifier, got {value!r}"
            )
        return value

    @field_validator("duration_s")
    @classmethod
    def _check_duration(cls, value: float | None) -> float | None:
        if value is None:
            return None
        if not isfinite(value) or value < 0.0:
            raise ValueError(f"cloud action duration_s must be finite and >= 0, got {value!r}")
        return value

    @model_validator(mode="after")
    def _check_permissions(self) -> CloudAction:
        # Delegates to the decision function for the same reason
        # CloudSelector._check_exactness does: one rule, so the refusal code in
        # the message and the code the decision function returns cannot drift.
        declared = check_action_declares_permissions(self.action_id, self.required_permissions)
        if not declared.allowed:
            raise ValueError(f"[{declared.code}] {declared.reason}")
        return self

    @property
    def is_irreversible(self) -> bool:
        """True when the cloud cannot roll this action back."""
        return self.reversibility is Reversibility.IRREVERSIBLE

    def describe(self) -> str:
        duration = "" if self.duration_s is None else f" for {self.duration_s:g}s"
        return (
            f"{self.kind.value} {self.target.describe()}{duration} "
            f"({self.reversibility.value}, {self.risk.value} risk)"
        )


class ReversibleCloudAction(CloudAction):
    """A cloud action the provider can undo: stop, reboot, isolate, failover.

    The reversibility of one of these is still a claim, not a demonstration —
    Phase 2's acceptance is that every adapter action demonstrates
    compensate→verify on a sandbox account before it reaches the catalog. What
    the type guarantees is narrower and load-bearing: a *reversible* action is
    not gated for elevated approval, and an *irreversible* one is a different
    type, so no code path can confuse the two.
    """

    @model_validator(mode="after")
    def _check_reversible(self) -> ReversibleCloudAction:
        if self.reversibility is Reversibility.IRREVERSIBLE:
            raise ValueError(
                f"cloud action {self.action_id!r} declares reversibility "
                f"{self.reversibility.value!r}; an irreversible action must be an "
                "IrreversibleCloudAction so admission can gate it"
            )
        return self


class IrreversibleCloudAction(CloudAction):
    """A cloud action the provider *cannot* undo.

    Deleting a volume, revoking a key, destroying a disk image. Two things are
    structural here:

    * it is a different type from a reversible action, so
      :func:`requires_elevated_approval` is an ``isinstance`` check that no
      field rewrite can defeat; and
    * ``rationale`` is required, so "we could not think of a rollback" has to
      be written down at plan time rather than discovered afterwards.

    Plan 09 owns what elevated approval *means*; until then this type only
    guarantees the action is distinguishable and self-justifying.
    """

    rationale: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def _check_irreversible(self) -> IrreversibleCloudAction:
        if self.reversibility is not Reversibility.IRREVERSIBLE:
            raise ValueError(
                f"IrreversibleCloudAction {self.action_id!r} declares reversibility "
                f"{self.reversibility.value!r}; an irreversible action must declare "
                f"{Reversibility.IRREVERSIBLE.value!r}"
            )
        if not self.rationale.strip():
            raise ValueError(
                f"irreversible cloud action {self.action_id!r} must state why the "
                "cloud cannot roll it back"
            )
        return self


type CloudSpec = ReversibleCloudAction | IrreversibleCloudAction
"""Any cloud action. The union a plan step holds, and the type every gate in
this module accepts — so a gate can never be handed a base :class:`CloudAction`
and quietly miss the irreversible subclass."""


def requires_elevated_approval(action: CloudSpec) -> bool:
    """True when admission must demand elevated approval for *action*.

    Structural, not a field comparison: the answer is decided by which of the
    two models the action is, so an action that declares
    ``reversibility="irreversible"`` while being built as the reversible model
    is refused at construction rather than quietly passing this check.
    """
    return isinstance(action, IrreversibleCloudAction)


# --- IAM ----------------------------------------------------------------------


DEFAULT_CLOUD_ROLE_GRANTS: frozenset[ProviderPermission] = frozenset()
"""Nothing is allowed unless a grant says otherwise.

Deliberately the same empty set as ``mayhem.providers.permissions.DEFAULT_PERMISSION_SET``
and deliberately *not* an import of it: the domain may not depend on the loader
layer, and a second literal that agrees with the first is safer than a
dependency that cannot be checked. If one ever changes, the other must change
with it.
"""


class CloudRoleRef(BaseModel):
    """A cloud IAM role and the provider permissions it is granted.

    ``granted`` defaults to nothing, so the default role can perform no cloud
    action — the same default-deny posture the provider sandbox states. The
    provider travels with the role so that an AWS role can never authorise a
    GCP action, even by accident.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    role_id: str
    provider: CloudProviderRef
    granted: frozenset[ProviderPermission] = DEFAULT_CLOUD_ROLE_GRANTS

    @field_validator("role_id")
    @classmethod
    def _check_role_id(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("cloud role_id must not be empty")
        if not set(value) <= _IDENTIFIER_CHARS:
            raise ValueError(f"cloud role_id must be a lowercase dotted identifier, got {value!r}")
        return value

    @classmethod
    def read_only(cls, *, role_id: str, provider: CloudProviderRef) -> CloudRoleRef:
        """The minimum useful role: it may look, and may not act.

        Mirrors ``ProviderPermissionSet.default()`` so the two "safe by
        construction" role factories in the system read the same way.
        """
        return cls(
            role_id=role_id,
            provider=provider,
            granted=frozenset({ProviderPermission.TARGET_READ}),
        )

    @property
    def mutating(self) -> bool:
        """True when this role can change a cloud resource at all."""
        return ProviderPermission.TARGET_MUTATE in self.granted

    def missing_for(self, action: CloudSpec) -> tuple[str, ...]:
        """The sorted names of the permissions *action* needs and this role lacks."""
        return tuple(sorted(p.value for p in action.required_permissions - self.granted))


class CloudPermissionDecision(BaseModel):
    """The answer to "can this role perform this action?", as a value.

    Reports rather than judges-by-raising, so a caller that wants to *display*
    the answer never has to catch anything, and so the missing permissions are
    available to a remediation message whether or not the caller raised.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    role_id: str
    action_id: str
    allowed: bool
    code: str = ""
    missing: tuple[str, ...] = ()
    reason: str = ""

    @property
    def denied(self) -> bool:
        return not self.allowed


def check_role_can_perform(role: CloudRoleRef, action: CloudSpec) -> CloudPermissionDecision:
    """Answer, purely, whether *role* may perform *action*.

    Two independent refusals, and they are not the same refusal:

    * the role belongs to a different cloud than the action's target, which is
      :data:`CLOUD_ROLE_PROVIDER_MISMATCH` — an AWS role is not a GCP role,
      whatever permissions it holds; and
    * the role is on the right cloud but lacks a permission the action declared,
      which is :data:`CLOUD_PERMISSION_DENIED` and names each missing
      permission.

    The cross-provider case reports *every* required permission as missing: from
    this role's point of view it holds nothing that applies.
    """
    provider_mismatch = role.provider != action.target.provider
    if provider_mismatch:
        return CloudPermissionDecision(
            role_id=role.role_id,
            action_id=action.action_id,
            allowed=False,
            code=CLOUD_ROLE_PROVIDER_MISMATCH,
            missing=tuple(sorted(p.value for p in action.required_permissions)),
            reason=(
                f"role {role.role_id!r} is bound to {role.provider.key!r} but the "
                f"action targets {action.target.provider.key!r}"
            ),
        )
    missing = role.missing_for(action)
    if missing:
        return CloudPermissionDecision(
            role_id=role.role_id,
            action_id=action.action_id,
            allowed=False,
            code=CLOUD_PERMISSION_DENIED,
            missing=missing,
            reason=(
                f"role {role.role_id!r} cannot perform {action.action_id!r}: missing "
                f"{', '.join(missing)}"
            ),
        )
    return CloudPermissionDecision(
        role_id=role.role_id,
        action_id=action.action_id,
        allowed=True,
        reason=(
            f"role {role.role_id!r} holds "
            f"{', '.join(sorted(p.value for p in action.required_permissions))} "
            f"for {action.action_id!r}"
        ),
    )


def ensure_role_can_perform(role: CloudRoleRef, action: CloudSpec) -> CloudPermissionDecision:
    """Raise :class:`CloudRefused` unless *role* may perform *action*.

    The refusal names the missing permissions, because "insufficient IAM" with
    no name is the failure an operator cannot act on.
    """
    decision = check_role_can_perform(role, action)
    if decision.allowed:
        return decision
    raise CloudRefused(
        decision.code,
        decision.reason,
        details={
            "role_id": decision.role_id,
            "action_id": decision.action_id,
            "missing": list(decision.missing),
        },
        remediation=(
            f"grant {', '.join(decision.missing)} to role {decision.role_id!r}, or "
            "author the action against a role that already holds them"
        ),
    )


# --- cost ---------------------------------------------------------------------


def _round(value: float) -> float:
    """Round to the resource layer's replay-stable precision.

    Borrowed from :mod:`mayhem.domain.budgets` rather than re-invented, so a
    cost figure accumulated here and one accumulated there round identically
    and a replay cannot drift on the last binary digit.
    """
    return round(value, RESOURCE_PRECISION)


class CostEstimate(ResourceEstimate):
    """What a cloud action is expected to cost, and the ceiling it runs under.

    A :class:`~mayhem.domain.budgets.ResourceEstimate` narrowed to
    ``cloud_spend`` — an *extension* of the existing resource vocabulary rather
    than a second money type. What it inherits, deliberately: the mandatory
    ``basis`` (an estimate with no stated basis is a guess the comparison would
    treat as data), finiteness and non-negativity, the ``currency_micros`` unit
    that ``compare_estimate`` already reads, and the same
    :data:`~mayhem.domain.budgets.RESOURCE_PRECISION` rounding.

    What it adds is the shape a *cloud* cost needs and a scalar does not:

    * ``expected_low`` / ``expected_high`` — the range, because cloud spend
      depends on traffic and instance families nobody can pin exactly. The
      inherited scalar ``expected`` is defined as the midpoint, derived rather
      than authored, so there is exactly one number to compare against and it
      cannot disagree with the range it came from.
    * ``ceiling`` — the hard limit. A ceiling below the estimate's own high
      bound is a plan that is already over budget, and it is refused
      (:data:`RULE_COST_CEILING_BELOW_HIGH`) rather than carried as a fact
      waiting to fail at admission.

    The ceiling is a *limit*, not a prediction, so it is never compared against
    the estimate here; :func:`check_cost_ceiling` is what compares spend
    against it, and it is pure so Phase 4 can call it before mutating anything.
    """

    model_config = ConfigDict(frozen=True)

    dimension: ResourceDimension = ResourceDimension.CLOUD_SPEND
    expected_low: float = Field(ge=0.0)
    expected_high: float = Field(ge=0.0)
    ceiling: float = Field(ge=0.0)

    @model_validator(mode="before")
    @classmethod
    def _derive_expected(cls, data: object) -> object:
        """Fill the inherited scalar ``expected`` with the range's midpoint.

        ``mode="before"`` because the frozen model cannot assign to itself
        afterwards. An author-supplied ``expected`` is *not* overridden — it is
        checked against the midpoint below, so a hand-written scalar that
        disagrees with the range is a refusal rather than a silent rewrite.
        """
        if not isinstance(data, dict) or "expected" in data:
            return data
        low = data.get("expected_low")
        high = data.get("expected_high")
        if isinstance(low, (int, float)) and isinstance(high, (int, float)):
            return {**data, "expected": _round((float(low) + float(high)) / 2.0)}
        return data

    @model_validator(mode="after")
    def _check_range(self) -> CostEstimate:
        if self.dimension is not ResourceDimension.CLOUD_SPEND:
            raise InvariantViolationError(
                RULE_COST_ESTIMATE_ORDER,
                f"a cost estimate is counted in "
                f"{self.unit!r} (cloud_spend), not {self.dimension.value!r}",
            )
        if self.expected_high < self.expected_low:
            raise InvariantViolationError(
                RULE_COST_ESTIMATE_ORDER,
                f"cost estimate high bound {self.expected_high:g} is below its low "
                f"bound {self.expected_low:g}",
            )
        midpoint = _round((self.expected_low + self.expected_high) / 2.0)
        if _round(self.expected) != midpoint:
            raise InvariantViolationError(
                RULE_COST_ESTIMATE_ORDER,
                f"cost estimate expected {self.expected:g} is not the midpoint "
                f"{midpoint:g} of its range [{self.expected_low:g}, "
                f"{self.expected_high:g}]",
            )
        if self.ceiling < self.expected_high:
            raise InvariantViolationError(
                RULE_COST_CEILING_BELOW_HIGH,
                f"cost ceiling {self.ceiling:g} is below the estimate high bound "
                f"{self.expected_high:g}; the plan is already over budget",
            )
        return self

    @property
    def midpoint(self) -> float:
        """The expected value, defined as the midpoint of the range."""
        return self.expected

    @property
    def spread(self) -> float:
        """``expected_high - expected_low``: the width of the uncertainty."""
        return _round(self.expected_high - self.expected_low)

    @property
    def headroom(self) -> float:
        """How much spend the ceiling leaves above the high bound."""
        return _round(self.ceiling - self.expected_high)

    def describe(self) -> str:
        return (
            f"{self.scope.value}/{self.scope_key} expects {self.expected_low:g}-"
            f"{self.expected_high:g} {self.unit} (midpoint {self.expected:g}) under a "
            f"ceiling of {self.ceiling:g} (basis: {self.basis})"
        )


class CostCeilingDecision(BaseModel):
    """Whether a spend is inside a cost estimate's ceiling, as a value.

    Reports rather than raises, for the same reason
    :class:`CloudPermissionDecision` does: a pre-flight screen wants to show
    the number, not catch an exception to render it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    spent: float
    ceiling: float
    allowed: bool
    code: str = ""
    reason: str = ""

    @property
    def exceeded(self) -> bool:
        return not self.allowed

    @property
    def over_by(self) -> float:
        """How far past the ceiling the spend went; ``0.0`` when inside."""
        return _round(self.spent - self.ceiling) if not self.allowed else 0.0


def check_cost_ceiling(estimate: CostEstimate, spent: float) -> CostCeilingDecision:
    """Judge *spent* against *estimate*'s ceiling. Pure; never raises for a breach.

    A non-finite or negative ``spent`` is refused here too: an unknown or
    backwards spend is not evidence of being under a limit, and treating it as
    such would let a metering bug authorise an action.
    """
    if not isfinite(spent) or spent < 0.0:
        raise InvariantViolationError(
            "cloud.cost_spend_invalid",
            f"cloud spend must be a finite non-negative number, got {spent!r}",
        )
    if spent > estimate.ceiling:
        return CostCeilingDecision(
            spent=_round(spent),
            ceiling=estimate.ceiling,
            allowed=False,
            code=CLOUD_COST_CEILING_EXCEEDED,
            reason=(
                f"cloud spend {spent:g} {estimate.unit} exceeds the cost ceiling "
                f"{estimate.ceiling:g} by {spent - estimate.ceiling:g} "
                f"[{CLOUD_COST_CEILING_EXCEEDED}]"
            ),
        )
    return CostCeilingDecision(
        spent=_round(spent),
        ceiling=estimate.ceiling,
        allowed=True,
        reason=(
            f"cloud spend {spent:g} {estimate.unit} is within the cost ceiling {estimate.ceiling:g}"
        ),
    )


def ensure_cost_ceiling(estimate: CostEstimate, spent: float) -> CostCeilingDecision:
    """Raise :class:`CloudRefused` when *spent* breaches *estimate*'s ceiling.

    The pre-mutation hook: Phase 4 calls this *before* the action runs, so a
    plan that would exceed its ceiling is refused rather than detected on the
    invoice.
    """
    decision = check_cost_ceiling(estimate, spent)
    if decision.allowed:
        return decision
    raise CloudRefused(
        decision.code,
        decision.reason,
        details={
            "spent": decision.spent,
            "ceiling": decision.ceiling,
            "over_by": decision.over_by,
            "expected_high": estimate.expected_high,
        },
        remediation=(
            f"raise the cost ceiling above {estimate.expected_high:g} {estimate.unit}, "
            "or choose a cheaper resource class or region for the action"
        ),
    )


# --- resolution ----------------------------------------------------------------


def resolve_cloud_target(
    intent: CloudTargetIntent,
    identities: list[CloudResourceIdentity],
) -> CloudTarget:
    """Resolve *intent* against *identities* to exactly one :class:`CloudTarget`.

    Pure, and the only way a plan ever obtains a target. Three outcomes, and
    only the first one returns:

    * exactly one matching identity — the resolved target, carrying both the
      selector that was authored and the identity it named;
    * none — :data:`CLOUD_TARGET_UNRESOLVED`, a plan-time refusal; and
    * more than one — :data:`CLOUD_AMBIGUOUS_RESOLUTION`, also a plan-time
      refusal. This is the load-bearing refusal of the module: a selector that
      matches many resources means "act on everything this matches", which is a
      plan with a blast radius nobody has written down. It is refused here so
      somebody has to author one intent per resource and accept each one.

    Identities belonging to another cloud are ignored rather than matched: the
    intent's provider is the boundary. An identity of the right cloud but the
    wrong resource class, account or region is likewise not a match, because a
    selector that reached across a subscription boundary is exactly the mistake
    the boundary fields exist to catch.
    """
    matches = [
        identity
        for identity in identities
        if identity.provider == intent.provider and intent.selector.matches(identity)
    ]
    # Sorted by canonical id, never by provider API order: two resolutions of
    # the same plan against the same inventory must name their candidates the
    # same way, or a refusal is not reproducible.
    matches.sort(key=lambda identity: identity.canonical_id)
    if not matches:
        raise CloudRefused(
            CLOUD_TARGET_UNRESOLVED,
            f"selector {intent.selector.describe()!r} on {intent.provider.key!r} "
            f"resolved to no resource identity",
            details={
                "provider": intent.provider.key,
                "selector": intent.selector.describe(),
                "candidates": len(identities),
            },
            remediation=_RESOLUTION_REMEDIATION,
        )
    if len(matches) > 1:
        shown = [identity.canonical_id for identity in matches[:_MAX_NAMED_CANDIDATES]]
        raise CloudRefused(
            CLOUD_AMBIGUOUS_RESOLUTION,
            f"selector {intent.selector.describe()!r} on {intent.provider.key!r} "
            f"resolved to {len(matches)} resource identities; a cloud action may "
            f"only name one",
            details={
                "provider": intent.provider.key,
                "selector": intent.selector.describe(),
                "match_count": len(matches),
                "matched": shown,
            },
            remediation=_RESOLUTION_REMEDIATION,
        )
    identity = matches[0]
    return CloudTarget(
        provider=identity.provider,
        resource_class=identity.resource_class,
        selector=intent.selector,
        identity=identity,
    )
