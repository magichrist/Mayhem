"""Tests for the provider-neutral cloud vocabulary (v1.1.0 plan 06, Phase 1).

Phase 1's acceptance is a *type* property, so most of this file is negative
control: the shapes that must be impossible are shown to be impossible (a
wildcard selector, a provider-less target, an action that declares no
permission, a ceiling below its own high bound), and the predicates that make
those shapes decidable are shown to agree with the constructors that refuse
them.

Everything here is a value, so nothing is mocked: no cloud SDK, no credentials,
no network, no clock.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from mayhem.domain.budgets import ResourceDimension, ResourceScope
from mayhem.domain.cloud import (
    CLOUD_ACTION_PERMISSION_UNDECLARED,
    CLOUD_AMBIGUOUS_RESOLUTION,
    CLOUD_COST_CEILING_EXCEEDED,
    CLOUD_PERMISSION_DENIED,
    CLOUD_ROLE_PROVIDER_MISMATCH,
    CLOUD_SELECTOR_EMPTY,
    CLOUD_SELECTOR_WILDCARD,
    CLOUD_TARGET_UNRESOLVED,
    DEFAULT_CLOUD_ROLE_GRANTS,
    RULE_COST_CEILING_BELOW_HIGH,
    RULE_COST_ESTIMATE_ORDER,
    CloudActionKind,
    CloudProvider,
    CloudProviderRef,
    CloudRefused,
    CloudResourceClass,
    CloudResourceIdentity,
    CloudRoleRef,
    CloudSelector,
    CloudSelectorKind,
    CloudTarget,
    CloudTargetIntent,
    CostEstimate,
    IrreversibleCloudAction,
    ReversibleCloudAction,
    check_action_declares_permissions,
    check_cost_ceiling,
    check_role_can_perform,
    check_selector_is_specific,
    ensure_action_declares_permissions,
    ensure_cost_ceiling,
    ensure_role_can_perform,
    ensure_selector_is_specific,
    requires_elevated_approval,
    resolve_cloud_target,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.faults import Reversibility
from mayhem.domain.provider import ProviderPermission

AWS = CloudProviderRef(provider=CloudProvider.AWS)
GCP = CloudProviderRef(provider=CloudProvider.GCP)
CUSTOM = CloudProviderRef(provider=CloudProvider.CUSTOM, custom_id="onprem.hypervisor")

MUTATE = frozenset({ProviderPermission.TARGET_MUTATE})


# --- fixtures ------------------------------------------------------------------


def _identity(
    resource_id: str = "i-0abc123",
    *,
    provider: CloudProviderRef = AWS,
    resource_class: CloudResourceClass = CloudResourceClass.VM,
    account: str = "123456789012",
    region: str = "eu-west-1",
    tags: frozenset[str] = frozenset(),
) -> CloudResourceIdentity:
    return CloudResourceIdentity(
        provider=provider,
        resource_class=resource_class,
        account=account,
        region=region,
        resource_id=resource_id,
        tags=tags,
    )


def _by_id(resource_id: str = "i-0abc123", **kwargs: object) -> CloudSelector:
    return CloudSelector(
        resource_class=kwargs.pop("resource_class", CloudResourceClass.VM),  # type: ignore[arg-type]
        kind=CloudSelectorKind.IDENTIFIER,
        account=kwargs.pop("account", "123456789012"),  # type: ignore[arg-type]
        region=kwargs.pop("region", "eu-west-1"),  # type: ignore[arg-type]
        identifiers=(resource_id,),
    )


def _by_tag(*tags: str, **kwargs: object) -> CloudSelector:
    return CloudSelector(
        resource_class=kwargs.pop("resource_class", CloudResourceClass.VM),  # type: ignore[arg-type]
        kind=CloudSelectorKind.TAG,
        account=kwargs.pop("account", "123456789012"),  # type: ignore[arg-type]
        region=kwargs.pop("region", "eu-west-1"),  # type: ignore[arg-type]
        tags=frozenset(tags),
    )


def _target(resource_id: str = "i-0abc123", **kwargs: object) -> CloudTarget:
    selector = _by_id(resource_id, **kwargs)
    identity = _identity(
        resource_id,
        resource_class=selector.resource_class,
        account=selector.account,
        region=selector.region,
    )
    return CloudTarget(
        provider=identity.provider,
        resource_class=identity.resource_class,
        selector=selector,
        identity=identity,
    )


def _reversible(
    *,
    target: CloudTarget | None = None,
    action_id: str = "cloud.aws.stop_instance",
    permissions: frozenset[ProviderPermission] = MUTATE,
    reversibility: Reversibility = Reversibility.REVERSIBLE,
    duration_s: float | None = None,
) -> ReversibleCloudAction:
    return ReversibleCloudAction(
        action_id=action_id,
        kind=CloudActionKind.STOP,
        target=target or _target(),
        summary="stop the instance under test",
        reversibility=reversibility,
        required_permissions=permissions,
        duration_s=duration_s,
    )


def _irreversible(
    *, action_id: str = "cloud.aws.delete_volume", **kwargs: object
) -> IrreversibleCloudAction:
    return IrreversibleCloudAction(
        action_id=action_id,
        kind=CloudActionKind.IMPAIR,
        target=kwargs.pop("target", None) or _target(),  # type: ignore[arg-type]
        summary="destroy the block volume backing the instance",
        reversibility=Reversibility.IRREVERSIBLE,
        rationale="the provider offers no restore for a destroyed volume",
        required_permissions=kwargs.pop("required_permissions", MUTATE),  # type: ignore[arg-type]
    )


def _estimate(
    low: float = 1.0,
    high: float = 3.0,
    *,
    ceiling: float = 10.0,
    scope_key: str = "123456789012",
) -> CostEstimate:
    return CostEstimate(
        scope=ResourceScope.EXPERIMENT,
        scope_key=scope_key,
        expected_low=low,
        expected_high=high,
        ceiling=ceiling,
        basis="provider list price at the authored instance family",
    )


# --- providers -----------------------------------------------------------------


class TestCloudProviderRef:
    def test_named_providers_need_no_custom_id(self) -> None:
        for name in ("aws", "gcp", "azure"):
            assert CloudProviderRef(provider=CloudProvider(name)).key == name

    def test_provider_has_no_default(self) -> None:
        # Negative control: a provider-less reference is unrepresentable.
        with pytest.raises(ValidationError):
            CloudProviderRef()  # type: ignore[call-arg]

    def test_named_provider_refuses_a_custom_id(self) -> None:
        with pytest.raises(ValidationError, match="must not carry a custom_id"):
            CloudProviderRef(provider=CloudProvider.AWS, custom_id="prod")

    def test_custom_provider_requires_a_custom_id(self) -> None:
        with pytest.raises(ValidationError, match="must name a custom_id"):
            CloudProviderRef(provider=CloudProvider.CUSTOM)

    def test_custom_provider_key_is_its_custom_id(self) -> None:
        assert CUSTOM.key == "onprem.hypervisor"
        assert CUSTOM.provider is CloudProvider.CUSTOM

    def test_custom_provider_refuses_a_wildcard_id(self) -> None:
        with pytest.raises(ValidationError, match="wildcard"):
            CloudProviderRef(provider=CloudProvider.CUSTOM, custom_id="onprem-*")

    def test_equality_is_by_value(self) -> None:
        assert CloudProviderRef(provider=CloudProvider.AWS) == AWS


# --- resource classes ----------------------------------------------------------


class TestCloudResourceClass:
    def test_the_nine_core_classes_are_present(self) -> None:
        assert {member.value for member in CloudResourceClass} == {
            "vm",
            "network",
            "load_balancer",
            "object_storage",
            "block_storage",
            "managed_database",
            "queue",
            "function",
            "managed_kubernetes",
        }

    def test_class_is_named_on_the_identity(self) -> None:
        assert _identity().resource_class is CloudResourceClass.VM


# --- selectors: exactness ------------------------------------------------------


class TestSelectorExactness:
    def test_identifier_selector_matches_its_exact_resource(self) -> None:
        assert _by_id("i-0abc123").matches(_identity("i-0abc123")) is True

    def test_identifier_selector_does_not_match_a_prefix(self) -> None:
        # The load-bearing case: "i-0abc" is a prefix of "i-0abc123", and a
        # prefix is not an identity.
        assert _by_id("i-0abc").matches(_identity("i-0abc123")) is False

    def test_identifier_selector_does_not_match_a_longer_id(self) -> None:
        assert _by_id("i-0abc123").matches(_identity("i-0abc1234")) is False

    def test_wildcard_identifier_is_refused(self) -> None:
        # Negative control: there is no field in which to write "i-*".
        with pytest.raises(ValidationError, match="wildcard"):
            _by_id("i-*")

    def test_question_mark_identifier_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="wildcard"):
            _by_id("i-0abc?")

    def test_percent_identifier_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="wildcard"):
            _by_id("i-%")

    def test_wildcard_tag_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="wildcard"):
            _by_tag("env=prod*")

    def test_wildcard_account_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="wildcard"):
            CloudSelector(
                resource_class=CloudResourceClass.VM,
                kind=CloudSelectorKind.IDENTIFIER,
                account="*",
                region="eu-west-1",
                identifiers=("i-0abc123",),
            )

    def test_wildcard_region_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="wildcard"):
            CloudSelector(
                resource_class=CloudResourceClass.VM,
                kind=CloudSelectorKind.IDENTIFIER,
                account="123456789012",
                region="eu-*",
                identifiers=("i-0abc123",),
            )

    def test_empty_identifier_selector_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="at least one identifier or tag"):
            CloudSelector(
                resource_class=CloudResourceClass.VM,
                kind=CloudSelectorKind.IDENTIFIER,
                account="123456789012",
                region="eu-west-1",
            )

    def test_empty_tag_selector_is_refused(self) -> None:
        # A selector that constrains nothing matches everything, and
        # "everything" is never what a plan meant.
        with pytest.raises(ValidationError, match="at least one identifier or tag"):
            _by_tag()

    def test_identifier_selector_refuses_tags(self) -> None:
        with pytest.raises(ValidationError, match="must not carry tags"):
            CloudSelector(
                resource_class=CloudResourceClass.VM,
                kind=CloudSelectorKind.IDENTIFIER,
                account="123456789012",
                region="eu-west-1",
                identifiers=("i-0abc123",),
                tags=frozenset({"env=prod"}),
            )

    def test_tag_selector_refuses_identifiers(self) -> None:
        with pytest.raises(ValidationError, match="must not carry identifiers"):
            CloudSelector(
                resource_class=CloudResourceClass.VM,
                kind=CloudSelectorKind.TAG,
                account="123456789012",
                region="eu-west-1",
                identifiers=("i-0abc123",),
                tags=frozenset({"env=prod"}),
            )

    def test_duplicate_identifiers_are_refused(self) -> None:
        with pytest.raises(ValidationError, match="must be unique"):
            CloudSelector(
                resource_class=CloudResourceClass.VM,
                kind=CloudSelectorKind.IDENTIFIER,
                account="123456789012",
                region="eu-west-1",
                identifiers=("i-0abc123", "i-0abc123"),
            )

    def test_selector_requires_an_account_and_region(self) -> None:
        with pytest.raises(ValidationError):
            CloudSelector(
                resource_class=CloudResourceClass.VM,
                kind=CloudSelectorKind.IDENTIFIER,
                region="eu-west-1",
                identifiers=("i-0abc123",),
            )

    def test_boundary_is_part_of_the_match(self) -> None:
        selector = _by_id("i-0abc123")
        assert selector.matches(_identity("i-0abc123", account="999999999999")) is False
        assert selector.matches(_identity("i-0abc123", region="us-east-1")) is False

    def test_resource_class_is_part_of_the_match(self) -> None:
        selector = _by_id("i-0abc123", resource_class=CloudResourceClass.NETWORK)
        assert selector.matches(_identity("i-0abc123")) is False

    def test_tag_selector_requires_containment_of_every_tag(self) -> None:
        selector = _by_tag("env=prod", "tier=web")
        assert selector.matches(_identity(tags=frozenset({"env=prod", "tier=web"}))) is True
        assert selector.matches(_identity(tags=frozenset({"env=prod"}))) is False

    def test_selector_kind_has_no_wildcard_member(self) -> None:
        # Negative control on the vocabulary itself: there is no third kind to
        # add later without making every refusal here temporary.
        assert {member.value for member in CloudSelectorKind} == {"identifier", "tag"}

    def test_refusal_codes_exist_for_selector_construction(self) -> None:
        assert CLOUD_SELECTOR_WILDCARD == "cloud.selector_wildcard"
        assert CLOUD_SELECTOR_EMPTY == "cloud.selector_empty"


# --- the selector codes are reachable, not merely spelled ----------------------


class TestSelectorCodesAreRaisable:
    """A refusal code nothing can raise is a spelling, not a contract.

    Both codes fire inside a pydantic validator, which raises ``ValueError``, so
    before the decision functions existed no adapter or CLI could ever receive a
    :class:`CloudRefused` carrying either one. These are the reachability tests
    that were missing.
    """

    def test_an_empty_selector_raises_cloud_refused_with_its_code(self) -> None:
        with pytest.raises(CloudRefused) as excinfo:
            ensure_selector_is_specific()
        assert excinfo.value.code == CLOUD_SELECTOR_EMPTY
        assert excinfo.value.remediation

    def test_a_wildcard_selector_raises_cloud_refused_with_its_code(self) -> None:
        with pytest.raises(CloudRefused) as excinfo:
            ensure_selector_is_specific(identifiers=["i-0abc*"])
        assert excinfo.value.code == CLOUD_SELECTOR_WILDCARD
        assert excinfo.value.details["offending"] == ["i-0abc*"]

    def test_a_wildcard_is_reported_as_a_wildcard_even_when_it_is_the_only_member(
        self,
    ) -> None:
        """Ordering matters: an otherwise-empty selector must not mask the mistake.

        Reporting ``selector_empty`` for ``identifiers=['i-*']`` would tell the
        author to add a second identifier, which would still be a wildcard.
        """
        decision = check_selector_is_specific(identifiers=["i-*"])
        assert decision.code == CLOUD_SELECTOR_WILDCARD
        assert decision.code != CLOUD_SELECTOR_EMPTY

    def test_a_specific_selector_is_admitted(self) -> None:
        decision = check_selector_is_specific(identifiers=["i-0abc"], tags=["env=prod"])
        assert decision.allowed is True
        assert decision.denied is False

    def test_the_decision_function_agrees_with_the_constructor(self) -> None:
        """One rule, two surfaces: the code cannot drift from the refusal.

        The constructor delegates to this decision function, so a selector that
        builds and a selector the check admits must be the same set of inputs.
        """
        admitted = check_selector_is_specific(identifiers=["i-0abc"], tags=["env=prod"])
        CloudSelector(
            resource_class=CloudResourceClass.VM,
            kind=CloudSelectorKind.IDENTIFIER,
            account="123456789012",
            region="eu-west-1",
            identifiers=["i-0abc"],
        )
        assert admitted.allowed is True

    def test_the_constructor_names_the_code_in_its_own_refusal(self) -> None:
        """The ValueError path still carries the branchable code."""
        with pytest.raises(ValidationError, match=CLOUD_SELECTOR_EMPTY):
            CloudSelector(
                resource_class=CloudResourceClass.VM,
                kind=CloudSelectorKind.IDENTIFIER,
                account="123456789012",
                region="eu-west-1",
            )


# --- identities ----------------------------------------------------------------


class TestResourceIdentity:
    def test_identity_requires_a_provider(self) -> None:
        with pytest.raises(ValidationError):
            CloudResourceIdentity(
                resource_class=CloudResourceClass.VM,
                account="123456789012",
                region="eu-west-1",
                resource_id="i-0abc123",
            )

    def test_identity_requires_an_account(self) -> None:
        with pytest.raises(ValidationError):
            CloudResourceIdentity(
                provider=AWS,
                resource_class=CloudResourceClass.VM,
                region="eu-west-1",
                resource_id="i-0abc123",
            )

    def test_identity_requires_a_region(self) -> None:
        with pytest.raises(ValidationError):
            CloudResourceIdentity(
                provider=AWS,
                resource_class=CloudResourceClass.VM,
                account="123456789012",
                resource_id="i-0abc123",
            )

    def test_identity_requires_a_resource_id(self) -> None:
        with pytest.raises(ValidationError):
            CloudResourceIdentity(
                provider=AWS,
                resource_class=CloudResourceClass.VM,
                account="123456789012",
                region="eu-west-1",
            )

    def test_identity_refuses_a_wildcard_resource_id(self) -> None:
        with pytest.raises(ValidationError, match="wildcard"):
            _identity("i-0abc*")

    def test_canonical_id_names_every_boundary(self) -> None:
        assert _identity("i-0abc123").canonical_id == "aws:123456789012:eu-west-1:vm/i-0abc123"

    def test_canonical_id_separates_providers(self) -> None:
        assert _identity("i-0abc123", provider=GCP).canonical_id.startswith("gcp:")
        assert _identity("i-0abc123", provider=CUSTOM).canonical_id.startswith("onprem.hypervisor:")

    def test_identity_is_immutable(self) -> None:
        identity = _identity()
        with pytest.raises(ValidationError):
            identity.resource_id = "i-other"  # type: ignore[misc]

    def test_identity_refuses_unknown_fields(self) -> None:
        # No zone, no ARN alias, no "extra": a cloud identity is the five
        # boundary facts and the provider-native id, or it is not one.
        with pytest.raises(ValidationError):
            CloudResourceIdentity(
                provider=AWS,
                resource_class=CloudResourceClass.VM,
                account="123456789012",
                region="eu-west-1",
                resource_id="i-0abc123",
                zone="eu-west-1a",
            )


# --- resolution ----------------------------------------------------------------


class TestResolution:
    def test_exact_identity_resolves_to_a_target(self) -> None:
        intent = CloudTargetIntent(provider=AWS, selector=_by_id("i-0abc123"))
        target = resolve_cloud_target(intent, [_identity("i-0abc123")])
        assert target.identity.resource_id == "i-0abc123"
        assert target.provider == AWS
        assert target.resource_class is CloudResourceClass.VM

    def test_resolved_target_carries_both_selector_and_identity(self) -> None:
        intent = CloudTargetIntent(provider=AWS, selector=_by_id("i-0abc123"))
        target = resolve_cloud_target(intent, [_identity("i-0abc123")])
        assert target.selector is intent.selector
        assert target.selector.matches(target.identity)

    def test_a_prefix_only_candidate_does_not_resolve(self) -> None:
        # "i-0abc" is a prefix of "i-0abc123" and must not select it.
        intent = CloudTargetIntent(provider=AWS, selector=_by_id("i-0abc"))
        with pytest.raises(CloudRefused) as excinfo:
            resolve_cloud_target(intent, [_identity("i-0abc123")])
        assert excinfo.value.code == CLOUD_TARGET_UNRESOLVED

    def test_unresolved_selector_is_a_plan_time_refusal(self) -> None:
        intent = CloudTargetIntent(provider=AWS, selector=_by_id("i-missing"))
        with pytest.raises(CloudRefused) as excinfo:
            resolve_cloud_target(intent, [_identity("i-0abc123")])
        assert excinfo.value.code == CLOUD_TARGET_UNRESOLVED
        assert excinfo.value.details["candidates"] == 1
        assert excinfo.value.remediation

    def test_unresolved_refusal_names_the_selector(self) -> None:
        intent = CloudTargetIntent(provider=AWS, selector=_by_id("i-missing"))
        with pytest.raises(CloudRefused, match="i-missing"):
            resolve_cloud_target(intent, [])

    def test_empty_inventory_is_unresolved_not_a_no_op(self) -> None:
        intent = CloudTargetIntent(provider=AWS, selector=_by_id("i-0abc123"))
        with pytest.raises(CloudRefused) as excinfo:
            resolve_cloud_target(intent, [])
        assert excinfo.value.code == CLOUD_TARGET_UNRESOLVED

    def test_multiple_matches_are_refused_as_ambiguous(self) -> None:
        # The load-bearing refusal: "act on everything this matches" is a
        # different plan, and it must be written out as one intent per resource.
        intent = CloudTargetIntent(
            provider=AWS,
            selector=CloudSelector(
                resource_class=CloudResourceClass.VM,
                kind=CloudSelectorKind.IDENTIFIER,
                account="123456789012",
                region="eu-west-1",
                identifiers=("i-0abc123", "i-0def456"),
            ),
        )
        with pytest.raises(CloudRefused) as excinfo:
            resolve_cloud_target(intent, [_identity("i-0abc123"), _identity("i-0def456")])
        assert excinfo.value.code == CLOUD_AMBIGUOUS_RESOLUTION
        assert excinfo.value.details["match_count"] == 2

    def test_ambiguity_refusal_names_candidates_deterministically(self) -> None:
        intent = CloudTargetIntent(
            provider=AWS,
            selector=CloudSelector(
                resource_class=CloudResourceClass.VM,
                kind=CloudSelectorKind.IDENTIFIER,
                account="123456789012",
                region="eu-west-1",
                identifiers=("i-0abc123", "i-0def456"),
            ),
        )
        forward = _identity("i-0abc123"), _identity("i-0def456")
        backward = _identity("i-0def456"), _identity("i-0abc123")
        with pytest.raises(CloudRefused) as first:
            resolve_cloud_target(intent, list(forward))
        with pytest.raises(CloudRefused) as second:
            resolve_cloud_target(intent, list(backward))
        assert first.value.details["matched"] == second.value.details["matched"]

    def test_ambiguous_refusal_truncates_a_wide_match_set(self) -> None:
        ids = tuple(f"i-{index:06d}" for index in range(40))
        intent = CloudTargetIntent(
            provider=AWS,
            selector=CloudSelector(
                resource_class=CloudResourceClass.VM,
                kind=CloudSelectorKind.IDENTIFIER,
                account="123456789012",
                region="eu-west-1",
                identifiers=ids,
            ),
        )
        with pytest.raises(CloudRefused) as excinfo:
            resolve_cloud_target(intent, [_identity(name) for name in ids])
        assert excinfo.value.details["match_count"] == 40
        assert len(excinfo.value.details["matched"]) == 8

    def test_identities_from_another_cloud_are_not_candidates(self) -> None:
        intent = CloudTargetIntent(provider=AWS, selector=_by_id("i-0abc123"))
        with pytest.raises(CloudRefused) as excinfo:
            resolve_cloud_target(intent, [_identity("i-0abc123", provider=GCP)])
        assert excinfo.value.code == CLOUD_TARGET_UNRESOLVED

    def test_identities_outside_the_account_are_not_candidates(self) -> None:
        intent = CloudTargetIntent(provider=AWS, selector=_by_id("i-0abc123"))
        with pytest.raises(CloudRefused) as excinfo:
            resolve_cloud_target(intent, [_identity("i-0abc123", account="999999999999")])
        assert excinfo.value.code == CLOUD_TARGET_UNRESOLVED

    def test_tag_selector_resolves_when_exactly_one_resource_carries_it(self) -> None:
        intent = CloudTargetIntent(
            provider=AWS,
            selector=_by_tag("env=prod", resource_class=CloudResourceClass.MANAGED_DATABASE),
        )
        target = resolve_cloud_target(
            intent,
            [
                _identity(
                    "db-1",
                    resource_class=CloudResourceClass.MANAGED_DATABASE,
                    tags=frozenset({"env=prod"}),
                ),
                _identity("vm-1", tags=frozenset({"env=prod"})),
            ],
        )
        assert target.identity.resource_id == "db-1"

    def test_resolution_is_deterministic_across_inventory_order(self) -> None:
        intent = CloudTargetIntent(provider=AWS, selector=_by_id("i-0abc123"))
        first = resolve_cloud_target(intent, [_identity("i-other"), _identity("i-0abc123")])
        second = resolve_cloud_target(intent, [_identity("i-0abc123"), _identity("i-other")])
        assert first == second


# --- targets -------------------------------------------------------------------


class TestCloudTarget:
    def test_target_requires_a_provider(self) -> None:
        selector = _by_id("i-0abc123")
        identity = _identity("i-0abc123")
        with pytest.raises(ValidationError):
            CloudTarget(
                resource_class=CloudResourceClass.VM,
                selector=selector,
                identity=identity,
            )

    def test_target_requires_an_identity(self) -> None:
        # Negative control: there is no unresolved CloudTarget. An unresolved
        # plan is a CloudTargetIntent, which is a different type.
        with pytest.raises(ValidationError):
            CloudTarget(
                provider=AWS,
                resource_class=CloudResourceClass.VM,
                selector=_by_id("i-0abc123"),
            )

    def test_target_refuses_an_identity_its_selector_does_not_select(self) -> None:
        with pytest.raises(ValidationError, match="is not selected by"):
            CloudTarget(
                provider=AWS,
                resource_class=CloudResourceClass.VM,
                selector=_by_id("i-0abc123"),
                identity=_identity("i-other"),
            )

    def test_target_refuses_a_disagreeing_resource_class(self) -> None:
        # A network identity under a vm-declared target: the identity is
        # refused before the selector is even consulted.
        with pytest.raises(ValidationError, match="disagrees with its identity"):
            CloudTarget(
                provider=AWS,
                resource_class=CloudResourceClass.VM,
                selector=_by_id("i-0abc123"),
                identity=_identity("i-0abc123", resource_class=CloudResourceClass.NETWORK),
            )

    def test_target_refuses_a_class_the_selector_does_not_declare(self) -> None:
        selector = _by_id("i-0abc123", resource_class=CloudResourceClass.NETWORK)
        with pytest.raises(ValidationError, match="disagrees with its selector"):
            CloudTarget(
                provider=AWS,
                resource_class=CloudResourceClass.VM,
                selector=selector,
                identity=_identity("i-0abc123", resource_class=CloudResourceClass.NETWORK),
            )

    def test_target_refuses_a_disagreeing_provider(self) -> None:
        with pytest.raises(ValidationError, match="names provider"):
            CloudTarget(
                provider=GCP,
                resource_class=CloudResourceClass.VM,
                selector=_by_id("i-0abc123"),
                identity=_identity("i-0abc123", provider=AWS),
            )

    def test_target_describe_names_the_resource(self) -> None:
        assert _target("i-0abc123").describe() == "vm aws:123456789012:eu-west-1:vm/i-0abc123"

    def test_intent_is_not_a_target(self) -> None:
        intent = CloudTargetIntent(provider=AWS, selector=_by_id("i-0abc123"))
        assert not isinstance(intent, CloudTarget)
        assert "identity" not in type(intent).model_fields


# --- actions -------------------------------------------------------------------


class TestActionPermissions:
    def test_an_action_with_no_declared_permission_is_refused(self) -> None:
        # Negative control: an action that says nothing about what it needs
        # cannot be built.
        with pytest.raises(ValidationError, match="declares no required_permissions"):
            ReversibleCloudAction(
                action_id="cloud.aws.stop_instance",
                kind=CloudActionKind.STOP,
                target=_target(),
                summary="stop the instance",
                reversibility=Reversibility.REVERSIBLE,
                required_permissions=frozenset(),
            )

    def test_a_mutating_action_must_require_target_mutate(self) -> None:
        with pytest.raises(ValidationError, match="must declare target:mutate"):
            _reversible(permissions=frozenset({ProviderPermission.TARGET_READ}))

    def test_an_action_may_declare_more_than_the_minimum(self) -> None:
        action = _reversible(
            permissions=frozenset({ProviderPermission.TARGET_MUTATE, ProviderPermission.NETWORK})
        )
        assert ProviderPermission.NETWORK in action.required_permissions

    def test_action_id_must_be_a_lowercase_dotted_identifier(self) -> None:
        with pytest.raises(ValidationError, match="lowercase dotted identifier"):
            _reversible(action_id="Cloud AWS Stop")

    def test_action_id_must_not_be_empty(self) -> None:
        with pytest.raises(ValidationError):
            _reversible(action_id="   ")

    def test_action_refuses_a_negative_duration(self) -> None:
        with pytest.raises(ValidationError, match="finite and >= 0"):
            _reversible(duration_s=-1.0)

    def test_action_refuses_a_non_finite_duration(self) -> None:
        with pytest.raises(ValidationError, match="finite and >= 0"):
            _reversible(duration_s=float("inf"))

    def test_action_kind_covers_the_five_primitives(self) -> None:
        assert {member.value for member in CloudActionKind} == {
            "stop",
            "reboot",
            "isolate",
            "impair",
            "failover",
        }

    def test_action_is_immutable(self) -> None:
        action = _reversible()
        with pytest.raises(ValidationError):
            action.action_id = "cloud.aws.other"  # type: ignore[misc]

    def test_action_describe_names_kind_target_and_reversibility(self) -> None:
        described = _reversible().describe()
        assert "stop" in described
        assert "reversible" in described
        assert "i-0abc123" in described

    def test_permission_refusal_code_is_named(self) -> None:
        assert CLOUD_ACTION_PERMISSION_UNDECLARED == "cloud.action_permission_undeclared"


# --- the action permission code is reachable, not merely spelled --------------


class TestActionPermissionCodeIsRaisable:
    """``CLOUD_ACTION_PERMISSION_UNDECLARED`` fires in a pydantic validator.

    A validator raises ``ValueError``, which pydantic re-wraps, so no caller
    ever received a :class:`CloudRefused` carrying this code. The decision
    function is what makes it a real refusal.
    """

    def test_an_action_with_no_permissions_raises_with_its_code(self) -> None:
        with pytest.raises(CloudRefused) as excinfo:
            ensure_action_declares_permissions("cloud.aws.stop", [])
        assert excinfo.value.code == CLOUD_ACTION_PERMISSION_UNDECLARED
        assert excinfo.value.details["action_id"] == "cloud.aws.stop"

    def test_an_action_missing_target_mutate_names_what_would_have_passed(self) -> None:
        with pytest.raises(CloudRefused) as excinfo:
            ensure_action_declares_permissions("cloud.aws.stop", [ProviderPermission.TARGET_READ])
        assert excinfo.value.code == CLOUD_ACTION_PERMISSION_UNDECLARED
        assert excinfo.value.details["missing"] == ["target:mutate"]
        assert "target:mutate" in excinfo.value.remediation

    def test_a_fully_declared_action_is_admitted(self) -> None:
        decision = check_action_declares_permissions(
            "cloud.aws.stop", [ProviderPermission.TARGET_READ, ProviderPermission.TARGET_MUTATE]
        )
        assert decision.allowed is True

    def test_the_decision_function_agrees_with_the_constructor(self) -> None:
        """The constructor delegates here, so the two cannot disagree."""
        with pytest.raises(ValidationError, match=CLOUD_ACTION_PERMISSION_UNDECLARED):
            _reversible(permissions=frozenset({ProviderPermission.TARGET_READ}))
        assert (
            check_action_declares_permissions("x", [ProviderPermission.TARGET_READ]).code
            == CLOUD_ACTION_PERMISSION_UNDECLARED
        )

    def test_a_constructible_action_is_admitted_by_the_check(self) -> None:
        action = _reversible()
        decision = check_action_declares_permissions(action.action_id, action.required_permissions)
        assert decision.allowed is True


# --- reversibility: the structural distinction ----------------------------------


class TestIrreversibilityIsStructural:
    def test_a_reversible_action_does_not_need_elevated_approval(self) -> None:
        assert requires_elevated_approval(_reversible()) is False

    def test_an_irreversible_action_does(self) -> None:
        assert requires_elevated_approval(_irreversible()) is True

    def test_reversible_and_irreversible_are_distinct_types(self) -> None:
        assert isinstance(_reversible(), ReversibleCloudAction)
        assert not isinstance(_reversible(), IrreversibleCloudAction)
        assert isinstance(_irreversible(), IrreversibleCloudAction)

    def test_the_two_types_are_not_interchangeable(self) -> None:
        # The distinction a gate depends on: a reversible action cannot be
        # passed off as irreversible, and an irreversible one cannot be built
        # as the reversible model.
        assert not issubclass(IrreversibleCloudAction, ReversibleCloudAction)
        assert not issubclass(ReversibleCloudAction, IrreversibleCloudAction)

    def test_declaring_irreversible_on_the_reversible_model_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="must be an IrreversibleCloudAction"):
            _reversible(reversibility=Reversibility.IRREVERSIBLE)

    def test_declaring_reversible_on_the_irreversible_model_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="must declare 'irreversible'"):
            IrreversibleCloudAction(
                action_id="cloud.aws.delete_volume",
                kind=CloudActionKind.IMPAIR,
                target=_target(),
                summary="destroy the volume",
                reversibility=Reversibility.REVERSIBLE,
                rationale="no restore exists",
                required_permissions=MUTATE,
            )

    def test_irreversible_requires_a_rationale(self) -> None:
        with pytest.raises(ValidationError, match="at least 1"):
            IrreversibleCloudAction(
                action_id="cloud.aws.delete_volume",
                kind=CloudActionKind.IMPAIR,
                target=_target(),
                summary="destroy the volume",
                reversibility=Reversibility.IRREVERSIBLE,
                rationale="",
                required_permissions=MUTATE,
            )

    def test_irreversible_refuses_a_blank_rationale(self) -> None:
        with pytest.raises(ValidationError, match="must state why"):
            IrreversibleCloudAction(
                action_id="cloud.aws.delete_volume",
                kind=CloudActionKind.IMPAIR,
                target=_target(),
                summary="destroy the volume",
                reversibility=Reversibility.IRREVERSIBLE,
                rationale="   ",
                required_permissions=MUTATE,
            )

    def test_is_irreversible_agrees_with_the_type(self) -> None:
        assert _irreversible().is_irreversible is True
        assert _reversible().is_irreversible is False
        assert _reversible(reversibility=Reversibility.RECONCILED).is_irreversible is False

    def test_reconciled_is_still_a_reversible_cloud_action(self) -> None:
        action = _reversible(reversibility=Reversibility.RECONCILED)
        assert requires_elevated_approval(action) is False

    def test_reversibility_vocabulary_is_the_fault_one(self) -> None:
        # One word for "irreversible" in the whole system: the same enum the
        # damage quota prices faults with.
        assert set(Reversibility) == {
            Reversibility.REVERSIBLE,
            Reversibility.RECONCILED,
            Reversibility.IRREVERSIBLE,
        }


# --- IAM -----------------------------------------------------------------------


class TestPermissionCheck:
    def _role(self, *granted: ProviderPermission) -> CloudRoleRef:
        return CloudRoleRef(role_id="mayhem.cloud.ops", provider=AWS, granted=frozenset(granted))

    def test_a_sufficient_role_is_allowed(self) -> None:
        decision = check_role_can_perform(
            self._role(ProviderPermission.TARGET_MUTATE), _reversible()
        )
        assert decision.allowed is True
        assert decision.denied is False
        assert decision.code == ""
        assert decision.missing == ()

    def test_an_insufficient_role_is_refused_by_name(self) -> None:
        decision = check_role_can_perform(self._role(ProviderPermission.TARGET_READ), _reversible())
        assert decision.allowed is False
        assert decision.code == CLOUD_PERMISSION_DENIED
        assert decision.missing == ("target:mutate",)
        assert "target:mutate" in decision.reason

    def test_the_default_role_can_perform_nothing(self) -> None:
        # Negative control: the default posture is *nothing*.
        role = CloudRoleRef(role_id="mayhem.cloud.default", provider=AWS)
        assert role.granted == DEFAULT_CLOUD_ROLE_GRANTS
        assert role.granted == frozenset()
        decision = check_role_can_perform(role, _reversible())
        assert decision.allowed is False
        assert decision.missing == ("target:mutate",)

    def test_every_missing_permission_is_named(self) -> None:
        action = _reversible(
            permissions=frozenset({ProviderPermission.TARGET_MUTATE, ProviderPermission.NETWORK})
        )
        decision = check_role_can_perform(self._role(ProviderPermission.TARGET_MUTATE), action)
        assert decision.missing == ("network",)

    def test_a_cross_provider_role_is_refused_even_when_permissions_match(self) -> None:
        role = CloudRoleRef(
            role_id="mayhem.gcp.ops",
            provider=GCP,
            granted=frozenset({ProviderPermission.TARGET_MUTATE}),
        )
        decision = check_role_can_perform(role, _reversible())
        assert decision.allowed is False
        assert decision.code == CLOUD_ROLE_PROVIDER_MISMATCH

    def test_a_cross_provider_refusal_names_every_required_permission(self) -> None:
        action = _reversible(
            permissions=frozenset({ProviderPermission.TARGET_MUTATE, ProviderPermission.NETWORK})
        )
        role = CloudRoleRef(
            role_id="mayhem.gcp.ops", provider=GCP, granted=frozenset(action.required_permissions)
        )
        decision = check_role_can_perform(role, action)
        assert decision.missing == ("network", "target:mutate")

    def test_the_check_is_pure(self) -> None:
        role = self._role(ProviderPermission.TARGET_MUTATE)
        action = _reversible()
        first = check_role_can_perform(role, action)
        second = check_role_can_perform(role, action)
        assert first == second

    def test_the_check_does_not_mutate_the_role(self) -> None:
        role = CloudRoleRef(role_id="mayhem.cloud.ops", provider=AWS)
        check_role_can_perform(role, _reversible())
        assert role.granted == frozenset()

    def test_ensure_raises_naming_the_missing_permission(self) -> None:
        with pytest.raises(CloudRefused) as excinfo:
            ensure_role_can_perform(self._role(ProviderPermission.TARGET_READ), _reversible())
        assert excinfo.value.code == CLOUD_PERMISSION_DENIED
        assert excinfo.value.details["missing"] == ["target:mutate"]
        assert "target:mutate" in excinfo.value.remediation

    def test_ensure_returns_the_decision_on_success(self) -> None:
        decision = ensure_role_can_perform(
            self._role(ProviderPermission.TARGET_MUTATE), _reversible()
        )
        assert decision.allowed is True

    def test_read_only_factory_can_never_authorise_a_mutation(self) -> None:
        role = CloudRoleRef.read_only(role_id="mayhem.cloud.audit", provider=AWS)
        assert role.granted == frozenset({ProviderPermission.TARGET_READ})
        assert role.mutating is False
        decision = check_role_can_perform(role, _reversible())
        assert decision.allowed is False
        assert decision.missing == ("target:mutate",)

    def test_mutating_reports_the_granted_posture(self) -> None:
        assert self._role(ProviderPermission.TARGET_MUTATE).mutating is True

    def test_role_refuses_an_uppercase_id(self) -> None:
        with pytest.raises(ValidationError, match="lowercase dotted identifier"):
            CloudRoleRef(role_id="Mayhem Cloud Ops", provider=AWS)

    def test_role_requires_a_provider(self) -> None:
        with pytest.raises(ValidationError):
            CloudRoleRef(role_id="mayhem.cloud.ops")  # type: ignore[call-arg]

    def test_an_irreversible_action_is_gated_by_iam_too(self) -> None:
        # Elevated approval (plan 09) and IAM are separate gates; this one only
        # says the IAM question is answerable for irreversible actions too.
        decision = check_role_can_perform(
            self._role(ProviderPermission.TARGET_MUTATE), _irreversible()
        )
        assert decision.allowed is True
        assert requires_elevated_approval(_irreversible()) is True


# --- cost ----------------------------------------------------------------------


class TestCostEstimate:
    def test_estimate_is_a_resource_estimate_narrowed_to_cloud_spend(self) -> None:
        # The "extend, do not duplicate" property: this is the existing money
        # type, not a second one.
        from mayhem.domain.budgets import ResourceEstimate

        assert issubclass(CostEstimate, ResourceEstimate)
        estimate = _estimate()
        assert estimate.dimension is ResourceDimension.CLOUD_SPEND
        assert estimate.unit == "currency_micros"

    def test_expected_is_the_midpoint_of_the_range(self) -> None:
        estimate = _estimate(1.0, 3.0)
        assert estimate.expected == 2.0
        assert estimate.midpoint == 2.0

    def test_spread_is_the_width_of_the_range(self) -> None:
        assert _estimate(1.0, 3.0).spread == 2.0

    def test_headroom_is_ceiling_minus_high_bound(self) -> None:
        assert _estimate(1.0, 3.0, ceiling=10.0).headroom == 7.0

    def test_an_author_supplied_midpoint_is_honoured(self) -> None:
        estimate = CostEstimate(
            scope=ResourceScope.EXPERIMENT,
            scope_key="123456789012",
            expected=2.0,
            expected_low=1.0,
            expected_high=3.0,
            ceiling=10.0,
            basis="list price",
        )
        assert estimate.expected == 2.0

    def test_a_midpoint_that_disagrees_with_the_range_is_refused(self) -> None:
        # One number to compare against: the scalar cannot drift from the range.
        with pytest.raises(InvariantViolationError) as excinfo:
            CostEstimate(
                scope=ResourceScope.EXPERIMENT,
                scope_key="123456789012",
                expected=9.0,
                expected_low=1.0,
                expected_high=3.0,
                ceiling=10.0,
                basis="list price",
            )
        assert excinfo.value.rule == RULE_COST_ESTIMATE_ORDER
        assert "not the midpoint" in str(excinfo.value)

    def test_a_high_bound_below_the_low_bound_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            _estimate(5.0, 1.0)
        assert excinfo.value.rule == RULE_COST_ESTIMATE_ORDER
        assert "below its low bound" in str(excinfo.value)

    def test_a_ceiling_below_the_high_bound_is_refused(self) -> None:
        # Negative control: a plan already over budget is refused, not carried.
        with pytest.raises(InvariantViolationError) as excinfo:
            _estimate(1.0, 3.0, ceiling=2.0)
        assert excinfo.value.rule == RULE_COST_CEILING_BELOW_HIGH
        assert "already over budget" in str(excinfo.value)

    def test_a_ceiling_equal_to_the_high_bound_is_allowed(self) -> None:
        assert _estimate(1.0, 3.0, ceiling=3.0).headroom == 0.0

    def test_a_negative_low_bound_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            _estimate(-1.0, 3.0)

    def test_an_estimate_requires_a_basis(self) -> None:
        # Inherited from ResourceEstimate: an unmeasured claim is
        # unrepresentable, so an estimate with no stated basis cannot be built.
        with pytest.raises(InvariantViolationError):
            CostEstimate(
                scope=ResourceScope.EXPERIMENT,
                scope_key="123456789012",
                expected_low=1.0,
                expected_high=3.0,
                ceiling=10.0,
                basis="   ",
            )

    def test_a_non_cloud_spend_dimension_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError) as excinfo:
            CostEstimate(
                dimension=ResourceDimension.CPU,
                scope=ResourceScope.EXPERIMENT,
                scope_key="123456789012",
                expected=2.0,
                expected_low=1.0,
                expected_high=3.0,
                ceiling=10.0,
                basis="list price",
            )
        assert excinfo.value.rule == RULE_COST_ESTIMATE_ORDER

    def test_describe_names_the_range_ceiling_and_basis(self) -> None:
        described = _estimate(1.0, 3.0).describe()
        assert "1-3" in described
        assert "currency_micros" in described
        assert "ceiling of 10" in described
        assert "list price" in described


class TestCostCeiling:
    def test_spend_inside_the_ceiling_is_allowed(self) -> None:
        decision = check_cost_ceiling(_estimate(), 4.0)
        assert decision.allowed is True
        assert decision.exceeded is False
        assert decision.code == ""

    def test_spend_equal_to_the_ceiling_is_allowed(self) -> None:
        assert check_cost_ceiling(_estimate(), 10.0).allowed is True

    def test_spend_above_the_ceiling_is_refused(self) -> None:
        decision = check_cost_ceiling(_estimate(), 10.5)
        assert decision.allowed is False
        assert decision.exceeded is True
        assert decision.code == CLOUD_COST_CEILING_EXCEEDED

    def test_an_exceeded_ceiling_reports_how_far_over(self) -> None:
        assert check_cost_ceiling(_estimate(), 12.5).over_by == 2.5

    def test_spend_inside_the_ceiling_has_no_overage(self) -> None:
        assert check_cost_ceiling(_estimate(), 4.0).over_by == 0.0

    def test_the_refusal_names_the_ceiling_and_the_unit(self) -> None:
        decision = check_cost_ceiling(_estimate(), 10.5)
        assert "10" in decision.reason
        assert "currency_micros" in decision.reason

    def test_a_negative_spend_is_refused(self) -> None:
        # An unknown or backwards spend is not evidence of being under a limit.
        with pytest.raises(InvariantViolationError) as excinfo:
            check_cost_ceiling(_estimate(), -1.0)
        assert excinfo.value.rule == "cloud.cost_spend_invalid"

    def test_a_non_finite_spend_is_refused(self) -> None:
        with pytest.raises(InvariantViolationError):
            check_cost_ceiling(_estimate(), float("inf"))

    def test_the_check_is_pure(self) -> None:
        estimate = _estimate()
        assert check_cost_ceiling(estimate, 4.0) == check_cost_ceiling(estimate, 4.0)

    def test_ensure_raises_on_a_breach(self) -> None:
        with pytest.raises(CloudRefused) as excinfo:
            ensure_cost_ceiling(_estimate(), 11.0)
        assert excinfo.value.code == CLOUD_COST_CEILING_EXCEEDED
        assert excinfo.value.details["over_by"] == 1.0
        assert excinfo.value.details["expected_high"] == 3.0

    def test_ensure_returns_the_decision_inside_the_ceiling(self) -> None:
        assert ensure_cost_ceiling(_estimate(), 4.0).allowed is True

    def test_a_zero_estimate_is_legitimate(self) -> None:
        estimate = _estimate(0.0, 0.0, ceiling=0.0)
        assert check_cost_ceiling(estimate, 0.0).allowed is True
        assert check_cost_ceiling(estimate, 0.01).allowed is False
