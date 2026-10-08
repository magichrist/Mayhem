"""Plan 06 Phase 5 — adapter contract, refusal family, and cost-estimate guards.

Acceptance: *suite green without cloud credentials*. Every transport in this
file is a fake (counting or scripted); no test opens a socket, imports an SDK,
or reads an environment credential. Three groups:

1. **Adapter contract** (parametric over AWS/GCP/Azure): one lifecycle, one
   permission model, one honesty shape. A provider adds rows, not special
   cases, so the contract is asserted per adapter, not per table.
2. **Refusal family**: unresolved/ambiguous targets, insufficient IAM (named
   grants and cross-provider roles), exceeded ceilings, missing durations,
   unpriced-under-a-declared-ceiling, unsupported pairs, and the damage-quota
   breach — each pinned to its exact code, each leaving the transport
   untouched.
3. **Cost estimates**: UNPRICED honesty (zeros mean unknown, never free),
   priced math from an operator card, the ceiling boundary, and invalid
   spends refused rather than judged.
"""

from __future__ import annotations

import pytest

from mayhem.controller.cloud_evidence import CloudGateStage, admit_cloud_action
from mayhem.domain.budgets import ResourceScope
from mayhem.domain.cloud import (
    CLOUD_COST_CEILING_EXCEEDED,
    CloudActionKind,
    CloudProvider,
    CloudProviderRef,
    CloudResourceClass,
    CloudResourceIdentity,
    CloudRoleRef,
    CloudSelector,
    CloudSelectorKind,
    CloudTarget,
    CloudTargetIntent,
    CostEstimate,
    IrreversibleCloudAction,
    Reversibility,
    ReversibleCloudAction,
    check_cost_ceiling,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.outcomes import StepOutcome, TargetOutcome
from mayhem.domain.provider import ProviderPermission
from mayhem.domain.quota import DamageLedger, DamageQuota
from mayhem.providers.cloud.aws import AwsCloudAdapter
from mayhem.providers.cloud.azure import AzureCloudAdapter
from mayhem.providers.cloud.gcp import GcpCloudAdapter
from mayhem.providers.cloud.port import (
    CLOUD_ACTION_UNSUPPORTED,
    CLOUD_COST_UNPRICED,
    CLOUD_DURATION_REQUIRED,
    CLOUD_IRREVERSIBLE_APPROVAL_REQUIRED,
    CloudAdapter,
    CloudRateCard,
    CloudTransport,
    MutationReceipt,
    ResourceQuery,
    ResourceRecord,
    ReversibleCapability,
)

GRANTS_ALL = frozenset(
    {
        ProviderPermission.TARGET_MUTATE,
        ProviderPermission.TARGET_READ,
        ProviderPermission.NETWORK,
    }
)
GRANTS_READ_ONLY = frozenset({ProviderPermission.TARGET_READ})


# =============================================================================
# Fakes and builders (no cloud, no SDK, no credentials)
# =============================================================================


class _CountingTransport:
    """Counts mutations and never lets one through.

    The negative control: any path that reaches the transport names itself
    here, and every refusal test below asserts the count stayed zero.
    """

    def __init__(self, records: tuple[ResourceRecord, ...] = ()) -> None:
        self.mutations = 0
        self._records = records

    def list_resources(self, query: ResourceQuery) -> tuple[ResourceRecord, ...]:
        return self._records

    def read_resource(self, query: ResourceQuery, resource_id: str) -> ResourceRecord | None:
        return None

    def mutate(self, command: object) -> MutationReceipt:
        self.mutations += 1
        raise AssertionError(f"refused paths must never mutate; got {command!r}")


class _ScriptedTransport:
    """A fake cloud that answers reads with canned fields and accepts mutates.

    The states a real binding would report, without a real binding: reads
    return the applied fields until a compensating operation lands, then the
    compensated fields. Receipts echo the requested operation, as a binding
    must.
    """

    def __init__(self, *, applied: dict[str, str], compensated: dict[str, str]) -> None:
        self.mutations = 0
        self.reads = 0
        self._applied = dict(applied)
        self._compensated = dict(compensated)
        self._fields = dict(applied)

    def list_resources(self, query: ResourceQuery) -> tuple[ResourceRecord, ...]:
        return ()

    def read_resource(self, query: ResourceQuery, resource_id: str) -> ResourceRecord | None:
        self.reads += 1
        return ResourceRecord(query=query, resource_id=resource_id, fields=dict(self._fields))

    def mutate(self, command) -> MutationReceipt:  # type: ignore[no-untyped-def]
        self.mutations += 1
        if "StartInstances" in command.operation:
            self._fields = dict(self._compensated)
        return MutationReceipt(
            operation=command.operation,
            resource_id=command.resource_id,
            request_id="req-fake-1",
        )


def _ref(provider: CloudProvider) -> CloudProviderRef:
    return CloudProviderRef(provider=provider)


def _stop_action(
    provider: CloudProvider = CloudProvider.AWS,
    *,
    duration_s: float | None = 3600.0,
    account: str = "123456789012",
    region: str = "us-east-1",
    resource_id: str = "i-0p5",
) -> ReversibleCloudAction:
    ref = _ref(provider)
    identity = CloudResourceIdentity(
        provider=ref,
        resource_class=CloudResourceClass.VM,
        account=account,
        region=region,
        resource_id=resource_id,
    )
    selector = CloudSelector(
        resource_class=CloudResourceClass.VM,
        kind=CloudSelectorKind.IDENTIFIER,
        account=account,
        region=region,
        identifiers=(resource_id,),
    )
    target = CloudTarget(
        provider=ref,
        resource_class=CloudResourceClass.VM,
        selector=selector,
        identity=identity,
    )
    return ReversibleCloudAction(
        action_id=f"p5.probe.{provider.value}.vm.stop",
        kind=CloudActionKind.STOP,
        target=target,
        summary="phase 5 contract probe",
        reversibility=Reversibility.REVERSIBLE,
        duration_s=duration_s,
        required_permissions=frozenset(
            {ProviderPermission.TARGET_MUTATE, ProviderPermission.TARGET_READ}
        ),
    )


def _irreversible_action(
    provider: CloudProvider,
    kind: CloudActionKind,
    resource_class: CloudResourceClass,
) -> IrreversibleCloudAction:
    ref = _ref(provider)
    account, region, resource_id = "p5-acct", "p5-region", "p5-res"
    identity = CloudResourceIdentity(
        provider=ref,
        resource_class=resource_class,
        account=account,
        region=region,
        resource_id=resource_id,
    )
    selector = CloudSelector(
        resource_class=resource_class,
        kind=CloudSelectorKind.IDENTIFIER,
        account=account,
        region=region,
        identifiers=(resource_id,),
    )
    target = CloudTarget(
        provider=ref,
        resource_class=resource_class,
        selector=selector,
        identity=identity,
    )
    return IrreversibleCloudAction(
        action_id=f"p5.probe.{provider.value}.{resource_class.value}.{kind.value}",
        kind=kind,
        target=target,
        summary="phase 5 irreversible probe",
        reversibility=Reversibility.IRREVERSIBLE,
        rationale="the provider API offers no restore for this operation",
        required_permissions=frozenset(
            {ProviderPermission.TARGET_MUTATE, ProviderPermission.TARGET_READ}
        ),
    )


def _role(
    provider: CloudProvider = CloudProvider.AWS,
    grants: frozenset[ProviderPermission] = GRANTS_ALL,
) -> CloudRoleRef:
    return CloudRoleRef(role_id="p5.operator", provider=_ref(provider), granted=grants)


def _card(
    provider: CloudProvider = CloudProvider.AWS,
    *,
    micros_per_api_call: float = 1.0,
    micros_per_instance_hour: float = 0.0,
    high_factor: float = 1.0,
    region: str = "us-east-1",
    source: str = "p5: unit rate card",
) -> CloudRateCard:
    return CloudRateCard(
        provider=_ref(provider),
        resource_class=CloudResourceClass.VM,
        region=region,
        source=source,
        micros_per_api_call=micros_per_api_call,
        micros_per_instance_hour=micros_per_instance_hour,
        high_factor=high_factor,
    )


def _roomy_quota() -> DamageQuota:
    return DamageQuota(budget_s=1_000_000.0, per_fault_ceiling_s=1_000_000.0)


ADAPTERS: dict[str, type[CloudAdapter]] = {
    "aws": AwsCloudAdapter,
    "gcp": GcpCloudAdapter,
    "azure": AzureCloudAdapter,
}

#: The irreversible pair each adapter declares (kind, class).
IRREVERSIBLE_PAIRS: dict[str, tuple[CloudActionKind, CloudResourceClass]] = {
    "aws": (CloudActionKind.IMPAIR, CloudResourceClass.BLOCK_STORAGE),
    "gcp": (CloudActionKind.IMPAIR, CloudResourceClass.BLOCK_STORAGE),
    "azure": (CloudActionKind.ISOLATE, CloudResourceClass.FUNCTION),
}


@pytest.fixture(params=sorted(ADAPTERS))
def adapter_name(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.fixture()
def adapter(adapter_name: str) -> CloudAdapter:
    return ADAPTERS[adapter_name](_CountingTransport(), rate_cards=())


# =============================================================================
# 1. Adapter contract — one lifecycle for all three providers
# =============================================================================


class TestAdapterContract:
    def test_provider_key_services_and_sorted_matrix(
        self, adapter: CloudAdapter, adapter_name: str
    ) -> None:
        assert adapter.provider_key == adapter_name
        assert adapter.services, "an adapter with no services can discover nothing"
        pairs = adapter.supported_actions()
        assert pairs, "an adapter with no capabilities has nothing to expose"
        assert pairs == tuple(sorted(pairs, key=lambda p: (p[0].value, p[1].value)))
        assert adapter.transport.mutations == 0  # type: ignore[attr-defined]

    def test_adapter_permission_needs_are_identical(self, adapter: CloudAdapter) -> None:
        assert adapter.adapter_permissions == frozenset(
            {ProviderPermission.NETWORK, ProviderPermission.TARGET_READ}
        )

    def test_reversible_rows_name_a_verifiable_compensation(self, adapter: CloudAdapter) -> None:
        reversible = [
            cap for cap in adapter.capabilities.values() if isinstance(cap, ReversibleCapability)
        ]
        assert reversible, "every adapter must declare at least one reversible action"
        for cap in reversible:
            assert cap.compensate_operation.strip()
            assert cap.apply_verify.describe().strip()
            assert cap.compensate_verify.describe().strip()

    def test_irreversible_rows_carry_a_rationale_and_no_compensation(
        self, adapter: CloudAdapter, adapter_name: str
    ) -> None:
        from mayhem.providers.cloud.port import IrreversibleCapability

        kind, cls = IRREVERSIBLE_PAIRS[adapter_name]
        cap = adapter.capabilities[(kind, cls)]
        assert isinstance(cap, IrreversibleCapability)
        assert cap.rationale.strip()
        assert not hasattr(cap, "compensate_operation")

    def test_unknown_pair_is_unsupported_not_approximated(
        self, adapter: CloudAdapter, adapter_name: str
    ) -> None:
        provider = CloudProvider(adapter_name)
        action = _stop_action(provider).model_copy(update={"kind": CloudActionKind.REBOOT})
        assert adapter.capability_for(action) is None
        preview = adapter.estimate_cost(action, ceiling=0.0)
        assert preview.denied
        assert preview.code == CLOUD_ACTION_UNSUPPORTED
        assert preview.counts.api_calls == 0
        preflight = adapter.preflight(action, role=_role(provider), ceiling=0.0)
        assert not preflight.allowed
        assert "does not implement" in preflight.reason
        assert adapter.transport.mutations == 0  # type: ignore[attr-defined]

    def test_irreversible_action_cannot_execute(
        self, adapter: CloudAdapter, adapter_name: str
    ) -> None:
        provider = CloudProvider(adapter_name)
        kind, cls = IRREVERSIBLE_PAIRS[adapter_name]
        action = _irreversible_action(provider, kind, cls)
        result = adapter.execute(action, role=_role(provider), ceiling=0.0)
        assert result.denied
        assert result.code == CLOUD_IRREVERSIBLE_APPROVAL_REQUIRED
        assert result.target_outcome is TargetOutcome.FAILED_TO_APPLY
        assert adapter.transport.mutations == 0  # type: ignore[attr-defined]

    def test_irreversible_capability_has_no_verifiable_post_state(
        self, adapter: CloudAdapter, adapter_name: str
    ) -> None:
        provider = CloudProvider(adapter_name)
        kind, cls = IRREVERSIBLE_PAIRS[adapter_name]
        action = _irreversible_action(provider, kind, cls)
        verification = adapter.verify(action)
        assert not verification.confirmed
        assert verification.outcome is StepOutcome.FAILED
        assert "verification_unavailable" in verification.reason

    def test_cross_provider_intent_is_refused(
        self, adapter: CloudAdapter, adapter_name: str
    ) -> None:
        other = "gcp" if adapter_name == "aws" else "aws"
        intent = CloudTargetIntent(
            provider=_ref(CloudProvider(other)),
            selector=CloudSelector(
                resource_class=CloudResourceClass.VM,
                kind=CloudSelectorKind.IDENTIFIER,
                account="x",
                region="y",
                identifiers=("i-1",),
            ),
        )
        result = adapter.resolve(intent)
        assert result.denied
        assert "role_provider_mismatch" in result.code
        assert result.target is None

    def test_analyses_never_touch_the_transport(
        self, adapter: CloudAdapter, adapter_name: str
    ) -> None:
        provider = CloudProvider(adapter_name)
        action = _stop_action(provider)
        role = _role(provider)
        analysis = adapter.analyze_permission(role, action)
        assert analysis.ok
        preview = adapter.estimate_cost(action, ceiling=0.0)
        assert preview.ok
        preflight = adapter.preflight(action, role=role, ceiling=0.0)
        assert preflight.allowed
        assert preflight.api_calls == 0
        assert adapter.transport.mutations == 0  # type: ignore[attr-defined]


class TestCompensateVerifyShapeOnFakes:
    """The compensate→verify shape, demonstrated on a fake — never a sandbox.

    Phase 2's acceptance (demonstrate on a sandbox account) is unmet and the
    plan says so; what this pins is the machine-checkable half: execute
    verifies the applied state, compensate verifies the compensated state, and
    neither reports COMPLETED on a receipt alone.
    """

    def test_execute_then_compensate_verify_on_aws_fake(self) -> None:
        transport = _ScriptedTransport(
            applied={"State.Name": "stopped"},
            compensated={"State.Name": "running"},
        )
        adapter = AwsCloudAdapter(transport, rate_cards=())
        action = _stop_action()
        role = _role()
        executed = adapter.execute(action, role=role, ceiling=0.0)
        assert executed.outcome is StepOutcome.COMPLETED
        assert executed.verification is not None
        assert executed.verification.confirmed
        assert executed.api_calls == 2  # one mutate, one verification read
        compensated = adapter.compensate(action, role=role)
        assert compensated.outcome is StepOutcome.COMPLETED
        assert compensated.verification is not None
        assert compensated.verification.confirmed
        assert transport.mutations == 2

    def test_completed_is_unconstructible_without_a_confirming_verification(
        self,
    ) -> None:
        from pydantic import ValidationError

        from mayhem.providers.cloud.port import ExecutionResult

        with pytest.raises(ValidationError):
            ExecutionResult(
                outcome=StepOutcome.COMPLETED,
                receipt=MutationReceipt(
                    operation="ec2:StopInstances",
                    resource_id="i-0p5",
                    request_id="req-1",
                ),
                verification=None,
            )


# =============================================================================
# 2. Refusal family — exact codes, transport untouched
# =============================================================================


def _record(
    ref: CloudProviderRef,
    resource_id: str,
    *,
    tags: frozenset[str] = frozenset(),
    fields: dict[str, str] | None = None,
) -> ResourceRecord:
    query = ResourceQuery(
        provider=ref,
        resource_class=CloudResourceClass.VM,
        account="123456789012",
        region="us-east-1",
        service="ec2",
    )
    return ResourceRecord(
        query=query, resource_id=resource_id, tags=tags, fields=dict(fields or {})
    )


class TestTargetResolutionRefusals:
    def test_zero_matches_is_a_plan_time_refusal(self) -> None:
        adapter = AwsCloudAdapter(_CountingTransport(), rate_cards=())
        ref = _ref(CloudProvider.AWS)
        intent = CloudTargetIntent(
            provider=ref,
            selector=CloudSelector(
                resource_class=CloudResourceClass.VM,
                kind=CloudSelectorKind.IDENTIFIER,
                account="123456789012",
                region="us-east-1",
                identifiers=("i-missing",),
            ),
        )
        result = adapter.resolve(intent)
        assert result.denied
        assert "target_unresolved" in result.code
        assert result.target is None

    def test_two_matches_refuse_and_name_both(self) -> None:
        ref = _ref(CloudProvider.AWS)
        records = (
            _record(ref, "i-aaa", tags=frozenset({"web"})),
            _record(ref, "i-bbb", tags=frozenset({"web"})),
        )
        adapter = AwsCloudAdapter(_CountingTransport(records), rate_cards=())
        intent = CloudTargetIntent(
            provider=ref,
            selector=CloudSelector(
                resource_class=CloudResourceClass.VM,
                kind=CloudSelectorKind.TAG,
                account="123456789012",
                region="us-east-1",
                tags=frozenset({"web"}),
            ),
        )
        result = adapter.resolve(intent)
        assert result.denied
        assert "ambiguous_resolution" in result.code
        assert result.details.get("match_count") == 2
        assert result.target is None

    def test_exact_single_match_resolves(self) -> None:
        ref = _ref(CloudProvider.AWS)
        records = (
            _record(ref, "i-aaa", tags=frozenset({"web"})),
            _record(ref, "i-bbb", tags=frozenset({"db"})),
        )
        adapter = AwsCloudAdapter(_CountingTransport(records), rate_cards=())
        intent = CloudTargetIntent(
            provider=ref,
            selector=CloudSelector(
                resource_class=CloudResourceClass.VM,
                kind=CloudSelectorKind.IDENTIFIER,
                account="123456789012",
                region="us-east-1",
                identifiers=("i-aaa",),
            ),
        )
        result = adapter.resolve(intent)
        assert result.ok
        assert result.target is not None
        assert result.target.identity.resource_id == "i-aaa"


class TestGateRefusals:
    def _admit(self, **overrides):  # type: ignore[no-untyped-def]
        transport = _CountingTransport()
        params = {
            "adapter": AwsCloudAdapter(transport, rate_cards=overrides.pop("rate_cards", ())),
            "action": _stop_action(),
            "role": _role(),
            "run_id": "p5",
            "owner_agent": "p5",
            "duration_s": 3600.0,
            "ceiling": 0.0,
            "quota": _roomy_quota(),
            "ledger": DamageLedger(),
        }
        params.update(overrides)
        adapter = params.pop("adapter")
        return admit_cloud_action(adapter, **params), transport  # type: ignore[arg-type]

    def test_insufficient_iam_names_the_missing_grant(self) -> None:
        outcome, transport = self._admit(role=_role(grants=GRANTS_READ_ONLY))
        assert outcome.refused
        assert outcome.stage is CloudGateStage.PERMISSION
        assert "target:mutate" in outcome.reason
        assert outcome.preview is None and outcome.blast is None
        assert transport.mutations == 0

    def test_cross_provider_role_refuses_at_the_gate(self) -> None:
        outcome, transport = self._admit(role=_role(CloudProvider.GCP))
        assert outcome.refused
        assert outcome.stage is CloudGateStage.PERMISSION
        assert "role_provider_mismatch" in outcome.rule_id
        assert transport.mutations == 0

    def test_projected_spend_above_ceiling_refuses_before_mutation(self) -> None:
        # Priced at 4 api calls x 1 micro = 4 high; the ceiling covers the
        # estimate, but the caller's own projection does not fit it.
        transport = _CountingTransport()
        adapter = AwsCloudAdapter(transport, rate_cards=(_card(),))
        outcome = admit_cloud_action(
            adapter,
            _stop_action(),
            _role(),
            run_id="p5",
            owner_agent="p5",
            duration_s=3600.0,
            ceiling=10.0,
            quota=_roomy_quota(),
            ledger=DamageLedger(),
            projected_spend=500.0,
        )
        assert outcome.refused
        assert outcome.stage is CloudGateStage.COST
        assert outcome.rule_id == CLOUD_COST_CEILING_EXCEEDED
        assert outcome.projected_spend == 500.0
        assert transport.mutations == 0

    def test_ceiling_below_estimate_high_bound_refuses(self) -> None:
        # Priced high is 4 micros; a ceiling of 3 is already over budget.
        transport = _CountingTransport()
        adapter = AwsCloudAdapter(transport, rate_cards=(_card(),))
        outcome = admit_cloud_action(
            adapter,
            _stop_action(),
            _role(),
            run_id="p5",
            owner_agent="p5",
            duration_s=3600.0,
            ceiling=3.0,
            quota=_roomy_quota(),
            ledger=DamageLedger(),
        )
        assert outcome.refused
        assert outcome.stage is CloudGateStage.COST
        assert "cost_ceiling_below_high" in outcome.rule_id
        assert transport.mutations == 0

    def test_unpriced_action_under_a_declared_ceiling_refuses(self) -> None:
        outcome, transport = self._admit(ceiling=1_000_000.0)
        assert outcome.refused
        assert outcome.stage is CloudGateStage.COST
        assert outcome.rule_id == CLOUD_COST_UNPRICED
        assert transport.mutations == 0

    def test_billable_action_without_duration_refuses(self) -> None:
        ref = _ref(CloudProvider.AWS)
        identity = CloudResourceIdentity(
            provider=ref,
            resource_class=CloudResourceClass.VM,
            account="123456789012",
            region="us-east-1",
            resource_id="i-0p5",
        )
        selector = CloudSelector(
            resource_class=CloudResourceClass.VM,
            kind=CloudSelectorKind.IDENTIFIER,
            account="123456789012",
            region="us-east-1",
            identifiers=("i-0p5",),
        )
        action = ReversibleCloudAction(
            action_id="p5.probe.aws.vm.impair",
            kind=CloudActionKind.IMPAIR,
            target=CloudTarget(
                provider=ref,
                resource_class=CloudResourceClass.VM,
                selector=selector,
                identity=identity,
            ),
            summary="billable impair with no duration",
            reversibility=Reversibility.REVERSIBLE,
            duration_s=None,
            required_permissions=frozenset(
                {ProviderPermission.TARGET_MUTATE, ProviderPermission.TARGET_READ}
            ),
        )
        transport = _CountingTransport()
        adapter = AwsCloudAdapter(transport, rate_cards=())
        outcome = admit_cloud_action(
            adapter,
            action,
            _role(),
            run_id="p5",
            owner_agent="p5",
            duration_s=3600.0,
            ceiling=0.0,
            quota=_roomy_quota(),
            ledger=DamageLedger(),
        )
        assert outcome.refused
        assert outcome.stage is CloudGateStage.COST
        assert outcome.rule_id == CLOUD_DURATION_REQUIRED
        assert transport.mutations == 0

    def test_quota_breach_refuses_on_the_ledger_rule_and_keeps_the_charge(
        self,
    ) -> None:
        ledger = DamageLedger()
        transport = _CountingTransport()
        adapter = AwsCloudAdapter(transport, rate_cards=())
        outcome = admit_cloud_action(
            adapter,
            _stop_action(),
            _role(),
            run_id="p5",
            owner_agent="p5",
            duration_s=2_600_000.0,
            ceiling=0.0,
            quota=DamageQuota(),
            ledger=ledger,
        )
        assert outcome.refused
        assert outcome.stage is CloudGateStage.DAMAGE_QUOTA
        assert outcome.rule_id.startswith("damage_quota.")
        assert transport.mutations == 0
        identity = _stop_action().target.identity
        assert ledger.damage_for(identity.canonical_id) > 0.0

    def test_fully_granted_priced_action_admits(self) -> None:
        outcome, transport = self._admit(rate_cards=(_card(),), ceiling=10.0)
        assert outcome.admitted
        assert outcome.stage is CloudGateStage.NONE
        assert outcome.blast is not None
        assert outcome.weight_source == "unresolved_conservative"
        assert transport.mutations == 0


# =============================================================================
# 3. Cost estimates — honest zeros, priced math, hard boundaries
# =============================================================================


class TestCostEstimates:
    def test_unpriced_without_ceiling_is_an_honest_zero(self) -> None:
        adapter = AwsCloudAdapter(_CountingTransport(), rate_cards=())
        preview = adapter.estimate_cost(_stop_action(), ceiling=0.0)
        assert preview.ok
        assert preview.priced is False
        assert preview.estimate is not None
        assert preview.estimate.expected_low == 0.0
        assert preview.estimate.expected_high == 0.0
        assert "UNPRICED" in preview.estimate.basis
        assert "not that the action is free" in preview.estimate.basis
        assert preview.counts.api_calls == 4  # mutate+verify, compensate+verify

    def test_priced_math_comes_from_the_operator_card(self) -> None:
        card = _card(micros_per_api_call=2.0, high_factor=2.0, source="p5: card-a")
        adapter = AwsCloudAdapter(_CountingTransport(), rate_cards=(card,))
        preview = adapter.estimate_cost(_stop_action(), ceiling=16.0)
        assert preview.ok
        assert preview.priced is True
        assert preview.price_source == "p5: card-a"
        assert preview.estimate is not None
        assert preview.estimate.expected_low == 8.0  # 4 calls x 2 micros
        assert preview.estimate.expected_high == 16.0
        assert preview.ceiling_decision is not None
        assert preview.ceiling_decision.allowed

    def test_card_for_another_region_does_not_apply(self) -> None:
        card = _card(region="eu-west-1")
        adapter = AwsCloudAdapter(_CountingTransport(), rate_cards=(card,))
        preview = adapter.estimate_cost(_stop_action(), ceiling=1_000_000.0)
        assert preview.denied
        assert preview.code == CLOUD_COST_UNPRICED

    def test_reversible_projects_four_calls_irreversible_two(self) -> None:
        adapter = AwsCloudAdapter(_CountingTransport(), rate_cards=())
        stop = _stop_action()
        stop_cap = adapter.capability_for(stop)
        assert stop_cap is not None
        assert adapter.operation_counts(stop, stop_cap).api_calls == 4
        destroying = _irreversible_action(
            CloudProvider.AWS,
            CloudActionKind.IMPAIR,
            CloudResourceClass.BLOCK_STORAGE,
        )
        destroying_cap = adapter.capability_for(destroying)
        assert destroying_cap is not None
        assert adapter.operation_counts(destroying, destroying_cap).api_calls == 2

    def test_spend_exactly_at_ceiling_is_inside(self) -> None:
        estimate = CostEstimate(
            scope=ResourceScope.EXPERIMENT,
            scope_key="p5",
            expected_low=4.0,
            expected_high=4.0,
            ceiling=4.0,
            basis="p5 boundary",
        )
        assert estimate.headroom == 0.0
        assert check_cost_ceiling(estimate, 4.0).allowed
        assert not check_cost_ceiling(estimate, 4.001).allowed

    def test_invalid_spend_is_refused_not_judged(self) -> None:
        estimate = CostEstimate(
            scope=ResourceScope.EXPERIMENT,
            scope_key="p5",
            expected_low=0.0,
            expected_high=0.0,
            ceiling=0.0,
            basis="p5 unpriced",
        )
        for bad in (float("nan"), float("inf"), -1.0):
            with pytest.raises(InvariantViolationError):
                check_cost_ceiling(estimate, bad)


assert CloudTransport is not None  # the port is the seam every fake implements
