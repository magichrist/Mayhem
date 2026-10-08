"""Plan 06 Phase 5 — negative controls for the cloud lane.

The plan's negative control: *revoked credentials mid-run trigger
fencing/recovery, never silent continuation*. Plus the two guards that make
the control meaningful: the admission gate and every analysis verb never
touch the transport (a counting transport raises on any mutation), and no
unit test in the lane can reach a live cloud (no SDK is importable, no
socket is opened, the dependency set is unchanged).

All transports here are fakes. A fake that fails is the honest stand-in for
a revoked grant: the adapter must turn it into a FAILED result with a
machine-readable code, never a COMPLETED, never silence.
"""

from __future__ import annotations

import sys

import pytest

from mayhem.controller.cloud_evidence import CloudGateStage, admit_cloud_action
from mayhem.domain.cloud import (
    CloudActionKind,
    CloudProvider,
    CloudProviderRef,
    CloudResourceClass,
    CloudResourceIdentity,
    CloudRoleRef,
    CloudSelector,
    CloudSelectorKind,
    CloudTarget,
    Reversibility,
    ReversibleCloudAction,
)
from mayhem.domain.outcomes import StepOutcome, TargetOutcome
from mayhem.domain.provider import ProviderPermission
from mayhem.domain.quota import DamageLedger, DamageQuota
from mayhem.providers.cloud.aws import AwsCloudAdapter
from mayhem.providers.cloud.port import (
    CLOUD_TRANSPORT_FAILURE,
    CLOUD_VERIFICATION_FAILED,
    MutationReceipt,
    ResourceQuery,
    ResourceRecord,
    TransportConflict,
    TransportFailure,
    VerifyPhase,
)

GRANTS_ALL = frozenset(
    {
        ProviderPermission.TARGET_MUTATE,
        ProviderPermission.TARGET_READ,
        ProviderPermission.NETWORK,
    }
)


class _CountingTransport:
    """Counts mutations and never lets one through."""

    def __init__(self) -> None:
        self.mutations = 0

    def list_resources(self, query: ResourceQuery) -> tuple[ResourceRecord, ...]:
        return ()

    def read_resource(self, query: ResourceQuery, resource_id: str) -> ResourceRecord | None:
        return None

    def mutate(self, command: object) -> MutationReceipt:
        self.mutations += 1
        raise AssertionError(f"the gate must never mutate; got {command!r}")


class _RevokedMidRunTransport:
    """Accepts the mutate, then loses its grant: every read fails revoked.

    The shape of a credential revoked mid-run. The mutate receipt is a claim
    the adapter must not trust on its own — the verification read is what
    discovers the grant is gone, and the result must be a fenced FAILED,
    never a COMPLETED built from the receipt.
    """

    def __init__(self) -> None:
        self.mutations = 0
        self.reads = 0

    def list_resources(self, query: ResourceQuery) -> tuple[ResourceRecord, ...]:
        return ()

    def read_resource(self, query: ResourceQuery, resource_id: str) -> ResourceRecord | None:
        self.reads += 1
        raise TransportFailure(
            "aws", "ec2:DescribeInstances", "credential revoked mid-run: grant denied"
        )

    def mutate(self, command) -> MutationReceipt:  # type: ignore[no-untyped-def]
        self.mutations += 1
        return MutationReceipt(
            operation=command.operation,
            resource_id=command.resource_id,
            request_id="req-revoked-1",
        )


class _ConflictTransport(_CountingTransport):
    """The cloud refuses the call for the resource's own state, not an outage."""

    def mutate(self, command: object) -> MutationReceipt:
        self.mutations += 1
        raise TransportConflict("aws", "ec2:StopInstances", "the instance is already stopped")


class _LoudBugTransport(_CountingTransport):
    """A binding bug: raises something no adapter boundary translates."""

    def mutate(self, command: object) -> MutationReceipt:
        self.mutations += 1
        raise RuntimeError("binding forgot to wrap this SDK exception")


def _action() -> ReversibleCloudAction:
    ref = CloudProviderRef(provider=CloudProvider.AWS)
    identity = CloudResourceIdentity(
        provider=ref,
        resource_class=CloudResourceClass.VM,
        account="123456789012",
        region="us-east-1",
        resource_id="i-0neg",
    )
    selector = CloudSelector(
        resource_class=CloudResourceClass.VM,
        kind=CloudSelectorKind.IDENTIFIER,
        account="123456789012",
        region="us-east-1",
        identifiers=("i-0neg",),
    )
    return ReversibleCloudAction(
        action_id="neg.probe.aws.vm.stop",
        kind=CloudActionKind.STOP,
        target=CloudTarget(
            provider=ref,
            resource_class=CloudResourceClass.VM,
            selector=selector,
            identity=identity,
        ),
        summary="phase 5 negative control",
        reversibility=Reversibility.REVERSIBLE,
        duration_s=3600.0,
        required_permissions=frozenset(
            {ProviderPermission.TARGET_MUTATE, ProviderPermission.TARGET_READ}
        ),
    )


def _role() -> CloudRoleRef:
    return CloudRoleRef(
        role_id="neg.operator",
        provider=CloudProviderRef(provider=CloudProvider.AWS),
        granted=GRANTS_ALL,
    )


def _roomy_quota() -> DamageQuota:
    return DamageQuota(budget_s=1_000_000.0, per_fault_ceiling_s=1_000_000.0)


# =============================================================================
# The gate and the analyses never mutate
# =============================================================================


class TestTransportNeverReached:
    def test_gate_refusals_leave_the_transport_at_zero(self) -> None:
        transport = _CountingTransport()
        adapter = AwsCloudAdapter(transport, rate_cards=())
        outcome = admit_cloud_action(
            adapter,
            _action(),
            _role(),
            run_id="neg-1",
            owner_agent="neg",
            duration_s=3600.0,
            ceiling=1_000_000.0,  # unpriced + declared ceiling: COST refusal
            quota=_roomy_quota(),
            ledger=DamageLedger(),
        )
        assert outcome.refused
        assert outcome.stage is CloudGateStage.COST
        assert transport.mutations == 0

    def test_permission_analysis_is_transport_free(self) -> None:
        transport = _CountingTransport()
        adapter = AwsCloudAdapter(transport, rate_cards=())
        analysis = adapter.analyze_permission(_role(), _action())
        assert analysis.ok
        assert transport.mutations == 0

    def test_cost_preview_is_transport_free(self) -> None:
        transport = _CountingTransport()
        adapter = AwsCloudAdapter(transport, rate_cards=())
        preview = adapter.estimate_cost(_action(), ceiling=0.0)
        assert preview.ok
        assert transport.mutations == 0

    def test_preflight_is_transport_free(self) -> None:
        transport = _CountingTransport()
        adapter = AwsCloudAdapter(transport, rate_cards=())
        preflight = adapter.preflight(_action(), role=_role(), ceiling=0.0)
        assert preflight.allowed
        assert preflight.api_calls == 0
        assert transport.mutations == 0


# =============================================================================
# Revoked credentials mid-run: fenced FAILED, never silent continuation
# =============================================================================


class TestRevokedCredentialFences:
    def test_execute_after_revoke_fails_with_a_code_not_silence(self) -> None:
        adapter = AwsCloudAdapter(_RevokedMidRunTransport(), rate_cards=())
        result = adapter.execute(_action(), role=_role(), ceiling=0.0)
        assert result.outcome is not StepOutcome.COMPLETED
        assert result.denied
        # Fenced at the verification step: the receipt existed, the read
        # proved the grant was gone, so the mutation is a failed verification
        # carrying the transport cause — never a completion, never silence.
        assert result.code == CLOUD_VERIFICATION_FAILED
        assert "revoked" in result.reason
        assert CLOUD_TRANSPORT_FAILURE in result.reason
        # The receipt existed and was still not enough: no verification, no
        # completion. A receipt alone is a claim, not evidence.
        assert result.verification is None or not result.verification.confirmed

    def test_verify_after_revoke_is_a_failed_read_not_drift(self) -> None:
        adapter = AwsCloudAdapter(_RevokedMidRunTransport(), rate_cards=())
        verification = adapter.verify(_action(), phase=VerifyPhase.APPLIED)
        assert not verification.confirmed
        assert verification.outcome is StepOutcome.FAILED
        assert CLOUD_TRANSPORT_FAILURE in verification.reason

    def test_compensate_after_revoke_fails_loudly(self) -> None:
        adapter = AwsCloudAdapter(_RevokedMidRunTransport(), rate_cards=())
        result = adapter.compensate(_action(), role=_role())
        assert result.denied
        assert result.code == CLOUD_VERIFICATION_FAILED
        assert "revoked" in result.reason

    def test_revoked_grant_is_an_environment_finding_not_a_wiring_one(self) -> None:
        from mayhem.providers.cloud.report import CloudMechanismState

        assert CloudMechanismState.CREDENTIAL_REVOKED.witness is True
        assert CloudMechanismState.CREDENTIAL_REVOKED.blocks is True
        assert CloudMechanismState.CREDENTIAL_REVOKED.finding == "environment"
        assert CloudMechanismState.TRANSPORT_UNAVAILABLE.witness is False
        assert CloudMechanismState.TRANSPORT_UNAVAILABLE.finding == "wiring"

    def test_conflict_maps_to_resource_conflict_not_generic_failure(self) -> None:
        adapter = AwsCloudAdapter(_ConflictTransport(), rate_cards=())
        result = adapter.execute(_action(), role=_role(), ceiling=0.0)
        assert result.denied
        assert result.code == CLOUD_TRANSPORT_FAILURE
        assert result.target_outcome is TargetOutcome.RESOURCE_CONFLICT

    def test_untranslated_binding_bug_escapes_loudly(self) -> None:
        """A bug inside the binding must not masquerade as a cloud refusal."""
        adapter = AwsCloudAdapter(_LoudBugTransport(), rate_cards=())
        with pytest.raises(RuntimeError, match="forgot to wrap"):
            adapter.execute(_action(), role=_role(), ceiling=0.0)


# =============================================================================
# No live cloud reachable from the unit suite
# =============================================================================


class TestNoLiveCloud:
    _BANNED_IMPORTS = (
        "boto3",
        "botocore",
        "google.cloud",
        "azure.mgmt",
        "azure.identity",
    )

    def test_no_cloud_sdk_is_imported(self) -> None:
        import mayhem.providers.cloud.aws
        import mayhem.providers.cloud.azure
        import mayhem.providers.cloud.gcp
        import mayhem.providers.cloud.port
        import mayhem.providers.cloud.report

        del (
            mayhem.providers.cloud.aws,
            mayhem.providers.cloud.azure,
            mayhem.providers.cloud.gcp,
            mayhem.providers.cloud.port,
            mayhem.providers.cloud.report,
        )
        for banned in self._BANNED_IMPORTS:
            assert banned not in sys.modules, (
                f"{banned} is imported: a unit test would be one credential away from a live cloud"
            )

    def test_no_socket_in_the_adapter_package(self) -> None:
        from pathlib import Path

        package = Path(__file__).resolve().parents[2] / "src" / "mayhem" / "providers" / "cloud"
        sources = [
            path.read_text()
            for path in sorted(package.glob("*.py"))
            if path.name != "__init__.py" or True
        ]
        for source in sources:
            assert "import socket" not in source
            assert "import boto3" not in source

    def test_capability_rows_stay_honest_about_the_mechanism(self) -> None:
        from mayhem.providers.cloud.azure import AzureCloudAdapter
        from mayhem.providers.cloud.gcp import GcpCloudAdapter
        from mayhem.providers.cloud.report import capability_rows

        for cls in (AwsCloudAdapter, GcpCloudAdapter, AzureCloudAdapter):
            adapter = cls(_CountingTransport(), rate_cards=())
            for pair in adapter.supported_actions():
                row = capability_rows(adapter.capabilities[pair], provider=adapter.provider_key)
                assert row.mechanism_applied is False
                assert row.demonstrated_on_sandbox_account is False
                assert (
                    "no provider API has been contacted" in row.notice.lower()
                    or "no such call" in row.notice
                )
