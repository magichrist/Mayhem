"""Cloud adapters behind the provider contract (v1.1.0 plan 06, Phase 2).

The AWS, GCP and Azure adapters, plus the
:class:`~mayhem.providers.cloud.port.CloudTransport` port they all run on.

**No cloud SDK ships here.** Mayhem's declared dependencies are pydantic,
typer, click, pyyaml, structlog and kubernetes, and this package adds none:
there is no boto3, no google-cloud, no azure-mgmt. Every adapter is a
provider-native *capability table* plus an injectable transport, and the port is
the seam a later phase binds an SDK to. Nothing in this package opens a socket.

Re-exports are the seam's vocabulary plus the three adapters; the capability
tables are re-exported too so a report or a CLI can build a capability matrix
without reaching into a provider module.
"""

from __future__ import annotations

from mayhem.providers.cloud.aws import (
    AWS_CAPABILITIES,
    AWS_PROVIDER,
    AWS_SERVICES,
    AwsCloudAdapter,
)
from mayhem.providers.cloud.azure import (
    AZURE_CAPABILITIES,
    AZURE_PROVIDER,
    AZURE_SERVICES,
    AzureCloudAdapter,
)
from mayhem.providers.cloud.gcp import (
    GCP_CAPABILITIES,
    GCP_PROVIDER,
    GCP_SERVICES,
    GcpCloudAdapter,
)
from mayhem.providers.cloud.port import (
    ActionCapability,
    CloudAdapter,
    CloudAdapterError,
    CloudCapability,
    CloudOperationCounts,
    CloudPermissionAnalysis,
    CloudRateCard,
    CloudStep,
    CloudStepResult,
    CloudTransport,
    CompensationResult,
    DiscoveryRequest,
    DiscoveryResult,
    ExecutionResult,
    ExpectedState,
    IrreversibleCapability,
    MutationCommand,
    MutationReceipt,
    PreflightResult,
    ResolutionResult,
    ResourceQuery,
    ResourceRecord,
    ReversibleCapability,
    TransportConflict,
    TransportFailure,
    VerificationOutcome,
    VerifyPhase,
)

__all__ = [
    "AWS_CAPABILITIES",
    "AWS_PROVIDER",
    "AWS_SERVICES",
    "AZURE_CAPABILITIES",
    "AZURE_PROVIDER",
    "AZURE_SERVICES",
    "GCP_CAPABILITIES",
    "GCP_PROVIDER",
    "GCP_SERVICES",
    "ActionCapability",
    "AwsCloudAdapter",
    "AzureCloudAdapter",
    "CloudAdapter",
    "CloudAdapterError",
    "CloudCapability",
    "CloudOperationCounts",
    "CloudPermissionAnalysis",
    "CloudRateCard",
    "CloudStep",
    "CloudStepResult",
    "CloudTransport",
    "CompensationResult",
    "DiscoveryRequest",
    "DiscoveryResult",
    "ExecutionResult",
    "ExpectedState",
    "GcpCloudAdapter",
    "IrreversibleCapability",
    "MutationCommand",
    "MutationReceipt",
    "PreflightResult",
    "ResolutionResult",
    "ResourceQuery",
    "ResourceRecord",
    "ReversibleCapability",
    "TransportConflict",
    "TransportFailure",
    "VerificationOutcome",
    "VerifyPhase",
]
