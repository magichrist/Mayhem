"""The AWS adapter (v1.1.0 plan 06, Phase 2).

An EC2- and RDS-shaped capability table behind
:class:`mayhem.providers.cloud.port.CloudTransport`. **No boto3 is imported,
declared or installed**: the adapter's entire provider-specific content is the
table below plus the transport port it is handed, and the port is the seam a
later phase binds an SDK to.

What is real here: the operation names, the service names, the account/region
boundary, the EC2 instance state field (``State.Name``), the RDS multi-AZ field,
and the billing consequence of each action. What is *declared* rather than
measured: ``billable_instance_hours``, which says the instance keeps computing
during the action. What is not done at all: the plan's Phase 2 acceptance of
demonstrating every action's compensate\u2192verify against a sandbox account, which
needs credentials Mayhem does not have — the STATUS ledger says so rather than a
capability docstring pretending otherwise.

**Deliberately unsupported, with reasons**, because an adapter that cannot
implement a kind reports it unsupported rather than substituting a near-miss:

* ``reboot`` — self-reconciling rather than compensable. The instance returns to
  ``running`` on its own, so there is no compensating API call to send and
  nothing for ``compensate_verify`` to assert. Modelling "wait for it to come
  back" as a rollback would be a compensation Mayhem cannot verify.
* ``isolate`` — no identity-preserving compensation. Removing a peering
  connection or a security group and restoring it does not restore the *same*
  resource identity, so the compensating operation could never satisfy
  ``compensate_verify``, which is asserted against the resolved target.
* ``impair`` on a network, load balancer, object storage bucket, queue, function
  or managed Kubernetes cluster — not implemented in this phase.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Final

from mayhem.domain.cloud import (
    CloudActionKind,
    CloudProvider,
    CloudProviderRef,
    CloudResourceClass,
)
from mayhem.providers.cloud.port import (
    CloudAdapter,
    CloudCapability,
    ExpectedState,
    IrreversibleCapability,
    ReversibleCapability,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__ = [
    "AWS_CAPABILITIES",
    "AWS_PROVIDER",
    "AWS_SERVICES",
    "AwsCloudAdapter",
]


AWS_PROVIDER: Final[CloudProviderRef] = CloudProviderRef(provider=CloudProvider.AWS)
"""The provider reference every AWS identity and role carries."""

AWS_SERVICES: Final[dict[CloudResourceClass, str]] = {
    CloudResourceClass.VM: "ec2",
    CloudResourceClass.BLOCK_STORAGE: "ec2",
    CloudResourceClass.NETWORK: "ec2",
    CloudResourceClass.MANAGED_DATABASE: "rds",
}
"""Resource class -> AWS service.

``ec2`` for VMs, volumes and networks because they really are one service with
three resource types; ``rds`` for managed databases. A class absent from this
table cannot be discovered, because Mayhem does not know which collection to
enumerate and would otherwise be guessing at the API.
"""

AWS_CAPABILITIES: Final[dict[tuple[CloudActionKind, CloudResourceClass], CloudCapability]] = {
    (CloudActionKind.STOP, CloudResourceClass.VM): ReversibleCapability(
        kind=CloudActionKind.STOP,
        resource_class=CloudResourceClass.VM,
        service="ec2",
        execute_operation="ec2:StopInstances",
        compensate_operation="ec2:StartInstances",
        summary="stop a running EC2 instance; a stopped instance bills no compute",
        billable_instance_hours=False,
        apply_verify=ExpectedState(equal={"State.Name": "stopped"}),
        compensate_verify=ExpectedState(equal={"State.Name": "running"}),
    ),
    (CloudActionKind.IMPAIR, CloudResourceClass.VM): ReversibleCapability(
        kind=CloudActionKind.IMPAIR,
        resource_class=CloudResourceClass.VM,
        service="ec2",
        execute_operation="ec2:ModifyInstanceAttribute",
        compensate_operation="ec2:ModifyInstanceAttribute",
        summary=(
            "disable source/destination checking on the instance, which breaks the "
            "return path of asymmetric routing while the instance keeps running"
        ),
        # The instance is still running for the duration, so it is still billing.
        # This is the flag that makes instance-hours a real number here and 0.0 for
        # the stop above, and the reason the cost estimator cannot compute one
        # without a stated duration.
        billable_instance_hours=True,
        apply_verify=ExpectedState(equal={"SourceDestCheck": "false"}),
        compensate_verify=ExpectedState(equal={"SourceDestCheck": "true"}),
    ),
    (CloudActionKind.FAILOVER, CloudResourceClass.MANAGED_DATABASE): ReversibleCapability(
        kind=CloudActionKind.FAILOVER,
        resource_class=CloudResourceClass.MANAGED_DATABASE,
        service="rds",
        execute_operation="rds:FailoverDBInstance",
        compensate_operation="rds:FailoverDBInstance",
        summary="fail an RDS instance over to its standby; failing back is the same call",
        billable_instance_hours=True,
        apply_verify=ExpectedState(equal={"IsMultiAZ": "false"}),
        compensate_verify=ExpectedState(equal={"IsMultiAZ": "true"}),
    ),
    (CloudActionKind.IMPAIR, CloudResourceClass.BLOCK_STORAGE): IrreversibleCapability(
        kind=CloudActionKind.IMPAIR,
        resource_class=CloudResourceClass.BLOCK_STORAGE,
        service="ec2",
        execute_operation="ec2:DeleteVolume",
        summary="impair a workload by deleting its EBS volume",
        rationale=(
            "EBS is destructive-delete only: a deleted volume's contents are gone and "
            "the API offers no restore. Only a snapshot taken beforehand recovers the "
            "data, and whether one exists is not something an adapter can check."
        ),
    ),
}
"""Every action this adapter declares, keyed by ``(kind, resource_class)``.

Three reversible rows and one irreversible row. The irreversible row has no
``compensate_operation`` field to fill in at all — see
:class:`~mayhem.providers.cloud.port.IrreversibleCapability`.
"""


class AwsCloudAdapter(CloudAdapter):
    """AWS behind the shared adapter contract.

    No behaviour beyond the two tables: the lifecycle, the cost estimator, the
    permission analyzer and every refusal are inherited from
    :class:`~mayhem.providers.cloud.port.CloudAdapter`, which is what lets the
    conformance suite hold all three providers to one contract.
    """

    provider_key: ClassVar[str] = AWS_PROVIDER.key
    services: ClassVar[Mapping[CloudResourceClass, str]] = AWS_SERVICES
    capabilities: ClassVar[
        Mapping[tuple[CloudActionKind, CloudResourceClass], CloudCapability]
    ] = AWS_CAPABILITIES
