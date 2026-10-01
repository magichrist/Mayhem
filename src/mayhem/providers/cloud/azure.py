"""The Azure adapter (v1.1.0 plan 06, Phase 2).

An Azure Resource Manager capability table behind
:class:`mayhem.providers.cloud.port.CloudTransport`. **No ``azure-mgmt-*``
package is imported, declared or installed**: the adapter's entire
provider-specific content is the table below plus the transport port it is
handed, and the port is the seam a later phase binds the Azure SDK to.

What is real here: the operation names, the service names, the
subscription/region boundary, the VM ``powerState`` field, the SQL database
``replicationRole`` field, and the billing consequence of each action. What is
*declared* rather than measured: ``billable_instance_hours``. What is not done
at all: the plan's Phase 2 acceptance of demonstrating every action's
compensate\u2192verify against a sandbox subscription — the STATUS ledger says so.

The load-bearing Azure difference, and the reason this table is not a copy of
AWS's: **an Azure VM that is merely powered off is still allocated and still
bills compute.** Deallocating it would stop the bill, but ``deallocate`` is a
different, longer operation with different semantics, so the capability declares
``virtualMachines/powerOff`` — which is what an operator asking to "stop this
VM" means — and declares honestly that it keeps billing. That single flag is
what makes the cost estimator refuse an Azure stop with no ``duration_s``
(:data:`CLOUD_DURATION_REQUIRED`) while an AWS or GCP stop estimates happily at
zero instance-hours.

Azure's operation names are ARM resource-provider paths
(``virtualMachines/powerOff``, ``web/delete``) rather than colon-separated
service/action pairs, and they are carried verbatim so an evidence record names
the same operation the Azure activity log will.

**Deliberately unsupported, with reasons:**

* ``reboot`` — self-reconciling rather than compensable; there is no
  compensating API call whose result ``compensate_verify`` could assert.
* ``isolate`` on a network or load balancer — no identity-preserving
  compensation, for the same reason as AWS: a compensating operation that does
  not restore the same resource identity cannot satisfy ``compensate_verify``
  against the resolved target.
* ``impair`` on a VM — the natural candidate is detaching its NIC, which leaves
  the NIC as a separate resource and changes the instance's resource id, so the
  post-condition could not be asserted against the resolved target.
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
    "AZURE_CAPABILITIES",
    "AZURE_PROVIDER",
    "AZURE_SERVICES",
    "AzureCloudAdapter",
]


AZURE_PROVIDER: Final[CloudProviderRef] = CloudProviderRef(provider=CloudProvider.AZURE)
"""The provider reference every Azure identity and role carries."""

AZURE_SERVICES: Final[dict[CloudResourceClass, str]] = {
    CloudResourceClass.VM: "compute",
    CloudResourceClass.MANAGED_DATABASE: "sql",
    CloudResourceClass.FUNCTION: "web",
}
"""Resource class -> Azure ARM resource provider. ``compute`` for VMs, ``sql``
for Azure SQL databases, ``web`` for App Service / Function Apps."""

AZURE_CAPABILITIES: Final[
    dict[tuple[CloudActionKind, CloudResourceClass], CloudCapability]
] = {
    (CloudActionKind.STOP, CloudResourceClass.VM): ReversibleCapability(
        kind=CloudActionKind.STOP,
        resource_class=CloudResourceClass.VM,
        service="compute",
        execute_operation="virtualMachines/powerOff",
        compensate_operation="virtualMachines/start",
        summary=(
            "power off an Azure VM; powerOff leaves the VM allocated, so compute keeps "
            "billing until it is deallocated"
        ),
        # True, unlike the equivalent AWS and GCP rows. A powered-off-but-allocated
        # Azure VM still incurs compute charges, so instance-hours are a real number
        # here and the estimator refuses to guess them without a duration.
        billable_instance_hours=True,
        apply_verify=ExpectedState(equal={"powerState": "stopped"}),
        compensate_verify=ExpectedState(equal={"powerState": "running"}),
    ),
    (CloudActionKind.FAILOVER, CloudResourceClass.MANAGED_DATABASE): ReversibleCapability(
        kind=CloudActionKind.FAILOVER,
        resource_class=CloudResourceClass.MANAGED_DATABASE,
        service="sql",
        execute_operation="servers/databases/failover",
        compensate_operation="servers/databases/failover",
        summary="fail an Azure SQL database over to its geo-replica; failing back is the same call",
        billable_instance_hours=True,
        # Azure reports the flip as a role change on the same database resource, so
        # unlike GCP's failoverReplica block this one is an enumerable value.
        apply_verify=ExpectedState(equal={"replicationRole": "Secondary"}),
        compensate_verify=ExpectedState(equal={"replicationRole": "Primary"}),
    ),
    (CloudActionKind.ISOLATE, CloudResourceClass.FUNCTION): IrreversibleCapability(
        kind=CloudActionKind.ISOLATE,
        resource_class=CloudResourceClass.FUNCTION,
        service="web",
        execute_operation="web/delete",
        summary="isolate a workload by deleting its Function App",
        rationale=(
            "deleting the Function App removes its deployment, configuration and state "
            "with it; Azure offers no restore of a deleted site, only a redeployment "
            "from source that a caller may not be able to reproduce."
        ),
    ),
}
"""Every action this adapter declares, keyed by ``(kind, resource_class)``.

Two reversible rows and one irreversible row. Note that the irreversible row
here is ``isolate``/function, where AWS and GCP declare
``impair``/block-storage: the same structural shape, three different provider
answers — which is the point of holding one contract across three tables.
"""


class AzureCloudAdapter(CloudAdapter):
    """Azure behind the shared adapter contract.

    No behaviour beyond the two tables — the lifecycle, the cost estimator, the
    permission analyzer and every refusal are inherited from
    :class:`~mayhem.providers.cloud.port.CloudAdapter`.
    """

    provider_key: ClassVar[str] = AZURE_PROVIDER.key
    services: ClassVar[Mapping[CloudResourceClass, str]] = AZURE_SERVICES
    capabilities: ClassVar[
        Mapping[tuple[CloudActionKind, CloudResourceClass], CloudCapability]
    ] = AZURE_CAPABILITIES
