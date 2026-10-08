"""The GCP adapter (v1.1.0 plan 06, Phase 2).

A Compute Engine and Cloud SQL capability table behind
:class:`mayhem.providers.cloud.port.CloudTransport`. **No ``google-cloud-*``
package is imported, declared or installed**: the adapter's entire
provider-specific content is the table below plus the transport port it is
handed, and the port is the seam a later phase binds the Google SDKs to.

What is real here: the operation names, the service names, the project/region
boundary, the Compute Engine ``status`` field, the Cloud SQL
``settings.failoverReplica`` block, and the billing consequence of each action.
What is *declared* rather than measured: ``billable_instance_hours``. What is
not done at all: the plan's Phase 2 acceptance of demonstrating every action's
compensate\u2192verify against a sandbox project — the STATUS ledger says so.

This adapter is deliberately **not** a transliteration of
:mod:`mayhem.providers.cloud.aws`. GCP's shapes differ where the clouds differ:

* a stopped Compute Engine instance reports ``TERMINATED``, not ``stopped``, and
  bills no compute — so ``stop`` here is non-billable where Azure's equivalent is
  not;
* a Cloud SQL failover is not observable as a boolean, so its post-condition is
  the *appearance* of ``settings.failoverReplica.name`` and its compensation
  asserts that block is *gone* again. That is why :class:`ExpectedState` has
  ``present`` and ``absent`` shapes alongside ``equal``; and
* the irreversible row here destroys a *persistent disk* rather than AWS's volume,
  because the operation a GCP adapter reaches for is
  ``compute.disks.delete``.

**Deliberately unsupported, with reasons:**

* ``reboot`` — self-reconciling rather than compensable; there is no
  compensating API call whose result ``compensate_verify`` could assert.
* ``impair`` on a VM — the natural candidate is resizing the machine type, but
  the expected post-condition would be a machine-type value the plan does not
  carry, and a verify that cannot state what it expects is not a verify.
* ``isolate`` — no identity-preserving compensation, for the same reason as AWS:
  a compensating operation that does not restore the same resource identity
  cannot satisfy ``compensate_verify`` against the resolved target.
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
    "GCP_CAPABILITIES",
    "GCP_PROVIDER",
    "GCP_SERVICES",
    "GcpCloudAdapter",
]


GCP_PROVIDER: Final[CloudProviderRef] = CloudProviderRef(provider=CloudProvider.GCP)
"""The provider reference every GCP identity and role carries."""

GCP_SERVICES: Final[dict[CloudResourceClass, str]] = {
    CloudResourceClass.VM: "compute",
    CloudResourceClass.BLOCK_STORAGE: "compute",
    CloudResourceClass.MANAGED_DATABASE: "sqladmin",
}
"""Resource class -> GCP service. ``compute`` for VMs and persistent disks
because Compute Engine really does own both; ``sqladmin`` for Cloud SQL, whose
API is a different service with its own methods."""

GCP_CAPABILITIES: Final[dict[tuple[CloudActionKind, CloudResourceClass], CloudCapability]] = {
    (CloudActionKind.STOP, CloudResourceClass.VM): ReversibleCapability(
        kind=CloudActionKind.STOP,
        resource_class=CloudResourceClass.VM,
        service="compute",
        execute_operation="compute.instances.stop",
        compensate_operation="compute.instances.start",
        summary=(
            "stop a Compute Engine instance; a TERMINATED instance bills no vCPU, so "
            "this action's own cost is its API calls"
        ),
        billable_instance_hours=False,
        apply_verify=ExpectedState(equal={"status": "TERMINATED"}),
        compensate_verify=ExpectedState(equal={"status": "RUNNING"}),
    ),
    (CloudActionKind.FAILOVER, CloudResourceClass.MANAGED_DATABASE): ReversibleCapability(
        kind=CloudActionKind.FAILOVER,
        resource_class=CloudResourceClass.MANAGED_DATABASE,
        service="sqladmin",
        execute_operation="sqladmin.instances.failover",
        compensate_operation="sqladmin.instances.failover",
        summary="promote a Cloud SQL standby; failing back is the same call",
        billable_instance_hours=True,
        # Not a boolean in GCP's API: after a failover the instance carries a
        # failoverReplica block, and after failing back that block is gone. So the
        # post-condition asserts presence/absence rather than a value.
        apply_verify=ExpectedState(present=("settings.failoverReplica.name",)),
        compensate_verify=ExpectedState(absent=("settings.failoverReplica.name",)),
    ),
    (CloudActionKind.IMPAIR, CloudResourceClass.BLOCK_STORAGE): IrreversibleCapability(
        kind=CloudActionKind.IMPAIR,
        resource_class=CloudResourceClass.BLOCK_STORAGE,
        service="compute",
        execute_operation="compute.disks.delete",
        summary="impair a workload by deleting its Compute Engine persistent disk",
        rationale=(
            "a deleted Compute Engine disk cannot be restored: the API has no "
            "undelete, and only a snapshot or an image taken beforehand still holds "
            "the data. Whether one exists is not something this adapter can check."
        ),
    ),
}
"""Every action this adapter declares, keyed by ``(kind, resource_class)``.

Two reversible rows and one irreversible row; the irreversible row has no
``compensate_operation`` field to fill in at all.
"""


class GcpCloudAdapter(CloudAdapter):
    """GCP behind the shared adapter contract.

    No behaviour beyond the two tables — the lifecycle, the cost estimator, the
    permission analyzer and every refusal are inherited from
    :class:`~mayhem.providers.cloud.port.CloudAdapter`.
    """

    provider_key: ClassVar[str] = GCP_PROVIDER.key
    services: ClassVar[Mapping[CloudResourceClass, str]] = GCP_SERVICES
    capabilities: ClassVar[Mapping[tuple[CloudActionKind, CloudResourceClass], CloudCapability]] = (
        GCP_CAPABILITIES
    )
