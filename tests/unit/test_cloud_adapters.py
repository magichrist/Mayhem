"""Conformance and negative-control tests for the cloud adapters (plan 06, Phase 2).

**No live cloud, no SDK, no credentials.** Mayhem's declared dependencies are
pydantic, typer, click, pyyaml, structlog and kubernetes, and this file must not
change that — one test reads ``pyproject.toml`` and asserts the dependency set is
still exactly those six, and another parses the adapter package's own ASTs and
asserts it imports no cloud SDK and opens no socket. The adapters talk to a
recording of a cloud API, never to a cloud.

**The recorded payloads below are provider-native**, in the shape each provider's
own API returns them: EC2's ``Reservations[].Instances[]`` with a nested
``State.Name``, GCP's ``items[]`` with a ``status``, Azure's ``value[]`` with
``properties.powerState`` and full ARM resource ids. Translating those payloads
into :class:`ResourceRecord` is the *binding's* job, and the binding does not
exist yet — so the translation lives here, in the test, and that is the honest
place for it. What the adapter receives is already the port's vocabulary, which
is exactly what a future boto3/google/azure binding would hand it. The
consequence a reviewer should hold in mind: **the provider-payload parsing is
untested against a real SDK, because there is no real SDK**, and the first thing
a binding phase must do is re-point these fixtures at recorded responses from a
real API rather than trust these hand-written ones.

``RecordedTransport`` is deliberately strict in two ways a real cloud is not: it
refuses to answer for an operation no fixture declares, and it counts every call.
The first means an adapter that invented an operation fails the test rather than
passing quietly; the second is what makes the ``api_calls`` on every result
checkable rather than asserted.
"""

from __future__ import annotations

import ast
import inspect
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from mayhem.domain.cloud import (
    CLOUD_AMBIGUOUS_RESOLUTION,
    CLOUD_PERMISSION_DENIED,
    CLOUD_ROLE_PROVIDER_MISMATCH,
    CLOUD_SELECTOR_WILDCARD,
    CLOUD_TARGET_UNRESOLVED,
    RULE_COST_CEILING_BELOW_HIGH,
    CloudActionKind,
    CloudProviderRef,
    CloudRefused,
    CloudResourceClass,
    CloudResourceIdentity,
    CloudRoleRef,
    CloudSelector,
    CloudSelectorKind,
    CloudTarget,
    CloudTargetIntent,
    IrreversibleCloudAction,
    ReversibleCloudAction,
)
from mayhem.domain.faults import Reversibility
from mayhem.domain.outcomes import StepOutcome, TargetOutcome
from mayhem.domain.provider import ProviderPermission
from mayhem.providers.cloud import (
    AWS_PROVIDER,
    AZURE_PROVIDER,
    GCP_PROVIDER,
    AwsCloudAdapter,
    AzureCloudAdapter,
    CloudAdapter,
    CloudAdapterError,
    CloudRateCard,
    CloudStep,
    CloudTransport,
    CompensationResult,
    DiscoveryRequest,
    ExecutionResult,
    ExpectedState,
    GcpCloudAdapter,
    IrreversibleCapability,
    MutationReceipt,
    ResourceQuery,
    ResourceRecord,
    ReversibleCapability,
    TransportConflict,
    TransportFailure,
    VerificationOutcome,
    VerifyPhase,
)
from mayhem.providers.cloud.port import (
    CLOUD_ACTION_UNSUPPORTED,
    CLOUD_COMPENSATION_UNAVAILABLE,
    CLOUD_COST_UNPRICED,
    CLOUD_DURATION_REQUIRED,
    CLOUD_IDENTITY_UNREPRESENTABLE,
    CLOUD_IRREVERSIBLE_APPROVAL_REQUIRED,
    CLOUD_RECEIPT_MISMATCH,
    CLOUD_RESOURCE_CONFLICT,
    CLOUD_TRANSPORT_FAILURE,
    CLOUD_UNKNOWN_RESOURCE_CLASS,
    CLOUD_VERIFICATION_FAILED,
    CLOUD_VERIFICATION_UNAVAILABLE,
    MutationCommand,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
CLOUD_PACKAGE = REPO_ROOT / "src" / "mayhem" / "providers" / "cloud"

MUTATE_ONLY = frozenset({ProviderPermission.TARGET_MUTATE})
FULL_ROLE = frozenset(
    {
        ProviderPermission.TARGET_READ,
        ProviderPermission.TARGET_MUTATE,
        ProviderPermission.NETWORK,
    }
)

VM = CloudResourceClass.VM
BLOCK_STORAGE = CloudResourceClass.BLOCK_STORAGE
MANAGED_DATABASE = CloudResourceClass.MANAGED_DATABASE
FUNCTION = CloudResourceClass.FUNCTION


# --- the recorded transport ----------------------------------------------------


@dataclass(frozen=True)
class RecordedResource:
    """One resource exactly as the provider's API described it."""

    resource_id: str
    tags: frozenset[str]
    fields: dict[str, str]


@dataclass(frozen=True)
class RecordedOperation:
    """One recorded provider answer, and the state it left behind.

    ``next_fields`` merges into the resource's state; a ``None`` value *removes*
    the key, because GCP's failover replica appears and then disappears and a
    recording that could not express removal could not express failing back.
    """

    request_id: str
    next_fields: dict[str, str | None] = field(default_factory=dict)


class RecordedTransport:
    """Replays recorded provider payloads through the three-call port.

    Implements :class:`CloudTransport` structurally, so it is the port's own
    conformance target rather than a mock of the adapter.
    """

    def __init__(
        self,
        provider: str,
        *,
        inventory: dict[tuple[str, CloudResourceClass], tuple[RecordedResource, ...]],
        operations: dict[str, tuple[RecordedOperation, ...]],
        failing: bool = False,
        conflicting: bool = False,
        mislabelled: str | None = None,
        disregard_effects: bool = False,
    ) -> None:
        self.provider = provider
        self.operations = operations
        self.failing = failing
        self.conflicting = conflicting
        self.mislabelled = mislabelled
        #: When true, ``mutate`` returns a receipt but leaves the resource's state
        #: alone — the cloud that accepts a call and does not do the thing. This is
        #: the case a receipt alone would report as success, and it is the reason a
        #: receipt is not evidence.
        self.disregard_effects = disregard_effects
        self.calls: list[str] = []
        # Copied, not aliased: a mutation in one test's recording must not leak
        # into the next test's, or "still running" would be a global accident.
        self._state: dict[tuple[str, CloudResourceClass], dict[str, RecordedResource]] = {
            key: {
                record.resource_id: RecordedResource(
                    resource_id=record.resource_id,
                    tags=record.tags,
                    fields=dict(record.fields),
                )
                for record in records
            }
            for key, records in inventory.items()
        }

    # -- CloudTransport --------------------------------------------------------

    def list_resources(self, query: ResourceQuery) -> tuple[ResourceRecord, ...]:
        self.calls.append(f"list_resources:{query.service}/{query.resource_class.value}")
        self._maybe_fail("list_resources")
        bucket = self._state.get((query.service, query.resource_class), {})
        return tuple(
            ResourceRecord(
                query=query,
                resource_id=record.resource_id,
                tags=record.tags,
                fields=dict(record.fields),
            )
            # Sorted, because a real API's order is not a guarantee and an
            # adapter that depended on it would be untestable.
            for _, record in sorted(bucket.items())
        )

    def read_resource(self, query: ResourceQuery, resource_id: str) -> ResourceRecord | None:
        self.calls.append(f"read_resource:{resource_id}")
        self._maybe_fail("read_resource")
        record = self._state.get((query.service, query.resource_class), {}).get(resource_id)
        if record is None:
            return None
        return ResourceRecord(
            query=query,
            resource_id=record.resource_id,
            tags=record.tags,
            fields=dict(record.fields),
        )

    def mutate(self, command: MutationCommand) -> MutationReceipt:
        self.calls.append(f"mutate:{command.operation}")
        self._maybe_fail(command.operation)
        recorded = self.operations.get(command.operation)
        if recorded is None:
            raise AssertionError(
                f"adapter asked for undocumented operation {command.operation!r}; the "
                "recorded fixture declares no such call"
            )
        index = self.calls.count(f"mutate:{command.operation}") - 1
        response = recorded[min(index, len(recorded) - 1)]
        key = (command.query.service, command.query.resource_class)
        record = self._state.get(key, {}).get(command.resource_id)
        if record is None:
            raise AssertionError(
                f"recorded fixture has no {command.resource_class.value} named "
                f"{command.resource_id!r} in {command.query.service!r}"
            )
        if self.disregard_effects:
            return MutationReceipt(
                operation=self.mislabelled or command.operation,
                resource_id=command.resource_id,
                request_id=response.request_id,
                fields=dict(record.fields),
            )
        for field_name, value in response.next_fields.items():
            if value is None:
                record.fields.pop(field_name, None)
            else:
                record.fields[field_name] = value
        return MutationReceipt(
            operation=self.mislabelled or command.operation,
            resource_id=command.resource_id,
            request_id=response.request_id,
            fields=dict(record.fields),
        )

    # -- fixture controls ------------------------------------------------------

    def _maybe_fail(self, operation: str) -> None:
        if self.failing:
            raise TransportFailure(self.provider, operation, "recorded failure")
        if self.conflicting:
            raise TransportConflict(self.provider, operation, "recorded conflict")

    def recorded_ids(self, service: str, resource_class: CloudResourceClass) -> tuple[str, ...]:
        """The ids this fixture holds for one collection — the ground truth."""
        return tuple(sorted(self._state.get((service, resource_class), {})))

    def retag(
        self,
        service: str,
        resource_class: CloudResourceClass,
        resource_id: str,
        tags: frozenset[str],
    ) -> None:
        """Replace a recorded resource's tags, to record something unrepresentable."""
        record = self._state[(service, resource_class)][resource_id]
        self._state[(service, resource_class)][resource_id] = RecordedResource(
            resource_id=record.resource_id, tags=tags, fields=dict(record.fields)
        )

    def drop(self, service: str, resource_class: CloudResourceClass, resource_id: str) -> None:
        """Forget a resource, so a read reports it gone (drift)."""
        self._state.get((service, resource_class), {}).pop(resource_id, None)

    def force_fields(
        self,
        service: str,
        resource_class: CloudResourceClass,
        resource_id: str,
        fields: dict[str, str],
    ) -> None:
        """Overwrite a resource's state, to make verification disagree."""
        record = self._state[(service, resource_class)][resource_id]
        record.fields.clear()
        record.fields.update(fields)


# --- the recorded API payloads -------------------------------------------------
#
# Provider-native shapes. `_bind_*` below is the binding a real SDK would replace.


def _aws_instances() -> tuple[RecordedResource, ...]:
    described: dict[str, object] = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-0mayhem01",
                        "State": {"Name": "running"},
                        "SourceDestCheck": True,
                        "Tags": [{"Key": "Name", "Value": "web"}],
                    },
                    {
                        "InstanceId": "i-0mayhem02",
                        "State": {"Name": "running"},
                        "SourceDestCheck": True,
                        "Tags": [{"Key": "Name", "Value": "web"}],
                    },
                    {
                        "InstanceId": "i-0mayhem03",
                        "State": {"Name": "running"},
                        "SourceDestCheck": True,
                        "Tags": [{"Key": "Name", "Value": "api"}],
                    },
                ]
            }
        ]
    }
    return tuple(_aws_instance(inst) for inst in described["Reservations"][0]["Instances"])


def _aws_instance(instance: dict[str, Any]) -> RecordedResource:
    fields = {"State.Name": instance["State"]["Name"]}
    if "SourceDestCheck" in instance:
        fields["SourceDestCheck"] = str(instance["SourceDestCheck"]).lower()
    return RecordedResource(
        resource_id=instance["InstanceId"],
        tags=frozenset(tag["Value"] for tag in instance.get("Tags", [])),
        fields=fields,
    )


AWS_RDS = (
    RecordedResource(
        resource_id="rds-mayhem01",
        tags=frozenset({"db"}),
        fields={"IsMultiAZ": "true"},
    ),
)
AWS_VOLUMES = (
    RecordedResource(
        resource_id="vol-mayhem01",
        tags=frozenset({"data"}),
        fields={"State": "in-use"},
    ),
)

AWS_INVENTORY: dict[tuple[str, CloudResourceClass], tuple[RecordedResource, ...]] = {
    ("ec2", VM): _aws_instances(),
    ("rds", MANAGED_DATABASE): AWS_RDS,
    ("ec2", BLOCK_STORAGE): AWS_VOLUMES,
}

AWS_OPERATIONS: dict[str, tuple[RecordedOperation, ...]] = {
    "ec2:StopInstances": (RecordedOperation("aws-req-stop", {"State.Name": "stopped"}),),
    "ec2:StartInstances": (RecordedOperation("aws-req-start", {"State.Name": "running"}),),
    "ec2:ModifyInstanceAttribute": (
        RecordedOperation("aws-req-impair", {"SourceDestCheck": "false"}),
        RecordedOperation("aws-req-restore", {"SourceDestCheck": "true"}),
    ),
    "rds:FailoverDBInstance": (
        RecordedOperation("aws-req-failover", {"IsMultiAZ": "false"}),
        RecordedOperation("aws-req-failback", {"IsMultiAZ": "true"}),
    ),
    "ec2:DeleteVolume": (RecordedOperation("aws-req-delete", {"State": "deleted"}),),
}


def _gcp_instances() -> tuple[RecordedResource, ...]:
    described: dict[str, object] = {
        "items": [
            {"name": "mayhem-vm-01", "status": "RUNNING", "labels": {"env": "prod"}},
            {"name": "mayhem-vm-02", "status": "RUNNING", "labels": {"env": "prod"}},
            {"name": "mayhem-vm-03", "status": "RUNNING", "labels": {"env": "staging"}},
        ]
    }
    return tuple(
        # Label keys and values are both exact tags: {"env": "staging"} becomes
        # {"env", "staging"} so either is nameable in a selector.
        RecordedResource(
            resource_id=item["name"],
            tags=frozenset(item["labels"]) | frozenset(item["labels"].values()),
            fields={"status": item["status"]},
        )
        for item in described["items"]
    )


def _gcp_sql() -> tuple[RecordedResource, ...]:
    described: dict[str, object] = {
        "items": [
            {"name": "mayhem-sql-01", "settings": {"tier": "db-n1-standard-1"}},
        ]
    }
    return tuple(
        RecordedResource(
            resource_id=item["name"],
            tags=frozenset({"sql"}),
            fields={"settings.tier": item["settings"]["tier"]},
        )
        for item in described["items"]
    )


GCP_DISKS = (
    RecordedResource(
        resource_id="mayhem-disk-01",
        tags=frozenset({"data"}),
        fields={"status": "READY"},
    ),
)

GCP_INVENTORY: dict[tuple[str, CloudResourceClass], tuple[RecordedResource, ...]] = {
    ("compute", VM): _gcp_instances(),
    ("sqladmin", MANAGED_DATABASE): _gcp_sql(),
    ("compute", BLOCK_STORAGE): GCP_DISKS,
}

GCP_OPERATIONS: dict[str, tuple[RecordedOperation, ...]] = {
    "compute.instances.stop": (RecordedOperation("gcp-req-stop", {"status": "TERMINATED"}),),
    "compute.instances.start": (RecordedOperation("gcp-req-start", {"status": "RUNNING"}),),
    "sqladmin.instances.failover": (
        # The failoverReplica block appears, then is gone again on the way back —
        # which is why ExpectedState has present/absent shapes.
        RecordedOperation(
            "gcp-req-failover", {"settings.failoverReplica.name": "mayhem-sql-01-replica"}
        ),
        RecordedOperation("gcp-req-failback", {"settings.failoverReplica.name": None}),
    ),
    "compute.disks.delete": (RecordedOperation("gcp-req-delete", {"status": "DELETING"}),),
}


def _azure_vms() -> tuple[RecordedResource, ...]:
    base = (
        "/subscriptions/sub-mayhem/resourceGroups/rg-mayhem/providers/"
        "Microsoft.Compute/virtualMachines"
    )
    described: dict[str, object] = {
        "value": [
            {
                "id": f"{base}/vm-mayhem-01",
                "properties": {"powerState": "running"},
                "tags": {"env": "prod"},
            },
            {
                "id": f"{base}/vm-mayhem-02",
                "properties": {"powerState": "running"},
                "tags": {"env": "staging"},
            },
        ]
    }
    return tuple(
        # Tag keys and values are both exact tags, as on GCP.
        RecordedResource(
            resource_id=item["id"],
            tags=frozenset(item["tags"]) | frozenset(item["tags"].values()),
            fields={"powerState": item["properties"]["powerState"]},
        )
        for item in described["value"]
    )


AZURE_SQL = (
    RecordedResource(
        resource_id=(
            "/subscriptions/sub-mayhem/resourceGroups/rg-mayhem/providers/"
            "Microsoft.Sql/servers/sql-mayhem/databases/db-mayhem-01"
        ),
        tags=frozenset({"sql"}),
        fields={"replicationRole": "Primary"},
    ),
)
AZURE_FUNCTIONS = (
    RecordedResource(
        resource_id=(
            "/subscriptions/sub-mayhem/resourceGroups/rg-mayhem/providers/"
            "Microsoft.Web/sites/func-mayhem-01"
        ),
        tags=frozenset({"web"}),
        fields={"state": "Running"},
    ),
)

AZURE_INVENTORY: dict[tuple[str, CloudResourceClass], tuple[RecordedResource, ...]] = {
    ("compute", VM): _azure_vms(),
    ("sql", MANAGED_DATABASE): AZURE_SQL,
    ("web", FUNCTION): AZURE_FUNCTIONS,
}

AZURE_OPERATIONS: dict[str, tuple[RecordedOperation, ...]] = {
    "virtualMachines/powerOff": (
        RecordedOperation("azure-req-poweroff", {"powerState": "stopped"}),
    ),
    "virtualMachines/start": (RecordedOperation("azure-req-start", {"powerState": "running"}),),
    "servers/databases/failover": (
        RecordedOperation("azure-req-failover", {"replicationRole": "Secondary"}),
        RecordedOperation("azure-req-failback", {"replicationRole": "Primary"}),
    ),
    "web/delete": (RecordedOperation("azure-req-delete", {"state": "Deleted"}),),
}


# --- one case per provider -----------------------------------------------------


@dataclass(frozen=True)
class AdapterCase:
    """Everything the conformance tests need to treat three clouds as one."""

    name: str
    provider: CloudProviderRef
    account: str
    region: str
    vm_service: str
    vm_ids: tuple[str, ...]
    shared_tag: str
    unique_tag: str
    unique_id: str
    inventory: dict[tuple[str, CloudResourceClass], tuple[RecordedResource, ...]]
    operations: dict[str, tuple[RecordedOperation, ...]]

    # -- construction ----------------------------------------------------------

    def transport(self, **kwargs: Any) -> RecordedTransport:
        return RecordedTransport(
            self.provider.key, inventory=self.inventory, operations=self.operations, **kwargs
        )

    def adapter(self, transport: RecordedTransport, **kwargs: Any) -> CloudAdapter:
        return self.adapter_cls(transport, **kwargs)

    adapter_cls: type[CloudAdapter]

    # -- domain builders -------------------------------------------------------

    def identifier_selector(
        self, resource_id: str, resource_class: CloudResourceClass = VM
    ) -> CloudSelector:
        return CloudSelector(
            resource_class=resource_class,
            kind=CloudSelectorKind.IDENTIFIER,
            account=self.account,
            region=self.region,
            identifiers=(resource_id,),
        )

    def tag_selector(self, tag: str, resource_class: CloudResourceClass = VM) -> CloudSelector:
        return CloudSelector(
            resource_class=resource_class,
            kind=CloudSelectorKind.TAG,
            account=self.account,
            region=self.region,
            tags=frozenset({tag}),
        )

    def identity(
        self,
        resource_id: str,
        resource_class: CloudResourceClass = VM,
        tags: frozenset[str] = frozenset(),
    ) -> CloudResourceIdentity:
        return CloudResourceIdentity(
            provider=self.provider,
            resource_class=resource_class,
            account=self.account,
            region=self.region,
            resource_id=resource_id,
            tags=tags,
        )

    def target(
        self,
        resource_id: str,
        resource_class: CloudResourceClass = VM,
        *,
        tags: frozenset[str] = frozenset(),
        selector: CloudSelector | None = None,
    ) -> CloudTarget:
        return CloudTarget(
            provider=self.provider,
            resource_class=resource_class,
            selector=selector or self.identifier_selector(resource_id, resource_class),
            identity=self.identity(resource_id, resource_class, tags),
        )

    def intent(self, selector: CloudSelector) -> CloudTargetIntent:
        return CloudTargetIntent(provider=self.provider, selector=selector)

    def role(self, granted: frozenset[ProviderPermission] = FULL_ROLE) -> CloudRoleRef:
        return CloudRoleRef(
            role_id=f"{self.provider.key}.chaos", provider=self.provider, granted=granted
        )

    def reversible(
        self,
        *,
        kind: CloudActionKind = CloudActionKind.STOP,
        resource_class: CloudResourceClass = VM,
        resource_id: str | None = None,
        duration_s: float | None = None,
        permissions: frozenset[ProviderPermission] = MUTATE_ONLY,
    ) -> ReversibleCloudAction:
        return ReversibleCloudAction(
            action_id=f"{self.provider.key}.chaos.{kind.value}",
            kind=kind,
            target=self.target(resource_id or self.vm_ids[0], resource_class),
            summary=f"{kind.value} {resource_class.value} in the {self.name} fixture",
            reversibility=Reversibility.REVERSIBLE,
            duration_s=duration_s,
            required_permissions=permissions,
        )

    def irreversible(
        self,
        *,
        kind: CloudActionKind = CloudActionKind.IMPAIR,
        resource_class: CloudResourceClass = BLOCK_STORAGE,
        resource_id: str,
    ) -> IrreversibleCloudAction:
        return IrreversibleCloudAction(
            action_id=f"{self.provider.key}.chaos.{kind.value}",
            kind=kind,
            target=self.target(resource_id, resource_class),
            summary=f"{kind.value} {resource_class.value} in the {self.name} fixture",
            reversibility=Reversibility.IRREVERSIBLE,
            rationale="the fixture declares the provider cannot roll this back",
            required_permissions=MUTATE_ONLY,
        )

    @property
    def action_duration_s(self) -> float | None:
        """The duration an action on this cloud's stop needs, if any.

        Azure is the only fixture whose stop stays billable, so it is the only
        one whose cost estimate refuses an action that states no duration.
        Derived from the capability rather than hard-coded per test, so a change
        to the tables cannot leave a test quietly passing on a stale assumption.
        """
        capability = self.adapter_cls.capabilities.get((CloudActionKind.STOP, VM))
        assert capability is not None
        return 300.0 if capability.billable_instance_hours else None

    def discovery_request(self, **kwargs: Any) -> DiscoveryRequest:
        return DiscoveryRequest(
            provider=self.provider,
            resource_class=kwargs.pop("resource_class", VM),
            account=self.account,
            region=self.region,
            **kwargs,
        )


AWS_CASE = AdapterCase(
    name="aws",
    provider=AWS_PROVIDER,
    account="123456789012",
    region="eu-west-1",
    vm_service="ec2",
    vm_ids=("i-0mayhem01", "i-0mayhem02", "i-0mayhem03"),
    shared_tag="web",
    unique_tag="api",
    unique_id="i-0mayhem03",
    inventory=AWS_INVENTORY,
    operations=AWS_OPERATIONS,
    adapter_cls=AwsCloudAdapter,
)

GCP_CASE = AdapterCase(
    name="gcp",
    provider=GCP_PROVIDER,
    account="mayhem-project",
    region="us-central1",
    vm_service="compute",
    vm_ids=("mayhem-vm-01", "mayhem-vm-02", "mayhem-vm-03"),
    shared_tag="env",
    unique_tag="staging",
    unique_id="mayhem-vm-03",
    inventory=GCP_INVENTORY,
    operations=GCP_OPERATIONS,
    adapter_cls=GcpCloudAdapter,
)

AZURE_CASE = AdapterCase(
    name="azure",
    provider=AZURE_PROVIDER,
    account="sub-mayhem",
    region="westeurope",
    vm_service="compute",
    vm_ids=(
        "/subscriptions/sub-mayhem/resourceGroups/rg-mayhem/providers/"
        "Microsoft.Compute/virtualMachines/vm-mayhem-01",
        "/subscriptions/sub-mayhem/resourceGroups/rg-mayhem/providers/"
        "Microsoft.Compute/virtualMachines/vm-mayhem-02",
    ),
    shared_tag="env",
    unique_tag="staging",
    unique_id=(
        "/subscriptions/sub-mayhem/resourceGroups/rg-mayhem/providers/"
        "Microsoft.Compute/virtualMachines/vm-mayhem-02"
    ),
    inventory=AZURE_INVENTORY,
    operations=AZURE_OPERATIONS,
    adapter_cls=AzureCloudAdapter,
)

CASES = (AWS_CASE, GCP_CASE, AZURE_CASE)
CASE_IDS = ("aws", "gcp", "azure")


@pytest.fixture(params=CASES, ids=CASE_IDS)
def case(request: pytest.FixtureRequest) -> AdapterCase:
    return cast("AdapterCase", request.param)


@pytest.fixture
def adapter(case: AdapterCase) -> CloudAdapter:
    return case.adapter(case.transport())


# --- conformance: one contract, three providers -------------------------------


def test_the_transport_implements_the_port(case: AdapterCase) -> None:
    transport = case.transport()
    assert isinstance(transport, CloudTransport)


def test_adapter_declares_its_own_provider_key(case: AdapterCase) -> None:
    adapter = case.adapter(case.transport())
    assert adapter.provider_key == case.provider.key


def test_discover_returns_every_exact_identity(case: AdapterCase, adapter: CloudAdapter) -> None:
    result = adapter.discover(case.discovery_request())

    assert result.outcome is StepOutcome.COMPLETED
    assert result.target_outcome is None
    assert result.code == ""
    assert [i.resource_id for i in result.identities] == list(case.vm_ids)
    assert all(i.provider == case.provider for i in result.identities)
    assert all(i.account == case.account and i.region == case.region for i in result.identities)


def test_discover_mints_one_exact_intent_per_resource(
    case: AdapterCase, adapter: CloudAdapter
) -> None:
    result = adapter.discover(case.discovery_request())

    assert len(result.intents) == len(result.identities) == len(case.vm_ids)
    for intent, identity in zip(result.intents, result.identities, strict=True):
        assert intent.selector.identifiers == (identity.resource_id,)
        assert intent.selector.kind is CloudSelectorKind.IDENTIFIER
        # Each intent is immediately resolvable on its own: that is the whole
        # point of enumerating into intents rather than leaving a broad selector.
        assert adapter.resolve(intent).outcome is StepOutcome.COMPLETED


def test_discover_is_deterministic(adapter: CloudAdapter, case: AdapterCase) -> None:
    first = adapter.discover(case.discovery_request())
    second = adapter.discover(case.discovery_request())
    assert [i.canonical_id for i in first.identities] == [i.canonical_id for i in second.identities]


def test_discover_narrows_by_exact_identifier(case: AdapterCase, adapter: CloudAdapter) -> None:
    result = adapter.discover(case.discovery_request(identifiers=(case.unique_id,)))
    assert result.outcome is StepOutcome.COMPLETED
    assert [i.resource_id for i in result.identities] == [case.unique_id]


def test_discover_narrows_by_tag_subset(case: AdapterCase, adapter: CloudAdapter) -> None:
    result = adapter.discover(case.discovery_request(tags=frozenset({case.unique_tag})))
    assert [i.resource_id for i in result.identities] == [case.unique_id]


def test_exact_identity_resolution(case: AdapterCase, adapter: CloudAdapter) -> None:
    intent = case.intent(case.identifier_selector(case.vm_ids[0]))

    result = adapter.resolve(intent)

    assert result.outcome is StepOutcome.COMPLETED
    assert result.target is not None
    assert result.target.identity.resource_id == case.vm_ids[0]
    assert result.target.identity.canonical_id == (
        f"{case.provider.key}:{case.account}:{case.region}:vm/{case.vm_ids[0]}"
    )
    assert result.target.selector is intent.selector


def test_multi_match_resolution_is_refused(case: AdapterCase, adapter: CloudAdapter) -> None:
    intent = case.intent(case.tag_selector(case.shared_tag))

    result = adapter.resolve(intent)

    assert result.outcome is StepOutcome.FAILED
    assert result.target_outcome is TargetOutcome.FAILED_TO_APPLY
    assert result.code == CLOUD_AMBIGUOUS_RESOLUTION
    assert result.target is None
    assert result.details["match_count"] >= 2
    assert len(result.details["matched"]) >= 2


def test_zero_match_resolution_is_refused(case: AdapterCase, adapter: CloudAdapter) -> None:
    intent = case.intent(case.identifier_selector("i-nonexistent"))

    result = adapter.resolve(intent)

    assert result.outcome is StepOutcome.FAILED
    assert result.code == CLOUD_TARGET_UNRESOLVED
    assert result.target is None


def test_execute_then_verify_then_compensate(case: AdapterCase) -> None:
    """The full reversible lifecycle, end to end, on recorded payloads."""
    transport = case.transport()
    adapter = case.adapter(transport)
    duration = 300.0 if case.name == "azure" else None
    action = case.reversible(duration_s=duration)

    executed = adapter.execute(action, role=case.role(), ceiling=0.0)
    assert executed.outcome is StepOutcome.COMPLETED
    assert executed.receipt is not None
    assert executed.verification is not None
    assert executed.verification.confirmed
    assert executed.verification.phase is VerifyPhase.APPLIED
    assert executed.verification.observed

    compensated = adapter.compensate(action, role=case.role())
    assert compensated.outcome is StepOutcome.COMPLETED
    assert compensated.verification is not None
    assert compensated.verification.phase is VerifyPhase.COMPENSATED
    assert compensated.verification.confirmed

    # The rollback went to the compensating operation, not back to the fault.
    mutates = [call for call in transport.calls if call.startswith("mutate:")]
    capability = adapter.capability_for(action)
    assert isinstance(capability, ReversibleCapability)
    assert mutates[0] == f"mutate:{capability.execute_operation}"
    assert mutates[1] == f"mutate:{capability.compensate_operation}"


def test_api_calls_are_counted_not_asserted(case: AdapterCase) -> None:
    transport = case.transport()
    adapter = case.adapter(transport)
    action = case.reversible(duration_s=case.action_duration_s)

    executed = adapter.execute(action, role=case.role())

    assert executed.api_calls == len(transport.calls) == 2


def test_projected_counts_include_the_rollback_reserve(
    case: AdapterCase, adapter: CloudAdapter
) -> None:
    action = case.reversible(duration_s=case.action_duration_s)
    capability = adapter.capability_for(action)

    counts = adapter.operation_counts(action, cast("Any", capability))

    # execute + verify + compensate + verify
    assert counts.api_calls == 4
    assert counts.describe().startswith("api_calls=4, instance_hours=")


def test_preflight_touches_no_transport(case: AdapterCase) -> None:
    transport = case.transport()
    adapter = case.adapter(transport)
    action = case.reversible(duration_s=case.action_duration_s)

    gate = adapter.preflight(action, role=case.role(), ceiling=0.0)

    assert gate.allowed
    assert gate.api_calls == 0
    assert transport.calls == []


# --- irreversible actions ------------------------------------------------------


IRREVERSIBLE_FIXTURES = (
    pytest.param(
        AWS_CASE,
        AWS_CASE.irreversible(resource_id="vol-mayhem01"),
        id="aws-impair-volume",
    ),
    pytest.param(
        GCP_CASE,
        GCP_CASE.irreversible(resource_id="mayhem-disk-01"),
        id="gcp-impair-disk",
    ),
    pytest.param(
        AZURE_CASE,
        AZURE_CASE.irreversible(
            kind=CloudActionKind.ISOLATE,
            resource_class=FUNCTION,
            resource_id=(
                "/subscriptions/sub-mayhem/resourceGroups/rg-mayhem/providers/"
                "Microsoft.Web/sites/func-mayhem-01"
            ),
        ),
        id="azure-isolate-function",
    ),
)


@pytest.mark.parametrize(("case", "action"), IRREVERSIBLE_FIXTURES)
def test_irreversible_capability_has_no_compensating_operation(
    case: AdapterCase, action: IrreversibleCloudAction
) -> None:
    adapter = case.adapter(case.transport())
    capability = adapter.capability_for(action)

    assert isinstance(capability, IrreversibleCapability)
    assert "compensate_operation" not in type(capability).model_fields
    assert "compensate_verify" not in type(capability).model_fields
    assert capability.rationale.strip()
    assert (action.kind, action.target.resource_class) in adapter.irreversible_actions()


@pytest.mark.parametrize(("case", "action"), IRREVERSIBLE_FIXTURES)
def test_irreversible_capability_cannot_be_given_a_compensation(
    case: AdapterCase, action: IrreversibleCloudAction
) -> None:
    adapter = case.adapter(case.transport())
    capability = adapter.capability_for(action)
    assert isinstance(capability, IrreversibleCapability)

    payload = capability.model_dump()
    payload["compensate_operation"] = "some.rollback"
    with pytest.raises(ValidationError, match="compensate_operation"):
        IrreversibleCapability(**payload)


@pytest.mark.parametrize(("case", "action"), IRREVERSIBLE_FIXTURES)
def test_irreversible_action_cannot_execute(
    case: AdapterCase, action: IrreversibleCloudAction
) -> None:
    transport = case.transport()
    adapter = case.adapter(transport)

    result = adapter.execute(action, role=case.role())

    assert result.outcome is StepOutcome.FAILED
    assert result.code == CLOUD_IRREVERSIBLE_APPROVAL_REQUIRED
    assert result.target_outcome is TargetOutcome.FAILED_TO_APPLY
    assert transport.calls == []


@pytest.mark.parametrize(("case", "action"), IRREVERSIBLE_FIXTURES)
def test_irreversible_action_cannot_reach_the_compensation_path(
    case: AdapterCase, action: IrreversibleCloudAction
) -> None:
    """The structural half of requirement 4, checked at the boundary.

    The ``cast`` is the point: it simulates a caller who ignored the
    ``compensate`` signature's ``ReversibleCloudAction`` annotation, and the
    adapter must still refuse rather than find a rollback to send.
    """
    transport = case.transport()
    adapter = case.adapter(transport)

    result = adapter.compensate(cast("ReversibleCloudAction", action), role=case.role())

    assert result.outcome is StepOutcome.FAILED
    assert result.code == CLOUD_COMPENSATION_UNAVAILABLE
    assert transport.calls == []


def test_compensate_is_annotated_for_reversible_actions_only() -> None:
    signature = inspect.signature(CloudAdapter.compensate)
    annotation = signature.parameters["action"].annotation
    # `from __future__ import annotations` in the adapter module means the
    # annotation is the string the source wrote; that string is the contract.
    assert annotation == "ReversibleCloudAction"


@pytest.mark.parametrize(("case", "action"), IRREVERSIBLE_FIXTURES)
def test_irreversible_action_declares_no_post_state_to_verify(
    case: AdapterCase, action: IrreversibleCloudAction
) -> None:
    adapter = case.adapter(case.transport())

    outcome = adapter.verify(action, phase=VerifyPhase.APPLIED)

    assert outcome.outcome is StepOutcome.FAILED
    assert outcome.reason and CLOUD_VERIFICATION_UNAVAILABLE in outcome.reason
    assert not outcome.confirmed


def test_compensation_reporting_success_without_evidence_is_unconstructible(
    case: AdapterCase,
) -> None:
    receipt = MutationReceipt(
        operation="ec2:StopInstances", resource_id="i-0mayhem01", request_id="req-1"
    )
    with pytest.raises(ValidationError, match="no verification evidence"):
        CompensationResult(outcome=StepOutcome.COMPLETED, receipt=receipt)

    unconfirmed = VerificationOutcome(
        outcome=StepOutcome.FAILED,
        expected=ExpectedState(equal={"State.Name": "stopped"}),
        violated=("State.Name='running' != 'stopped'",),
        reason="still running",
    )
    with pytest.raises(ValidationError, match="did not confirm"):
        CompensationResult(outcome=StepOutcome.COMPLETED, receipt=receipt, verification=unconfirmed)


def test_execution_result_is_bound_to_the_execute_step() -> None:
    """A cost preview mislabelled as an execution result is refused."""
    with pytest.raises(ValidationError, match="only 'execute' is valid"):
        ExecutionResult(step=CloudStep.ESTIMATE_COST, outcome=StepOutcome.FAILED)


# --- cost estimation -----------------------------------------------------------


def test_unpriced_estimate_discloses_counts_and_says_not_free(
    case: AdapterCase, adapter: CloudAdapter
) -> None:
    action = case.reversible(duration_s=case.action_duration_s)

    preview = adapter.estimate_cost(action, ceiling=0.0)

    assert preview.outcome is StepOutcome.COMPLETED
    assert preview.priced is False
    assert preview.price_source == ""
    assert preview.estimate is not None
    assert preview.estimate.expected_low == preview.estimate.expected_high == 0.0
    assert preview.estimate.unit == "currency_micros"
    assert "UNPRICED" in preview.estimate.basis
    assert "not that the action is free" in preview.estimate.basis
    # The disclosure is the real content: what Mayhem counts, not what it invents.
    assert preview.counts.api_calls == 4
    assert "api_calls=4" in preview.estimate.basis
    assert "volume_operations=0" in preview.estimate.basis
    assert preview.ceiling_decision is not None
    assert preview.ceiling_decision.allowed


def test_unpriced_action_is_refused_against_a_declared_ceiling(
    case: AdapterCase, adapter: CloudAdapter
) -> None:
    action = case.reversible(duration_s=case.action_duration_s)

    preview = adapter.estimate_cost(action, ceiling=10_000.0)

    assert preview.outcome is StepOutcome.FAILED
    assert preview.code == CLOUD_COST_UNPRICED
    assert preview.priced is False
    assert preview.estimate is None
    assert "cannot certify an action it cannot price" in preview.reason
    assert preview.details["ceiling"] == 10_000.0


def test_declared_ceiling_refuses_execution(case: AdapterCase) -> None:
    transport = case.transport()
    adapter = case.adapter(transport)
    action = case.reversible(duration_s=case.action_duration_s)

    result = adapter.execute(action, role=case.role(), ceiling=5_000.0)

    assert result.outcome is StepOutcome.FAILED
    assert result.code == CLOUD_COST_UNPRICED
    assert transport.calls == []


def test_billable_action_without_a_duration_is_refused() -> None:
    adapter = AZURE_CASE.adapter(AZURE_CASE.transport())
    action = AZURE_CASE.reversible(duration_s=None)

    preview = adapter.estimate_cost(action, ceiling=0.0)

    assert preview.outcome is StepOutcome.FAILED
    assert preview.code == CLOUD_DURATION_REQUIRED
    assert "without inventing a number" in preview.reason


def test_priced_estimate_uses_the_operator_rate_card() -> None:
    card = CloudRateCard(
        provider=AWS_PROVIDER,
        resource_class=VM,
        region=AWS_CASE.region,
        source="internal-finance:2026-01-14 rate card",
        micros_per_api_call=100.0,
        micros_per_instance_hour=1_000_000.0,
        high_factor=1.5,
    )
    adapter = AWS_CASE.adapter(AWS_CASE.transport(), rate_cards=(card,))
    action = AWS_CASE.reversible()

    preview = adapter.estimate_cost(action, ceiling=10_000.0)

    assert preview.outcome is StepOutcome.COMPLETED
    assert preview.priced is True
    assert preview.price_source == card.source
    assert preview.estimate is not None
    # 4 api calls * 100 micros; no billable instance hours for an AWS stop.
    assert preview.estimate.expected_low == pytest.approx(400.0)
    assert preview.estimate.expected_high == pytest.approx(600.0)
    assert preview.estimate.expected == pytest.approx(500.0)
    assert "priced from operator rate card" in preview.estimate.basis
    assert preview.ceiling_decision is not None
    assert preview.ceiling_decision.allowed


def test_priced_estimate_above_the_ceiling_is_refused() -> None:
    card = CloudRateCard(
        provider=AWS_PROVIDER,
        resource_class=VM,
        region=AWS_CASE.region,
        source="internal-finance:2026-01-14 rate card",
        micros_per_api_call=1_000.0,
        high_factor=2.0,
    )
    adapter = AWS_CASE.adapter(AWS_CASE.transport(), rate_cards=(card,))
    action = AWS_CASE.reversible()

    preview = adapter.estimate_cost(action, ceiling=100.0)

    assert preview.outcome is StepOutcome.FAILED
    assert preview.code == RULE_COST_CEILING_BELOW_HIGH
    assert preview.priced is True
    assert preview.details["expected_high"] == pytest.approx(8_000.0)


def test_rate_card_does_not_cover_another_region() -> None:
    card = CloudRateCard(
        provider=AWS_PROVIDER,
        resource_class=VM,
        region="us-east-1",
        source="internal-finance:2026-01-14 rate card",
        micros_per_api_call=100.0,
    )
    adapter = AWS_CASE.adapter(AWS_CASE.transport(), rate_cards=(card,))

    preview = adapter.estimate_cost(AWS_CASE.reversible(), ceiling=0.0)

    assert preview.outcome is StepOutcome.COMPLETED
    assert preview.priced is False


# --- permission analysis -------------------------------------------------------


def test_permission_denied_names_the_missing_permission(
    case: AdapterCase, adapter: CloudAdapter
) -> None:
    action = case.reversible(duration_s=case.action_duration_s)
    role = case.role(granted=frozenset({ProviderPermission.TARGET_READ}))

    analysis = adapter.analyze_permission(role, action)

    assert analysis.outcome is StepOutcome.FAILED
    assert analysis.code == CLOUD_PERMISSION_DENIED
    assert "target:mutate" in analysis.missing
    assert "target:mutate" in analysis.reason
    assert analysis.role_id == role.role_id


def test_missing_network_permission_is_named_separately(
    case: AdapterCase, adapter: CloudAdapter
) -> None:
    """The adapter's own need, checked through the loader-layer permission model."""
    action = case.reversible(duration_s=case.action_duration_s)
    role = case.role(
        granted=frozenset({ProviderPermission.TARGET_READ, ProviderPermission.TARGET_MUTATE})
    )

    analysis = adapter.analyze_permission(role, action)

    assert analysis.outcome is StepOutcome.FAILED
    assert analysis.missing == ()  # the action's own requirement is satisfied
    assert analysis.adapter_missing == ("network",)
    assert "network" in analysis.reason
    assert analysis.details["adapter_required"] == ["network", "target:read"]


def test_permission_agrees_with_the_existing_sandbox_model(
    case: AdapterCase, adapter: CloudAdapter
) -> None:
    """The analyzer consults ``ProviderPermissionSet``, not a parallel model."""
    from mayhem.providers.permissions import ProviderPermissionSet

    action = case.reversible(duration_s=case.action_duration_s)
    role = case.role(granted=frozenset({ProviderPermission.TARGET_MUTATE}))

    sandbox = adapter.sandbox_permissions_for(role)
    assert isinstance(sandbox, ProviderPermissionSet)
    assert sandbox.granted == role.granted
    analysis = adapter.analyze_permission(role, action)

    assert analysis.adapter_missing == sandbox.check(adapter.adapter_permissions)
    assert analysis.adapter_missing == ("network", "target:read")


def test_permission_allowed_for_a_fully_granted_role(
    case: AdapterCase, adapter: CloudAdapter
) -> None:
    action = case.reversible(duration_s=case.action_duration_s)

    analysis = adapter.analyze_permission(case.role(), action)

    assert analysis.outcome is StepOutcome.COMPLETED
    assert analysis.missing == ()
    assert analysis.adapter_missing == ()


def test_cross_provider_role_is_refused_separately(
    case: AdapterCase, adapter: CloudAdapter
) -> None:
    action = case.reversible(duration_s=case.action_duration_s)
    other = CloudRoleRef(
        role_id="othercloud.chaos",
        provider=GCP_CASE.provider if case.provider != GCP_CASE.provider else AWS_CASE.provider,
        granted=FULL_ROLE,
    )

    analysis = adapter.analyze_permission(other, action)

    assert analysis.outcome is StepOutcome.FAILED
    assert analysis.code == CLOUD_ROLE_PROVIDER_MISMATCH
    assert analysis.missing == ("target:mutate",)


def test_permission_refusal_blocks_execution(case: AdapterCase) -> None:
    transport = case.transport()
    adapter = case.adapter(transport)
    action = case.reversible(duration_s=case.action_duration_s)

    result = adapter.execute(action, role=case.role(granted=frozenset()))

    assert result.outcome is StepOutcome.FAILED
    assert result.code == CLOUD_PERMISSION_DENIED
    assert transport.calls == []


def test_permission_refusal_blocks_compensation(case: AdapterCase) -> None:
    transport = case.transport()
    adapter = case.adapter(transport)
    action = case.reversible(duration_s=case.action_duration_s)

    result = adapter.compensate(action, role=case.role(granted=frozenset()))

    assert result.outcome is StepOutcome.FAILED
    assert result.code == CLOUD_PERMISSION_DENIED
    assert transport.calls == []


def test_an_action_cannot_be_built_without_declaring_a_permission(
    case: AdapterCase,
) -> None:
    """Negative control at the boundary: the adapter can never see one."""
    payload = case.reversible().model_dump()
    payload["required_permissions"] = frozenset()
    with pytest.raises(ValidationError, match=r"cloud\.action_permission_undeclared"):
        ReversibleCloudAction(**payload)

    payload["required_permissions"] = frozenset({ProviderPermission.TARGET_READ})
    with pytest.raises(ValidationError, match="target:mutate"):
        ReversibleCloudAction(**payload)


# --- negative controls ---------------------------------------------------------


def test_wildcard_selector_is_refused_before_any_call(case: AdapterCase) -> None:
    transport = case.transport()
    adapter = case.adapter(transport)

    result = adapter.discover(case.discovery_request(identifiers=("i-0mayhem*",)))

    assert result.outcome is StepOutcome.FAILED
    assert result.code == CLOUD_SELECTOR_WILDCARD
    assert transport.calls == []
    assert result.identities == () and result.intents == ()


def test_wildcard_selector_is_unbuildable_in_the_first_place() -> None:
    with pytest.raises(ValidationError, match="wildcard"):
        AWS_CASE.identifier_selector("i-0mayhem*")
    with pytest.raises(ValidationError, match="wildcard"):
        CloudSelector(
            resource_class=VM,
            kind=CloudSelectorKind.TAG,
            account=AWS_CASE.account,
            region=AWS_CASE.region,
            tags=frozenset({"web*"}),
        )


def test_transport_failure_becomes_a_failed_step_never_a_success(
    case: AdapterCase,
) -> None:
    transport = case.transport(failing=True)
    adapter = case.adapter(transport)
    action = case.reversible(duration_s=case.action_duration_s)

    executed = adapter.execute(action, role=case.role())
    discovered = adapter.discover(case.discovery_request())
    verified = adapter.verify(action)

    for result in (executed, discovered):
        assert result.outcome is StepOutcome.FAILED
        assert result.code == CLOUD_TRANSPORT_FAILURE
        assert result.target_outcome is TargetOutcome.FAILED_TO_APPLY
    assert verified.outcome is StepOutcome.FAILED
    assert verified.reason and CLOUD_TRANSPORT_FAILURE in verified.reason


def test_transport_conflict_is_resource_conflict_not_failed_to_apply(
    case: AdapterCase,
) -> None:
    transport = case.transport(conflicting=True)
    adapter = case.adapter(transport)
    action = case.reversible(duration_s=case.action_duration_s)

    result = adapter.execute(action, role=case.role())

    assert result.outcome is StepOutcome.FAILED
    assert result.code == CLOUD_TRANSPORT_FAILURE
    assert result.target_outcome is TargetOutcome.RESOURCE_CONFLICT


def test_a_receipt_alone_never_makes_an_execution_complete(case: AdapterCase) -> None:
    """The cloud accepts the call and does not do the thing: still not success."""
    transport = case.transport(disregard_effects=True)
    adapter = case.adapter(transport)
    action = case.reversible(duration_s=case.action_duration_s)

    result = adapter.execute(action, role=case.role())

    assert result.outcome is StepOutcome.FAILED
    assert result.code == CLOUD_VERIFICATION_FAILED
    # The receipt exists — the cloud really did accept the call — and it is not
    # enough: its request id is filed as evidence of the *failure*, not a success.
    assert str(result.details["request_id"]).startswith(f"{case.name}-req-")
    assert any(call.startswith("mutate:") for call in transport.calls)


def test_a_mislabelled_receipt_is_refused(case: AdapterCase) -> None:
    transport = case.transport(mislabelled="some.other.operation")
    adapter = case.adapter(transport)
    action = case.reversible(duration_s=case.action_duration_s)

    result = adapter.execute(action, role=case.role())

    assert result.outcome is StepOutcome.FAILED
    assert result.code == CLOUD_RECEIPT_MISMATCH
    assert result.details["returned"] == "some.other.operation"


def test_compensation_that_cannot_be_verified_is_refused(case: AdapterCase) -> None:
    transport = case.transport()
    adapter = case.adapter(transport)
    action = case.reversible(duration_s=case.action_duration_s)

    executed = adapter.execute(action, role=case.role())
    assert executed.outcome is StepOutcome.COMPLETED
    # The fault landed; the rollback is accepted and the resource does not come back.
    transport.disregard_effects = True

    compensated = adapter.compensate(action, role=case.role())

    assert compensated.outcome is StepOutcome.FAILED
    assert compensated.code == CLOUD_VERIFICATION_FAILED
    assert compensated.verification is None


def test_a_vanished_target_is_drift_not_failure(case: AdapterCase) -> None:
    transport = case.transport()
    adapter = case.adapter(transport)
    action = case.reversible(duration_s=case.action_duration_s)
    capability = adapter.capability_for(action)
    assert isinstance(capability, ReversibleCapability)
    transport.drop(
        capability.service,
        action.target.resource_class,
        action.target.identity.resource_id,
    )

    outcome = adapter.verify(action)

    assert outcome.outcome is StepOutcome.TARGET_DRIFT
    assert outcome.target_outcome is TargetOutcome.TARGET_DRIFT
    assert not outcome.resource_present
    assert not outcome.confirmed
    assert "not the object present" in outcome.reason


def test_an_execution_whose_target_vanished_is_not_reported_complete(
    case: AdapterCase,
) -> None:
    transport = case.transport()
    adapter = case.adapter(transport)
    action = case.reversible(duration_s=case.action_duration_s)
    capability = adapter.capability_for(action)
    assert isinstance(capability, ReversibleCapability)
    original_mutate = transport.mutate

    def mutate_and_lose(command: MutationCommand) -> MutationReceipt:
        receipt = original_mutate(command)
        transport.drop(capability.service, command.query.resource_class, command.resource_id)
        return receipt

    transport.mutate = mutate_and_lose  # type: ignore[method-assign]

    result = adapter.execute(action, role=case.role())

    assert result.outcome is StepOutcome.FAILED
    assert result.code == CLOUD_VERIFICATION_FAILED


def test_an_unrepresentable_resource_is_refused() -> None:
    """A tag carrying a glob cannot become an exact identity, so it never does."""
    transport = AWS_CASE.transport()
    transport.retag("ec2", VM, "i-0mayhem01", frozenset({"web*"}))
    adapter = AWS_CASE.adapter(transport)

    result = adapter.discover(AWS_CASE.discovery_request())

    assert result.outcome is StepOutcome.FAILED
    assert result.code == CLOUD_IDENTITY_UNREPRESENTABLE
    assert result.identities == ()


def test_unsupported_action_is_reported_not_approximated(
    case: AdapterCase, adapter: CloudAdapter
) -> None:
    """Reboot is unsupported everywhere, and no adapter substitutes a near-miss."""
    action = case.reversible(kind=CloudActionKind.REBOOT, resource_id=case.vm_ids[0])

    assert adapter.capability_for(action) is None
    executed = adapter.execute(action, role=case.role())
    discovered = adapter.discover(case.discovery_request(resource_class=CloudResourceClass.QUEUE))

    assert executed.outcome is StepOutcome.FAILED
    assert executed.code == CLOUD_ACTION_UNSUPPORTED
    assert "does not implement" in executed.reason
    assert discovered.code == CLOUD_UNKNOWN_RESOURCE_CLASS


def test_resolving_another_providers_intent_is_refused(
    case: AdapterCase, adapter: CloudAdapter
) -> None:
    other = next(c for c in CASES if c.provider != case.provider)
    intent = other.intent(other.identifier_selector(other.vm_ids[0]))

    result = adapter.resolve(intent)

    assert result.outcome is StepOutcome.FAILED
    assert result.code == CLOUD_ROLE_PROVIDER_MISMATCH
    assert result.target is None


def test_every_adapter_declares_a_non_empty_contract() -> None:
    """A provider that declares nothing has nothing to expose, and says so."""
    for case in CASES:
        adapter = case.adapter(case.transport())
        assert adapter.capabilities
        assert adapter.services
        assert set(adapter.services) >= {
            resource_class for _, resource_class in adapter.capabilities
        }, f"{case.name} declares a capability for a class it cannot enumerate"


def test_the_adapter_contract_is_exactly_the_five_steps_and_three_analyses() -> None:
    public = {
        name
        for name in vars(CloudAdapter)
        if not name.startswith("_") and callable(vars(CloudAdapter)[name])
    }
    assert public == {
        "analyze_permission",
        "capability_for",
        "compensate",
        "discover",
        "estimate_cost",
        "execute",
        "irreversible_actions",
        "operation_counts",
        "preflight",
        "resolve",
        "sandbox_permissions_for",
        "service_for",
        "supported_actions",
        "verify",
    }


def test_expected_state_that_asserts_nothing_is_refused() -> None:
    with pytest.raises(ValidationError, match="asserts nothing"):
        ExpectedState()
    with pytest.raises(ValidationError, match="both present and absent"):
        ExpectedState(present=("a",), absent=("a",))


def test_expected_state_reports_violations_verbatim() -> None:
    expected = ExpectedState(equal={"State.Name": "stopped"})
    matched, violated = expected.check({"State.Name": "running"})
    assert matched == ()
    assert violated == ("State.Name='running' != 'stopped'",)


def test_adapter_error_carries_its_outcome_mapping() -> None:
    error = CloudAdapterError(
        code=CLOUD_RESOURCE_CONFLICT,
        reason="busy",
        target_outcome=TargetOutcome.RESOURCE_CONFLICT,
        details={"operation": "ec2:StopInstances"},
    )
    assert error.code == CLOUD_RESOURCE_CONFLICT
    assert error.target_outcome is TargetOutcome.RESOURCE_CONFLICT
    assert error.details == {"operation": "ec2:StopInstances"}


# --- the provider tables are genuinely different -------------------------------


def test_stop_billing_differs_between_a_stopped_vm_and_a_powered_off_one() -> None:
    aws = AWS_CASE.adapter(AWS_CASE.transport()).capability_for(AWS_CASE.reversible())
    gcp = GCP_CASE.adapter(GCP_CASE.transport()).capability_for(GCP_CASE.reversible())
    azure = AzureCloudAdapter.__new__(AzureCloudAdapter).capability_for(
        AZURE_CASE.reversible(duration_s=60.0)
    )
    assert aws is not None and gcp is not None and azure is not None
    # A stopped EC2 instance and a TERMINATED GCP instance bill no compute; a
    # powered-off Azure VM is still allocated and still bills.
    assert (aws.billable_instance_hours, gcp.billable_instance_hours) == (False, False)
    assert azure.billable_instance_hours is True


def test_each_provider_declares_a_different_supported_set() -> None:
    sets = {
        case.name: {f"{kind.value}/{cls.value}" for kind, cls in case.adapter_cls.capabilities}
        for case in CASES
    }
    assert sets["aws"] == {
        "stop/vm",
        "impair/vm",
        "failover/managed_database",
        "impair/block_storage",
    }
    assert sets["gcp"] == {"stop/vm", "failover/managed_database", "impair/block_storage"}
    assert sets["azure"] == {"stop/vm", "failover/managed_database", "isolate/function"}
    assert sets["aws"] != sets["gcp"] != sets["azure"]


def test_failover_verification_uses_present_and_absent_on_gcp() -> None:
    adapter = GCP_CASE.adapter(GCP_CASE.transport())
    action = GCP_CASE.reversible(
        kind=CloudActionKind.FAILOVER,
        resource_class=MANAGED_DATABASE,
        resource_id="mayhem-sql-01",
        duration_s=60.0,
    )
    capability = adapter.capability_for(action)
    assert isinstance(capability, ReversibleCapability)

    executed = adapter.execute(action, role=GCP_CASE.role())
    compensated = adapter.compensate(action, role=GCP_CASE.role())

    assert capability.apply_verify.present == ("settings.failoverReplica.name",)
    assert capability.compensate_verify.absent == ("settings.failoverReplica.name",)
    assert executed.outcome is StepOutcome.COMPLETED
    assert "settings.failoverReplica.name" in executed.verification.evidence  # type: ignore[union-attr]
    assert compensated.outcome is StepOutcome.COMPLETED


def test_azure_carries_full_arm_resource_ids_verbatim() -> None:
    adapter = AZURE_CASE.adapter(AZURE_CASE.transport())

    discovered = adapter.discover(AZURE_CASE.discovery_request())

    assert discovered.outcome is StepOutcome.COMPLETED
    assert all(
        i.resource_id.startswith("/subscriptions/sub-mayhem/") for i in discovered.identities
    )
    intent = AZURE_CASE.intent(AZURE_CASE.identifier_selector(AZURE_CASE.vm_ids[0]))
    resolved = adapter.resolve(intent)
    assert resolved.target is not None
    assert resolved.target.identity.resource_id == AZURE_CASE.vm_ids[0]


def test_refusals_are_typed_domain_errors_not_strings() -> None:
    """The domain code still arrives as a ``CloudRefused`` where the domain made it."""
    with pytest.raises(CloudRefused) as excinfo:
        from mayhem.domain.cloud import ensure_selector_is_specific

        ensure_selector_is_specific(identifiers=("i-0*",))
    assert excinfo.value.code == CLOUD_SELECTOR_WILDCARD
    assert excinfo.value.remediation


# --- the dependency constraint -------------------------------------------------


def test_no_cloud_sdk_is_imported_by_the_adapter_package() -> None:
    """The CRITICAL CONSTRAINT, enforced on the source rather than trusted."""
    forbidden_roots = {
        "boto3",
        "botocore",
        "google",
        "azure",
        "requests",
        "urllib",
        "http",
        "socket",
        "subprocess",
    }
    offenders: list[str] = []
    for path in sorted(CLOUD_PACKAGE.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                roots = [(node.module or "").split(".")[0]]
            else:
                continue
            offenders += [f"{path.name}:{root}" for root in roots if root in forbidden_roots]
    assert offenders == []


def test_the_declared_dependency_set_is_unchanged() -> None:
    manifest = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = {
        name.split(">=")[0].split("==")[0].split("[")[0].strip()
        for name in manifest["project"]["dependencies"]
    }
    assert declared == {
        "pydantic",
        "typer",
        "click",
        "pyyaml",
        "structlog",
        "kubernetes",
    }
