"""``mayhem cloud`` — plan 06 Phase 3: ask a cloud question before paying for it.

Three verbs, all read-only, and none of them *does* anything to a cloud:

``mayhem cloud capabilities``
    The per-provider capability matrix, rendered from the adapter tables
    themselves — the same rows Phase 6's documentation gates on. Every row
    carries ``mechanism_applied=false`` because no ``CloudTransport``
    implementation ships in this build: a matrix that cannot tell the
    difference between "the provider offers this" and "mayhem has performed
    this" would be the one lie this surface must not print, so the notice is
    part of the output, not a docstring.

``mayhem cloud check-permission``
    ``Can this role perform this action?``, answered before a run through the
    domain's own ``check_role_can_perform`` *and* the adapter's sandbox
    cross-check — one analysis, two permission models that must agree. The
    default role is the domain's ``read_only`` factory, so the default answer
    is a refusal that names the missing permission: that is the point. An
    IAM-insufficient plan is refused here, where it costs nothing, rather than
    at the provider, where it costs an incident.

``mayhem cloud estimate-cost``
    What the action would cost, from the quantities the adapter actually
    projects (API calls, instance-hours, volume operations) priced only from a
    rate card the operator supplies. Without a card the estimate is refused
    rather than invented — ``cloud.cost_unpriced`` prints the quantities and
    says plainly that unknown is not free, because "0.00" is how an estimator
    launders a guess into a number.

The transport passed to each adapter is a stub that raises on every call. The
analysis verbs never touch it — that is a property of the port, not a promise
in this docstring — so a future edit that makes one of these verbs reach a
provider fails loudly here instead of quietly becoming a mutation surface.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import click

from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.resolver import make_group

if TYPE_CHECKING:
    from collections.abc import Callable

    from mayhem.providers.cloud.port import CloudAdapter

cloud = make_group(
    "cloud",
    "Read cloud capabilities, permissions, and costs before any run.",
)

# --- the stub transport ---------------------------------------------------------

_CALLS_REACH_NOTHING = (
    "mayhem cloud is a read-only surface: its analyses answer from the domain "
    "and the adapter tables, and never call the transport. Reaching this stub "
    "means an analysis path grew a provider call, which is a surface-regression."
)


class _DeadTransport:
    """A transport that refuses every call, loud enough to fail a test.

    The port's analyses (``analyze_permission``, ``estimate_cost``, the
    capability tables) are transport-free by construction. Passing this stub is
    how the CLI makes that construction *checkable*: if any code path on this
    surface ever reaches for a cloud, it gets this exception instead of a
    connection.
    """

    def list_resources(self, query: object) -> tuple[Any, ...]:
        raise RuntimeError(_CALLS_REACH_NOTHING)

    def read_resource(self, query: object, resource_id: str) -> Any:
        raise RuntimeError(_CALLS_REACH_NOTHING)

    def mutate(self, command: object) -> Any:
        raise RuntimeError(_CALLS_REACH_NOTHING)


_ADAPTER_CLASSES: dict[str, type[CloudAdapter]] = {}


def _adapters() -> dict[str, type[CloudAdapter]]:
    """The three provider tables, imported lazily and keyed by provider."""
    if not _ADAPTER_CLASSES:
        from mayhem.providers.cloud.aws import AwsCloudAdapter
        from mayhem.providers.cloud.azure import AzureCloudAdapter
        from mayhem.providers.cloud.gcp import GcpCloudAdapter

        _ADAPTER_CLASSES.update(
            {
                "aws": AwsCloudAdapter,
                "gcp": GcpCloudAdapter,
                "azure": AzureCloudAdapter,
            }
        )
    return _ADAPTER_CLASSES


def _adapter_for(provider: str, *, rate_cards: tuple[Any, ...] = ()) -> CloudAdapter:
    """Construct the provider adapter over the stub transport, never a cloud."""
    return _adapters()[provider](_DeadTransport(), rate_cards=rate_cards)


# --- shared option stacks ---------------------------------------------------------

_RESOURCE_CLASSES = (
    "vm",
    "network",
    "load_balancer",
    "object_storage",
    "block_storage",
    "managed_database",
    "queue",
    "function",
    "managed_kubernetes",
)
_ACTION_KINDS = ("stop", "reboot", "isolate", "impair", "failover")
_PERMISSIONS = (
    "network",
    "filesystem:read",
    "filesystem:write",
    "subprocess",
    "target:read",
    "target:mutate",
)


def _action_options(fn: Callable[..., Any]) -> Callable[..., Any]:
    """The options both analyzers share: one action, one role, one provider.

    The role is the domain's ``read_only`` factory plus any ``--grant`` the
    operator declares, so the default posture is the domain's own
    default-deny: the default answer to "can this role do this?" is a refusal
    that names what is missing, not a permissive guess.
    """
    for decorator in reversed(
        (
            click.option(
                "--provider",
                required=True,
                type=click.Choice(["aws", "gcp", "azure"]),
                help="Which provider's tables to analyze against.",
            ),
            click.option(
                "--account",
                required=True,
                metavar="ACCOUNT",
                help="Account the target lives in.",
            ),
            click.option(
                "--region",
                required=True,
                metavar="REGION",
                help="Region the target lives in.",
            ),
            click.option(
                "--resource-id",
                "resource_id",
                required=True,
                metavar="ID",
                help="The provider-native id of the exact resource (no wildcards).",
            ),
            click.option(
                "--resource-class",
                "resource_class",
                required=True,
                type=click.Choice(_RESOURCE_CLASSES),
                help="The resource class the action would act on.",
            ),
            click.option(
                "--kind",
                required=True,
                type=click.Choice(_ACTION_KINDS),
                help="The failure primitive the action would apply.",
            ),
            click.option(
                "--duration-s",
                "duration_s",
                type=float,
                default=None,
                help="How long the action runs; instance-hours are projected from this.",
            ),
            click.option(
                "--action-id",
                "action_id",
                default=None,
                metavar="ID",
                help=("Dotted action id to report (default: probe.<provider>.<class>.<kind>)."),
            ),
            click.option(
                "--grant",
                "grants",
                multiple=True,
                type=click.Choice(_PERMISSIONS),
                help="A permission the declared role holds, on top of target:read; repeatable.",
            ),
            click.option(
                "--role-id",
                "role_id",
                default="declared.reader",
                show_default=True,
                metavar="ID",
                help="Dotted role id the analysis reports against.",
            ),
            click.option("--json", "as_json", is_flag=True, help="Emit JSON."),
        )
    ):
        fn = decorator(fn)
    return fn


def _build_action(
    provider: str,
    account: str,
    region: str,
    resource_id: str,
    resource_class: str,
    kind: str,
    duration_s: float | None,
    action_id: str | None,
) -> Any:
    """Build the action exactly as the plan would: selector → identity → target.

    The pair is constructed through the domain's own validator, so a target
    that names a resource the selector does not select is refused here rather
    than analyzed — the same admission the run path reaches, read-only.
    """
    from mayhem.domain.cloud import (
        CloudActionKind,
        CloudProvider,
        CloudProviderRef,
        CloudResourceClass,
        CloudResourceIdentity,
        CloudSelector,
        CloudSelectorKind,
        CloudTarget,
        Reversibility,
        ReversibleCloudAction,
    )
    from mayhem.domain.provider import ProviderPermission

    ref = CloudProviderRef(provider=CloudProvider(provider))
    resource_cls = CloudResourceClass(resource_class)
    identity = CloudResourceIdentity(
        provider=ref,
        resource_class=resource_cls,
        account=account,
        region=region,
        resource_id=resource_id,
    )
    selector = CloudSelector(
        resource_class=resource_cls,
        kind=CloudSelectorKind.IDENTIFIER,
        account=account,
        region=region,
        identifiers=(resource_id,),
    )
    target = CloudTarget(
        provider=ref, resource_class=resource_cls, selector=selector, identity=identity
    )
    resolved_id = action_id or f"probe.{provider}.{resource_class}.{kind}"
    return ReversibleCloudAction(
        action_id=resolved_id,
        kind=CloudActionKind(kind),
        target=target,
        summary=f"mayhem cloud analysis: {kind} {resource_cls.value} {resource_id}",
        reversibility=Reversibility.REVERSIBLE,
        duration_s=duration_s,
        required_permissions=frozenset(
            {
                ProviderPermission.TARGET_MUTATE,
                ProviderPermission.TARGET_READ,
            }
        ),
    )


def _refusal(
    ctx: click.Context, message: str, payload: dict[str, Any] | None, as_json: bool
) -> None:
    """One refusal shape for both analyzers: reason, then exit 5."""
    if payload is not None and echo(payload, as_json):
        ctx.exit(int(ExitCode.SAFETY_REFUSAL))
    click.echo(f"refused: {message}", err=True)
    ctx.exit(int(ExitCode.SAFETY_REFUSAL))


def echo(payload: dict[str, Any], as_json: bool) -> bool:
    """Machine-mode echo; returns True when it handled the output."""
    from mayhem.cli.output import echo_machine

    return echo_machine(payload, as_json=as_json)


# --- capabilities -----------------------------------------------------------------


@cloud.command("capabilities")
@click.option(
    "--provider",
    type=click.Choice(["aws", "gcp", "azure", "all"]),
    default="all",
    show_default=True,
    help="Which provider's table to render.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def capabilities(ctx: click.Context, provider: str, as_json: bool) -> None:
    """Render the per-provider capability matrix from the adapter tables.

    What the provider API supports as against what Mayhem wraps, per row — and
    every row reports ``mechanism_applied=false``, because no transport ships
    in this build and a matrix that implied otherwise would be the one lie a
    capability page must not tell.
    """
    from mayhem.providers.cloud.report import CLOUD_MECHANISM_NOT_APPLIED_NOTICE, capability_rows

    names = sorted(_adapters()) if provider == "all" else [provider]
    rows: list[dict[str, Any]] = []
    irreversible: list[str] = []
    for name in names:
        adapter = _adapter_for(name)
        for pair in adapter.supported_actions():
            capability = adapter.capabilities[pair]
            row = capability_rows(capability, provider=adapter.provider_key)
            rows.append(row.to_payload())
            if not row.reversible:
                irreversible.append(row.label)

    payload = {
        "providers": names,
        "rows": rows,
        "count": len(rows),
        "irreversible": irreversible,
        "mechanism_applied": False,
        "notice": CLOUD_MECHANISM_NOT_APPLIED_NOTICE,
    }
    if echo(payload, as_json):
        ctx.exit(int(ExitCode.SUCCESS))
    for name in names:
        adapter_rows = [row for row in rows if row["provider"] == name]
        click.echo(f"{name}: {len(adapter_rows)} declared capabilities")
        for payload_row in adapter_rows:
            compensate = payload_row["compensate_operation"] or "-"
            click.echo(
                f"  {payload_row['label']:<34} {payload_row['execute_operation']:<36} "
                f"reversible={str(payload_row['reversible']).lower()} "
                f"compensate={compensate} "
                f"billable_instance_hours={str(payload_row['billable_instance_hours']).lower()} "
                f"applied=false"
            )
    if irreversible:
        click.echo("irreversible (the cloud offers no rollback): " + ", ".join(irreversible))
    click.echo(CLOUD_MECHANISM_NOT_APPLIED_NOTICE)
    ctx.exit(int(ExitCode.SUCCESS))


# --- check-permission -------------------------------------------------------------


@cloud.command("check-permission")
@_action_options
@click.pass_context
def check_permission(ctx: click.Context, /, **kwargs: Any) -> None:
    """Answer "can this role perform this action?" before a run exists.

    Two permission models are asked the same question and must agree: the
    domain's ``check_role_can_perform``, which names each missing permission,
    and the adapter sandbox's read of the same grants. An IAM-insufficient plan
    is refused here with the missing permission named — the phase's acceptance
    — because the cheap place to learn that answer is before anything exists.
    """
    from pydantic import ValidationError

    from mayhem.domain.cloud import CloudRoleRef
    from mayhem.domain.errors import InvariantViolationError
    from mayhem.domain.provider import ProviderPermission

    (
        provider,
        account,
        region,
        resource_id,
        resource_class,
        kind,
        duration_s,
        action_id,
        grants,
        role_id,
        as_json,
    ) = _unpack(kwargs)

    try:
        action = _build_action(
            provider, account, region, resource_id, resource_class, kind, duration_s, action_id
        )
        ref = action.target.provider
        granted = frozenset({ProviderPermission.TARGET_READ}) | frozenset(
            ProviderPermission(g) for g in grants
        )
        role = CloudRoleRef(role_id=role_id, provider=ref, granted=granted)
    except (ValueError, InvariantViolationError, ValidationError) as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(int(ExitCode.VALIDATION_ERROR))

    adapter = _adapter_for(provider)
    analysis = adapter.analyze_permission(role, action)
    capability = adapter.capability_for(action)
    payload: dict[str, Any] = {
        "role_id": role.role_id,
        "action_id": action.action_id,
        "action": action.describe(),
        "allowed": analysis.ok,
        "code": analysis.code,
        "reason": analysis.reason,
        "missing": list(analysis.missing),
        "adapter_missing": list(analysis.adapter_missing),
        "granted": sorted(p.value for p in role.granted),
        "required": sorted(p.value for p in action.required_permissions),
        "provider_supports_action": capability is not None,
    }
    if analysis.ok:
        if echo(payload, as_json):
            ctx.exit(int(ExitCode.SUCCESS))
        click.echo(f"allowed: {analysis.reason or action.action_id}")
        if capability is None:
            click.echo(
                "note: the grants are sufficient, but this provider's table declares "
                "no capability for this pair — an allowed permission is not a "
                "promise the provider implements it"
            )
        ctx.exit(int(ExitCode.SUCCESS))
    missing = ", ".join(sorted(analysis.missing + analysis.adapter_missing))
    _refusal(
        ctx,
        (
            f"{analysis.reason}. The plan is IAM-insufficient: the role is "
            f"missing {missing or 'unknown permissions'}. Grant the named "
            "permissions or change the plan's action."
        ),
        payload,
        as_json,
    )


# --- estimate-cost ----------------------------------------------------------------


@cloud.command("estimate-cost")
@_action_options
@click.option(
    "--rate-card-source",
    "rate_card_source",
    default=None,
    metavar="LABEL",
    help="Where the unit rates came from; required when any rate is given.",
)
@click.option(
    "--micros-per-api-call",
    "micros_per_api_call",
    type=float,
    default=0.0,
    show_default=True,
    help="Unit rate for API calls, in currency micros.",
)
@click.option(
    "--micros-per-instance-hour",
    "micros_per_instance_hour",
    type=float,
    default=0.0,
    show_default=True,
    help="Unit rate for instance-hours, in currency micros.",
)
@click.option(
    "--micros-per-volume-operation",
    "micros_per_volume_operation",
    type=float,
    default=0.0,
    show_default=True,
    help="Unit rate for volume operations, in currency micros.",
)
@click.option(
    "--high-factor",
    "high_factor",
    type=float,
    default=1.0,
    show_default=True,
    help="Widens the low bound into the high bound (>= 1.0).",
)
@click.option(
    "--ceiling",
    "ceiling",
    type=float,
    default=0.0,
    show_default=True,
    help="Declared cost ceiling in currency micros (0 means none declared).",
)
@click.pass_context
def estimate_cost(ctx: click.Context, /, **kwargs: Any) -> None:
    """Project what the action would cost, from countable quantities.

    The counts are projected from the capability's own declarations and the
    action's duration — never from a guess. Pricing happens only from an
    operator-supplied rate card: with no card the estimate is refused with the
    quantities printed and ``cloud.cost_unpriced`` named, because an
    estimator's zero is a claim of "free" and unknown is not free. A declared
    ceiling the estimate cannot be shown to fit is refused before a mutation
    could ever read it.
    """
    from pydantic import ValidationError

    from mayhem.domain.errors import InvariantViolationError
    from mayhem.providers.cloud.port import CLOUD_COST_UNPRICED

    (
        provider,
        account,
        region,
        resource_id,
        resource_class,
        kind,
        duration_s,
        action_id,
        _grants,
        _role_id,
        as_json,
    ) = _unpack(kwargs)
    rate_card_source = kwargs.get("rate_card_source")
    micros_per_api_call = kwargs.get("micros_per_api_call", 0.0)
    micros_per_instance_hour = kwargs.get("micros_per_instance_hour", 0.0)
    micros_per_volume_operation = kwargs.get("micros_per_volume_operation", 0.0)
    high_factor = kwargs.get("high_factor", 1.0)
    ceiling = kwargs.get("ceiling", 0.0)

    try:
        action = _build_action(
            provider, account, region, resource_id, resource_class, kind, duration_s, action_id
        )
    except (ValueError, InvariantViolationError, ValidationError) as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(int(ExitCode.VALIDATION_ERROR))

    rate_options_given = bool(
        micros_per_api_call
        or micros_per_instance_hour
        or micros_per_volume_operation
        or high_factor != 1.0
    )
    if rate_options_given and not rate_card_source:
        click.echo(
            "error: unit rates without --rate-card-source would produce a number "
            "nobody can trace; name the source of the rates.",
            err=True,
        )
        ctx.exit(int(ExitCode.VALIDATION_ERROR))

    if rate_card_source:
        from mayhem.domain.cloud import CloudProvider, CloudProviderRef, CloudResourceClass
        from mayhem.providers.cloud.port import CloudRateCard

        rate_cards: tuple[CloudRateCard, ...] = (
            CloudRateCard(
                provider=CloudProviderRef(provider=CloudProvider(provider)),
                resource_class=CloudResourceClass(resource_class),
                region=region,
                source=rate_card_source,
                micros_per_api_call=micros_per_api_call,
                micros_per_instance_hour=micros_per_instance_hour,
                micros_per_volume_operation=micros_per_volume_operation,
                high_factor=high_factor,
            ),
        )
    else:
        rate_cards = ()
    adapter = _adapter_for(provider, rate_cards=rate_cards)
    preview = adapter.estimate_cost(action, ceiling=ceiling)
    estimate = preview.estimate
    counts = preview.counts
    payload: dict[str, Any] = {
        "action_id": action.action_id,
        "action": action.describe(),
        "priced": preview.priced,
        "price_source": preview.price_source,
        "counts": counts.model_dump(),
        "counts_summary": counts.describe(),
        "code": preview.code,
        "reason": preview.reason,
        "expected_low": estimate.expected_low if estimate else None,
        "expected_high": estimate.expected_high if estimate else None,
        "expected": estimate.expected if estimate else None,
        "ceiling": ceiling if ceiling > 0.0 else None,
        "basis": estimate.basis if estimate else "",
    }
    if preview.ok:
        if echo(payload, as_json):
            ctx.exit(int(ExitCode.SUCCESS))
        click.echo(preview.reason or preview.code or f"estimate for {action.action_id}")
        click.echo(counts.describe())
        if preview.priced and estimate:
            click.echo(
                f"priced from {preview.price_source!r}: "
                f"{estimate.expected_low:g}..{estimate.expected_high:g} micros"
            )
        elif estimate:
            # The domain's own honesty line: zeros that mean "no price known",
            # never "free".
            click.echo(estimate.basis)
        ctx.exit(int(ExitCode.SUCCESS))

    if preview.code == CLOUD_COST_UNPRICED:
        _refusal(
            ctx,
            (
                f"{preview.reason}. Mayhem has no rate card for this provider/"
                "class/region, so the estimate is unknown, not free — the "
                f"quantities to price are {counts.describe()}. Supply a rate card "
                "with --rate-card-source and the unit rates to get a number."
            ),
            payload,
            as_json,
        )
    _refusal(ctx, preview.reason or preview.code or "estimate refused", payload, as_json)


def _unpack(kwargs: dict[str, Any]) -> tuple[Any, ...]:
    """The shared option stack's names, in the order both commands consume."""
    keys = (
        "provider",
        "account",
        "region",
        "resource_id",
        "resource_class",
        "kind",
        "duration_s",
        "action_id",
        "grants",
        "role_id",
        "as_json",
    )
    return tuple(kwargs.get(key) for key in keys)
