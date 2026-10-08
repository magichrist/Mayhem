"""``mayhem enterprise`` — plan 20 Phase 4: the acceptance walkthrough as CLI verbs.

Two verbs over the drafted engine (:mod:`mayhem.controller.enterprise_walkthrough`),
and deliberately a thin surface:

``mayhem enterprise walkthrough``
    Run the ten acceptance steps (deploy → authenticate → policy → approve →
    execute → observe → stop → recover → verify → export) with a container
    runtime injected as the provisioner's runner. Steps that need a live site
    (an IdP, a human approver, a container runtime, a cluster for the Helm
    chart) are reported as open items, not proven — a green harness with named
    live items is PARTIAL, not DONE. Exits 0 only when the harness proved
    every runnable step; live-open items are named in the output either way.

``mayhem enterprise compliance-map``
    Map sealed evidence digests onto a compliance template's required evidence
    kinds (:mod:`mayhem.controller.compliance_map`). Refuses unsealed digests
    and evidence kinds the template does not ask for. The output is a mapping,
    never a certification — the statement says so.

What this surface does not do: it injects the runtime and the directory, and
renders the report. Admission, simulation, verification, redaction, and the
compliance honesty rules all live in the engines this surface reads aloud.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import click

from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.resolver import make_group
from mayhem.cli.sandbox_cmd import SubprocessSandboxRunner, build_policy
from mayhem.controller.compliance_map import (
    ComplianceEvidence,
    build_compliance_map,
    map_statement,
)
from mayhem.controller.enterprise_walkthrough import STEP_NAMES, run_walkthrough
from mayhem.domain.deployment import DeploymentModel
from mayhem.domain.failure_modes import COMPLIANCE_TEMPLATES

enterprise = make_group(
    "enterprise",
    "Run the acceptance walkthrough and map sealed compliance evidence.",
)

__all__ = ["enterprise"]


def _echo(payload: dict[str, Any], as_json: bool) -> bool:
    from mayhem.cli.output import echo_machine

    return echo_machine(payload, as_json=as_json)


def _policy_options(fn: Any) -> Any:
    """The relay/proxy configuration UX, shared with ``mayhem sandbox``."""
    for decorator in reversed(
        (
            click.option(
                "--http-proxy",
                default="",
                help="HTTP proxy for image pulls (empty means direct).",
            ),
            click.option(
                "--https-proxy",
                default="",
                help="HTTPS proxy for image pulls (empty means direct).",
            ),
            click.option(
                "--ca-bundle",
                default="",
                help="Custom CA bundle path the runtime trusts.",
            ),
            click.option(
                "--allow-host",
                "allowlist",
                multiple=True,
                help="Outbound host the policy permits; repeatable.",
            ),
            click.option(
                "--enforce-allowlist",
                is_flag=True,
                default=False,
                help="Refuse image hosts the allowlist does not name.",
            ),
            click.option(
                "--air-gapped",
                is_flag=True,
                default=False,
                help="Refuse all image egress; provision from pre-pulled images.",
            ),
        )
    ):
        fn = decorator(fn)
    return fn


@enterprise.command("walkthrough")
@click.option("--name", default="mayhem-acceptance", help="Sandbox project name.")
@click.option(
    "--dir",
    "directory",
    default=".",
    help="Directory holding the rendered compose document.",
)
@click.option(
    "--model",
    type=click.Choice([model.value for model in DeploymentModel]),
    default=DeploymentModel.LOCAL.value,
    show_default=True,
    help="Deployment model the walkthrough runs under.",
)
@_policy_options
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def walkthrough_cmd(
    ctx: click.Context,
    name: str,
    directory: str,
    model: str,
    http_proxy: str,
    https_proxy: str,
    ca_bundle: str,
    allowlist: tuple[str, ...],
    enforce_allowlist: bool,
    air_gapped: bool,
    as_json: bool,
) -> None:
    """Run the acceptance walkthrough. Live-only steps are named, not proven."""
    from mayhem.controller.enterprise_walkthrough import run_walkthrough as _run

    policy = build_policy(
        http_proxy=http_proxy,
        https_proxy=https_proxy,
        ca_bundle=ca_bundle,
        allowlist=allowlist,
        enforce_allowlist=enforce_allowlist,
        air_gapped=air_gapped,
    )
    report = _run(
        SubprocessSandboxRunner(),
        Path(directory),
        name=name,
        policy=policy,
        model=DeploymentModel(model),
    )
    payload: dict[str, Any] = {
        "steps": [
            {
                "name": step.name,
                "proven": step.proven,
                "detail": step.detail,
                "live_item": step.live_item,
            }
            for step in report.steps
        ],
        "harness_ok": report.harness_ok,
        "complete": report.complete,
        "live_open_items": list(report.live_open_items),
    }
    if _echo(payload, as_json):
        ctx.exit(int(ExitCode.SUCCESS if report.harness_ok else ExitCode.SAFETY_REFUSAL))
    click.echo(report.describe())
    ctx.exit(int(ExitCode.SUCCESS if report.harness_ok else ExitCode.SAFETY_REFUSAL))


@enterprise.command("compliance-map")
@click.option(
    "--control",
    "control_id",
    default=None,
    help="Control id from the illustrative template set (default: first).",
)
@click.option(
    "--evidence",
    "evidence_pairs",
    multiple=True,
    metavar="KIND=DIGEST",
    help="One cited evidence kind and its sealed sha256 digest; repeatable.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit JSON.")
@click.pass_context
def compliance_map_cmd(
    ctx: click.Context,
    control_id: str | None,
    evidence_pairs: tuple[str, ...],
    as_json: bool,
) -> None:
    """Map sealed evidence digests onto a template's evidence kinds."""
    templates = {template.control_id: template for template in COMPLIANCE_TEMPLATES}
    control = templates.get(control_id) if control_id else COMPLIANCE_TEMPLATES[0]
    if control is None:  # pragma: no cover - control_id names a shipped template or nothing
        click.echo(
            f"error: unknown control {control_id!r} (known: {sorted(templates)})",
            err=True,
        )
        ctx.exit(int(ExitCode.VALIDATION_ERROR))
    records: list[ComplianceEvidence] = []
    for pair in evidence_pairs:
        kind, sep, digest = pair.partition("=")
        if not sep or not kind.strip() or not digest.strip():
            click.echo(
                f"error: --evidence {pair!r} is not KIND=DIGEST. "
                "The kind names a template evidence kind; the digest is sealed hex.",
                err=True,
            )
            ctx.exit(int(ExitCode.VALIDATION_ERROR))
        records.append(
            ComplianceEvidence(evidence_kind=kind.strip(), evidence_digest=digest.strip())
        )
    try:
        mapped = build_compliance_map(control, records)
    except Exception as exc:
        rule = getattr(exc, "rule", type(exc).__name__)
        click.echo(f"refused [{rule}]: {exc}", err=True)
        ctx.exit(int(ExitCode.SAFETY_REFUSAL))
    statement = map_statement(mapped)
    payload: dict[str, Any] = {
        "control": control.control_id,
        "framework": control.framework,
        "supplied": [{"kind": kind, "digest": digest} for kind, digest in mapped.supplied],
        "missing": list(mapped.missing),
        "evidence_complete": mapped.evidence_complete,
        "statement": statement,
    }
    if _echo(payload, as_json):
        ctx.exit(int(ExitCode.SUCCESS))
    click.echo(statement)
    ctx.exit(int(ExitCode.SUCCESS))


assert STEP_NAMES, "the walkthrough step names must be imported so drift fails loudly"
assert run_walkthrough is not None
