"""``toolkit`` group: fault catalog and capability probing."""

from __future__ import annotations

import json

import click

from mayhem.cli.resolver import make_group
from mayhem.domain.catalog import all_definitions

toolkit = make_group("toolkit", "Inspect the fault catalog and local tool capabilities.")


@toolkit.command("faults")
@click.option(
    "--engine",
    "engine_opt",
    type=click.Choice(["docker", "podman", "kubernetes"], case_sensitive=False),
    default=None,
    help="Filter catalog by engine; kubernetes shows support labels per fault.",
)
@click.option("--coverage", is_flag=True, help="Emit the generated catalog coverage matrix.")
@click.option(
    "-e",
    "--explain",
    "explain_id",
    metavar="FAULT",
    help="Explain one fault instead of listing the catalog.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable output.")
def faults(engine_opt: str | None, coverage: bool, explain_id: str | None, as_json: bool) -> None:
    if explain_id is not None:
        from mayhem.infra.catalog_report import explain_catalog_fault

        try:
            report = explain_catalog_fault(explain_id, engine=(engine_opt or "docker").lower())
        except LookupError as exc:
            raise click.ClickException(str(exc)) from exc
        click.echo(json.dumps(report, indent=2, sort_keys=True))
        return

    from mayhem.cli.app import _STATE
    from mayhem.controller.k8s_runtime import (
        K8S_ARGV_FAULTS,
        K8S_DELETE_FAULTS,
        K8S_NETNS_FAULTS,
        K8S_NETWORK_FAULTS,
        K8S_NODE_FAULTS,
        k8s_available_faults,
        k8s_contract_for,
    )

    engine = engine_opt or str(_STATE.get("engine", "")) or ""
    if coverage:
        from mayhem.infra.catalog_report import build_coverage

        report = build_coverage(engine=engine or None)
        if as_json:
            click.echo(json.dumps(report, indent=2, sort_keys=True))
        else:
            for label, values in report.items():
                if isinstance(values, dict):
                    click.echo(f"{label}: {json.dumps(values, sort_keys=True)}")
                else:
                    click.echo(f"{label}: {values}")
        return
    kubernetes = engine == "kubernetes"
    available = k8s_available_faults() if kubernetes else None

    def _lane(fault_id: str) -> str:
        if fault_id in K8S_NODE_FAULTS:
            return "node"
        if fault_id in K8S_NETNS_FAULTS and fault_id in K8S_ARGV_FAULTS:
            return "argv+netns"
        if fault_id in K8S_ARGV_FAULTS:
            return "argv"
        if fault_id in K8S_DELETE_FAULTS:
            return "pod-delete"
        if fault_id in K8S_NETWORK_FAULTS:
            return "network-policy"
        return "in-pod-signal"

    for definition in sorted(all_definitions(), key=lambda d: d.id):
        if kubernetes:
            if (
                available is not None
                and definition.id not in available
                and not definition.id.startswith("k8s.")
            ):
                continue
            supported = definition.id in available if available is not None else True
            support_label = "supported" if supported else "catalog-only"
            undoable = "yes" if definition.reversible else "no"
            contract = None
            if definition.id.startswith("k8s."):
                try:
                    contract = k8s_contract_for(definition.id)
                except LookupError:
                    contract = None
            contract_text = ""
            if contract is not None:
                contract_text = (
                    f" target={contract.target_kind} targets={','.join(contract.target_kinds)}"
                    f" capability={contract.capability}"
                    f" safety={contract.safety_decision} executor={contract.executor}"
                    f" compensation={contract.compensation}"
                )
            click.echo(
                f"{definition.id:<24} risk={definition.risk.value:<6} "
                f"undo={undoable} lane={_lane(definition.id)} support={support_label}"
                f"{contract_text}"
            )
        else:
            if available is not None and definition.id not in available:
                continue
            undoable = "yes" if definition.reversible else "no"
            click.echo(f"{definition.id:<24} risk={definition.risk.value:<6} undo={undoable}")


@toolkit.command("capabilities")
@click.option(
    "--engine",
    "engine_opt",
    type=click.Choice(["docker", "podman", "kubernetes"], case_sensitive=False),
    default=None,
    help="Filter capability truth by engine.",
)
@click.option("--explain", "explain_id", metavar="FAULT", help="Explain one fault capability.")
@click.option("--family", default=None, help="Only rows whose fault family matches.")
@click.option("--maturity", default=None, help="Only rows with this maturity level.")
@click.option(
    "--blocked/--supported",
    "blocked",
    default=None,
    help="Only blocked rows, or only rows that are not blocked.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit capability truth as JSON.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "yaml"], case_sensitive=False),
    default=None,
    help="Output format; --json is retained for compatibility.",
)
def capabilities(
    engine_opt: str | None,
    explain_id: str | None,
    family: str | None,
    maturity: str | None,
    blocked: bool | None,
    as_json: bool,
    output_format: str | None,
) -> None:
    """Report registered, available, verified, and blocked fault capabilities."""
    from mayhem.infra.catalog_report import build_capability_dashboard

    engine = engine_opt.lower() if engine_opt else None
    dashboard = build_capability_dashboard(
        engine=engine, family=family, maturity=maturity, blocked=blocked
    )
    if explain_id:
        rows = dashboard.find(explain_id)
        if not rows:
            raise click.ClickException(f"unknown fault: {explain_id}")
        payload: object = {"capabilities": [row.to_dict() for row in rows]}
    else:
        payload = dashboard.to_dict()
    from mayhem.cli.output import current_format

    # The command's own --format wins; otherwise honour the root group's
    # resolved --format so every command supports text/json/yaml.
    fmt = output_format.lower() if output_format else ("json" if as_json else current_format())
    if fmt == "json":
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    if fmt == "yaml":
        import yaml

        click.echo(yaml.safe_dump(payload, sort_keys=True))
        return
    rows = payload["capabilities"] if isinstance(payload, dict) else []
    if isinstance(payload, dict) and "summary" in payload:
        summary = payload["summary"]
        click.echo(
            f"capabilities: {summary['total']} rows, {summary['supported']} supported, "
            f"{summary['blocked']} blocked (schema {payload['schema_version']})"
        )
    for row in rows:
        reason = row.get("blocked_reason") or "-"
        click.echo(
            f"{row['fault_id']:<28} {row['engine']:<10} "
            f"supported={str(row['supported']).lower():<5} "
            f"registered={str(row['registered']).lower():<5} "
            f"available={str(row['available']).lower():<5} "
            f"unit={str(row['unit_verified']).lower():<5} "
            f"live={str(row['live_verified']).lower():<5} "
            f"compensation={str(row['compensation_complete']).lower():<5} "
            f"maturity={row.get('maturity_band', 'unknown'):<14} "
            f"reason={reason}"
        )
        if row.get("remediation"):
            click.echo(
                f"{'':<28} ↳ {row['remediation']} (source: {row.get('source_of_truth', '-')})"
            )


@toolkit.command("list")
@click.option("--host", default="local", show_default=True, help="Host to probe.")
@click.option("--json", "as_json", is_flag=True, help="Emit the CapabilityReport as JSON.")
def list_tools(host: str, as_json: bool) -> None:
    """Probe declared tool manifests on the host and report capabilities."""
    from mayhem.cli.services import probe_capabilities
    from mayhem.toolkit.registry import default_registry

    report = probe_capabilities(host=host)
    if as_json:
        click.echo(json.dumps(report.model_dump(mode="json"), indent=2))
        return
    seen = {probed.manifest.tool for probed in report.tools}
    for probed in report.tools:
        caps = ",".join(probed.manifest.provides)
        click.echo(f"{probed.manifest.tool:<16} ok       {probed.version:<12} [{caps}]")
    for manifest in default_registry().manifests:
        if manifest.tool not in seen:
            click.echo(f"{manifest.tool:<16} MISSING  probe failed or version undetectable")
