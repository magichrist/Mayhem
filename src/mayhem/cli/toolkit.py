"""``toolkit`` group: fault catalog and capability probing."""

from __future__ import annotations

import json

import click

from mayhem.cli.resolver import make_group
from mayhem.domain.catalog import all_definitions

toolkit = make_group("toolkit", "Inspect the fault catalog and local tool capabilities.")


@toolkit.command("faults")
def faults() -> None:
    """List the fault catalog with risk and compensatability."""
    for definition in sorted(all_definitions(), key=lambda d: d.id):
        undoable = "yes" if definition.reversible else "no"
        click.echo(f"{definition.id:<24} risk={definition.risk.value:<6} undo={undoable}")


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
