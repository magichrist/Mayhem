"""``toolkit`` group: fault catalog and capability probing."""

from __future__ import annotations

import json

import click

from mayhem.cli.resolver import make_group
from mayhem.domain.catalog import all_definitions

toolkit = make_group("toolkit", "Inspect the fault catalog and local tool capabilities.")


@toolkit.command("faults")
def faults() -> None:
    """List the fault catalog with risk and compensatability.

    Honors the global ``-k/--kubernetes`` flag: with Kubernetes selected, only
    the faults the k8s driver can actually execute are listed (pod/node
    targets), each annotated with its delivery lane. Without it the full
    cross-runtime catalog is shown.
    """
    from mayhem.cli.app import _STATE
    from mayhem.controller.k8s_runtime import (
        K8S_ARGV_FAULTS,
        K8S_DELETE_FAULTS,
        K8S_NETNS_FAULTS,
        K8S_NETWORK_FAULTS,
        K8S_NODE_FAULTS,
        k8s_available_faults,
    )

    kubernetes = str(_STATE.get("engine", "")) == "kubernetes"
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
        if available is not None and definition.id not in available:
            continue
        undoable = "yes" if definition.reversible else "no"
        if kubernetes:
            click.echo(
                f"{definition.id:<24} risk={definition.risk.value:<6} "
                f"undo={undoable} lane={_lane(definition.id)}"
            )
        else:
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
