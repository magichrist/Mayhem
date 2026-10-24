from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

import click

from mayhem.cli.context import CliContext
from mayhem.cli.exit_codes import ExitCode
from mayhem.domain.errors import InvariantViolationError
from mayhem.infra.diagnostics import (
    DiagnosticCategory,
    DiagnosticRecord,
    DiagnosticSeverity,
    run_diagnostics,
)

if TYPE_CHECKING:
    from collections.abc import Mapping


def _render_human(records: list[DiagnosticRecord]) -> None:
    for rec in records:
        prefix = rec.severity.value.upper()
        line = f"[{prefix}] {rec.category.value}/{rec.id}: {rec.message}"
        if rec.severity in (DiagnosticSeverity.error, DiagnosticSeverity.warning):
            click.echo(line)
            if rec.remediation:
                click.echo(f"  remediation: {rec.remediation}")
        else:
            click.echo(line)
    errs = sum(1 for r in records if r.severity == DiagnosticSeverity.error)
    warns = sum(1 for r in records if r.severity == DiagnosticSeverity.warning)
    click.echo(f"doctor: {errs} error(s), {warns} warning(s), {len(records)} total")


# The deployment's two bindings (``MAYHEM_GATE_WITNESSES``,
# ``MAYHEM_BUDGET_GUARD``) are read at the CLI edge by ``mayhem.cli.app`` and
# named by no checked-in document, so doctor is where an operator first learns
# whether their deployment is gated or budgeted at all.
#
# The tension: reporting whether a *set* spec resolves means loading it, and
# full resolution — what ``gate_from_spec`` / ``budget_guard_from_spec`` do —
# **calls** what it loaded: a zero-argument gate factory, or a budget factory
# given a ``run_id`` that doctor does not have and must not invent. A factory
# may touch the deployment's own infrastructure, and a doctor line must be safe
# to run, so the safe option is chosen: doctor stops at ``_load_binding``, the
# import seam both of those functions call first, and where a spec that cannot
# be resolved fails (malformed spec, unimportable module, missing attribute).
# Its ``InvariantViolationError`` — the same exception those functions raise —
# is caught and rendered as the message rather than raised: ``mayhem doctor``
# must never crash on a misconfigured deployment. What doctor stops short of
# seeing (a factory that would raise, an attribute of the wrong shape) the run
# path still refuses loudly, before any store is touched — which is why the
# resolved line says the factory is not called here instead of claiming more
# than doctor checked. Additive: both variables unset is the shipped default
# and yields two info records; no record ``run_diagnostics`` produced is
# touched.
def _binding_records(environ: Mapping[str, str] | None = None) -> list[DiagnosticRecord]:
    """One record per binding variable: set or unset, the spec, whether it resolves."""
    from mayhem.cli.execution import BUDGET_GUARD_ENV, GATE_WITNESSES_ENV, _load_binding

    env = os.environ if environ is None else environ
    bindings = (
        (GATE_WITNESSES_ENV, "gate_binding", "config.binding.gate_witnesses"),
        (BUDGET_GUARD_ENV, "budget_binding", "config.binding.budget_guard"),
    )
    records: list[DiagnosticRecord] = []
    for variable, rule_prefix, record_id in bindings:
        spec = str(env.get(variable, "")).strip()
        if not spec:
            # Unset is reported as unset and never resolved: an empty binding
            # must not become a gate built here and discarded.
            records.append(
                DiagnosticRecord(
                    id=record_id,
                    category=DiagnosticCategory.config,
                    severity=DiagnosticSeverity.info,
                    message=f"{variable} unset; no binding configured (the run path is unchanged)",
                )
            )
            continue
        try:
            _load_binding(spec, variable, rule_prefix)
        except InvariantViolationError as exc:
            records.append(
                DiagnosticRecord(
                    id=record_id,
                    category=DiagnosticCategory.config,
                    severity=DiagnosticSeverity.error,
                    message=f"{variable}={spec} does not resolve: {exc}",
                    remediation=(
                        f"fix the module:attribute in {variable} or unset it; see docs/config.md"
                    ),
                    evidence_ref=spec,
                )
            )
            continue
        records.append(
            DiagnosticRecord(
                id=record_id,
                category=DiagnosticCategory.config,
                severity=DiagnosticSeverity.info,
                message=f"{variable}={spec} resolves; the factory is not called by doctor",
                evidence_ref=spec,
            )
        )
    return records


@click.command("doctor")
@click.option("--json", "as_json", is_flag=True, help="Emit diagnostics as JSON.")
@click.option("--quiet", is_flag=True, help="Suppress output; exit code signals errors.")
@click.option(
    "--category",
    "category",
    type=click.Choice([c.value for c in DiagnosticCategory]),
    default=None,
    help="Filter to one category.",
)
@click.pass_context
def doctor_cmd(
    ctx: click.Context,
    as_json: bool,
    quiet: bool,
    category: str | None,
) -> None:
    obj = ctx.obj
    assert isinstance(obj, CliContext)
    compose = None
    try:
        from mayhem.cli.topology import _resolve_compose

        compose = _resolve_compose(None)
    except Exception:
        compose = None
    records = run_diagnostics(
        config_path=obj.config,
        profile=obj.profile,
        policy=obj.policy,
        target=obj.target,
        db_path=obj.db,
        compose_path=compose,
        spec_path=obj.config,
    )
    records.extend(_binding_records())
    if category is not None:
        records = [r for r in records if r.category.value == category]
    if as_json:
        from mayhem.cli.app import _STATE
        from mayhem.controller.catalog_report import build_capability_report

        payload = {
            "diagnostics": [r.model_dump(mode="json") for r in records],
            "summary": {
                "total": len(records),
                "errors": sum(1 for r in records if r.severity == DiagnosticSeverity.error),
                "warnings": sum(1 for r in records if r.severity == DiagnosticSeverity.warning),
                "infos": sum(1 for r in records if r.severity == DiagnosticSeverity.info),
            },
            "capabilities": build_capability_report(engine=_STATE.get("engine") or None),
        }
        click.echo(json.dumps(payload, indent=2))
    elif not quiet:
        _render_human(records)
    has_error = any(r.severity == DiagnosticSeverity.error for r in records)
    if has_error:
        ctx.exit(int(ExitCode.VALIDATION_ERROR))
