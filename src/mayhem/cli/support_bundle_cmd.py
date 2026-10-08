"""``mayhem support-bundle`` — plan 20 Phase 3: redacted diagnostics for support.

One verb over the Phase-4-drafted engine
(:mod:`mayhem.controller.support_bundle`), and deliberately a thin one:

``mayhem support-bundle build --section NAME=PATH ... --out PATH``
    Build a publishable bundle from raw JSON field files. Each ``--section``
    names one :class:`SupportSection` (the file holds the raw fields; the
    companion ``--grade`` option declares a ``section.field`` plan-29 grade).
    Ungraded fields grade through the plan-29 default, exactly as the engine
    grades them.

    Secrets are **dropped**, never rewritten: a secret-graded field is removed
    entirely and named in the redaction manifest. Sensitive and lower fields
    are kept only after the redactor ran over them.

    The bundle seals the execution-mode marker of the run it describes
    (``--mode training`` seals ``TRAINING — no mutation performed``). A
    bundle built from a training run carries that banner, and
    :func:`presentation_refusal` refuses to present it as production
    diagnostics. Support diagnostics that could be mistaken for production
    evidence are how a rehearsal becomes an incident report.

What this surface does not do: it writes bytes (the bundle JSON plus the
manifest is what the caller sends to support), but it invents no policy —
grades come from the caller, redaction from the domain redactor, and the
marker from the sealed Phase-1 path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from mayhem.cli.exit_codes import ExitCode
from mayhem.cli.resolver import make_group
from mayhem.controller.support_bundle import (
    BUNDLE_REDACTION_RULES,
    SupportSection,
    build_support_bundle,
    presentation_refusal,
)
from mayhem.domain.deployment import ExecutionMode, sealed_mode_marker
from mayhem.domain.secrets import DataClassification, FieldClassifications

support_bundle = make_group(
    "support-bundle",
    "Build a redacted support bundle with a redaction manifest.",
)

__all__ = ["parse_section", "support_bundle"]

_GRADE_CHOICES = ("public", "internal", "sensitive", "secret")


def parse_section(spec: str) -> tuple[str, Path]:
    """Split ``NAME=PATH`` into a section name and its raw-field JSON file."""
    name, sep, path = spec.partition("=")
    if not sep or not name.strip() or not path.strip():
        raise click.UsageError(
            f"--section {spec!r} is not NAME=PATH. "
            "The name becomes the bundle section; the path holds its raw JSON fields."
        )
    return name.strip(), Path(path.strip())


def _parse_grades(pairs: tuple[str, ...]) -> dict[str, DataClassification]:
    """``section.field=GRADE`` pairs into plan-29 grades, or a usage error."""
    grades: dict[str, DataClassification] = {}
    for pair in pairs:
        dotted, sep, grade = pair.partition("=")
        if not sep or "." not in dotted or not grade.strip():
            raise click.UsageError(
                f"--grade {pair!r} is not SECTION.FIELD=GRADE. "
                f"Grades are {', '.join(_GRADE_CHOICES)}."
            )
        normalized = grade.strip().lower()
        if normalized not in _GRADE_CHOICES:
            raise click.UsageError(
                f"--grade {pair!r} names no grade: choose from {', '.join(_GRADE_CHOICES)}."
            )
        grades[dotted.strip()] = DataClassification(normalized)
    return grades


def _read_fields(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise click.ClickException(f"cannot read section file {path}: {exc}") from None
    except ValueError as exc:
        raise click.ClickException(f"section file {path} is not JSON: {exc}") from None
    if not isinstance(payload, dict):
        raise click.ClickException(
            f"section file {path} must hold a JSON object of fields, not {type(payload).__name__}"
        )
    return dict(payload)


def _echo(payload: dict[str, Any], as_json: bool) -> bool:
    from mayhem.cli.output import echo_machine

    return echo_machine(payload, as_json=as_json)


@support_bundle.command("build")
@click.option(
    "--section",
    "sections",
    multiple=True,
    required=True,
    metavar="NAME=PATH",
    help="One bundle section from a JSON field file; repeatable.",
)
@click.option(
    "--grade",
    "grade_pairs",
    multiple=True,
    metavar="SECTION.FIELD=GRADE",
    help="Plan-29 grade for one field (public|internal|sensitive|secret); repeatable.",
)
@click.option(
    "--mode",
    type=click.Choice([mode.value for mode in ExecutionMode]),
    default=ExecutionMode.TRAINING.value,
    show_default=True,
    help="Execution mode the bundle's marker is sealed from.",
)
@click.option(
    "--out", "out_path", required=True, metavar="PATH", help="Write the bundle JSON here."
)
@click.option("--json", "as_json", is_flag=True, help="Emit the manifest as JSON.")
@click.pass_context
def build_cmd(
    ctx: click.Context,
    sections: tuple[str, ...],
    grade_pairs: tuple[str, ...],
    mode: str,
    out_path: str,
    as_json: bool,
) -> None:
    """Build a redacted support bundle and write its bytes to --out."""
    grades = _parse_grades(grade_pairs)
    materialized: list[SupportSection] = []
    for spec in sections:
        name, path = parse_section(spec)
        fields = _read_fields(path)
        per_field = {
            field: grades[f"{name}.{field}"] for field in fields if f"{name}.{field}" in grades
        }
        materialized.append(
            SupportSection(
                name=name,
                fields=fields,
                grades=FieldClassifications(fields=per_field),
            )
        )
    execution_mode = ExecutionMode(mode)
    marker = sealed_mode_marker(execution_mode, basis=f"support bundle ({execution_mode.value})")
    try:
        bundle = build_support_bundle(materialized, marker=marker)
    except ValueError as exc:
        click.echo(f"refused: {exc}", err=True)
        ctx.exit(int(ExitCode.VALIDATION_ERROR))
    destination = Path(out_path)
    if destination.is_dir():
        click.echo(
            f"error: {out_path} is a directory; mayhem will not write a file over one",
            err=True,
        )
        ctx.exit(int(ExitCode.VALIDATION_ERROR))
    refusal = presentation_refusal(bundle, as_production=True)
    manifest: dict[str, Any] = {
        "sections": [name for name, _ in bundle.sections],
        "field_count": bundle.field_count,
        "dropped_secret_fields": list(bundle.dropped_fields),
        "redacted_paths": list(bundle.redacted_paths),
        "highest_published_grade": bundle.highest.value if bundle.highest else "none",
        "mode_banner": bundle.mode_banner,
        "mutates": bundle.mutates,
        "redaction_rules": list(BUNDLE_REDACTION_RULES),
        "production_presentation": refusal or "presentable",
        "out": str(destination),
    }
    document = {
        "sections": [{"name": name, "fields": fields} for name, fields in bundle.sections],
        "manifest": manifest,
    }
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    except OSError as exc:
        click.echo(f"error: cannot write {out_path}: {exc}", err=True)
        ctx.exit(int(ExitCode.VALIDATION_ERROR))
    if _echo(manifest, as_json):
        ctx.exit(int(ExitCode.SUCCESS))
    click.echo(bundle.describe())
    click.echo(f"wrote {destination} ({bundle.field_count} field(s))")
    if refusal:
        click.echo(f"note: {refusal}")
    ctx.exit(int(ExitCode.SUCCESS))
