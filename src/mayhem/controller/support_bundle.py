"""Plan 20 Phase 3 — redacted support bundles (gap 110 support process input).

A support bundle is the artifact a customer sends Mayhem support, so it is the
artifact most likely to carry a credential out of the customer's site. This
module builds it from two mechanisms that already exist, not from a third copy
of either:

* :func:`mayhem.domain.redaction.redact` — name- and pattern-based redaction,
  applied to every section. What it removes is recorded, per section, as the
  paths it removed them from.
* :class:`mayhem.domain.secrets.FieldClassifications` — the plan-29 data
  classification grades. A field graded ``secret`` is **dropped**, not
  redacted: redaction rewrites a value in place, and a secret has no safe
  in-place rewrite inside a support artifact. ``sensitive`` fields are kept
  only after redaction ran over them, and the bundle manifest says so.

The bundle also seals the execution-mode marker of the run it describes (Phase
1's :class:`~mayhem.domain.deployment.ModeMarker`). A bundle built from a
training run therefore carries the ``TRAINING — no mutation performed`` banner
and :func:`presentation_refusal` refuses to present it as production
diagnostics. Support diagnostics that could be mistaken for production evidence
are how a rehearsal becomes an incident report.

Pure: no clock, no file, no store. The CLI writes the bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final

from mayhem.domain.redaction import RULE_VERSION as REDACTION_RULE_VERSION
from mayhem.domain.redaction import redact
from mayhem.domain.secrets import DataClassification, FieldClassifications

if TYPE_CHECKING:
    from collections.abc import Mapping

    from mayhem.domain.deployment import DeploymentModel, ModeMarker

__all__ = [
    "REDACTED_VALUE",
    "RULE_SUPPORT_EMPTY",
    "RULE_SUPPORT_SECRET_DROPPED",
    "SupportBundle",
    "SupportSection",
    "build_support_bundle",
    "presentation_refusal",
]

#: A field graded ``secret`` is dropped, never rewritten — so there is no
#: placeholder value for one. This marker is for redacted (not dropped) values
#: in prose contexts only.
REDACTED_VALUE: Final[str] = "***REDACTED***"

RULE_SUPPORT_EMPTY = "support.empty_bundle"
RULE_SUPPORT_SECRET_DROPPED = "support.secret_field_dropped"


@dataclass(frozen=True, slots=True)
class SupportSection:
    """One named group of fields, with its classification grades.

    ``fields`` are the raw values; ``grades`` declares each field's plan-29
    grade. An ungraded field grades as the
    :data:`~mayhem.domain.secrets.DEFAULT_CLASSIFICATION` default through
    :meth:`FieldClassifications.classification_for`, so an undeclared field
    still gets a decision rather than a pass.
    """

    name: str
    fields: Mapping[str, Any]
    grades: FieldClassifications = FieldClassifications()


@dataclass(frozen=True, slots=True)
class SupportBundle:
    """A redacted bundle plus the manifest proving what was removed.

    ``sections`` holds the publishable fields only. ``dropped_fields`` names
    the secret-graded ``section.field`` entries that were removed entirely;
    ``redacted_paths`` names what the redactor rewrote. ``highest`` is the
    most restricted grade present in the *published* sections — a bundle whose
    highest grade is ``secret`` is a bundle this builder refused to build.
    """

    sections: tuple[tuple[str, dict[str, Any]], ...]
    dropped_fields: tuple[str, ...]
    redacted_paths: tuple[str, ...]
    highest: DataClassification | None
    deployment_model: DeploymentModel | None = None
    mode_banner: str = ""
    mutates: bool = False

    @property
    def field_count(self) -> int:
        return sum(len(fields) for _, fields in self.sections)

    def describe(self) -> str:
        lines = [
            f"support bundle: {self.field_count} field(s) in "
            f"{len(self.sections)} section(s)"
            + (f" [{self.deployment_model.value}]" if self.deployment_model else ""),
            f"highest published grade: {self.highest.value if self.highest else 'none'}",
            f"dropped secret fields: {list(self.dropped_fields) or 'none'}",
            f"redacted paths: {list(self.redacted_paths) or 'none'}",
        ]
        if self.mode_banner:
            lines.append(f"mode: {self.mode_banner}")
        return "\n".join(lines)


def build_support_bundle(
    sections: tuple[SupportSection, ...] | list[SupportSection],
    *,
    deployment_model: DeploymentModel | None = None,
    marker: ModeMarker | None = None,
) -> SupportBundle:
    """Build a publishable bundle from raw sections.

    Raises:
        ValueError: ``[support.empty_bundle]`` when there is nothing to
            publish — an empty bundle is not evidence of a healthy system, it
            is evidence the collector failed.
    """
    published: list[tuple[str, dict[str, Any]]] = []
    dropped: list[str] = []
    redacted: list[str] = []
    grades: list[DataClassification] = []
    for section in sections:
        kept: dict[str, Any] = {}
        for field, value in section.fields.items():
            grade = section.grades.classification_for(field)
            if grade is DataClassification.SECRET:
                dropped.append(f"{section.name}.{field}")
                continue
            kept[field] = value
            grades.append(grade)
        result = redact(kept)
        published.append((section.name, dict(result.value)))
        redacted.extend(f"{section.name}.{path}" for path in result.removed_paths)
    if not published or (all(not fields for _, fields in published) and not dropped):
        raise ValueError(
            f"[{RULE_SUPPORT_EMPTY}] no sections supplied: a support bundle "
            "with no content describes nothing and proves nothing"
        )
    from mayhem.domain.secrets import most_restrictive

    return SupportBundle(
        sections=tuple(published),
        dropped_fields=tuple(sorted(dropped)),
        redacted_paths=tuple(sorted(set(redacted))),
        highest=most_restrictive(grades),
        deployment_model=deployment_model,
        mode_banner=marker.marker if marker is not None else "",
        mutates=marker.mutates if marker is not None else False,
    )


def presentation_refusal(bundle: SupportBundle, *, as_production: bool = False) -> str:
    """Why ``bundle`` may not be presented as production diagnostics, or ``""``.

    A bundle sealed with a non-mutating mode banner describes a rehearsal, not
    an incident. Presenting it as production diagnostics would claim the
    customer's system was observed under load that was never applied.
    """
    if not as_production:
        return ""
    if bundle.mode_banner and not bundle.mutates:
        return (
            f"support.non_production_bundle: this bundle was sealed as "
            f"{bundle.mode_banner!r}, so it may not be presented as production "
            "diagnostics. The observations describe a run in which no mutation "
            "was performed"
        )
    return ""


#: The redaction rule version every bundle built here was scrubbed with.
#: Recorded so a support engineer can tell whether a bundle predates a rule fix.
BUNDLE_REDACTION_RULES: Final[tuple[str, ...]] = (REDACTION_RULE_VERSION,)
