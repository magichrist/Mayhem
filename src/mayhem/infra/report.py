"""M5 report + experiment guidance builder (M5 Phase 5.7).

Consumes Run/Outcome history, coverage, and the Maniac candidate backlog to
produce a rich, model-only report:
  - a coverage heatmap (rendered ASCII grid),
  - per-cell verdicts with supported-by evidence (run links),
  - the candidate backlog ranked by Maniac score,
  - the guided "what to run next" list (untouched/``UNKNOWN`` cells).

The builder is deterministic and pure: given the same history it always
renders the same report. Assertions in tests are model/string level.
"""

from __future__ import annotations

import html
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from mayhem.infra.candidate_gates import CandidateGatePipeline
from mayhem.infra.maniac import SelectionInputs, select_next

if TYPE_CHECKING:
    from mayhem.domain.candidates import ExperimentCandidate
    from mayhem.domain.coverage import CoverageCell, CoverageRecord
    from mayhem.domain.evidence import EvidenceEnvelope
    from mayhem.domain.run_outcome import Outcome, RunRecord

# Verdict / heatmap symbols.
_CELL_COVERED = "█"
_CELL_UNKNOWN = "·"


class _PermissiveGate:
    """A gate that passes every candidate (used when no gates are given)."""

    def check(self, candidate: object) -> str | None:
        return None


def _permissive_gates() -> CandidateGatePipeline:
    return CandidateGatePipeline(safety=_PermissiveGate(), feasibility=_PermissiveGate())


@dataclass(frozen=True)
class CellVerdictReport:
    """One cell's verdict plus the runs that support/evidence it."""

    cell: CoverageCell
    covered: bool
    run_ids: tuple[str, ...] = ()
    verdict: str = "UNKNOWN"


@dataclass(frozen=True)
class M5Report:
    """Rendered report over a landscape + recorded history."""

    landscape: tuple[CoverageCell, ...] = ()
    heatmap: str = ""
    cell_verdicts: tuple[CellVerdictReport, ...] = ()
    coverage_fraction: float = 0.0
    next_to_run: tuple[CoverageCell, ...] = ()
    ranked_backlog: tuple[ExperimentCandidate, ...] = ()

    def render_markdown(self) -> str:
        """Render the whole report as a markdown string."""
        lines = [
            "# M5 Campaign Report",
            "",
            "## Coverage",
            "",
            self.heatmap,
            "",
            f"**coverage**: {self.coverage_fraction:.1%} of the landscape covered",
            "",
            "## Per-cell verdicts",
            "",
        ]
        if not self.cell_verdicts:
            lines.append("_no cells recorded_")
        else:
            lines.append("| cell | verdict | evidence runs |")
            lines.append("| --- | --- | --- |")
            for v in self.cell_verdicts:
                ev = ", ".join(v.run_ids) if v.run_ids else "—"
                lines.append(f"| `{v.cell.key}` | {v.verdict} | {ev} |")
        lines.append("")
        lines.append("## What to run next")
        lines.append("")
        if self.next_to_run:
            for cell in self.next_to_run:
                lines.append(f"- `{cell.key}` (UNKNOWN)")
        else:
            lines.append("_no gap remains_")
        lines.append("")
        lines.append("## Candidate backlog (Maniac-ranked)")
        lines.append("")
        if self.ranked_backlog:
            for i, cand in enumerate(self.ranked_backlog, 1):
                lines.append(f"{i}. `{cand.id}` -> {cand.target} [{cand.primary_fault}]")
        else:
            lines.append("_backlog empty_")
        return "\n".join(lines) + "\n"


def _cell_verdict(
    covered: bool,
    run_ids: tuple[str, ...],
    runs: dict[str, RunRecord],
    outcomes: dict[str, Outcome],
) -> str:
    """Derive a verdict for a cell from its evidence (Runs/Outcomes)."""
    if not covered or not run_ids:
        return "UNKNOWN"
    # Use the most recent run's outcome as the cell verdict.
    for run_id in reversed(run_ids):
        outcome = outcomes.get(run_id)
        if outcome is not None and outcome.total_checks > 0:
            return "PASS" if outcome.all_checks_passed else "FAIL"
    # No outcome with checks; fall back to the run verdict if it FAILED.
    for run_id in reversed(run_ids):
        run = runs.get(run_id)
        if run is not None and run.verdict.value == "fail":
            return "FAIL"
    return "PASS"


def render_heatmap(
    landscape: tuple[CoverageCell, ...],
    covered_keys: frozenset[str],
) -> str:
    """Render a compact ASCII heatmap: targets (rows) x faults (cols).

    A cell is marked covered when any landscape cell in that (target, fault)
    group is covered. Unknown cells use ``·``, covered cells use ``█``.
    """
    targets: list[str] = []
    faults: list[str] = []
    seen_cells: dict[tuple[str, str], bool] = {}
    for cell in landscape:
        group = (cell.target, cell.fault_kind)
        covered = cell.key in covered_keys
        if group not in seen_cells or (covered and not seen_cells[group]):
            seen_cells[group] = covered
        if cell.target not in targets:
            targets.append(cell.target)
        if cell.fault_kind not in faults:
            faults.append(cell.fault_kind)

    header = "        " + " ".join(f"{f:<6}" for f in faults)
    lines = [header]
    for t in targets:
        row_parts = []
        for f in faults:
            covered = seen_cells.get((t, f), False)
            row_parts.append(f"{_CELL_COVERED if covered else _CELL_UNKNOWN:<6}")
        lines.append(f"{t:<8} " + " ".join(row_parts))
    lines.append("")
    lines.append(f"legend: {_CELL_COVERED}=covered  {_CELL_UNKNOWN}=unknown")
    return "\n".join(lines)


def build_m5_report(
    *,
    landscape: tuple[CoverageCell, ...],
    covered_records: tuple[CoverageRecord, ...] = (),
    runs: dict[str, RunRecord] | None = None,
    outcomes: dict[str, Outcome] | None = None,
    candidates: tuple[ExperimentCandidate, ...] = (),
    gates: CandidateGatePipeline | None = None,
    seed: int = 0,
    max_runs: int = 50,
) -> M5Report:
    """Assemble the report from recorded history (pure/deterministic)."""
    runs = runs or {}
    outcomes = outcomes or {}

    covered_keys: set[str] = set()
    run_ids_by_cell: dict[str, list[str]] = {}
    for rec in covered_records:
        covered_keys.add(rec.cell.key)
        run_ids_by_cell.setdefault(rec.cell.key, []).append(rec.run_id)

    covered_count = len(covered_keys)
    fraction = covered_count / len(landscape) if landscape else 0.0

    verdicts = tuple(
        CellVerdictReport(
            cell=cell,
            covered=cell.key in covered_keys,
            run_ids=tuple(run_ids_by_cell.get(cell.key, ())),
            verdict=_cell_verdict(
                cell.key in covered_keys,
                tuple(run_ids_by_cell.get(cell.key, ())),
                runs,
                outcomes,
            ),
        )
        for cell in landscape
    )

    unknown = [cell for cell in landscape if cell.key not in covered_keys]

    # Candidate backlog ranked by Maniac (deterministic greedy coverage).
    ranked: tuple[ExperimentCandidate, ...] = ()
    if candidates:
        result = select_next(
            SelectionInputs(
                candidates=candidates,
                covered_keys=frozenset(covered_keys),
                gates=gates if gates is not None else _permissive_gates(),
                max_runs=max_runs,
                coverage_target=max(len(landscape), 1),
                seed=seed,
            )
        )
        ranked = result.selected

    heatmap = render_heatmap(landscape, frozenset(covered_keys))

    return M5Report(
        landscape=landscape,
        heatmap=heatmap,
        cell_verdicts=verdicts,
        coverage_fraction=fraction,
        next_to_run=tuple(unknown),
        ranked_backlog=ranked,
    )


_SECRET_KEYS = frozenset(
    {
        "password",
        "secret",
        "token",
        "credentials",
        "api_key",
        "apikey",
        "kubeconfig",
        "registry_token",
        "registry_tokens",
        "secret_value",
        "secrets",
    }
)
_ENVIRONMENT_KEYS = frozenset(
    {
        "logical_target",
        "resolved_target",
        "target_identity",
        "k8s_context",
        "k8s_namespace",
    }
)
_PATH_PATTERN = re.compile(r"(?:/Users/|/home/)[^/\s]+(?:/[^\s]*)?|(?:[A-Za-z]:\\Users\\)[^\s]*")


def report_id_for_run(run_id: str) -> str:
    safe = "".join(
        character if character.isalnum() or character in "-_" else "_"
        for character in run_id
    )
    return f"report-{safe}"


def redact_report_data(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            lowered = key.lower()
            if lowered in _SECRET_KEYS or any(
                token in lowered for token in ("password", "token", "secret")
            ):
                redacted[key] = "***REDACTED***"
            elif lowered in _ENVIRONMENT_KEYS:
                redacted[key] = "<redacted-environment>"
            else:
                redacted[key] = redact_report_data(item)
        return redacted
    if isinstance(value, list):
        return [redact_report_data(item) for item in value]
    if isinstance(value, tuple):
        return [redact_report_data(item) for item in value]
    if isinstance(value, str):
        return _PATH_PATTERN.sub("<redacted-path>", value)
    return value


def _report_id(envelope: EvidenceEnvelope) -> str:
    return envelope.report_id or report_id_for_run(envelope.run_id)


def _report_document(envelope: EvidenceEnvelope) -> dict[str, Any]:
    evidence = redact_report_data(envelope.model_dump(mode="json"))
    report_id = _report_id(envelope)
    basis = envelope.verification_basis or "unknown"
    verdict = envelope.verdict or "unrecorded"
    recovery = envelope.recovery_state or "unknown"
    timeline = [
        {"kind": "step", **item} for item in evidence.get("step_reports", [])
    ] + [{"kind": "lease", **item} for item in evidence.get("lease_timeline", [])]
    return {
        "report_id": report_id,
        "executive_summary": (
            f"Run {envelope.run_id} ended with verdict {verdict}; recovery is {recovery}."
        ),
        "environment": {
            "engine": envelope.engine or "unknown",
            "engine_version": envelope.engine_version,
            "target_profile": envelope.target_profile or "none",
            "environment_fingerprint": envelope.environment_fingerprint or "unknown",
            "topology_fingerprint": envelope.topology_fingerprint,
            "drift_status": envelope.drift_status or "not recorded",
        },
        "plan": {
            "plan_id": envelope.plan_id or envelope.run_id,
            "plan_hash": envelope.plan_hash,
            "blast_radius": evidence.get("blast_radius", {}),
        },
        "safety_decisions": list(envelope.safety_decisions),
        "timeline": timeline,
        "observations": evidence.get("observations", []),
        "verdict": verdict,
        "recovery": {
            "state": recovery,
            "compensation": envelope.compensation_status or "not recorded",
            "remediation": list(envelope.remediation),
        },
        "limitations": {
            "verification_basis": basis,
            "unit_tested_behavior_is_not_live_verified": basis != "live",
            "rendering_does_not_execute_or_compensate_targets": True,
            "redaction_applied": True,
        },
        "evidence": evidence,
    }


def render_report_json(envelope: EvidenceEnvelope) -> str:
    return json.dumps(_report_document(envelope), indent=2, sort_keys=True)


def _markdown_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def render_report_markdown(envelope: EvidenceEnvelope) -> str:
    document = _report_document(envelope)
    lines = [
        f"# Mayhem Report {document['report_id']}",
        "",
        "## Executive Summary",
        "",
        document["executive_summary"],
        "",
        "## Environment",
        "",
    ]
    for key, value in document["environment"].items():
        lines.append(f"- **{key}**: {_markdown_value(value)}")
    lines.extend(["", "## Plan", ""])
    for key, value in document["plan"].items():
        lines.append(f"- **{key}**: {_markdown_value(value)}")
    lines.extend(["", "## Safety Decisions", ""])
    lines.extend(
        [f"- {decision}" for decision in document["safety_decisions"]]
        or ["- No decisions recorded"]
    )
    lines.extend(["", "## Timeline", ""])
    lines.extend(
        [f"- {_markdown_value(item)}" for item in document["timeline"]]
        or ["- No timeline evidence recorded"]
    )
    lines.extend(["", "## Observations", ""])
    lines.extend(
        [f"- {_markdown_value(item)}" for item in document["observations"]]
        or ["- No observations recorded"]
    )
    lines.extend(["", "## Verdict", "", f"**{document['verdict']}**", "", "## Recovery", ""])
    for key, value in document["recovery"].items():
        lines.append(f"- **{key}**: {_markdown_value(value)}")
    lines.extend(["", "## Limitations", ""])
    for key, value in document["limitations"].items():
        lines.append(f"- **{key}**: {_markdown_value(value)}")
    return "\n".join(lines) + "\n"


def _html_section(title: str, body: Any) -> str:
    if isinstance(body, list):
        content = "".join(f"<li>{html.escape(_markdown_value(item))}</li>" for item in body)
        return f"<section><h2>{html.escape(title)}</h2><ul>{content}</ul></section>"
    if isinstance(body, dict):
        rows = "".join(
            f"<dt>{html.escape(str(key))}</dt><dd>{html.escape(_markdown_value(value))}</dd>"
            for key, value in body.items()
        )
        return f"<section><h2>{html.escape(title)}</h2><dl>{rows}</dl></section>"
    return (
        f"<section><h2>{html.escape(title)}</h2>"
        f"<p>{html.escape(_markdown_value(body))}</p></section>"
    )


def render_report_html(envelope: EvidenceEnvelope) -> str:
    document = _report_document(envelope)
    sections = "".join(
        _html_section(title, document[key])
        for key, title in (
            ("executive_summary", "Executive Summary"),
            ("environment", "Environment"),
            ("plan", "Plan"),
            ("safety_decisions", "Safety Decisions"),
            ("timeline", "Timeline"),
            ("observations", "Observations"),
            ("verdict", "Verdict"),
            ("recovery", "Recovery"),
            ("limitations", "Limitations"),
        )
    )
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>Mayhem {html.escape(document['report_id'])}</title></head>"
        f"<body><h1>Mayhem Report {html.escape(document['report_id'])}</h1>{sections}</body></html>"
    )


@dataclass(frozen=True)
class ReportArtifactPolicy:
    artifact_dir: Path
    retention_days: int = 30
    max_reports: int = 100


def apply_report_retention(
    artifact_dir: str | Path,
    *,
    retention_days: int,
    max_reports: int,
    now_epoch_s: float | None = None,
) -> tuple[Path, ...]:
    directory = Path(artifact_dir)
    if not directory.exists():
        return ()
    current = time.time() if now_epoch_s is None else now_epoch_s
    cutoff = current - max(0, retention_days) * 24 * 60 * 60
    groups: dict[str, list[Path]] = {}
    newest: dict[str, float] = {}
    for path in directory.glob("report-*.*"):
        if path.suffix not in {".md", ".json", ".html"}:
            continue
        groups.setdefault(path.stem, []).append(path)
        newest[path.stem] = max(newest.get(path.stem, 0), path.stat().st_mtime)
    retained = {
        report_id
        for report_id, _ in sorted(newest.items(), key=lambda item: item[1], reverse=True)[
            : max(1, max_reports)
        ]
    }
    removed: list[Path] = []
    for report_id, paths in groups.items():
        for path in paths:
            if report_id not in retained or path.stat().st_mtime < cutoff:
                path.unlink(missing_ok=True)
                removed.append(path)
    return tuple(removed)


def write_report_artifacts(
    envelope: EvidenceEnvelope,
    *,
    policy: ReportArtifactPolicy | None = None,
    artifact_dir: str | Path | None = None,
    formats: tuple[str, ...] = ("markdown", "json", "html"),
) -> dict[str, Path]:
    selected_policy = policy or ReportArtifactPolicy(
        artifact_dir=Path(artifact_dir or ".mayhem/artifacts")
    )
    directory = Path(selected_policy.artifact_dir)
    directory.mkdir(parents=True, exist_ok=True)
    report_id = _report_id(envelope)
    renderers = {
        "markdown": ("md", render_report_markdown),
        "json": ("json", render_report_json),
        "html": ("html", render_report_html),
    }
    paths: dict[str, Path] = {}
    for format_name in formats:
        if format_name not in renderers:
            raise ValueError(f"unsupported report format: {format_name}")
        suffix, renderer = renderers[format_name]
        path = directory / f"{report_id}.{suffix}"
        path.write_text(renderer(envelope))
        paths[format_name] = path
    apply_report_retention(
        directory,
        retention_days=selected_policy.retention_days,
        max_reports=selected_policy.max_reports,
    )
    return paths


def compare_reports(
    before: EvidenceEnvelope,
    after: EvidenceEnvelope,
) -> dict[str, Any]:
    def changed(left: Any, right: Any) -> bool:
        return left != right

    return {
        "before_report_id": _report_id(before),
        "after_report_id": _report_id(after),
        "verdict": {
            "before": before.verdict,
            "after": after.verdict,
            "changed": changed(before.verdict, after.verdict),
        },
        "recovery": {
            "before": before.recovery_state,
            "after": after.recovery_state,
            "changed": changed(before.recovery_state, after.recovery_state),
        },
        "environment": {
            "before": before.environment_fingerprint,
            "after": after.environment_fingerprint,
            "changed": changed(before.environment_fingerprint, after.environment_fingerprint),
        },
        "step_count": {
            "before": len(before.step_reports),
            "after": len(after.step_reports),
            "changed": changed(len(before.step_reports), len(after.step_reports)),
        },
        "observation_count": {
            "before": len(before.observations),
            "after": len(after.observations),
            "changed": changed(len(before.observations), len(after.observations)),
        },
    }
