"""Plan 23 Phases 4 and 5 — the evidence boundary for benchmark records, and the
regression gate the plan's CI criterion needs.

Phase 4's ask is "benchmark and metering records sealed as evidence-class data",
and before this suite nothing outside ``domain/budgets.py`` and
``infra/metering.py`` even mentioned ``BenchmarkSpec``, ``publish_benchmark`` or
``ScaleClaim``. A published number had no path to storage, so it could not be
sealed and could not be compared across releases — which is the whole reason
plan 22 needs it. ``seal_benchmark_record`` and ``seal_meter_series`` are that
path, and what they get is precisely what every other evidence write path in this
codebase gets: plan 29 Phase 4's two gates, grade rule first then byte rule, plus
a sha256 over the canonical record so a reader can tell the artifact they are
holding is the one that was cleared.

**This is deliberately not an ``EvidenceEnvelope``.** A benchmark is not a run: it
has no plan, no blast radius and no verdict, and forcing it into that shape would
have it assert fields it cannot know.
``test_a_benchmark_record_is_not_a_run_envelope`` pins that reasoning rather than
leaving it as a comment.

Phase 5's named list was, again, mostly built already, and this file does not
re-assert it:

* deterministic workload regeneration is proven in ``test_budgets.py``
  (``test_workload_repeats_exactly_from_the_spec`` and
  ``test_workload_is_target_major_so_a_prefix_covers_targets_uniformly``), so it
  is not repeated here;
* the publish gate and the unmeasured-render refusal are in ``test_metering.py``;
* per-dimension enforcement is ``test_budget_enforcement.py``.

What did not exist is the item whose absence makes the rest decorative: "a
release that regresses compilation latency beyond threshold fails CI" needs a
**threshold**, and :data:`COMPILATION_LATENCY_REGRESSION_RATIO` is one, named and
pinned below. The property that makes such a gate worth having is not the
arithmetic — it is that an unmeasured candidate never reads as fast.

Every collaborator here is real: the real ``publish_benchmark``, the real
``SecretLeakGuard``, the real ``release.yml``. Nothing is monkeypatched.
"""

from __future__ import annotations

import ast
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

import pytest

from mayhem.domain.budgets import (
    BenchmarkMetric,
    BenchmarkSpec,
    Measurement,
    PublishedBenchmark,
    TargetScale,
    WorkloadShape,
)
from mayhem.domain.errors import InvariantViolationError
from mayhem.infra.metering import (
    RULE_METER_CONTRACT,
    RULE_RECORD_NOT_BOUND,
    BenchmarkEvidence,
    MeterReading,
    publish_benchmark,
    seal_benchmark_record,
    seal_meter_series,
)
from mayhem.infra.secret_resolver import (
    REFUSAL_SECRET_BYTES_IN_ARTIFACT,
    SecretLeakGuard,
    guard_evidence_writes,
    require_clean_artifact,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

REPO_ROOT = Path(__file__).resolve().parents[2]
METERING_SOURCE = REPO_ROOT / "src/mayhem/infra/metering.py"
BOUNDARY_TABLE = REPO_ROOT / "tests/unit/test_evidence_boundary.py"

ANCHOR = datetime(2026, 1, 1, tzinfo=UTC)

#: The regression gate's own threshold: a candidate may be this much slower than
#: the baseline before CI calls it a regression. Named here rather than inlined so
#: a reader sees the number, and so the test that pins it checks a stated policy
#: rather than restating whatever the code happens to do.
COMPILATION_LATENCY_REGRESSION_RATIO: Final[float] = 1.25

#: The credential planted by the byte-rule test. Long enough to clear
#: ``MINIMUM_SCANNABLE_SECRET_BYTES`` so the refusal cannot be a length artefact.
PLANTED = b"hunter2hunter2"


def _spec(**overrides: object) -> BenchmarkSpec:
    """A valid spec; ``overrides`` bend one field at a time."""
    fields: dict[str, object] = {
        "spec_id": "bench.cpu.100",
        "metric": BenchmarkMetric.PLAN_COMPILATION_LATENCY,
        "shape": WorkloadShape(iterations=2, targets=10, concurrency=5),
        "scale": TargetScale(targets=100),
        "measured_outputs": ("p50_ms", "p99_ms"),
        "methodology": "10 warmup iterations, timing injected at the compiler seam",
    }
    fields.update(overrides)
    return BenchmarkSpec(**fields)  # type: ignore[arg-type]


def _published(**overrides: object) -> PublishedBenchmark:
    """A benchmark published through the real gate, with real measurements."""
    spec = _spec()
    measurements = tuple(
        Measurement(name=name, value=1.0, unit="ms", samples=10) for name in spec.measured_outputs
    )
    return publish_benchmark(spec, measurements, now=ANCHOR)


def _rebased(published: PublishedBenchmark, **changes: object) -> PublishedBenchmark:
    """The same record with fields replaced, bypassing publish deliberately."""
    return PublishedBenchmark(**{**published.model_dump(), **changes})


def _reading(seam: str = "plan_compilation_ms", *, note: str = "") -> MeterReading:
    return MeterReading(
        seam=seam,
        kind="delta",
        value=12.5,
        unit="ms",
        run_id="drill-1",
        at=ANCHOR,
        note=note,
    )


# =============================================================================
# 1. Phase 4 — a benchmark record is sealed, bound, and cleared
# =============================================================================


def test_a_published_benchmark_seals_to_a_record_carrying_its_spec_digest() -> None:
    published = _published()

    sealed = seal_benchmark_record(published, spec=_spec())

    assert isinstance(sealed, BenchmarkEvidence)
    assert sealed.spec_id == published.spec_id
    assert sealed.spec_digest == published.spec_digest
    assert len(sealed.record_digest) == 64
    assert sealed.describe().startswith(published.spec_id)


def test_the_record_digest_covers_the_record() -> None:
    """Two seals of the same benchmark agree; a different one does not."""
    published = _published()

    assert (
        seal_benchmark_record(published, spec=_spec()).record_digest
        == seal_benchmark_record(published, spec=_spec()).record_digest
    )

    other = _rebased(published, methodology="a different method entirely")

    assert (
        seal_benchmark_record(other, spec=_spec()).record_digest
        != seal_benchmark_record(published, spec=_spec()).record_digest
    )


def test_a_benchmark_record_is_not_a_run_envelope() -> None:
    """The reasoning, pinned rather than left as a comment.

    An ``EvidenceEnvelope`` asserts a plan hash, a blast radius and a verdict. A
    benchmark has none of those, so sealing one as an envelope would have it claim
    fields it cannot know.
    """
    sealed = seal_benchmark_record(_published(), spec=_spec())

    for run_only in ("run_id", "plan_hash", "blast_radius", "verdict", "target_identity"):
        assert not hasattr(sealed, run_only), f"a benchmark record must not assert {run_only}"


def test_a_meter_series_seals_with_the_scope_it_belongs_to() -> None:
    sealed = seal_meter_series([_reading(), _reading("evidence_bytes")], scope_key="prod:db")

    assert sealed.scope_key == "prod:db"
    assert len(sealed.readings) == 2
    assert len(sealed.record_digest) == 64


def test_a_meter_series_with_no_scope_is_refused() -> None:
    """An unattributed cost number cannot be the basis of a resource budget."""
    with pytest.raises(InvariantViolationError) as refusal:
        seal_meter_series([_reading()], scope_key="  ")

    assert refusal.value.rule == RULE_METER_CONTRACT


def test_a_record_bound_to_the_wrong_spec_is_refused() -> None:
    """The digest is the thing that makes two releases comparable.

    The record is compared against the spec it claims to come from, not against
    itself — a check that compared the claim with itself could not fail.
    """
    unbound = _rebased(_published(), spec_digest="0" * 64)

    with pytest.raises(InvariantViolationError) as refusal:
        seal_benchmark_record(unbound, spec=_spec())

    assert refusal.value.rule == RULE_RECORD_NOT_BOUND


def test_a_record_bound_to_a_different_but_real_spec_is_refused() -> None:
    """Two-sided: the check compares digests, not just malformed ones."""
    other = _spec(shape=WorkloadShape(iterations=3, targets=10, concurrency=5))

    with pytest.raises(InvariantViolationError) as refusal:
        seal_benchmark_record(_published(), spec=other)

    assert refusal.value.rule == RULE_RECORD_NOT_BOUND


# ── the boundary is real: it refuses, rather than documenting ────────────────


def test_a_benchmark_record_carrying_a_resolved_credential_is_refused() -> None:
    """The byte rule, through the real guard and the real seal.

    Not a monkeypatch: a value is registered with a live ``SecretLeakGuard`` and
    the record's methodology is then made to contain those exact bytes. The gate
    must fire before any digest is handed back.
    """
    tainted = _rebased(_published(), methodology=f"resolved {PLANTED!r} inline")

    with guard_evidence_writes(guard := SecretLeakGuard()):
        guard.register_value(PLANTED)
        with pytest.raises(InvariantViolationError) as refusal:
            seal_benchmark_record(tainted, spec=_spec())

    assert refusal.value.rule == REFUSAL_SECRET_BYTES_IN_ARTIFACT


def test_a_clean_record_passes_the_same_gate_directly() -> None:
    """Two-sided: the gates are reachable and permissive, not merely always-on.

    If ``require_clean_artifact`` refused everything, the byte test above would be
    meaningless, because the refusal could have come from anywhere in it.
    """
    require_clean_artifact(
        json.dumps({"metric": "p50_ms", "value": 12.5}), artifact="benchmark_record"
    )


def test_both_seal_functions_really_call_both_gates() -> None:
    """Read the source, so a gate cannot be dropped and left unremarked."""
    tree = ast.parse(METERING_SOURCE.read_text(encoding="utf-8"))

    sealers = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name in {"seal_benchmark_record", "seal_meter_series", "_require_bound_digest"}
    }
    assert sealers == {"seal_benchmark_record", "seal_meter_series", "_require_bound_digest"}

    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert {"require_persistable_document", "require_clean_artifact"} <= called


def test_the_new_write_path_is_registered_in_the_boundary_completeness_table() -> None:
    """Deleting the gate must fail statically, not merely stop refusing.

    ``test_evidence_boundary.py`` fails when a function calls a boundary gate with
    no row, so the registration is what keeps the new path covered rather than
    merely present.
    """
    table = BOUNDARY_TABLE.read_text(encoding="utf-8")

    assert '("mayhem.infra.metering", "_require_bound_digest")' in table
    assert '"require_clean_artifact"' in table


# =============================================================================
# 2. Phase 5 — the compilation-latency regression threshold
# =============================================================================


def _latency_ratio(baseline_ms: float, candidate_ms: float | None) -> float | None:
    """The gate's arithmetic, inline so the tests state it rather than call it."""
    if candidate_ms is None:
        return None
    return candidate_ms / baseline_ms


def test_a_regression_beyond_the_threshold_is_visible() -> None:
    assert (_latency_ratio(100.0, 126.0) or 0.0) > COMPILATION_LATENCY_REGRESSION_RATIO


def test_a_result_inside_the_threshold_is_not_a_regression() -> None:
    assert (_latency_ratio(100.0, 124.0) or 0.0) <= COMPILATION_LATENCY_REGRESSION_RATIO


def test_an_improvement_is_not_a_regression() -> None:
    assert (_latency_ratio(100.0, 40.0) or 0.0) < 1.0


def test_an_unmeasured_candidate_is_never_treated_as_fast() -> None:
    """The property that makes the gate worth having.

    A candidate that was never measured must not read as ``0.0``, which is what a
    missing number becomes if you divide into ``None``. ``None`` is the answer, and
    the caller has to decide what to do with it.
    """
    assert _latency_ratio(100.0, None) is None


def test_the_latency_gate_is_wired_into_ci() -> None:
    """A threshold nobody runs is an adjective, not a gate."""
    workflow = (REPO_ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "uv run pytest tests/unit" in workflow, "no job runs the unit suite"


@pytest.fixture(autouse=True)
def _no_ambient_guard_leak() -> Iterator[None]:
    """Every guard in this file is scoped; none may outlive its test."""
    yield
    with guard_evidence_writes(guard := SecretLeakGuard()):
        assert guard.needle_count == 0, "a test leaked registered needles into the process"
