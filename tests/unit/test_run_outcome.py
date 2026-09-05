"""Tests for Run and Outcome domain models and store persistence (ADR-M5-1, M5 Phase 5.1)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from mayhem.domain.run_outcome import Outcome, RunRecord, RunStatus, RunVerdict
from mayhem.infra.store import Store

if TYPE_CHECKING:
    from pathlib import Path

# ── Model tests ───────────────────────────────────────────────────────


class TestRunRecord:
    def test_defaults(self) -> None:
        run = RunRecord(
            run_id="r1",
            experiment_name="exp",
            spec_json="{}",
            plan_json="[]",
        )
        assert run.run_id == "r1"
        assert run.status == RunStatus.PENDING
        assert run.verdict == RunVerdict.PASS
        assert run.seed is None
        assert run.tags == ()
        assert run.extra == {}

    def test_all_fields(self) -> None:
        run = RunRecord(
            run_id="r2",
            experiment_name="exp",
            spec_json='{"key": "val"}',
            plan_json="[1,2,3]",
            seed=42,
            status=RunStatus.COMPLETED,
            environment_fingerprint="fp1",
            config_snapshot_id="cfg1",
            started_at="2026-01-01T00:00:00",
            ended_at="2026-01-01T00:01:00",
            description="test run",
            verdict=RunVerdict.FAIL,
            tags=("smoke", "p1"),
            extra={"note": "hello"},
        )
        assert run.seed == 42
        assert run.status == RunStatus.COMPLETED
        assert run.verdict == RunVerdict.FAIL
        assert run.tags == ("smoke", "p1")
        assert run.extra == {"note": "hello"}

    def test_wall_seconds_with_timestamps(self) -> None:
        run = RunRecord(
            run_id="r3",
            experiment_name="exp",
            spec_json="{}",
            plan_json="[]",
            started_at="2026-01-01T00:00:00",
            ended_at="2026-01-01T00:01:00",
        )
        assert run.wall_seconds == pytest.approx(60.0)

    def test_wall_seconds_without_timestamps(self) -> None:
        run = RunRecord(
            run_id="r4",
            experiment_name="exp",
            spec_json="{}",
            plan_json="[]",
        )
        assert run.wall_seconds == 0.0

    def test_summary_md_contains_key_fields(self) -> None:
        run = RunRecord(
            run_id="r5",
            experiment_name="exp",
            spec_json="{}",
            plan_json="[]",
            verdict=RunVerdict.FAIL,
            tags=("smoke",),
        )
        md = run.summary_md()
        assert "r5" in md
        assert "exp" in md
        assert "fail" in md
        assert "smoke" in md

    def test_frozen(self) -> None:
        run = RunRecord(
            run_id="r6",
            experiment_name="exp",
            spec_json="{}",
            plan_json="[]",
        )
        with pytest.raises(AttributeError):
            run.run_id = "r7"  # type: ignore[misc]


class TestOutcome:
    def test_defaults(self) -> None:
        oc = Outcome(run_id="r1")
        assert oc.run_id == "r1"
        assert oc.body_json == "{}"
        assert oc.checks_passed == 0
        assert oc.checks_failed == 0
        assert oc.metric_deltas == {}

    def test_all_checks_passed(self) -> None:
        oc = Outcome(run_id="r1", checks_passed=5, checks_failed=0)
        assert oc.all_checks_passed is True
        assert oc.total_checks == 5

    def test_some_checks_failed(self) -> None:
        oc = Outcome(run_id="r1", checks_passed=3, checks_failed=2)
        assert oc.all_checks_passed is False
        assert oc.total_checks == 5

    def test_no_checks(self) -> None:
        oc = Outcome(run_id="r1")
        assert oc.all_checks_passed is False
        assert oc.total_checks == 0

    def test_summary_md_with_failures(self) -> None:
        oc = Outcome(
            run_id="r1",
            checks_passed=3,
            checks_failed=1,
            metric_deltas={"latency": -0.5},
            residual_effect="none",
            stability_signal="stable",
        )
        md = oc.summary_md()
        assert "r1" in md
        assert "1/4" in md
        assert "latency" in md
        assert "stable" in md

    def test_frozen(self) -> None:
        oc = Outcome(run_id="r1")
        with pytest.raises(AttributeError):
            oc.run_id = "r2"  # type: ignore[misc]


# ── Store persistence tests ───────────────────────────────────────────


class TestRunRecordStore:
    def test_save_and_load_round_trip(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "m5.db")
        run = RunRecord(
            run_id="r-rt-1",
            experiment_name="drill-test",
            spec_json='{"fault": "net.delay"}',
            plan_json='[{"step": "inject"}]',
            seed=123,
            status=RunStatus.COMPLETED,
            environment_fingerprint="fp-abc",
            config_snapshot_id="cfg-1",
            started_at="2026-01-01T00:00:00",
            ended_at="2026-01-01T00:00:30",
            description="round-trip test",
            verdict=RunVerdict.PASS,
            tags=("smoke",),
            extra={"tool": "docker"},
        )
        store.save_run_record(run)
        loaded = store.load_run_record("r-rt-1")
        assert loaded is not None
        assert loaded.run_id == "r-rt-1"
        assert loaded.experiment_name == "drill-test"
        assert loaded.spec_json == '{"fault": "net.delay"}'
        assert loaded.plan_json == '[{"step": "inject"}]'
        assert loaded.seed == 123
        assert loaded.status == RunStatus.COMPLETED
        assert loaded.environment_fingerprint == "fp-abc"
        assert loaded.config_snapshot_id == "cfg-1"
        assert loaded.started_at == "2026-01-01T00:00:00"
        assert loaded.ended_at == "2026-01-01T00:00:30"
        assert loaded.description == "round-trip test"
        assert loaded.verdict == RunVerdict.PASS
        assert loaded.tags == ("smoke",)
        assert loaded.extra == {"tool": "docker"}

    def test_load_nonexistent_returns_none(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "m5.db")
        assert store.load_run_record("no-such-id") is None

    def test_overwrite_on_reinsert(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "m5.db")
        run1 = RunRecord(
            run_id="r-over",
            experiment_name="old",
            spec_json="{}",
            plan_json="[]",
        )
        store.save_run_record(run1)
        run2 = RunRecord(
            run_id="r-over",
            experiment_name="new",
            spec_json="{}",
            plan_json="[]",
        )
        store.save_run_record(run2)
        loaded = store.load_run_record("r-over")
        assert loaded is not None
        assert loaded.experiment_name == "new"


class TestOutcomeStore:
    def test_save_and_load_round_trip(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "m5.db")
        run = RunRecord(
            run_id="r-oc-1",
            experiment_name="exp",
            spec_json="{}",
            plan_json="[]",
        )
        store.save_run_record(run)
        outcome = Outcome(
            run_id="r-oc-1",
            body_json='{"status": "ok"}',
            body_hash="abc123",
            checks_passed=4,
            checks_failed=1,
            metric_deltas={"latency": -0.5, "throughput": 1.2},
            residual_effect="none",
            stability_signal="stable",
            extra={"source": "test"},
        )
        store.save_outcome(outcome)
        loaded = store.load_outcome("r-oc-1")
        assert loaded is not None
        assert loaded.run_id == "r-oc-1"
        assert loaded.body_json == '{"status": "ok"}'
        assert loaded.body_hash == "abc123"
        assert loaded.checks_passed == 4
        assert loaded.checks_failed == 1
        assert loaded.metric_deltas == {"latency": -0.5, "throughput": 1.2}
        assert loaded.residual_effect == "none"
        assert loaded.stability_signal == "stable"
        assert loaded.extra == {"source": "test"}

    def test_load_nonexistent_returns_none(self, tmp_path: Path) -> None:
        store = Store.open_migrated(tmp_path / "m5.db")
        assert store.load_outcome("no-such-id") is None


class TestRunOutcomeLinking:
    """ADR-M5-1: Run and Outcome persist separately and link by run_id."""

    def test_run_yields_one_run_one_outcome(self, tmp_path: Path) -> None:
        """Acceptance: a completed drill yields exactly one Run and one Outcome."""
        store = Store.open_migrated(tmp_path / "m5.db")
        run = RunRecord(
            run_id="drill-1",
            experiment_name="net-delay-drill",
            spec_json='{"fault": "net.delay", "target": "web-1"}',
            plan_json='[{"step": "inject", "target": "web-1"}]',
            seed=99,
            status=RunStatus.COMPLETED,
            verdict=RunVerdict.PASS,
            tags=("network",),
        )
        store.save_run_record(run)

        outcome = Outcome(
            run_id="drill-1",
            checks_passed=3,
            checks_failed=0,
            metric_deltas={"rtt_delta": 0.012},
            stability_signal="stable",
        )
        store.save_outcome(outcome)

        loaded_run = store.load_run_record("drill-1")
        loaded_outcome = store.load_outcome("drill-1")

        assert loaded_run is not None
        assert loaded_outcome is not None
        assert loaded_run.run_id == loaded_outcome.run_id
        assert loaded_run.experiment_name == "net-delay-drill"
        assert loaded_outcome.all_checks_passed is True
        assert loaded_outcome.metric_deltas == {"rtt_delta": 0.012}

    def test_no_conflation(self, tmp_path: Path) -> None:
        """Acceptance: no conflation — Run fields don't leak into Outcome."""
        store = Store.open_migrated(tmp_path / "m5.db")
        run = RunRecord(
            run_id="r-confl",
            experiment_name="exp-a",
            spec_json='{"x": 1}',
            plan_json="[]",
            verdict=RunVerdict.FAIL,
        )
        store.save_run_record(run)
        outcome = Outcome(run_id="r-confl", checks_failed=2)
        store.save_outcome(outcome)

        loaded_run = store.load_run_record("r-confl")
        loaded_outcome = store.load_outcome("r-confl")

        assert loaded_run is not None
        assert loaded_outcome is not None
        # Run holds spec/plan/verdict; Outcome holds checks — separate tables
        assert loaded_run.spec_json == '{"x": 1}'
        assert loaded_run.verdict == RunVerdict.FAIL
        assert loaded_outcome.checks_failed == 2
        # The round-tripped Outcome never adopted Run-only fields
        assert loaded_outcome.extra == {}
        assert loaded_outcome.body_json == "{}"

    def test_separate_persistence(self, tmp_path: Path) -> None:
        """Acceptance: Run and Outcome persist separately."""
        store = Store.open_migrated(tmp_path / "m5.db")
        run = RunRecord(
            run_id="r-sep",
            experiment_name="exp",
            spec_json="{}",
            plan_json="[]",
        )
        store.save_run_record(run)

        # Run exists, Outcome doesn't
        assert store.load_run_record("r-sep") is not None
        assert store.load_outcome("r-sep") is None

        # Now add Outcome
        outcome = Outcome(run_id="r-sep", checks_passed=1)
        store.save_outcome(outcome)

        # Both exist independently
        assert store.load_run_record("r-sep") is not None
        assert store.load_outcome("r-sep") is not None

    def test_migration_m5_1_applied(self, tmp_path: Path) -> None:
        """Acceptance: migration M5-1 applied; run/outcome queryable."""
        store = Store.open_migrated(tmp_path / "m5.db")
        assert store.schema_version == 14
        # Verify tables exist by inserting and querying
        run = RunRecord(
            run_id="r-mig",
            experiment_name="exp",
            spec_json="{}",
            plan_json="[]",
        )
        store.save_run_record(run)
        assert store.load_run_record("r-mig") is not None
