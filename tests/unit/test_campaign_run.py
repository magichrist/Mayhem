"""Campaign sequence orchestrator unit tests (ADR-0023 policy).

These drive :func:`run_campaign_sequence` with a fake per-spec runner so the
failure/retry/deadline policy matrix is exercised without a real engine.
"""

from __future__ import annotations

import pytest

from mayhem.cli.services import CampaignExecutionError, run_campaign_sequence
from mayhem.controller.executor import RunResult


def _result(run_id: str, status: str = "completed") -> RunResult:
    return RunResult(
        run_id=run_id,
        status=status,
        started_at_epoch_s=0.0,
        ended_at_epoch_s=1.0,
    )


class _ObsStore:
    """Minimal stand-in for Store.save_observation (recorded in-memory)."""

    def __init__(self) -> None:
        self.rows: list[tuple[str, str, str, dict[str, object]]] = []

    def save_observation(
        self,
        kind: str,
        *,
        run_id: str = "",
        source: str = "",
        data: dict[str, object] | None = None,
    ) -> None:
        self.rows.append((kind, run_id, source, data or {}))

    def observations(self, kind: str) -> list[tuple[str, str, str, dict[str, object]]]:
        return [row for row in self.rows if row[0] == kind]


def _run(calls: list[str], *statuses: str):
    def run_one(spec_path: str) -> RunResult:
        calls.append(spec_path)
        status = statuses[len(calls) - 1] if len(calls) <= len(statuses) else "completed"
        return _result(f"r-{len(calls)}", status)

    return run_one


class TestAbortPolicy:
    def test_all_complete_marks_campaign_done(self) -> None:
        calls: list[str] = []
        store = _ObsStore()
        result = run_campaign_sequence(
            campaign_id="c-1",
            experiments=["a.yaml", "b.yaml"],
            policy={"on_experiment_failure": "abort_campaign"},
            window={},
            store=store,
            run_one=_run(calls, "completed", "completed"),
        )
        assert result.status == "completed"
        assert [e.spec_path for e in result.runs] == ["a.yaml", "b.yaml"]
        assert calls == ["a.yaml", "b.yaml"]
        assert len(store.observations("campaign_run")) == 2
        assert len(store.observations("campaign_done")) == 1

    def test_first_failure_aborts_immediately(self) -> None:
        calls: list[str] = []
        store = _ObsStore()
        result = run_campaign_sequence(
            campaign_id="c-1",
            experiments=["a.yaml", "b.yaml", "c.yaml"],
            policy={"on_experiment_failure": "abort_campaign"},
            window={},
            store=store,
            run_one=_run(calls, "failed", "completed"),
        )
        assert result.status == "failed"
        assert [e.status for e in result.runs] == ["failed"]
        assert calls == ["a.yaml"], "later specs must not run after abort"
        assert store.observations("campaign_done") == []


class TestSkipAndContinue:
    def test_failed_spec_is_skipped_and_sequence_continues(self) -> None:
        calls: list[str] = []
        store = _ObsStore()
        result = run_campaign_sequence(
            campaign_id="c-1",
            experiments=["a.yaml", "b.yaml"],
            policy={"on_experiment_failure": "skip_and_continue"},
            window={},
            store=store,
            run_one=_run(calls, "failed", "completed"),
        )
        assert result.status == "completed"
        assert [e.spec_path for e in result.runs] == ["a.yaml", "b.yaml"]
        assert [e.status for e in result.runs] == ["failed", "completed"]
        assert calls == ["a.yaml", "b.yaml"]
        assert len(store.observations("campaign_done")) == 1

    def test_exception_is_swallowed_and_sequence_continues(self) -> None:
        calls: list[str] = []

        def run_one(spec_path: str) -> RunResult:
            calls.append(spec_path)
            if len(calls) == 1:
                raise ValueError("boom")
            return _result("r-2")

        store = _ObsStore()
        result = run_campaign_sequence(
            campaign_id="c-1",
            experiments=["a.yaml", "b.yaml"],
            policy={"on_experiment_failure": "skip_and_continue"},
            window={},
            store=store,
            run_one=run_one,
        )
        assert result.status == "completed"
        assert len(result.runs) == 1  # only the successful spec recorded


class TestRetryThenAbort:
    def test_single_retry_succeeds(self) -> None:
        calls: list[str] = []

        def run_one(spec_path: str) -> RunResult:
            calls.append(spec_path)
            return _result("r-1", "failed") if len(calls) == 1 else _result("r-2")

        store = _ObsStore()
        result = run_campaign_sequence(
            campaign_id="c-1",
            experiments=["a.yaml"],
            policy={"on_experiment_failure": "retry_then_abort"},
            window={},
            store=store,
            run_one=run_one,
        )
        assert result.status == "completed"
        assert calls == ["a.yaml", "a.yaml"]
        assert [e.status for e in result.runs] == ["failed", "completed"]
        assert len(store.observations("campaign_run")) == 2

    def test_retry_failure_aborts(self) -> None:
        calls: list[str] = []

        def run_one(spec_path: str) -> RunResult:
            calls.append(spec_path)
            return _result("r-1", "failed")

        store = _ObsStore()
        result = run_campaign_sequence(
            campaign_id="c-1",
            experiments=["a.yaml", "b.yaml"],
            policy={"on_experiment_failure": "retry_then_abort"},
            window={},
            store=store,
            run_one=run_one,
        )
        assert result.status == "failed"
        assert calls.count("a.yaml") == 2
        assert "b.yaml" not in calls

    def test_policy_default_is_abort(self) -> None:
        calls: list[str] = []
        result = run_campaign_sequence(
            campaign_id="c-1",
            experiments=["a.yaml", "b.yaml"],
            policy={},
            window={},
            store=_ObsStore(),
            run_one=_run(calls, "failed"),
        )
        assert result.status == "failed"
        assert calls == ["a.yaml"]


class TestAbortOnException:
    def test_unexpected_exception_propagates(self) -> None:
        def run_one(spec_path: str) -> RunResult:
            raise RuntimeError("engine exploded")

        with pytest.raises(CampaignExecutionError) as excinfo:
            run_campaign_sequence(
                campaign_id="c-1",
                experiments=["a.yaml"],
                policy={"on_experiment_failure": "abort_campaign"},
                window={},
                store=_ObsStore(),
                run_one=run_one,
            )
        assert "a.yaml" in str(excinfo.value)


class TestDeadline:
    def test_deadline_reached_aborts_before_next_spec(self) -> None:
        calls: list[str] = []
        times = iter([0.0, 2.0, 6.0])
        store = _ObsStore()
        result = run_campaign_sequence(
            campaign_id="c-1",
            experiments=["a.yaml", "b.yaml"],
            policy={},
            window={"max_duration_s": 4.0},
            store=store,
            run_one=_run(calls, "completed"),
            now_fn=lambda: next(times),
        )
        assert result.status == "aborted"
        assert calls == ["a.yaml"]
        stop = store.observations("campaign_stop")
        assert len(stop) == 1
        assert stop[0][3]["reason"] == "deadline_passed"

    def test_default_long_window_ignored(self) -> None:
        calls: list[str] = []
        result = run_campaign_sequence(
            campaign_id="c-1",
            experiments=["a.yaml"],
            policy={},
            window={},
            store=_ObsStore(),
            run_one=_run(calls),
            now_fn=lambda: 0.0,
        )
        assert result.status == "completed"
