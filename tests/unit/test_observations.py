"""Tests for observation engine (ADR-0020)."""

from mayhem.controller.observations import (
    Observation,
    ObservationKind,
    ObservationLog,
)


class TestObservationKind:
    def test_all_values(self) -> None:
        assert len(ObservationKind) == 11
        assert ObservationKind.FAULT_INJECTED.value == "fault.injected"
        assert ObservationKind.ANOMALY_DETECTED.value == "anomaly.detected"


class TestObservationLog:
    def test_empty_log(self) -> None:
        log = ObservationLog()
        assert len(log) == 0
        assert log.observations == ()

    def test_record_and_count(self) -> None:
        log = ObservationLog()
        obs = Observation(
            kind=ObservationKind.FAULT_INJECTED,
            run_id="r1",
            source="executor",
            data={"fault_id": "net.latency"},
        )
        log.record(obs)
        assert len(log) == 1

    def test_emit_shorthand(self) -> None:
        log = ObservationLog()
        log.emit(
            ObservationKind.STEP_STARTED,
            "r1",
            source="executor",
            step_id="s1",
        )
        assert len(log) == 1
        obs = log.observations[0]
        assert obs.kind == ObservationKind.STEP_STARTED
        assert obs.data["step_id"] == "s1"

    def test_for_run(self) -> None:
        log = ObservationLog()
        log.emit(ObservationKind.FAULT_INJECTED, "r1")
        log.emit(ObservationKind.FAULT_INJECTED, "r2")
        log.emit(ObservationKind.FAULT_UNDONE, "r1")
        assert len(log.for_run("r1")) == 2
        assert len(log.for_run("r2")) == 1

    def test_for_kind(self) -> None:
        log = ObservationLog()
        log.emit(ObservationKind.FAULT_INJECTED, "r1")
        log.emit(ObservationKind.FAULT_INJECTED, "r2")
        log.emit(ObservationKind.FAULT_UNDONE, "r1")
        assert len(log.for_kind(ObservationKind.FAULT_INJECTED)) == 2
        assert len(log.for_kind(ObservationKind.FAULT_UNDONE)) == 1

    def test_for_kind_with_run_filter(self) -> None:
        log = ObservationLog()
        log.emit(ObservationKind.FAULT_INJECTED, "r1")
        log.emit(ObservationKind.FAULT_INJECTED, "r2")
        result = log.for_kind(ObservationKind.FAULT_INJECTED, run_id="r1")
        assert len(result) == 1

    def test_anomalies_for_run(self) -> None:
        log = ObservationLog()
        log.emit(ObservationKind.ANOMALY_DETECTED, "r1", metric="latency")
        log.emit(ObservationKind.ANOMALY_DETECTED, "r2", metric="error_rate")
        log.emit(ObservationKind.FAULT_INJECTED, "r1")
        assert len(log.anomalies_for_run("r1")) == 1
        assert len(log.anomalies_for_run("r2")) == 1

    def test_snapshot(self) -> None:
        log = ObservationLog()
        log.emit(ObservationKind.FAULT_INJECTED, "r1", fault_id="net.latency")
        snap = log.snapshot()
        assert len(snap) == 1
        assert snap[0]["kind"] == "fault.injected"
        assert snap[0]["run_id"] == "r1"
        assert snap[0]["data"]["fault_id"] == "net.latency"
