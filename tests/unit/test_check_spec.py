"""M4 Phase 4.2: execution-locus checks (ADR-M4-2).

A check's *execution* locus is distinct from the fault target's locus. An
explicit locus wins; a bare (unset) locus infers from the fault target so
pre-0.3.0 specs keep working unchanged.
"""

from pathlib import Path
from typing import Any

import pytest

from mayhem.controller.executor import RunEngine
from mayhem.domain.checks import CheckLocus, FileProbe, MetricProbe, Probe, ProcessProbe
from mayhem.domain.experiments import CheckSpecStep, PlannedStep
from mayhem.infra.lease_repository import SQLiteLeaseSink
from mayhem.infra.store import Store


def _engine(tmp_path: Path, *, engine: str | None = "podman") -> RunEngine:
    store = Store.open_migrated(tmp_path / "tg.db")
    sink = SQLiteLeaseSink(store)
    return RunEngine(store, sink, live_graph=None, engine=engine)


def _step(
    probe: Probe,
    *,
    execution: CheckLocus | None = None,
    target: str | None = None,
    check_id: str = "c1",
) -> PlannedStep:
    return PlannedStep(
        id="check-0000-0",
        seq=0,
        raw_action=CheckSpecStep(
            type="check_spec",
            check_id=check_id,
            probe=probe,
            execution=execution,
            target=target,
        ),
    )


def _capture(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    from mayhem.agents.probes import ProbeResult
    from mayhem.controller import executor as executor_mod

    captured: list[Any] = []

    def fake_run_probe(verify: Any) -> ProbeResult:
        captured.append(verify)
        return ProbeResult(verify.probe, True, "ok")

    monkeypatch.setattr(executor_mod, "run_probe", fake_run_probe)
    return captured


def _summarize(captured: list[Any]) -> dict[str, Any]:
    assert captured, "expected exactly one probe to run"
    verify = captured[0]
    return {"probe": verify.probe, "args": dict(verify.args)}


def _patch_resolve(monkeypatch: pytest.MonkeyPatch) -> None:
    from mayhem.controller import executor as executor_mod
    from mayhem.topology.resolve import ContainerInfo

    def fake_resolve(container_name: str, engine: str | None = None) -> ContainerInfo:
        return ContainerInfo(pid=999, ip_address="127.0.0.1", state="running")

    monkeypatch.setattr(executor_mod, "resolve_container", fake_resolve)


class TestExecutionLocusInference:
    def test_bare_check_infers_container_locus_from_target(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_resolve(monkeypatch)
        patched = _capture(monkeypatch)
        engine = _engine(tmp_path)
        step = _step(
            FileProbe(path="/var/run/app.pid"),
            target="testcase-api",  # no explicit execution → infer
        )
        report = engine._execute_check_spec(step)
        assert report.ok is True
        summary = _summarize(patched)
        # container-inferred: the probe was scoped into the container
        assert summary["args"].get("cont") == "testcase-api"
        assert summary["args"].get("incontainer") is True

    def test_explicit_host_locus_probes_host(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        patched = _capture(monkeypatch)
        engine = _engine(tmp_path, engine=None)
        step = _step(
            FileProbe(path="/var/tmp/sentinel"),
            execution=CheckLocus.HOST,
            target="testcase-api",
        )
        report = engine._execute_check_spec(step)
        assert report.ok is True
        summary = _summarize(patched)
        assert summary["probe"] == "file"
        # host locus: no container scoping leaked into the probe
        assert "cont" not in summary["args"]
        assert "engine" not in summary["args"]

    def test_container_locus_scopes_probe(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_resolve(monkeypatch)
        patched = _capture(monkeypatch)
        engine = _engine(tmp_path, engine="podman")
        step = _step(
            ProcessProbe(name="nginx"),
            execution=CheckLocus.CONTAINER,
            target="testcase-api",
        )
        report = engine._execute_check_spec(step)
        assert report.ok is True
        summary = _summarize(patched)
        assert summary["probe"] == "process"
        assert summary["args"].get("cont") == "testcase-api"
        assert summary["args"].get("incontainer") is True

    def test_service_locus_scopes_probe(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _patch_resolve(monkeypatch)
        captured = _capture(monkeypatch)

        engine = _engine(tmp_path, engine="podman")
        step = _step(
            MetricProbe(endpoint="http://127.0.0.1:9090/metrics", query="up"),
            execution=CheckLocus.SERVICE,
            target="testcase-api",
        )
        report = engine._execute_check_spec(step)
        assert report.ok is True
        summary = _summarize(captured)
        assert summary["args"].get("cont") == "testcase-api"
        assert summary["args"].get("incontainer") is True


class TestProbeTypeMapping:
    def test_new_probe_types_map_to_verify_probe(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        patched = _capture(monkeypatch)
        engine = _engine(tmp_path, engine=None)
        step = _step(
            MetricProbe(endpoint="http://localhost:9090", query="up"),
            execution=CheckLocus.HOST,
        )
        report = engine._execute_check_spec(step)
        assert report.ok is True
        assert patched[0].probe == "metric"
        assert patched[0].args["endpoint"] == "http://localhost:9090"
