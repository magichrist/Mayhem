"""Tests for the drill spec DSL (ADR-0019)."""

from __future__ import annotations

import pytest

from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.experiments import (
    CheckExpectation,
    CheckProbe,
    DrillConfig,
    DrillContainer,
    DrillFault,
    DrillSpec,
    ExecutionStep,
    OnFailure,
)
from mayhem.domain.risks import RiskLevel
from mayhem.spec import load_drill, parse_drill

# ---------------------------------------------------------------------------
# DrillFault
# ---------------------------------------------------------------------------


class TestDrillFault:
    def test_defaults(self) -> None:
        f = DrillFault(fault="proc.pause")
        assert f.fault == "proc.pause"
        assert f.duration == "10s"
        assert f.on_failure == OnFailure.ABORT_AND_RECOVER
        assert f.targets == ()

    def test_explicit_values(self) -> None:
        f = DrillFault(
            fault="net.partition",
            duration="5s",
            on_failure=OnFailure.CONTINUE,
            targets=("api", "web"),
        )
        assert f.fault == "net.partition"
        assert f.duration == 5.0  # Duration converts "5s" to 5.0
        assert f.on_failure == OnFailure.CONTINUE
        assert f.targets == ("api", "web")

    def test_frozen(self) -> None:
        f = DrillFault(fault="proc.pause")
        with pytest.raises(Exception):
            f.fault = "other"  # type: ignore[misc]

    def test_extra_params_allowed(self) -> None:
        f = DrillFault(fault="proc.pause", status=500)
        assert f.fault == "proc.pause"
        assert f.status == 500  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# DrillContainer
# ---------------------------------------------------------------------------


class TestDrillContainer:
    def test_empty(self) -> None:
        c = DrillContainer()
        assert c.faults == ()

    def test_with_faults(self) -> None:
        c = DrillContainer(faults=(DrillFault(fault="proc.pause"),))
        assert len(c.faults) == 1
        assert c.faults[0].fault == "proc.pause"


# ---------------------------------------------------------------------------
# DrillConfig
# ---------------------------------------------------------------------------


class TestDrillConfig:
    def test_defaults(self) -> None:
        c = DrillConfig()
        assert c.risk_ceiling == RiskLevel.HIGH
        assert c.max_faults == 1
        assert c.timeout == "30m"
        assert c.log_level == "INFO"

    def test_explicit(self) -> None:
        c = DrillConfig(
            risk_ceiling=RiskLevel.CRITICAL,
            max_faults=3,
            timeout="1h",
            log_level="DEBUG",
        )
        assert c.risk_ceiling == RiskLevel.CRITICAL
        assert c.max_faults == 3
        assert c.timeout == 3600.0  # Duration converts "1h" to 3600.0
        assert c.log_level == "DEBUG"

    def test_frozen(self) -> None:
        c = DrillConfig()
        with pytest.raises(Exception):
            c.log_level = "DEBUG"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# CheckProbe / CheckExpectation
# ---------------------------------------------------------------------------


class TestCheckProbe:
    def test_http_check(self) -> None:
        p = CheckProbe(http="http://api:8080/", expect=CheckExpectation(status=200))
        assert p.http == "http://api:8080/"
        assert p.expect.status == 200

    def test_defaults(self) -> None:
        p = CheckProbe()
        assert p.http is None
        assert p.expect.status is None


# ---------------------------------------------------------------------------
# ExecutionStep
# ---------------------------------------------------------------------------


class TestExecutionStep:
    def test_parallel(self) -> None:
        s = ExecutionStep(parallel=("api", "web"))
        assert s.parallel == ("api", "web")
        assert s.sequential is None
        assert s.wait is None
        assert s.check is None

    def test_sequential(self) -> None:
        s = ExecutionStep(sequential=("redis",))
        assert s.sequential == ("redis",)

    def test_wait(self) -> None:
        s = ExecutionStep(wait="5s")
        assert s.wait == 5.0  # Duration converts "5s" to 5.0

    def test_check(self) -> None:
        s = ExecutionStep(
            check=(CheckProbe(http="http://api:8080/", expect=CheckExpectation(status=200)),)
        )
        assert s.check is not None
        assert len(s.check) == 1

    def test_frozen(self) -> None:
        s = ExecutionStep(wait="5s")
        with pytest.raises(Exception):
            s.wait = "10s"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# DrillSpec
# ---------------------------------------------------------------------------


class TestDrillSpec:
    def test_minimal_valid(self) -> None:
        spec = DrillSpec(
            kind="drill",
            name="test",
            containers={"api": DrillContainer(faults=(DrillFault(fault="proc.pause"),))},
            execution=(ExecutionStep(parallel=("api",)),),
        )
        assert spec.kind == "drill"
        assert spec.name == "test"
        assert spec.hypothesis == ""
        assert spec.config.risk_ceiling == RiskLevel.HIGH
        assert len(spec.containers) == 1
        assert len(spec.execution) == 1

    def test_full_spec(self) -> None:
        spec = DrillSpec(
            kind="drill",
            name="full-fault-drill",
            hypothesis="Stack recovers from every implemented fault",
            config=DrillConfig(
                risk_ceiling=RiskLevel.CRITICAL,
                max_faults=1,
                timeout="30m",
                log_level="INFO",
            ),
            containers={
                "testcase-api": DrillContainer(
                    faults=(DrillFault(fault="proc.pause", duration="10s"),)
                ),
                "testcase-redis": DrillContainer(
                    faults=(DrillFault(fault="node.service_stop", duration="15s"),)
                ),
            },
            execution=(
                ExecutionStep(parallel=("testcase-api",)),
                ExecutionStep(wait="5s"),
                ExecutionStep(
                    check=(
                        CheckProbe(
                            http="http://testcase-api:8080/",
                            expect=CheckExpectation(status=200),
                        ),
                    )
                ),
            ),
        )
        assert spec.kind == "drill"
        assert spec.name == "full-fault-drill"
        assert spec.hypothesis == "Stack recovers from every implemented fault"
        assert spec.config.risk_ceiling == RiskLevel.CRITICAL
        assert "testcase-api" in spec.containers
        assert "testcase-redis" in spec.containers
        assert len(spec.execution) == 3

    def test_frozen(self) -> None:
        spec = DrillSpec(
            kind="drill",
            name="test",
            containers={"api": DrillContainer()},
            execution=(ExecutionStep(parallel=("api",)),),
        )
        with pytest.raises(Exception):
            spec.name = "other"  # type: ignore[misc]

    def test_empty_containers_rejected(self) -> None:
        with pytest.raises(Exception):
            DrillSpec(
                kind="drill",
                name="test",
                containers={},
                execution=(ExecutionStep(parallel=("api",)),),
            )

    def test_empty_execution_rejected(self) -> None:
        with pytest.raises(Exception):
            DrillSpec(
                kind="drill",
                name="test",
                containers={"api": DrillContainer()},
                execution=(),
            )


# ---------------------------------------------------------------------------
# parse_drill
# ---------------------------------------------------------------------------


class TestParseDrill:
    def test_valid_yaml(self) -> None:
        data = {
            "kind": "drill",
            "name": "test",
            "containers": {
                "api": {
                    "faults": [
                        {"fault": "proc.pause", "duration": "10s"},
                    ],
                },
            },
            "execution": [
                {"parallel": ["api"]},
            ],
        }
        spec = parse_drill(data)
        assert spec.kind == "drill"
        assert spec.name == "test"
        assert "api" in spec.containers
        assert spec.containers["api"].faults[0].fault == "proc.pause"

    def test_missing_kind(self) -> None:
        data = {"name": "test", "containers": {"api": {}}, "execution": [{"wait": "5s"}]}
        with pytest.raises(SchemaValidationError, match="expected kind: drill"):
            parse_drill(data)

    def test_wrong_kind(self) -> None:
        data = {
            "kind": "deterministic",
            "name": "test",
            "containers": {"api": {}},
            "execution": [{"wait": "5s"}],
        }
        with pytest.raises(SchemaValidationError, match="expected kind: drill"):
            parse_drill(data)

    def test_not_a_mapping(self) -> None:
        with pytest.raises(SchemaValidationError, match="top level must be a mapping"):
            parse_drill("not a dict")

    def test_none_input(self) -> None:
        with pytest.raises(SchemaValidationError, match="top level must be a mapping"):
            parse_drill(None)

    def test_missing_name(self) -> None:
        data = {
            "kind": "drill",
            "containers": {"api": {}},
            "execution": [{"wait": "5s"}],
        }
        with pytest.raises(SchemaValidationError):
            parse_drill(data)

    def test_missing_containers(self) -> None:
        data = {
            "kind": "drill",
            "name": "test",
            "execution": [{"wait": "5s"}],
        }
        with pytest.raises(SchemaValidationError):
            parse_drill(data)

    def test_missing_execution(self) -> None:
        data = {
            "kind": "drill",
            "name": "test",
            "containers": {"api": {}},
        }
        with pytest.raises(SchemaValidationError):
            parse_drill(data)

    def test_config_embedded(self) -> None:
        data = {
            "kind": "drill",
            "name": "test",
            "config": {
                "risk_ceiling": "critical",
                "max_faults": 3,
                "timeout": "1h",
                "log_level": "DEBUG",
            },
            "containers": {"api": {}},
            "execution": [{"wait": "5s"}],
        }
        spec = parse_drill(data)
        assert spec.config.risk_ceiling == RiskLevel.CRITICAL
        assert spec.config.max_faults == 3
        assert spec.config.timeout == 3600.0  # Duration converts "1h" to 3600.0
        assert spec.config.log_level == "DEBUG"

    def test_execution_with_check(self) -> None:
        data = {
            "kind": "drill",
            "name": "test",
            "containers": {"api": {}},
            "execution": [
                {"parallel": ["api"]},
                {"wait": "5s"},
                {"check": [{"http": "http://api:8080/", "expect": {"status": 200}}]},
            ],
        }
        spec = parse_drill(data)
        assert len(spec.execution) == 3
        assert spec.execution[2].check is not None
        assert spec.execution[2].check[0].http == "http://api:8080/"
        assert spec.execution[2].check[0].expect.status == 200

    def test_fault_with_targets(self) -> None:
        data = {
            "kind": "drill",
            "name": "test",
            "containers": {
                "lb": {
                    "faults": [
                        {
                            "fault": "net.partition",
                            "duration": "5s",
                            "targets": ["api", "download-1"],
                        },
                    ],
                },
            },
            "execution": [{"parallel": ["lb"]}],
        }
        spec = parse_drill(data)
        assert spec.containers["lb"].faults[0].targets == ("api", "download-1")


# ---------------------------------------------------------------------------
# load_drill (file-based)
# ---------------------------------------------------------------------------


class TestLoadDrill:
    def test_load_from_file(self, tmp_path: object) -> None:
        import pathlib

        p = pathlib.Path(str(tmp_path)) / "mayhem.yaml"
        p.write_text(
            """\
kind: drill
name: test-drill
containers:
  api:
    faults:
      - fault: proc.pause
        duration: 10s
execution:
  - parallel: [api]
""",
            encoding="utf-8",
        )
        spec = load_drill(str(p))
        assert spec.kind == "drill"
        assert spec.name == "test-drill"

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError, match="spec file not found"):
            load_drill("/nonexistent/mayhem.yaml")

    def test_invalid_yaml(self, tmp_path: object) -> None:
        import pathlib

        p = pathlib.Path(str(tmp_path)) / "bad.yml"
        p.write_text("{{{{invalid yaml", encoding="utf-8")
        with pytest.raises(SchemaValidationError, match="invalid YAML"):
            load_drill(str(p))
