"""CLI surface: lifecycle commands, prefix resolution, output formats."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mayhem.cli.app import main
from mayhem.cli.exit_codes import ExitCode

TESTCASE = Path(__file__).resolve().parents[2] / "examples" / "testCase"
COMPOSE_FILE = TESTCASE / "docker-compose.yml"

DRILL_YAML = """\
kind: drill
apiVersion: "mayhem/v1"
name: drill-pause
hypothesis: brief process pause is survivable
config:
  risk_ceiling: critical
  max_faults: 1
  timeout: 10m
containers:
  testcase-api:
    faults:
      - fault: proc.pause
        duration: 10s
  testcase-lb:
    faults:
      - fault: fuzz.protocol_abuse
        duration: 5s
execution:
  - parallel: [testcase-api, testcase-lb]
  - wait: 2s
  - check:
      - http: http://testcase-api:8080/
        expect: { status: 200 }
"""


def _write(tmp_path: Path, text: str) -> Path:
    spec_file = tmp_path / "spec.yaml"
    spec_file.write_text(text)
    return spec_file


class TestToolkitGroup:
    def test_faults_lists_catalog(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["toolkit", "faults"]) == 0
        assert "proc.pause" in capsys.readouterr().out

    def test_two_level_prefix_reaches_nested_command(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, DRILL_YAML)
        assert main(["experiment", "v", str(spec), "--compose", str(COMPOSE_FILE)]) == 0
        assert "validated r-drill-pause-" in capsys.readouterr().out


class TestPlanValidateRun:
    def test_plan_prints_frozen_json(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, DRILL_YAML)
        assert main(["plan", str(spec), "--compose", str(COMPOSE_FILE)]) == 0
        out = capsys.readouterr().out
        plan = json.loads(out)
        assert plan["run_id"].startswith("r-drill-pause")
        assert "proc.pause" in out

    def test_validate_passes_gates(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, DRILL_YAML)
        assert main(["v", str(spec), "--compose", str(COMPOSE_FILE)]) == 0
        assert "validated r-drill-pause-" in capsys.readouterr().out

    def test_missing_compose_is_usage_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        spec = _write(tmp_path, DRILL_YAML)
        assert main(["plan", str(spec)]) == 2
        err = capsys.readouterr().err
        assert "compose" in err

    @patch("mayhem.cli.services.RunEngine")
    def test_run_mocked_engine_completes(
        self,
        mock_engine_cls: MagicMock,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        engine = mock_engine_cls.return_value
        result = engine.execute.return_value
        result.status = "completed"
        result.summary_md.return_value = "run completed"
        spec = _write(tmp_path, DRILL_YAML)
        db = tmp_path / "cli.db"
        rc = main(
            ["--db", str(db), "--skip-gate", "run", str(spec), "--compose", str(COMPOSE_FILE)]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "completed" in out
        assert "mayhem history r-drill-pause-" in out

    def test_run_bypasses_inert_fault_at_gate(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mayhem.agents import impact as impact_mod
        from mayhem.controller.executor import RunResult

        drill = """\
kind: drill
name: drill-load
config:
  risk_ceiling: critical
  max_faults: 1
  timeout: 10m
containers:
  testcase-api:
    faults:
      - fault: net.load
        duration: 10s
execution:
  - parallel: [testcase-api]
  - wait: 1s
"""
        spec = _write(tmp_path, drill)
        runtime = impact_mod.ContainerRuntime(
            container="testcase-api",
            engine="podman",
            bins={"k6": False},
            uid=0,
            cap_eff=0,
        )
        monkeypatch.setattr(impact_mod, "probe_container_runtime", lambda *a, **k: runtime)
        monkeypatch.setattr(impact_mod, "_host_bin_present", lambda name: False)
        captured: dict[str, object] = {}

        def _stub_engine(*args: object, **kwargs: object):
            captured.update(kwargs)
            eng = MagicMock()
            eng.execute.return_value = RunResult(
                run_id="r-gate",
                status="completed",
                started_at_epoch_s=0.0,
                ended_at_epoch_s=0.0,
            )
            return eng

        monkeypatch.setattr("mayhem.cli.services.RunEngine", _stub_engine)
        db = tmp_path / "cli.db"
        rc = main(["--db", str(db), "run", str(spec), "--compose", str(COMPOSE_FILE)])
        assert rc == 0
        err = capsys.readouterr().err
        assert "impact gate — bypassing" in err
        assert "net.load → testcase-api: bypass due to missing host tooling: bin:k6" in err
        bypass = captured["bypass"]
        assert isinstance(bypass, dict)
        assert bypass[("net.load", "testcase-api")] == "missing host tooling: bin:k6"

    def test_skip_gate_bypasses_inert_refusal(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from mayhem.agents import impact as impact_mod

        drill = """\
kind: drill
name: drill-load-skip
config:
  risk_ceiling: critical
  max_faults: 1
  timeout: 10m
containers:
  testcase-api:
    faults:
      - fault: net.load
        duration: 10s
execution:
  - parallel: [testcase-api]
  - wait: 1s
"""
        spec = _write(tmp_path, drill)
        inert = impact_mod.ContainerRuntime(
            container="testcase-api",
            engine="podman",
            bins={"k6": False},
            uid=0,
            cap_eff=0,
        )
        monkeypatch.setattr(impact_mod, "probe_container_runtime", lambda *a, **k: inert)
        engine = MagicMock()
        result = engine.execute.return_value
        result.status = "completed"
        result.summary_md.return_value = "run completed"
        with patch("mayhem.cli.services.RunEngine", return_value=engine):
            rc = main(
                [
                    "--db",
                    str(tmp_path / "cli.db"),
                    "--skip-gate",
                    "run",
                    str(spec),
                    "--compose",
                    str(COMPOSE_FILE),
                ]
            )
        assert rc == 0
        assert "gate skipped" in capsys.readouterr().err


class TestManiacCommand:
    @patch("mayhem.cli.services.RunEngine")
    def test_maniac_compiles_random_plan_from_spec_config(
        self,
        mock_engine_cls: MagicMock,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        maniac_yaml = DRILL_YAML.replace(
            "name: drill-pause\n",
            "name: drill-maniac\n",
            1,
        ).replace(
            "  timeout: 10m\n",
            "  timeout: 10m\n  maniac:\n    level: 3\n    run_level: 4\n    seed: 7\n",
            1,
        )
        spec = _write(tmp_path, maniac_yaml)
        engine = mock_engine_cls.return_value
        result = engine.execute.return_value
        result.status = "completed"
        result.summary_md.return_value = "maniac complete"
        result.wall_seconds = 1.0
        result.dirty_leases = ()
        rc = main(
            [
                "--db",
                str(tmp_path / "m.db"),
                "--skip-gate",
                "maniac",
                str(spec),
                "--compose",
                str(COMPOSE_FILE),
            ]
        )
        assert rc == 0
        captured = capsys.readouterr()
        out, err = captured.out, captured.err
        assert "maniac mode — 4 random fault round(s)" in err
        assert "mayhem history r-drill-maniac-" in out
        plan = engine.execute.call_args.args[0]
        faults = [s for s in plan.steps if s.fault is not None]
        assert len(faults) == 4  # run_level rounds, one fault each
        assert any(r.decision_id == "ADR-M5-1" for r in plan.decision_refs)

    @patch("mayhem.cli.services.RunEngine")
    def test_maniac_falls_back_to_layered_config_maniac(
        self,
        mock_engine_cls: MagicMock,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        spec = _write(tmp_path, DRILL_YAML)  # no maniac in the spec
        config_file = tmp_path / "mayhem.yaml"
        config_file.write_text(
            "apiVersion: mayhem/v1\nmaniac:\n  level: 2\n  run_level: 6\n  seed: 9\n"
        )
        engine = mock_engine_cls.return_value
        result = engine.execute.return_value
        result.status = "completed"
        result.summary_md.return_value = "maniac complete"
        result.wall_seconds = 1.0
        result.dirty_leases = ()
        rc = main(
            [
                "--db",
                str(tmp_path / "m.db"),
                "--config",
                str(config_file),
                "--skip-gate",
                "maniac",
                str(spec),
                "--compose",
                str(COMPOSE_FILE),
            ]
        )
        assert rc == 0
        assert "maniac mode — 6 random fault round(s)" in capsys.readouterr().err
        plan = engine.execute.call_args.args[0]
        faults = [s for s in plan.steps if s.fault is not None]
        assert len(faults) == 6
        # spec-level per-fault authored durations are untouched at levels < 4
        assert all(s.fault.fault_id in ("proc.pause", "fuzz.protocol_abuse") for s in faults)

    @patch("mayhem.cli.services.RunEngine")
    def test_maniac_spec_named_mayhem_yaml_is_not_read_as_config(
        self,
        mock_engine_cls: MagicMock,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Regression: a drill spec literally named `mayhem.yaml` in the cwd must
        # not be re-parsed as the layered configuration file — the maniac config
        # fallback skips the default file layer (same guard as `prepare`).
        monkeypatch.chdir(tmp_path)
        spec = tmp_path / "mayhem.yaml"
        spec.write_text(DRILL_YAML)  # no `maniac:` block -> layered fallback
        engine = mock_engine_cls.return_value
        result = engine.execute.return_value
        result.status = "completed"
        result.summary_md.return_value = "maniac complete"
        result.wall_seconds = 1.0
        result.dirty_leases = ()
        rc = main(
            [
                "--db",
                str(tmp_path / "m.db"),
                "--skip-gate",
                "maniac",
                str(spec),
                "--compose",
                str(COMPOSE_FILE),
            ]
        )
        assert rc == 0, capsys.readouterr().err
        err = capsys.readouterr().err
        assert "maniac mode —" in err
        plan = engine.execute.call_args.args[0]
        faults = [s for s in plan.steps if s.fault is not None]
        assert len(faults) == 10  # default config maniac.run_level when spec omits it

    @patch("mayhem.cli.services.RunEngine")
    def test_maniac_steps_flag_overrides_run_level(
        self,
        mock_engine_cls: MagicMock,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        # -s/--steps beats both the spec's config.maniac.run_level and the
        # layered-config fallback; 12 rounds are drawn, not the authored 4.
        maniac_yaml = DRILL_YAML.replace(
            "name: drill-pause\n",
            "name: drill-maniac\n",
            1,
        ).replace(
            "  timeout: 10m\n",
            "  timeout: 10m\n  maniac:\n    level: 3\n    run_level: 4\n    seed: 7\n",
            1,
        )
        spec = _write(tmp_path, maniac_yaml)
        engine = mock_engine_cls.return_value
        result = engine.execute.return_value
        result.status = "completed"
        result.summary_md.return_value = "maniac complete"
        result.wall_seconds = 1.0
        result.dirty_leases = ()
        rc = main(
            [
                "--db",
                str(tmp_path / "m.db"),
                "--skip-gate",
                "maniac",
                "-s",
                "12",
                str(spec),
                "--compose",
                str(COMPOSE_FILE),
            ]
        )
        assert rc == 0
        assert "maniac mode — 12 random fault round(s)" in capsys.readouterr().err
        plan = engine.execute.call_args.args[0]
        faults = [s for s in plan.steps if s.fault is not None]
        assert len(faults) == 12

    @patch("mayhem.cli.services.RunEngine")
    def test_maniac_config_flag_doubles_as_spec_path(
        self,
        mock_engine_cls: MagicMock,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Regression: `mayhem --config <drill-spec> maniac` from a directory
        # without a spec file must use the --config path as the spec (and not
        # re-parse it as the layered config document).
        monkeypatch.chdir(tmp_path)
        spec = tmp_path / "mayhem.yaml"
        spec.write_text(DRILL_YAML)
        engine = mock_engine_cls.return_value
        result = engine.execute.return_value
        result.status = "completed"
        result.summary_md.return_value = "maniac complete"
        result.wall_seconds = 1.0
        result.dirty_leases = ()
        rc = main(
            [
                "--db",
                str(tmp_path / "m.db"),
                "--config",
                str(spec),
                "--skip-gate",
                "maniac",
                "--compose",
                str(COMPOSE_FILE),
            ]
        )
        assert rc == 0, capsys.readouterr().err
        assert "maniac mode —" in capsys.readouterr().err
        plan = engine.execute.call_args.args[0]
        faults = [s for s in plan.steps if s.fault is not None]
        assert len(faults) == 10  # default maniac.run_level; spec has no maniac block

    def test_config_flag_spec_resolution_used_outside_cwd(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # `mayhem --config <spec> plan` resolves the spec from the flag even
        # when the cwd has no mayhem.yaml at all.
        monkeypatch.chdir(tmp_path)  # tmp_path holds the spec, cwd is empty subdir
        spec_dir = tmp_path / "specs"
        spec_dir.mkdir()
        spec = spec_dir / "drill.yaml"
        spec.write_text(DRILL_YAML)
        assert (
            main(
                [
                    "--db",
                    str(tmp_path / "m.db"),
                    "--config",
                    str(spec),
                    "plan",
                    "--compose",
                    str(COMPOSE_FILE),
                ]
            )
            == 0
        )
        out = capsys.readouterr().out
        plan = json.loads(out)
        assert plan["run_id"].startswith("r-drill-pause")

    def test_maniac_rejects_no_injectable_container(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bare = (
            DRILL_YAML.replace(
                "  timeout: 10m\n",
                "  timeout: 10m\n  maniac:\n    level: 3\n    run_level: 4\n    seed: 7\n",
                1,
            )
            .replace(
                "    faults:\n      - fault: proc.pause\n        duration: 10s\n",
                "    faults: []\n",
                1,
            )
            .replace(
                "    faults:\n      - fault: fuzz.protocol_abuse\n        duration: 5s\n",
                "    faults: []\n",
                1,
            )
        )
        spec = _write(tmp_path, bare)
        from mayhem.cli import lifecycle

        with patch.object(lifecycle, "engine_for", lambda *a, **k: object()):
            rc = main(
                [
                    "--db",
                    str(tmp_path / "m.db"),
                    "--skip-gate",
                    "maniac",
                    str(spec),
                    "--compose",
                    str(COMPOSE_FILE),
                ]
            )
        assert rc == int(ExitCode.VALIDATION_ERROR)
        assert "maniac mode needs at least one container with faults" in capsys.readouterr().err

    @patch("mayhem.cli.services.RunEngine")
    def test_maniac_synthesizes_spec_from_compose_only(
        self,
        mock_engine_cls: MagicMock,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # `mayhem maniac -c compose.yml` with no drill spec anywhere derives
        # the config from the topology: every container pools the full
        # container-addressable catalog, and the draw still plans cleanly.
        monkeypatch.chdir(tmp_path)  # no mayhem.yaml in cwd
        engine = mock_engine_cls.return_value
        result = engine.execute.return_value
        result.status = "completed"
        result.summary_md.return_value = "maniac complete"
        result.wall_seconds = 1.0
        result.dirty_leases = ()
        rc = main(
            [
                "--db",
                str(tmp_path / "m.db"),
                "--skip-gate",
                "maniac",
                "--steps",
                "3",
                "--compose",
                str(COMPOSE_FILE),
            ]
        )
        assert rc == 0, capsys.readouterr().err
        err = capsys.readouterr().err
        assert "no drill spec; synthesized config from compose topology" in err
        assert "3 random fault round(s) drawn" in err
        plan = engine.execute.call_args.args[0]
        faults = [s for s in plan.steps if s.fault is not None]
        assert len(faults) == 3
        for step in faults:
            assert step.fault.fault_id != "k8s.node_drain"  # k8s-only caps excluded
            assert step.raw_action.selectors  # resolved against the topology

    @patch("mayhem.cli.services.RunEngine")
    def test_maniac_synthesized_spec_honors_layered_config_doc(
        self,
        mock_engine_cls: MagicMock,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A cwd `mayhem.yaml` that is a plain config document (no `kind`)
        # tunes the synthesized spec through its `maniac:` block instead of
        # being rejected as no-spec.
        monkeypatch.chdir(tmp_path)
        (tmp_path / "mayhem.yaml").write_text(
            "apiVersion: mayhem/v1\nmaniac:\n  level: 3\n  run_level: 4\n  seed: 7\n"
        )
        engine = mock_engine_cls.return_value
        result = engine.execute.return_value
        result.status = "completed"
        result.summary_md.return_value = "maniac complete"
        result.wall_seconds = 1.0
        result.dirty_leases = ()
        rc = main(
            [
                "--db",
                str(tmp_path / "m.db"),
                "--skip-gate",
                "maniac",
                "--compose",
                str(COMPOSE_FILE),
            ]
        )
        assert rc == 0, capsys.readouterr().err
        assert "4 random fault round(s) drawn" in capsys.readouterr().err
        plan = engine.execute.call_args.args[0]
        faults = [s for s in plan.steps if s.fault is not None]
        assert len(faults) == 4  # layered `maniac.run_level`

    @patch("mayhem.cli.services.RunEngine")
    def test_maniac_synthesized_spec_honors_config_doc_via_flag(
        self,
        mock_engine_cls: MagicMock,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # `--config` pointing at a plain config document (not a drill spec)
        # layer-tunes the synthesized spec from any directory.
        monkeypatch.chdir(tmp_path)
        config_doc = tmp_path / "layers.yaml"
        config_doc.write_text(
            "apiVersion: mayhem/v1\nmaniac:\n  level: 5\n  run_level: 2\n  seed: 7\n"
        )
        engine = mock_engine_cls.return_value
        result = engine.execute.return_value
        result.status = "completed"
        result.summary_md.return_value = "maniac complete"
        result.wall_seconds = 1.0
        result.dirty_leases = ()
        rc = main(
            [
                "--db",
                str(tmp_path / "m.db"),
                "--config",
                str(config_doc),
                "--skip-gate",
                "maniac",
                "--compose",
                str(COMPOSE_FILE),
            ]
        )
        assert rc == 0, capsys.readouterr().err
        assert "2 random fault round(s) drawn" in capsys.readouterr().err
        plan = engine.execute.call_args.args[0]
        faults = [s for s in plan.steps if s.fault is not None]
        assert len(faults) == 2


class TestRecoveryCommands:
    def test_janitor_quiet_sweep(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--db", str(tmp_path / "j.db"), "janitor"]) == 0

    def test_recover_unknown_run_is_noop(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["--db", str(tmp_path / "j.db"), "recover", "r-ghost"]) == 0
        assert "nothing to recover" in capsys.readouterr().out

    def test_history_unknown_run_returns_empty(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["--db", str(tmp_path / "j.db"), "history", "r-ghost"])
        assert rc == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data == {"steps": [], "events": [], "leases": []}

    def test_status_empty_db(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--db", str(tmp_path / "j.db"), "status"]) == 0
