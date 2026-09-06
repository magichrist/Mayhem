"""Maniac mode: random draw logic, config wiring (ADR-M5-1)."""

from __future__ import annotations

import copy

import pytest
from pydantic import ValidationError

from mayhem.domain.experiments import ManiacCfg
from mayhem.domain.maniac import ManiacError, draw_maniac_rounds
from mayhem.spec import parse_drill

TWO_CONTAINER = {
    "kind": "drill",
    "name": "maniac-spec",
    "config": {"risk_ceiling": "critical", "max_faults": 1, "timeout": "30m"},
    "containers": {
        "api": {"faults": [{"fault": "proc.pause", "duration": "10s"}]},
        "lb": {"faults": [{"fault": "fuzz.protocol_abuse", "duration": "50s"}]},
    },
    "execution": [{"parallel": ["api"]}, {"wait": "1s"}],
}


def _spec(**config_overrides):
    data = copy.deepcopy(TWO_CONTAINER)
    if config_overrides:
        data["config"].update(config_overrides)
    return parse_drill(data)


def test_level_1_takes_first_authored_fault_without_jitter() -> None:
    spec = _spec(maniac={"level": 1, "run_level": 8, "seed": 1})
    draws = draw_maniac_rounds(spec, level=1, run_level=8, seed=1)
    assert len(draws) == 8
    for i, draw in enumerate(draws):
        assert draw.round == i + 1
        assert draw.container in ("api", "lb")
        expected = {"api": 10.0, "lb": 50.0}[draw.container]
        assert (
            draw.fault.fault
            == {
                "api": "proc.pause",
                "lb": "fuzz.protocol_abuse",
            }[draw.container]
        )
        assert draw.fault.duration == expected


def test_level_2_draws_only_from_authored_faults() -> None:
    spec = _spec()
    draws = draw_maniac_rounds(spec, level=2, run_level=60, seed=3)
    for draw in draws:
        assert (
            draw.fault.fault
            == {
                "api": "proc.pause",
                "lb": "fuzz.protocol_abuse",
            }[draw.container]
        )


def test_level_3_spans_loci() -> None:
    spec = _spec(maniac={"level": 3, "run_level": 400, "seed": 11})
    draws = draw_maniac_rounds(spec, level=3, run_level=400, seed=11)
    pairs = {(d.container, d.fault.fault) for d in draws}
    assert ("api", "fuzz.protocol_abuse") in pairs
    assert ("lb", "proc.pause") in pairs


def test_level_4_jitters_duration_within_catalog_cap() -> None:
    spec = _spec(maniac={"level": 4, "run_level": 300, "seed": 5})
    draws = draw_maniac_rounds(spec, level=4, run_level=300, seed=5)
    assert any(d.fault.duration != {"api": 10.0, "lb": 50.0}[d.container] for d in draws)
    for d in draws:
        cap = {"proc.pause": 600.0, "fuzz.protocol_abuse": 180.0}[d.fault.fault]
        assert d.fault.duration <= cap
        assert d.fault.duration >= 1.0


def test_jitter_never_drops_below_one_second() -> None:
    data = copy.deepcopy(TWO_CONTAINER)
    data["containers"]["api"]["faults"][0]["duration"] = "1s"
    spec = parse_drill(data)
    draws = draw_maniac_rounds(spec, level=5, run_level=60, seed=2)
    assert all(d.fault.duration >= 1.0 for d in draws)


def test_containers_without_faults_are_excluded() -> None:
    data = copy.deepcopy(TWO_CONTAINER)
    data["containers"]["empty"] = {"faults": []}
    spec = parse_drill(data)
    draws = draw_maniac_rounds(spec, level=5, run_level=50, seed=7)
    assert all(d.container != "empty" for d in draws)


def test_no_injectable_containers_raises() -> None:
    data = copy.deepcopy(TWO_CONTAINER)
    data["containers"] = {"api": {"faults": []}, "lb": {"faults": []}}
    spec = parse_drill(data)
    with pytest.raises(ManiacError):
        draw_maniac_rounds(spec, level=3, run_level=5, seed=1)


def test_seed_makes_draws_reproducible() -> None:
    spec = _spec()
    a = draw_maniac_rounds(spec, level=3, run_level=40, seed=42)
    b = draw_maniac_rounds(spec, level=3, run_level=40, seed=42)
    c = draw_maniac_rounds(spec, level=3, run_level=40, seed=43)
    assert a == b
    assert a != c


class TestManiacCfg:
    def test_defaults(self) -> None:
        cfg = ManiacCfg()
        assert cfg.level == 2
        assert cfg.run_level == 10
        assert cfg.seed is None

    def test_level_bounds(self) -> None:
        for bad in (0, 6):
            with pytest.raises(ValidationError):
                ManiacCfg(level=bad)
        for good in (1, 5):
            assert ManiacCfg(level=good).level == good

    def test_run_level_bounds(self) -> None:
        with pytest.raises(ValidationError):
            ManiacCfg(run_level=0)
        assert ManiacCfg(run_level=1).run_level == 1

    def test_extra_keys_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            ManiacCfg(level=3, surge=True)

    def test_spec_config_maniac_parses(self) -> None:
        spec = _spec(maniac={"level": 3, "run_level": 4, "seed": 7})
        assert spec.config.maniac is not None
        assert spec.config.maniac.level == 3
        assert spec.config.maniac.run_level == 4
        assert spec.config.maniac.seed == 7

    def test_absent_by_default(self) -> None:
        assert _spec().config.maniac is None

    def test_layered_config_exposes_maniac(self) -> None:
        from mayhem.config import MayhemConfigBase

        cfg = MayhemConfigBase(api_version="mayhem/v1", maniac={"level": 4, "run_level": 3})
        assert cfg.maniac.level == 4
        assert cfg.maniac.run_level == 3
