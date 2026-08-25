"""Tests for load generation strategy models (ADR-0021)."""

from mayhem.domain.load_strategy import (
    FuzzStrategy,
    LoadPattern,
    LoadPhase,
    LoadStrategy,
)


class TestLoadPattern:
    def test_all_values(self) -> None:
        assert set(LoadPattern) == {
            LoadPattern.CONSTANT,
            LoadPattern.RAMP_UP,
            LoadPattern.RAMP_DOWN,
            LoadPattern.BURST,
            LoadPattern.SPIKE,
            LoadPattern.STEP,
        }


class TestLoadStrategy:
    def test_default_single_phase(self) -> None:
        strat = LoadStrategy()
        assert len(strat.phases) == 1
        assert strat.phases[0].pattern == LoadPattern.CONSTANT

    def test_total_duration(self) -> None:
        strat = LoadStrategy(
            phases=(
                LoadPhase(pattern=LoadPattern.CONSTANT, vus=10, duration=30.0),
                LoadPhase(pattern=LoadPattern.RAMP_UP, vus=10, target_vus=50, duration=20.0),
            )
        )
        assert strat.total_duration() == 50.0

    def test_max_concurrency(self) -> None:
        strat = LoadStrategy(
            phases=(
                LoadPhase(pattern=LoadPattern.CONSTANT, vus=10, duration=10.0),
                LoadPhase(pattern=LoadPattern.BURST, vus=100, duration=5.0),
                LoadPhase(pattern=LoadPattern.RAMP_DOWN, vus=50, target_vus=10, duration=15.0),
            )
        )
        assert strat.max_concurrency() == 100

    def test_constant_profile_factory(self) -> None:
        strat = LoadStrategy.constant_profile(vus=25, duration=60.0)
        assert len(strat.phases) == 1
        assert strat.phases[0].vus == 25
        assert strat.phases[0].duration == 60.0
        assert strat.total_duration() == 60.0

    def test_ramp_profile_factory(self) -> None:
        strat = LoadStrategy.ramp_profile(start_vus=5, end_vus=50, duration=30.0)
        assert strat.phases[0].pattern == LoadPattern.RAMP_UP
        assert strat.phases[0].vus == 5
        assert strat.phases[0].target_vus == 50
        assert strat.phases[0].ramp_seconds == 30.0

    def test_json_round_trip(self) -> None:
        strat = LoadStrategy(
            name="api-flood",
            phases=(
                LoadPhase(pattern=LoadPattern.RAMP_UP, vus=1, target_vus=20, duration=10.0),
                LoadPhase(pattern=LoadPattern.CONSTANT, vus=20, duration=60.0),
            ),
            endpoint="https://api.example.com/health",
            method="POST",
        )
        restored = LoadStrategy.model_validate(strat.model_dump(mode="json"))
        assert restored == strat


class TestFuzzStrategy:
    def test_defaults(self) -> None:
        fs = FuzzStrategy()
        assert fs.mutations_per_request == 1
        assert fs.max_requests == 100
        assert fs.seed is None
        assert fs.dictionary == ()

    def test_json_round_trip(self) -> None:
        fs = FuzzStrategy(
            target_field="username",
            mutations_per_request=3,
            seed=42,
            dictionary=("null", "<script>", "../../etc/passwd"),
        )
        restored = FuzzStrategy.model_validate(fs.model_dump(mode="json"))
        assert restored == fs
