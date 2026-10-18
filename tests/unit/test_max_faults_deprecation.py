"""``DrillConfig.max_faults`` is deprecated *and* unenforced — loudly.

The field is parseable and stored, and *nothing* reads it: no scheduler,
planner, executor, or safety gate consults ``config.max_faults``. v1 keeps it
parseable (removing it would break existing specs) but emits one warning per
config load when a spec actually sets it, pointing operators at the budget that
*is* enforced — ``blast_radius.max_concurrent_faults``, the safety gate in
``mayhem.controller.safety``.

Two properties matter more than the warning itself:

* an *omitted* value must stay silent — warning on the default is noise, and
  noise is why deprecations get muted; and
* the warning must not harden into enforcement. ``max_faults: 1`` still plans
  every authored fault. Only the blast-radius budget bounds concurrency.
"""

from __future__ import annotations

import warnings
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from mayhem.controller.planner import plan_drill
from mayhem.domain.experiments import (
    BlastRadiusBudget,
    DrillConfig,
    DrillContainer,
    DrillFault,
    DrillSpec,
    ExecutionStep,
    MaxFaultsNotEnforced,
)
from mayhem.domain.topology import TopologyGraph
from mayhem.spec import parse_drill


@contextmanager
def _records() -> Iterator[list[warnings.WarningMessage]]:
    """Capture every warning raised in the block, with no dedup by location."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        yield caught


def _deprecations(caught: list[warnings.WarningMessage]) -> list[warnings.WarningMessage]:
    return [w for w in caught if issubclass(w.category, MaxFaultsNotEnforced)]


#: The smallest document that parses: one container, one authored fault.
_MINIMAL_SPEC: dict[str, Any] = {
    "kind": "drill",
    "name": "legacy-max-faults",
    "containers": {"api": {"faults": [{"fault": "proc.pause", "duration": "3s"}]}},
    "execution": [{"parallel": ["api"]}],
}


# ---------------------------------------------------------------------------
# 1. An authored value warns
# ---------------------------------------------------------------------------


class TestWarnsWhenAuthored:
    def test_explicit_value_emits_one_deprecation_warning(self) -> None:
        with _records() as caught:
            config = DrillConfig(max_faults=1)
        assert config.max_faults == 1  # the field still round-trips
        assert len(_deprecations(caught)) == 1

    def test_warns_on_the_default_numeric_value_too(self) -> None:
        # `max_faults: 1` *is* the field default, and is exactly what
        # `mayhem init` scaffolds and the README example ships. Warning only on
        # a value that differs from the default would leave the one case the
        # deprecation exists to catch completely silent.
        with _records() as caught:
            DrillConfig(max_faults=1)
        assert len(_deprecations(caught)) == 1

    def test_spec_parse_emits_the_warning(self) -> None:
        # The real config-parse path, not just direct construction.
        with _records() as caught:
            spec = parse_drill({**_MINIMAL_SPEC, "config": {"max_faults": 2}})
        assert spec.config.max_faults == 2
        assert len(_deprecations(caught)) == 1


# ---------------------------------------------------------------------------
# 2. An omitted value stays silent
# ---------------------------------------------------------------------------


class TestSilentWhenOmitted:
    def test_default_construction_is_silent(self) -> None:
        with _records() as caught:
            DrillConfig()
        assert _deprecations(caught) == []

    def test_config_block_without_the_field_is_silent(self) -> None:
        with _records() as caught:
            DrillConfig(risk_ceiling="high", timeout="10m")
        assert _deprecations(caught) == []

    def test_spec_with_no_config_block_is_silent(self) -> None:
        with _records() as caught:
            parse_drill(dict(_MINIMAL_SPEC))
        assert _deprecations(caught) == []

    def test_spec_config_block_without_the_field_is_silent(self) -> None:
        with _records() as caught:
            parse_drill({**_MINIMAL_SPEC, "config": {"timeout": "10m", "recovery": True}})
        assert _deprecations(caught) == []


# ---------------------------------------------------------------------------
# 3. Once per load, not once per access
# ---------------------------------------------------------------------------


class TestFiresOnce:
    def test_repeated_reads_do_not_re_warn(self) -> None:
        with _records() as caught:
            config = DrillConfig(max_faults=4)
            for _ in range(25):
                assert config.max_faults == 4
                assert config.model_dump()["max_faults"] == 4
        assert len(_deprecations(caught)) == 1

    def test_two_loads_warn_twice(self) -> None:
        with _records() as caught:
            parse_drill({**_MINIMAL_SPEC, "config": {"max_faults": 1}})
            parse_drill({**_MINIMAL_SPEC, "config": {"max_faults": 1}})
        assert len(_deprecations(caught)) == 2


# ---------------------------------------------------------------------------
# 4. The message is actionable
# ---------------------------------------------------------------------------


class TestMessageQuality:
    @pytest.fixture
    def message(self) -> str:
        with _records() as caught:
            DrillConfig(max_faults=7)
        return str(_deprecations(caught)[0].message)

    def test_names_the_field(self, message: str) -> None:
        assert "max_faults" in message

    def test_says_it_is_not_enforced(self, message: str) -> None:
        assert "not enforced" in message.lower()

    def test_points_at_the_enforced_control(self, message: str) -> None:
        assert "max_concurrent_faults" in message

    def test_carries_the_offending_value(self, message: str) -> None:
        assert "7" in message


# ---------------------------------------------------------------------------
# 5. Still parseable, still not enforcing (anti-regression)
# ---------------------------------------------------------------------------


def _graph() -> TopologyGraph:
    from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
    from mayhem.domain.topology import ContainerNode, Edge, EdgeKind, ProcessNode, ServiceNode

    return TopologyGraph(
        nodes=(
            ContainerNode(
                id="ctr-api",
                name="api",
                engine="podman",
                runtime_identity=RuntimeIdentity(
                    runtime="podman", host_id="h1", runtime_id="cid-api"
                ),
                runtime_metadata=RuntimeMetadata(service="api-svc", name="api"),
                container_name="api",
                ip_address="172.18.0.2",
                state="running",
            ),
            ServiceNode(id="svc-api", name="api-svc", container_name="api"),
            ProcessNode(
                id="proc-api",
                name="api-proc",
                pid=4242,
                host_id="h1",
                container_name="api",
            ),
        ),
        edges=(
            Edge(src="svc-api", dst="ctr-api", kind=EdgeKind.RUNS_ON),
            Edge(src="ctr-api", dst="proc-api", kind=EdgeKind.RUNS_ON),
        ),
    )


class TestStillNotEnforcing:
    def test_field_round_trips_through_dump_and_revalidate(self) -> None:
        with _records():
            config = DrillConfig(max_faults=5)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", MaxFaultsNotEnforced)
            reloaded = DrillConfig.model_validate(config.model_dump())
        assert reloaded.max_faults == 5
        assert "max_faults" in config.model_dump()

    def test_max_faults_1_does_not_cap_the_planned_run(self) -> None:
        """The guard against deprecation hardening into enforcement.

        Three authored faults with ``config.max_faults: 1`` must still compile
        to three planned fault steps. If someone "fixes" this by making the
        field enforce, the plan truncates and this fails.
        """
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", MaxFaultsNotEnforced)
            spec = DrillSpec(
                kind="drill",
                name="three-faults-one-max",
                config=DrillConfig(max_faults=1),
                containers={
                    "api": DrillContainer(
                        faults=(
                            DrillFault(fault="proc.pause"),
                            DrillFault(fault="proc.pause"),
                            DrillFault(fault="proc.pause"),
                        )
                    )
                },
                execution=(ExecutionStep(sequential=("api",)),),
            )
        plan = plan_drill(
            "r-legacy",
            spec,
            _graph(),
            config_snapshot_id="c",
            topology_snapshot_id="t",
            environment_fingerprint="e",
        )
        assert len([step for step in plan.steps if step.fault is not None]) == 3

    def test_max_faults_is_not_a_member_of_the_safety_budget(self) -> None:
        # The enforced knob lives on BlastRadiusBudget, which `max_faults`
        # neither belongs to nor influences.
        assert "max_faults" not in BlastRadiusBudget.model_fields
        assert BlastRadiusBudget().max_concurrent_faults == 3


# ---------------------------------------------------------------------------
# 6. Round-trips: the warning fires on AUTHORING, not on machine re-reads
# ---------------------------------------------------------------------------


class TestSilentOnARoundTrip:
    """A store re-reading its own bytes must not warn an operator who never typed it.

    This is the defect the serializer fix closed. ``mayhem.infra.api_store``
    persists ``resource_json`` and re-validates it on every ``load_experiment``,
    which turns a dump back into a dict — so the ``mode="before"`` validator
    saw ``max_faults`` again and warned. Seven of this repository's own tests
    emitted the warning that way. The real symptom is worse than noisy output: a
    *load* advertising a deprecation to somebody who never authored the key.

    The properties below are two-sided. Silencing every round-trip would be just
    as wrong as never silencing one, so the non-default case is asserted to keep
    warning — that key really is still there, and hiding it would be the
    overclaim this whole file exists to prevent.
    """

    def test_a_default_valued_dump_omits_the_key(self) -> None:
        with _records():  # the authoring load warns by design
            config = DrillConfig.model_validate({"max_faults": 1})
        # Losslessness rests on this: the field default IS 1, so a payload
        # without the key validates back to the same value.
        default = DrillConfig.model_fields["max_faults"].default
        assert default == 1
        assert "max_faults" not in config.model_dump()

    def test_revalidating_a_default_valued_dump_is_silent_and_value_identical(self) -> None:
        with _records():
            original = DrillConfig.model_validate({"max_faults": 1})
        dumped = original.model_dump()
        with _records() as caught:
            reloaded = DrillConfig.model_validate(dumped)
        assert _deprecations(caught) == [], (
            "a machine round-trip warned an operator who never authored the key"
        )
        assert reloaded.max_faults == original.max_faults

    def test_the_json_path_the_store_actually_takes_is_silent(self) -> None:
        # Not the in-memory dump: `model_dump(mode="json")` -> json -> dict is
        # what `ApiStore.save_experiment` / `load_experiment` do, and it is the
        # path that produced the seven spurious warnings.
        import json

        with _records():
            original = DrillConfig.model_validate({"max_faults": 1})
        wire = json.loads(json.dumps(original.model_dump(mode="json")))
        with _records() as caught:
            reloaded = DrillConfig.model_validate(wire)
        assert _deprecations(caught) == []
        assert reloaded.max_faults == 1

    def test_a_non_default_value_survives_the_round_trip_and_keeps_warning(self) -> None:
        with _records():  # the seeding load warns by design; keep it off the stream
            original = DrillConfig.model_validate({"max_faults": 5})
        dumped = original.model_dump()
        assert "max_faults" in dumped, (
            "a non-default must be serialized or it would be silently lost"
        )
        with _records() as caught:
            reloaded = DrillConfig.model_validate(dumped)
        assert len(_deprecations(caught)) == 1, (
            "a key that really is still present must keep warning"
        )
        assert reloaded.max_faults == 5

    def test_the_warning_still_fires_on_the_authoring_event_itself(self) -> None:
        # The control for the four above: if this ever stops warning, the whole
        # class is vacuous and the deprecation has gone silent.
        with _records() as caught:
            DrillConfig.model_validate({"max_faults": 1})
        assert len(_deprecations(caught)) == 1

    def test_a_spec_round_tripped_through_json_is_silent_end_to_end(self) -> None:
        import json

        with _records():
            spec = parse_drill({**_MINIMAL_SPEC, "config": {"max_faults": 1}})
        wire = json.loads(json.dumps(spec.model_dump(mode="json")))
        with _records() as caught:
            reloaded = parse_drill(wire)
        assert _deprecations(caught) == [], (
            "the whole-document path the API store uses still warned"
        )
        assert reloaded.config.max_faults == 1
