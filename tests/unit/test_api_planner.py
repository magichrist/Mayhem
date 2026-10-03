"""CLI and API compile the same authored spec into the same frozen plan (plan 08,
Phase 3 acceptance).

The plan's acceptance criterion is one sentence: *"CLI and UI submissions produce
byte-identical frozen plans for the same inputs."* This file is that sentence, as
an executable claim.

Why bytes and not fields
------------------------

Two plans can agree on every field the test happened to look at and still differ
in a field nobody looked at. ``ExecutionPlan.model_dump_json()`` equality is a
single comparison over the whole serialized object, so this test cannot pass by
being incomplete — it either hashes the same bytes or it fails. That is strictly
stronger than "the same fields are set", and it is the only form in which the
claim is worth making to somebody who wants to trust two surfaces with the same
plan.

What this file does **not** claim, and why
------------------------------------------

**Literal byte-identity is not achievable in this build, and the reason is not
the API.** :func:`mayhem.controller.planner.plan_drill` mints a fresh
``execution_group_id`` for every step group from ``uuid.uuid4()``
(``src/mayhem/controller/planner.py`` lines 705, 828, and 1033). Two compilations
of the *same* spec against the *same* graph therefore differ in that field alone,
on either surface — the CLI's and the API's, equally. So the acceptance criterion
is met in the only form that is a property of this code:

* **every field either surface can influence is byte-identical**, asserted over
  the whole serialization with exactly one named normalization;
* **the one field that differs is a per-compilation nonce neither surface
  chooses**, asserted by *enumerating the differing paths* rather than by
  asserting a normalization — so a second, meaningful difference would fail even
  though the normalized comparison would still pass;
* **the nonce is well-formed on both paths**, so "identical but for a nonce" is
  not "identical but for two different shapes of garbage";
* and :func:`test_the_nonce_is_the_only_thing_that_diffs_is_what_makes_the_claim`
  pins the limitation itself, so if a future change to the planner removes the
  randomness this file fails and the limitation can be struck.

Closing the gap is a two-line change in the planner plus one call-site change in
``cli/services.py``: give ``plan_drill`` an optional ``group_id`` factory defaulting
to ``uuid4``, and have ``plan_from_spec`` pass a deterministic generator. Neither
file belongs to this work item, so this records the finding rather than making it.

What makes it true
------------------

There is **one** compiler. :func:`mayhem.controller.planner.plan_drill` is called
by :func:`mayhem.cli.services.plan_from_spec` on the CLI path and by
:func:`mayhem.controller.api_planner._plan` on the API path, and neither wrapper
adds, removes, defaults, or reorders anything. This file proves that by calling
both and comparing bytes — it does not prove it by asserting that both modules
contain the same line, which is a thing a refactor would change without changing
behaviour.

The ``run_id`` is passed explicitly on both paths. That is deliberate: the CLI
mints ``r-<name>-<random>`` because a CLI invocation is one run, and an API
submission names the run it is compiling *for*. Pinning it is what makes the
comparison possible at all, and it is also a real requirement — a plan's digest
covers its run id, so two submissions for the same experiment produce two
different plans by design.

Negative controls
-----------------

Three, each breaking a property the byte comparison depends on:

* an extra spec field the API accepts but the CLI does not (or vice versa) would
  make the two paths *validate* differently; asserted through the shared
  ``DrillSpec`` type, which both paths use;
* a changed snapshot identity changes the digest, so "the same inputs" is
  asserted by showing a one-field change produces different bytes;
* a submission missing an identity cannot be compiled at all, rather than being
  given a default.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.controller.api_planner import (
    REQUIRED_SUBMISSION_KEYS,
    PlannerService,
    PlanSubmission,
)
from mayhem.controller.api_planner import (
    _plan as api_plan,
)
from mayhem.domain.api import plan_digest_of
from mayhem.domain.errors import InvariantViolationError
from mayhem.domain.experiments import DrillSpec
from mayhem.domain.identity import RuntimeIdentity, RuntimeMetadata
from mayhem.domain.topology import ContainerNode, TopologyGraph

if TYPE_CHECKING:
    from pathlib import Path

RUN_ID = "r-equivalence-0001"

SPEC_DOCUMENT: dict[str, Any] = {
    "kind": "drill",
    "name": "checkout-latency",
    "hypothesis": "p99 rises under packet loss",
    "containers": {
        "checkout": {
            "faults": [
                {"fault": "net.latency", "duration": "5s"},
                {"fault": "mem.leak", "duration": "20s"},
            ]
        }
    },
    "execution": [{"sequential": ["checkout"]}],
}

SNAPSHOTS: dict[str, str] = {
    "config_snapshot_id": "cfg-0001",
    "topology_snapshot_id": "topo-0001",
    "environment_fingerprint": "env-fp-1",
}


def _graph() -> TopologyGraph:
    return TopologyGraph(
        nodes=(
            ContainerNode(
                id="checkout",
                name="checkout",
                engine="podman",
                runtime_identity=RuntimeIdentity(
                    runtime="podman", host_id="h1", runtime_id="ctr-checkout"
                ),
                runtime_metadata=RuntimeMetadata(service="checkout", name="checkout"),
                container_name="checkout",
                state="running",
            ),
        ),
        edges=(),
    )


class _Prepared:
    """The minimum :class:`mayhem.cli.services.Prepared` shape ``plan_from_spec`` reads.

    A stand-in rather than a real ``prepare()`` run, because the object under test
    is the *compiler*: ``plan_from_spec`` reads ``config_snapshot_id``,
    ``topology_snapshot_id``, and ``fingerprint`` off it and passes them through,
    and a real ``prepare()`` would add a config file, a profile, and a compose
    blueprint to a comparison that does not involve any of them.
    """

    config_snapshot_id = SNAPSHOTS["config_snapshot_id"]
    topology_snapshot_id = SNAPSHOTS["topology_snapshot_id"]
    fingerprint = SNAPSHOTS["environment_fingerprint"]
    safety = None


def _write_spec(tmp_path: Path) -> Path:
    path = tmp_path / "checkout-latency.json"
    path.write_text(json.dumps(SPEC_DOCUMENT), encoding="utf-8")
    return path


# ── the acceptance criterion ────────────────────────────────────────────────


def _normalized(plan: Any) -> str:
    """The plan's bytes with the per-compilation group nonce removed.

    One named normalization, applied to both sides, and asserted to be *only* that
    by :func:`test_the_nonce_is_the_only_thing_that_diffs`.
    """
    document = json.loads(plan.model_dump_json())
    for step in document.get("steps", ()):
        step.pop("execution_group_id", None)
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def _diff_paths(left: Any, right: Any, prefix: str = "") -> list[str]:
    """Every leaf path at which two JSON documents differ."""
    if isinstance(left, dict) and isinstance(right, dict):
        paths: list[str] = []
        for key in sorted(set(left) | set(right)):
            paths.extend(_diff_paths(left.get(key), right.get(key), f"{prefix}.{key}"))
        return paths
    if isinstance(left, list) and isinstance(right, list):
        paths = []
        for index, (one, other) in enumerate(zip(left, right, strict=True)):
            paths.extend(_diff_paths(one, other, f"{prefix}[{index}]"))
        return paths
    return [] if left == right else [prefix]


def test_the_cli_and_the_api_compile_byte_identical_plans(tmp_path: Path) -> None:
    from mayhem.cli.services import plan_from_spec

    spec_path = _write_spec(tmp_path)
    graph = _graph()

    # The CLI path, with the run id pinned so the two are comparable.
    cli_plan = plan_from_spec(str(spec_path), graph, prepared=_Prepared()).plan
    cli_plan = cli_plan.model_copy(update={"run_id": RUN_ID})

    # The API path.
    submission = PlanSubmission(
        run_id=RUN_ID,
        spec=DrillSpec.model_validate(SPEC_DOCUMENT),
        **SNAPSHOTS,
    )
    api_compiled = api_plan(submission, graph)

    assert _normalized(cli_plan) == _normalized(api_compiled), (
        "the CLI and the API produced different bytes for the same authored spec and the "
        "same snapshot identities, beyond the per-compilation group nonce: two compilers "
        "exist, and they will drift"
    )


def test_the_nonce_is_the_only_thing_that_diffs(tmp_path: Path) -> None:
    """The negative control on the normalization above.

    Asserting the *set* of differing paths, rather than trusting that stripping one
    key was enough. If the planner grew a second per-compilation value, the
    normalized comparison would keep passing and this would not.
    """
    from mayhem.cli.services import plan_from_spec

    spec_path = _write_spec(tmp_path)
    graph = _graph()
    cli_plan = plan_from_spec(str(spec_path), graph, prepared=_Prepared()).plan
    api_compiled = api_plan(
        PlanSubmission(
            run_id=RUN_ID, spec=DrillSpec.model_validate(SPEC_DOCUMENT), **SNAPSHOTS
        ),
        graph,
    )
    differing = _diff_paths(
        json.loads(cli_plan.model_copy(update={"run_id": RUN_ID}).model_dump_json()),
        json.loads(api_compiled.model_dump_json()),
    )
    assert all(path.endswith(".execution_group_id") for path in differing), differing
    assert differing, (
        "nothing differs at all, which means the planner stopped minting a group nonce "
        "and the normalization in _normalized is now untested — strike the limitation"
    )


def test_the_nonce_is_a_fresh_well_formed_token_on_both_paths(tmp_path: Path) -> None:
    import re

    from mayhem.cli.services import plan_from_spec

    graph = _graph()
    cli_ids = _group_ids(
        plan_from_spec(str(_write_spec(tmp_path)), graph, prepared=_Prepared()).plan
    )
    api_ids = _group_ids(
        api_plan(
            PlanSubmission(
                run_id=RUN_ID, spec=DrillSpec.model_validate(SPEC_DOCUMENT), **SNAPSHOTS
            ),
            graph,
        )
    )
    pattern = re.compile(r"^grp-[0-9a-f]{12}$")
    assert cli_ids and api_ids
    assert all(pattern.match(value) for value in cli_ids + api_ids)
    assert cli_ids != api_ids, "the nonce is not fresh, so it is a constant in disguise"


def _group_ids(plan: Any) -> list[str]:
    document = json.loads(plan.model_dump_json())
    return [
        str(step["execution_group_id"])
        for step in document.get("steps", ())
        if step.get("execution_group_id")
    ]


def test_the_api_path_really_does_go_through_the_clis_planner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The byte comparison above would pass even if the API had its own compiler.

    So: break ``plan_drill`` and assert the API path notices. If the API path
    bypassed the shared compiler, breaking the shared compiler would change
    nothing here and the equivalence claim would be resting on a coincidence.
    """
    from mayhem.controller import api_planner
    from mayhem.domain.experiments import ExecutionPlan

    def _explode(*_args: Any, **_kwargs: Any) -> ExecutionPlan:
        msg = "the shared planner was reached"
        raise AssertionError(msg)

    monkeypatch.setattr(api_planner, "plan_drill", _explode)
    submission = PlanSubmission(
        run_id=RUN_ID,
        spec=DrillSpec.model_validate(SPEC_DOCUMENT),
        **SNAPSHOTS,
    )
    with pytest.raises(AssertionError, match="the shared planner was reached"):
        api_plan(submission, _graph())


def test_the_compiler_does_not_mutate_the_submitted_spec() -> None:
    """Compiling twice through the API path yields the same bytes, modulo the nonce."""
    spec = DrillSpec.model_validate(SPEC_DOCUMENT)
    graph = _graph()
    first = api_plan(PlanSubmission(run_id=RUN_ID, spec=spec, **SNAPSHOTS), graph)
    second = api_plan(PlanSubmission(run_id=RUN_ID, spec=spec, **SNAPSHOTS), graph)
    assert _normalized(first) == _normalized(second)


# ── negative controls: what makes "the same inputs" true ────────────────────


def test_a_changed_snapshot_identity_changes_the_bytes(tmp_path: Path) -> None:
    """The negative control on the comparison itself.

    If a snapshot identity did *not* change the plan, the byte comparison above
    would be passing for a reason that has nothing to do with equivalence: it
    would be comparing two renderings of a constant.
    """
    graph = _graph()
    spec = DrillSpec.model_validate(SPEC_DOCUMENT)
    baseline = api_plan(PlanSubmission(run_id=RUN_ID, spec=spec, **SNAPSHOTS), graph)
    moved = api_plan(
        PlanSubmission(
            run_id=RUN_ID,
            spec=spec,
            **{**SNAPSHOTS, "environment_fingerprint": "env-fp-2"},
        ),
        graph,
    )
    assert baseline.model_dump_json() != moved.model_dump_json()
    assert plan_digest_of(baseline) != plan_digest_of(moved)


def test_a_different_run_id_produces_a_different_plan() -> None:
    """Two submissions for one experiment are two plans, by design."""
    graph = _graph()
    spec = DrillSpec.model_validate(SPEC_DOCUMENT)
    first = api_plan(PlanSubmission(run_id="r-one", spec=spec, **SNAPSHOTS), graph)
    second = api_plan(PlanSubmission(run_id="r-two", spec=spec, **SNAPSHOTS), graph)
    assert first.model_dump_json() != second.model_dump_json()


def test_both_surfaces_validate_the_spec_through_the_same_type(tmp_path: Path) -> None:
    """One validator, not two that agree today.

    The CLI path reaches ``DrillSpec`` through
    :func:`mayhem.cli.services.load_drill` and the API path through
    ``DrillSpec.model_validate``. This asserts the CLI loader *returns that class*
    by loading a real file, so a future change that gave the API its own loosened
    copy — or the CLI a stricter one — fails here rather than at a divergence.
    """
    from mayhem.cli.services import load_drill

    spec_path = _write_spec(tmp_path)
    assert type(load_drill(str(spec_path))) is DrillSpec
    api_spec = DrillSpec.model_validate(json.loads(spec_path.read_text(encoding="utf-8")))
    assert api_spec.model_dump_json() == load_drill(str(spec_path)).model_dump_json()


def test_a_submission_missing_an_identity_cannot_be_compiled() -> None:
    """Refused, not defaulted: a defaulted identity is a digest nothing can bind to."""
    for key in REQUIRED_SUBMISSION_KEYS:
        payload: dict[str, Any] = {
            "run_id": RUN_ID,
            "spec": SPEC_DOCUMENT,
            **SNAPSHOTS,
        }
        payload.pop(key)
        if key == "spec":
            payload[key] = None
        with pytest.raises(InvariantViolationError) as caught:
            PlanSubmission.from_payload(payload)
        assert key in str(caught.value), key


def test_an_unknown_spec_field_is_ignored_identically_by_both_surfaces(
    tmp_path: Path,
) -> None:
    """A recorded limitation, asserted as a property rather than a hope.

    ``DrillSpec`` declares ``extra`` at its **default**, so an unknown key is
    silently ignored rather than refused. That is the same answer on both
    surfaces — which is why the equivalence claim above still holds — but it is
    not the answer this file would prefer. A typo'd ``duraton:`` compiles to the
    same plan as a spec with no duration at all, on the CLI and in the browser
    alike.

    The fix is one word (``extra="forbid"`` on ``DrillSpec``), and it is a
    **breaking change** to every spec file carrying an unrecognised key, so it is
    not this work item's to make. What is asserted here is the honest current
    state, so that the day it changes this test fails and the report can be
    corrected.
    """
    from mayhem.cli.services import load_drill

    with_extra = {**SPEC_DOCUMENT, "not_a_field": True}
    spec_path = tmp_path / "extra.json"
    spec_path.write_text(json.dumps(with_extra), encoding="utf-8")

    from_cli = load_drill(str(spec_path))
    from_api = PlanSubmission.from_payload(
        {
            "run_id": RUN_ID,
            "spec": with_extra,
            **SNAPSHOTS,
        }
    ).spec
    assert from_cli.model_dump_json() == from_api.model_dump_json()
    assert "not_a_field" not in from_cli.model_dump_json(), (
        "DrillSpec now forbids extras; the limitation recorded in this test's docstring "
        "no longer holds and the breaking change has landed"
    )


# ── the facade stores what the CLI would have run ───────────────────────────


def test_the_planner_facade_persists_a_resource_the_api_can_read_back(
    tmp_path: Path,
) -> None:
    from tests.unit.test_api_service import MIGRATIONS

    from mayhem.infra.api_store import ApiStore
    from mayhem.infra.migrations import ALL_MIGRATIONS
    from mayhem.infra.store import Store

    del tmp_path, ALL_MIGRATIONS
    store = Store.open_migrated(":memory:", MIGRATIONS)
    api = ApiStore(store)
    resource = PlannerService(api).compile(
        PlanSubmission(
            run_id=RUN_ID,
            spec=DrillSpec.model_validate(SPEC_DOCUMENT),
            **SNAPSHOTS,
        ),
        _graph(),
    )
    loaded = api.load_plan(resource.plan_digest)
    assert loaded is not None
    assert loaded.plan_digest == resource.plan_digest
    assert plan_digest_of(loaded.plan) == resource.plan_digest, (
        "the stored plan no longer hashes to the digest it is filed under, which is the "
        "one thing Phase 1's digest binding exists to prevent"
    )
    assert api.plan_for_run(RUN_ID) is not None
    store.close()
