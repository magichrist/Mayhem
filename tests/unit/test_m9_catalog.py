"""M9 catalog-contract tests for the fs.fill family archetypes.

The M9 fs family pairs ``percent``-driven inode exhaustion with bounded writer
stress, both marker-addressed so compensation restores the filesystem exactly:
a payload writes its pid (``marker``) and creates ``marker.*`` siblings; undo
SIGKILLs the pid and glob-removes every sibling. Every archetype must (a) be a
defined STORAGE fault whose prefix maps to STORAGE, (b) resolve to the
:class:`PayloadExecutor` (prefix ``fs``), and (c) be compensatable at plan time
via ``controller.compensation.compensated``.
"""

import pytest

from mayhem.agents.executors import PayloadExecutor, executor_for
from mayhem.controller.compensation import (
    _payload_source,
    compensated,
    template_for,
)
from mayhem.domain.catalog import definition_for
from mayhem.domain.errors import SchemaValidationError
from mayhem.domain.experiments import PlannedFault
from mayhem.domain.faults import FaultCategory
from mayhem.domain.topology import ServiceNode

M9_FS_FAMILY = ("fs.fill", "fs.inode_exhaust", "fs.io_stress")


def _fault(fault_id: str, **params: object) -> PlannedFault:
    return PlannedFault(fault_id=fault_id, targets=(), params=params, duration=30.0)


def _nodes() -> tuple[ServiceNode, ...]:
    return (
        ServiceNode(
            id="svc.api",
            name="api",
            container_name="api_cont",
            image="api:latest",
        ),
    )


@pytest.mark.parametrize("fault_id", M9_FS_FAMILY)
def test_m9_archetype_has_catalog_definition(fault_id: str) -> None:
    defn = definition_for(fault_id)
    assert defn.category is FaultCategory.STORAGE
    assert FaultCategory.from_fault_id(defn.id) is FaultCategory.STORAGE
    assert defn.reversible
    assert {k.value for k in defn.applicable_node_kinds} >= {"service", "container", "host"}


@pytest.mark.parametrize("fault_id", M9_FS_FAMILY)
def test_m9_archetype_resolves_to_payload_executor(fault_id: str) -> None:
    assert isinstance(executor_for(fault_id), PayloadExecutor)


@pytest.mark.parametrize("fault_id", M9_FS_FAMILY)
def test_m9_archetype_has_compensation_template_and_undo_op(fault_id: str) -> None:
    tpl = template_for(fault_id)
    assert tpl is not None
    undo_ops, probes = tpl.build(_fault(fault_id), _nodes())
    assert undo_ops and probes
    op = undo_ops[0]
    assert op.op == "payload.undo"
    assert op.args["fault"] == fault_id
    assert op.args["marker"].startswith("/tmp/mayhem.")
    assert op.args["pid"].endswith("@live-pid")


@pytest.mark.parametrize("fault_id", M9_FS_FAMILY)
def test_m9_compensated_writes_undo_and_verify_ahead_of_plan(fault_id: str) -> None:
    planned = compensated(_fault(fault_id), _nodes())
    assert planned.undo_ops and planned.verify_probes
    assert planned.undo_ops[0].op == "payload.undo"


def test_m9_inode_exhaust_writes_zero_byte_marker_siblings() -> None:
    marker = "/tmp/mayhem.fs.inode_exhaust.svc.api.pid"
    source = _payload_source(_fault("fs.inode_exhaust", percent=40), marker)
    assert "open(marker + '.' + str(i), 'w').close()" in source
    assert "st.f_ffree" in source
    assert "s.f_files - s.f_ffree" in source
    assert "open('/tmp/mayhem.fs.inode_exhaust.svc.api.pid', 'w').write(str(os.getpid()))" in source


def test_m9_io_stress_writers_are_bounded_and_marker_adjacent() -> None:
    marker = "/tmp/mayhem.fs.io_stress.svc.api.pid"
    source = _payload_source(_fault("fs.io_stress", workers=2, io_bytes=64 * 1024 * 1024), marker)
    assert "os.urandom(65536)" in source
    assert "open(marker + '.w' + str(w), 'wb')" in source
    assert "f.truncate(0)" in source
    assert "for w in range(2):" in source
    assert "total = min(67108864, 1024 ** 3)" in source


def test_m9_payload_children_are_marker_dot_prefixed() -> None:
    """Every artifact a new payload creates must be an adjacent ``marker.<x>``
    sibling of the same marker the undo payload globs (``mp + '.*'``), so
    payload.undo reclaims inode files (``.N``) and writer files (``.wN``)."""
    marker = "/tmp/mayhem.fs.svc.api.pid"
    for fid, fragment in (
        ("fs.inode_exhaust", "open(marker + '.' + str(i), 'w').close()"),
        ("fs.io_stress", "open(marker + '.w' + str(w), 'wb')"),
    ):
        source = _payload_source(_fault(fid), marker)
        assert fragment in source
        assert f"open({marker!r}, 'w').write(str(os.getpid()))" in source


def test_m9_inode_exhaust_rejects_out_of_range_percent() -> None:
    defn = definition_for("fs.inode_exhaust")
    with pytest.raises(SchemaValidationError, match="below minimum"):
        defn.validate_params({"percent": 0})
    with pytest.raises(SchemaValidationError, match="above maximum"):
        defn.validate_params({"percent": 100})
    assert defn.validate_params({"percent": 50}) == {"percent": 50.0}


def test_m9_io_stress_param_contract() -> None:
    defn = definition_for("fs.io_stress")
    with pytest.raises(SchemaValidationError, match="unknown parameter"):
        defn.validate_params({"filler": 1})
    with pytest.raises(SchemaValidationError, match="below minimum"):
        defn.validate_params({"workers": 0})
    with pytest.raises(SchemaValidationError, match="above maximum"):
        defn.validate_params({"workers": 9})
    with pytest.raises(SchemaValidationError, match="below minimum"):
        defn.validate_params({"io_bytes": "512K"})
    normalized = defn.validate_params({"workers": 2, "io_bytes": "64M"})
    assert normalized["workers"] == 2
    assert normalized["io_bytes"] == 64 * 1024 * 1024
    defaults = defn.validate_params({})
    assert defaults["workers"] == 1
    assert defaults["io_bytes"] == 64 * 1024 * 1024
