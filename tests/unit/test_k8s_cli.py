"""CLI wiring for ``mayhem topology discover --runtime kubernetes``.

Uses a stub provider to keep tests offline; the provider itself is covered in
``test_k8s_discovery.py``.
"""

from __future__ import annotations

from typing import ClassVar

from click.testing import CliRunner

from mayhem.cli.topology import topology
from mayhem.domain.topology import NodeKind, PodNode
from mayhem.topology.providers.base import PartialGraph


class _StubProvider:
    """Records constructor args so CLI wiring is assertable."""

    instances: ClassVar[list[_StubProvider]] = []

    def __init__(self, engine: str, **kwargs: str | None) -> None:
        self.engine = engine
        self.kwargs = kwargs
        self.__class__.instances.append(self)

    @property
    def id(self) -> str:
        return "kubernetes"

    def is_available(self) -> bool:
        return True

    def discover(self) -> PartialGraph:
        pod = PodNode(
            id="k8s::pod/checkout/web-1",
            name="web-1",
            kind=NodeKind.POD,
            namespace="checkout",
            state="Running",
            owner_kind="Deployment",
            owner_name="web",
        )
        return PartialGraph(source="kubernetes", nodes=(pod,), edges=())


def _patch_provider(monkeypatch, stub=_StubProvider):
    monkeypatch.setattr("mayhem.topology.providers.kubernetes.KubernetesProvider", stub)
    monkeypatch.setattr("mayhem.topology.providers.kubernetes.KUBERNETES_IMPORT_ERROR", None)
    _StubProvider.instances = []
    return stub


def test_discover_runtime_k8s_wires_context_and_namespace(monkeypatch) -> None:
    _patch_provider(monkeypatch)
    runner = CliRunner()
    result = runner.invoke(
        topology,
        ["discover", "--runtime", "kubernetes", "--context", "prod", "--namespace", "pay"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert _StubProvider.instances[-1].kwargs == {"context": "prod", "namespace": "pay"}
    assert '"k8s::pod/checkout/web-1"' in result.output


def test_discover_k8s_no_context_defaults(monkeypatch) -> None:
    _patch_provider(monkeypatch)
    runner = CliRunner()
    result = runner.invoke(
        topology,
        ["discover", "--runtime", "kubernetes"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0
    assert _StubProvider.instances[-1].kwargs == {"context": None, "namespace": None}


def test_discover_k8s_missing_sdk_hint(monkeypatch) -> None:
    monkeypatch.setattr(
        "mayhem.topology.providers.kubernetes.KUBERNETES_IMPORT_ERROR",
        ImportError("pip install mayhem[k8s]"),
    )
    runner = CliRunner()
    result = runner.invoke(
        topology,
        ["discover", "--runtime", "kubernetes"],
    )
    assert result.exit_code != 0
    assert "mayhem[k8s]" in result.output


def test_discover_k8s_unreachable_cluster(monkeypatch) -> None:
    class _Unreachable(_StubProvider):
        def is_available(self) -> bool:
            return False

    _patch_provider(monkeypatch, _Unreachable)
    runner = CliRunner()
    result = runner.invoke(
        topology,
        ["discover", "--runtime", "kubernetes"],
    )
    assert result.exit_code != 0
    assert "not reachable" in result.output


def test_default_runtime_never_constructs_k8s_provider(monkeypatch) -> None:
    k8s_called: list = []
    original_inst = __import__("mayhem.topology.providers.kubernetes", fromlist=["x"])
    monkeypatch.setattr(
        "mayhem.topology.providers.kubernetes.KubernetesProvider",
        lambda *a, **k: k8s_called.append(a),
    )
    _patch_provider(monkeypatch)  # resets instances; harmless
    runner = CliRunner()
    result = runner.invoke(
        topology,
        ["discover"],
        catch_exceptions=True,
    )
    # Whatever the ambient docker/podman result is, kubernetes must be untouched.
    assert k8s_called == []
    assert "mayhem[k8s]" not in result.output
    assert original_inst.KUBERNETES_INSTALL_HINT  # module stays importable
