from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from mayhem.domain.provider import (
    PROVIDER_API_VERSION,
    ProviderCompatibilityError,
    ProviderPermission,
    ProviderPermissionError,
)
from mayhem.providers.builtin import create_builtin_registry
from mayhem.providers.loader import ProviderLoader

if TYPE_CHECKING:
    from pathlib import Path


class TestRuntime:
    pass


class FakeEntryPoint:
    def __init__(self, name: str, value: Any, *, error: Exception | None = None) -> None:
        self.name = name
        self.value = value
        self.dist = None
        self._error = error
        self.loaded = 0

    def load(self) -> Any:
        self.loaded += 1
        if self._error is not None:
            raise self._error
        return self.value


def metadata(
    provider_id: str = "test.provider",
    *,
    permissions: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "apiVersion": PROVIDER_API_VERSION,
        "providerId": provider_id,
        "name": "Test Provider",
        "version": "1.0.0",
        "description": "A test provider.",
        "permissions": permissions or [],
        "capabilities": [
            {
                "id": "target.discovery",
                "summary": "Resolve test targets.",
            }
        ],
        "targetLocators": [
            {
                "id": "test.target",
                "kind": "test_object",
                "selectorSchema": {"name": "string"},
                "requiredPermissions": [],
            }
        ],
        "evidenceSchema": {
            "name": "test-evidence",
            "version": "1.0",
            "fields": ("target",),
        },
    }


def catalog_document(
    *, target: str = "tests.unit.test_provider_loader:TestRuntime"
) -> dict[str, Any]:
    return {
        "apiVersion": "mayhem.provider-catalog/v1",
        "providers": [
            {
                "metadata": metadata(),
                "implementation": {"kind": "import", "target": target, "factory": False},
            }
        ],
    }


def write_catalog(path: Path, document: dict[str, Any]) -> None:
    path.write_text(json.dumps(document), encoding="utf-8")


def test_dry_run_catalog_inspection_never_imports_runtime(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog, catalog_document())
    imports: list[str] = []
    def record_import(_: str) -> None:
        imports.append("runtime")

    loader = ProviderLoader(import_module_fn=record_import)

    report = loader.inspect_catalog(catalog)

    assert report.loaded == ()
    assert report.failures == ()
    assert report.providers[0].status == "ready"
    assert imports == []


def test_metadata_is_validated_before_runtime_import(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    invalid = catalog_document()
    invalid["providers"][0]["metadata"]["apiVersion"] = "mayhem.provider/v99"
    write_catalog(catalog, invalid)
    imports: list[str] = []
    def record_import(_: str) -> None:
        imports.append("runtime")

    loader = ProviderLoader(import_module_fn=record_import)

    with pytest.raises(ProviderCompatibilityError, match="provider_api_incompatible"):
        loader.load_catalog(catalog)

    assert imports == []


def test_catalog_load_registers_only_validated_plugin(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    write_catalog(catalog, catalog_document())
    registry = create_builtin_registry()
    loader = ProviderLoader(registry=registry)

    report = loader.load_catalog(catalog)

    assert report.loaded == ("test.provider",)
    assert registry.runtime("test.provider") is not None
    assert type(registry.runtime("test.provider")).__name__ == "type"
    assert {item.metadata.provider_id for item in registry.registrations()} == {
        "docker",
        "podman",
        "kubernetes",
        "test.provider",
    }


def test_loader_rejects_permissions_outside_policy(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    document = catalog_document()
    document["providers"][0]["metadata"]["permissions"] = [ProviderPermission.TARGET_MUTATE.value]
    write_catalog(catalog, document)
    loader = ProviderLoader()

    with pytest.raises(ProviderPermissionError, match="provider_permission_denied"):
        loader.load_catalog(catalog)


def test_one_broken_plugin_does_not_remove_builtins(tmp_path: Path) -> None:
    catalog = tmp_path / "catalog.json"
    document = catalog_document(target="tests.missing_provider:Missing")
    document["providers"].append(
        {
            "metadata": metadata("working.provider"),
            "implementation": {
                "kind": "import",
                "target": "tests.unit.test_provider_loader:TestRuntime",
                "factory": False,
            },
        }
    )
    write_catalog(catalog, document)
    registry = create_builtin_registry()
    loader = ProviderLoader(registry=registry)

    report = loader.load_catalog(catalog)

    assert report.loaded == ("working.provider",)
    assert report.failures[0].provider_id == "test.provider"
    assert {item.metadata.provider_id for item in registry.registrations()} >= {
        "docker",
        "podman",
        "kubernetes",
        "working.provider",
    }


def test_entry_point_metadata_loads_before_implementation() -> None:
    metadata_entry = FakeEntryPoint("test.provider", metadata())
    implementation_entry = FakeEntryPoint("test.provider", TestRuntime)
    calls: list[str] = []

    def entry_points(*, group: str) -> list[FakeEntryPoint]:
        calls.append(group)
        if group == "mayhem.provider.metadata":
            return [metadata_entry]
        return [implementation_entry]

    loader = ProviderLoader(entry_points_fn=entry_points)

    report = loader.load_entry_points()

    assert report.loaded == ("test.provider",)
    assert metadata_entry.loaded == 1
    assert implementation_entry.loaded == 1
    assert calls == ["mayhem.provider.metadata", "mayhem.providers"]


def test_invalid_entry_point_metadata_never_loads_implementation() -> None:
    invalid = metadata()
    invalid["apiVersion"] = "mayhem.provider/v99"
    metadata_entry = FakeEntryPoint("test.provider", invalid)
    implementation_entry = FakeEntryPoint("test.provider", TestRuntime)
    loader = ProviderLoader(
        entry_points_fn=lambda *, group: (
            [metadata_entry]
            if group == "mayhem.provider.metadata"
            else [implementation_entry]
        )
    )

    with pytest.raises(ProviderCompatibilityError, match="provider_api_incompatible"):
        loader.load_entry_points()

    assert implementation_entry.loaded == 0
