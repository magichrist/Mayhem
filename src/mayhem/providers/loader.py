from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import import_module
from importlib.metadata import entry_points
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from mayhem.domain.provider import (
    ImplementationKind,
    ProviderCatalog,
    ProviderError,
    ProviderMetadata,
    ProviderPermission,
    ProviderRegistration,
    ProviderSource,
    ensure_api_compatible,
    ensure_permissions,
)
from mayhem.providers.builtin import create_builtin_registry

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from mayhem.providers.registry import ProviderRegistry

METADATA_ENTRY_POINT_GROUP = "mayhem.provider.metadata"
IMPLEMENTATION_ENTRY_POINT_GROUP = "mayhem.providers"


class ProviderLoadError(ProviderError, ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ProviderLoadFailure:
    provider_id: str
    code: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "provider_id": self.provider_id,
            "code": self.code,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class ProviderInspection:
    provider_id: str
    status: str
    source: str
    metadata: dict[str, Any] | None = None
    error: ProviderLoadFailure | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "provider_id": self.provider_id,
            "status": self.status,
            "source": self.source,
        }
        if self.metadata is not None:
            payload["metadata"] = self.metadata
        if self.error is not None:
            payload["error"] = self.error.to_dict()
        return payload


@dataclass(frozen=True, slots=True)
class ProviderLoadReport:
    providers: tuple[ProviderInspection, ...] = ()
    loaded: tuple[str, ...] = ()
    failures: tuple[ProviderLoadFailure, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "providers": [provider.to_dict() for provider in self.providers],
            "loaded": list(self.loaded),
            "failures": [failure.to_dict() for failure in self.failures],
        }


class ProviderLoader:
    def __init__(
        self,
        *,
        registry: ProviderRegistry | None = None,
        allowed_permissions: frozenset[ProviderPermission] = frozenset(),
        import_module_fn: Callable[[str], Any] | None = None,
        entry_points_fn: Callable[..., Iterable[Any]] | None = None,
    ) -> None:
        self.registry = registry if registry is not None else create_builtin_registry()
        self.allowed_permissions = allowed_permissions
        self._import_module = import_module_fn if import_module_fn is not None else import_module
        self._entry_points = entry_points_fn if entry_points_fn is not None else entry_points

    def inspect_catalog(self, catalog_path: str | Path) -> ProviderLoadReport:
        catalog = self._read_catalog(catalog_path)
        providers = tuple(
            ProviderInspection(
                provider_id=registration.metadata.provider_id,
                status="ready",
                source=ProviderSource.CATALOG.value,
                metadata=registration.metadata.model_dump(mode="json", by_alias=True),
            )
            for registration in catalog.providers
        )
        return ProviderLoadReport(providers=providers)

    def load_catalog(self, catalog_path: str | Path) -> ProviderLoadReport:
        catalog = self._read_catalog(catalog_path)
        providers: list[ProviderInspection] = []
        loaded: list[str] = []
        failures: list[ProviderLoadFailure] = []
        for registration in catalog.providers:
            provider_id = registration.metadata.provider_id
            self._validate_before_load(registration)
            try:
                runtime = self._load_registration_runtime(registration)
                self.registry.register(registration, lambda runtime=runtime: runtime)
            except Exception as exc:
                failure = self._failure(provider_id, exc)
                failures.append(failure)
                providers.append(
                    ProviderInspection(
                        provider_id=provider_id,
                        status="failed",
                        source=ProviderSource.CATALOG.value,
                        metadata=registration.metadata.model_dump(mode="json", by_alias=True),
                        error=failure,
                    )
                )
                continue
            loaded.append(provider_id)
            providers.append(
                ProviderInspection(
                    provider_id=provider_id,
                    status="loaded",
                    source=ProviderSource.CATALOG.value,
                    metadata=registration.metadata.model_dump(mode="json", by_alias=True),
                )
            )
        return ProviderLoadReport(
            providers=tuple(providers),
            loaded=tuple(loaded),
            failures=tuple(failures),
        )

    def inspect_entry_points(self, provider_ids: Iterable[str] = ()) -> ProviderLoadReport:
        selected = set(provider_ids)
        registrations: list[ProviderRegistration] = []
        for entry_point in self._metadata_entry_points():
            if selected and entry_point.name not in selected:
                continue
            registrations.append(self._registration_from_metadata_entry_point(entry_point))
        return ProviderLoadReport(
            providers=tuple(
                ProviderInspection(
                    provider_id=registration.metadata.provider_id,
                    status="ready",
                    source=ProviderSource.ENTRY_POINT.value,
                    metadata=registration.metadata.model_dump(mode="json", by_alias=True),
                )
                for registration in registrations
            )
        )

    def load_entry_points(self, provider_ids: Iterable[str] = ()) -> ProviderLoadReport:
        registrations = tuple(
            self._registration_from_metadata_entry_point(entry_point)
            for entry_point in self._metadata_entry_points()
            if not provider_ids or entry_point.name in set(provider_ids)
        )
        if not registrations:
            return ProviderLoadReport()
        implementations = {
            entry_point.name: entry_point
            for entry_point in self._entry_points(group=IMPLEMENTATION_ENTRY_POINT_GROUP)
        }
        providers: list[ProviderInspection] = []
        loaded: list[str] = []
        failures: list[ProviderLoadFailure] = []
        for registration in registrations:
            provider_id = registration.metadata.provider_id
            self._validate_before_load(registration)
            try:
                implementation = implementations.get(provider_id)
                if implementation is None:
                    raise ProviderLoadError(
                        "provider_implementation_missing",
                        f"entry point {provider_id!r} has no "
                        f"{IMPLEMENTATION_ENTRY_POINT_GROUP!r} registration",
                    )
                runtime = self._materialize(implementation.load(), registration.implementation)
                self.registry.register(registration, lambda runtime=runtime: runtime)
            except Exception as exc:
                failure = self._failure(provider_id, exc)
                failures.append(failure)
                providers.append(
                    ProviderInspection(
                        provider_id=provider_id,
                        status="failed",
                        source=ProviderSource.ENTRY_POINT.value,
                        metadata=registration.metadata.model_dump(mode="json", by_alias=True),
                        error=failure,
                    )
                )
                continue
            loaded.append(provider_id)
            providers.append(
                ProviderInspection(
                    provider_id=provider_id,
                    status="loaded",
                    source=ProviderSource.ENTRY_POINT.value,
                    metadata=registration.metadata.model_dump(mode="json", by_alias=True),
                )
            )
        return ProviderLoadReport(
            providers=tuple(providers),
            loaded=tuple(loaded),
            failures=tuple(failures),
        )

    def _read_catalog(self, catalog_path: str | Path) -> ProviderCatalog:
        path = Path(catalog_path)
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            message = f"cannot read provider catalog {path}: {exc}"
            raise ProviderLoadError("catalog_invalid", message) from exc
        try:
            return ProviderCatalog.model_validate(document)
        except ValidationError as exc:
            message = f"invalid provider catalog {path}: {exc}"
            raise ProviderLoadError("catalog_invalid", message) from exc

    def _metadata_entry_points(self) -> tuple[Any, ...]:
        return tuple(self._entry_points(group=METADATA_ENTRY_POINT_GROUP))

    def _registration_from_metadata_entry_point(self, entry_point: Any) -> ProviderRegistration:
        try:
            value = entry_point.load()
            metadata = (
                value
                if isinstance(value, ProviderMetadata)
                else ProviderMetadata.model_validate(value)
            ).model_copy(update={"source": ProviderSource.ENTRY_POINT})
        except (ValidationError, ValueError, TypeError, AttributeError, ImportError) as exc:
            raise ProviderLoadError(
                "provider_metadata_invalid",
                f"entry point {entry_point.name!r} has invalid metadata: {exc}",
            ) from exc
        if metadata.provider_id != entry_point.name:
            raise ProviderLoadError(
                "provider_metadata_invalid",
                f"entry point {entry_point.name!r} declares provider {metadata.provider_id!r}",
            )
        ensure_api_compatible(metadata)
        return ProviderRegistration(
            metadata=metadata,
            implementation={
                "kind": ImplementationKind.ENTRY_POINT,
                "target": entry_point.name,
                "factory": False,
            },
        )

    def _validate_before_load(self, registration: ProviderRegistration) -> None:
        ensure_api_compatible(registration.metadata)
        ensure_permissions(registration.metadata, self.allowed_permissions)

    def _load_registration_runtime(self, registration: ProviderRegistration) -> object:
        implementation = registration.implementation
        if implementation.kind is ImplementationKind.IMPORT:
            module_name, attribute = implementation.target.split(":", 1)
            value = getattr(self._import_module(module_name), attribute)
            return self._materialize(value, implementation)
        entry_point = next(
            (
                candidate
                for candidate in self._entry_points(group=IMPLEMENTATION_ENTRY_POINT_GROUP)
                if candidate.name == implementation.target
            ),
            None,
        )
        if entry_point is None:
            raise ProviderLoadError(
                "provider_implementation_missing",
                f"entry point {implementation.target!r} is not installed",
            )
        return self._materialize(entry_point.load(), implementation)

    @staticmethod
    def _materialize(value: object, implementation: Any) -> object:
        if not implementation.factory:
            return value
        if not callable(value):
            raise ProviderLoadError(
                "provider_factory_invalid",
                f"implementation {implementation.target!r} is not callable",
            )
        return value()

    @staticmethod
    def _failure(provider_id: str, exc: Exception) -> ProviderLoadFailure:
        if isinstance(exc, ProviderError):
            return ProviderLoadFailure(provider_id, exc.code, str(exc))
        return ProviderLoadFailure(
            provider_id,
            "provider_load_failed",
            f"{type(exc).__name__}: {exc}",
        )
