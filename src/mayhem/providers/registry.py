from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from mayhem.domain.provider import (
    ProviderNotFoundError,
    ProviderPermission,
    ProviderRegistration,
    ProviderRegistrationError,
    ensure_api_compatible,
    ensure_permissions,
)

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass(frozen=True, slots=True)
class RegisteredProvider:
    registration: ProviderRegistration
    factory: Callable[[], object]


class ProviderRegistry:
    def __init__(
        self,
        *,
        allowed_permissions: frozenset[ProviderPermission] = frozenset(),
    ) -> None:
        self._providers: dict[str, RegisteredProvider] = {}
        self._allowed_permissions = allowed_permissions

    def register(
        self,
        registration: ProviderRegistration,
        factory: Callable[[], object],
        *,
        replace: bool = False,
    ) -> None:
        metadata = registration.metadata
        ensure_api_compatible(metadata)
        ensure_permissions(metadata, self._allowed_permissions)
        provider_id = metadata.provider_id
        if provider_id in self._providers and not replace:
            raise ProviderRegistrationError(
                "provider_already_registered",
                f"provider {provider_id!r} is already registered",
            )
        self._providers[provider_id] = RegisteredProvider(registration, factory)

    def registration(self, provider_id: str) -> ProviderRegistration:
        try:
            return self._providers[provider_id].registration
        except KeyError as exc:
            raise ProviderNotFoundError(
                "provider_not_found",
                f"provider {provider_id!r} is not registered",
            ) from exc

    def runtime(self, provider_id: str) -> object:
        try:
            factory = self._providers[provider_id].factory
        except KeyError as exc:
            raise ProviderNotFoundError(
                "provider_not_found",
                f"provider {provider_id!r} is not registered",
            ) from exc
        return factory()

    def registrations(self) -> tuple[ProviderRegistration, ...]:
        return tuple(
            sorted(
                (entry.registration for entry in self._providers.values()),
                key=lambda item: item.metadata.provider_id,
            )
        )

    def ids(self) -> frozenset[str]:
        return frozenset(self._providers)
