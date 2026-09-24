from __future__ import annotations

from typing import Any


class TestProvider:
    id = "example.test"

    def is_available(self) -> bool:
        return True

    def capabilities(self) -> tuple[str, ...]:
        return ("target.discovery",)

    def discover(self) -> tuple[Any, ...]:
        return ()

    def resolve_target(self, selector: object) -> tuple[object, ...]:
        return (selector,)
