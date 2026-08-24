"""Tgondi domain models.

Pure, importable-by-everything data layer (ADR-0002): no IO, no upward imports.
All models serialize deterministically via ``model_dump(mode="json")``; enums
serialize as their string values and timestamps are ISO-8601 UTC.
"""
