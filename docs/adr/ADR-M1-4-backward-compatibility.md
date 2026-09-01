# ADR-M1-4: Backward compatibility

**Status:** Approved
**Date:** 2026-08-30
**Deciders:** Ali
**Relates to:** ADR-M1-1, ADR-0019, ADR-M1-3

## Context

`kind: drill` specs (ADR-0019) are authored against `container_name`/`service` keys,
and a large un-mocked unit suite asserts planner/lease behavior in terms of those
names. Moving records to `RuntimeIdentity` (ADR-M1-1, ADR-M1-3) must not force
authors or historical specs to change, and must not silently skew recorded history.

## Decision

1. **Authored YAML may key by `container_name`/`service` only.** The DSL surface is
   unchanged; names are resolved to a `RuntimeIdentity` at planning time.
2. **The plan and all persisted records resolve to and carry `RuntimeIdentity`.** The
   name-driven intent is compiled to an identity the moment a plan is produced.
3. **Existing `kind: drill` specs and the current un-mocked unit suite keep passing
   unchanged**, with one exception: any test that asserted `container_name` in a
   *persisted/plan* record is updated to assert the identity-equivalent
   `RuntimeIdentity`, preserving semantic equality (name resolved to same container).
4. `container_name` remains on records as a *resolver key* (ADR-M1-1) so diagnostic
   output stays readable; it is never the equality key.

## Migration / implications

- No DSL change; no spec rewrite.
- Identity columns are additive (ADR-M1-3); old rows read identically.
- The e2e smoke (Phase 1.5) authors a drill by name and asserts the planned/recorded
  identity matches the live `RuntimeIdentity`.

## References

- ADR-M1-1 (name is a resolver key), ADR-M1-2, ADR-M1-3 (persistence).