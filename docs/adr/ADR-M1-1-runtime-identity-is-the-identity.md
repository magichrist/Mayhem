# ADR-M1-1: RuntimeIdentity is the identity; container_name is a resolver key

**Status:** Approved
**Date:** 2026-08-30
**Deciders:** Ali
**Relates to:** ADR-0013, ADR-0019, ADR-0020, ADR-0021

## Context

Container targets were historically bound by their authored name (`container_name`,
e.g. `testcase-api`, ADR-0019/ADR-0020) and by ad-hoc `runtime_id`/`host_id`/
`service_name` scalars on `ContainerNode`. Two problems follow:

1. **Authoring name is not a runtime identity.** A `docker-compose up` can recreate a
   container with a different runtime id, while the authored name stays the same. Any
   record keyed by `container_name` silently keeps describing "the same target" even
   though the underlying container is a brand-new object. Recovery, leasing, and
   reporting then attribute one container's lifecycle to another's faults.
2. **Ad-hoc scalars are not a contract.** `runtime_id`, `host_id`, `service_name` are
   optional, inconsistently populated, and never treated as a single equality key, so
   no persisted record can be *queried by identity*.

## Decision

Introduce a single value object that IS the container identity:

```
RuntimeIdentity(runtime: str, host_id: str | None, runtime_id: str)
```

- Equality, hashing, and `resolve_key()` / `key()` operate on the three identity fields
  **only**. Names, labels, and service bindings never participate in equality
  (ADR-M1-2).
- `container_name` (and `service`) become **authoring resolver keys** only: the DSL
  resolves them to a `RuntimeIdentity` at planning time. They are degrees of user
  intent, not identity.
- `runtime` is the engine label as today (`"docker"`/`"podman"`), matching
  ADR-0013's "label only, no runtime types" rule.
- `runtime_id` is the full container id reported by the engine (e.g. the
  `ps` row id / `inspect .Id`).
- `host_id` is the host node identity the container runs on (today
  `h-<engine>-local`).
- An identity that cannot be populated is represented by absence (None), never by a
  synthetic value.

### Canonical key

Persisted records carry `RuntimeIdentity` as a canonical opaque key string so the
store stays schema-simple:

```
runtime|host_id|runtime_id      e.g. "podman|h-podman-local|5f3a..."
```

The canonical key round-trips and is the value used to query store rows by identity.

## Migration / implications

- `ContainerNode` drops `runtime_id`/`host_id`/`service_name`; it gains
  `runtime_identity: RuntimeIdentity` and `runtime_metadata: RuntimeMetadata | None`.
  `container_name` remains as the resolver key (ADR-M1-4).
- Planning records, leases, execution rows, and recovery rows are keyed by identity —
  not by `container_name` (ADR-M1-3, ADR-M1-4).
- In-place schema change is allowed during M1; identities freeze at M4 (ADR-M1-3).

## References

- ADR-M1-2 (what is NOT identity), ADR-M1-3 (persistence + drift semantics),
  ADR-M1-4 (backward compatibility).