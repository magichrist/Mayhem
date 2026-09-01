# ADR-M1-2: RuntimeMetadata is descriptive, not identity

**Status:** Approved
**Date:** 2026-08-30
**Deciders:** Ali
**Relates to:** ADR-M1-1, ADR-0013

## Context

Runtime state carries a lot of *descriptive* data that is convenient to persist and
inspect — compose project, compose service name, container name, labels, image,
created/started timestamps. Milestone history shows these fields drifting around the
`ContainerNode` integer scalars (`service_name`, `image`, …) without a clear rule for
what is identity and what is only description.

## Decision

Split the fields along one line: **identity** vs **metadata**.

```
RuntimeMetadata(project, service, name, labels, created_at, started_at, image)
```

- `RuntimeMetadata` is purely descriptive and **explicitly excluded from equality**.
  Two metadata blobs describing the same container may differ; the identity is
  unchanged.
- Identity equality compares `RuntimeIdentity.runtime + host_id + runtime_id` only
  (ADR-M1-1).
- A `container_name` or `service` change in metadata does **not** change the persisted
  identity key. This is enforced by Phases 1.1–1.3 acceptance: metadata churn leaves
  `resolve_key()` stable.

### Construction helpers

- `RuntimeMetadata.from_compose_labels(labels, name)` — derives `project`/`service`
  from the engine's compose labels.
- `RuntimeMetadata.from_inspect(info, name)` — derives lifecycle timestamps plus
  image/label context from an engine inspect mapping.

These helpers are lossy on purpose: metadata is for humans and debugging, not for
identity decisions.

## Migration / implications

- Docs and tooling expose `runtime_metadata` as informative; identity queries and the
  drift contract (ADR-M1-3) read `runtime_identity` only.

## References

- ADR-M1-1 (what IS identity), ADR-M1-3 (drift compares identity, not metadata).