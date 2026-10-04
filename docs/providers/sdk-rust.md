# The Rust wire contract

> **There is no Rust crate in this repository.** `RUST_SDK_SHIPPED` is `False`
> and no `Cargo.toml` exists for mayhem's provider SDK. What follows describes
> the *wire contract* a Rust derive macro must implement — the field names, the
> serialisation convention, and the reader that checks a manifest against them.

That distinction is deliberate and worth being blunt about. "We have a Rust SDK"
and "we have the Rust SDK's field map" are different sentences, and only the
second one is true here. A Rust-shaped manifest reader shipped without saying so
would be exactly the overclaim this document exists to prevent.

What does exist, and is tested:

- `RUST_FIELD_NAMES` — the frozen mapping from a Rust struct field name to the
  wire key a `#[derive(Serialize)] #[serde(rename_all = "camelCase")]` struct
  emits. Hand-written, and a removal or rename is a contract break.
- `mayhem.providers.sdk.rust_declaration` — the reader, which normalises a
  Rust-shaped manifest through that map and builds it with the same
  `ProviderBuilder` the Python front-end uses.
- A conformance suite that authors one provider through all three front-ends and
  asserts the canonical forms are byte-identical and the loaded registrations
  compare equal.

## The serialisation convention

Rust struct fields are `snake_case`; the wire contract is a mix. Two conventions
meet inside a single declaration, and that mix is the thing a hand-rolled
serialiser gets wrong:

- `ProviderMetadata`, `CapabilityDescriptor`, `TargetLocator`, `FaultDeclaration`
  and `CompatibilityBounds` declare camelCase aliases, so their Rust fields are
  snake_case and serialise to camelCase.
- `ParameterDeclaration`, `EvidenceSchema` and `EvidenceMapping` declare **no**
  aliases, so their wire keys stay snake_case all the way through —
  `target_locator_ids`, `fault_id`, `schema_version`.

That is why `RUST_FIELD_NAMES` is written out rather than derived: deriving it
would make the guard tautological, because a mapping changed carelessly would
then be blessed by the very test meant to notice.

## A manifest, in Rust field names

```json
{
  "provider_id": "acme.injector",
  "name": "ACME Injector",
  "version": "1.2.3",
  "description": "Slows a service without taking it down.",
  "permissions": ["target:read", "target:mutate"],
  "capabilities": [
    {
      "id": "acme.injector.mutate",
      "summary": "Adds latency to one service.",
      "required_permissions": ["target:read", "target:mutate"],
      "mutates_targets": true,
      "compensable": true
    }
  ],
  "target_locators": [
    {"id": "acme.svc", "kind": "service", "required_permissions": ["target:read"]}
  ],
  "fault_declarations": [
    {
      "id": "acme.slow",
      "capability": "acme.injector.mutate",
      "summary": "Adds latency.",
      "required_permissions": ["target:read", "target:mutate"],
      "target_locator_ids": ["acme.svc"],
      "mutation": "mutating",
      "reversible": true,
      "risk": "medium",
      "parameter_grammar": [
        {"name": "scale", "kind": "integer", "required": false, "default": "1",
         "minimum": 1.0, "maximum": 10.0, "choices": [], "pattern": null}
      ]
    }
  ],
  "evidence_schema": {"name": "acme-injector-evidence", "version": "1.0"},
  "evidence_mappings": [{"fault_id": "acme.slow"}],
  "compatibility": {"api_majors": ["v1"], "mayhem_min": "1.0.0", "engines": ["podman"]}
}
```

Reading it:

```python
from mayhem.providers.sdk import rust_declaration

artifact = rust_declaration(manifest)
```

## What an unknown key does

It is refused, by name, with the field named:

```
[sdk_rust_unknown_field] rust manifest field 'providerID' at rust has no wire name;
mayhem.providers.sdk.rust_declaration refuses it rather than dropping it, because a
field that vanishes on the way to the wire is a declaration that silently says less
than its author wrote.
```

The alternative — ignoring an unrecognised key — is the failure this whole
mechanism is for. A misspelled `providerId` that is silently dropped yields a
declaration that validates and has no identity.

## What this does not do for you

> **No signature is checked anywhere on this path.**
> `mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` is `False`. A Rust
> manifest describes what its author says the provider is; nothing in mayhem can
> establish that the person who wrote it is who the manifest claims.

When a real crate does ship, it will change exactly three things and nothing
else: the language surface, the transport for getting a manifest in front of the
reader, and the packaging. The wire contract it must satisfy is already pinned by
`RUST_FIELD_NAMES` and by the conformance suite.

## See also

- [sdk-python.md](sdk-python.md) — the reference front-end.
- [sdk-go.md](sdk-go.md) — the same contract with Go's acronym problem.
- [security-model.md](security-model.md).