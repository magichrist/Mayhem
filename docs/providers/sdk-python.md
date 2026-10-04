# The Python SDK

`mayhem.providers.sdk` is the reference front-end. It is the only one of the
three that is an actual authoring library in this build; see
[sdk-rust.md](sdk-rust.md) and [sdk-go.md](sdk-go.md) for why the other two are
wire contracts rather than packages.

> **An SDK-built declaration is a claim of authorship, not a verified one.**
> `mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` is `False`. Building
> a declaration here validates its *grammar* and nothing else: not the code, not
> the publisher, not the artifact's integrity since publication.

## A provider, end to end

```python
from mayhem.providers.sdk import ProviderBuilder, python_declaration

builder = ProviderBuilder(
    "acme.injector",
    name="ACME Injector",
    version="1.2.3",
    description="Slows a service without taking it down.",
    permissions=["target:read", "target:mutate"],
)

builder.capability(
    "acme.injector.mutate",
    summary="Adds latency to one service.",
    required_permissions=["target:read", "target:mutate"],
    mutates_targets=True,
    compensable=True,
)
builder.locator("acme.svc", kind="service")

builder.fault(
    "acme.slow",
    capability="acme.injector.mutate",
    summary="Adds latency.",
    required_permissions=["target:read", "target:mutate"],
    target_locator_ids=["acme.svc"],
    mutation="mutating",
    reversible=True,
    parameter_grammar=[
        builder.parameter("scale", kind="integer", required=False, default="1",
                          minimum=1, maximum=10,
                          summary="multiplier on the added latency"),
    ],
)

builder.evidence_schema("acme-injector-evidence", "1.0")
builder.evidence_mapping("acme.slow")
builder.compatibility(mayhem_min="1.0.0", engines=["podman"])

artifact = python_declaration(builder)
print(artifact.canonical)          # byte-stable; safe to hash
print(artifact.authenticity)      # declared_unverified
```

`artifact.canonical` is produced by `canonical_json`, the one canonicaliser in
the module. Rust and Go artifacts route through the same function, which is what
makes "the three SDKs agree byte for byte" a checkable claim rather than a hope.

## What the builder validates, and what it does not

**It validates** — by calling `ProviderMetadata.model_validate`, so the SDK and
the core share one grammar:

- identifier shapes, semantic versions, and identifier/version uniqueness;
- that a fault hangs off a declared capability and declared locators;
- that no part of the declaration asks for a permission the provider did not
  declare;
- that a mutating fault requires `target:mutate` and declares a compensation
  path, and that a read-only fault requires no action permissions;
- that every evidence mapping names a declared fault and this provider's own
  published schema;
- that an optional parameter declares a default.

**It does not validate:**

- anything about your code — the SDK never sees it;
- that the provider id, version or homepage names anything real;
- that the runtime you hand the loader behaves as the declaration says. That is
  `ProviderLoader._register_runtime`'s job, and it runs *before* the runtime
  reaches the registry, so a runtime that advertises a fault, capability or
  permission it never declared is refused rather than registered and revoked.

## What the SDK refuses to build

Two refusals are worth knowing, because both are cases where building anyway
would produce a declaration that says more than you wrote:

- **No evidence schema.** `evidence_schema()` is required. A declaration with
  none cannot be checked for evidence coverage by the loader, so the SDK refuses
  before you get that far.
- **An unknown field.** The Rust and Go readers refuse an unrecognised manifest
  key by name (`rust_unknown_field`, `go_unknown_field`) rather than passing it
  through. A field that vanishes on the way to the wire is a declaration that
  silently says less than its author wrote, which is the failure mode a derive
  macro exists to prevent.

## Loading it

`ProviderLoader.load_registration` runs an in-memory registration through the
same gates, in the same order, as a catalog-loaded one:

```python
from mayhem.domain.provider import ProviderPermission
from mayhem.providers.loader import ProviderLoader

loader = ProviderLoader(allowed_permissions=frozenset(ProviderPermission))
inspection = loader.load_registration(artifact.registration(), runtime)
```

It is the *same* `_admit` then `_register_runtime` a catalog load takes. A
declaration that loads here and would not have loaded from a catalog is a bug in
the gates, and using this method is what makes that bug observable rather than
something you have to arrange a temporary file to discover.

## The permission display (gap 74)

Before an install, an operator has to be shown what an extension **can** and
**cannot** do:

```python
from mayhem.providers.sdk import approve_permission_display, describe_permission_display, permission_display

display = permission_display(artifact.metadata,
                             grant=frozenset({ProviderPermission.TARGET_READ}))
print(describe_permission_display(display))
```

The display is never approved when it is built. `display.approved` is `False`,
`display.can_do` is empty, and every requested permission appears under
`cannot_do` with the reason and which part of the provider asked for it.
`approve_permission_display(display, actor=..., approval_id=...)` is the only
thing that grants anything, and it grants exactly one thing: that *this*
declaration may reach *these* permissions for *this* install. It does not widen
the loader's grant, so a display approved while a declared permission is
ungranted is still not `installable`.

Every rendered `can_do` line carries the sandbox caveat, because **allowed is not
confined** — see [security-model.md](security-model.md).

## Three properties worth relying on

1. **`AuthoredArtifact` has no field that could carry a signature.** Not an empty
   one, not a nullable one. There is nowhere to put one, so an artifact cannot
   become the thing that makes a reader believe a check happened.
2. **`ArtifactAuthenticity` has one member** and refuses to become two.
   `DECLARED_UNVERIFIED` is the only value, and promoting it requires a trust
   store and a key — not a flag.
3. **The canonical form is derived, never supplied.** The document and its
   canonical string are computed from the metadata inside
   `author_artifact`, so a caller cannot attach a document that does not match.

## See also

- [security-model.md](security-model.md) — what a provider can reach and what is
  actually confined.
- [marketplace-readiness.md](marketplace-readiness.md) — what plan 18 checks
  before it will list a provider.
- [sdk-rust.md](sdk-rust.md), [sdk-go.md](sdk-go.md) — the other two front-ends.