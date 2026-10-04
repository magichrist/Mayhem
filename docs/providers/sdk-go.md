# The Go wire contract

> **There is no Go package in this repository.** `GO_SDK_SHIPPED` is `False` and
> mayhem ships no `go.mod` for its provider SDK. What follows is the *wire
> contract* a Go struct must satisfy — its `json:"..."` tags, the normalisation
> the reader performs, and the reason no package is distributed here.

The honest reason is on [sdk-rust.md](sdk-rust.md) and applies unchanged. What
is specific to Go is that a derived mapping is **actively wrong**, and that is
what `GO_FIELD_TAGS` exists for.

## Why Go needs an explicit tag map

Go's initialism convention puts consecutive capitals in a field name, and a
mechanical lower-casing mangles every one of them:

| Go field | mechanical lower-case | correct wire key |
|---|---|---|
| `ProviderID` | `providerid` | `providerId` |
| `TargetLocatorIDs` | `targetlocatorids` | `target_locator_ids` |
| `FaultID` | `faultid` | `fault_id` |
| `APIVersion` | `apiversion` | `apiVersion` |

Only an explicit tag map gets these right, and only an explicit tag map is
checkable. So `GO_FIELD_TAGS` is the contract — hand-written, complete, and
covering every key the Rust front-end can spell, so a missing tag is a refusal
rather than a silently-dropped field.

## The serialisation convention

Identical to the Rust side, and the same mix is the point: aliased models
serialise to camelCase, and `ParameterDeclaration`, `EvidenceSchema` and
`EvidenceMapping` declare no aliases and stay snake_case on the wire.

## A manifest, in Go field names

```json
{
  "ProviderID": "acme.injector",
  "Name": "ACME Injector",
  "Version": "1.2.3",
  "Description": "Slows a service without taking it down.",
  "Permissions": ["target:read", "target:mutate"],
  "Capabilities": [
    {
      "ID": "acme.injector.mutate",
      "Summary": "Adds latency to one service.",
      "RequiredPermissions": ["target:read", "target:mutate"],
      "MutatesTargets": true,
      "Compensable": true
    }
  ],
  "TargetLocators": [
    {"ID": "acme.svc", "Kind": "service", "RequiredPermissions": ["target:read"]}
  ],
  "FaultDeclarations": [
    {
      "ID": "acme.slow",
      "Capability": "acme.injector.mutate",
      "Summary": "Adds latency.",
      "RequiredPermissions": ["target:read", "target:mutate"],
      "TargetLocatorIDs": ["acme.svc"],
      "Mutation": "mutating",
      "Reversible": true,
      "Risk": "medium",
      "ParameterGrammar": [
        {"Name": "scale", "Kind": "integer", "Required": false, "Default": "1",
         "Minimum": 1.0, "Maximum": 10.0, "Choices": [], "Pattern": null}
      ]
    }
  ],
  "EvidenceSchema": {"Name": "acme-injector-evidence", "Version": "1.0"},
  "EvidenceMappings": [{"FaultID": "acme.slow"}],
  "Compatibility": {"APIMajors": ["v1"], "MayhemMin": "1.0.0", "Engines": ["podman"]}
}
```

Reading it:

```python
from mayhem.providers.sdk import go_declaration

artifact = go_declaration(manifest)
```

## The conformance claim

The Go front-end and the Python front-end produce **byte-identical** canonical
documents for the same provider, and their artifacts load into equal
registrations through a real `ProviderLoader`. That is asserted, not asserted
about: `tests/unit/test_provider_sdk.py::TestCrossSdkConformance` drives all
three front-ends and compares the canonical strings.

It is also a property with teeth. Delete one key from `GO_FIELD_TAGS` and the
conformance suite fails; spell `ProviderId` instead of `ProviderID` and the Go
reader refuses by name.

## What this does not do for you

> **No signature is checked anywhere on this path.**
> `mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` is `False`. A Go
> manifest describes what its author says the provider is; nothing in mayhem can
> establish that the person who wrote it is who the manifest claims.

A Go implementation may also face a question the Python and Rust front-ends do
not: mayhem cannot receive a Go runtime in this build. The loader's runtime
contract (`mayhem.providers.protocols.ProviderRuntime`) is structural and
satisfied by an in-process object, and a cross-language runtime bridge is not part
of this build. That is a real limitation, not a formatting detail, and it is why
no package is distributed.

## See also

- [sdk-python.md](sdk-python.md) — the reference front-end.
- [sdk-rust.md](sdk-rust.md) — the same contract in snake_case.
- [security-model.md](security-model.md).