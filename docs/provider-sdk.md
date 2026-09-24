# Provider SDK and governance

Mayhem providers extend discovery, fault declaration, target resolution, compensation, checks, observability, and reporting without replacing the plan-first, safety, lease, or evidence contracts. The provider boundary is deliberately two-phase:

1. A declarative `ProviderMetadata` object describes what a provider contributes and what it needs.
2. A runtime implementation is loaded only after metadata, compatibility, and permission checks succeed.

The domain declaration models live in `mayhem.domain.provider`. They do not import providers, perform I/O, inspect entry points, or construct runtime objects. Runtime protocols live in `mayhem.providers.protocols`.

## Author a provider

A provider starts with a stable lowercase dotted identifier, a semantic provider version, a catalog API version, and an evidence schema. Every capability, target locator, and fault declaration must reference only declarations in the same provider.

```python
from mayhem.domain.provider import (
    PROVIDER_API_VERSION,
    CapabilityDescriptor,
    EvidenceSchema,
    ProviderMetadata,
    ProviderPermission,
    ProviderRegistration,
    TargetLocator,
)

metadata = ProviderMetadata(
    api_version=PROVIDER_API_VERSION,
    provider_id="acme.platform",
    name="ACME Platform",
    version="1.0.0",
    description="Discovers ACME platform objects.",
    permissions={ProviderPermission.TARGET_READ},
    capabilities=(
        CapabilityDescriptor(
            id="target.discovery",
            summary="Resolve ACME targets.",
            required_permissions={ProviderPermission.TARGET_READ},
        ),
    ),
    target_locators=(
        TargetLocator(
            id="acme.target",
            kind="acme_object",
            selector_schema={"id": "string"},
            required_permissions={ProviderPermission.TARGET_READ},
        ),
    ),
    evidence_schema=EvidenceSchema(
        name="acme-platform-evidence",
        version="1.0",
        fields=("recorded_at", "operation", "target", "outcome"),
    ),
)
registration = ProviderRegistration(
    metadata=metadata,
    implementation={
        "kind": "import",
        "target": "acme_mayhem.provider:Provider",
        "factory": True,
    },
)
```

The implementation may be a runtime object or a zero-argument factory. A class reference is loaded as a class; set `factory: true` only for a callable that returns the runtime object. A provider must not execute an uncompiled plan, call safety policy, create leases, or manufacture compensation receipts. Those remain Mayhem-owned responsibilities.

`ProviderRuntime` is the minimum discovery shape: `id`, `is_available`, `capabilities`, and `discover`. `FaultRuntime`, `TargetLocatorRuntime`, and `EvidenceRuntime` are optional structural protocols. A provider may implement only the protocols corresponding to its declarations.

The complete dependency-free example is `examples/providers/test_provider.py`, with a matching catalog at `examples/providers/test-catalog.json`.

## Permissions and safety

Permissions are explicit and deny-by-default for external providers:

| Permission | Meaning |
| --- | --- |
| `network` | Outbound network access. |
| `filesystem:read` | Reading files outside Mayhem-owned read-only inputs. |
| `filesystem:write` | Writing or changing filesystem state. |
| `subprocess` | Starting a process or executable. |
| `target:read` | Reading provider target metadata. |
| `target:mutate` | Changing a selected target. |

A mutating capability must require `target:mutate`; a mutating fault must also declare a reversible compensation path. The metadata model rejects incomplete mutation declarations. The loader then intersects every declared permission with the caller's allowed set. A plugin is not loaded when a permission is missing, even if the permission appears only in a nested fault or capability declaration.

Safety remains outside the provider:

- Mayhem compiles and validates the plan before provider mutation.
- Mayhem applies policy, blast-radius, environment, and lease gates.
- Mayhem owns compensation scheduling and recovery decisions.
- Providers return observations and provider-scoped evidence; they do not suppress failed checks.

The permission list is a declaration and policy gate, not a sandbox. Providers that need process isolation should be packaged and run behind a separate, reviewed service boundary. Mayhem does not claim to sandbox arbitrary Python code inside the CLI process.

## Catalog format and loading

A catalog is a JSON document with `apiVersion: mayhem.provider-catalog/v1` and a `providers` array. Each provider contains a metadata object and an implementation reference. The implementation reference is either:

```json
{
  "kind": "import",
  "target": "package.module:Factory",
  "factory": true
}
```

or an entry-point reference with `kind: "entry_point"` and the provider id as `target`. Import paths are explicit configuration and are only resolved by an explicit load operation.

Inspect without loading an implementation:

```bash
mayhem extend providers inspect --catalog examples/providers/test-catalog.json --json
```

Load only a selected catalog with an explicit permission grant:

```bash
mayhem extend providers load \
  --catalog examples/providers/test-catalog.json \
  --allow-permission target:read \
  --json
```

For installed distributions, declare two entry-point groups. The metadata entry point is a declaration-only object and is validated before the implementation entry point is loaded:

```toml
[project.entry-points."mayhem.provider.metadata"]
"acme.platform" = "acme_mayhem:PROVIDER_METADATA"

[project.entry-points."mayhem.providers"]
"acme.platform" = "acme_mayhem:provider_factory"
```

Then explicitly inspect or load a provider id:

```bash
mayhem extend providers inspect --entry-point acme.platform --json
mayhem extend providers load --entry-point acme.platform --allow-permission target:read --json
```

Entry-point discovery is not part of ordinary Mayhem commands. Built-in Docker, Podman, and Kubernetes operations use the built-in registry and never import external provider implementations.

## Versioning

- Provider versions use semantic versioning: `MAJOR.MINOR.PATCH`.
- Provider API compatibility is determined by the `mayhem.provider/v1` major version.
- A major API change requires a new `mayhem.provider/vN` contract and a new compatibility release.
- Additive capabilities, locators, or evidence fields require a minor provider version and must preserve old readers.
- Removing or changing an existing declaration requires a major version and a deprecation window.
- Catalog schema and evidence schema versions are independent and must be included in compatibility checks.

## Testing requirements

Provider tests should be deterministic and local. Do not import or execute untrusted third-party code in Mayhem unit tests. Use first-party fixtures, fake APIs, injected import functions, and in-memory entry points.

At minimum, test:

- metadata acceptance and rejection of malformed graphs;
- API and catalog compatibility;
- permission policy refusal, including mutation permissions;
- dry-run inspection proving implementation code was not loaded;
- lazy factory construction and duplicate registration;
- typed import and factory failures isolated from built-ins;
- target resolution and drift evidence;
- compensation success, failure, and incomplete-receipt behavior;
- evidence records with timestamps, source, outcome, and compensation status.

The provider's own unit tests should cover all declared capabilities and every mutating path. Live or end-to-end tests belong in a separately isolated environment and are not part of the provider SDK test suite.

## Compensation and evidence

A mutating provider operation returns a provider-scoped receipt containing enough information for Mayhem to request compensation and later verify the result. The provider must not return a successful compensation status without an observed target state and a compensation token. `ProviderEvidenceRecord` requires an operation, target, outcome, timestamp, source, and compensation status; an `observed` status additionally requires a token.

Evidence must distinguish:

- planned versus resolved target;
- requested versus observed mutation;
- pending versus observed compensation;
- capability refusal versus provider failure;
- provider version and evidence schema version.

Mayhem wraps provider evidence in its run envelope and retains the plan hash, safety decisions, lease timeline, and provider version. Provider evidence cannot replace run-level evidence.

## Deprecation procedure

1. Mark the declaration deprecated in provider metadata and release notes.
2. Publish a replacement declaration or supported alternative.
3. Add catalog-level compatibility tests for both versions.
4. Announce the removal version and minimum supported Mayhem API.
5. Keep the old declaration loadable during the published window.
6. Remove it only after the compatibility matrix marks the version unsupported.

Deprecation does not grant a provider a new permission or allow it to bypass a safety gate.

## Security response procedure

1. Disable the provider id in the explicit load policy and revoke its permissions.
2. Preserve the catalog, metadata, evidence, and version used by the affected run.
3. Reproduce with a local fixture; do not import the suspect implementation in unit tests.
4. Report the provider, provider version, API version, permission set, and minimal evidence.
5. Notify downstream catalog operators if the provider id or distribution is compromised.
6. Publish a fixed version or a security advisory with a compatibility impact statement.
7. Require a new metadata and evidence review before restoring the permission.

A missing, broken, or incompatible provider must leave built-in Docker, Podman, and Kubernetes behavior unchanged.

## Compatibility matrix

| Mayhem contract | Supported version | Compatibility rule | Provider response |
| --- | --- | --- | --- |
| CLI surface | Mayhem 0.6 workflow groups | Built-in commands remain available without plugins | Reject external providers that require CLI changes |
| Provider API | `mayhem.provider/v1` | Same major API is accepted; incompatible major is rejected | Declare a new API major or adapt to v1 |
| Catalog schema | `mayhem.provider-catalog/v1` | Catalog major must match exactly | Publish a catalog-compatible release |
| Evidence envelope | `mayhem.provider-evidence/v1` | Evidence major must match exactly | Emit the declared evidence schema |
| Built-in registry | Docker, Podman, Kubernetes | Built-ins are independent of plugin availability | Use built-ins as the fallback path |

## Builder workflow

A builder or test author can add a test provider by creating metadata and a first-party runtime, then registering it directly with `ProviderRegistry` or loading its explicit catalog. No CLI internals need to change. The provider remains test-only until its permissions, safety behavior, compensation, evidence, catalog, and security response have been reviewed.
