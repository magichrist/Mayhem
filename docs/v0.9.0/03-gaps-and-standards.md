# v0.9.0 Gaps and Standards Register

## Current product gaps

### P0: execution and truth gaps

| Gap | Evidence | v0.9.0 response |
|---|---|---|
| Mutation intent is inconsistent | `mayhem run` and campaign/dependency paths do not share one explicit approval contract | Execution Intent Contract |
| Engine can be resolved differently between phases | lifecycle, services, and topology each resolve engine state | Resolved Runtime Context |
| Target profiles are not authoritative in main config | `MayhemConfigBase` does not expose the target-profile document shape | First-class target configuration |
| Capability truth is fragmented | registered executor, catalog status, runtime readiness, and live evidence are separate concepts | Capability Truth Dashboard |
| Some actions acknowledge without a backend | executor reports no-backend acknowledgements as success | Honest Action Outcomes |
| Kubernetes admission can fail late | node/pod target mismatches are discovered at mutation time in some paths | Typed target admission before lease creation |
| Evidence persistence can degrade silently | run paths suppress evidence write failures | Evidence completeness state |
| CLI/docs/examples disagree | Justfile and product docs contain stale command and install assumptions | Single product contract and contract tests |

### P1: reliability and operations gaps

| Gap | Consequence | v0.9.0 response |
|---|---|---|
| No PR quality gate | regressions reach release tags | Pull-request CI matrix |
| No package/schema smoke gate | artifacts can build but install incorrectly | wheel/sdist install smoke tests |
| No live conformance tier | “executable” can be mistaken for “live verified” | opt-in runtime conformance profiles |
| No campaign resume protocol | controller loss can force unsafe restart | checkpoint and resume state machine |
| Residual impact is operator-assessed | recovery success lacks a common post-check | Before/After Residual Impact |
| Redaction is fragmented | secrets can reach multiple persistence paths | one typed redaction boundary |
| No release provenance/SBOM | artifact trust is incomplete | SBOM, checksums, signed tags/artifact metadata |

## Standards needs

Mayhem should adopt the following standards and practices without claiming formal certification unless a separate audit proves it.

### Software and artifact quality

- Semantic Versioning and a documented compatibility matrix.
- PEP 517/PEP 621 packaging with wheel and sdist smoke tests.
- SPDX or CycloneDX SBOM for every release.
- SLSA-aligned provenance metadata for release artifacts.
- SHA-256 checksums and signed Git tags.
- Reproducible builds where the toolchain permits.
- Dependency lock/constraint policy and automated vulnerability scanning.
- GitHub Actions pinned to immutable commit SHAs.
- `python -m build` followed by installation into a clean virtual environment.

### API and schema standards

- Versioned JSON/YAML output schemas.
- Stable numeric exit-code contract.
- Database migrations with forward and rollback tests.
- Fault IDs as stable identifiers with deprecation metadata.
- Provider and capability contracts with explicit compatibility ranges.
- Schema validation for plans, approvals, evidence, and reports.
- No silent breaking changes to output fields; add fields compatibly or version the schema.

### Observability and evidence

- OpenTelemetry trace/span model for execution phases.
- Structured logs with correlation IDs, run IDs, plan IDs, lease IDs, and provider IDs.
- Redaction before any durable write or report render.
- Retention and deletion controls for databases and artifacts.
- Evidence bundle with immutable input manifest and hash chain.
- Clock skew, process death, and partial-write handling documented and tested.

### Kubernetes standards

- Supported Kubernetes minor-version matrix.
- RBAC preflight for every mutating operation.
- Namespace and context pinning in the plan.
- UID and `resourceVersion` capture for drift detection.
- PDB, admission policy, quota, and ownership checks where relevant.
- Dry-run and manifest inspection before live execution.
- Conformance tests for eviction, HPA reconciliation, ConfigMap/Secret restore, Service endpoints, storage detach/attach, node drain/uncordon, and DNS/CoreDNS restoration.
- Live results separated into a conformance artifact; no inferred live status from unit tests.

### Safety and governance

- Named target owner and environment classification.
- Change window and freeze-window policy.
- Dual control for critical faults and destructive Kubernetes actions.
- Break-glass ticket, approver, expiry, and post-incident review.
- Explicit blast-radius budget and forbidden fault pairs.
- Human-readable refusal with remediation.
- Cancellation and compensation escalation tested under controller loss.

### Security and supply chain

- OWASP ASVS-style controls for the CLI, provider loader, remote agent, and any future service.
- SAST, dependency scanning, secret scanning, and CodeQL or equivalent on pull requests.
- Provider permissions declared as data and enforced before entry-point loading.
- No provider receives implicit target mutation authority.
- No remote agent access without authenticated identity, scoped authorization, and replay protection.
- Kubeconfig, registry, environment, and command-line credential redaction.

## Quality SLOs proposed for v0.9.0

| SLO | Target | Measurement |
|---|---:|---|
| Plan completeness | 100% of mutating plans include intent, engine, target, policy, blast radius, and evidence requirements | schema validation |
| Correct refusal | 100% of known unsupported target/capability combinations refuse before lease creation | admission matrix tests |
| Compensation verification | 100% of clean successful runs have verified compensation state | run invariant test |
| Evidence completeness | ≥99.5% of completed runs have complete persisted evidence; remainder visibly degraded | evidence audit |
| Replay reproducibility | 100% of replay capsules pass deterministic dry-run validation | capsule validator |
| Redaction | 0 known credential fixtures in durable artifacts | redaction conformance suite |
| CI confidence | 100% of pull requests run unit, integration, package, schema, and security checks before merge | workflow inspection |
| Live conformance | every advertised `live_verified` status has a dated artifact and environment manifest | conformance registry |
