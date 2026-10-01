# Plan 17 — Extension SDK and Provider Protocol

**Priority:** P1. Gap items 34, 35, 37, 74, 75.

## Objective
Allow Mayhem's execution ecosystem to grow without expanding the core codebase for every specialized injector.

## Builds on
- `providers/registry.py` plus `permissions.py` (default posture nothing), `protocols.py` (`ProviderRuntime`), `domain/provider.py` (permissions, capability descriptors, fault declarations, evidence schemas, API compatibility) stay the sandbox core — the SDK is a nicer authoring path onto this exact contract, not a second contract.
- `providers/pack.py` validation (digest match, no shadowing, no path traversal, compensation required, unsigned-is-local-only) stays the loading gate; SDK-built providers pass through it unchanged.
- Honesty note: SDK signing conveniences change nothing about verification — a built artifact's signature is NOT verified in this build, and any document discussing SDK signing must say so in the same breath.

## Provider contract
A provider declares: provider identity/version, fault types, targets,
required capabilities, risk class, parameters/schema, execute function,
compensation, verification, permissions, evidence mapping.

## SDK languages
Rust, Python, Go.

## Security
Extensions are untrusted by default. Require: signed artifacts (with
the honesty note above), declared permissions, sandboxing where
possible, capability dropping, network egress restrictions, SBOM.

## Phase 1 — Domain model: declaration schema
Stabilize `domain/provider.py` declarations as the versioned wire contract (`mayhem.provider/v1` family): fault declarations with parameter grammars, capability descriptors, permission sets, evidence-schema mappings, compatibility bounds. Pure data with schema tests. Acceptance: a provider built against v1 loads unchanged after core minor releases (compat test with a frozen fixture provider).

## Phase 2 — Engine: loader and sandbox enforcement
Harden `providers/loader.py` checks as the single enforcement point (digest, shadowing, traversal, declaration/definition agreement, compensation presence); add sandbox profiles (seccomp/AppArmor/SELinux, container isolation, filesystem and egress restrictions per gap 75) selected by declared permissions. The 37 "Mayhem-compatible provider" protocol is this declaration schema plus the 03 fabric command envelope — one protocol, two documents referencing it. Acceptance: a provider requesting undeclared capabilities is refused at load; a sandboxed provider attempting egress outside policy is denied with the denial in evidence.

## Phase 3 — Surface: SDKs and permission UX
Ship Rust/Python/Go SDKs generating declaration schemas from code (derive macros / decorators), plus the extension permission display (gap 74: what this extension CAN and CANNOT do, requiring explicit approval before install or execution). Acceptance: the examples/providers TestProvider reimplemented via each SDK with identical loaded registrations.

## Phase 4 — Safety and evidence integration
Provider actions participate in admission, blast accounting, damage quota, leases, and evidence exactly like native actions (the acceptance criterion that matters); provider faults enter the 01 certification pipeline with their provider version pinned in the matrix cell. Acceptance: a provider fault without compensation is refused at load (existing rule, new test per SDK).

## Phase 5 — Tests, regression guards, negative controls
SDK conformance suite (same provider, three SDKs, identical behavior), loader refusal tests (20+ refusal paths extended), sandbox escape-attempt tests, permission-display accuracy tests. Negative controls: a provider whose loaded behavior differs from its declarations is revoked; shadowing a built-in id fails loudly. Acceptance: full matrix green.

## Phase 6 — Docs, honesty gates, rollout
SDK guides per language, provider security model doc, marketplace-readiness checklist (feeds 18). Rollout: Python SDK first (closest to core), Rust and Go second, sandbox profiles third. Acceptance: no doc calls an SDK-built artifact trusted, verified, or signed without the same-breath disclaimer.

## Dependencies
03 (fabric envelope), 07 (permission/collision policy), 12 (evidence mapping), 18 (distribution), 19 (sandbox primitives, SBOM).

## STATUS
- Phase 1 (domain model): DONE — `src/mayhem/domain/provider.py` extended in place as the versioned `mayhem.provider-declaration/v1` wire contract (parameter grammar, capability descriptors, permission set, evidence-schema mapping, explicit compatibility bounds, and the pure gates `ensure_compatibility_bounds` / `ensure_declared_permissions` / `fault_parameter_problems`); every added field carries a default, and `tests/unit/test_provider_declaration.py` pins that with a frozen pre-Phase-1 v1 fixture that still parses, still emits every key it used to, and still registers across core minor releases. **SIGNATURE VERIFICATION IS NOT IMPLEMENTED** — `mayhem.providers.pack.SIGNATURE_VERIFICATION_IMPLEMENTED` remains `False` and this phase does not change it: a declaration carries no signature field at all (a test asserts that structurally), no provider artifact's signature is checked here, and no later-phase SDK signing convenience changes any of that — an SDK-built artifact stays an unverified claim of authorship until that flag is `True`.
- Phase 2 (engine): DONE — `providers/loader.py` is the single enforcement point (`ProviderLoader._admit` runs compatibility bounds → declared permissions → declaration graph → parameter defaults → evidence coverage → id shadowing → sandbox profile, in that fixed order, every refusal carrying a named code, and `_register_runtime` adds the runtime-behaviour check *before* a mismatched runtime reaches the registry), and `providers/sandbox.py` defines the gap-75 seam: profiles selected by declared permissions (seccomp/AppArmor/SELinux/container isolation/capability dropping/filesystem egress rules) whose *decisions* are proven with fakes and whose mechanisms are labelled `declared_not_applied` — **no seccomp filter, AppArmor profile, SELinux label or container is created in this build, so a provider that declares `network` or `target:mutate` is loaded unconfined**; `ProviderLoader(require_sandbox_enforcement=True)` refuses those instead, and every sandbox denial is written as a `ProviderEvidenceRecord` *and* raised, never swallowed. **SIGNATURE VERIFICATION IS STILL NOT IMPLEMENTED** and Phase 2 changes nothing about it: sandboxing, capability dropping and egress rules are decisions about *what a provider declared*, not evidence about *who wrote it*, no SDK exists yet, and no sandbox convenience turns an unverified claim of authorship into a verified one.
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 2 of 6 phases complete.
