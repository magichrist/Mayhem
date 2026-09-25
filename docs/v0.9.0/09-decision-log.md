# v0.9.0 Decision Log and Risk Register

## Accepted decisions

| ID | Decision | Rationale | Revisit when |
|---|---|---|---|
| ADR-001 | Resolve one runtime context per plan | Prevents engine drift between planning and execution | A runtime requires cross-process context transfer |
| ADR-002 | Require explicit execution intent | Prevents accidental destructive behavior | A product decision explicitly restores a named unsafe adapter |
| ADR-003 | Model capability truth as multiple dimensions | Avoids equating registration with live support | A mature capability registry can replace the model |
| ADR-004 | Persist replay capsules and evidence bundles | Makes results portable and independently verifiable | Artifact format reaches a stable external standard |
| ADR-005 | Redact before every durable boundary | Prevents fragmented secret handling | A platform-wide secret broker is adopted |
| ADR-006 | Keep live conformance separate from default CI | Preserves safe, reproducible automation | Live clusters become disposable test infrastructure |
| ADR-007 | Refactor architecture in vertical slices | Limits regression risk while reducing import debt | The project adopts a large architectural rewrite |

## Top risks

| Risk | Probability | Impact | Mitigation | Owner |
|---|---:|---:|---|---|
| Scope expansion into too many features | High | High | Lock the P0 portfolio; defer P2 work | Product owner |
| Runtime context migration changes behavior | Medium | High | Golden CLI/E2E tests and staged rollout | Runtime owner |
| Explicit intent breaks scripts | Medium | Medium | Release migration guide and explicit compatibility diagnostics | Product owner |
| Live Kubernetes claims exceed evidence | Medium | High | Separate conformance registry and release gate | Kubernetes owner |
| Evidence schema becomes unstable | Medium | High | Version schemas and preserve old readers | Evidence owner |
| Redaction misses secret shapes | Medium | High | Adversarial fixtures, structured boundary tests, security review | Security owner |
| CI becomes slow or flaky | Medium | Medium | Serial correctness tier, opt-in conformance tier, shard by file | CI owner |
| Provider loading becomes an RCE path | Low/Medium | High | Explicit permission sandbox and no implicit mutation | Security owner |
| Architecture debt remains hidden | High | Medium | Track import contracts and add new boundary tests per feature | Architecture owner |
| Release metadata drifts from executable behavior | Medium | High | Registry/schema/package contract tests | Release owner |

## Rejected shortcuts

- Do not mark every registered Kubernetes fault as live-supported.
- Do not silently choose Docker when multiple engines are installed.
- Do not treat no-backend acknowledgements as success.
- Do not remove the evidence pipeline to make tests pass.
- Do not add a broad REST service before the CLI/application-service contract is stable.
- Do not use a remote agent to bypass local safety and lease boundaries.
- Do not add every brainstormed feature to v0.9.0.

## Planning completion checklist

- [x] Current capabilities and gaps are documented.
- [x] Creative feature portfolio is prioritized.
- [x] Standards and operational requirements are listed.
- [x] Architecture and ADRs are explicit.
- [x] Release phases and dependencies are defined.
- [x] Core implementation tasks have files, interfaces, tests, commands, and commit points.
- [x] Expansion implementation tasks have the same level of detail.
- [x] Release readiness and rollback are defined.
- [ ] Human/product review — not requested in this planning-only run.
- [ ] Implementation begins only after the roadmap is accepted.

## Recommended implementation order

1. Task 1: truth baseline.
2. Task 2: runtime context.
3. Task 3: execution intent.
4. Task 4: target profiles.
5. Task 6: typed admission.
6. Task 7 and Task 8: replay, evidence, and redaction.
7. Task 5 and Task 10: capability truth and honest actions.
8. Task 9: quality gates.
9. Task 11 onward: operator expansion.

Tasks 5, 7, 8, and 10 can be developed in parallel after Tasks 1–4, provided their shared contracts are reviewed first. Live conformance and remote-agent work must remain opt-in.
