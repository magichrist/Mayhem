# Plan 06 — Cloud Fault Providers

**Priority:** P1. Gap items 6, 69.

## Objective
Provide provider-neutral cloud failure primitives while supporting cloud-native capabilities through adapters.

## Builds on
- `providers/` permission model (default posture nothing; capabilities declared and visible pre-execution).
- `domain/quota.py` damage pricing and blast-radius dependents closure — cloud actions price real `FaultDefinition`s, never estimates alone.
- Evidence envelope and redaction (cloud identifiers and account data classified; secrets never enter evidence per 29).

## Providers
AWS, GCP, Azure.

## Core resource classes
VM/instance, network, load balancer, object storage, block storage,
managed database, queues, functions, managed Kubernetes.

## Provider abstraction
```text
CloudProvider
  discover()
  capabilities()
  preview()
  execute()
  compensate()
  verify()
```

## Safety
Provider IAM role validation, resource allowlists,
account/project/subscription boundaries, region/AZ restrictions, cost
estimation (gap 69: expected incremental cost shown before execution,
cost ceiling enforced), stop conditions, automatic rollback where
supported.

## Phase 1 — Domain model: cloud vocabulary
Add `domain/cloud.py`: `CloudTarget` (provider, resource class, selector, resolved resource identity), `CloudAction` (stop, reboot, isolate, impair, failover), `CostEstimate` (expected range plus ceiling), all pure. Selectors resolve to exact resource identities; unresolved selectors are a plan-time refusal. Acceptance: resolution tests pin exact-identity semantics — no prefix/wildcard execution.

## Phase 2 — Engine: adapters behind the provider contract
Implement AWS/GCP/Azure adapters behind the abstraction; each action implements execute/compensate/verify or declares itself irreversible (irreversible actions require elevated approval per 09 and never run under implicit execution). Acceptance: every adapter action demonstrates compensate→verify on a sandbox account before catalog exposure.

## Phase 3 — Surface: provider commands and permission analysis
`mayhem cloud` command group (single inventory entry each, README/Justfile updated per the release contract), provider permission analyzer (`can this role perform this action?` answered pre-run), cost estimator output. Acceptance: IAM-insufficient plans refused with the missing permission named.

## Phase 4 — Safety and evidence integration
Cloud actions enter blast-radius and damage-quota accounting (region/AZ blast rules in 07); cloud action logs correlated with Mayhem evidence (timestamped, monotonic-clock-annotated per the 12 time-sync rule). Acceptance: an action exceeding the cost ceiling refuses before mutation.

## Phase 5 — Tests, regression guards, negative controls
Adapter conformance against recorded API fixtures (no live cloud in unit tests); refusal tests for unresolved targets, insufficient IAM, exceeded ceilings. Negative control: revoked credentials mid-run trigger fencing/recovery, never silent continuation. Acceptance: suite green without cloud credentials; live cells via 01 only where sandbox accounts exist.

## Phase 6 — Docs, honesty gates, rollout
Provider capability matrices marked per adapter honesty (what the cloud API actually supports vs. what Mayhem wraps); rollout one provider and one resource class at a time. Acceptance: no doc implies rollback where the cloud offers none.

## Deliverables
AWS provider, GCP provider, Azure provider, cost estimator, provider
permission analyzer, cloud audit integration.

## Dependencies
03 (fabric distribution), 07 (region/AZ policy, cost ceilings), 09 (elevated approvals), 12 (correlated evidence), 29 (cloud credentials).

## STATUS
- Phase 1 (domain model): DONE — `domain/cloud.py` landed `CloudProviderRef` (aws/gcp/azure plus a required-custom-id escape hatch), the nine-member `CloudResourceClass` vocabulary, `CloudSelector`/`CloudResourceIdentity`/`CloudTargetIntent`/`CloudTarget` with exact-identity-only resolution, `ReversibleCloudAction` vs `IrreversibleCloudAction` as structurally distinct types gated by `requires_elevated_approval`, `CloudRoleRef` + `check_role_can_perform` naming each missing permission, and `CostEstimate` extending the existing `budgets.ResourceEstimate` at `cloud_spend`; 121 tests.
- Phase 2: not started
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 1 of 6 phases complete.

Known limitations:
- **`CostEstimate` extends `budgets.ResourceEstimate` rather than defining a cloud money type.** It inherits the mandatory `basis`, the finiteness/non-negativity rules, the `currency_micros` unit that `compare_estimate` already reads, and `RESOURCE_PRECISION` rounding, so there is one resource-vocabulary and one rounding in the system. The cost is that a cloud estimate carries a `scope`/`scope_key` the plan did not otherwise name; a caller must supply them (`ResourceScope.EXPERIMENT` + the account id is the natural choice). Nothing in `budgets.py` was modified to accommodate this.
- **The derived scalar `expected` is filled by a `mode="before"` validator**, because a frozen model cannot assign to itself afterwards. An author-supplied `expected` is checked against the range midpoint rather than silently overwritten, so a drifting scalar is a refusal — but the mechanism is a before-validator rather than a computed field, which a reviewer should confirm reads acceptably.
- **Nothing calls any of this yet.** `check_role_can_perform`, `check_cost_ceiling` and `resolve_cloud_target` have no call sites; Phase 2 (adapters) and Phase 4 (admission) are what wire them. Until then this is vocabulary with no consumer, exactly like plans 03 and 07 Phase 1.
- **`CLOUD_SELECTOR_EMPTY` and `CLOUD_ACTION_PERMISSION_UNDECLARED` are named but raised nowhere.** Both refusals happen inside a pydantic `model_validator`, which raises `ValueError` — there is no `CloudRefused` construction path that a field-level rule can reach, so a caller catching `CloudRefused` does *not* catch these two. They are kept in the vocabulary so a renderer can branch on a code it may eventually be handed off a wire, following the same reasoning as `FABRIC_UNDERSIGNED` in `domain/fabric.py`. A reviewer should decide whether a future phase wires them to real `CloudRefused` raise sites or drops them.
- **Irreversible actions are gated by *type*, not by an approval token.** `requires_elevated_approval` answers "does this need elevated approval", which is all Phase 1 can honestly answer; plan 09 owns what supplying that approval looks like, and no `approval_ref` field exists yet.
- **A reversible action's reversibility is still a claim.** The type guarantees a reversible action is not gated and an irreversible one is distinguishable and self-justifying; it does not demonstrate that the provider can roll it back. Phase 2's acceptance (compensate→verify on a sandbox account before catalog exposure) is what would make it true, and no adapter exists yet.
