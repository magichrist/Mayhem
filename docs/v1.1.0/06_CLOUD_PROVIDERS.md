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
- Phase 2 (engine): DONE — `providers/cloud/` puts AWS, GCP and Azure behind one three-call `CloudTransport` port (enumerate / read once / act) and one `CloudAdapter` contract (discover, resolve, execute, compensate, verify) plus a pre-execution cost estimator and permission analyzer; each provider contributes only a capability table, so `ReversibleCapability` vs `IrreversibleCapability` makes "has no rollback" a type rather than a flag and a `COMPLETED` result is unconstructible without a verification that confirmed; 143 tests against recorded provider payloads.
- Phase 3: not started
- Phase 4: not started
- Phase 5: not started
- Phase 6: not started

Overall: 2 of 6 phases complete.

Known limitations:
- **`CostEstimate` extends `budgets.ResourceEstimate` rather than defining a cloud money type.** It inherits the mandatory `basis`, the finiteness/non-negativity rules, the `currency_micros` unit that `compare_estimate` already reads, and `RESOURCE_PRECISION` rounding, so there is one resource-vocabulary and one rounding in the system. The cost is that a cloud estimate carries a `scope`/`scope_key` the plan did not otherwise name; a caller must supply them (`ResourceScope.EXPERIMENT` + the account id is the natural choice). Nothing in `budgets.py` was modified to accommodate this.
- **The derived scalar `expected` is filled by a `mode="before"` validator**, because a frozen model cannot assign to itself afterwards. An author-supplied `expected` is checked against the range midpoint rather than silently overwritten, so a drifting scalar is a refusal — but the mechanism is a before-validator rather than a computed field, which a reviewer should confirm reads acceptably.
- **Nothing calls any of this yet.** `check_role_can_perform`, `check_cost_ceiling` and `resolve_cloud_target` have no call sites; Phase 2 (adapters) and Phase 4 (admission) are what wire them. Until then this is vocabulary with no consumer, exactly like plans 03 and 07 Phase 1.
- **`CLOUD_SELECTOR_EMPTY` and `CLOUD_ACTION_PERMISSION_UNDECLARED` are named but raised nowhere.** Both refusals happen inside a pydantic `model_validator`, which raises `ValueError` — there is no `CloudRefused` construction path that a field-level rule can reach, so a caller catching `CloudRefused` does *not* catch these two. They are kept in the vocabulary so a renderer can branch on a code it may eventually be handed off a wire, following the same reasoning as `FABRIC_UNDERSIGNED` in `domain/fabric.py`. A reviewer should decide whether a future phase wires them to real `CloudRefused` raise sites or drops them.
- **Irreversible actions are gated by *type*, not by an approval token.** `requires_elevated_approval` answers "does this need elevated approval", which is all Phase 1 can honestly answer; plan 09 owns what supplying that approval looks like, and no `approval_ref` field exists yet.
- **No real cloud SDK is wired; the transport port is the seam, and it is unbound.** Mayhem's declared dependencies are unchanged (pydantic, typer, click, pyyaml, structlog, kubernetes) — no boto3, no `google-cloud-*`, no `azure-mgmt-*`, and `pyproject.toml` was not touched. Every adapter is a provider-native capability table plus an injectable `CloudTransport`, and **no implementation of that port ships in Mayhem**: the only one that exists is the recorded-payload replay in `tests/unit/test_cloud_adapters.py`. Binding a real SDK is a later phase, and it has real work to do that this phase could not fake — translating SDK exceptions into `TransportFailure`, and re-pointing the recorded fixtures at responses captured from a live API rather than hand-written ones. Until then **nothing here has talked to a cloud**, and the provider-payload shapes in the tests are hand-authored, not captured.
- **The plan's own Phase 2 acceptance is not met: no adapter action has demonstrated compensate→verify on a sandbox account.** That needs credentials Mayhem does not have. What *is* demonstrated is that each action's compensation is a declared operation with a declared post-condition (`compensate_verify`) that the adapter checks against a fresh read, and that an action with neither is not declarable. The distinction matters: reversibility here is a **declaration with a machine-checkable shape**, not a demonstrated fact.
- **Cost estimates are UNPRICED by default, and a declared ceiling refuses them.** Mayhem bundles no price table. Without one, `expected_low == expected_high == 0.0` means *no price is known*, never *free*, and the basis discloses the real counts (API calls, instance-hours, volume operations). `ceiling == 0.0` is read as "no ceiling was declared"; a *declared* ceiling plus an unpriced action is refused (`cloud.cost_unpriced`), because Mayhem cannot certify an action it cannot price fits a limit somebody wrote down. A priced path exists only for an operator-supplied `CloudRateCard`, which must carry its own `source` string — Mayhem vouches for no number it did not read, and a card for a different region simply does not apply.
- **`billable_instance_hours` is a declaration about the provider, not a measurement.** It lives on the capability table so a reviewer reads the claim rather than trusting it, and it is why an Azure `powerOff` (still allocated, still billing) can be refused for a missing `duration_s` while an AWS or GCP stop estimates at zero instance-hours. If any of those billing claims is wrong, the wrong number is a table row and one test — the mechanism is honest, the inputs need review.
- **`reboot` and `isolate` are unsupported on every adapter, by design.** `reboot` is self-reconciling rather than compensable (no compensating API call, so no `compensate_verify` to assert), and `isolate` has no identity-preserving compensation, since restoring a peering or security group does not restore the same resource identity that `compensate_verify` is asserted against. Reporting unsupported beats substituting a near-miss, but it does mean the vocabulary is wider than what any adapter implements.
- **An irreversible capability declares no post-state, and `verify` refuses it.** The only post-state a destructive operation can honestly assert is absence, and Phase 1's vocabulary has no rung for it — `target_drift` means the planned identity is no longer the object present, which is the *opposite* claim from "destroyed as intended". So `verify` on an irreversible capability returns `cloud.verification_unavailable` rather than filing a confirmed deletion as drift. An irreversible action that left a resource present and observable would need a post-condition field here; that is a later phase's call.
- **Irreversible actions cannot execute at all in this phase.** `execute` refuses them with `cloud.irreversible_approval_required`, because plan 09 has not defined what supplying elevated approval looks like and inventing an approval token here would be inventing a policy. The capability declarations and the compensation refusals are therefore testable, but the execute path for an irreversible action is not reachable.
- **The adapter boundary catches `CloudAdapterError`, `CloudRefused` and `InvariantViolationError`, and deliberately no bare `Exception`.** That is what guarantees "a transport failure becomes a `StepOutcome`, never a silent success". The price is that a binding which forgets to wrap an SDK exception produces a traceback instead of a failed step — a louder failure, chosen on purpose, because a bug inside Mayhem must not be able to masquerade as a cloud refusal.
- **A reversible action's reversibility is still a claim.** The type guarantees a reversible action is not gated and an irreversible one is distinguishable and self-justifying; it does not demonstrate that the provider can roll it back. Phase 2's acceptance (compensate→verify on a sandbox account before catalog exposure) is what would make it true, and no adapter exists yet.
