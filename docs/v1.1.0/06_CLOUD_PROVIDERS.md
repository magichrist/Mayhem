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
Cloud actions enter blast-radius and damage-quota accounting (region/AZ blast rules in 07); cloud action logs correlated with Mayhem evidence (timestamped, monotonic-clock-annotated per the 12 time-sync rule). Acceptance: an action exceeding the cost ceiling refuses before mutation. DONE (STATUS): `controller/cloud_evidence.py`, the admission gate over the shared damage ledger and the attested chain per the plan-12 clock policy; region/AZ rules remain plan 07's, stated on every payload.

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
- Phase 3 (surface): DONE — `cli/cloud_cmd.py` mounts `mayhem cloud` (workflow `inspect`, not mutating) with three read-only verbs: `capabilities` renders each adapter's table through `capability_rows` with `mechanism_applied=false` on every row and the no-transport notice as output; `check-permission` answers "can this role perform this action?" through `analyze_permission` — the default role is the domain's `read_only` factory, so the default answer is a refusal naming the missing permission (the phase's acceptance), and the domain and sandbox permission models must agree or the analysis refuses; `estimate-cost` projects counts and prices only from an operator-supplied `CloudRateCard`, printing the domain's UNPRICED honesty line (zeros mean no price known, not free) and refusing a declared ceiling the estimate cannot fit. The adapter is constructed over a stub transport that raises on every call, so a future edit that made an analysis verb reach a provider fails loudly. Registered in `COMMAND_HELP`/`COMMAND_SPECS`/`register_commands`; pinned in `test_command_inventory.py` and `test_cli_exhaustive_matrix.py`; README CLI-surface row added; 20 tests in `test_cloud_surface.py`.
- Phase 4 (safety and evidence integration): DONE — `controller/cloud_evidence.py` wires cloud actions into the shared damage ledger and the attested-evidence chain. `admit_cloud_action` is the pre-mutation gate: permission stage (`analyze_permission`, refusals name the missing grant, and a cross-provider role's raised `cloud.role_provider_mismatch` is converted into the same staged refusal rather than escaping the gate), cost stage (`estimate_cost`, then the domain's own `ensure_cost_ceiling` judging the projected spend — **the acceptance**, an action exceeding its ceiling refusing before anything mutates, is pinned by a counting transport that raises on any `mutate`), then the damage-quota stage, which charges the caller's `DamageLedger` through `providers/participation.charge_provider_blast` — the same charge a native step and a third-party provider step make — at `UNRESOLVED_FAULT_WEIGHT` with `weight_source="unresolved_conservative"` reported, and refuses on the ledger's own `damage_quota.*` ids (charged-then-judged: the breach stays on the ledger). Region/AZ blast rules are plan 07's and every payload says so (`region_blast_rules` note) rather than implying "within quota" means "regionally bounded". `seal_cloud_decision` seals every allow *or* refusal into a chain under the namespaced key `<run_id>:cloud-actions` through the ordinary `AttestationRepository` (no second sealer), each event stamped by the plan-12 clock policy (`_recorded_at`, wall+monotonic taken once), with payloads naming action id, canonical resource id, account/region and projected spend so a sealed row joins the provider's own audit log without a second correlation scheme; `load_cloud_decisions` reloads exactly, and `verify_cloud_decision_chain` reports an unsealed run as `valid=False` ("no chain stored"), never silently allowed. No new `BOUNDARY_CALL_SITES` row is owed — persistence goes through the already-registered `save_chain`/`save_manifest` (same argument `controller/k8s_evidence.py` records). 27 tests in `test_cloud_evidence.py`.
- Phase 5: DONE — `tests/unit/test_plan06_phase5_contract.py` (adapter contract, refusal family, cost estimates) plus `tests/unit/test_plan06_phase5_negative_controls.py` (transport-never-reached, revoked-credential fencing, no-live-cloud). Contract: one lifecycle parametric over all three adapters (sorted matrix, identical adapter permission needs, reversible rows name a verifiable compensation, irreversible rows carry a rationale and no compensation field, unknown pairs unsupported never approximated, irreversible execute refused, irreversible verify unavailable, cross-provider intents refused, analyses transport-free) plus execute→compensate→verify demonstrated on a scripted fake and COMPLETED unconstructible without a confirming verification. Refusals: unresolved/ambiguous targets, insufficient IAM naming the grant, cross-provider roles, projected spend above ceiling (`cloud.cost_ceiling_exceeded`), ceiling below high, unpriced-under-declared-ceiling, billable-without-duration, quota breach on the ledger's own rule with the charge kept — every one leaving a counting transport at zero mutations, with an admitted priced control. Cost: UNPRICED zeros with the unknown-not-free basis, priced math from the operator card, foreign-region cards not applying, 4/2 call projection, spend-at-ceiling inside, invalid spends refused.
- Phase 6: DONE — adapter guide, honesty-marked capability matrix, machine-checked honesty gates (`tests/unit/test_plan06_phase6_docs.py`), and rollout order appended below.

Overall: 6 of 6 phases complete.

Known limitations:
- **`CostEstimate` extends `budgets.ResourceEstimate` rather than defining a cloud money type.** It inherits the mandatory `basis`, the finiteness/non-negativity rules, the `currency_micros` unit that `compare_estimate` already reads, and `RESOURCE_PRECISION` rounding, so there is one resource-vocabulary and one rounding in the system. The cost is that a cloud estimate carries a `scope`/`scope_key` the plan did not otherwise name; a caller must supply them (`ResourceScope.EXPERIMENT` + the account id is the natural choice). Nothing in `budgets.py` was modified to accommodate this.
- **The derived scalar `expected` is filled by a `mode="before"` validator**, because a frozen model cannot assign to itself afterwards. An author-supplied `expected` is checked against the range midpoint rather than silently overwritten, so a drifting scalar is a refusal — but the mechanism is a before-validator rather than a computed field, which a reviewer should confirm reads acceptably.
- **The analyses have two consumers, and both are transport-less.** `check_role_can_perform` and the adapter's `analyze_permission`/`estimate_cost` are called by `cli/cloud_cmd.py` (Phase 3, read-only) and by `controller/cloud_evidence.py`'s `admit_cloud_action` (Phase 4, the admission gate); `check_cost_ceiling` is reached through both. `resolve_cloud_target` still has no call site — it is the plan-authoring path, and neither the CLI nor the gate resolves against a live cloud because no transport ships.
- **`CLOUD_SELECTOR_EMPTY` and `CLOUD_ACTION_PERMISSION_UNDECLARED` are named but raised nowhere.** Both refusals happen inside a pydantic `model_validator`, which raises `ValueError` — there is no `CloudRefused` construction path that a field-level rule can reach, so a caller catching `CloudRefused` does *not* catch these two. They are kept in the vocabulary so a renderer can branch on a code it may eventually be handed off a wire, following the same reasoning as `FABRIC_UNDERSIGNED` in `domain/fabric.py`. A reviewer should decide whether a future phase wires them to real `CloudRefused` raise sites or drops them.
- **Irreversible actions are gated by *type*, not by an approval token.** `requires_elevated_approval` answers "does this need elevated approval", which is all Phase 1 can honestly answer; plan 09 owns what supplying that approval looks like, and no `approval_ref` field exists yet.
- **No real cloud SDK is wired; the transport port is the seam, and it is unbound.** Mayhem's declared dependencies are unchanged (pydantic, typer, click, pyyaml, structlog, kubernetes) — no boto3, no `google-cloud-*`, no `azure-mgmt-*`, and `pyproject.toml` was not touched. Every adapter is a provider-native capability table plus an injectable `CloudTransport`, and **no implementation of that port ships in Mayhem**: the only one that exists is the recorded-payload replay in `tests/unit/test_cloud_adapters.py`. Binding a real SDK is a later phase, and it has real work to do that this phase could not fake — translating SDK exceptions into `TransportFailure`, and re-pointing the recorded fixtures at responses captured from a live API rather than hand-written ones. Until then **nothing here has talked to a cloud**, and the provider-payload shapes in the tests are hand-authored, not captured.
- **The plan's own Phase 2 acceptance is not met: no adapter action has demonstrated compensate→verify on a sandbox account.** That needs credentials Mayhem does not have. What *is* demonstrated is that each action's compensation is a declared operation with a declared post-condition (`compensate_verify`) that the adapter checks against a fresh read, and that an action with neither is not declarable. The distinction matters: reversibility here is a **declaration with a machine-checkable shape**, not a demonstrated fact.
- **Cost estimates are UNPRICED by default, and a declared ceiling refuses them.** Mayhem bundles no price table. Without one, `expected_low == expected_high == 0.0` means *no price is known*, never *free*, and the basis discloses the real counts (API calls, instance-hours, volume operations). `ceiling == 0.0` is read as "no ceiling was declared"; a *declared* ceiling plus an unpriced action is refused (`cloud.cost_unpriced`), because Mayhem cannot certify an action it cannot price fits a limit somebody wrote down. A priced path exists only for an operator-supplied `CloudRateCard`, which must carry its own `source` string — Mayhem vouches for no number it did not read, and a card for a different region simply does not apply.
- **`billable_instance_hours` is a declaration about the provider, not a measurement.** It lives on the capability table so a reviewer reads the claim rather than trusting it, and it is why an Azure `powerOff` (still allocated, still billing) can be refused for a missing `duration_s` while an AWS or GCP stop estimates at zero instance-hours. If any of those billing claims is wrong, the wrong number is a table row and one test — the mechanism is honest, the inputs need review.
- **`reboot` and `isolate` are unsupported on every adapter, by design.** `reboot` is self-reconciling rather than compensable (no compensating API call, so no `compensate_verify` to assert), and `isolate` has no identity-preserving compensation, since restoring a peering or security group does not restore the same resource identity that `compensate_verify` is asserted against. Reporting unsupported beats substituting a near-miss, but it does mean the vocabulary is wider than what any adapter implements.
- **An irreversible capability declares no post-state, and `verify` refuses it.** The only post-state a destructive operation can honestly assert is absence, and Phase 1's vocabulary has no rung for it — `target_drift` means the planned identity is no longer the object present, which is the *opposite* claim from "destroyed as intended". So `verify` on an irreversible capability returns `cloud.verification_unavailable` rather than filing a confirmed deletion as drift. An irreversible action that left a resource present and observable would need a post-condition field here; that is a later phase's call.
- **Irreversible actions cannot execute at all in this phase.** `execute` refuses them with `cloud.irreversible_approval_required`, because plan 09 has not defined what supplying elevated approval looks like and inventing an approval token here would be inventing a policy. The capability declarations and the compensation refusals are therefore testable, but the execute path for an irreversible action is not reachable.

## Phase 6 — Adapter guide

Adding a fourth provider means adding rows, not code. The lifecycle
(`CloudAdapter.discover/resolve/execute/compensate/verify`, plus
`estimate_cost`/`analyze_permission`/`preflight`) is implemented once in
`providers/cloud/port.py`; a new adapter supplies three class attributes and
nothing else:

1. `provider_key` — the string `CloudProviderRef.key` compares against.
2. `services` — resource class to provider-native collection (`ec2`,
   `compute`, `sql`), because without it Mayhem does not know what to
   enumerate and must not guess.
3. `capabilities` — `(kind, resource_class)` to `ReversibleCapability` or
   `IrreversibleCapability`. A pair absent from the table is reported
   `cloud.action_unsupported`; it is never approximated by a near-miss. An
   action with no compensating operation is declared as
   `IrreversibleCapability` with a `rationale`, which has no
   `compensate_operation` field to fill in.

Binding a real SDK to `CloudTransport` (a later phase; no binding ships)
has four obligations, all of them fenced by tests, not by review:

- translate every SDK remote-failure exception into `TransportFailure`
  (or `TransportConflict` when the resource's own state refused the call);
  an untranslated exception escapes loudly rather than becoming a success;
- translate SDK payloads into `ResourceRecord` with provider-native field
  names carried verbatim, because verification compares those keys and a
  renamed key is evidence that no longer matches the console;
- echo the requested operation verbatim on every `MutationReceipt`;
  a receipt naming another operation is refused with
  `cloud.receipt_mismatch` rather than filed;
- re-point the recorded fixtures at responses captured from a live API
  rather than trusting the hand-written ones in
  `tests/unit/test_cloud_adapters.py`, which are shaped like the provider
  but were never returned by one.

## Capability matrix, honesty-marked

What the cloud API actually supports versus what Mayhem wraps, per row.
`demonstrated` is `false` on every row: no adapter action has demonstrated
compensate→verify on a sandbox account (the plan's own Phase 2 acceptance,
unmet — see Known limitations), and the `demonstrated_on_sandbox_account`
field on `CloudCapabilityRow` is a constant `False`, not a parameter, so no
caller can set it to `true`. `applied` is `false` on every row for the same
structural reason: no `CloudTransport` implementation ships, so no row
describes an operation Mayhem has performed.

| provider | kind/class | execute operation | reversible | compensate operation | demonstrated | billing note |
|---|---|---|---|---|---|---|
| aws | `stop/vm` | `ec2:StopInstances` | yes | `ec2:StartInstances` | no | stopped bills no compute |
| aws | `impair/vm` | `ec2:ModifyInstanceAttribute` | yes | `ec2:ModifyInstanceAttribute` | no | running: needs `duration_s` |
| aws | `failover/managed_database` | `rds:FailoverDBInstance` | yes | `rds:FailoverDBInstance` | no | running: needs `duration_s` |
| aws | `impair/block_storage` | `ec2:DeleteVolume` | no | — (none exists) | no | destructive delete |
| gcp | `stop/vm` | `compute.instances.stop` | yes | `compute.instances.start` | no | terminated bills no compute |
| gcp | `failover/managed_database` | `sqladmin.instances.failover` | yes | `sqladmin.instances.failover` | no | running: needs `duration_s` |
| gcp | `impair/block_storage` | `compute.disks.delete` | no | — (none exists) | no | destructive delete |
| azure | `stop/vm` | `virtualMachines/powerOff` | yes | `virtualMachines/start` | no | still allocated, still billing: needs `duration_s` |
| azure | `failover/managed_database` | `servers/databases/failover` | yes | `servers/databases/failover` | no | running: needs `duration_s` |
| azure | `isolate/function` | `web/delete` | no | — (none exists) | no | destructive delete |

No doc implies rollback where the cloud offers none: the three `no` rows in
the reversible column have no compensating operation to name, and
`mayhem cloud capabilities` prints each of them with
`irreversible (the cloud offers no rollback)`.

## Honesty gates

Machine-checked by `tests/unit/test_plan06_phase6_docs.py`, which reads this
document and fails the suite — not the review — when any of these stops
being true:

1. `Overall:` says 6 of 6 and the Phase 5/Phase 6 STATUS lines say DONE.
2. Every ``cloud.*`` code quoted in backticks exists in
   `domain/cloud.py` or `providers/cloud/port.py` — a refusal code nothing
   raises is a spelling, not a contract.
3. Every ``kind/class`` pair in the matrix above exists in the adapter
   tables, and every irreversible row states its rationale in source.
4. No row claims `demonstrated` or `applied`; the document promises no
   rollback it cannot perform, no delivery semantics it does not implement,
   and no live-account demonstration it has not run.
5. The rollout order below names `aws` first and requires one provider and
   one resource class at a time.

## Rollout order

One provider and one resource class at a time; each step graduates only
after its compensate→verify demonstrates on a sandbox account, which no
step has yet:

1. `aws` `stop/vm` first: reversible, non-billable while stopped, and the
   compensation (`ec2:StartInstances`) is the best-understood rollback in
   the tables.
2. Then the remaining reversible `aws` rows (`impair/vm`,
   `failover/managed_database`), one class at a time.
3. Then `gcp`, then `azure`, same rule: one resource class per step,
   reversible rows before any irreversible declaration is exercised.
4. Irreversible rows (`impair/block_storage`, `isolate/function`) never
   execute before plan 09 defines elevated approval; until then they are
   declarations a matrix can print, not actions a run can take.
5. Live cells only via plan 01 and only where sandbox accounts exist; the
   unit suite stays green without cloud credentials at every step.
- **The adapter boundary catches `CloudAdapterError`, `CloudRefused` and `InvariantViolationError`, and deliberately no bare `Exception`.** That is what guarantees "a transport failure becomes a `StepOutcome`, never a silent success". The price is that a binding which forgets to wrap an SDK exception produces a traceback instead of a failed step — a louder failure, chosen on purpose, because a bug inside Mayhem must not be able to masquerade as a cloud refusal.
- **A reversible action's reversibility is still a claim.** The type guarantees a reversible action is not gated and an irreversible one is distinguishable and self-justifying; it does not demonstrate that the provider can roll it back. Phase 2's acceptance (compensate→verify on a sandbox account before catalog exposure) is what would make it true, and no adapter exists yet.
