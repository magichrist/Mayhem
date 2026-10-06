# Policy authoring, precedence, and migration

The operating guide for plan 07's policy engine: how to author a bundle, what
the evaluator can actually read, which check decides when two disagree, how to
migrate from the `policy:` config block, and in what order the program rolls
this out. Phase 6 of `docs/v1.1.0/07_POLICY_SAFETY_ENGINE.md`; every claim here
is machine-checked by `tests/unit/test_policy_plan_docs.py`.

## Publishing a bundle

A bundle is a YAML or JSON document with a `bundle_id`, a `version`, and its
rules. The verbs over it live in `mayhem policy`:

```bash
mayhem policy publish policy.yaml        # author as a new, immutable version
mayhem policy list                       # what exists
mayhem policy show prod-rules --version 3 # one version, read back verbatim
mayhem policy resolve prod-rules         # which version a run would decide under
mayhem policy retire prod-rules --version 3  # tombstone; there is no delete
mayhem policy explain plan.json --policy prod-rules --environment production
```

A minimal document:

```yaml
bundle_id: prod-rules
version: 1
default_effect: allow
rules:
  - rule_id: prod.no-critical
    dimension: risk
    predicate: { operator: in, values: [critical] }
    effect: deny
    reason: production policy forbids critical faults without two approvals.
    remediation: use --environment staging
compatibility_edges: []
```

Rules the authoring surface enforces at publish time, before anything can
decide under the document:

- **Digest pinning.** Publishing computes `content_digest` and pins the
  bundle, so an approval, an evidence record, and a replay all name the same
  bundle by value. A document whose stated digest disagrees with its content
  is refused as `pin_drifted`, not normalised.
- **Immutability.** A `(bundle_id, version)` row is never rewritten.
  Re-publishing an identical document is absorbed (one row, the stored
  `created_at`); a *rewritten* one is refused. To change policy, publish a new
  version. To withdraw one, `retire` it — approvals and evidence still name it,
  which is why nothing deletes it.
- **Expiry.** `expires_at` is checked on every evaluation, not at publish: an
  expired version authorizes nothing whenever a run asks (see Precedence).

## The fourteen dimensions

A rule speaks to exactly one `PolicyDimension`. The set is a vocabulary, not a
licence: a dimension nobody observes never satisfies a rule, so what follows
splits the fourteen by *who can observe them*.

### Derived by the evaluator

The gate observes these itself, from the plan, the run's environment, and the
mounted budget — a rule on one of these decides without the caller supplying
anything:

environment, target, fault_family, risk, capability, concurrency, damage_budget

### Supplied by the caller

These name the world rather than the plan. The gate reads them from
`PolicyGateInputs.observed` — `mayhem policy explain` fills them from
`--team` and `--approval-held` — and a dimension left unsupplied stays
*unobserved*, which means a `deny ... in (...)` rule on it simply does not
match. A policy cannot enforce what nobody told it:

team, schedule, maintenance_window, cloud_cost, approval_level, deployment_state, incident_state

Two consequences worth stating plainly, because both look like bugs and are
design:

- `not_in` does not match an unobserved dimension. Otherwise a facts set that
  merely forgot to record a dimension would satisfy every deny-shaped "not
  in" rule, and the policy would refuse work for the wrong reason. Use
  `absent`/`present` when the question is observability itself.
- Derived values win over supplied ones: a caller can fill a dimension the
  gate is blind to, but cannot talk the facts into a different target set or
  fault family than the plan carries.

## Precedence

Two bundles, a config block, and five preconditions all get a say. The order
below is the whole answer — each step refuses or falls through to the next:

1. **An unreadable configuration refuses first** — `policy.config_invalid`,
   naming the defect (drifted pin, missing parent, inheritance cycle,
   unmappable budget path) and its fix. None of the checks below can be
   evaluated without a readable rule set.
2. **An expired version refuses** — `policy.bundle_expired`. Expiry outranks
   every allow rule the bundle has: an expired version authorizes nothing.
3. **Lock contention refuses** — `policy.resource_lock_contended`, naming the
   owner to queue behind. Your own experiment's lock is re-entrant; a lock
   whose window has closed fences nobody.
4. **Budget refuses** — `policy.damage_budget_exhausted`: the hierarchical
   budget and the damage quota are a
   conjunction: the plan is within budget iff *both* permit it. When both
   refuse, the hierarchy reports (it names the scope an operator would change)
   and the quota's rule id rides along under `also_refused_by`.
5. **The collision graph refuses** — `policy.compatibility_conflict`, once per
   `{earlier, new}` fault pair, so a three-fault plan is checked as completely
   as a two-fault one. The bundle's own `compatibility_edges` win a pair the
   caller's side-channel also declares, because the bundle is what a policy
   digest pins.
6. **The bundle's own decision** — deny overrides allow: any matching deny
   decides on its own and no combination of allow rules outranks it. When
   nothing matches, `default_effect` applies (author `allow` deliberately;
   the model's own default is fail-closed `deny`).

Within one effect, evaluation and reporting order is total and content-derived
(`resolve_precedence`): higher `precedence` first, then dimension name, then
`rule_id`. Order decides what a reader sees first, never the verdict.

Inheritance is a map, not a stack: `parents` bundles are folded depth-first in
authored order and a child rule with the same `rule_id` replaces the parent's.
A missing parent or a cycle is an authoring defect, refused at step 1 above
rather than silently dropping a policy layer.

Approval requirements are **surfaced, not enforced, by this plan**: a matching
`approval_level` rule puts `Required: ...` on the refusal and hands the
outstanding levels to plan 09's approval gate, which is what turns them into a
quorum. Nothing in plan 07 approves anything.

## Migrating from the config policy block

The `policy:` block in `mayhem.yaml` stays valid and is additive to bundles —
bundles add dimension policy, they do not replace the block. Both are enforced
at once: a fault on the config `deny_faults` list is refused by the config half
even when a mounted bundle permits everything, and the block's decisions are
recorded beside the bundle's (`policy.deny_faults` versus `policy.allow`).
Migration is therefore optional and can be incremental, per rule:

| Config field | What it does today | Migrating to a bundle |
| ------------ | ------------------ | --------------------- |
| `allow_faults` | per-fault catalog allowlist (`None` = whole catalog) | stays: the dimension vocabulary has no per-fault id dimension, so a per-fault allow is config's own mechanism |
| `deny_faults` | per-fault denylist | family-wide denials move to a `deny` rule on `fault_family`; per-fault entries stay in config |
| `risk_ceiling` | highest admissible risk | becomes a `deny` rule on `risk` listing the levels above the ceiling |
| `allow_critical` | config half of the critical triple opt-in | stays: the triple opt-in is config + per-fault `critical_fault_acks` + the `--allow-critical` flag; a bundle can demand approvals on top but cannot relax it |
| `critical_fault_acks` | per-fault critical acknowledgements | stays, same reason as above |

What bundles add that the block cannot express: environment, team, target,
capability, schedule and maintenance windows, concurrency ceilings, cloud cost,
approval-level requirements, deployment/incident state, and the
`compatibility_edges` collision graph. What neither can do: decide a run that
nobody wires to the gate — see the rollout note below before assuming a
published bundle is live.

## Rollout order

1. **Native model first.** Shipped: the `PolicyBundle` vocabulary, evaluation
   inside `validate_plan`, and the `mayhem policy` surface (publish, list,
   show, resolve, retire, explain). Honest status: a published bundle decides
   nothing until a caller constructs `PolicyGateInputs` for it — `explain` is
   the only surface that reaches the gate today, and it simulates.
2. **OPA delegate second.** The OPA/Rego delegate is not wired: no Rego is
   parsed or evaluated anywhere in mayhem today, and the native model above
   is the only evaluator. An external-policy estate needs this before it can
   centralise policy outside mayhem.
3. **Hierarchical budgets third.** The five-level `BudgetNode` tree (team →
   environment → service → experiment → fault) is live at admission as a
   probe: `probe_budget` reports what a run *would* spend and never spends it.
   The posting path (`commit_budget` in `src/mayhem/domain/policy_gate.py`)
   writes charges to a ledger and judges after every append — it is tested in
   `tests/unit/test_policy_regression.py`, but it has no production call site,
   so today no run's charges persist across runs through that path.
