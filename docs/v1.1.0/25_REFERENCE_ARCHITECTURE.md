# Plan 25 — Target Reference Architecture

Status: **describes landed architecture.** Meta document: the target architecture the
feature plans build toward, with the build order that keeps it honest.

```text
                           MAYHEM
                  RESILIENCE CONTROL PLANE

       CLI / Web / GitOps / CI / ChatOps / SDKs
                         |
                    API Gateway
                         |
        +----------------+----------------+
        |                |                |
     Identity         Policy          Scheduler
      /RBAC           Engine           /Campaigns
        |                |                |
        +----------------+----------------+
                         |
                    Orchestrator
                         |
                 Safety Compiler
                         |
          +--------------+--------------+
          |              |              |
      Target Graph   Impact Model   Safety Proof
          |              |              |
          +--------------+--------------+
                         |
                  Distributed Fabric
                         |
        +----------------+----------------+
        |                |                |
      Agents          Providers       Cloud APIs
        |                |                |
  +-----+------+     +----+------+     +----+----+
  |            |     |           |     |         |
Docker       K8s  ChaosMesh   Litmus  AWS/GCP/ Azure
Podman       Host  eBPF/JVM    BYOC    FIS
              |
          Fault Engines
              |
       Observe continuously
              |
         Compensation
              |
        Recovery Verify
              |
           Verdict
              |
      Evidence / Attestations
              |
       +------+-------+
       |              |
  Object Storage   Analytics
       |              |
   Audit/Reports  Coverage/Regression
```

## Architectural rule
The injector must never decide whether an experiment is safe, approved, or successful. The Mayhem control plane owns policy, admission, orchestration semantics, evidence, and verdicts. Provider-specific engines only provide the mechanism to cause and undo a declared fault.

## Build order (maps to 27 milestones)
1. Safety Compiler row first (07 policy, 30 proof, 14 impact) — the moat before the breadth.
2. Distributed Fabric plus agents second (03, 19) — one trustworthy lane before many.
3. Control-plane column third (08 API, 09 identity, 13 scheduler) — multi-user only on proven execution.
4. Evidence column fourth (12 attestations, object storage) — proof before scale.
5. Provider breadth fifth (04, 05, 06, 17) — mechanisms under the proven compiler.
6. Experience and intelligence last (08 UI, 16 workflows, 15 analytics, 21 advisor, 22 coverage).

## Non-architecture
Any box built before its dependencies inverts the diagram (e.g. a
marketplace before certification, a UI before the API contract). The
milestone exit criteria in 00 plus the gates in 24 exist to catch
exactly that inversion.

## STATUS — reference document, no phase ledger

This file is architecture, not a feature lane, so it carries no `Overall:` count
and no phase ledger; the six-phase convention in `../README.md` applies to
feature plans. Its sections describe the shape the code landed in. Where it
disagrees with `src/`, `src/` is current — see `docs/README.md` §"Source
authority".

Known divergence, stated rather than hidden: ~~the run-close evidence seal
(`controller/policy_evidence.seal_policy_decision`) has no production caller,
so a mutating run seals an INCOMPLETE chain today.~~ **Closed by
`docs/v1.1.0/LAST/L2_RUN_CLOSE_AUTHORIZATION.md`** — `cli/lifecycle.py`'s
`_write_evidence_after_run` calls `seal_policy_decision` between
`write_evidence` and `write_evidence_file`, sealing the run's attestation
events. What is still true: the seal is conditional on both admission gates
having been configured and both allowed — a policy gate with no approval gate
still seals nothing, both inputs being required — and a deployment that
configures neither, which is every deployment in this repository (no CLI path
sets `policy_gate=`), still seals an INCOMPLETE chain whose
`chain_completeness` reads "missing policy.decided, approval.evaluated".
