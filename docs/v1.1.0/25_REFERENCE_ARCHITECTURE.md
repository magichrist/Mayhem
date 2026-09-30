# Plan 25 — Target Reference Architecture

Status: **planning only.** Meta document: the target architecture the
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

## STATUS — planning only, 0%
