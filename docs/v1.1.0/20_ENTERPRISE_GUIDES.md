# Enterprise deployment guides (plan 20, Phase 6)

This guide covers the four deployment models, the sandbox tutorial, the
compliance-mapping methodology, the support process, and the telemetry/privacy
policy. It is a Phase 6 operator document: every claim below names the
mechanism that enforces it, and every claim a harness cannot prove names the
live site that must.

## Deployment models

| Model | Command | What it means | Live proof still owed |
|---|---|---|---|
| Local CLI | `mayhem sandbox up --dir ./sbx` | The sandbox provisions into the local model; its six services are the throwaway targets. | A container runtime (the harness uses a recording fake). |
| Self-hosted Kubernetes | Helm chart `deploy/mayhem/helm/mayhem` (plan 02 Phase 3 stub) | The chart installs the self-hosted model; the walkthrough's `deploy` step names that chart rather than duplicating it. | Installing the chart on a live cluster. |
| Managed/SaaS | operator-provisioned | `demo.mode` and `sandbox.provisioning` are not permitted here; a demo flag in a production run is refused as `flag.production_unsafe`. | The provider's own admission gate. |
| Air-gapped | `mayhem sandbox up --model air_gapped --air-gapped` with `NetworkPolicy(air_gapped=True)` | No egress is permitted; every registry pull is refused before the first command with `sandbox.image_egress_refused`. | Exchanging bundles out of band (`offline.bundle_import` / `offline.bundle_export`). |

A model/policy mismatch is refused before anything runs
(`deployment_model.air_gapped_without_policy`): an install configured as
air-gapped whose policy forgot to say so fails closed rather than reaching
the network.

## Sandbox tutorial

```bash
mayhem sandbox up --dir ./sbx        # config → pull → up → ps; ready=True or a named refusal
mayhem sandbox status --dir ./sbx    # blueprint, registry hosts, topology — no runtime touched
mayhem enterprise walkthrough --dir ./sbx   # the ten acceptance steps with injected seams
mayhem sandbox down --dir ./sbx      # teardown; a failed teardown is reported, not raised
```

The sandbox is not a policy-free zone: runs pass through admission with the
sandbox's own ceilings (`SANDBOX_CEILINGS`: at most 4 nodes, depth 2, 1
customer-facing service, 60% of nodes), which are tighter than production's.
A run that breaches a ceiling is refused as `sandbox.admission_refused`, and
a sandbox run with no admission record is refused as
`sandbox.admission_missing`.

## Demo and training modes

Demo, training, and simulation are the plan-14 simulate path with the
mutation backend detached by construction. Every piece of evidence carries
the sealed banner (`TRAINING — no mutation performed`), the verifier accepts
the run and refuses its presentation as production
(`evidence.non_production_mode`), and a later flag cannot reclassify it
(`evidence.flag_drift`). A training run can never become a production run
by flag drift: the marker is derived from the mode, not supplied.

## Compliance-mapping methodology

What a compliance pack proves vs. what the customer must still do:

* A template (`COMPLIANCE_TEMPLATES`) describes *what evidence a control
  would need* and records the customer's remaining obligations. It is not
  an attestation, and `require_non_asserting_template` refuses any template
  that claims otherwise (`compliance.template_must_not_assert`).
* A compliance map (`mayhem enterprise compliance-map`) cites sealed
  evidence digests against a template's evidence kinds and reports what is
  still missing. An unsealed digest is refused
  (`compliance.digest_unsealed`); a kind the template does not ask for is
  refused (`compliance.evidence_kind_unknown`).
* "Nothing missing" means every kind of evidence the template asked for was
  cited. It is a statement about the supplied evidence, never about
  conformance. **No template and no map in this repository certifies
  compliance with any framework** — the customer must perform their own assessment without concluding it: mayhem's evidence informs the assessment without concluding it.

## Support process (gap 110)

`mayhem support-bundle build --section NAME=PATH --grade SECTION.FIELD=GRADE
--out bundle.json` builds the artifact a customer sends to support:

* Secret-graded fields are **dropped**, never rewritten, and named in the
  manifest (`dropped_secret_fields`). Sensitive and lower fields are kept
  only after the redactor ran over them (`redacted_paths`, rule version
  recorded).
* The bundle seals the execution-mode marker of the run it describes. A
  bundle from a training run carries the training banner, and presenting it
  as production diagnostics is refused (`support.non_production_bundle`).

SLA/SLO definitions:

* **SLO — redaction completeness:** every secret-graded field is dropped
  (the manifest names each one); a bundle whose highest published grade is
  `secret` is a bundle the builder refused to build. Measured per bundle
  by the manifest.
* **SLO — refusal latency:** a refusal names its rule id and cause in the
  same message; no refusal path raises an unnamed error. Measured per
  command by the exit code (`5` safety-refusal) and the rule id.
* **SLA boundary (honest):** response and resolution times are an operator
  commitment the code cannot enforce, so none is stated here. What is
  stated is what the artifact guarantees: no credential leaves the site
  inside a bundle the builder produced.

## Telemetry and privacy policy

* Mayhem collects no telemetry by default: there is no phone-home path in
  the CLI, and an enforced-but-empty allowlist permits nothing.
* Support bundles are the only outbound artifact, and they are built locally
  by the operator, redacted locally, and sent by the operator — nothing is
  transmitted by the build command itself.
* An install that must not phone home sets `allowlist_enforced` with an
  empty allowlist (valid configuration) or declares the air gap (all egress
  refused with the cause named, transport never reached).

## Rollout order

Local plus sandbox first, self-hosted second, SaaS and air-gapped last.
Each step names its proof: the walkthrough harness (`mayhem enterprise
walkthrough`) for the sequence, the live container runtime for
execute/stop/recover, the live IdP and a human approver for
authenticate/approve, and a live cluster for the Helm install.

## Honesty gates

No document in this repository claims compliance or certification without
qualification: every template and every map is a mapping, never a
certification, and not a finding, an assessment, or an attestation of
conformance. The machine-checked version of that rule lives in
`tests/unit/test_enterprise_guides.py`: it fails the suite when this guide
claims a framework attestation, names a live proof as done, or quotes a
refusal code nothing raises.
