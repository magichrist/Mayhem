# v0.9.0 Release Readiness

## Definition of Done

A v0.9.0 feature is complete only when:

- its user-visible behavior is documented in the active CLI reference;
- its machine output has a versioned schema and stable exit codes;
- its policy, capability, and failure behavior is explicit;
- it has unit tests for contracts and fake-runtime integration tests for side effects;
- it does not create hidden mutation paths;
- it records enough evidence for an operator to explain what happened;
- secrets are redacted before durable writes;
- it has a rollback or safe-disable path;
- it passes packaging and clean-install smoke tests.

## Required release gates

### Source and tests

- `python -m pytest tests/unit tests/integration -q`
- `python -m pytest tests/e2e -q` when the environment supports in-process E2E.
- `ruff check` on changed source and test files.
- `mypy` on the newly created typed boundaries, with existing baseline violations tracked separately.
- `lint-imports` only after the architecture migration has reduced the current contract debt; until then it must not be presented as a passing release gate.
- `.github/workflows/ci.yml` runs unit, integration, in-process E2E, fatal-Ruff, package build, wheel smoke, and artifact verification jobs; the advisory job reports the current lint, type, and architecture debt without blocking unrelated pull requests.

### Package

- `python -m build --sdist --wheel`
- install the wheel in a clean virtual environment;
- run `mayhem --help`;
- run `mayhem discover capabilities --format json` (the capability dashboard now accepts `--format` directly);
- validate the sdist and wheel metadata;
- verify distribution name is `mayhem-cli` and console command is `mayhem`;
- verify `kubernetes` is installed as a default dependency.

### Safety and evidence

- no mutating command runs without an intent;
- no ambiguous engine/target/policy can reach a lease;
- no known target-type mismatch reaches a runtime tool;
- compensation verification is required for clean success;
- evidence persistence failure is visible as degraded;
- redaction fixtures are absent from SQLite, reports, logs, bundles, and debug output.

### Runtime profiles

- Docker/Podman unit and fake-executor tests pass;
- manifest/dry-run Kubernetes tests pass;
- live conformance is opt-in, versioned, and records environment details;
- no live-cluster claim appears without a conformance artifact.

### Release metadata

- v0.9.0 changelog is curated by user impact;
- compatibility matrix is current;
- SBOM and artifact checksums are attached;
- release workflow actions are pinned;
- tag and package version agree;
- release notes distinguish added, changed, fixed, deprecated, removed, and security changes.

## v0.9.0 gate results (local, 2026-09-26)

| Gate | Result |
| --- | --- |
| `pytest tests/unit tests/integration tests/e2e` | PASS (full run, after tasks 1-10, again after tasks 11-20, and again after the v0.9.0 edge-case and docs-contract test pass) |
| Coverage of the v0.9.0 modules | 100% on 14 of 15 new modules; `domain/scenarios.py` 99% (3 defensive lines: an unreachable type fallback and a re-raise that pydantic pre-empts) |
| Documented examples | PASS — `tests/unit/test_v090_docs_contract.py` loads the README and `docs/drill-spec.md` examples and compiles them against the real schema |
| `uv build --sdist --wheel` | PASS |
| `python scripts/verify_release_artifacts.py dist` | PASS (9 checks) |
| Wheel install + import + console scripts + `mayhem --version` + `python -m mayhem` | PASS (offline: `pip install --no-deps --target`, then run) |
| Every new v0.9.0 command reachable from the installed wheel | PASS (`game-day`, `bundle`, `inspect replay/graph/residual`, `campaign resume-plan`, `experiment compose`, `discover capabilities`) |
| Core checkpoint (6 invariants) | PASS (`docs/v0.9.0/06-core-implementation-plan.md`) |
| Expansion checkpoint (6 invariants) | PASS (`tests/unit/test_expansion_checkpoint.py`) |
| Clean-venv wheel smoke (`MAYHEM_PACKAGE_SMOKE=1`) | PASS on CI (run 36275532737). Locally this sandbox cannot reach pypi.org, so the same job was reproduced offline: `pip install --no-deps --target`, import, console scripts, `mayhem --version`, `python -m mayhem --version`, and every new command's `--help`. |
| `lint-imports` | NOT A GATE — known architecture-contract debt, deliberately non-blocking (`advisory quality checks` runs with `continue-on-error: true`) |
| `ruff` fatal subset (E9,F63,F7,F82,F821,F811) | PASS |
| Repository-wide `ruff` / `mypy` | PRE-EXISTING FAILURES — not introduced by v0.9.0; advisory only |
| GitHub Actions CI on `v0.9.0` | PASS (run 36275532737): unit, integration, e2e, schema, ruff-fatal, package build, wheel smoke, artifact verification |

## Rollback plan

1. Do not delete the previous release tag or wheel.
2. Mark v0.9.0 as withdrawn if a safety or evidence defect is found.
3. Pin users to the previous known-good release with a documented command.
4. Preserve failed-run evidence and redaction reports for diagnosis.
5. Apply a forward fix; never rewrite a published release artifact.
6. If a migration is unsafe, disable the migration behind a versioned feature flag and document the manual recovery path.

## v0.9.0 release labels

A release candidate is:

- **Alpha:** core commands work locally; no live claims; schemas may change.
- **Beta:** core safety, replay, evidence, and package gates pass; live conformance is incomplete.
- **Release candidate:** all required gates pass; live claims are backed by artifacts; rollback is tested.
- **Stable:** the release candidate has no open P0/P1 safety defects and has a published compatibility matrix.
