# L1 — the four documents that stopped matching the code

## What is open

Commit `d4201c9` is titled *"Correct the stale 'planning only, 0%' status
blocks."* Its message says:

> "Every plan document in this program still opened with 'Status: planning only.
> 0%'. That stopped being true several phases ago and was never corrected, which
> is the failure mode this repository argues against everywhere else: a document
> that has quietly stopped matching the code. **Both blocks are replaced with what
> is actually open**…"

`git show --name-only d4201c9` lists four files: `README.md`,
`docs/v1.1.0/00_MASTER_ROADMAP.md`, `docs/v1.1.0/27_IMPLEMENTATION_BACKLOG.md`,
`docs/v1.1.0/README.md`.

Four documents still carry the string verbatim today:

| File | Line | Current text |
| ---- | ---- | ------------ |
| `docs/v1.1.0/24_RELEASE_GATES.md` | 67 | `## STATUS — planning only, 0%` + "Gates defined; enforcement begins with the first M1 lane." |
| `docs/v1.1.0/25_REFERENCE_ARCHITECTURE.md` | 78 | `## STATUS — planning only, 0%` |
| `docs/v1.1.0/26_COMPETITIVE_GAPS_MATRIX.md` | 37 | `## STATUS — planning only, 0%` + "Matrix opened; Mayhem-column states advance only via 01 records and 24 gates, never by editing this file optimistically." |
| `docs/v1.1.0/28_EXECUTION_CHECKLIST.md` | 48 | `## STATUS — planning only, 0%` + "Checklist defined; items become enforceable as their owning plans land." |

Why this matters more than it looks:

* `24` is **P0** in the file index and is the file every other plan's exit
  criterion names. "Enforcement begins with the first M1 lane" is false — all
  eight M lanes have landed.
* **Nothing catches it.** `grep -rl "24_RELEASE_GATES\|25_REFERENCE_ARCH\|26_COMPETITIVE\|28_EXECUTION" tests/`
  returns nothing. There is no plan-document gate for these four, while plans 21,
  22, 23, 29 and 30 each have one. The gap is unguarded precisely where the guard
  is missing.

This is the same defect class the repo already has a name for. Fixing it without a
gate means it comes back on the next plan that is written.

---

## Phase 1 — replace the four blocks with what is actually open

Additive prose only. No source change, no behaviour change.

### 1a. `docs/v1.1.0/24_RELEASE_GATES.md`

Replace lines 67–68:

```markdown
## STATUS — gates defined and enforced on the certification pipeline; three
phases of the *release* half remain live

The gate engine is not a plan. `domain/pipeline.blocking_reasons`,
`controller/check_gate.evaluate_pr_checks`, `controller/check_gate.release_gate`
and `controller/check_gate.proof_view_for_report` all landed, and the fault-gate
section passes on the certification pipeline itself — which was Phase 1's exit
criterion.

What is **not** done:

* `release_gate()` has no production caller. `--release-gate` is rendered into
  generated CI workflows by `controller/ci_surface.py`, but nothing in `src/`
  invokes the Python gate. See `docs/v1.1.0/LAST/L3_RELEASE_GATE_CALLER.md`.
* Nothing calls `release_gate(..., open_findings=...)`, so the regression-finding
  feed plan 22 Phase 4 built has no path into a release decision.
* The full suite is not green for a production-class release, and cannot be until
  `certified_faults > 0` (plan 01) and a soak run exists (plan 23). The gate
  reports that honestly: no live claim means nothing to regress.
```

### 1b. `docs/v1.1.0/25_REFERENCE_ARCHITECTURE.md`

Replace line 78. This is a reference architecture, so the honest block says what
it describes rather than claiming a delivery percentage:

```markdown
## STATUS — reference document, no phase ledger

This file is architecture, not a feature lane, so it carries no `Overall:` count
and no phase ledger; the six-phase convention in `../README.md` applies to feature
plans. Its sections describe the shape the code landed in. Where it disagrees
with `src/`, `src/` is current — see `docs/README.md` §"Source authority".

Known divergence, stated rather than hidden: the run-close evidence seal
(`controller/policy_evidence.seal_policy_decision`) has no production caller, so a
mutating run seals an INCOMPLETE chain today. See
`docs/v1.1.0/LAST/L2_RUN_CLOSE_AUTHORIZATION.md`.
```

### 1c. `docs/v1.1.0/26_COMPETITIVE_GAPS_MATRIX.md`

Keep the existing sentence — it is correct and it is the reason this file cannot
be optimistically edited. Replace only the header:

```markdown
## STATUS — matrix live; Mayhem column still reads zero on every live-verification row

The matrix is tracked, not aspirational. The Mayhem-column states advance only via
plan 01 certification records and plan 24 gates, never by editing this file
optimistically — and because `certified_faults = 0`, **every row whose claim is
live verification still reads unfilled**. That is the correct state, not a gap in
the matrix.
```

### 1d. `docs/v1.1.0/28_EXECUTION_CHECKLIST.md`

Replace lines 48–49:

```markdown
## STATUS — checklist live; items enforceable as their owning plans land, and the
owning plans have landed

Every item's owning plan is in `docs/v1.1.0/` and each carries its own `## STATUS`
block, which is the authoritative per-item state. Two items are enforced by tests
rather than by review today: the plan-document gates
(`tests/unit/test_*_plan_docs.py`, eight suites) and the evidence-boundary
completeness guard (`tests/unit/test_evidence_boundary.py`).

Items still open are the live ones: the k8s DaemonSet transport and live-cluster
cells (`02_KUBERNETES_RUNTIME.md` Phases 4–5) and the enterprise walkthrough's
live-site clause (`20_ENTERPRISE_PRODUCT_HARDENING.md` Phase 4).
```

### Acceptance

* `grep -rn "planning only, 0%" docs/v1.1.0/` returns nothing.
* Each replacement states what is open. No block claims a delivery percentage it
  cannot evidence.

---

## Phase 2 — the plan-document gate that makes Phase 1 stick

New file: `tests/unit/test_plan_doc_status_blocks.py`.

This is the pattern `tests/unit/test_proof_plan_docs.py` already establishes —
read the document, cross-check against source, prove each checker bites. It is
deliberately *not* per-plan: it is one gate over the whole directory, because the
defect is directory-wide.

```python
"""L1 Phase 2 — the honesty gate over every plan-document STATUS block.

One test file for the whole directory, because the defect is directory-wide: four
documents kept a `planning only, 0%` header after the commit that claimed to have
removed them all, and nothing referenced those four files, so nothing caught it.

Four checks:

* no `## STATUS` block in ``docs/v1.1.0/`` carries a bare completion
  percentage — the string ``planning only`` is refused outright, and a
  ``## STATUS`` header must name either a delivered phase set or a named open
  item;
* every feature plan with a phase ledger carries an ``Overall:`` line whose
  count equals its number of ``DONE`` phase lines, so a plan cannot quietly
  demote a finished phase while keeping its count;
* a plan that names a phase as ``PARTIAL`` says *why* — the line must contain a
  reference to a live acceptance or a named file, not only the word;
* the two meta plans this gate exists for (24 and 28) do not claim enforcement
  has not started: each must either name a landed engine or say plainly that the
  items are unenforced.

Each checker is proven to bite against a mutated copy of the directory, so a
checker that silently stopped checking fails here too.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterator

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN_DIR = REPO_ROOT / "docs/v1.1.0"

#: Plans that carry a six-phase ledger, and therefore must carry `Overall:`.
FEATURE_PLANS: Final = (
    "01_RUNTIME_CERTIFICATION.md",
    "02_KUBERNETES_RUNTIME.md",
    "03_EXECUTION_FABRIC.md",
    "04_EBPF_KERNEL_IO_JVM.md",
    "05_APP_AND_DEPENDENCY_FAULTS.md",
    "06_CLOUD_PROVIDERS.md",
    "07_POLICY_SAFETY_ENGINE.md",
    "08_CONTROL_PLANE_API_UI.md",
    "09_IDENTITY_RBAC_APPROVALS.md",
    "10_EMERGENCY_STOP_PREFLIGHT.md",
    "11_OBSERVABILITY_PROBES_STOP_CONDITIONS.md",
    "12_CRYPTOGRAPHIC_EVIDENCE.md",
    "13_SCHEDULING_CAMPAIGNS_GAMEDAYS.md",
    "14_TOPOLOGY_BLAST_RADIUS.md",
    "15_RESILIENCE_ANALYTICS_ADAPTIVE.md",
    "16_CI_GITOPS_INTEGRATIONS.md",
    "17_EXTENSION_SDK_PROVIDER_PROTOCOL.md",
    "18_MARKETPLACE_CATALOG.md",
    "19_HA_DR_SECURITY.md",
    "20_ENTERPRISE_PRODUCT_HARDENING.md",
    "21_RELIABILITY_ADVISOR.md",
    "22_RESILIENCE_COVERAGE_REGRESSION.md",
    "23_PERFORMANCE_SCALE.md",
    "29_SECRETS_MANAGEMENT.md",
    "30_SAFETY_PROOF.md",
)

#: A completion percentage with no named open item behind it.
BARE_PERCENT: Final = re.compile(r"planning only|^\s*[-*]?\s*(?:Overall:\s*)?\d+%", re.M)
DONE_LINE: Final = re.compile(r"^-\s+Phase\s+\d+.*\bDONE\b", re.M)
OVERALL_LINE: Final = re.compile(r"^Overall:\s*(\d+)\s+of\s+(\d+)\s+phases", re.M)
PARTIAL_LINE: Final = re.compile(r"^-\s+Phase\s+\d+.*\bPARTIAL\b", re.M)
STATUS_HEADER: Final = re.compile(r"^## STATUS\b.*$", re.M)


def _plans() -> Iterator[Path]:
    yield from sorted(PLAN_DIR.glob("*.md"))


def _status_block(text: str) -> str:
    """The ``## STATUS`` section, up to the next level-2 heading or EOF."""
    match = STATUS_HEADER.search(text)
    if match is None:
        return ""
    rest = text[match.start() :]
    nxt = re.search(r"^## (?!STATUS)", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


# --- the four checks ------------------------------------------------------- #


def test_no_plan_claims_a_bare_completion_percentage() -> None:
    """`planning only` is refused anywhere in the directory, not only in STATUS."""
    offenders = [
        f"{path.relative_to(REPO_ROOT)}:{text[: m.start()].count(chr(10)) + 1}"
        for path in _plans()
        for text in [path.read_text(encoding="utf-8")]
        for m in re.finditer(r"planning only", text)
    ]
    assert offenders == [], f"stale 'planning only' claims remain: {offenders}"


def test_every_status_block_names_a_state() -> None:
    """A STATUS block must exist and must say more than a percentage."""
    for path in _plans():
        block = _status_block(path.read_text(encoding="utf-8"))
        assert block, f"{path.name} has no ## STATUS block"
        assert not BARE_PERCENT.search(block), (
            f"{path.name} STATUS carries a bare percentage with no named state"
        )


def test_overall_count_equals_the_done_lines() -> None:
    for name in FEATURE_PLANS:
        text = (PLAN_DIR / name).read_text(encoding="utf-8")
        overall = OVERALL_LINE.search(text)
        assert overall is not None, f"{name} carries a phase ledger but no Overall: line"
        done = len(DONE_LINE.findall(text))
        partial = len(PARTIAL_LINE.findall(text))
        assert int(overall.group(1)) == done, (
            f"{name} says {overall.group(1)} of {overall.group(2)} complete but has "
            f"{done} DONE phase lines ({partial} PARTIAL)"
        )


def test_a_partial_phase_names_why() -> None:
    """`PARTIAL` alone is not a status; it must name the acceptance that has not run."""
    for path in _plans():
        text = path.read_text(encoding="utf-8")
        for match in PARTIAL_LINE.finditer(text):
            line = match.group(0)
            assert re.search(r"live|cluster|IdP|approver|runtime|no cell|has not run", line), (
                f"{path.name} marks a phase PARTIAL without naming the open "
                f"acceptance: {line[:120]!r}"
            )


# --- the checkers bite ----------------------------------------------------- #


def test_every_checker_bites_against_a_mutated_plan(tmp_path: Path) -> None:
    """Each checker must fail on a document that has the defect."""
    good = (PLAN_DIR / "30_SAFETY_PROOF.md").read_text(encoding="utf-8")

    stale = good.replace("## STATUS", "## STATUS — planning only, 0%", 1)
    assert BARE_PERCENT.search(_status_block(stale)), "percentage checker did not bite"

    inflated = good.replace("Overall: 6 of 6 phases complete", "Overall: 5 of 6 phases complete")
    match = OVERALL_LINE.search(inflated)
    assert match is not None and int(match.group(1)) != len(DONE_LINE.findall(inflated)), (
        "count checker did not bite"
    )

    unexplained = good.replace("## STATUS", "## STATUS — PARTIAL, not done", 1)
    assert PARTIAL_LINE.search(unexplained) is None or True  # line shape is phase-prefixed

    assert STATUS_HEADER.search(good) is not None
```

> The last assertion in the bite test is deliberately weak and is called out here
> rather than left to look load-bearing: `PARTIAL` is only counted on
> `- Phase N …` lines, so a bare `## STATUS — PARTIAL` does not reach that
> checker. Tighten it to match `PARTIAL` anywhere in a STATUS block, or delete
> the assertion. Do not leave it as written.

### Acceptance

* `uv run pytest -n 3 tests/unit/test_plan_doc_status_blocks.py` — green.
* Delete any one `Overall:` line and the suite fails naming the plan and both
  counts.
* Re-introduce `planning only, 0%` into any plan and the suite fails naming the
  file and line.

---

## Phase 3 — the ledger, and the honesty gate over this document

New file: `tests/unit/test_last_l1_plan_docs.py`, modelled exactly on
`tests/unit/test_proof_plan_docs.py`.

Checks, each mutation-tested against a mutated copy of **this** file:

- Phase 1: DONE — the four STATUS blocks replaced, plus two top-of-file
  `Status:` headers the phase as written had missed (`25_REFERENCE_ARCHITECTURE.md`
  and `28_EXECUTION_CHECKLIST.md`, both line 3). Six lines changed across four
  files; no source file touched.
- Phase 2: DONE — `tests/unit/test_plan_doc_status_blocks.py`, 12 tests, green.
  Three of its rules had to be corrected against the real documents before it
  would pass, and each correction is recorded in the module docstring rather
  than tuned away. See "Deviations" below.
- Phase 3: DONE — `tests/unit/test_last_l1_plan_docs.py`, 10 tests, green. It
  pins the `Overall:` arithmetic, the existence of all four cited files, that
  every `file:line` citation still resolves to a non-stale STATUS header, that
  the document claims no live capability, and that it still says the gate is what
  makes Phase 1 stick.

Overall: 3 of 3 phases complete (Phases 1, 2, and 3).

## Deviations, recorded rather than hidden

Three places where the phase as written above was wrong, and what the code says
instead. All three were found by running the gate against the real documents —
the failure mode the gate exists to catch, caught in the gate.

**1. Check 1's scope was too wide, and widening it was the wrong fix.** The phase
specified refusing `planning only` "anywhere in the directory". Two files
legitimately contain the phrase: `27_IMPLEMENTATION_BACKLOG.md` and
`README.md` both *report* that the stale header was corrected. A gate that flags
those flags the correction as the defect it corrects, and the tempting fix —
narrowing until the suite is green — is exactly how a gate stops checking.
The shipped scope is the STATUS **header line** plus the leading state of a
`Status:` header, and both the scope and the reason for it are in the module
docstring, so the next reader can widen it deliberately rather than by accident.

**2. The ledger rule needed three corrections, not one.** The first draft matched
`.*DONE` anywhere on a phase line and counted lines. Against the real plans that
reported eight false alarms:

* plan 20's Phase 4 line reads `PARTIAL` and then says "DONE" several hundred
  characters later in its prose — a loose match counts a PARTIAL phase as done,
  which is the flattering miscount the whole gate exists to prevent;
* plan 12 carries an extra `Phase 4 correction …: DONE` line, so counting *lines*
  inflated six phases to seven. Corrections inside a phase are the house style;
  the rule counts distinct phase *numbers*;
* several phase labels contain their own colon — plan 3's is `Phase 3 (surface:
  agent enrollment and provider registration)` — so a match that stopped at the
  first colon silently dropped the phase out of the count.

The shipped regex anchors the verdict to the label, matches the label lazily, and
keys on the phase number. Each of the three is pinned by its own test against the
real document, because a test written against a fixture would not have found any
of them.

**3. Phase 1's file list was incomplete.** Two files carried the stale claim at
the top of file as well as in the STATUS block, which is where a reader looking
for the current state actually looks first. Both are now cited in Phase 3's gate.

## The one thing this plan does not make stick-proof

Deleting `tests/unit/test_plan_doc_status_blocks.py` removes the guard entirely:
nothing else in the repository references it, and no CI job asserts its
existence. That is stated here rather than described as unremovable, because the
only claim that would be false is the one about being unremovable.

- Phase 3's gate checks, each mutation-tested against a mutated copy of this
  file:

  1. the `Overall:` count equals the number of `DONE` phase lines here;
  2. the four filenames in the Phase 1 table exist on disk;
  3. no line in this document claims `certified_faults > 0`, `verified-live > 0`,
     or that any live acceptance has been run — the claims most likely to rot;
  4. every `file:line` citation above still resolves to a `## STATUS` header that
     is not stale, because a citation to a line that moved is a citation that is
     wrong;
  5. this document still says the gate in Phase 2 is what makes Phase 1 stick, and
     still says removing it is one deleted file with no other reference. That is
     the honest description of a guard, not a claim that it is unremovable.

### Rollout

Phase 1 is prose and can land alone. Phase 2 must land in the same commit as
Phase 1 or the drift returns on the next plan written — that ordering is the whole
point of the item. Phase 3 lands last.

### What this does not claim

It does not make the release gates pass. It makes the documents that describe
them stop lying, which is a smaller and separately verifiable thing.

---

## STATUS — 3 of 3 phases complete

All three landed. Six lines of prose across four plan documents, one new gate
over the whole directory (`tests/unit/test_plan_doc_status_blocks.py`, 12 tests),
one honesty gate over this document (`tests/unit/test_last_l1_plan_docs.py`, 10
tests). **No file under `src/` changed** — this plan was documents and the two
gates that keep them true.

The eight pre-existing plan-document gates (`test_*_plan_docs.py`) and
`test_readme_honesty.py` were re-run after the Phase 1 edits: 326 passed.

`certified_faults = 0` and every live-verification row is still unfilled. That
is the state this plan's corrections describe, and it is unchanged by it.