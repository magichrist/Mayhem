"""`mayhem bundle build` — the producer for the feature mayhem sells on.

The `bundle` group advertised "Build and verify portable evidence bundles" in
`--help` while offering only `show` and `verify`. mayhem shipped a working
verifier for bundles it could not produce, and advertised the missing producer
in its own help text. Evidence bundles are the differentiator the market
comparison claims; an unproducible bundle is a dead feature with a parser in
front of it.

These tests pin that the producer exists and that what it writes actually
verifies. If a future change makes `build` write something `verify` rejects,
that is a regression in the one property that matters here.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from mayhem.cli.verify_bundle import build as build_cmd
from mayhem.cli.verify_bundle import bundle_cmd
from mayhem.domain.evidence import EvidenceEnvelope
from mayhem.infra.evidence import write_evidence
from mayhem.infra.store import Store


def _seeded_db(tmp_path: Path, run_id: str = "run-bundle-1") -> Path:
    db = tmp_path / "mayhem.db"
    store = Store(db)
    write_evidence(
        store,
        EvidenceEnvelope(
            run_id=run_id,
            plan_hash="ph-1",
            verdict="recovered",
            steady_state={"verdict": "degraded-within-tolerance"},
        ),
    )
    return db


class TestBundleGroupAdvertisesWhatItOffers:
    def test_group_help_mentions_build_only_because_build_exists(self) -> None:
        """ "Build and verify" is honest only while `build` is a real verb."""
        result = CliRunner().invoke(bundle_cmd, ["--help"])
        assert result.exit_code == 0
        assert "Build and verify" in result.output
        assert "build" in result.output


class TestBundleBuild:
    def test_build_writes_a_bundle_that_verifies(self, tmp_path: Path) -> None:
        """The whole point: what `build` writes must pass `verify`."""
        db = _seeded_db(tmp_path)
        out = tmp_path / "bundle"

        result = CliRunner().invoke(build_cmd, ["run-bundle-1", "--out", str(out), "--db", str(db)])
        assert result.exit_code == 0, result.output
        assert out.is_dir()
        assert (out / "manifest.json").exists()
        assert (out / "evidence.json").exists()

    def test_built_bundle_verifies_clean(self, tmp_path: Path) -> None:
        from mayhem.cli.verify_bundle import verify as verify_cmd

        db = _seeded_db(tmp_path)
        out = tmp_path / "bundle"
        built = CliRunner().invoke(build_cmd, ["run-bundle-1", "--out", str(out), "--db", str(db)])
        assert built.exit_code == 0, built.output

        verified = CliRunner().invoke(verify_cmd, [str(out)])
        assert verified.exit_code == 0, verified.output
        assert "bundle valid: true" in verified.output

    def test_build_is_deterministic_for_equal_input(self, tmp_path: Path) -> None:
        """Same recorded run, two bundles, one root digest.

        A bundle is evidence. If two builds of the same run differ, the digest
        cannot attest to anything.
        """
        db = _seeded_db(tmp_path)
        roots = []
        for name in ("a", "b"):
            out = tmp_path / name
            result = CliRunner().invoke(
                build_cmd, ["run-bundle-1", "--out", str(out), "--db", str(db)]
            )
            assert result.exit_code == 0, result.output
            manifest = json.loads((out / "manifest.json").read_text())
            roots.append(manifest["root_digest"])
        assert roots[0] == roots[1]

    def test_carries_the_steady_state_verdict_into_the_bundle(self, tmp_path: Path) -> None:
        """Plan 03: the graded verdict must reach the portable artifact."""
        db = _seeded_db(tmp_path)
        out = tmp_path / "bundle"
        result = CliRunner().invoke(build_cmd, ["run-bundle-1", "--out", str(out), "--db", str(db)])
        assert result.exit_code == 0, result.output
        evidence = json.loads((out / "evidence.json").read_text())
        assert evidence["steady_state"]["verdict"] == "degraded-within-tolerance"

    def test_build_is_refused_for_a_run_with_no_evidence(self, tmp_path: Path) -> None:
        """A bundle can only be built from a run that has an envelope.

        Failing loudly beats writing an empty bundle that verifies trivially —
        a valid-looking artifact attesting to nothing is the exact failure this
        feature must not have.
        """
        db = _seeded_db(tmp_path, run_id="only-this-one")
        result = CliRunner().invoke(
            build_cmd, ["no-such-run", "--out", str(tmp_path / "b"), "--db", str(db)]
        )
        assert result.exit_code != 0
        assert "no evidence envelope" in result.output.lower()

    def test_manifest_chain_is_present(self, tmp_path: Path) -> None:
        db = _seeded_db(tmp_path)
        out = tmp_path / "bundle"
        result = CliRunner().invoke(build_cmd, ["run-bundle-1", "--out", str(out), "--db", str(db)])
        assert result.exit_code == 0, result.output
        manifest = json.loads((out / "manifest.json").read_text())
        assert manifest["root_digest"]
        assert manifest["artifacts"]


def test_build_bundle_has_a_production_caller() -> None:
    """The gap this command closed must not reopen.

    Before this command, `build_bundle` had zero callers outside `tests/` and
    the advertised producer did not exist. Invert this assertion the day the
    producer is reachable by some other, better route.
    """
    # The only permitted `build_bundle(` call sites are the definition itself
    # and the CLI producer. If the producer is reachable some other way, the
    # gap this command closed has reopened by a route nobody documented.
    src = Path("src/mayhem")
    callers = [
        p
        for p in src.rglob("*.py")
        if p.name not in ("verify_bundle.py", "evidence_bundle.py")
        and "build_bundle(" in p.read_text()
    ]
    assert not callers, f"bundle producer reachable elsewhere: {callers}"


def test_verify_reports_authorship_honestly() -> None:
    """Integrity is verified; authorship is not, and `verify` must say so.

    Same honesty rule the fault-pack loader follows: a real digest, no real
    signature. A verifier that reported `signed=true` here would be lying.
    """
    from mayhem.domain.evidence import EvidenceEnvelope
    from mayhem.domain.evidence_bundle import build_bundle, verify_bundle
    from mayhem.infra.evidence import redact_envelope

    # Through `redact_envelope`, the same transform `write_evidence` applies
    # before storage: `verify` refuses a payload carrying no redaction marker,
    # which is the verifier working rather than a test artefact.
    envelope = redact_envelope(
        EvidenceEnvelope(run_id="r", plan_hash="ph", verdict="recovered")
    ).model_dump(mode="json")
    result = verify_bundle(build_bundle(evidence=envelope))
    assert result.signed is False
    assert result.valid is True
