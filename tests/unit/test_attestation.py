"""Phase 1 domain model for plan 12: attestations, provenance, time.

The vectors here are the contract another language's verifier must reproduce:
canonical bytes, chain links, the provenance ladder, and the clock-uncertainty
arithmetic. Nothing in this file needs a store, a cluster, or a control plane —
that is the point of an attestation.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from mayhem.domain.attestation import (
    ATTESTATION_SCHEMA_VERSION,
    GENESIS_DIGEST,
    PROVENANCE_LADDER,
    AttestedEvent,
    AttestedTimestamp,
    Manifest,
    ProvenanceEdge,
    ProvenanceNodeKind,
    ProvenancePath,
    ProvenanceRef,
    ProvenanceRole,
    RetentionClass,
    accumulated_uncertainty,
    build_manifest,
    canonical_event_bytes,
    canonical_event_json,
    chain_root,
    content_digest,
    monotonic_ordering,
    monotonic_span_ns,
    plain_digest,
    seal_events,
    verify_chain,
    verify_manifest,
    wall_clock_offset,
    wall_clock_ordering_ambiguous,
)
from mayhem.domain.hashing import digest as project_digest

BASE_WALL_CLOCK = datetime(2026, 3, 1, 12, 0, 0, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# Builders                                                                    #
# --------------------------------------------------------------------------- #


def make_time(
    *,
    wall_clock: datetime = BASE_WALL_CLOCK,
    monotonic_ns: int = 1_000_000,
    uncertainty_ms: float = 0.0,
    source: str = "system",
) -> AttestedTimestamp:
    return AttestedTimestamp(
        wall_clock=wall_clock,
        monotonic_ns=monotonic_ns,
        uncertainty_ms=uncertainty_ms,
        source=source,
    )


def make_event(
    *,
    event_id: str,
    sequence: int,
    payload: dict[str, Any] | None = None,
    recorded_at: AttestedTimestamp | None = None,
    event_kind: str = "run.step.finished",
    run_id: str = "run-1",
) -> AttestedEvent:
    return AttestedEvent(
        event_id=event_id,
        event_kind=event_kind,
        run_id=run_id,
        sequence=sequence,
        payload=payload if payload is not None else {"step": "s-1", "verdict": "degraded"},
        recorded_at=recorded_at or make_time(monotonic_ns=1_000_000 + sequence * 1_000),
    )


def make_chain(count: int = 3) -> tuple[AttestedEvent, ...]:
    events = [make_event(event_id=f"e-{index}", sequence=index) for index in range(count)]
    return seal_events(events)


def make_ladder_nodes() -> list[ProvenanceRef]:
    return [ProvenanceRef(kind=kind, id=f"{kind.value}-1") for kind in PROVENANCE_LADDER]


def full_path() -> ProvenancePath:
    return ProvenancePath.ladder(make_ladder_nodes(), role=ProvenanceRole.PRODUCED)


# --------------------------------------------------------------------------- #
# Canonicalization vectors                                                    #
# --------------------------------------------------------------------------- #


def test_key_reorder_canonicalizes_identically() -> None:
    first = {"b": 2, "a": 1, "c": {"z": 26, "y": 25}}
    second = {"c": {"y": 25, "z": 26}, "a": 1, "b": 2}

    assert canonical_event_bytes(first) == canonical_event_bytes(second)
    assert content_digest(first) == content_digest(second)
    assert canonical_event_json(first) == '{"a":1,"b":2,"c":{"y":25,"z":26}}'


def test_insignificant_whitespace_is_not_attested() -> None:
    spaced = json.loads('{ "run_id" : "run-1",\n  "verdict": "degraded" }')
    tight = {"run_id": "run-1", "verdict": "degraded"}

    assert canonical_event_bytes(spaced) == canonical_event_bytes(tight)
    assert b" " not in canonical_event_bytes(spaced)


def test_list_order_is_significant() -> None:
    # Reordering *keys* is not information; reordering a sequence is.
    assert content_digest(["a", "b"]) != content_digest(["b", "a"])
    assert content_digest({"steps": [("a", 1)]}) == content_digest({"steps": [("a", 1)]})


def test_unicode_normalizes_to_nfc_in_keys_and_values() -> None:
    composed = "caf\u00e9"  # é as one code point
    decomposed = "cafe\u0301"  # e + combining acute
    assert composed != decomposed
    assert unicodedata.normalize("NFC", decomposed) == composed

    assert canonical_event_bytes({"note": composed}) == canonical_event_bytes({"note": decomposed})
    assert canonical_event_bytes({decomposed: 1}) == canonical_event_bytes({composed: 1})
    assert content_digest({"note": decomposed}) == content_digest({"note": composed})


def test_non_ascii_is_emitted_as_utf8_not_escaped() -> None:
    encoded = canonical_event_bytes({"note": "\u00e9"})

    assert encoded == '{"note":"\u00e9"}'.encode("utf-8")
    assert b"\\u" not in encoded


def test_nested_containers_normalize_recursively() -> None:
    left = {"runs": [{"events": ["cafe\u0301"]}]}
    right = {"runs": [{"events": ["caf\u00e9"]}]}

    assert canonical_event_bytes(left) == canonical_event_bytes(right)


@pytest.mark.parametrize(
    "payload",
    [
        {"value": float("nan")},
        {"value": float("inf")},
        {"value": [float("-inf")]},
    ],
)
def test_non_finite_numbers_are_refused(payload: dict[str, Any]) -> None:
    # JSON has no NaN/Infinity; a reader in another language could not read them.
    with pytest.raises(ValueError, match="non-finite"):
        canonical_event_json(payload)


@pytest.mark.parametrize(
    "value",
    [{"value": object()}, {"value": {1: "int key"}}, {"value": {"s", "set"}}],
)
def test_non_json_native_values_are_refused(value: dict[str, Any]) -> None:
    # domain/hashing.canonical_json stringifies these via default=str; an
    # attestation must refuse rather than digest a lossy rendering.
    with pytest.raises(TypeError):
        canonical_event_json(value)


def test_attested_event_refuses_non_json_native_payload() -> None:
    with pytest.raises(ValidationError, match="not attestable JSON"):
        make_event(event_id="e-0", sequence=0, payload={"bad": object()})


def test_canonicalization_is_deterministic_across_calls() -> None:
    payload = {"run_id": "run-1", "steps": [{"id": 2}, {"id": 1}]}

    assert len({canonical_event_bytes(payload) for _ in range(5)}) == 1
    assert len({content_digest(payload) for _ in range(5)}) == 1


def test_plain_digest_agrees_with_the_project_convention_for_ascii() -> None:
    # The bridge for externally computed digests (07 plan hash, 09 approval):
    # for plain ASCII JSON-native input there is exactly one convention.
    payload = {"plan_hash": "abc123", "approved_by": "operator", "count": 3}

    assert plain_digest(payload) == project_digest(payload)
    assert plain_digest(payload) == content_digest(payload)


def test_event_canonical_bytes_exclude_only_the_declared_hash_fields() -> None:
    event = make_chain(1)[0]
    view = event.canonical_view()

    assert "digest" not in view
    assert "chain_link" not in view
    assert view["event_id"] == event.event_id
    assert event.canonical_bytes() == canonical_event_bytes(view)
    assert event.digest == hashlib.sha256(event.canonical_bytes()).hexdigest()


def test_event_round_trips_through_json_without_changing_its_digest() -> None:
    event = make_chain(2)[1]

    revived = AttestedEvent.model_validate(json.loads(json.dumps(event.to_dict())))

    assert revived == event
    assert revived.canonical_bytes() == event.canonical_bytes()
    assert revived.digest == event.digest


# --------------------------------------------------------------------------- #
# Chain links                                                                 #
# --------------------------------------------------------------------------- #


def test_sealed_chain_verifies_and_yields_a_root() -> None:
    chain = make_chain(3)
    verdict = verify_chain(chain)

    assert verdict.valid is True
    assert verdict.errors == ()
    assert verdict.checked == 3
    assert verdict.root_digest == chain[-1].chain_link == chain_root(chain)
    assert len(chain_root(chain)) == 64


def test_chain_is_wired_to_each_predecessor_link() -> None:
    chain = make_chain(4)

    for index in range(1, len(chain)):
        assert chain[index].previous_digest == chain[index - 1].chain_link
    assert chain[0].previous_digest == GENESIS_DIGEST
    assert chain[0].is_genesis is True


def test_chain_continues_from_a_previous_root() -> None:
    first = make_chain(2)
    seed = chain_root(first)
    later = seal_events([make_event(event_id="e-2", sequence=2)], previous_digest=seed)

    assert later[0].previous_digest == seed
    assert verify_chain(later).valid is True
    assert later[0].chain_link != chain_root(first)


def test_flipping_any_single_byte_of_the_canonical_form_breaks_the_digest() -> None:
    event = make_chain(1)[0]
    original = event.canonical_bytes()

    assert original
    for index in range(len(original)):
        current = original[index : index + 1]
        replacement = b"0" if current != b"0" else b"1"
        mutated = original[:index] + replacement + original[index + 1 :]
        assert hashlib.sha256(mutated).hexdigest() != event.digest, index


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            {"payload": {"step": "s-1", "verdict": "degraded", "extra": 1}},
            id="payload-byte",
        ),
        pytest.param({"event_kind": "run.step.started"}, id="event-kind"),
        pytest.param({"event_id": "e-0-renamed"}, id="event-id"),
        pytest.param({"sequence": 7}, id="sequence"),
        pytest.param({"redaction_policy": "v9"}, id="redaction-policy"),
        pytest.param({"digest": "0" * 64}, id="declared-digest"),
        pytest.param({"chain_link": "0" * 64}, id="declared-chain-link"),
        pytest.param({"previous_digest": "1" * 64}, id="previous-digest"),
    ],
)
def test_tampering_any_covered_field_fails_verification_naming_the_event(
    mutation: dict[str, Any],
) -> None:
    chain = list(make_chain(3))
    target = chain[1]
    chain[1] = target.model_copy(update=mutation)
    verdict = verify_chain(chain)

    assert verdict.valid is False
    assert verdict.errors
    # The error must name the tampered event *as it now reads* — including when
    # the tamper was a rename, since event_id is itself a covered field.
    assert any(f"'{chain[1].event_id}'" in error for error in verdict.errors), verdict.errors


def test_tampering_the_timestamp_fails_and_names_the_event() -> None:
    chain = list(make_chain(2))
    chain[1] = chain[1].model_copy(
        update={"recorded_at": make_time(monotonic_ns=999, uncertainty_ms=1.0)}
    )

    verdict = verify_chain(chain)

    assert verdict.valid is False
    assert any("'e-1'" in error for error in verdict.errors)


def test_reordering_a_valid_chain_is_detected() -> None:
    chain = list(make_chain(3))
    reordered = [chain[0], chain[2], chain[1]]

    verdict = verify_chain(reordered)

    assert verdict.valid is False
    assert any("does not link to predecessor" in error for error in verdict.errors)


def test_unsealed_event_is_rejected() -> None:
    chain = list(make_chain(2))
    chain[0] = make_event(event_id="e-0", sequence=0)  # never sealed

    verdict = verify_chain(chain)

    assert verdict.valid is False
    assert any("unsealed" in error and "'e-0'" in error for error in verdict.errors)


def test_duplicate_event_id_is_reported() -> None:
    chain = list(make_chain(2))
    chain[1] = chain[1].model_copy(update={"event_id": "e-0"})

    verdict = verify_chain(chain)

    assert verdict.valid is False
    assert any("duplicate event 'e-0'" in error for error in verdict.errors)


def test_sequence_regression_is_reported() -> None:
    chain = [make_event(event_id="e-0", sequence=0), make_event(event_id="e-1", sequence=0)]

    verdict = verify_chain(seal_events(chain))

    assert verdict.valid is False
    assert any("does not follow predecessor" in error for error in verdict.errors)


def test_run_switch_mid_chain_is_reported() -> None:
    chain = list(make_chain(2))
    chain[1] = chain[1].model_copy(update={"run_id": "run-2"})

    verdict = verify_chain(chain)

    assert verdict.valid is False
    assert any("belongs to run 'run-2'" in error for error in verdict.errors)


def test_genesis_that_claims_a_predecessor_is_reported() -> None:
    event = make_event(event_id="e-0", sequence=0).model_copy(update={"previous_digest": "2" * 64})

    verdict = verify_chain([event.seal()])

    assert verdict.valid is False
    assert any("starts a chain but links to" in error for error in verdict.errors)


def test_empty_chain_is_vacuously_valid() -> None:
    verdict = verify_chain([])

    assert verdict.valid is True
    assert verdict.checked == 0
    assert verdict.root_digest == GENESIS_DIGEST


def test_chain_links_cover_every_predecessor_transitively() -> None:
    """Changing event 0 changes event 1's digest, and therefore the whole tail."""
    original = make_chain(3)
    altered = list(original)
    altered[0] = original[0].model_copy(update={"payload": {"step": "s-9", "verdict": "ok"}})
    resealed = seal_events([altered[0], original[1], original[2]])

    assert resealed[0].chain_link != original[0].chain_link
    assert resealed[1].digest != original[1].digest
    assert verify_chain(resealed).valid is True  # internally consistent ...
    assert chain_root(resealed) != chain_root(original)  # ... but a different root


# --------------------------------------------------------------------------- #
# Provenance                                                                  #
# --------------------------------------------------------------------------- #


def test_ladder_constant_is_the_declared_order_and_covers_every_kind() -> None:
    assert PROVENANCE_LADDER == (
        ProvenanceNodeKind.FACT,
        ProvenanceNodeKind.OBSERVATION,
        ProvenanceNodeKind.PROBE,
        ProvenanceNodeKind.STEP,
        ProvenanceNodeKind.FAULT,
        ProvenanceNodeKind.TARGET,
        ProvenanceNodeKind.EXPERIMENT,
        ProvenanceNodeKind.VERDICT,
    )
    assert set(PROVENANCE_LADDER) == set(ProvenanceNodeKind)
    assert len(set(PROVENANCE_LADDER)) == len(PROVENANCE_LADDER)


def test_full_path_walks_every_rung_exactly_once() -> None:
    path = full_path()

    assert path.is_complete() is True
    assert path.errors() == ()
    assert len(path.edges) == len(PROVENANCE_LADDER) - 1
    assert path.kinds() == PROVENANCE_LADDER
    assert [node.id for node in path.nodes()] == [f"{kind.value}-1" for kind in PROVENANCE_LADDER]
    assert {edge.role for edge in path.edges} == {ProvenanceRole.PRODUCED}


def test_edges_chain_source_to_target() -> None:
    path = full_path()

    for index in range(1, len(path.edges)):
        assert path.edges[index].source == path.edges[index - 1].target
        assert path.edges[index].source.ladder_index == index


def test_edge_carries_a_role_label() -> None:
    edge = ProvenanceEdge(
        source=ProvenanceRef(kind=ProvenanceNodeKind.OBSERVATION, id="obs-7"),
        target=ProvenanceRef(kind=ProvenanceNodeKind.PROBE, id="probe-2"),
        role=ProvenanceRole.MEASURED,
        note="http probe",
    )

    assert edge.label() == "observation:obs-7 -measured-> probe:probe-2"
    assert edge.to_dict()["role"] == "measured"
    assert edge.to_dict()["note"] == "http probe"


def test_edge_must_ascend_the_ladder() -> None:
    with pytest.raises(ValidationError, match="ascend the ladder"):
        ProvenanceEdge(
            source=ProvenanceRef(kind=ProvenanceNodeKind.VERDICT, id="v-1"),
            target=ProvenanceRef(kind=ProvenanceNodeKind.FACT, id="f-1"),
        )


def test_edge_may_not_stay_on_the_same_rung() -> None:
    with pytest.raises(ValidationError, match="ascend the ladder"):
        ProvenanceEdge(
            source=ProvenanceRef(kind=ProvenanceNodeKind.FACT, id="f-1"),
            target=ProvenanceRef(kind=ProvenanceNodeKind.FACT, id="f-2"),
        )


def test_ladder_builder_refuses_out_of_order_nodes() -> None:
    nodes = make_ladder_nodes()
    nodes[2], nodes[3] = nodes[3], nodes[2]

    with pytest.raises(ValueError, match="must be in ladder order"):
        ProvenancePath.ladder(nodes)


def test_ladder_builder_refuses_a_short_path() -> None:
    with pytest.raises(ValueError, match="needs 8 nodes"):
        ProvenancePath.ladder(make_ladder_nodes()[:5])


def test_incomplete_path_reports_the_missing_rungs() -> None:
    path = ProvenancePath(edges=full_path().edges[:3])

    assert path.is_complete() is False
    assert any("do not equal the declared ladder" in error for error in path.errors())


def test_empty_path_is_not_complete() -> None:
    assert ProvenancePath().is_complete() is False
    assert ProvenancePath().kinds() == ()


def test_discontinuous_path_names_the_gap() -> None:
    edges = list(full_path().edges)
    edges[3] = edges[3].model_copy(update={"role": ProvenanceRole.AGGREGATED_INTO})
    path = ProvenancePath(edges=(*edges[:2], edges[3]))

    problems = path.errors()

    assert path.is_complete() is False
    assert any("edge 2 starts at" in error for error in problems)


def test_reused_node_id_is_reported() -> None:
    nodes = make_ladder_nodes()
    nodes[1] = ProvenanceRef(kind=ProvenanceNodeKind.OBSERVATION, id=nodes[0].id)
    path = ProvenancePath.ladder(nodes)

    problems = path.errors()

    assert path.is_complete() is False
    assert any("reuses node id(s)" in error for error in problems)


def test_provenance_ref_key_is_canonical() -> None:
    ref = ProvenanceRef(kind=ProvenanceNodeKind.TARGET, id="svc-a")

    assert ref.key() == "target:svc-a"
    assert ProvenanceRef.model_validate(ref.to_dict()) == ref


def test_provenance_ref_normalizes_unicode_ids() -> None:
    assert ProvenanceRef(kind=ProvenanceNodeKind.FACT, id="cafe\u0301").id == "caf\u00e9"


def test_empty_provenance_id_is_refused() -> None:
    with pytest.raises(ValidationError, match="must be non-empty"):
        ProvenanceRef(kind=ProvenanceNodeKind.FACT, id="   ")


# --------------------------------------------------------------------------- #
# Clock-uncertainty arithmetic                                                #
# --------------------------------------------------------------------------- #


def test_exact_timestamps_order_strictly_on_the_wall_clock() -> None:
    earlier = make_time(monotonic_ns=1_000)
    later = make_time(wall_clock=BASE_WALL_CLOCK + timedelta(seconds=5), monotonic_ns=6_000)
    offset = wall_clock_offset(earlier, later)

    assert offset.ordering == "after"
    assert offset.ordered is True
    assert offset.seconds == pytest.approx(5.0)
    assert offset.lower == offset.upper == pytest.approx(5.0)
    assert wall_clock_ordering_ambiguous(earlier, later) is False


def test_zero_uncertainty_means_the_reading_is_its_own_bound() -> None:
    stamp = make_time(uncertainty_ms=0.0)

    assert stamp.is_exact is True
    assert stamp.earliest_wall_clock() == stamp.latest_wall_clock() == BASE_WALL_CLOCK
    assert stamp.uncertainty == timedelta(0)


def test_uncertainty_widens_the_interval_symmetrically() -> None:
    stamp = make_time(uncertainty_ms=250.0)

    assert stamp.earliest_wall_clock() == BASE_WALL_CLOCK - timedelta(milliseconds=250)
    assert stamp.latest_wall_clock() == BASE_WALL_CLOCK + timedelta(milliseconds=250)
    assert stamp.is_exact is False


def test_overlapping_uncertainty_bounds_are_indeterminate() -> None:
    # Two readings 100 ms apart, each uncertain by 100 ms: the wall clock
    # cannot say which came first, and must not pretend to.
    first = make_time(monotonic_ns=1_000, uncertainty_ms=100.0)
    second = make_time(
        wall_clock=BASE_WALL_CLOCK + timedelta(milliseconds=100),
        monotonic_ns=2_000,
        uncertainty_ms=100.0,
    )
    offset = wall_clock_offset(first, second)

    assert offset.ordering == "indeterminate"
    assert offset.ordered is False
    assert offset.lower == pytest.approx(-0.1)
    assert offset.upper == pytest.approx(0.3)
    assert offset.seconds == pytest.approx(0.1)
    assert wall_clock_ordering_ambiguous(first, second) is True
    assert wall_clock_ordering_ambiguous(second, first) is True


def test_separated_bounds_prove_order_in_both_directions() -> None:
    first = make_time(monotonic_ns=1_000, uncertainty_ms=10.0)
    second = make_time(
        wall_clock=BASE_WALL_CLOCK + timedelta(seconds=2),
        monotonic_ns=2_000,
        uncertainty_ms=10.0,
    )

    assert wall_clock_offset(first, second).ordering == "after"
    assert wall_clock_offset(second, first).ordering == "before"
    assert wall_clock_ordering_ambiguous(first, second) is False


def test_monotonic_reading_totally_orders_even_when_wall_clocks_agree() -> None:
    first = make_time(monotonic_ns=5_000)
    second = make_time(monotonic_ns=6_000)

    assert monotonic_ordering(first, second) == "1"
    assert monotonic_ordering(second, first) == "-1"
    assert monotonic_ordering(first, first) == "0"
    assert wall_clock_ordering_ambiguous(first, second) is True


def test_monotonic_span_is_the_elapsed_reading() -> None:
    first = make_time(monotonic_ns=1_000)
    second = make_time(
        wall_clock=BASE_WALL_CLOCK + timedelta(seconds=1), monotonic_ns=1_000_500_000
    )

    assert monotonic_span_ns(first, second) == 1_000_499_000


def test_monotonic_span_refuses_backwards_readings() -> None:
    first = make_time(monotonic_ns=9_000)
    second = make_time(monotonic_ns=1_000)

    with pytest.raises(ValueError, match="run backwards"):
        monotonic_span_ns(first, second)


def test_accumulated_uncertainty_is_the_conservative_sum() -> None:
    samples = [make_time(uncertainty_ms=2.5), make_time(uncertainty_ms=2.5)]

    assert accumulated_uncertainty(samples) == timedelta(milliseconds=5)
    assert accumulated_uncertainty([]) == timedelta(0)


def test_naive_wall_clock_is_refused() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        AttestedTimestamp(
            wall_clock=datetime(2026, 3, 1, 12),  # noqa: DTZ001 - naive is the point
            monotonic_ns=1,
        )


def test_wall_clock_is_normalized_to_utc() -> None:
    stamp = AttestedTimestamp(
        wall_clock=datetime(2026, 3, 1, 13, 0, tzinfo=timezone(timedelta(hours=1))),
        monotonic_ns=1,
    )

    assert stamp.wall_clock.tzinfo is UTC
    assert stamp.wall_clock == BASE_WALL_CLOCK


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1.0])
def test_invalid_uncertainty_is_refused(value: float) -> None:
    with pytest.raises(ValidationError):
        make_time(uncertainty_ms=value)


# --------------------------------------------------------------------------- #
# Manifest and the negative controls                                          #
# --------------------------------------------------------------------------- #


def test_manifest_covers_event_roots_in_order() -> None:
    chain = make_chain(3)
    manifest = build_manifest(chain, manifest_id="m-1", retention_class=RetentionClass.LEGAL_HOLD)

    assert manifest.event_ids == ("e-0", "e-1", "e-2")
    assert manifest.event_roots == tuple(event.digest for event in chain)
    assert manifest.covered_events == 3
    assert manifest.retention_class is RetentionClass.LEGAL_HOLD
    assert manifest.digest_matches() is True
    assert manifest.previous_manifest_digest == GENESIS_DIGEST


def test_unsigned_manifest_verifies_integrity_but_warns_about_authorship() -> None:
    chain = make_chain(2)
    manifest = build_manifest(chain, manifest_id="m-1")
    verdict = verify_manifest(manifest, chain)

    assert verdict.valid is True
    assert verdict.signed is False
    assert verdict.events_checked == 2
    assert verdict.warnings == ("manifest is unsigned: integrity is verified, authorship is not",)


def test_signer_without_a_trust_root_fails_review() -> None:
    # Plan 12 Phase 6: a signing claim must name the key holder and the trust
    # root. "Signed" without "trusted how" is not a verifiable statement.
    chain = make_chain(1)
    manifest = build_manifest(chain, manifest_id="m-1", signer_identity="operator@mayhem")
    verdict = verify_manifest(manifest, chain)

    assert verdict.signed is True
    assert verdict.valid is False
    assert any("but no trust root" in error for error in verdict.errors)


def test_trust_root_without_a_signer_fails_review() -> None:
    chain = make_chain(1)
    manifest = build_manifest(chain, manifest_id="m-1", trust_root_ref="file:///trust/roots.json")
    verdict = verify_manifest(manifest, chain)

    assert verdict.valid is False
    assert any("but no signer" in error for error in verdict.errors)


def test_named_signer_with_trust_root_passes_the_honesty_gate() -> None:
    chain = make_chain(1)
    manifest = build_manifest(
        chain,
        manifest_id="m-1",
        signer_identity="operator@mayhem",
        trust_root_ref="file:///trust/roots.json",
    )
    verdict = verify_manifest(manifest, chain)

    assert verdict.valid is True
    assert verdict.signed is True
    assert verdict.warnings == ()


def test_swapped_event_is_rejected_by_the_manifest_predicate() -> None:
    chain = list(make_chain(3))
    honest = seal_events([make_event(event_id=f"e-{index}", sequence=index) for index in range(3)])
    manifest = build_manifest(honest, manifest_id="m-1")
    swapped = list(chain)
    swapped[1] = chain[1].model_copy(update={"payload": {"step": "s-2", "verdict": "ok"}})
    verdict = verify_manifest(manifest, swapped)

    assert verdict.valid is False
    assert any("'e-1'" in error for error in verdict.errors)


def test_manifest_tampering_breaks_its_digest() -> None:
    chain = make_chain(2)
    manifest = build_manifest(chain, manifest_id="m-1")
    tampered = manifest.model_copy(update={"retention_class": RetentionClass.EPHEMERAL})
    verdict = verify_manifest(tampered, chain)

    assert verdict.valid is False
    assert any("digest mismatch" in error for error in verdict.errors)


def test_manifest_over_unsealed_events_is_refused() -> None:
    with pytest.raises(ValueError, match="unsealed event"):
        build_manifest([make_event(event_id="e-0", sequence=0)], manifest_id="m-1")


def test_mismatched_event_count_is_reported() -> None:
    chain = make_chain(3)
    manifest = build_manifest(chain, manifest_id="m-1")
    verdict = verify_manifest(manifest, chain[:2])

    assert verdict.valid is False
    assert any("covers 3 events, 2 supplied" in error for error in verdict.errors)


def test_manifest_with_duplicate_event_ids_is_refused() -> None:
    with pytest.raises(ValidationError, match="must be unique"):
        Manifest(
            manifest_id="m-1",
            run_id="run-1",
            event_ids=("e-0", "e-0"),
            event_roots=("0" * 64, "1" * 64),
        )


def test_manifest_round_trips_through_json() -> None:
    chain = make_chain(2)
    manifest = build_manifest(chain, manifest_id="m-1", retention_class=RetentionClass.ARCHIVE)
    revived = Manifest.model_validate(json.loads(json.dumps(manifest.to_dict())))

    assert revived == manifest
    assert revived.computed_digest() == manifest.computed_digest()


def test_schema_version_is_the_phase_one_value() -> None:
    chain = make_chain(1)
    manifest = build_manifest(chain, manifest_id="m-1")

    assert manifest.schema_version == ATTESTATION_SCHEMA_VERSION == "1.0"
    assert chain[0].schema_version == ATTESTATION_SCHEMA_VERSION
