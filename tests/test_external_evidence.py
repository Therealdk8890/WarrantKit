import json
from pathlib import Path

from agentcontain.evidence import EvidenceEnvelope
from agentcontain.external_evidence import ExternalEvidenceReference


FIXTURE = Path(__file__).parent / "fixtures" / "cross_repo_evidence_v1.json"


def _reference(**overrides) -> ExternalEvidenceReference:
    values = {
        "source": "warden",
        "reference_id": "warden-event-1",
        "digest": "sha256:" + "a" * 64,
        "relation": "observed_during",
        "captured_at": "2026-09-27T00:00:00Z",
    }
    values.update(overrides)
    return ExternalEvidenceReference(**values)


def _fixture_references() -> tuple[ExternalEvidenceReference, ...]:
    document = json.loads(FIXTURE.read_text())
    assert document["schema_version"] == "agentcontain.external-evidence/v1"
    return tuple(
        ExternalEvidenceReference.from_dict(item)
        for item in document["references"]
    )


def _envelope(
    references: tuple[ExternalEvidenceReference, ...],
) -> EvidenceEnvelope:
    return EvidenceEnvelope.from_execution(
        execution={
            "execution_id": "exec-cross-repo-1",
            "agent_id": "agent-1",
            "policy_id": "production",
            "policy_digest": "sha256:" + "1" * 64,
            "epoch": 7,
        },
        events=(
            {
                "execution_id": "exec-cross-repo-1",
                "sequence": 1,
                "name": "admission_verified",
                "epoch": 7,
            },
        ),
        enforcement={"complete": True, "external_verified": True},
        verification={"status": "verified", "method": "cross-repo-fixture"},
        proof={"claims": ["containment", "provenance", "claim-verification"]},
        provenance={"producer": "agentcontain"},
        external_evidence=references,
    )


def test_external_evidence_reference_roundtrip() -> None:
    reference = _reference()
    assert ExternalEvidenceReference.from_dict(reference.to_dict()) == reference


def test_external_evidence_reference_rejects_unknown_source() -> None:
    try:
        _reference(source="unknown")
    except ValueError as exc:
        assert "source" in str(exc)
    else:
        raise AssertionError("unknown evidence source was accepted")



def test_evidentia_is_an_evidence_source_not_an_authority_source() -> None:
    reference = _reference(
        source="evidentia",
        reference_id="EV-REAL-PROOF-PLACEHOLDER",
        relation="attests",
    )

    assert reference.source == "evidentia"
    assert reference.relation == "attests"

def test_external_evidence_reference_rejects_bad_digest() -> None:
    try:
        _reference(digest="sha256:not-a-digest")
    except ValueError as exc:
        assert "sha256" in str(exc)
    else:
        raise AssertionError("invalid digest was accepted")


def test_external_evidence_reference_rejects_unknown_relation() -> None:
    try:
        _reference(relation="authorizes")
    except ValueError as exc:
        assert "relation" in str(exc)
    else:
        raise AssertionError("authority relation was accepted")


def test_cross_repo_fixture_covers_all_platform_evidence_sources() -> None:
    references = _fixture_references()

    assert {reference.source for reference in references} == {
        "warden",
        "agentcontainment",
        "dprovenancekit",
        "claimproofkit",
    }


def test_cross_repo_fixture_roundtrips_through_evidence_envelope() -> None:
    envelope = _envelope(_fixture_references())

    restored = EvidenceEnvelope.from_json(envelope.to_json())

    assert restored.external_evidence == envelope.external_evidence
    assert restored.execution == envelope.execution
    assert restored.to_json() == envelope.to_json()


def test_cross_repo_references_preserve_integrity_metadata() -> None:
    references = _fixture_references()

    assert all(reference.digest.startswith("sha256:") for reference in references)
    assert all(len(reference.digest.removeprefix("sha256:")) == 64 for reference in references)
    assert {reference.relation for reference in references} == {
        "observed_during",
        "derived_from",
        "attests",
        "verifies",
    }


def test_external_evidence_cannot_introduce_runtime_authority() -> None:
    reference = _fixture_references()[0]
    document = reference.to_dict()
    document["relation"] = "authorizes"

    try:
        ExternalEvidenceReference.from_dict(document)
    except ValueError as exc:
        assert "relation" in str(exc)
    else:
        raise AssertionError("external evidence introduced an authority relation")


def test_changing_a_reference_changes_the_canonical_envelope() -> None:
    references = list(_fixture_references())
    original = _envelope(tuple(references)).to_json()

    references[0] = ExternalEvidenceReference(
        source=references[0].source,
        reference_id=references[0].reference_id,
        digest="sha256:" + "b" * 64,
        relation=references[0].relation,
        captured_at=references[0].captured_at,
    )

    changed = _envelope(tuple(references)).to_json()

    assert changed != original
