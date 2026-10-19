import pytest

from agentcontain.external_handoff import (
    CorrelationState,
    ExternalEvidenceHandoff,
    correlate_handoff,
)


def _handoff(**overrides) -> ExternalEvidenceHandoff:
    values = {
        "execution_id": "exec-1",
        "warrant_id": "warrant-1",
        "runtime_id": "runtime-1",
        "epoch": 3,
        "source": "evidentia",
        "artifact_ref": "EV-SYSTEM-PROOF-001",
        "artifact_digest": "sha256:" + "a" * 64,
        "anchor_ref": "anchor-1",
        "anchor_digest": "sha256:" + "a" * 64,
    }
    values.update(overrides)
    return ExternalEvidenceHandoff(**values)


def test_handoff_roundtrips() -> None:
    handoff = _handoff()

    assert ExternalEvidenceHandoff.from_dict(handoff.to_dict()) == handoff



@pytest.mark.parametrize("digest", [None, "", "sha256:abc", "SHA256:" + "a" * 64, 123])
def test_artifact_digest_is_required_and_strictly_validated(digest) -> None:
    with pytest.raises(ValueError, match="artifact_digest"):
        _handoff(artifact_digest=digest)


@pytest.mark.parametrize("digest", ["", "sha256:abc", "SHA256:" + "a" * 64, 123])
def test_present_anchor_digest_is_strictly_validated(digest) -> None:
    with pytest.raises(ValueError, match="anchor_digest"):
        _handoff(anchor_digest=digest)


def test_matching_anchor_is_correlated_but_not_verified() -> None:
    result = correlate_handoff(
        _handoff(),
        execution_id="exec-1",
        warrant_id="warrant-1",
        runtime_id="runtime-1",
        epoch=3,
        trusted_anchor_digest="sha256:" + "a" * 64,
    )

    assert result.state == CorrelationState.CORRELATED
    assert result.correlated is True
    assert result.anchored is True


def test_valid_but_wrong_replacement_is_conflict() -> None:
    result = correlate_handoff(
        _handoff(artifact_digest="sha256:" + "b" * 64),
        execution_id="exec-1",
        warrant_id="warrant-1",
        runtime_id="runtime-1",
        epoch=3,
        trusted_anchor_digest="sha256:" + "a" * 64,
    )

    assert result.state == CorrelationState.CONFLICT
    assert "trusted anchor digest" in result.reasons[0]


def test_self_asserted_anchor_metadata_cannot_establish_correlation() -> None:
    result = correlate_handoff(
        _handoff(),
        execution_id="exec-1",
        warrant_id="warrant-1",
        runtime_id="runtime-1",
        epoch=3,
    )
    assert result.state == CorrelationState.UNANCHORED
    assert result.anchored is False


def test_handoff_anchor_digest_must_match_independent_anchor() -> None:
    result = correlate_handoff(
        _handoff(anchor_digest="sha256:" + "b" * 64),
        execution_id="exec-1",
        warrant_id="warrant-1",
        runtime_id="runtime-1",
        epoch=3,
        trusted_anchor_digest="sha256:" + "a" * 64,
    )
    assert result.state == CorrelationState.CONFLICT
    assert "handoff anchor digest" in result.reasons[0]


def test_missing_anchor_is_not_verified() -> None:
    result = correlate_handoff(
        _handoff(anchor_ref=None, anchor_digest=None),
        execution_id="exec-1",
        warrant_id="warrant-1",
        runtime_id="runtime-1",
        epoch=3,
    )

    assert result.state == CorrelationState.UNANCHORED
    assert result.correlated is False


def test_identity_mismatch_fails_closed() -> None:
    result = correlate_handoff(
        _handoff(),
        execution_id="exec-other",
        warrant_id="warrant-1",
        runtime_id="runtime-1",
        epoch=3,
    )

    assert result.state == CorrelationState.CONFLICT
    assert "execution_id mismatch" in result.reasons


@pytest.mark.parametrize("field", ["schema_version", "source", "execution_id", "warrant_id", "runtime_id", "artifact_ref"])
@pytest.mark.parametrize("bad_value", [None, 7, [], {}])
def test_handoff_from_dict_rejects_non_string_required_fields(field, bad_value):
    document = _handoff().to_dict()
    document[field] = bad_value

    with pytest.raises(ValueError, match=field if field != "schema_version" else "schema"):
        ExternalEvidenceHandoff.from_dict(document)


@pytest.mark.parametrize("anchor_ref", [7, [], {}, ""])
def test_handoff_rejects_invalid_anchor_reference(anchor_ref):
    with pytest.raises(ValueError, match="anchor_ref"):
        _handoff(anchor_ref=anchor_ref)


def test_correlate_handoff_rejects_boolean_expected_epoch() -> None:
    with pytest.raises(ValueError, match="expected epoch"):
        correlate_handoff(
            _handoff(),
            execution_id="exec-1",
            warrant_id="warrant-1",
            runtime_id="runtime-1",
            epoch=True,
            trusted_anchor_digest="sha256:" + "a" * 64,
        )


@pytest.mark.parametrize("digest", ["", "sha256:abc", "SHA256:" + "a" * 64, 7])
def test_trusted_anchor_digest_is_strictly_validated(digest) -> None:
    with pytest.raises(ValueError, match="trusted_anchor_digest"):
        correlate_handoff(
            _handoff(),
            execution_id="exec-1",
            warrant_id="warrant-1",
            runtime_id="runtime-1",
            epoch=3,
            trusted_anchor_digest=digest,
        )


def test_handoff_from_dict_rejects_boolean_epoch():
    document = _handoff().to_dict()
    document["epoch"] = True

    with pytest.raises(ValueError, match="epoch"):
        ExternalEvidenceHandoff.from_dict(document)
