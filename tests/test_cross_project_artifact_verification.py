from __future__ import annotations

import pytest

from agentcontain.external_evidence import (
    ExternalEvidenceReference,
    digest_artifact,
    verify_artifact_digest,
)


def _reference(artifact: bytes) -> ExternalEvidenceReference:
    return ExternalEvidenceReference(
        source="dprovenancekit",
        reference_id="dpk-proof:test-001",
        digest=digest_artifact(artifact),
        relation="attests",
        captured_at="2026-10-14T00:00:00Z",
    )


def test_external_artifact_verification_accepts_exact_referenced_bytes() -> None:
    artifact = b'{"schema_version":"proof/v1","events":[1,2]}\n'
    reference = _reference(artifact)

    assert verify_artifact_digest(artifact, reference)


def test_external_artifact_verification_rejects_one_byte_mutation() -> None:
    artifact = b'{"schema_version":"proof/v1","events":[1,2]}\n'
    reference = _reference(artifact)
    mutated = artifact.replace(b'"events":[1,2]', b'"events":[1,3]')

    assert mutated != artifact
    assert not verify_artifact_digest(mutated, reference)


def test_external_artifact_verification_binds_serialization_bytes_not_json_meaning() -> None:
    compact = b'{"a":1,"b":2}'
    reordered = b'{"b":2,"a":1}'
    reference = _reference(compact)

    # Both byte strings represent equivalent JSON objects, but the contract
    # binds the exact exported artifact bytes rather than parsed JSON meaning.
    assert verify_artifact_digest(compact, reference)
    assert not verify_artifact_digest(reordered, reference)


def test_external_artifact_verification_rejects_non_bytes() -> None:
    artifact = b'{"proof":"example"}'
    reference = _reference(artifact)

    with pytest.raises(TypeError, match="artifact must be bytes"):
        verify_artifact_digest("not bytes", reference)  # type: ignore[arg-type]


def test_external_artifact_verification_rejects_wrong_reference_type() -> None:
    with pytest.raises(TypeError, match="reference must be an ExternalEvidenceReference"):
        verify_artifact_digest(b"artifact", object())  # type: ignore[arg-type]
