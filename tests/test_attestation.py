from datetime import datetime, timezone, tzinfo

import pytest

from agentcontain.attestation import (
    ARTIFACT_RECEIPT,
    ARTIFACT_WARRANT,
    AttestationEnvelope,
    Ed25519Signer,
    Ed25519Verifier,
)
from agentcontain.policy import Policy
from agentcontain.warrant import Warrant


class MissingOffsetTimezone(tzinfo):
    def utcoffset(self, dt):
        return None

    def dst(self, dt):
        return None


def _warrant() -> Warrant:
    policy = Policy("production", capabilities=("read",))
    return Warrant.issue(
        warrant_id="w-1",
        issuer="controller",
        agent_id="agent-1",
        execution_id="exec-1",
        policy=policy,
        runtime_id="runtime-1",
        epoch=1,
        issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        expires_at=datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc),
    )


def _verifier(signer: Ed25519Signer) -> Ed25519Verifier:
    return Ed25519Verifier({signer.key_id: signer.public_key()})


def test_valid_warrant_verifies() -> None:
    signer = Ed25519Signer.generate("wk-test-01")
    envelope = signer.sign_warrant(
        _warrant(), issued_at=datetime(2026, 1, 1, tzinfo=timezone.utc)
    )
    restored = AttestationEnvelope.from_dict(envelope.to_dict())
    assert _verifier(signer).verify_warrant(restored) == _warrant()


def test_modified_payload_fails() -> None:
    signer = Ed25519Signer.generate("wk-test-01")
    document = signer.sign_warrant(_warrant()).to_dict()
    document["payload"]["authority"]["policy_id"] = "tampered"
    with pytest.raises(ValueError, match="signature"):
        _verifier(signer).verify(document)


def test_modified_issued_at_fails() -> None:
    signer = Ed25519Signer.generate("wk-test-01")
    document = signer.sign_warrant(_warrant()).to_dict()
    document["issued_at"] = "2026-01-02T00:00:00+00:00"
    with pytest.raises(ValueError, match="signature"):
        _verifier(signer).verify(document)


def test_modified_key_id_fails_even_when_new_key_is_trusted() -> None:
    first = Ed25519Signer.generate("wk-01")
    second = Ed25519Signer.generate("wk-02")
    document = first.sign_warrant(_warrant()).to_dict()
    document["key_id"] = second.key_id
    verifier = Ed25519Verifier(
        {first.key_id: first.public_key(), second.key_id: second.public_key()}
    )
    with pytest.raises(ValueError, match="signature"):
        verifier.verify(document)


def test_wrong_key_fails() -> None:
    signer = Ed25519Signer.generate("wk-01")
    other = Ed25519Signer.generate("wk-other")
    envelope = signer.sign_warrant(_warrant())
    with pytest.raises(ValueError, match="signature"):
        Ed25519Verifier({signer.key_id: other.public_key()}).verify(envelope)


def test_unknown_key_id_fails() -> None:
    signer = Ed25519Signer.generate("wk-01")
    envelope = signer.sign_warrant(_warrant())
    with pytest.raises(ValueError, match="key_id"):
        Ed25519Verifier({}).verify(envelope)


def test_wrong_artifact_type_fails_closed() -> None:
    signer = Ed25519Signer.generate("wk-01")
    envelope = signer.sign(
        artifact_type=ARTIFACT_WARRANT, payload=_warrant().to_dict()
    )
    with pytest.raises(ValueError, match="artifact type"):
        _verifier(signer).verify(
            envelope, expected_artifact_type=ARTIFACT_RECEIPT
        )


def test_modified_schema_fails() -> None:
    signer = Ed25519Signer.generate("wk-01")
    document = signer.sign_warrant(_warrant()).to_dict()
    document["schema_version"] = "warrantkit.attestation/v999"
    with pytest.raises(ValueError, match="schema"):
        _verifier(signer).verify(document)


def test_key_rotation_accepts_overlap_and_rejects_unknown_retired_key() -> None:
    first = Ed25519Signer.generate("wk-01")
    second = Ed25519Signer.generate("wk-02")
    envelope = first.sign_warrant(_warrant())
    assert Ed25519Verifier(
        {first.key_id: first.public_key(), second.key_id: second.public_key()}
    ).verify(envelope)["warrant_id"] == "w-1"
    with pytest.raises(ValueError, match="key_id"):
        Ed25519Verifier({second.key_id: second.public_key()}).verify(envelope)


def test_receipt_profile_is_explicit() -> None:
    signer = Ed25519Signer.generate("wk-receipt")
    envelope = signer.sign_receipt(
        {"status": "verified", "execution_id": "exec-1"}
    )
    assert envelope.algorithm == "ed25519"
    assert envelope.artifact_type == ARTIFACT_RECEIPT


def test_non_finite_payload_is_rejected() -> None:
    signer = Ed25519Signer.generate("wk-test-01")
    with pytest.raises(ValueError, match="Out of range float values"):
        signer.sign_receipt({"value": float("nan")})


def test_malformed_envelope_types_fail_closed() -> None:
    signer = Ed25519Signer.generate("wk-test-01")
    document = signer.sign_warrant(_warrant()).to_dict()
    document["key_id"] = 123
    with pytest.raises(ValueError, match="key_id"):
        AttestationEnvelope.from_dict(document)

    document = signer.sign_warrant(_warrant()).to_dict()
    document["issued_at"] = 123
    with pytest.raises(TypeError, match="issued_at"):
        AttestationEnvelope.from_dict(document)

    document = signer.sign_warrant(_warrant()).to_dict()
    document["signature"] = 123
    with pytest.raises(ValueError, match="signature"):
        AttestationEnvelope.from_dict(document)


def test_signer_rejects_issued_at_timezone_without_utc_offset() -> None:
    signer = Ed25519Signer.generate("wk-test-invalid-timezone")
    with pytest.raises(ValueError, match="issued_at must be timezone-aware"):
        signer.sign_receipt(
            {"status": "verified"},
            issued_at=datetime(2026, 1, 1, tzinfo=MissingOffsetTimezone()),
        )
