from agentcontain.evidence import EvidenceEnvelope


def _envelope() -> EvidenceEnvelope:
    return EvidenceEnvelope.from_execution(
        execution={
            "execution_id": "exec-1",
            "agent_id": "agent-1",
            "policy_id": "production",
            "policy_digest": "digest",
            "epoch": 0,
        },
        events=(
            {"execution_id": "exec-1", "sequence": 1, "name": "admission_verified", "epoch": 0},
        ),
        enforcement={"complete": True},
        verification={"status": "verified", "method": "unit-test"},
        proof={"claims": ["containment"]},
        provenance={"producer": "agentcontain", "created_at": "2026-09-26T00:00:00Z"},
    )


def _receipt(**payload_overrides):
    payload = {
        "schema_version": 1,
        "receipt_id": "receipt-1",
        "execution_id": "exec-1",
        "agent_id": "agent-1",
        "epoch": 0,
        "policy_id": "production",
        "proof_status": "verified",
    }
    payload.update(payload_overrides)
    return {
        "payload": payload,
        "digest": "digest-1",
        "signature": "signature-1",
    }


def test_evidence_serialization_is_deterministic() -> None:
    envelope = _envelope()
    assert envelope.to_json() == EvidenceEnvelope.from_json(envelope.to_json()).to_json()


def test_evidence_roundtrip_preserves_identity() -> None:
    restored = EvidenceEnvelope.from_json(_envelope().to_json())
    assert restored.execution == _envelope().execution
    assert restored.verification["status"] == "verified"


def test_evidence_rejects_event_identity_mismatch() -> None:
    try:
        EvidenceEnvelope.from_execution(
            execution={
                "execution_id": "exec-1",
                "agent_id": "agent-1",
                "policy_id": "production",
                "policy_digest": "digest",
                "epoch": 0,
            },
            events=({"execution_id": "exec-2", "sequence": 1, "name": "bad"},),
        )
    except ValueError as exc:
        assert "execution_id" in str(exc)
    else:
        raise AssertionError("mismatched event identity was accepted")


def test_evidence_rejects_invalid_status() -> None:
    try:
        EvidenceEnvelope.from_execution(
            execution={
                "execution_id": "exec-1",
                "agent_id": "agent-1",
                "policy_id": "production",
                "policy_digest": "digest",
                "epoch": 0,
            },
            verification={"status": "bogus"},
        )
    except ValueError as exc:
        assert "invalid verification status" in str(exc)
    else:
        raise AssertionError("invalid verification status was accepted")


def test_receipt_binding_preserves_full_receipt() -> None:
    receipt = _receipt()
    bound = _envelope().with_receipt(receipt)
    assert bound.receipt == receipt
    assert bound.receipt_id == "receipt-1"
    assert EvidenceEnvelope.from_json(bound.to_json()).receipt == receipt


def test_receipt_identity_cannot_diverge_from_evidence() -> None:
    for field, value in (
        ("execution_id", "other-execution"),
        ("agent_id", "other-agent"),
        ("policy_id", "other-policy"),
        ("epoch", 1),
    ):
        try:
            _envelope().with_receipt(_receipt(**{field: value}))
        except ValueError as exc:
            assert field in str(exc)
        else:
            raise AssertionError(f"receipt {field} mismatch was accepted")


def test_receipt_binding_does_not_verify_or_rewrite_cryptography() -> None:
    receipt = _receipt()
    bound = _envelope().with_receipt(receipt)
    assert bound.receipt["digest"] == "digest-1"
    assert bound.receipt["signature"] == "signature-1"


def test_evidence_parses_legacy_v1_without_external_evidence() -> None:
    document = _envelope().to_dict()
    document.pop("external_evidence")
    document["schema_version"] = "agentcontain.evidence/v1"

    restored = EvidenceEnvelope.from_dict(document)

    assert restored.schema_version == "agentcontain.evidence/v1"
    assert restored.external_evidence == ()



def test_evidence_rejects_event_without_epoch() -> None:
    try:
        EvidenceEnvelope.from_execution(
            execution={
                "execution_id": "exec-1",
                "agent_id": "agent-1",
                "policy_id": "production",
                "policy_digest": "digest",
                "epoch": 0,
            },
            events=({"execution_id": "exec-1", "sequence": 1, "name": "event_without_epoch"},),
        )
    except ValueError as exc:
        assert "epoch is required" in str(exc)
    else:
        raise AssertionError("event without epoch was accepted")
