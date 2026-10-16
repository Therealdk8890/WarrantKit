from agentcontain.evidence import EvidenceEnvelope
from agentcontain.store import InMemoryEvidenceStore


def _envelope(receipt_id=None, digest="digest") -> EvidenceEnvelope:
    receipt = None
    if receipt_id is not None:
        receipt = {
            "payload": {
                "schema_version": 1,
                "receipt_id": receipt_id,
                "execution_id": "exec-1",
                "agent_id": "agent-1",
                "epoch": 0,
                "policy_id": "production",
            },
            "digest": digest,
            "signature": "sig",
        }
    return EvidenceEnvelope.from_execution(
        execution={
            "execution_id": "exec-1",
            "agent_id": "agent-1",
            "policy_id": "production",
            "policy_digest": "policy-digest",
            "epoch": 0,
        },
        events=({"execution_id": "exec-1", "sequence": 1, "name": "admission_verified", "epoch": 0},),
        verification={"status": "verified", "method": "test"},
        receipt=receipt,
    )


def test_store_put_get_round_trip_preserves_envelope():
    store = InMemoryEvidenceStore()
    envelope = _envelope("receipt-1")
    stored = store.put(envelope)
    assert stored == envelope
    assert stored is not envelope
    assert store.get("receipt-1") == envelope
    assert store.exists("receipt-1")


def test_store_is_idempotent_for_identical_receipt():
    store = InMemoryEvidenceStore()
    envelope = _envelope("receipt-1")
    store.put(envelope)
    assert store.put(EvidenceEnvelope.from_json(envelope.to_json())) == envelope


def test_store_rejects_receipt_collision_with_changed_evidence():
    store = InMemoryEvidenceStore()
    store.put(_envelope("receipt-1", digest="digest-a"))
    changed = _envelope("receipt-1", digest="digest-b")
    try:
        store.put(changed)
    except ValueError as exc:
        assert "receipt_id collision" in str(exc)
    else:
        raise AssertionError("receipt collision was silently overwritten")


def test_store_retains_receiptless_evidence():
    store = InMemoryEvidenceStore()
    envelope = _envelope()
    stored = store.put(envelope)
    assert stored == envelope
    assert stored is not envelope
    assert store.all() == (envelope,)


def test_store_snapshots_nested_evidence_from_mutation():
    store = InMemoryEvidenceStore()
    envelope = _envelope("receipt-immutable")
    returned = store.put(envelope)

    envelope.proof["mutated_source"] = True
    returned.proof["mutated_return"] = True

    retrieved = store.get("receipt-immutable")
    assert retrieved is not None
    assert "mutated_source" not in retrieved.proof
    assert "mutated_return" not in retrieved.proof

    retrieved.proof["mutated_read"] = True
    again = store.get("receipt-immutable")
    assert again is not None
    assert "mutated_read" not in again.proof

    listed = store.all()
    listed[0].proof["mutated_list"] = True
    assert "mutated_list" not in store.get("receipt-immutable").proof
