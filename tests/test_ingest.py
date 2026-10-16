from agentcontain.evidence import EvidenceEnvelope
from agentcontain.ingest import InMemoryEvidenceSink

def _envelope(receipt=None, execution_id="exec-1"):
    return EvidenceEnvelope.from_execution(
        execution={"execution_id": execution_id, "agent_id": "agent-1", "policy_id": "policy-1", "policy_digest": "digest-1", "epoch": 0},
        events=({"execution_id": execution_id, "sequence": 1, "name": "admitted", "epoch": 0},),
        verification={"status": "verified", "method": "test"}, receipt=receipt,
    )

def test_ingestion_preserves_original_envelope():
    envelope = _envelope()
    sink = InMemoryEvidenceSink()
    submitted = sink.submit(envelope)
    assert submitted == envelope
    assert submitted is not envelope
    assert sink.all() == (envelope,)

def test_ingestion_is_idempotent_by_receipt_id():
    receipt={"payload":{"receipt_id":"receipt-1","execution_id":"exec-1","agent_id":"agent-1","policy_id":"policy-1","epoch":0},"digest":"digest","signature":"signature"}
    envelope=_envelope(receipt); sink=InMemoryEvidenceSink()
    assert sink.submit(envelope) is envelope
    duplicate=EvidenceEnvelope.from_json(envelope.to_json())
    assert sink.submit(duplicate) == envelope
    assert sink.get("receipt-1") == envelope
    assert sink.all() == (envelope,)

def test_ingestion_rejects_receipt_id_collision_with_different_evidence():
    receipt={"payload":{"receipt_id":"receipt-1","execution_id":"exec-1","agent_id":"agent-1","policy_id":"policy-1","epoch":0},"digest":"digest","signature":"signature"}
    first=_envelope(receipt)
    second=EvidenceEnvelope.from_dict({**first.to_dict(),"provenance":{"producer":"different"}})
    sink=InMemoryEvidenceSink(); sink.submit(first)
    try: sink.submit(second)
    except ValueError as exc: assert "receipt-1" in str(exc)
    else: raise AssertionError("expected receipt ID collision")

def test_ingestion_accepts_multiple_receiptless_envelopes():
    first=_envelope(); second=_envelope(execution_id="exec-2")
    sink=InMemoryEvidenceSink(); sink.submit(first); sink.submit(second)
    assert sink.all() == (first, second)
