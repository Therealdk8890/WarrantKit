import hashlib
import json

import pytest

from agentcontain.native_provenance import (
    NativeProvenanceError,
    validate_native_provenance_manifest,
)


RUN_ID = "00000000-0000-0000-0000-000000000099"
EVENT_EXTRACTED = "00000000-0000-0000-0000-000000000001"
EVENT_VERIFIED = "00000000-0000-0000-0000-000000000002"
EVENT_FINALIZED = "00000000-0000-0000-0000-000000000003"


def _event(event_id, sequence, type_identifier, payload):
    return {
        "id": event_id,
        "runID": RUN_ID,
        "contextID": "claimproof",
        "engineName": "ClaimProofKit",
        "schemaVersion": 1,
        "sequence": sequence,
        "payload": {
            "typeIdentifier": type_identifier,
            "priorityValue": 3,
            "rawJSON": json.dumps(payload, sort_keys=True, separators=(",", ":")),
        },
    }


def _manifest(status="directlySupported", safe_to_publish=True):
    report_fp = hashlib.sha256(
        f"cpk:v1:report:claim-fp:{status}|".encode()
    ).hexdigest()
    events = [
        _event(EVENT_EXTRACTED, 0, "cpk_claim_extracted", {
            "fingerprint": "claim-fp",
            "text": "example claim",
        }),
        _event(EVENT_VERIFIED, 1, "cpk_claim_verified", {
            "claimFingerprint": "claim-fp",
            "status": status,
            "confidence": 0.99 if safe_to_publish else 0.0,
            "evidenceFingerprints": [],
        }),
        _event(EVENT_FINALIZED, 2, "cpk_report_finalized", {
            "reportFingerprint": report_fp,
            "policyFingerprint": "policy-fp",
            "safeToPublish": safe_to_publish,
            "specVersion": "1.0",
            "statusCounts": {status: 1},
        }),
    ]
    run_fp = hashlib.sha1(
        b"cpk_claim_extracted:ClaimProofKit|cpk_claim_verified:ClaimProofKit|cpk_report_finalized:ClaimProofKit|"
    ).hexdigest()
    return {
        "bridgeVersion": "1.0",
        "specVersion": "1.0",
        "engineName": "ClaimProofKit",
        "contextID": "claimproof",
        "runFingerprint": run_fp,
        "reportFingerprint": report_fp,
        "policyFingerprint": "policy-fp",
        "events": events,
        "edges": [
            {"sourceID": EVENT_EXTRACTED, "targetID": EVENT_VERIFIED, "type": "verifiedBy"},
            {"sourceID": EVENT_VERIFIED, "targetID": EVENT_FINALIZED, "type": "derivedFrom"},
        ],
    }


def _validate(manifest, **overrides):
    raw = json.dumps(manifest, sort_keys=True, indent=2, separators=(",", " : "))
    args = {
        "incident_id": "INC-1",
        "execution_id": "EXEC-1",
        "runtime_id": "RUNTIME-1",
        "epoch": 4,
        "expected_run_id": RUN_ID,
        "expected_context_id": "claimproof",
        "expected_report_fingerprint": hashlib.sha256(
            b"cpk:v1:report:claim-fp:directlySupported|"
        ).hexdigest(),
        "expected_policy_fingerprint": "policy-fp",
    }
    args.update(overrides)
    return validate_native_provenance_manifest(raw, **args)


def test_valid_native_manifest_is_bound_without_claiming_truth():
    result = _validate(_manifest())
    assert result["incident_id"] == "INC-1"
    assert result["execution_id"] == "EXEC-1"
    assert result["integrity"] == "validated"
    assert result["claim_truth"] == "not_established"
    assert result["runtime_enforcement"] == "not_established_by_provenance"
    assert result["claim_verification"] == "SUPPORTED"


def test_unsupported_verdict_cannot_be_relabelled_as_supported():
    manifest = _manifest(status="unsupported", safe_to_publish=False)
    finalized = json.loads(manifest["events"][2]["payload"]["rawJSON"])
    finalized["safeToPublish"] = True
    manifest["events"][2]["payload"]["rawJSON"] = json.dumps(
        finalized, sort_keys=True, separators=(",", ":")
    )
    with pytest.raises(NativeProvenanceError, match="safeToPublish"):
        _validate(
            manifest,
            expected_report_fingerprint=manifest["reportFingerprint"],
        )


def test_rejects_run_id_mismatch():
    with pytest.raises(NativeProvenanceError, match="run ID"):
        _validate(_manifest(), expected_run_id="00000000-0000-0000-0000-000000000098")


def test_rejects_report_fingerprint_mismatch():
    with pytest.raises(NativeProvenanceError, match="report fingerprint"):
        _validate(_manifest(), expected_report_fingerprint="sha256:other")


def test_rejects_tampered_run_fingerprint():
    manifest = _manifest()
    manifest["runFingerprint"] = "tampered"
    with pytest.raises(NativeProvenanceError, match="run fingerprint"):
        _validate(manifest)


def test_rejects_edges_to_unknown_events():
    manifest = _manifest()
    manifest["edges"][0]["targetID"] = "00000000-0000-0000-0000-000000000098"
    with pytest.raises(NativeProvenanceError, match="unknown event"):
        _validate(manifest)


def test_rejects_manifest_digest_mismatch():
    raw = json.dumps(_manifest(), sort_keys=True, indent=2, separators=(",", " : "))
    with pytest.raises(NativeProvenanceError, match="digest mismatch"):
        validate_native_provenance_manifest(
            raw,
            incident_id="INC-1",
            execution_id="EXEC-1",
            runtime_id="RUNTIME-1",
            epoch=4,
            expected_run_id=RUN_ID,
            expected_context_id="claimproof",
            expected_report_fingerprint=hashlib.sha256(
                b"cpk:v1:report:claim-fp:directlySupported|"
            ).hexdigest(),
            expected_policy_fingerprint="policy-fp",
            expected_sha256="sha256:wrong",
        )


def test_rejects_finalized_report_payload_mismatch():
    manifest = _manifest()
    finalized = json.loads(manifest["events"][2]["payload"]["rawJSON"])
    finalized["reportFingerprint"] = "different"
    manifest["events"][2]["payload"]["rawJSON"] = json.dumps(
        finalized, sort_keys=True, separators=(",", ":")
    )
    with pytest.raises(NativeProvenanceError, match="finalized report fingerprint"):
        _validate(manifest)


def test_rejects_event_context_mismatch():
    manifest = _manifest()
    manifest["events"][0]["contextID"] = "other-context"
    with pytest.raises(NativeProvenanceError, match="engine or context"):
        _validate(manifest)


def test_rejects_invalid_event_payload_json():
    manifest = _manifest()
    manifest["events"][0]["payload"]["rawJSON"] = "{"
    with pytest.raises(NativeProvenanceError, match="rawJSON is invalid"):
        _validate(manifest)


def test_rejects_missing_claim_lineage_edge():
    manifest = _manifest()
    manifest["edges"].pop(0)
    with pytest.raises(NativeProvenanceError, match="verifiedBy edge"):
        _validate(manifest)



def test_rejects_extracted_claim_fingerprint_mismatch():
    manifest = _manifest()
    extracted = json.loads(manifest["events"][0]["payload"]["rawJSON"])
    extracted["fingerprint"] = "different-claim"
    manifest["events"][0]["payload"]["rawJSON"] = json.dumps(
        extracted, sort_keys=True, separators=(",", ":")
    )
    with pytest.raises(NativeProvenanceError, match="fingerprints differ"):
        _validate(manifest)
