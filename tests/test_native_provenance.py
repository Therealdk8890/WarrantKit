import hashlib
import json

import pytest

from agentcontain.native_provenance import (
    NativeProvenanceError,
    validate_native_provenance_manifest,
)


def _manifest():
    events = [
        {
            "id": "00000000-0000-0000-0000-000000000001",
            "runID": "00000000-0000-0000-0000-000000000099",
            "contextID": "claimproof",
            "engineName": "ClaimProofKit",
            "schemaVersion": 1,
            "sequence": 0,
            "payload": {"typeIdentifier": "cpk_claim_verified", "priorityValue": 3, "rawJSON": "{}"},
        },
        {
            "id": "00000000-0000-0000-0000-000000000002",
            "runID": "00000000-0000-0000-0000-000000000099",
            "contextID": "claimproof",
            "engineName": "ClaimProofKit",
            "schemaVersion": 1,
            "sequence": 1,
            "payload": {"typeIdentifier": "cpk_report_finalized", "priorityValue": 3, "rawJSON": "{}"},
        },
    ]
    report_fp = hashlib.sha256(b"cpk:v1:report:claim-fp:directlySupported|").hexdigest()
    events[0]["payload"]["rawJSON"] = json.dumps({
        "claimFingerprint": "claim-fp",
        "status": "directlySupported",
        "confidence": 0.99,
        "evidenceFingerprints": [],
    }, sort_keys=True, separators=(",", ":"))
    events[1]["payload"]["rawJSON"] = json.dumps({
        "reportFingerprint": report_fp,
        "policyFingerprint": "policy-fp",
        "safeToPublish": True,
        "specVersion": "1.0",
        "statusCounts": {"directlySupported": 1},
    }, sort_keys=True, separators=(",", ":"))
    run_fp = hashlib.sha1(
        b"cpk_claim_verified:ClaimProofKit|cpk_report_finalized:ClaimProofKit|"
    ).hexdigest()
    value = {
        "bridgeVersion": "1.0",
        "specVersion": "1.0",
        "engineName": "ClaimProofKit",
        "contextID": "claimproof",
        "runFingerprint": run_fp,
        "reportFingerprint": report_fp,
        "policyFingerprint": "policy-fp",
        "events": events,
        "edges": [{"sourceID": "00000000-0000-0000-0000-000000000001", "targetID": "00000000-0000-0000-0000-000000000002", "type": "derivedFrom"}],
    }
    return value


def _validate(manifest, **overrides):
    raw = json.dumps(manifest, sort_keys=True, indent=2, separators=(",", " : "))
    args = {
        "incident_id": "INC-1",
        "execution_id": "EXEC-1",
        "runtime_id": "RUNTIME-1",
        "epoch": 4,
        "expected_run_id": "00000000-0000-0000-0000-000000000099",
        "expected_context_id": "claimproof",
        "expected_report_fingerprint": hashlib.sha256(b"cpk:v1:report:claim-fp:directlySupported|").hexdigest(),
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
    manifest = _manifest()
    events = manifest["events"]
    events[0]["payload"]["rawJSON"] = json.dumps({
        "claimFingerprint": "claim-fp",
        "status": "unsupported",
        "confidence": 0.0,
        "evidenceFingerprints": [],
    }, sort_keys=True, separators=(",", ":"))
    report_fp = hashlib.sha256(b"cpk:v1:report:claim-fp:unsupported|").hexdigest()
    manifest["reportFingerprint"] = report_fp
    events[1]["payload"]["rawJSON"] = json.dumps({
        "reportFingerprint": report_fp,
        "policyFingerprint": "policy-fp",
        "safeToPublish": True,
        "specVersion": "1.0",
        "statusCounts": {"unsupported": 1},
    }, sort_keys=True, separators=(",", ":"))
    with pytest.raises(NativeProvenanceError, match="safeToPublish"):
        _validate(manifest, expected_report_fingerprint=report_fp)


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
    manifest = _manifest()
    raw = json.dumps(manifest, sort_keys=True, indent=2, separators=(",", " : "))
    with pytest.raises(NativeProvenanceError, match="digest mismatch"):
        validate_native_provenance_manifest(
            raw,
            incident_id="INC-1",
            execution_id="EXEC-1",
            runtime_id="RUNTIME-1",
            epoch=4,
            expected_run_id="RUN-1",
            expected_context_id="claimproof",
            expected_report_fingerprint="sha256:report",
            expected_policy_fingerprint="sha256:policy",
            expected_sha256="sha256:wrong",
        )
