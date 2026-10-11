import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.incident_bundle import verify_incident_bundle, write_incident_bundle


def _valid_records() -> dict:
    execution_id = "exec-1"
    runtime_id = "runtime-1"
    agent_id = "agent-1"
    evidence = {
        "execution": {
            "execution_id": execution_id,
            "runtime_id": runtime_id,
            "agent_id": agent_id,
            "epoch": 1,
        },
        "events": [
            {
                "execution_id": execution_id,
                "sequence": 1,
                "name": "containment_verified",
                "epoch": 1,
            },
            {
                "execution_id": execution_id,
                "sequence": 2,
                "name": "stale_authority_rejected",
                "epoch": 1,
                "details": {"warrant_epoch": 0, "reason": "runtime_epoch_mismatch"},
            },
        ],
        "verification": {"status": "observed"},
    }
    evidence_bytes = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode()
    return {
        "incident_id": "INC-test",
        "authority": {"warrant_id": "w-1", "runtime": {"epoch": 0}},
        "containment": {
            "schema_version": "warrantkit.containment-event/v1",
            "incident_id": "INC-test",
            "runtime_id": runtime_id,
            "execution_id": execution_id,
            "agent_id": agent_id,
            "epoch_before": 0,
            "epoch_after": 1,
            "state_after": "CONTAINED",
            "operation": "external_containment",
            "external_verified": True,
        },
        "runtime_evidence": evidence,
        "external_proof": {
            "schema_version": "warrantkit.external-proof/v1",
            "runtime_id": runtime_id,
            "agent_id": agent_id,
            "epoch": 1,
            "runtime_state": "TERMINATED",
            "can_execute": False,
            "cgroup_populated": False,
            "workload_exit_code": -9,
            "terminal_state_independently_observed": True,
        },
        "provenance": {
            "schema_version": "warrantkit.incident-provenance/v1",
            "producer": "test",
            "execution_id": execution_id,
            "runtime_evidence_sha256": "sha256:" + hashlib.sha256(evidence_bytes).hexdigest(),
            "runtime_verifier_result": "OBSERVED",
        },
    }


def _write_valid_bundle(bundle: Path) -> dict:
    records = _valid_records()
    return write_incident_bundle(
        bundle,
        incident_id=records["incident_id"],
        authority=records["authority"],
        containment=records["containment"],
        runtime_evidence=records["runtime_evidence"],
        external_proof=records["external_proof"],
        provenance=records["provenance"],
    )


def test_incident_bundle_round_trip(tmp_path: Path) -> None:
    bundle = tmp_path / "incident"
    manifest = _write_valid_bundle(bundle)

    result = verify_incident_bundle(bundle)
    assert result["status"] == "VERIFIED"
    assert result["incident_id"] == "INC-test"
    assert result["evidence_contract"] == "validated"
    # A key carried by the same bundle proves internal integrity only.
    assert result["authenticity"] == "bundle-key-integrity-only"
    assert manifest["incident_id"] == "INC-test"


def test_incident_bundle_fails_closed_on_tamper(tmp_path: Path) -> None:
    bundle = tmp_path / "incident"
    _write_valid_bundle(bundle)

    (bundle / "external-proof.json").write_text(
        '{"cgroup_populated":true}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="bundle file digest mismatch"):
        verify_incident_bundle(bundle)


def test_incident_bundle_rejects_unsupported_claims(tmp_path: Path) -> None:
    bundle = tmp_path / "incident"
    records = _valid_records()
    records["external_proof"]["can_execute"] = True

    with pytest.raises(ValueError, match="terminal state"):
        write_incident_bundle(
            bundle,
            incident_id=records["incident_id"],
            authority=records["authority"],
            containment=records["containment"],
            runtime_evidence=records["runtime_evidence"],
            external_proof=records["external_proof"],
            provenance=records["provenance"],
        )


def test_incident_bundle_rejects_cross_execution_evidence(tmp_path: Path) -> None:
    bundle = tmp_path / "incident"
    records = _valid_records()
    records["external_proof"]["runtime_id"] = "different-runtime"

    with pytest.raises(ValueError, match="runtime identity"):
        write_incident_bundle(
            bundle,
            incident_id=records["incident_id"],
            authority=records["authority"],
            containment=records["containment"],
            runtime_evidence=records["runtime_evidence"],
            external_proof=records["external_proof"],
            provenance=records["provenance"],
        )


def test_incident_bundle_rejects_mismatched_incident_id(tmp_path: Path) -> None:
    bundle = tmp_path / "incident"
    records = _valid_records()
    records["containment"]["incident_id"] = "INC-other"
    with pytest.raises(ValueError, match="containment incident identity"):
        write_incident_bundle(
            bundle, incident_id=records["incident_id"], authority=records["authority"],
            containment=records["containment"], runtime_evidence=records["runtime_evidence"],
            external_proof=records["external_proof"], provenance=records["provenance"],
        )


def test_incident_bundle_rejects_duplicate_required_events(tmp_path: Path) -> None:
    bundle = tmp_path / "incident"
    records = _valid_records()
    records["runtime_evidence"]["events"].append(
        dict(records["runtime_evidence"]["events"][0], sequence=3)
    )
    with pytest.raises(ValueError, match="exactly one containment_verified"):
        write_incident_bundle(
            bundle, incident_id=records["incident_id"], authority=records["authority"],
            containment=records["containment"], runtime_evidence=records["runtime_evidence"],
            external_proof=records["external_proof"], provenance=records["provenance"],
        )


def test_incident_bundle_requires_runtime_evidence_digest(tmp_path: Path) -> None:
    bundle = tmp_path / "incident"
    records = _valid_records()
    records["provenance"].pop("runtime_evidence_sha256")
    with pytest.raises(ValueError, match="missing the runtime evidence digest"):
        write_incident_bundle(
            bundle, incident_id=records["incident_id"], authority=records["authority"],
            containment=records["containment"], runtime_evidence=records["runtime_evidence"],
            external_proof=records["external_proof"], provenance=records["provenance"],
        )


def test_incident_bundle_supports_external_trust_anchor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = tmp_path / "incident"
    key = Ed25519PrivateKey.generate()
    key_file = tmp_path / "signing-key.pem"
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    monkeypatch.setenv("WARRANTKIT_INCIDENT_SIGNING_KEY_FILE", str(key_file))
    monkeypatch.setenv("WARRANTKIT_INCIDENT_SIGNING_KEY_ID", "test-deployment-key")

    records = _valid_records()
    write_incident_bundle(
        bundle,
        incident_id=records["incident_id"],
        authority=records["authority"],
        containment=records["containment"],
        runtime_evidence=records["runtime_evidence"],
        external_proof=records["external_proof"],
        provenance=records["provenance"],
    )

    public_key = base64.b64encode(
        key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode("ascii")

    result = verify_incident_bundle(
        bundle,
        trusted_public_key_b64=public_key,
    )
    assert result["authenticity"] == "trusted-anchor"

    untrusted_key = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    with pytest.raises(ValueError, match="trusted public key does not match bundle key"):
        verify_incident_bundle(
            bundle,
            trusted_public_key_b64=base64.b64encode(untrusted_key).decode("ascii"),
        )
