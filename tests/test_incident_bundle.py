import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.incident_bundle import verify_incident_bundle, write_incident_bundle


def test_incident_bundle_round_trip(tmp_path: Path) -> None:
    bundle = tmp_path / "incident"
    manifest = write_incident_bundle(
        bundle,
        incident_id="INC-test",
        authority={"warrant_id": "w-1", "runtime": {"epoch": 0}},
        containment={"epoch_before": 0, "epoch_after": 1, "external_verified": True},
        runtime_evidence={"execution": {"execution_id": "exec-1"}},
        external_proof={"cgroup_populated": False, "workload_exit_code": -9},
        provenance={"producer": "test"},
    )

    result = verify_incident_bundle(bundle)
    assert result["status"] == "VERIFIED"
    assert result["incident_id"] == "INC-test"
    assert manifest["incident_id"] == "INC-test"


def test_incident_bundle_fails_closed_on_tamper(tmp_path: Path) -> None:
    bundle = tmp_path / "incident"
    write_incident_bundle(
        bundle,
        incident_id="INC-tamper",
        authority={"warrant_id": "w-1"},
        containment={"epoch_after": 1},
        runtime_evidence={"status": "observed"},
        external_proof={"cgroup_populated": False},
        provenance={"producer": "test"},
    )

    (bundle / "external-proof.json").write_text(
        '{"cgroup_populated":true}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="digest mismatch"):
        verify_incident_bundle(bundle)


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

    write_incident_bundle(
        bundle,
        incident_id="INC-trusted",
        authority={"warrant_id": "w-1"},
        containment={"epoch_after": 1},
        runtime_evidence={"status": "observed"},
        external_proof={"cgroup_populated": False},
        provenance={"producer": "test"},
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
