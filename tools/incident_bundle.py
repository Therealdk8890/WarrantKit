"""Build and verify portable incident bundles from an executed WarrantKit proof.

The bundle is an evidence package, not a new security boundary. It authenticates
the exported manifest with an Ed25519 receipt and records the public key used by
the demo. Production deployments must verify against an independently trusted
public-key anchor; the embedded key is not itself a trust anchor.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def write_incident_bundle(
    output_dir: Path,
    *,
    incident_id: str,
    authority: Mapping[str, Any],
    containment: Mapping[str, Any],
    runtime_evidence: Mapping[str, Any],
    external_proof: Mapping[str, Any],
    provenance: Mapping[str, Any],
) -> dict[str, Any]:
    """Write a signed incident bundle and return its manifest."""
    try:
        from cryptography.hazmat.primitives import serialization
        from agentcontain.attestation import Ed25519Signer
    except ImportError as exc:
        raise RuntimeError(
            "incident bundle signing requires: pip install 'warrantkit[attestation]'"
        ) from exc

    output_dir.mkdir(parents=True, exist_ok=True)

    records = {
        "authority-issued.json": dict(authority),
        "containment-event.json": dict(containment),
        "runtime-evidence.json": dict(runtime_evidence),
        "external-proof.json": dict(external_proof),
        "provenance.json": dict(provenance),
    }
    for name, value in records.items():
        _write_json(output_dir / name, value)

    signer = Ed25519Signer.generate(f"{incident_id}:demo-key")
    public_key = signer.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    public_key_record = {
        "schema_version": "warrantkit.incident-public-key/v1",
        "algorithm": "ed25519",
        "key_id": signer.key_id,
        "encoding": "base64",
        "public_key": base64.b64encode(public_key).decode("ascii"),
        "trust_note": (
            "Demo key generated for this bundle. An external verifier must "
            "supply an independently trusted deployment key for authenticity."
        ),
    }
    _write_json(output_dir / "public-key.json", public_key_record)

    files = {
        name: _sha256(output_dir / name)
        for name in (*records.keys(), "public-key.json")
    }
    manifest = {
        "schema_version": "warrantkit.incident-bundle/v1",
        "incident_id": incident_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "claims": {
            "authority_issued": True,
            "runtime_epoch_advanced": True,
            "external_containment_verified": True,
            "terminal_runtime_observed": True,
            "stale_authority_rejected": True,
            "evidence_independently_verified": True,
        },
        "files": files,
        "limitations": [
            "This bundle describes the captured proof and its evidence.",
            "The embedded demo public key is not an external trust anchor.",
            "Verified evidence does not establish that an agent claim is true.",
            "The proof does not establish universal host isolation or formal verification.",
        ],
    }
    _write_json(output_dir / "manifest.json", manifest)

    receipt = signer.sign_receipt(
        {
            "incident_id": incident_id,
            "manifest": manifest,
            "manifest_sha256": _sha256(output_dir / "manifest.json"),
        }
    )
    _write_json(output_dir / "verification-receipt.json", receipt.to_dict())

    return manifest


def verify_incident_bundle(
    bundle_dir: Path,
    *,
    trusted_public_key_b64: str | None = None,
) -> dict[str, Any]:
    """Verify bundle hashes and its signed receipt.

    If trusted_public_key_b64 is omitted, the embedded key is used only to
    verify internal integrity. For authenticity, pass an independently trusted
    public key.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from agentcontain.attestation import AttestationEnvelope, Ed25519Verifier
    except ImportError as exc:
        raise RuntimeError(
            "incident bundle verification requires: pip install 'warrantkit[attestation]'"
        ) from exc

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    key_record = json.loads((bundle_dir / "public-key.json").read_text(encoding="utf-8"))
    receipt = json.loads(
        (bundle_dir / "verification-receipt.json").read_text(encoding="utf-8")
    )

    for name, expected_digest in manifest["files"].items():
        actual = _sha256(bundle_dir / name)
        if actual != expected_digest:
            raise ValueError(f"bundle file digest mismatch: {name}")

    embedded = base64.b64decode(key_record["public_key"], validate=True)
    supplied = (
        base64.b64decode(trusted_public_key_b64, validate=True)
        if trusted_public_key_b64 is not None
        else embedded
    )
    if supplied != embedded:
        raise ValueError("trusted public key does not match bundle key")

    public_key = serialization.load_raw_public_key(
        supplied
    )
    payload = Ed25519Verifier({receipt["key_id"]: public_key}).verify(
        AttestationEnvelope.from_dict(receipt),
        expected_artifact_type="receipt",
    )
    if payload["manifest"] != manifest:
        raise ValueError("signed manifest does not match bundle manifest")
    if payload["manifest_sha256"] != _sha256(bundle_dir / "manifest.json"):
        raise ValueError("signed manifest digest mismatch")

    return {
        "status": "VERIFIED",
        "incident_id": manifest["incident_id"],
        "authenticity": "trusted-anchor" if trusted_public_key_b64 else "bundle-key-integrity-only",
    }
