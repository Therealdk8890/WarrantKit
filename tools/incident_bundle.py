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
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


_RECORD_FILES = (
    "authority-issued.json",
    "containment-event.json",
    "runtime-evidence.json",
    "external-proof.json",
    "provenance.json",
)
_BUNDLE_FILES = {*_RECORD_FILES, "public-key.json"}


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


def _require_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object")
    return value


def _validate_evidence_contract(records: Mapping[str, Any], *, incident_id: str) -> None:
    """Validate minimum cross-record semantics, not just file hashes."""
    authority = _require_mapping(records.get("authority-issued.json"), "authority-issued.json")
    containment = _require_mapping(records.get("containment-event.json"), "containment-event.json")
    evidence = _require_mapping(records.get("runtime-evidence.json"), "runtime-evidence.json")
    external = _require_mapping(records.get("external-proof.json"), "external-proof.json")
    provenance = _require_mapping(records.get("provenance.json"), "provenance.json")

    execution = _require_mapping(evidence.get("execution"), "runtime evidence execution")
    events = evidence.get("events")
    if not isinstance(events, list) or not all(isinstance(event, dict) for event in events):
        raise ValueError("runtime evidence events must be a list of objects")

    execution_id = execution.get("execution_id")
    runtime_id = execution.get("runtime_id")
    agent_id = execution.get("agent_id")
    epoch = execution.get("epoch")
    if not all(isinstance(value, str) and value for value in (execution_id, runtime_id, agent_id)):
        raise ValueError("runtime evidence execution identity is incomplete")
    if not isinstance(epoch, int) or isinstance(epoch, bool):
        raise ValueError("runtime evidence epoch must be an integer")

    if not isinstance(incident_id, str) or not incident_id:
        raise ValueError("manifest incident_id must be a non-empty string")
    if containment.get("incident_id") != incident_id:
        raise ValueError("containment incident identity does not match bundle manifest")

    before = containment.get("epoch_before")
    after = containment.get("epoch_after")
    if not isinstance(before, int) or isinstance(before, bool) or not isinstance(after, int) or isinstance(after, bool):
        raise ValueError("containment epoch transition must use integer epochs")
    if before >= after or after != epoch:
        raise ValueError("containment epoch transition does not match runtime evidence epoch")
    if containment.get("operation") != "external_containment" or containment.get("external_verified") is not True:
        raise ValueError("containment record does not establish externally verified containment")
    for name, record in (("containment", containment), ("external proof", external)):
        if record.get("execution_id", execution_id) != execution_id:
            raise ValueError(f"{name} execution identity does not match runtime evidence")
        if record.get("runtime_id") != runtime_id or record.get("agent_id") != agent_id:
            raise ValueError(f"{name} runtime identity does not match runtime evidence")
    if containment.get("epoch_after") != epoch:
        raise ValueError("containment event epoch does not match runtime evidence")

    if external.get("epoch") != epoch:
        raise ValueError("external proof epoch does not match runtime evidence")
    if (
        external.get("runtime_state") != "TERMINATED"
        or external.get("can_execute") is not False
        or external.get("cgroup_populated") is not False
        or external.get("terminal_state_independently_observed") is not True
    ):
        raise ValueError("external proof does not establish an independently observed terminal state")
    exit_code = external.get("workload_exit_code")
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        raise ValueError("external proof workload exit code must be an integer")

    authority_runtime = _require_mapping(authority.get("runtime"), "authority runtime")
    if authority_runtime.get("epoch") != before:
        raise ValueError("issued authority epoch does not match containment's pre-transition epoch")

    sequences = [event.get("sequence") for event in events]
    if any(not isinstance(value, int) or isinstance(value, bool) for value in sequences):
        raise ValueError("runtime evidence event sequence values must be integers")
    if sequences != sorted(sequences) or len(set(sequences)) != len(sequences):
        raise ValueError("runtime evidence event sequence must be strictly increasing")
    for event_name in ("containment_verified", "stale_authority_rejected"):
        matching = [event for event in events if event.get("name") == event_name]
        if len(matching) != 1:
            raise ValueError(f"runtime evidence must contain exactly one {event_name} event")
    by_name = {event.get("name"): event for event in events}
    for event_name in ("containment_verified", "stale_authority_rejected"):
        event = by_name.get(event_name)
        if event is None:
            raise ValueError(f"runtime evidence is missing required event: {event_name}")
        if event.get("execution_id") != execution_id or event.get("epoch") != epoch:
            raise ValueError(f"runtime evidence event identity mismatch: {event_name}")
    stale = by_name["stale_authority_rejected"]
    details = _require_mapping(stale.get("details"), "stale-authority event details")
    warrant_epoch = details.get("warrant_epoch")
    if (
        not isinstance(warrant_epoch, int)
        or isinstance(warrant_epoch, bool)
        or warrant_epoch >= epoch
        or details.get("reason") != "runtime_epoch_mismatch"
    ):
        raise ValueError("stale-authority event does not prove rejection of an older runtime epoch")

    if provenance.get("execution_id") != execution_id:
        raise ValueError("provenance execution identity does not match runtime evidence")
    if provenance.get("runtime_verifier_result") != "VERIFIED":
        raise ValueError("provenance does not record successful runtime evidence verification")
    source_digest = provenance.get("runtime_evidence_sha256")
    if not isinstance(source_digest, str) or not source_digest:
        raise ValueError("provenance is missing the runtime evidence digest")
    if source_digest != "sha256:" + hashlib.sha256(
        (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode("utf-8")
    ).hexdigest():
        raise ValueError("provenance runtime evidence digest does not match bundled evidence")


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
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
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
    _validate_evidence_contract(records, incident_id=incident_id)
    for name, value in records.items():
        _write_json(output_dir / name, value)

    signing_key_file = os.environ.get("WARRANTKIT_INCIDENT_SIGNING_KEY_FILE")
    key_id = os.environ.get("WARRANTKIT_INCIDENT_SIGNING_KEY_ID", "incident-signing-key")
    if signing_key_file:
        private_key = serialization.load_pem_private_key(
            Path(signing_key_file).read_bytes(),
            password=None,
        )
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ValueError("incident signing key file must contain an Ed25519 private key")
        signer = Ed25519Signer(key_id, private_key)
        trust_note = "Signing key supplied by the deployment operator."
        key_source = "deployment-key"
    else:
        signer = Ed25519Signer.generate(f"{incident_id}:demo-key")
        trust_note = (
            "Demo key generated for this bundle. An external verifier must "
            "supply an independently trusted deployment key for authenticity."
        )
        key_source = "ephemeral-demo-key"

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
        "key_source": key_source,
        "trust_note": trust_note,
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
    """Verify bundle hashes, cross-record evidence semantics, and signed receipt.

    If trusted_public_key_b64 is omitted, the embedded key is used only to
    verify internal integrity. For authenticity, pass an independently trusted
    public key.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from agentcontain.attestation import AttestationEnvelope, Ed25519Verifier
    except ImportError as exc:
        raise RuntimeError(
            "incident bundle verification requires: pip install 'warrantkit[attestation]'"
        ) from exc

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "warrantkit.incident-bundle/v1":
        raise ValueError("unsupported or malformed incident bundle manifest")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != _BUNDLE_FILES:
        raise ValueError("incident bundle manifest must list the exact required files")

    records: dict[str, Any] = {}
    for name, expected_digest in files.items():
        path = bundle_dir / name
        if not path.is_file():
            raise ValueError(f"required bundle file is missing: {name}")
        if not isinstance(expected_digest, str) or _sha256(path) != expected_digest:
            raise ValueError(f"bundle file digest mismatch: {name}")
        if name in _RECORD_FILES:
            try:
                records[name] = json.loads(path.read_text(encoding="utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"bundle record is not valid JSON: {name}") from exc
    _validate_evidence_contract(records, incident_id=manifest.get("incident_id"))

    key_record = json.loads((bundle_dir / "public-key.json").read_text(encoding="utf-8"))
    receipt = json.loads(
        (bundle_dir / "verification-receipt.json").read_text(encoding="utf-8")
    )

    embedded = base64.b64decode(key_record["public_key"], validate=True)
    supplied = (
        base64.b64decode(trusted_public_key_b64, validate=True)
        if trusted_public_key_b64 is not None
        else embedded
    )
    if supplied != embedded:
        raise ValueError("trusted public key does not match bundle key")

    public_key = Ed25519PublicKey.from_public_bytes(supplied)
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
        "evidence_contract": "validated",
    }
