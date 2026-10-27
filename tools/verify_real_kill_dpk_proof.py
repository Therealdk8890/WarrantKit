#!/usr/bin/env python3
"""Verify a persisted real-kill DPK attestation and its bound artifacts."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _read_regular_file(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"cannot open proof artifact {path}: {exc}") from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"proof artifact is not a regular file: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(descriptor)


def _snapshot_directory(source: Path, destination: Path) -> dict[str, bytes]:
    if source.is_symlink() or not source.is_dir():
        raise ValueError(f"incident bundle directory is missing: {source}")
    snapshot: dict[str, bytes] = {}
    for item in sorted(source.iterdir(), key=lambda path: path.name):
        if item.is_symlink():
            raise ValueError(f"incident bundle contains a non-regular file: {item.name}")
        if item.name in snapshot:
            raise ValueError(f"duplicate incident bundle filename: {item.name}")
        data = _read_regular_file(item)
        snapshot[item.name] = data
        (destination / item.name).write_bytes(data)
    if "manifest.json" not in snapshot:
        raise ValueError("incident bundle manifest is missing")
    return snapshot


def _decode_bound_event(document: Any) -> dict[str, Any]:
    events = getattr(getattr(document, "trace", None), "events", None)
    if not isinstance(events, tuple) or not events:
        raise ValueError("DPK attestation trace has no events")
    matching = [event for event in events if getattr(event, "type_identifier", None) == "evidence_artifacts_bound"]
    if len(matching) != 1 or events[-1] is not matching[0]:
        raise ValueError("DPK trace must end with exactly one evidence_artifacts_bound event")
    try:
        payload = json.loads(matching[0].payload_json)
    except (AttributeError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("DPK evidence binding event payload is malformed") from exc
    if not isinstance(payload, dict):
        raise ValueError("DPK evidence binding event payload must be an object")
    for name in ("runtime_evidence_sha256", "incident_bundle_manifest_sha256"):
        if not isinstance(payload.get(name), str) or not _SHA256.fullmatch(payload[name]):
            raise ValueError(f"DPK evidence binding event has an invalid {name}")
    return payload


def verify_real_kill_dpk_proof(
    *,
    attestation_path: Path,
    runtime_evidence_path: Path,
    incident_bundle_dir: Path,
    trusted_key_id: str,
    trusted_incident_public_key_b64: str,
) -> dict[str, str]:
    """Verify signatures and all cross-artifact hashes against stable byte snapshots."""
    if not trusted_key_id:
        raise ValueError("trusted DPK key ID is required")
    try:
        trusted_public_key = base64.b64decode(trusted_incident_public_key_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("trusted incident public key is not valid base64") from exc
    if len(trusted_public_key) != 32:
        raise ValueError("trusted incident Ed25519 public key must be 32 bytes")

    for path, label in (
        (attestation_path, "DPK attestation"),
        (runtime_evidence_path, "runtime evidence"),
    ):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"{label} file is missing or not a regular file: {path}")

    # Each artifact is read once. Verifiers consume private snapshots of these
    # bytes, and the DPK binding is compared to the same immutable byte values.
    attestation_bytes = _read_regular_file(attestation_path)
    runtime_evidence_bytes = _read_regular_file(runtime_evidence_path)

    from dprovenancekit.attestation import TraceAttestationDocument

    try:
        document = TraceAttestationDocument.decode_json(attestation_bytes)
    except Exception as exc:
        raise ValueError(f"persisted DPK attestation is malformed: {exc}") from exc
    result = document.verify(trusted_key_ids=[trusted_key_id])
    if (
        not result.is_valid
        or getattr(result.trust, "value", None) != "trustedKey"
        or result.key_id != trusted_key_id
    ):
        failure = getattr(getattr(result, "failure", None), "value", None)
        raise ValueError(f"persisted DPK attestation did not verify with the trusted key: {failure}")

    bound = _decode_bound_event(document)
    if bound["runtime_evidence_sha256"] != _digest(runtime_evidence_bytes):
        raise ValueError("runtime evidence bytes do not match the DPK-signed digest")
    try:
        runtime_document = json.loads(runtime_evidence_bytes)
        execution = runtime_document["execution"]
    except (TypeError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError("runtime evidence is malformed") from exc
    if (
        not isinstance(execution, dict)
        or bound.get("execution_id") != execution.get("execution_id")
        or bound.get("runtime_id") != execution.get("runtime_id")
    ):
        raise ValueError("DPK evidence binding identity does not match runtime evidence")

    with tempfile.TemporaryDirectory(prefix="warrantkit-proof-verify-") as temp_name:
        temp_root = Path(temp_name)
        runtime_snapshot = temp_root / "runtime-evidence.json"
        runtime_snapshot.write_bytes(runtime_evidence_bytes)
        bundle_snapshot = temp_root / "incident-bundle"
        bundle_snapshot.mkdir()
        bundle_files = _snapshot_directory(incident_bundle_dir, bundle_snapshot)
        manifest_bytes = bundle_files["manifest.json"]
        if bound["incident_bundle_manifest_sha256"] != _digest(manifest_bytes):
            raise ValueError("incident manifest bytes do not match the DPK-signed digest")
        if bundle_files.get("runtime-evidence.json") != runtime_evidence_bytes:
            raise ValueError("incident bundle runtime evidence differs from the DPK-bound runtime evidence")

        runtime_verifier = Path(__file__).with_name("verify_runtime_evidence.py")
        runtime_result = subprocess.run(
            [sys.executable, str(runtime_verifier), str(runtime_snapshot)],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        runtime_status = runtime_result.stdout.strip()
        if runtime_result.returncode != 0 or runtime_status != "OBSERVED":
            raise ValueError(
                "runtime evidence verification failed: "
                + (runtime_result.stderr.strip() or runtime_status or "no verifier output")
            )

        from agentcontain.incident_bundle import verify_incident_bundle

        try:
            bundle_result = verify_incident_bundle(
                bundle_snapshot,
                trusted_public_key_b64=trusted_incident_public_key_b64,
            )
        except Exception as exc:
            raise ValueError(f"incident bundle verification failed: {exc}") from exc
        if (
            bundle_result.get("status") != "AUTHENTICATED"
            or bundle_result.get("authenticity") != "trusted-anchor"
        ):
            raise ValueError("incident bundle did not authenticate against the supplied trust anchor")

    return {
        "dpk_verification": "trustedKey",
        "runtime_evidence_verification": "OBSERVED",
        "incident_bundle_verification": "AUTHENTICATED: authenticity=trusted-anchor",
        "attestation_sha256": _digest(attestation_bytes),
        "runtime_evidence_sha256": _digest(runtime_evidence_bytes),
        "incident_bundle_manifest_sha256": _digest(manifest_bytes),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--runtime-evidence", type=Path, required=True)
    parser.add_argument("--incident-bundle", type=Path, required=True)
    parser.add_argument("--trusted-key-id", required=True)
    parser.add_argument("--trusted-public-key", required=True)
    args = parser.parse_args()
    try:
        result = verify_real_kill_dpk_proof(
            attestation_path=args.attestation,
            runtime_evidence_path=args.runtime_evidence,
            incident_bundle_dir=args.incident_bundle,
            trusted_key_id=args.trusted_key_id,
            trusted_incident_public_key_b64=args.trusted_public_key,
        )
    except Exception as exc:
        print(f"REJECTED: {exc}", file=sys.stderr)
        return 1
    print("VERIFIED: DPK signature and bound artifacts")
    print(f"runtime evidence: {result['runtime_evidence_sha256']}")
    print(f"incident manifest: {result['incident_bundle_manifest_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
