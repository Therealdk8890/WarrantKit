"""Validation helpers for native ClaimProofKit/DProvenanceKit manifests.

A valid manifest establishes structural integrity and linkage only. It does not
establish that a claim is true or that a runtime was contained.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


class NativeProvenanceError(ValueError):
    """Raised when a native provenance manifest cannot be safely bound."""


def validate_native_provenance_manifest(
    manifest_json: str,
    *,
    incident_id: str,
    execution_id: str,
    runtime_id: str,
    epoch: int,
    expected_run_id: str,
    expected_context_id: str,
    expected_report_fingerprint: str,
    expected_policy_fingerprint: str,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate a ClaimProofKit-exported, DProvenanceKit-compatible manifest.

    The execution binding is an explicit adapter envelope supplied by the
    integration caller; the native trace schema does not itself define an
    incident/runtime identity contract. Fingerprints must come from the
    actual ClaimProofKit report/policy objects, not caller-supplied verdict
    strings. The optional SHA-256 is over the exact UTF-8 manifest bytes.
    """
    if not all(isinstance(value, str) and value for value in (
        incident_id, execution_id, runtime_id, expected_run_id,
        expected_context_id, expected_report_fingerprint,
        expected_policy_fingerprint,
    )):
        raise NativeProvenanceError("provenance binding fields must be non-empty strings")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise NativeProvenanceError("provenance binding epoch must be a non-negative integer")
    if not isinstance(manifest_json, str):
        raise NativeProvenanceError("native provenance manifest must be UTF-8 JSON text")

    raw = manifest_json.encode("utf-8")
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        raise NativeProvenanceError("native provenance manifest digest mismatch")
    try:
        manifest = json.loads(manifest_json)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise NativeProvenanceError("native provenance manifest is not valid JSON") from exc
    if not isinstance(manifest, dict):
        raise NativeProvenanceError("native provenance manifest must be a JSON object")

    required_strings = {
        "bridgeVersion": manifest.get("bridgeVersion"),
        "specVersion": manifest.get("specVersion"),
        "engineName": manifest.get("engineName"),
        "contextID": manifest.get("contextID"),
        "runFingerprint": manifest.get("runFingerprint"),
        "reportFingerprint": manifest.get("reportFingerprint"),
        "policyFingerprint": manifest.get("policyFingerprint"),
    }
    if any(not isinstance(value, str) or not value for value in required_strings.values()):
        raise NativeProvenanceError("native provenance manifest is missing version or fingerprint fields")
    if manifest["specVersion"] != "1.0":
        raise NativeProvenanceError("unsupported native provenance specification version")
    if manifest["engineName"] != "ClaimProofKit":
        raise NativeProvenanceError("native provenance engine is not ClaimProofKit")
    if manifest["contextID"] != expected_context_id:
        raise NativeProvenanceError("native provenance context does not match incident binding")
    if manifest["reportFingerprint"] != expected_report_fingerprint:
        raise NativeProvenanceError("ClaimProofKit report fingerprint mismatch")
    if manifest["policyFingerprint"] != expected_policy_fingerprint:
        raise NativeProvenanceError("ClaimProofKit policy fingerprint mismatch")

    events = manifest.get("events")
    edges = manifest.get("edges")
    if not isinstance(events, list) or not events:
        raise NativeProvenanceError("native provenance manifest must contain events")
    if not isinstance(edges, list):
        raise NativeProvenanceError("native provenance edges must be a list")
    event_ids: set[str] = set()
    run_ids: set[str] = set()
    event_contexts: set[str] = set()
    sequences: list[int] = []
    fingerprint = hashlib.sha1()
    for event in events:
        if not isinstance(event, dict):
            raise NativeProvenanceError("native provenance event must be an object")
        event_id, run_id = event.get("id"), event.get("runID")
        context_id, engine_name = event.get("contextID"), event.get("engineName")
        sequence, payload = event.get("sequence"), event.get("payload")
        if not all(isinstance(v, str) and v for v in (event_id, run_id, context_id, engine_name)):
            raise NativeProvenanceError("native provenance event identity is incomplete")
        if event_id in event_ids:
            raise NativeProvenanceError("duplicate native provenance event ID")
        event_ids.add(event_id)
        run_ids.add(run_id)
        event_contexts.add(context_id)
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            raise NativeProvenanceError("native provenance event sequence must be non-negative integer")
        sequences.append(sequence)
        if not isinstance(payload, dict):
            raise NativeProvenanceError("native provenance event payload is missing")
        type_identifier = payload.get("typeIdentifier")
        if not isinstance(type_identifier, str) or not type_identifier:
            raise NativeProvenanceError("native provenance event type identifier is missing")
        fingerprint.update(f"{type_identifier}:{engine_name}|".encode("utf-8"))
    if run_ids != {expected_run_id}:
        raise NativeProvenanceError("native provenance run ID does not match incident binding")
    if event_contexts != {expected_context_id}:
        raise NativeProvenanceError("native provenance event context mismatch")
    if sequences != list(range(len(events))):
        raise NativeProvenanceError("native provenance event sequence is not contiguous")
    if fingerprint.hexdigest() != manifest["runFingerprint"]:
        raise NativeProvenanceError("native provenance run fingerprint mismatch")

    for edge in edges:
        if not isinstance(edge, dict):
            raise NativeProvenanceError("native provenance edge must be an object")
        if edge.get("sourceID") not in event_ids or edge.get("targetID") not in event_ids:
            raise NativeProvenanceError("native provenance edge references an unknown event")

    # These values are returned as bindings for a containing signed bundle.
    # They are not assertions that the claims are true or containment occurred.
    return {
        "schema_version": manifest["specVersion"],
        "bridge_version": manifest["bridgeVersion"],
        "incident_id": incident_id,
        "execution_id": execution_id,
        "runtime_id": runtime_id,
        "epoch": epoch,
        "run_id": expected_run_id,
        "context_id": expected_context_id,
        "run_fingerprint": manifest["runFingerprint"],
        "report_fingerprint": manifest["reportFingerprint"],
        "policy_fingerprint": manifest["policyFingerprint"],
        "manifest_sha256": digest,
        "integrity": "validated",
        "claim_truth": "not_established",
        "runtime_enforcement": "not_established_by_provenance",
    }
