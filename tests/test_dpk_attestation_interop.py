"""Opt-in interoperability tests against a real DProvenanceKit Python attestation.

Set WARRANTKIT_DPK_ATTESTATION_EXPORT to an exported DPK attestation JSON file and
WARRANTKIT_DPK_TRUSTED_KEY_ID to the independently provisioned expected key ID.
The artifact's embedded public key is never treated as an independent trust anchor.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from agentcontain.external_evidence import (
    ExternalEvidenceReference,
    digest_artifact,
    verify_artifact_digest,
)


def _real_dpk_export() -> tuple[bytes, str, str]:
    export_path = os.environ.get("WARRANTKIT_DPK_ATTESTATION_EXPORT")
    trusted_key_id = os.environ.get("WARRANTKIT_DPK_TRUSTED_KEY_ID")
    if not export_path or not trusted_key_id:
        pytest.skip(
            "set WARRANTKIT_DPK_ATTESTATION_EXPORT and "
            "WARRANTKIT_DPK_TRUSTED_KEY_ID to verify a real DPK attestation"
        )
    path = Path(export_path)
    if not path.is_file():
        pytest.fail(f"DPK attestation export does not exist: {path}")
    return (
        path.read_bytes(),
        trusted_key_id,
        os.environ.get("WARRANTKIT_DPK_PROOF_ID", path.name),
    )


def _dpk_document():
    module = pytest.importorskip(
        "dprovenancekit.attestation",
        reason="install dprovenancekit[crypto] to run DPK interoperability tests",
    )
    return module.TraceAttestationDocument


def test_real_dpk_attestation_verifies_only_with_independent_trusted_key() -> None:
    artifact, trusted_key_id, proof_id = _real_dpk_export()
    TraceAttestationDocument = _dpk_document()
    document = TraceAttestationDocument.decode_json(artifact)

    reference = ExternalEvidenceReference(
        source="dprovenancekit",
        reference_id=proof_id,
        digest=digest_artifact(artifact),
        relation="attests",
        captured_at=os.environ.get("WARRANTKIT_DPK_CAPTURED_AT", "unknown"),
    )

    # Byte integrity is checked separately from DPK's own signature/trust result.
    assert verify_artifact_digest(artifact, reference)

    embedded_only = document.verify()
    assert embedded_only.is_valid
    assert embedded_only.trust.value == "embeddedKeyOnly"

    independently_trusted = document.verify(trusted_key_ids=[trusted_key_id])
    assert independently_trusted.is_valid
    assert independently_trusted.trust.value == "trustedKey"
    assert independently_trusted.key_id == trusted_key_id


def test_real_dpk_attestation_rejects_tampered_trace_and_changed_artifact_bytes() -> None:
    artifact, trusted_key_id, _proof_id = _real_dpk_export()
    TraceAttestationDocument = _dpk_document()

    changed_document = json.loads(artifact.decode("utf-8"))
    changed_document["trace"]["contextID"] = (
        str(changed_document["trace"]["contextID"]) + "-tampered"
    )
    mutated = json.dumps(
        changed_document, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")

    original_reference = ExternalEvidenceReference(
        source="dprovenancekit",
        reference_id="dpk-proof:tamper-check",
        digest=digest_artifact(artifact),
        relation="attests",
        captured_at="unknown",
    )
    assert mutated != artifact
    assert not verify_artifact_digest(mutated, original_reference)

    changed = TraceAttestationDocument.decode_json(mutated)
    result = changed.verify(trusted_key_ids=[trusted_key_id])
    assert not result.is_valid
