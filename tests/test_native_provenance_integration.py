from __future__ import annotations

import uuid

from claimproofkit import (
    Claim,
    ClaimType,
    ClaimVerifier,
    EvidencePassage,
    ProvenanceExporter,
    SourceType,
    VerificationPolicy,
)

from agentcontain.incident_bundle import verify_incident_bundle, write_incident_bundle
from test_incident_bundle import _valid_records


def test_actual_claimproofkit_api_manifest_round_trips_through_signed_bundle(tmp_path):
    """Exercise real ClaimProofKit report/export APIs, not a hand-built manifest."""
    policy = VerificationPolicy()
    claim = Claim(
        id="claim-1",
        text="The runtime was contained at epoch five.",
        type=ClaimType.FACTUAL,
    )
    evidence = EvidencePassage(
        id="evidence-1",
        source="integration-test",
        text="The runtime was contained at epoch five.",
        source_type=SourceType.EVIDENCE,
    )
    report = ClaimVerifier(policy).verify_claims(
        [claim], [evidence], created_at=1_700_000_000.0
    )
    assert report.is_safe_to_publish

    run_id = uuid.UUID("00000000-0000-0000-0000-000000000168")
    trace = ProvenanceExporter(context_id="claimproof").trace(
        report, policy, run_id=run_id
    )
    records = _valid_records()
    bundle = tmp_path / "claimproofkit-api-incident"

    write_incident_bundle(
        bundle,
        incident_id=records["incident_id"],
        authority=records["authority"],
        containment=records["containment"],
        runtime_evidence=records["runtime_evidence"],
        external_proof=records["external_proof"],
        provenance=records["provenance"],
        native_provenance={
            "manifest_json": trace.manifest_json(),
            "run_id": str(run_id).upper(),
            "context_id": trace.context_id,
            "report_fingerprint": trace.report_fingerprint,
            "policy_fingerprint": trace.policy_fingerprint,
        },
    )

    result = verify_incident_bundle(bundle)
    assert result["native_provenance"]["integrity"] == "validated"
    assert result["native_provenance"]["claim_verification"] == "SUPPORTED"
    assert result["native_provenance"]["claim_truth"] == "not_established"
    assert (
        result["native_provenance"]["runtime_enforcement"]
        == "not_established_by_provenance"
    )
