#!/usr/bin/env python3
"""Run a real ClaimProofKit verification and bind its artifacts in WarrantKit.

This is an offline, partial integration proof. It exercises ClaimProofKit's
published verifier and DProvenanceKit-compatible trace exporter, then verifies
the exact artifact bytes against WarrantKit references. It intentionally does
not claim that DProvenanceKit ingested the trace, that producers are
authenticated, or that a live AgentContainment runtime was contained.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any

from claimproofkit import (
    ClaimVerifier,
    EvidencePassage,
    ProvenanceExporter,
    SourceType,
    VerificationPolicy,
    report_fingerprint,
)
from claimproofkit.identity import SPEC_VERSION, VERIFIER_IDENTIFIER, VERIFIER_VERSION

from agentcontain import (
    ExternalEvidenceHandoff,
    ExternalEvidenceReference,
    compose_verification,
    correlate_handoff,
    digest_artifact,
    verify_artifact_digest,
)


EXECUTION_ID = "platform-proof-execution-001"
WARRANT_ID = "platform-proof-warrant-001"
RUNTIME_ID = "platform-proof-runtime-001"
EPOCH = 1


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def run(output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)

    document = "The court denied the request for an extension."
    evidence = [
        EvidencePassage(
            id="order-001",
            source="Illustrative Scheduling Order",
            source_type=SourceType.COURT_RECORD,
            text="The court denied the request for an extension.",
        )
    ]
    policy = VerificationPolicy()
    report = ClaimVerifier(policy).verify_document(document, evidence, created_at=0.0)
    trace = ProvenanceExporter().trace(report, policy)

    report_document = {
        "schema_version": "warrantkit.claimproofkit-report/v1",
        "producer": "claimproofkit",
        "spec_version": SPEC_VERSION,
        "verifier_identifier": VERIFIER_IDENTIFIER,
        "verifier_version": VERIFIER_VERSION,
        "report_fingerprint": report_fingerprint(report),
        "safe_to_publish": report.is_safe_to_publish,
        "verdicts": [
            {
                "claim_fingerprint": verdict.claim.fingerprint,
                "claim_text": verdict.claim.text,
                "status": verdict.status.value,
                "confidence": verdict.confidence,
                "evidence_ids": [match.passage.id for match in verdict.evidence],
                "evidence_fingerprints": [
                    hashlib.sha256(match.passage.text.encode("utf-8")).hexdigest()
                    for match in verdict.evidence
                ],
            }
            for verdict in report.verdicts
        ],
    }
    report_bytes = _canonical_json(report_document)
    trace_bytes = trace.manifest_json().encode("utf-8")

    report_path = output_dir / "claimproof-report.json"
    trace_path = output_dir / "claimproof-dpk-compatible-trace.json"
    report_path.write_bytes(report_bytes)
    trace_path.write_bytes(trace_bytes)

    captured_at = datetime.now(timezone.utc).isoformat()
    artifacts = [
        ("claimproofkit", f"claimproofkit:report:{report_document['report_fingerprint']}", "verifies", report_path, report_bytes),
        ("claimproofkit", f"claimproofkit:trace:{trace.run_fingerprint}", "derived_from", trace_path, trace_bytes),
    ]

    artifact_results: list[dict[str, Any]] = []
    for source, reference_id, relation, path, payload in artifacts:
        reference = ExternalEvidenceReference(
            source=source,
            reference_id=reference_id,
            digest=digest_artifact(payload),
            relation=relation,
            captured_at=captured_at,
        )
        handoff = ExternalEvidenceHandoff(
            execution_id=EXECUTION_ID,
            warrant_id=WARRANT_ID,
            runtime_id=RUNTIME_ID,
            epoch=EPOCH,
            source=source,
            artifact_ref=str(path.name),
            artifact_digest=reference.digest,
        )
        correlation = correlate_handoff(
            handoff,
            execution_id=EXECUTION_ID,
            warrant_id=WARRANT_ID,
            runtime_id=RUNTIME_ID,
            epoch=EPOCH,
        )
        artifact_results.append(
            {
                "path": path.name,
                "reference": reference.to_dict(),
                "handoff": handoff.to_dict(),
                "digest_matches_exact_bytes": verify_artifact_digest(payload, reference),
                "correlation_state": correlation.state.value,
                "correlation_reasons": list(correlation.reasons),
            }
        )

    # Deliberately incomplete: this demo has no independently provisioned
    # producer key, no live runtime proof, no Warden artifact, and no trusted
    # external anchor. Do not turn a successful local hash check into a
    # platform-wide VERIFIED result.
    result = compose_verification(
        authority_valid=False,
        runtime_valid=False,
        authenticated=False,
        correlated=False,
        anchored=False,
        verifier_executed=True,
        missing=(
            "independent producer authentication",
            "trusted external artifact anchor",
            "live AgentContainment runtime evidence",
            "Warden observation artifact",
            "independent DProvenanceKit ingestion/verification",
        ),
    )

    manifest = {
        "schema_version": "warrantkit.platform-proof/v1",
        "execution": {
            "execution_id": EXECUTION_ID,
            "warrant_id": WARRANT_ID,
            "runtime_id": RUNTIME_ID,
            "epoch": EPOCH,
            "synthetic_context": True,
        },
        "claimproofkit": {
            "safe_to_publish": report.is_safe_to_publish,
            "report_fingerprint": report_document["report_fingerprint"],
            "verifier_identifier": VERIFIER_IDENTIFIER,
            "verifier_version": VERIFIER_VERSION,
            "spec_version": SPEC_VERSION,
            "trace_run_fingerprint": trace.run_fingerprint,
            "trace_note": "ClaimProofKit exported a DProvenanceKit-compatible trace; this script does not claim DProvenanceKit ingested it.",
        },
        "artifacts": artifact_results,
        "platform_verification": result.to_dict(),
        "limitations": [
            "Execution, Warrant and runtime identifiers are synthetic demo identifiers.",
            "Digest matching proves byte integrity relative to the generated reference, not producer authenticity.",
            "The proof does not exercise live AgentContainment containment.",
            "The proof does not include Warden observation evidence.",
            "DProvenanceKit ingestion or independent verification is not performed by this script.",
        ],
    }
    manifest_path = output_dir / "platform-proof-manifest.json"
    manifest_path.write_bytes(_canonical_json(manifest))

    print(f"ClaimProofKit verifier executed: {'PASS' if report.is_safe_to_publish else 'BLOCKED'}")
    print(f"Exact artifact digest checks: {'PASS' if all(item['digest_matches_exact_bytes'] for item in artifact_results) else 'FAIL'}")
    print(f"ClaimProofKit trace exported: {trace_path}")
    print(f"WarrantKit platform status: {result.status.value.upper()} (expected: not yet fully authenticated)")
    print(f"Manifest: {manifest_path}")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("platform-proof-artifacts"),
        help="directory for the report, trace and manifest (default: ./platform-proof-artifacts)",
    )
    args = parser.parse_args()
    manifest = run(args.output)
    digest_checks_pass = all(item["digest_matches_exact_bytes"] for item in manifest["artifacts"])
    return 0 if manifest["claimproofkit"]["safe_to_publish"] and digest_checks_pass else 2


if __name__ == "__main__":
    raise SystemExit(main())
