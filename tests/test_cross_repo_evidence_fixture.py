from __future__ import annotations

import json
from pathlib import Path

from agentcontain.evidence import EvidenceEnvelope
from agentcontain.external_evidence import ExternalEvidenceReference


FIXTURE = Path(__file__).parent / "fixtures" / "cross_repo_evidence_v1.json"


def _execution() -> dict[str, object]:
    return {
        "execution_id": "exec-cross-repo-1",
        "agent_id": "agent-1",
        "policy_id": "payments",
        "policy_digest": "policy-digest-1",
        "epoch": 1,
    }


def test_cross_repo_fixture_interoperability() -> None:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))

    references = tuple(
        ExternalEvidenceReference.from_dict(item)
        for item in document["references"]
    )

    assert {reference.source for reference in references} == {
        "warden",
        "agentcontainment",
        "dprovenancekit",
        "claimproofkit",
    }
    assert all(reference.digest.startswith("sha256:") for reference in references)

    envelope = EvidenceEnvelope.from_execution(
        execution=_execution(),
        events=(
            {
                "execution_id": "exec-cross-repo-1",
                "sequence": 1,
                "name": "containment_verified",
                "epoch": 1,
            },
        ),
        enforcement={"complete": True},
        verification={"status": "verified", "method": "cross-repo-fixture"},
        proof={"claims": ["containment"]},
        provenance={"producer": "agentcontain", "created_at": "2026-09-27T00:00:00Z"},
        external_evidence=references,
    )

    restored = EvidenceEnvelope.from_json(envelope.to_json())

    assert restored.external_evidence == references
    assert restored.to_json() == envelope.to_json()
    assert all(
        reference.relation
        in {"observed_during", "derived_from", "attests", "verifies"}
        for reference in restored.external_evidence
    )


def test_cross_repo_references_carry_no_runtime_authority() -> None:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))

    references = tuple(
        ExternalEvidenceReference.from_dict(item)
        for item in document["references"]
    )

    assert not any(reference.relation in {"authorizes", "releases", "extends_epoch"} for reference in references)
    assert not any(
        key in reference.to_dict()
        for reference in references
        for key in ("allow", "deny", "decision", "credential", "release")
    )
