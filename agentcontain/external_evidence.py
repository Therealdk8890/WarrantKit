"""Typed references to evidence owned by external platform components.

ExternalEvidenceReference deliberately carries identity and integrity metadata,
not authority. AgentContain may correlate or display these references, but
external evidence can never authorize execution or mutate runtime state.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re
from typing import Any, Mapping

SCHEMA_VERSION = "agentcontain.external-evidence/v1"

VALID_SOURCES = {
    "warden",
    "agentcontainment",
    "dprovenancekit",
    "claimproofkit",
    "evidentia",
}
VALID_RELATIONS = {
    "observed_during",
    "derived_from",
    "verifies",
    "attests",
    "supports",
    "contradicts",
}
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def digest_artifact(artifact: bytes) -> str:
    """Return the content digest for the exact external artifact bytes."""
    if not isinstance(artifact, bytes):
        raise TypeError("artifact must be bytes")
    return "sha256:" + hashlib.sha256(artifact).hexdigest()


@dataclass(frozen=True)
class ExternalEvidenceReference:
    """A validated, authority-neutral pointer to externally owned evidence."""

    source: str
    reference_id: str
    digest: str
    relation: str
    captured_at: str
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError(
                f"unsupported external evidence schema: {self.schema_version}"
            )
        if self.source not in VALID_SOURCES:
            raise ValueError(f"unsupported evidence source: {self.source}")
        if not self.reference_id.strip():
            raise ValueError("reference_id must not be empty")
        if not _SHA256_RE.fullmatch(self.digest):
            raise ValueError("digest must be a lowercase sha256:<64 hex> digest")
        if self.relation not in VALID_RELATIONS:
            raise ValueError(f"unsupported evidence relation: {self.relation}")
        if not self.captured_at.strip():
            raise ValueError("captured_at must not be empty")

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "source": self.source,
            "reference_id": self.reference_id,
            "digest": self.digest,
            "relation": self.relation,
            "captured_at": self.captured_at,
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "ExternalEvidenceReference":
        if not isinstance(document, Mapping):
            raise TypeError("external evidence reference must be a mapping")
        expected = {
            "schema_version",
            "source",
            "reference_id",
            "digest",
            "relation",
            "captured_at",
        }
        if set(document) != expected:
            raise ValueError("external evidence reference has an invalid shape")
        return cls(
            schema_version=str(document["schema_version"]),
            source=str(document["source"]),
            reference_id=str(document["reference_id"]),
            digest=str(document["digest"]),
            relation=str(document["relation"]),
            captured_at=str(document["captured_at"]),
        )


def verify_artifact_digest(
    artifact: bytes,
    reference: ExternalEvidenceReference,
) -> bool:
    """Check that exact artifact bytes match a reference's SHA-256 digest.

    This establishes content integrity relative to the supplied reference only.
    It does not authenticate who created the reference or prove the artifact's
    claims true; those require separate trust and verification procedures.
    """
    if not isinstance(artifact, bytes):
        raise TypeError("artifact must be bytes")
    if not isinstance(reference, ExternalEvidenceReference):
        raise TypeError("reference must be an ExternalEvidenceReference")
    return hmac.compare_digest(digest_artifact(artifact), reference.digest)
