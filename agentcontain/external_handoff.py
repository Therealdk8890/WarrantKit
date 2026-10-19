"""Transport-neutral external evidence handoff and correlation contract."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping
import re

from .external_evidence import VALID_SOURCES

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


SCHEMA_VERSION = "warrantkit.external-evidence/v1"


class CorrelationState(StrEnum):
    CORRELATED = "correlated"
    UNANCHORED = "unanchored"
    CONFLICT = "conflict"


@dataclass(frozen=True)
class ExternalEvidenceHandoff:
    """Bind an external artifact to one WarrantKit execution context.

    This record carries correlation and anchor metadata only. It does not
    authenticate the producer and does not promote external evidence into
    authority or verification.
    """

    execution_id: str
    warrant_id: str
    runtime_id: str
    epoch: int
    source: str
    artifact_ref: str
    artifact_digest: str
    anchor_ref: str | None = None
    anchor_digest: str | None = None
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        for name, value in (
            ("execution_id", self.execution_id),
            ("warrant_id", self.warrant_id),
            ("runtime_id", self.runtime_id),
            ("source", self.source),
            ("artifact_ref", self.artifact_ref),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
        if not isinstance(self.schema_version, str) or self.schema_version != SCHEMA_VERSION:
            raise ValueError(f"unsupported external evidence handoff schema: {self.schema_version}")
        if self.source not in VALID_SOURCES:
            raise ValueError(f"unsupported evidence source: {self.source}")
        if self.anchor_ref is not None and (
            not isinstance(self.anchor_ref, str) or not self.anchor_ref.strip()
        ):
            raise ValueError("anchor_ref must be None or a non-empty string")
        if isinstance(self.epoch, bool) or not isinstance(self.epoch, int) or self.epoch < 1:
            raise ValueError("epoch must be a positive integer")
        if not isinstance(self.artifact_digest, str) or not _SHA256_RE.fullmatch(self.artifact_digest):
            raise ValueError("artifact_digest must be a lowercase sha256:<64 hex> digest")
        if self.anchor_digest is not None:
            if not isinstance(self.anchor_digest, str) or not _SHA256_RE.fullmatch(self.anchor_digest):
                raise ValueError("anchor_digest must be a lowercase sha256:<64 hex> digest")
        if self.anchor_digest is not None and self.anchor_ref is None:
            raise ValueError("anchor_digest requires anchor_ref")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "execution_id": self.execution_id,
            "warrant_id": self.warrant_id,
            "runtime_id": self.runtime_id,
            "epoch": self.epoch,
            "source": self.source,
            "artifact_ref": self.artifact_ref,
            "artifact_digest": self.artifact_digest,
            "anchor_ref": self.anchor_ref,
            "anchor_digest": self.anchor_digest,
        }

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "ExternalEvidenceHandoff":
        if not isinstance(document, Mapping):
            raise TypeError("external evidence handoff must be a mapping")
        expected = {
            "schema_version",
            "execution_id",
            "warrant_id",
            "runtime_id",
            "epoch",
            "source",
            "artifact_ref",
            "artifact_digest",
            "anchor_ref",
            "anchor_digest",
        }
        if set(document) != expected:
            raise ValueError("external evidence handoff has an invalid shape")
        return cls(**{key: document[key] for key in expected})


@dataclass(frozen=True)
class HandoffCorrelation:
    state: CorrelationState
    reasons: tuple[str, ...] = ()

    @property
    def correlated(self) -> bool:
        return self.state == CorrelationState.CORRELATED

    @property
    def anchored(self) -> bool:
        return self.state == CorrelationState.CORRELATED


def correlate_handoff(
    handoff: ExternalEvidenceHandoff,
    *,
    execution_id: str,
    warrant_id: str,
    runtime_id: str,
    epoch: int,
) -> HandoffCorrelation:
    """Correlate a handoff to expected execution identity and optional anchor.

    A valid handoff is not considered verified. If an anchor is supplied,
    the artifact must match that anchored digest or the result is conflict.
    """

    if not isinstance(handoff, ExternalEvidenceHandoff):
        raise TypeError("handoff must be an ExternalEvidenceHandoff")

    mismatches = []
    for field, expected in (
        ("execution_id", execution_id),
        ("warrant_id", warrant_id),
        ("runtime_id", runtime_id),
        ("epoch", epoch),
    ):
        if getattr(handoff, field) != expected:
            mismatches.append(f"{field} mismatch")

    if mismatches:
        return HandoffCorrelation(CorrelationState.CONFLICT, tuple(mismatches))

    if handoff.anchor_digest is None:
        return HandoffCorrelation(
            CorrelationState.UNANCHORED,
            ("no external anchor supplied",),
        )

    if handoff.artifact_digest != handoff.anchor_digest:
        return HandoffCorrelation(
            CorrelationState.CONFLICT,
            ("artifact digest differs from anchored digest",),
        )

    return HandoffCorrelation(CorrelationState.CORRELATED)
