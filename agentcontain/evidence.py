"""Transport-neutral evidence envelope for AgentContain executions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from .external_evidence import ExternalEvidenceReference

SCHEMA_VERSION = "agentcontain.evidence/v2"
LEGACY_SCHEMA_VERSION = "agentcontain.evidence/v1"
VALID_STATUSES = {"observed", "verified", "degraded", "tampered", "incomplete"}


def canonical_json(value: Any) -> str:
    """Canonicalize evidence JSON for content hashing and transport.\n\nThis is the EvidenceEnvelope serialization profile. It is intentionally\nseparate from the Ed25519 attestation serialization profile in\n``attestation.py``; changing either profile can change security-relevant\ndigests or signatures.\n"""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def validate_runtime_pinned_binding(
    binding: Mapping[str, Any],
    execution: Mapping[str, Any],
) -> None:
    """Fail closed unless independent runtime records share one epoch."""
    import re
    from datetime import datetime

    if not isinstance(binding, Mapping):
        raise TypeError("runtime binding must be a mapping")
    required = {"schema_version", "runtime_id", "agent_id", "epoch", "authority", "enforcement", "observation"}
    if set(binding) != required:
        raise ValueError("runtime binding has an invalid shape")
    if binding["schema_version"] != "agentcontain.runtime-binding/v1":
        raise ValueError("unsupported runtime binding schema")
    if not isinstance(binding["runtime_id"], str) or not binding["runtime_id"].strip():
        raise ValueError("runtime binding runtime_id must not be empty")
    if binding["agent_id"] != execution["agent_id"]:
        raise ValueError("runtime binding agent_id does not match execution")
    expected_runtime_id = execution.get("runtime_id")
    if expected_runtime_id is not None and binding["runtime_id"] != expected_runtime_id:
        raise ValueError("runtime binding runtime_id does not match execution")
    if binding["epoch"] != execution["epoch"]:
        raise ValueError("runtime binding epoch does not match execution")
    if isinstance(binding["epoch"], bool) or not isinstance(binding["epoch"], int) or binding["epoch"] < 1:
        raise ValueError("runtime binding epoch must be a positive integer")

    authority, enforcement, observation = binding["authority"], binding["enforcement"], binding["observation"]
    if not all(isinstance(item, Mapping) for item in (authority, enforcement, observation)):
        raise TypeError("runtime binding authority, enforcement, and observation must be mappings")
    digest_re = re.compile(r"^sha256:[0-9a-f]{64}$")
    for label, item in (("authority", authority), ("enforcement", enforcement), ("observation", observation)):
        if not isinstance(item.get("digest"), str) or not digest_re.fullmatch(item["digest"]):
            raise ValueError(f"runtime binding {label} digest is invalid")
        payload = item.get("record")
        if not isinstance(payload, Mapping):
            raise ValueError(f"runtime binding {label} record is required")
        expected_digest = "sha256:" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        if item["digest"] != expected_digest:
            raise ValueError(f"runtime binding {label} digest does not match record")
        if payload.get("runtime_id") != binding["runtime_id"]:
            raise ValueError(f"runtime binding {label} runtime_id does not match")
        if payload.get("agent_id") != binding["agent_id"]:
            raise ValueError(f"runtime binding {label} agent_id does not match")
        if payload.get("epoch") != binding["epoch"]:
            raise ValueError(f"runtime binding {label} epoch does not match")
    authority_record = authority["record"]
    enforcement_record = enforcement["record"]
    observation_record = observation["record"]

    # Convenience fields are untrusted transport metadata. Check their
    # security semantics before canonical-record consistency so a self-claim
    # or impossible ordering cannot be hidden behind a generic mismatch.
    if enforcement.get("external_boundary") is False:
        raise ValueError("runtime binding enforcement must be external to the agent")
    observed_at = observation.get("observed_at")
    occurred_at = enforcement_record.get("occurred_at")
    if isinstance(observed_at, str) and isinstance(occurred_at, str):
        try:
            observed_time = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
            occurred_time = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
        except ValueError:
            observed_time = occurred_time = None
        if observed_time is not None and occurred_time is not None and observed_time < occurred_time:
            raise ValueError("runtime binding observation predates enforcement")

    for label, item, record, fields in (
        ("authority", authority, authority_record, ("revoked", "revoked_at")),
        ("enforcement", enforcement, enforcement_record, ("action", "external_boundary", "occurred_at")),
        ("observation", observation, observation_record, ("state", "observed_at")),
    ):
        for field in fields:
            if field in item and item[field] != record.get(field):
                raise ValueError(f"runtime binding {label} {field} does not match record")
    if authority_record.get("revoked") is not True:
        raise ValueError("runtime binding requires explicit authority revocation evidence")
    if enforcement_record.get("action") not in {"KILL", "FENCE"}:
        raise ValueError("runtime binding enforcement action must be KILL or FENCE")
    if enforcement_record.get("external_boundary") is not True:
        raise ValueError("runtime binding enforcement must be external to the agent")
    if observation_record.get("state") not in {"TERMINATED", "FENCED", "contained", "halted"}:
        raise ValueError("runtime binding observation state must be TERMINATED, FENCED, contained, or halted")

    def _timestamp(label: str, value: Any):
        if isinstance(value, bool):
            raise ValueError(f"runtime binding {label} timestamp is invalid")
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError(f"runtime binding {label} timestamp is not ISO-8601") from exc
        raise ValueError(f"runtime binding {label} timestamp is required")

    times = [
        _timestamp("authority revoked_at", authority_record.get("revoked_at")),
        _timestamp("enforcement occurred_at", enforcement_record.get("occurred_at")),
        _timestamp("observation observed_at", observation_record.get("observed_at")),
    ]
    # Runtime observation currently exports epoch time as a numeric value,
    # while authority/enforcement records use ISO-8601 strings. Convert only
    # for ordering; the canonical record retains its producer-native value.
    def _seconds(value):
        return value.timestamp() if isinstance(value, datetime) else value

    seconds = [_seconds(value) for value in times]
    if seconds[1] < seconds[0]:
        raise ValueError("runtime binding enforcement predates authority revocation")
    if seconds[2] < seconds[1]:
        raise ValueError("runtime binding observation predates enforcement")


@dataclass(frozen=True)
class EvidenceEnvelope:
    """Machine-readable evidence for one AgentContain execution."""

    execution: Mapping[str, Any]
    events: tuple[Mapping[str, Any], ...] = ()
    enforcement: Mapping[str, Any] = None  # type: ignore[assignment]
    verification: Mapping[str, Any] = None  # type: ignore[assignment]
    proof: Mapping[str, Any] = None  # type: ignore[assignment]
    receipt: Mapping[str, Any] | None = None
    governance: Mapping[str, Any] | None = None
    provenance: Mapping[str, Any] = None  # type: ignore[assignment]
    external_evidence: tuple[ExternalEvidenceReference, ...] = ()
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version not in {SCHEMA_VERSION, LEGACY_SCHEMA_VERSION}:
            raise ValueError(f"unsupported evidence schema: {self.schema_version}")
        for name in ("execution", "enforcement", "verification", "proof", "provenance"):
            value = getattr(self, name)
            if not isinstance(value, Mapping):
                raise TypeError(f"{name} must be a mapping")
        if not isinstance(self.events, tuple):
            object.__setattr__(self, "events", tuple(self.events))
        if any(not isinstance(event, Mapping) for event in self.events):
            raise TypeError("events must contain mappings")
        if not isinstance(self.external_evidence, tuple):
            object.__setattr__(
                self,
                "external_evidence",
                tuple(self.external_evidence),
            )
        if any(not isinstance(item, ExternalEvidenceReference) for item in self.external_evidence):
            raise TypeError("external_evidence must contain ExternalEvidenceReference values")
        self.validate()

    @classmethod
    def from_execution(
        cls,
        *,
        execution: Mapping[str, Any],
        events: tuple[Mapping[str, Any], ...] = (),
        enforcement: Mapping[str, Any] | None = None,
        verification: Mapping[str, Any] | None = None,
        proof: Mapping[str, Any] | None = None,
        receipt: Mapping[str, Any] | None = None,
        governance: Mapping[str, Any] | None = None,
        provenance: Mapping[str, Any] | None = None,
        external_evidence: tuple[ExternalEvidenceReference, ...] = (),
    ) -> "EvidenceEnvelope":
        return cls(
            execution=dict(execution),
            events=tuple(dict(event) for event in events),
            enforcement=dict(enforcement or {}),
            verification=dict(verification or {}),
            proof=dict(proof or {}),
            receipt=dict(receipt) if receipt is not None else None,
            governance=dict(governance) if governance is not None else None,
            provenance=dict(provenance or {"producer": "agentcontain"}),
            external_evidence=tuple(external_evidence),
        )

    def with_external_evidence(
        self,
        reference: ExternalEvidenceReference,
    ) -> "EvidenceEnvelope":
        """Return a copy with one additional external evidence reference."""
        if not isinstance(reference, ExternalEvidenceReference):
            raise TypeError("reference must be an ExternalEvidenceReference")
        return EvidenceEnvelope(
            execution=self.execution,
            events=self.events,
            enforcement=self.enforcement,
            verification=self.verification,
            proof=self.proof,
            receipt=self.receipt,
            governance=self.governance,
            provenance=self.provenance,
            external_evidence=self.external_evidence + (reference,),
            schema_version=SCHEMA_VERSION,
        )

    def with_receipt(self, receipt: Mapping[str, Any]) -> "EvidenceEnvelope":
        """Return a copy bound to an existing authenticated receipt.

        The receipt is treated as an opaque transport-neutral mapping. Its
        payload identity must agree with this envelope when the corresponding
        fields are present. Cryptographic verification remains the
        responsibility of the existing receipt verifier.
        """
        if not isinstance(receipt, Mapping):
            raise TypeError("receipt must be a mapping")
        required = {"payload", "digest", "signature"}
        if set(receipt) != required:
            raise ValueError("receipt has an invalid envelope")
        payload = receipt["payload"]
        if not isinstance(payload, Mapping):
            raise TypeError("receipt payload must be a mapping")

        for field in ("execution_id", "agent_id", "policy_id", "epoch"):
            receipt_value = payload.get(field)
            if receipt_value is not None and receipt_value != self.execution[field]:
                raise ValueError(f"receipt {field} does not match evidence execution")

        receipt_id = payload.get("receipt_id")
        if receipt_id is not None and not isinstance(receipt_id, str):
            raise ValueError("receipt receipt_id must be a string")

        return EvidenceEnvelope(
            execution=self.execution,
            events=self.events,
            enforcement=self.enforcement,
            verification=self.verification,
            proof=self.proof,
            receipt=dict(receipt),
            governance=self.governance,
            provenance=self.provenance,
            external_evidence=self.external_evidence,
            schema_version=SCHEMA_VERSION,
        )

    def with_runtime_pinned_evidence(
        self,
        binding: Mapping[str, Any],
    ) -> "EvidenceEnvelope":
        """Bind independent runtime evidence to this exact execution epoch.

        This does not manufacture host proof. The binding must carry digests
        produced by the authority, enforcement, and observation boundaries.
        WarrantKit only validates that those independently produced records
        refer to the same runtime, agent, epoch, and ordered enforcement path.
        """
        validate_runtime_pinned_binding(binding, self.execution)
        proof = dict(self.proof)
        proof["runtime_binding"] = dict(binding)
        verification = dict(self.verification)
        verification.update({
            "status": "verified",
            "method": "runtime-pinned-second-evidence",
            "scope": "external-runtime-enforcement",\n            "verification_semantics": (\n                "verified means the defined runtime-pinning checks passed; " \n                "it does not establish the truth of unrelated claims"\n            ),
        })
        return EvidenceEnvelope(
            execution=self.execution,
            events=self.events,
            enforcement=self.enforcement,
            verification=verification,
            proof=proof,
            receipt=self.receipt,
            governance=self.governance,
            provenance=self.provenance,
            external_evidence=self.external_evidence,
            schema_version=SCHEMA_VERSION,
        )


    def validate(self) -> None:
        required = {"execution_id", "agent_id", "policy_id", "policy_digest", "epoch"}
        missing = required - set(self.execution)
        if missing:
            raise ValueError("execution identity missing fields: " + ", ".join(sorted(missing)))

        status = self.verification.get("status")
        if status is not None and status not in VALID_STATUSES:
            raise ValueError(f"invalid verification status: {status}")

        execution_id = self.execution["execution_id"]
        execution_epoch = self.execution["epoch"]
        sequences: list[int] = []
        for event in self.events:
            if event.get("execution_id") != execution_id:
                raise ValueError("event execution_id does not match envelope")
            if "epoch" in event and event.get("epoch") != execution_epoch:
                raise ValueError("event epoch does not match envelope execution")
            sequence = event.get("sequence")
            if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
                raise ValueError("event sequence must be a positive integer")
            sequences.append(sequence)

        if sequences and sequences != list(range(1, len(sequences) + 1)):
            raise ValueError("event sequence must be contiguous starting at 1")

        runtime_binding = self.proof.get("runtime_binding")
        if runtime_binding is not None:
            validate_runtime_pinned_binding(runtime_binding, self.execution)
        if status == "verified" and not self.events:
            raise ValueError("verified evidence requires at least one event")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "execution": dict(self.execution),
            "events": [dict(event) for event in self.events],
            "enforcement": dict(self.enforcement),
            "verification": dict(self.verification),
            "proof": dict(self.proof),
            "receipt": dict(self.receipt) if self.receipt is not None else None,
            "governance": dict(self.governance) if self.governance is not None else None,
            "provenance": dict(self.provenance),
            "external_evidence": [item.to_dict() for item in self.external_evidence],
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> "EvidenceEnvelope":
        if not isinstance(document, Mapping):
            raise TypeError("evidence envelope must be a mapping")

        base_expected = {
            "schema_version",
            "execution",
            "events",
            "enforcement",
            "verification",
            "proof",
            "receipt",
            "governance",
            "provenance",
        }
        expected_v2 = base_expected | {"external_evidence"}
        keys = set(document)
        if keys == base_expected:
            if document["schema_version"] != LEGACY_SCHEMA_VERSION:
                raise ValueError("evidence envelope has an invalid shape")
            external_evidence: tuple[ExternalEvidenceReference, ...] = ()
        elif keys == expected_v2:
            if document["schema_version"] != SCHEMA_VERSION:
                raise ValueError("evidence envelope has an invalid shape")
            raw_refs = document["external_evidence"]
            if not isinstance(raw_refs, list):
                raise TypeError("external_evidence must be a list")
            external_evidence = tuple(
                ExternalEvidenceReference.from_dict(item) for item in raw_refs
            )
        else:
            raise ValueError("evidence envelope has an invalid shape")

        if not isinstance(document["events"], list):
            raise TypeError("events must be a list")
        return cls(
            execution=dict(document["execution"]),
            events=tuple(dict(event) for event in document["events"]),
            enforcement=dict(document["enforcement"]),
            verification=dict(document["verification"]),
            proof=dict(document["proof"]),
            receipt=dict(document["receipt"]) if document["receipt"] is not None else None,
            governance=dict(document["governance"]) if document["governance"] is not None else None,
            provenance=dict(document["provenance"]),
            external_evidence=external_evidence,
            schema_version=document["schema_version"],
        )

    @classmethod
    def from_json(cls, document: str) -> "EvidenceEnvelope":
        return cls.from_dict(json.loads(document))

    @property
    def receipt_id(self) -> str | None:
        if self.receipt is None:
            return None
        value = self.receipt.get("payload", {}).get("receipt_id")
        return value if isinstance(value, str) else None
