"""Read-only operator projections for incidents and evidence.

This module composes existing identity, fleet, policy, lifecycle, and evidence
primitives into an operator-facing view. It never authorizes, enforces, or
mutates runtime state.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .evidence import EvidenceEnvelope
from .external_evidence import ExternalEvidenceReference
from .fleet import FleetRegistry
from .incident import IncidentSummary
from .identity import ExecutionIdentity
from .policy_assignment import PolicyAssignmentRegistry
from .verification_result import VerificationResult


@dataclass(frozen=True)
class EvidenceTimelineEvent:
    """One evidence event projected for an operator timeline."""

    sequence: int
    name: str
    timestamp: str
    epoch: int
    details: Mapping[str, str]

    def to_dict(self) -> dict[str, object]:
        return {
            "sequence": self.sequence,
            "name": self.name,
            "timestamp": self.timestamp,
            "epoch": self.epoch,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class OperatorIncidentView:
    """Operator-facing Agent → Policy → Incident → Evidence view.

    External evidence is projected as typed references only. The view is
    deliberately read-only; AgentContainment and the platform lifecycle remain
    authoritative for runtime decisions.
    """

    incident: IncidentSummary
    agent: Mapping[str, str]
    governance: Mapping[str, str] | None
    policy: Mapping[str, object]
    evidence: EvidenceEnvelope
    verification_result: VerificationResult | None
    timeline: tuple[EvidenceTimelineEvent, ...]
    external_evidence: tuple[ExternalEvidenceReference, ...]
    receipt_id: str | None

    @classmethod
    def from_evidence(
        cls,
        envelope: EvidenceEnvelope,
        *,
        fleet: FleetRegistry | None = None,
        assignments: PolicyAssignmentRegistry | None = None,
        verification_result: VerificationResult | None = None,
    ) -> "OperatorIncidentView":
        execution = envelope.execution
        identity = ExecutionIdentity(
            execution_id=str(execution["execution_id"]),
            agent_id=str(execution["agent_id"]),
            policy_id=str(execution["policy_id"]),
            policy_digest=str(execution["policy_digest"]),
            epoch=int(execution["epoch"]),
        )

        events = tuple(
            _event_from_mapping(event, identity.execution_id)
            for event in envelope.events
        )
        proof_status = str(envelope.verification.get("status", "observed"))
        incident = IncidentSummary.from_execution(
            identity, events, proof_status=proof_status, verification_result=verification_result
        )

        governance = (
            dict(envelope.governance)
            if envelope.governance is not None
            else None
        )
        agent: dict[str, str] = {"agent_id": identity.agent_id}
        if fleet is not None:
            registered = fleet.agents.get(identity.agent_id)
            if registered is not None:
                agent["name"] = registered.name
                agent["runtime_id"] = registered.runtime_id
            if governance is None:
                governance = fleet.governance_for_agent(identity.agent_id)

        policy: dict[str, object] = {
            "policy_id": identity.policy_id,
            "policy_digest": identity.policy_digest,
            "epoch": identity.epoch,
        }
        if assignments is not None:
            assignment = next(
                (
                    item
                    for item in assignments.all()
                    if item.target_id == identity.agent_id
                    and item.policy_id == identity.policy_id
                    and item.policy_digest == identity.policy_digest
                ),
                None,
            )
            if assignment is not None:
                policy.update(
                    {
                        "assignment_id": assignment.assignment_id,
                        "policy_version": assignment.policy_version,
                        "assignment_state": assignment.state.value,
                    }
                )

        timeline = tuple(
            EvidenceTimelineEvent(
                sequence=event.sequence,
                name=event.name,
                timestamp=event.timestamp,
                epoch=event.epoch,
                details=event.details,
            )
            for event in events
        )
        return cls(
            incident=incident,
            agent=agent,
            governance=governance,
            policy=policy,
            evidence=envelope,
            verification_result=verification_result,
            timeline=timeline,
            external_evidence=envelope.external_evidence,
            receipt_id=envelope.receipt_id,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "agent": dict(self.agent),
            "governance": dict(self.governance) if self.governance is not None else None,
            "policy": dict(self.policy),
            "incident": self.incident.to_dict(),
            "evidence": self.evidence.to_dict(),
            "verification_result": (
                self.verification_result.to_dict()
                if self.verification_result is not None
                else None
            ),
            "timeline": [event.to_dict() for event in self.timeline],
            "external_evidence": [
                reference.to_dict() for reference in self.external_evidence
            ],
            "receipt_id": self.receipt_id,
        }


def _event_from_mapping(
    event: Mapping[str, object], execution_id: str
):
    """Reconstruct an Event through its existing validation path."""
    from .events import Event

    required = ("name", "execution_id", "epoch", "sequence", "timestamp", "details")
    missing = [field for field in required if field not in event]
    if missing:
        raise ValueError("evidence event missing fields: " + ", ".join(missing))
    if event["execution_id"] != execution_id:
        raise ValueError("evidence event execution_id does not match execution")
    details = event["details"]
    if not isinstance(details, Mapping):
        raise TypeError("evidence event details must be a mapping")
    return Event(
        name=str(event["name"]),
        execution_id=execution_id,
        epoch=int(event["epoch"]),
        sequence=int(event["sequence"]),
        timestamp=str(event["timestamp"]),
        details={str(key): str(value) for key, value in details.items()},
    )
