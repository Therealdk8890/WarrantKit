"""Buyer-facing incident projection derived from execution evidence.

Incident summaries are operational views, not a second enforcement authority.
The execution lifecycle and AgentContainment runtime remain authoritative.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from .events import Event
from .identity import ExecutionIdentity
from .verification_result import VerificationResult


class IncidentStatus(StrEnum):
    OPEN = "open"
    CONTAINED = "contained"
    VERIFIED = "verified"
    RECOVERY_PENDING = "recovery_pending"
    RECOVERED = "recovered"


@dataclass(frozen=True)
class IncidentSummary:
    """Stable operator-facing summary of one security-relevant execution."""

    incident_id: str
    execution_id: str
    agent_id: str
    policy_id: str
    policy_digest: str
    epoch: int
    status: IncidentStatus
    trigger: str
    latest_event: str
    event_count: int
    proof_status: str

    @classmethod
    def from_execution(
        cls,
        identity: ExecutionIdentity,
        events: tuple[Event, ...],
        *,
        proof_status: str = "observed",
        verification_result: VerificationResult | None = None,
    ) -> "IncidentSummary":
        if not events:
            raise ValueError("incident requires at least one execution event")

        trigger = next(
            (
                event.name
                for event in events
                if event.name in {"anomaly_detected", "policy_violation", "unauthorized_action"}
            ),
            events[-1].name,
        )

        names = {event.name for event in events}
        if "runtime_recovery_complete" in names:
            status = IncidentStatus.RECOVERED
        elif "recovery_requested" in names:
            status = IncidentStatus.RECOVERY_PENDING
        elif verification_result is not None and verification_result.is_verified:
            status = IncidentStatus.VERIFIED
        elif "containment_verified" in names or "recontainment_verified" in names:
            status = IncidentStatus.CONTAINED
        else:
            status = IncidentStatus.OPEN

        return cls(
            incident_id=f"incident-{identity.execution_id}",
            execution_id=identity.execution_id,
            agent_id=identity.agent_id,
            policy_id=identity.policy_id,
            policy_digest=identity.policy_digest,
            epoch=identity.epoch,
            status=status,
            trigger=trigger,
            latest_event=events[-1].name,
            event_count=len(events),
            proof_status=proof_status,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "incident_id": self.incident_id,
            "execution_id": self.execution_id,
            "agent_id": self.agent_id,
            "policy_id": self.policy_id,
            "policy_digest": self.policy_digest,
            "epoch": self.epoch,
            "status": self.status.value,
            "trigger": self.trigger,
            "latest_event": self.latest_event,
            "event_count": self.event_count,
            "proof_status": self.proof_status,
        }
