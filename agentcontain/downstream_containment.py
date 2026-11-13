"""Explicit orchestration of local containment and downstream acknowledgment.

Never modify or reinterpret the underlying AgentContainment report. The
combined result is only successful after a signed downstream receipt.
"""
from dataclasses import dataclass

from .downstream_transition_delivery import (
    TransitionEnvelope, TransitionReceipt, VerifiedTransitionDelivery
)


@dataclass(frozen=True)
class CombinedContainmentEvidence:
    local_report: object
    downstream_receipt: TransitionReceipt
    downstream_verified: bool = True


class DownstreamContainmentUnverified(RuntimeError):
    """Local containment may have succeeded, but remote fence is unverified."""

    def __init__(self, local_report: object, reason: Exception):
        self.local_report = local_report
        self.downstream_verified = False
        super().__init__(f"downstream containment not verified: {reason}")


def contain_with_downstream_ack(admission, *, delivery: VerifiedTransitionDelivery,
                                envelope_factory) -> CombinedContainmentEvidence:
    """Contain locally, then demand an authenticated remote fence receipt.

    The factory receives (agent_id, fenced_epoch) and must be a trusted
    controller-only signer. An unverified remote result raises an exception
    carrying the original local report; it is NEVER marked remotely complete.
    This is a synchronous reference, not a durable retry/outbox integration.
    """
    from .engine import contain

    local_report = contain(admission)
    if getattr(local_report, "complete", None) is not True:
        raise DownstreamContainmentUnverified(
            local_report, RuntimeError("local containment was not complete")
        )
    try:
        epoch = admission.identity.epoch
        envelope: TransitionEnvelope = envelope_factory(admission.identity.agent_id, epoch)
        if (not isinstance(envelope, TransitionEnvelope)
                or envelope.agent_id != admission.identity.agent_id
                or type(envelope.epoch) is not int or envelope.epoch != epoch
                or envelope.active is not False):
            raise ValueError("controller envelope does not match fenced runtime")
        receipt = delivery.deliver(envelope)
    except Exception as exc:
        raise DownstreamContainmentUnverified(local_report, exc) from exc
    return CombinedContainmentEvidence(local_report, receipt)
