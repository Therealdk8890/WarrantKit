"""Conservative restart reconciliation for missing downstream fence transitions.

The source MUST be an authenticated, durable AgentContainment incident record
or equivalent controller-authoritative recovery record. A live runtime
snapshot, cached report, or untrusted agent statement is not sufficient.

This reference never marks a transition verified. It reconstructs a pending
signed fence from independently validated authoritative evidence, then the
outbox must obtain a downstream receipt. It cannot prove the upstream source
is durable: that is a required integration responsibility.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from .downstream_commit_fence import DownstreamDenied
from .downstream_outbox import DurableTransitionOutbox, PendingDownstreamFence
from .downstream_transition_delivery import TransitionEnvelope


@dataclass(frozen=True)
class DurableFenceRecord:
    agent_id: str
    epoch: int
    state: str
    can_execute: bool
    record_id: str


class TrustedFenceRecordReader(Protocol):
    def __call__(self, agent_id: str) -> DurableFenceRecord: ...


def reconcile_missing_fence(
    *, agent_id: str, outbox: DurableTransitionOutbox,
    read_authoritative_record: TrustedFenceRecordReader,
    verify_authoritative_record: Callable[[DurableFenceRecord], bool],
    sign_transition: Callable[[str, int, bool], TransitionEnvelope],
) -> TransitionEnvelope:
    """Reconstruct a missing pending fence, never an acknowledgment.

    Fail closed if the durable source cannot be authenticated, is executable,
    or has an unexpected state/epoch. Signer must be controller-owned and must
    not accept records supplied by agents. A preexisting conflicting outbox
    entry is rejected by DurableTransitionOutbox.enqueue().
    """
    record = read_authoritative_record(agent_id)
    if (not isinstance(record, DurableFenceRecord)
            or record.agent_id != agent_id
            or not record.record_id
            or type(record.epoch) is not int or record.epoch < 1
            or record.state not in {"contained", "halted"}
            or record.can_execute is not False):
        raise DownstreamDenied("invalid authoritative fenced incident record")
    if verify_authoritative_record(record) is not True:
        raise DownstreamDenied("authoritative incident record not authenticated")
    envelope = sign_transition(record.agent_id, record.epoch, False)
    if (not isinstance(envelope, TransitionEnvelope)
            or envelope.agent_id != record.agent_id
            or type(envelope.epoch) is not int
            or envelope.epoch != record.epoch
            or envelope.active is not False):
        raise DownstreamDenied("signer returned a mismatched fence transition")
    outbox.enqueue(envelope)
    return envelope


def require_reconciled_downstream_fence(
    *, agent_id: str, epoch: int, outbox: DurableTransitionOutbox,
) -> None:
    """Never infer downstream success from an authoritative local record."""
    outbox.require_verified(agent_id, epoch)
