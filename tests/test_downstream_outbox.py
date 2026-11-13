"""Restart-safe outbox and missing-ack regression tests."""
from dataclasses import replace

import pytest

from agentcontain.downstream_commit_fence import DownstreamCommitFence, DownstreamDenied
from agentcontain.downstream_transition_delivery import (
    DownstreamTransitionEndpoint, TransitionReceiptVerifier, new_transition_envelope,
)
from agentcontain.downstream_outbox import DurableTransitionOutbox, PendingDownstreamFence


@pytest.fixture
def components(tmp_path):
    fence = DownstreamCommitFence(
        tmp_path / "downstream.db",
        controller_key=b"controller-secret-for-outbox-tests-0001",
        gateway_key=b"gateway-secret-for-outbox-tests-000002",
    )
    receipt_key = b"receipt-secret-for-outbox-tests-000002"
    endpoint = DownstreamTransitionEndpoint(fence, receipt_key=receipt_key)
    verifier = TransitionReceiptVerifier(receipt_key)
    outbox_path = tmp_path / "controller-outbox.db"
    outbox = DurableTransitionOutbox(outbox_path, verifier=verifier)
    return fence, endpoint, verifier, outbox, outbox_path


def transition(fence, epoch, active):
    return new_transition_envelope(fence, agent_id="agent", epoch=epoch, active=active)


def test_restart_replays_lost_ack_without_duplicating_transition(components):
    fence, endpoint, verifier, outbox, path = components
    initial = transition(fence, 0, True)
    fenced = transition(fence, 1, False)
    outbox.enqueue(initial)
    outbox.enqueue(fenced)
    with pytest.raises(PendingDownstreamFence):
        outbox.require_verified("agent", 1)

    def lost_ack(envelope):
        endpoint.apply(envelope)
        raise ConnectionError("acknowledgment lost after remote commit")

    with pytest.raises(ConnectionError, match="lost"):
        outbox.deliver_pending("agent", lost_ack)
    assert len(outbox.pending("agent")) == 2

    # Controller restarts; reconstruct from persisted DB and trusted verifier.
    restarted = DurableTransitionOutbox(path, verifier=verifier)
    assert restarted.deliver_pending("agent", endpoint.apply) == 2
    assert restarted.pending("agent") == []
    restarted.require_verified("agent", 1)
    with pytest.raises(DownstreamDenied, match="fenced"):
        fence.commit(fence.sign_operation(
            agent_id="agent", epoch=0, operation_id="late", value="denied"))


def test_offline_downstream_keeps_fence_pending_and_remote_epoch_live(components):
    fence, endpoint, verifier, outbox, path = components
    outbox.enqueue(transition(fence, 0, True))
    outbox.deliver_pending("agent", endpoint.apply)
    outbox.enqueue(transition(fence, 1, False))
    def unavailable(_):
        raise ConnectionError("offline")
    with pytest.raises(ConnectionError):
        outbox.deliver_pending("agent", unavailable)
    assert not outbox.verified("agent", 1)
    assert fence.commit(fence.sign_operation(
        agent_id="agent", epoch=0, operation_id="old-epoch", value="remote-still-active"))
    assert outbox.deliver_pending("agent", endpoint.apply) == 1
    with pytest.raises(DownstreamDenied, match="fenced"):
        fence.commit(fence.sign_operation(
            agent_id="agent", epoch=0, operation_id="too-late", value="denied"))


def test_forged_ack_is_not_persisted(components):
    fence, endpoint, verifier, outbox, path = components
    outbox.enqueue(transition(fence, 0, True))
    def forged(envelope):
        return replace(endpoint.apply(envelope), signature="f" * 64)
    with pytest.raises(DownstreamDenied, match="authentication failed"):
        outbox.deliver_pending("agent", forged)
    assert len(outbox.pending("agent")) == 1
    with pytest.raises(PendingDownstreamFence):
        outbox.require_verified("agent", 0)
    assert outbox.deliver_pending("agent", endpoint.apply) == 1


def test_conflicting_epoch_and_duplicate_enqueues(components):
    fence, endpoint, verifier, outbox, path = components
    first = transition(fence, 0, True)
    outbox.enqueue(first)
    outbox.enqueue(first)
    with pytest.raises(DownstreamDenied, match="conflicting"):
        outbox.enqueue(transition(fence, 0, True))
    assert outbox.pending("agent") == [first]


def test_delivery_order_and_stop_on_first_failure(components):
    fence, endpoint, verifier, outbox, path = components
    outbox.enqueue(transition(fence, 0, True))
    outbox.enqueue(transition(fence, 1, False))
    attempted = []
    def fail_first(envelope):
        attempted.append(envelope.epoch)
        raise ConnectionError("failed")
    with pytest.raises(ConnectionError):
        outbox.deliver_pending("agent", fail_first)
    assert attempted == [0]
    assert [item.epoch for item in outbox.pending("agent")] == [0, 1]
    assert outbox.deliver_pending("agent", endpoint.apply) == 2


def test_tampered_persisted_receipt_does_not_count_as_verified(components):
    import sqlite3
    fence, endpoint, verifier, outbox, path = components
    outbox.enqueue(transition(fence, 0, True))
    assert outbox.deliver_pending("agent", endpoint.apply) == 1
    outbox.require_verified("agent", 0)
    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE transitions SET receipt_json=? WHERE agent_id=? AND epoch=?",
            ('{"signature":"forged"}', "agent", 0),
        )
    restarted = DurableTransitionOutbox(path, verifier=verifier)
    assert not restarted.verified("agent", 0)
    with pytest.raises(PendingDownstreamFence):
        restarted.require_verified("agent", 0)
