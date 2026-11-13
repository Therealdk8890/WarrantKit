"""Crash-window reconstruction requires independently authenticated durable evidence."""
from dataclasses import replace

import pytest

from agentcontain.downstream_commit_fence import DownstreamCommitFence, DownstreamDenied
from agentcontain.downstream_outbox import DurableTransitionOutbox, PendingDownstreamFence
from agentcontain.downstream_transition_delivery import (
    DownstreamTransitionEndpoint, TransitionReceiptVerifier, new_transition_envelope,
)
from agentcontain.downstream_reconciliation import (
    DurableFenceRecord, reconcile_missing_fence, require_reconciled_downstream_fence,
)


@pytest.fixture
def env(tmp_path):
    fence = DownstreamCommitFence(
        tmp_path / "remote.db", controller_key=b"controller-key-for-reconcile-tests-001",
        gateway_key=b"gateway-key-for-reconcile-tests-00002",
    )
    key = b"receipt-key-for-reconcile-tests-00002"
    endpoint = DownstreamTransitionEndpoint(fence, receipt_key=key)
    outbox = DurableTransitionOutbox(tmp_path / "outbox.db",
                                     verifier=TransitionReceiptVerifier(key))
    first = new_transition_envelope(fence, agent_id="agent", epoch=0, active=True)
    outbox.enqueue(first)
    outbox.deliver_pending("agent", endpoint.apply)
    record = DurableFenceRecord("agent", 1, "contained", False, "incident-1")
    signer = lambda agent, epoch, active: new_transition_envelope(
        fence, agent_id=agent, epoch=epoch, active=active)
    return fence, endpoint, outbox, record, signer


def reconcile(env, *, record=None, trusted=True, signer=None):
    fence, endpoint, outbox, original, sign = env
    return reconcile_missing_fence(
        agent_id="agent", outbox=outbox,
        read_authoritative_record=lambda _agent: original if record is None else record,
        verify_authoritative_record=lambda _record: trusted,
        sign_transition=sign if signer is None else signer,
    )


def test_missing_outbox_fence_reconstructed_then_delivered(env):
    fence, endpoint, outbox, record, signer = env
    # Simulate local fence durably committed, controller crashed before enqueue.
    with pytest.raises(PendingDownstreamFence):
        require_reconciled_downstream_fence(agent_id="agent", epoch=1, outbox=outbox)
    assert fence.commit(fence.sign_operation(
        agent_id="agent", epoch=0, operation_id="remote-before-recovery", value="still-live"))
    pending = reconcile(env)
    assert pending.epoch == 1 and pending.active is False
    with pytest.raises(PendingDownstreamFence):
        require_reconciled_downstream_fence(agent_id="agent", epoch=1, outbox=outbox)
    assert outbox.deliver_pending("agent", endpoint.apply) == 1
    require_reconciled_downstream_fence(agent_id="agent", epoch=1, outbox=outbox)
    with pytest.raises(DownstreamDenied, match="fenced"):
        fence.commit(fence.sign_operation(
            agent_id="agent", epoch=0, operation_id="remote-after-recovery", value="blocked"))


@pytest.mark.parametrize("bad", [
    DurableFenceRecord("other", 1, "contained", False, "incident-1"),
    DurableFenceRecord("agent", 0, "contained", False, "incident-1"),
    DurableFenceRecord("agent", 1, "active", False, "incident-1"),
    DurableFenceRecord("agent", 1, "contained", True, "incident-1"),
    DurableFenceRecord("agent", 1, "contained", False, ""),
])
def test_invalid_durable_record_never_enqueued(env, bad):
    _, _, outbox, _, _ = env
    with pytest.raises(DownstreamDenied, match="invalid"):
        reconcile(env, record=bad)
    assert outbox.pending("agent") == []


def test_untrusted_durable_record_rejected(env):
    _, _, outbox, _, _ = env
    with pytest.raises(DownstreamDenied, match="not authenticated"):
        reconcile(env, trusted=False)
    assert outbox.pending("agent") == []


def test_mismatched_controller_signer_rejected(env):
    _, _, outbox, _, signer = env
    with pytest.raises(DownstreamDenied, match="mismatched"):
        reconcile(env, signer=lambda agent, epoch, active: signer(agent, epoch + 1, active))
    assert outbox.pending("agent") == []


def test_reconciliation_is_not_idempotent_without_same_envelope(env):
    _, _, outbox, _, _ = env
    first = reconcile(env)
    # A second independently generated request ID for the same epoch cannot
    # replace the already persisted pending envelope.
    with pytest.raises(DownstreamDenied, match="conflicting"):
        reconcile(env)
    assert outbox.pending("agent") == [first]
