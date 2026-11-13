"""Authenticated downstream fence transition delivery contract tests."""
from dataclasses import replace

import pytest

from agentcontain.downstream_commit_fence import DownstreamCommitFence, DownstreamDenied
from agentcontain.downstream_transition_delivery import (
    DownstreamTransitionEndpoint,
    TransitionReceiptVerifier,
    VerifiedTransitionDelivery,
    new_transition_envelope,
)


@pytest.fixture
def setup(tmp_path):
    fence = DownstreamCommitFence(
        tmp_path / "authority.db",
        controller_key=b"controller-key-unique-for-test-0001",
        gateway_key=b"gateway-key-unique-for-test-0000002",
    )
    receipt_key = b"receipt-key-unique-for-test-0000002"
    endpoint = DownstreamTransitionEndpoint(fence, receipt_key=receipt_key)
    verifier = TransitionReceiptVerifier(receipt_key)
    delivery = VerifiedTransitionDelivery(endpoint.apply, verifier)
    return fence, endpoint, verifier, delivery


def envelope(fence, epoch=0, active=True):
    return new_transition_envelope(
        fence, agent_id="agent-1", epoch=epoch, active=active
    )


def test_authenticated_receipt_only_after_committed_transition(setup):
    fence, endpoint, verifier, delivery = setup
    initial = envelope(fence)
    receipt = delivery.deliver(initial)
    assert receipt.status == "committed"
    verifier.verify(initial, receipt)
    assert not fence.commit(fence.sign_operation(
        agent_id="agent-1", epoch=0, operation_id="first", value="committed"
    )) is False

    fence_transition = envelope(fence, epoch=1, active=False)
    fenced_receipt = delivery.deliver(fence_transition)
    verifier.verify(fence_transition, fenced_receipt)
    with pytest.raises(DownstreamDenied, match="fenced"):
        fence.commit(fence.sign_operation(
            agent_id="agent-1", epoch=0, operation_id="late", value="rejected"
        ))


def test_tampered_receipt_and_wrong_request_id_fail_closed(setup):
    fence, endpoint, verifier, delivery = setup
    initial = envelope(fence)
    receipt = endpoint.apply(initial)
    for forged in (
        replace(receipt, request_id="different"),
        replace(receipt, status="committed-but-not-really"),
        replace(receipt, signature="0" * 64),
        replace(receipt, epoch=99),
    ):
        with pytest.raises(DownstreamDenied):
            verifier.verify(initial, forged)


def test_transport_failure_never_produces_verified_receipt(setup):
    fence, endpoint, verifier, _ = setup
    def unavailable(_envelope):
        raise ConnectionError("downstream unavailable")
    delivery = VerifiedTransitionDelivery(unavailable, verifier)
    with pytest.raises(ConnectionError, match="unavailable"):
        delivery.deliver(envelope(fence))
    assert fence.effects("agent-1") == []


def test_replayed_authenticated_transition_is_idempotent(setup):
    fence, endpoint, verifier, delivery = setup
    initial = envelope(fence)
    receipt1 = delivery.deliver(initial)
    receipt2 = delivery.deliver(initial)
    assert receipt1 == receipt2


def test_forged_controller_transition_never_receives_receipt(setup):
    fence, endpoint, verifier, delivery = setup
    initial = envelope(fence)
    with pytest.raises(DownstreamDenied, match="unauthenticated"):
        delivery.deliver(replace(initial, controller_signature="f" * 64))
    with pytest.raises(DownstreamDenied, match="first transition"):
        delivery.deliver(envelope(fence, epoch=1, active=False))


def test_wrong_receipt_key_rejected(setup):
    fence, endpoint, verifier, delivery = setup
    wrong = VerifiedTransitionDelivery(
        endpoint.apply, TransitionReceiptVerifier(b"incorrect-receipt-key-for-test-001")
    )
    with pytest.raises(DownstreamDenied, match="authentication failed"):
        wrong.deliver(envelope(fence))
