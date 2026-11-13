"""Combined containment: remote acknowledgment must not be inferred."""
import pytest

from agentcontain import Policy, admit, build_agentcontainment_engine
from agentcontain.downstream_commit_fence import DownstreamCommitFence, DownstreamDenied
from agentcontain.downstream_transition_delivery import (
    DownstreamTransitionEndpoint, TransitionReceiptVerifier,
    VerifiedTransitionDelivery, new_transition_envelope,
)
from agentcontain.downstream_containment import (
    DownstreamContainmentUnverified, contain_with_downstream_ack,
)


def setup(tmp_path, agent_id):
    engine = build_agentcontainment_engine(agent_id)
    admission = admit(Policy("combined-containment"), agent_id=agent_id,
                      engine=engine, runtime_id=engine.runtime_id)
    fence = DownstreamCommitFence(tmp_path / "remote.db",
                                  controller_key=b"controller-unique-secret-000000000",
                                  gateway_key=b"gateway-unique-secret-00000000000")
    receipt_key = b"receipt-unique-secret-0000000000000"
    endpoint = DownstreamTransitionEndpoint(fence, receipt_key=receipt_key)
    verifier = TransitionReceiptVerifier(receipt_key)
    def factory(agent, epoch):
        return new_transition_envelope(fence, agent_id=agent, epoch=epoch, active=False)
    # Initial downstream state is active epoch 0.
    fence.transition(agent_id=agent_id, epoch=0, active=True,
                     signature=fence.sign_transition(agent_id=agent_id, epoch=0, active=True))
    return admission, fence, endpoint, verifier, factory


def test_verified_downstream_fence_requires_durable_receipt(tmp_path):
    admission, fence, endpoint, verifier, factory = setup(tmp_path, "ack-success")
    delivery = VerifiedTransitionDelivery(endpoint.apply, verifier)
    result = contain_with_downstream_ack(admission, delivery=delivery,
                                          envelope_factory=factory)
    assert result.local_report.complete
    assert result.downstream_verified is True
    assert result.downstream_receipt.epoch == admission.identity.epoch
    assert result.downstream_receipt.active is False
    with pytest.raises(DownstreamDenied, match="fenced"):
        fence.commit(fence.sign_operation(
            agent_id="ack-success", epoch=0, operation_id="late", value="bad"))


def test_failed_remote_delivery_preserves_local_proof_but_not_remote_claim(tmp_path):
    admission, fence, endpoint, verifier, factory = setup(tmp_path, "ack-failure")
    def offline(_envelope):
        raise ConnectionError("downstream unavailable")
    delivery = VerifiedTransitionDelivery(offline, verifier)
    with pytest.raises(DownstreamContainmentUnverified, match="unavailable") as error:
        contain_with_downstream_ack(admission, delivery=delivery, envelope_factory=factory)
    assert error.value.local_report.complete
    assert error.value.downstream_verified is False
    assert admission.engine.controller.runtime.can_execute is False
    # Downstream never saw the transition: old epoch can still commit there.
    assert fence.commit(fence.sign_operation(
        agent_id="ack-failure", epoch=0, operation_id="still-live", value="danger"))


def test_forged_receipt_fails_combined_enforcement(tmp_path):
    admission, fence, endpoint, verifier, factory = setup(tmp_path, "ack-forgery")
    def forged(envelope):
        from dataclasses import replace
        return replace(endpoint.apply(envelope), signature="0" * 64)
    delivery = VerifiedTransitionDelivery(forged, verifier)
    with pytest.raises(DownstreamContainmentUnverified, match="authentication failed") as error:
        contain_with_downstream_ack(admission, delivery=delivery, envelope_factory=factory)
    assert error.value.local_report.complete
    assert error.value.downstream_verified is False
    # The actual downstream fence may have committed despite the invalid
    # receipt, but the controller cannot claim it was verified.
    with pytest.raises(DownstreamDenied, match="fenced"):
        fence.commit(fence.sign_operation(
            agent_id="ack-forgery", epoch=0, operation_id="late", value="bad"))
