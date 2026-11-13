"""Real AgentContainment registry recovery contract (newer source only)."""
import pytest

from agent_containment.incident_state import IncidentRegistry
from agent_containment.runtime_fence import RuntimeFenceRegistry
from agentcontain.agentcontainment_fence_recovery import reconcile_agentcontainment_registries
from agentcontain.downstream_commit_fence import DownstreamCommitFence, DownstreamDenied
from agentcontain.downstream_outbox import DurableTransitionOutbox, PendingDownstreamFence
from agentcontain.downstream_transition_delivery import (
    DownstreamTransitionEndpoint, TransitionReceiptVerifier, new_transition_envelope,
)


@pytest.fixture
def env(tmp_path):
    agent = "restart-agent"
    fence_path = tmp_path / "runtime-fences.json"
    incident_path = tmp_path / "incidents.json"
    fences = RuntimeFenceRegistry(fence_path)
    incidents = IncidentRegistry(incident_path)
    downstream = DownstreamCommitFence(
        tmp_path / "downstream.db",
        controller_key=b"controller-actual-registry-test-key-01",
        gateway_key=b"gateway-actual-registry-test-key-0002",
    )
    receipt_key = b"receipt-actual-registry-test-key-0002"
    endpoint = DownstreamTransitionEndpoint(downstream, receipt_key=receipt_key)
    outbox = DurableTransitionOutbox(
        tmp_path / "outbox.db", verifier=TransitionReceiptVerifier(receipt_key))
    initial = new_transition_envelope(downstream, agent_id=agent, epoch=0, active=True)
    outbox.enqueue(initial)
    outbox.deliver_pending(agent, endpoint.apply)
    signer = lambda a, epoch, active: new_transition_envelope(
        downstream, agent_id=a, epoch=epoch, active=active)
    return agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path


def recover(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    return reconcile_agentcontainment_registries(
        agent_id=agent, fence_path=fence_path, incident_path=incident_path,
        outbox=outbox, sign_transition=signer)


def test_real_durable_fence_survives_restart_without_incident_record(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)
    # Reopen from disk, rather than passing an in-memory fence record.
    recovered = recover(env)
    assert recovered.epoch == 1 and recovered.active is False
    with pytest.raises(PendingDownstreamFence):
        outbox.require_verified(agent, 1)
    assert outbox.deliver_pending(agent, endpoint.apply) == 1
    outbox.require_verified(agent, 1)
    with pytest.raises(DownstreamDenied, match="fenced"):
        downstream.commit(downstream.sign_operation(
            agent_id=agent, epoch=0, operation_id="late", value="blocked"))


def test_real_incident_record_and_fence_agree(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)
    incidents.record_containment("incident-1", agent, 1)
    assert recover(env).epoch == 1


def test_recovered_incident_conflicts_with_still_present_fence(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)
    incidents.record_containment("incident-1", agent, 1)
    incidents.mark_recovered("incident-1")
    with pytest.raises(DownstreamDenied, match="conflicts"):
        recover(env)
    assert outbox.pending(agent) == []


def test_missing_or_malformed_durable_fence_never_creates_remote_authority(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    with pytest.raises(DownstreamDenied, match="unavailable"):
        recover(env)
    fence_path.write_text('{"records":[{"agent_id":"restart-agent","containment_epoch":"bad"}]}')
    with pytest.raises(DownstreamDenied, match="valid"):
        recover(env)
    assert outbox.pending(agent) == []


def test_mismatched_incident_epoch_fails_closed(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)
    incidents.record_containment("incident-1", agent, 2)
    with pytest.raises(DownstreamDenied, match="conflicts"):
        recover(env)
    assert outbox.pending(agent) == []
