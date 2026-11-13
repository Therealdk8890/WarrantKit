"""Real AgentContainment registry recovery contract (newer source only)."""
import pytest

from agentcontain.agentcontainment_fence_recovery import (
    reconcile_agentcontainment_registries,
    reconcile_authenticated_agentcontainment_registries,
    require_verified_against_agentcontainment_fence,
)
from agentcontain.downstream_commit_fence import DownstreamCommitFence, DownstreamDenied
from agentcontain.downstream_outbox import DurableTransitionOutbox, PendingDownstreamFence
from agentcontain.downstream_transition_delivery import (
    DownstreamTransitionEndpoint, TransitionReceiptVerifier, new_transition_envelope,
)

IncidentRegistry = pytest.importorskip("agent_containment.incident_state").IncidentRegistry
RuntimeFenceRegistry = pytest.importorskip("agent_containment.runtime_fence").RuntimeFenceRegistry


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


def test_real_registry_rejects_restored_old_outbox_epoch(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)
    with pytest.raises(PendingDownstreamFence, match="independent authority"):
        require_verified_against_agentcontainment_fence(
            agent_id=agent, epoch=0, fence_path=fence_path, outbox=outbox,
        )
    recover(env)
    outbox.deliver_pending(agent, endpoint.apply)
    require_verified_against_agentcontainment_fence(
        agent_id=agent, epoch=1, fence_path=fence_path, outbox=outbox,
    )


def test_missing_controller_fence_blocks_receipt_verification(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    with pytest.raises(DownstreamDenied, match="unavailable"):
        require_verified_against_agentcontainment_fence(
            agent_id=agent, epoch=0, fence_path=fence_path, outbox=outbox,
        )


def test_corrupt_controller_fence_blocks_receipt_verification(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fence_path.write_text("{not-json", encoding="utf-8")
    with pytest.raises(RuntimeError, match="invalid runtime fence registry"):
        require_verified_against_agentcontainment_fence(
            agent_id=agent, epoch=0, fence_path=fence_path, outbox=outbox,
        )


def test_authenticated_recovery_rejects_missing_trust_decision(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)
    for decision in (False, None, 1, "yes"):
        with pytest.raises(DownstreamDenied, match="not authenticated"):
            reconcile_authenticated_agentcontainment_registries(
                agent_id=agent, fence_path=fence_path, incident_path=incident_path,
                outbox=outbox, sign_transition=signer,
                verify_registry_snapshot=lambda *_args, d=decision: d,
            )
    assert outbox.pending(agent) == []


def test_authenticated_recovery_requires_trusted_verifier_to_approve(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)
    calls = []
    def trusted_checkpoint(fence_file, incident_file):
        calls.append((fence_file, incident_file))
        return True
    result = reconcile_authenticated_agentcontainment_registries(
        agent_id=agent, fence_path=fence_path, incident_path=incident_path,
        outbox=outbox, sign_transition=signer,
        verify_registry_snapshot=trusted_checkpoint,
    )
    assert result.epoch == 1 and result.active is False
    assert calls == [(fence_path, incident_path)]
    assert not outbox.verified(agent, 1)
