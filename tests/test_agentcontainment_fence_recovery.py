"""Real AgentContainment registry recovery contract (newer source only)."""
import hashlib

import pytest

from agentcontain.agentcontainment_fence_recovery import (
    reconcile_agentcontainment_registries,
    reconcile_authenticated_agentcontainment_registries,
    pinned_registry_snapshot_verifier,
    TrustedRegistryCheckpoint,
    reconcile_with_trusted_checkpoint,
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
    def trusted_checkpoint(fence_file, incident_file, fence_bytes, incident_bytes):
        calls.append((fence_file, incident_file, fence_bytes, incident_bytes))
        return True
    result = reconcile_authenticated_agentcontainment_registries(
        agent_id=agent, fence_path=fence_path, incident_path=incident_path,
        outbox=outbox, sign_transition=signer,
        verify_registry_snapshot=trusted_checkpoint,
    )
    assert result.epoch == 1 and result.active is False
    assert len(calls) == 1
    assert calls[0][:2] == (fence_path, incident_path)
    assert calls[0][2] == fence_path.read_bytes()
    assert calls[0][3] is None
    assert not outbox.verified(agent, 1)


def test_authenticated_recovery_uses_verified_bytes_after_source_replacement(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)
    original = fence_path.read_bytes()

    def verify_then_replace(original_fence, original_incident, fence_bytes, incident_bytes):
        assert fence_bytes == original and incident_bytes is None
        # Simulate adversarial replacement after verification but before parse.
        original_fence.write_text('{"records":[]}', encoding="utf-8")
        return True

    recovered = reconcile_authenticated_agentcontainment_registries(
        agent_id=agent, fence_path=fence_path, incident_path=incident_path,
        outbox=outbox, sign_transition=signer,
        verify_registry_snapshot=verify_then_replace,
    )
    assert recovered.epoch == 1 and recovered.active is False
    assert outbox.pending(agent) == [recovered]


def test_authenticated_recovery_rejects_modified_snapshot_bytes(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)
    trusted_bytes = fence_path.read_bytes()
    fence_path.write_text('{"records":[]}', encoding="utf-8")
    with pytest.raises(DownstreamDenied, match="not authenticated"):
        reconcile_authenticated_agentcontainment_registries(
            agent_id=agent, fence_path=fence_path, incident_path=incident_path,
            outbox=outbox, sign_transition=signer,
            verify_registry_snapshot=lambda _fp, _ip, fb, _ib: fb == trusted_bytes,
        )
    assert outbox.pending(agent) == []


def test_pinned_snapshot_digest_accepts_exact_captured_registry_bytes(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)
    expected = hashlib.sha256(fence_path.read_bytes()).hexdigest()
    recovered = reconcile_authenticated_agentcontainment_registries(
        agent_id=agent, fence_path=fence_path, incident_path=incident_path,
        outbox=outbox, sign_transition=signer,
        verify_registry_snapshot=pinned_registry_snapshot_verifier(
            expected_fence_sha256=expected, expected_incident_sha256=None,
        ),
    )
    assert recovered.epoch == 1 and recovered.active is False


def test_pinned_snapshot_digest_rejects_tampering_and_missing_incident(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)
    expected = hashlib.sha256(fence_path.read_bytes()).hexdigest()
    verifier = pinned_registry_snapshot_verifier(
        expected_fence_sha256=expected,
        expected_incident_sha256=hashlib.sha256(b"expected-incident").hexdigest(),
    )
    with pytest.raises(DownstreamDenied, match="not authenticated"):
        reconcile_authenticated_agentcontainment_registries(
            agent_id=agent, fence_path=fence_path, incident_path=incident_path,
            outbox=outbox, sign_transition=signer, verify_registry_snapshot=verifier,
        )
    fence_path.write_bytes(b"tampered")
    verifier = pinned_registry_snapshot_verifier(
        expected_fence_sha256=expected, expected_incident_sha256=None,
    )
    with pytest.raises(DownstreamDenied, match="not authenticated"):
        reconcile_authenticated_agentcontainment_registries(
            agent_id=agent, fence_path=fence_path, incident_path=incident_path,
            outbox=outbox, sign_transition=signer, verify_registry_snapshot=verifier,
        )
    assert outbox.pending(agent) == []


def test_pinned_snapshot_digest_rejects_invalid_checkpoint_digest():
    with pytest.raises(ValueError, match="fence SHA-256"):
        pinned_registry_snapshot_verifier(
            expected_fence_sha256="not-a-digest", expected_incident_sha256=None,
        )
    with pytest.raises(ValueError, match="incident SHA-256"):
        pinned_registry_snapshot_verifier(
            expected_fence_sha256="0" * 64, expected_incident_sha256="x" * 64,
        )


def test_authenticated_recovery_rejects_stale_epoch_despite_matching_digest(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)
    verifier = pinned_registry_snapshot_verifier(
        expected_fence_sha256=hashlib.sha256(fence_path.read_bytes()).hexdigest(),
        expected_incident_sha256=None,
    )
    with pytest.raises(DownstreamDenied, match="below trusted minimum"):
        reconcile_authenticated_agentcontainment_registries(
            agent_id=agent, fence_path=fence_path, incident_path=incident_path,
            outbox=outbox, sign_transition=signer,
            verify_registry_snapshot=verifier, minimum_trusted_epoch=2,
        )
    assert outbox.pending(agent) == []


def test_authenticated_recovery_accepts_matching_minimum_epoch(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)
    verifier = pinned_registry_snapshot_verifier(
        expected_fence_sha256=hashlib.sha256(fence_path.read_bytes()).hexdigest(),
        expected_incident_sha256=None,
    )
    result = reconcile_authenticated_agentcontainment_registries(
        agent_id=agent, fence_path=fence_path, incident_path=incident_path,
        outbox=outbox, sign_transition=signer,
        verify_registry_snapshot=verifier, minimum_trusted_epoch=1,
    )
    assert result.epoch == 1


@pytest.mark.parametrize("invalid", [True, 0, -1, "1", 1.0])
def test_authenticated_recovery_rejects_invalid_minimum_epoch(env, invalid):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)
    with pytest.raises(DownstreamDenied, match="invalid trusted minimum"):
        reconcile_authenticated_agentcontainment_registries(
            agent_id=agent, fence_path=fence_path, incident_path=incident_path,
            outbox=outbox, sign_transition=signer,
            verify_registry_snapshot=lambda *_: True,
            minimum_trusted_epoch=invalid,
        )
    assert outbox.pending(agent) == []


def test_authenticated_recovery_rejects_checkpointed_malformed_registry(env):
    """Matching a trusted digest does not make malformed authority executable."""
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    malformed = b'{"records": "not-a-list"}'
    fence_path.write_bytes(malformed)
    verifier = pinned_registry_snapshot_verifier(
        expected_fence_sha256=hashlib.sha256(malformed).hexdigest(),
        expected_incident_sha256=None,
    )
    with pytest.raises((DownstreamDenied, RuntimeError, ValueError, TypeError)):
        reconcile_authenticated_agentcontainment_registries(
            agent_id=agent, fence_path=fence_path, incident_path=incident_path,
            outbox=outbox, sign_transition=signer,
            verify_registry_snapshot=verifier,
        )
    assert outbox.pending(agent) == []


def test_authenticated_recovery_verifier_failure_cannot_enqueue(env):
    """Checkpoint backend outages must never create downstream authority."""
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)

    def unavailable_checkpoint(*_args):
        raise OSError("independent checkpoint unavailable")

    with pytest.raises(OSError, match="independent checkpoint unavailable"):
        reconcile_authenticated_agentcontainment_registries(
            agent_id=agent, fence_path=fence_path, incident_path=incident_path,
            outbox=outbox, sign_transition=signer,
            verify_registry_snapshot=unavailable_checkpoint,
        )
    assert outbox.pending(agent) == []


def test_external_checkpoint_pins_recovery_to_exact_registry_snapshot(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)
    checkpoint = TrustedRegistryCheckpoint(
        agent_id=agent, epoch=1,
        fence_sha256=hashlib.sha256(fence_path.read_bytes()).hexdigest(),
        incident_sha256=None,
    )
    result = reconcile_with_trusted_checkpoint(
        agent_id=agent, fence_path=fence_path, incident_path=incident_path,
        outbox=outbox, sign_transition=signer,
        read_trusted_checkpoint=lambda _agent: checkpoint,
    )
    assert result.epoch == 1 and result.active is False
    assert outbox.pending(agent) == [result]


@pytest.mark.parametrize("checkpoint", [None, True, 1, "invalid"])
def test_external_checkpoint_missing_or_invalid_fails_closed(env, checkpoint):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)
    with pytest.raises(DownstreamDenied, match="invalid independent registry checkpoint"):
        reconcile_with_trusted_checkpoint(
            agent_id=agent, fence_path=fence_path, incident_path=incident_path,
            outbox=outbox, sign_transition=signer,
            read_trusted_checkpoint=lambda _agent: checkpoint,
        )
    assert outbox.pending(agent) == []


def test_external_checkpoint_rejects_rollback_and_wrong_identity(env):
    agent, fences, incidents, downstream, endpoint, outbox, signer, fence_path, incident_path = env
    fences.prepare(agent, 1)
    digest = hashlib.sha256(fence_path.read_bytes()).hexdigest()
    for checkpoint in (
        TrustedRegistryCheckpoint("another-agent", 1, digest, None),
        TrustedRegistryCheckpoint(agent, 2, digest, None),
        TrustedRegistryCheckpoint(agent, 1, "0" * 64, None),
    ):
        with pytest.raises((DownstreamDenied, ValueError)):
            reconcile_with_trusted_checkpoint(
                agent_id=agent, fence_path=fence_path, incident_path=incident_path,
                outbox=outbox, sign_transition=signer,
                read_trusted_checkpoint=lambda _agent, cp=checkpoint: cp,
            )
    assert outbox.pending(agent) == []
