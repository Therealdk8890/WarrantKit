"""Cross-layer restart regression tests for WarrantKit authority.

These tests use AgentContainment's real controller/service and durable incident
and fence registries. They do not claim to exercise host cgroup/eBPF enforcement.
"""
from agent_containment.containment import ContainmentController
from agent_containment.control import ContainmentService
from agent_containment.incident_state import IncidentRegistry
from agent_containment.runtime import Runtime
from agent_containment.runtime_fence import RuntimeFenceRegistry

from agentcontain.attestation import Ed25519Signer
from agentcontain.engine import (
    AgentContainmentRuntimeAdapter,
    admit,
    contain,
    recover,
)
from agentcontain.policy import Policy
from agentcontain.warrant import verify_warrant


def test_old_warrant_and_lease_stay_invalid_across_controller_restart(tmp_path):
    agent_id = "restart-boundary-agent"
    runtime_id = "restart-boundary-runtime"
    incidents_path = tmp_path / "incidents.json"
    fences_path = tmp_path / "fences.json"
    signer = Ed25519Signer.generate("restart-test-key")

    first_runtime = Runtime(agent_id, runtime_id=runtime_id)
    first_service = ContainmentService(
        incidents=IncidentRegistry(incidents_path),
        fences=RuntimeFenceRegistry(fences_path),
    )
    first_controller = ContainmentController(first_runtime)
    first_engine = AgentContainmentRuntimeAdapter(
        agent_id, first_controller, first_service
    )
    admission = admit(
        Policy("restart-test", capabilities=("read",)),
        agent_id=agent_id,
        engine=first_engine,
        runtime_id=runtime_id,
        warrant_signer=signer,
    )
    old_warrant = admission.warrant
    old_lease = first_runtime.acquire_lease()
    assert old_warrant is not None
    assert old_lease is not None

    report = contain(admission)
    assert report.epoch == 1
    assert first_runtime.lease_valid(old_lease) is False
    assert admission.warrant.lifecycle.state.value == "revoked"

    # Reconstruct controller-owned state using the durable incident and fence
    # files, as a restarted controller process would.
    restarted_runtime = Runtime(agent_id, runtime_id=runtime_id)
    restarted_runtime.restore_contained(1)
    restarted_service = ContainmentService(
        incidents=IncidentRegistry(incidents_path),
        fences=RuntimeFenceRegistry(fences_path),
    )
    restarted_controller = ContainmentController(restarted_runtime)
    restarted_engine = AgentContainmentRuntimeAdapter(
        agent_id, restarted_controller, restarted_service
    )

    assert restarted_runtime.snapshot().epoch == 1
    assert restarted_runtime.snapshot().can_execute is False
    assert restarted_runtime.acquire_lease() is None
    assert restarted_runtime.lease_valid(old_lease) is False

    # The pre-containment Warrant must fail against the authoritative
    # post-restart epoch even though the runtime identifier is unchanged.
    try:
        verify_warrant(
            old_warrant,
            execution_id=admission.identity.execution_id,
            agent_id=agent_id,
            policy_id=admission.identity.policy_id,
            policy_digest=admission.identity.policy_digest,
            runtime_id=runtime_id,
            epoch=restarted_runtime.snapshot().epoch,
        )
    except (TypeError, ValueError) as exc:
        assert "epoch" in str(exc).lower() or "revok" in str(exc).lower()
    else:
        raise AssertionError("pre-containment Warrant remained valid after restart")

    # Resume recovery through the new controller, not the stale service.
    authorization = restarted_engine.issue_recovery_authorization()
    admission.engine = restarted_engine
    new_epoch = recover(admission, authorization, warrant_signer=signer)

    assert new_epoch == 2
    snapshot = restarted_runtime.snapshot()
    assert snapshot.epoch == 2
    assert snapshot.can_execute is True
    assert admission.warrant is not None
    assert admission.warrant.epoch == 2
    assert admission.warrant_attestation is not None

    # Recovery grants only fresh epoch-scoped authority; the old Warrant
    # and lease do not become valid again.
    assert restarted_runtime.lease_valid(old_lease) is False
    try:
        verify_warrant(
            old_warrant,
            execution_id=admission.identity.execution_id,
            agent_id=agent_id,
            policy_id=admission.identity.policy_id,
            policy_digest=admission.identity.policy_digest,
            runtime_id=runtime_id,
            epoch=2,
        )
    except (TypeError, ValueError) as exc:
        assert "epoch" in str(exc).lower() or "revok" in str(exc).lower()
    else:
        raise AssertionError("old Warrant became valid after recovery")

    verify_warrant(
        admission.warrant,
        execution_id=admission.identity.execution_id,
        agent_id=agent_id,
        policy_id=admission.identity.policy_id,
        policy_digest=admission.identity.policy_digest,
        runtime_id=runtime_id,
        epoch=2,
    )
