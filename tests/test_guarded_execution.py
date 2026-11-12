"""Public guarded-execution contract: test the actual controller/gateway path."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from agentcontain import (
    BoundGuardedExecution,
    GuardedExecutionDenied,
    Policy,
    admit,
    build_agentcontainment_engine,
)
from agentcontain.attestation import Ed25519Signer, Ed25519Verifier
from agent_containment.gateway import ActionGateway
from agent_containment.models import Action, Decision, DecisionType
from agent_containment.policy import PolicyEngine


def setup_boundary(*, agent_id="guarded-test", granted=("write_record",)):
    engine = build_agentcontainment_engine(agent_id)
    signer = Ed25519Signer.generate("guarded-test-issuer")
    admission = admit(
        Policy("guarded-test-policy", capabilities=granted),
        agent_id=agent_id,
        engine=engine,
        runtime_id=engine.runtime_id,
        warrant_signer=signer,
    )
    gateway = ActionGateway(PolicyEngine(), engine.controller)
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    action = Action(agent_id, "test-action", "write_record", "test-resource", risk=1)
    return admission, gateway, verifier, signer, action


def test_public_contract_executes_with_valid_authority_and_returns_any_payload():
    admission, gateway, verifier, _, action = setup_boundary()
    bound = BoundGuardedExecution(admission, gateway, warrant_verifier=verifier)
    calls = []
    assert bound.execute(action, lambda approved: calls.append(approved.action_id) or "ok") == "ok"
    assert calls == ["test-action"]
    assert bound.execute(action, lambda approved: None) is None
    # Legitimate executor payloads can contain a Decision. Only the gateway's
    # own denial must be interpreted as authority failure.
    payload = Decision(action.action_id, DecisionType.DENY, "application payload")
    assert bound.execute(action, lambda approved: payload) is payload


def test_public_contract_denies_out_of_scope_operation_before_callback():
    admission, gateway, verifier, _, action = setup_boundary(granted=("read_only",))
    bound = BoundGuardedExecution(admission, gateway, warrant_verifier=verifier)
    calls = []
    with pytest.raises(GuardedExecutionDenied, match="does not grant capability"):
        bound.execute(action, lambda approved: calls.append(approved))
    assert calls == []


def test_public_contract_rejects_untrusted_key_and_tampered_signature():
    admission, gateway, _, signer, action = setup_boundary()
    wrong_signer = Ed25519Signer.generate("unknown")
    wrong = Ed25519Verifier({wrong_signer.key_id: wrong_signer.public_key()})
    bound = BoundGuardedExecution(admission, gateway, warrant_verifier=wrong)
    calls = []
    with pytest.raises(GuardedExecutionDenied, match="signature"):
        bound.execute(action, lambda approved: calls.append(approved))
    assert calls == []

    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    admission.warrant_attestation = dict(admission.warrant_attestation)
    admission.warrant_attestation["signature"] = "tampered"
    bound = BoundGuardedExecution(admission, gateway, warrant_verifier=verifier)
    with pytest.raises(GuardedExecutionDenied):
        bound.execute(action, lambda approved: calls.append(approved))
    assert calls == []


def test_public_contract_rejects_correctly_signed_expired_warrant():
    admission, gateway, verifier, signer, action = setup_boundary()
    now = datetime.now(timezone.utc)
    expired = replace(
        admission.warrant,
        validity=replace(
            admission.warrant.validity,
            issued_at=now - timedelta(minutes=3),
            expires_at=now - timedelta(minutes=2),
        ),
    )
    admission.warrant = expired
    admission.warrant_attestation = signer.sign_warrant(expired).to_dict()
    bound = BoundGuardedExecution(admission, gateway, warrant_verifier=verifier)
    called = []
    with pytest.raises(GuardedExecutionDenied, match="expired"):
        bound.execute(action, lambda approved: called.append(approved))
    assert called == []


def test_public_contract_denies_revocation_during_gateway_policy(monkeypatch):
    admission, gateway, verifier, _, action = setup_boundary()
    bound = BoundGuardedExecution(admission, gateway, warrant_verifier=verifier)
    evaluate = gateway.policy.evaluate
    called = []
    def revoke_after_preflight(pending):
        admission.warrant = admission.warrant.revoke(revoked_at=datetime.now(timezone.utc))
        return evaluate(pending)
    monkeypatch.setattr(gateway.policy, "evaluate", revoke_after_preflight)
    with pytest.raises(GuardedExecutionDenied):
        bound.execute(action, lambda approved: called.append(approved))
    assert called == []


def test_public_contract_rechecks_expiry_after_gateway_policy(monkeypatch):
    import agentcontain.integrations._authority as authority

    admission, gateway, verifier, signer, action = setup_boundary()
    instant = datetime.now(timezone.utc)
    expiring = replace(
        admission.warrant,
        validity=replace(
            admission.warrant.validity,
            issued_at=instant - timedelta(minutes=1),
            expires_at=instant + timedelta(seconds=1),
        ),
    )
    admission.warrant = expiring
    admission.warrant_attestation = signer.sign_warrant(expiring).to_dict()
    bound = BoundGuardedExecution(admission, gateway, warrant_verifier=verifier)

    class Clock:
        ticks = 0
        @classmethod
        def now(cls, zone):
            cls.ticks += 1
            return instant if cls.ticks == 1 else instant + timedelta(seconds=2)

    # Deterministic fake clock only for the shared authority verifier: the
    # first call is valid, and the guarded callback is already expired.
    monkeypatch.setattr(authority, "datetime", Clock)
    called = []
    with pytest.raises(GuardedExecutionDenied, match="expired"):
        bound.execute(action, lambda approved: called.append(approved))
    assert Clock.ticks >= 2
    assert called == []


def test_public_contract_rejects_epoch_rotation_during_policy(monkeypatch):
    admission, gateway, verifier, _, action = setup_boundary()
    bound = BoundGuardedExecution(admission, gateway, warrant_verifier=verifier)
    evaluate = gateway.policy.evaluate
    called = []
    def halt_during_policy(pending):
        gateway.containment.halt()
        return evaluate(pending)
    monkeypatch.setattr(gateway.policy, "evaluate", halt_during_policy)
    with pytest.raises(GuardedExecutionDenied):
        bound.execute(action, lambda approved: called.append(approved))
    assert called == []


def test_public_contract_keeps_gateway_policy_authoritative():
    admission, gateway, verifier, _, action = setup_boundary()
    gateway.policy.denied_operations.add("write_record")
    bound = BoundGuardedExecution(admission, gateway, warrant_verifier=verifier)
    called = []
    with pytest.raises(GuardedExecutionDenied, match="AgentContainment denied"):
        bound.execute(action, lambda approved: called.append(approved))
    assert called == []


def test_public_contract_rejects_wrong_controller_and_subject():
    admission, gateway, verifier, _, action = setup_boundary()
    other, other_gateway, _, _, _ = setup_boundary(agent_id="other")
    with pytest.raises(GuardedExecutionDenied, match="admitted runtime controller"):
        BoundGuardedExecution(admission, other_gateway, warrant_verifier=verifier)
    bound = BoundGuardedExecution(admission, gateway, warrant_verifier=verifier)
    wrong_action = replace(action, agent_id="other")
    with pytest.raises(GuardedExecutionDenied):
        bound.execute(wrong_action, lambda approved: 1)


def test_public_contract_rejects_mutated_admission_and_async_executor():
    admission, gateway, verifier, _, action = setup_boundary()
    bound = BoundGuardedExecution(admission, gateway, warrant_verifier=verifier)
    async def unsupported(approved):
        return "not safe"
    with pytest.raises(TypeError, match="async"):
        bound.execute(action, unsupported)
    admission.warrant = admission.warrant.revoke(revoked_at=datetime.now(timezone.utc))
    called = []
    with pytest.raises(GuardedExecutionDenied):
        bound.execute(action, lambda approved: called.append(approved))
    assert called == []
