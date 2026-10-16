from datetime import timedelta

import pytest

from agentcontain.attestation import Ed25519Signer, Ed25519Verifier
from agentcontain.engine import admit, contain, issue_recovery_authorization, recover
from agentcontain.policy import Policy


class _Report:
    def __init__(self, *, complete: bool, epoch: int) -> None:
        self.complete = complete
        self.epoch = epoch
        self.failures = ()


class _RecoverableEngine:
    def __init__(self) -> None:
        self.last_report = None
        self.recover_calls = 0

    def contain(self):
        self.last_report = _Report(complete=True, epoch=1)
        return self.last_report

    def issue_recovery_authorization(self):
        return "controller-authorized-recovery"

    def recover(self, authorization):
        assert authorization == "controller-authorized-recovery"
        self.recover_calls += 1
        return 2


def _contained_signed_admission(*, issuer="tenant-security", ttl=timedelta(minutes=7)):
    signer = Ed25519Signer.generate("test-key")
    engine = _RecoverableEngine()
    admission = admit(
        Policy(policy_id="production", capabilities=("read",)),
        agent_id="agent-1",
        engine=engine,
        runtime_id="runtime-1",
        warrant_issuer=issuer,
        warrant_ttl=ttl,
        warrant_signer=signer,
    )
    contain(admission)
    return admission, engine, signer, ttl


def test_signed_warrant_recovery_requires_signer_before_runtime_recovery():
    admission, engine, _, _ = _contained_signed_admission()
    authorization = issue_recovery_authorization(admission)

    with pytest.raises(RuntimeError, match="requires warrant_signer"):
        recover(admission, authorization)

    assert engine.recover_calls == 0
    assert admission.machine.state.value == "contained"
    assert admission.identity.epoch == 1
    assert admission.warrant is not None
    assert admission.warrant.lifecycle.state.value == "revoked"
    assert admission.warrant_attestation is None


def test_recovery_preserves_issuer_ttl_and_signed_authority():
    admission, engine, signer, ttl = _contained_signed_admission()
    authorization = issue_recovery_authorization(admission)

    recovered_epoch = recover(admission, authorization, warrant_signer=signer)

    assert recovered_epoch == 2
    assert engine.recover_calls == 1
    assert admission.machine.state.value == "recovered"
    assert admission.warrant is not None
    assert admission.warrant.issuer == "tenant-security"
    assert admission.warrant.runtime.epoch == recovered_epoch
    assert admission.warrant.validity.expires_at - admission.warrant.validity.issued_at == ttl
    assert admission.warrant_attestation is not None

    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    assert verifier.verify_warrant(admission.warrant_attestation) == admission.warrant
