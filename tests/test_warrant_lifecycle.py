from __future__ import annotations

import pytest

from agentcontain.engine import (
    admit,
    contain,
    issue_recovery_authorization,
    recover,
)
from agentcontain.policy import Policy
from agentcontain.warrant import RevocationState, verify_warrant


class RuntimeReport:
    complete = True
    certified = True
    durable = True
    external_verified = True
    failures = ()
    persistence_failures = ()
    epoch = 1


class RuntimeEngine:
    last_report = None
    halt_should_fail = False

    def contain(self):
        self.last_report = RuntimeReport()
        return self.last_report

    def halt(self):
        if self.halt_should_fail:
            raise RuntimeError("halt failed")
    
    def issue_recovery_authorization(self):
        return object()

    def recover(self, authorization):
        assert authorization is not None
        return 2


def test_admission_issues_warrant_bound_to_execution_and_policy():
    engine = RuntimeEngine()
    admission = admit(
        Policy("production", capabilities=("network",)),
        agent_id="agent-1",
        engine=engine,
        runtime_id="runtime-1",
    )

    assert admission.warrant is not None
    assert admission.warrant.subject.execution_id == admission.identity.execution_id
    assert admission.warrant.subject.agent_id == "agent-1"
    assert admission.warrant.authority.policy_id == "production"
    assert admission.warrant.authority.policy_digest == admission.identity.policy_digest
    assert admission.warrant.runtime.epoch == 0
    assert admission.machine.events.events[0].details["warrant_id"] == admission.warrant.warrant_id

    verify_warrant(
        admission.warrant,
        execution_id=admission.identity.execution_id,
        agent_id=admission.identity.agent_id,
        policy_id=admission.identity.policy_id,
        policy_digest=admission.identity.policy_digest,
        runtime_id="runtime-1",
        epoch=0,
    )


def test_containment_revokes_pre_containment_warrant():
    engine = RuntimeEngine()
    admission = admit(
        Policy("production"),
        agent_id="agent-1",
        engine=engine,
        runtime_id="runtime-1",
    )
    old_warrant = admission.warrant
    assert old_warrant is not None

    contain(admission)

    assert admission.identity.epoch == 1
    assert admission.warrant is not None
    assert admission.warrant.warrant_id == old_warrant.warrant_id
    assert admission.warrant.lifecycle.state == RevocationState.REVOKED
    with pytest.raises(ValueError, match="revoked"):
        verify_warrant(
            admission.warrant,
            execution_id=admission.identity.execution_id,
            agent_id=admission.identity.agent_id,
            policy_id=admission.identity.policy_id,
            policy_digest=admission.identity.policy_digest,
            runtime_id="runtime-1",
            epoch=1,
        )


def test_recovery_issues_fresh_warrant_only_after_new_epoch():
    engine = RuntimeEngine()
    admission = admit(
        Policy("production"),
        agent_id="agent-1",
        engine=engine,
        runtime_id="runtime-1",
    )
    old_warrant = admission.warrant
    assert old_warrant is not None

    contain(admission)
    revoked_warrant = admission.warrant
    assert revoked_warrant is not None
    assert revoked_warrant.lifecycle.state == RevocationState.REVOKED

    recovered_epoch = recover(
        admission,
        issue_recovery_authorization(admission),
    )

    assert recovered_epoch == 2
    assert admission.identity.epoch == 2
    assert admission.warrant is not None
    assert admission.warrant.warrant_id != old_warrant.warrant_id
    assert admission.warrant.lifecycle.state == RevocationState.ACTIVE
    assert admission.warrant.runtime.epoch == 2

    verify_warrant(
        admission.warrant,
        execution_id=admission.identity.execution_id,
        agent_id=admission.identity.agent_id,
        policy_id=admission.identity.policy_id,
        policy_digest=admission.identity.policy_digest,
        runtime_id="runtime-1",
        epoch=2,
    )



def test_stale_runtime_report_cannot_verify_after_epoch_advance():
    engine = RuntimeEngine()
    admission = admit(
        Policy("production"),
        agent_id="agent-1",
        engine=engine,
        runtime_id="runtime-1",
    )

    contain(admission)
    assert admission.identity.epoch == 1

    # Simulate a late report from the pre-containment epoch. The existing
    # verifier must reject it rather than projecting old evidence into the
    # current epoch.
    stale_report = RuntimeReport()
    stale_report.epoch = 0
    engine.last_report = stale_report

    from agentcontain.engine import verify

    with pytest.raises(RuntimeError, match="verification report is unavailable"):
        verify(admission)


def test_warrant_binding_rejects_wrong_execution_identity():
    engine = RuntimeEngine()
    admission = admit(
        Policy("production"),
        agent_id="agent-1",
        engine=engine,
        runtime_id="runtime-1",
    )
    assert admission.warrant is not None

    with pytest.raises(ValueError, match="execution_id"):
        verify_warrant(
            admission.warrant,
            execution_id="other-execution",
            agent_id="agent-1",
            policy_id="production",
            policy_digest=admission.identity.policy_digest,
            runtime_id="runtime-1",
            epoch=0,
        )

def test_halt_revokes_active_warrant_after_runtime_halt():
    engine = RuntimeEngine()
    admission = admit(
        Policy("production"),
        agent_id="agent-1",
        engine=engine,
        runtime_id="runtime-1",
    )
    warrant = admission.warrant
    assert warrant is not None
    assert warrant.lifecycle.state == RevocationState.ACTIVE

    from agentcontain.engine import halt

    halt(admission)

    assert admission.machine.state.value == "halted"
    assert admission.warrant is not None
    assert admission.warrant.warrant_id == warrant.warrant_id
    assert admission.warrant.lifecycle.state == RevocationState.REVOKED
    with pytest.raises(ValueError, match="revoked"):
        verify_warrant(
            admission.warrant,
            execution_id=admission.identity.execution_id,
            agent_id=admission.identity.agent_id,
            policy_id=admission.identity.policy_id,
            policy_digest=admission.identity.policy_digest,
            runtime_id="runtime-1",
            epoch=0,
        )


def test_failed_halt_does_not_revoke_warrant():
    engine = RuntimeEngine()
    engine.halt_should_fail = True
    admission = admit(
        Policy("production"),
        agent_id="agent-1",
        engine=engine,
        runtime_id="runtime-1",
    )
    warrant = admission.warrant
    assert warrant is not None

    from agentcontain.engine import halt

    with pytest.raises(RuntimeError, match="halt failed"):
        halt(admission)

    assert admission.machine.state.value == "admitted"
    assert admission.warrant == warrant
    assert admission.warrant.lifecycle.state == RevocationState.ACTIVE

