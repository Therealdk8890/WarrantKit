from dataclasses import dataclass

import pytest

from agentcontain import Policy, WarrantBoundReceipt
from agentcontain.engine import (
    admit,
    contain,
    containment_receipt,
    detect,
    evidence_envelope,
    halt,
    issue_recovery_authorization,
    recover,
    recontain,
    verify,
)


@dataclass(frozen=True)
class Report:
    complete: bool


class FakeEngine:
    def __init__(self, complete=True):
        self.complete = complete
        self.calls = 0
        self.last_report = None

    def contain(self):
        self.calls += 1
        self.last_report = Report(self.complete)
        return self.last_report


def test_admission_binds_policy_and_engine():
    engine = FakeEngine()
    admission = admit(Policy("production"), agent_id="agent-1", engine=engine)
    assert admission.identity.agent_id == "agent-1"
    assert admission.identity.policy_id == "production"
    assert admission.identity.policy_digest == Policy("production").digest
    assert admission.machine.state.value == "admitted"


def test_runtime_epoch_reset_archives_prior_epoch_and_restarts_sequence():
    engine = RuntimeProofEngine()
    admission = admit(Policy("production"), agent_id="agent-1", engine=engine)

    contain(admission)

    assert admission.identity.epoch == 1
    assert admission.machine.events.events[-1].epoch == 1
    assert admission.machine.events.events[-1].sequence == 1
    assert len(admission.machine.event_history) == 1
    assert admission.machine.event_history[0].events[-1].epoch == 0
    assert admission.machine.event_history[0].events[-1].sequence == 1


def test_runtime_epoch_must_be_an_integer():
    class MalformedEpochEngine(FakeEngine):
        def contain(self):
            self.calls += 1
            self.last_report = type("MalformedReport", (), {"complete": True, "epoch": "1"})()
            return self.last_report

    admission = admit(
        Policy("production"),
        agent_id="agent-1",
        engine=MalformedEpochEngine(),
    )

    with pytest.raises(TypeError, match="epoch must be an integer"):
        contain(admission)

    assert admission.identity.epoch == 0
    assert admission.machine.state.value == "admitted"


def test_containment_calls_engine_before_recording_platform_state():
    engine = FakeEngine()
    admission = admit(Policy("production"), agent_id="agent-1", engine=engine)
    report = contain(admission)
    assert report.complete
    assert engine.calls == 1
    assert admission.machine.state.value == "contained"
    assert admission.machine.events.events[-1].name == "containment_verified"


def test_failed_engine_does_not_create_containment_event():
    engine = FakeEngine(complete=False)
    admission = admit(Policy("production"), agent_id="agent-1", engine=engine)
    with pytest.raises(RuntimeError, match="containment failures"):
        contain(admission)
    assert engine.calls == 1
    assert admission.machine.state.value == "admitted"
    assert admission.machine.events.events[-1].name == "admission_verified"


def test_containment_receipt_binds_platform_identity():
    class ReceiptReport:
        complete = True
        def to_receipt(self, secret, *, execution_id, policy_id):
            return type("Receipt", (), {"execution_id": execution_id, "policy_id": policy_id})()

    class ReceiptEngine(FakeEngine):
        def contain(self):
            self.calls += 1
            self.last_report = ReceiptReport()
            return self.last_report

    engine = ReceiptEngine()
    admission = admit(Policy("production"), agent_id="agent-1", engine=engine)
    contain(admission)
    receipt = containment_receipt(admission, b"secret")
    assert receipt.execution_id == admission.identity.execution_id
    assert receipt.policy_id == "production"

def test_runtime_receipt_is_bound_to_warrant_without_changing_signed_receipt():
    class SignedReceipt:
        execution_id = "unused"
        policy_id = "unused"

    class ReceiptReport:
        complete = True
        epoch = 1

        def to_receipt(self, secret, *, execution_id, policy_id):
            return SignedReceipt()

    class ReceiptEngine(FakeEngine):
        def contain(self):
            self.calls += 1
            self.last_report = ReceiptReport()
            return self.last_report

    admission = admit(
        Policy("production"),
        agent_id="agent-1",
        engine=ReceiptEngine(),
        runtime_id="runtime-1",
    )
    contain(admission)

    receipt = containment_receipt(admission, b"secret")

    assert isinstance(receipt, WarrantBoundReceipt)
    assert receipt.warrant_id == admission.warrant.warrant_id
    assert receipt.execution_id == admission.identity.execution_id
    assert receipt.agent_id == admission.identity.agent_id
    assert receipt.policy_digest == admission.identity.policy_digest
    assert receipt.runtime_id == "runtime-1"
    assert receipt.epoch == 1
    assert receipt.runtime_receipt is not None
    assert receipt.to_dict()["warrant_binding"]["warrant_id"] == admission.warrant.warrant_id

    with pytest.raises(TypeError, match="warrant"):
        from agentcontain.warrant import verify_warrant
        verify_warrant(
            receipt,
            execution_id=admission.identity.execution_id,
            agent_id=admission.identity.agent_id,
            policy_id=admission.identity.policy_id,
            policy_digest=admission.identity.policy_digest,
            runtime_id="runtime-1",
            epoch=1,
        )


def test_evidence_uses_locally_accepted_policy_identity():
    policy = Policy("production", version=7, capabilities=("read",))
    engine = FakeEngine()
    admission = admit(policy, agent_id="agent-1", engine=engine)

    evidence = evidence_envelope(admission)

    assert evidence.execution["policy_id"] == policy.policy_id
    assert evidence.execution["policy_digest"] == policy.digest
    assert evidence.execution["epoch"] == admission.identity.epoch


def test_evidence_rejects_admission_policy_divergence():
    policy = Policy("production", version=1)
    engine = FakeEngine()
    admission = admit(policy, agent_id="agent-1", engine=engine)
    conflicting = Policy("production", version=2)
    object.__setattr__(
        admission,
        "policy",
        type(admission.policy).from_policy(conflicting),
    )

    with pytest.raises(RuntimeError, match="policy_id|policy_digest"):
        evidence_envelope(admission)


def test_evidence_can_bind_validated_fleet_governance_scope():
    from agentcontain.fleet import Agent, FleetRegistry, Organization, Project, Runtime

    fleet = FleetRegistry()
    organization = fleet.register_organization(Organization.create("acme"))
    project = fleet.register_project(Project.create(organization.organization_id, "payments"))
    runtime = fleet.register_runtime(Runtime.create(project.project_id, "prod"))
    agent = fleet.register_agent(Agent.create(runtime.runtime_id, "checkout", agent_id="agent-1"))

    admission = admit(Policy("production"), agent_id=agent.agent_id, engine=FakeEngine())
    evidence = evidence_envelope(admission, fleet=fleet)

    assert evidence.governance == {
        "organization_id": organization.organization_id,
        "project_id": project.project_id,
        "runtime_id": runtime.runtime_id,
        "agent_id": agent.agent_id,
    }


def test_evidence_governance_requires_registered_agent():
    from agentcontain.fleet import FleetRegistry

    admission = admit(Policy("production"), agent_id="unregistered", engine=FakeEngine())

    with pytest.raises(KeyError):
        evidence_envelope(admission, fleet=FleetRegistry())


@dataclass(frozen=True)
class RuntimeReport:
    epoch: int = 1
    complete: bool = True
    external_verified: bool = True
    certified: bool = True
    durable: bool = True
    stages: tuple[str, ...] = ("runtime_fenced", "enforcer:cgroup-v2:verified")
    failures: tuple[str, ...] = ()
    persistence_failures: tuple[str, ...] = ()
    enforcement_latency_seconds: float = 0.14


class RuntimeProofEngine(FakeEngine):
    def contain(self):
        self.calls += 1
        self.last_report = RuntimeReport()
        return self.last_report


def test_evidence_projects_authoritative_runtime_proof():
    engine = RuntimeProofEngine()
    admission = admit(Policy("production"), agent_id="agent-1", engine=engine)
    contain(admission)

    evidence = evidence_envelope(admission)

    assert evidence.enforcement["complete"] is True
    assert evidence.enforcement["external_verified"] is True
    assert evidence.enforcement["certified"] is True
    assert evidence.enforcement["durable"] is True
    assert evidence.enforcement["stages"] == [
        "runtime_fenced",
        "enforcer:cgroup-v2:verified",
    ]
    assert evidence.enforcement["enforcement_latency_seconds"] == 0.14
    assert evidence.verification == {
        "status": "verified",
        "method": "agentcontainment-runtime-report",
        "scope": "runtime-enforcement",
    }
    assert evidence.proof == {
        "host_enforcement_verified": True,
        "runtime_report": True,
    }


def test_verify_rejects_stale_runtime_proof_after_recovery():
    engine = RuntimeProofEngine()
    admission = admit(Policy("production"), agent_id="agent-1", engine=engine)
    contain(admission)
    admission.machine.recover()
    admission.machine.recovered(2)
    admission.identity = admission.machine.identity

    with pytest.raises(RuntimeError, match="runtime verification report is unavailable"):
        verify(admission)


def test_containment_receipt_rejects_stale_runtime_report_after_recovery():
    engine = RuntimeProofEngine()
    admission = admit(Policy("production"), agent_id="agent-1", engine=engine)
    contain(admission)
    admission.machine.recover()
    admission.machine.recovered(2)
    admission.identity = admission.machine.identity

    with pytest.raises(RuntimeError, match="containment report epoch"):
        containment_receipt(admission, b"secret")


def test_evidence_does_not_project_stale_runtime_proof_after_recovery():
    engine = RuntimeProofEngine()
    admission = admit(Policy("production"), agent_id="agent-1", engine=engine)
    contain(admission)
    admission.machine.recover()
    admission.machine.recovered(2)
    admission.identity = admission.machine.identity

    evidence = evidence_envelope(admission)

    assert evidence.execution["epoch"] == 2
    assert evidence.verification == {
        "status": "observed",
        "method": "agentcontain-platform-events",
        "reason": "runtime-report-epoch-mismatch",
    }
    assert evidence.proof == {}


def test_evidence_epoch_mismatch_is_rejected():
    policy = Policy("production")
    admission = admit(policy, agent_id="agent-1", engine=FakeEngine())
    contain(admission)
    document = evidence_envelope(admission).to_dict()
    document["events"][0]["epoch"] = admission.identity.epoch + 1

    with pytest.raises(ValueError, match="event epoch does not match"):
        type(evidence_envelope(admission)).from_dict(document)


class LifecycleEngine(FakeEngine):
    def __init__(self):
        super().__init__()
        self.halted = False
        self.recovered = False
        self.recontained = False

    def contain(self):
        self.calls += 1
        self.last_report = type(
            "LifecycleReport",
            (),
            {
                "complete": True,
                "certified": True,
                "durable": True,
                "external_verified": True,
                "failures": (),
                "persistence_failures": (),
            },
        )()
        return self.last_report

    def halt(self):
        self.halted = True

    def issue_recovery_authorization(self):
        return object()

    def recover(self, authorization):
        assert authorization is not None
        self.recovered = True
        return 1

    def recontain_enforcers(self):
        self.recontained = True
        return ()


def test_platform_lifecycle_bridge_uses_runtime_authority():
    engine = LifecycleEngine()
    admission = admit(Policy("production"), agent_id="agent-1", engine=engine)

    detect(admission, {"reason": "policy_violation"})
    contain(admission)
    verify(admission)

    assert admission.machine.state.value == "verified"
    assert admission.machine.events.events[-1].name == "verification_completed"

    authorization = issue_recovery_authorization(admission)
    epoch = recover(admission, authorization)

    assert epoch == 1
    assert engine.recovered is True
    assert admission.machine.state.value == "recovered"
    assert admission.identity.epoch == epoch
    assert admission.identity == admission.machine.identity


def test_platform_halt_delegates_to_runtime_authority():
    engine = LifecycleEngine()
    admission = admit(Policy("production"), agent_id="agent-1", engine=engine)
    contain(admission)

    halt(admission)

    assert engine.halted is True
    assert admission.machine.state.value == "halted"
    assert admission.machine.events.events[-1].name == "halt_requested"


def test_failed_recovery_recontains_platform_state():
    class FailingRecoveryEngine(LifecycleEngine):
        def recover(self, authorization):
            raise RuntimeError("release failed")

    engine = FailingRecoveryEngine()
    admission = admit(Policy("production"), agent_id="agent-1", engine=engine)
    contain(admission)

    with pytest.raises(RuntimeError, match="release failed"):
        recover(admission, issue_recovery_authorization(admission))

    assert admission.machine.state.value == "contained"
    assert admission.machine.events.events[-1].name == "recovery_failed_containment_restored"


def test_recontain_requires_runtime_verification():
    engine = LifecycleEngine()
    admission = admit(Policy("production"), agent_id="agent-1", engine=engine)
    contain(admission)

    recontain(admission)

    assert engine.recontained is True
    assert admission.machine.state.value == "contained"


def test_recovery_rejects_runtime_epoch_divergence():
    class DivergentRecoveryEngine(LifecycleEngine):
        def recover(self, authorization):
            return 2

    engine = DivergentRecoveryEngine()
    admission = admit(Policy("production"), agent_id="agent-1", engine=engine)
    contain(admission)

    with pytest.raises(RuntimeError, match="does not match expected platform epoch"):
        recover(admission, issue_recovery_authorization(admission))

    assert admission.machine.state.value == "recovering"
    assert admission.identity.epoch == 0


def test_authoritative_epoch_chain_spans_containment_recovery_and_evidence():
    class EpochEngine(RuntimeProofEngine):
        def issue_recovery_authorization(self):
            return object()

        def recover(self, authorization):
            assert authorization is not None
            return 2

    engine = EpochEngine()
    admission = admit(Policy("production"), agent_id="agent-1", engine=engine)

    contain(admission)
    assert admission.identity.epoch == 1
    assert admission.machine.events.events[-1].epoch == 1
    assert admission.machine.events.events[-1].sequence == 1

    verify(admission)

    authorization = issue_recovery_authorization(admission)
    assert recover(admission, authorization) == 2

    assert admission.identity.epoch == 2
    assert admission.machine.identity.epoch == 2
    assert len(admission.machine.event_history) == 2
    assert [event.epoch for event in admission.machine.event_history[0].events] == [0]
    assert [event.epoch for event in admission.machine.event_history[1].events] == [1, 1, 1]
    assert [event.sequence for event in admission.machine.event_history[1].events] == [1, 2, 3]
    assert [event.epoch for event in admission.machine.events.events] == [2]
    assert [event.sequence for event in admission.machine.events.events] == [1]

    with pytest.raises(RuntimeError, match="runtime verification report is unavailable"):
        verify(admission)

    evidence = evidence_envelope(admission)
    assert evidence.execution["epoch"] == 2
    assert [event["epoch"] for event in evidence.events] == [2]
    assert [event["sequence"] for event in evidence.events] == [1]
    assert evidence.verification == {
        "status": "observed",
        "method": "agentcontain-platform-events",
        "reason": "runtime-report-epoch-mismatch",
    }
    assert evidence.proof == {}
