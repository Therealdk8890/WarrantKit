from agentcontain.evidence import EvidenceEnvelope
from agentcontain.external_evidence import ExternalEvidenceReference
from agentcontain.fleet import Agent, FleetRegistry, Organization, Project, Runtime
from agentcontain.operator import OperatorIncidentView
from agentcontain.policy import Policy
from agentcontain.policy_assignment import PolicyAssignment, PolicyAssignmentRegistry
from agentcontain.policy_distribution import PolicyBundle


def _envelope(policy: Policy) -> EvidenceEnvelope:
    return EvidenceEnvelope.from_execution(
        execution={
            "execution_id": "exec-1",
            "agent_id": "agent-1",
            "policy_id": policy.policy_id,
            "policy_digest": policy.digest,
            "epoch": 3,
        },
        events=(
            {"name": "admission_verified", "execution_id": "exec-1", "epoch": 3, "sequence": 1, "timestamp": "2026-09-27T00:00:00+00:00", "details": {}},
            {"name": "anomaly_detected", "execution_id": "exec-1", "epoch": 3, "sequence": 2, "timestamp": "2026-09-27T00:00:01+00:00", "details": {"reason": "unauthorized_action"}},
            {"name": "containment_verified", "execution_id": "exec-1", "epoch": 3, "sequence": 3, "timestamp": "2026-09-27T00:00:02+00:00", "details": {}},
        ),
        verification={"status": "verified", "method": "test"},
        proof={"checks": ["containment"]},
    )


def test_operator_view_composes_agent_policy_incident_and_timeline() -> None:
    fleet = FleetRegistry()
    org = fleet.register_organization(Organization.create("Acme"))
    project = fleet.register_project(Project.create(org.organization_id, "Payments"))
    runtime = fleet.register_runtime(Runtime.create(project.project_id, "prod"))
    fleet.register_agent(Agent.create(runtime.runtime_id, "payments-agent", agent_id="agent-1"))

    assignments = PolicyAssignmentRegistry()
    policy = Policy(policy_id="payments", version=7, capabilities=("payments:charge",))
    bundle = PolicyBundle.from_policy(policy)
    assignments.assign(PolicyAssignment.from_bundle("assign-1", bundle, "agent-1"))

    view = OperatorIncidentView.from_evidence(_envelope(policy), fleet=fleet, assignments=assignments)

    assert view.agent["name"] == "payments-agent"
    assert view.policy["policy_version"] == 7
    assert view.policy["assignment_id"] == "assign-1"
    assert view.incident.status.value == "contained"
    assert view.incident.trigger == "anomaly_detected"
    assert [event.name for event in view.timeline] == ["admission_verified", "anomaly_detected", "containment_verified"]
    assert view.timeline[1].details["reason"] == "unauthorized_action"


def test_operator_view_does_not_mutate_evidence() -> None:
    policy = Policy(policy_id="payments", version=7)
    envelope = _envelope(policy)
    before = envelope.to_json()
    view = OperatorIncidentView.from_evidence(envelope)
    assert view.to_dict()["evidence"] == envelope.to_dict()
    assert envelope.to_json() == before


def test_operator_view_projects_external_evidence_references() -> None:
    policy = Policy(policy_id="payments", version=7)
    reference = ExternalEvidenceReference(
        source="warden",
        reference_id="warden-event-1",
        digest="sha256:" + "b" * 64,
        relation="observed_during",
        captured_at="2026-09-27T00:00:00Z",
    )
    envelope = _envelope(policy).with_external_evidence(reference)

    view = OperatorIncidentView.from_evidence(envelope)

    assert view.external_evidence == (reference,)
    assert view.to_dict()["external_evidence"] == [reference.to_dict()]
    assert view.to_dict()["evidence"]["external_evidence"] == [reference.to_dict()]


def test_operator_view_requires_explicit_verification_result_for_verified_status():
    from agentcontain.verification_result import compose_verification

    policy = Policy(policy_id="payments", version=7)
    envelope = _envelope(policy)

    # A serialized status string is a producer claim, not a verifier result.
    untrusted_view = OperatorIncidentView.from_evidence(envelope)
    assert untrusted_view.incident.status.value == "contained"
    assert untrusted_view.incident.proof_status == "verified"
    assert untrusted_view.verification_result is None

    result = compose_verification(
        authority_valid=True,
        runtime_valid=True,
        authenticated=True,
        correlated=True,
        anchored=True,
        verifier_executed=True,
    )
    verified_view = OperatorIncidentView.from_evidence(
        envelope,
        verification_result=result,
    )
    assert verified_view.incident.status.value == "verified"
    assert verified_view.to_dict()["verification_result"]["status"] == "verified"


def test_verification_event_alone_does_not_promote_observed_evidence():
    from agentcontain.evidence import EvidenceEnvelope

    policy = Policy(policy_id="payments", version=7)
    document = _envelope(policy).to_dict()
    document["verification"]["status"] = "observed"
    document["events"].append(
        {
            "name": "verification_completed",
            "execution_id": "exec-1",
            "epoch": 3,
            "sequence": 4,
            "timestamp": "2026-09-27T00:00:03+00:00",
            "details": {},
        }
    )

    view = OperatorIncidentView.from_evidence(EvidenceEnvelope.from_dict(document))

    assert view.incident.status.value == "contained"
    assert view.incident.proof_status == "observed"
    assert view.verification_result is None
