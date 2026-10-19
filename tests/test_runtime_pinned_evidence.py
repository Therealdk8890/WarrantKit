import pytest

from agentcontain.engine import admit, contain, verify
from agentcontain.evidence import EvidenceEnvelope
from agentcontain.policy import Policy


class Report:
    epoch = 1
    complete = True
    certified = True
    durable = True
    external_verified = True


class Engine:
    last_report = None

    def contain(self):
        self.last_report = Report()
        return self.last_report


def _admission(runtime_id="runtime-1"):
    return admit(
        Policy("production"),
        agent_id="agent-1",
        runtime_id=runtime_id,
        engine=Engine(),
    )


def _binding(*, epoch=1, runtime_id="runtime-1", action="KILL", state="TERMINATED", execution_id="e", policy_id="p", policy_digest="d"):
    from agentcontain.evidence import canonical_json
    import hashlib

    def signed_record(record):
        return {
            "digest": "sha256:" + hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest(),
            "record": record,
        }

    return {
        "schema_version": "agentcontain.runtime-binding/v1",
        "runtime_id": runtime_id,
        "agent_id": "agent-1",
        "epoch": epoch,
        "authority": signed_record({
            "runtime_id": runtime_id, "agent_id": "agent-1", "epoch": epoch,
            "execution_id": execution_id, "policy_id": policy_id, "policy_digest": policy_digest,
            "revoked": True, "revoked_at": "2026-09-30T17:00:00Z",
        }) | {"revoked": True, "revoked_at": "2026-09-30T17:00:00Z"},
        "enforcement": signed_record({
            "runtime_id": runtime_id, "agent_id": "agent-1", "epoch": epoch,
            "action": action, "external_boundary": True, "occurred_at": "2026-09-30T17:00:01Z",
        }) | {"action": action, "external_boundary": True, "occurred_at": "2026-09-30T17:00:01Z"},
        "observation": signed_record({
            "runtime_id": runtime_id, "agent_id": "agent-1", "epoch": epoch,
            "state": state, "can_execute": False, "observed_at": "2026-09-30T17:00:02Z",
        }) | {"state": state, "observed_at": "2026-09-30T17:00:02Z"},
    }


def test_runtime_pinned_binding_checks_structure_without_claiming_authenticity():
    admission = _admission()
    contain(admission)
    envelope = EvidenceEnvelope.from_execution(
        execution={
            "execution_id": admission.identity.execution_id,
            "agent_id": admission.identity.agent_id,
            "policy_id": admission.identity.policy_id,
            "policy_digest": admission.identity.policy_digest,
            "epoch": admission.identity.epoch,
            "runtime_id": admission.identity.runtime_id,
        },
        events=({"execution_id": admission.identity.execution_id, "sequence": 1, "name": "containment_verified", "epoch": 1},),
        verification={"status": "observed"},
    )

    bound = envelope.with_runtime_pinned_evidence(_binding(
        execution_id=admission.identity.execution_id,
        policy_id=admission.identity.policy_id,
        policy_digest=admission.identity.policy_digest,
    ))

    assert bound.verification["status"] == "observed"
    assert bound.proof["runtime_binding"]["runtime_id"] == "runtime-1"
    assert bound.proof["runtime_binding"]["epoch"] == 1


def test_stale_runtime_binding_cannot_verify_new_epoch():
    admission = _admission()
    contain(admission)
    admission.identity = admission.identity.advance_epoch()
    binding = _binding(
        epoch=1,
        execution_id=admission.identity.execution_id,
        policy_id=admission.identity.policy_id,
        policy_digest=admission.identity.policy_digest,
    )

    with pytest.raises(ValueError, match="epoch does not match"):
        EvidenceEnvelope.from_execution(
            execution={
                "execution_id": admission.identity.execution_id,
                "agent_id": admission.identity.agent_id,
                "policy_id": admission.identity.policy_id,
                "policy_digest": admission.identity.policy_digest,
                "epoch": admission.identity.epoch,
                "runtime_id": admission.identity.runtime_id,
            },
            events=({"execution_id": admission.identity.execution_id, "sequence": 1, "name": "containment_verified", "epoch": 2},),
        ).with_runtime_pinned_evidence(binding)


def test_substituted_runtime_cannot_verify():
    admission = _admission(runtime_id="runtime-intended")
    contain(admission)
    envelope = EvidenceEnvelope.from_execution(
        execution={
            "execution_id": admission.identity.execution_id,
            "agent_id": admission.identity.agent_id,
            "policy_id": admission.identity.policy_id,
            "policy_digest": admission.identity.policy_digest,
            "epoch": admission.identity.epoch,
            "runtime_id": admission.identity.runtime_id,
        },
        events=({"execution_id": admission.identity.execution_id, "sequence": 1, "name": "containment_verified", "epoch": 1},),
    )

    with pytest.raises(ValueError, match="runtime_id does not match"):
        envelope.with_runtime_pinned_evidence(_binding(
            runtime_id="runtime-substituted",
            execution_id=admission.identity.execution_id,
            policy_id=admission.identity.policy_id,
            policy_digest=admission.identity.policy_digest,
        ))


def test_agent_self_claim_cannot_satisfy_runtime_binding():
    binding = _binding()
    binding["enforcement"]["external_boundary"] = False

    with pytest.raises(ValueError, match="external to the agent"):
        EvidenceEnvelope.from_execution(
            execution={"execution_id": "e", "agent_id": "agent-1", "policy_id": "p", "policy_digest": "d", "epoch": 1, "runtime_id": "runtime-1"},
            events=({"execution_id": "e", "sequence": 1, "name": "agent_claimed_stopped", "epoch": 1},),
        ).with_runtime_pinned_evidence(binding)


def test_observation_before_enforcement_fails_closed():
    binding = _binding()
    binding["observation"]["observed_at"] = "2026-09-30T16:59:59Z"

    with pytest.raises(ValueError, match="observation predates enforcement"):
        EvidenceEnvelope.from_execution(
            execution={"execution_id": "e", "agent_id": "agent-1", "policy_id": "p", "policy_digest": "d", "epoch": 1, "runtime_id": "runtime-1"},
            events=({"execution_id": "e", "sequence": 1, "name": "containment_verified", "epoch": 1},),
        ).with_runtime_pinned_evidence(binding)


def test_verify_path_accepts_runtime_pinned_second_evidence():
    admission = _admission()
    contain(admission)
    verify(admission, runtime_binding=_binding(
        execution_id=admission.identity.execution_id,
        policy_id=admission.identity.policy_id,
        policy_digest=admission.identity.policy_digest,
    ))
    assert admission.machine.state.value == "verified"


def test_tampered_serialized_runtime_binding_fails_closed():
    admission = _admission()
    contain(admission)
    envelope = EvidenceEnvelope.from_execution(
        execution={
            "execution_id": admission.identity.execution_id,
            "agent_id": admission.identity.agent_id,
            "policy_id": admission.identity.policy_id,
            "policy_digest": admission.identity.policy_digest,
            "epoch": 1,
            "runtime_id": admission.identity.runtime_id,
        },
        events=({"execution_id": admission.identity.execution_id, "sequence": 1, "name": "containment_verified", "epoch": 1},),
    ).with_runtime_pinned_evidence(_binding(
        execution_id=admission.identity.execution_id,
        policy_id=admission.identity.policy_id,
        policy_digest=admission.identity.policy_digest,
    ))
    document = envelope.to_dict()
    document["proof"]["runtime_binding"]["epoch"] = 0

    with pytest.raises(ValueError, match="runtime binding epoch"):
        EvidenceEnvelope.from_dict(document)


def test_tampered_runtime_record_fails_digest_binding():
    binding = _binding()
    binding["enforcement"]["record"]["action"] = "FENCE"
    with pytest.raises(ValueError, match="digest does not match record"):
        EvidenceEnvelope.from_execution(
            execution={"execution_id": "e", "agent_id": "agent-1", "policy_id": "p", "policy_digest": "d", "epoch": 1, "runtime_id": "runtime-1"},
            events=({"execution_id": "e", "sequence": 1, "name": "containment_verified", "epoch": 1},),
        ).with_runtime_pinned_evidence(binding)


def test_authority_record_tampering_fails_digest_binding():
    binding = _binding()
    binding["authority"]["record"]["revoked"] = False
    with pytest.raises(ValueError, match="digest does not match record"):
        EvidenceEnvelope.from_execution(
            execution={"execution_id": "e", "agent_id": "agent-1", "policy_id": "p", "policy_digest": "d", "epoch": 1, "runtime_id": "runtime-1"},
            events=({"execution_id": "e", "sequence": 1, "name": "containment_verified", "epoch": 1},),
        ).with_runtime_pinned_evidence(binding)


def test_observation_semantics_are_taken_from_digested_record():
    binding = _binding(state="TERMINATED")
    binding["observation"]["state"] = "FENCED"
    binding["observation"]["record"]["state"] = "FENCED"
    with pytest.raises(ValueError, match="digest does not match record"):
        EvidenceEnvelope.from_execution(
            execution={"execution_id": "e", "agent_id": "agent-1", "policy_id": "p", "policy_digest": "d", "epoch": 1, "runtime_id": "runtime-1"},
            events=({"execution_id": "e", "sequence": 1, "name": "containment_verified", "epoch": 1},),
        ).with_runtime_pinned_evidence(binding)



def test_numeric_runtime_observation_timestamp_is_accepted():
    binding = _binding()
    observation_record = dict(binding["observation"]["record"])
    observation_record["observed_at"] = 1790790002.0
    import hashlib
    from agentcontain.evidence import canonical_json

    binding["observation"]["record"] = observation_record
    binding["observation"]["observed_at"] = observation_record["observed_at"]
    binding["observation"]["digest"] = "sha256:" + hashlib.sha256(
        canonical_json(observation_record).encode("utf-8")
    ).hexdigest()

    envelope = EvidenceEnvelope.from_execution(
        execution={
            "execution_id": "e",
            "agent_id": "agent-1",
            "policy_id": "p",
            "policy_digest": "d",
            "epoch": 1,
            "runtime_id": "runtime-1",
        },
        events=({"execution_id": "e", "sequence": 1, "name": "containment_verified", "epoch": 1},),
    ).with_runtime_pinned_evidence(binding)

    assert envelope.verification["status"] == "observed"
    assert envelope.proof["runtime_binding"]["observation"]["observed_at"] == 1790790002.0


def test_enforcement_cannot_predate_authority_revocation():
    binding = _binding()
    enforcement_record = dict(binding["enforcement"]["record"])
    enforcement_record["occurred_at"] = "2026-09-30T16:59:59Z"
    import hashlib
    from agentcontain.evidence import canonical_json

    binding["enforcement"]["record"] = enforcement_record
    binding["enforcement"]["occurred_at"] = enforcement_record["occurred_at"]
    binding["enforcement"]["digest"] = "sha256:" + hashlib.sha256(
        canonical_json(enforcement_record).encode("utf-8")
    ).hexdigest()

    with pytest.raises(ValueError, match="enforcement predates authority revocation"):
        EvidenceEnvelope.from_execution(
            execution={
                "execution_id": "e",
                "agent_id": "agent-1",
                "policy_id": "p",
                "policy_digest": "d",
                "epoch": 1,
                "runtime_id": "runtime-1",
            },
            events=({"execution_id": "e", "sequence": 1, "name": "containment_verified", "epoch": 1},),
        ).with_runtime_pinned_evidence(binding)


def test_authority_record_must_bind_exact_execution_and_policy():
    import hashlib
    from agentcontain.evidence import canonical_json

    binding = _binding()
    binding["authority"]["record"]["policy_digest"] = "sha256:other-policy"
    binding["authority"]["digest"] = "sha256:" + hashlib.sha256(
        canonical_json(binding["authority"]["record"]).encode("utf-8")
    ).hexdigest()
    envelope = EvidenceEnvelope.from_execution(
        execution={"execution_id": "e", "agent_id": "agent-1", "policy_id": "p", "policy_digest": "d", "epoch": 1, "runtime_id": "runtime-1"},
        events=({"execution_id": "e", "sequence": 1, "name": "containment_verified", "epoch": 1},),
    )

    with pytest.raises(ValueError, match="authority policy_digest does not match execution"):
        envelope.with_runtime_pinned_evidence(binding)


@pytest.mark.parametrize("can_execute", [True, None])
def test_observation_must_explicitly_prove_non_executability(can_execute):
    import hashlib
    from agentcontain.evidence import canonical_json

    binding = _binding()
    record = binding["observation"]["record"]
    if can_execute is None:
        del record["can_execute"]
    else:
        record["can_execute"] = can_execute
    binding["observation"]["digest"] = "sha256:" + hashlib.sha256(
        canonical_json(record).encode("utf-8")
    ).hexdigest()
    envelope = EvidenceEnvelope.from_execution(
        execution={"execution_id": "e", "agent_id": "agent-1", "policy_id": "p", "policy_digest": "d", "epoch": 1, "runtime_id": "runtime-1"},
        events=({"execution_id": "e", "sequence": 1, "name": "containment_verified", "epoch": 1},),
    )

    with pytest.raises(ValueError, match="does not prove non-executability"):
        envelope.with_runtime_pinned_evidence(binding)


def test_non_finite_runtime_timestamp_is_rejected():
    binding = _binding()
    binding["authority"]["record"]["revoked_at"] = float("nan")
    envelope = EvidenceEnvelope.from_execution(
        execution={"execution_id": "e", "agent_id": "agent-1", "policy_id": "p", "policy_digest": "d", "epoch": 1, "runtime_id": "runtime-1"},
        events=({"execution_id": "e", "sequence": 1, "name": "containment_verified", "epoch": 1},),
    )

    with pytest.raises(ValueError):
        envelope.with_runtime_pinned_evidence(binding)


@pytest.mark.parametrize(
    ("section", "field", "outer_field"),
    [
        ("authority", "revoked_at", "revoked_at"),
        ("enforcement", "occurred_at", "occurred_at"),
        ("observation", "observed_at", "observed_at"),
    ],
)
def test_runtime_binding_rejects_naive_record_timestamps(section, field, outer_field):
    import hashlib
    from agentcontain.evidence import canonical_json

    binding = _binding()
    record = dict(binding[section]["record"])
    record[field] = "2026-09-30T17:00:00"
    binding[section]["record"] = record
    binding[section][outer_field] = record[field]
    binding[section]["digest"] = "sha256:" + hashlib.sha256(
        canonical_json(record).encode("utf-8")
    ).hexdigest()

    with pytest.raises(ValueError, match="must include a UTC offset"):
        EvidenceEnvelope.from_execution(
            execution={
                "execution_id": "e",
                "agent_id": "agent-1",
                "policy_id": "p",
                "policy_digest": "d",
                "epoch": 1,
                "runtime_id": "runtime-1",
            },
            events=({"execution_id": "e", "sequence": 1, "name": "containment_verified", "epoch": 1},),
        ).with_runtime_pinned_evidence(binding)


@pytest.mark.parametrize("label", ["authority", "enforcement", "observation"])
def test_runtime_binding_rejects_boolean_record_epochs(label):
    import hashlib
    from agentcontain.evidence import canonical_json

    binding = _binding()
    record = dict(binding[label]["record"])
    record["epoch"] = True
    binding[label]["record"] = record
    binding[label]["digest"] = "sha256:" + hashlib.sha256(
        canonical_json(record).encode("utf-8")
    ).hexdigest()

    with pytest.raises(ValueError, match="record epoch must be a positive integer"):
        EvidenceEnvelope.from_execution(
            execution={
                "execution_id": "e",
                "agent_id": "agent-1",
                "policy_id": "p",
                "policy_digest": "d",
                "epoch": 1,
                "runtime_id": "runtime-1",
            },
            events=({"execution_id": "e", "sequence": 1, "name": "containment_verified", "epoch": 1},),
        ).with_runtime_pinned_evidence(binding)
